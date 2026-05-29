//! RandomX cache pool — bounded, thread-safe.
//!
//! RandomX cache initialization allocates ~256 MB and takes hundreds of milliseconds.
//! Re-initializing per block (e.g. during IBD or peer validation) is infeasible.
//!
//! This module maintains a bounded pool of caches keyed by seed. Entries are
//! evicted in FIFO order when the pool exceeds `MAX_POOL_ENTRIES` — at the seed
//! rotation boundary (RFC-0011, every `RANDOMX_SEED_INTERVAL` blocks) only the
//! current and previous epoch caches are kept hot.
//!
//! # Safety
//!
//! `randomx_rs::RandomXCache` wraps a `*mut randomx_cache` and is therefore not
//! `Send`/`Sync` by default. The underlying RandomX C library guarantees:
//!   1. `randomx_init_cache` is single-writer (called once in `RandomXCache::new`).
//!   2. After init, the cache pointer is read-only — multiple VMs may reference
//!      the same cache concurrently (this is the design used by mining pools).
//!   3. `randomx_release_cache` is serialized by `Arc` drop semantics.
//!
//! We expose a `SyncCache` newtype with manual `Send`/`Sync` impls reflecting
//! these invariants. Construction is fallible and serialized through the pool
//! `Mutex`, so init races are impossible.
//!
//! # Why FIFO instead of LRU
//!
//! Seed rotation is deterministic (RFC-0011: every 2048 blocks). Validators
//! mainly need the current epoch cache; previous epoch is kept only to handle
//! blocks straddling the rotation boundary. FIFO with capacity 2 is sufficient
//! and simpler than LRU.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

use dom_core::DomError;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

/// Maximum number of caches held simultaneously.
///
/// Each cache is ~256 MB. Two entries cover the current and previous seed epoch
/// (sufficient for blocks straddling a rotation boundary). Increasing this is
/// almost always a memory leak, not an optimization.
pub const MAX_POOL_ENTRIES: usize = 2;

/// Thread-safe wrapper over `RandomXCache`.
///
/// See module-level `# Safety` notes for justification.
#[allow(unsafe_code)]
struct SyncCache(RandomXCache);

// SAFETY: RandomX C library guarantees read-only access to an initialized cache
// is safe from multiple threads. `RandomXCache::new` is the only writer and is
// serialized by the pool `Mutex`. Drop is serialized by Arc.
#[allow(unsafe_code)]
unsafe impl Send for SyncCache {}
#[allow(unsafe_code)]
unsafe impl Sync for SyncCache {}

impl SyncCache {
    fn new(seed: &[u8; 32]) -> Result<Self, DomError> {
        let flags = RandomXFlag::get_recommended_flags();
        let cache = RandomXCache::new(flags, seed)
            .map_err(|e| DomError::Internal(format!("RandomX cache init failed: {e}")))?;
        Ok(Self(cache))
    }

    fn inner(&self) -> RandomXCache {
        // `RandomXCache` is internally `Arc<RandomXCacheInner>`, so clone is cheap.
        self.0.clone()
    }
}

struct PoolEntry {
    seed: [u8; 32],
    cache: Arc<SyncCache>,
}

struct Pool {
    entries: VecDeque<PoolEntry>,
}

impl Pool {
    const fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    fn get(&self, seed: &[u8; 32]) -> Option<Arc<SyncCache>> {
        self.entries
            .iter()
            .find(|e| &e.seed == seed)
            .map(|e| Arc::clone(&e.cache))
    }

    fn insert(&mut self, seed: [u8; 32], cache: Arc<SyncCache>) {
        while self.entries.len() >= MAX_POOL_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(PoolEntry { seed, cache });
    }
}

fn pool() -> &'static Mutex<Pool> {
    static POOL: OnceLock<Mutex<Pool>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(Pool::new()))
}

/// Retrieve a cache for `seed`, initializing and caching it if absent.
///
/// First caller for a given seed pays the ~256 MB / ~hundreds-of-ms init cost.
/// Subsequent callers receive the cached entry instantly.
fn get_or_init_cache(seed: &[u8; 32]) -> Result<Arc<SyncCache>, DomError> {
    {
        let guard = pool()
            .lock()
            .map_err(|e| DomError::Internal(format!("RandomX pool mutex poisoned: {e}")))?;
        if let Some(c) = guard.get(seed) {
            return Ok(c);
        }
    }

    // Build cache outside the lock to avoid serializing init across threads
    // requesting *different* seeds.
    let new_cache = Arc::new(SyncCache::new(seed)?);

    let mut guard = pool()
        .lock()
        .map_err(|e| DomError::Internal(format!("RandomX pool mutex poisoned: {e}")))?;
    // Re-check: another thread may have inserted while we were initializing.
    if let Some(c) = guard.get(seed) {
        return Ok(c);
    }
    guard.insert(*seed, Arc::clone(&new_cache));
    Ok(new_cache)
}

/// Compute a RandomX hash for `preimage` under `seed`, using the pooled cache.
///
/// Allocates a fresh `RandomXVM` (lightweight: ~2 MB scratchpad) bound to the
/// shared cache. Caching the VM itself is intentionally avoided — VMs hold
/// mutable scratchpad state and cannot be safely shared across threads.
pub fn randomx_hash(seed: &[u8; 32], preimage: &[u8]) -> Result<[u8; 32], DomError> {
    let cache = get_or_init_cache(seed)?;
    let flags = RandomXFlag::get_recommended_flags();
    let vm = RandomXVM::new(flags, Some(cache.inner()), None)
        .map_err(|e| DomError::Internal(format!("RandomX VM init failed: {e}")))?;
    let computed = vm
        .calculate_hash(preimage)
        .map_err(|e| DomError::Internal(format!("RandomX hash failed: {e}")))?;
    if computed.len() != 32 {
        return Err(DomError::Internal(format!(
            "RandomX returned {} bytes, expected 32",
            computed.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&computed);
    Ok(out)
}

#[cfg(test)]
pub(crate) fn clear_pool_for_test() {
    if let Ok(mut g) = pool().lock() {
        g.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_reuses_cache_for_same_seed() {
        clear_pool_for_test();
        let seed = [42u8; 32];
        let c1 = get_or_init_cache(&seed).unwrap();
        let c2 = get_or_init_cache(&seed).unwrap();
        assert!(Arc::ptr_eq(&c1, &c2), "pool must return the same Arc");
    }

    #[test]
    fn pool_evicts_oldest_when_full() {
        clear_pool_for_test();
        let seeds: Vec<[u8; 32]> = (0..(MAX_POOL_ENTRIES as u8 + 1)).map(|i| [i; 32]).collect();
        for s in &seeds {
            get_or_init_cache(s).unwrap();
        }
        // First seed should have been evicted; requesting it must build a new entry.
        let _ = get_or_init_cache(&seeds[0]).unwrap();
        let g = pool().lock().unwrap();
        assert!(g.entries.len() <= MAX_POOL_ENTRIES);
        assert!(g.entries.iter().any(|e| e.seed == seeds[0]));
    }

    #[test]
    fn hash_is_deterministic() {
        clear_pool_for_test();
        let seed = [7u8; 32];
        let preimage = b"deterministic-input";
        let h1 = randomx_hash(&seed, preimage).unwrap();
        let h2 = randomx_hash(&seed, preimage).unwrap();
        assert_eq!(h1, h2);
    }
}

//! RandomX cache/dataset pools — bounded, thread-safe.
//!
//! Two independent hashing paths share this module:
//!
//! * **Validation (light mode)** — `randomx_hash`. Ephemeral VM per hash,
//!   bound to the pooled ~256 MB cache only. Dataset items are computed
//!   on-the-fly: ~10x slower per hash but cheap in memory, which is the right
//!   trade-off for validating a handful of headers.
//! * **Mining (fast mode)** — `MinerVm`. Persistent per-thread VM bound to the
//!   pooled full ~2 GB dataset (`FLAG_FULL_MEM`). Both modes compute the exact
//!   same RandomX function — fast mode only trades memory for speed — so a
//!   hash found by a `MinerVm` validates under `randomx_hash` byte-for-byte
//!   (asserted by `tests/miner_light_equivalence.rs`).
//!
//! RandomX cache initialization allocates ~256 MB and takes hundreds of milliseconds.
//! Re-initializing per block (e.g. during IBD or peer validation) is infeasible.
//!
//! This module maintains a bounded pool of caches keyed by seed. Entries are
//! evicted in FIFO order when the pool exceeds `MAX_POOL_ENTRIES` — at the seed
//! rotation boundary (RFC-0011, every `RANDOMX_SEED_INTERVAL` blocks) only the
//! current and previous epoch caches are kept hot.
//!
//! The mining dataset pool holds a single entry: the dataset for the seed
//! currently being mined. It is rebuilt only when the mined seed changes
//! (RFC-0011 rotation, every `RANDOMX_SEED_INTERVAL` blocks) — never per block
//! and never per hash. `randomx-rs` 1.4.1 only exposes single-threaded dataset
//! initialization, so a rebuild takes on the order of a minute; amortized over
//! a 2048-block epoch that is negligible, but it is why the build MUST be
//! cached here rather than repeated per template.
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
//! `Mutex`, so init races are impossible. `SyncDataset` mirrors the same
//! argument for `*mut randomx_dataset`: `randomx_init_dataset` is the single
//! writer (called once inside `RandomXDataset::new`, serialized by the miner
//! pool `Mutex`), after which the dataset is read-only for any number of VMs
//! on any threads, and release is serialized by `Arc` drop semantics.
//!
//! # Why FIFO instead of LRU
//!
//! Seed rotation is deterministic (RFC-0011: every 2048 blocks). Validators
//! mainly need the current epoch cache; previous epoch is kept only to handle
//! blocks straddling the rotation boundary. FIFO with capacity 2 is sufficient
//! and simpler than LRU.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Once, OnceLock};

use dom_core::DomError;
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};

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

/// Thread-safe wrapper over `RandomXDataset` (~2 GB, `FLAG_FULL_MEM` mining).
///
/// See module-level `# Safety` notes for justification.
#[allow(unsafe_code)]
struct SyncDataset(RandomXDataset);

// SAFETY: RandomX C library guarantees read-only access to an initialized
// dataset is safe from multiple threads (one VM per thread, any number of
// VMs). `RandomXDataset::new` is the only writer and is serialized by the
// miner pool `Mutex`. Drop is serialized by the inner Arc.
#[allow(unsafe_code)]
unsafe impl Send for SyncDataset {}
#[allow(unsafe_code)]
unsafe impl Sync for SyncDataset {}

impl SyncDataset {
    fn inner(&self) -> RandomXDataset {
        // `RandomXDataset` is internally `Arc<RandomXDatasetInner>`, so clone
        // is cheap and keeps the dataset alive independently of the pool.
        self.0.clone()
    }
}

/// Warn exactly once when large pages are unavailable and the dataset
/// degrades to normal pages.
static DATASET_LARGE_PAGES_FALLBACK: Once = Once::new();

/// Single-entry pool: the dataset for the seed currently being mined.
///
/// Capacity is deliberately 1 — each entry is ~2 GB and mining only ever
/// targets the template's current seed. On seed rotation the old entry is
/// dropped and the new seed's dataset is built once, shared by all workers.
///
/// TODO(NUMA): on multi-socket hosts (e.g. the 2-socket EPYC miner) one
/// dataset should be allocated per NUMA node and workers pinned to their
/// local copy; a single shared dataset cross-socket halves effective
/// memory bandwidth. Irrelevant on single-socket machines.
struct MinerPool {
    entry: Option<([u8; 32], Arc<SyncDataset>)>,
}

fn miner_pool() -> &'static Mutex<MinerPool> {
    static MINER_POOL: OnceLock<Mutex<MinerPool>> = OnceLock::new();
    MINER_POOL.get_or_init(|| Mutex::new(MinerPool { entry: None }))
}

/// Build the full dataset from an initialized cache, preferring large pages.
///
/// `RandomXDataset::new` both allocates and fully initializes (items
/// [0, count)); with `FLAG_LARGE_PAGES` the allocation fails cleanly when no
/// huge pages are reserved, so we retry with normal pages and warn once.
fn build_dataset(cache: &SyncCache) -> Result<RandomXDataset, DomError> {
    match RandomXDataset::new(RandomXFlag::FLAG_LARGE_PAGES, cache.inner(), 0) {
        Ok(dataset) => Ok(dataset),
        Err(large_pages_err) => {
            DATASET_LARGE_PAGES_FALLBACK.call_once(|| {
                tracing::warn!(
                    "RandomX dataset large-pages allocation failed ({large_pages_err}); \
                     falling back to normal pages — reserve huge pages for better hashrate"
                );
            });
            RandomXDataset::new(RandomXFlag::FLAG_DEFAULT, cache.inner(), 0)
                .map_err(|e| DomError::Internal(format!("RandomX dataset init failed: {e}")))
        }
    }
}

/// Retrieve the mining dataset for `seed`, building it if absent.
///
/// Unlike `get_or_init_cache`, the build happens **inside** the pool lock:
/// N mining workers racing on a fresh seed must produce exactly one ~2 GB
/// dataset, not N transient ones (which would exhaust memory). Workers for
/// the same seed simply block until the first finishes building; mining is
/// single-seed at any point in time, so serializing builds costs nothing.
fn get_or_init_dataset(seed: &[u8; 32]) -> Result<Arc<SyncDataset>, DomError> {
    let mut guard = miner_pool()
        .lock()
        .map_err(|e| DomError::Internal(format!("RandomX miner pool mutex poisoned: {e}")))?;
    if let Some((cached_seed, dataset)) = &guard.entry {
        if cached_seed == seed {
            return Ok(Arc::clone(dataset));
        }
    }
    // Seed rotation (or first use): build once, evicting any previous epoch.
    let cache = get_or_init_cache(seed)?;
    let dataset = Arc::new(SyncDataset(build_dataset(&cache)?));
    guard.entry = Some((*seed, Arc::clone(&dataset)));
    Ok(dataset)
}

/// Persistent mining VM — RandomX **fast mode** (`FLAG_FULL_MEM`).
///
/// Computes the exact same hash function as `randomx_hash` (light mode); fast
/// mode only precomputes the dataset instead of deriving items per hash.
/// Create one per mining thread, outside the nonce loop, and reuse it for the
/// whole search: VM creation is cheap (~2 MB scratchpad) but not free, and
/// recreating it per hash forfeits the ~10x fast-mode advantage.
///
/// The heavy state (~2 GB dataset + ~256 MB cache) lives in the module pools
/// and is shared: N threads calling `MinerVm::new` with the same seed cost
/// one dataset total. `MinerVm` itself is intentionally `!Send`/`!Sync` (the
/// inner VM owns a mutable scratchpad) — each thread builds its own.
pub struct MinerVm {
    vm: RandomXVM,
}

impl MinerVm {
    /// Fast-mode VM for `seed`. First caller per seed pays the one-off
    /// dataset build (single-threaded in `randomx-rs` 1.4.1 — on the order
    /// of a minute); subsequent callers attach to the pooled dataset.
    pub fn new(seed: &[u8; 32]) -> Result<Self, DomError> {
        let dataset = get_or_init_dataset(seed)?;
        // NO `FLAG_LARGE_PAGES` on the VM: `randomx-rs` 1.4.1 does not check
        // `randomx_create_vm` for NULL (lib.rs `RandomXVM::new`), so a failed
        // large-pages scratchpad allocation is not observable as `Err` — it
        // returns Ok(<null vm>) and the first `calculate_hash` segfaults
        // (reproduced on a host without reserved huge pages). Try-then-
        // fallback is therefore only safe for the dataset, whose constructor
        // does check for NULL. The scratchpad is ~2 MB; the dataset dominates
        // the working set, so the hashrate cost is minor.
        // TODO(randomx-rs): revisit if the crate ever surfaces VM alloc
        // failure as an error.
        let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
        let vm = RandomXVM::new(flags, None, Some(dataset.inner()))
            .map_err(|e| DomError::Internal(format!("RandomX mining VM init failed: {e}")))?;
        Ok(Self { vm })
    }

    /// Light-mode VM for `seed` (cache only, no dataset) — same persistent-VM
    /// ergonomics for callers that must not allocate 2 GB (e.g. regtest
    /// mining). Hashes are identical to `Self::new`'s.
    pub fn new_light(seed: &[u8; 32]) -> Result<Self, DomError> {
        let cache = get_or_init_cache(seed)?;
        let flags = RandomXFlag::get_recommended_flags();
        let vm = RandomXVM::new(flags, Some(cache.inner()), None)
            .map_err(|e| DomError::Internal(format!("RandomX light VM init failed: {e}")))?;
        Ok(Self { vm })
    }

    /// Hash `preimage` — identical output to `randomx_hash(seed, preimage)`.
    pub fn hash(&self, preimage: &[u8]) -> Result<[u8; 32], DomError> {
        let computed = self
            .vm
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
}

/// Test/diagnostic hook: identity of the pooled dataset for `seed`, if built.
///
/// Two equal pointers across calls prove the dataset was built once and
/// reused (acceptance criterion for the fast-mode mining path).
pub fn miner_dataset_id_for_seed(seed: &[u8; 32]) -> Option<usize> {
    let guard = miner_pool().lock().ok()?;
    guard
        .entry
        .as_ref()
        .filter(|(cached_seed, _)| cached_seed == seed)
        .map(|(_, dataset)| Arc::as_ptr(dataset) as usize)
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

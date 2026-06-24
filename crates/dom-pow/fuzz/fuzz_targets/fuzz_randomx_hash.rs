#![no_main]
//! Fuzz target: dom_pow::randomx_pool::randomx_hash on arbitrary preimage.
//!
//! Invariant (Lens A: panic/crash): hashing an arbitrary preimage under a fixed
//! seed must never panic. RandomX cache init is expensive (~256 MB), so this
//! target pins the SEED to a single constant and varies only the preimage —
//! every iteration reuses the one pooled cache (no per-iteration 256 MB alloc,
//! no seed churn). This keeps the target a panic/OOB probe over the preimage
//! path, not a memory-amplification stressor.
//!
//! NOTE: run with a SMALL parallel job count and a modest rss limit; RandomX
//! holds a ~256 MB cache for the life of the process.

use libfuzzer_sys::fuzz_target;
use dom_pow::randomx_pool::randomx_hash;

const FIXED_SEED: [u8; 32] = [0x7eu8; 32];

fuzz_target!(|data: &[u8]| {
    // Single fixed seed ⇒ one cached cache entry, reused every iteration.
    let _ = randomx_hash(&FIXED_SEED, data);
});

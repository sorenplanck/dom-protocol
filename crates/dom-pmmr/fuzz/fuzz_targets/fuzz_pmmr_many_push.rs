#![no_main]
//! fuzz-panic — many sequential pushes (peak-merge stress).
//!
//! Drives a large number of pushes of a fuzzer-chosen small payload to
//! exercise the merge_peaks cascade and node_count arithmetic across
//! many peak-boundary transitions (2^k - 1, 2^k, 2^k + 1). Recomputes
//! root() at several points. Must never panic; push may return Err.
//!
//! The push count is capped from the first two fuzz bytes so a single
//! input stays bounded (no unbounded-time inputs from the corpus).

use libfuzzer_sys::fuzz_target;
use dom_pmmr::Pmmr;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // Bounded push count: 0..=65535, capped to 20_000 for time safety.
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let count = count.min(20_000);
    let payload = &data[2..];

    let mut pmmr = Pmmr::new();
    for i in 0..count {
        // Vary the payload slightly per push so peaks differ.
        let mut p = payload.to_vec();
        p.push((i & 0xff) as u8);
        if pmmr.push(&p).is_err() {
            return;
        }
        // Recompute the root at every peak boundary to stress bagging.
        if i.is_power_of_two() {
            let _ = pmmr.root();
        }
    }
    let _ = pmmr.root();
    let _ = pmmr.node_count();
});

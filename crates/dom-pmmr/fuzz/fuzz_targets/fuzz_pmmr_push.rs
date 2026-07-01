#![no_main]
//! fuzz-panic — dom_pmmr::Pmmr::push with arbitrary payloads.
//!
//! Invariant: pushing a sequence of arbitrary byte payloads, then
//! computing root() and node_count(), must NEVER panic. push() may
//! return Err on overflow but must not crash. root() returns Result
//! (FIX-021); on an append-only PMMR all peaks are present, so root()
//! must be Ok — an Err here means push/merge left a hole, which is a bug.

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use dom_pmmr::Pmmr;

#[derive(Arbitrary, Debug)]
struct Input {
    payloads: Vec<Vec<u8>>,
}

fuzz_target!(|input: Input| {
    let mut pmmr = Pmmr::new();
    for p in &input.payloads {
        if pmmr.push(p).is_err() {
            return;
        }
    }
    // Infallible queries must not panic on any reachable state.
    let _ = pmmr.root().expect("append-built PMMR has all peaks present; root() must be Ok (FIX-021)");
    let _ = pmmr.node_count();
    let _ = pmmr.leaf_count();
});

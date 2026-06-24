#![no_main]
//! fuzz-panic — dom_pmmr::Pmmr::push with arbitrary payloads.
//!
//! Invariant: pushing a sequence of arbitrary byte payloads, then
//! computing root() and node_count(), must NEVER panic. push() may
//! return Err on overflow but must not crash; root() is infallible and
//! must not panic on any reachable state.

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
    let _ = pmmr.root();
    let _ = pmmr.node_count();
    let _ = pmmr.leaf_count();
});

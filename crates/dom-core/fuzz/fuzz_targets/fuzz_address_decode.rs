#![no_main]
//! Fuzz target: `dom_core::Address::decode` on ARBITRARY strings.
//!
//! `Address::decode` is the entry point for any externally-supplied DOM address
//! (CLI input, RPC payment requests, slatepack metadata). It runs a hand-rolled
//! bech32m decoder: `rfind('1')` separator scan, byte-indexing into the charset
//! reverse table, polymod checksum, and 5-bit→8-bit repacking with padding
//! validation. Every one of those steps does slicing / shifting on
//! attacker-controlled bytes.
//!
//! Invariant: decoding ANY string must NEVER panic, abort, slice out of bounds,
//! or overflow — the only acceptable outcomes are `Ok(Address)` or `Err(_)`.
//! A crash here is a remotely-reachable DoS on anything that parses an address.
//!
//! We feed both the raw bytes (lossy UTF-8) AND treat the input as a string so
//! libFuzzer can explore multibyte / non-ASCII boundaries around the `rfind`
//! and the `c >= 128` guard.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Lossy conversion exercises the non-ASCII / multibyte paths deterministically.
    let s = String::from_utf8_lossy(data);
    let _ = dom_core::Address::decode(&s);

    // If the bytes happen to be valid UTF-8, also drive the borrowed &str path
    // directly (no replacement-char substitution), widening coverage.
    if let Ok(direct) = core::str::from_utf8(data) {
        let _ = dom_core::Address::decode(direct);
    }
});

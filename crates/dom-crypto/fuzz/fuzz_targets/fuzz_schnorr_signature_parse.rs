#![no_main]
//! Fuzz target: SchnorrSignature::from_bytes
//!
//! 65-byte signature parser. Subgroup/scalar validation paths.
use libfuzzer_sys::fuzz_target;
use dom_crypto::schnorr::SchnorrSignature;

fuzz_target!(|data: &[u8]| {
    let _ = SchnorrSignature::from_bytes(data);
});

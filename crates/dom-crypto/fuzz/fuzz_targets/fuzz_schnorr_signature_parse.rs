#![no_main]
//! Fuzz target: SchnorrSignature::from_bytes + PartialSig::from_bytes
//!
//! 65-byte signature parser + 32-byte partial-signature scalar parser. Both
//! exercise subgroup/scalar (0 < s < n) validation paths on untrusted bytes.
//! Invariant: parsing ARBITRARY bytes must NEVER panic — only Ok(_) | Err(_).
use libfuzzer_sys::fuzz_target;
use dom_crypto::schnorr::{PartialSig, SchnorrSignature};

fuzz_target!(|data: &[u8]| {
    let _ = SchnorrSignature::from_bytes(data);
    let _ = PartialSig::from_bytes(data);
});

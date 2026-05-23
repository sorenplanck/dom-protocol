#![no_main]
//! Fuzz target: Commitment::from_compressed_bytes
//!
//! Validates parser of compressed secp256k1 points. Untrusted commitments
//! enter via wire serialization of Outputs.
use libfuzzer_sys::fuzz_target;
use dom_crypto::pedersen::Commitment;

fuzz_target!(|data: &[u8]| {
    let _ = Commitment::from_compressed_bytes(data);
});

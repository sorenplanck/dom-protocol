#![no_main]
//! Fuzz target: PublicKey::from_compressed_bytes (keys.rs)
//!
//! 33-byte compressed SEC1 point parser. Length/prefix/on-curve/infinity
//! validation. Public keys enter from untrusted wire bytes (e.g. Schnorr R,
//! aggregated keys). Invariant: parsing ARBITRARY bytes must NEVER panic — the
//! only outcomes are Ok(_) or Err(_).
use libfuzzer_sys::fuzz_target;
use dom_crypto::keys::PublicKey;

fuzz_target!(|data: &[u8]| {
    let _ = PublicKey::from_compressed_bytes(data);
});

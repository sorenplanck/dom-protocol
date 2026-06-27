#![no_main]
//! Fuzz target: SEC1<->zkp commitment bridge (sec1_zkp_bridge.rs).
//!
//! The bridge (`sec1_to_zkp` / `zkp_to_sec1`) is crate-private, so it cannot be
//! called directly from this external fuzz crate. It IS, however, the first thing
//! `bp2_verify` runs on the attacker-controlled 33-byte commitment
//! (bulletproof_bp.rs:496 -> sec1_to_zkp), and the borromean `bp_verify` path
//! runs `zkp_to_sec1` internally. This target drives the bridge through those
//! public surfaces with a FULLY attacker-controlled commitment prefix+X:
//!
//!   * First 33 bytes -> commitment_sec1 (any prefix 0x00..0xFF, any X incl.
//!     off-curve / >= field modulus / identity). This hits sec1_to_zkp's
//!     PublicKey::from_slice parse, the serialize_uncompressed Y extraction, and
//!     the FieldElement::sqrt is_square oracle on whatever Y is reconstructed.
//!   * Remaining bytes -> proof bytes for the verify call (size-gated inside).
//!
//! Invariant: NO panic/abort/fault for ANY input. The bridge's
//! `.expect("Y from a valid curve point is a valid field element")` and the
//! `.try_into().unwrap()` slices must only ever run on already-validated points;
//! this fuzzer exercises the validation boundary that protects them. Only
//! Ok(true) | Ok(false) | Err(_) are acceptable outcomes.
use dom_crypto::bp2_verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let mut commitment = [0u8; 33];
    commitment.copy_from_slice(&data[..33]);
    let proof = &data[33..];
    // sec1_to_zkp(commitment) runs BEFORE any proof check, so the bridge is
    // exercised on every input regardless of proof validity.
    let _ = bp2_verify(&commitment, proof);
});

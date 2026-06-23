#![no_main]
//! Fuzz target: borromean (legacy) range-proof path — RangeProof::from_bytes
//! (bulletproof.rs:125) + bp_verify / bulletproof::verify (bulletproof.rs:264).
//!
//! The standard-Bulletproof path is fuzzed by fuzz_bp2_verify; this covers the
//! parallel BORROMEAN backend, still consensus-reachable. Two surfaces:
//!   (1) RangeProof::from_bytes: size-cap + Vec parse.
//!   (2) bp_verify against a VALID fixed commitment, feeding attacker proof bytes
//!       through the unsafe libsecp256k1-zkp FFI. This also drives sec1_to_zkp /
//!       zkp_to_sec1 internally (indirect coverage of the pub(crate) bridge — no
//!       production shim added).
//!
//! Invariant: arbitrary input must NEVER panic/abort/fault. Only Ok(false) |
//! Ok(true) | Err(_) are acceptable. A crash here is a release blocker.
use libfuzzer_sys::fuzz_target;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{bp_verify, RangeProof};

fuzz_target!(|data: &[u8]| {
    // (1) Parse path: attacker-controlled proof bytes -> RangeProof.
    let _ = RangeProof::from_bytes(data.to_vec());

    // (2) Verify path against a valid, deterministic commitment. Deriving it
    // here exercises Commitment::commit (H/G arithmetic) and zkp_to_sec1; the
    // verify then runs sec1_to_zkp + the borromean FFI on the attacker proof.
    let bf = BlindingFactor::from_bytes([1u8; 32]).expect("static non-zero blinding");
    let commitment = *Commitment::commit(0, &bf).as_bytes();
    let _ = bp_verify(&commitment, data);
});

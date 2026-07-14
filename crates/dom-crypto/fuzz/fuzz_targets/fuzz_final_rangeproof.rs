#![no_main]
//! Fuzz target: final range-proof parse and verify path.
//!
//! This covers two public surfaces:
//!   (1) RangeProof::from_bytes: size-cap + Vec parse.
//!   (2) range_proof_verify against a valid fixed commitment, feeding attacker proof bytes
//!       through the unsafe libsecp256k1-zkp FFI. This also drives sec1_to_zkp /
//!       zkp_to_sec1 internally.
//!
//! Invariant: arbitrary input must NEVER panic/abort/fault. Only Ok(false) |
//! Ok(true) | Err(_) are acceptable. A crash here is a release blocker.
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{range_proof_verify, RangeProof};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // (1) Parse path: attacker-controlled proof bytes -> RangeProof.
    let _ = RangeProof::from_bytes(data.to_vec());

    // (2) Verify path against a valid, deterministic commitment. Deriving it
    // here exercises Commitment::commit (H/G arithmetic) and zkp_to_sec1; the
    // verify then runs sec1_to_zkp + the final range-proof FFI on the attacker proof.
    let bf = BlindingFactor::from_bytes([1u8; 32]).expect("static non-zero blinding");
    let commitment = *Commitment::commit(0, &bf).as_bytes();
    let _ = range_proof_verify(&commitment, data);
});

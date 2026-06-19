#![no_main]
//! Fuzz target: bp2_verify with attacker-controlled commitment + proof bytes.
//!
//! bp2_verify(commitment_sec1: &[u8; 33], proof_bytes: &[u8]) feeds proof_bytes
//! into grin's C bulletproof verifier through an unsafe FFI boundary. Both
//! arguments are fully attacker-controllable on the wire.
//!
//! Invariant under test: verifying ARBITRARY input must NEVER panic. The only
//! acceptable outcomes are Ok(false), Ok(true), or Err(_) (including the
//! >MAX_PROOF_SIZE rejection and any FFI-side rejection). A panic, abort, or
//! memory fault here is a consensus-reachable crash and a release blocker.

use libfuzzer_sys::fuzz_target;
use dom_crypto::bp2_verify;

fuzz_target!(|data: &[u8]| {
    // Need at least the 33-byte SEC1 commitment; remainder is the proof.
    if data.len() < 33 {
        return;
    }
    let (commitment_slice, proof_bytes) = data.split_at(33);
    let commitment: &[u8; 33] = commitment_slice
        .try_into()
        .expect("split_at(33) guarantees exactly 33 bytes");
    // proof_bytes is unbounded: exercises both the MAX_PROOF_SIZE (768) cap
    // branch and, for 1..=768-byte inputs, the unsafe FFI path.
    let _ = bp2_verify(commitment, proof_bytes);
});

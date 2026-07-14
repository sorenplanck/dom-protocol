#![no_main]
//! Fuzz target (DoS / amplification): final RangeProof size-cap enforcement.
//!
//! The final range-proof API accepts exactly 739-byte proofs, while consensus
//! serialization caps the proof field at `dom_core::MAX_PROOF_SIZE`. The
//! amplification risk: if either gate regressed, an attacker could submit a
//! multi-megabyte "proof" and force unbounded work / allocation inside the C
//! verifier.
//!
//! This target asserts the cap is honored as an INVARIANT, not merely "no panic".
//! RangeProof::from_bytes MUST return Err for any input that is not exactly 739
//! bytes, and range_proof_verify MUST return Err for oversized proof bytes,
//! rejecting on the length gate before the FFI. A violation (Ok on an
//! oversized input) trips the assert -> fuzzer crash = finding. Inputs within the
//! cap are exercised for the no-panic invariant only.
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{range_proof_verify, RangeProof, RANGE_PROOF_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parse = RangeProof::from_bytes(data.to_vec());
    if data.len() != RANGE_PROOF_SIZE {
        assert!(
            parse.is_err(),
            "AMPLIFICATION: RangeProof::from_bytes accepted {} bytes, expected {}",
            data.len(),
            RANGE_PROOF_SIZE
        );
    }

    // Verify path against a valid, deterministic commitment. The length gate must
    // reject oversized proof bytes before reaching the FFI verifier.
    let bf = BlindingFactor::from_bytes([1u8; 32]).expect("static non-zero blinding");
    let commitment = *Commitment::commit(0, &bf).as_bytes();
    let verdict = range_proof_verify(&commitment, data);
    if data.len() > dom_core::MAX_PROOF_SIZE {
        assert!(
            verdict.is_err(),
            "AMPLIFICATION: range_proof_verify did not reject {} bytes > cap {} on the \
             length gate (would hand oversized bytes to the FFI verifier)",
            data.len(),
            dom_core::MAX_PROOF_SIZE
        );
    }
});

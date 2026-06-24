#![no_main]
//! Fuzz target (DoS / amplification): borromean RangeProof size-cap enforcement.
//!
//! bulletproof.rs caps proof bytes at LEGACY_BORROMEAN_MAX_PROOF_SIZE (6144) in
//! BOTH RangeProof::from_bytes (line 129) and verify (line 268) BEFORE handing
//! the bytes to the libsecp256k1-zkp FFI. The amplification risk: if either gate
//! regressed, an attacker could submit a multi-megabyte "proof" and force
//! unbounded work / allocation inside the C verifier (a single small wire field
//! expanding into large CPU/memory — classic amplification).
//!
//! This target asserts the cap is honored as an INVARIANT, not merely "no panic".
//! RangeProof::from_bytes MUST return Err for any input > 6144 bytes, and
//! bp_verify MUST return Err (never Ok / never long work) for oversized proof
//! bytes, rejecting on the length gate before the FFI. A violation (Ok on an
//! oversized input) trips the assert -> fuzzer crash = finding. Inputs within the
//! cap are exercised for the no-panic invariant only.
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{bp_verify, RangeProof};
use libfuzzer_sys::fuzz_target;

const LEGACY_BORROMEAN_MAX_PROOF_SIZE: usize = 6_144;

fuzz_target!(|data: &[u8]| {
    let parse = RangeProof::from_bytes(data.to_vec());
    if data.len() > LEGACY_BORROMEAN_MAX_PROOF_SIZE {
        assert!(
            parse.is_err(),
            "AMPLIFICATION: RangeProof::from_bytes accepted {} bytes > cap {}",
            data.len(),
            LEGACY_BORROMEAN_MAX_PROOF_SIZE
        );
    }

    // Verify path against a valid, deterministic commitment. The length gate must
    // reject oversized proof bytes before reaching the FFI verifier.
    let bf = BlindingFactor::from_bytes([1u8; 32]).expect("static non-zero blinding");
    let commitment = *Commitment::commit(0, &bf).as_bytes();
    let verdict = bp_verify(&commitment, data);
    if data.len() > LEGACY_BORROMEAN_MAX_PROOF_SIZE {
        assert!(
            verdict.is_err(),
            "AMPLIFICATION: bp_verify did not reject {} bytes > cap {} on the \
             length gate (would hand oversized bytes to the FFI verifier)",
            data.len(),
            LEGACY_BORROMEAN_MAX_PROOF_SIZE
        );
    }
});

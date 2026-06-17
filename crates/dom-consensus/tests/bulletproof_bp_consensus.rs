//! Phase 2 sub-step 1: prove the standard-Bulletproof shim (`bp2_prove`/
//! `bp2_verify`, grin backend) is callable and correct at the CONSENSUS level,
//! in parallel to the borromean path. Nothing here rewires consensus: it builds
//! real `TransactionOutput`s with `bp2_prove` and runs them through a validator
//! shaped exactly like `dom_consensus::validate_range_proofs`, but using
//! `bp2_verify` instead of the borromean `bp_verify`.

use dom_consensus::TransactionOutput;
use dom_core::DomError;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{bp2_prove, bp2_verify};

/// Mirror of `dom_consensus::transaction::validate_range_proofs`, but verifying
/// with the standard-Bulletproof `bp2_verify`. Same control-flow shape: iterate
/// outputs, verify each proof against its commitment, map results to DomError.
fn validate_range_proofs_bp2(outputs: &[TransactionOutput]) -> Result<(), DomError> {
    for (i, output) in outputs.iter().enumerate() {
        match bp2_verify(output.commitment.as_bytes(), &output.proof) {
            Ok(true) => {}
            Ok(false) => {
                return Err(DomError::Invalid(format!(
                    "output {i} range proof verification failed"
                )));
            }
            Err(e) => {
                return Err(DomError::Invalid(format!("output {i} range proof error: {e}")));
            }
        }
    }
    Ok(())
}

/// Build a real TransactionOutput using the NEW standard-Bulletproof prover.
fn make_output(value: u64, blinding: &BlindingFactor) -> TransactionOutput {
    let (proof, commitment_sec1) = bp2_prove(value, blinding).expect("bp2_prove");
    let commitment = Commitment::from_compressed_bytes(&commitment_sec1).expect("commitment parse");
    TransactionOutput { commitment, proof }
}

#[test]
fn bp2_outputs_validate_at_consensus_shape() {
    let outputs: Vec<TransactionOutput> = [1u64, 42, 1_000_000, (1u64 << 52) - 1]
        .iter()
        .enumerate()
        .map(|(i, &v)| make_output(v, &BlindingFactor::from_bytes([(i as u8) + 1; 32]).unwrap()))
        .collect();

    // Every output is a real 675-byte standard Bulletproof.
    for o in &outputs {
        assert_eq!(o.proof.len(), 675, "expected a 675-byte standard Bulletproof");
    }

    // Validates through the consensus-shaped range-proof check.
    validate_range_proofs_bp2(&outputs).expect("valid bp2 outputs must pass consensus-shape validation");
}

#[test]
fn bp2_tampered_proof_rejected() {
    let blinding = BlindingFactor::from_bytes([7u8; 32]).unwrap();
    let mut output = make_output(1_000_000, &blinding);

    // Sanity: untampered validates.
    validate_range_proofs_bp2(std::slice::from_ref(&output)).expect("untampered must pass");

    // Flip a byte in the proof → must be rejected.
    let mid = output.proof.len() / 2;
    output.proof[mid] ^= 0x01;
    let err = validate_range_proofs_bp2(std::slice::from_ref(&output));
    assert!(err.is_err(), "tampered range proof must be rejected");
}

#[test]
fn bp2_wrong_commitment_rejected() {
    let blinding = BlindingFactor::from_bytes([8u8; 32]).unwrap();
    let good = make_output(500_000, &blinding);

    // Swap in a commitment for a DIFFERENT value while keeping the same proof.
    let other = make_output(999_999, &BlindingFactor::from_bytes([9u8; 32]).unwrap());
    let mismatched = TransactionOutput {
        commitment: other.commitment,
        proof: good.proof.clone(),
    };

    let err = validate_range_proofs_bp2(std::slice::from_ref(&mismatched));
    assert!(err.is_err(), "proof must not verify against a different commitment");
}

#[test]
fn bp2_proof_is_distinct_from_borromean_path() {
    // Demonstrate the two paths are genuinely separate: a grin standard-Bulletproof
    // (675 bytes) is NOT accepted by the borromean verifier the live consensus
    // path uses (`dom_crypto::bp_verify`). This is why bp2 must be validated via
    // bp2_verify, and confirms the borromean path is untouched/independent.
    let blinding = BlindingFactor::from_bytes([5u8; 32]).unwrap();
    let output = make_output(42, &blinding);

    let borromean_accepts = matches!(
        dom_crypto::bp_verify(output.commitment.as_bytes(), &output.proof),
        Ok(true)
    );
    assert!(
        !borromean_accepts,
        "a standard Bulletproof must NOT verify under the borromean bp_verify"
    );
}

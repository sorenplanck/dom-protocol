//! Phase 2 sub-step 1: prove the standard-Bulletproof shim (`bp2_prove`/
//! `bp2_verify`, grin backend) is callable and correct at the CONSENSUS level.

use dom_consensus::{validate_range_proofs, Transaction, TransactionOutput, TransactionKernel};
use dom_core::DomError;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{bp2_prove, bp2_test_only_prove_legacy_single_with_nonce, bp2_verify};

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
                return Err(DomError::Invalid(format!(
                    "output {i} range proof error: {e}"
                )));
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

    // Every output is a real 739-byte bounded aggregate Bulletproof.
    for o in &outputs {
        assert_eq!(
            o.proof.len(),
            739,
            "expected a 739-byte bounded aggregate Bulletproof"
        );
    }

    // Validates through the consensus-shaped range-proof check.
    validate_range_proofs_bp2(&outputs)
        .expect("valid bp2 outputs must pass consensus-shape validation");
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
    assert!(
        err.is_err(),
        "proof must not verify against a different commitment"
    );
}

#[test]
fn bp2_proof_is_distinct_from_borromean_path() {
    // Demonstrate the two paths are genuinely separate: a grin standard-Bulletproof
    // (739 bytes) is NOT accepted by the borromean verifier the legacy API name
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

/// Sub-step 6: the MAX_PROOF_SIZE serialization envelope is sized to the
/// Bulletproof format. A real bp2 proof is exactly 739 bytes (pinned), a valid
/// output round-trips through (de)serialization, and a proof exceeding
/// MAX_PROOF_SIZE is rejected by the deserializer BEFORE allocation.
#[test]
fn bp2_proof_size_and_serialization_envelope() {
    use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};

    // (1) bp2 proof is exactly 739 bytes (pinned — catches any future size drift),
    //     comfortably within the 700-byte envelope.
    let blinding = BlindingFactor::from_bytes([4u8; 32]).unwrap();
    let valid = make_output(1_000, &blinding);
    assert_eq!(
        valid.proof.len(),
        739,
        "bp2 proof must be exactly 739 bytes"
    );
    assert!(valid.proof.len() <= dom_core::MAX_PROOF_SIZE);
    assert_eq!(dom_core::MAX_PROOF_SIZE, 768, "Bulletproof envelope");

    // (2) A valid output round-trips through serialization and re-validates.
    let mut w = Writer::new();
    valid.serialize(&mut w).expect("serialize");
    let bytes = w.finish();
    let mut r = Reader::new(&bytes);
    let decoded = TransactionOutput::deserialize(&mut r).expect("deserialize valid output");
    assert_eq!(decoded.proof.len(), 739);
    validate_range_proofs_bp2(std::slice::from_ref(&decoded)).expect("decoded output validates");

    // (3) A proof exceeding MAX_PROOF_SIZE is rejected by the deserializer BEFORE
    //     allocating it (read_vec checks the declared length against the cap first).
    let oversized = TransactionOutput {
        commitment: valid.commitment.clone(),
        proof: vec![0u8; dom_core::MAX_PROOF_SIZE + 1],
    };
    let mut w2 = Writer::new();
    oversized.serialize(&mut w2).expect("serialize oversized");
    let bytes2 = w2.finish();
    let mut r2 = Reader::new(&bytes2);
    assert!(
        TransactionOutput::deserialize(&mut r2).is_err(),
        "a proof above MAX_PROOF_SIZE must be rejected at deserialize, before allocation"
    );
}

#[test]
fn legacy_over_cap_bp2_proof_is_rejected_by_live_consensus() {
    let blinding = BlindingFactor::from_bytes([0x33; 32]).unwrap();
    let nonce = [0x99; 32];
    let over_cap = dom_crypto::bulletproof::MAX_PROVABLE_VALUE + 1;
    let (proof, commitment_sec1) =
        bp2_test_only_prove_legacy_single_with_nonce(over_cap, &blinding, &nonce)
            .expect("legacy unsafe proof");
    assert_eq!(proof.len(), 675, "legacy unsafe proof must stay 675 bytes");
    let commitment = Commitment::from_compressed_bytes(&commitment_sec1).expect("commitment");
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput { commitment, proof }],
        kernels: vec![TransactionKernel {
            features: dom_core::KERNEL_FEAT_PLAIN,
            fee: dom_core::Amount::from_noms(1).unwrap(),
            lock_height: 0,
            excess: make_output(1, &BlindingFactor::from_bytes([0x11; 32]).unwrap()).commitment,
            excess_signature: [0u8; 65],
        }],
        offset: [0u8; 32],
    };
    let err = validate_range_proofs(&tx).expect_err("legacy over-cap proof must reject");
    assert!(
        err.to_string().contains("range proof"),
        "unexpected error: {err}"
    );
}

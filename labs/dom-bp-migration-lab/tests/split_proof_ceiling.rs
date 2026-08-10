use dom_bp_migration_lab::{
    protocol::MAX_PROVABLE_VALUE,
    split_proof_candidate::{
        prove_split_output, recover_split_output, verify_split_components_for_test,
        verify_split_output, CanonicalMetadata, LabError, SPLIT_PROOF_ENVELOPE_LEN,
    },
    CurrentOracle, Operation, OracleCase, ProveResult,
};
use dom_crypto::BlindingFactor;

fn blind(byte: u8) -> BlindingFactor {
    BlindingFactor::from_bytes([byte; 32]).expect("nonzero blind")
}
fn nonce(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn split_candidate_matches_l0_at_mandatory_ceiling_values() {
    let oracle = CurrentOracle;
    for (index, value) in [
        0,
        1,
        1_u64 << 51,
        MAX_PROVABLE_VALUE - 1,
        MAX_PROVABLE_VALUE,
    ]
    .into_iter()
    .enumerate()
    {
        let bf = blind((index + 1) as u8);
        let metadata =
            CanonicalMetadata::new(index as u32, 1, index as u32 + 100).expect("metadata");
        let (commitment, envelope) =
            prove_split_output(value, &bf, &nonce((index + 10) as u8), metadata.clone())
                .expect("split prove");
        assert_eq!(envelope.len(), SPLIT_PROOF_ENVELOPE_LEN);
        assert!(
            verify_split_output(&commitment, &envelope).expect("split verify"),
            "value={value}, components={:?}",
            verify_split_components_for_test(&commitment, &envelope)
        );
        let recovered = recover_split_output(&commitment, &envelope, &nonce((index + 10) as u8))
            .expect("recover")
            .expect("recovered");
        assert_eq!(recovered.value, value);
        assert_eq!(recovered.blinding.as_bytes(), bf.as_bytes());
        assert_eq!(recovered.metadata.as_bytes(), metadata.as_bytes());
        let current = oracle.prove_verify(&OracleCase {
            schema_version: 1,
            case_id: format!("l2d-{index}"),
            operation: Operation::ProveVerify,
            value,
            blind_hex: hex::encode(bf.as_bytes()),
        });
        assert_eq!(current.prove_result, ProveResult::Accepted);
    }
}

#[test]
fn split_candidate_rejects_all_mandatory_over_ceiling_values() {
    let oracle = CurrentOracle;
    for (index, value) in [
        MAX_PROVABLE_VALUE + 1,
        MAX_PROVABLE_VALUE + 2,
        (1_u64 << 53) - 1,
        1_u64 << 53,
        u64::MAX - 1,
        u64::MAX,
    ]
    .into_iter()
    .enumerate()
    {
        let bf = blind((index + 1) as u8);
        assert_eq!(
            prove_split_output(
                value,
                &bf,
                &nonce(77),
                CanonicalMetadata::new(1, 0, 1).expect("metadata")
            ),
            Err(LabError::ValueAboveMaximum)
        );
        let current = oracle.prove_verify(&OracleCase {
            schema_version: 1,
            case_id: format!("reject-{index}"),
            operation: Operation::ProveVerify,
            value,
            blind_hex: hex::encode(bf.as_bytes()),
        });
        assert_ne!(current.prove_result, ProveResult::Accepted);
    }
}

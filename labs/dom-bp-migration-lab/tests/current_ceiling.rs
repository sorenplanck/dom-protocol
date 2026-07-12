use dom_bp_migration_lab::{
    corpus::{deterministic_blind, ACCEPTED_VALUES, REJECTED_VALUES},
    CurrentOracle, Operation, OracleCase, ProveResult, VerifyResult,
};

fn case(id: &str, value: u64, blind: [u8; 32]) -> OracleCase {
    OracleCase {
        schema_version: 1,
        case_id: id.to_owned(),
        operation: Operation::ProveVerify,
        value,
        blind_hex: hex::encode(blind),
    }
}

#[test]
fn accepted_values_produce_739_byte_valid_proofs() {
    let oracle = CurrentOracle;
    for (index, value) in ACCEPTED_VALUES.into_iter().enumerate() {
        let verdict =
            oracle.prove_verify(&case("accepted", value, deterministic_blind(index as u64)));
        assert_eq!(verdict.prove_result, ProveResult::Accepted, "value={value}");
        assert_eq!(verdict.verify_result, VerifyResult::True, "value={value}");
        assert_eq!(verdict.proof_len, Some(739), "value={value}");
    }
}

#[test]
fn above_ceiling_values_are_rejected_by_the_prover() {
    let oracle = CurrentOracle;
    for (index, value) in REJECTED_VALUES.into_iter().enumerate() {
        let verdict =
            oracle.prove_verify(&case("rejected", value, deterministic_blind(index as u64)));
        assert_eq!(verdict.prove_result, ProveResult::Rejected, "value={value}");
        assert_eq!(
            verdict.verify_result,
            VerifyResult::Malformed,
            "value={value}"
        );
        assert!(!verdict.verify_attempted, "value={value}");
        assert_eq!(
            verdict.error_class,
            Some("value_above_max"),
            "value={value}"
        );
    }
}

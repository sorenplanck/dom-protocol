use dom_bp_migration_lab::{
    corpus::{deterministic_blind, property_values, PROPERTY_CASES, PROPERTY_SEED},
    CurrentOracle, Operation, OracleCase, ProveResult, VerifyResult,
};

#[test]
fn seeded_current_ceiling_property_10k_cases() {
    let oracle = CurrentOracle;
    let values = property_values();
    assert_eq!(values.len(), PROPERTY_CASES);
    for (index, value) in values.into_iter().enumerate() {
        let case = OracleCase {
            schema_version: 1,
            case_id: format!("seed-{PROPERTY_SEED:016x}-{index}"),
            operation: Operation::ProveVerify,
            value,
            blind_hex: hex::encode(deterministic_blind(index as u64)),
        };
        let verdict = oracle.prove_verify(&case);
        let expected = value <= dom_bp_migration_lab::protocol::MAX_PROVABLE_VALUE;
        assert_eq!(
            verdict.prove_result == ProveResult::Accepted,
            expected,
            "seed={PROPERTY_SEED:#x} index={index} value={value} verdict={verdict:?}"
        );
        if expected {
            assert_eq!(verdict.proof_len, Some(739));
            assert_eq!(verdict.verify_result, VerifyResult::True);
        } else {
            assert_ne!(verdict.verify_result, VerifyResult::True);
        }
    }
}

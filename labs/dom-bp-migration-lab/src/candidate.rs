//! Fail-closed extension point for future, separately reviewed candidates.

use crate::protocol::{OracleCase, OracleResponse, ProveResult, VerifyResult};

pub trait CandidateOracle {
    fn name(&self) -> &'static str;
    fn prove_verify(&self, case: &OracleCase) -> OracleResponse;
    fn supports_rewind(&self) -> bool;
}

#[derive(Debug, Default)]
pub struct UnavailableCandidate;

impl CandidateOracle for UnavailableCandidate {
    fn name(&self) -> &'static str {
        "candidate_not_implemented"
    }

    fn prove_verify(&self, case: &OracleCase) -> OracleResponse {
        let mut response = OracleResponse::new(case.case_id.clone());
        response.prove_result = ProveResult::Error;
        response.verify_result = VerifyResult::Malformed;
        response.error_class = Some("candidate_not_implemented");
        response
    }

    fn supports_rewind(&self) -> bool {
        false
    }
}

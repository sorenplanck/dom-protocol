//! Versioned JSON Lines protocol for the isolated oracle process.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const BACKEND: &str = "dom-current-classic-bulletproof";
pub const BACKEND_VERSION: &str = "grin_secp256k1zkp-0.7.15";
pub const MAX_PROVABLE_VALUE: u64 = (1_u64 << 52) - 1;
pub const PROOF_NBITS: u8 = 64;
pub const PROOF_NCOMMITS: u8 = 2;
pub const CURRENT_PROOF_LEN: usize = 739;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ProveVerify,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OracleCase {
    pub schema_version: u32,
    pub case_id: String,
    pub operation: Operation,
    pub value: u64,
    pub blind_hex: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProveResult {
    Accepted,
    Rejected,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyResult {
    True,
    False,
    Malformed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OracleResponse {
    pub schema_version: u32,
    pub case_id: String,
    pub backend: &'static str,
    pub backend_version: &'static str,
    pub max_provable_value: u64,
    pub proof_nbits: u8,
    pub proof_ncommits: u8,
    pub expected_proof_len: usize,
    pub prove_result: ProveResult,
    pub verify_result: VerifyResult,
    pub verify_attempted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<&'static str>,
}

impl OracleResponse {
    pub fn new(case_id: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            case_id,
            backend: BACKEND,
            backend_version: BACKEND_VERSION,
            max_provable_value: MAX_PROVABLE_VALUE,
            proof_nbits: PROOF_NBITS,
            proof_ncommits: PROOF_NCOMMITS,
            expected_proof_len: CURRENT_PROOF_LEN,
            prove_result: ProveResult::Error,
            verify_result: VerifyResult::Malformed,
            verify_attempted: false,
            proof_len: None,
            error_class: None,
        }
    }

    pub fn malformed_input() -> Self {
        let mut response = Self::new("malformed-input".to_owned());
        response.error_class = Some("malformed_request");
        response
    }
}

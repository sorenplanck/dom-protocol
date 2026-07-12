//! Isolated, non-production oracle for the current DOM classic Bulletproof.

pub mod candidate;
pub mod corpus;
pub mod current_oracle;
pub mod protocol;

pub use current_oracle::CurrentOracle;
pub use protocol::{Operation, OracleCase, OracleResponse, ProveResult, VerifyResult};

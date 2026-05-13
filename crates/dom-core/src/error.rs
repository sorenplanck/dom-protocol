//! Consensus error taxonomy — DOM_v6_1_Error_Taxonomy_RFC.md

use thiserror::Error;

/// Top-level DOM protocol error.
///
/// Error classes determine peer ban scoring and retry behavior.
/// Only `Malformed` and repeated `Invalid` increase ban score.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomError {
    /// Invalid serialization — peer sent a malformed message.
    /// Increases ban score.
    #[error("Malformed: {0}")]
    Malformed(String),

    /// Permanently consensus-invalid object.
    /// Increases ban score on repeated submission.
    #[error("Invalid: {0}")]
    Invalid(String),

    /// Temporarily invalid — future timestamp or missing dependency.
    /// Do NOT ban; retry after delay.
    #[error("TemporarilyInvalid: {0}")]
    TemporarilyInvalid(String),

    /// Unknown parent block — orphan.
    /// Request parent before processing.
    #[error("Orphan: unknown parent {0}")]
    Orphan(String),

    /// Rejected by local relay policy only.
    /// MUST NOT affect consensus validity.
    #[error("PolicyRejected: {0}")]
    PolicyRejected(String),

    /// Internal implementation error (not a peer error).
    #[error("Internal: {0}")]
    Internal(String),
}

impl DomError {
    /// Returns true if this error should increase the peer's ban score.
    pub fn increases_ban_score(&self) -> bool {
        matches!(self, DomError::Malformed(_) | DomError::Invalid(_))
    }

    /// Returns true if the object may become valid later.
    pub fn is_retryable(&self) -> bool {
        matches!(self, DomError::TemporarilyInvalid(_) | DomError::Orphan(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_increases_ban_score() {
        let e = DomError::Malformed("trailing bytes".into());
        assert!(e.increases_ban_score());
        assert!(!e.is_retryable());
    }

    #[test]
    fn temporarily_invalid_does_not_ban() {
        let e = DomError::TemporarilyInvalid("future timestamp".into());
        assert!(!e.increases_ban_score());
        assert!(e.is_retryable());
    }

    #[test]
    fn policy_rejected_does_not_ban() {
        let e = DomError::PolicyRejected("below min fee rate".into());
        assert!(!e.increases_ban_score());
    }
}

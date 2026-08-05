//! Error taxonomy for fail-closed Scriptless parsing and verification.

use thiserror::Error;

/// Result type used by `dom-adaptor`.
pub type Result<T> = core::result::Result<T, AdaptorError>;

/// Fail-closed errors returned by canonical G1a operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdaptorError {
    /// A fixed-size object did not have its exact canonical length.
    #[error("{object} must be exactly {expected} bytes, got {actual}")]
    InvalidLength {
        /// Name of the rejected object.
        object: &'static str,
        /// Required canonical length.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// A purpose byte is outside the closed G1a v1 registry.
    #[error("unknown G1a v1 purpose 0x{0:02x}")]
    UnknownPurpose(u8),
    /// Transcript fields violate a frozen structural invariant.
    #[error("invalid transcript: {0}")]
    InvalidTranscript(&'static str),
    /// An authoritative DOM cryptographic operation rejected the input.
    #[error("DOM cryptographic rejection: {0}")]
    Crypto(String),
    /// A cryptographic relation did not verify.
    #[error("cryptographic verification failed: {0}")]
    VerificationFailed(&'static str),
}

impl From<dom_core::DomError> for AdaptorError {
    fn from(value: dom_core::DomError) -> Self {
        Self::Crypto(value.to_string())
    }
}

pub(crate) fn exact_array<const N: usize>(object: &'static str, bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| AdaptorError::InvalidLength {
        object,
        expected: N,
        actual: bytes.len(),
    })
}

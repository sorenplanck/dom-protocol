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
    /// A purpose byte is outside the closed Scriptless v1 registry.
    #[error("unknown Scriptless v1 purpose 0x{0:02x}")]
    UnknownPurpose(u8),
    /// A direction byte is outside the ratified closed V1 registry.
    #[error("unknown Scriptless v1 direction 0x{0:02x}")]
    UnknownDirection(u8),
    /// A signing phase is outside the ratified closed V1 subregistry.
    #[error("unknown Scriptless v1 signing phase 0x{0:04x}")]
    UnknownSigningPhase(u16),
    /// A recognized codec purpose is not authorized by strict Phase 1 policy.
    #[error("Scriptless v1 purpose 0x{0:02x} is not authorized for strict Phase 1 execution")]
    PurposeNotAuthorized(u8),
    /// Transcript fields violate a frozen structural invariant.
    #[error("invalid transcript: {0}")]
    InvalidTranscript(&'static str),
    /// Canonical session context validation failed.
    #[error("invalid SessionContextV1: {0}")]
    InvalidContext(&'static str),
    /// The participant roster contains a duplicate key.
    #[error("invalid SessionContextV1: duplicate participant public key")]
    DuplicateParticipant,
    /// The participant roster is not strictly ascending bytewise.
    #[error("invalid SessionContextV1: participant roster is out of order")]
    ParticipantOrder,
    /// The operating-system CSPRNG failed.
    #[error("operating-system CSPRNG failed")]
    RandomnessFailure,
    /// The nonce retry counter overflowed before public export.
    #[error("secret nonce retry counter overflow")]
    RetryCounterOverflow,
    /// A durable authorization permit does not match the reserved nonce.
    #[error("durable signing authorization does not match the nonce reservation")]
    AuthorizationMismatch,
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

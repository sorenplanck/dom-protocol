//! Fail-closed backend errors (Annex M M.4.4).
//!
//! No variant carries a key, nonce, scalar, preimage, share,
//! `session_secrand` or an FFI-structure dump (M.21). Each names only the
//! *class* of failure.

/// Errors of the cryptographic backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcCryptoError {
    /// A 33-byte compressed point failed to parse on the curve.
    InvalidPoint,
    /// An x-only 32-byte key failed to parse.
    InvalidXOnlyKey,
    /// A secret scalar was not canonical/non-zero.
    NonCanonicalScalar,
    /// Key aggregation failed (e.g. aggregate is the identity point).
    KeyAggregationFailed,
    /// The TapTweak was ≥ n or produced the identity point — fail closed,
    /// never reduce (M.2.2 step 7).
    TapTweakRejected,
    /// Nonce generation failed.
    NonceGenerationFailed,
    /// Public-nonce (de)serialization failed.
    InvalidPublicNonce,
    /// Aggregate-nonce (de)serialization failed.
    InvalidAggregateNonce,
    /// `nonce_process` failed to build the session.
    SessionFailed,
    /// A partial signature failed `partial_verify` (M.6.7).
    InvalidPartialSignature,
    /// Partial (de)serialization failed.
    PartialSerializationFailed,
    /// Aggregating the partials into a (pre-)signature failed.
    PreSignatureAggregationFailed,
    /// The pre-signature verified as a final signature — an adaptor
    /// breach (M.11.3 rule 7).
    PreSignatureIsFinal,
    /// The adapted signature failed BIP340 verification.
    InvalidFinalSignature,
    /// Adapting the pre-signature failed.
    AdaptFailed,
    /// Extracting the adaptor secret failed.
    ExtractFailed,
    /// The extracted secret did not satisfy `t·G == T` (M.4.2 step 10).
    AdaptorPointMismatch,
    /// The session's nonce parity was outside {0,1}.
    NonceParityOutOfDomain,
}

impl core::fmt::Display for BtcCryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidPoint => "invalid compressed point",
            Self::InvalidXOnlyKey => "invalid x-only key",
            Self::NonCanonicalScalar => "non-canonical scalar",
            Self::KeyAggregationFailed => "key aggregation failed",
            Self::TapTweakRejected => "TapTweak rejected (>= n or infinity)",
            Self::NonceGenerationFailed => "nonce generation failed",
            Self::InvalidPublicNonce => "invalid public nonce",
            Self::InvalidAggregateNonce => "invalid aggregate nonce",
            Self::SessionFailed => "session build failed",
            Self::InvalidPartialSignature => "partial signature failed verification",
            Self::PartialSerializationFailed => "partial (de)serialization failed",
            Self::PreSignatureAggregationFailed => "pre-signature aggregation failed",
            Self::PreSignatureIsFinal => "pre-signature verified as final (adaptor breach)",
            Self::InvalidFinalSignature => "final signature failed BIP340 verification",
            Self::AdaptFailed => "adapt failed",
            Self::ExtractFailed => "extract failed",
            Self::AdaptorPointMismatch => "extracted secret does not satisfy t*G == T",
            Self::NonceParityOutOfDomain => "nonce parity out of domain",
        })
    }
}

impl std::error::Error for BtcCryptoError {}

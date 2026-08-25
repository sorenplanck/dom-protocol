//! Fail-closed error taxonomy of the Bitcoin leg (M.4.4, M.12.3).
//!
//! No variant ever carries a key, nonce, scalar, preimage, share,
//! `session_secrand` or a dump of an FFI structure — errors describe the
//! *class* of failure, never the bytes that produced it (M.21).

/// Scalar-domain failures (M.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScalarError {
    /// The bytes do not encode a canonical scalar in `1..n-1`.
    #[error("non-canonical scalar")]
    NonCanonicalScalar,
}

/// Canonical DOMBTC wire failures (M.5.3).
///
/// Positions are byte offsets into the *input*, safe to log: they never
/// reveal content, only structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// Input does not start with the ASCII magic `DOMBTC`.
    #[error("bad magic")]
    BadMagic,
    /// Wire version is not the frozen version of this codec.
    #[error("unsupported wire version")]
    UnsupportedVersion,
    /// The kind field does not match the type being decoded.
    #[error("kind mismatch")]
    KindMismatch,
    /// Input ended before the fixed-width field at this offset.
    #[error("truncated at byte {0}")]
    Truncated(usize),
    /// Bytes remained after the last field — canonical encodings have
    /// exactly one length (P3).
    #[error("trailing bytes after byte {0}")]
    TrailingBytes(usize),
    /// Input exceeds the per-type maximum length; rejected before any
    /// allocation or parse (M.5.3).
    #[error("input exceeds MAX_ENCODED_LEN")]
    OverCap,
    /// An enum discriminant holds a value outside the frozen registry.
    #[error("unknown discriminant for {field}")]
    UnknownDiscriminant {
        /// Name of the offending field (static, never input bytes).
        field: &'static str,
    },
    /// A field failed its domain validation (prefix, range, zero check).
    #[error("invalid field {field}")]
    InvalidField {
        /// Name of the offending field (static, never input bytes).
        field: &'static str,
    },
    /// The embedded digest does not match the recomputed digest — the
    /// artifact was tampered with or assembled inconsistently.
    #[error("digest mismatch")]
    DigestMismatch,
    /// The structure violates a roster rule (M.1.3).
    #[error(transparent)]
    Roster(#[from] RosterError),
}

/// Taproot construction failures (M.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TaprootError {
    /// The CSV delay could not be encoded (disable flag).
    #[error("invalid timelock")]
    InvalidTimelock,
    /// The roster is invalid (M.1.3).
    #[error(transparent)]
    Roster(#[from] RosterError),
    /// BIP327 key aggregation failed (e.g. aggregate is the identity).
    #[error("key aggregation failed")]
    KeyAggregationFailed,
    /// The TapTweak was ≥ n or produced the identity point — fail closed,
    /// never reduce (M.2.2 step 7).
    #[error("TapTweak rejected")]
    TapTweakRejected,
}

/// Roster violations (M.1.3): rejected at the protocol level even when a
/// generic library would accept them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RosterError {
    /// The roster version is not the frozen version.
    #[error("unsupported roster version")]
    UnsupportedVersion,
    /// Two participants share the same id.
    #[error("duplicate participant id")]
    DuplicateParticipantId,
    /// Two participants share the same role.
    #[error("duplicate role")]
    DuplicateRole,
    /// Two participants share the same public key.
    #[error("duplicate key")]
    DuplicateKey,
    /// A compressed key does not carry a valid SEC1 prefix (0x02/0x03).
    #[error("malformed compressed key")]
    MalformedKey,
}

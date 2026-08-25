//! Durable reservation states and artifact descriptors (Annex M M.6.3).

/// The durable lifecycle of a reservation (M.6.3). No terminal state ever
/// returns to a live state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinNonceStateV1 {
    /// Reserved but not yet consumed.
    Reserved = 0,
    /// The one-shot consumption is durably committed.
    ConsumptionCommitted = 1,
    /// The public nonce bytes are durably committed (not yet exposed).
    PublicArtifactCommitted = 2,
    /// The public nonce has been exposed (its bytes may leave).
    PublicArtifactExposed = 3,
    /// The partial signature is durably committed.
    PartialArtifactCommitted = 4,
    /// Terminal: the reservation completed.
    Spent = 5,
    /// Terminal: the reservation was aborted (crash, refund, cancel).
    Aborted = 6,
    /// Terminal: a divergent identity was detected.
    Equivocated = 7,
}

impl BitcoinNonceStateV1 {
    /// Decodes the stored discriminant.
    pub(crate) fn from_i64(value: i64) -> Option<Self> {
        Some(match value {
            0 => Self::Reserved,
            1 => Self::ConsumptionCommitted,
            2 => Self::PublicArtifactCommitted,
            3 => Self::PublicArtifactExposed,
            4 => Self::PartialArtifactCommitted,
            5 => Self::Spent,
            6 => Self::Aborted,
            7 => Self::Equivocated,
            _ => return None,
        })
    }

    /// True for the three terminal states.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Spent | Self::Aborted | Self::Equivocated)
    }
}

/// The artifact kinds a reservation persists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ArtifactKind {
    PublicNonce = 1,
    PartialSignature = 2,
}

/// A durable descriptor of a persisted artifact (M.6.4). Returned by the
/// persist calls; the bytes are only released through
/// [`crate::BitcoinNonceVault::expose`] / `resend`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PersistedArtifactDescriptorV1 {
    /// The reservation this artifact belongs to.
    pub reservation_id: [u8; 32],
    /// The artifact kind discriminant (1 = public nonce, 2 = partial).
    pub artifact_kind: u8,
    /// Digest over the persisted bytes and the binding.
    pub outbound_digest: [u8; 32],
    /// Length of the persisted bytes.
    pub byte_length: u32,
}

/// Public abort reasons (never carry secret material — M.21).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PublicAbortReasonV1 {
    /// Legacy F5 crash recovery, or authenticated F7 owner corruption,
    /// selected the pre-armed refund path.
    CrashRefund = 1,
    /// The template or session changed; a new session/attempt is required.
    TemplateChanged = 2,
    /// Operator or protocol cancellation.
    Cancelled = 3,
    /// A divergent binding was detected for this reservation.
    Equivocation = 4,
}

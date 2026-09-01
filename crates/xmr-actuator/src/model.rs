//! Durable operation model for the Monero face.
//!
//! Mirrors `solana-actuator`'s discipline with the differences Monero
//! forces: the funding side is external custody (the counterparty places
//! the shared output), a signed sweep stays cryptographically valid
//! indefinitely, and the only local absence statement available is the
//! sweep's own key image being unspent at the daemon quorum — a
//! point-in-time proof, adjudicated in
//! `docs/interop/engine/CHILD_SOCKETS_DESIGN.md` §5, never a permanent
//! one like Solana's blockhash expiry.

/// 32-byte commitment.
pub type Digest32 = [u8; 32];

/// Economic operation one durable row represents. Funding has no row: the
/// XMR funder externalizes it outside this authority's custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum XmrOperationKindV1 {
    /// Sweep of the shared output to the recipient's destination.
    Claim,
    /// Sweep of the shared output to the refund destination.
    Refund,
}

impl XmrOperationKindV1 {
    /// Frozen wire tag; part of every durable identity.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Claim => 1,
            Self::Refund => 2,
        }
    }

    /// Decode a frozen tag.
    pub fn from_tag(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Claim),
            2 => Some(Self::Refund),
            _ => None,
        }
    }
}

/// Stage of one durable operation. Transitions are one-way except the
/// explicit finality invalidation, which never rolls anything back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmrTxStageV1 {
    /// Exact signed sweep bytes are durable; nothing offered to a daemon.
    Signed,
    /// At least one submission may have reached a daemon.
    SendAttempted,
    /// The exact txid was seen below the required confirmation depth.
    Observed,
    /// The exact txid reached the profile's confirmation depth.
    Final,
    /// A takeover reconciliation outcome was durably recorded.
    Reconciled,
    /// A formerly final transaction is no longer canonical.
    FinalityInvalidated,
}

impl XmrTxStageV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Signed => 1,
            Self::SendAttempted => 2,
            Self::Observed => 3,
            Self::Final => 4,
            Self::Reconciled => 5,
            Self::FinalityInvalidated => 6,
        }
    }

    pub(crate) fn from_tag(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Signed),
            2 => Some(Self::SendAttempted),
            3 => Some(Self::Observed),
            4 => Some(Self::Final),
            5 => Some(Self::Reconciled),
            6 => Some(Self::FinalityInvalidated),
            _ => None,
        }
    }
}

/// Outcome kind durably recorded by a takeover reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XmrReconciliationKindV1 {
    /// The txid is absent at the quorum and the sweep's own key image is
    /// unspent: nothing has crossed the boundary as of this observation.
    /// Point-in-time by nature — the retained bytes stay valid.
    KeyImageUnspentAbsent,
    /// The exact txid was found below the confirmation depth.
    Observed,
    /// The exact txid was found at or beyond the confirmation depth.
    Final,
    /// Nothing conclusive: cannot authorize anything.
    Unknown,
}

/// Exact durable identity of one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct XmrOperationLocatorV1 {
    /// Settlement that owns the shared output.
    pub settlement_id: Digest32,
    /// Which economic operation.
    pub kind: XmrOperationKindV1,
}

/// Owner-scoped lease over one Monero network identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XmrActuatorLeaseV1 {
    pub(crate) authority_id: Digest32,
    pub(crate) owner_id: Digest32,
    pub(crate) network_id: Digest32,
    pub(crate) fencing_epoch: u64,
    pub(crate) lease_until_unix_ms: u64,
}

impl core::fmt::Debug for XmrActuatorLeaseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("XmrActuatorLeaseV1")
            .field("fencing_epoch", &self.fencing_epoch)
            .finish_non_exhaustive()
    }
}

impl XmrActuatorLeaseV1 {
    /// Mints a lease. Every identity field must be non-zero.
    pub fn new(
        authority_id: Digest32,
        owner_id: Digest32,
        network_id: Digest32,
        fencing_epoch: u64,
        lease_until_unix_ms: u64,
    ) -> Result<Self, XmrActuatorErrorV1> {
        if authority_id == [0; 32]
            || owner_id == [0; 32]
            || network_id == [0; 32]
            || fencing_epoch == 0
            || lease_until_unix_ms == 0
        {
            return Err(XmrActuatorErrorV1::InvalidLease);
        }
        Ok(Self {
            authority_id,
            owner_id,
            network_id,
            fencing_epoch,
            lease_until_unix_ms,
        })
    }

    /// Fence this lease writes under.
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }

    /// Monero network identity the lease is scoped to.
    pub const fn network_id(&self) -> Digest32 {
        self.network_id
    }

    pub(crate) const fn is_live_at(&self, now_unix_ms: u64) -> bool {
        now_unix_ms < self.lease_until_unix_ms
    }
}

/// Monotone finality facts, fixed once verified at the quorum depth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmrFinalityFactsV1 {
    /// Height the transaction was included at.
    pub final_height: u64,
    /// Canonical block hash of that height.
    pub final_block_hash: Digest32,
    /// Commitment over the verified inclusion evidence.
    pub final_evidence_digest: Digest32,
}

/// Read-only projection of one durable operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmrOperationViewV1 {
    /// Exact durable identity.
    pub locator: XmrOperationLocatorV1,
    /// Fence the row was last written under.
    pub fencing_epoch: u64,
    /// Monotone revision; every mutation increments it exactly once.
    pub revision: u64,
    /// Current stage.
    pub stage: XmrTxStageV1,
    /// Transaction hash of the retained exact bytes.
    pub tx_hash: Digest32,
    /// Sweep key image of the retained exact bytes.
    pub key_image: Digest32,
    /// Commitment to the retained exact signed bytes.
    pub custody_digest: Digest32,
    /// Present only from `Final` onward.
    pub finality: Option<XmrFinalityFactsV1>,
    /// Present only after a reconciliation recorded an outcome.
    pub reconciliation_kind: Option<XmrReconciliationKindV1>,
}

/// Actuator failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum XmrActuatorErrorV1 {
    /// A lease field is zero or otherwise cannot authorize anything.
    #[error("invalid XMR actuator lease")]
    InvalidLease,
    /// The lease is past its expiry at the supplied clock.
    #[error("XMR actuator lease expired")]
    LeaseExpired,
    /// The durable store refused an open, read or write.
    #[error("XMR actuator storage unavailable")]
    StorageUnavailable,
    /// Durable state violates an invariant that never self-heals.
    #[error("XMR actuator durable state is corrupt")]
    Corrupt,
    /// No durable row exists for the locator.
    #[error("XMR operation not found")]
    NotFound,
    /// The mutation contradicts durable facts or a newer fence.
    #[error("XMR operation state conflict")]
    Conflict,
    /// A caller-supplied field is out of its frozen bounds.
    #[error("invalid XMR operation input")]
    InvalidInput,
    /// The daemon/observation boundary could not produce an answer.
    #[error("XMR observation boundary unavailable")]
    ObservationUnavailable,
    /// The supplied clock reading is unusable.
    #[error("invalid XMR clock reading")]
    InvalidTime,
}

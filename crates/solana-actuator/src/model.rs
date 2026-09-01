//! Durable operation model for the Solana face.
//!
//! Mirrors the discipline of `evm-actuator`'s model, with the one structural
//! difference Solana forces: a legacy transaction is only valid while its
//! recent blockhash is inside the cluster's ~150-slot window. Expiry is not a
//! failure mode to paper over — it is the **positive proof** that bytes which
//! were sent can no longer land, and it is what turns an otherwise ambiguous
//! `SendAttempted` into `ProvenNotExternalized`. No other chain in this tree
//! offers that proof for free.

use solana_types::{SolanaHash, SolanaPubkey, SolanaSignature};

/// 32-byte commitment.
pub type Digest32 = [u8; 32];

/// Economic operation one durable row represents.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SolanaOperationKindV1 {
    /// Create the escrow state and vault PDAs.
    Initialize,
    /// Move the funder's amount into the vault.
    Fund,
    /// Release to the recipient against the revealed witness.
    Claim,
    /// Release to the refund recipient after the timelock.
    Refund,
    /// Reclaim rent after a terminal state.
    Close,
}

impl SolanaOperationKindV1 {
    /// Frozen wire tag; part of every durable identity.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Initialize => 1,
            Self::Fund => 2,
            Self::Claim => 3,
            Self::Refund => 4,
            Self::Close => 5,
        }
    }

    /// Decode a frozen tag.
    pub fn from_tag(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Initialize),
            2 => Some(Self::Fund),
            3 => Some(Self::Claim),
            4 => Some(Self::Refund),
            5 => Some(Self::Close),
            _ => None,
        }
    }

    /// Whether externalizing this operation publishes the route witness.
    ///
    /// Only the claim carries the revealed scalar in its instruction data;
    /// everything else is publicly derivable from the setup.
    pub const fn exposes_secret(self) -> bool {
        matches!(self, Self::Claim)
    }
}

/// Stage of one durable operation. Transitions are one-way except the
/// explicit finality invalidation, which never rolls back publicity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolanaTxStageV1 {
    /// Exact signed bytes are durable; nothing has been offered to a node.
    Signed,
    /// At least one send may have reached the cluster; absence is ambiguous
    /// while the blockhash is still valid.
    SendAttempted,
    /// The exact signature was seen at or above `Confirmed`.
    Observed,
    /// The exact signature is finalized under quorum evidence.
    Final,
    /// A takeover reconciliation outcome was durably recorded.
    Reconciled,
    /// A formerly final transaction is no longer canonical. Any witness
    /// already published stays published; this never un-exposes a secret.
    FinalityInvalidated,
}

impl SolanaTxStageV1 {
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
pub enum SolanaReconciliationKindV1 {
    /// The blockhash expired with the signature absent at the quorum: the
    /// exact bytes can never land, so nothing crossed the boundary.
    ExpiredNeverLanded,
    /// The exact signature was found, not yet finalized.
    Observed,
    /// The exact signature was found finalized.
    Final,
    /// Absence while the blockhash is still live: cannot authorize a retry.
    Unknown,
}

/// Exact durable identity of one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SolanaOperationLocatorV1 {
    /// Settlement that owns the escrow.
    pub settlement_id: Digest32,
    /// Which economic operation.
    pub kind: SolanaOperationKindV1,
}

/// Owner-scoped lease over one cluster identity and fee payer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SolanaActuatorLeaseV1 {
    pub(crate) authority_id: Digest32,
    pub(crate) owner_id: Digest32,
    pub(crate) genesis_hash: Digest32,
    pub(crate) fee_payer: SolanaPubkey,
    pub(crate) fencing_epoch: u64,
    pub(crate) lease_until_unix_ms: u64,
}

impl core::fmt::Debug for SolanaActuatorLeaseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SolanaActuatorLeaseV1")
            .field("fencing_epoch", &self.fencing_epoch)
            .finish_non_exhaustive()
    }
}

impl SolanaActuatorLeaseV1 {
    /// Mints a lease. Every identity field must be non-zero: a lease that
    /// cannot name its cluster or its payer authorizes nothing.
    pub fn new(
        authority_id: Digest32,
        owner_id: Digest32,
        genesis_hash: Digest32,
        fee_payer: SolanaPubkey,
        fencing_epoch: u64,
        lease_until_unix_ms: u64,
    ) -> Result<Self, SolanaActuatorErrorV1> {
        if authority_id == [0; 32]
            || owner_id == [0; 32]
            || genesis_hash == [0; 32]
            || fee_payer.is_zero()
            || fencing_epoch == 0
            || lease_until_unix_ms == 0
        {
            return Err(SolanaActuatorErrorV1::InvalidLease);
        }
        Ok(Self {
            authority_id,
            owner_id,
            genesis_hash,
            fee_payer,
            fencing_epoch,
            lease_until_unix_ms,
        })
    }

    /// Fence this lease writes under.
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }

    /// Cluster identity the lease is scoped to.
    pub const fn genesis_hash(&self) -> Digest32 {
        self.genesis_hash
    }

    /// Fee payer the lease authorizes.
    pub const fn fee_payer(&self) -> SolanaPubkey {
        self.fee_payer
    }

    pub(crate) const fn is_live_at(&self, now_unix_ms: u64) -> bool {
        now_unix_ms < self.lease_until_unix_ms
    }
}

/// Monotone finality facts. Absent until finality is verified under quorum,
/// fixed afterwards; a mutable confirmation counter is never a substitute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolanaFinalityFactsV1 {
    /// Slot the transaction finalized in.
    pub final_slot: u64,
    /// Canonical blockhash of that slot, agreed by the quorum.
    pub final_blockhash: SolanaHash,
    /// Quorum-agreed commitment over the finalized transaction record.
    pub final_evidence_digest: Digest32,
}

/// Read-only projection of one durable operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaOperationViewV1 {
    /// Exact durable identity.
    pub locator: SolanaOperationLocatorV1,
    /// Fence the row was last written under.
    pub fencing_epoch: u64,
    /// Monotone revision; every mutation increments it exactly once.
    pub revision: u64,
    /// Current stage.
    pub stage: SolanaTxStageV1,
    /// Primary signature of the retained exact bytes.
    pub signature: SolanaSignature,
    /// Commitment to the retained exact signed bytes.
    pub custody_digest: Digest32,
    /// Recent blockhash embedded in the retained bytes.
    pub recent_blockhash: SolanaHash,
    /// Last block height at which the retained bytes can still land.
    pub last_valid_block_height: u64,
    /// Whether externalization published the route witness.
    pub secret_exposed: bool,
    /// Present only from `Final` onward.
    pub finality: Option<SolanaFinalityFactsV1>,
    /// Present only in `Reconciled`.
    pub reconciliation_kind: Option<SolanaReconciliationKindV1>,
}

/// Actuator failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SolanaActuatorErrorV1 {
    /// A lease field is zero or otherwise cannot authorize anything.
    #[error("invalid Solana actuator lease")]
    InvalidLease,
    /// The lease is past its expiry at the supplied clock.
    #[error("Solana actuator lease expired")]
    LeaseExpired,
    /// The durable store refused an open, read or write.
    #[error("Solana actuator storage unavailable")]
    StorageUnavailable,
    /// Durable state violates an invariant that never self-heals.
    #[error("Solana actuator durable state is corrupt")]
    Corrupt,
    /// No durable row exists for the locator.
    #[error("Solana operation not found")]
    NotFound,
    /// The mutation contradicts durable facts or a newer fence.
    #[error("Solana operation state conflict")]
    Conflict,
    /// A caller-supplied field is out of its frozen bounds.
    #[error("invalid Solana operation input")]
    InvalidInput,
    /// The RPC quorum could not produce a unique answer.
    #[error("Solana RPC quorum unavailable")]
    QuorumUnavailable,
    /// The supplied clock reading is unusable.
    #[error("invalid Solana clock reading")]
    InvalidTime,
}

#![forbid(unsafe_code)]

//! Canonical DOM Wallet V3 domain state.
//!
//! This crate intentionally contains no filesystem, network, Tauri, or raw
//! cryptographic implementation. It owns the typed state and invariants that
//! those adapters must preserve.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

pub const MODEL_VERSION: u16 = 1;
pub const SECRET_PROFILE_VERSION: u16 = 1;
pub const TRANSACTION_EXPOSURE_VERSION: u16 = 1;
/// Frozen version of the common-wallet funding reservation handoff.
pub const SCRIPTLESS_FUNDING_RESERVATION_VERSION: u16 = 1;
/// Frozen version of the common-wallet claim/refund payout handoff.
pub const SCRIPTLESS_PAYOUT_RESERVATION_VERSION: u16 = 1;
/// The frozen DOM Interop Scriptless profile is strictly bilateral.
pub const SCRIPTLESS_PARTICIPANT_COUNT_V1: u32 = 2;
pub const MAX_ACCOUNTS: usize = 64;
pub const MAX_OUTPUTS: usize = 100_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Network {
    PrivateTestnet,
    PublicTestnet,
    Mainnet,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PrivateTestnet => "PRIVATE_TESTNET",
            Self::PublicTestnet => "PUBLIC_TESTNET",
            Self::Mainnet => "MAINNET",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentity {
    pub network: Network,
    pub chain_id: [u8; 32],
    pub genesis_id: [u8; 32],
}

impl NetworkIdentity {
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCursor {
    pub height: u64,
    pub block_hash: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanBounds {
    pub start_height: u64,
    pub end_height: u64,
    pub max_pages: u32,
    pub max_records_per_page: u32,
}

impl ScanBounds {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.start_height > self.end_height
            || self.max_pages == 0
            || self.max_records_per_page == 0
        {
            return Err(DomainError::InvalidScanBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanTarget {
    pub target_height: u64,
    pub target_block_hash: [u8; 32],
    pub source_identity: String,
    pub scan_bounds: ScanBounds,
    pub evidence_version: u16,
}

impl ScanTarget {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.source_identity.is_empty()
            || self.source_identity.len() > 128
            || self.evidence_version == 0
        {
            return Err(DomainError::InvalidScanTarget);
        }
        if self.target_height != self.scan_bounds.end_height {
            return Err(DomainError::InvalidScanTarget);
        }
        self.scan_bounds.validate()
    }

    pub fn cursor(&self) -> CanonicalCursor {
        CanonicalCursor {
            height: self.target_height,
            block_hash: self.target_block_hash,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Idle,
    Synchronizing,
    Synced,
    Degraded { reason: String },
    RecoveryRequired { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub id: Uuid,
    pub label: String,
    pub created_generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputState {
    Confirmed,
    Immature { required_height: u64 },
    PendingIncoming,
    PendingOutgoing,
    Locked,
    Spent { spent_height: u64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRecord {
    pub id: Uuid,
    pub account_id: Uuid,
    /// The authoritative local descriptor used for scan ownership matching.
    /// Older encrypted generations did not contain descriptors and therefore
    /// fail closed as unprovable rather than becoming heuristic matches.
    #[serde(default, with = "serde_option_bytes_33")]
    pub commitment: Option<[u8; 33]>,
    pub value: u64,
    pub state: OutputState,
    pub discovered_height: u64,
    /// A reservation is durable wallet evidence, never a chain observation.
    /// It prevents two locally-created slates selecting one canonical output.
    #[serde(default)]
    pub reserved_by: Option<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutputOwnership {
    KnownLocalOutput(OutputRecord),
    DeterministicallyRecoverableOutput(OutputRecord),
    NotOwnedOrUnprovable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionLifecycle {
    Draft,
    InputsReserved,
    RequestExported,
    RequestImported,
    ResponsePrepared,
    ResponseExported,
    ResponseImported,
    Finalized,
    Submitting,
    Submitted,
    AcceptedNotRelayed,
    InMempool,
    Confirmed { height: u64, block_hash: [u8; 32] },
    Reorged,
    RetransmitRequired,
    Cancelled,
    Failed,
    ReconciliationRequired,
}

/// Authoritative durable evidence of how far a transaction may have reached.
///
/// This is deliberately monotonic. A lifecycle can move to a reconciliation
/// state after a reorg or an ambiguous response, but evidence that bytes may
/// have reached the network can never be forgotten.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BroadcastExposure {
    #[default]
    NeverBroadcast,
    SubmissionStarted,
    PossiblyRelayed,
    ObservedInMempool,
    Confirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationDecision {
    ReleaseNeverBroadcastReservations,
    DenyPossiblyBroadcast,
    RequireReconciliation,
}

pub fn cancellation_decision(exposure: BroadcastExposure) -> CancellationDecision {
    match exposure {
        BroadcastExposure::NeverBroadcast => {
            CancellationDecision::ReleaseNeverBroadcastReservations
        }
        BroadcastExposure::SubmissionStarted
        | BroadcastExposure::PossiblyRelayed
        | BroadcastExposure::ObservedInMempool
        | BroadcastExposure::Confirmed => CancellationDecision::RequireReconciliation,
    }
}

pub fn infer_legacy_exposure(
    lifecycle: &TransactionLifecycle,
    submitted: bool,
) -> BroadcastExposure {
    if submitted
        || matches!(
            lifecycle,
            TransactionLifecycle::Submitting
                | TransactionLifecycle::Submitted
                | TransactionLifecycle::AcceptedNotRelayed
                | TransactionLifecycle::InMempool
                | TransactionLifecycle::RetransmitRequired
                | TransactionLifecycle::ReconciliationRequired
                | TransactionLifecycle::Reorged
                | TransactionLifecycle::Failed
                | TransactionLifecycle::Confirmed { .. }
        )
    {
        BroadcastExposure::PossiblyRelayed
    } else {
        BroadcastExposure::NeverBroadcast
    }
}

fn minimum_current_exposure(
    lifecycle: &TransactionLifecycle,
    submitted: bool,
) -> BroadcastExposure {
    if submitted {
        return BroadcastExposure::PossiblyRelayed;
    }
    match lifecycle {
        TransactionLifecycle::Submitting => BroadcastExposure::SubmissionStarted,
        TransactionLifecycle::Submitted
        | TransactionLifecycle::AcceptedNotRelayed
        | TransactionLifecycle::InMempool
        | TransactionLifecycle::Confirmed { .. }
        | TransactionLifecycle::Reorged
        | TransactionLifecycle::RetransmitRequired
        | TransactionLifecycle::Failed
        | TransactionLifecycle::ReconciliationRequired => BroadcastExposure::PossiblyRelayed,
        _ => BroadcastExposure::NeverBroadcast,
    }
}

/// Evidence required for every persisted lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionTransitionEvidence {
    LocalConstruction,
    RecipientResponse,
    Finalization,
    SubmissionStarted,
    SubmissionOutcome,
    MempoolObservation,
    ConfirmationEvidence,
    ReorgEvidence,
    ReconciliationEvidence,
    Cancellation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionRole {
    Sender,
    Recipient,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransactionCancellationReason {
    Manual,
    ExpiredBeforeFinalization,
}

/// Secrets required to continue an interactive DOM slate. This object is
/// encrypted as part of `WalletState`; it is deliberately redacted from Debug
/// so it cannot reach command errors or application logs.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateTransactionContext {
    #[serde(default, with = "serde_option_bytes_32")]
    pub sender_excess_blinding: Option<[u8; 32]>,
    #[serde(default, with = "serde_option_bytes_32")]
    pub sender_nonce: Option<[u8; 32]>,
    #[serde(default, with = "serde_option_bytes_32")]
    pub recipient_output_blinding: Option<[u8; 32]>,
}

impl std::fmt::Debug for PrivateTransactionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateTransactionContext(REDACTED)")
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateOutputBlinding {
    pub output_id: Uuid,
    #[serde(with = "serde_bytes_32")]
    pub blinding: [u8; 32],
}

/// Secret common-wallet contribution retained only inside encrypted wallet
/// state.  It is not a Scriptless shared-output blinding share: it is the
/// local ordinary-wallet excess contribution from selected inputs, change and
/// the participant's public transaction offset.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateScriptlessFundingContext {
    #[serde(with = "serde_bytes_32")]
    wallet_excess_contribution: [u8; 32],
    #[serde(default, with = "serde_option_bytes_32")]
    change_output_blinding: Option<[u8; 32]>,
}

impl PrivateScriptlessFundingContext {
    pub fn new(
        wallet_excess_contribution: [u8; 32],
        change_output_blinding: Option<[u8; 32]>,
    ) -> Self {
        Self {
            wallet_excess_contribution,
            change_output_blinding,
        }
    }

    /// Copy the contribution only into the in-process opaque adaptor boundary.
    pub fn copy_wallet_excess_contribution_to(&self, destination: &mut [u8; 32]) {
        destination.copy_from_slice(&self.wallet_excess_contribution);
    }

    /// Copy change spending evidence only while rebuilding encrypted state
    /// after a chain rollback.
    pub fn copy_change_output_blinding_to(&self, destination: &mut [u8; 32]) -> bool {
        if let Some(blinding) = self.change_output_blinding {
            destination.copy_from_slice(&blinding);
            true
        } else {
            false
        }
    }

    fn is_structurally_valid(&self, expects_change: bool) -> bool {
        self.wallet_excess_contribution != [0u8; 32]
            && self.change_output_blinding.is_some() == expects_change
            && self
                .change_output_blinding
                .is_none_or(|blinding| blinding != [0u8; 32])
    }
}

impl fmt::Debug for PrivateScriptlessFundingContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateScriptlessFundingContext(REDACTED)")
    }
}

/// Monotonic exposure state of a common-wallet funding reservation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScriptlessFundingReservationState {
    /// Inputs and any recovery coordinate are durable, but no component exists.
    Reserved,
    /// Exact components exist durably but have never left the wallet boundary.
    Prepared,
    /// The complete DOM session-share binding is durable; only its derived
    /// public kernel point may now be returned.
    SessionBound,
    /// Public components may have left the process; inputs stay reserved.
    Exported,
    /// The exact authoritative funding template is durably bound.
    TemplateBound,
    /// Operator abandoned an exposed attempt; reservations remain fail-closed.
    AbandonedRetained,
    /// No component was exposed and all input reservations were released.
    Cancelled,
}

impl ScriptlessFundingReservationState {
    pub fn retains_inputs(self) -> bool {
        self != Self::Cancelled
    }

    pub fn may_cancel_and_release(self) -> bool {
        matches!(self, Self::Reserved | Self::Prepared)
    }
}

/// Exact public two-party decomposition accepted with a Scriptless template.
///
/// These values are ordinary public transaction contributions, not wallet
/// secrets. They are retained so an idempotent retry cannot replace the other
/// participant's contribution while preserving only the aggregate offset or
/// kernel excess. Byte vectors keep the encrypted-state schema compatible
/// with serde versions that do not implement arrays longer than 32 bytes.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptlessTemplateParticipantBindingV1 {
    pub ordered_offset_contributions: Vec<Vec<u8>>,
    pub ordered_kernel_excess_points: Vec<Vec<u8>>,
}

impl ScriptlessTemplateParticipantBindingV1 {
    pub fn new(
        ordered_offset_contributions: [[u8; 32]; 2],
        ordered_kernel_excess_points: [[u8; 33]; 2],
    ) -> Self {
        Self {
            ordered_offset_contributions: ordered_offset_contributions
                .into_iter()
                .map(|bytes| bytes.to_vec())
                .collect(),
            ordered_kernel_excess_points: ordered_kernel_excess_points
                .into_iter()
                .map(|bytes| bytes.to_vec())
                .collect(),
        }
    }

    pub fn is_structurally_valid(&self) -> bool {
        self.ordered_offset_contributions.len() == SCRIPTLESS_PARTICIPANT_COUNT_V1 as usize
            && self.ordered_kernel_excess_points.len() == SCRIPTLESS_PARTICIPANT_COUNT_V1 as usize
            && self
                .ordered_offset_contributions
                .iter()
                .all(|contribution| {
                    contribution.len() == 32 && contribution.iter().any(|b| *b != 0)
                })
            && self
                .ordered_kernel_excess_points
                .iter()
                .all(|point| point.len() == 33 && point.iter().any(|b| *b != 0))
    }
}

impl fmt::Debug for ScriptlessTemplateParticipantBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptlessTemplateParticipantBindingV1")
            .field(
                "participant_count",
                &self.ordered_offset_contributions.len(),
            )
            .field("contributions", &"[PUBLIC TRANSACTION MATERIAL]")
            .finish()
    }
}

/// Durable common-wallet side of one Scriptless funding transaction.
///
/// The state is encrypted by the existing Wallet V3 generation envelope. Its
/// custom Debug implementation deliberately redacts amount, session and all
/// private context even though inputs/change/offset become normal public DOM
/// transaction data after export.
const fn empty_bytes_33() -> [u8; 33] {
    [0; 33]
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptlessFundingReservation {
    pub version: u16,
    pub id: Uuid,
    #[serde(with = "serde_bytes_32")]
    pub session_id: [u8; 32],
    /// Exact collaborative output this funding transaction must create.
    #[serde(default = "empty_bytes_33", with = "serde_bytes_33")]
    pub shared_output_commitment: [u8; 33],
    pub created_at_height: u64,
    /// Exact local debit assigned by the frozen funding terms. For a sole
    /// funder this is shared-output value plus the full funding fee.
    pub local_debit_noms: u64,
    pub funding_fee_noms: u64,
    pub expected_input_count: u32,
    /// Aggregate count: one global shared output plus every ordinary change
    /// output across all participants. The shared output is never local-owned.
    pub expected_output_count: u32,
    pub reserved_output_ids: Vec<Uuid>,
    pub input_commitments: Vec<Vec<u8>>,
    pub change_value_noms: u64,
    pub change_derivation_index: Option<u64>,
    pub change_output_id: Option<Uuid>,
    #[serde(default, with = "serde_option_bytes_33")]
    pub change_commitment: Option<[u8; 33]>,
    #[serde(default)]
    pub change_output_bytes: Vec<u8>,
    #[serde(default, with = "serde_option_bytes_32")]
    pub offset_contribution: Option<[u8; 32]>,
    #[serde(default)]
    pub wallet_excess_public_key: Vec<u8>,
    #[serde(default, with = "serde_option_bytes_32")]
    pub template_hash: Option<[u8; 32]>,
    /// Digest of the exact durable DOM shared-blinding capability binding.
    #[serde(default, with = "serde_option_bytes_32")]
    pub session_share_binding_digest: Option<[u8; 32]>,
    /// Frozen participant/offset position in the canonical two-party roster.
    #[serde(default)]
    pub participant_position: Option<u32>,
    /// Complete ordered public decomposition accepted with `template_hash`.
    #[serde(default)]
    pub template_participants: Option<ScriptlessTemplateParticipantBindingV1>,
    #[serde(default)]
    pub private_context: Option<PrivateScriptlessFundingContext>,
    pub state: ScriptlessFundingReservationState,
}

impl fmt::Debug for ScriptlessFundingReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptlessFundingReservation")
            .field("version", &self.version)
            .field("id", &self.id)
            .field("created_at_height", &self.created_at_height)
            .field("state", &self.state)
            .field("reserved_input_count", &self.reserved_output_ids.len())
            .field("has_change", &self.change_output_id.is_some())
            .field("session_id", &"[REDACTED]")
            .field("shared_output_commitment", &"[PUBLIC COMMITMENT]")
            .field("amounts", &"[REDACTED]")
            .field("template_hash", &"[REDACTED]")
            .field("private_context", &"[REDACTED]")
            .finish()
    }
}

/// Secret contribution for one wallet-owned claim or refund payout. The
/// output blinding and `e_i = payout_blinding_i - offset_i` remain only in the
/// encrypted wallet generation and are never serialized into a handoff DTO.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateScriptlessPayoutContext {
    #[serde(with = "serde_bytes_32")]
    payout_excess_contribution: [u8; 32],
    #[serde(default, with = "serde_option_bytes_32")]
    output_blinding: Option<[u8; 32]>,
}

impl PrivateScriptlessPayoutContext {
    pub fn new(payout_excess_contribution: [u8; 32], output_blinding: Option<[u8; 32]>) -> Self {
        Self {
            payout_excess_contribution,
            output_blinding,
        }
    }

    /// Copy only into the in-process opaque DOM adaptor boundary.
    pub fn copy_payout_excess_contribution_to(&self, destination: &mut [u8; 32]) {
        destination.copy_from_slice(&self.payout_excess_contribution);
    }

    /// Copy only while reconstructing the encrypted local output projection.
    pub fn copy_output_blinding_to(&self, destination: &mut [u8; 32]) -> bool {
        if let Some(blinding) = self.output_blinding {
            destination.copy_from_slice(&blinding);
            true
        } else {
            false
        }
    }

    fn is_structurally_valid(&self, expects_output: bool) -> bool {
        self.payout_excess_contribution != [0u8; 32]
            && self.output_blinding.is_some() == expects_output
            && self
                .output_blinding
                .is_none_or(|blinding| blinding != [0u8; 32])
    }
}

impl fmt::Debug for PrivateScriptlessPayoutContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateScriptlessPayoutContext(REDACTED)")
    }
}

/// The two shared-output spend roles that require wallet-owned payout output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScriptlessPayoutRoleV1 {
    Claim,
    Refund,
}

/// Monotonic exposure state of one claim/refund payout reservation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScriptlessPayoutReservationState {
    /// A distinct recovery coordinate is durable; no output exists yet.
    Reserved,
    /// Exact output and local excess exist durably but have not left Wallet V3.
    Prepared,
    /// The complete DOM session-share binding is durable; only its derived
    /// public kernel point may now be returned.
    SessionBound,
    /// Public components left Wallet V3 so the real template can be composed.
    ComponentsExposed,
    /// The exact authoritative claim/refund template is durably bound.
    TemplateBound,
    /// The attempt was abandoned, but exact output material remains retained.
    AbandonedRetained,
    /// Nothing was exposed; material was erased but the coordinate stays burned.
    Cancelled,
}

impl ScriptlessPayoutReservationState {
    pub fn has_prepared_material(self) -> bool {
        matches!(
            self,
            Self::Prepared
                | Self::SessionBound
                | Self::ComponentsExposed
                | Self::TemplateBound
                | Self::AbandonedRetained
        )
    }

    pub fn may_cancel_unexposed(self) -> bool {
        matches!(self, Self::Reserved | Self::Prepared)
    }
}

/// Durable Wallet V3 side of one participant's claim or refund payout.
///
/// Claim and refund use separate records and separate SelfTransfer recovery
/// coordinates even when their public values are equal. The template hash is
/// absent until public components have been used to construct and validate the
/// real DOM template; after binding it is immutable.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptlessPayoutReservation {
    pub version: u16,
    pub id: Uuid,
    #[serde(with = "serde_bytes_32")]
    pub session_id: [u8; 32],
    pub role: ScriptlessPayoutRoleV1,
    pub created_at_height: u64,
    #[serde(with = "serde_bytes_33")]
    pub shared_output_commitment: [u8; 33],
    pub payout_value_noms: u64,
    pub kernel_fee_noms: u64,
    pub expected_output_count: u32,
    pub refund_lock_height: u64,
    pub output_id: Option<Uuid>,
    pub derivation_index: Option<u64>,
    #[serde(default, with = "serde_option_bytes_33")]
    pub output_commitment: Option<[u8; 33]>,
    #[serde(default)]
    pub output_bytes: Vec<u8>,
    #[serde(default, with = "serde_option_bytes_32")]
    pub offset_contribution: Option<[u8; 32]>,
    #[serde(default)]
    pub payout_excess_public_key: Vec<u8>,
    #[serde(default, with = "serde_option_bytes_32")]
    pub template_hash: Option<[u8; 32]>,
    /// Digest of the exact durable DOM shared-blinding capability binding.
    #[serde(default, with = "serde_option_bytes_32")]
    pub session_share_binding_digest: Option<[u8; 32]>,
    /// Frozen participant/offset position in the canonical two-party roster.
    /// This is independent of the aggregate output position because a
    /// participant can contribute no payout output. It is absent until
    /// the complete DOM session-share binding is persisted.
    #[serde(default)]
    pub participant_position: Option<u32>,
    /// Complete ordered public decomposition accepted with `template_hash`.
    #[serde(default)]
    pub template_participants: Option<ScriptlessTemplateParticipantBindingV1>,
    #[serde(default)]
    pub private_context: Option<PrivateScriptlessPayoutContext>,
    pub state: ScriptlessPayoutReservationState,
}

impl fmt::Debug for ScriptlessPayoutReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptlessPayoutReservation")
            .field("version", &self.version)
            .field("id", &self.id)
            .field("role", &self.role)
            .field("created_at_height", &self.created_at_height)
            .field("state", &self.state)
            .field("session_id", &"[REDACTED]")
            .field("shared_output_commitment", &"[REDACTED]")
            .field("amounts", &"[REDACTED]")
            .field("template_hash", &"[REDACTED]")
            .field("private_context", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for PrivateOutputBlinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateOutputBlinding(REDACTED)")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalTransactionIntent {
    pub id: Uuid,
    /// Canonical height at which the local intent first reserved its inputs.
    /// Legacy intents use zero and expose their age as unknown.
    #[serde(default)]
    pub created_at_height: u64,
    /// Wall-clock creation time used only for presentation. Consensus and
    /// expiry decisions always use canonical heights.
    #[serde(default)]
    pub created_at_unix_seconds: u64,
    /// Durable tombstone metadata. `ExpiredBeforeFinalization` is written only
    /// when no finalized transaction bytes exist and the envelope has expired.
    #[serde(default)]
    pub cancellation_reason: Option<TransactionCancellationReason>,
    #[serde(default)]
    pub cancelled_at_height: Option<u64>,
    /// Exactly 33 canonical commitment bytes. This is persisted before an
    /// external submission and is the only kernel-to-wallet association.
    pub kernel_excess: Vec<u8>,
    pub lifecycle: TransactionLifecycle,
    pub submitted: bool,
    #[serde(default)]
    pub exposure: BroadcastExposure,
    /// A protocol-independent identifier carried by the manual transport
    /// envelope. It is not a replacement for the DOM canonical slate bytes.
    #[serde(default)]
    pub slate_id: Option<Uuid>,
    #[serde(default)]
    pub role: Option<TransactionRole>,
    #[serde(default)]
    pub amount: u64,
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub reserved_output_ids: Vec<Uuid>,
    #[serde(default)]
    pub request_bytes: Vec<u8>,
    #[serde(default)]
    pub response_bytes: Vec<u8>,
    /// Durable canonical transaction bytes. Once populated, submission and
    /// recovery after restart do not depend on the disposable Slate envelope.
    #[serde(default)]
    pub finalized_transaction_bytes: Vec<u8>,
    #[serde(default)]
    pub transaction_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub attempt_count: u32,
    #[serde(default)]
    pub private_context: Option<PrivateTransactionContext>,
    #[serde(default)]
    pub recipient_output_id: Option<Uuid>,
    #[serde(default)]
    pub change_output_id: Option<Uuid>,
    /// Cached expiry used for fail-closed checks after restart. Legacy
    /// transactions retain zero here and are validated from canonical slate
    /// bytes before any operation that can expose or submit them.
    #[serde(default)]
    pub expires_at_height: u64,
}

impl LocalTransactionIntent {
    pub fn transition(
        &mut self,
        next: TransactionLifecycle,
        evidence: TransactionTransitionEvidence,
    ) -> Result<(), DomainError> {
        use TransactionLifecycle as L;
        use TransactionTransitionEvidence as E;

        let allowed = if self.lifecycle == next {
            true
        } else {
            matches!(
                (self.lifecycle, next, evidence),
                (L::Draft, L::InputsReserved, E::LocalConstruction)
                    | (
                        L::RequestImported,
                        L::ResponsePrepared,
                        E::RecipientResponse
                    )
                    | (
                        L::InputsReserved | L::RequestExported,
                        L::ResponseImported,
                        E::RecipientResponse
                    )
                    | (L::ResponseImported, L::Finalized, E::Finalization)
                    | (
                        L::Finalized | L::RetransmitRequired,
                        L::Submitting,
                        E::SubmissionStarted
                    )
                    | (
                        L::Submitting,
                        L::Submitted
                            | L::AcceptedNotRelayed
                            | L::InMempool
                            | L::RetransmitRequired
                            | L::Failed
                            | L::ReconciliationRequired,
                        E::SubmissionOutcome
                    )
                    | (
                        L::Submitting
                            | L::Submitted
                            | L::AcceptedNotRelayed
                            | L::RetransmitRequired
                            | L::ReconciliationRequired
                            | L::Reorged,
                        L::InMempool,
                        E::MempoolObservation
                    )
                    | (
                        L::ResponsePrepared
                            | L::ResponseExported
                            | L::Submitting
                            | L::Submitted
                            | L::AcceptedNotRelayed
                            | L::InMempool
                            | L::RetransmitRequired
                            | L::ReconciliationRequired
                            | L::Reorged,
                        L::Confirmed { .. },
                        E::ConfirmationEvidence
                    )
                    | (L::Confirmed { .. }, L::Reorged, E::ReorgEvidence)
                    | (
                        L::Submitting
                            | L::Submitted
                            | L::AcceptedNotRelayed
                            | L::InMempool
                            | L::Confirmed { .. }
                            | L::Reorged
                            | L::RetransmitRequired
                            | L::Failed,
                        L::ReconciliationRequired,
                        E::ReconciliationEvidence
                    )
                    | (
                        L::Draft
                            | L::InputsReserved
                            | L::RequestExported
                            | L::RequestImported
                            | L::ResponsePrepared
                            | L::ResponseExported
                            | L::ResponseImported
                            | L::Finalized
                            | L::Failed,
                        L::Cancelled,
                        E::Cancellation
                    )
            )
        };
        if !allowed || matches!(self.lifecycle, L::Cancelled) && next != L::Cancelled {
            return Err(DomainError::InvalidTransactionTransition);
        }

        let observed = match evidence {
            E::SubmissionStarted => BroadcastExposure::SubmissionStarted,
            E::SubmissionOutcome | E::ReconciliationEvidence | E::ReorgEvidence => {
                BroadcastExposure::PossiblyRelayed
            }
            E::MempoolObservation => BroadcastExposure::ObservedInMempool,
            E::ConfirmationEvidence => BroadcastExposure::Confirmed,
            E::LocalConstruction | E::RecipientResponse | E::Finalization | E::Cancellation => {
                BroadcastExposure::NeverBroadcast
            }
        };
        self.exposure = self.exposure.max(observed);
        self.lifecycle = next;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RescanPhase {
    Prepared,
    Scanning,
    ValidatingTarget,
    ReadyToActivate,
    Activating,
    Complete,
    Invalidated,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RescanPlan {
    pub version: u16,
    pub plan_id: Uuid,
    pub wallet_id: Uuid,
    pub identity: NetworkIdentity,
    pub source_identity: String,
    pub target: ScanTarget,
    pub recovery_start_height: u64,
    pub next_page: u32,
    pub next_page_height: u64,
    pub provisional_generation_id: u64,
    pub retained_canonical_generation_id: u64,
    pub phase: RescanPhase,
    pub provisional_outputs: Vec<OutputRecord>,
    pub provisional_transactions: Vec<LocalTransactionIntent>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalanceProjection {
    pub confirmed: u64,
    pub immature: u64,
    pub pending_incoming: u64,
    pub pending_outgoing: u64,
    pub locked: u64,
    pub spendable: u64,
    pub total: u64,
}

impl BalanceProjection {
    pub fn from_outputs(outputs: &[OutputRecord]) -> Self {
        let mut balance = Self::default();
        for output in outputs {
            match output.state {
                OutputState::Confirmed => {
                    balance.total = balance.total.saturating_add(output.value);
                    balance.confirmed = balance.confirmed.saturating_add(output.value);
                    balance.spendable = balance.spendable.saturating_add(output.value);
                }
                OutputState::Immature { .. } => {
                    balance.total = balance.total.saturating_add(output.value);
                    balance.immature = balance.immature.saturating_add(output.value)
                }
                OutputState::PendingIncoming => {
                    balance.total = balance.total.saturating_add(output.value);
                    balance.pending_incoming = balance.pending_incoming.saturating_add(output.value)
                }
                OutputState::PendingOutgoing => {
                    balance.total = balance.total.saturating_add(output.value);
                    balance.pending_outgoing = balance.pending_outgoing.saturating_add(output.value)
                }
                OutputState::Locked => {
                    balance.total = balance.total.saturating_add(output.value);
                    balance.locked = balance.locked.saturating_add(output.value)
                }
                OutputState::Spent { .. } => {}
            }
        }
        balance
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfiguration {
    pub endpoint_url: String,
    pub expected_identity: NetworkIdentity,
    pub source_identity: String,
    pub api_compatibility_version: u16,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub poll_interval_ms: u64,
    pub retry_ceiling: u32,
    pub max_backoff_ms: u64,
    pub stable_success_threshold: u32,
    pub tls_required: bool,
    pub credential_reference: Option<String>,
}

impl NodeConfiguration {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.endpoint_url.is_empty()
            || self.endpoint_url.len() > 2048
            || self.source_identity.is_empty()
            || self.source_identity.len() > 128
            || self.api_compatibility_version == 0
            || self.connect_timeout_ms == 0
            || self.request_timeout_ms == 0
            || self.poll_interval_ms == 0
            || self.retry_ceiling == 0
            || self.max_backoff_ms < self.poll_interval_ms
            || self.stable_success_threshold == 0
        {
            return Err(DomainError::InvalidNodeConfiguration);
        }
        if self.tls_required && !self.endpoint_url.starts_with("https://") {
            return Err(DomainError::TlsRequired);
        }
        if self
            .credential_reference
            .as_ref()
            .is_some_and(|value| value.len() > 256)
        {
            return Err(DomainError::InvalidNodeConfiguration);
        }
        Ok(())
    }

    pub fn redacted(&self) -> RedactedNodeConfiguration {
        RedactedNodeConfiguration {
            endpoint_url: self.endpoint_url.clone(),
            expected_network: self.expected_identity.network,
            source_identity: self.source_identity.clone(),
            api_compatibility_version: self.api_compatibility_version,
            tls_required: self.tls_required,
            has_credential_reference: self.credential_reference.is_some(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedNodeConfiguration {
    pub endpoint_url: String,
    pub expected_network: Network,
    pub source_identity: String,
    pub api_compatibility_version: u16,
    pub tls_required: bool,
    pub has_credential_reference: bool,
}

/// BIP-39 eligibility marker for encrypted Wallet V3 state.
pub const RECOVERY_SCHEME_BIP39_256_V1: &str = "BIP39_ENTROPY_256_V1";

/// Non-secret recovery eligibility. Mnemonic and seed bytes are never stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryMetadata {
    pub scheme: String,
    pub phrase_confirmed: bool,
}

/// Wallet-owned output purpose used to reserve a durable recovery coordinate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutputClass {
    ReceiveRequest,
    ReceiveSlate,
    Change,
    SelfTransfer,
    Coinbase,
}

/// Persisted independent non-reuse floors for recovery metadata domains.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryAllocationFloors {
    pub received: u64,
    pub change: u64,
    pub self_transfer: u64,
    pub coinbase: u64,
}

/// Canonical private recovery domain stored only after capsule authentication.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveredOutputDomain {
    Received,
    Change,
    SelfTransfer,
    Coinbase,
}

/// Non-secret metadata bound to one authenticated restored output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredOutputMetadata {
    pub output_id: Uuid,
    pub recovery_account: u32,
    pub derivation_index: u64,
    pub domain: RecoveredOutputDomain,
    pub is_coinbase: bool,
    pub block_hash: [u8; 32],
    pub output_position: u32,
}

/// Mapping from authenticated capsule account numbers to local account IDs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredAccountMapping {
    pub recovery_account: u32,
    pub account_id: Uuid,
}

/// Canonical block identity retained for bounded reorg reconciliation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCanonicalBlock {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub previous_block_hash: [u8; 32],
    pub output_count: u32,
    pub legacy_proof_only_outputs: u32,
}

/// Durable publication state for a seed-only restore staging wallet.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedRestoreStatus {
    InProgress,
    Complete,
}

/// A coordinate is returned only after its corresponding floor is advanced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservedRecoveryCoordinate {
    account: u32,
    derivation_index: u64,
    class: RecoveryOutputClass,
}

impl ReservedRecoveryCoordinate {
    pub fn account(self) -> u32 {
        self.account
    }

    pub fn derivation_index(self) -> u64 {
        self.derivation_index
    }

    pub fn class(self) -> RecoveryOutputClass {
        self.class
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletState {
    pub model_version: u16,
    pub secret_profile_version: u16,
    pub wallet_id: Uuid,
    pub identity: NetworkIdentity,
    pub generation: u64,
    pub default_account: Account,
    pub allocation_floor: u64,
    pub non_reuse_floor: u64,
    pub cursor: Option<CanonicalCursor>,
    pub outputs: Vec<OutputRecord>,
    /// Per-output secrets are encrypted in the canonical wallet generation and
    /// are never part of scan, summary, slate transport, or Tauri DTOs.
    #[serde(default)]
    pub private_output_blindings: Vec<PrivateOutputBlinding>,
    #[serde(default)]
    pub transactions: Vec<LocalTransactionIntent>,
    /// Common-wallet UTXO reservations used by the independent Scriptless
    /// session/store. This contains no session nonce or shared blinding share.
    #[serde(default)]
    pub scriptless_funding_reservations: Vec<ScriptlessFundingReservation>,
    /// Wallet-owned claim/refund payout outputs and opaque local excesses.
    /// Claim and refund always occupy distinct records and burned coordinates.
    #[serde(default)]
    pub scriptless_payout_reservations: Vec<ScriptlessPayoutReservation>,
    /// Version of the transaction exposure migration applied to this state.
    /// Missing legacy values deserialize as zero and are upgraded before use.
    #[serde(default)]
    pub transaction_exposure_version: u16,
    pub sync_status: SyncStatus,
    pub provisional_target: Option<ScanTarget>,
    #[serde(default)]
    pub rescan_plan: Option<RescanPlan>,
    #[serde(default)]
    pub recovery: Option<RecoveryMetadata>,
    #[serde(default)]
    pub recovery_allocation_floors: RecoveryAllocationFloors,
    /// Exact canonical WalletScanCursor v1 bytes for the Core recovery stream.
    #[serde(default)]
    pub core_scan_cursor: Option<Vec<u8>>,
    /// Encrypted canonical anchors used only for recovery reorg reconciliation.
    #[serde(default)]
    pub recovery_canonical_blocks: Vec<RecoveryCanonicalBlock>,
    /// Local account IDs reconstructed from authenticated capsule account IDs.
    #[serde(default)]
    pub recovered_accounts: Vec<RecoveredAccountMapping>,
    /// Authenticated metadata keyed to restored output IDs.
    #[serde(default)]
    pub recovered_output_metadata: Vec<RecoveredOutputMetadata>,
    /// Present only in a seed-restore staging wallet or a completed restore.
    #[serde(default)]
    pub seed_restore_status: Option<SeedRestoreStatus>,
    /// Count of canonical proof-only outputs observed during recovery.
    #[serde(default)]
    pub legacy_proof_only_outputs: u64,
    /// Durable count of canonical blocks scanned by recovery. Unlike
    /// `recovery_canonical_blocks`, which is pruned to a rolling reorg window,
    /// this counter covers the whole scanned history. Zero means the state
    /// predates the counter and still carries the complete block list.
    #[serde(default)]
    pub recovery_scanned_blocks: u64,
    /// Durable count of canonical outputs observed by recovery, maintained
    /// alongside `recovery_scanned_blocks` across window pruning.
    #[serde(default)]
    pub recovery_scanned_outputs: u64,
    pub node_configuration: NodeConfiguration,
    /// Non-secret local CPU mining preferences. Runtime mining state is never persisted.
    #[serde(default)]
    pub mining_preferences: MiningPreferences,
    #[serde(with = "serde_bytes_32")]
    pub root_material: [u8; 32],
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MiningPreferences {
    pub enabled: bool,
    /// Zero means not selected yet; the desktop maps it to its recommended count.
    pub cpu_threads: usize,
}

impl WalletState {
    pub fn new(
        identity: NetworkIdentity,
        root_material: [u8; 32],
        node_configuration: NodeConfiguration,
    ) -> Self {
        let wallet_id = Uuid::new_v4();
        Self {
            model_version: MODEL_VERSION,
            secret_profile_version: SECRET_PROFILE_VERSION,
            wallet_id,
            identity,
            generation: 0,
            default_account: Account {
                id: Uuid::new_v4(),
                label: "Default account".into(),
                created_generation: 0,
            },
            allocation_floor: 0,
            non_reuse_floor: 0,
            cursor: None,
            outputs: Vec::new(),
            private_output_blindings: Vec::new(),
            transactions: Vec::new(),
            scriptless_funding_reservations: Vec::new(),
            scriptless_payout_reservations: Vec::new(),
            transaction_exposure_version: TRANSACTION_EXPOSURE_VERSION,
            sync_status: SyncStatus::Idle,
            provisional_target: None,
            rescan_plan: None,
            recovery: None,
            recovery_allocation_floors: RecoveryAllocationFloors::default(),
            core_scan_cursor: None,
            recovery_canonical_blocks: Vec::new(),
            recovered_accounts: Vec::new(),
            recovered_output_metadata: Vec::new(),
            seed_restore_status: None,
            legacy_proof_only_outputs: 0,
            recovery_scanned_blocks: 0,
            recovery_scanned_outputs: 0,
            node_configuration,
            mining_preferences: MiningPreferences::default(),
            root_material,
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.model_version != MODEL_VERSION
            || self.secret_profile_version != SECRET_PROFILE_VERSION
        {
            return Err(DomainError::UnsupportedVersion);
        }
        if self.outputs.len() > MAX_OUTPUTS
            || self.default_account.label.is_empty()
            || self.default_account.label.len() > 128
            || self.mining_preferences.cpu_threads > 4_096
            || self.transaction_exposure_version != TRANSACTION_EXPOSURE_VERSION
        {
            return Err(DomainError::InvalidState);
        }
        self.node_configuration.validate()?;
        if !self
            .identity
            .matches(&self.node_configuration.expected_identity)
        {
            return Err(DomainError::IdentityMismatch);
        }
        if self.non_reuse_floor < self.allocation_floor {
            return Err(DomainError::NonReuseFloorRegression);
        }
        if self
            .recovery
            .as_ref()
            .is_some_and(|value| value.scheme != RECOVERY_SCHEME_BIP39_256_V1)
        {
            return Err(DomainError::InvalidState);
        }
        if let Some(target) = &self.provisional_target {
            target.validate()?;
        }
        for transaction in &self.transactions {
            if (!transaction.kernel_excess.is_empty() && transaction.kernel_excess.len() != 33)
                || (transaction.submitted && transaction.kernel_excess.len() != 33)
                || transaction.exposure
                    < minimum_current_exposure(&transaction.lifecycle, transaction.submitted)
            {
                return Err(DomainError::InvalidTransactionIntent);
            }
        }
        self.validate_scriptless_funding_reservations()?;
        self.validate_scriptless_payout_reservations()?;
        if let Some(plan) = &self.rescan_plan {
            if plan.wallet_id != self.wallet_id
                || plan.identity != self.identity
                || plan.target.source_identity != plan.source_identity
                || plan.version != 1
                || plan.next_page_height < plan.recovery_start_height
                || plan.next_page_height > plan.target.scan_bounds.end_height.saturating_add(1)
            {
                return Err(DomainError::InvalidRescanPlan);
            }
        }
        let mut account_ids = std::collections::BTreeSet::from([self.default_account.id]);
        let mut recovery_accounts = std::collections::BTreeSet::new();
        if self.recovered_accounts.len() > MAX_ACCOUNTS
            || self.recovered_accounts.iter().any(|account| {
                !account_ids.insert(account.account_id)
                    || !recovery_accounts.insert(account.recovery_account)
            })
            || self
                .outputs
                .iter()
                .any(|output| !account_ids.contains(&output.account_id))
        {
            return Err(DomainError::InvalidState);
        }
        if self
            .core_scan_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() != 86)
            || self.recovery_canonical_blocks.len() > MAX_OUTPUTS
            || self.recovery_canonical_blocks.windows(2).any(|blocks| {
                blocks[1].height != blocks[0].height.saturating_add(1)
                    || blocks[1].previous_block_hash != blocks[0].block_hash
            })
            // A nonzero durable counter must cover at least the retained
            // rolling window. Zero marks a pre-counter state whose complete
            // block list migrates on the next recovery batch.
            || (self.recovery_scanned_blocks != 0
                && self.recovery_scanned_blocks < self.recovery_canonical_blocks.len() as u64)
        {
            return Err(DomainError::InvalidState);
        }
        if self.private_output_blindings.iter().any(|secret| {
            !self
                .outputs
                .iter()
                .any(|output| output.id == secret.output_id)
        }) {
            return Err(DomainError::InvalidState);
        }
        let mut commitments = std::collections::BTreeSet::new();
        if self.outputs.iter().any(|output| {
            output
                .commitment
                .is_some_and(|commitment| !commitments.insert(commitment))
        }) {
            return Err(DomainError::InvalidState);
        }
        let mut recovered_output_ids = std::collections::BTreeSet::new();
        if self.recovered_output_metadata.iter().any(|metadata| {
            !recovered_output_ids.insert(metadata.output_id)
                || !self
                    .outputs
                    .iter()
                    .any(|output| output.id == metadata.output_id)
                || metadata.is_coinbase != (metadata.domain == RecoveredOutputDomain::Coinbase)
                || metadata.block_hash == [0u8; 32]
        }) {
            return Err(DomainError::InvalidState);
        }
        Ok(())
    }

    fn validate_scriptless_funding_reservations(&self) -> Result<(), DomainError> {
        if self.scriptless_funding_reservations.len() > MAX_OUTPUTS {
            return Err(DomainError::InvalidScriptlessFundingReservation);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut sessions = std::collections::BTreeSet::new();
        let mut reserved_inputs = std::collections::BTreeSet::new();
        let mut reserved_commitments = std::collections::BTreeSet::new();
        for reservation in &self.scriptless_funding_reservations {
            let is_zero_debit_signer = reservation.local_debit_noms == 0;
            let has_change = reservation.change_value_noms != 0;
            let prepared = matches!(
                reservation.state,
                ScriptlessFundingReservationState::Prepared
                    | ScriptlessFundingReservationState::SessionBound
                    | ScriptlessFundingReservationState::Exported
                    | ScriptlessFundingReservationState::TemplateBound
                    | ScriptlessFundingReservationState::AbandonedRetained
            );
            if reservation.version != SCRIPTLESS_FUNDING_RESERVATION_VERSION
                || reservation.id.is_nil()
                || reservation.session_id == [0u8; 32]
                || reservation.shared_output_commitment == [0u8; 33]
                || reservation.funding_fee_noms == 0
                || (!is_zero_debit_signer && reservation.expected_input_count == 0)
                || reservation.expected_output_count == 0
                || reservation.reserved_output_ids.is_empty() != is_zero_debit_signer
                || reservation.reserved_output_ids.len() != reservation.input_commitments.len()
                || reservation.reserved_output_ids.len() > reservation.expected_input_count as usize
                // The collaborative output is global, not owned by the payer.
                // Nevertheless every participant's frozen aggregate shape
                // must have room for that one output plus its local change.
                || usize::from(has_change).saturating_add(1)
                    > reservation.expected_output_count as usize
                || (is_zero_debit_signer
                    && (has_change
                        || reservation.change_derivation_index.is_some()
                        || reservation.change_output_id.is_some()))
                || reservation
                    .input_commitments
                    .iter()
                    .any(|commitment| commitment.len() != 33)
                || !ids.insert(reservation.id)
                || !sessions.insert(reservation.session_id)
                || (has_change != reservation.change_derivation_index.is_some())
                || (has_change != reservation.change_output_id.is_some())
                || reservation.change_derivation_index.is_some_and(|index| {
                    index == 0 || index > self.recovery_allocation_floors.change
                })
            {
                return Err(DomainError::InvalidScriptlessFundingReservation);
            }

            let has_prepared_fields = reservation.change_commitment.is_some() == has_change
                && (!reservation.change_output_bytes.is_empty()) == has_change
                && reservation.offset_contribution.is_some()
                && reservation.wallet_excess_public_key.len() == 33
                && reservation
                    .private_context
                    .as_ref()
                    .is_some_and(|context| context.is_structurally_valid(has_change));
            match reservation.state {
                ScriptlessFundingReservationState::Reserved => {
                    if reservation.change_commitment.is_some()
                        || !reservation.change_output_bytes.is_empty()
                        || reservation.offset_contribution.is_some()
                        || !reservation.wallet_excess_public_key.is_empty()
                        || reservation.template_hash.is_some()
                        || reservation.session_share_binding_digest.is_some()
                        || reservation.participant_position.is_some()
                        || reservation.template_participants.is_some()
                        || reservation.private_context.is_some()
                    {
                        return Err(DomainError::InvalidScriptlessFundingReservation);
                    }
                }
                ScriptlessFundingReservationState::Prepared => {
                    if !has_prepared_fields
                        || reservation.template_hash.is_some()
                        || reservation.session_share_binding_digest.is_some()
                        || reservation.participant_position.is_some()
                        || reservation.template_participants.is_some()
                    {
                        return Err(DomainError::InvalidScriptlessFundingReservation);
                    }
                }
                ScriptlessFundingReservationState::SessionBound
                | ScriptlessFundingReservationState::Exported => {
                    if !has_prepared_fields
                        || reservation.template_hash.is_some()
                        || reservation
                            .session_share_binding_digest
                            .is_none_or(|binding| binding == [0u8; 32])
                        || reservation
                            .participant_position
                            .is_none_or(|position| position >= SCRIPTLESS_PARTICIPANT_COUNT_V1)
                        || reservation.template_participants.is_some()
                    {
                        return Err(DomainError::InvalidScriptlessFundingReservation);
                    }
                }
                ScriptlessFundingReservationState::TemplateBound => {
                    if !has_prepared_fields
                        || reservation
                            .template_hash
                            .is_none_or(|template_hash| template_hash == [0u8; 32])
                        || reservation
                            .session_share_binding_digest
                            .is_none_or(|binding| binding == [0u8; 32])
                        || reservation
                            .participant_position
                            .is_none_or(|position| position >= SCRIPTLESS_PARTICIPANT_COUNT_V1)
                        || reservation
                            .template_participants
                            .as_ref()
                            .is_none_or(|participants| !participants.is_structurally_valid())
                    {
                        return Err(DomainError::InvalidScriptlessFundingReservation);
                    }
                }
                ScriptlessFundingReservationState::AbandonedRetained => {
                    if !has_prepared_fields
                        || reservation
                            .session_share_binding_digest
                            .is_none_or(|binding| binding == [0u8; 32])
                        || reservation
                            .participant_position
                            .is_none_or(|position| position >= SCRIPTLESS_PARTICIPANT_COUNT_V1)
                        || reservation.template_hash.is_some()
                            != reservation.template_participants.is_some()
                        || reservation
                            .template_hash
                            .is_some_and(|template_hash| template_hash == [0u8; 32])
                        || reservation
                            .template_participants
                            .as_ref()
                            .is_some_and(|participants| !participants.is_structurally_valid())
                    {
                        return Err(DomainError::InvalidScriptlessFundingReservation);
                    }
                }
                ScriptlessFundingReservationState::Cancelled => {
                    if reservation.change_commitment.is_some()
                        || !reservation.change_output_bytes.is_empty()
                        || reservation.offset_contribution.is_some()
                        || !reservation.wallet_excess_public_key.is_empty()
                        || reservation.template_hash.is_some()
                        || reservation.session_share_binding_digest.is_some()
                        || reservation.participant_position.is_some()
                        || reservation.template_participants.is_some()
                        || reservation.private_context.is_some()
                    {
                        return Err(DomainError::InvalidScriptlessFundingReservation);
                    }
                }
            }

            let mut local_output_ids = std::collections::BTreeSet::new();
            let mut local_commitments = std::collections::BTreeSet::new();
            let mut present_input_total = 0u64;
            let mut all_inputs_present = true;
            for (output_id, commitment) in reservation
                .reserved_output_ids
                .iter()
                .zip(&reservation.input_commitments)
            {
                if !local_output_ids.insert(*output_id)
                    || !local_commitments.insert(commitment.as_slice())
                {
                    return Err(DomainError::InvalidScriptlessFundingReservation);
                }
                if reservation.state.retains_inputs()
                    && (!reserved_inputs.insert(*output_id)
                        || !reserved_commitments.insert(commitment.as_slice()))
                {
                    return Err(DomainError::InvalidScriptlessFundingReservation);
                }
                let Some(output) = self.outputs.iter().find(|output| output.id == *output_id)
                else {
                    // A whole-history rescan can temporarily remove the local
                    // projection of an input whose creation height is above
                    // the rewind point. The durable commitment remains the
                    // authority and is rebound when the scanner rediscovers
                    // it; absence never makes an output selectable.
                    all_inputs_present = false;
                    continue;
                };
                if output.commitment.as_ref().map(<[u8; 33]>::as_slice)
                    != Some(commitment.as_slice())
                {
                    return Err(DomainError::InvalidScriptlessFundingReservation);
                }
                present_input_total = present_input_total
                    .checked_add(output.value)
                    .ok_or(DomainError::InvalidScriptlessFundingReservation)?;
                if reservation.state.retains_inputs() {
                    match output.state {
                        OutputState::Spent { .. } if output.reserved_by.is_none() => {}
                        _ if output.reserved_by == Some(reservation.id)
                            && output.state == OutputState::PendingOutgoing => {}
                        _ => return Err(DomainError::InvalidScriptlessFundingReservation),
                    }
                } else if output.reserved_by == Some(reservation.id) {
                    return Err(DomainError::InvalidScriptlessFundingReservation);
                }
            }
            if all_inputs_present
                && present_input_total
                    != reservation
                        .local_debit_noms
                        .checked_add(reservation.change_value_noms)
                        .ok_or(DomainError::InvalidScriptlessFundingReservation)?
            {
                return Err(DomainError::InvalidScriptlessFundingReservation);
            }

            if prepared && has_change {
                let output_id = reservation
                    .change_output_id
                    .ok_or(DomainError::InvalidScriptlessFundingReservation)?;
                let change = self
                    .outputs
                    .iter()
                    .find(|output| output.id == output_id)
                    .ok_or(DomainError::InvalidScriptlessFundingReservation)?;
                if change.commitment != reservation.change_commitment
                    || change.value != reservation.change_value_noms
                    || change.account_id != self.default_account.id
                    || self.output_blinding(output_id).is_none()
                {
                    return Err(DomainError::InvalidScriptlessFundingReservation);
                }
            } else if reservation.state == ScriptlessFundingReservationState::Cancelled
                && reservation.change_output_id.is_some_and(|output_id| {
                    self.outputs.iter().any(|output| output.id == output_id)
                })
            {
                return Err(DomainError::InvalidScriptlessFundingReservation);
            }
        }
        for output in self.outputs.iter().filter(|output| {
            output.reserved_by.is_some() && !matches!(output.state, OutputState::Spent { .. })
        }) {
            let owner = output
                .reserved_by
                .ok_or(DomainError::InvalidScriptlessFundingReservation)?;
            let ordinary_owner = self.transactions.iter().any(|transaction| {
                transaction.id == owner
                    && transaction.reserved_output_ids.contains(&output.id)
                    && !matches!(
                        transaction.lifecycle,
                        TransactionLifecycle::Cancelled | TransactionLifecycle::Failed
                    )
            });
            let scriptless_owner = self
                .scriptless_funding_reservations
                .iter()
                .any(|reservation| {
                    reservation.id == owner
                        && reservation.state.retains_inputs()
                        && reservation.reserved_output_ids.contains(&output.id)
                });
            if ordinary_owner == scriptless_owner {
                return Err(DomainError::InvalidState);
            }
        }
        Ok(())
    }

    fn validate_scriptless_payout_reservations(&self) -> Result<(), DomainError> {
        if self.scriptless_payout_reservations.len() > MAX_OUTPUTS {
            return Err(DomainError::InvalidScriptlessPayoutReservation);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut sessions_and_roles = std::collections::BTreeSet::new();
        let mut output_ids = std::collections::BTreeSet::new();
        let mut output_commitments = std::collections::BTreeSet::new();
        for reservation in &self.scriptless_payout_reservations {
            let has_output = reservation.payout_value_noms != 0;
            let has_material = reservation.state.has_prepared_material();
            let role_lock_is_valid = match reservation.role {
                ScriptlessPayoutRoleV1::Claim => reservation.refund_lock_height == 0,
                ScriptlessPayoutRoleV1::Refund => reservation.refund_lock_height != 0,
            };
            if reservation.version != SCRIPTLESS_PAYOUT_RESERVATION_VERSION
                || reservation.id.is_nil()
                || reservation.session_id == [0u8; 32]
                || reservation.shared_output_commitment == [0u8; 33]
                || reservation.kernel_fee_noms == 0
                || reservation.expected_output_count == 0
                || reservation.output_id.is_some() != has_output
                || reservation.derivation_index.is_some() != has_output
                || reservation
                    .output_id
                    .is_some_and(|output_id| output_id.is_nil())
                || reservation
                    .derivation_index
                    .is_some_and(|derivation_index| {
                        derivation_index == 0
                            || derivation_index > self.recovery_allocation_floors.self_transfer
                    })
                || !role_lock_is_valid
                || !ids.insert(reservation.id)
                || !sessions_and_roles.insert((reservation.session_id, reservation.role))
                || reservation
                    .output_id
                    .is_some_and(|output_id| !output_ids.insert(output_id))
            {
                return Err(DomainError::InvalidScriptlessPayoutReservation);
            }

            let complete_material = reservation.output_commitment.is_some() == has_output
                && (!reservation.output_bytes.is_empty()) == has_output
                && reservation.offset_contribution.is_some()
                && reservation.payout_excess_public_key.len() == 33
                && reservation
                    .private_context
                    .as_ref()
                    .is_some_and(|context| context.is_structurally_valid(has_output));
            if has_material != complete_material
                || (!has_material
                    && (reservation.output_commitment.is_some()
                        || !reservation.output_bytes.is_empty()
                        || reservation.offset_contribution.is_some()
                        || !reservation.payout_excess_public_key.is_empty()
                        || reservation.template_hash.is_some()
                        || reservation.session_share_binding_digest.is_some()
                        || reservation.participant_position.is_some()
                        || reservation.template_participants.is_some()
                        || reservation.private_context.is_some()))
                || reservation
                    .offset_contribution
                    .is_some_and(|offset| offset == [0u8; 32])
                || reservation
                    .template_hash
                    .is_some_and(|template_hash| template_hash == [0u8; 32])
            {
                return Err(DomainError::InvalidScriptlessPayoutReservation);
            }
            match reservation.state {
                ScriptlessPayoutReservationState::Reserved
                | ScriptlessPayoutReservationState::Cancelled => {
                    if reservation.template_hash.is_some()
                        || reservation.session_share_binding_digest.is_some()
                        || reservation.participant_position.is_some()
                        || reservation.template_participants.is_some()
                    {
                        return Err(DomainError::InvalidScriptlessPayoutReservation);
                    }
                }
                ScriptlessPayoutReservationState::Prepared => {
                    if reservation.template_hash.is_some()
                        || reservation.session_share_binding_digest.is_some()
                        || reservation.participant_position.is_some()
                        || reservation.template_participants.is_some()
                    {
                        return Err(DomainError::InvalidScriptlessPayoutReservation);
                    }
                }
                ScriptlessPayoutReservationState::SessionBound
                | ScriptlessPayoutReservationState::ComponentsExposed => {
                    if reservation.template_hash.is_some()
                        || reservation
                            .session_share_binding_digest
                            .is_none_or(|binding| binding == [0u8; 32])
                        || reservation
                            .participant_position
                            .is_none_or(|position| position >= SCRIPTLESS_PARTICIPANT_COUNT_V1)
                        || reservation.template_participants.is_some()
                    {
                        return Err(DomainError::InvalidScriptlessPayoutReservation);
                    }
                }
                ScriptlessPayoutReservationState::TemplateBound => {
                    if reservation
                        .template_hash
                        .is_none_or(|template_hash| template_hash == [0u8; 32])
                        || reservation
                            .session_share_binding_digest
                            .is_none_or(|binding| binding == [0u8; 32])
                        || reservation
                            .participant_position
                            .is_none_or(|position| position >= SCRIPTLESS_PARTICIPANT_COUNT_V1)
                        || reservation
                            .template_participants
                            .as_ref()
                            .is_none_or(|participants| !participants.is_structurally_valid())
                    {
                        return Err(DomainError::InvalidScriptlessPayoutReservation);
                    }
                }
                ScriptlessPayoutReservationState::AbandonedRetained => {
                    if reservation
                        .session_share_binding_digest
                        .is_none_or(|binding| binding == [0u8; 32])
                        || reservation
                            .participant_position
                            .is_none_or(|position| position >= SCRIPTLESS_PARTICIPANT_COUNT_V1)
                        || reservation.template_hash.is_some()
                            != reservation.template_participants.is_some()
                        || reservation
                            .template_participants
                            .as_ref()
                            .is_some_and(|participants| !participants.is_structurally_valid())
                    {
                        return Err(DomainError::InvalidScriptlessPayoutReservation);
                    }
                }
            }

            if has_material && has_output {
                let commitment = reservation
                    .output_commitment
                    .ok_or(DomainError::InvalidScriptlessPayoutReservation)?;
                if !output_commitments.insert(commitment) {
                    return Err(DomainError::InvalidScriptlessPayoutReservation);
                }
                let output = self
                    .outputs
                    .iter()
                    .find(|output| Some(output.id) == reservation.output_id)
                    .ok_or(DomainError::InvalidScriptlessPayoutReservation)?;
                let mut expected_blinding = [0u8; 32];
                if !reservation
                    .private_context
                    .as_ref()
                    .ok_or(DomainError::InvalidScriptlessPayoutReservation)?
                    .copy_output_blinding_to(&mut expected_blinding)
                {
                    return Err(DomainError::InvalidScriptlessPayoutReservation);
                }
                if output.account_id != self.default_account.id
                    || output.commitment != Some(commitment)
                    || output.value != reservation.payout_value_noms
                    || self.output_blinding(output.id) != Some(expected_blinding)
                {
                    return Err(DomainError::InvalidScriptlessPayoutReservation);
                }
            } else if reservation.output_id.is_some_and(|output_id| {
                self.outputs.iter().any(|output| output.id == output_id)
                    || self
                        .private_output_blindings
                        .iter()
                        .any(|secret| secret.output_id == output_id)
            }) {
                return Err(DomainError::InvalidScriptlessPayoutReservation);
            }
        }
        Ok(())
    }

    /// Upgrade pre-exposure wallet generations conservatively. This is
    /// idempotent and never lowers exposure already persisted by a newer
    /// writer.
    pub fn migrate_transaction_exposure(&mut self) -> Result<bool, DomainError> {
        match self.transaction_exposure_version {
            0 | TRANSACTION_EXPOSURE_VERSION => {
                let mut changed = self.transaction_exposure_version == 0;
                for transaction in &mut self.transactions {
                    let inferred = if self.transaction_exposure_version == 0 {
                        infer_legacy_exposure(&transaction.lifecycle, transaction.submitted)
                    } else {
                        minimum_current_exposure(&transaction.lifecycle, transaction.submitted)
                    };
                    if transaction.exposure < inferred {
                        transaction.exposure = inferred;
                        changed = true;
                    }
                }
                self.transaction_exposure_version = TRANSACTION_EXPOSURE_VERSION;
                Ok(changed)
            }
            _ => Err(DomainError::UnsupportedVersion),
        }
    }

    pub fn allocate(&mut self) -> Result<u64, DomainError> {
        let position = self
            .allocation_floor
            .checked_add(1)
            .ok_or(DomainError::AllocationOverflow)?;
        self.allocation_floor = position;
        self.non_reuse_floor = self.non_reuse_floor.max(position);
        Ok(position)
    }

    /// Burn the next domain-specific coordinate before public material exists.
    pub fn reserve_recovery_coordinate(
        &mut self,
        account: u32,
        class: RecoveryOutputClass,
    ) -> Result<ReservedRecoveryCoordinate, DomainError> {
        let floor = match class {
            RecoveryOutputClass::ReceiveRequest | RecoveryOutputClass::ReceiveSlate => {
                &mut self.recovery_allocation_floors.received
            }
            RecoveryOutputClass::Change => &mut self.recovery_allocation_floors.change,
            RecoveryOutputClass::SelfTransfer => &mut self.recovery_allocation_floors.self_transfer,
            RecoveryOutputClass::Coinbase => &mut self.recovery_allocation_floors.coinbase,
        };
        let derivation_index = floor
            .checked_add(1)
            .ok_or(DomainError::AllocationOverflow)?;
        *floor = derivation_index;
        self.non_reuse_floor = self.non_reuse_floor.max(derivation_index);
        Ok(ReservedRecoveryCoordinate {
            account,
            derivation_index,
            class,
        })
    }

    /// Rehydrate an already-burned coordinate after restart. This can never
    /// advance or lower a floor and rejects a coordinate that was not durably
    /// reserved by an earlier generation.
    pub fn resume_recovery_coordinate(
        &self,
        account: u32,
        derivation_index: u64,
        class: RecoveryOutputClass,
    ) -> Result<ReservedRecoveryCoordinate, DomainError> {
        let floor = match class {
            RecoveryOutputClass::ReceiveRequest | RecoveryOutputClass::ReceiveSlate => {
                self.recovery_allocation_floors.received
            }
            RecoveryOutputClass::Change => self.recovery_allocation_floors.change,
            RecoveryOutputClass::SelfTransfer => self.recovery_allocation_floors.self_transfer,
            RecoveryOutputClass::Coinbase => self.recovery_allocation_floors.coinbase,
        };
        if derivation_index == 0 || derivation_index > floor {
            return Err(DomainError::InvalidState);
        }
        Ok(ReservedRecoveryCoordinate {
            account,
            derivation_index,
            class,
        })
    }

    pub fn begin_scan(&mut self, target: ScanTarget) -> Result<(), DomainError> {
        target.validate()?;
        self.provisional_target = Some(target);
        self.sync_status = SyncStatus::Synchronizing;
        Ok(())
    }

    pub fn activate_scan(
        &mut self,
        target: &ScanTarget,
        observations: Vec<OutputRecord>,
    ) -> Result<(), DomainError> {
        if self.provisional_target.as_ref() != Some(target) {
            return Err(DomainError::ProvisionalTargetMismatch);
        }
        if observations.len() > MAX_OUTPUTS
            || observations
                .iter()
                .any(|output| output.account_id != self.default_account.id)
        {
            return Err(DomainError::InvalidState);
        }
        self.outputs = observations;
        self.restore_scriptless_funding_reservations()?;
        self.restore_scriptless_payout_reservations()?;
        self.cursor = Some(target.cursor());
        self.provisional_target = None;
        self.sync_status = SyncStatus::Synced;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(DomainError::GenerationOverflow)?;
        self.validate()
    }

    pub fn invalidate_scan(&mut self, reason: impl Into<String>) {
        self.provisional_target = None;
        self.sync_status = SyncStatus::RecoveryRequired {
            reason: reason.into(),
        };
    }

    pub fn balance(&self) -> BalanceProjection {
        BalanceProjection::from_outputs(&self.outputs)
    }

    /// The sole ownership classifier. There is no approved DOM derivation and
    /// value-recovery interface in this foundation, so descriptor equality is
    /// the only positive evidence. Callers that require recovery must treat
    /// `NotOwnedOrUnprovable` as `UnsupportedRecoveryEvidence`.
    pub fn classify_commitment(&self, commitment: &[u8; 33]) -> OutputOwnership {
        self.outputs
            .iter()
            .find(|output| output.commitment.as_ref() == Some(commitment))
            .cloned()
            .map(OutputOwnership::KnownLocalOutput)
            .unwrap_or(OutputOwnership::NotOwnedOrUnprovable)
    }

    pub fn mark_known_output_spent(&mut self, commitment: &[u8; 33], height: u64) -> bool {
        if let Some(output) = self
            .outputs
            .iter_mut()
            .find(|output| output.commitment.as_ref() == Some(commitment))
        {
            output.state = OutputState::Spent {
                spent_height: height,
            };
            output.reserved_by = None;
            return true;
        }
        false
    }

    /// Applies public block-output evidence only to already persisted local
    /// descriptors.  The node deliberately provides commitments rather than
    /// ownership or value claims, so an unknown commitment never becomes a
    /// wallet output.
    pub fn mark_known_outputs_confirmed(
        &mut self,
        commitments: &[[u8; 33]],
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<(), DomainError> {
        let mut seen = std::collections::BTreeSet::new();
        for commitment in commitments {
            if !seen.insert(*commitment) {
                return Err(DomainError::InvalidState);
            }
            let Some(output_index) = self
                .outputs
                .iter()
                .position(|output| output.commitment == Some(*commitment))
            else {
                continue;
            };
            if !matches!(self.outputs[output_index].state, OutputState::Spent { .. }) {
                self.outputs[output_index].state = OutputState::Confirmed;
                self.outputs[output_index].discovered_height = height;
            }
            let output_id = self.outputs[output_index].id;
            for transaction in &mut self.transactions {
                if transaction.recipient_output_id == Some(output_id)
                    && matches!(
                        transaction.lifecycle,
                        TransactionLifecycle::ResponsePrepared
                            | TransactionLifecycle::ResponseExported
                    )
                {
                    transaction.transition(
                        TransactionLifecycle::Confirmed { height, block_hash },
                        TransactionTransitionEvidence::ConfirmationEvidence,
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn output_blinding(&self, output_id: Uuid) -> Option<[u8; 32]> {
        self.private_output_blindings
            .iter()
            .find(|secret| secret.output_id == output_id)
            .map(|secret| secret.blinding)
    }

    pub fn remember_output_blinding(&mut self, output_id: Uuid, blinding: [u8; 32]) {
        if let Some(existing) = self
            .private_output_blindings
            .iter_mut()
            .find(|secret| secret.output_id == output_id)
        {
            existing.blinding = blinding;
        } else {
            self.private_output_blindings.push(PrivateOutputBlinding {
                output_id,
                blinding,
            });
        }
    }

    pub fn apply_kernel_evidence(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        kernels: &[[u8; 33]],
    ) -> Result<(), DomainError> {
        let mut seen = std::collections::BTreeSet::new();
        for kernel in kernels {
            if !seen.insert(*kernel) {
                return Err(DomainError::DuplicateKernelEvidence);
            }
            let matches = self
                .transactions
                .iter()
                .enumerate()
                .filter(|(_, transaction)| {
                    transaction.kernel_excess.as_slice() == kernel.as_slice()
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if matches.len() > 1 {
                return Err(DomainError::AmbiguousKernelEvidence);
            }
            if let Some(index) = matches.first() {
                let transaction = &mut self.transactions[*index];
                match transaction.lifecycle {
                    TransactionLifecycle::Submitted
                    | TransactionLifecycle::AcceptedNotRelayed
                    | TransactionLifecycle::InMempool
                    | TransactionLifecycle::RetransmitRequired
                    | TransactionLifecycle::Submitting
                    | TransactionLifecycle::Reorged => {
                        transaction.transition(
                            TransactionLifecycle::Confirmed { height, block_hash },
                            TransactionTransitionEvidence::ConfirmationEvidence,
                        )?;
                    }
                    TransactionLifecycle::Confirmed {
                        height: known_height,
                        block_hash: known_hash,
                    } if known_height == height && known_hash == block_hash => {}
                    TransactionLifecycle::Confirmed { .. } => {
                        transaction.transition(
                            TransactionLifecycle::ReconciliationRequired,
                            TransactionTransitionEvidence::ReconciliationEvidence,
                        )?;
                    }
                    TransactionLifecycle::ReconciliationRequired
                    | TransactionLifecycle::Draft
                    | TransactionLifecycle::InputsReserved
                    | TransactionLifecycle::RequestExported
                    | TransactionLifecycle::RequestImported
                    | TransactionLifecycle::ResponsePrepared
                    | TransactionLifecycle::ResponseExported
                    | TransactionLifecycle::ResponseImported
                    | TransactionLifecycle::Finalized
                    | TransactionLifecycle::Cancelled
                    | TransactionLifecycle::Failed => {}
                }
            }
        }
        Ok(())
    }

    pub fn rollback_confirmations_for_rescan(&mut self) -> Result<(), DomainError> {
        for transaction in &mut self.transactions {
            if matches!(
                transaction.lifecycle,
                TransactionLifecycle::Confirmed { .. }
            ) {
                transaction.transition(
                    TransactionLifecycle::Reorged,
                    TransactionTransitionEvidence::ReorgEvidence,
                )?;
            }
        }
        self.restore_reorged_reservations()?;
        Ok(())
    }

    pub fn rollback_confirmations_after_height(
        &mut self,
        safe_height: u64,
    ) -> Result<(), DomainError> {
        for transaction in &mut self.transactions {
            if matches!(
                transaction.lifecycle,
                TransactionLifecycle::Confirmed { height, .. } if height > safe_height
            ) {
                transaction.transition(
                    TransactionLifecycle::Reorged,
                    TransactionTransitionEvidence::ReorgEvidence,
                )?;
            }
        }
        self.restore_reorged_reservations()
    }

    fn restore_reorged_reservations(&mut self) -> Result<(), DomainError> {
        let reservations = self
            .transactions
            .iter()
            .filter(|transaction| transaction.lifecycle == TransactionLifecycle::Reorged)
            .map(|transaction| (transaction.id, transaction.reserved_output_ids.clone()))
            .collect::<Vec<_>>();
        for (transaction_id, output_ids) in reservations {
            for output in self
                .outputs
                .iter_mut()
                .filter(|output| output_ids.contains(&output.id))
            {
                if matches!(output.state, OutputState::Spent { .. }) {
                    continue;
                }
                if output
                    .reserved_by
                    .is_some_and(|owner| owner != transaction_id)
                {
                    return Err(DomainError::InvalidState);
                }
                output.reserved_by = Some(transaction_id);
                output.state = OutputState::PendingOutgoing;
            }
        }
        self.restore_scriptless_funding_reservations()?;
        self.restore_scriptless_payout_reservations()?;
        Ok(())
    }

    /// Restore fail-closed common-wallet reservations after a reversible chain
    /// projection moves an input back to unspent. Exposed funding components
    /// are never forgotten or made selectable by a reorg.
    pub fn restore_scriptless_funding_reservations(&mut self) -> Result<(), DomainError> {
        let reservation_indexes = self
            .scriptless_funding_reservations
            .iter()
            .enumerate()
            .filter(|(_, reservation)| reservation.state.retains_inputs())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        for reservation_index in reservation_indexes {
            let reservation = self.scriptless_funding_reservations[reservation_index].clone();
            if let (Some(output_id), Some(commitment), Some(context)) = (
                reservation.change_output_id,
                reservation.change_commitment,
                reservation.private_context.as_ref(),
            ) {
                if !self.outputs.iter().any(|output| output.id == output_id) {
                    let mut blinding = [0u8; 32];
                    if !context.copy_change_output_blinding_to(&mut blinding) {
                        return Err(DomainError::InvalidScriptlessFundingReservation);
                    }
                    self.outputs.push(OutputRecord {
                        id: output_id,
                        account_id: self.default_account.id,
                        commitment: Some(commitment),
                        value: reservation.change_value_noms,
                        state: OutputState::PendingIncoming,
                        discovered_height: 0,
                        reserved_by: None,
                    });
                    self.remember_output_blinding(output_id, blinding);
                }
            }
            for (input_index, (output_id, commitment)) in reservation
                .reserved_output_ids
                .iter()
                .zip(&reservation.input_commitments)
                .enumerate()
            {
                let exact = self
                    .outputs
                    .iter()
                    .position(|output| output.id == *output_id);
                let output_index = match exact {
                    Some(index)
                        if self.outputs[index]
                            .commitment
                            .as_ref()
                            .map(<[u8; 33]>::as_slice)
                            == Some(commitment.as_slice()) =>
                    {
                        Some(index)
                    }
                    Some(_) => return Err(DomainError::InvalidScriptlessFundingReservation),
                    None => {
                        let matches = self
                            .outputs
                            .iter()
                            .enumerate()
                            .filter(|(_, output)| {
                                output.commitment.as_ref().map(<[u8; 33]>::as_slice)
                                    == Some(commitment.as_slice())
                            })
                            .map(|(index, _)| index)
                            .collect::<Vec<_>>();
                        if matches.len() > 1 {
                            return Err(DomainError::InvalidScriptlessFundingReservation);
                        }
                        matches.first().copied()
                    }
                };
                let Some(output_index) = output_index else {
                    continue;
                };
                let rebound_id = self.outputs[output_index].id;
                self.scriptless_funding_reservations[reservation_index].reserved_output_ids
                    [input_index] = rebound_id;
                let output = &mut self.outputs[output_index];
                if matches!(output.state, OutputState::Spent { .. }) {
                    continue;
                }
                if output
                    .reserved_by
                    .is_some_and(|owner| owner != reservation.id)
                {
                    return Err(DomainError::InvalidScriptlessFundingReservation);
                }
                output.reserved_by = Some(reservation.id);
                output.state = OutputState::PendingOutgoing;
            }
        }
        Ok(())
    }

    /// Reconstruct or rebind exact wallet-owned claim/refund payout outputs
    /// after a scanner rewind. Publicly exposed components and their private
    /// spend evidence remain durable and byte-identical across restart/reorg.
    pub fn restore_scriptless_payout_reservations(&mut self) -> Result<(), DomainError> {
        let reservation_indexes = self
            .scriptless_payout_reservations
            .iter()
            .enumerate()
            .filter(|(_, reservation)| reservation.state.has_prepared_material())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        for reservation_index in reservation_indexes {
            let reservation = self.scriptless_payout_reservations[reservation_index].clone();
            let Some(output_id) = reservation.output_id else {
                if reservation.payout_value_noms != 0
                    || reservation.output_commitment.is_some()
                    || !reservation.output_bytes.is_empty()
                {
                    return Err(DomainError::InvalidScriptlessPayoutReservation);
                }
                continue;
            };
            let commitment = reservation
                .output_commitment
                .ok_or(DomainError::InvalidScriptlessPayoutReservation)?;
            let context = reservation
                .private_context
                .as_ref()
                .ok_or(DomainError::InvalidScriptlessPayoutReservation)?;
            let mut blinding = [0u8; 32];
            if !context.copy_output_blinding_to(&mut blinding) {
                return Err(DomainError::InvalidScriptlessPayoutReservation);
            }

            let exact = self
                .outputs
                .iter()
                .position(|output| output.id == output_id);
            let output_index = match exact {
                Some(index) if self.outputs[index].commitment == Some(commitment) => index,
                Some(_) => return Err(DomainError::InvalidScriptlessPayoutReservation),
                None => {
                    let matching = self
                        .outputs
                        .iter()
                        .enumerate()
                        .filter(|(_, output)| output.commitment == Some(commitment))
                        .map(|(index, _)| index)
                        .collect::<Vec<_>>();
                    if matching.len() > 1 {
                        return Err(DomainError::InvalidScriptlessPayoutReservation);
                    }
                    if let Some(index) = matching.first().copied() {
                        let rebound_id = self.outputs[index].id;
                        self.scriptless_payout_reservations[reservation_index].output_id =
                            Some(rebound_id);
                        self.private_output_blindings
                            .retain(|secret| secret.output_id != output_id);
                        index
                    } else {
                        self.outputs.push(OutputRecord {
                            id: output_id,
                            account_id: self.default_account.id,
                            commitment: Some(commitment),
                            value: reservation.payout_value_noms,
                            state: OutputState::PendingIncoming,
                            discovered_height: 0,
                            reserved_by: None,
                        });
                        self.outputs.len() - 1
                    }
                }
            };
            let output = &self.outputs[output_index];
            if output.account_id != self.default_account.id
                || output.value != reservation.payout_value_noms
            {
                return Err(DomainError::InvalidScriptlessPayoutReservation);
            }
            let output_id = output.id;
            if let Some(existing) = self.output_blinding(output_id) {
                if existing != blinding {
                    return Err(DomainError::InvalidScriptlessPayoutReservation);
                }
            } else {
                self.remember_output_blinding(output_id, blinding);
            }
        }
        Ok(())
    }

    pub fn prepare_rescan(&mut self, target: ScanTarget) -> Result<(), DomainError> {
        if self.rescan_plan.is_some() {
            return Err(DomainError::RescanAlreadyActive);
        }
        target.validate()?;
        let mut transactions = self.transactions.clone();
        for transaction in &mut transactions {
            if matches!(
                transaction.lifecycle,
                TransactionLifecycle::Confirmed { .. }
            ) {
                transaction.transition(
                    TransactionLifecycle::Reorged,
                    TransactionTransitionEvidence::ReorgEvidence,
                )?;
            }
        }
        self.rescan_plan = Some(RescanPlan {
            version: 1,
            plan_id: Uuid::new_v4(),
            wallet_id: self.wallet_id,
            identity: self.identity.clone(),
            source_identity: target.source_identity.clone(),
            recovery_start_height: target.scan_bounds.start_height,
            next_page: 0,
            next_page_height: target.scan_bounds.start_height,
            provisional_generation_id: self
                .generation
                .checked_add(1)
                .ok_or(DomainError::GenerationOverflow)?,
            retained_canonical_generation_id: self.generation,
            phase: RescanPhase::Prepared,
            provisional_outputs: self.outputs.clone(),
            provisional_transactions: transactions,
            target,
        });
        Ok(())
    }

    pub fn rescan_plan_mut(&mut self) -> Result<&mut RescanPlan, DomainError> {
        self.rescan_plan
            .as_mut()
            .ok_or(DomainError::InvalidRescanPlan)
    }

    pub fn transition_rescan(&mut self, next: RescanPhase) -> Result<(), DomainError> {
        let plan = self.rescan_plan_mut()?;
        let allowed = matches!(
            (&plan.phase, &next),
            (RescanPhase::Prepared, RescanPhase::Scanning)
                | (RescanPhase::Scanning, RescanPhase::ValidatingTarget)
                | (RescanPhase::ValidatingTarget, RescanPhase::ReadyToActivate)
                | (RescanPhase::ReadyToActivate, RescanPhase::Activating)
                | (RescanPhase::Activating, RescanPhase::Complete)
                | (
                    RescanPhase::Prepared
                        | RescanPhase::Scanning
                        | RescanPhase::ValidatingTarget
                        | RescanPhase::ReadyToActivate
                        | RescanPhase::Activating,
                    RescanPhase::Invalidated | RescanPhase::Failed
                )
        );
        if !allowed {
            return Err(DomainError::InvalidRescanTransition);
        }
        plan.phase = next;
        Ok(())
    }

    /// Advances the durable cursor only after a complete page has been applied
    /// to the provisional state. `next_page_height` is always the first height
    /// not represented by a durable page effect.
    pub fn apply_rescan_page_cursor(
        &mut self,
        page_number: u32,
        start: u64,
        end: u64,
    ) -> Result<(), DomainError> {
        let plan = self.rescan_plan_mut()?;
        if plan.phase != RescanPhase::Scanning
            || page_number != plan.next_page
            || start != plan.next_page_height
            || end < start
            || end > plan.target.target_height
        {
            return Err(DomainError::InvalidRescanPage);
        }
        let next = end.checked_add(1).ok_or(DomainError::InvalidRescanPage)?;
        if next > plan.target.target_height.saturating_add(1) {
            return Err(DomainError::InvalidRescanPage);
        }
        plan.next_page = plan
            .next_page
            .checked_add(1)
            .ok_or(DomainError::InvalidRescanPage)?;
        plan.next_page_height = next;
        if next == plan.target.target_height.saturating_add(1) {
            plan.phase = RescanPhase::ValidatingTarget;
        }
        Ok(())
    }

    pub fn activate_rescan(&mut self) -> Result<(), DomainError> {
        let plan = self
            .rescan_plan
            .take()
            .ok_or(DomainError::InvalidRescanPlan)?;
        if plan.phase != RescanPhase::Activating {
            return Err(DomainError::InvalidRescanPlan);
        }
        self.outputs = plan.provisional_outputs;
        self.transactions = plan.provisional_transactions;
        self.restore_scriptless_funding_reservations()?;
        self.restore_scriptless_payout_reservations()?;
        self.cursor = Some(plan.target.cursor());
        self.sync_status = SyncStatus::Synced;
        Ok(())
    }
}

pub mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 32 bytes"))
    }
}

pub mod serde_bytes_33 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 33 bytes"))
    }
}

pub mod serde_option_bytes_32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .as_ref()
            .map(|bytes| bytes.as_slice())
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Vec<u8>>::deserialize(deserializer)?.map_or(Ok(None), |bytes| {
            bytes
                .try_into()
                .map(Some)
                .map_err(|_| serde::de::Error::custom("expected exactly 32 bytes"))
        })
    }
}

pub mod serde_option_bytes_33 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 33]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .as_ref()
            .map(|bytes| bytes.as_slice())
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 33]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Vec<u8>>::deserialize(deserializer)?.map_or(Ok(None), |bytes| {
            bytes
                .try_into()
                .map(Some)
                .map_err(|_| serde::de::Error::custom("expected exactly 33 bytes"))
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    #[error("unsupported schema or profile version")]
    UnsupportedVersion,
    #[error("invalid canonical wallet state")]
    InvalidState,
    #[error("invalid node configuration")]
    InvalidNodeConfiguration,
    #[error("TLS is required for the configured endpoint")]
    TlsRequired,
    #[error("wallet and node identity differ")]
    IdentityMismatch,
    #[error("invalid ScanTarget")]
    InvalidScanTarget,
    #[error("invalid scan bounds")]
    InvalidScanBounds,
    #[error("provisional ScanTarget differs from the activation target")]
    ProvisionalTargetMismatch,
    #[error("allocation floor overflow")]
    AllocationOverflow,
    #[error("generation overflow")]
    GenerationOverflow,
    #[error("non-reuse floor regressed")]
    NonReuseFloorRegression,
    #[error("invalid local transaction intent")]
    InvalidTransactionIntent,
    #[error("invalid Scriptless funding reservation")]
    InvalidScriptlessFundingReservation,
    #[error("invalid Scriptless claim/refund payout reservation")]
    InvalidScriptlessPayoutReservation,
    #[error("invalid transaction lifecycle transition")]
    InvalidTransactionTransition,
    #[error("duplicate kernel evidence")]
    DuplicateKernelEvidence,
    #[error("kernel evidence maps to multiple local transactions")]
    AmbiguousKernelEvidence,
    #[error("invalid rescan plan")]
    InvalidRescanPlan,
    #[error("a rescan is already active")]
    RescanAlreadyActive,
    #[error("invalid rescan phase transition")]
    InvalidRescanTransition,
    #[error("invalid rescan page cursor")]
    InvalidRescanPage,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_lifecycles() -> Vec<TransactionLifecycle> {
        vec![
            TransactionLifecycle::Draft,
            TransactionLifecycle::InputsReserved,
            TransactionLifecycle::RequestExported,
            TransactionLifecycle::RequestImported,
            TransactionLifecycle::ResponsePrepared,
            TransactionLifecycle::ResponseExported,
            TransactionLifecycle::ResponseImported,
            TransactionLifecycle::Finalized,
            TransactionLifecycle::Submitting,
            TransactionLifecycle::Submitted,
            TransactionLifecycle::AcceptedNotRelayed,
            TransactionLifecycle::InMempool,
            TransactionLifecycle::Confirmed {
                height: 7,
                block_hash: [7; 32],
            },
            TransactionLifecycle::Reorged,
            TransactionLifecycle::RetransmitRequired,
            TransactionLifecycle::Cancelled,
            TransactionLifecycle::Failed,
            TransactionLifecycle::ReconciliationRequired,
        ]
    }

    fn transaction_in(lifecycle: TransactionLifecycle) -> LocalTransactionIntent {
        LocalTransactionIntent {
            id: Uuid::nil(),
            created_at_height: 0,
            created_at_unix_seconds: 0,
            cancellation_reason: None,
            cancelled_at_height: None,
            kernel_excess: Vec::new(),
            lifecycle,
            submitted: false,
            exposure: BroadcastExposure::NeverBroadcast,
            slate_id: None,
            role: None,
            amount: 0,
            fee: 0,
            reserved_output_ids: Vec::new(),
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
            expires_at_height: 0,
        }
    }

    #[test]
    fn regression_c2_exhaustive_lifecycle_exposure_cancellation_invariant() {
        let exposures = [
            BroadcastExposure::NeverBroadcast,
            BroadcastExposure::SubmissionStarted,
            BroadcastExposure::PossiblyRelayed,
            BroadcastExposure::ObservedInMempool,
            BroadcastExposure::Confirmed,
        ];
        for lifecycle in all_lifecycles() {
            for exposure in exposures {
                let decision = cancellation_decision(exposure);
                assert_eq!(
                    decision == CancellationDecision::ReleaseNeverBroadcastReservations,
                    exposure == BroadcastExposure::NeverBroadcast,
                    "{lifecycle:?} with {exposure:?}"
                );
            }
            let inferred = infer_legacy_exposure(&lifecycle, false);
            let expected_exposed = matches!(
                lifecycle,
                TransactionLifecycle::Submitting
                    | TransactionLifecycle::Submitted
                    | TransactionLifecycle::AcceptedNotRelayed
                    | TransactionLifecycle::InMempool
                    | TransactionLifecycle::RetransmitRequired
                    | TransactionLifecycle::ReconciliationRequired
                    | TransactionLifecycle::Reorged
                    | TransactionLifecycle::Failed
                    | TransactionLifecycle::Confirmed { .. }
            );
            assert_eq!(
                inferred != BroadcastExposure::NeverBroadcast,
                expected_exposed
            );
            assert_ne!(
                infer_legacy_exposure(&lifecycle, true),
                BroadcastExposure::NeverBroadcast
            );
        }
    }

    #[test]
    fn regression_c4_transition_table_is_exhaustive_and_cancelled_is_terminal() {
        let evidence = [
            TransactionTransitionEvidence::LocalConstruction,
            TransactionTransitionEvidence::RecipientResponse,
            TransactionTransitionEvidence::Finalization,
            TransactionTransitionEvidence::SubmissionStarted,
            TransactionTransitionEvidence::SubmissionOutcome,
            TransactionTransitionEvidence::MempoolObservation,
            TransactionTransitionEvidence::ConfirmationEvidence,
            TransactionTransitionEvidence::ReorgEvidence,
            TransactionTransitionEvidence::ReconciliationEvidence,
            TransactionTransitionEvidence::Cancellation,
        ];
        for current in all_lifecycles() {
            for next in all_lifecycles() {
                for reason in evidence {
                    let mut transaction = transaction_in(current);
                    let result = transaction.transition(next, reason);
                    if current == TransactionLifecycle::Cancelled
                        && next != TransactionLifecycle::Cancelled
                    {
                        assert!(result.is_err());
                    }
                    if matches!(current, TransactionLifecycle::Confirmed { .. })
                        && next == TransactionLifecycle::Reorged
                    {
                        assert_eq!(
                            result.is_ok(),
                            reason == TransactionTransitionEvidence::ReorgEvidence
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn regression_c2_legacy_exposure_migration_is_conservative_and_idempotent() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        state.transaction_exposure_version = 0;
        state
            .transactions
            .push(transaction_in(TransactionLifecycle::RetransmitRequired));
        assert!(state.migrate_transaction_exposure().unwrap());
        assert_eq!(
            state.transactions[0].exposure,
            BroadcastExposure::PossiblyRelayed
        );
        assert!(!state.migrate_transaction_exposure().unwrap());

        let mut legacy = WalletState::new(identity(), [7; 32], configuration());
        legacy.transaction_exposure_version = 0;
        legacy
            .transactions
            .push(transaction_in(TransactionLifecycle::RetransmitRequired));
        let mut legacy_json = serde_json::to_value(legacy).unwrap();
        let object = legacy_json.as_object_mut().unwrap();
        object.remove("transaction_exposure_version");
        object["transactions"][0]
            .as_object_mut()
            .unwrap()
            .remove("exposure");
        let mut deserialized: WalletState = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(deserialized.transaction_exposure_version, 0);
        assert_eq!(
            deserialized.transactions[0].exposure,
            BroadcastExposure::NeverBroadcast
        );
        assert!(deserialized.migrate_transaction_exposure().unwrap());
        assert_eq!(
            deserialized.transactions[0].exposure,
            BroadcastExposure::PossiblyRelayed
        );

        let mut current_version = WalletState::new(identity(), [7; 32], configuration());
        current_version
            .transactions
            .push(transaction_in(TransactionLifecycle::Submitting));
        assert!(current_version.validate().is_err());
        assert!(current_version.migrate_transaction_exposure().unwrap());
        assert_eq!(
            current_version.transactions[0].exposure,
            BroadcastExposure::SubmissionStarted
        );
        current_version.validate().unwrap();
    }

    fn identity() -> NetworkIdentity {
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [1; 32],
            genesis_id: [2; 32],
        }
    }

    fn configuration() -> NodeConfiguration {
        NodeConfiguration {
            endpoint_url: "https://node.invalid".into(),
            expected_identity: identity(),
            source_identity: "mock-a".into(),
            api_compatibility_version: 1,
            connect_timeout_ms: 100,
            request_timeout_ms: 100,
            poll_interval_ms: 10,
            retry_ceiling: 3,
            max_backoff_ms: 100,
            stable_success_threshold: 2,
            tls_required: true,
            credential_reference: Some("environment:DOM_NODE_TOKEN".into()),
        }
    }

    #[test]
    fn allocation_and_non_reuse_floors_are_monotonic() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        assert_eq!(state.allocate().unwrap(), 1);
        assert_eq!(state.allocate().unwrap(), 2);
        assert_eq!(state.non_reuse_floor, 2);
        assert!(state.validate().is_ok());
    }

    #[test]
    fn scan_activation_needs_the_same_provisional_target() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let target = ScanTarget {
            target_height: 4,
            target_block_hash: [4; 32],
            source_identity: "mock-a".into(),
            scan_bounds: ScanBounds {
                start_height: 0,
                end_height: 4,
                max_pages: 2,
                max_records_per_page: 10,
            },
            evidence_version: 1,
        };
        state.begin_scan(target.clone()).unwrap();
        let wrong = ScanTarget {
            target_block_hash: [5; 32],
            ..target.clone()
        };
        assert_eq!(
            state.activate_scan(&wrong, Vec::new()),
            Err(DomainError::ProvisionalTargetMismatch)
        );
        state.activate_scan(&target, Vec::new()).unwrap();
        assert_eq!(state.cursor, Some(target.cursor()));
    }

    #[test]
    fn descriptor_ownership_and_spend_are_exact_and_fail_closed() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let commitment = [9; 33];
        state.outputs.push(OutputRecord {
            id: Uuid::new_v4(),
            account_id: state.default_account.id,
            commitment: Some(commitment),
            value: 42,
            state: OutputState::Confirmed,
            discovered_height: 3,
            reserved_by: None,
        });
        assert!(matches!(
            state.classify_commitment(&commitment),
            OutputOwnership::KnownLocalOutput(_)
        ));
        assert_eq!(
            state.classify_commitment(&[8; 33]),
            OutputOwnership::NotOwnedOrUnprovable
        );
        assert!(state.mark_known_output_spent(&commitment, 4));
        assert!(matches!(
            state.outputs[0].state,
            OutputState::Spent { spent_height: 4 }
        ));
    }

    #[test]
    fn kernel_evidence_confirms_only_existing_intent_and_conflicts_reconcile() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        state.transactions.push(LocalTransactionIntent {
            id: Uuid::new_v4(),
            created_at_height: 0,
            created_at_unix_seconds: 0,
            cancellation_reason: None,
            cancelled_at_height: None,
            kernel_excess: vec![3; 33],
            lifecycle: TransactionLifecycle::Submitted,
            submitted: true,
            exposure: BroadcastExposure::PossiblyRelayed,
            slate_id: None,
            role: None,
            amount: 0,
            fee: 0,
            reserved_output_ids: Vec::new(),
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
            expires_at_height: 0,
        });
        state
            .apply_kernel_evidence(8, [8; 32], &[[3; 33], [4; 33]])
            .unwrap();
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::Confirmed {
                height: 8,
                block_hash: [8; 32]
            }
        );
        state.apply_kernel_evidence(8, [8; 32], &[[3; 33]]).unwrap();
        state.apply_kernel_evidence(9, [9; 32], &[[3; 33]]).unwrap();
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::ReconciliationRequired
        );
    }

    #[test]
    fn canonical_output_evidence_confirms_only_persisted_recipient_descriptor() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let output_id = Uuid::new_v4();
        state.outputs.push(OutputRecord {
            id: output_id,
            account_id: state.default_account.id,
            commitment: Some([5; 33]),
            value: 600_000,
            state: OutputState::PendingIncoming,
            discovered_height: 0,
            reserved_by: None,
        });
        state.transactions.push(LocalTransactionIntent {
            id: Uuid::new_v4(),
            created_at_height: 0,
            created_at_unix_seconds: 0,
            cancellation_reason: None,
            cancelled_at_height: None,
            kernel_excess: Vec::new(),
            lifecycle: TransactionLifecycle::ResponseExported,
            submitted: false,
            exposure: BroadcastExposure::NeverBroadcast,
            slate_id: Some(Uuid::new_v4()),
            role: Some(TransactionRole::Recipient),
            amount: 600_000,
            fee: 50_000,
            reserved_output_ids: Vec::new(),
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: Some(output_id),
            change_output_id: None,
            expires_at_height: 0,
        });
        state
            .mark_known_outputs_confirmed(&[[5; 33], [6; 33]], 12, [7; 32])
            .unwrap();
        assert_eq!(state.outputs.len(), 1);
        assert_eq!(state.outputs[0].state, OutputState::Confirmed);
        assert_eq!(state.outputs[0].discovered_height, 12);
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::Confirmed {
                height: 12,
                block_hash: [7; 32]
            }
        );
    }

    #[test]
    fn rescan_plan_is_durable_state_until_ready_activation() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let target = ScanTarget {
            target_height: 0,
            target_block_hash: [9; 32],
            source_identity: "mock-a".into(),
            scan_bounds: ScanBounds {
                start_height: 0,
                end_height: 0,
                max_pages: 1,
                max_records_per_page: 10,
            },
            evidence_version: 1,
        };
        state.prepare_rescan(target).unwrap();
        assert_eq!(
            state.rescan_plan.as_ref().unwrap().phase,
            RescanPhase::Prepared
        );
        state.transition_rescan(RescanPhase::Scanning).unwrap();
        state
            .transition_rescan(RescanPhase::ValidatingTarget)
            .unwrap();
        state
            .transition_rescan(RescanPhase::ReadyToActivate)
            .unwrap();
        state.transition_rescan(RescanPhase::Activating).unwrap();
        state.activate_rescan().unwrap();
        assert!(state.rescan_plan.is_none());
    }

    #[test]
    fn page_cursor_accepts_only_the_next_complete_page() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let target = ScanTarget {
            target_height: 1,
            target_block_hash: [9; 32],
            source_identity: "mock-a".into(),
            scan_bounds: ScanBounds {
                start_height: 0,
                end_height: 1,
                max_pages: 2,
                max_records_per_page: 10,
            },
            evidence_version: 1,
        };
        state.prepare_rescan(target).unwrap();
        state.transition_rescan(RescanPhase::Scanning).unwrap();
        assert!(state.apply_rescan_page_cursor(0, 1, 1).is_err());
        state.apply_rescan_page_cursor(0, 0, 0).unwrap();
        state.apply_rescan_page_cursor(1, 1, 1).unwrap();
        assert_eq!(
            state.rescan_plan.as_ref().unwrap().phase,
            RescanPhase::ValidatingTarget
        );
    }

    #[test]
    fn recovery_schema_fields_default_for_existing_encrypted_state() {
        let state = WalletState::new(identity(), [7; 32], configuration());
        let mut value = serde_json::to_value(&state).unwrap();
        let object = value.as_object_mut().unwrap();
        for field in [
            "core_scan_cursor",
            "recovery_canonical_blocks",
            "recovered_accounts",
            "recovered_output_metadata",
            "seed_restore_status",
            "legacy_proof_only_outputs",
            "recovery_scanned_blocks",
            "recovery_scanned_outputs",
            "scriptless_funding_reservations",
            "scriptless_payout_reservations",
        ] {
            object.remove(field);
        }
        let decoded: WalletState = serde_json::from_value(value).unwrap();
        assert!(decoded.core_scan_cursor.is_none());
        assert!(decoded.recovery_canonical_blocks.is_empty());
        assert!(decoded.recovered_accounts.is_empty());
        assert!(decoded.recovered_output_metadata.is_empty());
        assert!(decoded.seed_restore_status.is_none());
        assert_eq!(decoded.legacy_proof_only_outputs, 0);
        assert_eq!(decoded.recovery_scanned_blocks, 0);
        assert_eq!(decoded.recovery_scanned_outputs, 0);
        assert!(decoded.scriptless_funding_reservations.is_empty());
        assert!(decoded.scriptless_payout_reservations.is_empty());
        decoded.validate().unwrap();

        let mut legacy_transaction =
            serde_json::to_value(transaction_in(TransactionLifecycle::InputsReserved)).unwrap();
        let transaction = legacy_transaction.as_object_mut().unwrap();
        for field in [
            "created_at_height",
            "created_at_unix_seconds",
            "cancellation_reason",
            "cancelled_at_height",
        ] {
            transaction.remove(field);
        }
        let decoded: LocalTransactionIntent = serde_json::from_value(legacy_transaction).unwrap();
        assert_eq!(decoded.created_at_height, 0);
        assert_eq!(decoded.created_at_unix_seconds, 0);
        assert!(decoded.cancellation_reason.is_none());
        assert!(decoded.cancelled_at_height.is_none());
    }

    #[test]
    fn scriptless_claim_and_refund_payouts_are_distinct_and_reorg_restorable() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        let session_id = [8u8; 32];
        for (marker, role, refund_lock_height) in [
            (3u8, ScriptlessPayoutRoleV1::Claim, 0u64),
            (4u8, ScriptlessPayoutRoleV1::Refund, 42u64),
        ] {
            let coordinate = state
                .reserve_recovery_coordinate(0, RecoveryOutputClass::SelfTransfer)
                .unwrap();
            let reservation_id = Uuid::new_v4();
            let output_id = Uuid::new_v4();
            let commitment = [marker; 33];
            let output_blinding = [marker.saturating_add(20); 32];
            state.outputs.push(OutputRecord {
                id: output_id,
                account_id: state.default_account.id,
                commitment: Some(commitment),
                value: 900,
                state: OutputState::PendingIncoming,
                discovered_height: 0,
                reserved_by: None,
            });
            state.remember_output_blinding(output_id, output_blinding);
            state
                .scriptless_payout_reservations
                .push(ScriptlessPayoutReservation {
                    version: SCRIPTLESS_PAYOUT_RESERVATION_VERSION,
                    id: reservation_id,
                    session_id,
                    role,
                    created_at_height: 1,
                    shared_output_commitment: [9; 33],
                    payout_value_noms: 900,
                    kernel_fee_noms: 100,
                    expected_output_count: 2,
                    refund_lock_height,
                    output_id: Some(output_id),
                    derivation_index: Some(coordinate.derivation_index()),
                    output_commitment: Some(commitment),
                    output_bytes: vec![marker; 16],
                    offset_contribution: Some([marker.saturating_add(1); 32]),
                    payout_excess_public_key: vec![marker.saturating_add(2); 33],
                    template_hash: None,
                    session_share_binding_digest: Some([marker.saturating_add(4); 32]),
                    participant_position: Some(0),
                    template_participants: None,
                    private_context: Some(PrivateScriptlessPayoutContext::new(
                        [marker.saturating_add(3); 32],
                        Some(output_blinding),
                    )),
                    state: ScriptlessPayoutReservationState::ComponentsExposed,
                });
        }
        state.validate().unwrap();
        assert_ne!(
            state.scriptless_payout_reservations[0].derivation_index,
            state.scriptless_payout_reservations[1].derivation_index
        );

        let removed_output = state.scriptless_payout_reservations[0].output_id.unwrap();
        state.outputs.retain(|output| output.id != removed_output);
        state
            .private_output_blindings
            .retain(|secret| secret.output_id != removed_output);
        state.restore_scriptless_payout_reservations().unwrap();
        state.validate().unwrap();
        assert!(state
            .outputs
            .iter()
            .any(|output| output.id == removed_output));

        state.scriptless_payout_reservations[0].template_hash = Some([12; 32]);
        state.scriptless_payout_reservations[0].session_share_binding_digest = Some([11; 32]);
        state.scriptless_payout_reservations[0].template_participants = Some(
            ScriptlessTemplateParticipantBindingV1::new([[1; 32], [2; 32]], [[3; 33], [4; 33]]),
        );
        state.scriptless_payout_reservations[0].state =
            ScriptlessPayoutReservationState::TemplateBound;
        state.validate().unwrap();
        state.scriptless_payout_reservations[0].participant_position = Some(2);
        assert_eq!(
            state.validate(),
            Err(DomainError::InvalidScriptlessPayoutReservation)
        );
        state.scriptless_payout_reservations[0].participant_position = Some(0);
        state.scriptless_payout_reservations[0]
            .template_participants
            .as_mut()
            .unwrap()
            .ordered_kernel_excess_points
            .pop();
        assert_eq!(
            state.validate(),
            Err(DomainError::InvalidScriptlessPayoutReservation)
        );
        state.scriptless_payout_reservations[0]
            .template_participants
            .as_mut()
            .unwrap()
            .ordered_kernel_excess_points
            .push(vec![4; 33]);
        state.validate().unwrap();

        let output_count = state.outputs.len();
        state
            .scriptless_payout_reservations
            .push(ScriptlessPayoutReservation {
                version: SCRIPTLESS_PAYOUT_RESERVATION_VERSION,
                id: Uuid::new_v4(),
                session_id: [13; 32],
                role: ScriptlessPayoutRoleV1::Claim,
                created_at_height: 1,
                shared_output_commitment: [14; 33],
                payout_value_noms: 0,
                kernel_fee_noms: 100,
                expected_output_count: 1,
                refund_lock_height: 0,
                output_id: None,
                derivation_index: None,
                output_commitment: None,
                output_bytes: Vec::new(),
                offset_contribution: Some([15; 32]),
                payout_excess_public_key: vec![16; 33],
                template_hash: None,
                session_share_binding_digest: Some([18; 32]),
                participant_position: Some(1),
                template_participants: None,
                private_context: Some(PrivateScriptlessPayoutContext::new([17; 32], None)),
                state: ScriptlessPayoutReservationState::ComponentsExposed,
            });
        state.validate().unwrap();
        state.restore_scriptless_payout_reservations().unwrap();
        assert_eq!(state.outputs.len(), output_count);

        let mut duplicate_role = state.scriptless_payout_reservations[0].clone();
        duplicate_role.id = Uuid::new_v4();
        duplicate_role.output_id = Some(Uuid::new_v4());
        duplicate_role.output_commitment = Some([7; 33]);
        duplicate_role.output_bytes = vec![7; 16];
        duplicate_role.offset_contribution = Some([8; 32]);
        duplicate_role.payout_excess_public_key = vec![9; 33];
        duplicate_role.private_context = Some(PrivateScriptlessPayoutContext::new(
            [10; 32],
            Some([11; 32]),
        ));
        state.outputs.push(OutputRecord {
            id: duplicate_role.output_id.unwrap(),
            account_id: state.default_account.id,
            commitment: duplicate_role.output_commitment,
            value: duplicate_role.payout_value_noms,
            state: OutputState::PendingIncoming,
            discovered_height: 0,
            reserved_by: None,
        });
        state.remember_output_blinding(duplicate_role.output_id.unwrap(), [11; 32]);
        state.scriptless_payout_reservations.push(duplicate_role);
        assert_eq!(
            state.validate(),
            Err(DomainError::InvalidScriptlessPayoutReservation)
        );
    }

    #[test]
    fn scriptless_zero_debit_funding_signer_has_no_wallet_input_or_output() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        state
            .scriptless_funding_reservations
            .push(ScriptlessFundingReservation {
                version: SCRIPTLESS_FUNDING_RESERVATION_VERSION,
                id: Uuid::new_v4(),
                session_id: [18; 32],
                shared_output_commitment: [22; 33],
                created_at_height: 1,
                local_debit_noms: 0,
                funding_fee_noms: 100,
                expected_input_count: 1,
                expected_output_count: 1,
                reserved_output_ids: Vec::new(),
                input_commitments: Vec::new(),
                change_value_noms: 0,
                change_derivation_index: None,
                change_output_id: None,
                change_commitment: None,
                change_output_bytes: Vec::new(),
                offset_contribution: Some([19; 32]),
                wallet_excess_public_key: vec![20; 33],
                template_hash: None,
                session_share_binding_digest: Some([22; 32]),
                participant_position: Some(1),
                template_participants: None,
                private_context: Some(PrivateScriptlessFundingContext::new([21; 32], None)),
                state: ScriptlessFundingReservationState::Exported,
            });
        state.validate().unwrap();
        assert!(state.outputs.is_empty());
        state.restore_scriptless_funding_reservations().unwrap();
        assert!(state.outputs.is_empty());

        // The usual request carries the frozen aggregate input count, but a
        // strictly local no-input description remains valid. Binding to the
        // real funding template later still requires at least one aggregate
        // input and the shared output.
        state.scriptless_funding_reservations[0].expected_input_count = 0;
        state.validate().unwrap();

        state.scriptless_funding_reservations[0].template_hash = Some([23; 32]);
        state.scriptless_funding_reservations[0].session_share_binding_digest = Some([24; 32]);
        state.scriptless_funding_reservations[0].template_participants = Some(
            ScriptlessTemplateParticipantBindingV1::new([[1; 32], [2; 32]], [[3; 33], [4; 33]]),
        );
        state.scriptless_funding_reservations[0].state =
            ScriptlessFundingReservationState::TemplateBound;
        state.validate().unwrap();
        state.scriptless_funding_reservations[0].participant_position = Some(2);
        assert_eq!(
            state.validate(),
            Err(DomainError::InvalidScriptlessFundingReservation)
        );
        state.scriptless_funding_reservations[0].participant_position = Some(1);
        state.scriptless_funding_reservations[0]
            .template_participants
            .as_mut()
            .unwrap()
            .ordered_offset_contributions[0] = vec![0; 32];
        assert_eq!(
            state.validate(),
            Err(DomainError::InvalidScriptlessFundingReservation)
        );
    }

    #[test]
    fn spent_outputs_do_not_inflate_current_balance() {
        let mut state = WalletState::new(identity(), [7; 32], configuration());
        state.outputs.push(OutputRecord {
            id: Uuid::new_v4(),
            account_id: state.default_account.id,
            commitment: Some([8; 33]),
            value: 42,
            state: OutputState::Spent { spent_height: 5 },
            discovered_height: 2,
            reserved_by: None,
        });
        assert_eq!(state.balance(), BalanceProjection::default());
    }
}

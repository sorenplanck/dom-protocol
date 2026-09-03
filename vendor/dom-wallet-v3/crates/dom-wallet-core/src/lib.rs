#![forbid(unsafe_code)]

//! Production Wallet orchestration over the frozen embedded DOM Core boundary.

use dom_adaptor::{
    aggregate_transaction_offset_contributions_v1, ContractTxRoleV1,
    ScriptlessTransactionTemplateV1, SessionBlindingShareCapabilityV1,
};
use dom_consensus::{Transaction, TransactionInput, TransactionOutput};
use dom_core::{KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
use dom_crypto::{scriptless_add_public_points, PublicKey};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_slate::{
    sender_excess_blinding, CoverLockOutcomeV1, CoverLockPolicyV1, ValidatedChainSnapshotV1,
};
use dom_wallet_core_api::WalletScanCursor;
use dom_wallet_core_protocol::{
    AddressIdentityPurpose, CanonicalSlate, ProtocolAdapterError, SlatePhase, WalletAddress,
    WalletTransactionShape,
};
use dom_wallet_core_recovery::{
    finalize_recoverable_transaction, verify_recoverable_transaction_against_response,
    BoundScriptlessSigningContextV1, CanonicalWalletSeed, OpaqueScriptlessFundingExcessV1,
    OpaqueScriptlessPayoutExcessV1, RecoverableOutputBuilder, RecoverableSenderParts,
    ScriptlessFundingSigningCapabilityV1, ScriptlessPayoutSigningCapabilityV1,
    VerifiedRecoverableTransaction, WalletSlateInput, CANONICAL_TRANSACTION_OUTPUT_SIZE,
};
pub use dom_wallet_core_recovery::{PhraseProblem, CANONICAL_PHRASE_WORDS};
use dom_wallet_core_restore::{
    apply_recovery_batch, offline_restore_state, rewind_recovery_state, SeedRestoreError,
    SeedRestoreResult,
};
use dom_wallet_core_submit::{
    CanonicalTransactionSubmission, WalletSubmissionOutcome, WalletSubmissionQuery,
    WalletTransactionIdentifier, WalletTransactionStatus,
};
use dom_wallet_core_sync::{
    CoreBlockReference, CoreChainIdentity, CoreCursorBytes, CoreScanBatch, CoreScanTransactionSink,
    PersistedCoreCursorState,
};
use dom_wallet_crypto::{KdfParameters, SecretBytes};
use dom_wallet_domain::{
    cancellation_decision, BalanceProjection, BroadcastExposure, CancellationDecision,
    LocalTransactionIntent, MiningPreferences, Network, NetworkIdentity, NodeConfiguration,
    OutputRecord, OutputState, PrivateScriptlessFundingContext, PrivateScriptlessPayoutContext,
    PrivateTransactionContext, RecoveryMetadata, RecoveryOutputClass, RedactedNodeConfiguration,
    ScriptlessFundingReservation, ScriptlessFundingReservationState, ScriptlessPayoutReservation,
    ScriptlessPayoutReservationState, ScriptlessPayoutRoleV1,
    ScriptlessTemplateParticipantBindingV1, SeedRestoreStatus, SyncStatus,
    TransactionCancellationReason, TransactionLifecycle, TransactionRole,
    TransactionTransitionEvidence, WalletState, RECOVERY_SCHEME_BIP39_256_V1,
    SCRIPTLESS_FUNDING_RESERVATION_VERSION, SCRIPTLESS_PARTICIPANT_COUNT_V1,
    SCRIPTLESS_PAYOUT_RESERVATION_VERSION,
};
use dom_wallet_embedded_core::{EmbeddedCoreConfiguration, EmbeddedPeerStatus};
use dom_wallet_production_backend::{ProductionBackendError, PRODUCTION_BACKEND_KIND};
pub use dom_wallet_production_backend::{ProductionWalletBackend, REMOTE_BACKEND_KIND};
use dom_wallet_storage::{
    default_node_configuration, StorageError, WalletDirectory, WalletMetadata,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{
    fmt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Explicit maximum lifetime for interactive Slate negotiation, measured from
/// the authoritative canonical tip observed at each negotiation boundary.
/// This does not expire a finalized transaction: its independently persisted
/// bytes remain valid, and a kernel `lock_height` may legitimately be later.
pub const MAX_TRANSACTION_LIFETIME_BLOCKS: u64 = 1_440;

pub const MAINNET_CHAIN_ID_HEX: &str =
    "f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b";
pub const MAINNET_GENESIS_HASH_HEX: &str =
    "182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplicationState {
    Closed,
    Locked,
    Unlocking,
    Unlocked,
    Synchronizing,
    Degraded { reason: String },
    Error { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletSummary {
    pub wallet_id: Uuid,
    pub network: Network,
    pub generation: u64,
    pub cursor_height: Option<u64>,
    /// Canonical tip height observed by the last committed scan batch or, when
    /// no batch has committed yet, by the embedded Core identity.
    #[serde(default)]
    pub tip_height: Option<u64>,
    /// Redacted seed-restore progress: `in_progress` while the canonical
    /// recovery scan is still catching up, `complete` afterwards.
    #[serde(default)]
    pub seed_restore_status: Option<String>,
    /// Partial balances are exposed while synchronizing; they grow per batch.
    pub balance: BalanceProjection,
    pub state: String,
    pub experimental: bool,
    pub unaudited: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSnapshot {
    pub application_state: String,
    pub connection_state: String,
    pub generation: Option<u64>,
    pub cursor_height: Option<u64>,
    pub cursor_hash: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    pub source_identity: String,
    pub network: Network,
    pub tip_height: u64,
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionSummary {
    pub id: Uuid,
    pub slate_id: Option<Uuid>,
    pub created_at_height: Option<u64>,
    pub created_at_unix_seconds: Option<u64>,
    pub role: Option<String>,
    pub state: String,
    pub amount: u64,
    pub fee: u64,
    pub kernel_excess: Option<String>,
    pub transaction_hash: Option<String>,
    pub attempt_count: u32,
    pub expires_at_height: u64,
    pub has_finalized_transaction: bool,
    pub manual_cancel_allowed: bool,
    pub manual_cancel_warning: bool,
    pub awaiting_broadcast_confirmation: bool,
    pub cancellation_reason: Option<String>,
    pub cancelled_at_height: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeeEstimate {
    pub amount: u64,
    pub selected_input_count: u32,
    pub expected_output_count: u32,
    pub weight: u32,
    pub minimum_fee: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FundingPreflight {
    pub amount: u64,
    pub spendable: u64,
    pub selected_input_count: u32,
    pub estimated_fee: u64,
    pub fundable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlateExport {
    pub transaction_id: Uuid,
    pub slate_id: Uuid,
    pub text: String,
}

/// Exact finalized bytes exchanged only after the normal Slate response.
/// All fields are public chain data; no participant secret is included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedTransactionExport {
    pub transaction_id: Uuid,
    pub slate_id: Uuid,
    pub canonical_bytes: Vec<u8>,
    pub transaction_hash: [u8; 32],
}

/// Observable result of the ordinary-send cover decision made before a Slate
/// exists. A fallback is explicit so G-COVER can count it; it is never hidden
/// as a successful cover send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverSendDecision {
    HeightLocked { lock_height: u64 },
    NotSelectedPlain,
    NoSatisfiedHeightPlainFallback,
}

/// Public result of constructing an eligible ordinary send under G-COVER.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverSendResult {
    pub transaction: TransactionSummary,
    pub decision: CoverSendDecision,
}

/// Frozen request from the independent Scriptless session/store to the common
/// wallet. `local_debit_noms` is this participant's assigned reduction in
/// wallet value; across all participants it must equal shared-output value plus
/// the single funding fee. The authoritative Scriptless transaction builder
/// proves that final balance equation before signing.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ScriptlessFundingReservationRequestV1 {
    pub session_id: [u8; 32],
    /// Exact collaborative output the aggregate funding template must create.
    pub shared_output_commitment: [u8; 33],
    /// Zero explicitly represents the non-paying participant's required
    /// `e_i = -offset_i` contribution and selects no wallet input.
    pub local_debit_noms: u64,
    pub funding_fee_noms: u64,
    /// Frozen aggregate funding shape used for the real node fee-policy check.
    pub expected_input_count: u32,
    /// Frozen aggregate count including the one global shared output exactly
    /// once, plus every participant's ordinary change outputs.
    pub expected_output_count: u32,
}

impl fmt::Debug for ScriptlessFundingReservationRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptlessFundingReservationRequestV1")
            .field("session_id", &"[REDACTED]")
            .field("shared_output_commitment", &"[PUBLIC COMMITMENT]")
            .field("amounts", &"[REDACTED]")
            .field("expected_input_count", &self.expected_input_count)
            .field("expected_output_count", &self.expected_output_count)
            .finish()
    }
}

/// Redacted durable state returned by reservation lifecycle operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptlessFundingReservationSummaryV1 {
    pub reservation_id: Uuid,
    pub state: ScriptlessFundingReservationState,
    pub selected_input_count: u32,
    pub has_change: bool,
    pub template_bound: bool,
}

/// Exact normal-DOM components handed to
/// `dom_adaptor::ScriptlessTransactionTemplateV1::funding` by the independent
/// Scriptless orchestrator. No scalar, seed, nonce, value opening or recovery
/// key is present.
#[derive(Clone, Eq, PartialEq)]
pub struct ScriptlessFundingCompositionV1 {
    pub reservation_id: Uuid,
    pub session_id: [u8; 32],
    pub chain_id: [u8; 32],
    pub shared_output_commitment: [u8; 33],
    pub inputs: Vec<TransactionInput>,
    pub other_outputs: Vec<TransactionOutput>,
    pub offset_contribution: [u8; 32],
    pub wallet_excess_public_key: [u8; 33],
    pub funding_fee_noms: u64,
    pub expected_input_count: u32,
    pub expected_output_count: u32,
}

/// Complete canonical two-party public decomposition used when binding a real
/// DOM Scriptless template. The aggregate values already appear in the
/// transaction, but both ordered local contributions are required so each
/// wallet can prove that the coordinator did not omit or replace its slot.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ScriptlessTemplateParticipantSetV1 {
    pub ordered_offset_contributions: [[u8; 32]; 2],
    pub ordered_kernel_excess_points: [[u8; 33]; 2],
}

impl fmt::Debug for ScriptlessTemplateParticipantSetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptlessTemplateParticipantSetV1")
            .field("participant_count", &2)
            .field("ordered_offset_contributions", &"[PUBLIC OFFSETS]")
            .field("ordered_kernel_excess_points", &"[PUBLIC KEYS]")
            .finish()
    }
}

/// Frozen request for one Wallet V3-owned output in a real Scriptless claim
/// or refund. Claim and refund are distinct reservations even for one session.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ScriptlessPayoutReservationRequestV1 {
    pub session_id: [u8; 32],
    pub role: ScriptlessPayoutRoleV1,
    pub shared_output_commitment: [u8; 33],
    /// Zero explicitly represents a non-beneficiary signer and exports no
    /// output; Wallet V3 never constructs a zero-value confidential output.
    pub payout_value_noms: u64,
    pub kernel_fee_noms: u64,
    pub expected_output_count: u32,
    /// Must be zero for Claim and nonzero for Refund.
    pub refund_lock_height: u64,
}

impl fmt::Debug for ScriptlessPayoutReservationRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptlessPayoutReservationRequestV1")
            .field("session_id", &"[REDACTED]")
            .field("role", &self.role)
            .field("shared_output_commitment", &"[PUBLIC COMMITMENT]")
            .field("amounts", &"[REDACTED]")
            .field("expected_output_count", &self.expected_output_count)
            .field("refund_lock_height", &self.refund_lock_height)
            .finish()
    }
}

/// Redacted lifecycle result for one durable payout reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptlessPayoutReservationSummaryV1 {
    pub reservation_id: Uuid,
    pub role: ScriptlessPayoutRoleV1,
    pub state: ScriptlessPayoutReservationState,
    pub template_bound: bool,
}

/// Exact normal-DOM public components exported before the independent
/// orchestrator builds the authoritative claim/refund template.
#[derive(Clone, Eq, PartialEq)]
pub struct ScriptlessPayoutCompositionV1 {
    pub reservation_id: Uuid,
    pub session_id: [u8; 32],
    pub chain_id: [u8; 32],
    pub role: ScriptlessPayoutRoleV1,
    pub shared_output_commitment: [u8; 33],
    /// Empty for a non-beneficiary signer and exactly one recoverable output
    /// for the participant assigned a payout.
    pub outputs: Vec<TransactionOutput>,
    pub offset_contribution: [u8; 32],
    pub payout_excess_public_key: [u8; 33],
    pub kernel_fee_noms: u64,
    pub expected_output_count: u32,
    pub refund_lock_height: u64,
}

impl fmt::Debug for ScriptlessPayoutCompositionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptlessPayoutCompositionV1")
            .field("reservation_id", &self.reservation_id)
            .field("session_id", &"[REDACTED]")
            .field("chain_id", &"[PUBLIC CHAIN ID]")
            .field("role", &self.role)
            .field("shared_output_commitment", &"[PUBLIC COMMITMENT]")
            .field("output_count", &self.outputs.len())
            .field("offset_contribution", &"[PUBLIC OFFSET]")
            .field("payout_excess_public_key", &"[PUBLIC KEY]")
            .field("kernel_fee_noms", &"[REDACTED]")
            .field("expected_output_count", &self.expected_output_count)
            .field("refund_lock_height", &self.refund_lock_height)
            .finish()
    }
}

impl fmt::Debug for ScriptlessFundingCompositionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptlessFundingCompositionV1")
            .field("reservation_id", &self.reservation_id)
            .field("session_id", &"[REDACTED]")
            .field("chain_id", &"[PUBLIC CHAIN ID]")
            .field("shared_output_commitment", &"[PUBLIC COMMITMENT]")
            .field("input_count", &self.inputs.len())
            .field("other_output_count", &self.other_outputs.len())
            .field("offset_contribution", &"[PUBLIC OFFSET]")
            .field("wallet_excess_public_key", &"[PUBLIC KEY]")
            .field("funding_fee_noms", &"[REDACTED]")
            .finish()
    }
}

pub struct RecoveryCreateResult {
    pub wallet: WalletSummary,
    pub mnemonic: Zeroizing<String>,
}

pub struct RecoveryRestoreResult {
    pub wallet: WalletSummary,
    pub recovery: SeedRestoreResult,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDomainSnapshot {
    pub authentication: Option<String>,
    pub storage: Option<String>,
    pub lifecycle: Option<String>,
    pub node: Option<String>,
    pub peer_bootstrap: Option<String>,
    pub synchronization: Option<String>,
    pub mining: Option<String>,
    pub submission: Option<String>,
    pub updater: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupStatus {
    pub format_version: u16,
    pub destination_name: String,
}

pub struct WalletService {
    location: Option<WalletDirectory>,
    metadata: Option<WalletMetadata>,
    state: ApplicationState,
    unlocked: Option<WalletState>,
    password: Option<SecretBytes>,
    kdf: KdfParameters,
    backend: Option<ProductionWalletBackend>,
    sender_secrets: Option<(Uuid, RecoverableSenderParts)>,
    errors: ErrorDomainSnapshot,
    /// Last canonical tip height observed from a committed batch or Core identity.
    observed_tip_height: Option<u64>,
}

impl fmt::Debug for WalletService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletService")
            .field("state", &self.state)
            .field(
                "backend",
                &self.backend.as_ref().map(|_| PRODUCTION_BACKEND_KIND),
            )
            .field("secrets", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Default for WalletService {
    fn default() -> Self {
        Self {
            location: None,
            metadata: None,
            state: ApplicationState::Closed,
            unlocked: None,
            password: None,
            kdf: KdfParameters::DOM_CONTINUITY,
            backend: None,
            sender_secrets: None,
            errors: ErrorDomainSnapshot::default(),
            observed_tip_height: None,
        }
    }
}

impl WalletService {
    /// Legacy creation is deliberately disabled: every new Wallet must expose its BIP-39 ceremony.
    pub fn create(
        &mut self,
        _path: impl AsRef<Path>,
        _password: &str,
        _identity: NetworkIdentity,
    ) -> Result<WalletSummary, CoreError> {
        Err(CoreError::RecoveryCeremonyRequired)
    }

    pub fn create_recoverable(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
        identity: NetworkIdentity,
    ) -> Result<RecoveryCreateResult, CoreError> {
        self.ensure_closed()?;
        validate_password(password)?;
        let seed = CanonicalWalletSeed::generate().map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let mut root_material = Zeroizing::new([0u8; 32]);
        seed.copy_entropy_to(&mut root_material);
        let mut state = WalletState::new(
            identity.clone(),
            *root_material,
            default_node_configuration(identity),
        );
        state.recovery = Some(RecoveryMetadata {
            scheme: RECOVERY_SCHEME_BIP39_256_V1.into(),
            phrase_confirmed: false,
        });
        let directory = WalletDirectory::create(path, &state, password, self.kdf)?;
        self.metadata = Some(directory.metadata()?);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        Ok(RecoveryCreateResult {
            wallet: self.summary_locked()?,
            mnemonic: seed.mnemonic_text(),
        })
    }

    pub fn resume_recoverable_creation(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<RecoveryCreateResult, CoreError> {
        self.ensure_closed()?;
        validate_password(password)?;
        let (directory, state) = WalletDirectory::resume_create(path, password)?;
        if !state.recovery.as_ref().is_some_and(|recovery| {
            recovery.scheme == RECOVERY_SCHEME_BIP39_256_V1 && !recovery.phrase_confirmed
        }) {
            return Err(CoreError::RecoveryPhraseAlreadyConfirmed);
        }
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        self.metadata = Some(directory.metadata()?);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        Ok(RecoveryCreateResult {
            wallet: self.summary_locked()?,
            mnemonic: seed.mnemonic_text(),
        })
    }

    pub fn abort_recoverable_creation(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<(), CoreError> {
        self.ensure_closed()?;
        validate_password(password)?;
        WalletDirectory::abort_create(path, password).map_err(CoreError::from)
    }

    pub fn create_recoverable_for_embedded(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<RecoveryCreateResult, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .clone();
        self.create_recoverable(
            path,
            password,
            NetworkIdentity {
                network: map_network(identity.network),
                chain_id: identity.chain_id,
                genesis_id: identity.genesis_hash,
            },
        )
    }

    pub fn open(&mut self, path: impl AsRef<Path>) -> Result<WalletSummary, CoreError> {
        self.ensure_closed()?;
        let directory = WalletDirectory::open(path)?;
        let metadata = directory.metadata()?;
        if let Some(backend) = &self.backend {
            require_canonical_mainnet_when_applicable(&metadata.identity)?;
            require_domain_identity(&metadata.identity, backend.identity())?;
        }
        self.metadata = Some(metadata);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        self.summary_locked()
    }

    pub fn unlock(&mut self, password: &str) -> Result<WalletSummary, CoreError> {
        if self.state != ApplicationState::Locked {
            return Err(CoreError::InvalidLifecycleState);
        }
        self.state = ApplicationState::Unlocking;
        let result = (|| {
            let password_secret = SecretBytes::from_bytes(password.as_bytes().to_vec())
                .map_err(|_| CoreError::InvalidPassword)?;
            let state = self
                .location
                .as_ref()
                .ok_or(CoreError::WalletNotOpen)?
                .load(password)?;
            if let Some(backend) = &self.backend {
                require_canonical_mainnet_when_applicable(&state.identity)?;
                require_domain_identity(&state.identity, backend.identity())?;
            }
            self.password = Some(password_secret);
            self.unlocked = Some(state);
            self.state = ApplicationState::Unlocked;
            self.summary()
        })();
        if let Err(error) = &result {
            self.state = ApplicationState::Locked;
            self.errors.authentication = Some(error.redacted_code().into());
        } else {
            self.errors.authentication = None;
        }
        result
    }

    /// Start the embedded production backend. No remote endpoint is consulted.
    pub fn start_embedded_core(
        &mut self,
        configuration: EmbeddedCoreConfiguration,
    ) -> Result<ProbeResult, CoreError> {
        if self.backend.is_some() {
            return Err(CoreError::InvalidLifecycleState);
        }
        let backend = ProductionWalletBackend::start(configuration, None)?;
        self.attach_backend(backend)
    }

    /// Start a remote scan-only backend over an already constructed frozen
    /// `WalletCoreApi` (e.g. `dom-wallet-remote-source::RemoteNodeSource`).
    ///
    /// The chain adapter, cursor rules and atomic commit path are identical to
    /// the embedded backend; submission, fees, peers and mining stay
    /// embedded-only and return a typed "requires the embedded node" error.
    pub fn start_remote_source(
        &mut self,
        api: Arc<dyn dom_wallet_core_api::WalletCoreApi + Send + Sync>,
    ) -> Result<ProbeResult, CoreError> {
        if self.backend.is_some() {
            return Err(CoreError::InvalidLifecycleState);
        }
        let backend = ProductionWalletBackend::start_remote(api, None)?;
        self.attach_backend(backend)
    }

    /// Install an externally constructed backend (embedded or remote).
    ///
    /// This exists so slow construction — `DomNode::init` performs NTP checks
    /// and `ChainState::open` — can run on a dedicated thread WITHOUT holding
    /// the `WalletService` lock; only this short attach step needs the lock.
    pub fn attach_backend(
        &mut self,
        backend: ProductionWalletBackend,
    ) -> Result<ProbeResult, CoreError> {
        if self.backend.is_some() {
            return Err(CoreError::InvalidLifecycleState);
        }
        if let Some(state) = self.unlocked.as_ref() {
            require_domain_identity(&state.identity, backend.identity())?;
        }
        let identity = backend.current_identity()?;
        let result = ProbeResult {
            source_identity: if backend.is_embedded() {
                PRODUCTION_BACKEND_KIND.into()
            } else {
                REMOTE_BACKEND_KIND.into()
            },
            network: map_network(identity.network),
            tip_height: identity.current_tip.height,
            connected: true,
        };
        self.backend = Some(backend);
        self.observed_tip_height = Some(identity.current_tip.height);
        Ok(result)
    }

    /// Whether any chain-source backend (embedded or remote) is attached.
    pub fn has_backend(&self) -> bool {
        self.backend.is_some()
    }

    /// Whether the attached backend owns the embedded node (false when the
    /// backend is a remote scan-only source or absent).
    pub fn backend_is_embedded(&self) -> bool {
        self.backend
            .as_ref()
            .is_some_and(ProductionWalletBackend::is_embedded)
    }

    pub fn embedded_core_identity(&self) -> Result<CoreChainIdentity, CoreError> {
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()
            .map_err(CoreError::from)
    }

    pub fn embedded_core_cached_identity(&self) -> Result<CoreChainIdentity, CoreError> {
        self.backend
            .as_ref()
            .map(|backend| backend.identity().clone())
            .ok_or(CoreError::EmbeddedCoreRequired)
    }

    pub fn embedded_core_running(&self) -> Result<bool, CoreError> {
        self.backend
            .as_ref()
            .map(ProductionWalletBackend::is_running)
            .ok_or(CoreError::EmbeddedCoreRequired)
    }

    pub fn embedded_core_ready(&self) -> Result<bool, CoreError> {
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .is_ready()
            .map_err(CoreError::from)
    }

    pub fn embedded_peer_status(&self) -> Result<EmbeddedPeerStatus, CoreError> {
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .peer_status()
            .map_err(CoreError::from)
    }

    pub fn embedded_node_handle(
        &self,
    ) -> Result<std::sync::Arc<dom_node::node::DomNode>, CoreError> {
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .node_handle()
            .map_err(CoreError::from)
    }

    /// Stop the embedded node without changing the open or unlocked wallet state.
    pub fn stop_embedded_core(&mut self) -> Result<(), CoreError> {
        if let Some(mut backend) = self.backend.take() {
            backend.shutdown()?;
        }
        Ok(())
    }

    /// Reserve a Coinbase recovery coordinate before creating public mining
    /// material. Seed and blinding data never cross into the embedded node.
    pub fn mining_coinbase_candidate(
        &mut self,
        height: u64,
    ) -> Result<dom_consensus::CoinbaseTransaction, CoreError> {
        self.ensure_phrase_confirmed()?;
        self.backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        require_canonical_mainnet_when_applicable(
            &self.unlocked.as_ref().ok_or(CoreError::Locked)?.identity,
        )?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let coordinate = state.reserve_recovery_coordinate(0, RecoveryOutputClass::Coinbase)?;
        self.commit(state)?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let builder = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .output_builder(&seed)?;
        builder
            .build_coinbase(dom_core::BlockHeight(height), 0, coordinate)
            .map_err(CoreError::from)
    }

    pub fn mining_preferences(&self) -> Result<MiningPreferences, CoreError> {
        Ok(self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .mining_preferences
            .clone())
    }

    pub fn set_mining_preferences(
        &mut self,
        enabled: bool,
        cpu_threads: usize,
    ) -> Result<MiningPreferences, CoreError> {
        if cpu_threads == 0 || cpu_threads > 4_096 {
            return Err(CoreError::InvalidTransactionInput);
        }
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        state.mining_preferences = MiningPreferences {
            enabled,
            cpu_threads,
        };
        self.commit(state)?;
        self.mining_preferences()
    }

    pub fn mining_reward_destination(&self) -> Result<String, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        Ok(format!("DOM-MAINNET-RECOVERY:{}", state.wallet_id))
    }

    pub fn validate_wallet_address(&self, address: &str) -> Result<String, CoreError> {
        let network = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .network;
        WalletAddress::parse(
            address,
            network,
            AddressIdentityPurpose::TransactionInteraction,
        )
        .map(|value| value.encode())
        .map_err(CoreError::from)
    }

    /// Diagnose a recovery phrase without touching disk, the network or any
    /// wallet state, so the shell can report which word is wrong instead of a
    /// blanket "invalid phrase". Agreement with the real parser is guaranteed
    /// by `diagnose_phrase_agrees_with_restore` in the shell test suite.
    pub fn diagnose_recovery_phrase(phrase: &str) -> Result<(), PhraseProblem> {
        dom_wallet_core_recovery::CanonicalWalletSeed::diagnose_phrase(phrase)
    }

    /// Immediate offline restore: parse the mnemonic and create the encrypted
    /// wallet directly at `path` with the canonical Mainnet identity, without
    /// requiring any backend or node. The wallet is left `Locked` and ready to
    /// unlock; `seed_restore_status` stays `in_progress` and the canonical
    /// recovery scan runs later on the normal synchronization path, which
    /// applies recovery per page and commits cursor plus state atomically.
    pub fn restore_from_mnemonic_offline(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
        phrase: &str,
    ) -> Result<WalletSummary, CoreError> {
        self.restore_from_mnemonic_offline_with_identity(
            path,
            password,
            phrase,
            mainnet_network_identity()?,
        )
    }

    /// Offline restore bound to an explicit network identity. Production uses
    /// the Mainnet wrapper; non-Mainnet identities exist for embedded regtest
    /// and test harnesses. When a backend is already running its identity must
    /// match the requested one.
    pub fn restore_from_mnemonic_offline_with_identity(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
        phrase: &str,
        identity: NetworkIdentity,
    ) -> Result<WalletSummary, CoreError> {
        self.ensure_closed()?;
        validate_password(password)?;
        if let Some(backend) = &self.backend {
            require_domain_identity(&identity, backend.identity())?;
        }
        let seed =
            CanonicalWalletSeed::parse(phrase).map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let state = offline_restore_state(&seed, identity);
        let directory = WalletDirectory::create(path, &state, password, self.kdf)?;
        self.metadata = Some(directory.metadata()?);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        let mut summary = self.summary_locked()?;
        summary.seed_restore_status =
            Some(seed_restore_status_name(SeedRestoreStatus::InProgress).into());
        Ok(summary)
    }

    pub fn restore_from_mnemonic(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
        phrase: &str,
    ) -> Result<RecoveryRestoreResult, CoreError> {
        self.ensure_closed()?;
        let backend = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        let recovery = backend
            .restore(phrase, password, &path, self.kdf)
            .map_err(|error| match error {
                ProductionBackendError::Restore(error) => CoreError::Restore(error),
                other => CoreError::Backend(other),
            })?;
        let directory = WalletDirectory::open(path)?;
        self.metadata = Some(directory.metadata()?);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        Ok(RecoveryRestoreResult {
            wallet: self.summary_locked()?,
            recovery,
        })
    }

    pub fn recovery_phrase_confirmed(&mut self, password: &str) -> Result<(), CoreError> {
        if self.state != ApplicationState::Locked {
            return Err(CoreError::InvalidLifecycleState);
        }
        validate_password(password)?;
        let location = self.location.as_ref().ok_or(CoreError::WalletNotOpen)?;
        let mut state = location.load(password)?;
        let recovery = state
            .recovery
            .as_mut()
            .ok_or(CoreError::RecoveryUnavailable)?;
        recovery.phrase_confirmed = true;
        let expected = state.generation;
        let committed = location.commit(expected, state, password, self.kdf)?;
        self.metadata = Some(location.metadata()?);
        debug_assert!(committed.recovery.is_some());
        Ok(())
    }

    /// Re-display an unfinished creation ceremony only after authenticating the
    /// currently open wallet. This is the restart/dismissal recovery path; a
    /// confirmed phrase is never exposed again.
    pub fn recovery_phrase_resume(
        &self,
        password: &str,
    ) -> Result<RecoveryCreateResult, CoreError> {
        if !matches!(
            self.state,
            ApplicationState::Locked | ApplicationState::Unlocked
        ) {
            return Err(CoreError::InvalidLifecycleState);
        }
        validate_password(password)?;
        let state = self
            .location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .load(password)?;
        let recovery = state
            .recovery
            .as_ref()
            .ok_or(CoreError::RecoveryUnavailable)?;
        if recovery.scheme != RECOVERY_SCHEME_BIP39_256_V1 {
            return Err(CoreError::RecoveryPhraseInvalid);
        }
        if recovery.phrase_confirmed {
            return Err(CoreError::RecoveryPhraseAlreadyConfirmed);
        }
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let wallet = if self.state == ApplicationState::Unlocked {
            self.summary()?
        } else {
            self.summary_locked()?
        };
        Ok(RecoveryCreateResult {
            wallet,
            mnemonic: seed.mnemonic_text(),
        })
    }

    pub fn backup_export(
        &self,
        destination: impl AsRef<Path>,
        backup_password: &str,
    ) -> Result<BackupStatus, CoreError> {
        validate_password(backup_password)?;
        self.ensure_phrase_confirmed()?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let password = self.password.as_ref().ok_or(CoreError::Locked)?;
        let wallet_password = std::str::from_utf8(password.expose_for_crypto())
            .map_err(|_| CoreError::InvalidPassword)?;
        let name = destination
            .as_ref()
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .ok_or(CoreError::InvalidBackupDestination)?
            .to_owned();
        self.location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .export_backup(wallet_password, backup_password, self.kdf, destination)?;
        let _ = state.wallet_id;
        Ok(BackupStatus {
            format_version: dom_wallet_storage::BACKUP_FORMAT_VERSION,
            destination_name: name,
        })
    }

    pub fn backup_import(
        &mut self,
        destination: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
        backup_password: &str,
        wallet_password: &str,
        expected_identity: NetworkIdentity,
    ) -> Result<WalletSummary, CoreError> {
        self.ensure_closed()?;
        validate_password(backup_password)?;
        validate_password(wallet_password)?;
        let directory = WalletDirectory::import_backup(
            destination,
            backup_path,
            backup_password,
            wallet_password,
            &expected_identity,
            self.kdf,
        )?;
        self.metadata = Some(directory.metadata()?);
        self.location = Some(directory);
        self.state = ApplicationState::Locked;
        self.summary_locked()
    }

    pub fn lock(&mut self) -> Result<(), CoreError> {
        if self.location.is_none() {
            return Err(CoreError::WalletNotOpen);
        }
        self.sender_secrets = None;
        self.unlocked = None;
        self.password = None;
        self.state = ApplicationState::Locked;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), CoreError> {
        if self.location.is_some() {
            self.lock()?;
        }
        if let Some(mut backend) = self.backend.take() {
            backend.shutdown()?;
        }
        self.location = None;
        self.metadata = None;
        self.state = ApplicationState::Closed;
        Ok(())
    }

    pub fn summary(&self) -> Result<WalletSummary, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        Ok(summary_from_state(
            state,
            application_state_name(&self.state),
            self.observed_tip_height,
        ))
    }

    pub fn summary_locked(&self) -> Result<WalletSummary, CoreError> {
        let metadata = self.metadata.as_ref().ok_or(CoreError::WalletNotOpen)?;
        Ok(WalletSummary {
            wallet_id: metadata.wallet_id,
            network: metadata.identity.network,
            generation: metadata.active_generation,
            cursor_height: None,
            tip_height: self.observed_tip_height,
            seed_restore_status: None,
            balance: BalanceProjection::default(),
            state: application_state_name(&self.state).into(),
            experimental: true,
            unaudited: true,
        })
    }

    pub fn accounts(&self) -> Result<Vec<(Uuid, String)>, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        Ok(vec![(
            state.default_account.id,
            state.default_account.label.clone(),
        )])
    }

    /// Deprecated endpoint fields remain readable only as schema compatibility data.
    pub fn node_configuration(&self) -> Result<RedactedNodeConfiguration, CoreError> {
        Ok(self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .node_configuration
            .redacted())
    }

    pub fn set_node_configuration(
        &mut self,
        configuration: NodeConfiguration,
    ) -> Result<(), CoreError> {
        configuration.validate()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        if configuration.expected_identity != state.identity {
            return Err(CoreError::IdentityMismatch);
        }
        state.node_configuration = configuration;
        self.commit(state)
    }

    pub fn synchronize(&mut self) -> Result<WalletSummary, CoreError> {
        let backend = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        if !backend.is_ready()? {
            return Err(CoreError::NodeNotReady);
        }
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let identity = backend.current_identity()?;
        require_domain_identity(&state.identity, &identity)?;
        let location = self
            .location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .clone();
        let password = self.password_text()?.to_owned();

        let backend = self.backend.take().ok_or(CoreError::EmbeddedCoreRequired)?;
        let state = self.unlocked.take().ok_or(CoreError::Locked)?;
        let mut sink = WalletRecoverySink::new(location, state, password, self.kdf, seed, identity);
        self.state = ApplicationState::Synchronizing;
        let result = backend.reconcile_once(&mut sink);
        let recovery_error = sink.last_recovery_error.take();
        self.backend = Some(backend);
        self.observed_tip_height = sink
            .observed_tip_height
            .or(self.observed_tip_height)
            .or(Some(sink.identity.current_tip.height));
        self.unlocked = Some(sink.state);
        match result {
            Ok(_) => {
                self.errors.synchronization = None;
                self.metadata = Some(
                    self.location
                        .as_ref()
                        .ok_or(CoreError::WalletNotOpen)?
                        .metadata()?,
                );
                self.state = ApplicationState::Unlocked;
                self.summary()
            }
            Err(error) => {
                self.finish_sync_failure(&error);
                recovery_error.map_or_else(|| Err(error.into()), |error| Err(error.into()))
            }
        }
    }

    fn finish_sync_failure(&mut self, error: &ProductionBackendError) {
        if error.is_transient_sync_unavailability() {
            self.state = ApplicationState::Unlocked;
        } else {
            self.record_sync_failure(error);
        }
    }

    fn record_sync_failure(&mut self, error: &ProductionBackendError) {
        self.errors.synchronization = Some(match error {
            ProductionBackendError::Scan(scan) => {
                format!("CURSOR_SYNCHRONIZATION_FAILED:{scan}")
            }
            _ => "CURSOR_SYNCHRONIZATION_FAILED".into(),
        });
        self.state = ApplicationState::Unlocked;
    }

    pub fn synchronize_live(&mut self) -> Result<WalletSummary, CoreError> {
        let backend = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        if !backend.is_ready()? {
            return Err(CoreError::NodeNotReady);
        }
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let identity = backend.current_identity()?;
        require_domain_identity(&state.identity, &identity)?;
        let location = self
            .location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .clone();
        let password = self.password_text()?.to_owned();

        let backend = self.backend.take().ok_or(CoreError::EmbeddedCoreRequired)?;
        let state = self.unlocked.take().ok_or(CoreError::Locked)?;
        let mut sink = WalletRecoverySink::new(location, state, password, self.kdf, seed, identity);
        self.state = ApplicationState::Synchronizing;
        let result = backend.reconcile_page(&mut sink);
        let recovery_error = sink.last_recovery_error.take();
        self.backend = Some(backend);
        self.observed_tip_height = sink
            .observed_tip_height
            .or(self.observed_tip_height)
            .or(Some(sink.identity.current_tip.height));
        self.unlocked = Some(sink.state);
        match result {
            Ok(_) => {
                self.errors.synchronization = None;
                self.metadata = Some(
                    self.location
                        .as_ref()
                        .ok_or(CoreError::WalletNotOpen)?
                        .metadata()?,
                );
                self.state = ApplicationState::Unlocked;
                self.summary()
            }
            Err(error) => {
                self.finish_sync_failure(&error);
                recovery_error.map_or_else(|| Err(error.into()), |error| Err(error.into()))
            }
        }
    }

    pub fn rescan_from_genesis(&mut self) -> Result<WalletSummary, CoreError> {
        let tip = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?
            .current_tip
            .height;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        rewind_recovery_state(&mut state, 0, tip)?;
        state.core_scan_cursor = None;
        state.recovery_canonical_blocks.clear();
        // A genesis rescan restarts the whole-history totals. This also clears
        // any residue that pre-window states accumulated for pruned heights,
        // keeping the durable counters coherent with the emptied window.
        state.recovery_scanned_blocks = 0;
        state.recovery_scanned_outputs = 0;
        state.legacy_proof_only_outputs = 0;
        self.commit(state)?;
        self.synchronize()
    }

    pub fn transaction_fee_estimate(
        &self,
        amount: u64,
        selected_input_count: u32,
        change_output: bool,
    ) -> Result<FeeEstimate, CoreError> {
        if amount == 0 || selected_input_count == 0 {
            return Err(CoreError::InvalidTransactionInput);
        }
        self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let estimate = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .minimum_fee(WalletTransactionShape {
                input_count: selected_input_count,
                output_count: if change_output { 2 } else { 1 },
                kernel_count: 1,
            })?;
        Ok(FeeEstimate {
            amount,
            selected_input_count,
            expected_output_count: estimate.shape.output_count,
            weight: u32::try_from(estimate.weight.total_weight)
                .map_err(|_| CoreError::ArithmeticOverflow)?,
            minimum_fee: estimate.minimum_fee_noms,
        })
    }

    pub fn preflight_funding(&self, amount: u64) -> Result<FundingPreflight, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let mut total = 0u64;
        let mut selected = 0u32;
        let mut fee = 0u64;
        for output in spendable_outputs(state) {
            selected = selected
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow)?;
            fee = self
                .transaction_fee_estimate(amount, selected, true)?
                .minimum_fee;
            total = total
                .checked_add(output.value)
                .ok_or(CoreError::ArithmeticOverflow)?;
            if total
                >= amount
                    .checked_add(fee)
                    .ok_or(CoreError::ArithmeticOverflow)?
            {
                break;
            }
        }
        Ok(FundingPreflight {
            amount,
            spendable: state.balance().spendable,
            selected_input_count: selected,
            estimated_fee: fee,
            fundable: selected > 0
                && total
                    >= amount
                        .checked_add(fee)
                        .ok_or(CoreError::ArithmeticOverflow)?,
        })
    }

    /// Create a manual interactive Slate v4 request. Address v1 interaction
    /// identities are derived from public one-time Slate participant keys.
    pub fn transaction_send_create(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CoreError> {
        self.transaction_send_create_with_identities(
            amount,
            requested_fee,
            None,
            None,
            0,
            expires_at_height,
        )
    }

    /// Atomically reserve ordinary wallet UTXOs for one Scriptless funding
    /// session and prepare exact DOM inputs, recoverable change and a public
    /// offset contribution. Retrying the identical request after a process
    /// crash resumes the same reservation; a changed request for the same
    /// session fails closed.
    pub fn scriptless_funding_prepare(
        &mut self,
        request: ScriptlessFundingReservationRequestV1,
    ) -> Result<ScriptlessFundingReservationSummaryV1, CoreError> {
        if request.session_id == [0u8; 32]
            || request.shared_output_commitment == [0u8; 33]
            || request.funding_fee_noms == 0
            || request.expected_output_count == 0
            || (request.local_debit_noms != 0 && request.expected_input_count == 0)
        {
            return Err(CoreError::InvalidScriptlessFundingRequest);
        }
        self.ensure_phrase_confirmed()?;
        dom_crypto::pedersen::Commitment::from_compressed_bytes(&request.shared_output_commitment)
            .map_err(|_| CoreError::InvalidScriptlessFundingRequest)?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let minimum = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .minimum_fee(WalletTransactionShape {
                input_count: request.expected_input_count,
                output_count: request.expected_output_count,
                kernel_count: 1,
            })?;
        if request.funding_fee_noms < minimum.minimum_fee_noms {
            return Err(CoreError::FeeTooLow);
        }

        if let Some(existing) = self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .scriptless_funding_reservations
            .iter()
            .find(|reservation| reservation.session_id == request.session_id)
        {
            if existing.shared_output_commitment != request.shared_output_commitment
                || existing.local_debit_noms != request.local_debit_noms
                || existing.funding_fee_noms != request.funding_fee_noms
                || existing.expected_input_count != request.expected_input_count
                || existing.expected_output_count != request.expected_output_count
            {
                return Err(CoreError::ScriptlessFundingSessionConflict);
            }
            let reservation_id = existing.id;
            if !matches!(
                existing.state,
                ScriptlessFundingReservationState::Cancelled
                    | ScriptlessFundingReservationState::AbandonedRetained
            ) {
                self.scriptless_funding_resume_preparation(reservation_id)?;
            }
            return self.scriptless_funding_summary(reservation_id);
        }

        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let mut selected = Vec::new();
        let mut total = 0u64;
        if request.local_debit_noms != 0 {
            for output in spendable_outputs(&state) {
                selected.push(output.clone());
                total = total
                    .checked_add(output.value)
                    .ok_or(CoreError::ArithmeticOverflow)?;
                if total >= request.local_debit_noms {
                    break;
                }
            }
        }
        if total < request.local_debit_noms {
            return Err(CoreError::InsufficientFunds);
        }
        let change_value_noms = total - request.local_debit_noms;
        validate_scriptless_funding_local_shape(
            selected.len(),
            usize::from(change_value_noms != 0),
            request.expected_input_count,
            request.expected_output_count,
        )?;

        let reservation_id = Uuid::new_v4();
        let (change_derivation_index, change_output_id) = if change_value_noms == 0 {
            (None, None)
        } else {
            let coordinate = state.reserve_recovery_coordinate(0, RecoveryOutputClass::Change)?;
            (Some(coordinate.derivation_index()), Some(Uuid::new_v4()))
        };
        let reserved_output_ids = selected.iter().map(|output| output.id).collect::<Vec<_>>();
        let input_commitments = selected
            .iter()
            .map(|output| {
                output
                    .commitment
                    .map(|commitment| commitment.to_vec())
                    .ok_or(CoreError::UnsupportedSpendingEvidence)
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        for output in &mut state.outputs {
            if reserved_output_ids.contains(&output.id) {
                if output.reserved_by.is_some() || output.state != OutputState::Confirmed {
                    return Err(CoreError::ReservationConflict);
                }
                output.reserved_by = Some(reservation_id);
                output.state = OutputState::PendingOutgoing;
            }
        }
        state
            .scriptless_funding_reservations
            .push(ScriptlessFundingReservation {
                version: SCRIPTLESS_FUNDING_RESERVATION_VERSION,
                id: reservation_id,
                session_id: request.session_id,
                shared_output_commitment: request.shared_output_commitment,
                created_at_height: identity.current_tip.height,
                local_debit_noms: request.local_debit_noms,
                funding_fee_noms: request.funding_fee_noms,
                expected_input_count: request.expected_input_count,
                expected_output_count: request.expected_output_count,
                reserved_output_ids,
                input_commitments,
                change_value_noms,
                change_derivation_index,
                change_output_id,
                change_commitment: None,
                change_output_bytes: Vec::new(),
                offset_contribution: None,
                wallet_excess_public_key: Vec::new(),
                template_hash: None,
                session_share_binding_digest: None,
                participant_position: None,
                template_participants: None,
                private_context: None,
                state: ScriptlessFundingReservationState::Reserved,
            });
        self.commit(state)?; // Inputs and coordinate are durable before construction.
        self.scriptless_funding_resume_preparation(reservation_id)?;
        self.scriptless_funding_summary(reservation_id)
    }

    /// Bind the exact durable DOM shared-blinding capability before any
    /// funding component leaves Wallet V3, then return only this
    /// participant's public composed kernel-excess point `R_i + E_i`.
    ///
    /// The point is deterministic for the persisted wallet excess and the
    /// authenticated session capability. No `SigningShareV1` is constructed,
    /// exported or consumed on this pre-template path.
    pub fn scriptless_funding_prepare_kernel_excess_point(
        &mut self,
        reservation_id: Uuid,
        session_share: &SessionBlindingShareCapabilityV1,
    ) -> Result<[u8; 33], CoreError> {
        self.scriptless_funding_resume_preparation(reservation_id)?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_funding_index(&state, reservation_id)?;
        let (binding_digest, participant_position) = validate_session_share_binding(
            identity.chain_id,
            state.scriptless_funding_reservations[index].session_id,
            session_share,
        )?;
        match state.scriptless_funding_reservations[index].state {
            ScriptlessFundingReservationState::Prepared => {
                let record = &mut state.scriptless_funding_reservations[index];
                record.session_share_binding_digest = Some(binding_digest);
                record.participant_position = Some(u32::from(participant_position));
                record.state = ScriptlessFundingReservationState::SessionBound;
                self.commit(state)?; // Binding is durable before returning the public point.
            }
            ScriptlessFundingReservationState::SessionBound
            | ScriptlessFundingReservationState::Exported
            | ScriptlessFundingReservationState::TemplateBound => {
                require_persisted_session_binding(
                    &state.scriptless_funding_reservations[index],
                    binding_digest,
                    participant_position,
                )?;
            }
            ScriptlessFundingReservationState::Reserved => {
                return Err(CoreError::ScriptlessFundingNotPrepared)
            }
            ScriptlessFundingReservationState::AbandonedRetained
            | ScriptlessFundingReservationState::Cancelled => {
                return Err(CoreError::ScriptlessFundingSigningNotAuthorized)
            }
        }
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = &state.scriptless_funding_reservations
            [find_scriptless_funding_index(state, reservation_id)?];
        require_persisted_session_binding(record, binding_digest, participant_position)?;
        let wallet_excess_point = parse_funding_public_key(&record.wallet_excess_public_key)?;
        session_share
            .funding_kernel_excess_point_v1(&wallet_excess_point)
            .map(|point| point.to_compressed_bytes())
            .map_err(|_| CoreError::ScriptlessSessionBindingMismatch)
    }

    /// Persist the exposure transition before returning exact public funding
    /// components. A crash after that commit may only retransmit these same
    /// components; it can never release the reserved inputs automatically.
    pub fn scriptless_funding_export(
        &mut self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessFundingCompositionV1, CoreError> {
        self.scriptless_funding_resume_preparation(reservation_id)?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_funding_index(&state, reservation_id)?;
        match state.scriptless_funding_reservations[index].state {
            ScriptlessFundingReservationState::SessionBound => {
                state.scriptless_funding_reservations[index].state =
                    ScriptlessFundingReservationState::Exported;
                self.commit(state)?;
            }
            ScriptlessFundingReservationState::Exported => {}
            ScriptlessFundingReservationState::TemplateBound => {}
            ScriptlessFundingReservationState::Reserved
            | ScriptlessFundingReservationState::Prepared => {
                return Err(CoreError::ScriptlessSessionBindingRequired)
            }
            ScriptlessFundingReservationState::AbandonedRetained
            | ScriptlessFundingReservationState::Cancelled => {
                return Err(CoreError::ScriptlessFundingCannotExport)
            }
        }
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = &state.scriptless_funding_reservations
            [find_scriptless_funding_index(state, reservation_id)?];
        scriptless_funding_composition(record, identity.chain_id)
    }

    /// Validate and durably bind the authoritative real DOM funding template.
    /// Every public participant contribution is supplied in canonical roster
    /// order and re-aggregated only by pinned DOM authorities. An idempotent
    /// retry must present byte-identical session and participant bindings.
    pub fn scriptless_funding_bind_template(
        &mut self,
        reservation_id: Uuid,
        template: &ScriptlessTransactionTemplateV1,
        session_share: &SessionBlindingShareCapabilityV1,
        participants: ScriptlessTemplateParticipantSetV1,
    ) -> Result<ScriptlessFundingReservationSummaryV1, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_funding_index(&state, reservation_id)?;
        let record = state.scriptless_funding_reservations[index].clone();
        if !matches!(
            record.state,
            ScriptlessFundingReservationState::Exported
                | ScriptlessFundingReservationState::TemplateBound
        ) {
            return Err(CoreError::ScriptlessFundingSigningNotAuthorized);
        }
        let (binding_digest, participant_position) =
            validate_session_share_binding(identity.chain_id, record.session_id, session_share)?;
        require_persisted_session_binding(&record, binding_digest, participant_position)?;
        if template.role() != ContractTxRoleV1::Funding
            || template.shared_output_commitment() != &record.shared_output_commitment
            || template.template_hash() == &[0u8; 32]
        {
            return Err(CoreError::ScriptlessTemplateBindingMismatch);
        }
        let transaction = template.transaction_template();
        if transaction.inputs.is_empty()
            || transaction.inputs.len() != record.expected_input_count as usize
            || transaction.outputs.len() != record.expected_output_count as usize
            || transaction.kernels.len() != 1
        {
            return Err(CoreError::ScriptlessFundingShapeMismatch);
        }
        let kernel = &transaction.kernels[0];
        if kernel.features != KERNEL_FEAT_PLAIN
            || kernel.lock_height != 0
            || kernel.fee.noms() != record.funding_fee_noms
            || kernel.excess_signature != [0u8; 65]
        {
            return Err(CoreError::ScriptlessTemplateBindingMismatch);
        }
        let composition = scriptless_funding_composition(&record, identity.chain_id)?;
        if composition.inputs.iter().any(|local| {
            transaction
                .inputs
                .iter()
                .filter(|candidate| *candidate == local)
                .count()
                != 1
        }) || composition.other_outputs.iter().any(|local| {
            transaction
                .outputs
                .iter()
                .filter(|candidate| *candidate == local)
                .count()
                != 1
        }) || transaction
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &record.shared_output_commitment)
            .count()
            != 1
        {
            return Err(CoreError::ScriptlessTemplateBindingMismatch);
        }
        let wallet_excess_point = parse_funding_public_key(&record.wallet_excess_public_key)?;
        let local_kernel_point = session_share
            .funding_kernel_excess_point_v1(&wallet_excess_point)
            .map_err(|_| CoreError::ScriptlessSessionBindingMismatch)?
            .to_compressed_bytes();
        let participant_binding = validate_template_participant_set(
            transaction,
            record
                .offset_contribution
                .ok_or(CoreError::ScriptlessFundingNotPrepared)?,
            local_kernel_point,
            participant_position,
            participants,
        )?;

        if record.state == ScriptlessFundingReservationState::TemplateBound {
            if record.template_hash.as_ref() != Some(template.template_hash())
                || record.template_participants.as_ref() != Some(&participant_binding)
            {
                return Err(CoreError::ScriptlessTemplateBindingMismatch);
            }
            return self.scriptless_funding_summary(reservation_id);
        }
        let record = &mut state.scriptless_funding_reservations[index];
        record.template_hash = Some(*template.template_hash());
        record.template_participants = Some(participant_binding);
        record.state = ScriptlessFundingReservationState::TemplateBound;
        self.commit(state)?;
        self.scriptless_funding_summary(reservation_id)
    }

    /// Rehydrate the wallet excess as a purpose-specific, non-serializable
    /// capability only after the exact real DOM funding template is bound.
    pub fn scriptless_funding_signing_capability(
        &self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessFundingSigningCapabilityV1, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = &state.scriptless_funding_reservations
            [find_scriptless_funding_index(state, reservation_id)?];
        if record.state != ScriptlessFundingReservationState::TemplateBound {
            return Err(CoreError::ScriptlessFundingSigningNotAuthorized);
        }
        let context = record
            .private_context
            .as_ref()
            .ok_or(CoreError::ScriptlessFundingNotPrepared)?;
        let mut contribution = Zeroizing::new([0u8; 32]);
        context.copy_wallet_excess_contribution_to(&mut contribution);
        let capability =
            ScriptlessFundingSigningCapabilityV1::from_template_bound_encrypted_context(
                *contribution,
                bound_signing_context(record, identity.chain_id)?,
            )?;
        if capability.public_key_bytes().as_slice() != record.wallet_excess_public_key.as_slice() {
            return Err(CoreError::ScriptlessFundingContextMismatch);
        }
        Ok(capability)
    }

    /// Release a reservation only while no public component has ever left the
    /// wallet boundary. The tombstone and burned recovery coordinate remain.
    pub fn scriptless_funding_cancel_unexposed(
        &mut self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessFundingReservationSummaryV1, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_funding_index(&state, reservation_id)?;
        let record = state.scriptless_funding_reservations[index].clone();
        if !record.state.may_cancel_and_release() {
            return Err(CoreError::ScriptlessFundingCannotRelease);
        }
        for output_id in &record.reserved_output_ids {
            let output = state
                .outputs
                .iter_mut()
                .find(|output| output.id == *output_id)
                .ok_or(CoreError::ScriptlessFundingContextMismatch)?;
            if output.reserved_by != Some(reservation_id)
                || output.state != OutputState::PendingOutgoing
            {
                return Err(CoreError::ScriptlessFundingCannotRelease);
            }
            output.reserved_by = None;
            output.state = OutputState::Confirmed;
        }
        if let Some(change_output_id) = record.change_output_id {
            state.outputs.retain(|output| output.id != change_output_id);
            state
                .private_output_blindings
                .retain(|secret| secret.output_id != change_output_id);
        }
        let record = &mut state.scriptless_funding_reservations[index];
        record.change_commitment = None;
        record.change_output_bytes.clear();
        record.offset_contribution = None;
        record.wallet_excess_public_key.clear();
        record.template_hash = None;
        record.session_share_binding_digest = None;
        record.participant_position = None;
        record.template_participants = None;
        record.private_context = None;
        record.state = ScriptlessFundingReservationState::Cancelled;
        self.commit(state)?;
        self.scriptless_funding_summary(reservation_id)
    }

    /// Record operator abandonment after exposure without making any input
    /// selectable. Resolution now belongs to authoritative chain/session
    /// reconciliation.
    pub fn scriptless_funding_abandon_exposed(
        &mut self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessFundingReservationSummaryV1, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_funding_index(&state, reservation_id)?;
        match state.scriptless_funding_reservations[index].state {
            ScriptlessFundingReservationState::SessionBound
            | ScriptlessFundingReservationState::Exported
            | ScriptlessFundingReservationState::TemplateBound => {
                state.scriptless_funding_reservations[index].state =
                    ScriptlessFundingReservationState::AbandonedRetained;
                self.commit(state)?;
            }
            ScriptlessFundingReservationState::AbandonedRetained => {}
            _ => return Err(CoreError::ScriptlessFundingCannotRelease),
        }
        self.scriptless_funding_summary(reservation_id)
    }

    /// Read the redacted durable reservation state without changing exposure.
    pub fn scriptless_funding_status(
        &self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessFundingReservationSummaryV1, CoreError> {
        self.scriptless_funding_summary(reservation_id)
    }

    fn scriptless_funding_resume_preparation(
        &mut self,
        reservation_id: Uuid,
    ) -> Result<(), CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = state.scriptless_funding_reservations
            [find_scriptless_funding_index(state, reservation_id)?]
        .clone();
        match record.state {
            ScriptlessFundingReservationState::Prepared
            | ScriptlessFundingReservationState::SessionBound
            | ScriptlessFundingReservationState::Exported
            | ScriptlessFundingReservationState::TemplateBound => return Ok(()),
            ScriptlessFundingReservationState::Reserved => {}
            ScriptlessFundingReservationState::AbandonedRetained
            | ScriptlessFundingReservationState::Cancelled => {
                return Err(CoreError::ScriptlessFundingCannotExport)
            }
        }

        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let builder = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .output_builder(&seed)?;
        let inputs = record
            .reserved_output_ids
            .iter()
            .zip(&record.input_commitments)
            .map(|(output_id, commitment)| {
                let output = state
                    .outputs
                    .iter()
                    .find(|output| output.id == *output_id)
                    .ok_or(CoreError::ScriptlessFundingContextMismatch)?;
                if output.reserved_by != Some(reservation_id)
                    || output.state != OutputState::PendingOutgoing
                    || output.commitment.as_ref().map(<[u8; 33]>::as_slice)
                        != Some(commitment.as_slice())
                {
                    return Err(CoreError::ScriptlessFundingContextMismatch);
                }
                let commitment: [u8; 33] = commitment
                    .as_slice()
                    .try_into()
                    .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?;
                Ok(WalletSlateInput::new(
                    commitment,
                    state
                        .output_blinding(*output_id)
                        .ok_or(CoreError::UnsupportedSpendingEvidence)?,
                ))
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        let coordinate = record
            .change_derivation_index
            .map(|derivation_index| {
                state.resume_recovery_coordinate(0, derivation_index, RecoveryOutputClass::Change)
            })
            .transpose()?;
        let prepared = builder.build_scriptless_funding_contribution(
            &inputs,
            record.change_value_noms,
            coordinate,
        )?;
        let public = prepared.public.clone();
        if public.inputs.len() != record.input_commitments.len()
            || public
                .inputs
                .iter()
                .zip(&record.input_commitments)
                .any(|(input, expected)| input.commitment.as_bytes().as_slice() != expected)
            || public.other_outputs.len() != usize::from(record.change_value_noms != 0)
        {
            return Err(CoreError::ScriptlessFundingContextMismatch);
        }
        let mut wallet_excess = Zeroizing::new([0u8; 32]);
        prepared.copy_wallet_excess_to(&mut wallet_excess);
        let mut change_blinding = None;
        if let Some(change) = &prepared.change {
            let mut blinding = Zeroizing::new([0u8; 32]);
            change.copy_blinding_to(&mut blinding);
            change_blinding = Some(*blinding);
        }

        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_funding_index(&state, reservation_id)?;
        if state.scriptless_funding_reservations[index].state
            != ScriptlessFundingReservationState::Reserved
        {
            return Err(CoreError::ScriptlessFundingContextMismatch);
        }
        let (change_commitment, change_output_bytes) =
            if let Some(output) = public.other_outputs.first() {
                let output_id = record
                    .change_output_id
                    .ok_or(CoreError::ScriptlessFundingContextMismatch)?;
                let commitment = *output.commitment.as_bytes();
                let canonical_bytes = output.to_bytes().map_err(|_| CoreError::ProtocolRejected)?;
                state.outputs.push(OutputRecord {
                    id: output_id,
                    account_id: state.default_account.id,
                    commitment: Some(commitment),
                    value: record.change_value_noms,
                    state: OutputState::PendingIncoming,
                    discovered_height: 0,
                    reserved_by: None,
                });
                state.remember_output_blinding(
                    output_id,
                    change_blinding.ok_or(CoreError::ScriptlessFundingContextMismatch)?,
                );
                (Some(commitment), canonical_bytes)
            } else {
                (None, Vec::new())
            };
        let record_mut = &mut state.scriptless_funding_reservations[index];
        record_mut.change_commitment = change_commitment;
        record_mut.change_output_bytes = change_output_bytes;
        record_mut.offset_contribution = Some(public.offset_contribution);
        record_mut.wallet_excess_public_key = public.wallet_excess_public_key.to_vec();
        record_mut.private_context = Some(PrivateScriptlessFundingContext::new(
            *wallet_excess,
            change_blinding,
        ));
        record_mut.state = ScriptlessFundingReservationState::Prepared;
        self.commit(state)?; // Exact public bytes and private context become durable together.
        Ok(())
    }

    fn scriptless_funding_summary(
        &self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessFundingReservationSummaryV1, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = &state.scriptless_funding_reservations
            [find_scriptless_funding_index(state, reservation_id)?];
        Ok(ScriptlessFundingReservationSummaryV1 {
            reservation_id,
            state: record.state,
            selected_input_count: u32::try_from(record.reserved_output_ids.len())
                .map_err(|_| CoreError::ArithmeticOverflow)?,
            has_change: record.change_value_noms != 0,
            template_bound: record.template_hash.is_some(),
        })
    }

    /// Durably reserve and prepare one participant-owned output for either the
    /// real claim or real refund template. The `(session, role)` key is
    /// idempotent; Claim and Refund always burn distinct SelfTransfer recovery
    /// coordinates and retain distinct encrypted excess contributions.
    pub fn scriptless_payout_prepare(
        &mut self,
        request: ScriptlessPayoutReservationRequestV1,
    ) -> Result<ScriptlessPayoutReservationSummaryV1, CoreError> {
        let role_lock_is_valid = match request.role {
            ScriptlessPayoutRoleV1::Claim => request.refund_lock_height == 0,
            ScriptlessPayoutRoleV1::Refund => request.refund_lock_height != 0,
        };
        if request.session_id == [0u8; 32]
            || request.shared_output_commitment == [0u8; 33]
            || request.payout_value_noms > dom_crypto::MAX_PROVABLE_VALUE
            || request.kernel_fee_noms == 0
            || request.expected_output_count == 0
            || !role_lock_is_valid
        {
            return Err(CoreError::InvalidScriptlessPayoutRequest);
        }
        self.ensure_phrase_confirmed()?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        dom_crypto::pedersen::Commitment::from_compressed_bytes(&request.shared_output_commitment)
            .map_err(|_| CoreError::InvalidScriptlessPayoutRequest)?;

        if let Some(existing) = self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .scriptless_payout_reservations
            .iter()
            .find(|reservation| {
                reservation.session_id == request.session_id && reservation.role == request.role
            })
        {
            if existing.shared_output_commitment != request.shared_output_commitment
                || existing.payout_value_noms != request.payout_value_noms
                || existing.kernel_fee_noms != request.kernel_fee_noms
                || existing.expected_output_count != request.expected_output_count
                || existing.refund_lock_height != request.refund_lock_height
            {
                return Err(CoreError::ScriptlessPayoutSessionConflict);
            }
            let reservation_id = existing.id;
            if !matches!(
                existing.state,
                ScriptlessPayoutReservationState::Cancelled
                    | ScriptlessPayoutReservationState::AbandonedRetained
            ) {
                self.scriptless_payout_resume_preparation(reservation_id)?;
            }
            return self.scriptless_payout_summary(reservation_id);
        }

        if request.role == ScriptlessPayoutRoleV1::Refund
            && request.refund_lock_height <= identity.current_tip.height
        {
            return Err(CoreError::InvalidScriptlessPayoutRequest);
        }
        let minimum = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .minimum_fee(WalletTransactionShape {
                input_count: 1,
                output_count: request.expected_output_count,
                kernel_count: 1,
            })?;
        if request.kernel_fee_noms < minimum.minimum_fee_noms {
            return Err(CoreError::FeeTooLow);
        }

        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let (derivation_index, output_id) = if request.payout_value_noms == 0 {
            (None, None)
        } else {
            let coordinate =
                state.reserve_recovery_coordinate(0, RecoveryOutputClass::SelfTransfer)?;
            (Some(coordinate.derivation_index()), Some(Uuid::new_v4()))
        };
        let reservation_id = Uuid::new_v4();
        state
            .scriptless_payout_reservations
            .push(ScriptlessPayoutReservation {
                version: SCRIPTLESS_PAYOUT_RESERVATION_VERSION,
                id: reservation_id,
                session_id: request.session_id,
                role: request.role,
                created_at_height: identity.current_tip.height,
                shared_output_commitment: request.shared_output_commitment,
                payout_value_noms: request.payout_value_noms,
                kernel_fee_noms: request.kernel_fee_noms,
                expected_output_count: request.expected_output_count,
                refund_lock_height: request.refund_lock_height,
                output_id,
                derivation_index,
                output_commitment: None,
                output_bytes: Vec::new(),
                offset_contribution: None,
                payout_excess_public_key: Vec::new(),
                template_hash: None,
                session_share_binding_digest: None,
                participant_position: None,
                template_participants: None,
                private_context: None,
                state: ScriptlessPayoutReservationState::Reserved,
            });
        self.commit(state)?; // Burn the role-specific coordinate before construction.
        self.scriptless_payout_resume_preparation(reservation_id)?;
        self.scriptless_payout_summary(reservation_id)
    }

    /// Bind the exact durable DOM shared-blinding capability before any
    /// Claim/Refund component leaves Wallet V3, then return only this
    /// participant's public composed kernel point `E_i - R_i`.
    pub fn scriptless_payout_prepare_kernel_excess_point(
        &mut self,
        reservation_id: Uuid,
        session_share: &SessionBlindingShareCapabilityV1,
    ) -> Result<[u8; 33], CoreError> {
        self.scriptless_payout_resume_preparation(reservation_id)?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_payout_index(&state, reservation_id)?;
        let (binding_digest, participant_position) = validate_session_share_binding(
            identity.chain_id,
            state.scriptless_payout_reservations[index].session_id,
            session_share,
        )?;
        match state.scriptless_payout_reservations[index].state {
            ScriptlessPayoutReservationState::Prepared => {
                let record = &mut state.scriptless_payout_reservations[index];
                record.session_share_binding_digest = Some(binding_digest);
                record.participant_position = Some(u32::from(participant_position));
                record.state = ScriptlessPayoutReservationState::SessionBound;
                self.commit(state)?; // Binding is durable before returning the public point.
            }
            ScriptlessPayoutReservationState::SessionBound
            | ScriptlessPayoutReservationState::ComponentsExposed
            | ScriptlessPayoutReservationState::TemplateBound => {
                require_persisted_payout_session_binding(
                    &state.scriptless_payout_reservations[index],
                    binding_digest,
                    participant_position,
                )?;
            }
            ScriptlessPayoutReservationState::Reserved => {
                return Err(CoreError::ScriptlessPayoutNotPrepared)
            }
            ScriptlessPayoutReservationState::AbandonedRetained
            | ScriptlessPayoutReservationState::Cancelled => {
                return Err(CoreError::ScriptlessPayoutSigningNotAuthorized)
            }
        }
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = &state.scriptless_payout_reservations
            [find_scriptless_payout_index(state, reservation_id)?];
        require_persisted_payout_session_binding(record, binding_digest, participant_position)?;
        let payout_excess_point = parse_payout_public_key(&record.payout_excess_public_key)?;
        session_share
            .shared_output_spend_kernel_excess_point_v1(&payout_excess_point)
            .map(|point| point.to_compressed_bytes())
            .map_err(|_| CoreError::ScriptlessSessionBindingMismatch)
    }

    /// Mark public payout components exposed before returning them. Every
    /// retry, including after restart, revalidates and returns identical DOM
    /// objects and bytes.
    pub fn scriptless_payout_export(
        &mut self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessPayoutCompositionV1, CoreError> {
        self.scriptless_payout_resume_preparation(reservation_id)?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_payout_index(&state, reservation_id)?;
        match state.scriptless_payout_reservations[index].state {
            ScriptlessPayoutReservationState::SessionBound => {
                state.scriptless_payout_reservations[index].state =
                    ScriptlessPayoutReservationState::ComponentsExposed;
                self.commit(state)?;
            }
            ScriptlessPayoutReservationState::ComponentsExposed
            | ScriptlessPayoutReservationState::TemplateBound => {}
            ScriptlessPayoutReservationState::Reserved
            | ScriptlessPayoutReservationState::Prepared => {
                return Err(CoreError::ScriptlessSessionBindingRequired)
            }
            ScriptlessPayoutReservationState::AbandonedRetained
            | ScriptlessPayoutReservationState::Cancelled => {
                return Err(CoreError::ScriptlessPayoutCannotExport)
            }
        }
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = &state.scriptless_payout_reservations
            [find_scriptless_payout_index(state, reservation_id)?];
        scriptless_payout_composition(record, identity.chain_id)
    }

    /// Validate and durably bind the authoritative real DOM Claim or Refund
    /// template before allowing an opaque signing-share composition.
    pub fn scriptless_payout_bind_template(
        &mut self,
        reservation_id: Uuid,
        template: &ScriptlessTransactionTemplateV1,
        session_share: &SessionBlindingShareCapabilityV1,
        participants: ScriptlessTemplateParticipantSetV1,
    ) -> Result<ScriptlessPayoutReservationSummaryV1, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_payout_index(&state, reservation_id)?;
        let record = state.scriptless_payout_reservations[index].clone();
        if !matches!(
            record.state,
            ScriptlessPayoutReservationState::ComponentsExposed
                | ScriptlessPayoutReservationState::TemplateBound
        ) {
            return Err(CoreError::ScriptlessPayoutSigningNotAuthorized);
        }
        let (binding_digest, participant_position) =
            validate_session_share_binding(identity.chain_id, record.session_id, session_share)?;
        require_persisted_payout_session_binding(&record, binding_digest, participant_position)?;
        let expected_role = match record.role {
            ScriptlessPayoutRoleV1::Claim => ContractTxRoleV1::Claim,
            ScriptlessPayoutRoleV1::Refund => ContractTxRoleV1::Refund,
        };
        if template.role() != expected_role
            || template.shared_output_commitment() != &record.shared_output_commitment
            || template.template_hash() == &[0u8; 32]
        {
            return Err(CoreError::ScriptlessTemplateBindingMismatch);
        }
        let transaction = template.transaction_template();
        if transaction.inputs.len() != 1
            || transaction.inputs[0].commitment.as_bytes() != &record.shared_output_commitment
            || transaction.outputs.is_empty()
            || transaction.outputs.len() != record.expected_output_count as usize
            || transaction.kernels.len() != 1
        {
            return Err(CoreError::ScriptlessTemplateBindingMismatch);
        }
        let kernel = &transaction.kernels[0];
        let expected_kernel = match record.role {
            ScriptlessPayoutRoleV1::Claim => {
                kernel.features == KERNEL_FEAT_PLAIN && kernel.lock_height == 0
            }
            ScriptlessPayoutRoleV1::Refund => {
                kernel.features == KERNEL_FEAT_HEIGHT_LOCKED
                    && kernel.lock_height == record.refund_lock_height
            }
        };
        if !expected_kernel
            || kernel.fee.noms() != record.kernel_fee_noms
            || kernel.excess_signature != [0u8; 65]
        {
            return Err(CoreError::ScriptlessTemplateBindingMismatch);
        }
        let composition = scriptless_payout_composition(&record, identity.chain_id)?;
        if composition.outputs.iter().any(|local| {
            transaction
                .outputs
                .iter()
                .filter(|candidate| *candidate == local)
                .count()
                != 1
        }) {
            return Err(CoreError::ScriptlessTemplateBindingMismatch);
        }
        let payout_excess_point = parse_payout_public_key(&record.payout_excess_public_key)?;
        let local_kernel_point = session_share
            .shared_output_spend_kernel_excess_point_v1(&payout_excess_point)
            .map_err(|_| CoreError::ScriptlessSessionBindingMismatch)?
            .to_compressed_bytes();
        let participant_binding = validate_template_participant_set(
            transaction,
            record
                .offset_contribution
                .ok_or(CoreError::ScriptlessPayoutNotPrepared)?,
            local_kernel_point,
            participant_position,
            participants,
        )?;

        if record.state == ScriptlessPayoutReservationState::TemplateBound {
            if record.template_hash.as_ref() != Some(template.template_hash())
                || record.template_participants.as_ref() != Some(&participant_binding)
            {
                return Err(CoreError::ScriptlessTemplateBindingMismatch);
            }
            return self.scriptless_payout_summary(reservation_id);
        }
        let record = &mut state.scriptless_payout_reservations[index];
        record.template_hash = Some(*template.template_hash());
        record.template_participants = Some(participant_binding);
        record.state = ScriptlessPayoutReservationState::TemplateBound;
        self.commit(state)?;
        self.scriptless_payout_summary(reservation_id)
    }

    /// Rehydrate the role-specific wallet excess only after binding the exact
    /// real DOM Claim/Refund template. The returned capability exposes one
    /// purpose-specific `e_i-r_i` operation and no bytes or generic callback.
    pub fn scriptless_payout_signing_capability(
        &self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessPayoutSigningCapabilityV1, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = &state.scriptless_payout_reservations
            [find_scriptless_payout_index(state, reservation_id)?];
        if record.state != ScriptlessPayoutReservationState::TemplateBound {
            return Err(CoreError::ScriptlessPayoutSigningNotAuthorized);
        }
        let context = record
            .private_context
            .as_ref()
            .ok_or(CoreError::ScriptlessPayoutNotPrepared)?;
        let mut contribution = Zeroizing::new([0u8; 32]);
        context.copy_payout_excess_contribution_to(&mut contribution);
        let capability =
            ScriptlessPayoutSigningCapabilityV1::from_template_bound_encrypted_context(
                *contribution,
                bound_payout_signing_context(record, identity.chain_id)?,
            )?;
        if capability.public_key_bytes().as_slice() != record.payout_excess_public_key.as_slice() {
            return Err(CoreError::ScriptlessPayoutContextMismatch);
        }
        Ok(capability)
    }

    /// Cancel only while the exact payout components have never crossed the
    /// wallet boundary. The recovery coordinate remains burned in the
    /// tombstone so Claim and Refund can never reuse it.
    pub fn scriptless_payout_cancel_unexposed(
        &mut self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessPayoutReservationSummaryV1, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_payout_index(&state, reservation_id)?;
        let record = state.scriptless_payout_reservations[index].clone();
        if !record.state.may_cancel_unexposed() {
            return Err(CoreError::ScriptlessPayoutCannotRelease);
        }
        if let Some(output_id) = record.output_id {
            state.outputs.retain(|output| output.id != output_id);
            state
                .private_output_blindings
                .retain(|secret| secret.output_id != output_id);
        }
        let record = &mut state.scriptless_payout_reservations[index];
        record.output_commitment = None;
        record.output_bytes.clear();
        record.offset_contribution = None;
        record.payout_excess_public_key.clear();
        record.template_hash = None;
        record.session_share_binding_digest = None;
        record.participant_position = None;
        record.template_participants = None;
        record.private_context = None;
        record.state = ScriptlessPayoutReservationState::Cancelled;
        self.commit(state)?;
        self.scriptless_payout_summary(reservation_id)
    }

    /// Record abandonment without releasing an exposed output or its private
    /// material. A later authenticated DOM terminal authority is required for
    /// any release; none is inferred locally.
    pub fn scriptless_payout_abandon_exposed(
        &mut self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessPayoutReservationSummaryV1, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_payout_index(&state, reservation_id)?;
        match state.scriptless_payout_reservations[index].state {
            ScriptlessPayoutReservationState::SessionBound
            | ScriptlessPayoutReservationState::ComponentsExposed
            | ScriptlessPayoutReservationState::TemplateBound => {
                state.scriptless_payout_reservations[index].state =
                    ScriptlessPayoutReservationState::AbandonedRetained;
                self.commit(state)?;
            }
            ScriptlessPayoutReservationState::AbandonedRetained => {}
            _ => return Err(CoreError::ScriptlessPayoutCannotRelease),
        }
        self.scriptless_payout_summary(reservation_id)
    }

    pub fn scriptless_payout_status(
        &self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessPayoutReservationSummaryV1, CoreError> {
        self.scriptless_payout_summary(reservation_id)
    }

    fn scriptless_payout_resume_preparation(
        &mut self,
        reservation_id: Uuid,
    ) -> Result<(), CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = state.scriptless_payout_reservations
            [find_scriptless_payout_index(state, reservation_id)?]
        .clone();
        match record.state {
            ScriptlessPayoutReservationState::Prepared
            | ScriptlessPayoutReservationState::SessionBound
            | ScriptlessPayoutReservationState::ComponentsExposed
            | ScriptlessPayoutReservationState::TemplateBound => return Ok(()),
            ScriptlessPayoutReservationState::Reserved => {}
            ScriptlessPayoutReservationState::AbandonedRetained
            | ScriptlessPayoutReservationState::Cancelled => {
                return Err(CoreError::ScriptlessPayoutCannotExport)
            }
        }

        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let builder = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .output_builder(&seed)?;
        let coordinate = record
            .derivation_index
            .map(|derivation_index| {
                state.resume_recovery_coordinate(
                    0,
                    derivation_index,
                    RecoveryOutputClass::SelfTransfer,
                )
            })
            .transpose()?;
        let prepared = builder.build_scriptless_shared_output_spend_contribution(
            record.payout_value_noms,
            coordinate,
        )?;
        let public = prepared.public.clone();
        let has_output = record.payout_value_noms != 0;
        if public.outputs.len() != usize::from(has_output)
            || prepared.owned_output.is_some() != has_output
            || prepared
                .owned_output
                .as_ref()
                .zip(public.outputs.first())
                .is_some_and(|(owned, output)| {
                    owned.commitment != *output.commitment.as_bytes()
                        || owned.value != record.payout_value_noms
                })
        {
            return Err(CoreError::ScriptlessPayoutContextMismatch);
        }
        let output_bytes = public
            .outputs
            .first()
            .map(|output| output.to_bytes().map_err(|_| CoreError::ProtocolRejected))
            .transpose()?
            .unwrap_or_default();
        let mut payout_excess = Zeroizing::new([0u8; 32]);
        prepared.copy_payout_excess_to(&mut payout_excess);
        let mut output_blinding = Zeroizing::new([0u8; 32]);
        let has_output_blinding = if let Some(owned) = &prepared.owned_output {
            owned.copy_blinding_to(&mut output_blinding);
            true
        } else {
            false
        };

        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_scriptless_payout_index(&state, reservation_id)?;
        if state.scriptless_payout_reservations[index].state
            != ScriptlessPayoutReservationState::Reserved
            || record
                .output_id
                .is_some_and(|output_id| state.outputs.iter().any(|output| output.id == output_id))
            || public.outputs.first().is_some_and(|public_output| {
                state
                    .outputs
                    .iter()
                    .any(|output| output.commitment == Some(*public_output.commitment.as_bytes()))
            })
        {
            return Err(CoreError::ScriptlessPayoutContextMismatch);
        }
        if let (Some(output_id), Some(public_output)) = (record.output_id, public.outputs.first()) {
            state.outputs.push(OutputRecord {
                id: output_id,
                account_id: state.default_account.id,
                commitment: Some(*public_output.commitment.as_bytes()),
                value: record.payout_value_noms,
                state: OutputState::PendingIncoming,
                discovered_height: 0,
                reserved_by: None,
            });
            state.remember_output_blinding(output_id, *output_blinding);
        }
        let record_mut = &mut state.scriptless_payout_reservations[index];
        record_mut.output_commitment = public
            .outputs
            .first()
            .map(|output| *output.commitment.as_bytes());
        record_mut.output_bytes = output_bytes;
        record_mut.offset_contribution = Some(public.offset_contribution);
        record_mut.payout_excess_public_key = public.payout_excess_public_key.to_vec();
        record_mut.private_context = Some(PrivateScriptlessPayoutContext::new(
            *payout_excess,
            has_output_blinding.then_some(*output_blinding),
        ));
        record_mut.state = ScriptlessPayoutReservationState::Prepared;
        self.commit(state)?; // Public output and private recovery state commit atomically.
        Ok(())
    }

    fn scriptless_payout_summary(
        &self,
        reservation_id: Uuid,
    ) -> Result<ScriptlessPayoutReservationSummaryV1, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let record = &state.scriptless_payout_reservations
            [find_scriptless_payout_index(state, reservation_id)?];
        Ok(ScriptlessPayoutReservationSummaryV1 {
            reservation_id,
            role: record.role,
            state: record.state,
            template_bound: record.template_hash.is_some(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transaction_send_create_recoverable(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
        sender: &WalletAddress,
        receiver: &WalletAddress,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CoreError> {
        self.transaction_send_create_with_identities(
            amount,
            requested_fee,
            Some(sender),
            Some(receiver),
            0,
            expires_at_height,
        )
    }

    /// Create an ordinary recovery-capable send under the canonical G-COVER
    /// policy, before any Slate byte or signature is created.
    ///
    /// The validated height comes from the currently attached canonical Core,
    /// not a peer claim or cached startup tip. A genesis-only snapshot has no
    /// valid nonzero HEIGHT_LOCKED value, so it produces an explicit PLAIN
    /// fallback. Rollout non-selection is also explicit and is not a fallback.
    pub fn transaction_send_create_with_cover(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
        expires_at_height: u64,
        policy: CoverLockPolicyV1,
    ) -> Result<CoverSendResult, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let snapshot = ValidatedChainSnapshotV1::from_validated_height(identity.current_tip.height);
        let decision = match policy.cover_lock_for_send(&snapshot, &mut rand::rngs::OsRng) {
            Ok(CoverLockOutcomeV1::Cover(lock_height)) => {
                CoverSendDecision::HeightLocked { lock_height }
            }
            Ok(CoverLockOutcomeV1::NotSelected) => CoverSendDecision::NotSelectedPlain,
            Err(_) if identity.current_tip.height == 0 => {
                CoverSendDecision::NoSatisfiedHeightPlainFallback
            }
            Err(_) => return Err(CoreError::CoverPolicyRejected),
        };
        let lock_height = match decision {
            CoverSendDecision::HeightLocked { lock_height } => lock_height,
            CoverSendDecision::NotSelectedPlain
            | CoverSendDecision::NoSatisfiedHeightPlainFallback => 0,
        };
        let transaction = self.transaction_send_create_with_identities(
            amount,
            requested_fee,
            None,
            None,
            lock_height,
            expires_at_height,
        )?;
        Ok(CoverSendResult {
            transaction,
            decision,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn transaction_send_create_with_identities(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
        sender: Option<&WalletAddress>,
        receiver: Option<&WalletAddress>,
        lock_height: u64,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CoreError> {
        if amount == 0 {
            return Err(CoreError::InvalidTransactionInput);
        }
        self.ensure_phrase_confirmed()?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        if lock_height > identity.current_tip.height {
            return Err(CoreError::CoverPolicyRejected);
        }
        validate_transaction_expiry(expires_at_height, identity.current_tip.height)?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let mut selected = Vec::new();
        let mut total = 0u64;
        let mut fee = 0u64;
        for output in spendable_outputs(&state) {
            selected.push(output.clone());
            let minimum = self
                .backend
                .as_ref()
                .ok_or(CoreError::EmbeddedCoreRequired)?
                .minimum_fee(WalletTransactionShape {
                    input_count: u32::try_from(selected.len())
                        .map_err(|_| CoreError::ArithmeticOverflow)?,
                    output_count: 2,
                    kernel_count: 1,
                })?;
            fee = requested_fee.unwrap_or(minimum.minimum_fee_noms);
            if fee < minimum.minimum_fee_noms {
                return Err(CoreError::FeeTooLow);
            }
            total = total
                .checked_add(output.value)
                .ok_or(CoreError::ArithmeticOverflow)?;
            if total
                >= amount
                    .checked_add(fee)
                    .ok_or(CoreError::ArithmeticOverflow)?
            {
                break;
            }
        }
        let required = amount
            .checked_add(fee)
            .ok_or(CoreError::ArithmeticOverflow)?;
        if total < required {
            return Err(CoreError::InsufficientFunds);
        }
        let change_value = total - required;
        let transaction_id = Uuid::new_v4();
        let coordinate = state.reserve_recovery_coordinate(0, RecoveryOutputClass::Change)?;
        let reserved_output_ids = selected.iter().map(|output| output.id).collect::<Vec<_>>();
        for output in &mut state.outputs {
            if reserved_output_ids.contains(&output.id) {
                if output.reserved_by.is_some() {
                    return Err(CoreError::ReservationConflict);
                }
                output.reserved_by = Some(transaction_id);
                output.state = OutputState::PendingOutgoing;
            }
        }
        let mut slate_id = [0u8; 32];
        let mut replay_id = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut slate_id)
            .map_err(|_| CoreError::RandomnessUnavailable)?;
        rand::rngs::OsRng
            .try_fill_bytes(&mut replay_id)
            .map_err(|_| CoreError::RandomnessUnavailable)?;
        let public_slate_id = uuid_from_protocol_id(slate_id);
        state.transactions.push(LocalTransactionIntent {
            id: transaction_id,
            created_at_height: identity.current_tip.height,
            created_at_unix_seconds: unix_seconds(),
            cancellation_reason: None,
            cancelled_at_height: None,
            kernel_excess: Vec::new(),
            lifecycle: TransactionLifecycle::InputsReserved,
            submitted: false,
            exposure: BroadcastExposure::NeverBroadcast,
            slate_id: Some(public_slate_id),
            role: Some(TransactionRole::Sender),
            amount,
            fee,
            reserved_output_ids,
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
            expires_at_height,
        });
        self.commit(state)?; // Coordinate and reservations are durable before construction.

        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let builder = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .output_builder(&seed)?;
        let inputs = selected
            .iter()
            .map(|output| {
                Ok(WalletSlateInput::new(
                    output
                        .commitment
                        .ok_or(CoreError::UnsupportedSpendingEvidence)?,
                    state
                        .output_blinding(output.id)
                        .ok_or(CoreError::UnsupportedSpendingEvidence)?,
                ))
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        let sender_parts = builder
            .build_sender_offer_with_lock_height(
                &inputs,
                change_value,
                amount,
                fee,
                lock_height,
                coordinate,
            )?
            .into_sender_parts()?;
        let (automatic_sender, automatic_receiver);
        let (sender, receiver) = match (sender, receiver) {
            (Some(sender), Some(receiver)) => (sender, receiver),
            (None, None) => {
                let (sender_key, receiver_key) = sender_parts.body.manual_interaction_public_keys();
                automatic_sender = WalletAddress::from_public_key(
                    sender_key,
                    identity.network,
                    AddressIdentityPurpose::TransactionInteraction,
                )?;
                automatic_receiver = WalletAddress::from_public_key(
                    receiver_key,
                    identity.network,
                    AddressIdentityPurpose::TransactionInteraction,
                )?;
                (&automatic_sender, &automatic_receiver)
            }
            _ => return Err(CoreError::AddressIdentityRequired),
        };
        let envelope = CanonicalSlate::new_recoverable(
            &identity,
            slate_id,
            replay_id,
            SlatePhase::SenderOffer,
            expires_at_height,
            sender,
            receiver,
            sender_parts.body.clone(),
        )?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, public_slate_id, TransactionRole::Sender)?;
        if let Some(change) = &sender_parts.change {
            let output_id = Uuid::new_v4();
            let mut blinding = Zeroizing::new([0u8; 32]);
            change.copy_blinding_to(&mut blinding);
            state.outputs.push(OutputRecord {
                id: output_id,
                account_id: state.default_account.id,
                commitment: Some(change.commitment),
                value: change.value,
                state: OutputState::PendingIncoming,
                discovered_height: 0,
                reserved_by: None,
            });
            state.remember_output_blinding(output_id, *blinding);
            state.transactions[index].change_output_id = Some(output_id);
        }
        let mut excess = Zeroizing::new([0u8; 32]);
        let mut nonce = Zeroizing::new([0u8; 32]);
        sender_parts.copy_signing_secrets_to(&mut excess, &mut nonce);
        state.transactions[index].private_context = Some(PrivateTransactionContext {
            sender_excess_blinding: Some(*excess),
            sender_nonce: Some(*nonce),
            recipient_output_blinding: None,
        });
        state.transactions[index].request_bytes = envelope.canonical_bytes().to_vec();
        self.commit(state)?;
        self.sender_secrets = Some((public_slate_id, sender_parts));
        self.transaction_summary(transaction_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transaction_send_create_with_addresses(
        &mut self,
        amount: u64,
        requested_fee: Option<u64>,
        sender_address: &str,
        receiver_address: &str,
        expires_at_height: u64,
    ) -> Result<TransactionSummary, CoreError> {
        let network = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .identity()
            .network;
        let sender = WalletAddress::parse(
            sender_address,
            network,
            AddressIdentityPurpose::TransactionInteraction,
        )?;
        let receiver = WalletAddress::parse(
            receiver_address,
            network,
            AddressIdentityPurpose::TransactionInteraction,
        )?;
        self.transaction_send_create_recoverable(
            amount,
            requested_fee,
            &sender,
            &receiver,
            expires_at_height,
        )
    }

    pub fn slate_request_export(&self, slate_id: Uuid) -> Result<SlateExport, CoreError> {
        self.ensure_phrase_confirmed()?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let index = find_transaction_index(state, slate_id, TransactionRole::Sender)?;
        let transaction = state
            .transactions
            .get(index)
            .ok_or(CoreError::TransactionNotFound)?;
        let slate = CanonicalSlate::from_recovery_bytes(
            &transaction.request_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        validate_transaction_expiry(slate.expires_at_height(), identity.current_tip.height)?;
        let export = SlateExport {
            transaction_id: transaction.id,
            slate_id,
            text: slate.to_text(),
        };
        Ok(export)
    }

    pub fn slate_request_import(&mut self, text: &str) -> Result<TransactionSummary, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let slate = CanonicalSlate::from_text(text, &identity, identity.current_tip.height)?;
        validate_transaction_expiry(slate.expires_at_height(), identity.current_tip.height)?;
        if slate.phase()? != SlatePhase::SenderOffer {
            return Err(CoreError::InvalidSlateTransport);
        }
        let replay = slate.replay_key();
        let slate_id = uuid_from_protocol_id(replay.slate_id);
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        if state
            .transactions
            .iter()
            .any(|tx| tx.slate_id == Some(slate_id))
        {
            return Err(CoreError::SlateReplayConflict);
        }
        let id = Uuid::new_v4();
        state.transactions.push(LocalTransactionIntent {
            id,
            created_at_height: identity.current_tip.height,
            created_at_unix_seconds: unix_seconds(),
            cancellation_reason: None,
            cancelled_at_height: None,
            kernel_excess: Vec::new(),
            lifecycle: TransactionLifecycle::RequestImported,
            submitted: false,
            exposure: BroadcastExposure::NeverBroadcast,
            slate_id: Some(slate_id),
            role: Some(TransactionRole::Recipient),
            amount: slate.recovery_body()?.amount_noms(),
            fee: slate.fee_noms(),
            reserved_output_ids: Vec::new(),
            request_bytes: slate.canonical_bytes().to_vec(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
            expires_at_height: slate.expires_at_height(),
        });
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn slate_response_create(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Recipient)?;
        let coordinate = state.reserve_recovery_coordinate(0, RecoveryOutputClass::ReceiveSlate)?;
        self.commit(state)?; // Burn the recipient coordinate before response construction.
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let request = CanonicalSlate::from_recovery_bytes(
            &state.transactions[index].request_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        validate_transaction_expiry(request.expires_at_height(), identity.current_tip.height)?;
        let seed = CanonicalWalletSeed::from_entropy(&state.root_material)
            .map_err(|_| CoreError::RecoveryPhraseInvalid)?;
        let builder = RecoverableOutputBuilder::new(&seed, &identity)?;
        let recipient = builder
            .build_recipient_response(&request.recovery_body()?, coordinate)?
            .into_recipient_parts()?;
        let response = request.with_recovery_body(
            SlatePhase::ReceiverResponse,
            recipient.body,
            &identity,
            identity.current_tip.height,
        )?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let output_id = Uuid::new_v4();
        let mut blinding = Zeroizing::new([0u8; 32]);
        recipient.output.copy_blinding_to(&mut blinding);
        state.outputs.push(OutputRecord {
            id: output_id,
            account_id: state.default_account.id,
            commitment: Some(recipient.output.commitment),
            value: recipient.output.value,
            state: OutputState::PendingIncoming,
            discovered_height: 0,
            reserved_by: None,
        });
        state.remember_output_blinding(output_id, *blinding);
        state.transactions[index].recipient_output_id = Some(output_id);
        state.transactions[index].private_context = Some(PrivateTransactionContext {
            sender_excess_blinding: None,
            sender_nonce: None,
            recipient_output_blinding: Some(*blinding),
        });
        state.transactions[index].response_bytes = response.canonical_bytes().to_vec();
        state.transactions[index].transition(
            TransactionLifecycle::ResponsePrepared,
            TransactionTransitionEvidence::RecipientResponse,
        )?;
        let id = state.transactions[index].id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn slate_response_export(&self, slate_id: Uuid) -> Result<SlateExport, CoreError> {
        self.ensure_phrase_confirmed()?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let index = find_transaction_index(state, slate_id, TransactionRole::Recipient)?;
        let transaction = state
            .transactions
            .get(index)
            .ok_or(CoreError::TransactionNotFound)?;
        let slate = CanonicalSlate::from_recovery_bytes(
            &transaction.response_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        validate_transaction_expiry(slate.expires_at_height(), identity.current_tip.height)?;
        let export = SlateExport {
            transaction_id: transaction.id,
            slate_id,
            text: slate.to_text(),
        };
        Ok(export)
    }

    pub fn slate_response_import(&mut self, text: &str) -> Result<TransactionSummary, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let response = CanonicalSlate::from_text(text, &identity, identity.current_tip.height)?;
        validate_transaction_expiry(response.expires_at_height(), identity.current_tip.height)?;
        if response.phase()? != SlatePhase::ReceiverResponse {
            return Err(CoreError::InvalidSlateTransport);
        }
        let slate_id = uuid_from_protocol_id(response.replay_key().slate_id);
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let transaction = find_transaction_mut(&mut state, slate_id, TransactionRole::Sender)?;
        let request = CanonicalSlate::from_recovery_bytes(
            &transaction.request_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        validate_transaction_expiry(request.expires_at_height(), identity.current_tip.height)?;
        if request.replay_key() != response.replay_key() {
            return Err(CoreError::SlateReplayConflict);
        }
        transaction.response_bytes = response.canonical_bytes().to_vec();
        transaction.transition(
            TransactionLifecycle::ResponseImported,
            TransactionTransitionEvidence::RecipientResponse,
        )?;
        let id = transaction.id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn transaction_finalize(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        self.ensure_phrase_confirmed()?;
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let index = find_transaction_index(state, slate_id, TransactionRole::Sender)?;
        if state.transactions[index].lifecycle == TransactionLifecycle::Finalized {
            return Ok(transaction_summary_from(&state.transactions[index]));
        }
        let request = CanonicalSlate::from_recovery_bytes(
            &state.transactions[index].request_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        validate_transaction_expiry(request.expires_at_height(), identity.current_tip.height)?;
        let response = CanonicalSlate::from_recovery_bytes(
            &state.transactions[index].response_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        validate_transaction_expiry(response.expires_at_height(), identity.current_tip.height)?;
        let persisted_sender;
        let sender = if let Some((_, sender)) = self
            .sender_secrets
            .as_ref()
            .filter(|(id, _)| *id == slate_id)
        {
            sender
        } else {
            let context = state.transactions[index]
                .private_context
                .as_ref()
                .ok_or(CoreError::MissingPrivateContext)?;
            persisted_sender = RecoverableSenderParts::from_encrypted_context(
                request.recovery_body()?,
                context
                    .sender_excess_blinding
                    .ok_or(CoreError::MissingPrivateContext)?,
                context
                    .sender_nonce
                    .ok_or(CoreError::MissingPrivateContext)?,
            )?;
            &persisted_sender
        };
        let finalized = finalize_recoverable_transaction(
            &response.recovery_body()?,
            &request.recovery_body()?,
            sender,
            identity.chain_id,
        )?;
        verify_recoverable_transaction_against_response(
            &finalized.canonical_bytes,
            &response.recovery_body()?,
            &identity,
        )?;
        let transaction = Transaction::from_bytes(&finalized.canonical_bytes)
            .map_err(|_| CoreError::ProtocolRejected)?;
        if transaction.outputs.iter().any(|output| {
            output.to_bytes().map_or(true, |bytes| {
                bytes.len() != CANONICAL_TRANSACTION_OUTPUT_SIZE
            }) || output.recovery_capsule().ok().flatten().is_none()
        }) {
            return Err(CoreError::MixedOutputRegime);
        }
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        // The envelope is disposable after signing. Persist the exact canonical
        // transaction bytes in the encrypted generation before exposing the
        // Finalized lifecycle; restart/rebroadcast/refund must never depend on
        // recovering the negotiation envelope.
        state.transactions[index].finalized_transaction_bytes = finalized.canonical_bytes;
        state.transactions[index].transaction_hash = Some(finalized.transaction_hash);
        state.transactions[index].kernel_excess = finalized.kernel_excess.to_vec();
        state.transactions[index].transition(
            TransactionLifecycle::Finalized,
            TransactionTransitionEvidence::Finalization,
        )?;
        self.commit(state)?;
        self.transaction_summary(state_transaction_id(self.unlocked.as_ref(), index)?)
    }

    /// Export exact finalized transaction bytes after sender-side canonical DOM
    /// verification. This is the third, public-only message in the G0 manual
    /// exchange; it never exposes Slate private context.
    pub fn transaction_finalized_export(
        &self,
        slate_id: Uuid,
    ) -> Result<FinalizedTransactionExport, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let index = find_transaction_index(state, slate_id, TransactionRole::Sender)?;
        let transaction = &state.transactions[index];
        if transaction.lifecycle != TransactionLifecycle::Finalized {
            return Err(CoreError::InvalidTransactionTransition);
        }
        let response = CanonicalSlate::from_recovery_bytes(
            &transaction.response_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        let verified = verify_recoverable_transaction_against_response(
            &transaction.finalized_transaction_bytes,
            &response.recovery_body()?,
            &identity,
        )?;
        if transaction.transaction_hash != Some(verified.transaction_hash) {
            return Err(CoreError::ProtocolRejected);
        }
        Ok(FinalizedTransactionExport {
            transaction_id: transaction.id,
            slate_id,
            canonical_bytes: transaction.finalized_transaction_bytes.clone(),
            transaction_hash: verified.transaction_hash,
        })
    }

    /// Independently verify and durably retain a sender's exact finalized
    /// transaction against this recipient's persisted response.
    ///
    /// Repeating the identical import is idempotent. Different bytes for the
    /// same Slate fail closed, preventing a post-response substitution before
    /// broadcast.
    pub fn transaction_finalized_verify_and_import(
        &mut self,
        slate_id: Uuid,
        canonical_bytes: &[u8],
    ) -> Result<VerifiedRecoverableTransaction, CoreError> {
        let identity = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?
            .current_identity()?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let index = find_transaction_index(state, slate_id, TransactionRole::Recipient)?;
        let response = CanonicalSlate::from_recovery_bytes(
            &state.transactions[index].response_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        let verified = verify_recoverable_transaction_against_response(
            canonical_bytes,
            &response.recovery_body()?,
            &identity,
        )?;
        if !state.transactions[index]
            .finalized_transaction_bytes
            .is_empty()
            && state.transactions[index].finalized_transaction_bytes != canonical_bytes
        {
            return Err(CoreError::FinalizedTransactionConflict);
        }

        let mut state = state.clone();
        let transaction = &mut state.transactions[index];
        transaction.finalized_transaction_bytes = canonical_bytes.to_vec();
        transaction.transaction_hash = Some(verified.transaction_hash);
        transaction.kernel_excess = verified.kernel_excess.to_vec();
        self.commit(state)?;
        Ok(verified)
    }

    pub fn transaction_submit(&mut self, slate_id: Uuid) -> Result<TransactionSummary, CoreError> {
        self.submit_transaction(slate_id, false)
    }

    pub fn transaction_retry_submission(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        self.submit_transaction(slate_id, true)
    }

    pub fn transaction_reconcile_submission(
        &mut self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        let backend = self
            .backend
            .as_ref()
            .ok_or(CoreError::EmbeddedCoreRequired)?;
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        let index = find_transaction_index(state, slate_id, TransactionRole::Sender)?;
        let hash = state.transactions[index]
            .transaction_hash
            .ok_or(CoreError::ProtocolRejected)?;
        let identifier = WalletTransactionIdentifier::TransactionHash(hash);
        let query = backend.query_submission(identifier)?;
        let status = if matches!(query, WalletSubmissionQuery::Unknown) {
            Some(backend.transaction_status(identifier)?)
        } else {
            None
        };

        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        apply_submission_query(&mut state.transactions[index], query, status)?;
        let id = state.transactions[index].id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    fn submit_transaction(
        &mut self,
        slate_id: Uuid,
        retry: bool,
    ) -> Result<TransactionSummary, CoreError> {
        self.ensure_phrase_confirmed()?;
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        let tx = &state.transactions[index];
        if tx.lifecycle != TransactionLifecycle::Finalized
            && !(retry
                && matches!(
                    tx.lifecycle,
                    TransactionLifecycle::Submitting | TransactionLifecycle::RetransmitRequired
                ))
        {
            return Err(CoreError::InvalidTransactionTransition);
        }
        // Finalization ends Slate negotiation. Do not re-validate the disposable
        // envelope here: these persisted transaction bytes may be broadcast or
        // rebroadcast after `expires_at_height`, including when their kernel is
        // HEIGHT_LOCKED beyond the former envelope lifetime.
        let transaction = Transaction::from_bytes(&tx.finalized_transaction_bytes)
            .map_err(|_| CoreError::ProtocolRejected)?;
        let hash = tx.transaction_hash.ok_or(CoreError::ProtocolRejected)?;
        let kernel = (tx.kernel_excess.len() == 33)
            .then(|| tx.kernel_excess.clone().try_into().ok())
            .flatten();
        let submission = CanonicalTransactionSubmission::new(transaction, hash, kernel)?;
        state.transactions[index].transition(
            TransactionLifecycle::Submitting,
            TransactionTransitionEvidence::SubmissionStarted,
        )?;
        state.transactions[index].attempt_count = state.transactions[index]
            .attempt_count
            .checked_add(1)
            .ok_or(CoreError::ArithmeticOverflow)?;
        self.commit(state)?;
        let outcome = if retry {
            self.backend
                .as_ref()
                .ok_or(CoreError::EmbeddedCoreRequired)?
                .rebroadcast(WalletTransactionIdentifier::TransactionHash(hash))?
        } else {
            self.backend
                .as_ref()
                .ok_or(CoreError::EmbeddedCoreRequired)?
                .submit(&submission)?
        };
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = find_transaction_index(&state, slate_id, TransactionRole::Sender)?;
        apply_submission_outcome(&mut state.transactions[index], outcome)?;
        let id = state.transactions[index].id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    pub fn transaction_cancel(
        &mut self,
        slate_id: Uuid,
        confirm_exported: bool,
    ) -> Result<TransactionSummary, CoreError> {
        let mut state = self.unlocked.as_ref().ok_or(CoreError::Locked)?.clone();
        let index = state
            .transactions
            .iter()
            .position(|transaction| transaction.slate_id == Some(slate_id))
            .ok_or(CoreError::TransactionNotFound)?;
        match cancellation_decision(state.transactions[index].exposure) {
            CancellationDecision::ReleaseNeverBroadcastReservations => {}
            CancellationDecision::DenyPossiblyBroadcast => {
                return Err(CoreError::CannotCancelTransaction);
            }
            CancellationDecision::RequireReconciliation => {
                if state.transactions[index].lifecycle
                    != TransactionLifecycle::ReconciliationRequired
                {
                    state.transactions[index].transition(
                        TransactionLifecycle::ReconciliationRequired,
                        TransactionTransitionEvidence::ReconciliationEvidence,
                    )?;
                    self.commit(state)?;
                }
                return Err(CoreError::CannotCancelTransaction);
            }
        }
        if (matches!(
            state.transactions[index].lifecycle,
            TransactionLifecycle::RequestExported | TransactionLifecycle::ResponseExported
        ) || !state.transactions[index]
            .finalized_transaction_bytes
            .is_empty())
            && !confirm_exported
        {
            return Err(CoreError::ConfirmationRequired);
        }
        let reserved = state.transactions[index].reserved_output_ids.clone();
        for output in &mut state.outputs {
            if reserved.contains(&output.id) {
                output.reserved_by = None;
                if matches!(output.state, OutputState::PendingOutgoing) {
                    output.state = OutputState::Confirmed;
                }
            }
        }
        state.transactions[index].transition(
            TransactionLifecycle::Cancelled,
            TransactionTransitionEvidence::Cancellation,
        )?;
        state.transactions[index].cancellation_reason = Some(TransactionCancellationReason::Manual);
        state.transactions[index].cancelled_at_height = None;
        let id = state.transactions[index].id;
        self.commit(state)?;
        self.transaction_summary(id)
    }

    /// Desktop-facing name retained for the manual Slate workflow. The
    /// durable cancellation semantics live in `transaction_cancel`.
    pub fn slate_cancel(
        &mut self,
        slate_id: Uuid,
        confirm_exported: bool,
    ) -> Result<TransactionSummary, CoreError> {
        self.transaction_cancel(slate_id, confirm_exported)
    }

    pub fn transaction_list(&self) -> Result<Vec<TransactionSummary>, CoreError> {
        Ok(self
            .unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .transactions
            .iter()
            .map(transaction_summary_from)
            .collect())
    }

    pub fn transaction_detail_redacted(
        &self,
        slate_id: Uuid,
    ) -> Result<TransactionSummary, CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        state
            .transactions
            .iter()
            .find(|transaction| transaction.slate_id == Some(slate_id))
            .map(transaction_summary_from)
            .ok_or(CoreError::TransactionNotFound)
    }

    pub fn diagnostics(&self) -> DiagnosticSnapshot {
        let cursor = self
            .unlocked
            .as_ref()
            .and_then(|state| state.core_scan_cursor.as_deref())
            .and_then(|bytes| WalletScanCursor::from_bytes(bytes).ok());
        DiagnosticSnapshot {
            application_state: application_state_name(&self.state).into(),
            connection_state: if self.backend.is_some() {
                PRODUCTION_BACKEND_KIND.into()
            } else {
                "EMBEDDED_CORE_STOPPED".into()
            },
            generation: self.unlocked.as_ref().map(|state| state.generation),
            cursor_height: cursor.as_ref().map(|cursor| cursor.anchor_height),
            cursor_hash: cursor.map(|cursor| hex::encode(cursor.anchor_hash)),
            last_error: self.errors.synchronization.clone(),
        }
    }

    pub fn error_domains(&self) -> ErrorDomainSnapshot {
        self.errors.clone()
    }

    fn transaction_summary(&self, id: Uuid) -> Result<TransactionSummary, CoreError> {
        self.unlocked
            .as_ref()
            .ok_or(CoreError::Locked)?
            .transactions
            .iter()
            .find(|transaction| transaction.id == id)
            .map(transaction_summary_from)
            .ok_or(CoreError::TransactionNotFound)
    }

    fn password_text(&self) -> Result<&str, CoreError> {
        std::str::from_utf8(
            self.password
                .as_ref()
                .ok_or(CoreError::Locked)?
                .expose_for_crypto(),
        )
        .map_err(|_| CoreError::InvalidPassword)
    }

    fn ensure_phrase_confirmed(&self) -> Result<(), CoreError> {
        let state = self.unlocked.as_ref().ok_or(CoreError::Locked)?;
        if state
            .recovery
            .as_ref()
            .is_some_and(|recovery| recovery.phrase_confirmed)
        {
            Ok(())
        } else {
            Err(CoreError::RecoveryCeremonyRequired)
        }
    }

    fn commit(&mut self, state: WalletState) -> Result<(), CoreError> {
        let expected = self.unlocked.as_ref().ok_or(CoreError::Locked)?.generation;
        let committed = self
            .location
            .as_ref()
            .ok_or(CoreError::WalletNotOpen)?
            .commit(expected, state, self.password_text()?, self.kdf)?;
        self.metadata = Some(
            self.location
                .as_ref()
                .ok_or(CoreError::WalletNotOpen)?
                .metadata()?,
        );
        self.unlocked = Some(committed);
        Ok(())
    }

    fn ensure_closed(&self) -> Result<(), CoreError> {
        if self.state == ApplicationState::Closed {
            Ok(())
        } else {
            Err(CoreError::InvalidLifecycleState)
        }
    }
}

impl Drop for WalletService {
    fn drop(&mut self) {
        if let Some(mut backend) = self.backend.take() {
            let _ = backend.shutdown();
        }
    }
}

struct WalletRecoverySink {
    directory: WalletDirectory,
    state: WalletState,
    password: Zeroizing<String>,
    kdf: KdfParameters,
    seed: CanonicalWalletSeed,
    identity: CoreChainIdentity,
    observed_tip_height: Option<u64>,
    last_recovery_error: Option<SeedRestoreError>,
}

impl WalletRecoverySink {
    fn new(
        directory: WalletDirectory,
        state: WalletState,
        password: String,
        kdf: KdfParameters,
        seed: CanonicalWalletSeed,
        identity: CoreChainIdentity,
    ) -> Self {
        Self {
            directory,
            state,
            password: Zeroizing::new(password),
            kdf,
            seed,
            identity,
            observed_tip_height: None,
            last_recovery_error: None,
        }
    }

    fn commit(
        &mut self,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
        reorg: Option<CoreBlockReference>,
    ) -> Result<(), CoreError> {
        let mut next = self.state.clone();
        if let Some(anchor) = reorg {
            rewind_recovery_state(&mut next, anchor.height, batch.observed_tip.height)?;
        }
        if let Err(error) = apply_recovery_batch(
            &self.seed,
            dom_crypto::recovery::RecoveryChainContext {
                network_magic: self.identity.network_magic,
                chain_id: self.identity.chain_id,
            },
            &self.identity,
            &mut next,
            batch,
        ) {
            self.last_recovery_error = Some(error);
            return Err(error.into());
        }
        for transaction_id in
            cancel_expired_unfinalized_reservations(&mut next, batch.observed_tip.height)?
        {
            let transaction = next
                .transactions
                .iter()
                .find(|transaction| transaction.id == transaction_id)
                .ok_or(CoreError::TransactionNotFound)?;
            tracing::info!(
                %transaction_id,
                slate_id = ?transaction.slate_id,
                expires_at_height = transaction.expires_at_height,
                canonical_tip_height = batch.observed_tip.height,
                "automatically cancelled expired unfinalized Slate reservation"
            );
        }
        next.core_scan_cursor = Some(cursor.as_bytes().to_vec());
        // An offline-restored wallet completes its seed restore the moment the
        // committed cursor anchor catches up with the observed canonical tip.
        if next.seed_restore_status == Some(SeedRestoreStatus::InProgress) {
            let anchor_height = cursor
                .decode()
                .map_err(|_| CoreError::InvalidCoreCursor)?
                .anchor_height;
            if anchor_height >= batch.observed_tip.height {
                next.seed_restore_status = Some(SeedRestoreStatus::Complete);
                next.sync_status = SyncStatus::Synced;
            }
        }
        self.state = self.directory.commit(
            self.state.generation,
            next,
            self.password.as_str(),
            self.kdf,
        )?;
        self.observed_tip_height = Some(batch.observed_tip.height);
        Ok(())
    }
}

impl CoreScanTransactionSink for WalletRecoverySink {
    type Error = CoreError;

    fn core_cursor_state(&self) -> Result<PersistedCoreCursorState, Self::Error> {
        match self.state.core_scan_cursor.as_deref() {
            None => Ok(PersistedCoreCursorState::Absent),
            Some(bytes) => CoreCursorBytes::parse(bytes, &self.identity)
                .map(PersistedCoreCursorState::Valid)
                .map_err(|_| CoreError::InvalidCoreCursor),
        }
    }

    fn committed_canonical_hash(&self, height: u64) -> Result<Option<[u8; 32]>, Self::Error> {
        Ok(self
            .state
            .recovery_canonical_blocks
            .iter()
            .find(|block| block.height == height)
            .map(|block| block.block_hash))
    }

    fn commit_core_batch(
        &mut self,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error> {
        self.commit(batch, cursor, None)
    }

    fn commit_core_reorg(
        &mut self,
        safe_anchor: CoreBlockReference,
        batch: &CoreScanBatch,
        cursor: CoreCursorBytes,
    ) -> Result<(), Self::Error> {
        self.commit(batch, cursor, Some(safe_anchor))
    }
}

fn validate_password(password: &str) -> Result<(), CoreError> {
    if (8..=1024).contains(&password.len()) {
        Ok(())
    } else {
        Err(CoreError::InvalidPassword)
    }
}

pub fn validate_transaction_expiry(
    expires_at_height: u64,
    canonical_tip_height: u64,
) -> Result<(), CoreError> {
    // `expires_at_height` bounds only the interactive negotiation envelope.
    // It is deliberately unrelated to the finalized kernel's `lock_height`,
    // which may exceed it; finalized transaction validity is consensus-owned.
    if expires_at_height <= canonical_tip_height {
        return Err(CoreError::TransactionExpired);
    }
    let maximum = canonical_tip_height
        .checked_add(MAX_TRANSACTION_LIFETIME_BLOCKS)
        .ok_or(CoreError::ArithmeticOverflow)?;
    if expires_at_height > maximum {
        return Err(CoreError::TransactionLifetimeExceeded);
    }
    Ok(())
}

fn require_domain_identity(
    expected: &NetworkIdentity,
    core: &CoreChainIdentity,
) -> Result<(), CoreError> {
    if expected.network != map_network(core.network)
        || expected.chain_id != core.chain_id
        || expected.genesis_id != core.genesis_hash
    {
        Err(CoreError::IdentityMismatch)
    } else {
        Ok(())
    }
}

/// Canonical Mainnet identity assembled from the frozen desktop constants.
pub fn mainnet_network_identity() -> Result<NetworkIdentity, CoreError> {
    let mut chain_id = [0u8; 32];
    let mut genesis_id = [0u8; 32];
    hex::decode_to_slice(MAINNET_CHAIN_ID_HEX, &mut chain_id)
        .map_err(|_| CoreError::IdentityMismatch)?;
    hex::decode_to_slice(MAINNET_GENESIS_HASH_HEX, &mut genesis_id)
        .map_err(|_| CoreError::IdentityMismatch)?;
    Ok(NetworkIdentity {
        network: Network::Mainnet,
        chain_id,
        genesis_id,
    })
}

fn seed_restore_status_name(status: SeedRestoreStatus) -> &'static str {
    match status {
        SeedRestoreStatus::InProgress => "in_progress",
        SeedRestoreStatus::Complete => "complete",
    }
}

fn require_mainnet_identity(identity: &NetworkIdentity) -> Result<(), CoreError> {
    if identity.network != Network::Mainnet
        || hex::encode(identity.chain_id) != MAINNET_CHAIN_ID_HEX
        || hex::encode(identity.genesis_id) != MAINNET_GENESIS_HASH_HEX
    {
        Err(CoreError::IdentityMismatch)
    } else {
        Ok(())
    }
}

fn require_canonical_mainnet_when_applicable(identity: &NetworkIdentity) -> Result<(), CoreError> {
    if identity.network == Network::Mainnet {
        require_mainnet_identity(identity)
    } else {
        Ok(())
    }
}

fn map_network(network: dom_wallet_core_api::CoreNetwork) -> Network {
    match network {
        dom_wallet_core_api::CoreNetwork::Mainnet => Network::Mainnet,
        dom_wallet_core_api::CoreNetwork::Testnet => Network::PublicTestnet,
        dom_wallet_core_api::CoreNetwork::Regtest => Network::PrivateTestnet,
    }
}

fn spendable_outputs(state: &WalletState) -> Vec<&OutputRecord> {
    let mut outputs = state
        .outputs
        .iter()
        .filter(|output| {
            matches!(output.state, OutputState::Confirmed)
                && output.reserved_by.is_none()
                && output.commitment.is_some()
                && state.output_blinding(output.id).is_some()
        })
        .collect::<Vec<_>>();
    outputs.sort_by(|left, right| {
        left.value
            .cmp(&right.value)
            .then_with(|| left.commitment.cmp(&right.commitment))
            .then_with(|| left.id.cmp(&right.id))
    });
    outputs
}

fn find_scriptless_funding_index(
    state: &WalletState,
    reservation_id: Uuid,
) -> Result<usize, CoreError> {
    state
        .scriptless_funding_reservations
        .iter()
        .position(|reservation| reservation.id == reservation_id)
        .ok_or(CoreError::ScriptlessFundingReservationNotFound)
}

fn validate_session_share_binding(
    chain_id: [u8; 32],
    session_id: [u8; 32],
    session_share: &SessionBlindingShareCapabilityV1,
) -> Result<([u8; 32], u16), CoreError> {
    let binding = session_share.binding();
    let participant_position = binding.participant_index();
    let binding_digest = binding.binding_digest_v1();
    if chain_id == [0u8; 32]
        || session_id == [0u8; 32]
        || binding.chain_id() != &chain_id
        || binding.session_id() != &session_id
        || binding.roster().len() != SCRIPTLESS_PARTICIPANT_COUNT_V1 as usize
        || participant_position >= SCRIPTLESS_PARTICIPANT_COUNT_V1 as u16
        || binding.terms_hash() == &[0u8; 32]
        || binding.capsule_hash() == &[0u8; 32]
        || binding_digest == [0u8; 32]
        || binding.roster().get(usize::from(participant_position)) != Some(binding.participant_id())
        || binding.share_point() != session_share.public_key()
    {
        return Err(CoreError::ScriptlessSessionBindingMismatch);
    }
    Ok((binding_digest, participant_position))
}

fn require_persisted_session_binding(
    record: &ScriptlessFundingReservation,
    binding_digest: [u8; 32],
    participant_position: u16,
) -> Result<(), CoreError> {
    if record.session_share_binding_digest != Some(binding_digest)
        || record.participant_position != Some(u32::from(participant_position))
    {
        return Err(CoreError::ScriptlessSessionBindingMismatch);
    }
    Ok(())
}

fn require_persisted_payout_session_binding(
    record: &ScriptlessPayoutReservation,
    binding_digest: [u8; 32],
    participant_position: u16,
) -> Result<(), CoreError> {
    if record.session_share_binding_digest != Some(binding_digest)
        || record.participant_position != Some(u32::from(participant_position))
    {
        return Err(CoreError::ScriptlessSessionBindingMismatch);
    }
    Ok(())
}

fn bound_signing_context(
    record: &ScriptlessFundingReservation,
    chain_id: [u8; 32],
) -> Result<BoundScriptlessSigningContextV1, CoreError> {
    Ok(BoundScriptlessSigningContextV1 {
        chain_id,
        session_id: record.session_id,
        session_share_binding_digest: record
            .session_share_binding_digest
            .ok_or(CoreError::ScriptlessSessionBindingRequired)?,
        participant_position: record
            .participant_position
            .ok_or(CoreError::ScriptlessSessionBindingRequired)?
            .try_into()
            .map_err(|_| CoreError::ScriptlessSessionBindingMismatch)?,
        template_hash: record
            .template_hash
            .ok_or(CoreError::ScriptlessTemplateBindingMismatch)?,
    })
}

fn bound_payout_signing_context(
    record: &ScriptlessPayoutReservation,
    chain_id: [u8; 32],
) -> Result<BoundScriptlessSigningContextV1, CoreError> {
    Ok(BoundScriptlessSigningContextV1 {
        chain_id,
        session_id: record.session_id,
        session_share_binding_digest: record
            .session_share_binding_digest
            .ok_or(CoreError::ScriptlessSessionBindingRequired)?,
        participant_position: record
            .participant_position
            .ok_or(CoreError::ScriptlessSessionBindingRequired)?
            .try_into()
            .map_err(|_| CoreError::ScriptlessSessionBindingMismatch)?,
        template_hash: record
            .template_hash
            .ok_or(CoreError::ScriptlessTemplateBindingMismatch)?,
    })
}

fn parse_funding_public_key(bytes: &[u8]) -> Result<PublicKey, CoreError> {
    let bytes: [u8; 33] = bytes
        .try_into()
        .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?;
    PublicKey::from_compressed_bytes(&bytes)
        .map_err(|_| CoreError::ScriptlessFundingContextMismatch)
}

fn parse_payout_public_key(bytes: &[u8]) -> Result<PublicKey, CoreError> {
    let bytes: [u8; 33] = bytes
        .try_into()
        .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?;
    PublicKey::from_compressed_bytes(&bytes).map_err(|_| CoreError::ScriptlessPayoutContextMismatch)
}

/// Check only the participant-local portion of a frozen aggregate funding
/// shape. The shared output is global, so it is counted exactly once for every
/// participant regardless of which wallet contributes the real inputs. Exact
/// aggregate equality and uniqueness are enforced later against the typed DOM
/// template.
fn validate_scriptless_funding_local_shape(
    local_input_count: usize,
    local_other_output_count: usize,
    expected_input_count: u32,
    expected_output_count: u32,
) -> Result<(), CoreError> {
    let minimum_global_output_count = local_other_output_count
        .checked_add(1)
        .ok_or(CoreError::ArithmeticOverflow)?;
    if local_input_count > expected_input_count as usize
        || minimum_global_output_count > expected_output_count as usize
    {
        return Err(CoreError::ScriptlessFundingShapeMismatch);
    }
    Ok(())
}

fn validate_template_participant_set(
    transaction: &Transaction,
    local_offset: [u8; 32],
    local_kernel_excess_point: [u8; 33],
    participant_position: u16,
    participants: ScriptlessTemplateParticipantSetV1,
) -> Result<ScriptlessTemplateParticipantBindingV1, CoreError> {
    let position = usize::from(participant_position);
    if participants.ordered_offset_contributions.get(position) != Some(&local_offset)
        || participants.ordered_kernel_excess_points.get(position)
            != Some(&local_kernel_excess_point)
        || transaction.kernels.len() != 1
    {
        return Err(CoreError::ScriptlessTemplateBindingMismatch);
    }
    let aggregate_offset =
        aggregate_transaction_offset_contributions_v1(&participants.ordered_offset_contributions)
            .map_err(|_| CoreError::ScriptlessTemplateBindingMismatch)?;
    if transaction.offset != aggregate_offset {
        return Err(CoreError::ScriptlessTemplateBindingMismatch);
    }
    let points = participants
        .ordered_kernel_excess_points
        .iter()
        .map(|point| PublicKey::from_compressed_bytes(point.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreError::ScriptlessTemplateBindingMismatch)?;
    let aggregate_point = scriptless_add_public_points(&points)
        .map_err(|_| CoreError::ScriptlessTemplateBindingMismatch)?;
    if transaction.kernels[0].excess.as_bytes() != &aggregate_point.to_compressed_bytes() {
        return Err(CoreError::ScriptlessTemplateBindingMismatch);
    }
    Ok(ScriptlessTemplateParticipantBindingV1::new(
        participants.ordered_offset_contributions,
        participants.ordered_kernel_excess_points,
    ))
}

fn scriptless_funding_composition(
    record: &ScriptlessFundingReservation,
    chain_id: [u8; 32],
) -> Result<ScriptlessFundingCompositionV1, CoreError> {
    if !matches!(
        record.state,
        ScriptlessFundingReservationState::Exported
            | ScriptlessFundingReservationState::TemplateBound
    ) || record.offset_contribution.is_none()
        || record.wallet_excess_public_key.len() != 33
        || record.reserved_output_ids.len() != record.input_commitments.len()
    {
        return Err(CoreError::ScriptlessFundingNotPrepared);
    }
    let inputs = record
        .input_commitments
        .iter()
        .map(|commitment| {
            let commitment: [u8; 33] = commitment
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?;
            Ok(TransactionInput {
                commitment: dom_crypto::pedersen::Commitment::from_compressed_bytes(&commitment)
                    .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?,
            })
        })
        .collect::<Result<Vec<_>, CoreError>>()?;
    let other_outputs = if record.change_output_bytes.is_empty() {
        Vec::new()
    } else {
        let output = TransactionOutput::from_bytes(&record.change_output_bytes)
            .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?;
        if output
            .to_bytes()
            .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?
            != record.change_output_bytes
            || Some(*output.commitment.as_bytes()) != record.change_commitment
        {
            return Err(CoreError::ScriptlessFundingContextMismatch);
        }
        let capsule = output
            .recovery_capsule()
            .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?
            .ok_or(CoreError::ScriptlessFundingContextMismatch)?;
        let proof = output
            .range_proof_bytes()
            .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?;
        if !dom_crypto::range_proof_verify_with_extra_commit(
            output.commitment.as_bytes(),
            proof,
            capsule.as_bytes(),
        )
        .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?
        {
            return Err(CoreError::ScriptlessFundingContextMismatch);
        }
        vec![output]
    };
    validate_scriptless_funding_local_shape(
        inputs.len(),
        other_outputs.len(),
        record.expected_input_count,
        record.expected_output_count,
    )?;
    dom_crypto::pedersen::Commitment::from_compressed_bytes(&record.shared_output_commitment)
        .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?;
    dom_crypto::pedersen::BlindingFactor::from_bytes(
        record
            .offset_contribution
            .ok_or(CoreError::ScriptlessFundingNotPrepared)?,
    )
    .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?;
    let wallet_excess_public_key: [u8; 33] = record
        .wallet_excess_public_key
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?;
    dom_crypto::PublicKey::from_compressed_bytes(&wallet_excess_public_key)
        .map_err(|_| CoreError::ScriptlessFundingContextMismatch)?;

    let context = record
        .private_context
        .as_ref()
        .ok_or(CoreError::ScriptlessFundingNotPrepared)?;
    let mut private = Zeroizing::new([0u8; 32]);
    context.copy_wallet_excess_contribution_to(&mut private);
    let opaque = OpaqueScriptlessFundingExcessV1::from_encrypted_context(*private)?;
    if opaque.public_key_bytes() != wallet_excess_public_key {
        return Err(CoreError::ScriptlessFundingContextMismatch);
    }

    Ok(ScriptlessFundingCompositionV1 {
        reservation_id: record.id,
        session_id: record.session_id,
        chain_id,
        shared_output_commitment: record.shared_output_commitment,
        inputs,
        other_outputs,
        offset_contribution: record
            .offset_contribution
            .ok_or(CoreError::ScriptlessFundingNotPrepared)?,
        wallet_excess_public_key,
        funding_fee_noms: record.funding_fee_noms,
        expected_input_count: record.expected_input_count,
        expected_output_count: record.expected_output_count,
    })
}

fn find_scriptless_payout_index(
    state: &WalletState,
    reservation_id: Uuid,
) -> Result<usize, CoreError> {
    state
        .scriptless_payout_reservations
        .iter()
        .position(|reservation| reservation.id == reservation_id)
        .ok_or(CoreError::ScriptlessPayoutReservationNotFound)
}

fn scriptless_payout_composition(
    record: &ScriptlessPayoutReservation,
    chain_id: [u8; 32],
) -> Result<ScriptlessPayoutCompositionV1, CoreError> {
    let has_output = record.payout_value_noms != 0;
    if !matches!(
        record.state,
        ScriptlessPayoutReservationState::ComponentsExposed
            | ScriptlessPayoutReservationState::TemplateBound
    ) || record.output_bytes.is_empty() == has_output
        || record.output_commitment.is_some() != has_output
        || record.offset_contribution.is_none()
        || record.payout_excess_public_key.len() != 33
        || record.expected_output_count == 0
    {
        return Err(CoreError::ScriptlessPayoutNotPrepared);
    }
    let outputs = if has_output {
        let output = TransactionOutput::from_bytes(&record.output_bytes)
            .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?;
        if output
            .to_bytes()
            .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?
            != record.output_bytes
            || record.output_commitment != Some(*output.commitment.as_bytes())
        {
            return Err(CoreError::ScriptlessPayoutContextMismatch);
        }
        let capsule = output
            .recovery_capsule()
            .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?
            .ok_or(CoreError::ScriptlessPayoutContextMismatch)?;
        let proof = output
            .range_proof_bytes()
            .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?;
        if !dom_crypto::range_proof_verify_with_extra_commit(
            output.commitment.as_bytes(),
            proof,
            capsule.as_bytes(),
        )
        .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?
        {
            return Err(CoreError::ScriptlessPayoutContextMismatch);
        }
        vec![output]
    } else {
        Vec::new()
    };
    if outputs.len() > record.expected_output_count as usize {
        return Err(CoreError::ScriptlessPayoutContextMismatch);
    }
    dom_crypto::pedersen::Commitment::from_compressed_bytes(&record.shared_output_commitment)
        .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?;
    dom_crypto::pedersen::BlindingFactor::from_bytes(
        record
            .offset_contribution
            .ok_or(CoreError::ScriptlessPayoutNotPrepared)?,
    )
    .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?;
    let payout_excess_public_key: [u8; 33] = record
        .payout_excess_public_key
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?;
    dom_crypto::PublicKey::from_compressed_bytes(&payout_excess_public_key)
        .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?;

    let context = record
        .private_context
        .as_ref()
        .ok_or(CoreError::ScriptlessPayoutNotPrepared)?;
    let mut private = Zeroizing::new([0u8; 32]);
    context.copy_payout_excess_contribution_to(&mut private);
    let mut output_blinding = Zeroizing::new([0u8; 32]);
    let has_output_blinding = context.copy_output_blinding_to(&mut output_blinding);
    if has_output_blinding != has_output {
        return Err(CoreError::ScriptlessPayoutContextMismatch);
    }
    if let Some(output) = outputs.first() {
        let output_blinding_factor =
            dom_crypto::pedersen::BlindingFactor::from_bytes(*output_blinding)
                .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?;
        if dom_crypto::pedersen::Commitment::commit(
            record.payout_value_noms,
            &output_blinding_factor,
        ) != output.commitment
        {
            return Err(CoreError::ScriptlessPayoutContextMismatch);
        }
    }
    let recomputed = Zeroizing::new(
        sender_excess_blinding(
            std::iter::empty::<&[u8; 32]>(),
            has_output.then_some(&*output_blinding),
            record
                .offset_contribution
                .as_ref()
                .ok_or(CoreError::ScriptlessPayoutNotPrepared)?,
        )
        .map_err(|_| CoreError::ScriptlessPayoutContextMismatch)?,
    );
    if *recomputed != *private {
        return Err(CoreError::ScriptlessPayoutContextMismatch);
    }
    let opaque = OpaqueScriptlessPayoutExcessV1::from_encrypted_context(*private)?;
    if opaque.public_key_bytes() != payout_excess_public_key {
        return Err(CoreError::ScriptlessPayoutContextMismatch);
    }

    Ok(ScriptlessPayoutCompositionV1 {
        reservation_id: record.id,
        session_id: record.session_id,
        chain_id,
        role: record.role,
        shared_output_commitment: record.shared_output_commitment,
        outputs,
        offset_contribution: record
            .offset_contribution
            .ok_or(CoreError::ScriptlessPayoutNotPrepared)?,
        payout_excess_public_key,
        kernel_fee_noms: record.kernel_fee_noms,
        expected_output_count: record.expected_output_count,
        refund_lock_height: record.refund_lock_height,
    })
}

fn find_transaction_index(
    state: &WalletState,
    slate_id: Uuid,
    role: TransactionRole,
) -> Result<usize, CoreError> {
    state
        .transactions
        .iter()
        .position(|transaction| {
            transaction.slate_id == Some(slate_id) && transaction.role == Some(role.clone())
        })
        .ok_or(CoreError::TransactionNotFound)
}

fn find_transaction_mut(
    state: &mut WalletState,
    slate_id: Uuid,
    role: TransactionRole,
) -> Result<&mut LocalTransactionIntent, CoreError> {
    let index = find_transaction_index(state, slate_id, role)?;
    state
        .transactions
        .get_mut(index)
        .ok_or(CoreError::TransactionNotFound)
}

fn uuid_from_protocol_id(id: [u8; 32]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&id[..16]);
    Uuid::from_bytes(bytes)
}

fn state_transaction_id(state: Option<&WalletState>, index: usize) -> Result<Uuid, CoreError> {
    state
        .and_then(|state| state.transactions.get(index))
        .map(|transaction| transaction.id)
        .ok_or(CoreError::TransactionNotFound)
}

fn apply_submission_outcome(
    transaction: &mut LocalTransactionIntent,
    outcome: WalletSubmissionOutcome,
) -> Result<(), CoreError> {
    let (lifecycle, evidence) = match outcome {
        WalletSubmissionOutcome::Accepted(evidence) if evidence.relayed => {
            transaction.submitted = true;
            (
                TransactionLifecycle::Submitted,
                TransactionTransitionEvidence::SubmissionOutcome,
            )
        }
        WalletSubmissionOutcome::Accepted(_) => {
            transaction.submitted = true;
            (
                TransactionLifecycle::AcceptedNotRelayed,
                TransactionTransitionEvidence::SubmissionOutcome,
            )
        }
        WalletSubmissionOutcome::AlreadyKnown(_) => {
            transaction.submitted = true;
            (
                TransactionLifecycle::InMempool,
                TransactionTransitionEvidence::MempoolObservation,
            )
        }
        WalletSubmissionOutcome::NodeNotReady(_)
        | WalletSubmissionOutcome::TemporaryFailure(_)
        | WalletSubmissionOutcome::InternalFailure(_) => (
            TransactionLifecycle::RetransmitRequired,
            TransactionTransitionEvidence::SubmissionOutcome,
        ),
        WalletSubmissionOutcome::RejectedInvalid(_)
        | WalletSubmissionOutcome::RejectedFee(_)
        | WalletSubmissionOutcome::RejectedDoubleSpend(_)
        | WalletSubmissionOutcome::RejectedImmatureCoinbase(_)
        | WalletSubmissionOutcome::RejectedExpired(_)
        | WalletSubmissionOutcome::RejectedPolicy(_) => (
            TransactionLifecycle::Failed,
            TransactionTransitionEvidence::SubmissionOutcome,
        ),
    };
    transaction.transition(lifecycle, evidence)?;
    Ok(())
}

fn apply_submission_query(
    transaction: &mut LocalTransactionIntent,
    query: WalletSubmissionQuery,
    status: Option<WalletTransactionStatus>,
) -> Result<(), CoreError> {
    match query {
        WalletSubmissionQuery::InMempool(outcome) => {
            apply_submission_outcome(transaction, outcome)?;
            transaction.submitted = true;
            transaction.transition(
                TransactionLifecycle::InMempool,
                TransactionTransitionEvidence::MempoolObservation,
            )?;
        }
        WalletSubmissionQuery::Confirmed {
            height, block_hash, ..
        } => {
            transaction.submitted = true;
            transaction.transition(
                TransactionLifecycle::Confirmed { height, block_hash },
                TransactionTransitionEvidence::ConfirmationEvidence,
            )?;
        }
        WalletSubmissionQuery::Rejected(outcome)
        | WalletSubmissionQuery::TemporarilyUnavailable(outcome) => {
            apply_submission_outcome(transaction, outcome)?;
        }
        WalletSubmissionQuery::Unknown => match status {
            Some(WalletTransactionStatus::Confirmed { height, block_hash }) => {
                transaction.submitted = true;
                transaction.transition(
                    TransactionLifecycle::Confirmed { height, block_hash },
                    TransactionTransitionEvidence::ConfirmationEvidence,
                )?;
            }
            Some(WalletTransactionStatus::InMempool) => {
                transaction.submitted = true;
                transaction.transition(
                    TransactionLifecycle::InMempool,
                    TransactionTransitionEvidence::MempoolObservation,
                )?;
            }
            Some(WalletTransactionStatus::Unknown)
                if matches!(
                    transaction.lifecycle,
                    TransactionLifecycle::Confirmed { .. }
                ) =>
            {
                transaction.transition(
                    TransactionLifecycle::Reorged,
                    TransactionTransitionEvidence::ReorgEvidence,
                )?;
            }
            Some(WalletTransactionStatus::Unknown) | None => {
                transaction.transition(
                    TransactionLifecycle::ReconciliationRequired,
                    TransactionTransitionEvidence::ReconciliationEvidence,
                )?;
            }
        },
    }
    Ok(())
}

fn summary_from_state(
    state: &WalletState,
    application_state: &str,
    observed_tip_height: Option<u64>,
) -> WalletSummary {
    WalletSummary {
        wallet_id: state.wallet_id,
        network: state.identity.network,
        generation: state.generation,
        cursor_height: state
            .core_scan_cursor
            .as_deref()
            .and_then(|bytes| WalletScanCursor::from_bytes(bytes).ok())
            .map(|cursor| cursor.anchor_height),
        tip_height: observed_tip_height,
        seed_restore_status: state
            .seed_restore_status
            .map(|status| seed_restore_status_name(status).into()),
        balance: state.balance(),
        state: application_state.into(),
        experimental: true,
        unaudited: true,
    }
}

fn transaction_summary_from(transaction: &LocalTransactionIntent) -> TransactionSummary {
    TransactionSummary {
        id: transaction.id,
        slate_id: transaction.slate_id,
        created_at_height: (transaction.created_at_height != 0)
            .then_some(transaction.created_at_height),
        created_at_unix_seconds: (transaction.created_at_unix_seconds != 0)
            .then_some(transaction.created_at_unix_seconds),
        role: transaction.role.as_ref().map(|role| match role {
            TransactionRole::Sender => "SENDER".into(),
            TransactionRole::Recipient => "RECIPIENT".into(),
        }),
        state: transaction_state_name(&transaction.lifecycle).into(),
        amount: transaction.amount,
        fee: transaction.fee,
        kernel_excess: (transaction.kernel_excess.len() == 33)
            .then(|| hex::encode(&transaction.kernel_excess)),
        transaction_hash: transaction.transaction_hash.map(hex::encode),
        attempt_count: transaction.attempt_count,
        expires_at_height: transaction.expires_at_height,
        has_finalized_transaction: !transaction.finalized_transaction_bytes.is_empty(),
        manual_cancel_allowed: transaction.exposure == BroadcastExposure::NeverBroadcast
            && !matches!(
                transaction.lifecycle,
                TransactionLifecycle::Cancelled
                    | TransactionLifecycle::Confirmed { .. }
                    | TransactionLifecycle::Submitting
                    | TransactionLifecycle::Submitted
                    | TransactionLifecycle::AcceptedNotRelayed
                    | TransactionLifecycle::InMempool
                    | TransactionLifecycle::Reorged
                    | TransactionLifecycle::RetransmitRequired
                    | TransactionLifecycle::ReconciliationRequired
            ),
        manual_cancel_warning: !transaction.finalized_transaction_bytes.is_empty()
            && transaction.exposure == BroadcastExposure::NeverBroadcast
            && !matches!(
                transaction.lifecycle,
                TransactionLifecycle::Cancelled | TransactionLifecycle::Confirmed { .. }
            ),
        awaiting_broadcast_confirmation: !transaction.finalized_transaction_bytes.is_empty()
            && !matches!(
                transaction.lifecycle,
                TransactionLifecycle::Cancelled | TransactionLifecycle::Confirmed { .. }
            ),
        cancellation_reason: transaction.cancellation_reason.map(|reason| match reason {
            TransactionCancellationReason::Manual => "MANUAL".into(),
            TransactionCancellationReason::ExpiredBeforeFinalization => {
                "EXPIRED_BEFORE_FINALIZATION".into()
            }
        }),
        cancelled_at_height: transaction.cancelled_at_height,
    }
}

fn cancel_expired_unfinalized_reservations(
    state: &mut WalletState,
    canonical_tip_height: u64,
) -> Result<Vec<Uuid>, CoreError> {
    let expiring = state
        .transactions
        .iter()
        .enumerate()
        .filter(|(_, transaction)| {
            transaction.role == Some(TransactionRole::Sender)
                && !transaction.reserved_output_ids.is_empty()
                && transaction.finalized_transaction_bytes.is_empty()
                && transaction.expires_at_height != 0
                && transaction.expires_at_height <= canonical_tip_height
                && transaction.exposure == BroadcastExposure::NeverBroadcast
                && !matches!(
                    transaction.lifecycle,
                    TransactionLifecycle::Cancelled
                        | TransactionLifecycle::Confirmed { .. }
                        | TransactionLifecycle::Submitting
                        | TransactionLifecycle::Submitted
                        | TransactionLifecycle::AcceptedNotRelayed
                        | TransactionLifecycle::InMempool
                        | TransactionLifecycle::Reorged
                        | TransactionLifecycle::RetransmitRequired
                        | TransactionLifecycle::ReconciliationRequired
                )
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let mut cancelled = Vec::with_capacity(expiring.len());
    for index in expiring {
        let transaction_id = state.transactions[index].id;
        let reserved = state.transactions[index].reserved_output_ids.clone();
        for output in &mut state.outputs {
            if reserved.contains(&output.id) && output.reserved_by == Some(transaction_id) {
                output.reserved_by = None;
                if matches!(output.state, OutputState::PendingOutgoing) {
                    output.state = OutputState::Confirmed;
                }
            }
        }
        state.transactions[index].transition(
            TransactionLifecycle::Cancelled,
            TransactionTransitionEvidence::Cancellation,
        )?;
        state.transactions[index].cancellation_reason =
            Some(TransactionCancellationReason::ExpiredBeforeFinalization);
        state.transactions[index].cancelled_at_height = Some(canonical_tip_height);
        cancelled.push(transaction_id);
    }
    Ok(cancelled)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn transaction_state_name(state: &TransactionLifecycle) -> &'static str {
    match state {
        TransactionLifecycle::Draft => "DRAFT",
        TransactionLifecycle::InputsReserved => "INPUTS_RESERVED",
        TransactionLifecycle::RequestExported => "REQUEST_EXPORTED",
        TransactionLifecycle::RequestImported => "REQUEST_IMPORTED",
        TransactionLifecycle::ResponsePrepared => "RESPONSE_PREPARED",
        TransactionLifecycle::ResponseExported => "RESPONSE_EXPORTED",
        TransactionLifecycle::ResponseImported => "RESPONSE_IMPORTED",
        TransactionLifecycle::Finalized => "FINALIZED",
        TransactionLifecycle::Submitting => "SUBMITTING",
        TransactionLifecycle::Submitted => "SUBMITTED",
        TransactionLifecycle::AcceptedNotRelayed => "ACCEPTED_NOT_RELAYED",
        TransactionLifecycle::InMempool => "IN_MEMPOOL",
        TransactionLifecycle::Confirmed { .. } => "CONFIRMED",
        TransactionLifecycle::Reorged => "REORGED",
        TransactionLifecycle::RetransmitRequired => "RETRANSMIT_REQUIRED",
        TransactionLifecycle::Cancelled => "CANCELLED",
        TransactionLifecycle::Failed => "FAILED",
        TransactionLifecycle::ReconciliationRequired => "RECONCILIATION_REQUIRED",
    }
}

fn application_state_name(state: &ApplicationState) -> &'static str {
    match state {
        ApplicationState::Closed => "CLOSED",
        ApplicationState::Locked => "LOCKED",
        ApplicationState::Unlocking => "UNLOCKING",
        ApplicationState::Unlocked => "READY",
        ApplicationState::Synchronizing => "SYNCHRONIZING",
        ApplicationState::Degraded { .. } => "DEGRADED",
        ApplicationState::Error { .. } => "ERROR",
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("wallet is not open")]
    WalletNotOpen,
    #[error("wallet is locked")]
    Locked,
    #[error("wallet lifecycle state does not permit this operation")]
    InvalidLifecycleState,
    #[error("password does not meet local requirements")]
    InvalidPassword,
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("BIP-39 recovery ceremony is required")]
    RecoveryCeremonyRequired,
    #[error("BIP-39 recovery phrase was already confirmed")]
    RecoveryPhraseAlreadyConfirmed,
    #[error("recovery phrase is invalid")]
    RecoveryPhraseInvalid,
    #[error("wallet is not eligible for mnemonic recovery")]
    RecoveryUnavailable,
    #[error("backup destination is invalid")]
    InvalidBackupDestination,
    #[error("embedded DOM Core must be running")]
    EmbeddedCoreRequired,
    #[error("embedded DOM Core is not ready")]
    NodeNotReady,
    #[error("wallet and Core identities differ")]
    IdentityMismatch,
    #[error("canonical Address v1 identities are required")]
    AddressIdentityRequired,
    #[error("transaction input is invalid")]
    InvalidTransactionInput,
    #[error("transaction expiry is not above the canonical tip")]
    TransactionExpired,
    #[error("transaction lifetime exceeds the local maximum")]
    TransactionLifetimeExceeded,
    #[error("insufficient spendable funds")]
    InsufficientFunds,
    #[error("selected outputs have no encrypted spending evidence")]
    UnsupportedSpendingEvidence,
    #[error("transaction fee is below the Core policy floor")]
    FeeTooLow,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("input is already reserved")]
    ReservationConflict,
    #[error("Scriptless funding reservation request is invalid")]
    InvalidScriptlessFundingRequest,
    #[error("Scriptless funding session already has different frozen terms")]
    ScriptlessFundingSessionConflict,
    #[error("Scriptless funding components disagree with the frozen aggregate shape")]
    ScriptlessFundingShapeMismatch,
    #[error("Scriptless funding reservation was not found")]
    ScriptlessFundingReservationNotFound,
    #[error("Scriptless funding components are not durably prepared")]
    ScriptlessFundingNotPrepared,
    #[error("Scriptless funding components cannot be exported in this state")]
    ScriptlessFundingCannotExport,
    #[error("Scriptless funding signing handoff is not authorized in this state")]
    ScriptlessFundingSigningNotAuthorized,
    #[error("Scriptless funding encrypted and public contexts disagree")]
    ScriptlessFundingContextMismatch,
    #[error("Scriptless funding reservation cannot be released after exposure or chain change")]
    ScriptlessFundingCannotRelease,
    #[error("the complete authenticated Scriptless session binding is required before exposure")]
    ScriptlessSessionBindingRequired,
    #[error("the Scriptless session-share capability disagrees with durable wallet state")]
    ScriptlessSessionBindingMismatch,
    #[error("the real DOM Scriptless template disagrees with durable wallet state")]
    ScriptlessTemplateBindingMismatch,
    #[error("Scriptless claim/refund payout reservation request is invalid")]
    InvalidScriptlessPayoutRequest,
    #[error("Scriptless claim/refund payout role already has different frozen terms")]
    ScriptlessPayoutSessionConflict,
    #[error("Scriptless claim/refund payout reservation was not found")]
    ScriptlessPayoutReservationNotFound,
    #[error("Scriptless claim/refund payout components are not durably prepared")]
    ScriptlessPayoutNotPrepared,
    #[error("Scriptless claim/refund payout components cannot be exported in this state")]
    ScriptlessPayoutCannotExport,
    #[error("Scriptless claim/refund payout encrypted and public contexts disagree")]
    ScriptlessPayoutContextMismatch,
    #[error("Scriptless claim/refund payout signing handoff is not authorized in this state")]
    ScriptlessPayoutSigningNotAuthorized,
    #[error("Scriptless claim/refund payout cannot be released after exposure")]
    ScriptlessPayoutCannotRelease,
    #[error("canonical Slate transport is invalid")]
    InvalidSlateTransport,
    #[error("canonical Slate replay conflicts with durable state")]
    SlateReplayConflict,
    #[error("transaction transition is invalid")]
    InvalidTransactionTransition,
    #[error("private transaction context is unavailable")]
    MissingPrivateContext,
    #[error("DOM protocol transaction validation failed")]
    ProtocolRejected,
    #[error("ordinary-send cover policy rejected the chain snapshot")]
    CoverPolicyRejected,
    #[error("different finalized bytes were already retained for this Slate")]
    FinalizedTransactionConflict,
    #[error("mixed recoverable and proof-only output regime")]
    MixedOutputRegime,
    #[error("transaction cannot be cancelled after submission evidence")]
    CannotCancelTransaction,
    #[error("explicit confirmation is required")]
    ConfirmationRequired,
    #[error("transaction not found")]
    TransactionNotFound,
    #[error("persisted Core cursor is invalid")]
    InvalidCoreCursor,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Domain(#[from] dom_wallet_domain::DomainError),
    #[error(transparent)]
    Backend(#[from] ProductionBackendError),
    #[error(transparent)]
    Protocol(#[from] ProtocolAdapterError),
    #[error(transparent)]
    Recovery(#[from] dom_wallet_core_recovery::RecoveryMaterialError),
    #[error(transparent)]
    Restore(#[from] dom_wallet_core_restore::SeedRestoreError),
    #[error(transparent)]
    Submission(#[from] dom_wallet_core_submit::WalletSubmissionError),
}

impl CoreError {
    pub fn redacted_code(&self) -> &'static str {
        match self {
            Self::WalletNotOpen => "WALLET_NOT_OPEN",
            Self::Locked => "WALLET_LOCKED",
            Self::InvalidLifecycleState => "INVALID_WALLET_STATE",
            Self::InvalidPassword => "INVALID_PASSWORD",
            Self::RandomnessUnavailable => "RANDOMNESS_UNAVAILABLE",
            Self::RecoveryCeremonyRequired => "RECOVERY_CONFIRMATION_REQUIRED",
            Self::RecoveryPhraseAlreadyConfirmed => "RECOVERY_PHRASE_ALREADY_CONFIRMED",
            Self::RecoveryPhraseInvalid => "RECOVERY_PHRASE_INVALID",
            Self::RecoveryUnavailable => "RECOVERY_UNAVAILABLE",
            Self::InvalidBackupDestination => "BACKUP_DESTINATION_INVALID",
            Self::EmbeddedCoreRequired => "EMBEDDED_NODE_REQUIRED",
            Self::NodeNotReady => "EMBEDDED_NODE_NOT_READY",
            Self::IdentityMismatch => "CHAIN_IDENTITY_MISMATCH",
            Self::AddressIdentityRequired => "ADDRESS_IDENTITY_REQUIRED",
            Self::InvalidTransactionInput => "TRANSACTION_INPUT_INVALID",
            Self::TransactionExpired => "TRANSACTION_EXPIRED",
            Self::TransactionLifetimeExceeded => "TRANSACTION_LIFETIME_EXCEEDED",
            Self::InsufficientFunds => "INSUFFICIENT_FUNDS",
            Self::UnsupportedSpendingEvidence => "SPENDING_EVIDENCE_UNSUPPORTED",
            Self::FeeTooLow => "FEE_TOO_LOW",
            Self::ArithmeticOverflow => "ARITHMETIC_OVERFLOW",
            Self::ReservationConflict => "OUTPUT_RESERVATION_CONFLICT",
            Self::InvalidScriptlessFundingRequest => "SCRIPTLESS_FUNDING_REQUEST_INVALID",
            Self::ScriptlessFundingSessionConflict => "SCRIPTLESS_FUNDING_SESSION_CONFLICT",
            Self::ScriptlessFundingShapeMismatch => "SCRIPTLESS_FUNDING_SHAPE_MISMATCH",
            Self::ScriptlessFundingReservationNotFound => {
                "SCRIPTLESS_FUNDING_RESERVATION_NOT_FOUND"
            }
            Self::ScriptlessFundingNotPrepared => "SCRIPTLESS_FUNDING_NOT_PREPARED",
            Self::ScriptlessFundingCannotExport => "SCRIPTLESS_FUNDING_CANNOT_EXPORT",
            Self::ScriptlessFundingSigningNotAuthorized => {
                "SCRIPTLESS_FUNDING_SIGNING_NOT_AUTHORIZED"
            }
            Self::ScriptlessFundingContextMismatch => "SCRIPTLESS_FUNDING_CONTEXT_MISMATCH",
            Self::ScriptlessFundingCannotRelease => "SCRIPTLESS_FUNDING_CANNOT_RELEASE",
            Self::ScriptlessSessionBindingRequired => "SCRIPTLESS_SESSION_BINDING_REQUIRED",
            Self::ScriptlessSessionBindingMismatch => "SCRIPTLESS_SESSION_BINDING_MISMATCH",
            Self::ScriptlessTemplateBindingMismatch => "SCRIPTLESS_TEMPLATE_BINDING_MISMATCH",
            Self::InvalidScriptlessPayoutRequest => "SCRIPTLESS_PAYOUT_REQUEST_INVALID",
            Self::ScriptlessPayoutSessionConflict => "SCRIPTLESS_PAYOUT_SESSION_CONFLICT",
            Self::ScriptlessPayoutReservationNotFound => "SCRIPTLESS_PAYOUT_RESERVATION_NOT_FOUND",
            Self::ScriptlessPayoutNotPrepared => "SCRIPTLESS_PAYOUT_NOT_PREPARED",
            Self::ScriptlessPayoutCannotExport => "SCRIPTLESS_PAYOUT_CANNOT_EXPORT",
            Self::ScriptlessPayoutContextMismatch => "SCRIPTLESS_PAYOUT_CONTEXT_MISMATCH",
            Self::ScriptlessPayoutSigningNotAuthorized => {
                "SCRIPTLESS_PAYOUT_SIGNING_NOT_AUTHORIZED"
            }
            Self::ScriptlessPayoutCannotRelease => "SCRIPTLESS_PAYOUT_CANNOT_RELEASE",
            Self::InvalidSlateTransport => "SLATE_V4_TRANSPORT_INVALID",
            Self::SlateReplayConflict => "SLATE_REPLAY_CONFLICT",
            Self::InvalidTransactionTransition => "TRANSACTION_STATE_INVALID",
            Self::MissingPrivateContext => "SLATE_PRIVATE_CONTEXT_MISSING",
            Self::ProtocolRejected => "PROTOCOL_REJECTED",
            Self::CoverPolicyRejected => "COVER_POLICY_REJECTED",
            Self::FinalizedTransactionConflict => "FINALIZED_TRANSACTION_CONFLICT",
            Self::MixedOutputRegime => "MIXED_OUTPUT_REGIME",
            Self::CannotCancelTransaction => "TRANSACTION_CANNOT_CANCEL",
            Self::ConfirmationRequired => "CONFIRMATION_REQUIRED",
            Self::TransactionNotFound => "TRANSACTION_NOT_FOUND",
            Self::InvalidCoreCursor => "CURSOR_INVALID",
            Self::Storage(StorageError::WriterActive) => "WALLET_WRITER_ACTIVE",
            Self::Storage(StorageError::InvalidPassword) => "INVALID_PASSWORD",
            Self::Storage(StorageError::AuthenticationDataCorrupt) => "WALLET_AUTH_DATA_CORRUPT",
            Self::Storage(StorageError::AuthenticatedPayloadCorrupt) => "WALLET_PAYLOAD_CORRUPT",
            Self::Storage(StorageError::InvalidMetadata) => "WALLET_METADATA_CORRUPT",
            Self::Storage(StorageError::NotFound) => "WALLET_NOT_FOUND",
            Self::Storage(_) => "WALLET_STORAGE_FAILED",
            Self::Domain(_) => "WALLET_STATE_VALIDATION_FAILED",
            Self::Backend(_) => "EMBEDDED_NODE_OPERATION_FAILED",
            Self::Protocol(_) => "PROTOCOL_VALIDATION_FAILED",
            Self::Recovery(_) => "RECOVERY_MATERIAL_FAILED",
            Self::Restore(_) => "RESTORE_FAILED",
            Self::Submission(_) => "TRANSACTION_SUBMISSION_FAILED",
        }
    }

    pub fn redacted_message(&self) -> String {
        let description: &str = match self {
            Self::Locked => "wallet is locked",
            Self::IdentityMismatch => "embedded Core identity does not match wallet",
            Self::InsufficientFunds => "insufficient spendable funds",
            Self::FeeTooLow => "transaction fee is below the required Core policy floor",
            Self::TransactionExpired => "transaction expiry is not above the canonical tip",
            Self::TransactionLifetimeExceeded => "transaction lifetime exceeds the local maximum",
            Self::NodeNotReady => "embedded Core is not ready",
            Self::InvalidCoreCursor => "wallet cursor is invalid",
            Self::InvalidSlateTransport => "Slate v4 transport is invalid",
            Self::MissingPrivateContext => "private Slate context is unavailable",
            Self::Storage(StorageError::WriterActive) => "wallet is already open by another writer",
            Self::Storage(StorageError::InvalidPassword) => "wallet password is invalid",
            Self::Storage(StorageError::AuthenticationDataCorrupt) => {
                "wallet authentication data is corrupt"
            }
            Self::Storage(StorageError::AuthenticatedPayloadCorrupt) => {
                "authenticated wallet payload is corrupt"
            }
            Self::Storage(StorageError::InvalidMetadata) => "wallet metadata is corrupt",
            Self::Storage(StorageError::NotFound) => "wallet was not found",
            _ => "the requested wallet operation was rejected",
        };
        format!("{}:{description}", self.redacted_code())
    }
}

/// Default production graph contains no legacy HTTP, custom scanner, or proof-only constructor.
pub const PRODUCTION_REACHABILITY: &[(&str, &str)] = &[
    ("node", "EmbeddedCoreLifecycle"),
    ("scanner", "CoreChainAdapter"),
    ("cursor", "WalletScanCursorV1"),
    ("submission", "CoreSubmissionService"),
    ("fees", "CoreFeePolicyService"),
    ("address", "WalletAddressV1"),
    ("slate", "RecoverySlateV4"),
    ("outputs", "RecoveryCapsuleV1Only"),
    ("restore", "SeedRestoreService"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn backup_identity() -> NetworkIdentity {
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [1; 32],
            genesis_id: [2; 32],
        }
    }

    fn canonical_mainnet_identity() -> NetworkIdentity {
        let mut chain_id = [0u8; 32];
        let mut genesis_id = [0u8; 32];
        hex::decode_to_slice(MAINNET_CHAIN_ID_HEX, &mut chain_id).unwrap();
        hex::decode_to_slice(MAINNET_GENESIS_HASH_HEX, &mut genesis_id).unwrap();
        NetworkIdentity {
            network: Network::Mainnet,
            chain_id,
            genesis_id,
        }
    }

    fn test_service() -> WalletService {
        let mut service = WalletService::default();
        service.kdf = KdfParameters::TEST;
        service
    }

    #[test]
    fn regression_c3_expiry_boundaries_overflow_and_restart_round_trip() {
        let tip = 10_000;
        assert!(matches!(
            validate_transaction_expiry(tip, tip),
            Err(CoreError::TransactionExpired)
        ));
        assert!(matches!(
            validate_transaction_expiry(tip - 1, tip),
            Err(CoreError::TransactionExpired)
        ));
        assert!(validate_transaction_expiry(tip + 1, tip).is_ok());
        assert!(validate_transaction_expiry(tip + MAX_TRANSACTION_LIFETIME_BLOCKS, tip).is_ok());
        assert!(matches!(
            validate_transaction_expiry(tip + MAX_TRANSACTION_LIFETIME_BLOCKS + 1, tip),
            Err(CoreError::TransactionLifetimeExceeded)
        ));
        assert!(matches!(
            validate_transaction_expiry(u64::MAX, u64::MAX - 1),
            Err(CoreError::ArithmeticOverflow)
        ));

        let mut state = WalletState::new(
            backup_identity(),
            [7; 32],
            default_node_configuration(backup_identity()),
        );
        state.transactions.push(LocalTransactionIntent {
            id: Uuid::nil(),
            created_at_height: 0,
            created_at_unix_seconds: 0,
            cancellation_reason: None,
            cancelled_at_height: None,
            kernel_excess: Vec::new(),
            lifecycle: TransactionLifecycle::InputsReserved,
            submitted: false,
            exposure: BroadcastExposure::NeverBroadcast,
            slate_id: Some(Uuid::nil()),
            role: Some(TransactionRole::Sender),
            amount: 1,
            fee: 1,
            reserved_output_ids: Vec::new(),
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
            expires_at_height: tip + 1,
        });
        let encoded = serde_json::to_vec(&state).unwrap();
        let restarted: WalletState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restarted.transactions[0].expires_at_height, tip + 1);
        assert!(
            validate_transaction_expiry(restarted.transactions[0].expires_at_height, tip).is_ok()
        );
    }

    #[test]
    fn abandoned_round_one_cancel_survives_restart_and_genesis_rescan() {
        let temp = tempfile::tempdir().unwrap();
        let wallet_path = temp.path().join("wallet");
        let password = "password-1";
        let mut service = test_service();
        service
            .create_recoverable(&wallet_path, password, backup_identity())
            .unwrap();
        service.recovery_phrase_confirmed(password).unwrap();
        service.unlock(password).unwrap();

        let transaction_id = Uuid::new_v4();
        let slate_id = Uuid::new_v4();
        let output_id = Uuid::new_v4();
        let mut state = service.unlocked.as_ref().unwrap().clone();
        state.outputs.push(OutputRecord {
            id: output_id,
            account_id: state.default_account.id,
            commitment: Some([3; 33]),
            value: 33_000_000_000,
            state: OutputState::PendingOutgoing,
            discovered_height: 1,
            reserved_by: Some(transaction_id),
        });
        state.remember_output_blinding(output_id, [4; 32]);
        state.transactions.push(LocalTransactionIntent {
            id: transaction_id,
            created_at_height: 10,
            created_at_unix_seconds: 1_700_000_000,
            cancellation_reason: None,
            cancelled_at_height: None,
            kernel_excess: Vec::new(),
            lifecycle: TransactionLifecycle::InputsReserved,
            submitted: false,
            exposure: BroadcastExposure::NeverBroadcast,
            slate_id: Some(slate_id),
            role: Some(TransactionRole::Sender),
            amount: 1_000_000_000,
            fee: 1,
            reserved_output_ids: vec![output_id],
            request_bytes: Vec::new(),
            response_bytes: Vec::new(),
            finalized_transaction_bytes: Vec::new(),
            transaction_hash: None,
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
            expires_at_height: 20,
        });
        service.commit(state).unwrap();
        assert_eq!(
            service.summary().unwrap().balance.pending_outgoing,
            33_000_000_000
        );

        // Dropping without `close` models process death after the durable
        // ROUND 1 reservation and before any lifecycle cleanup can run.
        drop(service);
        let mut restarted = test_service();
        restarted.open(&wallet_path).unwrap();
        restarted.unlock(password).unwrap();
        let cancelled = restarted.slate_cancel(slate_id, true).unwrap();
        assert_eq!(cancelled.state, "CANCELLED");
        let state = restarted.unlocked.as_ref().unwrap();
        assert_eq!(state.outputs[0].reserved_by, None);
        assert_eq!(state.outputs[0].state, OutputState::Confirmed);
        assert_eq!(state.balance().confirmed, 33_000_000_000);
        assert_eq!(state.balance().spendable, 33_000_000_000);
        assert_eq!(spendable_outputs(state).len(), 1);

        // This is the same state rewind used by `rescan_from_genesis`; the
        // CANCELLED intent is a durable tombstone and cannot reserve again.
        let mut rescanned = state.clone();
        rewind_recovery_state(&mut rescanned, 1, 20).unwrap();
        assert_eq!(
            rescanned.transactions[0].lifecycle,
            TransactionLifecycle::Cancelled
        );
        assert_eq!(rescanned.outputs[0].reserved_by, None);
        assert_eq!(rescanned.balance().spendable, 33_000_000_000);
        restarted.commit(rescanned).unwrap();
        drop(restarted);

        let mut reopened_after_rescan = test_service();
        reopened_after_rescan.open(&wallet_path).unwrap();
        reopened_after_rescan.unlock(password).unwrap();
        let state = reopened_after_rescan.unlocked.as_ref().unwrap();
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::Cancelled
        );
        assert_eq!(state.outputs[0].reserved_by, None);
        assert_eq!(spendable_outputs(state).len(), 1);
    }

    fn reserved_sender_state(finalized: bool) -> (WalletState, Uuid, Uuid, Uuid) {
        let mut state = WalletState::new(
            backup_identity(),
            [7; 32],
            default_node_configuration(backup_identity()),
        );
        let transaction_id = Uuid::new_v4();
        let slate_id = Uuid::new_v4();
        let output_id = Uuid::new_v4();
        state.outputs.push(OutputRecord {
            id: output_id,
            account_id: state.default_account.id,
            commitment: Some([9; 33]),
            value: 33_000_000_000,
            state: OutputState::PendingOutgoing,
            discovered_height: 1,
            reserved_by: Some(transaction_id),
        });
        state.remember_output_blinding(output_id, [8; 32]);
        state.transactions.push(LocalTransactionIntent {
            id: transaction_id,
            created_at_height: 90,
            created_at_unix_seconds: 1_700_000_000,
            cancellation_reason: None,
            cancelled_at_height: None,
            kernel_excess: if finalized { vec![7; 33] } else { Vec::new() },
            lifecycle: if finalized {
                TransactionLifecycle::Finalized
            } else {
                TransactionLifecycle::InputsReserved
            },
            submitted: false,
            exposure: BroadcastExposure::NeverBroadcast,
            slate_id: Some(slate_id),
            role: Some(TransactionRole::Sender),
            amount: 1_000_000_000,
            fee: 1,
            reserved_output_ids: vec![output_id],
            request_bytes: vec![1],
            response_bytes: if finalized { vec![2] } else { Vec::new() },
            finalized_transaction_bytes: if finalized { vec![3] } else { Vec::new() },
            transaction_hash: finalized.then_some([6; 32]),
            attempt_count: 0,
            private_context: None,
            recipient_output_id: None,
            change_output_id: None,
            expires_at_height: 100,
        });
        (state, transaction_id, slate_id, output_id)
    }

    #[test]
    fn expired_unfinalized_envelope_is_cancelled_automatically_once() {
        let (mut state, transaction_id, _, output_id) = reserved_sender_state(false);
        assert_eq!(
            cancel_expired_unfinalized_reservations(&mut state, 100).unwrap(),
            vec![transaction_id]
        );
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::Cancelled
        );
        assert_eq!(
            state.transactions[0].cancellation_reason,
            Some(TransactionCancellationReason::ExpiredBeforeFinalization)
        );
        assert_eq!(state.transactions[0].cancelled_at_height, Some(100));
        assert_eq!(state.outputs[0].id, output_id);
        assert_eq!(state.outputs[0].reserved_by, None);
        assert_eq!(state.outputs[0].state, OutputState::Confirmed);
        assert_eq!(state.balance().spendable, 33_000_000_000);
        assert!(cancel_expired_unfinalized_reservations(&mut state, 101)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn finalized_transaction_is_never_cancelled_automatically() {
        let (mut state, transaction_id, _, _) = reserved_sender_state(true);
        assert!(cancel_expired_unfinalized_reservations(&mut state, 101)
            .unwrap()
            .is_empty());
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::Finalized
        );
        assert_eq!(state.outputs[0].reserved_by, Some(transaction_id));
        assert_eq!(state.outputs[0].state, OutputState::PendingOutgoing);
        let summary = transaction_summary_from(&state.transactions[0]);
        assert!(summary.awaiting_broadcast_confirmation);
        assert!(summary.manual_cancel_warning);
        assert!(summary.manual_cancel_allowed);
        assert_eq!(summary.expires_at_height, 100);
    }

    #[test]
    fn finalized_manual_cancel_requires_warning_confirmation_and_releases_reservation() {
        let temp = tempfile::tempdir().unwrap();
        let wallet_path = temp.path().join("wallet");
        let password = "password-1";
        let mut service = test_service();
        service
            .create_recoverable(&wallet_path, password, backup_identity())
            .unwrap();
        service.recovery_phrase_confirmed(password).unwrap();
        service.unlock(password).unwrap();
        let (mut transaction_state, transaction_id, slate_id, output_id) =
            reserved_sender_state(true);
        let mut state = service.unlocked.as_ref().unwrap().clone();
        transaction_state.outputs[0].account_id = state.default_account.id;
        state.outputs.append(&mut transaction_state.outputs);
        state
            .private_output_blindings
            .append(&mut transaction_state.private_output_blindings);
        state
            .transactions
            .append(&mut transaction_state.transactions);
        service.commit(state).unwrap();

        let warning = service.transaction_summary(transaction_id).unwrap();
        assert!(warning.manual_cancel_warning);
        assert!(matches!(
            service.slate_cancel(slate_id, false),
            Err(CoreError::ConfirmationRequired)
        ));
        let cancelled = service.slate_cancel(slate_id, true).unwrap();
        assert_eq!(cancelled.state, "CANCELLED");
        assert_eq!(cancelled.cancellation_reason.as_deref(), Some("MANUAL"));
        let state = service.unlocked.as_ref().unwrap();
        assert_eq!(
            state
                .outputs
                .iter()
                .find(|output| output.id == output_id)
                .unwrap()
                .reserved_by,
            None
        );
        assert_eq!(state.balance().spendable, 33_000_000_000);
    }

    #[test]
    fn one_block_reorg_restores_exact_finalized_reservation_without_duplication() {
        let (mut state, transaction_id, _, output_id) = reserved_sender_state(true);
        state.transactions[0].lifecycle = TransactionLifecycle::Confirmed {
            height: 11,
            block_hash: [1; 32],
        };
        state.transactions[0].exposure = BroadcastExposure::Confirmed;
        state.outputs[0].state = OutputState::Spent { spent_height: 11 };
        state.outputs[0].reserved_by = None;

        rewind_recovery_state(&mut state, 10, 10).unwrap();
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::Reorged
        );
        assert_eq!(state.outputs.len(), 1);
        assert_eq!(state.outputs[0].id, output_id);
        assert_eq!(state.outputs[0].reserved_by, Some(transaction_id));
        assert_eq!(state.outputs[0].state, OutputState::PendingOutgoing);
        assert_eq!(state.balance().pending_outgoing, 33_000_000_000);
        assert_eq!(state.balance().spendable, 0);

        rewind_recovery_state(&mut state, 10, 10).unwrap();
        assert_eq!(state.outputs.len(), 1);
        assert_eq!(state.outputs[0].reserved_by, Some(transaction_id));
        assert!(state.mark_known_output_spent(&[9; 33], 11));
        state
            .apply_kernel_evidence(11, [2; 32], &[[7; 33]])
            .unwrap();
        assert_eq!(
            state.transactions[0].lifecycle,
            TransactionLifecycle::Confirmed {
                height: 11,
                block_hash: [2; 32]
            }
        );
        assert_eq!(state.outputs[0].reserved_by, None);
        assert_eq!(state.balance().total, 0);
    }

    #[test]
    fn scriptless_reorg_restores_input_reservation_and_pending_change_from_encrypted_context() {
        let mut state = WalletState::new(
            backup_identity(),
            [7; 32],
            default_node_configuration(backup_identity()),
        );
        let reservation_id = Uuid::new_v4();
        let input_id = Uuid::new_v4();
        let change_id = Uuid::new_v4();
        state.outputs.push(OutputRecord {
            id: input_id,
            account_id: state.default_account.id,
            commitment: Some([2; 33]),
            value: 100,
            state: OutputState::Spent { spent_height: 11 },
            discovered_height: 1,
            reserved_by: None,
        });
        state.remember_output_blinding(input_id, [3; 32]);
        state.outputs.push(OutputRecord {
            id: change_id,
            account_id: state.default_account.id,
            commitment: Some([4; 33]),
            value: 9,
            state: OutputState::Confirmed,
            discovered_height: 11,
            reserved_by: None,
        });
        state.remember_output_blinding(change_id, [5; 32]);
        state
            .scriptless_funding_reservations
            .push(ScriptlessFundingReservation {
                version: SCRIPTLESS_FUNDING_RESERVATION_VERSION,
                id: reservation_id,
                session_id: [6; 32],
                shared_output_commitment: [11; 33],
                created_at_height: 10,
                local_debit_noms: 91,
                funding_fee_noms: 1,
                expected_input_count: 1,
                expected_output_count: 2,
                reserved_output_ids: vec![input_id],
                input_commitments: vec![vec![2; 33]],
                change_value_noms: 9,
                change_derivation_index: Some(1),
                change_output_id: Some(change_id),
                change_commitment: Some([4; 33]),
                change_output_bytes: vec![7],
                offset_contribution: Some([8; 32]),
                wallet_excess_public_key: vec![9; 33],
                template_hash: None,
                session_share_binding_digest: Some([10; 32]),
                participant_position: Some(0),
                template_participants: None,
                private_context: Some(PrivateScriptlessFundingContext::new(
                    [10; 32],
                    Some([5; 32]),
                )),
                state: ScriptlessFundingReservationState::Exported,
            });
        state.recovery_allocation_floors.change = 1;
        state.non_reuse_floor = 1;
        state.validate().unwrap();

        rewind_recovery_state(&mut state, 0, 10).unwrap();
        assert!(state.outputs.iter().all(|output| output.id != input_id));
        let change = state
            .outputs
            .iter()
            .find(|output| output.id == change_id)
            .unwrap();
        assert_eq!(change.state, OutputState::PendingIncoming);
        assert_eq!(change.discovered_height, 0);
        assert_eq!(state.output_blinding(change_id), Some([5; 32]));
        assert_eq!(
            state.scriptless_funding_reservations[0].state,
            ScriptlessFundingReservationState::Exported
        );
        state.validate().unwrap();

        // A full scanner replay may assign a new local UUID to the same
        // canonical commitment. The reservation follows the commitment and
        // immediately makes that rediscovered output unavailable.
        let rebound_input_id = Uuid::new_v4();
        state.outputs.push(OutputRecord {
            id: rebound_input_id,
            account_id: state.default_account.id,
            commitment: Some([2; 33]),
            value: 100,
            state: OutputState::Confirmed,
            discovered_height: 1,
            reserved_by: None,
        });
        state.remember_output_blinding(rebound_input_id, [3; 32]);
        state.restore_scriptless_funding_reservations().unwrap();
        let input = state
            .outputs
            .iter()
            .find(|output| output.id == rebound_input_id)
            .unwrap();
        assert_eq!(input.state, OutputState::PendingOutgoing);
        assert_eq!(input.reserved_by, Some(reservation_id));
        assert_eq!(
            state.scriptless_funding_reservations[0].reserved_output_ids,
            vec![rebound_input_id]
        );
        state.validate().unwrap();
    }

    #[test]
    fn scriptless_reorg_restores_payout_and_preserves_no_output_signer_contribution() {
        let mut state = WalletState::new(
            backup_identity(),
            [7; 32],
            default_node_configuration(backup_identity()),
        );
        let session_id = [0x61; 32];
        let payout_id = Uuid::new_v4();
        let payout_output_id = Uuid::new_v4();
        let payout_commitment = [0x62; 33];
        let payout_bytes = vec![0x63; 835];
        let payout_blinding = [0x64; 32];
        state.outputs.push(OutputRecord {
            id: payout_output_id,
            account_id: state.default_account.id,
            commitment: Some(payout_commitment),
            value: 900,
            state: OutputState::Confirmed,
            discovered_height: 11,
            reserved_by: None,
        });
        state.remember_output_blinding(payout_output_id, payout_blinding);
        state
            .scriptless_payout_reservations
            .push(ScriptlessPayoutReservation {
                version: SCRIPTLESS_PAYOUT_RESERVATION_VERSION,
                id: payout_id,
                session_id,
                role: ScriptlessPayoutRoleV1::Claim,
                created_at_height: 10,
                shared_output_commitment: [0x65; 33],
                payout_value_noms: 900,
                kernel_fee_noms: 100,
                expected_output_count: 1,
                refund_lock_height: 0,
                output_id: Some(payout_output_id),
                derivation_index: Some(1),
                output_commitment: Some(payout_commitment),
                output_bytes: payout_bytes.clone(),
                offset_contribution: Some([0x66; 32]),
                payout_excess_public_key: vec![0x67; 33],
                template_hash: None,
                session_share_binding_digest: Some([0x68; 32]),
                participant_position: Some(0),
                template_participants: None,
                private_context: Some(PrivateScriptlessPayoutContext::new(
                    [0x68; 32],
                    Some(payout_blinding),
                )),
                state: ScriptlessPayoutReservationState::ComponentsExposed,
            });
        state
            .scriptless_payout_reservations
            .push(ScriptlessPayoutReservation {
                version: SCRIPTLESS_PAYOUT_RESERVATION_VERSION,
                id: Uuid::new_v4(),
                session_id,
                role: ScriptlessPayoutRoleV1::Refund,
                created_at_height: 10,
                shared_output_commitment: [0x65; 33],
                payout_value_noms: 0,
                kernel_fee_noms: 100,
                expected_output_count: 1,
                refund_lock_height: 20,
                output_id: None,
                derivation_index: None,
                output_commitment: None,
                output_bytes: Vec::new(),
                offset_contribution: Some([0x69; 32]),
                payout_excess_public_key: vec![0x6a; 33],
                template_hash: None,
                session_share_binding_digest: Some([0x6b; 32]),
                participant_position: Some(1),
                template_participants: None,
                private_context: Some(PrivateScriptlessPayoutContext::new([0x6b; 32], None)),
                state: ScriptlessPayoutReservationState::ComponentsExposed,
            });
        state.recovery_allocation_floors.self_transfer = 1;
        state.non_reuse_floor = 1;
        state.validate().unwrap();

        rewind_recovery_state(&mut state, 10, 10).unwrap();
        let restored = state
            .outputs
            .iter()
            .find(|output| output.id == payout_output_id)
            .expect("reorg restores the exact retained payout projection");
        assert_eq!(restored.commitment, Some(payout_commitment));
        assert_eq!(restored.value, 900);
        assert_eq!(restored.state, OutputState::PendingIncoming);
        assert_eq!(restored.discovered_height, 0);
        assert_eq!(
            state.output_blinding(payout_output_id),
            Some(payout_blinding)
        );
        assert_eq!(state.scriptless_payout_reservations.len(), 2);
        assert_eq!(
            state.scriptless_payout_reservations[0].output_bytes,
            payout_bytes
        );
        assert!(state.scriptless_payout_reservations[1].output_id.is_none());
        assert!(state.scriptless_payout_reservations[1]
            .output_bytes
            .is_empty());

        rewind_recovery_state(&mut state, 10, 10).unwrap();
        assert_eq!(
            state
                .outputs
                .iter()
                .filter(|output| output.commitment == Some(payout_commitment))
                .count(),
            1
        );
        state.validate().unwrap();
    }

    #[test]
    fn scriptless_template_participant_binding_requires_both_exact_ordered_slots() {
        let mut offset_a = [0u8; 32];
        offset_a[31] = 3;
        let mut offset_b = [0u8; 32];
        offset_b[31] = 5;
        let mut secret_a = [0u8; 32];
        secret_a[31] = 7;
        let mut secret_b = [0u8; 32];
        secret_b[31] = 11;
        let point_a = dom_crypto::SecretKey::from_bytes(&secret_a)
            .unwrap()
            .public_key();
        let point_b = dom_crypto::SecretKey::from_bytes(&secret_b)
            .unwrap()
            .public_key();
        let aggregate_point = scriptless_add_public_points(&[point_a.clone(), point_b.clone()])
            .expect("aggregate canonical public kernel contributions");
        let aggregate_offset = aggregate_transaction_offset_contributions_v1(&[offset_a, offset_b])
            .expect("aggregate canonical public offsets");
        let transaction = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![dom_consensus::TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: dom_core::Amount::from_noms(1).unwrap(),
                lock_height: 0,
                excess: dom_crypto::pedersen::Commitment::from_compressed_bytes(
                    &aggregate_point.to_compressed_bytes(),
                )
                .unwrap(),
                excess_signature: [0u8; 65],
            }],
            offset: aggregate_offset,
        };
        let participants = ScriptlessTemplateParticipantSetV1 {
            ordered_offset_contributions: [offset_a, offset_b],
            ordered_kernel_excess_points: [
                point_a.to_compressed_bytes(),
                point_b.to_compressed_bytes(),
            ],
        };
        let binding = validate_template_participant_set(
            &transaction,
            offset_a,
            point_a.to_compressed_bytes(),
            0,
            participants,
        )
        .expect("bind the complete ordered two-party decomposition");
        assert_eq!(
            binding.ordered_offset_contributions[0].as_slice(),
            offset_a.as_slice()
        );
        assert_eq!(
            binding.ordered_offset_contributions[1].as_slice(),
            offset_b.as_slice()
        );
        assert_eq!(
            binding.ordered_kernel_excess_points[0].as_slice(),
            point_a.to_compressed_bytes().as_slice()
        );

        let mut replaced_local = participants;
        replaced_local.ordered_offset_contributions[0] = offset_b;
        assert!(matches!(
            validate_template_participant_set(
                &transaction,
                offset_a,
                point_a.to_compressed_bytes(),
                0,
                replaced_local,
            ),
            Err(CoreError::ScriptlessTemplateBindingMismatch)
        ));
        let mut replaced_remote = participants;
        replaced_remote.ordered_kernel_excess_points[1] = point_a.to_compressed_bytes();
        assert!(matches!(
            validate_template_participant_set(
                &transaction,
                offset_a,
                point_a.to_compressed_bytes(),
                0,
                replaced_remote,
            ),
            Err(CoreError::ScriptlessTemplateBindingMismatch)
        ));
        assert!(matches!(
            validate_template_participant_set(
                &transaction,
                offset_a,
                point_a.to_compressed_bytes(),
                2,
                participants,
            ),
            Err(CoreError::ScriptlessTemplateBindingMismatch)
        ));
    }

    #[test]
    fn scriptless_funding_local_shape_counts_the_global_shared_output_once() {
        // A payer with no change contributes one input and no ordinary output;
        // the frozen aggregate still contains the one global shared output.
        validate_scriptless_funding_local_shape(1, 0, 1, 1).unwrap();

        // A payer with change needs room for that ordinary output in addition
        // to the same single global shared output.
        validate_scriptless_funding_local_shape(1, 1, 1, 2).unwrap();
        assert!(matches!(
            validate_scriptless_funding_local_shape(1, 1, 1, 1),
            Err(CoreError::ScriptlessFundingShapeMismatch)
        ));

        // A zero-debit participant contributes neither input nor output, but
        // sees the same aggregate shape and must not add a second shared output.
        validate_scriptless_funding_local_shape(0, 0, 1, 1).unwrap();
        validate_scriptless_funding_local_shape(0, 0, 0, 1).unwrap();
        assert!(matches!(
            validate_scriptless_funding_local_shape(0, 0, 0, 0),
            Err(CoreError::ScriptlessFundingShapeMismatch)
        ));
    }

    #[test]
    fn regression_c4_export_is_read_only_after_submitted_mempool_and_confirmed() {
        let _: fn(&WalletService, Uuid) -> Result<SlateExport, CoreError> =
            WalletService::slate_request_export;
        let _: fn(&WalletService, Uuid) -> Result<SlateExport, CoreError> =
            WalletService::slate_response_export;

        for lifecycle in [
            TransactionLifecycle::Submitted,
            TransactionLifecycle::InMempool,
            TransactionLifecycle::Confirmed {
                height: 42,
                block_hash: [8; 32],
            },
        ] {
            let mut state = WalletState::new(
                backup_identity(),
                [7; 32],
                default_node_configuration(backup_identity()),
            );
            state.recovery = Some(RecoveryMetadata {
                scheme: RECOVERY_SCHEME_BIP39_256_V1.into(),
                phrase_confirmed: true,
            });
            state.transactions.push(LocalTransactionIntent {
                id: Uuid::new_v4(),
                created_at_height: 0,
                created_at_unix_seconds: 0,
                cancellation_reason: None,
                cancelled_at_height: None,
                kernel_excess: vec![2; 33],
                lifecycle,
                submitted: true,
                exposure: BroadcastExposure::PossiblyRelayed,
                slate_id: Some(Uuid::new_v4()),
                role: Some(TransactionRole::Sender),
                amount: 1,
                fee: 1,
                reserved_output_ids: Vec::new(),
                request_bytes: b"durable canonical bytes".to_vec(),
                response_bytes: Vec::new(),
                finalized_transaction_bytes: Vec::new(),
                transaction_hash: Some([3; 32]),
                attempt_count: 1,
                private_context: None,
                recipient_output_id: None,
                change_output_id: None,
                expires_at_height: 100,
            });
            let before = state.transactions[0].clone();
            let mut service = test_service();
            service.state = ApplicationState::Unlocked;
            service.unlocked = Some(state);
            assert!(matches!(
                service.slate_request_export(before.slate_id.unwrap()),
                Err(CoreError::EmbeddedCoreRequired)
            ));
            assert_eq!(service.unlocked.as_ref().unwrap().transactions[0], before);
        }
    }

    #[test]
    fn backup_round_trip_preserves_existing_state_and_rejects_wrong_identity() {
        let temp = tempfile::tempdir().unwrap();
        let wallet_path = temp.path().join("wallet");
        let backup_path = temp.path().join("wallet.dombackup");
        let mut service = test_service();
        let created = service
            .create_recoverable(&wallet_path, "password-1", backup_identity())
            .unwrap();
        service.recovery_phrase_confirmed("password-1").unwrap();
        service.unlock("password-1").unwrap();
        service
            .backup_export(&backup_path, "backup-password")
            .unwrap();
        service.close().unwrap();

        let mut imported = test_service();
        let summary = imported
            .backup_import(
                temp.path().join("imported"),
                &backup_path,
                "backup-password",
                "password-2",
                backup_identity(),
            )
            .unwrap();
        assert_eq!(summary.wallet_id, created.wallet.wallet_id);
        imported.close().unwrap();

        let mut wrong_identity = backup_identity();
        wrong_identity.chain_id[0] ^= 1;
        let mut rejected = test_service();
        assert!(matches!(
            rejected.backup_import(
                temp.path().join("wrong-identity"),
                &backup_path,
                "backup-password",
                "password-3",
                wrong_identity,
            ),
            Err(CoreError::Storage(StorageError::IdentityMismatch))
        ));
    }

    #[test]
    fn regression_a2_lock_close_and_switch_wallets_without_process_restart() {
        let temp = tempfile::tempdir().unwrap();
        let wallet_a = temp.path().join("a");
        let wallet_b = temp.path().join("b");
        let mut service = test_service();
        service
            .create_recoverable(&wallet_a, "password-a", backup_identity())
            .unwrap();
        service.close().unwrap();
        service
            .create_recoverable(&wallet_b, "password-b", backup_identity())
            .unwrap();
        service.close().unwrap();

        service.open(&wallet_a).unwrap();
        service.unlock("password-a").unwrap();
        service.lock().unwrap();
        service.close().unwrap();
        service.open(&wallet_b).unwrap();
        service.unlock("password-b").unwrap();
        assert_eq!(service.diagnostics().application_state, "READY");
    }

    #[test]
    fn regression_m7_phrase_confirmation_is_a_durable_policy_gate() {
        let temp = tempfile::tempdir().unwrap();
        let wallet_path = temp.path().join("wallet");
        let mut service = test_service();
        let created = service
            .create_recoverable(&wallet_path, "password-1", backup_identity())
            .unwrap();
        service.unlock("password-1").unwrap();
        let resumed = service.recovery_phrase_resume("password-1").unwrap();
        assert_eq!(resumed.mnemonic.as_str(), created.mnemonic.as_str());
        assert!(matches!(
            service.recovery_phrase_resume("wrong-password"),
            Err(CoreError::Storage(StorageError::InvalidPassword))
        ));
        assert!(matches!(
            service.transaction_send_create(1, None, 10),
            Err(CoreError::RecoveryCeremonyRequired)
        ));
        assert!(matches!(
            service.mining_coinbase_candidate(1),
            Err(CoreError::RecoveryCeremonyRequired)
        ));
        assert!(matches!(
            service.backup_export(temp.path().join("blocked.dombackup"), "backup-pass"),
            Err(CoreError::RecoveryCeremonyRequired)
        ));
        assert!(matches!(
            service.slate_request_export(Uuid::nil()),
            Err(CoreError::RecoveryCeremonyRequired)
        ));
        assert!(matches!(
            service.transaction_submit(Uuid::nil()),
            Err(CoreError::RecoveryCeremonyRequired)
        ));

        service.lock().unwrap();
        service.close().unwrap();
        service.open(&wallet_path).unwrap();
        assert_eq!(
            service
                .recovery_phrase_resume("password-1")
                .unwrap()
                .mnemonic
                .as_str(),
            created.mnemonic.as_str(),
            "dismissal and process reconstruction must not strand the ceremony"
        );
        service.recovery_phrase_confirmed("password-1").unwrap();
        service.unlock("password-1").unwrap();
        assert!(matches!(
            service.recovery_phrase_resume("password-1"),
            Err(CoreError::RecoveryPhraseAlreadyConfirmed)
        ));
        assert!(matches!(
            service.transaction_send_create(1, None, 10),
            Err(CoreError::EmbeddedCoreRequired)
        ));
        service.lock().unwrap();
        service.unlock("password-1").unwrap();
        assert!(service
            .unlocked
            .as_ref()
            .and_then(|state| state.recovery.as_ref())
            .is_some_and(|recovery| recovery.phrase_confirmed));
    }

    #[test]
    fn desktop_mainnet_identity_is_exact_and_every_mismatch_fails_closed() {
        assert_eq!(
            MAINNET_CHAIN_ID_HEX,
            "f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b"
        );
        assert_eq!(
            MAINNET_GENESIS_HASH_HEX,
            "182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce"
        );
        let identity = canonical_mainnet_identity();
        require_mainnet_identity(&identity).unwrap();

        let mut wrong_network = identity.clone();
        wrong_network.network = Network::PublicTestnet;
        assert!(matches!(
            require_mainnet_identity(&wrong_network),
            Err(CoreError::IdentityMismatch)
        ));
        let mut wrong_chain = identity.clone();
        wrong_chain.chain_id[0] ^= 1;
        assert!(matches!(
            require_mainnet_identity(&wrong_chain),
            Err(CoreError::IdentityMismatch)
        ));
        let mut wrong_genesis = identity;
        wrong_genesis.genesis_id[0] ^= 1;
        assert!(matches!(
            require_mainnet_identity(&wrong_genesis),
            Err(CoreError::IdentityMismatch)
        ));
    }

    #[test]
    fn cursor_failure_does_not_close_unlocked_wallet() {
        let temp = tempfile::tempdir().unwrap();
        let mut service = test_service();
        service
            .create_recoverable(temp.path().join("wallet"), "password-1", backup_identity())
            .unwrap();
        service.unlock("password-1").unwrap();

        service.record_sync_failure(&ProductionBackendError::Scan(
            dom_wallet_core_sync::CoreScanError::CoreContract {
                code: "CORE_INTERNAL_FAILURE",
            },
        ));

        let diagnostics = service.diagnostics();
        assert_eq!(diagnostics.application_state, "READY");
        assert_eq!(
            diagnostics.last_error.as_deref(),
            Some("CURSOR_SYNCHRONIZATION_FAILED:Core scan contract failed (CORE_INTERNAL_FAILURE)")
        );
        assert!(service.summary().is_ok());
    }

    #[test]
    fn transient_core_not_ready_is_not_recorded_as_a_cursor_failure() {
        let temp = tempfile::tempdir().unwrap();
        let mut service = test_service();
        service
            .create_recoverable(temp.path().join("wallet"), "password-1", backup_identity())
            .unwrap();
        service.unlock("password-1").unwrap();
        service.state = ApplicationState::Synchronizing;

        service.finish_sync_failure(&ProductionBackendError::Scan(
            dom_wallet_core_sync::CoreScanError::CoreNotReady,
        ));

        let diagnostics = service.diagnostics();
        assert_eq!(diagnostics.application_state, "READY");
        assert!(diagnostics.last_error.is_none());
        assert!(service.summary().is_ok());
    }

    #[test]
    fn regression_a5_error_domains_do_not_contaminate_or_cross_clear() {
        let temp = tempfile::tempdir().unwrap();
        let mut service = test_service();
        service
            .create_recoverable(temp.path().join("wallet"), "password-1", backup_identity())
            .unwrap();
        assert!(matches!(
            service.unlock("password-2"),
            Err(CoreError::Storage(StorageError::InvalidPassword))
        ));
        assert_eq!(
            service.error_domains().authentication.as_deref(),
            Some("INVALID_PASSWORD")
        );
        assert!(service.error_domains().synchronization.is_none());
        assert!(service.diagnostics().last_error.is_none());

        service.errors.synchronization = Some("CURSOR_SYNCHRONIZATION_FAILED".into());
        service.unlock("password-1").unwrap();
        let domains = service.error_domains();
        assert!(domains.authentication.is_none());
        assert!(domains.synchronization.is_some());
        assert!(domains.node.is_none());
        assert!(domains.mining.is_none());
    }

    #[test]
    fn active_writer_has_a_distinct_redacted_error_code() {
        let error = CoreError::Storage(StorageError::WriterActive);
        assert_eq!(error.redacted_code(), "WALLET_WRITER_ACTIVE");
        assert_eq!(
            error.redacted_message(),
            "WALLET_WRITER_ACTIVE:wallet is already open by another writer"
        );
    }

    #[test]
    fn no_legacy_production_reachability() {
        let values = PRODUCTION_REACHABILITY
            .iter()
            .map(|(_, value)| *value)
            .collect::<Vec<_>>();
        assert!(!values.iter().any(|value| value.contains("Http")));
        assert!(!values.iter().any(|value| value.contains("ProofOnly")));
    }

    #[test]
    fn no_mixed_output_regime() {
        assert_eq!(CANONICAL_TRANSACTION_OUTPUT_SIZE, 872);
        assert_eq!(dom_wallet_core_recovery::PRODUCTION_OUTPUT_PATHS.len(), 5);
        assert!(dom_wallet_core_recovery::PRODUCTION_OUTPUT_PATHS
            .iter()
            .all(|path| path.recovery_required));
    }

    #[test]
    fn regression_offline_restore_creates_locked_wallet_without_backend() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("offline");
        let mut service = test_service();
        let phrase = CanonicalWalletSeed::from_entropy(&[0x11; 32])
            .unwrap()
            .mnemonic_text();

        let summary = service
            .restore_from_mnemonic_offline_with_identity(
                &path,
                "password-1",
                phrase.as_str(),
                backup_identity(),
            )
            .unwrap();
        assert_eq!(summary.state, "LOCKED");
        assert_eq!(summary.seed_restore_status.as_deref(), Some("in_progress"));
        assert!(summary.cursor_height.is_none());
        assert!(summary.tip_height.is_none());
        assert_eq!(summary.balance, BalanceProjection::default());

        let unlocked = service.unlock("password-1").unwrap();
        assert_eq!(unlocked.state, "READY");
        assert_eq!(unlocked.seed_restore_status.as_deref(), Some("in_progress"));
        assert!(unlocked.cursor_height.is_none());
        let state = service.unlocked.as_ref().unwrap();
        assert_eq!(state.sync_status, SyncStatus::Synchronizing);
        assert!(state.core_scan_cursor.is_none());
        assert!(state
            .recovery
            .as_ref()
            .is_some_and(|recovery| recovery.phrase_confirmed));
        assert!(matches!(
            service.recovery_phrase_resume("password-1"),
            Err(CoreError::RecoveryPhraseAlreadyConfirmed)
        ));
        // Scanning is deferred and gated only on the embedded Core being
        // available, never on restore staging or IBD completion.
        assert!(matches!(
            service.synchronize(),
            Err(CoreError::EmbeddedCoreRequired)
        ));

        // The wallet survives a full close/open/unlock round-trip.
        service.close().unwrap();
        service.open(&path).unwrap();
        service.unlock("password-1").unwrap();
        assert_eq!(
            service.summary().unwrap().seed_restore_status.as_deref(),
            Some("in_progress")
        );

        // Restoring onto an existing destination fails closed.
        let mut second = test_service();
        assert!(second
            .restore_from_mnemonic_offline_with_identity(
                &path,
                "password-1",
                phrase.as_str(),
                backup_identity(),
            )
            .is_err());
        // Invalid phrases never create a directory.
        let mut invalid = test_service();
        assert!(matches!(
            invalid.restore_from_mnemonic_offline_with_identity(
                temp.path().join("invalid"),
                "password-1",
                "not a valid canonical mnemonic",
                backup_identity(),
            ),
            Err(CoreError::RecoveryPhraseInvalid)
        ));
        assert!(!temp.path().join("invalid").exists());
    }

    /// R8: the process dies between the restore and the first scan batch.
    ///
    /// A graceful `close()` is the easy path and is already covered above; this
    /// covers the ugly one — the `WalletService` is dropped with no shutdown at
    /// all, the way a kill or a power cut leaves things. Reopening must find a
    /// complete wallet, no half-written staging sibling, and a restore that
    /// resumes from zero rather than reporting itself finished.
    #[test]
    fn regression_offline_restore_survives_a_crash_before_the_first_batch() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("crashed");
        let phrase = CanonicalWalletSeed::from_entropy(&[0x33; 32])
            .unwrap()
            .mnemonic_text();

        {
            let mut service = test_service();
            service
                .restore_from_mnemonic_offline_with_identity(
                    &path,
                    "password-1",
                    phrase.as_str(),
                    backup_identity(),
                )
                .unwrap();
            // No close(), no shutdown: the process simply stops existing here,
            // before a single block was ever scanned.
        }

        // The atomic create left no staging sibling behind to poison the name.
        let staging = temp.path().join(".crashed.create-staging");
        assert!(
            !staging.exists(),
            "a crashed restore must not leave an orphan staging directory"
        );
        let orphans: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "crashed")
            .collect();
        assert!(orphans.is_empty(), "unexpected leftovers: {orphans:?}");

        // A fresh service reopens the wallet the crashed one created.
        let mut reopened = test_service();
        let summary = reopened.open(&path).unwrap();
        assert_eq!(summary.state, "LOCKED");
        let unlocked = reopened.unlock("password-1").unwrap();
        assert_eq!(unlocked.state, "READY");

        // The scan resumes from the beginning: still in progress, no cursor,
        // nothing counted as recovered.
        assert_eq!(unlocked.seed_restore_status.as_deref(), Some("in_progress"));
        assert!(unlocked.cursor_height.is_none());
        assert!(unlocked.tip_height.is_none());
        assert_eq!(unlocked.balance, BalanceProjection::default());
        let state = reopened.unlocked.as_ref().unwrap();
        assert_eq!(state.sync_status, SyncStatus::Synchronizing);
        assert!(state.core_scan_cursor.is_none());
    }

    #[test]
    fn offline_restore_mainnet_wrapper_binds_the_canonical_identity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("mainnet-offline");
        let mut service = test_service();
        let phrase = CanonicalWalletSeed::from_entropy(&[0x12; 32])
            .unwrap()
            .mnemonic_text();
        let summary = service
            .restore_from_mnemonic_offline(&path, "password-1", phrase.as_str())
            .unwrap();
        assert_eq!(summary.network, Network::Mainnet);
        service.unlock("password-1").unwrap();
        let state = service.unlocked.as_ref().unwrap();
        require_mainnet_identity(&state.identity).unwrap();
    }

    #[test]
    fn regression_offline_restore_then_embedded_sync_completes_restore() {
        use std::time::{Duration, Instant};

        let node_directory = tempfile::tempdir().unwrap();
        let wallet_directory = tempfile::tempdir().unwrap();
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral embedded-core listener");
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut service = test_service();
        let phrase = CanonicalWalletSeed::from_entropy(&[0x13; 32])
            .unwrap()
            .mnemonic_text();

        // Capture the embedded Regtest identity, then restore fully offline.
        service
            .start_embedded_core(EmbeddedCoreConfiguration::new(
                dom_wallet_embedded_core::EmbeddedCoreNetwork::Regtest,
                node_directory.path(),
                address,
            ))
            .unwrap();
        let core_identity = service.embedded_core_cached_identity().unwrap();
        let identity = NetworkIdentity {
            network: map_network(core_identity.network),
            chain_id: core_identity.chain_id,
            genesis_id: core_identity.genesis_hash,
        };
        service.stop_embedded_core().unwrap();

        let path = wallet_directory.path().join("wallet");
        let restored = service
            .restore_from_mnemonic_offline_with_identity(
                &path,
                "password-1",
                phrase.as_str(),
                identity,
            )
            .unwrap();
        assert_eq!(restored.seed_restore_status.as_deref(), Some("in_progress"));
        service.unlock("password-1").unwrap();

        // The later synchronization pass performs the canonical recovery scan
        // and completes the restore once the cursor reaches the observed tip.
        service
            .start_embedded_core(EmbeddedCoreConfiguration::new(
                dom_wallet_embedded_core::EmbeddedCoreNetwork::Regtest,
                node_directory.path(),
                address,
            ))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let synced = loop {
            match service.synchronize() {
                Ok(summary) => break summary,
                Err(CoreError::NodeNotReady) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(CoreError::Backend(error))
                    if error.is_transient_sync_unavailability() && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(error) => panic!("synchronization failed: {error:?}"),
            }
        };
        assert_eq!(synced.seed_restore_status.as_deref(), Some("complete"));
        assert_eq!(synced.cursor_height, Some(0));
        assert_eq!(synced.tip_height, Some(0));
        assert!(synced.balance.total == 0);
        let state = service.unlocked.as_ref().unwrap();
        assert_eq!(state.sync_status, SyncStatus::Synced);
        assert_eq!(state.seed_restore_status, Some(SeedRestoreStatus::Complete));
        service.close().unwrap();
    }

    #[test]
    fn embedded_core_can_stop_and_restart_without_closing_the_service() {
        let directory = tempfile::tempdir().unwrap();
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral embedded-core listener");
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut service = test_service();

        service
            .start_embedded_core(EmbeddedCoreConfiguration::new(
                dom_wallet_embedded_core::EmbeddedCoreNetwork::Regtest,
                directory.path(),
                address,
            ))
            .unwrap();
        assert!(service.embedded_core_identity().is_ok());
        service.stop_embedded_core().unwrap();
        assert!(matches!(
            service.embedded_core_identity(),
            Err(CoreError::EmbeddedCoreRequired)
        ));
        service
            .start_embedded_core(EmbeddedCoreConfiguration::new(
                dom_wallet_embedded_core::EmbeddedCoreNetwork::Regtest,
                directory.path(),
                address,
            ))
            .unwrap();
        assert!(service.embedded_core_identity().is_ok());
        service.stop_embedded_core().unwrap();
    }
}

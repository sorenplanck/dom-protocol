//! Authenticated, retained-capability inventory for the Linux Phase 1 store.
//!
//! This module owns the retained-authority implementation of the canonical
//! Store transaction order. It never accepts ambient paths or alternate
//! persistent layouts.

#[cfg(any(test, feature = "evidence-only"))]
use super::{
    backup::{self, BackupPolicyLimitsV1, CompletedBackupV1},
    restore::ExistingDeviceRestorePreparationV1,
};
use super::{
    restore, ExpectedNodeType, LinuxCapabilityError, RetainedDirectory, RetainedExclusiveLock,
    RetainedFile, ValidatedComponent,
};
use crate::canonical::{
    ActiveSecretEvidenceV1, RestoreRecordFamilyV1, RestoreRecordItemV1, RestoreRecordSetV1,
    TerminalEvidenceV1,
};
use crate::{
    adaptor_outbound_digest_v1, canonical_attempt_relative_path, canonical_exposure_relative_path,
    canonical_generation_directory_name, canonical_journal_filename, canonical_tombstone_filename,
    canonical_tombstone_staging_filename, ActiveVaultGenerationV1, ArtifactKindV1, AttemptRecordV1,
    BudgetChargeV1, BudgetPolicyV1, CanonicalCodecError, ExposureRecordV1, ExposureStateV1,
    ExposureVersionIdV1, JournalEntryV1, JournalPayloadV1, NonceDerivationAttemptV1,
    NonceIdentityV1, ReservationAuthorityV1, ReservationContextBindingV1, SessionClaimV1,
    SigningPhaseV1, StoreLockIdentityV1, StoreRootIdentityV1, TombstoneV1,
    UnauthenticatedAttemptRecordV1, UnauthenticatedJournalEntryV1,
    UnauthenticatedJournalEnvelopeV1, UnauthenticatedVaultGenerationCoreV1, VaultGenerationCoreV1,
    ACTIVE_VAULT_GENERATION_LEN, ATTEMPT_RECORD_LEN, BUDGET_CHARGE_ADAPTOR_LEN,
    JOURNAL_ENTRY_MAX_LEN, NONCE_DERIVATION_ATTEMPT_LEN, RESERVATION_AUTHORITY_ADAPTOR_LEN,
    SESSION_CLAIM_LEN, STORE_IDENTITY_LEN, VAULT_GENERATION_CORE_LEN,
};
use cap_std::fs::Dir;
use dom_adaptor::{
    validate_prepared_exposure_v1, ExposureKindV1, FreshReservationRequestV1,
    NonceDerivationRequestV1, NonceIdentityV1 as AdaptorNonceIdentityV1, NonceSecretTransferV1,
    NonceVaultV1, ParticipantId, PermitIdV1, PreparedExposureV1, ProcessComputationBindingIdV1,
    ResendRequestV1, ReservationLiveStageV1 as AdaptorReservationLiveStageV1, ReservationNonceId,
    ReservationRequestLookupV1, ReservationResumeRequestV1, ReservationResumeResultV1,
    ReservationState, RestartArtifactRecoveryRequestV1, RestartArtifactRecoveryVaultV1,
    RestoreState, SessionId, StageComputationRequestV1, TerminalReservationV1,
    ValidatedResendAuthorizationV1 as AdaptorResendAuthorizationV1,
    VaultArtifactPersistencePermitV1, VaultComputationStageV1, VaultExportedArtifactV1,
    VaultReservationSnapshotV1, VaultSecretImportCapabilityV1, VaultSecretSealCapabilityV1,
    VaultSpentArtifactSnapshotV1,
};
use dom_scriptless_crypto::{
    audit_nonce_secret_record, authoritative_storage_hash_v1, generate_storage_ids,
    open_master_key, open_nonce_secret_record, open_tombstone_v1, seal_nonce_secret_record,
    seal_tombstone_v1, NonceSecretRecordMetadataV1, Passphrase, StorageHashDomainV1, StorageIdsV1,
    TombstonePlaintextV1, TombstoneRecordMetadataV1, VaultMasterKey, VaultMasterKeyEnvelopeV1,
    VaultObjectEnvelopeV1,
};
use dom_scriptless_crypto::{generate_vault_master_key, seal_master_key};
use rand_core::{OsRng, RngCore};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    ops::Deref,
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

mod collaborative;

const ROOT_IDENTITY: &str = "store-root-identity.bin";
const LOCK_IDENTITY: &str = "store-lock-identity.bin";
const ACTIVE_GENERATION: &str = "active-vault-generation";
const GENERATION_CORE: &str = "generation-core.bin";
const MASTER_KEY_ENVELOPE: &str = "master-key.envelope";
const MASTER_KEY_ENVELOPE_LEN: usize = 182;
const NONCE_SECRET_ENVELOPE_MAX_LEN: usize = 1_122;
pub(super) const TOMBSTONE_ENVELOPE_LEN: usize = 495;

#[cfg(all(test, feature = "evidence-only"))]
std::thread_local! {
    static TEST_UNIX_TIME: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

// Resend fault injection for the evidence-only signer E2E. The gate is the
// SAME pair that guards `mod signer_e2e`, its only consumer, so these items
// exist exactly where they are used and are dead in no configuration.
#[cfg(all(test, feature = "evidence-only"))]
type ResendInterpositionV1 = Box<dyn FnOnce() -> Result<(), InventoryError> + Send + 'static>;

#[cfg(all(test, feature = "evidence-only"))]
std::thread_local! {
    static RESEND_INTERPOSITION: std::cell::RefCell<Option<ResendInterpositionV1>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, feature = "evidence-only"))]
#[must_use]
pub(super) struct ResendInterpositionGuardV1 {
    previous: Option<ResendInterpositionV1>,
}

#[cfg(all(test, feature = "evidence-only"))]
impl Drop for ResendInterpositionGuardV1 {
    fn drop(&mut self) {
        RESEND_INTERPOSITION.with(|slot| {
            slot.replace(self.previous.take());
        });
    }
}

#[cfg(all(test, feature = "evidence-only"))]
pub(super) fn install_resend_interposition(
    interposition: ResendInterpositionV1,
) -> Result<ResendInterpositionGuardV1, InventoryError> {
    let previous = RESEND_INTERPOSITION.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(slot.replace(interposition))
    })?;
    Ok(ResendInterpositionGuardV1 { previous })
}

#[cfg(all(test, feature = "evidence-only"))]
fn run_resend_interposition() -> Result<(), InventoryError> {
    let interposition = RESEND_INTERPOSITION.with(|slot| slot.borrow_mut().take());
    match interposition {
        Some(interposition) => interposition(),
        None => Ok(()),
    }
}

/// Terminates a test subprocess after one exact normal-vault durability cut.
#[cfg(test)]
fn test_normal_vault_crash_hook(boundary: &str) {
    use std::io::Write as _;

    if std::env::var("DOM_G1B_NORMAL_VAULT_CRASH_CUT")
        .ok()
        .as_deref()
        != Some(boundary)
    {
        return;
    }
    if let Some(marker) = std::env::var_os("DOM_G1B_NORMAL_VAULT_CRASH_MARKER") {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(marker)
        {
            let _ = file.write_all(boundary.as_bytes());
            let _ = file.sync_all();
        }
    }
    std::process::abort();
}

/// Redacted failure from the canonical Linux Contracts nonce vault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryError {
    /// A retained filesystem operation failed.
    Filesystem,
    /// A canonical record or transition was rejected.
    Canonical,
    /// Storage cryptography rejected an envelope or operation.
    Crypto,
    /// Startup or recovery found ambiguous durable authority.
    RestoreQuarantined,
    /// The operating-system CSPRNG failed.
    RandomFailure,
}

impl fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Filesystem => "retained filesystem inventory failed",
            Self::Canonical => "canonical inventory authentication failed",
            Self::Crypto => "storage envelope validation failed",
            Self::RestoreQuarantined => "store inventory is restore quarantined",
            Self::RandomFailure => "operating-system randomness failed",
        })
    }
}

impl Error for InventoryError {}

impl From<LinuxCapabilityError> for InventoryError {
    fn from(_: LinuxCapabilityError) -> Self {
        Self::Filesystem
    }
}

impl From<CanonicalCodecError> for InventoryError {
    fn from(_: CanonicalCodecError) -> Self {
        Self::Canonical
    }
}

#[derive(Clone, Copy, Default)]
struct InventoryCounts {
    journal_entries: u64,
    reservation_authorities: u64,
    session_claims: u64,
    budget_charges: u64,
    attempts: u64,
    exposures: u64,
    nonce_secrets: u64,
    tombstones: u64,
    collaborative_states: u64,
}

struct AtomicInventorySnapshotV1 {
    open_instance_id: [u8; 32],
    root_identity_digest: [u8; 32],
    active_generation_digest: [u8; 32],
    journal_sequence: u64,
    journal_head_digest: [u8; 32],
    counts: InventoryCounts,
}

#[cfg(any(test, feature = "evidence-only"))]
struct BackupOperationAuthorityV1 {
    inventory: AtomicInventorySnapshotV1,
    history: backup::AuthenticatedBackupHistoryV1,
}

#[cfg(any(test, feature = "evidence-only"))]
impl BackupOperationAuthorityV1 {
    fn require_same(&self, other: &Self) -> Result<(), InventoryError> {
        if !self.inventory.same_authority(&other.inventory) {
            return Err(InventoryError::RestoreQuarantined);
        }
        self.history.require_same(&other.history)?;
        Ok(())
    }
}

/// Complete backup inputs minted only after retained live-Store authentication.
///
/// Private fields deliberately prevent sibling runtime modules from fabricating
/// an authority-bearing input set. The backup transaction can only consume the
/// value produced by `LiveStoreInventoryV1::current_backup_inputs`.
pub(super) struct VerifiedBackupInputsV1 {
    storage_ids: StorageIdsV1,
    source_epoch: u64,
    source_journal_sequence: u64,
    source_journal_head_digest: [u8; 32],
    journal_entries: Vec<Vec<u8>>,
    record_set: RestoreRecordSetV1,
}

impl VerifiedBackupInputsV1 {
    pub(super) const fn storage_ids(&self) -> StorageIdsV1 {
        self.storage_ids
    }

    pub(super) const fn source_epoch(&self) -> u64 {
        self.source_epoch
    }

    pub(super) const fn source_journal_sequence(&self) -> u64 {
        self.source_journal_sequence
    }

    pub(super) const fn source_journal_head_digest(&self) -> [u8; 32] {
        self.source_journal_head_digest
    }

    pub(super) const fn record_set(&self) -> &RestoreRecordSetV1 {
        &self.record_set
    }

    pub(super) fn into_payloads(self) -> (Vec<Vec<u8>>, RestoreRecordSetV1) {
        (self.journal_entries, self.record_set)
    }
}

impl AtomicInventorySnapshotV1 {
    fn same_authority(&self, other: &Self) -> bool {
        self.open_instance_id == other.open_instance_id
            && self.root_identity_digest == other.root_identity_digest
            && self.active_generation_digest == other.active_generation_digest
            && self.journal_sequence == other.journal_sequence
            && self.journal_head_digest == other.journal_head_digest
            && self.counts.same_inventory(&other.counts)
    }
}

impl InventoryCounts {
    fn same_inventory(&self, other: &Self) -> bool {
        self.journal_entries == other.journal_entries
            && self.reservation_authorities == other.reservation_authorities
            && self.session_claims == other.session_claims
            && self.budget_charges == other.budget_charges
            && self.attempts == other.attempts
            && self.exposures == other.exposures
            && self.nonce_secrets == other.nonce_secrets
            && self.tombstones == other.tombstones
            && self.collaborative_states == other.collaborative_states
    }
}

#[cfg(test)]
type AuthenticatedLifetimeCarryBytesV1 = (Vec<Vec<u8>>, Vec<Vec<u8>>);

#[cfg(any(test, feature = "evidence-only"))]
/// Evidence-only inputs for one canonical new-device restore publication.
pub struct NewDeviceRestoreEvidenceRequestV1 {
    /// Retained parent containing the authenticated source Store.
    pub source_parent: Arc<Dir>,
    /// Validated single-component source Store name.
    pub source_root_name: String,
    /// Exact canonical completed-backup directory name.
    pub selected_backup_name: String,
    /// Owned passphrase used only to authenticate the selected backup.
    pub source_backup_passphrase: Passphrase,
    /// Retained parent in which the restore-only target is created.
    pub destination_parent: Arc<Dir>,
    /// Validated single-component destination Store name.
    pub destination_root_name: String,
    /// Owned passphrase for the successor Store authority.
    pub target_unlock_passphrase: Passphrase,
    /// Explicit authenticated allocation limits for evidence execution.
    pub limits: BackupPolicyLimitsV1,
    /// Explicit evidence-only budget policy.
    pub budget_policy: BudgetPolicyV1,
}

/// Opaque process-bound handle for one authenticated reservation.
pub struct ReservationHandleV1 {
    open_instance_id: [u8; 32],
    reservation_id: [u8; 32],
    authority_digest: [u8; 32],
}

/// Atomic non-authoritative projection of one live reservation.
pub struct ReservationSnapshotV1 {
    request_lookup: ReservationRequestLookupV1,
    reservation_nonce_id: ReservationNonceId,
    context_binding_digest: [u8; 32],
    live_stage: AdaptorReservationLiveStageV1,
    final_retry_counter: Option<u64>,
    spent_commitment: Option<SpentArtifactSnapshotV1>,
    spent_reveal: Option<SpentArtifactSnapshotV1>,
}

/// Store-owned non-exporting projection of one exact spent artifact.
pub struct SpentArtifactSnapshotV1 {
    nonce_identity: AdaptorNonceIdentityV1,
    permit_id: PermitIdV1,
    kind: ExposureKindV1,
    adaptor_outbound_digest: [u8; 32],
}

/// Store-owned descriptor recovered from authenticated current-generation state.
pub struct RecoveredSpentArtifactV1 {
    nonce_identity: AdaptorNonceIdentityV1,
    permit_id: PermitIdV1,
    kind: ArtifactKindV1,
    adaptor_outbound_digest: [u8; 32],
}

impl VaultSpentArtifactSnapshotV1 for RecoveredSpentArtifactV1 {
    fn nonce_identity(&self) -> &AdaptorNonceIdentityV1 {
        &self.nonce_identity
    }

    fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }

    fn kind(&self) -> ExposureKindV1 {
        artifact_to_exposure_kind(self.kind)
    }

    fn adaptor_outbound_digest(&self) -> &[u8; 32] {
        &self.adaptor_outbound_digest
    }
}

/// Retained, non-exporting authority for one exact persisted exposure.
///
/// This process-local handle is invalidated by reopen and carries no public
/// bytes. Every use reloads and authenticates the complete durable record.
/// Opaque retained handle for one exact persisted exposure.
pub struct PersistedExposureHandleV1 {
    authority: Arc<StoreAuthorityInner>,
    issuance: CapabilityIssuanceV1,
    reservation_id: [u8; 32],
    nonce_identity: NonceIdentityV1,
    attempt_digest: [u8; 32],
    operation_input_digest: [u8; 32],
    phase: SigningPhaseV1,
    artifact: ArtifactKindV1,
    exposure_sequence: u64,
    expected_lifecycle_revision: u64,
    persisted_lifecycle_revision: u64,
    exposure_version: ExposureVersionIdV1,
    exposure_record_digest: [u8; 32],
    outbound_digest: [u8; 32],
    outbound_length: usize,
    persistence_journal_digest: [u8; 32],
    consumed_tombstone_digest: Option<[u8; 32]>,
    deleted_secret_envelope_digest: Option<[u8; 32]>,
}

/// One retained, AEAD-authenticated nonce-secret record bound to one open
/// Store instance. Consuming this value is the only partial-persistence route
/// that may delete the corresponding canonical secret path.
struct AuthenticatedSecretForDeletionV1 {
    open_instance_id: [u8; 32],
    reservation_id: [u8; 32],
    nonce_identity: NonceIdentityV1,
    component: ValidatedComponent,
    retained_file: RetainedFile,
    complete_envelope_digest: [u8; 32],
}

/// One-shot process-local proof that a newly sealed secret belongs to the
/// exact durable derivation attempt.
struct SealedSecretOpenPermitV1 {
    open_instance_id: [u8; 32],
    reservation_id: [u8; 32],
    attempt_digest: [u8; 32],
    complete_envelope_digest: [u8; 32],
}

/// Opaque one-shot proof of a durable nonce-derivation attempt.
pub struct DerivationAttemptPermitV1 {
    open_instance_id: [u8; 32],
    reservation_id: [u8; 32],
    derivation: NonceDerivationAttemptV1,
    operation_input_digest: [u8; 32],
    stage_context_digest: [u8; 32],
}

/// Opaque one-shot authority for the first sealed-secret open.
pub struct InitialSecretOpenPermitV1 {
    sealed: SealedSecretOpenPermitV1,
    derivation: NonceDerivationAttemptV1,
    operation_input_digest: [u8; 32],
    stage_context_digest: [u8; 32],
}

/// Opaque one-shot proof of a durable reveal or partial attempt.
pub struct StageComputationPermitV1 {
    open_instance_id: [u8; 32],
    reservation_id: [u8; 32],
    attempt: AttemptRecordV1,
    operation_input_digest: [u8; 32],
    stage_context_digest: [u8; 32],
}

/// Opaque one-shot binding between an opened secret and exact persistence.
pub struct ArtifactPersistencePermitV1 {
    open_instance_id: [u8; 32],
    reservation_id: ReservationNonceId,
    nonce_identity: AdaptorNonceIdentityV1,
    context_binding_digest: [u8; 32],
    derivation_attempt_digest: [u8; 32],
    operation_input_digest: [u8; 32],
    effective_retry_counter: u64,
    phase: SigningPhaseV1,
    exposure_kind: ExposureKindV1,
    exposure_sequence: u64,
    expected_lifecycle_revision: u64,
    stage_context_digest: [u8; 32],
    process_binding: ProcessComputationBindingIdV1,
    attempt: AttemptRecordV1,
    secret_for_deletion: Option<AuthenticatedSecretForDeletionV1>,
}

/// One-shot process-local authority to durably spend one exact exposure.
///
/// The constructor is confined to the retained Store implementation. It is
/// intentionally non-cloneable, non-serializable, and non-debuggable.
/// Opaque one-shot consume-before-export capability.
pub struct ExposurePermitV1 {
    authority: Arc<StoreAuthorityInner>,
    issuance: CapabilityIssuanceV1,
    reservation_id: [u8; 32],
    nonce_identity: NonceIdentityV1,
    artifact: ArtifactKindV1,
    exposure_sequence: u64,
    spent_version: ExposureVersionIdV1,
    spent_record_digest: [u8; 32],
    outbound_digest: [u8; 32],
    outbound_length: usize,
    spent_journal_digest: [u8; 32],
    permit_id: PermitIdV1,
}

/// Public bytes returned only after the corresponding canonical exposure has
/// reached the durable `Spent` state.
/// Exact persisted public bytes returned after durable permit spend.
pub struct ExportedArtifactV1 {
    permit_id: PermitIdV1,
    kind: ArtifactKindV1,
    outbound_bytes: Vec<u8>,
}

impl VaultSpentArtifactSnapshotV1 for SpentArtifactSnapshotV1 {
    fn nonce_identity(&self) -> &AdaptorNonceIdentityV1 {
        &self.nonce_identity
    }

    fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }

    fn kind(&self) -> ExposureKindV1 {
        self.kind
    }

    fn adaptor_outbound_digest(&self) -> &[u8; 32] {
        &self.adaptor_outbound_digest
    }
}

impl VaultReservationSnapshotV1 for ReservationSnapshotV1 {
    type SpentArtifact = SpentArtifactSnapshotV1;

    fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.request_lookup
    }

    fn reservation_nonce_id(&self) -> &ReservationNonceId {
        &self.reservation_nonce_id
    }

    fn reservation_context_binding_digest(&self) -> &[u8; 32] {
        &self.context_binding_digest
    }

    fn live_stage(&self) -> AdaptorReservationLiveStageV1 {
        self.live_stage
    }

    fn final_retry_counter(&self) -> Option<u64> {
        self.final_retry_counter
    }

    fn spent_commitment(&self) -> Option<&Self::SpentArtifact> {
        self.spent_commitment.as_ref()
    }

    fn spent_reveal(&self) -> Option<&Self::SpentArtifact> {
        self.spent_reveal.as_ref()
    }
}

impl VaultArtifactPersistencePermitV1 for ArtifactPersistencePermitV1 {
    fn reservation_nonce_id(&self) -> &ReservationNonceId {
        &self.reservation_id
    }

    fn nonce_identity(&self) -> &AdaptorNonceIdentityV1 {
        &self.nonce_identity
    }

    fn reservation_context_binding_digest(&self) -> &[u8; 32] {
        &self.context_binding_digest
    }

    fn derivation_attempt_digest(&self) -> &[u8; 32] {
        &self.derivation_attempt_digest
    }

    fn operation_input_digest(&self) -> &[u8; 32] {
        &self.operation_input_digest
    }

    fn effective_retry_counter(&self) -> u64 {
        self.effective_retry_counter
    }

    fn phase(&self) -> SigningPhaseV1 {
        self.phase
    }

    fn exposure_kind(&self) -> ExposureKindV1 {
        self.exposure_kind
    }

    fn exposure_sequence(&self) -> u64 {
        self.exposure_sequence
    }

    fn expected_lifecycle_revision(&self) -> u64 {
        self.expected_lifecycle_revision
    }

    fn stage_context_digest(&self) -> &[u8; 32] {
        &self.stage_context_digest
    }

    fn process_computation_binding_id(&self) -> &ProcessComputationBindingIdV1 {
        &self.process_binding
    }
}

impl VaultExportedArtifactV1 for ExportedArtifactV1 {
    fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }

    fn kind(&self) -> ExposureKindV1 {
        artifact_to_exposure_kind(self.kind)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.outbound_bytes
    }
}

/// Concrete canonical Linux implementation of the adaptor nonce-vault contract.
pub struct ContractsNonceVaultV1 {
    store: LiveStoreInventoryV1,
    budget_policy: Option<BudgetPolicyV1>,
    same_open_claims: BTreeSet<[u8; 32]>,
}

/// Opaque retained authority for one canonical restore target root.
///
/// The capability is acquired separately from restore resumption, owns the
/// already-validated root handle, and is consumed by the one public resume
/// operation. It intentionally implements none of `Clone`, `Debug`,
/// serialization, or conversion to path bytes.
pub struct RetainedRestoreTargetV1 {
    root: RetainedDirectory,
}

pub(crate) struct StoreAuthorityInner {
    root: RetainedDirectory,
    generation: RetainedDirectory,
    journal: RetainedDirectory,
    reservation_authorities: Mutex<Option<RetainedDirectory>>,
    session_claims: Mutex<Option<RetainedDirectory>>,
    budget_charges: Mutex<Option<RetainedDirectory>>,
    attempts: Mutex<Option<RetainedDirectory>>,
    exposures: Mutex<Option<RetainedDirectory>>,
    nonce_secrets: Mutex<Option<RetainedDirectory>>,
    collaborative_secrets: Mutex<Option<RetainedDirectory>>,
    tombstones: RetainedDirectory,
    retained_lock: RetainedExclusiveLock,
    root_identity: StoreRootIdentityV1,
    lock_identity: StoreLockIdentityV1,
    core: VaultGenerationCoreV1,
    active: Mutex<ActiveVaultGenerationV1>,
    master_key: VaultMasterKey,
    open_instance_id: [u8; 32],
}

struct CapabilityIssuanceV1 {
    open_instance_id: [u8; 32],
    root_identity_digest: [u8; 32],
    lock_identity_digest: [u8; 32],
    vault_id: [u8; 32],
    nonce_epoch: u64,
    generation: u64,
    journal_sequence: u64,
    journal_head_digest: [u8; 32],
}

pub(crate) struct LiveStoreInventoryV1 {
    authority: Arc<StoreAuthorityInner>,
    authorities: Option<RetainedDirectory>,
    claims: Option<RetainedDirectory>,
    charges: Option<RetainedDirectory>,
    attempts: Option<RetainedDirectory>,
    exposures: Option<RetainedDirectory>,
    nonce_secrets: Option<RetainedDirectory>,
    collaborative_secrets: Option<RetainedDirectory>,
    tombstones: RetainedDirectory,
}

impl Deref for LiveStoreInventoryV1 {
    type Target = StoreAuthorityInner;

    fn deref(&self) -> &Self::Target {
        &self.authority
    }
}

fn retained_optional_directory_alias(
    directory: &Option<RetainedDirectory>,
) -> Result<Option<RetainedDirectory>, LinuxCapabilityError> {
    directory
        .as_ref()
        .map(RetainedDirectory::retained_alias)
        .transpose()
}

fn retain_authority_namespace_alias(
    source: &Option<RetainedDirectory>,
    retained: &Mutex<Option<RetainedDirectory>>,
) -> Result<(), InventoryError> {
    let Some(source) = source.as_ref() else {
        return Err(InventoryError::RestoreQuarantined);
    };
    source.revalidate()?;
    let mut retained = retained
        .lock()
        .map_err(|_| InventoryError::RestoreQuarantined)?;
    match retained.as_ref() {
        Some(existing) => {
            existing.revalidate()?;
            existing.identity.require_same(&source.identity)?;
        }
        None => *retained = Some(source.retained_alias()?),
    }
    Ok(())
}

impl LiveStoreInventoryV1 {
    /// Resumes a published existing-device restore from disk-only authority.
    ///
    /// The target lock is acquired before transaction discovery and remains
    /// held throughout authentication and publication. No source path, source
    /// unlock material, caller digest, or pre-crash preparation is accepted.
    pub(crate) fn resume_restore_from_disk(
        root: RetainedDirectory,
        target_unlock_passphrase: Passphrase,
    ) -> Result<Self, InventoryError> {
        Self::resume_restore_from_disk_with_completion(root, target_unlock_passphrase, || Ok(()))
    }

    /// Runs the disk-authoritative restore path and invokes a private completion
    /// hook only after the restored Store has passed its final inventory check
    /// while retaining the exclusive lock.  The production caller supplies the
    /// no-op hook; tests pass a local closure instead of sharing process-global
    /// test state with concurrent restore tests.
    fn resume_restore_from_disk_with_completion<F>(
        root: RetainedDirectory,
        target_unlock_passphrase: Passphrase,
        completion: F,
    ) -> Result<Self, InventoryError>
    where
        F: FnOnce() -> Result<(), InventoryError>,
    {
        let lock_component = ValidatedComponent::registered(LOCK_IDENTITY)?;
        let retained_lock = root.acquire_lock(&lock_component)?;
        retained_lock.revalidate()?;
        let root_identity = StoreRootIdentityV1::from_bytes(&root.read_bounded_file(
            &ValidatedComponent::registered(ROOT_IDENTITY)?,
            STORE_IDENTITY_LEN,
        )?)?;
        StoreLockIdentityV1::from_bytes_with_root(
            &root.read_bounded_file(&lock_component, STORE_IDENTITY_LEN)?,
            &root_identity,
        )?;
        retained_lock.revalidate()?;
        let mut restore_only_marker = false;
        let mut initialized_marker = false;
        root.scan_independent(|name, identity| {
            if name == "restore-only-root.bin" {
                if identity.node_type != ExpectedNodeType::RegularFile || restore_only_marker {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                restore_only_marker = true;
            } else if name.starts_with("restore-initialized-") {
                if identity.node_type != ExpectedNodeType::RegularFile
                    || ValidatedComponent::registered(name).is_err()
                    || initialized_marker
                {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                initialized_marker = true;
            }
            Ok(())
        })?;
        let completed = if restore_only_marker {
            restore::resume_new_device_restore_from_disk(
                &root,
                &retained_lock,
                &root_identity,
                &target_unlock_passphrase,
            )?
        } else if initialized_marker {
            return Err(InventoryError::RestoreQuarantined);
        } else {
            restore::resume_existing_device_restore_from_disk(
                &root,
                &retained_lock,
                &root_identity,
                &target_unlock_passphrase,
            )?
        };
        completed.completed().revalidate()?;
        completed.generation().revalidate()?;
        completed.active().revalidate()?;
        root.require_named_file_identity(
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            completed.active(),
        )?;

        // Transfer the still-held lock directly into the normal live Store.
        // There is deliberately no unlock/relock interval between restore
        // publication and the final canonical inventory validation.
        let reopened =
            Self::open_with_retained_lock(root, retained_lock, target_unlock_passphrase)?;
        completed
            .generation()
            .identity
            .require_same(&reopened.generation.identity)?;
        reopened.snapshot()?;
        completion()?;
        Ok(reopened)
    }

    #[cfg(any(test, feature = "evidence-only"))]
    fn publish_new_device_restore(
        source_root: &RetainedDirectory,
        selected_backup_name: &str,
        source_backup_passphrase: Passphrase,
        destination_parent: Arc<Dir>,
        destination_root_name: &str,
        target_unlock_passphrase: Passphrase,
        limits: BackupPolicyLimitsV1,
    ) -> Result<Self, InventoryError> {
        let selected = restore::authenticate_selected_backup(
            source_root,
            selected_backup_name,
            source_backup_passphrase,
            limits,
        )?;
        let (initialized, preparation) = restore::initialize_new_device_restore_only_root(
            destination_parent,
            destination_root_name,
            selected,
        )?;
        let publication = restore::PreparedNewDeviceRestorePublicationV1::new(
            preparation,
            initialized.root_identity(),
            initialized.restore_only_root().clone(),
            &target_unlock_passphrase,
            limits,
        )?;
        let staged = restore::stage_new_device_restore(&initialized, publication)?;
        let completed = restore::publish_staged_new_device_restore(initialized, staged)?;
        let (root, retained_lock, root_identity, completed, generation, active) =
            completed.into_parts();
        root.revalidate()?;
        retained_lock.revalidate()?;
        completed.revalidate()?;
        generation.revalidate()?;
        active.revalidate()?;
        root.require_named_file_identity(
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            &active,
        )?;
        let reopened =
            Self::open_with_retained_lock(root, retained_lock, target_unlock_passphrase)?;
        if reopened.root_identity.as_bytes() != root_identity.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        generation
            .identity
            .require_same(&reopened.generation.identity)?;
        reopened.snapshot()?;
        Ok(reopened)
    }

    /// Creates the exact empty canonical generation under a retained parent.
    ///
    /// The caller supplies only the retained parent capability, a validated
    /// single-component root name, independent public storage IDs, and the
    /// approved passphrase boundary.  Every object created here is one of the
    /// P1-004 canonical authority objects; no compatibility layout exists.
    pub(crate) fn create(
        parent: Arc<Dir>,
        root_name: &str,
        storage_ids: StorageIdsV1,
        unlock_passphrase: &Passphrase,
    ) -> Result<Self, InventoryError> {
        let root = RetainedDirectory::create_under(
            parent,
            ValidatedComponent::operator_selected_root(root_name)?,
        )?;
        let root_identity = StoreRootIdentityV1::new(
            *storage_ids.contract_wallet_id(),
            random_nonzero::<32>()?,
            random_nonzero::<16>()?,
        )?;
        let lock_identity = StoreLockIdentityV1::from_root(&root_identity)?;
        root.create_immutable_file(
            &ValidatedComponent::registered(ROOT_IDENTITY)?,
            root_identity.as_bytes(),
        )?;
        root.create_immutable_file(
            &ValidatedComponent::registered(LOCK_IDENTITY)?,
            lock_identity.as_bytes(),
        )?;
        let retained_lock = root.acquire_lock(&ValidatedComponent::registered(LOCK_IDENTITY)?)?;
        let reopened_root_identity = StoreRootIdentityV1::from_bytes(&root.read_bounded_file(
            &ValidatedComponent::registered(ROOT_IDENTITY)?,
            STORE_IDENTITY_LEN,
        )?)?;
        let reopened_lock_identity = StoreLockIdentityV1::from_bytes_with_root(
            &root.read_bounded_file(
                &ValidatedComponent::registered(LOCK_IDENTITY)?,
                STORE_IDENTITY_LEN,
            )?,
            &reopened_root_identity,
        )?;
        if reopened_root_identity.as_bytes() != root_identity.as_bytes()
            || reopened_lock_identity.as_bytes() != lock_identity.as_bytes()
        {
            return Err(InventoryError::RestoreQuarantined);
        }

        let master_key = generate_vault_master_key().map_err(|_| InventoryError::Crypto)?;
        let master_envelope = seal_master_key(storage_ids, unlock_passphrase, &master_key)
            .map_err(|_| InventoryError::Crypto)?;
        let master_envelope_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::MasterEnvelope,
            master_envelope.as_bytes(),
        );
        // P1-004 assigns the initial generation and nonce epoch as the first
        // deterministic values.  They are not caller-controlled configuration.
        let mut store_root_id = [0_u8; 32];
        store_root_id.copy_from_slice(root_identity.store_root_id());
        let core = VaultGenerationCoreV1::new(
            *storage_ids.contract_wallet_id(),
            store_root_id,
            *storage_ids.vault_id(),
            1,
            1,
            master_envelope_digest,
        )?;
        let generation_name = canonical_generation_directory_name(
            &UnauthenticatedVaultGenerationCoreV1::parse_structural(core.as_bytes())?,
        );
        let generation_component = ValidatedComponent::registered(&generation_name)?;
        let generation_staging_component =
            ValidatedComponent::registered(&format!(".{generation_name}.staging"))?;
        let generation_staging =
            root.create_child_directory(generation_staging_component.clone())?;
        generation_staging.create_immutable_file(
            &ValidatedComponent::registered(GENERATION_CORE)?,
            core.as_bytes(),
        )?;
        generation_staging.create_immutable_file(
            &ValidatedComponent::registered(MASTER_KEY_ENVELOPE)?,
            master_envelope.as_bytes(),
        )?;
        for namespace in [
            "journal",
            "reservation-authorities",
            "session-claims",
            "budget-charges",
            "attempts",
            "exposures",
            "nonce-secrets",
            "collaborative-secrets",
            "tombstones",
        ] {
            let directory = generation_staging
                .create_child_directory(ValidatedComponent::registered(namespace)?)?;
            directory.sync()?;
        }
        generation_staging.sync()?;
        let generation = root.rename_generation_no_replace(
            &generation_staging_component,
            &generation_component,
            &generation_staging,
        )?;
        if generation.read_bounded_file(
            &ValidatedComponent::registered(GENERATION_CORE)?,
            VAULT_GENERATION_CORE_LEN,
        )? != core.as_bytes()
            || generation.read_bounded_file(
                &ValidatedComponent::registered(MASTER_KEY_ENVELOPE)?,
                MASTER_KEY_ENVELOPE_LEN,
            )? != master_envelope.as_bytes()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        for namespace in [
            "journal",
            "reservation-authorities",
            "session-claims",
            "budget-charges",
            "attempts",
            "exposures",
            "nonce-secrets",
            "collaborative-secrets",
            "tombstones",
        ] {
            generation
                .open_child_directory(ValidatedComponent::registered(namespace)?)?
                .sync()?;
        }
        generation.sync()?;
        let active = ActiveVaultGenerationV1::new(&core, 0, [0; 32])?;
        let active_staging_component =
            ValidatedComponent::registered(".active-vault-generation.staging")?;
        let active_staging =
            root.create_immutable_file(&active_staging_component, active.as_bytes())?;
        root.rename_no_replace(
            &active_staging_component,
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            &active_staging,
        )?;
        let active_bytes = root.read_bounded_file(
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            ACTIVE_VAULT_GENERATION_LEN,
        )?;
        if active_bytes != active.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        require_normal_root_inventory(&root)?;
        require_generation_inventory(&generation)?;
        let journal = open_namespace(&generation, "journal")?;
        let tombstones = open_namespace(&generation, "tombstones")?;
        let authorities = open_optional_namespace(&generation, "reservation-authorities")?;
        let claims = open_optional_namespace(&generation, "session-claims")?;
        let charges = open_optional_namespace(&generation, "budget-charges")?;
        let attempts = open_optional_namespace(&generation, "attempts")?;
        let exposures = open_optional_namespace(&generation, "exposures")?;
        let nonce_secrets = open_optional_namespace(&generation, "nonce-secrets")?;
        let collaborative_secrets = open_optional_namespace(&generation, "collaborative-secrets")?;
        let retained_authorities = retained_optional_directory_alias(&authorities)?;
        let retained_claims = retained_optional_directory_alias(&claims)?;
        let retained_charges = retained_optional_directory_alias(&charges)?;
        let retained_attempts = retained_optional_directory_alias(&attempts)?;
        let retained_exposures = retained_optional_directory_alias(&exposures)?;
        let retained_nonce_secrets = retained_optional_directory_alias(&nonce_secrets)?;
        let retained_collaborative_secrets =
            retained_optional_directory_alias(&collaborative_secrets)?;
        let retained_tombstones = tombstones.retained_alias()?;
        let open_instance_id = *generate_storage_ids()
            .map_err(|_| InventoryError::RandomFailure)?
            .contract_wallet_id();
        let store = Self {
            authority: Arc::new(StoreAuthorityInner {
                root,
                generation,
                journal,
                reservation_authorities: Mutex::new(retained_authorities),
                session_claims: Mutex::new(retained_claims),
                budget_charges: Mutex::new(retained_charges),
                attempts: Mutex::new(retained_attempts),
                exposures: Mutex::new(retained_exposures),
                nonce_secrets: Mutex::new(retained_nonce_secrets),
                collaborative_secrets: Mutex::new(retained_collaborative_secrets),
                tombstones: retained_tombstones,
                retained_lock,
                root_identity,
                lock_identity,
                core,
                active: Mutex::new(active),
                master_key,
                open_instance_id,
            }),
            authorities,
            claims,
            charges,
            attempts,
            exposures,
            nonce_secrets,
            collaborative_secrets,
            tombstones,
        };
        let snapshot = store.snapshot()?;
        if snapshot.journal_sequence != 0 || snapshot.journal_head_digest != [0; 32] {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(store)
    }

    fn open(
        parent: Arc<Dir>,
        root_name: &str,
        unlock_passphrase: Passphrase,
    ) -> Result<Self, InventoryError> {
        let root = RetainedDirectory::open_under(
            parent,
            ValidatedComponent::operator_selected_root(root_name)?,
        )?;
        let lock_component = ValidatedComponent::registered(LOCK_IDENTITY)?;
        let retained_lock = root.acquire_lock(&lock_component)?;
        Self::open_with_retained_lock(root, retained_lock, unlock_passphrase)
    }

    fn open_with_retained_lock(
        root: RetainedDirectory,
        retained_lock: RetainedExclusiveLock,
        unlock_passphrase: Passphrase,
    ) -> Result<Self, InventoryError> {
        retained_lock.revalidate()?;
        require_normal_root_inventory(&root)?;

        let lock_component = ValidatedComponent::registered(LOCK_IDENTITY)?;
        let root_identity = StoreRootIdentityV1::from_bytes(&root.read_bounded_file(
            &ValidatedComponent::registered(ROOT_IDENTITY)?,
            STORE_IDENTITY_LEN,
        )?)?;
        let lock_identity_bytes = root.read_bounded_file(&lock_component, STORE_IDENTITY_LEN)?;
        let lock_identity =
            StoreLockIdentityV1::from_bytes_with_root(&lock_identity_bytes, &root_identity)?;

        let active_bytes = root.read_bounded_file(
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            ACTIVE_VAULT_GENERATION_LEN,
        )?;
        let active_structural =
            crate::UnauthenticatedActiveVaultGenerationV1::parse_structural(&active_bytes)?;
        let generation_component = format!(
            "generation-{:020}-{}",
            active_structural.vault_generation(),
            hex_lower(&active_structural.as_bytes()[74..106])
        );
        let generation =
            root.open_child_directory(ValidatedComponent::registered(&generation_component)?)?;
        require_generation_inventory(&generation)?;

        let core = VaultGenerationCoreV1::from_bytes(&generation.read_bounded_file(
            &ValidatedComponent::registered(GENERATION_CORE)?,
            VAULT_GENERATION_CORE_LEN,
        )?)?;
        if core.as_bytes()[10..74] != root_identity.as_bytes()[10..74]
            || canonical_generation_directory_name(
                &UnauthenticatedVaultGenerationCoreV1::parse_structural(core.as_bytes())?,
            ) != generation_component
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let active = ActiveVaultGenerationV1::from_bytes_with_core(&active_bytes, &core)?;
        let master_envelope = VaultMasterKeyEnvelopeV1::from_bytes(&generation.read_bounded_file(
            &ValidatedComponent::registered(MASTER_KEY_ENVELOPE)?,
            MASTER_KEY_ENVELOPE_LEN,
        )?)
        .map_err(|_| InventoryError::Crypto)?;
        let master_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::MasterEnvelope,
            master_envelope.as_bytes(),
        );
        if core.master_envelope_digest() != master_digest {
            return Err(InventoryError::RestoreQuarantined);
        }
        let mut contract_wallet_id = [0_u8; 32];
        contract_wallet_id.copy_from_slice(root_identity.contract_wallet_id());
        let mut vault_id = [0_u8; 32];
        vault_id.copy_from_slice(core.vault_id());
        let storage_ids =
            StorageIdsV1::new(contract_wallet_id, vault_id).map_err(|_| InventoryError::Crypto)?;
        let master_key = open_master_key(&master_envelope, storage_ids, &unlock_passphrase)
            .map_err(|_| InventoryError::Crypto)?;

        let journal = open_namespace(&generation, "journal")?;
        let tombstones = open_namespace(&generation, "tombstones")?;
        let authorities = open_optional_namespace(&generation, "reservation-authorities")?;
        let claims = open_optional_namespace(&generation, "session-claims")?;
        let charges = open_optional_namespace(&generation, "budget-charges")?;
        let attempts = open_optional_namespace(&generation, "attempts")?;
        let exposures = open_optional_namespace(&generation, "exposures")?;
        let nonce_secrets = open_optional_namespace(&generation, "nonce-secrets")?;
        let collaborative_secrets = open_optional_namespace(&generation, "collaborative-secrets")?;
        let retained_authorities = retained_optional_directory_alias(&authorities)?;
        let retained_claims = retained_optional_directory_alias(&claims)?;
        let retained_charges = retained_optional_directory_alias(&charges)?;
        let retained_attempts = retained_optional_directory_alias(&attempts)?;
        let retained_exposures = retained_optional_directory_alias(&exposures)?;
        let retained_nonce_secrets = retained_optional_directory_alias(&nonce_secrets)?;
        let retained_collaborative_secrets =
            retained_optional_directory_alias(&collaborative_secrets)?;
        let retained_tombstones = tombstones.retained_alias()?;

        let open_instance_id = *generate_storage_ids()
            .map_err(|_| InventoryError::RandomFailure)?
            .contract_wallet_id();

        let mut store = Self {
            authority: Arc::new(StoreAuthorityInner {
                root,
                generation,
                journal,
                reservation_authorities: Mutex::new(retained_authorities),
                session_claims: Mutex::new(retained_claims),
                budget_charges: Mutex::new(retained_charges),
                attempts: Mutex::new(retained_attempts),
                exposures: Mutex::new(retained_exposures),
                nonce_secrets: Mutex::new(retained_nonce_secrets),
                collaborative_secrets: Mutex::new(retained_collaborative_secrets),
                tombstones: retained_tombstones,
                retained_lock,
                root_identity,
                lock_identity,
                core,
                active: Mutex::new(active),
                master_key,
                open_instance_id,
            }),
            authorities,
            claims,
            charges,
            attempts,
            exposures,
            nonce_secrets,
            collaborative_secrets,
            tombstones,
        };
        store.preflight_complete_inventory_before_recovery_mutation()?;
        store.recover_partial_consumption_prefixes()?;
        store.recover_authorized_exposure_prefixes()?;
        store.recover_lost_pre_authorization_capabilities()?;
        collaborative::recover_collaborative_state(&mut store)?;
        let _snapshot = store.snapshot()?;
        Ok(store)
    }

    fn snapshot(&self) -> Result<AtomicInventorySnapshotV1, InventoryError> {
        self.revalidate_authority()?;
        let journal = self.audit_current_generation_journal()?;
        let active = self.active_record()?;
        if self.core.vault_generation() == 1 && self.core.nonce_epoch() == 1 {
            if journal.composite.has_matching_anchor(&self.core)?
                || journal.sequence != active.journal_sequence()
                || journal.head_digest.as_slice() != active.journal_head_digest()
            {
                return Err(InventoryError::RestoreQuarantined);
            }
        } else {
            journal
                .composite
                .verify_current_generation_active_head(&self.core, &active)?;
        }
        let active_generation_digest = *active.active_generation_digest();
        drop(active);

        let counts = InventoryCounts {
            journal_entries: journal.entry_count,
            reservation_authorities: audit_optional_namespace(
                self.authorities.as_ref(),
                audit_authorities,
            )?,
            session_claims: audit_optional_namespace(self.claims.as_ref(), audit_claims)?,
            budget_charges: audit_optional_namespace(self.charges.as_ref(), audit_charges)?,
            attempts: audit_optional_namespace(self.attempts.as_ref(), audit_attempts)?,
            exposures: audit_optional_namespace(self.exposures.as_ref(), audit_exposures)?,
            nonce_secrets: self.audit_nonce_secrets()?,
            tombstones: self.audit_tombstones()?,
            collaborative_states: collaborative::audit_namespace(self)?,
        };
        if counts.reservation_authorities != counts.session_claims
            || counts.reservation_authorities != counts.budget_charges
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        if counts.exposures != 0 {
            audit_exposure_chains(
                self.exposures
                    .as_ref()
                    .ok_or(InventoryError::RestoreQuarantined)?,
                self.attempts
                    .as_ref()
                    .ok_or(InventoryError::RestoreQuarantined)?,
                &mut |identity_name| self.read_authenticated_tombstone(identity_name),
            )?;
        }
        self.audit_reservation_projection_set()?;
        self.revalidate_authority()?;
        Ok(AtomicInventorySnapshotV1 {
            open_instance_id: self.open_instance_id,
            root_identity_digest: *self.root_identity.identity_digest(),
            active_generation_digest,
            journal_sequence: journal.sequence,
            journal_head_digest: journal.head_digest,
            counts,
        })
    }

    /// Authenticates every unrelated durable object before a crash-prefix
    /// recovery is allowed to append, tombstone, unlink, or advance a pointer.
    ///
    /// Unlike [`Self::snapshot`], this accepts only the closed, recoverable
    /// active-pointer lag that can exist after an interrupted signed
    /// transaction.  It never mutates disk and rejects any pointer ahead of,
    /// detached from, or inconsistent with the authenticated journal.
    fn preflight_complete_inventory_before_recovery_mutation(&self) -> Result<(), InventoryError> {
        self.revalidate_authority()?;
        let journal = self.audit_current_generation_journal()?;
        let active = ActiveVaultGenerationV1::from_bytes_with_core(
            &self.root.read_bounded_file(
                &ValidatedComponent::registered(ACTIVE_GENERATION)?,
                ACTIVE_VAULT_GENERATION_LEN,
            )?,
            &self.core,
        )?;
        if active.journal_sequence() > journal.sequence
            || (active.journal_sequence() == 0 && active.journal_head_digest() != [0_u8; 32])
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        if active.journal_sequence() != 0 {
            let active_entry = journal
                .entries
                .iter()
                .find(|entry| entry.sequence() == active.journal_sequence())
                .ok_or(InventoryError::RestoreQuarantined)?;
            if active_entry.entry_digest() != active.journal_head_digest() {
                return Err(InventoryError::RestoreQuarantined);
            }
        }

        let counts = InventoryCounts {
            journal_entries: journal.entry_count,
            reservation_authorities: audit_optional_namespace(
                self.authorities.as_ref(),
                audit_authorities,
            )?,
            session_claims: audit_optional_namespace(self.claims.as_ref(), audit_claims)?,
            budget_charges: audit_optional_namespace(self.charges.as_ref(), audit_charges)?,
            attempts: audit_optional_namespace(self.attempts.as_ref(), audit_attempts)?,
            exposures: audit_optional_namespace(self.exposures.as_ref(), audit_exposures)?,
            nonce_secrets: self.audit_nonce_secrets()?,
            tombstones: self.audit_tombstones()?,
            collaborative_states: collaborative::audit_namespace(self)?,
        };
        if counts.reservation_authorities != counts.session_claims
            || counts.reservation_authorities != counts.budget_charges
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        if counts.exposures != 0 {
            audit_exposure_chains(
                self.exposures
                    .as_ref()
                    .ok_or(InventoryError::RestoreQuarantined)?,
                self.attempts
                    .as_ref()
                    .ok_or(InventoryError::RestoreQuarantined)?,
                &mut |identity_name| self.read_authenticated_tombstone(identity_name),
            )?;
        }
        self.audit_reservation_projection_set()?;
        self.require_journal_projection_correspondence_before_recovery(&journal)?;
        self.revalidate_authority()?;
        Ok(())
    }

    /// Reconstructs the complete non-secret projection set from retained
    /// directories and proves it is the journal projection, apart from the
    /// two explicitly signed partial-consumption prefixes which recovery can
    /// complete without any new secret material.
    fn require_journal_projection_correspondence_before_recovery(
        &self,
        journal: &JournalAudit,
    ) -> Result<(), InventoryError> {
        let actual_items = self.complete_projection_record_items()?;
        let expected_items =
            restore::canonical_record_items_from_journal(&journal.entries, &journal.terminals)
                .map_err(|_| InventoryError::RestoreQuarantined)?;

        let mut partial_prefixes = BTreeMap::<[u8; 105], ExposureRecordV1>::new();
        let mut unjournaled_tombstones = BTreeMap::<[u8; 105], TombstoneV1>::new();
        for (key, item) in &actual_items {
            if expected_items.get(key) == Some(item) {
                continue;
            }
            let family = RestoreRecordFamilyV1::try_from(key[105])
                .map_err(|_| InventoryError::RestoreQuarantined)?;
            let record = &item.as_bytes()[crate::RESTORE_RECORD_ITEM_PREFIX_LEN..];
            match family {
                RestoreRecordFamilyV1::Exposure => {
                    let exposure = ExposureRecordV1::from_bytes(record)?;
                    if exposure.artifact() != ArtifactKindV1::PartialSignature
                        || exposure.state() != ExposureStateV1::Persisted
                    {
                        return Err(InventoryError::RestoreQuarantined);
                    }
                    if partial_prefixes
                        .insert(*exposure.identity().as_bytes(), exposure)
                        .is_some()
                    {
                        return Err(InventoryError::RestoreQuarantined);
                    }
                }
                RestoreRecordFamilyV1::Tombstone => {
                    let tombstone = TombstoneV1::from_bytes(record)?;
                    if unjournaled_tombstones
                        .insert(*tombstone.identity().as_bytes(), tombstone)
                        .is_some()
                    {
                        return Err(InventoryError::RestoreQuarantined);
                    }
                }
                RestoreRecordFamilyV1::SessionClaim | RestoreRecordFamilyV1::Attempt => {
                    return Err(InventoryError::RestoreQuarantined)
                }
            }
        }
        for key in expected_items.keys() {
            if !actual_items.contains_key(key) {
                return Err(InventoryError::RestoreQuarantined);
            }
        }
        for (identity, tombstone) in &unjournaled_tombstones {
            let partial = partial_prefixes
                .get(identity)
                .ok_or(InventoryError::RestoreQuarantined)?;
            tombstone.validate_intervening_consumed(partial)?;
        }
        for (identity, partial) in &partial_prefixes {
            self.validate_partial_prefix_before_recovery(
                partial,
                unjournaled_tombstones.get(identity),
            )?;
        }
        Ok(())
    }

    /// Proves that an unjournaled partial record is one of the narrowly
    /// ratified P1-002 crash prefixes before any recovery step is permitted
    /// to create a tombstone, append a journal entry, or unlink a secret.
    fn validate_partial_prefix_before_recovery(
        &self,
        partial: &ExposureRecordV1,
        tombstone: Option<&TombstoneV1>,
    ) -> Result<(), InventoryError> {
        let identity = partial.identity();
        let identity_name = hex_lower(identity.as_bytes());
        let authority = self.find_authority_for_identity(identity)?;
        let attempt = read_attempt_for_artifact(
            self.attempts()?,
            &identity_name,
            ArtifactKindV1::PartialSignature,
        )?;
        let preceding = self
            .preceding_spent_for(identity, ArtifactKindV1::PartialSignature)?
            .ok_or(InventoryError::RestoreQuarantined)?;
        partial.validate_persisted_context(&attempt, Some(&preceding))?;

        let secret_component = ValidatedComponent::registered(&format!("{identity_name}.secret"))?;
        let secret_exists = contains_component(self.nonce_secrets()?, secret_component.as_str())?;
        let retained_secret = if secret_exists {
            let derivation = read_nonce_derivation_attempt(self.attempts()?, &identity_name)?;
            Some(
                self.authenticate_active_secret_for_terminal(&authority, &derivation)?
                    .1,
            )
        } else {
            None
        };
        match tombstone {
            Some(tombstone) => {
                tombstone.validate_intervening_consumed(partial)?;
                if let Some(secret) = retained_secret.as_ref() {
                    if secret.complete_envelope_digest
                        != *tombstone.deleted_secret_envelope_digest()
                    {
                        return Err(InventoryError::RestoreQuarantined);
                    }
                }
            }
            None if retained_secret.is_none() => return Err(InventoryError::RestoreQuarantined),
            None => {}
        }
        Ok(())
    }

    fn complete_projection_record_items(
        &self,
    ) -> Result<BTreeMap<[u8; crate::RESTORE_RECORD_KEY_LEN], RestoreRecordItemV1>, InventoryError>
    {
        let mut items = BTreeMap::new();
        let mut push =
            |family: RestoreRecordFamilyV1, bytes: &[u8]| -> Result<(), InventoryError> {
                let item = RestoreRecordItemV1::from_record_bytes(family, bytes)?;
                let mut key = [0_u8; crate::RESTORE_RECORD_KEY_LEN];
                key.copy_from_slice(&item.as_bytes()[..crate::RESTORE_RECORD_KEY_LEN]);
                match items.get(&key) {
                    Some(existing) if existing == &item => Ok(()),
                    Some(_) => Err(InventoryError::RestoreQuarantined),
                    None => {
                        items.insert(key, item);
                        Ok(())
                    }
                }
            };
        if let Some(claims) = self.claims.as_ref() {
            claims.scan_lexicographic(|name, node| {
                if node.node_type != ExpectedNodeType::RegularFile {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                let bytes = claims
                    .read_bounded_file(&ValidatedComponent::registered(name)?, SESSION_CLAIM_LEN)?;
                push(RestoreRecordFamilyV1::SessionClaim, &bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
            })?;
        }
        if let Some(attempts) = self.attempts.as_ref() {
            attempts.scan_lexicographic(|identity_name, identity_node| {
                if identity_node.node_type != ExpectedNodeType::Directory {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                let directory = attempts
                    .open_child_directory(ValidatedComponent::registered(identity_name)?)?;
                directory.scan_lexicographic(|name, node| {
                    if node.node_type != ExpectedNodeType::RegularFile {
                        return Err(LinuxCapabilityError::InvalidObject);
                    }
                    let bytes = directory.read_bounded_file(
                        &ValidatedComponent::registered(name)?,
                        NONCE_DERIVATION_ATTEMPT_LEN,
                    )?;
                    let canonical = if bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
                        NonceDerivationAttemptV1::from_bytes(&bytes)
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                            .as_bytes()
                            .to_vec()
                    } else {
                        AttemptRecordV1::from_bytes(&bytes)
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                            .as_bytes()
                            .to_vec()
                    };
                    push(RestoreRecordFamilyV1::Attempt, &canonical)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
                })
            })?;
        }
        if let Some(exposures) = self.exposures.as_ref() {
            scan_exposure_records(exposures, |exposure| {
                push(RestoreRecordFamilyV1::Exposure, exposure.as_bytes())
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
            })?;
        }
        self.tombstones.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || !name.ends_with(".tombstone") {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let identity = name
                .strip_suffix(".tombstone")
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            let tombstone = self.read_authenticated_tombstone(identity)?;
            push(RestoreRecordFamilyV1::Tombstone, tombstone.as_bytes())
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
        })?;
        Ok(items)
    }

    /// Completes only the uniquely determined P1-002 §6.10.1 partial prefix.
    ///
    /// This executes before normal inventory admission while the retained
    /// exclusive lock is continuously held. It never invokes the signer and
    /// never reconstructs an authorization handle or export capability.
    fn recover_partial_consumption_prefixes(&mut self) -> Result<(), InventoryError> {
        let Some(exposures) = self.exposures.as_ref() else {
            return Ok(());
        };
        let mut records = Vec::new();
        scan_exposure_records(exposures, |record| {
            records.push(record.clone());
            Ok(())
        })?;
        let pending = records
            .iter()
            .filter(|record| {
                record.artifact() == ArtifactKindV1::PartialSignature
                    && record.state() == ExposureStateV1::Persisted
                    && !records.iter().any(|candidate| {
                        candidate.identity().as_bytes() == record.identity().as_bytes()
                            && candidate.artifact() == record.artifact()
                            && matches!(
                                candidate.state(),
                                ExposureStateV1::Authorized | ExposureStateV1::Spent
                            )
                    })
            })
            .cloned()
            .collect::<Vec<_>>();

        for partial in pending {
            let identity = *partial.identity();
            let identity_name = hex_lower(identity.as_bytes());
            let authority = self.find_authority_for_identity(&identity)?;
            let attempt = read_attempt_for_artifact(
                self.attempts()?,
                &identity_name,
                ArtifactKindV1::PartialSignature,
            )?;
            let preceding = self
                .preceding_spent_for(&identity, ArtifactKindV1::PartialSignature)?
                .ok_or(InventoryError::RestoreQuarantined)?;
            partial.validate_persisted_context(&attempt, Some(&preceding))?;

            let secret_component =
                ValidatedComponent::registered(&format!("{identity_name}.secret"))?;
            let secret_exists =
                contains_component(self.nonce_secrets()?, secret_component.as_str())?;
            let mut retained_secret = if secret_exists {
                let derivation = read_nonce_derivation_attempt(self.attempts()?, &identity_name)?;
                Some(
                    self.authenticate_active_secret_for_terminal(&authority, &derivation)?
                        .1,
                )
            } else {
                None
            };
            let tombstone_component = format!("{identity_name}.tombstone");
            let tombstone = if contains_component(&self.tombstones, &tombstone_component)? {
                let tombstone = self.read_authenticated_tombstone(&identity_name)?;
                tombstone.validate_intervening_consumed(&partial)?;
                if let Some(secret) = retained_secret.as_ref() {
                    if secret.complete_envelope_digest
                        != *tombstone.deleted_secret_envelope_digest()
                    {
                        return Err(InventoryError::RestoreQuarantined);
                    }
                }
                tombstone
            } else {
                let secret = retained_secret
                    .as_ref()
                    .ok_or(InventoryError::RestoreQuarantined)?;
                let tombstone =
                    TombstoneV1::new_consumed(&attempt, &partial, secret.complete_envelope_digest)?;
                let plaintext = TombstonePlaintextV1::from_bytes(tombstone.as_bytes())
                    .map_err(|_| InventoryError::Crypto)?;
                let metadata = TombstoneRecordMetadataV1::from_tombstone(&plaintext)
                    .map_err(|_| InventoryError::Crypto)?;
                let envelope =
                    seal_tombstone_v1(self.storage_ids()?, &self.master_key, metadata, plaintext)
                        .map_err(|_| InventoryError::Crypto)?;
                self.persist_sealed_tombstone(&tombstone, &envelope)?;
                tombstone
            };

            let expected_payload =
                JournalPayloadV1::partial_consumed(&attempt, &preceding, &partial, &tombstone)?;
            let audit = self.audit_current_generation_journal()?;
            let mut exact_entries = audit
                .entries
                .iter()
                .filter(|entry| entry.payload().as_bytes() == expected_payload.as_bytes());
            let first = exact_entries.next().cloned();
            if exact_entries.next().is_some() {
                return Err(InventoryError::RestoreQuarantined);
            }
            let entry = match first {
                Some(entry) => {
                    if audit.head_digest != *entry.entry_digest() {
                        return Err(InventoryError::RestoreQuarantined);
                    }
                    entry
                }
                None => {
                    if retained_secret.is_none() {
                        return Err(InventoryError::RestoreQuarantined);
                    }
                    let entry = self.next_journal_entry(expected_payload)?;
                    self.persist_journal_entry(&entry)?;
                    let after = self.audit_current_generation_journal()?;
                    if after.head_digest != *entry.entry_digest() {
                        return Err(InventoryError::RestoreQuarantined);
                    }
                    entry
                }
            };

            if let Some(secret) = retained_secret.as_mut() {
                self.nonce_secrets()?
                    .require_named_file_identity(&secret.component, &secret.retained_file)?;
                let envelope = VaultObjectEnvelopeV1::from_bytes(
                    &secret
                        .retained_file
                        .read_bounded(NONCE_SECRET_ENVELOPE_MAX_LEN)?,
                )
                .map_err(|_| InventoryError::Crypto)?;
                if envelope.digest() != *tombstone.deleted_secret_envelope_digest() {
                    return Err(InventoryError::RestoreQuarantined);
                }
                self.nonce_secrets()?
                    .unlink_verified_file(&secret.component, &secret.retained_file)?;
            }
            if contains_component(self.nonce_secrets()?, secret_component.as_str())? {
                return Err(InventoryError::RestoreQuarantined);
            }
            self.activate_journal_head(&entry)?;
        }
        Ok(())
    }

    /// Resolves process-only authority loss exactly as P1-004 requires.
    ///
    /// Commitment/Reveal `Persisted` records and attempts for which no public
    /// artifact became durable cannot recreate a handle after restart. Their
    /// reservation is therefore irreversibly burned without refund. A
    /// completed consumed-partial prefix is deliberately excluded because its
    /// one canonical `Consumed` tombstone must not be replaced by `Burned`.
    fn recover_lost_pre_authorization_capabilities(&mut self) -> Result<(), InventoryError> {
        let Some(authorities) = self.authorities.as_ref() else {
            return Ok(());
        };
        let mut candidates = Vec::new();
        authorities.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let authority = ReservationAuthorityV1::from_bytes(&authorities.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                RESERVATION_AUTHORITY_ADAPTOR_LEN,
            )?)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let identity = authority
                .nonce_identity()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let identity_name = hex_lower(identity.as_bytes());
            let has_tombstone =
                contains_component(&self.tombstones, &format!("{identity_name}.tombstone"))
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if has_tombstone {
                return Ok(());
            }
            let has_attempt = self
                .attempts
                .as_ref()
                .map(|directory| contains_component(directory, &identity_name))
                .transpose()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                .unwrap_or(false);
            if !has_attempt {
                return Ok(());
            }
            let attempt_directory = self
                .attempts
                .as_ref()
                .ok_or(LinuxCapabilityError::ExactBytesMismatch)?
                .open_child_directory(ValidatedComponent::registered(&identity_name)?)?;
            let mut attempted = [false; 3];
            attempt_directory.scan_lexicographic(|name, node| {
                if node.node_type != ExpectedNodeType::RegularFile {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                let bytes = attempt_directory.read_bounded_file(
                    &ValidatedComponent::registered(name)?,
                    NONCE_DERIVATION_ATTEMPT_LEN,
                )?;
                let artifact = if bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
                    NonceDerivationAttemptV1::from_bytes(&bytes)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                        .attempt()
                        .artifact()
                } else {
                    AttemptRecordV1::from_bytes(&bytes)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                        .artifact()
                };
                attempted[usize::from(artifact as u8 - 1)] = true;
                Ok(())
            })?;
            let mut exposure_exists = [false; 3];
            let mut persisted = [false; 3];
            let mut authorized_or_spent = [false; 3];
            if let Some(exposures) = self.exposures.as_ref() {
                scan_exposure_records(exposures, |exposure| {
                    if exposure.identity().as_bytes() == identity.as_bytes() {
                        let index = usize::from(exposure.artifact() as u8 - 1);
                        exposure_exists[index] = true;
                        persisted[index] |= exposure.state() == ExposureStateV1::Persisted;
                        if matches!(
                            exposure.state(),
                            ExposureStateV1::Authorized | ExposureStateV1::Spent
                        ) {
                            authorized_or_spent[index] = true;
                        }
                    }
                    Ok(())
                })
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            }
            let attempt_without_artifact = attempted
                .iter()
                .zip(exposure_exists.iter())
                .any(|(attempt, exposure)| *attempt && !*exposure);
            let lost_public_handle =
                (0..2).any(|index| persisted[index] && !authorized_or_spent[index]);
            if attempt_without_artifact || lost_public_handle {
                let mut reservation_id = [0_u8; 32];
                reservation_id.copy_from_slice(authority.reservation_id());
                candidates.push((reservation_id, *authority.authority_digest()));
            }
            Ok(())
        })?;

        for (reservation_id, authority_digest) in candidates {
            let handle = ReservationHandleV1 {
                open_instance_id: self.open_instance_id,
                reservation_id,
                authority_digest,
            };
            self.persist_terminal_reservation(&handle, true)?;
        }
        Ok(())
    }

    /// Completes an already durable `Authorized` prefix to `Spent` without
    /// reconstructing the lost process-only export capability.
    fn recover_authorized_exposure_prefixes(&mut self) -> Result<(), InventoryError> {
        let Some(exposures) = self.exposures.as_ref() else {
            return Ok(());
        };
        let mut records = Vec::new();
        scan_exposure_records(exposures, |record| {
            records.push(record.clone());
            Ok(())
        })?;
        let pending = records
            .iter()
            .filter(|record| {
                record.state() == ExposureStateV1::Authorized
                    && !records.iter().any(|candidate| {
                        candidate.identity().as_bytes() == record.identity().as_bytes()
                            && candidate.artifact() == record.artifact()
                            && candidate.state() == ExposureStateV1::Spent
                    })
            })
            .cloned()
            .collect::<Vec<_>>();

        for authorized in pending {
            let persisted = records
                .iter()
                .find(|candidate| {
                    candidate.identity().as_bytes() == authorized.identity().as_bytes()
                        && candidate.artifact() == authorized.artifact()
                        && candidate.state() == ExposureStateV1::Persisted
                })
                .ok_or(InventoryError::RestoreQuarantined)?;
            let tombstone =
                if authorized.artifact() == ArtifactKindV1::PartialSignature {
                    Some(self.read_authenticated_tombstone(&hex_lower(
                        authorized.identity().as_bytes(),
                    ))?)
                } else {
                    None
                };
            authorized.validate_successor(persisted, tombstone.as_ref())?;
            let spent = ExposureRecordV1::new_successor(&authorized, None)?;
            let expected_payload =
                JournalPayloadV1::exposure_authorized(&authorized, &spent, None)?;
            let audit = self.audit_current_generation_journal()?;
            let mut exact_entries = audit
                .entries
                .iter()
                .filter(|entry| entry.payload().as_bytes() == expected_payload.as_bytes());
            let first = exact_entries.next().cloned();
            if exact_entries.next().is_some() {
                return Err(InventoryError::RestoreQuarantined);
            }
            let entry = match first {
                Some(entry) => {
                    if audit.head_digest != *entry.entry_digest() {
                        return Err(InventoryError::RestoreQuarantined);
                    }
                    entry
                }
                None => {
                    let entry = self.next_journal_entry(expected_payload)?;
                    self.persist_journal_entry(&entry)?;
                    entry
                }
            };
            persist_exposure_projection(self.exposures()?, &spent)?;
            self.activate_journal_head(&entry)?;
        }
        Ok(())
    }

    fn active_record(&self) -> Result<MutexGuard<'_, ActiveVaultGenerationV1>, InventoryError> {
        self.active
            .lock()
            .map_err(|_| InventoryError::RestoreQuarantined)
    }

    fn replace_active_record(&self, next: ActiveVaultGenerationV1) -> Result<(), InventoryError> {
        *self.active_record()? = next;
        Ok(())
    }

    fn capability_issuance(&self, snapshot: &AtomicInventorySnapshotV1) -> CapabilityIssuanceV1 {
        let mut vault_id = [0_u8; 32];
        vault_id.copy_from_slice(self.core.vault_id());
        CapabilityIssuanceV1 {
            open_instance_id: self.open_instance_id,
            root_identity_digest: *self.root_identity.identity_digest(),
            lock_identity_digest: *self.lock_identity.identity_digest(),
            vault_id,
            nonce_epoch: self.core.nonce_epoch(),
            generation: self.core.vault_generation(),
            journal_sequence: snapshot.journal_sequence,
            journal_head_digest: snapshot.journal_head_digest,
        }
    }

    fn revalidate_capability_issuance(
        &self,
        authority: &Arc<StoreAuthorityInner>,
        issuance: &CapabilityIssuanceV1,
    ) -> Result<JournalAudit, InventoryError> {
        if !Arc::ptr_eq(&self.authority, authority)
            || issuance.open_instance_id != self.open_instance_id
            || issuance.root_identity_digest != *self.root_identity.identity_digest()
            || issuance.lock_identity_digest != *self.lock_identity.identity_digest()
            || issuance.vault_id.as_slice() != self.core.vault_id()
            || issuance.nonce_epoch != self.core.nonce_epoch()
            || issuance.generation != self.core.vault_generation()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        self.revalidate_authority()?;
        let journal = self.audit_current_generation_journal()?;
        let bound = journal
            .entries
            .iter()
            .find(|entry| entry.sequence() == issuance.journal_sequence)
            .ok_or(InventoryError::RestoreQuarantined)?;
        if bound.entry_digest() != &issuance.journal_head_digest
            || journal.sequence < issuance.journal_sequence
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        self.retained_lock.revalidate()?;
        Ok(journal)
    }

    fn storage_ids(&self) -> Result<StorageIdsV1, InventoryError> {
        let mut contract_wallet_id = [0_u8; 32];
        contract_wallet_id.copy_from_slice(self.root_identity.contract_wallet_id());
        let mut vault_id = [0_u8; 32];
        vault_id.copy_from_slice(self.core.vault_id());
        StorageIdsV1::new(contract_wallet_id, vault_id).map_err(|_| InventoryError::Crypto)
    }

    fn authorities(&self) -> Result<&RetainedDirectory, InventoryError> {
        self.authorities
            .as_ref()
            .ok_or(InventoryError::RestoreQuarantined)
    }

    fn claims(&self) -> Result<&RetainedDirectory, InventoryError> {
        self.claims
            .as_ref()
            .ok_or(InventoryError::RestoreQuarantined)
    }

    fn charges(&self) -> Result<&RetainedDirectory, InventoryError> {
        self.charges
            .as_ref()
            .ok_or(InventoryError::RestoreQuarantined)
    }

    fn attempts(&self) -> Result<&RetainedDirectory, InventoryError> {
        self.attempts
            .as_ref()
            .ok_or(InventoryError::RestoreQuarantined)
    }

    fn exposures(&self) -> Result<&RetainedDirectory, InventoryError> {
        self.exposures
            .as_ref()
            .ok_or(InventoryError::RestoreQuarantined)
    }

    fn nonce_secrets(&self) -> Result<&RetainedDirectory, InventoryError> {
        self.nonce_secrets
            .as_ref()
            .ok_or(InventoryError::RestoreQuarantined)
    }

    fn collaborative_secrets(&self) -> Result<&RetainedDirectory, InventoryError> {
        self.collaborative_secrets
            .as_ref()
            .ok_or(InventoryError::RestoreQuarantined)
    }

    fn nonce_secret_metadata(
        &self,
        authority: &ReservationAuthorityV1,
        derivation: &NonceDerivationAttemptV1,
    ) -> Result<NonceSecretRecordMetadataV1, InventoryError> {
        let identity = authority.nonce_identity()?;
        if derivation.attempt().identity().as_bytes() != identity.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let revision = derivation
            .attempt()
            .expected_lifecycle_revision()
            .checked_add(1)
            .ok_or(InventoryError::Canonical)?;
        let mut session_id = [0_u8; 32];
        session_id.copy_from_slice(authority.session_id());
        let mut participant_id = [0_u8; 32];
        participant_id.copy_from_slice(authority.participant_id());
        NonceSecretRecordMetadataV1::new(
            authority.nonce_epoch(),
            session_id,
            participant_id,
            authority.purpose(),
            revision,
            *authority.bound_digest(),
        )
        .map_err(|_| InventoryError::Crypto)
    }

    /// Authenticates every retained secret envelope against its exact
    /// reservation and derivation projections without exporting plaintext.
    fn audit_nonce_secrets(&self) -> Result<u64, InventoryError> {
        let Some(directory) = self.nonce_secrets.as_ref() else {
            return Ok(0);
        };
        let mut count = 0_u64;
        directory.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || !name.ends_with(".secret") {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let bytes = directory.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                NONCE_SECRET_ENVELOPE_MAX_LEN,
            )?;
            let envelope = VaultObjectEnvelopeV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if envelope.record_kind() != dom_scriptless_crypto::RecordKindV1::NonceSecretRecord {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }

            let mut authority_match: Option<ReservationAuthorityV1> = None;
            let authorities = self
                .authorities
                .as_ref()
                .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
            authorities.scan_lexicographic(|authority_name, _| {
                let authority_bytes = authorities.read_bounded_file(
                    &ValidatedComponent::registered(authority_name)?,
                    RESERVATION_AUTHORITY_ADAPTOR_LEN,
                )?;
                let authority = ReservationAuthorityV1::from_bytes(&authority_bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let expected_name = format!(
                    "{}.secret",
                    hex_lower(
                        authority
                            .nonce_identity()
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                            .as_bytes()
                    )
                );
                if expected_name == name {
                    if authority_match.is_some() {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                    authority_match = Some(authority);
                }
                Ok(())
            })?;
            let authority = authority_match.ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
            let identity_name = hex_lower(
                authority
                    .nonce_identity()
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    .as_bytes(),
            );
            let derivation = read_nonce_derivation_attempt(
                self.attempts
                    .as_ref()
                    .ok_or(LinuxCapabilityError::ExactBytesMismatch)?,
                &identity_name,
            )?;
            let metadata = self
                .nonce_secret_metadata(&authority, &derivation)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            audit_nonce_secret_record(
                &envelope,
                self.storage_ids()
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
                &self.master_key,
                metadata,
            )
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            count = count
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            Ok(())
        })?;
        Ok(count)
    }

    fn audit_current_generation_journal(&self) -> Result<JournalAudit, InventoryError> {
        let terminals = self.authenticated_tombstone_map()?;
        audit_journal(&self.journal, &terminals)
    }

    fn authenticated_tombstone_map(
        &self,
    ) -> Result<BTreeMap<[u8; 105], TombstoneV1>, InventoryError> {
        let mut terminals = BTreeMap::new();
        self.tombstones.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || !name.ends_with(".tombstone") {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let identity_name = name
                .strip_suffix(".tombstone")
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            let tombstone = self.read_authenticated_tombstone(identity_name)?;
            if terminals
                .insert(*tombstone.identity().as_bytes(), tombstone)
                .is_some()
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            Ok(())
        })?;
        Ok(terminals)
    }

    fn read_authenticated_tombstone(
        &self,
        identity_name: &str,
    ) -> Result<TombstoneV1, LinuxCapabilityError> {
        let component = ValidatedComponent::registered(&format!("{identity_name}.tombstone"))?;
        let envelope_bytes = self
            .tombstones
            .read_bounded_file(&component, TOMBSTONE_ENVELOPE_LEN)?;
        let envelope = VaultObjectEnvelopeV1::from_bytes(&envelope_bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if envelope.as_bytes().len() != TOMBSTONE_ENVELOPE_LEN {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        let header = envelope.as_bytes();
        let metadata = TombstoneRecordMetadataV1::new(
            u64::from_le_bytes(
                header[78..86]
                    .try_into()
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            ),
            header[86..118]
                .try_into()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            header[118..150]
                .try_into()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            crate::PurposeV1::try_from(header[150])
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            u64::from_le_bytes(
                header[152..160]
                    .try_into()
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            ),
            header[160..192]
                .try_into()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
        )
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let opened = open_tombstone_v1(
            &envelope,
            self.storage_ids()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            &self.master_key,
            metadata,
        )
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let tombstone = TombstoneV1::from_bytes(opened.as_bytes())
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let structural = crate::UnauthenticatedTombstoneV1::parse_structural(tombstone.as_bytes())
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if canonical_tombstone_filename(&structural) != component.as_str() {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        Ok(tombstone)
    }

    fn open_authenticated_tombstone_component(
        &self,
        component: &ValidatedComponent,
        tombstone: &TombstoneV1,
    ) -> Result<(), LinuxCapabilityError> {
        let envelope_bytes = self
            .tombstones
            .read_bounded_file(component, TOMBSTONE_ENVELOPE_LEN)?;
        let envelope = VaultObjectEnvelopeV1::from_bytes(&envelope_bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let plaintext = TombstonePlaintextV1::from_bytes(tombstone.as_bytes())
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let metadata = TombstoneRecordMetadataV1::from_tombstone(&plaintext)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let opened = open_tombstone_v1(
            &envelope,
            self.storage_ids()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            &self.master_key,
            metadata,
        )
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if opened.as_bytes() != tombstone.as_bytes() {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        Ok(())
    }

    fn persist_sealed_tombstone(
        &self,
        tombstone: &TombstoneV1,
        envelope: &VaultObjectEnvelopeV1,
    ) -> Result<(), InventoryError> {
        if envelope.as_bytes().len() != TOMBSTONE_ENVELOPE_LEN {
            return Err(InventoryError::Crypto);
        }
        let structural = crate::UnauthenticatedTombstoneV1::parse_structural(tombstone.as_bytes())?;
        let staging_component =
            ValidatedComponent::registered(&canonical_tombstone_staging_filename(&structural))?;
        let final_component =
            ValidatedComponent::registered(&canonical_tombstone_filename(&structural))?;
        let retained_staging = self
            .tombstones
            .create_immutable_file(&staging_component, envelope.as_bytes())?;
        self.open_authenticated_tombstone_component(&staging_component, tombstone)?;
        self.tombstones.rename_no_replace(
            &staging_component,
            &final_component,
            &retained_staging,
        )?;
        self.open_authenticated_tombstone_component(&final_component, tombstone)?;
        Ok(())
    }

    fn audit_tombstones(&self) -> Result<u64, InventoryError> {
        let mut count = 0_u64;
        self.tombstones.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile || !name.ends_with(".tombstone") {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let identity_name = name
                .strip_suffix(".tombstone")
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            let tombstone = self.read_authenticated_tombstone(identity_name)?;
            let structural =
                crate::UnauthenticatedTombstoneV1::parse_structural(tombstone.as_bytes())
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if canonical_tombstone_filename(&structural) != name {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            count = count
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            Ok(())
        })?;
        Ok(count)
    }

    fn snapshot_reservation(
        &self,
        handle: &ReservationHandleV1,
    ) -> Result<ReservationSnapshotV1, InventoryError> {
        self.snapshot_reservation_inner(handle, || Ok(()))
    }

    /// Persists the first canonical reservation with P1-004 journal-first
    /// ordering. The Store rechecks every cross-record relation immediately
    /// before the first durable operation and publishes a handle only after
    /// the active-generation pointer names the complete projection set.
    fn persist_reservation(
        &mut self,
        claim: &SessionClaimV1,
        charge: &BudgetChargeV1,
    ) -> Result<ReservationHandleV1, InventoryError> {
        let before = self.snapshot()?;
        if before.counts.reservation_authorities != before.counts.session_claims
            || before.counts.reservation_authorities != before.counts.budget_charges
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let authority = charge.reservation_authority();
        let identity = authority.nonce_identity()?;
        if claim.identity().as_bytes() != identity.as_bytes()
            || authority.nonce_epoch() != self.core.nonce_epoch()
        {
            return Err(InventoryError::Canonical);
        }

        let lifetime_authority = self.audit_current_generation_journal()?;
        lifetime_authority
            .composite
            .lifetime_index()
            .require_fresh_reservation(claim, charge)?;
        self.require_fresh_reservation_absence(authority)?;
        let predecessor = self.load_journal_head()?;
        let expected_sequence = match predecessor.as_ref() {
            Some(entry) => entry
                .sequence()
                .checked_add(1)
                .ok_or(InventoryError::Canonical)?,
            None => 1,
        };
        if charge.reserve_journal_sequence() != expected_sequence {
            return Err(InventoryError::Canonical);
        }

        let payload = JournalPayloadV1::reserve(claim, charge)?;
        let entry = match predecessor.as_ref() {
            Some(previous) => JournalEntryV1::append(previous, payload)?,
            None => JournalEntryV1::first(payload)?,
        };
        let generation = self.generation.retained_alias()?;
        ensure_optional_namespace(
            &generation,
            &mut self.authorities,
            "reservation-authorities",
        )?;
        ensure_optional_namespace(&generation, &mut self.claims, "session-claims")?;
        ensure_optional_namespace(&generation, &mut self.charges, "budget-charges")?;
        retain_authority_namespace_alias(
            &self.authorities,
            &self.authority.reservation_authorities,
        )?;
        retain_authority_namespace_alias(&self.claims, &self.authority.session_claims)?;
        retain_authority_namespace_alias(&self.charges, &self.authority.budget_charges)?;
        let envelope = UnauthenticatedJournalEnvelopeV1::parse_outer(entry.as_bytes())?;
        self.journal.create_immutable_file(
            &ValidatedComponent::registered(&canonical_journal_filename(&envelope))?,
            entry.as_bytes(),
        )?;
        self.authorities()?.create_immutable_file(
            &ValidatedComponent::registered(&format!(
                "{}.authority",
                hex_lower(authority.reservation_id())
            ))?,
            authority.as_bytes(),
        )?;
        self.claims()?.create_immutable_file(
            &ValidatedComponent::registered(&format!(
                "{}.claim",
                hex_lower(claim.identity().session_id())
            ))?,
            claim.as_bytes(),
        )?;
        self.charges()?.create_immutable_file(
            &ValidatedComponent::registered(&format!(
                "{:020}-{}.charge",
                charge.reserve_journal_sequence(),
                hex_lower(authority.reservation_id())
            ))?,
            charge.as_bytes(),
        )?;

        self.activate_journal_head(&entry)?;

        let after = self.snapshot()?;
        if after.journal_sequence != expected_sequence
            || after.counts.reservation_authorities != before.counts.reservation_authorities + 1
            || after.counts.session_claims != before.counts.session_claims + 1
            || after.counts.budget_charges != before.counts.budget_charges + 1
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let mut reservation_id = [0_u8; 32];
        reservation_id.copy_from_slice(authority.reservation_id());
        Ok(ReservationHandleV1 {
            open_instance_id: self.open_instance_id,
            reservation_id,
            authority_digest: *authority.authority_digest(),
        })
    }

    fn load_journal_head(&self) -> Result<Option<JournalEntryV1>, InventoryError> {
        Ok(self.audit_current_generation_journal()?.head)
    }

    fn next_journal_entry(
        &self,
        payload: JournalPayloadV1,
    ) -> Result<JournalEntryV1, InventoryError> {
        match self.load_journal_head()?.as_ref() {
            Some(predecessor) => Ok(JournalEntryV1::append(predecessor, payload)?),
            None => Ok(JournalEntryV1::first(payload)?),
        }
    }

    fn persist_journal_entry(&self, entry: &JournalEntryV1) -> Result<(), InventoryError> {
        let envelope = UnauthenticatedJournalEnvelopeV1::parse_outer(entry.as_bytes())?;
        self.journal.create_immutable_file(
            &ValidatedComponent::registered(&canonical_journal_filename(&envelope))?,
            entry.as_bytes(),
        )?;
        Ok(())
    }

    fn activate_journal_head(&mut self, entry: &JournalEntryV1) -> Result<(), InventoryError> {
        let next_active =
            ActiveVaultGenerationV1::new(&self.core, entry.sequence(), *entry.entry_digest())?;
        let staging = ValidatedComponent::registered(".active-vault-generation.staging")?;
        let retained = self
            .root
            .create_immutable_file(&staging, next_active.as_bytes())?;
        self.root.replace_active_pointer(
            &staging,
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            &retained,
        )?;
        // P1-004 §11 requires a post-rename reopen and byte-for-byte
        // verification against the complete journal before the in-process
        // authority is advanced.  Never let the in-memory record outrun the
        // authenticated replacement on disk.
        let reopened = ActiveVaultGenerationV1::from_bytes_with_core(
            &self.root.read_bounded_file(
                &ValidatedComponent::registered(ACTIVE_GENERATION)?,
                ACTIVE_VAULT_GENERATION_LEN,
            )?,
            &self.core,
        )?;
        if reopened.as_bytes() != next_active.as_bytes()
            || reopened.journal_sequence() != entry.sequence()
            || reopened.journal_head_digest() != entry.entry_digest()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        self.replace_active_record(reopened)?;
        Ok(())
    }

    fn revalidate_reservation_handle(
        &self,
        handle: &ReservationHandleV1,
    ) -> Result<ReservationAuthorityV1, InventoryError> {
        let _snapshot = self.snapshot()?;
        if handle.open_instance_id != self.open_instance_id {
            return Err(InventoryError::RestoreQuarantined);
        }
        let authority = self.read_authority(&handle.reservation_id)?;
        if authority.authority_digest() != &handle.authority_digest {
            return Err(InventoryError::RestoreQuarantined);
        }
        self.require_reservation_projections(&authority)?;
        Ok(authority)
    }

    /// Durably records the final nonce-derivation attempt before secret
    /// sealing or public computation.
    fn persist_nonce_derivation_attempt(
        &mut self,
        handle: &ReservationHandleV1,
        attempt: &NonceDerivationAttemptV1,
    ) -> Result<(), InventoryError> {
        self.persist_attempt_for_handle(
            handle,
            attempt.attempt(),
            attempt.as_bytes(),
            JournalPayloadV1::nonce_derivation_attempt(attempt),
        )
    }

    /// Seals and durably creates the one canonical nonce-secret object bound
    /// to an already durable derivation attempt.
    fn seal_nonce_secret_for_reservation(
        &mut self,
        handle: &ReservationHandleV1,
        derivation: &NonceDerivationAttemptV1,
        secret: NonceSecretTransferV1,
        seal_capability: VaultSecretSealCapabilityV1,
    ) -> Result<SealedSecretOpenPermitV1, InventoryError> {
        let authority = self.revalidate_reservation_handle(handle)?;
        let identity = authority.nonce_identity()?;
        let identity_name = hex_lower(identity.as_bytes());
        let durable = read_nonce_derivation_attempt(self.attempts()?, &identity_name)?;
        if durable.as_bytes() != derivation.as_bytes()
            || contains_component(&self.tombstones, &format!("{identity_name}.tombstone"))?
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let generation = self.generation.retained_alias()?;
        ensure_optional_namespace(&generation, &mut self.nonce_secrets, "nonce-secrets")?;
        retain_authority_namespace_alias(&self.nonce_secrets, &self.authority.nonce_secrets)?;
        let component = ValidatedComponent::registered(&format!("{identity_name}.secret"))?;
        if contains_component(self.nonce_secrets()?, component.as_str())? {
            return Err(InventoryError::RestoreQuarantined);
        }
        let metadata = self.nonce_secret_metadata(&authority, derivation)?;
        let envelope = seal_nonce_secret_record(
            self.storage_ids()?,
            &self.master_key,
            metadata,
            secret,
            seal_capability,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let before = self.snapshot()?;
        let mut retained = self
            .nonce_secrets()?
            .create_immutable_file(&component, envelope.as_bytes())?;
        let reopened_bytes = retained.read_bounded(NONCE_SECRET_ENVELOPE_MAX_LEN)?;
        self.nonce_secrets()?
            .require_named_file_identity(&component, &retained)?;
        let reopened = VaultObjectEnvelopeV1::from_bytes(&reopened_bytes)
            .map_err(|_| InventoryError::Crypto)?;
        if reopened.as_bytes() != envelope.as_bytes() || reopened.digest() != envelope.digest() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let after = self.snapshot()?;
        if after.counts.nonce_secrets != before.counts.nonce_secrets + 1 {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(SealedSecretOpenPermitV1 {
            open_instance_id: self.open_instance_id,
            reservation_id: handle.reservation_id,
            attempt_digest: *derivation.attempt().attempt_digest(),
            complete_envelope_digest: envelope.digest(),
        })
    }

    /// Authenticates and opens the newly sealed secret exactly once for the
    /// commitment computation.
    fn open_newly_sealed_secret(
        &self,
        handle: &ReservationHandleV1,
        permit: SealedSecretOpenPermitV1,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<NonceSecretTransferV1, InventoryError> {
        let authority = self.revalidate_reservation_handle(handle)?;
        let identity = authority.nonce_identity()?;
        let identity_name = hex_lower(identity.as_bytes());
        let derivation = read_nonce_derivation_attempt(self.attempts()?, &identity_name)?;
        if permit.open_instance_id != self.open_instance_id
            || permit.reservation_id != handle.reservation_id
            || permit.attempt_digest != *derivation.attempt().attempt_digest()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let (transfer, retained) =
            self.open_authenticated_nonce_secret(&authority, &derivation, import_capability)?;
        if retained.complete_envelope_digest != permit.complete_envelope_digest {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(transfer)
    }

    /// Opens the exact secret for a durable partial attempt and retains the
    /// authenticated file identity for the subsequent terminal transaction.
    fn open_secret_for_stage_attempt(
        &self,
        handle: &ReservationHandleV1,
        partial_attempt: &AttemptRecordV1,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<(NonceSecretTransferV1, AuthenticatedSecretForDeletionV1), InventoryError> {
        if partial_attempt.artifact() == ArtifactKindV1::Commitment {
            return Err(InventoryError::Canonical);
        }
        let authority = self.revalidate_reservation_handle(handle)?;
        let identity = authority.nonce_identity()?;
        let identity_name = hex_lower(identity.as_bytes());
        let durable_attempt = read_attempt_for_artifact(
            self.attempts()?,
            &identity_name,
            partial_attempt.artifact(),
        )?;
        if durable_attempt.as_bytes() != partial_attempt.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let derivation = read_nonce_derivation_attempt(self.attempts()?, &identity_name)?;
        self.open_authenticated_nonce_secret(&authority, &derivation, import_capability)
    }

    fn open_authenticated_nonce_secret(
        &self,
        authority: &ReservationAuthorityV1,
        derivation: &NonceDerivationAttemptV1,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<(NonceSecretTransferV1, AuthenticatedSecretForDeletionV1), InventoryError> {
        let identity = authority.nonce_identity()?;
        let component =
            ValidatedComponent::registered(&format!("{}.secret", hex_lower(identity.as_bytes())))?;
        let mut retained_file = self.nonce_secrets()?.open_file(&component, false)?;
        let envelope_bytes = retained_file.read_bounded(NONCE_SECRET_ENVELOPE_MAX_LEN)?;
        self.nonce_secrets()?
            .require_named_file_identity(&component, &retained_file)?;
        let envelope = VaultObjectEnvelopeV1::from_bytes(&envelope_bytes)
            .map_err(|_| InventoryError::Crypto)?;
        let complete_envelope_digest = envelope.digest();
        let transfer = open_nonce_secret_record(
            &envelope,
            self.storage_ids()?,
            &self.master_key,
            self.nonce_secret_metadata(authority, derivation)?,
            import_capability,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let mut reservation_id = [0_u8; 32];
        reservation_id.copy_from_slice(authority.reservation_id());
        Ok((
            transfer,
            AuthenticatedSecretForDeletionV1 {
                open_instance_id: self.open_instance_id,
                reservation_id,
                nonce_identity: identity,
                component,
                retained_file,
                complete_envelope_digest,
            },
        ))
    }

    /// Authenticates an active secret for an irreversible terminal transition
    /// without producing plaintext or an adaptor import capability.
    fn authenticate_active_secret_for_terminal(
        &self,
        authority: &ReservationAuthorityV1,
        derivation: &NonceDerivationAttemptV1,
    ) -> Result<(ActiveSecretEvidenceV1, AuthenticatedSecretForDeletionV1), InventoryError> {
        let identity = authority.nonce_identity()?;
        let component =
            ValidatedComponent::registered(&format!("{}.secret", hex_lower(identity.as_bytes())))?;
        let mut retained_file = self.nonce_secrets()?.open_file(&component, false)?;
        let envelope_bytes = retained_file.read_bounded(NONCE_SECRET_ENVELOPE_MAX_LEN)?;
        self.nonce_secrets()?
            .require_named_file_identity(&component, &retained_file)?;
        let envelope = VaultObjectEnvelopeV1::from_bytes(&envelope_bytes)
            .map_err(|_| InventoryError::Crypto)?;
        let complete_envelope_digest = envelope.digest();
        audit_nonce_secret_record(
            &envelope,
            self.storage_ids()?,
            &self.master_key,
            self.nonce_secret_metadata(authority, derivation)?,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let object_header_revision = derivation
            .attempt()
            .expected_lifecycle_revision()
            .checked_add(1)
            .ok_or(InventoryError::Canonical)?;
        let evidence = ActiveSecretEvidenceV1::new(
            identity,
            object_header_revision,
            complete_envelope_digest,
        )?;
        let mut reservation_id = [0_u8; 32];
        reservation_id.copy_from_slice(authority.reservation_id());
        Ok((
            evidence,
            AuthenticatedSecretForDeletionV1 {
                open_instance_id: self.open_instance_id,
                reservation_id,
                nonce_identity: identity,
                component,
                retained_file,
                complete_envelope_digest,
            },
        ))
    }

    /// Durably records a reveal or partial computation attempt before opening
    /// the sealed secret record.
    fn persist_stage_attempt(
        &mut self,
        handle: &ReservationHandleV1,
        attempt: &AttemptRecordV1,
    ) -> Result<(), InventoryError> {
        if attempt.artifact() == ArtifactKindV1::Commitment {
            return Err(InventoryError::Canonical);
        }
        self.persist_attempt_for_handle(
            handle,
            attempt,
            attempt.as_bytes(),
            JournalPayloadV1::computation_attempt(attempt)?,
        )
    }

    fn persist_attempt_for_handle(
        &mut self,
        handle: &ReservationHandleV1,
        attempt: &AttemptRecordV1,
        projection_bytes: &[u8],
        payload: JournalPayloadV1,
    ) -> Result<(), InventoryError> {
        let authority = self.revalidate_reservation_handle(handle)?;
        if authority.nonce_identity()?.as_bytes() != attempt.identity().as_bytes() {
            return Err(InventoryError::Canonical);
        }
        let preceding = self.preceding_spent_for(attempt.identity(), attempt.artifact())?;
        match (attempt.artifact(), preceding.as_ref()) {
            (ArtifactKindV1::Commitment, None) if attempt.expected_lifecycle_revision() == 1 => {}
            (ArtifactKindV1::Commitment, _) | (_, None) => {
                return Err(InventoryError::Canonical);
            }
            (_, Some(spent))
                if spent.lifecycle_revision() == attempt.expected_lifecycle_revision() => {}
            _ => return Err(InventoryError::Canonical),
        }
        let generation = self.generation.retained_alias()?;
        ensure_optional_namespace(&generation, &mut self.attempts, "attempts")?;
        retain_authority_namespace_alias(&self.attempts, &self.authority.attempts)?;
        let attempt_path = if projection_bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
            let derivation = NonceDerivationAttemptV1::from_bytes(projection_bytes)?;
            canonical_attempt_relative_path(&UnauthenticatedAttemptRecordV1::parse_structural(
                derivation.attempt().as_bytes(),
            )?)
        } else {
            canonical_attempt_relative_path(&UnauthenticatedAttemptRecordV1::parse_structural(
                projection_bytes,
            )?)
        };
        let (identity_component, file_component) = attempt_path
            .split_once('/')
            .ok_or(InventoryError::Canonical)?;
        if contains_component(self.attempts()?, identity_component)? {
            let identity_directory = self
                .attempts()?
                .open_child_directory(ValidatedComponent::registered(identity_component)?)?;
            if contains_component(&identity_directory, file_component)? {
                return Err(InventoryError::RestoreQuarantined);
            }
        }

        let before = self.snapshot()?;
        let entry = self.next_journal_entry(payload)?;
        self.persist_journal_entry(&entry)?;
        // Journal-first ordering ensures a crash cannot make the projection
        // authoritative without its predecessor-linked durable intent. Any
        // incomplete prefix remains unreferenced by the active pointer and is
        // quarantined on reopen.
        persist_attempt_projection(self.attempts()?, projection_bytes)?;
        self.activate_journal_head(&entry)?;
        #[cfg(test)]
        test_normal_vault_crash_hook("attempt-after-durable-commit-before-return");
        let after = self.snapshot()?;
        if after.journal_sequence != before.journal_sequence + 1
            || after.counts.attempts != before.counts.attempts + 1
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(())
    }

    /// Persists exact computed commitment or reveal bytes before any
    /// authorization can be created.
    ///
    /// Partial-signature persistence is intentionally rejected here: its
    /// canonical transition must atomically include the authenticated sealed
    /// tombstone envelope and is handled only by the dedicated consumed-partial
    /// path.
    fn persist_computed_public_artifact(
        &mut self,
        handle: &ReservationHandleV1,
        attempt: &AttemptRecordV1,
        outbound_bytes: &[u8],
    ) -> Result<PersistedExposureHandleV1, InventoryError> {
        if attempt.artifact() == ArtifactKindV1::PartialSignature {
            return Err(InventoryError::Canonical);
        }
        let authority = self.revalidate_reservation_handle(handle)?;
        if authority.nonce_identity()?.as_bytes() != attempt.identity().as_bytes() {
            return Err(InventoryError::Canonical);
        }
        let durable_attempt = read_attempt_for_artifact(
            self.attempts()?,
            &hex_lower(attempt.identity().as_bytes()),
            attempt.artifact(),
        )?;
        if durable_attempt.as_bytes() != attempt.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        if self.exposure_occurs(attempt.identity(), attempt.artifact(), None)? {
            return Err(InventoryError::RestoreQuarantined);
        }
        let preceding = self.preceding_spent_for(attempt.identity(), attempt.artifact())?;
        let persisted =
            ExposureRecordV1::new_persisted(attempt, preceding.as_ref(), outbound_bytes)?;
        let payload = JournalPayloadV1::persisted(attempt, preceding.as_ref(), &persisted)?;
        let generation = self.generation.retained_alias()?;
        ensure_optional_namespace(&generation, &mut self.exposures, "exposures")?;
        retain_authority_namespace_alias(&self.exposures, &self.authority.exposures)?;
        let before = self.snapshot()?;
        let entry = self.next_journal_entry(payload)?;
        self.persist_journal_entry(&entry)?;
        persist_exposure_projection(self.exposures()?, &persisted)?;
        self.activate_journal_head(&entry)?;
        #[cfg(test)]
        test_normal_vault_crash_hook("persisted-after-durable-commit-before-return");
        let after = self.snapshot()?;
        if after.journal_sequence != before.journal_sequence + 1
            || after.counts.exposures != before.counts.exposures + 1
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(PersistedExposureHandleV1 {
            authority: Arc::clone(&self.authority),
            issuance: self.capability_issuance(&after),
            reservation_id: handle.reservation_id,
            nonce_identity: *persisted.identity(),
            attempt_digest: *attempt.attempt_digest(),
            operation_input_digest: *attempt.operation_input_digest(),
            phase: attempt.phase(),
            artifact: persisted.artifact(),
            exposure_sequence: persisted.sequence(),
            expected_lifecycle_revision: attempt.expected_lifecycle_revision(),
            persisted_lifecycle_revision: persisted.lifecycle_revision(),
            exposure_version: persisted.version_id(),
            exposure_record_digest: *persisted.record_digest(),
            outbound_digest: *persisted.outbound_digest(),
            outbound_length: persisted.outbound_bytes().len(),
            persistence_journal_digest: *entry.entry_digest(),
            consumed_tombstone_digest: None,
            deleted_secret_envelope_digest: None,
        })
    }

    /// Persists the terminal partial and its already-selected consumed
    /// tombstone as one canonical journal event. The deleted secret-envelope
    /// digest must come from the retained secret deletion operation; no raw
    /// secret or caller-provided nonce crosses this boundary.
    fn persist_consumed_partial(
        &mut self,
        handle: &ReservationHandleV1,
        attempt: &AttemptRecordV1,
        outbound_bytes: &[u8],
        mut secret_for_deletion: AuthenticatedSecretForDeletionV1,
    ) -> Result<PersistedExposureHandleV1, InventoryError> {
        if attempt.artifact() != ArtifactKindV1::PartialSignature {
            return Err(InventoryError::Canonical);
        }
        let authority = self.revalidate_reservation_handle(handle)?;
        let identity = authority.nonce_identity()?;
        if identity.as_bytes() != attempt.identity().as_bytes()
            || secret_for_deletion.open_instance_id != self.open_instance_id
            || secret_for_deletion.reservation_id != handle.reservation_id
            || secret_for_deletion.nonce_identity.as_bytes() != identity.as_bytes()
            || self.exposure_occurs(&identity, ArtifactKindV1::PartialSignature, None)?
        {
            return Err(InventoryError::Canonical);
        }
        let current_secret_bytes = secret_for_deletion
            .retained_file
            .read_bounded(NONCE_SECRET_ENVELOPE_MAX_LEN)?;
        self.nonce_secrets()?.require_named_file_identity(
            &secret_for_deletion.component,
            &secret_for_deletion.retained_file,
        )?;
        let current_secret = VaultObjectEnvelopeV1::from_bytes(&current_secret_bytes)
            .map_err(|_| InventoryError::Crypto)?;
        if current_secret.digest() != secret_for_deletion.complete_envelope_digest {
            return Err(InventoryError::RestoreQuarantined);
        }
        let durable_attempt = read_attempt_for_artifact(
            self.attempts()?,
            &hex_lower(identity.as_bytes()),
            ArtifactKindV1::PartialSignature,
        )?;
        if durable_attempt.as_bytes() != attempt.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let preceding_reveal = self
            .preceding_spent_for(&identity, ArtifactKindV1::PartialSignature)?
            .ok_or(InventoryError::RestoreQuarantined)?;
        let persisted =
            ExposureRecordV1::new_persisted(attempt, Some(&preceding_reveal), outbound_bytes)?;
        let tombstone = TombstoneV1::new_consumed(
            attempt,
            &persisted,
            secret_for_deletion.complete_envelope_digest,
        )?;
        let tombstone_plaintext = TombstonePlaintextV1::from_bytes(tombstone.as_bytes())
            .map_err(|_| InventoryError::Crypto)?;
        let tombstone_metadata = TombstoneRecordMetadataV1::from_tombstone(&tombstone_plaintext)
            .map_err(|_| InventoryError::Crypto)?;
        let tombstone_envelope = seal_tombstone_v1(
            self.storage_ids()?,
            &self.master_key,
            tombstone_metadata,
            tombstone_plaintext,
        )
        .map_err(|_| InventoryError::Crypto)?;
        let payload =
            JournalPayloadV1::partial_consumed(attempt, &preceding_reveal, &persisted, &tombstone)?;
        let before = self.snapshot()?;
        let entry = self.next_journal_entry(payload)?;
        #[cfg(test)]
        test_normal_vault_crash_hook("partial-before-exposure-projection");
        persist_exposure_projection(self.exposures()?, &persisted)?;
        #[cfg(test)]
        test_normal_vault_crash_hook("partial-after-exposure-before-tombstone");
        self.persist_sealed_tombstone(&tombstone, &tombstone_envelope)?;
        #[cfg(test)]
        test_normal_vault_crash_hook("partial-after-tombstone-before-journal");
        self.persist_journal_entry(&entry)?;
        let terminal_journal = self.audit_current_generation_journal()?;
        if terminal_journal.sequence != entry.sequence()
            || terminal_journal.head_digest != *entry.entry_digest()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        #[cfg(test)]
        test_normal_vault_crash_hook("partial-after-journal-before-secret-unlink");
        self.nonce_secrets()?.unlink_verified_file(
            &secret_for_deletion.component,
            &secret_for_deletion.retained_file,
        )?;
        if contains_component(
            self.nonce_secrets()?,
            secret_for_deletion.component.as_str(),
        )? {
            return Err(InventoryError::RestoreQuarantined);
        }
        #[cfg(test)]
        test_normal_vault_crash_hook("partial-after-secret-unlink-before-active-head");
        self.activate_journal_head(&entry)?;
        #[cfg(test)]
        test_normal_vault_crash_hook("partial-after-terminal-commit-before-return");
        let after = self.snapshot()?;
        if after.journal_sequence != before.journal_sequence + 1
            || after.counts.exposures != before.counts.exposures + 1
            || after.counts.tombstones != before.counts.tombstones + 1
            || after.counts.nonce_secrets + 1 != before.counts.nonce_secrets
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(PersistedExposureHandleV1 {
            authority: Arc::clone(&self.authority),
            issuance: self.capability_issuance(&after),
            reservation_id: handle.reservation_id,
            nonce_identity: *persisted.identity(),
            attempt_digest: *attempt.attempt_digest(),
            operation_input_digest: *attempt.operation_input_digest(),
            phase: attempt.phase(),
            artifact: persisted.artifact(),
            exposure_sequence: persisted.sequence(),
            expected_lifecycle_revision: attempt.expected_lifecycle_revision(),
            persisted_lifecycle_revision: persisted.lifecycle_revision(),
            exposure_version: persisted.version_id(),
            exposure_record_digest: *persisted.record_digest(),
            outbound_digest: *persisted.outbound_digest(),
            outbound_length: persisted.outbound_bytes().len(),
            persistence_journal_digest: *entry.entry_digest(),
            consumed_tombstone_digest: Some(*tombstone.tombstone_digest()),
            deleted_secret_envelope_digest: Some(*tombstone.deleted_secret_envelope_digest()),
        })
    }

    /// Persists an authenticated abort or conservative burn as one
    /// irreversible terminal transaction selected entirely from retained
    /// Store evidence.
    fn persist_terminal_reservation(
        &mut self,
        handle: &ReservationHandleV1,
        burn: bool,
    ) -> Result<ReservationState, InventoryError> {
        let authority = self.revalidate_reservation_handle(handle)?;
        let identity = authority.nonce_identity()?;
        let identity_name = hex_lower(identity.as_bytes());
        if contains_component(&self.tombstones, &format!("{identity_name}.tombstone"))? {
            return Err(InventoryError::RestoreQuarantined);
        }

        let claim_component = ValidatedComponent::registered(&format!(
            "{}.claim",
            hex_lower(authority.session_id())
        ))?;
        let claim = SessionClaimV1::from_bytes(
            &self
                .claims()?
                .read_bounded_file(&claim_component, SESSION_CLAIM_LEN)?,
        )?;
        if claim.identity().as_bytes() != identity.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }

        let mut attempts = Vec::new();
        if let Some(attempt_directory) = self.attempts.as_ref() {
            if contains_component(attempt_directory, &identity_name)? {
                let identity_directory = attempt_directory
                    .open_child_directory(ValidatedComponent::registered(&identity_name)?)?;
                identity_directory.scan_lexicographic(|name, node| {
                    if node.node_type != ExpectedNodeType::RegularFile {
                        return Err(LinuxCapabilityError::InvalidObject);
                    }
                    let bytes = identity_directory.read_bounded_file(
                        &ValidatedComponent::registered(name)?,
                        NONCE_DERIVATION_ATTEMPT_LEN,
                    )?;
                    let attempt = if bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
                        NonceDerivationAttemptV1::from_bytes(&bytes)
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                            .attempt()
                            .clone()
                    } else {
                        AttemptRecordV1::from_bytes(&bytes)
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    };
                    attempts.push(attempt);
                    Ok(())
                })?;
            }
        }
        let mut exposures = Vec::new();
        if let Some(exposure_directory) = self.exposures.as_ref() {
            scan_exposure_records(exposure_directory, |exposure| {
                if exposure.identity().as_bytes() == identity.as_bytes() {
                    exposures.push(exposure.clone());
                }
                Ok(())
            })?;
        }

        let secret_component = format!("{identity_name}.secret");
        let active_secret = match self.nonce_secrets.as_ref() {
            Some(directory) if contains_component(directory, &secret_component)? => {
                let derivation = read_nonce_derivation_attempt(self.attempts()?, &identity_name)?;
                Some(self.authenticate_active_secret_for_terminal(&authority, &derivation)?)
            }
            _ => None,
        };
        let attempt_refs: Vec<&AttemptRecordV1> = attempts.iter().collect();
        let exposure_refs: Vec<&ExposureRecordV1> = exposures.iter().collect();
        let evidence = TerminalEvidenceV1::select(
            &claim,
            &attempt_refs,
            &exposure_refs,
            active_secret.as_ref().map(|(selected, _)| selected),
        )?;
        let tombstone = if burn {
            TombstoneV1::new_burn(&evidence)?
        } else {
            TombstoneV1::new_abort(&evidence)?
        };
        tombstone.validate_terminal_evidence(&evidence)?;
        let plaintext = TombstonePlaintextV1::from_bytes(tombstone.as_bytes())
            .map_err(|_| InventoryError::Crypto)?;
        let metadata = TombstoneRecordMetadataV1::from_tombstone(&plaintext)
            .map_err(|_| InventoryError::Crypto)?;
        let envelope =
            seal_tombstone_v1(self.storage_ids()?, &self.master_key, metadata, plaintext)
                .map_err(|_| InventoryError::Crypto)?;
        let payload = if burn {
            JournalPayloadV1::burned(&tombstone)?
        } else {
            JournalPayloadV1::abort_consumed(&tombstone)?
        };
        let before = self.snapshot()?;
        let entry = self.next_journal_entry(payload)?;
        self.persist_sealed_tombstone(&tombstone, &envelope)?;
        self.persist_journal_entry(&entry)?;
        let terminal_journal = self.audit_current_generation_journal()?;
        if terminal_journal.sequence != entry.sequence()
            || terminal_journal.head_digest != *entry.entry_digest()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let had_active_secret = active_secret.is_some();
        if let Some((_, mut retained)) = active_secret {
            let current = retained
                .retained_file
                .read_bounded(NONCE_SECRET_ENVELOPE_MAX_LEN)?;
            self.nonce_secrets()?
                .require_named_file_identity(&retained.component, &retained.retained_file)?;
            let current =
                VaultObjectEnvelopeV1::from_bytes(&current).map_err(|_| InventoryError::Crypto)?;
            if current.digest() != retained.complete_envelope_digest {
                return Err(InventoryError::RestoreQuarantined);
            }
            self.nonce_secrets()?
                .unlink_verified_file(&retained.component, &retained.retained_file)?;
            if contains_component(self.nonce_secrets()?, retained.component.as_str())? {
                return Err(InventoryError::RestoreQuarantined);
            }
        }
        self.activate_journal_head(&entry)?;
        let after = self.snapshot()?;
        let secret_delta = u64::from(had_active_secret);
        if after.journal_sequence != before.journal_sequence + 1
            || after.counts.tombstones != before.counts.tombstones + 1
            || before.counts.nonce_secrets != after.counts.nonce_secrets + secret_delta
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let public_may_have_existed = exposures.iter().any(|exposure| {
            matches!(
                exposure.state(),
                ExposureStateV1::Authorized | ExposureStateV1::Spent
            )
        });
        Ok(if burn {
            ReservationState::Burned
        } else if public_may_have_existed {
            ReservationState::ConsumedOnAbort
        } else {
            ReservationState::AbortedBeforePublicMaterial
        })
    }

    /// Advances one exact persisted artifact through `Authorized` to `Spent`
    /// before returning a non-fabricable, process-local one-shot permit.
    fn authorize_persisted_public_exposure(
        &mut self,
        reservation: &ReservationHandleV1,
        persisted_handle: PersistedExposureHandleV1,
    ) -> Result<ExposurePermitV1, InventoryError> {
        let authority = self.revalidate_reservation_handle(reservation)?;
        let issuance_journal = self.revalidate_capability_issuance(
            &persisted_handle.authority,
            &persisted_handle.issuance,
        )?;
        if persisted_handle.reservation_id != reservation.reservation_id {
            return Err(InventoryError::RestoreQuarantined);
        }
        let identity = authority.nonce_identity()?;
        let attempt = read_attempt_for_artifact(
            self.attempts()?,
            &hex_lower(identity.as_bytes()),
            persisted_handle.artifact,
        )?;
        let persisted = self.find_exposure_by_digest(
            &identity,
            ExposureStateV1::Persisted,
            &persisted_handle.exposure_record_digest,
        )?;
        let expected_payload = if persisted.artifact() == ArtifactKindV1::PartialSignature {
            let preceding = self
                .preceding_spent_for(&identity, ArtifactKindV1::PartialSignature)?
                .ok_or(InventoryError::RestoreQuarantined)?;
            let tombstone = self.read_authenticated_tombstone(&hex_lower(identity.as_bytes()))?;
            JournalPayloadV1::partial_consumed(&attempt, &preceding, &persisted, &tombstone)?
        } else {
            JournalPayloadV1::persisted(
                &attempt,
                self.preceding_spent_for(&identity, persisted.artifact())?
                    .as_ref(),
                &persisted,
            )?
        };
        let persisted_entry = issuance_journal
            .entries
            .iter()
            .find(|entry| entry.entry_digest() == &persisted_handle.persistence_journal_digest)
            .ok_or(InventoryError::RestoreQuarantined)?;
        let complete_binding_matches = persisted_handle.nonce_identity.as_bytes()
            == identity.as_bytes()
            && persisted_handle.attempt_digest == *attempt.attempt_digest()
            && persisted_handle.operation_input_digest == *attempt.operation_input_digest()
            && persisted_handle.phase == attempt.phase()
            && persisted_handle.artifact == persisted.artifact()
            && persisted_handle.exposure_sequence == persisted.sequence()
            && persisted_handle.expected_lifecycle_revision
                == attempt.expected_lifecycle_revision()
            && persisted_handle.persisted_lifecycle_revision == persisted.lifecycle_revision()
            && persisted_handle.exposure_version.as_bytes() == persisted.version_id().as_bytes()
            && persisted_handle.exposure_record_digest == *persisted.record_digest()
            && persisted_handle.outbound_digest == *persisted.outbound_digest()
            && persisted_handle.outbound_length == persisted.outbound_bytes().len()
            && persisted_entry.payload().as_bytes() == expected_payload.as_bytes();
        if !complete_binding_matches {
            return Err(InventoryError::RestoreQuarantined);
        }
        let identity_name = hex_lower(identity.as_bytes());
        let tombstone = if persisted.artifact() == ArtifactKindV1::PartialSignature {
            Some(
                self.read_authenticated_tombstone(&identity_name)
                    .map_err(InventoryError::from)?,
            )
        } else {
            None
        };
        match (persisted.artifact(), tombstone.as_ref()) {
            (ArtifactKindV1::PartialSignature, Some(tombstone))
                if persisted_handle.consumed_tombstone_digest
                    == Some(*tombstone.tombstone_digest())
                    && persisted_handle.deleted_secret_envelope_digest
                        == Some(*tombstone.deleted_secret_envelope_digest()) => {}
            (ArtifactKindV1::PartialSignature, _) => {
                return Err(InventoryError::RestoreQuarantined);
            }
            (_, None)
                if persisted_handle.consumed_tombstone_digest.is_none()
                    && persisted_handle.deleted_secret_envelope_digest.is_none() => {}
            _ => return Err(InventoryError::RestoreQuarantined),
        }
        if self.exposure_occurs(
            &identity,
            persisted.artifact(),
            Some(ExposureStateV1::Authorized),
        )? || self.exposure_occurs(
            &identity,
            persisted.artifact(),
            Some(ExposureStateV1::Spent),
        )? {
            return Err(InventoryError::RestoreQuarantined);
        }
        let authorized = ExposureRecordV1::new_successor(&persisted, tombstone.as_ref())?;
        let payload =
            JournalPayloadV1::exposure_authorized(&persisted, &authorized, tombstone.as_ref())?;
        let before = self.snapshot()?;
        let entry = self.next_journal_entry(payload)?;
        self.persist_journal_entry(&entry)?;
        persist_exposure_projection(self.exposures()?, &authorized)?;
        self.activate_journal_head(&entry)?;
        #[cfg(test)]
        test_normal_vault_crash_hook("authorized-after-durable-commit-before-permit");
        let after = self.snapshot()?;
        if after.journal_sequence != before.journal_sequence + 1
            || after.counts.exposures != before.counts.exposures + 1
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let spent = ExposureRecordV1::new_successor(&authorized, None)?;
        let spent_payload = JournalPayloadV1::exposure_authorized(&authorized, &spent, None)?;
        let spent_entry = self.next_journal_entry(spent_payload)?;
        self.persist_journal_entry(&spent_entry)?;
        persist_exposure_projection(self.exposures()?, &spent)?;
        self.activate_journal_head(&spent_entry)?;
        #[cfg(test)]
        test_normal_vault_crash_hook("export-after-durable-spent-before-return");
        #[cfg(test)]
        if spent.artifact() == ArtifactKindV1::PartialSignature {
            test_normal_vault_crash_hook("partial-export-after-durable-spent-before-return");
        }
        let spent_snapshot = self.snapshot()?;
        let permit_id = derive_permit_id(&spent, *spent_entry.entry_digest())?;
        Ok(ExposurePermitV1 {
            authority: Arc::clone(&self.authority),
            issuance: self.capability_issuance(&spent_snapshot),
            reservation_id: reservation.reservation_id,
            nonce_identity: identity,
            artifact: spent.artifact(),
            exposure_sequence: spent.sequence(),
            spent_version: spent.version_id(),
            spent_record_digest: *spent.record_digest(),
            outbound_digest: *spent.outbound_digest(),
            outbound_length: spent.outbound_bytes().len(),
            spent_journal_digest: *spent_entry.entry_digest(),
            permit_id,
        })
    }

    /// Consumes a permit already bound to an exact durable `Spent` exposure
    /// and returns only the byte-identical persisted public bytes.
    fn export_public_artifact(
        &mut self,
        permit: ExposurePermitV1,
    ) -> Result<ExportedArtifactV1, InventoryError> {
        let issuance_journal =
            self.revalidate_capability_issuance(&permit.authority, &permit.issuance)?;
        let authority = self.read_authority(&permit.reservation_id)?;
        self.require_reservation_projections(&authority)?;
        let identity = authority.nonce_identity()?;
        let spent = self.find_exposure_by_digest(
            &identity,
            ExposureStateV1::Spent,
            &permit.spent_record_digest,
        )?;
        let spent_entry = issuance_journal
            .entries
            .iter()
            .find(|entry| entry.entry_digest() == &permit.spent_journal_digest)
            .ok_or(InventoryError::RestoreQuarantined)?;
        let authorized =
            self.find_unique_exposure(&identity, spent.artifact(), ExposureStateV1::Authorized)?;
        let expected_spent_payload =
            JournalPayloadV1::exposure_authorized(&authorized, &spent, None)?;
        let expected_permit_id = derive_permit_id(&spent, *spent_entry.entry_digest())?;
        if permit.nonce_identity.as_bytes() != identity.as_bytes()
            || permit.artifact != spent.artifact()
            || permit.exposure_sequence != spent.sequence()
            || permit.spent_version.as_bytes() != spent.version_id().as_bytes()
            || permit.outbound_digest != *spent.outbound_digest()
            || permit.outbound_length != spent.outbound_bytes().len()
            || permit.permit_id != expected_permit_id
            || spent_entry.payload().as_bytes() != expected_spent_payload.as_bytes()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(ExportedArtifactV1 {
            permit_id: permit.permit_id,
            kind: spent.artifact(),
            outbound_bytes: spent.outbound_bytes().to_vec(),
        })
    }

    fn preceding_spent_for(
        &self,
        identity: &NonceIdentityV1,
        artifact: ArtifactKindV1,
    ) -> Result<Option<ExposureRecordV1>, InventoryError> {
        let preceding = match artifact {
            ArtifactKindV1::Commitment => return Ok(None),
            ArtifactKindV1::Reveal => ArtifactKindV1::Commitment,
            ArtifactKindV1::PartialSignature => ArtifactKindV1::Reveal,
        };
        self.find_unique_exposure(identity, preceding, ExposureStateV1::Spent)
            .map(Some)
    }

    fn find_unique_exposure(
        &self,
        identity: &NonceIdentityV1,
        artifact: ArtifactKindV1,
        state: ExposureStateV1,
    ) -> Result<ExposureRecordV1, InventoryError> {
        let mut found: Option<ExposureRecordV1> = None;
        scan_exposure_records(self.exposures()?, |candidate| {
            if candidate.identity().as_bytes() == identity.as_bytes()
                && candidate.artifact() == artifact
                && candidate.state() == state
            {
                if found.is_some() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                found = Some(candidate.clone());
            }
            Ok(())
        })?;
        found.ok_or(InventoryError::RestoreQuarantined)
    }

    fn find_exposure_by_digest(
        &self,
        identity: &NonceIdentityV1,
        state: ExposureStateV1,
        record_digest: &[u8; 32],
    ) -> Result<ExposureRecordV1, InventoryError> {
        let mut found: Option<ExposureRecordV1> = None;
        scan_exposure_records(self.exposures()?, |candidate| {
            if candidate.identity().as_bytes() == identity.as_bytes()
                && candidate.state() == state
                && candidate.record_digest() == record_digest
            {
                if found.is_some() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                found = Some(candidate.clone());
            }
            Ok(())
        })?;
        found.ok_or(InventoryError::RestoreQuarantined)
    }

    fn exposure_occurs(
        &self,
        identity: &NonceIdentityV1,
        artifact: ArtifactKindV1,
        state: Option<ExposureStateV1>,
    ) -> Result<bool, InventoryError> {
        let Some(exposures) = self.exposures.as_ref() else {
            return Ok(false);
        };
        let mut found = false;
        scan_exposure_records(exposures, |candidate| {
            if candidate.identity().as_bytes() == identity.as_bytes()
                && candidate.artifact() == artifact
                && state.map_or(true, |expected| candidate.state() == expected)
            {
                if found {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                found = true;
            }
            Ok(())
        })?;
        Ok(found)
    }

    fn require_fresh_reservation_absence(
        &self,
        proposed: &ReservationAuthorityV1,
    ) -> Result<(), InventoryError> {
        let Some(authorities) = self.authorities.as_ref() else {
            return Ok(());
        };
        authorities.scan_lexicographic(|name, _| {
            let bytes = authorities.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                RESERVATION_AUTHORITY_ADAPTOR_LEN,
            )?;
            let existing = ReservationAuthorityV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if existing.reservation_id() == proposed.reservation_id()
                || existing.session_id() == proposed.session_id()
                || existing.request_lookup_id() == proposed.request_lookup_id()
                || existing.context_binding().as_bytes() == proposed.context_binding().as_bytes()
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            Ok(())
        })?;
        Ok(())
    }

    fn snapshot_reservation_inner<F>(
        &self,
        handle: &ReservationHandleV1,
        interposition: F,
    ) -> Result<ReservationSnapshotV1, InventoryError>
    where
        F: FnOnce() -> Result<(), InventoryError>,
    {
        let before = self.snapshot()?;
        if handle.open_instance_id != self.open_instance_id {
            return Err(InventoryError::RestoreQuarantined);
        }
        let authority = self.read_authority(&handle.reservation_id)?;
        if authority.authority_digest() != &handle.authority_digest {
            return Err(InventoryError::RestoreQuarantined);
        }
        self.require_reservation_projections(&authority)?;
        interposition()?;
        let after = self.snapshot()?;
        if !before.same_authority(&after) {
            return Err(InventoryError::RestoreQuarantined);
        }

        let request_lookup = ReservationRequestLookupV1::from_bytes(
            authority
                .request_lookup_id()
                .try_into()
                .map_err(|_| InventoryError::Canonical)?,
        )
        .map_err(|_| InventoryError::Canonical)?;
        let mut reservation_id = [0_u8; 32];
        reservation_id.copy_from_slice(authority.reservation_id());
        let reservation_nonce_id = ReservationNonceId::from_bytes(reservation_id)
            .map_err(|_| InventoryError::Canonical)?;
        let identity = authority.nonce_identity()?;
        let identity_name = hex_lower(identity.as_bytes());
        let derivation = match self.attempts.as_ref() {
            Some(attempts) if contains_component(attempts, &identity_name)? => {
                Some(read_nonce_derivation_attempt(attempts, &identity_name)?)
            }
            _ => None,
        };
        let spent_commitment =
            self.optional_spent_snapshot(&identity, ArtifactKindV1::Commitment)?;
        let spent_reveal = self.optional_spent_snapshot(&identity, ArtifactKindV1::Reveal)?;
        if self
            .optional_spent_snapshot(&identity, ArtifactKindV1::PartialSignature)?
            .is_some()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let live_stage = match (spent_commitment.is_some(), spent_reveal.is_some()) {
            (false, false) if derivation.is_none() => AdaptorReservationLiveStageV1::PreDerivation,
            (true, false) if derivation.is_some() => AdaptorReservationLiveStageV1::AfterCommitment,
            (true, true) if derivation.is_some() => AdaptorReservationLiveStageV1::AfterReveal,
            _ => return Err(InventoryError::RestoreQuarantined),
        };
        Ok(ReservationSnapshotV1 {
            request_lookup,
            reservation_nonce_id,
            context_binding_digest: *authority.context_binding().context_binding_digest(),
            live_stage,
            final_retry_counter: derivation
                .as_ref()
                .map(NonceDerivationAttemptV1::effective_retry_counter),
            spent_commitment,
            spent_reveal,
        })
    }

    fn optional_spent_snapshot(
        &self,
        identity: &NonceIdentityV1,
        artifact: ArtifactKindV1,
    ) -> Result<Option<SpentArtifactSnapshotV1>, InventoryError> {
        if !self.exposure_occurs(identity, artifact, Some(ExposureStateV1::Spent))? {
            return Ok(None);
        }
        let exposure = self.find_unique_exposure(identity, artifact, ExposureStateV1::Spent)?;
        let authorizing_digest = self.find_spent_authorizing_entry(&exposure)?;
        let authority = self.find_authority_for_identity(identity)?;
        Ok(Some(SpentArtifactSnapshotV1 {
            nonce_identity: adaptor_identity_from_store(
                identity,
                *authority.context_binding().context_binding_digest(),
            )?,
            permit_id: derive_permit_id(&exposure, authorizing_digest)?,
            kind: artifact_to_exposure_kind(artifact),
            adaptor_outbound_digest: adaptor_outbound_digest_v1(
                artifact,
                exposure.outbound_bytes(),
            )?,
        }))
    }

    fn recover_spent_artifact(
        &self,
        authorization: &AdaptorResendAuthorizationV1,
    ) -> Result<RecoveredSpentArtifactV1, InventoryError> {
        let before = self.snapshot()?;
        let mut recovered: Option<RecoveredSpentArtifactV1> = None;
        scan_exposure_records(self.exposures()?, |exposure| {
            if exposure.state() != ExposureStateV1::Spent
                || artifact_to_exposure_kind(exposure.artifact())
                    != authorization.protocol_stage().exposure_kind()
            {
                return Ok(());
            }
            let adaptor_digest =
                adaptor_outbound_digest_v1(exposure.artifact(), exposure.outbound_bytes())
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if &adaptor_digest != authorization.adaptor_outbound_digest()
                || exposure.identity().session_id() != authorization.session_id().as_bytes()
                || exposure.identity().purpose() != authorization.purpose()
            {
                return Ok(());
            }

            let authority = self
                .find_authority_for_identity(exposure.identity())
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if authority.request_lookup_id() != authorization.request_lookup().as_bytes()
                || authority.context_binding().context_binding_digest()
                    != authorization.reservation_context_binding_digest()
            {
                return Ok(());
            }
            let authorizing_journal_digest = self
                .find_spent_authorizing_entry(exposure)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let permit_id = derive_permit_id(exposure, authorizing_journal_digest)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if recovered.is_some() {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            recovered = Some(RecoveredSpentArtifactV1 {
                nonce_identity: adaptor_identity_from_store(
                    exposure.identity(),
                    *authority.context_binding().context_binding_digest(),
                )
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
                permit_id,
                kind: exposure.artifact(),
                adaptor_outbound_digest: adaptor_digest,
            });
            Ok(())
        })?;
        let recovered = recovered.ok_or(InventoryError::RestoreQuarantined)?;
        let after = self.snapshot()?;
        if !before.same_authority(&after) {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(recovered)
    }

    fn recover_spent_artifact_for_restart(
        &self,
        request: &RestartArtifactRecoveryRequestV1,
    ) -> Result<RecoveredSpentArtifactV1, InventoryError> {
        let before = self.snapshot()?;
        let mut recovered: Option<RecoveredSpentArtifactV1> = None;
        scan_exposure_records(self.exposures()?, |exposure| {
            if exposure.state() != ExposureStateV1::Spent
                || artifact_to_exposure_kind(exposure.artifact())
                    != request.protocol_stage().exposure_kind()
                || exposure.identity().session_id() != request.session_id().as_bytes()
                || exposure.identity().participant_id() != request.participant_id().as_bytes()
                || exposure.identity().purpose() != request.purpose()
            {
                return Ok(());
            }
            let authority = self
                .find_authority_for_identity(exposure.identity())
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if authority.request_lookup_id() != request.request_lookup().as_bytes()
                || authority.context_binding().context_binding_digest()
                    != request.reservation_context_binding_digest()
            {
                return Ok(());
            }
            let authorizing_journal_digest = self
                .find_spent_authorizing_entry(exposure)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let permit_id = derive_permit_id(exposure, authorizing_journal_digest)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let adaptor_outbound_digest =
                adaptor_outbound_digest_v1(exposure.artifact(), exposure.outbound_bytes())
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if recovered.is_some() {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            recovered = Some(RecoveredSpentArtifactV1 {
                nonce_identity: adaptor_identity_from_store(
                    exposure.identity(),
                    *authority.context_binding().context_binding_digest(),
                )
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
                permit_id,
                kind: exposure.artifact(),
                adaptor_outbound_digest,
            });
            Ok(())
        })?;
        let recovered = recovered.ok_or(InventoryError::RestoreQuarantined)?;
        let after = self.snapshot()?;
        if !before.same_authority(&after) {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(recovered)
    }

    fn find_authority_for_identity(
        &self,
        identity: &NonceIdentityV1,
    ) -> Result<ReservationAuthorityV1, InventoryError> {
        let mut match_found: Option<ReservationAuthorityV1> = None;
        let authorities = self.authorities()?;
        authorities.scan_lexicographic(|name, _| {
            let bytes = authorities.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                RESERVATION_AUTHORITY_ADAPTOR_LEN,
            )?;
            let authority = ReservationAuthorityV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let authority_identity = authority
                .nonce_identity()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if authority_identity.as_bytes() == identity.as_bytes() {
                if match_found.is_some() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                match_found = Some(authority);
            }
            Ok(())
        })?;
        match_found.ok_or(InventoryError::RestoreQuarantined)
    }

    fn find_spent_authorizing_entry(
        &self,
        exposure: &ExposureRecordV1,
    ) -> Result<[u8; 32], InventoryError> {
        let mut digest: Option<[u8; 32]> = None;
        self.journal.scan_lexicographic(|name, _| {
            let bytes = self.journal.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                JOURNAL_ENTRY_MAX_LEN,
            )?;
            let entry = UnauthenticatedJournalEntryV1::parse_structural(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if let crate::UnauthenticatedJournalPayloadV1::ExposureAuthorized(transition) =
                entry.payload()
            {
                if transition.successor().as_bytes() == exposure.as_bytes() {
                    if digest.is_some() {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                    let mut entry_digest = [0_u8; 32];
                    entry_digest.copy_from_slice(entry.envelope().entry_digest());
                    digest = Some(entry_digest);
                }
            }
            Ok(())
        })?;
        digest.ok_or(InventoryError::RestoreQuarantined)
    }

    fn audit_reservation_projection_set(&self) -> Result<(), InventoryError> {
        let Some(authorities) = self.authorities.as_ref() else {
            return Ok(());
        };
        authorities.scan_lexicographic(|name, _| {
            let bytes = authorities.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                RESERVATION_AUTHORITY_ADAPTOR_LEN,
            )?;
            let authority = ReservationAuthorityV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            self.require_reservation_projections(&authority)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
        })?;
        Ok(())
    }

    fn read_authority(
        &self,
        reservation_id: &[u8; 32],
    ) -> Result<ReservationAuthorityV1, InventoryError> {
        let component =
            ValidatedComponent::registered(&format!("{}.authority", hex_lower(reservation_id)))?;
        let bytes = self
            .authorities()?
            .read_bounded_file(&component, RESERVATION_AUTHORITY_ADAPTOR_LEN)?;
        let authority = ReservationAuthorityV1::from_bytes(&bytes)?;
        if authority.reservation_id() != reservation_id {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(authority)
    }

    fn require_reservation_projections(
        &self,
        authority: &ReservationAuthorityV1,
    ) -> Result<(), InventoryError> {
        let claim_component = ValidatedComponent::registered(&format!(
            "{}.claim",
            hex_lower(authority.session_id())
        ))?;
        let claim = SessionClaimV1::from_bytes(
            &self
                .claims()?
                .read_bounded_file(&claim_component, SESSION_CLAIM_LEN)?,
        )?;
        if claim.identity().as_bytes() != authority.nonce_identity()?.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }

        let mut matching_charge: Option<BudgetChargeV1> = None;
        let charges = self.charges()?;
        charges.scan_lexicographic(|name, _| {
            let bytes = charges.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                BUDGET_CHARGE_ADAPTOR_LEN,
            )?;
            let charge = BudgetChargeV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if charge.reservation_authority().as_bytes() == authority.as_bytes() {
                if matching_charge.is_some() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                matching_charge = Some(charge);
            }
            Ok(())
        })?;
        let charge = matching_charge.ok_or(InventoryError::RestoreQuarantined)?;

        let mut reserve_occurrences = 0_u64;
        self.journal.scan_lexicographic(|name, _| {
            let bytes = self.journal.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                JOURNAL_ENTRY_MAX_LEN,
            )?;
            let entry = UnauthenticatedJournalEntryV1::parse_structural(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if let crate::UnauthenticatedJournalPayloadV1::Reserve(reserve) = entry.payload() {
                if reserve.claim().as_bytes() == claim.as_bytes()
                    && reserve.charge().as_bytes() == charge.as_bytes()
                {
                    if entry.envelope().sequence() != charge.reserve_journal_sequence() {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                    reserve_occurrences = reserve_occurrences
                        .checked_add(1)
                        .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                }
            }
            Ok(())
        })?;
        if reserve_occurrences != 1 || authority.nonce_epoch() != self.core.nonce_epoch() {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(())
    }

    fn require_pre_derivation_inventory(
        &self,
        authority: &ReservationAuthorityV1,
    ) -> Result<(), InventoryError> {
        let identity_name = hex_lower(authority.nonce_identity()?.as_bytes());
        for directory in [self.attempts.as_ref(), self.exposures.as_ref()]
            .into_iter()
            .flatten()
        {
            if contains_component(directory, &identity_name)? {
                return Err(InventoryError::RestoreQuarantined);
            }
        }
        let secret_exists = match self.nonce_secrets.as_ref() {
            Some(nonce_secrets) => {
                contains_component(nonce_secrets, &format!("{identity_name}.secret"))?
            }
            None => false,
        };
        if secret_exists
            || contains_component(&self.tombstones, &format!("{identity_name}.tombstone"))?
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(())
    }

    #[cfg(test)]
    fn test_handle(&self, reservation_id: [u8; 32]) -> Result<ReservationHandleV1, InventoryError> {
        let _snapshot = self.snapshot()?;
        let authority = self.read_authority(&reservation_id)?;
        self.require_reservation_projections(&authority)?;
        Ok(ReservationHandleV1 {
            open_instance_id: self.open_instance_id,
            reservation_id,
            authority_digest: *authority.authority_digest(),
        })
    }

    fn revalidate_authority(&self) -> Result<(), InventoryError> {
        self.retained_lock.revalidate()?;
        self.root.revalidate()?;
        require_normal_root_inventory(&self.root)?;
        self.generation.revalidate()?;
        require_generation_inventory(&self.generation)?;
        // These aliases are retained by the same shared authority held by
        // every one-shot capability.  Revalidate all of them before any
        // record can become authorization, rather than relying on the
        // short-lived Store fields that may disappear with the caller.
        for directory in [
            &self.authority.reservation_authorities,
            &self.authority.session_claims,
            &self.authority.budget_charges,
            &self.authority.attempts,
            &self.authority.exposures,
            &self.authority.nonce_secrets,
            &self.authority.collaborative_secrets,
        ] {
            let directory = directory
                .lock()
                .map_err(|_| InventoryError::RestoreQuarantined)?;
            if let Some(directory) = directory.as_ref() {
                directory.revalidate()?;
            }
        }
        self.authority.tombstones.revalidate()?;

        let root_identity = StoreRootIdentityV1::from_bytes(&self.root.read_bounded_file(
            &ValidatedComponent::registered(ROOT_IDENTITY)?,
            STORE_IDENTITY_LEN,
        )?)?;
        if root_identity.as_bytes() != self.root_identity.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let lock_identity = StoreLockIdentityV1::from_bytes_with_root(
            &self.root.read_bounded_file(
                &ValidatedComponent::registered(LOCK_IDENTITY)?,
                STORE_IDENTITY_LEN,
            )?,
            &root_identity,
        )?;
        if lock_identity.as_bytes() != self.lock_identity.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }

        let core = VaultGenerationCoreV1::from_bytes(&self.generation.read_bounded_file(
            &ValidatedComponent::registered(GENERATION_CORE)?,
            VAULT_GENERATION_CORE_LEN,
        )?)?;
        if core.as_bytes() != self.core.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let master_envelope =
            VaultMasterKeyEnvelopeV1::from_bytes(&self.generation.read_bounded_file(
                &ValidatedComponent::registered(MASTER_KEY_ENVELOPE)?,
                MASTER_KEY_ENVELOPE_LEN,
            )?)
            .map_err(|_| InventoryError::Crypto)?;
        if authoritative_storage_hash_v1(
            StorageHashDomainV1::MasterEnvelope,
            master_envelope.as_bytes(),
        ) != *core.master_envelope_digest()
        {
            return Err(InventoryError::RestoreQuarantined);
        }

        let active = ActiveVaultGenerationV1::from_bytes_with_core(
            &self.root.read_bounded_file(
                &ValidatedComponent::registered(ACTIVE_GENERATION)?,
                ACTIVE_VAULT_GENERATION_LEN,
            )?,
            &core,
        )?;
        if active.as_bytes() != self.active_record()?.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        self.retained_lock.revalidate()?;
        Ok(())
    }

    #[cfg(any(test, feature = "evidence-only"))]
    fn current_backup_inputs(
        &self,
        limits: BackupPolicyLimitsV1,
    ) -> Result<VerifiedBackupInputsV1, InventoryError> {
        let snapshot = self.snapshot()?;
        // Collaborative secrets are deliberately excluded from the ratified
        // backup/restore registry. Advancing the generation/nonce epoch while
        // any such record exists would strand `r_i` or one-shot BP state under
        // the predecessor AEAD epoch. Refuse the rotation transaction before
        // it can stage a successor generation. The operator must first drive
        // every owning session to a terminal cleanup under the current epoch.
        if collaborative::has_epoch_bound_state(self)? {
            return Err(InventoryError::RestoreQuarantined);
        }
        let journal = self.audit_current_generation_journal()?;
        let record_limits = limits.record_set_limits()?;
        let mut record_items = Vec::new();
        let mut encoded_record_bytes = 4_usize;
        {
            let mut push_record = |family: RestoreRecordFamilyV1,
                                   record_bytes: &[u8]|
             -> Result<(), LinuxCapabilityError> {
                let next_item_bytes = crate::RESTORE_RECORD_ITEM_PREFIX_LEN
                    .checked_add(record_bytes.len())
                    .ok_or(LinuxCapabilityError::InvalidObject)?;
                if !limits.permits_record_accumulation(
                    record_items.len(),
                    encoded_record_bytes,
                    next_item_bytes,
                ) {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                encoded_record_bytes = encoded_record_bytes
                    .checked_add(next_item_bytes)
                    .ok_or(LinuxCapabilityError::InvalidObject)?;
                let item = RestoreRecordItemV1::from_record_bytes(family, record_bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                record_items.push(item);
                Ok(())
            };

            if let Some(claims) = self.claims.as_ref() {
                claims.scan_lexicographic(|name, node| {
                    if node.node_type != ExpectedNodeType::RegularFile {
                        return Err(LinuxCapabilityError::InvalidObject);
                    }
                    let bytes = claims.read_bounded_file(
                        &ValidatedComponent::registered(name)?,
                        SESSION_CLAIM_LEN,
                    )?;
                    let claim = SessionClaimV1::from_bytes(&bytes)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    push_record(RestoreRecordFamilyV1::SessionClaim, claim.as_bytes())?;
                    Ok(())
                })?;
            }

            if let Some(attempts) = self.attempts.as_ref() {
                attempts.scan_lexicographic(|identity_name, identity_node| {
                    if identity_node.node_type != ExpectedNodeType::Directory {
                        return Err(LinuxCapabilityError::InvalidObject);
                    }
                    let identity_directory = attempts
                        .open_child_directory(ValidatedComponent::registered(identity_name)?)?;
                    identity_directory.scan_lexicographic(|name, node| {
                        if node.node_type != ExpectedNodeType::RegularFile {
                            return Err(LinuxCapabilityError::InvalidObject);
                        }
                        let bytes = identity_directory.read_bounded_file(
                            &ValidatedComponent::registered(name)?,
                            NONCE_DERIVATION_ATTEMPT_LEN,
                        )?;
                        if bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
                            let attempt = NonceDerivationAttemptV1::from_bytes(&bytes)
                                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                            push_record(RestoreRecordFamilyV1::Attempt, attempt.as_bytes())?;
                        } else {
                            let attempt = AttemptRecordV1::from_bytes(&bytes)
                                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                            push_record(RestoreRecordFamilyV1::Attempt, attempt.as_bytes())?;
                        }
                        Ok(())
                    })
                })?;
            }

            if let Some(exposures) = self.exposures.as_ref() {
                scan_exposure_records(exposures, |exposure| {
                    push_record(RestoreRecordFamilyV1::Exposure, exposure.as_bytes())?;
                    Ok(())
                })?;
            }

            self.tombstones.scan_lexicographic(|name, node| {
                if node.node_type != ExpectedNodeType::RegularFile || !name.ends_with(".tombstone")
                {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                let identity_name = name
                    .strip_suffix(".tombstone")
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                let tombstone = self
                    .read_authenticated_tombstone(identity_name)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                push_record(RestoreRecordFamilyV1::Tombstone, tombstone.as_bytes())?;
                Ok(())
            })?;

            // End the closure's mutable borrows before constructing the record set.
        }
        // Apply the authenticated limits before the backup implementation can
        // allocate or copy the complete encoded set.
        let record_set = crate::canonical::RestoreRecordSetV1::new(record_items, &record_limits)?;
        let journal_projection = restore::canonical_record_set_from_journal(
            &journal.entries,
            &journal.terminals,
            &record_limits,
        )
        .map_err(|_| InventoryError::RestoreQuarantined)?;
        if journal_projection.as_bytes() != record_set.as_bytes() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let expected_record_count = snapshot
            .counts
            .session_claims
            .checked_add(snapshot.counts.attempts)
            .and_then(|count| count.checked_add(snapshot.counts.exposures))
            .and_then(|count| count.checked_add(snapshot.counts.tombstones))
            .ok_or(InventoryError::Canonical)?;
        if u64::from(record_set.record_count()) != expected_record_count {
            return Err(InventoryError::RestoreQuarantined);
        }
        let after = self.snapshot()?;
        if !snapshot.same_authority(&after)
            || snapshot.journal_sequence != journal.sequence
            || snapshot.journal_head_digest != journal.head_digest
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(VerifiedBackupInputsV1 {
            storage_ids: self.storage_ids()?,
            source_epoch: self.core.nonce_epoch(),
            source_journal_sequence: journal.sequence,
            source_journal_head_digest: journal.head_digest,
            journal_entries: journal
                .entries
                .into_iter()
                .map(|entry| entry.as_bytes().to_vec())
                .collect(),
            record_set,
        })
    }

    #[cfg(any(test, feature = "evidence-only"))]
    fn backup_operation_authority(
        &self,
        _limits: BackupPolicyLimitsV1,
    ) -> Result<BackupOperationAuthorityV1, InventoryError> {
        self.revalidate_complete_backup_authority()?;
        let inventory = self.snapshot()?;
        let history = backup::authenticate_completed_history(&self.root)?;
        self.revalidate_complete_backup_authority()?;
        let after = self.snapshot()?;
        if !inventory.same_authority(&after) {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(BackupOperationAuthorityV1 { inventory, history })
    }

    fn revalidate_complete_backup_authority(&self) -> Result<(), InventoryError> {
        self.revalidate_authority()
    }

    #[cfg(any(test, feature = "evidence-only"))]
    fn fresh_backup_id(
        &self,
        history: &backup::AuthenticatedBackupHistoryV1,
    ) -> Result<[u8; 32], InventoryError> {
        loop {
            let candidate = random_nonzero::<32>()?;
            if candidate == *self.storage_ids()?.contract_wallet_id()
                || candidate == *self.storage_ids()?.vault_id()
                || history.contains_backup_id(&candidate)
            {
                continue;
            }
            return Ok(candidate);
        }
    }

    #[cfg(any(test, feature = "evidence-only"))]
    fn create_backup(
        &mut self,
        backup_passphrase: Passphrase,
        limits: BackupPolicyLimitsV1,
    ) -> Result<CompletedBackupV1, InventoryError> {
        let before = self.backup_operation_authority(limits)?;
        let inputs = self.current_backup_inputs(limits)?;
        let pre_publication = self.backup_operation_authority(limits)?;
        before.require_same(&pre_publication)?;
        let backup_generation = before.history.next_generation()?;
        let backup_id = self.fresh_backup_id(&before.history)?;
        let completed = backup::create_backup(
            &self.root,
            &self.master_key,
            backup_passphrase,
            backup_id,
            backup_generation,
            inputs,
        )?;
        let after = self.backup_operation_authority(limits)?;
        if !before.inventory.same_authority(&after.inventory) {
            return Err(InventoryError::RestoreQuarantined);
        }
        before
            .history
            .require_exact_publication(&after.history, &completed)?;
        Ok(completed)
    }

    #[cfg(any(test, feature = "evidence-only"))]
    fn prepare_existing_device_restore_material(
        &self,
        source_root: &RetainedDirectory,
        selected_backup_name: &str,
        backup_passphrase: Passphrase,
        limits: BackupPolicyLimitsV1,
    ) -> Result<ExistingDeviceRestorePreparationV1, InventoryError> {
        self.revalidate_complete_backup_authority()?;
        require_existing_restore_target_branch(&self.root)?;
        let before = self.snapshot()?;
        let selected = restore::authenticate_selected_backup(
            source_root,
            selected_backup_name,
            backup_passphrase,
            limits,
        )?;
        let after = self.snapshot()?;
        if !before.same_authority(&after) {
            return Err(InventoryError::RestoreQuarantined);
        }
        let target_inputs = self.current_backup_inputs(limits)?;
        let target_journal = self.audit_current_generation_journal()?;
        selected.revalidate_source_authority()?;
        let mut active_target_secrets = BTreeMap::new();
        for identity in restore::record_set_identities(target_inputs.record_set())? {
            let identity_name = hex_lower(identity.as_bytes());
            let secret_name = format!("{identity_name}.secret");
            let secret_exists = match self.nonce_secrets.as_ref() {
                Some(directory) => contains_component(directory, &secret_name)?,
                None => false,
            };
            if secret_exists {
                let authority = self.find_authority_for_identity(&identity)?;
                let derivation = read_nonce_derivation_attempt(self.attempts()?, &identity_name)?;
                let (evidence, _retained_secret) =
                    self.authenticate_active_secret_for_terminal(&authority, &derivation)?;
                if active_target_secrets
                    .insert(*identity.as_bytes(), evidence)
                    .is_some()
                {
                    return Err(InventoryError::RestoreQuarantined);
                }
            }
        }
        let final_snapshot = self.snapshot()?;
        if !before.same_authority(&final_snapshot) {
            return Err(InventoryError::RestoreQuarantined);
        }
        let storage_ids = self.storage_ids()?;
        ExistingDeviceRestorePreparationV1::new(
            selected,
            &self.root_identity,
            *storage_ids.vault_id(),
            self.core.nonce_epoch(),
            before.journal_sequence,
            before.journal_head_digest,
            self.core.vault_generation(),
            &target_journal.composite,
            target_inputs.record_set(),
            &active_target_secrets,
        )
        .map_err(InventoryError::from)
    }

    /// Consumes the predecessor Store while retaining its exclusive lock
    /// through existing-device restore publication steps 9--14.
    #[cfg(any(test, feature = "evidence-only"))]
    fn publish_staged_existing_device_restore(
        self,
        staged: restore::StagedExistingRestoreV1,
    ) -> Result<restore::CompletedExistingRestoreV1, InventoryError> {
        let active = self.active_record()?;
        let completed = restore::publish_staged_existing_device_restore(
            &self.root,
            &self.retained_lock,
            &self.root_identity,
            &self.core,
            &active,
            staged,
        )?;
        self.retained_lock.revalidate()?;
        require_normal_root_inventory(&self.root)?;
        require_generation_inventory(completed.generation())?;
        completed.completed().revalidate()?;
        completed.generation().revalidate()?;
        completed.active().revalidate()?;
        self.root.revalidate()?;
        self.retained_lock.revalidate()?;
        Ok(completed)
    }
}

impl ContractsNonceVaultV1 {
    /// Creates a production-composition nonce vault from an explicit,
    /// separately ratified policy. No production policy is synthesized or
    /// selected by this crate.
    pub fn create_production(
        parent: Arc<Dir>,
        root_name: &str,
        storage_ids: StorageIdsV1,
        passphrase: &Passphrase,
        budget_policy: BudgetPolicyV1,
    ) -> Result<Self, InventoryError> {
        if budget_policy.profile() != crate::BudgetPolicyProfileV1::ProductionRatified {
            return Err(InventoryError::Canonical);
        }
        Ok(Self {
            store: LiveStoreInventoryV1::create(parent, root_name, storage_ids, passphrase)?,
            budget_policy: Some(budget_policy),
            same_open_claims: BTreeSet::new(),
        })
    }

    /// Reopens a production-composition nonce vault with the exact explicit,
    /// separately ratified policy selected by its trusted composition root.
    pub fn open_production(
        parent: Arc<Dir>,
        root_name: &str,
        passphrase: Passphrase,
        budget_policy: BudgetPolicyV1,
    ) -> Result<Self, InventoryError> {
        if budget_policy.profile() != crate::BudgetPolicyProfileV1::ProductionRatified {
            return Err(InventoryError::Canonical);
        }
        let vault = Self {
            store: LiveStoreInventoryV1::open(parent, root_name, passphrase)?,
            budget_policy: Some(budget_policy),
            same_open_claims: BTreeSet::new(),
        };
        vault.validate_policy_history()?;
        Ok(vault)
    }

    /// Retains one canonical restore target as an opaque process capability.
    ///
    /// Acquisition performs only component validation and retained root open;
    /// all authoritative reads occur later while `resume_restore` owns the
    /// exclusive target lock.
    pub fn retain_restore_target(
        parent: Arc<Dir>,
        root_name: &str,
    ) -> Result<RetainedRestoreTargetV1, InventoryError> {
        let root_component = ValidatedComponent::operator_selected_root(root_name)?;
        let root = RetainedDirectory::open_under(parent.clone(), root_component.clone())?;
        Ok(RetainedRestoreTargetV1 { root })
    }

    /// Resumes one already-published canonical existing- or new-device restore.
    ///
    /// The capability is consumed, the target lock remains held throughout
    /// disk authority selects the closed restore branch, and success is returned
    /// only after the completed tree is
    /// reopened through the normal Store authority and its full snapshot has
    /// authenticated every canonical namespace.
    pub fn resume_restore(
        target: RetainedRestoreTargetV1,
        target_unlock_passphrase: Passphrase,
    ) -> Result<(), InventoryError> {
        let RetainedRestoreTargetV1 { root } = target;
        let reopened =
            LiveStoreInventoryV1::resume_restore_from_disk(root, target_unlock_passphrase)?;
        reopened.retained_lock.revalidate()?;
        #[cfg(test)]
        restore::test_restore_crash_hook("step14-after-final-validation");
        drop(reopened);
        Ok(())
    }

    #[cfg(test)]
    fn resume_restore_with_completion_for_test<F>(
        target: RetainedRestoreTargetV1,
        target_unlock_passphrase: Passphrase,
        completion: F,
    ) -> Result<(), InventoryError>
    where
        F: FnOnce() -> Result<(), InventoryError>,
    {
        let RetainedRestoreTargetV1 { root } = target;
        let reopened = LiveStoreInventoryV1::resume_restore_from_disk_with_completion(
            root,
            target_unlock_passphrase,
            completion,
        )?;
        reopened.retained_lock.revalidate()?;
        drop(reopened);
        Ok(())
    }

    /// Creates an evidence-only canonical vault from an already retained parent.
    ///
    /// This constructor is absent from production builds. It accepts only an
    /// authenticated `EvidenceOnly` policy and never supplies numeric defaults.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn create_evidence_only(
        parent: Arc<Dir>,
        root_name: &str,
        storage_ids: StorageIdsV1,
        passphrase: &Passphrase,
        budget_policy: BudgetPolicyV1,
    ) -> Result<Self, InventoryError> {
        if budget_policy.profile() != crate::BudgetPolicyProfileV1::EvidenceOnly {
            return Err(InventoryError::Canonical);
        }
        Ok(Self {
            store: LiveStoreInventoryV1::create(parent, root_name, storage_ids, passphrase)?,
            budget_policy: Some(budget_policy),
            same_open_claims: BTreeSet::new(),
        })
    }

    /// Publishes one authenticated backup into an absent restore-only target.
    ///
    /// This evidence composition seam accepts only retained parent
    /// capabilities, exact single-component root names, owned passphrases,
    /// authenticated allocation limits, and an explicit evidence-only budget
    /// policy. The canonical new-device transaction retains the same target
    /// lock through final normal Store reopening.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn publish_new_device_restore_evidence_only(
        request: NewDeviceRestoreEvidenceRequestV1,
    ) -> Result<Self, InventoryError> {
        if request.budget_policy.profile() != crate::BudgetPolicyProfileV1::EvidenceOnly {
            return Err(InventoryError::Canonical);
        }
        let source_root = RetainedDirectory::open_under(
            request.source_parent,
            ValidatedComponent::operator_selected_root(&request.source_root_name)?,
        )?;
        Ok(Self {
            store: LiveStoreInventoryV1::publish_new_device_restore(
                &source_root,
                &request.selected_backup_name,
                request.source_backup_passphrase,
                request.destination_parent,
                &request.destination_root_name,
                request.target_unlock_passphrase,
                request.limits,
            )?,
            budget_policy: Some(request.budget_policy),
            same_open_claims: BTreeSet::new(),
        })
    }

    /// Reopens an evidence-only canonical vault under the retained lock.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn open_evidence_only(
        parent: Arc<Dir>,
        root_name: &str,
        passphrase: Passphrase,
        budget_policy: BudgetPolicyV1,
    ) -> Result<Self, InventoryError> {
        if budget_policy.profile() != crate::BudgetPolicyProfileV1::EvidenceOnly {
            return Err(InventoryError::Canonical);
        }
        let vault = Self {
            store: LiveStoreInventoryV1::open(parent, root_name, passphrase)?,
            budget_policy: Some(budget_policy),
            same_open_claims: BTreeSet::new(),
        };
        vault.validate_policy_history()?;
        Ok(vault)
    }

    fn policy(&self) -> Result<&BudgetPolicyV1, InventoryError> {
        self.budget_policy
            .as_ref()
            .ok_or(InventoryError::RestoreQuarantined)
    }

    #[cfg(test)]
    pub(super) fn authenticated_lifetime_carry_bytes(
        &self,
    ) -> Result<AuthenticatedLifetimeCarryBytesV1, InventoryError> {
        let before = self.store.snapshot()?;
        let journal = self.store.audit_current_generation_journal()?;
        let mut budget_carries = Vec::new();
        let mut permit_carries = Vec::new();
        for entry in &journal.entries {
            let structural = UnauthenticatedJournalEntryV1::parse_structural(entry.as_bytes())?;
            match structural.payload() {
                crate::UnauthenticatedJournalPayloadV1::BudgetCarryForward(charge) => {
                    budget_carries.push(charge.as_bytes().to_vec());
                }
                crate::UnauthenticatedJournalPayloadV1::PermitRetirementCarryForward(
                    retirement,
                ) => {
                    permit_carries.push(retirement.as_bytes().to_vec());
                }
                _ => {}
            }
        }
        let after = self.store.snapshot()?;
        if !before.same_authority(&after) {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok((budget_carries, permit_carries))
    }

    fn find_resend_artifact(
        &self,
        request: &ResendRequestV1,
    ) -> Result<ExportedArtifactV1, InventoryError> {
        let mut found: Option<ExportedArtifactV1> = None;
        scan_exposure_records(self.store.exposures()?, |exposure| {
            if exposure.state() != ExposureStateV1::Spent
                || artifact_to_exposure_kind(exposure.artifact())
                    != request.protocol_stage().exposure_kind()
            {
                return Ok(());
            }
            let authority = self
                .store
                .find_authority_for_identity(exposure.identity())
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let adaptor_digest =
                adaptor_outbound_digest_v1(exposure.artifact(), exposure.outbound_bytes())
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let authorizing = self
                .store
                .find_spent_authorizing_entry(exposure)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let permit_id = derive_permit_id(exposure, authorizing)?;
            if exposure.identity().session_id() == request.nonce_identity().session_id().as_bytes()
                && exposure.identity().participant_id()
                    == request.nonce_identity().participant_id().as_bytes()
                && exposure.identity().purpose() == request.nonce_identity().purpose()
                && exposure.identity().nonce_epoch() == request.nonce_identity().nonce_epoch()
                && request.nonce_identity().bound_digest()
                    == authority.context_binding().context_binding_digest()
                && authority.request_lookup_id() == request.request_lookup().as_bytes()
                && authority.context_binding().context_binding_digest()
                    == request.reservation_context_binding_digest()
                && &permit_id == request.permit_id()
                && &adaptor_digest == request.adaptor_outbound_digest()
            {
                if found.is_some() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                found = Some(ExportedArtifactV1 {
                    permit_id,
                    kind: exposure.artifact(),
                    outbound_bytes: exposure.outbound_bytes().to_vec(),
                });
            }
            Ok(())
        })?;
        found.ok_or(InventoryError::RestoreQuarantined)
    }

    fn resend_exported_inner<F>(
        &mut self,
        request: ResendRequestV1,
        interposition: F,
    ) -> Result<ExportedArtifactV1, InventoryError>
    where
        F: FnOnce() -> Result<(), InventoryError>,
    {
        let before = self.store.snapshot()?;
        let selected_before = self.find_resend_artifact(&request)?;
        interposition()?;
        let after = self.store.snapshot()?;
        if !before.same_authority(&after) {
            return Err(InventoryError::RestoreQuarantined);
        }
        let selected_after = self.find_resend_artifact(&request)?;
        if selected_before.permit_id != selected_after.permit_id
            || selected_before.kind != selected_after.kind
            || selected_before.outbound_bytes != selected_after.outbound_bytes
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(selected_after)
    }

    /// Creates one immutable canonical backup under the retained Store lock.
    ///
    /// Numeric allocation limits originate from authenticated operator policy;
    /// no production or evidence profile is selected by this method.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn create_backup_evidence_only(
        &mut self,
        backup_passphrase: Passphrase,
        limits: BackupPolicyLimitsV1,
    ) -> Result<CompletedBackupV1, InventoryError> {
        self.store.create_backup(backup_passphrase, limits)
    }

    /// Runs the evidence-only existing-device restore preparation and initial
    /// publication path using explicit validated allocation limits.
    ///
    /// The vault is consumed so no predecessor authority survives successful
    /// publication. Production policy and numeric defaults are intentionally
    /// absent from this evidence-only composition seam.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn publish_existing_device_restore_evidence_only(
        self,
        selected_backup_name: &str,
        source_backup_passphrase: Passphrase,
        successor_unlock_passphrase: Passphrase,
        limits: BackupPolicyLimitsV1,
    ) -> Result<(), InventoryError> {
        let preparation = self.store.prepare_existing_device_restore_material(
            &self.store.root,
            selected_backup_name,
            source_backup_passphrase,
            limits,
        )?;
        let publication = restore::PreparedExistingRestorePublicationV1::new(
            preparation,
            successor_unlock_passphrase,
            limits,
        )?;
        let staged = restore::stage_existing_device_restore(&self.store.root, publication)?;
        drop(self.store.publish_staged_existing_device_restore(staged)?);
        Ok(())
    }

    fn validate_policy_history(&self) -> Result<(), InventoryError> {
        let policy = self.policy()?;
        if let Some(charges) = self.store.charges.as_ref() {
            charges.scan_lexicographic(|name, _| {
                let bytes = charges.read_bounded_file(
                    &ValidatedComponent::registered(name)?,
                    BUDGET_CHARGE_ADAPTOR_LEN,
                )?;
                BudgetChargeV1::from_bytes(&bytes)
                    .and_then(|charge| charge.validate_policy(policy))
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
            })?;
        }
        Ok(())
    }

    /// Enforces all four authenticated P1-004 budget scopes and the trusted
    /// clock high-water rules before a fresh reservation identifier is used.
    fn validate_budget_admission(
        &self,
        proposed_budget_key_id: &[u8; 32],
        proposed_counterparty_id: &[u8; 32],
        now: u64,
    ) -> Result<(), InventoryError> {
        let policy = self.policy()?;
        if now < policy.effective_from_utc_seconds() {
            return Err(InventoryError::RestoreQuarantined);
        }
        let Some(charges) = self.store.charges.as_ref() else {
            return Ok(());
        };
        let mut key_lifetime = 0_u64;
        let mut counterparty_lifetime = 0_u64;
        let mut concurrent = 0_u64;
        let mut rolling = 0_u64;
        let mut clock_high_water: Option<u64> = None;
        let window_start = now.saturating_sub(policy.rolling_window_seconds());
        charges.scan_lexicographic(|name, node| {
            if node.node_type != ExpectedNodeType::RegularFile {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let bytes = charges.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                BUDGET_CHARGE_ADAPTOR_LEN,
            )?;
            let charge = BudgetChargeV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            charge
                .validate_policy(policy)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let charged_at = charge.charged_at_utc_seconds();
            if charged_at > now {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            clock_high_water =
                Some(clock_high_water.map_or(charged_at, |value| value.max(charged_at)));
            let authority = charge.reservation_authority();
            if authority.budget_key_id() != proposed_budget_key_id {
                return Ok(());
            }
            key_lifetime = key_lifetime
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            if authority.counterparty_id() == proposed_counterparty_id {
                counterparty_lifetime = counterparty_lifetime
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            }
            if charged_at > window_start {
                rolling = rolling
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            }
            let identity = authority
                .nonce_identity()
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let tombstone_name = format!("{}.tombstone", hex_lower(identity.as_bytes()));
            if !contains_component(&self.store.tombstones, &tombstone_name)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
            {
                concurrent = concurrent
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            }
            Ok(())
        })?;
        if let Some(high_water) = clock_high_water {
            let step = now
                .checked_sub(high_water)
                .ok_or(InventoryError::RestoreQuarantined)?;
            if step > policy.maximum_forward_step_seconds() {
                return Err(InventoryError::RestoreQuarantined);
            }
        }
        if key_lifetime >= policy.global_reservation_limit()
            || counterparty_lifetime >= policy.counterparty_reservation_limit()
            || concurrent >= u64::from(policy.concurrent_reservation_limit())
            || rolling >= policy.rolling_window_reservation_limit()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok(())
    }

    fn unix_time() -> Result<u64, InventoryError> {
        #[cfg(all(test, feature = "evidence-only"))]
        if let Some(now) = TEST_UNIX_TIME.with(std::cell::Cell::get) {
            return if now == 0 {
                Err(InventoryError::RestoreQuarantined)
            } else {
                Ok(now)
            };
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| InventoryError::RestoreQuarantined)?
            .as_secs()
            .checked_add(0)
            .filter(|value| *value != 0)
            .ok_or(InventoryError::RestoreQuarantined)
    }

    #[cfg(all(test, feature = "evidence-only"))]
    pub(super) fn set_evidence_test_time(now: Option<u64>) {
        TEST_UNIX_TIME.with(|value| value.set(now));
    }

    fn handle_for_authority(
        &self,
        authority: &ReservationAuthorityV1,
    ) -> Result<ReservationHandleV1, InventoryError> {
        let mut reservation_id = [0_u8; 32];
        reservation_id.copy_from_slice(authority.reservation_id());
        Ok(ReservationHandleV1 {
            open_instance_id: self.store.open_instance_id,
            reservation_id,
            authority_digest: *authority.authority_digest(),
        })
    }

    fn authority_for_lookup(
        &self,
        lookup: &ReservationRequestLookupV1,
    ) -> Result<Option<ReservationAuthorityV1>, InventoryError> {
        let Some(authorities) = self.store.authorities.as_ref() else {
            return Ok(None);
        };
        let mut found = None;
        authorities.scan_lexicographic(|name, _| {
            let bytes = authorities.read_bounded_file(
                &ValidatedComponent::registered(name)?,
                RESERVATION_AUTHORITY_ADAPTOR_LEN,
            )?;
            let authority = ReservationAuthorityV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if authority.request_lookup_id() == lookup.as_bytes() {
                if found.is_some() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                found = Some(authority);
            }
            Ok(())
        })?;
        Ok(found)
    }

    fn request_matches_authority(
        request: &ReservationResumeRequestV1,
        authority: &ReservationAuthorityV1,
    ) -> bool {
        authority.request_lookup_id() == request.request_lookup().as_bytes()
            && authority.session_id() == request.session_id().as_bytes()
            && authority.participant_id() == request.participant_id().as_bytes()
            && authority.purpose() == request.purpose()
            && authority.context_binding().as_bytes() == request.context_binding().as_bytes()
            && authority.context_binding().template_hash() == request.template_hash().as_bytes()
            && &authority.as_bytes()[42..74] == request.key_id().as_bytes()
            && &authority.as_bytes()[106..138] == request.counterparty().as_bytes()
    }

    fn make_persistence_permit(
        &self,
        authority: &ReservationAuthorityV1,
        derivation: &NonceDerivationAttemptV1,
        attempt: AttemptRecordV1,
        operation_input_digest: [u8; 32],
        secret_for_deletion: Option<AuthenticatedSecretForDeletionV1>,
    ) -> Result<ArtifactPersistencePermitV1, InventoryError> {
        let artifact = attempt.artifact();
        let reservation_id = ReservationNonceId::from_bytes(
            authority
                .reservation_id()
                .try_into()
                .map_err(|_| InventoryError::Canonical)?,
        )
        .map_err(|_| InventoryError::Canonical)?;
        Ok(ArtifactPersistencePermitV1 {
            open_instance_id: self.store.open_instance_id,
            reservation_id,
            nonce_identity: adaptor_identity_from_store(
                &authority.nonce_identity()?,
                *authority.context_binding().context_binding_digest(),
            )?,
            context_binding_digest: *authority.context_binding().context_binding_digest(),
            derivation_attempt_digest: *derivation.attempt().attempt_digest(),
            operation_input_digest,
            effective_retry_counter: derivation.effective_retry_counter(),
            phase: attempt.phase(),
            exposure_kind: artifact_to_exposure_kind(artifact),
            exposure_sequence: u64::from(artifact_to_exposure_kind(artifact).to_byte()),
            expected_lifecycle_revision: attempt.expected_lifecycle_revision(),
            stage_context_digest: operation_input_digest,
            process_binding: ProcessComputationBindingIdV1::generate()
                .map_err(|_| InventoryError::RandomFailure)?,
            attempt,
            secret_for_deletion,
        })
    }
}

impl NonceVaultV1 for ContractsNonceVaultV1 {
    type Error = InventoryError;
    type ReservationHandle = ReservationHandleV1;
    type ReservationSnapshot = ReservationSnapshotV1;
    type DerivationAttemptPermit = DerivationAttemptPermitV1;
    type InitialSecretOpenPermit = InitialSecretOpenPermitV1;
    type StageComputationPermit = StageComputationPermitV1;
    type ArtifactPersistencePermit = ArtifactPersistencePermitV1;
    type PersistedExposureHandle = PersistedExposureHandleV1;
    type ExposurePermit = ExposurePermitV1;
    type ExportedArtifact = ExportedArtifactV1;
    type RecoveredSpentArtifact = RecoveredSpentArtifactV1;

    fn claim_fresh_reservation(
        &mut self,
        request: FreshReservationRequestV1,
    ) -> Result<Self::ReservationHandle, Self::Error> {
        let policy = self.policy()?.clone();
        let binding =
            ReservationContextBindingV1::from_bytes(request.context_binding().as_bytes())?;
        if binding.session_id() != request.session_id().as_bytes()
            || binding.local_participant_id() != request.participant_id().as_bytes()
            || binding.purpose() != request.purpose()
            || binding.template_hash() != request.template_hash().as_bytes()
        {
            return Err(InventoryError::Canonical);
        }
        let request_lookup = *request.request_lookup().as_bytes();
        if self
            .authority_for_lookup(request.request_lookup())?
            .is_some()
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let budget_key_id = authoritative_storage_hash_v1(
            StorageHashDomainV1::BudgetKey,
            &[binding.chain_id(), binding.local_signing_public_key()].concat(),
        );
        let counterparty_id = authoritative_storage_hash_v1(
            StorageHashDomainV1::Counterparty,
            &[binding.chain_id(), binding.remote_participant_id()].concat(),
        );
        if &budget_key_id != request.key_id().as_bytes()
            || &counterparty_id != request.counterparty().as_bytes()
        {
            return Err(InventoryError::Canonical);
        }
        let _authenticated_inventory = self.store.snapshot()?;
        self.store.audit_reservation_projection_set()?;
        let now = Self::unix_time()?;
        self.validate_policy_history()?;
        self.validate_budget_admission(&budget_key_id, &counterparty_id, now)?;

        // Random assignment occurs only after the complete authenticated
        // absence, budget, and clock admission scan.
        let reservation_id = random_nonzero::<32>()?;
        let authority = ReservationAuthorityV1::new(
            &binding,
            request_lookup,
            reservation_id,
            self.store.core.nonce_epoch(),
            &policy,
        )?;
        if &authority.as_bytes()[42..74] != request.key_id().as_bytes()
            || &authority.as_bytes()[106..138] != request.counterparty().as_bytes()
        {
            return Err(InventoryError::Canonical);
        }
        self.store.require_fresh_reservation_absence(&authority)?;
        let sequence = self
            .store
            .active_record()?
            .journal_sequence()
            .checked_add(1)
            .ok_or(InventoryError::Canonical)?;
        let claim = SessionClaimV1::new(authority.nonce_identity()?)?;
        let charge = BudgetChargeV1::new(&authority, now, sequence, &policy)?;
        let handle = self.store.persist_reservation(&claim, &charge)?;
        self.same_open_claims.insert(request_lookup);
        Ok(handle)
    }

    fn resume_claimed_reservation(
        &mut self,
        request: ReservationResumeRequestV1,
    ) -> Result<ReservationResumeResultV1<Self::ReservationHandle>, Self::Error> {
        let Some(authority) = self.authority_for_lookup(request.request_lookup())? else {
            return Ok(ReservationResumeResultV1::RetryNotFound);
        };
        if !Self::request_matches_authority(&request, &authority) {
            return Err(InventoryError::RestoreQuarantined);
        }
        self.store.require_reservation_projections(&authority)?;
        let identity = authority.nonce_identity()?;
        let identity_name = hex_lower(identity.as_bytes());
        if contains_component(
            &self.store.tombstones,
            &format!("{identity_name}.tombstone"),
        )? {
            let tombstone = self.store.read_authenticated_tombstone(&identity_name)?;
            let state = match tombstone.reason() {
                crate::TerminalReasonV1::Consumed => {
                    let spent = self.store.find_unique_exposure(
                        &identity,
                        ArtifactKindV1::PartialSignature,
                        ExposureStateV1::Spent,
                    )?;
                    let persisted = self.store.find_unique_exposure(
                        &identity,
                        ArtifactKindV1::PartialSignature,
                        ExposureStateV1::Persisted,
                    )?;
                    tombstone.validate_intervening_consumed(&persisted)?;
                    let _authorizing_ancestry = self.store.find_spent_authorizing_entry(&spent)?;
                    ReservationState::ConsumedPartialAuthorized
                }
                crate::TerminalReasonV1::AbortConsumed => {
                    let public_may_have_existed = self.store.exposure_occurs(
                        &identity,
                        ArtifactKindV1::Commitment,
                        Some(ExposureStateV1::Authorized),
                    )? || self.store.exposure_occurs(
                        &identity,
                        ArtifactKindV1::Commitment,
                        Some(ExposureStateV1::Spent),
                    )? || self.store.exposure_occurs(
                        &identity,
                        ArtifactKindV1::Reveal,
                        Some(ExposureStateV1::Authorized),
                    )? || self.store.exposure_occurs(
                        &identity,
                        ArtifactKindV1::Reveal,
                        Some(ExposureStateV1::Spent),
                    )?;
                    if public_may_have_existed {
                        ReservationState::ConsumedOnAbort
                    } else {
                        ReservationState::AbortedBeforePublicMaterial
                    }
                }
                crate::TerminalReasonV1::Burned => ReservationState::Burned,
            };
            return Ok(ReservationResumeResultV1::Terminal(TerminalReservationV1 {
                reservation_id: ReservationNonceId::from_bytes(
                    authority
                        .reservation_id()
                        .try_into()
                        .map_err(|_| InventoryError::Canonical)?,
                )
                .map_err(|_| InventoryError::Canonical)?,
                state,
            }));
        }
        let handle = self.handle_for_authority(&authority)?;
        let snapshot = self.store.snapshot_reservation(&handle)?;
        if snapshot.live_stage == AdaptorReservationLiveStageV1::PreDerivation
            && !self
                .same_open_claims
                .contains(request.request_lookup().as_bytes())
        {
            let state = self.store.persist_terminal_reservation(&handle, true)?;
            return Ok(ReservationResumeResultV1::Terminal(TerminalReservationV1 {
                reservation_id: snapshot.reservation_nonce_id,
                state,
            }));
        }
        Ok(ReservationResumeResultV1::Live(handle))
    }

    fn snapshot_reservation(
        &mut self,
        reservation: &Self::ReservationHandle,
    ) -> Result<Self::ReservationSnapshot, Self::Error> {
        self.store.snapshot_reservation(reservation)
    }

    fn begin_nonce_derivation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: NonceDerivationRequestV1,
    ) -> Result<Self::DerivationAttemptPermit, Self::Error> {
        let authority = self.store.revalidate_reservation_handle(reservation)?;
        self.store.require_pre_derivation_inventory(&authority)?;
        let view = request.validated_view();
        if view.stage() != VaultComputationStageV1::NonceDerivation
            || view.reservation_context_binding_digest()
                != authority.context_binding().context_binding_digest()
            || view.context().session_id() != authority.session_id()
            || view.context().purpose() != authority.purpose()
            || view.context().signing_phase() != SigningPhaseV1::SigNonceCommit
            || view.operation_input_digest() == &[0; 32]
        {
            return Err(InventoryError::Canonical);
        }
        let attempt = AttemptRecordV1::new(
            authority.nonce_identity()?,
            1,
            SigningPhaseV1::SigNonceCommit,
            *view.operation_input_digest(),
        )?;
        let derivation = NonceDerivationAttemptV1::new(&attempt, view.effective_retry_counter())?;
        self.store
            .persist_nonce_derivation_attempt(reservation, &derivation)?;
        Ok(DerivationAttemptPermitV1 {
            open_instance_id: self.store.open_instance_id,
            reservation_id: reservation.reservation_id,
            derivation,
            operation_input_digest: *view.operation_input_digest(),
            stage_context_digest: *view.operation_input_digest(),
        })
    }

    fn seal_derived_secret(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        attempt: Self::DerivationAttemptPermit,
        secret: NonceSecretTransferV1,
        seal_capability: VaultSecretSealCapabilityV1,
    ) -> Result<Self::InitialSecretOpenPermit, Self::Error> {
        if attempt.open_instance_id != self.store.open_instance_id
            || attempt.reservation_id != reservation.reservation_id
            || attempt.operation_input_digest
                != *attempt.derivation.attempt().operation_input_digest()
            || attempt.stage_context_digest != attempt.operation_input_digest
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let sealed = self.store.seal_nonce_secret_for_reservation(
            reservation,
            &attempt.derivation,
            secret,
            seal_capability,
        )?;
        Ok(InitialSecretOpenPermitV1 {
            sealed,
            derivation: attempt.derivation,
            operation_input_digest: attempt.operation_input_digest,
            stage_context_digest: attempt.stage_context_digest,
        })
    }

    fn open_sealed_secret_for_commitment(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::InitialSecretOpenPermit,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<(NonceSecretTransferV1, Self::ArtifactPersistencePermit), Self::Error> {
        let authority = self.store.revalidate_reservation_handle(reservation)?;
        let transfer =
            self.store
                .open_newly_sealed_secret(reservation, permit.sealed, import_capability)?;
        let attempt = permit.derivation.attempt().clone();
        let persistence = self.make_persistence_permit(
            &authority,
            &permit.derivation,
            attempt,
            permit.operation_input_digest,
            None,
        )?;
        if persistence.stage_context_digest != permit.stage_context_digest {
            return Err(InventoryError::RestoreQuarantined);
        }
        Ok((transfer, persistence))
    }

    fn begin_stage_computation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: StageComputationRequestV1,
    ) -> Result<Self::StageComputationPermit, Self::Error> {
        let authority = self.store.revalidate_reservation_handle(reservation)?;
        let view = request.validated_view();
        let (phase, artifact, preceding) = match view.stage() {
            VaultComputationStageV1::NonceReveal => (
                SigningPhaseV1::SigNonceReveal,
                ArtifactKindV1::Reveal,
                ArtifactKindV1::Commitment,
            ),
            VaultComputationStageV1::PartialAttempt => (
                SigningPhaseV1::SigPartial,
                ArtifactKindV1::PartialSignature,
                ArtifactKindV1::Reveal,
            ),
            VaultComputationStageV1::NonceDerivation => return Err(InventoryError::Canonical),
        };
        if view.reservation_context_binding_digest()
            != authority.context_binding().context_binding_digest()
            || view.context().session_id() != authority.session_id()
            || view.context().purpose() != authority.purpose()
            || view.context().signing_phase() != phase
            || view.operation_input_digest() == &[0; 32]
        {
            return Err(InventoryError::Canonical);
        }
        let preceding = self.store.find_unique_exposure(
            &authority.nonce_identity()?,
            preceding,
            ExposureStateV1::Spent,
        )?;
        let attempt = AttemptRecordV1::new(
            authority.nonce_identity()?,
            preceding.lifecycle_revision(),
            phase,
            *view.operation_input_digest(),
        )?;
        if attempt.artifact() != artifact {
            return Err(InventoryError::Canonical);
        }
        self.store.persist_stage_attempt(reservation, &attempt)?;
        Ok(StageComputationPermitV1 {
            open_instance_id: self.store.open_instance_id,
            reservation_id: reservation.reservation_id,
            attempt,
            operation_input_digest: *view.operation_input_digest(),
            stage_context_digest: *view.operation_input_digest(),
        })
    }

    fn open_secret_for_stage(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::StageComputationPermit,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<(NonceSecretTransferV1, Self::ArtifactPersistencePermit), Self::Error> {
        if permit.open_instance_id != self.store.open_instance_id
            || permit.reservation_id != reservation.reservation_id
            || permit.operation_input_digest != *permit.attempt.operation_input_digest()
            || permit.stage_context_digest != permit.operation_input_digest
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let authority = self.store.revalidate_reservation_handle(reservation)?;
        let identity_name = hex_lower(authority.nonce_identity()?.as_bytes());
        let derivation = read_nonce_derivation_attempt(self.store.attempts()?, &identity_name)?;
        let (transfer, retained) = self.store.open_secret_for_stage_attempt(
            reservation,
            &permit.attempt,
            import_capability,
        )?;
        let secret_for_deletion = if permit.attempt.artifact() == ArtifactKindV1::PartialSignature {
            Some(retained)
        } else {
            None
        };
        let persistence = self.make_persistence_permit(
            &authority,
            &derivation,
            permit.attempt,
            permit.operation_input_digest,
            secret_for_deletion,
        )?;
        Ok((transfer, persistence))
    }

    fn persist_computed_artifact(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::ArtifactPersistencePermit,
        artifact: PreparedExposureV1,
    ) -> Result<Self::PersistedExposureHandle, Self::Error> {
        if permit.open_instance_id != self.store.open_instance_id
            || permit.reservation_id.as_bytes() != &reservation.reservation_id
            || permit.stage_context_digest != permit.operation_input_digest
        {
            return Err(InventoryError::RestoreQuarantined);
        }
        let validated = validate_prepared_exposure_v1(&permit, &artifact)
            .map_err(|_| InventoryError::Canonical)?;
        let bytes = validated.outbound_bytes().to_vec();
        match permit.attempt.artifact() {
            ArtifactKindV1::Commitment | ArtifactKindV1::Reveal => {
                if permit.secret_for_deletion.is_some() {
                    return Err(InventoryError::RestoreQuarantined);
                }
                self.store
                    .persist_computed_public_artifact(reservation, &permit.attempt, &bytes)
            }
            ArtifactKindV1::PartialSignature => self.store.persist_consumed_partial(
                reservation,
                &permit.attempt,
                &bytes,
                permit
                    .secret_for_deletion
                    .ok_or(InventoryError::RestoreQuarantined)?,
            ),
        }
    }

    fn authorize_persisted_exposure(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        persisted: Self::PersistedExposureHandle,
    ) -> Result<Self::ExposurePermit, Self::Error> {
        self.store
            .authorize_persisted_public_exposure(reservation, persisted)
    }

    fn export(
        &mut self,
        permit: Self::ExposurePermit,
    ) -> Result<Self::ExportedArtifact, Self::Error> {
        self.store.export_public_artifact(permit)
    }

    fn recover_spent_artifact(
        &mut self,
        authorization: &AdaptorResendAuthorizationV1,
    ) -> Result<Self::RecoveredSpentArtifact, Self::Error> {
        self.store.recover_spent_artifact(authorization)
    }

    fn resend_exported(
        &mut self,
        request: ResendRequestV1,
    ) -> Result<Self::ExportedArtifact, Self::Error> {
        self.resend_exported_inner(request, || {
            #[cfg(all(test, feature = "evidence-only"))]
            run_resend_interposition()?;
            Ok(())
        })
    }

    fn cancel_reservation(
        &mut self,
        reservation: Self::ReservationHandle,
    ) -> Result<TerminalReservationV1, Self::Error> {
        let state = self
            .store
            .persist_terminal_reservation(&reservation, false)?;
        Ok(TerminalReservationV1 {
            reservation_id: ReservationNonceId::from_bytes(reservation.reservation_id)
                .map_err(|_| InventoryError::Canonical)?,
            state,
        })
    }

    fn restore_state(&self) -> RestoreState {
        if self.store.revalidate_complete_backup_authority().is_ok()
            && self.store.snapshot().is_ok()
            && self.validate_policy_history().is_ok()
        {
            RestoreState::Operational
        } else {
            RestoreState::RestoreQuarantined
        }
    }
}

impl RestartArtifactRecoveryVaultV1 for ContractsNonceVaultV1 {
    fn recover_spent_artifact_for_restart(
        &mut self,
        request: &RestartArtifactRecoveryRequestV1,
    ) -> Result<Self::RecoveredSpentArtifact, Self::Error> {
        self.store.recover_spent_artifact_for_restart(request)
    }
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], InventoryError> {
    loop {
        let mut bytes = [0_u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| InventoryError::RandomFailure)?;
        if bytes != [0; N] {
            return Ok(bytes);
        }
    }
}

fn artifact_to_exposure_kind(artifact: ArtifactKindV1) -> ExposureKindV1 {
    match artifact {
        ArtifactKindV1::Commitment => ExposureKindV1::NonceCommitment,
        ArtifactKindV1::Reveal => ExposureKindV1::NonceReveal,
        ArtifactKindV1::PartialSignature => ExposureKindV1::PartialSignature,
    }
}

fn adaptor_identity_from_store(
    identity: &NonceIdentityV1,
    reservation_context_binding_digest: [u8; 32],
) -> Result<AdaptorNonceIdentityV1, InventoryError> {
    let session_id = SessionId::from_bytes(
        identity
            .session_id()
            .try_into()
            .map_err(|_| InventoryError::Canonical)?,
    )
    .map_err(|_| InventoryError::Canonical)?;
    let participant_id = ParticipantId::from_bytes(
        identity
            .participant_id()
            .try_into()
            .map_err(|_| InventoryError::Canonical)?,
    )
    .map_err(|_| InventoryError::Canonical)?;
    AdaptorNonceIdentityV1::new(
        session_id,
        participant_id,
        identity.purpose(),
        reservation_context_binding_digest,
        identity.nonce_epoch(),
    )
    .map_err(|_| InventoryError::Canonical)
}

fn contains_component(
    directory: &RetainedDirectory,
    expected: &str,
) -> Result<bool, InventoryError> {
    let mut found = false;
    directory.scan_independent(|name, _| {
        if name == expected {
            if found {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            }
            found = true;
        }
        Ok(())
    })?;
    Ok(found)
}

fn open_or_create_projection_directory(
    parent: &RetainedDirectory,
    name: &str,
) -> Result<RetainedDirectory, InventoryError> {
    let component = ValidatedComponent::registered(name)?;
    match parent.create_child_directory(component.clone()) {
        Ok(directory) => Ok(directory),
        Err(LinuxCapabilityError::AlreadyExists) => Ok(parent.open_child_directory(component)?),
        Err(error) => Err(error.into()),
    }
}

fn persist_attempt_projection(
    attempts: &RetainedDirectory,
    bytes: &[u8],
) -> Result<(), InventoryError> {
    let structural = if bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
        let derivation = NonceDerivationAttemptV1::from_bytes(bytes)?;
        UnauthenticatedAttemptRecordV1::parse_structural(derivation.attempt().as_bytes())?
    } else {
        UnauthenticatedAttemptRecordV1::parse_structural(bytes)?
    };
    let path = canonical_attempt_relative_path(&structural);
    let (identity, file) = path.split_once('/').ok_or(InventoryError::Canonical)?;
    let identity_directory = open_or_create_projection_directory(attempts, identity)?;
    identity_directory.create_immutable_file(&ValidatedComponent::registered(file)?, bytes)?;
    Ok(())
}

fn persist_exposure_projection(
    exposures: &RetainedDirectory,
    exposure: &ExposureRecordV1,
) -> Result<(), InventoryError> {
    let structural = crate::UnauthenticatedExposureRecordV1::parse_structural(exposure.as_bytes())?;
    let path = canonical_exposure_relative_path(&structural);
    let mut components = path.split('/');
    let identity = components.next().ok_or(InventoryError::Canonical)?;
    let sequence = components.next().ok_or(InventoryError::Canonical)?;
    let file = components.next().ok_or(InventoryError::Canonical)?;
    if components.next().is_some() {
        return Err(InventoryError::Canonical);
    }
    let identity_directory = open_or_create_projection_directory(exposures, identity)?;
    let sequence_directory = open_or_create_projection_directory(&identity_directory, sequence)?;
    sequence_directory
        .create_immutable_file(&ValidatedComponent::registered(file)?, exposure.as_bytes())?;
    Ok(())
}

struct JournalAudit {
    entry_count: u64,
    sequence: u64,
    head_digest: [u8; 32],
    head: Option<JournalEntryV1>,
    entries: Vec<JournalEntryV1>,
    composite: restore::AuthenticatedCompositeJournalV1,
    terminals: BTreeMap<[u8; 105], TombstoneV1>,
}

fn audit_journal(
    directory: &RetainedDirectory,
    terminals: &BTreeMap<[u8; 105], TombstoneV1>,
) -> Result<JournalAudit, InventoryError> {
    let mut encoded_entries = Vec::new();
    directory.scan_lexicographic(|name, _| {
        let bytes = directory.read_bounded_file(
            &ValidatedComponent::registered(name)?,
            JOURNAL_ENTRY_MAX_LEN,
        )?;
        let structural = UnauthenticatedJournalEntryV1::parse_structural(&bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let envelope = structural.envelope();
        if canonical_journal_filename(envelope) != name {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        encoded_entries.push(bytes);
        Ok(())
    })?;
    let composite = restore::authenticate_composite_journal(&encoded_entries, terminals)?;
    let (sequence, head_digest) = match composite.head() {
        Some(head) => (head.sequence(), *head.entry_digest()),
        None => (0, [0; 32]),
    };
    let head = composite.head().cloned();
    let entries = composite.entries().to_vec();
    Ok(JournalAudit {
        entry_count: u64::try_from(composite.entries().len())
            .map_err(|_| InventoryError::Canonical)?,
        sequence,
        head_digest,
        head,
        entries,
        composite,
        terminals: terminals.clone(),
    })
}

fn require_normal_root_inventory(root: &RetainedDirectory) -> Result<(), InventoryError> {
    let mut fixed = [false; 3];
    let mut generation_count = 0_u64;
    let mut incomplete_transaction = false;
    root.scan_independent(|name, identity| {
        match name {
            ROOT_IDENTITY => fixed[0] = identity.node_type == ExpectedNodeType::RegularFile,
            LOCK_IDENTITY => fixed[1] = identity.node_type == ExpectedNodeType::RegularFile,
            ACTIVE_GENERATION => fixed[2] = identity.node_type == ExpectedNodeType::RegularFile,
            ".active-vault-generation.staging" | "restore-pending" => {
                incomplete_transaction = true;
            }
            "restore-only-root.bin" => {
                if identity.node_type != ExpectedNodeType::RegularFile {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
            }
            value if value.starts_with("restore-initialized-") => {
                if identity.node_type != ExpectedNodeType::RegularFile
                    || ValidatedComponent::registered(value).is_err()
                {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
            }
            value if value.starts_with("generation-") => {
                if identity.node_type != ExpectedNodeType::Directory
                    || ValidatedComponent::registered(value).is_err()
                {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                generation_count = generation_count
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            }
            value
                if value.starts_with(".generation-")
                    || value.starts_with(".backup-")
                    || value.starts_with(".restore-") =>
            {
                ValidatedComponent::registered(value)?;
                incomplete_transaction = true;
            }
            value if value.starts_with("backup-") || value.starts_with("restore-complete-") => {
                if identity.node_type != ExpectedNodeType::Directory
                    || ValidatedComponent::registered(value).is_err()
                {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
            }
            _ => return Err(LinuxCapabilityError::InvalidDirectoryEntry),
        }
        Ok(())
    })?;
    if fixed == [true; 3] && generation_count != 0 && !incomplete_transaction {
        Ok(())
    } else {
        Err(InventoryError::RestoreQuarantined)
    }
}

#[cfg(any(test, feature = "evidence-only"))]
fn require_existing_restore_target_branch(root: &RetainedDirectory) -> Result<(), InventoryError> {
    require_normal_root_inventory(root)?;
    let mut restore_only_marker = false;
    root.scan_independent(|name, _| {
        if name == "restore-only-root.bin" {
            restore_only_marker = true;
        }
        Ok(())
    })?;
    if restore_only_marker {
        Err(InventoryError::RestoreQuarantined)
    } else {
        Ok(())
    }
}

pub(super) fn require_generation_inventory(
    generation: &RetainedDirectory,
) -> Result<(), InventoryError> {
    let entries = [
        (GENERATION_CORE, ExpectedNodeType::RegularFile, true),
        (MASTER_KEY_ENVELOPE, ExpectedNodeType::RegularFile, true),
        ("journal", ExpectedNodeType::Directory, true),
        ("tombstones", ExpectedNodeType::Directory, true),
        (
            "reservation-authorities",
            ExpectedNodeType::Directory,
            false,
        ),
        ("session-claims", ExpectedNodeType::Directory, false),
        ("budget-charges", ExpectedNodeType::Directory, false),
        ("attempts", ExpectedNodeType::Directory, false),
        ("exposures", ExpectedNodeType::Directory, false),
        ("nonce-secrets", ExpectedNodeType::Directory, false),
        ("collaborative-secrets", ExpectedNodeType::Directory, false),
    ];
    let mut seen = [false; 11];
    generation.scan_independent(|name, identity| {
        let Some(index) = entries
            .iter()
            .position(|(entry_name, _, _)| *entry_name == name)
        else {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        };
        if seen[index] || identity.node_type != entries[index].1 {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        seen[index] = true;
        Ok(())
    })?;
    if entries
        .iter()
        .enumerate()
        .all(|(index, (_, _, required))| !required || seen[index])
    {
        Ok(())
    } else {
        Err(InventoryError::RestoreQuarantined)
    }
}

fn open_namespace(
    generation: &RetainedDirectory,
    name: &str,
) -> Result<RetainedDirectory, InventoryError> {
    Ok(generation.open_child_directory(ValidatedComponent::registered(name)?)?)
}

fn open_optional_namespace(
    generation: &RetainedDirectory,
    name: &str,
) -> Result<Option<RetainedDirectory>, InventoryError> {
    let component = ValidatedComponent::registered(name)?;
    match generation.open_child_directory(component) {
        Ok(directory) => Ok(Some(directory)),
        Err(LinuxCapabilityError::NotFound) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn ensure_optional_namespace(
    generation: &RetainedDirectory,
    slot: &mut Option<RetainedDirectory>,
    name: &str,
) -> Result<(), InventoryError> {
    if slot.is_some() {
        return Ok(());
    }
    let directory = generation.create_child_directory(ValidatedComponent::registered(name)?)?;
    directory.sync()?;
    *slot = Some(directory);
    Ok(())
}

fn audit_optional_namespace(
    directory: Option<&RetainedDirectory>,
    audit: fn(&RetainedDirectory) -> Result<u64, InventoryError>,
) -> Result<u64, InventoryError> {
    match directory {
        Some(directory) => audit(directory),
        None => Ok(0),
    }
}

fn audit_authorities(directory: &RetainedDirectory) -> Result<u64, InventoryError> {
    audit_flat(
        directory,
        RESERVATION_AUTHORITY_ADAPTOR_LEN,
        |name, bytes| {
            let authority = ReservationAuthorityV1::from_bytes(bytes)?;
            Ok(name == format!("{}.authority", hex_lower(authority.reservation_id())))
        },
    )
}

fn audit_claims(directory: &RetainedDirectory) -> Result<u64, InventoryError> {
    audit_flat(directory, SESSION_CLAIM_LEN, |name, bytes| {
        let claim = SessionClaimV1::from_bytes(bytes)?;
        Ok(name == format!("{}.claim", hex_lower(claim.identity().session_id())))
    })
}

fn audit_charges(directory: &RetainedDirectory) -> Result<u64, InventoryError> {
    audit_flat(directory, BUDGET_CHARGE_ADAPTOR_LEN, |name, bytes| {
        let charge = BudgetChargeV1::from_bytes(bytes)?;
        Ok(name
            == format!(
                "{:020}-{}.charge",
                charge.reserve_journal_sequence(),
                hex_lower(charge.reservation_authority().reservation_id())
            ))
    })
}

fn audit_attempts(directory: &RetainedDirectory) -> Result<u64, InventoryError> {
    let mut count = 0_u64;
    directory.scan_lexicographic(|identity_name, identity_node| {
        if identity_node.node_type != ExpectedNodeType::Directory {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let identity_directory =
            directory.open_child_directory(ValidatedComponent::registered(identity_name)?)?;
        let before = count;
        identity_directory.scan_lexicographic(|record_name, _| {
            let component = ValidatedComponent::registered(record_name)?;
            let bytes =
                identity_directory.read_bounded_file(&component, NONCE_DERIVATION_ATTEMPT_LEN)?;
            let structural = if bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
                NonceDerivationAttemptV1::from_bytes(&bytes)
                    .map(|attempt| {
                        UnauthenticatedAttemptRecordV1::parse_structural(
                            attempt.attempt().as_bytes(),
                        )
                    })
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
            } else if bytes.len() == ATTEMPT_RECORD_LEN {
                UnauthenticatedAttemptRecordV1::parse_structural(&bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
            } else {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            };
            let expected = canonical_attempt_relative_path(&structural);
            if expected != format!("{identity_name}/{record_name}") {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            count = count
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            Ok(())
        })?;
        if count == before {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        Ok(())
    })?;
    Ok(count)
}

fn audit_exposures(directory: &RetainedDirectory) -> Result<u64, InventoryError> {
    let mut count = 0_u64;
    scan_exposure_records(directory, |_| {
        count = count
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
        Ok(())
    })?;
    Ok(count)
}

fn audit_exposure_chains(
    exposures: &RetainedDirectory,
    attempts: &RetainedDirectory,
    read_tombstone: &mut impl FnMut(&str) -> Result<TombstoneV1, LinuxCapabilityError>,
) -> Result<(), InventoryError> {
    exposures.scan_lexicographic(|identity_name, identity_node| {
        if identity_node.node_type != ExpectedNodeType::Directory {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let identity_directory =
            exposures.open_child_directory(ValidatedComponent::registered(identity_name)?)?;
        let mut versions: [Option<ExposureRecordV1>; 9] = std::array::from_fn(|_| None);
        identity_directory.scan_lexicographic(|sequence_name, sequence_node| {
            if sequence_node.node_type != ExpectedNodeType::Directory {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let sequence_directory = identity_directory
                .open_child_directory(ValidatedComponent::registered(sequence_name)?)?;
            sequence_directory.scan_lexicographic(|record_name, _| {
                let bytes = sequence_directory.read_bounded_file(
                    &ValidatedComponent::registered(record_name)?,
                    crate::EXPOSURE_RECORD_MAX_LEN,
                )?;
                let exposure = ExposureRecordV1::from_bytes(&bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let sequence_index = usize::try_from(
                    exposure
                        .sequence()
                        .checked_sub(1)
                        .ok_or(LinuxCapabilityError::ExactBytesMismatch)?,
                )
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let state_index = usize::from(exposure.state() as u8 - 1);
                let index = sequence_index
                    .checked_mul(3)
                    .and_then(|offset| offset.checked_add(state_index))
                    .filter(|index| *index < versions.len())
                    .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
                if versions[index].replace(exposure).is_some() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                Ok(())
            })
        })?;

        for sequence_index in 0..3 {
            let base = sequence_index * 3;
            let persisted = versions[base].as_ref();
            let authorized = versions[base + 1].as_ref();
            let spent = versions[base + 2].as_ref();
            if (persisted.is_none() && (authorized.is_some() || spent.is_some()))
                || (authorized.is_none() && spent.is_some())
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            let Some(persisted) = persisted else {
                continue;
            };
            let attempt = read_attempt_for_artifact(attempts, identity_name, persisted.artifact())?;
            let preceding_spent = if sequence_index == 0 {
                None
            } else {
                versions[(sequence_index - 1) * 3 + 2].as_ref()
            };
            persisted
                .validate_persisted_context(&attempt, preceding_spent)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if let Some(authorized) = authorized {
                let tombstone = if persisted.artifact() == ArtifactKindV1::PartialSignature {
                    Some(read_tombstone(identity_name)?)
                } else {
                    None
                };
                authorized
                    .validate_successor(persisted, tombstone.as_ref())
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if let Some(spent) = spent {
                    spent
                        .validate_successor(authorized, None)
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                }
            }
        }
        Ok(())
    })?;
    Ok(())
}

fn read_attempt_for_artifact(
    attempts: &RetainedDirectory,
    identity_name: &str,
    artifact: ArtifactKindV1,
) -> Result<crate::AttemptRecordV1, LinuxCapabilityError> {
    let identity_directory =
        attempts.open_child_directory(ValidatedComponent::registered(identity_name)?)?;
    let mut match_found: Option<crate::AttemptRecordV1> = None;
    identity_directory.scan_lexicographic(|record_name, _| {
        let bytes = identity_directory.read_bounded_file(
            &ValidatedComponent::registered(record_name)?,
            NONCE_DERIVATION_ATTEMPT_LEN,
        )?;
        let attempt = if bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
            NonceDerivationAttemptV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                .attempt()
                .clone()
        } else {
            crate::AttemptRecordV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
        };
        if attempt.artifact() == artifact {
            if match_found.is_some() {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            match_found = Some(attempt);
        }
        Ok(())
    })?;
    match_found.ok_or(LinuxCapabilityError::ExactBytesMismatch)
}

fn read_nonce_derivation_attempt(
    attempts: &RetainedDirectory,
    identity_name: &str,
) -> Result<NonceDerivationAttemptV1, LinuxCapabilityError> {
    let identity_directory =
        attempts.open_child_directory(ValidatedComponent::registered(identity_name)?)?;
    let mut match_found: Option<NonceDerivationAttemptV1> = None;
    identity_directory.scan_lexicographic(|record_name, _| {
        let bytes = identity_directory.read_bounded_file(
            &ValidatedComponent::registered(record_name)?,
            NONCE_DERIVATION_ATTEMPT_LEN,
        )?;
        if bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
            let derivation = NonceDerivationAttemptV1::from_bytes(&bytes)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if match_found.is_some() {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            match_found = Some(derivation);
        }
        Ok(())
    })?;
    match_found.ok_or(LinuxCapabilityError::ExactBytesMismatch)
}

pub(super) fn scan_exposure_records<F>(
    directory: &RetainedDirectory,
    mut inspect: F,
) -> Result<(), InventoryError>
where
    F: FnMut(&ExposureRecordV1) -> Result<(), LinuxCapabilityError>,
{
    directory.scan_lexicographic(|identity_name, identity_node| {
        if identity_node.node_type != ExpectedNodeType::Directory {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let identity_directory =
            directory.open_child_directory(ValidatedComponent::registered(identity_name)?)?;
        let mut identity_count = 0_u64;
        identity_directory.scan_lexicographic(|sequence_name, sequence_node| {
            if sequence_node.node_type != ExpectedNodeType::Directory {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let sequence_directory = identity_directory
                .open_child_directory(ValidatedComponent::registered(sequence_name)?)?;
            let mut sequence_count = 0_u64;
            sequence_directory.scan_lexicographic(|record_name, _| {
                let bytes = sequence_directory.read_bounded_file(
                    &ValidatedComponent::registered(record_name)?,
                    crate::EXPOSURE_RECORD_MAX_LEN,
                )?;
                let exposure = ExposureRecordV1::from_bytes(&bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let structural =
                    crate::UnauthenticatedExposureRecordV1::parse_structural(exposure.as_bytes())
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                let expected = canonical_exposure_relative_path(&structural);
                if expected != format!("{identity_name}/{sequence_name}/{record_name}") {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                inspect(&exposure)?;
                identity_count = identity_count
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                sequence_count = sequence_count
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                Ok(())
            })?;
            if sequence_count == 0 {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            }
            Ok(())
        })?;
        if identity_count == 0 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        Ok(())
    })?;
    Ok(())
}

fn derive_permit_id(
    exposure: &ExposureRecordV1,
    authorizing_journal_digest: [u8; 32],
) -> Result<PermitIdV1, LinuxCapabilityError> {
    let version_id = exposure.version_id();
    let mut preimage = [0_u8; 187];
    preimage[..155].copy_from_slice(version_id.as_bytes());
    preimage[155..].copy_from_slice(&authorizing_journal_digest);
    PermitIdV1::from_bytes(authoritative_storage_hash_v1(
        StorageHashDomainV1::ExportPermitId,
        &preimage,
    ))
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
}

fn audit_flat<F>(
    directory: &RetainedDirectory,
    maximum_length: usize,
    mut validate: F,
) -> Result<u64, InventoryError>
where
    F: FnMut(&str, &[u8]) -> Result<bool, CanonicalCodecError>,
{
    let mut count = 0_u64;
    directory.scan_lexicographic(|name, node| {
        if node.node_type != ExpectedNodeType::RegularFile {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let bytes =
            directory.read_bounded_file(&ValidatedComponent::registered(name)?, maximum_length)?;
        if !validate(name, &bytes).map_err(|_| LinuxCapabilityError::ExactBytesMismatch)? {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        count = count
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
        Ok(())
    })?;
    Ok(count)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AttemptRecordV1, JournalEntryV1, JournalPayloadV1, NonceDerivationAttemptV1, PurposeV1,
        SigningPhaseV1, UnauthenticatedJournalEnvelopeV1,
    };
    use dom_scriptless_crypto::{
        generate_vault_master_key, seal_master_key, Passphrase, StorageIdsV1,
    };
    use static_assertions::assert_not_impl_any;
    use std::{
        fs::{self, File},
        os::unix::{fs::PermissionsExt, process::ExitStatusExt},
        path::{Path, PathBuf},
        process::{self, Command},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc as StdArc, Barrier,
        },
        thread,
        time::Duration,
    };

    assert_not_impl_any!(ReservationHandleV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(ReservationSnapshotV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(AdaptorResendAuthorizationV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(RecoveredSpentArtifactV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(PersistedExposureHandleV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(DerivationAttemptPermitV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(InitialSecretOpenPermitV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(StageComputationPermitV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(ArtifactPersistencePermitV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(ExposurePermitV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(ExportedArtifactV1: Clone, Copy, fmt::Debug, fmt::Display);
    assert_not_impl_any!(RetainedRestoreTargetV1: Clone, Copy, fmt::Debug, fmt::Display);

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Result<Self, Box<dyn Error>> {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "dom-contracts-inventory-test-{}-{sequence}",
                    process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                        return Ok(Self { path });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(Box::new(error)),
                }
            }
        }

        fn capability(&self) -> Result<Arc<Dir>, Box<dyn Error>> {
            Ok(Arc::new(Dir::from_std_file(File::open(&self.path)?)))
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct InitializedStore {
        temporary: TestDirectory,
        root: RetainedDirectory,
        generation: RetainedDirectory,
        core: VaultGenerationCoreV1,
    }

    fn initialize() -> Result<InitializedStore, Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let root = RetainedDirectory::create_under(
            temporary.capability()?,
            ValidatedComponent::operator_selected_root("contracts-store")?,
        )?;
        let root_identity = StoreRootIdentityV1::new([0x11; 32], [0x22; 32], [0x33; 16])?;
        let lock_identity = StoreLockIdentityV1::from_root(&root_identity)?;
        root.create_immutable_file(
            &ValidatedComponent::registered(ROOT_IDENTITY)?,
            root_identity.as_bytes(),
        )?;
        root.create_immutable_file(
            &ValidatedComponent::registered(LOCK_IDENTITY)?,
            lock_identity.as_bytes(),
        )?;

        let ids = StorageIdsV1::new([0x11; 32], [0x44; 32])?;
        let master_key = generate_vault_master_key()?;
        let passphrase = Passphrase::new(b"inventory-test-passphrase".to_vec())?;
        let envelope = seal_master_key(ids, &passphrase, &master_key)?;
        let master_digest =
            authoritative_storage_hash_v1(StorageHashDomainV1::MasterEnvelope, envelope.as_bytes());
        let core =
            VaultGenerationCoreV1::new([0x11; 32], [0x22; 32], [0x44; 32], 1, 1, master_digest)?;
        let structural = UnauthenticatedVaultGenerationCoreV1::parse_structural(core.as_bytes())?;
        let generation = root.create_child_directory(ValidatedComponent::registered(
            &canonical_generation_directory_name(&structural),
        )?)?;
        generation.create_immutable_file(
            &ValidatedComponent::registered(GENERATION_CORE)?,
            core.as_bytes(),
        )?;
        generation.create_immutable_file(
            &ValidatedComponent::registered(MASTER_KEY_ENVELOPE)?,
            envelope.as_bytes(),
        )?;
        for name in [
            "journal",
            "reservation-authorities",
            "session-claims",
            "budget-charges",
            "attempts",
            "exposures",
            "nonce-secrets",
            "tombstones",
        ] {
            generation.create_child_directory(ValidatedComponent::registered(name)?)?;
        }
        let active = ActiveVaultGenerationV1::new(&core, 0, [0; 32])?;
        root.create_immutable_file(
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            active.as_bytes(),
        )?;
        Ok(InitializedStore {
            temporary,
            root,
            generation,
            core,
        })
    }

    #[test]
    fn canonical_create_then_reopen_uses_only_authoritative_records() -> Result<(), Box<dyn Error>>
    {
        let temporary = TestDirectory::create()?;
        let ids = StorageIdsV1::new([0x11; 32], [0x44; 32])?;
        let passphrase = Passphrase::new(b"canonical-store-test-passphrase".to_vec())?;
        let created = LiveStoreInventoryV1::create(
            temporary.capability()?,
            "contracts-store",
            ids,
            &passphrase,
        )?;
        let snapshot = created.snapshot()?;
        assert_eq!(snapshot.journal_sequence, 0);
        assert_eq!(snapshot.journal_head_digest, [0; 32]);
        let expected_generation = canonical_generation_directory_name(
            &UnauthenticatedVaultGenerationCoreV1::parse_structural(created.core.as_bytes())?,
        );
        let mut saw_generation = false;
        created.root.scan_independent(|name, _| {
            if name == expected_generation {
                saw_generation = true;
            }
            if name.starts_with(".generation-") || name == ".active-vault-generation.staging" {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            }
            Ok(())
        })?;
        assert!(saw_generation);
        drop(created);

        let reopened =
            LiveStoreInventoryV1::open(temporary.capability()?, "contracts-store", passphrase)?;
        let reopened_snapshot = reopened.snapshot()?;
        assert_eq!(reopened_snapshot.journal_sequence, 0);
        assert_eq!(reopened_snapshot.journal_head_digest, [0; 32]);
        Ok(())
    }

    #[test]
    fn canonical_backup_is_fully_staged_verified_and_reopenable() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let ids = StorageIdsV1::new([0x71; 32], [0x72; 32])?;
        let unlock = Passphrase::new(b"canonical-backup-unlock-passphrase".to_vec())?;
        let mut store =
            LiveStoreInventoryV1::create(temporary.capability()?, "contracts-store", ids, &unlock)?;
        let backup = store.create_backup(
            Passphrase::new(b"independent-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(0, 4)?,
        )?;
        assert_eq!(backup.backup_generation(), 1);
        assert_ne!(backup.backup_id(), ids.contract_wallet_id());
        assert_ne!(backup.backup_id(), ids.vault_id());
        assert_ne!(backup.bundle_digest(), &[0; 32]);
        let backup_name = format!(
            "backup-{:020}-{}",
            backup.backup_generation(),
            hex_lower(backup.backup_id())
        );
        let completed = store
            .root
            .open_child_directory(ValidatedComponent::registered(&backup_name)?)?;
        let expected = BTreeSet::from([
            "backup-master-key.envelope".to_owned(),
            "backup-manifest.object".to_owned(),
            "backup-bundle.digest".to_owned(),
            "journal".to_owned(),
            "records".to_owned(),
        ]);
        let mut found = BTreeSet::new();
        completed.scan_independent(|name, _| {
            found.insert(name.to_owned());
            Ok(())
        })?;
        assert_eq!(found, expected);
        drop(store);

        let reopened =
            LiveStoreInventoryV1::open(temporary.capability()?, "contracts-store", unlock)?;
        reopened.snapshot()?;
        Ok(())
    }

    #[test]
    fn canonical_backup_contains_authenticated_nonempty_record_set() -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let reservation =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0xa1, 0xb1)?;
        append_reservations(&initialized, &[reservation])?;
        let mut store = open_store(&initialized.temporary)?;
        let completed = store.create_backup(
            Passphrase::new(b"nonempty-independent-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(1, 318)?,
        )?;
        assert_eq!(completed.backup_generation(), 1);
        let name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        let backup = store
            .root
            .open_child_directory(ValidatedComponent::registered(&name)?)?;
        let records = backup.open_child_directory(ValidatedComponent::registered("records")?)?;
        let mut identity_directories = 0_u64;
        records.scan_independent(|_, node| {
            if node.node_type != ExpectedNodeType::Directory {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            identity_directories += 1;
            Ok(())
        })?;
        assert_eq!(identity_directories, 1);
        Ok(())
    }

    fn overwrite_immutable_test_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        fs::write(path, bytes)?;
        Ok(())
    }

    #[test]
    fn completed_history_rejects_journal_name_content_mismatch() -> Result<(), Box<dyn Error>> {
        let fixture = backup_crash_fixture()?;
        let mut store = open_store(&fixture.initialized.temporary)?;
        let completed = store.create_backup(
            Passphrase::new(b"journal-mismatch-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        let journal = fixture
            .initialized
            .temporary
            .path()
            .join("contracts-store")
            .join(backup_name)
            .join("journal");
        let mut files = fs::read_dir(&journal)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        files.sort();
        let left = fs::read(&files[0])?;
        let right = fs::read(&files[1])?;
        assert_eq!(left.len(), right.len());
        overwrite_immutable_test_file(&files[0], &right)?;
        overwrite_immutable_test_file(&files[1], &left)?;
        assert!(backup::authenticate_completed_history(&store.root).is_err());
        Ok(())
    }

    #[test]
    fn completed_history_rejects_rehashed_but_unlinked_journal_entry() -> Result<(), Box<dyn Error>>
    {
        let fixture = backup_crash_fixture()?;
        let mut store = open_store(&fixture.initialized.temporary)?;
        let completed = store.create_backup(
            Passphrase::new(b"journal-link-mismatch-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        let journal = fixture
            .initialized
            .temporary
            .path()
            .join("contracts-store")
            .join(backup_name)
            .join("journal");
        let mut files = fs::read_dir(&journal)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        files.sort();
        let original = files.get(1).ok_or(InventoryError::Canonical)?;
        let mut bytes = fs::read(original)?;
        bytes[18] ^= 0x01;
        let digest_offset = bytes
            .len()
            .checked_sub(32)
            .ok_or(InventoryError::Canonical)?;
        let digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::JournalEntry,
            &bytes[..digest_offset],
        );
        bytes[digest_offset..].copy_from_slice(&digest);
        let structural = UnauthenticatedJournalEntryV1::parse_structural(&bytes)?;
        let replacement = journal.join(canonical_journal_filename(structural.envelope()));
        overwrite_immutable_test_file(original, &bytes)?;
        fs::rename(original, replacement)?;
        assert!(backup::authenticate_completed_history(&store.root).is_err());
        Ok(())
    }

    #[test]
    fn completed_history_rejects_record_path_content_mismatch() -> Result<(), Box<dyn Error>> {
        let fixture = backup_crash_fixture()?;
        let mut store = open_store(&fixture.initialized.temporary)?;
        let completed = store.create_backup(
            Passphrase::new(b"record-mismatch-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        let records = fixture
            .initialized
            .temporary
            .path()
            .join("contracts-store")
            .join(backup_name)
            .join("records");
        let mut claims = Vec::new();
        for identity in fs::read_dir(records)? {
            let identity = identity?;
            for record in fs::read_dir(identity.path())? {
                let path = record?.path();
                if fs::metadata(&path)?.len() as usize == SESSION_CLAIM_LEN {
                    claims.push(path);
                }
            }
        }
        claims.sort();
        assert_eq!(claims.len(), 2);
        let left = fs::read(&claims[0])?;
        let right = fs::read(&claims[1])?;
        assert_eq!(left.len(), right.len());
        overwrite_immutable_test_file(&claims[0], &right)?;
        overwrite_immutable_test_file(&claims[1], &left)?;
        assert!(backup::authenticate_completed_history(&store.root).is_err());
        Ok(())
    }

    #[test]
    fn selected_backup_loader_authenticates_complete_dag_without_mutation(
    ) -> Result<(), Box<dyn Error>> {
        let fixture = backup_crash_fixture()?;
        let mut store = open_store(&fixture.initialized.temporary)?;
        let completed = store.create_backup(
            Passphrase::new(b"selected-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        let root_path = fixture.initialized.temporary.path().join("contracts-store");
        let before = snapshot_regular_files(&root_path)?;
        let selected = crate::runtime::linux::restore::authenticate_selected_backup(
            &store.root,
            &backup_name,
            Passphrase::new(b"selected-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        assert_eq!(selected.backup_generation(), 1);
        assert_eq!(selected.backup_id(), completed.backup_id());
        assert!(selected.storage_ids() == store.storage_ids()?);
        assert_eq!(selected.manifest().backup_generation(), 1);
        assert_eq!(selected.bundle().bundle_digest(), completed.bundle_digest());
        assert_eq!(selected.journal_entries().len(), 4);
        assert_eq!(selected.record_set().record_count(), 4);
        let _retained_secret_authority = selected.backup_master_key();
        assert_eq!(
            selected.master_envelope().as_bytes().len(),
            backup::MASTER_ENVELOPE_LEN
        );
        assert_eq!(
            selected.manifest_envelope().as_bytes().len(),
            backup::MANIFEST_ENVELOPE_LEN
        );
        let new_device = restore::NewDeviceRestorePreparationV1::new(selected)?;
        assert_eq!(new_device.successor_epoch(), 2);
        assert_eq!(new_device.successor_generation(), 1);
        assert_eq!(new_device.source().backup_id(), completed.backup_id());
        assert_eq!(new_device.terminal_union().len(), 2);
        assert_eq!(new_device.budget_carries().len(), 2);
        assert!(new_device.permit_carries().is_empty());
        assert!(new_device
            .budget_carries()
            .windows(2)
            .all(|pair| pair[0].reservation_authority().reservation_id()
                < pair[1].reservation_authority().reservation_id()));
        assert_eq!(
            new_device
                .terminal_union()
                .iter()
                .filter(|record| record.action() == crate::RestoreActionV1::PreserveTerminal)
                .count(),
            1
        );
        assert_eq!(
            new_device
                .terminal_union()
                .iter()
                .filter(|record| record.action() == crate::RestoreActionV1::Burn)
                .count(),
            1
        );
        assert!(new_device
            .terminal_union()
            .iter()
            .all(|record| { record.result().reason() == crate::TerminalReasonV1::Burned }));
        let successor_ids = StorageIdsV1::new(
            *store.storage_ids()?.contract_wallet_id(),
            *generate_storage_ids()?.vault_id(),
        )?;
        let successor_master_key = generate_vault_master_key()?;
        let successor_terminals = restore::SuccessorTerminalMaterialV1::new(
            new_device.terminal_union(),
            successor_ids,
            &successor_master_key,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        assert_eq!(successor_terminals.record_set().record_count(), 2);
        assert_eq!(successor_terminals.envelopes().len(), 2);
        assert_ne!(successor_terminals.envelope_set_digest(), &[0; 32]);
        for record in new_device.terminal_union() {
            let plaintext = TombstonePlaintextV1::from_bytes(record.result().as_bytes())?;
            let metadata = TombstoneRecordMetadataV1::from_tombstone(&plaintext)?;
            let opened = open_tombstone_v1(
                successor_terminals
                    .envelopes()
                    .get(record.identity().as_bytes())
                    .ok_or("missing successor tombstone envelope")?,
                successor_ids,
                &successor_master_key,
                metadata,
            )?;
            assert_eq!(opened.as_bytes(), record.result().as_bytes());
        }
        assert_eq!(snapshot_regular_files(&root_path)?, before);
        assert!(
            crate::runtime::linux::restore::authenticate_selected_backup(
                &store.root,
                &backup_name,
                Passphrase::new(b"incorrect-selected-backup-passphrase".to_vec())?,
                BackupPolicyLimitsV1::new(64, 1_048_576)?,
            )
            .is_err()
        );
        assert_eq!(snapshot_regular_files(&root_path)?, before);
        let prepared = store.prepare_existing_device_restore_material(
            &store.root,
            &backup_name,
            Passphrase::new(b"selected-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        assert_eq!(
            prepared.contract_wallet_id(),
            store.storage_ids()?.contract_wallet_id()
        );
        assert_eq!(prepared.target_vault_id(), store.storage_ids()?.vault_id());
        assert_eq!(prepared.target_epoch(), store.core.nonce_epoch());
        assert_eq!(prepared.target_journal_sequence(), 4);
        assert_ne!(prepared.target_journal_head_digest(), &[0; 32]);
        assert_eq!(prepared.target_generation(), store.core.vault_generation());
        assert_eq!(prepared.successor_epoch(), 2);
        assert_eq!(prepared.successor_generation(), 2);
        assert_eq!(prepared.source().backup_id(), completed.backup_id());
        assert_eq!(prepared.terminal_union().len(), 2);
        assert!(prepared.budget_carries().is_empty());
        assert!(prepared.permit_carries().is_empty());
        assert_eq!(
            prepared
                .terminal_union()
                .iter()
                .filter(|record| record.action() == crate::RestoreActionV1::PreserveTerminal)
                .count(),
            1
        );
        assert_eq!(
            prepared
                .terminal_union()
                .iter()
                .filter(|record| record.action() == crate::RestoreActionV1::Burn)
                .count(),
            1
        );
        assert!(prepared
            .terminal_union()
            .iter()
            .all(|record| record.result().reason() == crate::TerminalReasonV1::Burned));
        assert_eq!(
            prepared
                .terminal_union()
                .iter()
                .filter(|record| record.result().deleted_secret_envelope_digest() != &[0; 32])
                .count(),
            0
        );
        let successor_passphrase = Passphrase::new(b"prepared-existing-device-successor".to_vec())?;
        let publication = restore::PreparedExistingRestorePublicationV1::new(
            prepared,
            successor_passphrase,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        let mut restore_transaction_id = [0_u8; 16];
        restore_transaction_id.copy_from_slice(publication.manifest().restore_transaction_id());
        assert_ne!(restore_transaction_id, [0; 16]);
        assert_eq!(
            publication.manifest().restore_transaction_id(),
            &restore_transaction_id
        );
        assert_eq!(
            publication.successor_storage_ids().contract_wallet_id(),
            store.storage_ids()?.contract_wallet_id()
        );
        assert_ne!(
            publication.successor_storage_ids().vault_id(),
            store.storage_ids()?.vault_id()
        );
        assert_eq!(
            &publication.successor_core().as_bytes()[42..74],
            store.root_identity.store_root_id()
        );
        assert_eq!(publication.successor_core().nonce_epoch(), 2);
        assert_eq!(publication.successor_core().vault_generation(), 2);
        assert_eq!(
            publication
                .successor_terminals()
                .record_set()
                .record_count(),
            2
        );
        // The predecessor has four authenticated normal entries.  The
        // canonical restore tail is `RestoreBegin`, two terminal-union
        // records, `EpochAdvance`, and `RestoreComplete`, so publication
        // must retain all nine entries rather than silently omitting a
        // terminal record from the authenticated history.
        assert_eq!(publication.journal_entries().len(), 9);
        let final_head = publication
            .journal_entries()
            .last()
            .ok_or("missing prepared restore head")?;
        assert_eq!(
            publication.active().journal_sequence(),
            final_head.sequence()
        );
        assert_eq!(
            publication.active().journal_head_digest(),
            final_head.entry_digest()
        );
        let pending = publication.pending_index().fields();
        assert_eq!(pending.restore_transaction_id, restore_transaction_id);
        assert_eq!(
            pending.contract_wallet_id,
            *publication.preparation().contract_wallet_id()
        );
        assert_eq!(
            pending.restore_manifest_digest,
            *publication.manifest().manifest_digest()
        );
        assert_eq!(
            pending.source_backup_bundle_digest,
            *publication.preparation().source().bundle().bundle_digest()
        );
        assert_eq!(
            pending.source_backup_master_envelope_digest,
            authoritative_storage_hash_v1(
                StorageHashDomainV1::MasterEnvelope,
                publication
                    .preparation()
                    .source()
                    .master_envelope()
                    .as_bytes(),
            )
        );
        assert_eq!(
            pending.source_backup_manifest_object_envelope_digest,
            publication
                .preparation()
                .source()
                .manifest_envelope()
                .digest()
        );
        assert_eq!(
            pending.source_journal_sequence,
            publication
                .preparation()
                .source()
                .manifest()
                .source_journal_sequence()
        );
        assert_eq!(
            pending.source_journal_head_digest,
            publication
                .preparation()
                .source()
                .manifest()
                .source_journal_head_digest()
        );
        assert_eq!(
            pending.source_record_count,
            publication
                .preparation()
                .source()
                .record_set()
                .record_count()
        );
        assert_eq!(
            pending.source_record_set_digest,
            *publication
                .preparation()
                .source()
                .record_set()
                .record_set_digest()
        );
        assert_eq!(
            pending.successor_generation_core_digest,
            *publication.successor_core().generation_core_digest()
        );
        assert_eq!(
            pending.successor_master_envelope_digest,
            authoritative_storage_hash_v1(
                StorageHashDomainV1::MasterEnvelope,
                publication.successor_master_envelope().as_bytes(),
            )
        );
        assert_eq!(
            pending.successor_final_journal_sequence,
            final_head.sequence()
        );
        assert_eq!(
            pending.successor_final_journal_head_digest,
            *final_head.entry_digest()
        );
        assert_eq!(
            pending.successor_record_count,
            publication
                .successor_terminals()
                .record_set()
                .record_count()
        );
        assert_eq!(
            pending.successor_record_set_digest,
            *publication
                .successor_terminals()
                .record_set()
                .record_set_digest()
        );
        assert_eq!(
            pending.successor_tombstone_envelope_set_digest,
            *publication.successor_terminals().envelope_set_digest()
        );
        assert_eq!(
            pending.successor_active_generation_digest,
            *publication.active().active_generation_digest()
        );
        assert_eq!(pending.restore_only_root_digest, [0; 32]);
        assert_eq!(publication.epoch_advance().successor_epoch(), 2);
        // Creating the selected backup records one additional authenticated
        // predecessor event.  Existing-device restore must anchor its tail to
        // that complete four-entry journal, not to the pre-backup prefix.
        assert_eq!(publication.preparation().target_journal_entries().len(), 4);
        let verify_passphrase = Passphrase::new(b"prepared-existing-device-successor".to_vec())?;
        let _opened = open_master_key(
            publication.successor_master_envelope(),
            publication.successor_storage_ids(),
            &verify_passphrase,
        )?;
        let wrong_ids = loop {
            let candidate = StorageIdsV1::new(
                *publication.successor_storage_ids().contract_wallet_id(),
                *generate_storage_ids()?.vault_id(),
            )?;
            if candidate != publication.successor_storage_ids() {
                break candidate;
            }
        };
        assert!(open_master_key(
            publication.successor_master_envelope(),
            wrong_ids,
            &verify_passphrase,
        )
        .is_err());
        let wrong_passphrase = Passphrase::new(b"wrong-successor-passphrase".to_vec())?;
        assert!(open_master_key(
            publication.successor_master_envelope(),
            publication.successor_storage_ids(),
            &wrong_passphrase,
        )
        .is_err());
        let wrong_master_key = generate_vault_master_key()?;
        let first_terminal = publication
            .preparation()
            .terminal_union()
            .first()
            .ok_or("missing successor terminal")?;
        let terminal_plaintext =
            TombstonePlaintextV1::from_bytes(first_terminal.result().as_bytes())?;
        let terminal_metadata = TombstoneRecordMetadataV1::from_tombstone(&terminal_plaintext)?;
        assert!(open_tombstone_v1(
            publication
                .successor_terminals()
                .envelopes()
                .get(first_terminal.identity().as_bytes())
                .ok_or("missing sealed successor terminal")?,
            publication.successor_storage_ids(),
            &wrong_master_key,
            terminal_metadata,
        )
        .is_err());
        let wrong_root_identity = StoreRootIdentityV1::new(
            *store.storage_ids()?.contract_wallet_id(),
            [0xb1; 32],
            [0xb2; 16],
        )?;
        assert!(publication
            .preparation()
            .require_target_root_identity(&wrong_root_identity)
            .is_err());
        publication
            .preparation()
            .require_target_root_identity(&store.root_identity)?;
        assert_eq!(snapshot_regular_files(&root_path)?, before);
        Ok(())
    }

    #[test]
    fn existing_restore_staging_is_closed_no_clobber_and_source_retained(
    ) -> Result<(), Box<dyn Error>> {
        let fixture = backup_crash_fixture()?;
        let mut store = open_store(&fixture.initialized.temporary)?;
        let completed = store.create_backup(
            Passphrase::new(b"staging-source-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        let limits = BackupPolicyLimitsV1::new(64, 1_048_576)?;
        let prepare_publication = |store: &LiveStoreInventoryV1| -> Result<
            restore::PreparedExistingRestorePublicationV1,
            Box<dyn Error>,
        > {
            let preparation = store.prepare_existing_device_restore_material(
                &store.root,
                &backup_name,
                Passphrase::new(b"staging-source-backup-passphrase".to_vec())?,
                limits,
            )?;
            Ok(restore::PreparedExistingRestorePublicationV1::new(
                preparation,
                Passphrase::new(b"staging-successor-unlock-passphrase".to_vec())?,
                limits,
            )?)
        };
        let collision_publication = prepare_publication(&store)?;
        let exact_publication = prepare_publication(&store)?;
        let wrong_type_publication = prepare_publication(&store)?;
        let replaced_source_publication = prepare_publication(&store)?;
        let staging_name = |publication: &restore::PreparedExistingRestorePublicationV1| {
            let structural = crate::UnauthenticatedRestoreManifestV1::parse_structural(
                publication.manifest().as_bytes(),
            )?;
            Ok::<_, CanonicalCodecError>(crate::canonical_restore_staging_directory_name(
                &structural,
            ))
        };

        let collision_name = staging_name(&collision_publication)?;
        let _collision = store
            .root
            .create_child_directory(ValidatedComponent::registered(&collision_name)?)?;
        assert!(
            restore::stage_existing_device_restore(&store.root, collision_publication,).is_err()
        );

        let active_before = store.root.read_bounded_file(
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            ACTIVE_VAULT_GENERATION_LEN,
        )?;
        let staged = restore::stage_existing_device_restore(&store.root, exact_publication)?;
        restore::verify_existing_restore_staging(staged.staging(), staged.publication())?;
        staged.revalidate_retained_authorities()?;
        assert!(store
            .root
            .open_child_directory(ValidatedComponent::registered("restore-pending")?)
            .is_err());
        assert_eq!(
            store.root.read_bounded_file(
                &ValidatedComponent::registered(ACTIVE_GENERATION)?,
                ACTIVE_VAULT_GENERATION_LEN,
            )?,
            active_before
        );

        let root_path = fixture.initialized.temporary.path().join("contracts-store");
        let exact_name = staging_name(staged.publication())?;
        let journal_path = root_path
            .join(exact_name)
            .join("successor-generation")
            .join("journal");
        let journal_names = staged
            .publication()
            .journal_entries()
            .iter()
            .map(|entry| {
                Ok::<_, CanonicalCodecError>(canonical_journal_filename(
                    crate::UnauthenticatedJournalEntryV1::parse_structural(entry.as_bytes())?
                        .envelope(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(journal_names.len() >= 2);

        let first_path = journal_path.join(&journal_names[0]);
        let mut noncanonical_name = journal_names[0].as_bytes().to_vec();
        let changed_nibble = noncanonical_name
            .get_mut(21)
            .ok_or("canonical journal name is shorter than its frozen grammar")?;
        *changed_nibble = if *changed_nibble == b'0' { b'1' } else { b'0' };
        let noncanonical_path = journal_path.join(String::from_utf8(noncanonical_name)?);
        fs::rename(&first_path, &noncanonical_path)?;
        assert!(
            restore::verify_existing_restore_staging(staged.staging(), staged.publication(),)
                .is_err()
        );
        fs::rename(&noncanonical_path, &first_path)?;
        restore::verify_existing_restore_staging(staged.staging(), staged.publication())?;

        let second_path = journal_path.join(&journal_names[1]);
        let swap_path = fixture
            .initialized
            .temporary
            .path()
            .join("successor-journal-swap.tmp");
        fs::rename(&first_path, &swap_path)?;
        fs::rename(&second_path, &first_path)?;
        fs::rename(&swap_path, &second_path)?;
        assert!(
            restore::verify_existing_restore_staging(staged.staging(), staged.publication(),)
                .is_err()
        );
        fs::rename(&first_path, &swap_path)?;
        fs::rename(&second_path, &first_path)?;
        fs::rename(&swap_path, &second_path)?;
        restore::verify_existing_restore_staging(staged.staging(), staged.publication())?;

        let extra_staged = staged;
        extra_staged.staging().create_immutable_file(
            &ValidatedComponent::registered("restore-only-root.bin")?,
            &[0x91],
        )?;
        assert!(restore::verify_existing_restore_staging(
            extra_staged.staging(),
            extra_staged.publication(),
        )
        .is_err());

        let wrong_type_name = staging_name(&wrong_type_publication)?;
        let wrong_type_staged =
            restore::stage_existing_device_restore(&store.root, wrong_type_publication)?;
        let manifest_path = root_path
            .join(&wrong_type_name)
            .join("restore-manifest.bin");
        fs::rename(
            &manifest_path,
            fixture
                .initialized
                .temporary
                .path()
                .join("displaced-restore-manifest.bin"),
        )?;
        fs::create_dir(&manifest_path)?;
        assert!(restore::verify_existing_restore_staging(
            wrong_type_staged.staging(),
            wrong_type_staged.publication(),
        )
        .is_err());

        let source_path = root_path.join(&backup_name);
        fs::rename(
            &source_path,
            fixture
                .initialized
                .temporary
                .path()
                .join("displaced-source-backup"),
        )?;
        fs::create_dir(&source_path)?;
        assert!(
            restore::stage_existing_device_restore(&store.root, replaced_source_publication,)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn existing_restore_publisher_is_atomic_and_fail_closed() -> Result<(), Box<dyn Error>> {
        const SOURCE_PASSPHRASE: &[u8] = b"publisher-source-backup-passphrase";
        const SUCCESSOR_PASSPHRASE: &[u8] = b"publisher-successor-unlock-passphrase";

        let stage = |store: &mut LiveStoreInventoryV1|
         -> Result<restore::StagedExistingRestoreV1, Box<dyn Error>> {
            let limits = BackupPolicyLimitsV1::new(64, 1_048_576)?;
            let backup = store.create_backup(Passphrase::new(SOURCE_PASSPHRASE.to_vec())?, limits)?;
            let backup_name = format!(
                "backup-{:020}-{}",
                backup.backup_generation(),
                hex_lower(backup.backup_id())
            );
            let preparation = store.prepare_existing_device_restore_material(
                &store.root,
                &backup_name,
                Passphrase::new(SOURCE_PASSPHRASE.to_vec())?,
                limits,
            )?;
            let publication = restore::PreparedExistingRestorePublicationV1::new(
                preparation,
                Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?,
                limits,
            )?;
            Ok(restore::stage_existing_device_restore(
                &store.root,
                publication,
            )?)
        };

        // Positive: steps 9--14 complete while the predecessor Store is
        // consumed, and the successor reopens through the normal unlock path.
        let success_fixture = backup_crash_fixture()?;
        let mut success_store = open_store(&success_fixture.initialized.temporary)?;
        let success_staged = stage(&mut success_store)?;
        let successor_core = success_staged
            .publication()
            .successor_core()
            .as_bytes()
            .to_vec();
        let successor_active = success_staged.publication().active().as_bytes().to_vec();
        let success_completed =
            success_store.publish_staged_existing_device_restore(success_staged)?;
        success_completed.completed().revalidate()?;
        success_completed.generation().revalidate()?;
        success_completed.active().revalidate()?;
        assert_eq!(
            success_completed.generation().read_bounded_file(
                &ValidatedComponent::registered("generation-core.bin")?,
                VAULT_GENERATION_CORE_LEN,
            )?,
            successor_core
        );
        drop(success_completed);
        let reopened = open_store_with_passphrase(
            &success_fixture.initialized.temporary,
            SUCCESSOR_PASSPHRASE,
        )?;
        assert_eq!(
            reopened.core.as_bytes().as_slice(),
            successor_core.as_slice()
        );
        assert_eq!(
            reopened.active_record()?.as_bytes().as_slice(),
            successor_active.as_slice()
        );
        reopened.snapshot()?;
        assert!(reopened
            .root
            .open_child_directory(ValidatedComponent::registered("restore-pending")?)
            .is_err());
        drop(reopened);

        // Corruption is rejected independently. After exact restoration of
        // those bytes, moving the successor to an unassigned root location is
        // also rejected before publication; the orphan leaves normal open in
        // quarantine and the predecessor active pointer remains unchanged.
        let location_fixture = backup_crash_fixture()?;
        let mut location_store = open_store(&location_fixture.initialized.temporary)?;
        let location_active_before = location_store.root.read_bounded_file(
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            ACTIVE_VAULT_GENERATION_LEN,
        )?;
        let location_staged = stage(&mut location_store)?;
        let manifest = crate::UnauthenticatedRestoreManifestV1::parse_structural(
            location_staged.publication().manifest().as_bytes(),
        )?;
        let staging_name = crate::canonical_restore_staging_directory_name(&manifest);
        let root_path = location_fixture
            .initialized
            .temporary
            .path()
            .join("contracts-store");
        let manifest_path = root_path.join(&staging_name).join("restore-manifest.bin");
        let displaced_manifest = location_fixture
            .initialized
            .temporary
            .path()
            .join("publisher-displaced-manifest.bin");
        let rejected_manifest = location_fixture
            .initialized
            .temporary
            .path()
            .join("publisher-rejected-manifest.bin");
        fs::rename(&manifest_path, &displaced_manifest)?;
        let mut mutated_manifest = location_staged.publication().manifest().as_bytes().to_vec();
        mutated_manifest[42] ^= 0x01;
        fs::write(&manifest_path, mutated_manifest)?;
        assert!(restore::verify_existing_restore_staging(
            location_staged.staging(),
            location_staged.publication(),
        )
        .is_err());
        fs::rename(&manifest_path, &rejected_manifest)?;
        fs::rename(&displaced_manifest, &manifest_path)?;
        restore::verify_existing_restore_staging(
            location_staged.staging(),
            location_staged.publication(),
        )?;
        fs::rename(
            root_path.join(&staging_name).join("successor-generation"),
            root_path.join("successor-generation"),
        )?;
        assert!(location_store
            .publish_staged_existing_device_restore(location_staged)
            .is_err());
        assert_eq!(
            fs::read(root_path.join(ACTIVE_GENERATION))?,
            location_active_before
        );
        assert!(open_store(&location_fixture.initialized.temporary).is_err());

        // A pre-existing reserved pending name is never replaced. Its mere
        // presence keeps ordinary open quarantined and leaves the predecessor
        // active pointer byte-identical.
        let collision_fixture = backup_crash_fixture()?;
        let mut collision_store = open_store(&collision_fixture.initialized.temporary)?;
        let collision_active_before = collision_store.root.read_bounded_file(
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            ACTIVE_VAULT_GENERATION_LEN,
        )?;
        let collision_staged = stage(&mut collision_store)?;
        collision_store
            .root
            .create_child_directory(ValidatedComponent::registered("restore-pending")?)?;
        let collision_root = collision_fixture
            .initialized
            .temporary
            .path()
            .join("contracts-store");
        assert!(collision_store
            .publish_staged_existing_device_restore(collision_staged)
            .is_err());
        assert_eq!(
            fs::read(collision_root.join(ACTIVE_GENERATION))?,
            collision_active_before
        );
        assert!(open_store(&collision_fixture.initialized.temporary).is_err());
        Ok(())
    }

    #[test]
    fn existing_restore_disk_only_resume_finishes_after_step9() -> Result<(), Box<dyn Error>> {
        const SOURCE_PASSPHRASE: &[u8] = b"disk-resume-source-passphrase";
        const SUCCESSOR_PASSPHRASE: &[u8] = b"disk-resume-successor-passphrase";
        let fixture = backup_crash_fixture()?;
        let mut store = open_store(&fixture.initialized.temporary)?;
        let limits = BackupPolicyLimitsV1::new(64, 1_048_576)?;
        let backup = store.create_backup(Passphrase::new(SOURCE_PASSPHRASE.to_vec())?, limits)?;
        let backup_name = format!(
            "backup-{:020}-{}",
            backup.backup_generation(),
            hex_lower(backup.backup_id())
        );
        let preparation = store.prepare_existing_device_restore_material(
            &store.root,
            &backup_name,
            Passphrase::new(SOURCE_PASSPHRASE.to_vec())?,
            limits,
        )?;
        let publication = restore::PreparedExistingRestorePublicationV1::new(
            preparation,
            Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?,
            limits,
        )?;
        let manifest = crate::UnauthenticatedRestoreManifestV1::parse_structural(
            publication.manifest().as_bytes(),
        )?;
        let staging_name = ValidatedComponent::registered(
            &crate::canonical_restore_staging_directory_name(&manifest),
        )?;
        let staged = restore::stage_existing_device_restore(&store.root, publication)?;
        let pending = store
            .root
            .publish_restore_staging_no_replace(&staging_name, staged.staging())?;
        pending.revalidate()?;
        drop(staged);
        drop(store);

        // Resume authority is confined to the copied pending tree. Make the
        // original selected backup unavailable before reopening.
        let root_path = fixture.initialized.temporary.path().join("contracts-store");
        fs::rename(
            root_path.join(&backup_name),
            fixture
                .initialized
                .temporary
                .path()
                .join("source-backup-unavailable-after-crash"),
        )?;
        assert!(open_store(&fixture.initialized.temporary).is_err());
        let parent = Arc::new(Dir::from_std_file(File::open(
            fixture.initialized.temporary.path(),
        )?));
        resume_restore_at(parent, Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?)
            .map_err(|_| "initial disk-only resume failed")?;
        let mut reopened =
            open_store_with_passphrase(&fixture.initialized.temporary, SUCCESSOR_PASSPHRASE)?;
        reopened.snapshot()?;
        let next_sequence = reopened
            .active_record()?
            .journal_sequence()
            .checked_add(1)
            .ok_or("journal sequence overflow")?;
        let descendant = crate::canonical::reserve_records_with_ids(
            PurposeV1::Funding,
            next_sequence,
            0x73,
            0x74,
        )?;
        let (_, unique_lookup_charge) = replace_request_lookup(&descendant.1, 0x75)?;
        let (claim, charge) =
            replace_nonce_epoch(unique_lookup_charge, reopened.core.nonce_epoch())?;
        let authority = charge.reservation_authority();
        assert_eq!(authority.nonce_epoch(), reopened.core.nonce_epoch());
        let lifetime = reopened
            .audit_current_generation_journal()
            .map_err(|_| "descendant predecessor journal audit failed")?;
        lifetime
            .composite
            .lifetime_index()
            .require_fresh_reservation(&claim, &charge)
            .map_err(|_| "descendant lifetime admission failed")?;
        reopened
            .require_fresh_reservation_absence(authority)
            .map_err(|_| "descendant disk absence check failed")?;
        assert_eq!(
            charge.reserve_journal_sequence(),
            lifetime.sequence + 1,
            "descendant charge sequence differs"
        );
        let handle = reopened
            .persist_reservation(&claim, &charge)
            .map_err(|_| "normal descendant persistence failed")?;
        let derivation = commitment_attempt(authority.nonce_identity()?, 0x76)?;
        reopened
            .persist_nonce_derivation_attempt(&handle, &derivation)
            .map_err(|_| "normal descendant derivation persistence failed")?;
        drop(reopened);

        // Completed recognition accepts the exact activation as an ancestor of
        // the unique authenticated normal descendant head and performs no
        // second restore rename.
        let parent = Arc::new(Dir::from_std_file(File::open(
            fixture.initialized.temporary.path(),
        )?));
        resume_restore_at(parent, Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?)
            .map_err(|_| "completed descendant recognition failed")?;
        let mut reopened =
            open_store_with_passphrase(&fixture.initialized.temporary, SUCCESSOR_PASSPHRASE)?;
        let limits = BackupPolicyLimitsV1::new(64, 1_048_576)?;
        let next_backup_passphrase = b"post-restore-descendant-backup-passphrase";
        let next_backup =
            reopened.create_backup(Passphrase::new(next_backup_passphrase.to_vec())?, limits)?;
        let next_backup_name = format!(
            "backup-{:020}-{}",
            next_backup.backup_generation(),
            hex_lower(next_backup.backup_id())
        );
        let selected = restore::authenticate_selected_backup(
            &reopened.root,
            &next_backup_name,
            Passphrase::new(next_backup_passphrase.to_vec())?,
            limits,
        )?;
        let attempts = authenticated_record_items(selected.record_set())?
            .into_iter()
            .filter(|item| {
                crate::UnauthenticatedRestoreRecordItemV1::parse_structural(item.as_bytes())
                    .is_ok_and(|structural| {
                        structural.key().family() == RestoreRecordFamilyV1::Attempt
                    })
            })
            .collect::<Vec<_>>();
        assert!(attempts.iter().any(|item| {
            let record_bytes = &item.as_bytes()[crate::RESTORE_RECORD_ITEM_PREFIX_LEN..];
            record_bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN
                && record_bytes == derivation.as_bytes()
        }));
        Ok(())
    }

    #[test]
    fn public_evidence_composition_publishes_and_resumes_existing_restore(
    ) -> Result<(), Box<dyn Error>> {
        const BACKUP_PASSPHRASE: &[u8] = b"public-evidence-backup-passphrase";
        const SUCCESSOR_PASSPHRASE: &[u8] = b"public-evidence-successor-passphrase";
        let directory = TestDirectory::create()?;
        let limits = BackupPolicyLimitsV1::new(8, 65_536)?;
        let mut vault = ContractsNonceVaultV1::create_evidence_only(
            directory.capability()?,
            "contracts-store",
            StorageIdsV1::new([0x71; 32], [0x72; 32])?,
            &Passphrase::new(b"public-evidence-initial-passphrase".to_vec())?,
            test_budget_policy()?,
        )?;
        let backup = vault
            .create_backup_evidence_only(Passphrase::new(BACKUP_PASSPHRASE.to_vec())?, limits)?;
        let backup_name = format!(
            "backup-{:020}-{}",
            backup.backup_generation(),
            hex_lower(backup.backup_id())
        );
        vault.publish_existing_device_restore_evidence_only(
            &backup_name,
            Passphrase::new(BACKUP_PASSPHRASE.to_vec())?,
            Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?,
            limits,
        )?;
        resume_restore_at(
            directory.capability()?,
            Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?,
        )?;
        let _reopened = ContractsNonceVaultV1::open_evidence_only(
            directory.capability()?,
            "contracts-store",
            Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?,
            test_budget_policy()?,
        )?;
        Ok(())
    }

    #[test]
    fn existing_restore_process_death_resume_matrix() -> Result<(), Box<dyn Error>> {
        const SUCCESSOR_PASSPHRASE: &[u8] = b"step9-successor-passphrase";
        const CUTS: &[&str] = &[
            "step10-before-rename",
            "step10-after-rename-before-root-sync",
            "step10-after-root-sync",
            "step11-before-rename",
            "step11-after-rename-before-root-sync",
            "step11-after-root-sync",
            "step12-before-full-verify",
            "step12-during-full-verify",
            "step12-after-full-verify",
            "step13-before-rename",
            "step13-after-rename-before-root-sync",
            "step13-after-root-sync",
            "step14-before-final-validation",
            "step14-during-final-validation",
            "step14-after-final-validation",
        ];
        let base = pending_disk_restore_fixture()?;
        let base_root = base.temporary.path().join("contracts-store");
        for cut in CUTS {
            let case = TestDirectory::create()?;
            copy_directory_tree(&base_root, &case.path().join("contracts-store"))?;
            let marker = case.path().join("restore-crash-cut-reached.marker");
            let status = Command::new(std::env::current_exe()?)
                .arg("--ignored")
                .arg("--exact")
                .arg(
                    "runtime::linux::inventory::tests::child_existing_restore_resume_aborts_at_exact_cut",
                )
                .env("DOM_CONTRACTS_INVENTORY_TEST_ROOT", case.path())
                .env("DOM_G1B_RESTORE_CRASH_CUT", cut)
                .env("DOM_G1B_RESTORE_CRASH_MARKER", &marker)
                .current_dir(case.path())
                .status()?;
            assert_eq!(
                status.signal(),
                Some(nix::libc::SIGABRT),
                "unexpected cut status for {cut}"
            );
            assert_eq!(fs::read(&marker)?, cut.as_bytes());
            assert!(open_store(&case).is_err());
            let parent = Arc::new(Dir::from_std_file(File::open(case.path())?));
            resume_restore_at(parent, Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?)?;
            let reopened = open_store_with_passphrase(&case, SUCCESSOR_PASSPHRASE)?;
            reopened.snapshot()?;
            drop(reopened);
            let parent = Arc::new(Dir::from_std_file(File::open(case.path())?));
            resume_restore_at(parent, Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?)?;
        }
        Ok(())
    }

    #[test]
    fn tombstone_identity_or_envelope_epoch_mutation_fails_closed_on_reopen(
    ) -> Result<(), Box<dyn Error>> {
        let base = initialize()?;
        let mut store = open_store(&base.temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x89, 0x99)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        assert_eq!(
            store.persist_terminal_reservation(&handle, false)?,
            ReservationState::AbortedBeforePublicMaterial
        );
        drop(store);
        let base_root = base.temporary.path().join("contracts-store");
        let generation = generation_path(&base)?;

        let identity_case = TestDirectory::create()?;
        copy_directory_tree(&base_root, &identity_case.path().join("contracts-store"))?;
        let identity_tombstones = identity_case
            .path()
            .join("contracts-store")
            .join(
                generation
                    .file_name()
                    .ok_or("generation name is required")?,
            )
            .join("tombstones");
        let identity_path = fs::read_dir(&identity_tombstones)?
            .next()
            .ok_or("successor tombstone is required")??
            .path();
        let identity_name = identity_path
            .file_name()
            .ok_or("tombstone filename is required")?
            .to_string_lossy()
            .into_owned();
        let identity_hex = identity_name
            .strip_suffix(".tombstone")
            .ok_or("canonical tombstone suffix is required")?;
        let mut mutated_hex = identity_hex.as_bytes().to_vec();
        let epoch_nibble = mutated_hex
            .get_mut(194)
            .ok_or("canonical nonce identity is shorter than 105 bytes")?;
        *epoch_nibble = if *epoch_nibble == b'0' { b'1' } else { b'0' };
        let mutated_name = format!("{}.tombstone", String::from_utf8(mutated_hex)?);
        fs::rename(identity_path, identity_tombstones.join(mutated_name))?;
        assert!(LiveStoreInventoryV1::open(
            identity_case.capability()?,
            "contracts-store",
            Passphrase::new(b"inventory-test-passphrase".to_vec())?,
        )
        .is_err());

        let header_case = TestDirectory::create()?;
        copy_directory_tree(&base_root, &header_case.path().join("contracts-store"))?;
        let header_tombstones = header_case
            .path()
            .join("contracts-store")
            .join(
                generation
                    .file_name()
                    .ok_or("generation name is required")?,
            )
            .join("tombstones");
        let header_path = fs::read_dir(&header_tombstones)?
            .next()
            .ok_or("successor tombstone is required")??
            .path();
        let mut envelope = fs::read(&header_path)?;
        envelope[78] ^= 0x01;
        overwrite_immutable_test_file(&header_path, &envelope)?;
        assert!(LiveStoreInventoryV1::open(
            header_case.capability()?,
            "contracts-store",
            Passphrase::new(b"inventory-test-passphrase".to_vec())?,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn disk_phase_classifier_rejects_ambiguous_inventories() -> Result<(), Box<dyn Error>> {
        const SUCCESSOR_PASSPHRASE: &[u8] = b"step9-successor-passphrase";
        let base = pending_disk_restore_fixture()?;
        let base_root = base.temporary.path().join("contracts-store");
        let rejects = |case: &TestDirectory| -> Result<(), Box<dyn Error>> {
            let result = resume_restore_at(
                case.capability()?,
                Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?,
            );
            assert!(result.is_err());
            Ok(())
        };

        let extra = TestDirectory::create()?;
        copy_directory_tree(&base_root, &extra.path().join("contracts-store"))?;
        fs::write(
            extra
                .path()
                .join("contracts-store/restore-pending/unregistered-entry"),
            [0x01],
        )?;
        rejects(&extra)?;

        let wrong_type = TestDirectory::create()?;
        copy_directory_tree(&base_root, &wrong_type.path().join("contracts-store"))?;
        let index = wrong_type
            .path()
            .join("contracts-store/restore-pending/restore-pending.index");
        fs::remove_file(&index)?;
        fs::create_dir(&index)?;
        rejects(&wrong_type)?;

        let duplicate_successor = TestDirectory::create()?;
        copy_directory_tree(
            &base_root,
            &duplicate_successor.path().join("contracts-store"),
        )?;
        let duplicate_root = duplicate_successor.path().join("contracts-store");
        let nested_successor = duplicate_root.join("restore-pending/successor-generation");
        let successor_core = crate::UnauthenticatedVaultGenerationCoreV1::parse_structural(
            &fs::read(nested_successor.join(GENERATION_CORE))?,
        )?;
        let successor_name = canonical_generation_directory_name(&successor_core);
        copy_directory_tree(&nested_successor, &duplicate_root.join(successor_name))?;
        rejects(&duplicate_successor)?;

        let mixed_active = TestDirectory::create()?;
        copy_directory_tree(&base_root, &mixed_active.path().join("contracts-store"))?;
        let mixed_root = mixed_active.path().join("contracts-store");
        let staged_active =
            fs::read(mixed_root.join("restore-pending/activation/active-generation.bin"))?;
        overwrite_immutable_test_file(&mixed_root.join(ACTIVE_GENERATION), &staged_active)?;
        rejects(&mixed_active)?;

        let pending_and_completed = TestDirectory::create()?;
        copy_directory_tree(
            &base_root,
            &pending_and_completed.path().join("contracts-store"),
        )?;
        let collision_root = pending_and_completed.path().join("contracts-store");
        let pending = collision_root.join("restore-pending");
        let manifest = crate::UnauthenticatedRestoreManifestV1::parse_structural(&fs::read(
            pending.join("restore-manifest.bin"),
        )?)?;
        let completed_name = crate::canonical_restore_completed_directory_name(&manifest);
        copy_directory_tree(&pending, &collision_root.join(completed_name))?;
        rejects(&pending_and_completed)?;

        let multiple_completed = TestDirectory::create()?;
        copy_directory_tree(
            &base_root,
            &multiple_completed.path().join("contracts-store"),
        )?;
        resume_restore_at(
            multiple_completed.capability()?,
            Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?,
        )?;
        let completed_root = multiple_completed.path().join("contracts-store");
        let existing = fs::read_dir(&completed_root)?
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("restore-complete-")
            })
            .ok_or("completed restore is missing")?;
        copy_directory_tree(
            &existing.path(),
            &completed_root.join(format!("restore-complete-{}", "0".repeat(64))),
        )?;
        rejects(&multiple_completed)?;
        Ok(())
    }

    #[test]
    fn disk_resume_accepts_distinct_source_target_and_successor_epochs_with_history(
    ) -> Result<(), Box<dyn Error>> {
        const BACKUP_PASSPHRASE: &[u8] = b"distinct-epoch-backup-passphrase";
        const FIRST_SUCCESSOR_PASSPHRASE: &[u8] = b"distinct-epoch-first-successor";
        const SECOND_SUCCESSOR_PASSPHRASE: &[u8] = b"distinct-epoch-second-successor";
        let fixture = backup_crash_fixture()?;
        let limits = BackupPolicyLimitsV1::new(64, 1_048_576)?;
        let mut store = open_store(&fixture.initialized.temporary)?;
        let backup = store.create_backup(Passphrase::new(BACKUP_PASSPHRASE.to_vec())?, limits)?;
        let backup_name = format!(
            "backup-{:020}-{}",
            backup.backup_generation(),
            hex_lower(backup.backup_id())
        );
        let first_preparation = store.prepare_existing_device_restore_material(
            &store.root,
            &backup_name,
            Passphrase::new(BACKUP_PASSPHRASE.to_vec())?,
            limits,
        )?;
        let first_publication = restore::PreparedExistingRestorePublicationV1::new(
            first_preparation,
            Passphrase::new(FIRST_SUCCESSOR_PASSPHRASE.to_vec())?,
            limits,
        )?;
        let first_staged = restore::stage_existing_device_restore(&store.root, first_publication)?;
        let first_completed = store.publish_staged_existing_device_restore(first_staged)?;
        first_completed.completed().revalidate()?;
        drop(first_completed);

        let store =
            open_store_with_passphrase(&fixture.initialized.temporary, FIRST_SUCCESSOR_PASSPHRASE)?;
        assert_eq!(store.core.nonce_epoch(), 2);
        let second_preparation = store.prepare_existing_device_restore_material(
            &store.root,
            &backup_name,
            Passphrase::new(BACKUP_PASSPHRASE.to_vec())?,
            limits,
        )?;
        let second_publication = restore::PreparedExistingRestorePublicationV1::new(
            second_preparation,
            Passphrase::new(SECOND_SUCCESSOR_PASSPHRASE.to_vec())?,
            limits,
        )?;
        assert_eq!(second_publication.manifest().source_epoch(), 1);
        assert_eq!(second_publication.manifest().target_epoch(), 2);
        assert_eq!(second_publication.manifest().successor_epoch(), 3);
        let structural = crate::UnauthenticatedRestoreManifestV1::parse_structural(
            second_publication.manifest().as_bytes(),
        )?;
        let staging_name = ValidatedComponent::registered(
            &crate::canonical_restore_staging_directory_name(&structural),
        )?;
        let second_staged =
            restore::stage_existing_device_restore(&store.root, second_publication)?;
        let pending = store
            .root
            .publish_restore_staging_no_replace(&staging_name, second_staged.staging())?;
        pending.revalidate()?;
        drop(second_staged);
        drop(store);

        let root_path = fixture.initialized.temporary.path().join("contracts-store");
        fs::rename(
            root_path.join(&backup_name),
            fixture
                .initialized
                .temporary
                .path()
                .join("distinct-epoch-source-backup-unavailable"),
        )?;
        let parent = Arc::new(Dir::from_std_file(File::open(
            fixture.initialized.temporary.path(),
        )?));
        resume_restore_at(
            parent,
            Passphrase::new(SECOND_SUCCESSOR_PASSPHRASE.to_vec())?,
        )?;
        let reopened = open_store_with_passphrase(
            &fixture.initialized.temporary,
            SECOND_SUCCESSOR_PASSPHRASE,
        )?;
        assert_eq!(reopened.core.nonce_epoch(), 3);
        Ok(())
    }

    #[test]
    fn existing_restore_step9_process_death_matrix() -> Result<(), Box<dyn Error>> {
        const INITIAL_PASSPHRASE: &[u8] = b"step9-initial-passphrase";
        const SUCCESSOR_PASSPHRASE: &[u8] = b"step9-successor-passphrase";
        for cut in [
            "step9-before-rename",
            "step9-after-rename-before-root-sync",
            "step9-after-root-sync",
        ] {
            let directory = TestDirectory::create()?;
            let created = ContractsNonceVaultV1::create_evidence_only(
                directory.capability()?,
                "contracts-store",
                StorageIdsV1::new([0x81; 32], [0x82; 32])?,
                &Passphrase::new(INITIAL_PASSPHRASE.to_vec())?,
                test_budget_policy()?,
            )?;
            drop(created);
            let root_path = directory.path().join("contracts-store");
            let active_before = fs::read(root_path.join(ACTIVE_GENERATION))?;
            let marker = directory
                .path()
                .join("restore-step9-crash-cut-reached.marker");
            let status = Command::new(std::env::current_exe()?)
                .arg("--ignored")
                .arg("--exact")
                .arg(
                    "runtime::linux::inventory::tests::child_existing_restore_publish_aborts_at_step9_cut",
                )
                .env(
                    "DOM_CONTRACTS_INVENTORY_TEST_ROOT",
                    directory.path(),
                )
                .env("DOM_G1B_RESTORE_CRASH_CUT", cut)
                .env("DOM_G1B_RESTORE_CRASH_MARKER", &marker)
                .current_dir(directory.path())
                .status()?;
            assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
            assert_eq!(fs::read(&marker)?, cut.as_bytes());
            assert!(LiveStoreInventoryV1::open(
                directory.capability()?,
                "contracts-store",
                Passphrase::new(INITIAL_PASSPHRASE.to_vec())?,
            )
            .is_err());
            if cut == "step9-before-rename" {
                let parent = directory.capability()?;
                let resume =
                    resume_restore_at(parent, Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?);
                assert!(resume.is_err(), "private staging must never auto-resume");
                assert_eq!(
                    fs::read(root_path.join(ACTIVE_GENERATION))?,
                    active_before,
                    "pre-publication crash changed the canonical active generation"
                );
                assert!(
                    !root_path.join("restore-pending").exists(),
                    "pre-publication crash created public pending authority"
                );
                let orphan_staging = fs::read_dir(&root_path)?
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.starts_with(".restore-") && name.ends_with(".staging"))
                    .count();
                assert_eq!(orphan_staging, 1, "private staging orphan was not retained");
                continue;
            }
            // The public pending tree is the only post-crash source authority.
            // Remove every original root-level backup before the real resume.
            let unavailable = directory
                .path()
                .join(format!("source-backups-unavailable-{cut}"));
            fs::create_dir(&unavailable)?;
            for entry in fs::read_dir(&root_path)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("backup-") {
                    fs::rename(entry.path(), unavailable.join(name))?;
                }
            }
            let parent = directory.capability()?;
            let resume = resume_restore_at(parent, Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?);
            resume?;
            let reopened = open_store_with_passphrase(&directory, SUCCESSOR_PASSPHRASE)?;
            reopened.snapshot()?;
        }
        Ok(())
    }

    #[test]
    fn concurrent_restore_has_exactly_one_durable_winner() -> Result<(), Box<dyn Error>> {
        const INITIAL_PASSPHRASE: &[u8] = b"step9-initial-passphrase";
        const SUCCESSOR_PASSPHRASE: &[u8] = b"step9-successor-passphrase";
        let directory = TestDirectory::create()?;
        let created = ContractsNonceVaultV1::create_evidence_only(
            directory.capability()?,
            "contracts-store",
            StorageIdsV1::new([0x89; 32], [0x8a; 32])?,
            &Passphrase::new(INITIAL_PASSPHRASE.to_vec())?,
            test_budget_policy()?,
        )?;
        drop(created);
        let marker = directory.path().join("concurrent-restore-step9.marker");
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg(
                "runtime::linux::inventory::tests::child_existing_restore_publish_aborts_at_step9_cut",
            )
            .env("DOM_CONTRACTS_INVENTORY_TEST_ROOT", directory.path())
            .env("DOM_G1B_RESTORE_CRASH_CUT", "step9-after-root-sync")
            .env("DOM_G1B_RESTORE_CRASH_MARKER", &marker)
            .current_dir(directory.path())
            .status()?;
        assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
        assert_eq!(fs::read(marker)?, b"step9-after-root-sync");

        let (winner_entered_tx, winner_entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_winner_tx, release_winner_rx) = std::sync::mpsc::sync_channel(0);
        let completion = move || {
            winner_entered_tx
                .send(())
                .map_err(|_| InventoryError::Filesystem)?;
            release_winner_rx
                .recv()
                .map_err(|_| InventoryError::Filesystem)?;
            Ok(())
        };

        let winner_path = directory.path().to_path_buf();
        let winner = thread::spawn(move || {
            let parent = File::open(winner_path)
                .map(Dir::from_std_file)
                .map(Arc::new)
                .map_err(|_| InventoryError::Filesystem)?;
            let target = ContractsNonceVaultV1::retain_restore_target(parent, "contracts-store")?;
            ContractsNonceVaultV1::resume_restore_with_completion_for_test(
                target,
                Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())
                    .map_err(|_| InventoryError::Crypto)?,
                completion,
            )
        });
        winner_entered_rx
            .recv()
            .map_err(|_| InventoryError::Filesystem)?;

        let contender = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime::linux::inventory::tests::child_restore_contender_observes_busy_store")
            .env("DOM_CONTRACTS_INVENTORY_TEST_ROOT", directory.path())
            .current_dir(directory.path())
            .status()?;
        assert!(contender.success(), "restore contender did not fail closed");

        release_winner_tx
            .send(())
            .map_err(|_| InventoryError::Filesystem)?;
        winner.join().map_err(|_| InventoryError::Filesystem)??;
        let reopened = open_store_with_passphrase(&directory, SUCCESSOR_PASSPHRASE)?;
        reopened.snapshot()?;
        Ok(())
    }

    #[test]
    #[ignore = "subprocess crash helper"]
    fn child_existing_restore_resume_aborts_at_exact_cut() -> Result<(), Box<dyn Error>> {
        let root = PathBuf::from(
            std::env::var_os("DOM_CONTRACTS_INVENTORY_TEST_ROOT")
                .ok_or("DOM_CONTRACTS_INVENTORY_TEST_ROOT is required")?,
        );
        let parent = Arc::new(Dir::from_std_file(File::open(&root)?));
        resume_restore_at(
            parent,
            Passphrase::new(b"step9-successor-passphrase".to_vec())?,
        )?;
        Err("restore crash hook was not reached".into())
    }

    #[test]
    #[ignore = "subprocess crash helper"]
    fn child_existing_restore_publish_aborts_at_step9_cut() -> Result<(), Box<dyn Error>> {
        const SOURCE_PASSPHRASE: &[u8] = b"step9-source-passphrase";
        const SUCCESSOR_PASSPHRASE: &[u8] = b"step9-successor-passphrase";
        let root = PathBuf::from(
            std::env::var_os("DOM_CONTRACTS_INVENTORY_TEST_ROOT")
                .ok_or("DOM_CONTRACTS_INVENTORY_TEST_ROOT is required")?,
        );
        let directory = std::mem::ManuallyDrop::new(TestDirectory { path: root });
        let mut vault = ContractsNonceVaultV1::open_evidence_only(
            directory.capability()?,
            "contracts-store",
            Passphrase::new(b"step9-initial-passphrase".to_vec())?,
            test_budget_policy()?,
        )?;
        let limits = BackupPolicyLimitsV1::new(64, 1_048_576)?;
        let backup = vault
            .create_backup_evidence_only(Passphrase::new(SOURCE_PASSPHRASE.to_vec())?, limits)?;
        let backup_name = format!(
            "backup-{:020}-{}",
            backup.backup_generation(),
            hex_lower(backup.backup_id())
        );
        vault.publish_existing_device_restore_evidence_only(
            &backup_name,
            Passphrase::new(SOURCE_PASSPHRASE.to_vec())?,
            Passphrase::new(SUCCESSOR_PASSPHRASE.to_vec())?,
            limits,
        )?;
        Err("step9 restore crash hook was not reached".into())
    }

    #[test]
    #[ignore = "subprocess helper invoked by the restore concurrency test"]
    fn child_restore_contender_observes_busy_store() -> Result<(), Box<dyn Error>> {
        let root = PathBuf::from(
            std::env::var_os("DOM_CONTRACTS_INVENTORY_TEST_ROOT")
                .ok_or("DOM_CONTRACTS_INVENTORY_TEST_ROOT is required")?,
        );
        let parent = Arc::new(Dir::from_std_file(File::open(root)?));
        if let Ok(target) = ContractsNonceVaultV1::retain_restore_target(parent, "contracts-store")
        {
            assert!(ContractsNonceVaultV1::resume_restore(
                target,
                Passphrase::new(b"step9-successor-passphrase".to_vec())?,
            )
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn selected_backup_loader_rejects_manifest_ciphertext_mutation() -> Result<(), Box<dyn Error>> {
        let fixture = backup_crash_fixture()?;
        let mut store = open_store(&fixture.initialized.temporary)?;
        let completed = store.create_backup(
            Passphrase::new(b"selected-mutation-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        let manifest = fixture
            .initialized
            .temporary
            .path()
            .join("contracts-store")
            .join(&backup_name)
            .join("backup-manifest.object");
        let mut bytes = fs::read(&manifest)?;
        bytes[backup::MANIFEST_ENVELOPE_LEN - 17] ^= 0x01;
        overwrite_immutable_test_file(&manifest, &bytes)?;
        assert!(
            crate::runtime::linux::restore::authenticate_selected_backup(
                &store.root,
                &backup_name,
                Passphrase::new(b"selected-mutation-passphrase".to_vec())?,
                BackupPolicyLimitsV1::new(64, 1_048_576)?,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn selected_backup_loader_rejects_omitted_journal_projection_record(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let reservation =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x31, 0x41)?;
        append_reservations(&initialized, &[reservation])?;
        let store = open_store(&initialized.temporary)?;
        let limits = BackupPolicyLimitsV1::new(8, 65_536)?;
        let valid_inputs = store.current_backup_inputs(limits)?;
        assert_eq!(valid_inputs.record_set().record_count(), 1);
        let omitted = RestoreRecordSetV1::new(Vec::new(), &limits.record_set_limits()?)?;
        let mismatched_inputs = VerifiedBackupInputsV1 {
            record_set: omitted,
            ..valid_inputs
        };
        let passphrase = Passphrase::new(b"omitted-projection-record-passphrase".to_vec())?;
        let completed = backup::create_backup(
            &store.root,
            &store.master_key,
            passphrase,
            [0x91; 32],
            1,
            mismatched_inputs,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        assert!(restore::authenticate_selected_backup(
            &store.root,
            &backup_name,
            Passphrase::new(b"omitted-projection-record-passphrase".to_vec())?,
            limits,
        )
        .is_err());
        Ok(())
    }

    fn authenticated_record_items(
        set: &RestoreRecordSetV1,
    ) -> Result<Vec<RestoreRecordItemV1>, Box<dyn Error>> {
        let mut cursor = 4_usize;
        let mut items = Vec::new();
        while cursor < set.as_bytes().len() {
            let prefix_end = cursor
                .checked_add(crate::RESTORE_RECORD_ITEM_PREFIX_LEN)
                .ok_or(InventoryError::Canonical)?;
            let record_length = usize::try_from(u32::from_le_bytes(
                set.as_bytes()[cursor + crate::RESTORE_RECORD_KEY_LEN..prefix_end].try_into()?,
            ))?;
            let item_end = prefix_end
                .checked_add(record_length)
                .ok_or(InventoryError::Canonical)?;
            items.push(RestoreRecordItemV1::from_bytes(
                set.as_bytes()
                    .get(cursor..item_end)
                    .ok_or(InventoryError::Canonical)?,
            )?);
            cursor = item_end;
        }
        if cursor != set.as_bytes().len() {
            return Err(Box::new(InventoryError::Canonical));
        }
        Ok(items)
    }

    #[test]
    fn selected_backup_loader_rejects_injected_journal_projection_record(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let reservation =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x32, 0x42)?;
        append_reservations(&initialized, &[reservation])?;
        let store = open_store(&initialized.temporary)?;
        let limits = BackupPolicyLimitsV1::new(8, 65_536)?;
        let valid_inputs = store.current_backup_inputs(limits)?;
        let mut injected_items = authenticated_record_items(valid_inputs.record_set())?;
        let (injected_claim, _) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 2, 0x33, 0x43)?;
        injected_items.push(RestoreRecordItemV1::from_record_bytes(
            RestoreRecordFamilyV1::SessionClaim,
            injected_claim.as_bytes(),
        )?);
        let injected = RestoreRecordSetV1::new(injected_items, &limits.record_set_limits()?)?;
        assert_eq!(injected.record_count(), 2);
        let mismatched_inputs = VerifiedBackupInputsV1 {
            record_set: injected,
            ..valid_inputs
        };
        let passphrase = Passphrase::new(b"injected-projection-record-passphrase".to_vec())?;
        let completed = backup::create_backup(
            &store.root,
            &store.master_key,
            passphrase,
            [0x92; 32],
            1,
            mismatched_inputs,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        assert!(restore::authenticate_selected_backup(
            &store.root,
            &backup_name,
            Passphrase::new(b"injected-projection-record-passphrase".to_vec())?,
            limits,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn restore_source_replacement_after_authentication_is_detected_before_staging_copy(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let ids = StorageIdsV1::new([0x38; 32], [0x48; 32])?;
        let unlock = Passphrase::new(b"retained-source-replacement-unlock".to_vec())?;
        let mut store =
            LiveStoreInventoryV1::create(temporary.capability()?, "contracts-store", ids, &unlock)?;
        let completed = store.create_backup(
            Passphrase::new(b"retained-source-replacement-backup".to_vec())?,
            BackupPolicyLimitsV1::new(0, 4)?,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation(),
            hex_lower(completed.backup_id())
        );
        let selected = restore::authenticate_selected_backup(
            &store.root,
            &backup_name,
            Passphrase::new(b"retained-source-replacement-backup".to_vec())?,
            BackupPolicyLimitsV1::new(0, 4)?,
        )?;
        selected.revalidate_source_authority()?;

        let root_path = temporary.path().join("contracts-store");
        let original = root_path.join(&backup_name);
        let displaced = root_path.join("displaced-selected-backup-for-test");
        fs::rename(&original, &displaced)?;
        fs::create_dir(&original)?;
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700))?;

        assert!(selected.revalidate_source_authority().is_err());
        Ok(())
    }

    #[test]
    fn selected_backup_loader_accepts_exact_empty_generation_one_journal(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let ids = StorageIdsV1::new([0x37; 32], [0x47; 32])?;
        let unlock = Passphrase::new(b"empty-selected-loader-unlock".to_vec())?;
        let mut store =
            LiveStoreInventoryV1::create(temporary.capability()?, "contracts-store", ids, &unlock)?;
        let backup = store.create_backup(
            Passphrase::new(b"empty-selected-loader-backup".to_vec())?,
            BackupPolicyLimitsV1::new(0, 4)?,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            backup.backup_generation(),
            hex_lower(backup.backup_id())
        );
        let selected = restore::authenticate_selected_backup(
            &store.root,
            &backup_name,
            Passphrase::new(b"empty-selected-loader-backup".to_vec())?,
            BackupPolicyLimitsV1::new(0, 4)?,
        )?;
        assert!(selected.journal_entries().is_empty());
        assert!(selected.composite_journal().head().is_none());
        selected.revalidate_source_authority()?;
        Ok(())
    }

    #[test]
    fn adaptor_restore_state_quarantines_a_mixed_pending_root() -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let store = open_store(&initialized.temporary)?;
        let vault = ContractsNonceVaultV1 {
            store,
            budget_policy: Some(test_budget_policy()?),
            same_open_claims: BTreeSet::new(),
        };
        assert_eq!(
            NonceVaultV1::restore_state(&vault),
            RestoreState::Operational
        );
        vault
            .store
            .root
            .create_child_directory(ValidatedComponent::registered("restore-pending")?)?;
        assert_eq!(
            NonceVaultV1::restore_state(&vault),
            RestoreState::RestoreQuarantined
        );
        Ok(())
    }

    #[test]
    fn adaptor_restore_state_quarantines_invalid_object_projection_with_valid_root_and_active(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let store = open_store(&initialized.temporary)?;
        let vault = ContractsNonceVaultV1 {
            store,
            budget_policy: Some(test_budget_policy()?),
            same_open_claims: BTreeSet::new(),
        };
        assert_eq!(
            NonceVaultV1::restore_state(&vault),
            RestoreState::Operational
        );
        let (claim, _) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x39, 0x49)?;
        vault.store.claims()?.create_immutable_file(
            &ValidatedComponent::registered(&format!(
                "{}.claim",
                hex_lower(claim.identity().session_id())
            ))?,
            claim.as_bytes(),
        )?;
        assert_eq!(
            NonceVaultV1::restore_state(&vault),
            RestoreState::RestoreQuarantined
        );
        Ok(())
    }

    #[test]
    fn backup_policy_rejects_next_record_before_collection_or_staging() -> Result<(), Box<dyn Error>>
    {
        let initialized = initialize()?;
        let reservation =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0xa2, 0xb2)?;
        append_reservations(&initialized, &[reservation])?;
        let mut store = open_store(&initialized.temporary)?;
        assert!(store
            .create_backup(
                Passphrase::new(b"over-limit-backup-passphrase".to_vec())?,
                BackupPolicyLimitsV1::new(0, 4)?,
            )
            .is_err());
        let mut backup_entries = 0_u64;
        store.root.scan_independent(|name, _| {
            if name.starts_with("backup-") || name.starts_with(".backup-") {
                backup_entries += 1;
            }
            Ok(())
        })?;
        assert_eq!(backup_entries, 0);
        Ok(())
    }

    #[test]
    fn orphan_backup_staging_quarantines_generation_selection() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let ids = StorageIdsV1::new([0xc1; 32], [0xc2; 32])?;
        let unlock = Passphrase::new(b"orphan-backup-unlock-passphrase".to_vec())?;
        let store =
            LiveStoreInventoryV1::create(temporary.capability()?, "contracts-store", ids, &unlock)?;
        let staging = format!(".backup-{:020}-{}.staging", 1, "c3".repeat(32));
        store
            .root
            .create_child_directory(ValidatedComponent::registered(&staging)?)?;
        assert!(store
            .backup_operation_authority(BackupPolicyLimitsV1::new(1, 8_192)?)
            .is_err());
        Ok(())
    }

    struct BackupCrashFixture {
        initialized: InitializedStore,
        logical_files: Vec<String>,
        logical_directories: Vec<String>,
        expected_file_lengths: BTreeMap<String, usize>,
        active_bytes: Vec<u8>,
        generation_tree: BTreeMap<String, Vec<u8>>,
    }

    fn backup_crash_fixture() -> Result<BackupCrashFixture, Box<dyn Error>> {
        let initialized = initialize()?;
        let first = crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0xd1, 0xe1)?;
        let (_, second_template) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 2, 0xd2, 0xe2)?;
        let second = replace_request_lookup(&second_template, 0x08)?;
        let first_identity = *first.0.identity();
        let mut first_reservation_id = [0_u8; 32];
        first_reservation_id.copy_from_slice(first.1.reservation_authority().reservation_id());
        append_reservations(&initialized, &[first, second])?;
        let mut store = open_store(&initialized.temporary)?;
        let handle = store.test_handle(first_reservation_id)?;
        let _reservation = store.snapshot_reservation(&handle)?;
        let derivation = commitment_attempt(first_identity, 0xd3)?;
        store.persist_nonce_derivation_attempt(&handle, &derivation)?;
        drop(store);
        // The derivation-only prefix deliberately has no sealed secret.  A
        // fresh process must first apply the signed deterministic recovery
        // rule before backup authority is sampled; otherwise the crash child
        // would correctly advance the active pointer while this fixture still
        // compares it to an obsolete pre-recovery snapshot.
        let store = open_store(&initialized.temporary)?;
        let inputs = store.current_backup_inputs(BackupPolicyLimitsV1::new(64, 1_048_576)?)?;
        let (journal_entries, record_set) = inputs.into_payloads();
        drop(store);
        let generation = generation_path(&initialized)?;
        let mut expected_file_lengths = BTreeMap::from([
            ("backup-master-key.envelope".to_owned(), 182_usize),
            ("backup-manifest.object".to_owned(), 470_usize),
            ("backup-bundle.digest".to_owned(), 32_usize),
        ]);
        let mut logical_files = vec![
            "backup-master-key.envelope".to_owned(),
            "backup-manifest.object".to_owned(),
            "backup-bundle.digest".to_owned(),
        ];
        for bytes in journal_entries {
            let structural = UnauthenticatedJournalEntryV1::parse_structural(&bytes)?;
            let path = format!(
                "journal/{}",
                canonical_journal_filename(structural.envelope())
            );
            expected_file_lengths.insert(path.clone(), bytes.len());
            logical_files.push(path);
        }
        let mut identities = BTreeSet::new();
        let mut cursor = 4_usize;
        while cursor < record_set.as_bytes().len() {
            let prefix_end = cursor + crate::RESTORE_RECORD_ITEM_PREFIX_LEN;
            let length = u32::from_le_bytes(
                record_set.as_bytes()[cursor + crate::RESTORE_RECORD_KEY_LEN..prefix_end]
                    .try_into()?,
            ) as usize;
            let key = crate::UnauthenticatedRestoreRecordKeyV1::parse_structural(
                &record_set.as_bytes()[cursor..cursor + crate::RESTORE_RECORD_KEY_LEN],
            )?;
            let identity = crate::canonical_restore_record_directory_name(&key);
            let record = crate::canonical_restore_record_filename(&key);
            identities.insert(identity.clone());
            let path = format!("records/{identity}/{record}");
            expected_file_lengths.insert(path.clone(), length);
            logical_files.push(path);
            cursor = prefix_end + length;
        }
        let mut logical_directories = vec![
            "staging".to_owned(),
            "journal".to_owned(),
            "records".to_owned(),
            "staging-verification".to_owned(),
            "published-verification".to_owned(),
        ];
        logical_directories.extend(identities.into_iter().map(|id| format!("records/{id}")));
        let active_bytes = fs::read(
            initialized
                .temporary
                .path()
                .join("contracts-store")
                .join(ACTIVE_GENERATION),
        )?;
        let generation_tree = snapshot_regular_files(&generation)?;
        Ok(BackupCrashFixture {
            initialized,
            logical_files,
            logical_directories,
            expected_file_lengths,
            active_bytes,
            generation_tree,
        })
    }

    #[test]
    fn recovery_preflight_rejects_unrelated_corruption_without_mutation(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let records =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x91, 0xa1)?;
        let identity = *records.0.identity();
        let mut reservation_id = [0_u8; 32];
        reservation_id.copy_from_slice(records.1.reservation_authority().reservation_id());
        let mut session_id = [0_u8; 32];
        session_id.copy_from_slice(records.0.identity().session_id());
        append_reservations(&initialized, &[records])?;

        let mut store = open_store(&initialized.temporary)?;
        let handle = store.test_handle(reservation_id)?;
        store.persist_nonce_derivation_attempt(&handle, &commitment_attempt(identity, 0x92)?)?;
        drop(store);

        let root = initialized.temporary.path().join("contracts-store");
        let corrupted_claim = generation_path(&initialized)?
            .join("session-claims")
            .join(format!("{}.claim", hex_lower(&session_id)));
        let mut bytes = fs::read(&corrupted_claim)?;
        bytes[0] ^= 0x01;
        fs::write(&corrupted_claim, &bytes)?;
        let before = snapshot_regular_files(&root)?;

        assert!(LiveStoreInventoryV1::open(
            initialized.temporary.capability()?,
            "contracts-store",
            Passphrase::new(b"inventory-test-passphrase".to_vec())?,
        )
        .is_err());
        assert_eq!(snapshot_regular_files(&root)?, before);
        Ok(())
    }

    #[test]
    fn recovery_preflight_rejects_authenticated_orphan_authorized_exposure_without_mutation(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let mut store = open_store(&initialized.temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x93, 0xa3)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let derivation = commitment_attempt(*claim.identity(), 0xb3)?;
        store.persist_nonce_derivation_attempt(&handle, &derivation)?;
        let _persisted =
            store.persist_computed_public_artifact(&handle, derivation.attempt(), &[0xc3; 35])?;

        // Create a fully canonical successor record without its corresponding
        // authenticated journal transition. It is not corrupted bytes: the
        // preflight must reject this projection mismatch before recovery can
        // append a terminal event or otherwise mutate the namespace.
        let persisted = store.find_unique_exposure(
            claim.identity(),
            ArtifactKindV1::Commitment,
            ExposureStateV1::Persisted,
        )?;
        let orphan = ExposureRecordV1::new_successor(&persisted, None)?;
        assert_eq!(orphan.state(), ExposureStateV1::Authorized);
        persist_exposure_projection(store.exposures()?, &orphan)?;
        drop(store);

        let root = initialized.temporary.path().join("contracts-store");
        let before = snapshot_regular_files(&root)?;
        assert!(LiveStoreInventoryV1::open(
            initialized.temporary.capability()?,
            "contracts-store",
            Passphrase::new(b"inventory-test-passphrase".to_vec())?,
        )
        .is_err());
        assert_eq!(snapshot_regular_files(&root)?, before);
        Ok(())
    }

    #[test]
    fn recovery_preflight_rejects_missing_journal_projection_without_mutation(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let mut store = open_store(&initialized.temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x94, 0xa4)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let derivation = commitment_attempt(*claim.identity(), 0xb4)?;
        store.persist_nonce_derivation_attempt(&handle, &derivation)?;
        let _persisted =
            store.persist_computed_public_artifact(&handle, derivation.attempt(), &[0xc4; 35])?;
        let persisted = store.find_unique_exposure(
            claim.identity(),
            ArtifactKindV1::Commitment,
            ExposureStateV1::Persisted,
        )?;
        let structural =
            crate::UnauthenticatedExposureRecordV1::parse_structural(persisted.as_bytes())?;
        let relative = canonical_exposure_relative_path(&structural);
        drop(store);

        let root = initialized.temporary.path().join("contracts-store");
        fs::remove_file(
            generation_path(&initialized)?
                .join("exposures")
                .join(relative),
        )?;
        let before = snapshot_regular_files(&root)?;
        assert!(LiveStoreInventoryV1::open(
            initialized.temporary.capability()?,
            "contracts-store",
            Passphrase::new(b"inventory-test-passphrase".to_vec())?,
        )
        .is_err());
        assert_eq!(snapshot_regular_files(&root)?, before);
        Ok(())
    }

    fn snapshot_regular_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn Error>> {
        fn walk(
            base: &Path,
            current: &Path,
            output: &mut BTreeMap<String, Vec<u8>>,
        ) -> Result<(), Box<dyn Error>> {
            for entry in fs::read_dir(current)? {
                let entry = entry?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.is_dir() {
                    walk(base, &path, output)?;
                } else if metadata.is_file() {
                    output.insert(
                        path.strip_prefix(base)?.to_string_lossy().into_owned(),
                        fs::read(path)?,
                    );
                } else {
                    return Err(Box::new(InventoryError::Filesystem));
                }
            }
            Ok(())
        }
        let mut output = BTreeMap::new();
        walk(root, root, &mut output)?;
        Ok(output)
    }

    fn copy_directory_tree(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
        fs::create_dir(destination)?;
        fs::set_permissions(destination, fs::symlink_metadata(source)?.permissions())?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_path)?;
            if metadata.is_dir() {
                copy_directory_tree(&source_path, &destination_path)?;
            } else if metadata.is_file() {
                fs::copy(&source_path, &destination_path)?;
                fs::set_permissions(&destination_path, metadata.permissions())?;
            } else {
                return Err(Box::new(InventoryError::Filesystem));
            }
        }
        Ok(())
    }

    struct PendingRestoreFixture {
        temporary: TestDirectory,
    }

    fn pending_disk_restore_fixture() -> Result<PendingRestoreFixture, Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let created = ContractsNonceVaultV1::create_evidence_only(
            temporary.capability()?,
            "contracts-store",
            StorageIdsV1::new([0x81; 32], [0x82; 32])?,
            &Passphrase::new(b"step9-initial-passphrase".to_vec())?,
            test_budget_policy()?,
        )?;
        drop(created);
        let marker = temporary.path().join("public-step9-base.marker");
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg(
                "runtime::linux::inventory::tests::child_existing_restore_publish_aborts_at_step9_cut",
            )
            .env("DOM_CONTRACTS_INVENTORY_TEST_ROOT", temporary.path())
            .env("DOM_G1B_RESTORE_CRASH_CUT", "step9-after-root-sync")
            .env("DOM_G1B_RESTORE_CRASH_MARKER", &marker)
            .current_dir(temporary.path())
            .status()?;
        assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
        assert_eq!(fs::read(&marker)?, b"step9-after-root-sync");
        let root = temporary.path().join("contracts-store");
        let unavailable = temporary
            .path()
            .join("source-backup-unavailable-after-step9");
        fs::create_dir(&unavailable)?;
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("backup-") {
                fs::rename(entry.path(), unavailable.join(name))?;
            }
        }
        Ok(PendingRestoreFixture { temporary })
    }

    fn run_backup_crash_cut(cut: &str, logical_path: &str) -> Result<(), Box<dyn Error>> {
        let fixture = backup_crash_fixture()?;
        let root_before = fixture.initialized.temporary.path().join("contracts-store");
        let fixed_before = BTreeMap::from([
            (ROOT_IDENTITY, fs::read(root_before.join(ROOT_IDENTITY))?),
            (LOCK_IDENTITY, fs::read(root_before.join(LOCK_IDENTITY))?),
            (
                ACTIVE_GENERATION,
                fs::read(root_before.join(ACTIVE_GENERATION))?,
            ),
        ]);
        // Every case owns a fresh temporary root, so a fixed short basename is
        // collision-free and remains valid even when the canonical record path
        // approaches NAME_MAX.
        let marker = fixture
            .initialized
            .temporary
            .path()
            .join("backup-crash-cut-reached.marker");
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime::linux::inventory::tests::child_backup_aborts_at_exact_cut")
            .env(
                "DOM_CONTRACTS_INVENTORY_TEST_ROOT",
                fixture.initialized.temporary.path(),
            )
            .env("DOM_G1B_BACKUP_CRASH_CUT", cut)
            .env("DOM_G1B_BACKUP_CRASH_PATH", logical_path)
            .env("DOM_G1B_BACKUP_CRASH_MARKER", &marker)
            .current_dir(fixture.initialized.temporary.path())
            .status()?;
        assert!(
            !status.success(),
            "child unexpectedly survived {cut} at {logical_path}"
        );
        assert_eq!(
            status.signal(),
            Some(6),
            "child did not terminate by SIGABRT"
        );
        assert!(
            marker.is_file(),
            "cut was not reached: {cut} at {logical_path}"
        );
        let root = fixture.initialized.temporary.path().join("contracts-store");
        for (name, bytes) in fixed_before {
            assert_eq!(
                fs::read(root.join(name))?,
                bytes,
                "root authority changed at {name} for {cut} / {logical_path}"
            );
        }
        assert_eq!(
            fs::read(root.join(ACTIVE_GENERATION))?,
            fixture.active_bytes
        );
        assert_eq!(
            snapshot_regular_files(&generation_path(&fixture.initialized)?)?,
            fixture.generation_tree,
            "active generation changed at {cut} / {logical_path}"
        );
        let mut completed = 0_u64;
        let mut staging = 0_u64;
        let mut backup_path = None;
        let mut staging_path = None;
        let mut backup_prefixed_names = BTreeSet::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("backup-") {
                completed += 1;
                backup_prefixed_names.insert(name);
                backup_path = Some(entry.path());
            } else if name.starts_with(".backup-") {
                staging += 1;
                backup_prefixed_names.insert(name);
                staging_path = Some(entry.path());
            }
        }
        let post_rename = logical_path == "published-verification"
            || matches!(
                cut,
                "after-rename-before-root-sync"
                    | "after-root-sync-before-published-reopen"
                    | "after-final-verify-before-return"
            );
        if post_rename {
            assert_eq!(completed, 1);
            assert_eq!(staging, 0);
            let published = backup_path.ok_or(InventoryError::Canonical)?;
            let published_name = published
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(InventoryError::Filesystem)?
                .to_owned();
            assert_eq!(
                backup_prefixed_names,
                BTreeSet::from([published_name.clone()]),
                "unexpected backup-prefixed root entry after {cut}"
            );
            if let Some(expected_length) = fixture.expected_file_lengths.get(logical_path) {
                assert_eq!(
                    fs::metadata(published.join(logical_path))?.len() as usize,
                    *expected_length
                );
            }
            let reopened = open_store(&fixture.initialized.temporary)?;
            // The fixture deliberately begins with a derivation-only crash
            // prefix. Opening it applies the signed burn recovery before the
            // backup operation is sampled, so the authenticated baseline has
            // two reservations, one derivation, and its terminal burn.
            assert_eq!(reopened.snapshot()?.journal_sequence, 4);
            let history = backup::authenticate_completed_history(&reopened.root)?;
            assert_eq!(history.only_backup_name()?, published_name);
            assert_eq!(history.next_generation()?, 2);
            let inputs =
                reopened.current_backup_inputs(BackupPolicyLimitsV1::new(64, 1_048_576)?)?;
            let authenticated = backup::authenticate_completed_backup_for_test(
                &reopened.root,
                &published_name,
                Passphrase::new(b"crash-matrix-backup-passphrase".to_vec())?,
                inputs,
            )?;
            assert_eq!(authenticated.backup_generation(), 1);
            assert_ne!(authenticated.bundle_digest(), &[0; 32]);
        } else {
            assert_eq!(completed, 0);
            let before_staging_create =
                cut == "before-directory-create" && logical_path == "staging";
            assert_eq!(staging, if before_staging_create { 0 } else { 1 });
            if let (Some(staging_root), Some(expected_length)) = (
                staging_path.as_ref(),
                fixture.expected_file_lengths.get(logical_path),
            ) {
                let file = staging_root.join(logical_path);
                let length = fs::metadata(&file)?.len() as usize;
                match cut {
                    "after-file-create-before-write" => assert_eq!(length, 0),
                    "during-proper-prefix-write" => {
                        assert!(length > 0 && length < *expected_length)
                    }
                    "after-full-write-before-file-sync"
                    | "after-file-sync-before-parent-sync"
                    | "after-file-parent-sync-before-reopen"
                    | "after-file-reopen" => assert_eq!(length, *expected_length),
                    _ => {}
                }
            }
            if before_staging_create {
                let reopened = open_store(&fixture.initialized.temporary)?;
                let history = backup::authenticate_completed_history(&reopened.root)?;
                assert_eq!(history.next_generation()?, 1);
                assert!(backup_prefixed_names.is_empty());
            } else {
                assert!(open_store(&fixture.initialized.temporary).is_err());
            }
            if let Some(staging_root) = staging_path {
                let before_retry = snapshot_regular_files(&staging_root)?;
                let staging_name = staging_root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(InventoryError::Filesystem)?
                    .to_owned();
                assert_eq!(
                    backup_prefixed_names,
                    BTreeSet::from([staging_name.clone()]),
                    "unexpected backup-prefixed root entry before publication"
                );
                let parent = fixture.initialized.temporary.capability()?;
                let retained_root = RetainedDirectory::open_under(
                    parent,
                    ValidatedComponent::operator_selected_root("contracts-store")?,
                )?;
                let lock =
                    retained_root.acquire_lock(&ValidatedComponent::registered(LOCK_IDENTITY)?)?;
                assert!(backup::authenticate_completed_history(&retained_root).is_err());
                assert!(retained_root
                    .create_child_directory(ValidatedComponent::registered(&staging_name)?)
                    .is_err());
                drop(lock);
                assert_eq!(snapshot_regular_files(&staging_root)?, before_retry);
            }
        }
        Ok(())
    }

    #[test]
    fn backup_file_crash_cuts_use_real_process_death_for_every_file() -> Result<(), Box<dyn Error>>
    {
        let fixture = backup_crash_fixture()?;
        let files = fixture.logical_files.clone();
        drop(fixture);
        for cut in [
            "after-file-create-before-write",
            "during-proper-prefix-write",
            "after-full-write-before-file-sync",
            "after-file-sync-before-parent-sync",
            "after-file-parent-sync-before-reopen",
            "after-file-reopen",
        ] {
            for path in &files {
                run_backup_crash_cut(cut, path)?;
            }
        }
        Ok(())
    }

    #[test]
    fn backup_directory_creation_and_sync_cuts_use_real_process_death() -> Result<(), Box<dyn Error>>
    {
        let fixture = backup_crash_fixture()?;
        let directories = fixture.logical_directories.clone();
        drop(fixture);
        for cut in [
            "before-directory-create",
            "after-directory-create-before-parent-sync",
            "after-directory-parent-sync",
            "before-directory-sync",
            "after-directory-sync",
        ] {
            for path in &directories {
                if path == "published-verification"
                    && !matches!(cut, "before-directory-sync" | "after-directory-sync")
                {
                    continue;
                }
                if path == "staging-verification"
                    && !matches!(cut, "before-directory-sync" | "after-directory-sync")
                {
                    continue;
                }
                // The staging directory is explicitly synchronized but parent
                // creation hooks also cover its mkdir/root-sync boundary.
                run_backup_crash_cut(cut, path)?;
            }
        }
        Ok(())
    }

    #[test]
    fn backup_publication_cuts_use_real_process_death() -> Result<(), Box<dyn Error>> {
        for cut in [
            "after-staging-verify-before-rename",
            "after-rename-before-root-sync",
            "after-root-sync-before-published-reopen",
            "after-final-verify-before-return",
        ] {
            run_backup_crash_cut(cut, "publication")?;
        }
        Ok(())
    }

    #[test]
    fn normal_root_registry_permits_canonical_history_and_quarantines_staging(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let ids = StorageIdsV1::new([0x21; 32], [0x31; 32])?;
        let passphrase = Passphrase::new(b"root-registry-test-passphrase".to_vec())?;
        let store = LiveStoreInventoryV1::create(
            temporary.capability()?,
            "contracts-store",
            ids,
            &passphrase,
        )?;
        for name in [
            format!("generation-{:020}-{}", 2, "41".repeat(32)),
            format!("backup-{:020}-{}", 1, "42".repeat(32)),
            format!("restore-complete-{}", "43".repeat(16)),
        ] {
            store
                .root
                .create_child_directory(ValidatedComponent::registered(&name)?)?
                .sync()?;
        }
        store.root.create_immutable_file(
            &ValidatedComponent::registered(&format!(
                "restore-initialized-{}.bin",
                "44".repeat(16)
            ))?,
            b"registry-only-test-record",
        )?;
        require_normal_root_inventory(&store.root)?;

        let staging_name = format!(".generation-{:020}-{}.staging", 3, "45".repeat(32));
        store
            .root
            .create_child_directory(ValidatedComponent::registered(&staging_name)?)?
            .sync()?;
        assert_eq!(
            require_normal_root_inventory(&store.root),
            Err(InventoryError::RestoreQuarantined)
        );
        drop(store);
        assert!(
            LiveStoreInventoryV1::open(temporary.capability()?, "contracts-store", passphrase,)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn restored_generation_inventory_allows_only_the_seven_optional_namespaces(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let generation_name = canonical_generation_directory_name(
            &UnauthenticatedVaultGenerationCoreV1::parse_structural(initialized.core.as_bytes())?,
        );
        let generation_path = initialized
            .temporary
            .path()
            .join("contracts-store")
            .join(generation_name);
        for namespace in [
            "reservation-authorities",
            "session-claims",
            "budget-charges",
            "attempts",
            "exposures",
            "nonce-secrets",
            "collaborative-secrets",
        ] {
            // The seven are optional and created lazily: a freshly
            // initialized generation carries six of them, and
            // `collaborative-secrets` only appears once something writes there.
            // An already-absent namespace is the state this test is about, so
            // it is accepted — and only that. Any other removal failure still
            // propagates.
            match fs::remove_dir(generation_path.join(namespace)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            assert!(open_optional_namespace(&initialized.generation, namespace)?.is_none());
        }
        require_generation_inventory(&initialized.generation)?;

        let mut restored_attempts = None;
        ensure_optional_namespace(&initialized.generation, &mut restored_attempts, "attempts")?;
        assert!(restored_attempts.is_some());
        require_generation_inventory(&initialized.generation)?;
        Ok(())
    }

    #[test]
    fn journal_first_reserve_publishes_only_a_complete_projection_set() -> Result<(), Box<dyn Error>>
    {
        let temporary = TestDirectory::create()?;
        let ids = StorageIdsV1::new([0x31; 32], [0x41; 32])?;
        let passphrase = Passphrase::new(b"journal-first-reserve-test-passphrase".to_vec())?;
        let mut store = LiveStoreInventoryV1::create(
            temporary.capability()?,
            "contracts-store",
            ids,
            &passphrase,
        )?;
        let (claim, charge) =
            crate::canonical::reservation::tests::reserve_records(PurposeV1::Funding, 1)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let snapshot = store.snapshot_reservation(&handle)?;
        assert_eq!(snapshot.request_lookup.as_bytes(), &[6; 32]);
        assert_eq!(
            snapshot.live_stage,
            AdaptorReservationLiveStageV1::PreDerivation
        );

        drop(store);
        let reopened =
            LiveStoreInventoryV1::open(temporary.capability()?, "contracts-store", passphrase)?;
        let reopened_snapshot = reopened.snapshot()?;
        assert_eq!(reopened_snapshot.journal_sequence, 1);
        assert_eq!(reopened_snapshot.counts.reservation_authorities, 1);
        assert_eq!(reopened_snapshot.counts.session_claims, 1);
        assert_eq!(reopened_snapshot.counts.budget_charges, 1);
        Ok(())
    }

    #[test]
    fn incomplete_journal_first_prefix_fails_closed_on_reopen() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let ids = StorageIdsV1::new([0x51; 32], [0x61; 32])?;
        let passphrase = Passphrase::new(b"journal-prefix-fail-closed-test-passphrase".to_vec())?;
        let store = LiveStoreInventoryV1::create(
            temporary.capability()?,
            "contracts-store",
            ids,
            &passphrase,
        )?;
        let (claim, charge) =
            crate::canonical::reservation::tests::reserve_records(PurposeV1::Funding, 1)?;
        let entry = JournalEntryV1::first(JournalPayloadV1::reserve(&claim, &charge)?)?;
        let envelope = UnauthenticatedJournalEnvelopeV1::parse_outer(entry.as_bytes())?;
        store.journal.create_immutable_file(
            &ValidatedComponent::registered(&canonical_journal_filename(&envelope))?,
            entry.as_bytes(),
        )?;
        drop(store);

        assert!(matches!(
            LiveStoreInventoryV1::open(temporary.capability()?, "contracts-store", passphrase,),
            Err(InventoryError::RestoreQuarantined)
        ));
        Ok(())
    }

    fn append_reservations(
        initialized: &InitializedStore,
        records: &[(SessionClaimV1, BudgetChargeV1)],
    ) -> Result<(), Box<dyn Error>> {
        let journal = open_namespace(&initialized.generation, "journal")?;
        let authorities = open_namespace(&initialized.generation, "reservation-authorities")?;
        let claims = open_namespace(&initialized.generation, "session-claims")?;
        let charges = open_namespace(&initialized.generation, "budget-charges")?;
        let mut head: Option<JournalEntryV1> = None;
        for (claim, charge) in records {
            let payload = JournalPayloadV1::reserve(claim, charge)?;
            let entry = match head.as_ref() {
                Some(predecessor) => JournalEntryV1::append(predecessor, payload)?,
                None => JournalEntryV1::first(payload)?,
            };
            let envelope = UnauthenticatedJournalEnvelopeV1::parse_outer(entry.as_bytes())?;
            journal.create_immutable_file(
                &ValidatedComponent::registered(&canonical_journal_filename(&envelope))?,
                entry.as_bytes(),
            )?;
            let authority = charge.reservation_authority();
            authorities.create_immutable_file(
                &ValidatedComponent::registered(&format!(
                    "{}.authority",
                    hex_lower(authority.reservation_id())
                ))?,
                authority.as_bytes(),
            )?;
            claims.create_immutable_file(
                &ValidatedComponent::registered(&format!(
                    "{}.claim",
                    hex_lower(claim.identity().session_id())
                ))?,
                claim.as_bytes(),
            )?;
            charges.create_immutable_file(
                &ValidatedComponent::registered(&format!(
                    "{:020}-{}.charge",
                    charge.reserve_journal_sequence(),
                    hex_lower(authority.reservation_id())
                ))?,
                charge.as_bytes(),
            )?;
            head = Some(entry);
        }
        let head = head.ok_or(InventoryError::Canonical)?;
        let active =
            ActiveVaultGenerationV1::new(&initialized.core, head.sequence(), *head.entry_digest())?;
        let staging = ValidatedComponent::registered(".active-vault-generation.staging")?;
        let retained = initialized
            .root
            .create_immutable_file(&staging, active.as_bytes())?;
        initialized.root.replace_active_pointer(
            &staging,
            &ValidatedComponent::registered(ACTIVE_GENERATION)?,
            &retained,
        )?;
        Ok(())
    }

    fn open_store(temporary: &TestDirectory) -> Result<LiveStoreInventoryV1, InventoryError> {
        open_store_with_passphrase(temporary, b"inventory-test-passphrase")
    }

    fn resume_restore_at(parent: Arc<Dir>, passphrase: Passphrase) -> Result<(), InventoryError> {
        let target = ContractsNonceVaultV1::retain_restore_target(parent, "contracts-store")?;
        ContractsNonceVaultV1::resume_restore(target, passphrase)
    }

    fn open_store_with_passphrase(
        temporary: &TestDirectory,
        passphrase: &[u8],
    ) -> Result<LiveStoreInventoryV1, InventoryError> {
        let parent = Arc::new(Dir::from_std_file(
            File::open(temporary.path()).map_err(|_| InventoryError::Filesystem)?,
        ));
        let passphrase =
            Passphrase::new(passphrase.to_vec()).map_err(|_| InventoryError::Crypto)?;
        LiveStoreInventoryV1::open(parent, "contracts-store", passphrase)
    }

    struct NewDeviceSourceFixture {
        source: BackupCrashFixture,
        backup_name: String,
    }

    fn new_device_source_fixture() -> Result<NewDeviceSourceFixture, Box<dyn Error>> {
        let source = backup_crash_fixture()?;
        let mut store = open_store(&source.initialized.temporary)?;
        let backup = store.create_backup(
            Passphrase::new(b"new-device-source-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        )?;
        let backup_name = format!(
            "backup-{:020}-{}",
            backup.backup_generation(),
            hex_lower(backup.backup_id())
        );
        drop(store);
        Ok(NewDeviceSourceFixture {
            source,
            backup_name,
        })
    }

    fn generation_path(initialized: &InitializedStore) -> Result<PathBuf, CanonicalCodecError> {
        let structural =
            UnauthenticatedVaultGenerationCoreV1::parse_structural(initialized.core.as_bytes())?;
        Ok(initialized
            .temporary
            .path()
            .join("contracts-store")
            .join(canonical_generation_directory_name(&structural)))
    }

    #[test]
    fn atomic_snapshot_authenticates_multiple_interleaved_reservations(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let first = crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x41, 0x51)?;
        let (_, second_template) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 2, 0x42, 0x52)?;
        let second = replace_request_lookup(&second_template, 0x09)?;
        let mut first_reservation_id = [0_u8; 32];
        first_reservation_id.copy_from_slice(first.1.reservation_authority().reservation_id());
        append_reservations(&initialized, &[first, second])?;

        assert!(audit_journal(
            &open_namespace(&initialized.generation, "journal")?,
            &BTreeMap::new(),
        )
        .is_ok());
        assert!(audit_authorities(&open_namespace(
            &initialized.generation,
            "reservation-authorities"
        )?)
        .is_ok());
        assert!(audit_claims(&open_namespace(&initialized.generation, "session-claims")?).is_ok());
        assert!(audit_charges(&open_namespace(&initialized.generation, "budget-charges")?).is_ok());

        let store = open_store(&initialized.temporary)?;
        let snapshot = store.snapshot()?;
        assert_eq!(snapshot.journal_sequence, 2);
        assert_eq!(snapshot.counts.journal_entries, 2);
        assert_eq!(snapshot.counts.reservation_authorities, 2);
        assert_eq!(snapshot.counts.session_claims, 2);
        assert_eq!(snapshot.counts.budget_charges, 2);
        assert_ne!(snapshot.open_instance_id, [0; 32]);
        assert_ne!(snapshot.root_identity_digest, [0; 32]);
        assert_ne!(snapshot.active_generation_digest, [0; 32]);
        assert_ne!(snapshot.journal_head_digest, [0; 32]);

        let handle = store.test_handle(first_reservation_id)?;
        let reservation = store.snapshot_reservation(&handle)?;
        assert_eq!(
            reservation.reservation_nonce_id.as_bytes(),
            &first_reservation_id
        );
        assert_ne!(reservation.request_lookup.as_bytes(), &[0; 32]);
        assert_ne!(reservation.context_binding_digest, [0; 32]);
        assert!(matches!(
            reservation.live_stage,
            AdaptorReservationLiveStageV1::PreDerivation
        ));
        assert_eq!(reservation.final_retry_counter, None);
        Ok(())
    }

    #[test]
    fn reservation_snapshot_revalidates_lifecycle_inventory_after_handle_creation(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let reservation =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x62, 0x72)?;
        let identity = reservation.0.identity();
        let identity_name = hex_lower(identity.as_bytes());
        let mut reservation_id = [0_u8; 32];
        reservation_id.copy_from_slice(reservation.1.reservation_authority().reservation_id());
        append_reservations(&initialized, &[reservation])?;

        let store = open_store(&initialized.temporary)?;
        let handle = store.test_handle(reservation_id)?;
        let attempts = open_namespace(&initialized.generation, "attempts")?;
        attempts.create_child_directory(ValidatedComponent::registered(&identity_name)?)?;

        assert!(store.snapshot_reservation(&handle).is_err());
        Ok(())
    }

    #[test]
    fn reservation_snapshot_binds_every_current_generation_nonce_identity_field(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let reservation =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x63, 0x73)?;
        let authority = reservation.1.reservation_authority();
        let mut reservation_id = [0_u8; 32];
        reservation_id.copy_from_slice(authority.reservation_id());
        let original_authority = authority.as_bytes().to_vec();
        let bound_digest_offset = original_authority
            .len()
            .checked_sub(72)
            .ok_or(InventoryError::Canonical)?;
        append_reservations(&initialized, &[reservation])?;
        let store = open_store(&initialized.temporary)?;
        let handle = store.test_handle(reservation_id)?;
        let generation_name = canonical_generation_directory_name(
            &UnauthenticatedVaultGenerationCoreV1::parse_structural(initialized.core.as_bytes())?,
        );
        let authority_path = initialized
            .temporary
            .path()
            .join("contracts-store")
            .join(generation_name)
            .join("reservation-authorities")
            .join(format!("{}.authority", hex_lower(&reservation_id)));

        for offset in [74_usize, 138, 139, 235, bound_digest_offset] {
            let mut mutated = original_authority.clone();
            mutated[offset] ^= 1;
            fs::write(&authority_path, &mutated)?;
            assert!(store.snapshot_reservation(&handle).is_err());
            fs::write(&authority_path, &original_authority)?;
            assert!(store.snapshot_reservation(&handle).is_ok());
        }
        Ok(())
    }

    #[test]
    fn reservation_snapshot_detects_journal_change_during_atomic_revalidation(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let reservation =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x64, 0x74)?;
        let mut reservation_id = [0_u8; 32];
        reservation_id.copy_from_slice(reservation.1.reservation_authority().reservation_id());
        append_reservations(&initialized, &[reservation])?;
        let store = open_store(&initialized.temporary)?;
        let handle = store.test_handle(reservation_id)?;
        let generation_name = canonical_generation_directory_name(
            &UnauthenticatedVaultGenerationCoreV1::parse_structural(initialized.core.as_bytes())?,
        );
        let journal_directory = initialized
            .temporary
            .path()
            .join("contracts-store")
            .join(generation_name)
            .join("journal");
        let journal_path = fs::read_dir(journal_directory)?
            .next()
            .ok_or(InventoryError::Canonical)??
            .path();

        let result = store.snapshot_reservation_inner(&handle, || {
            let mut bytes = fs::read(&journal_path).map_err(|_| InventoryError::Filesystem)?;
            let last = bytes.last_mut().ok_or(InventoryError::Canonical)?;
            *last ^= 1;
            fs::write(&journal_path, bytes).map_err(|_| InventoryError::Filesystem)
        });
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn every_live_operation_revalidates_the_complete_durable_authority_set(
    ) -> Result<(), Box<dyn Error>> {
        for authority_file in [
            ROOT_IDENTITY,
            LOCK_IDENTITY,
            GENERATION_CORE,
            MASTER_KEY_ENVELOPE,
            ACTIVE_GENERATION,
        ] {
            let initialized = initialize()?;
            let store = open_store(&initialized.temporary)?;
            let root_path = initialized.temporary.path().join("contracts-store");
            let generation_name = canonical_generation_directory_name(
                &UnauthenticatedVaultGenerationCoreV1::parse_structural(
                    initialized.core.as_bytes(),
                )?,
            );
            let authority_path = match authority_file {
                ROOT_IDENTITY | LOCK_IDENTITY | ACTIVE_GENERATION => root_path.join(authority_file),
                GENERATION_CORE | MASTER_KEY_ENVELOPE => {
                    root_path.join(&generation_name).join(authority_file)
                }
                _ => return Err(Box::new(InventoryError::Canonical)),
            };
            let mut bytes = fs::read(&authority_path)?;
            let mutation_index = bytes.len() / 2;
            bytes[mutation_index] ^= 1;
            fs::write(&authority_path, bytes)?;
            assert!(
                store.snapshot().is_err(),
                "live authority mutation was accepted for {authority_file}",
            );
        }
        Ok(())
    }

    fn commitment_attempt(
        identity: NonceIdentityV1,
        marker: u8,
    ) -> Result<NonceDerivationAttemptV1, CanonicalCodecError> {
        let attempt =
            AttemptRecordV1::new(identity, 1, SigningPhaseV1::SigNonceCommit, [marker; 32])?;
        NonceDerivationAttemptV1::new(&attempt, 3)
    }

    fn test_budget_policy() -> Result<BudgetPolicyV1, CanonicalCodecError> {
        let mut bytes = [0_u8; crate::BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(b"DOMNVBP1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = crate::BudgetPolicyProfileV1::EvidenceOnly as u8;
        bytes[11] = 1;
        bytes[16..48].fill(0x41);
        bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&100_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&100_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&3_600_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
        let digest =
            authoritative_storage_hash_v1(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
        bytes[112..].copy_from_slice(&digest);
        BudgetPolicyV1::from_bytes(&bytes)
    }

    fn replace_request_lookup(
        charge: &BudgetChargeV1,
        request_lookup_byte: u8,
    ) -> Result<(SessionClaimV1, BudgetChargeV1), CanonicalCodecError> {
        let mut charge_bytes = charge.as_bytes().to_vec();
        let authority_length = charge.reservation_authority().as_bytes().len();
        let authority_end = 10_usize
            .checked_add(authority_length)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let authority = &mut charge_bytes[10..authority_end];
        authority[203..235].fill(request_lookup_byte);
        let binding_length = usize::try_from(u32::from_le_bytes(
            authority[275..279]
                .try_into()
                .map_err(|_| CanonicalCodecError::InvalidEncoding)?,
        ))
        .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let bound_offset = 279_usize
            .checked_add(binding_length)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let bound = authoritative_storage_hash_v1(
            StorageHashDomainV1::ReservationBinding,
            &authority[10..bound_offset],
        );
        authority[bound_offset..bound_offset + 32].copy_from_slice(&bound);
        let authority_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::ReservationAuthority,
            &authority[..bound_offset + 40],
        );
        authority[bound_offset + 40..bound_offset + 72].copy_from_slice(&authority_digest);
        let charge_digest_offset = charge_bytes
            .len()
            .checked_sub(32)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        let charge_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::BudgetCharge,
            &charge_bytes[..charge_digest_offset],
        );
        charge_bytes[charge_digest_offset..].copy_from_slice(&charge_digest);
        let charge = BudgetChargeV1::from_bytes(&charge_bytes)?;
        let claim = SessionClaimV1::new(charge.reservation_authority().nonce_identity()?)?;
        Ok((claim, charge))
    }

    fn replace_nonce_epoch(
        charge: BudgetChargeV1,
        nonce_epoch: u64,
    ) -> Result<(SessionClaimV1, BudgetChargeV1), CanonicalCodecError> {
        let mut charge_bytes = charge.as_bytes().to_vec();
        let authority_length = charge.reservation_authority().as_bytes().len();
        let authority_end = 10_usize
            .checked_add(authority_length)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let authority = &mut charge_bytes[10..authority_end];
        authority[235..243].copy_from_slice(&nonce_epoch.to_le_bytes());
        let binding_length = usize::try_from(u32::from_le_bytes(
            authority[275..279]
                .try_into()
                .map_err(|_| CanonicalCodecError::InvalidEncoding)?,
        ))
        .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let bound_offset = 279_usize
            .checked_add(binding_length)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        let bound = authoritative_storage_hash_v1(
            StorageHashDomainV1::ReservationBinding,
            &authority[10..bound_offset],
        );
        authority[bound_offset..bound_offset + 32].copy_from_slice(&bound);
        let authority_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::ReservationAuthority,
            &authority[..bound_offset + 40],
        );
        authority[bound_offset + 40..bound_offset + 72].copy_from_slice(&authority_digest);
        let charge_digest_offset = charge_bytes
            .len()
            .checked_sub(32)
            .ok_or(CanonicalCodecError::InvalidEncoding)?;
        let charge_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::BudgetCharge,
            &charge_bytes[..charge_digest_offset],
        );
        charge_bytes[charge_digest_offset..].copy_from_slice(&charge_digest);
        let charge = BudgetChargeV1::from_bytes(&charge_bytes)?;
        let claim = SessionClaimV1::new(charge.reservation_authority().nonce_identity()?)?;
        Ok((claim, charge))
    }

    #[test]
    fn nonce_derivation_retry_counter_equivocation_fails_closed() -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let mut store = open_store(&initialized.temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x80, 0x90)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let derivation = commitment_attempt(*claim.identity(), 0xa0)?;
        store.persist_nonce_derivation_attempt(&handle, &derivation)?;
        let conflicting = NonceDerivationAttemptV1::new(derivation.attempt(), 4)?;
        assert!(store
            .persist_nonce_derivation_attempt(&handle, &conflicting)
            .is_err());
        let durable = read_nonce_derivation_attempt(
            store.attempts()?,
            &hex_lower(claim.identity().as_bytes()),
        )?;
        assert_eq!(durable.as_bytes(), derivation.as_bytes());
        store.snapshot()?;
        Ok(())
    }

    #[test]
    fn retained_public_exposure_spends_before_export_and_rejects_double_authorization(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let mut store = open_store(&initialized.temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x81, 0x91)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let derivation = commitment_attempt(*claim.identity(), 0xa1)?;
        store.persist_nonce_derivation_attempt(&handle, &derivation)?;

        let exact_bytes = [0xb2_u8; 35];
        let persisted =
            store.persist_computed_public_artifact(&handle, derivation.attempt(), &exact_bytes)?;
        let duplicate = PersistedExposureHandleV1 {
            authority: Arc::clone(&persisted.authority),
            issuance: CapabilityIssuanceV1 {
                open_instance_id: persisted.issuance.open_instance_id,
                root_identity_digest: persisted.issuance.root_identity_digest,
                lock_identity_digest: persisted.issuance.lock_identity_digest,
                vault_id: persisted.issuance.vault_id,
                nonce_epoch: persisted.issuance.nonce_epoch,
                generation: persisted.issuance.generation,
                journal_sequence: persisted.issuance.journal_sequence,
                journal_head_digest: persisted.issuance.journal_head_digest,
            },
            reservation_id: persisted.reservation_id,
            nonce_identity: persisted.nonce_identity,
            attempt_digest: persisted.attempt_digest,
            operation_input_digest: persisted.operation_input_digest,
            phase: persisted.phase,
            artifact: persisted.artifact,
            exposure_sequence: persisted.exposure_sequence,
            expected_lifecycle_revision: persisted.expected_lifecycle_revision,
            persisted_lifecycle_revision: persisted.persisted_lifecycle_revision,
            exposure_version: persisted.exposure_version.clone(),
            exposure_record_digest: persisted.exposure_record_digest,
            outbound_digest: persisted.outbound_digest,
            outbound_length: persisted.outbound_length,
            persistence_journal_digest: persisted.persistence_journal_digest,
            consumed_tombstone_digest: persisted.consumed_tombstone_digest,
            deleted_secret_envelope_digest: persisted.deleted_secret_envelope_digest,
        };
        let permit = store.authorize_persisted_public_exposure(&handle, persisted)?;
        let exported = store.export_public_artifact(permit)?;
        assert_eq!(exported.kind, ArtifactKindV1::Commitment);
        assert_eq!(exported.outbound_bytes, exact_bytes);

        // A second authorization would be the only possible route to a
        // second first-export capability. It fails before any durable write.
        assert!(store
            .authorize_persisted_public_exposure(&handle, duplicate)
            .is_err());
        assert!(store.snapshot().is_ok());

        drop(store);
        let reopened = open_store(&initialized.temporary)?;
        assert!(reopened.snapshot().is_ok());
        Ok(())
    }

    #[test]
    fn persisted_handle_retains_exact_store_lock_and_loss_burns_without_reconstruction(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let mut store = open_store(&initialized.temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x93, 0xa3)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let derivation = commitment_attempt(*claim.identity(), 0xb3)?;
        store.persist_nonce_derivation_attempt(&handle, &derivation)?;
        let persisted =
            store.persist_computed_public_artifact(&handle, derivation.attempt(), &[0xc3; 35])?;
        drop(store);

        assert!(
            open_store(&initialized.temporary).is_err(),
            "the persisted handle did not retain the exact live lock authority",
        );
        drop(persisted);

        let reopened = open_store(&initialized.temporary)?;
        let identity_name = hex_lower(claim.identity().as_bytes());
        let tombstone = reopened.read_authenticated_tombstone(&identity_name)?;
        assert_eq!(tombstone.reason(), crate::TerminalReasonV1::Burned);
        assert!(!reopened.exposure_occurs(
            claim.identity(),
            ArtifactKindV1::Commitment,
            Some(ExposureStateV1::Authorized),
        )?);
        reopened.snapshot()?;
        Ok(())
    }

    #[test]
    fn capabilities_reject_cross_store_and_cross_session_use() -> Result<(), Box<dyn Error>> {
        let initialized_a = initialize()?;
        let initialized_b = initialize()?;
        let mut store_a = open_store(&initialized_a.temporary)?;
        let mut store_b = open_store(&initialized_b.temporary)?;
        let (claim_a, charge_a) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x84, 0x94)?;
        let handle_a = store_a.persist_reservation(&claim_a, &charge_a)?;

        assert!(store_b.snapshot_reservation(&handle_a).is_err());

        let (foreign_claim, _) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 2, 0x85, 0x95)?;
        let foreign_attempt = commitment_attempt(*foreign_claim.identity(), 0xa5)?;
        assert!(store_a
            .persist_nonce_derivation_attempt(&handle_a, &foreign_attempt)
            .is_err());

        let derivation_a = commitment_attempt(*claim_a.identity(), 0xa4)?;
        store_a.persist_nonce_derivation_attempt(&handle_a, &derivation_a)?;
        let persisted_a = store_a.persist_computed_public_artifact(
            &handle_a,
            derivation_a.attempt(),
            &[0xc4; 35],
        )?;
        let permit_a = store_a.authorize_persisted_public_exposure(&handle_a, persisted_a)?;
        assert!(store_b.export_public_artifact(permit_a).is_err());
        store_a.snapshot()?;
        store_b.snapshot()?;
        Ok(())
    }

    #[test]
    fn stable_reservation_authority_allows_multi_session_journal_append(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let mut store = open_store(&initialized.temporary)?;
        let (first_claim, first_charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x82, 0x92)?;
        let first_handle = store.persist_reservation(&first_claim, &first_charge)?;
        let first_attempt = commitment_attempt(*first_claim.identity(), 0xa2)?;
        store.persist_nonce_derivation_attempt(&first_handle, &first_attempt)?;
        let persisted = store.persist_computed_public_artifact(
            &first_handle,
            first_attempt.attempt(),
            &[0xc1; 35],
        )?;
        let permit = store.authorize_persisted_public_exposure(&first_handle, persisted)?;
        let _exported = store.export_public_artifact(permit)?;

        let (_, second_charge_template) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 6, 0x83, 0x93)?;
        let (second_claim, second_charge) = replace_request_lookup(&second_charge_template, 0x07)?;
        assert_ne!(
            first_charge.reservation_authority().reservation_id(),
            second_charge.reservation_authority().reservation_id()
        );
        assert_ne!(
            first_charge.reservation_authority().session_id(),
            second_charge.reservation_authority().session_id()
        );
        assert_ne!(
            first_charge.reservation_authority().request_lookup_id(),
            second_charge.reservation_authority().request_lookup_id()
        );
        assert_ne!(
            first_charge
                .reservation_authority()
                .context_binding()
                .as_bytes(),
            second_charge
                .reservation_authority()
                .context_binding()
                .as_bytes()
        );
        let second_handle = store.persist_reservation(&second_claim, &second_charge)?;
        let second_attempt = commitment_attempt(*second_claim.identity(), 0xa3)?;
        store.persist_nonce_derivation_attempt(&second_handle, &second_attempt)?;
        let second_persisted = store.persist_computed_public_artifact(
            &second_handle,
            second_attempt.attempt(),
            &[0xc2; 35],
        )?;
        let second_permit =
            store.authorize_persisted_public_exposure(&second_handle, second_persisted)?;
        let second_exported = store.export_public_artifact(second_permit)?;
        assert_eq!(second_exported.outbound_bytes, [0xc2; 35]);
        assert_eq!(store.snapshot()?.journal_sequence, 10);
        Ok(())
    }

    #[test]
    fn retained_abort_is_terminal_and_reopens_without_public_material() -> Result<(), Box<dyn Error>>
    {
        let initialized = initialize()?;
        let mut store = open_store(&initialized.temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x85, 0x95)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let state = store.persist_terminal_reservation(&handle, false)?;
        assert_eq!(state, ReservationState::AbortedBeforePublicMaterial);
        let snapshot = store.snapshot()?;
        assert_eq!(snapshot.journal_sequence, 2);
        assert_eq!(snapshot.counts.tombstones, 1);

        drop(store);
        let reopened = open_store(&initialized.temporary)?;
        let reopened_snapshot = reopened.snapshot()?;
        assert_eq!(reopened_snapshot.journal_sequence, 2);
        assert_eq!(reopened_snapshot.counts.tombstones, 1);
        Ok(())
    }

    #[test]
    fn retained_orphan_claim_burn_is_terminal_and_reopens() -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let mut store = open_store(&initialized.temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 1, 0x86, 0x96)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let state = store.persist_terminal_reservation(&handle, true)?;
        assert_eq!(state, ReservationState::Burned);
        assert_eq!(store.snapshot()?.journal_sequence, 2);

        drop(store);
        let reopened = open_store(&initialized.temporary)?;
        assert_eq!(reopened.snapshot()?.counts.tombstones, 1);
        Ok(())
    }

    #[test]
    fn incomplete_or_mutated_terminal_prefixes_fail_closed() -> Result<(), Box<dyn Error>> {
        for mutation in 0_u8..4 {
            let initialized = initialize()?;
            let mut store = open_store(&initialized.temporary)?;
            let (claim, charge) = crate::canonical::reserve_records_with_ids(
                PurposeV1::Funding,
                1,
                0x87_u8
                    .checked_add(mutation)
                    .ok_or(InventoryError::Canonical)?,
                0x97_u8
                    .checked_add(mutation)
                    .ok_or(InventoryError::Canonical)?,
            )?;
            let handle = store.persist_reservation(&claim, &charge)?;
            assert_eq!(
                store.persist_terminal_reservation(&handle, true)?,
                ReservationState::Burned
            );
            let identity_name = hex_lower(claim.identity().as_bytes());
            let generation = generation_path(&initialized)?;
            let tombstone = generation
                .join("tombstones")
                .join(format!("{identity_name}.tombstone"));
            let mut journal_entries: Vec<PathBuf> = fs::read_dir(generation.join("journal"))?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<Result<_, _>>()?;
            journal_entries.sort();
            let terminal_journal = journal_entries
                .last()
                .ok_or(InventoryError::Canonical)?
                .clone();
            drop(store);

            match mutation {
                // Journal exists, but its encrypted terminal projection is missing.
                0 => fs::remove_file(&tombstone)?,
                // Tombstone exists, but its terminal journal projection is missing.
                1 => fs::remove_file(&terminal_journal)?,
                // Authenticated envelope mutation must fail before plaintext use.
                2 => {
                    let mut bytes = fs::read(&tombstone)?;
                    let index = bytes.len() / 2;
                    bytes[index] ^= 1;
                    fs::set_permissions(&tombstone, fs::Permissions::from_mode(0o600))?;
                    fs::write(&tombstone, bytes)?;
                }
                // A staging name never grants terminal authority.
                3 => fs::rename(
                    &tombstone,
                    generation
                        .join("tombstones")
                        .join(format!(".{identity_name}.tombstone.staging")),
                )?,
                _ => return Err(Box::new(InventoryError::Canonical)),
            }
            assert!(open_store(&initialized.temporary).is_err());
        }
        Ok(())
    }

    #[test]
    fn computed_artifact_journal_prefix_without_projection_fails_closed(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let mut store = open_store(&initialized.temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x84, 0x94)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let derivation = commitment_attempt(*claim.identity(), 0xa4)?;
        store.persist_nonce_derivation_attempt(&handle, &derivation)?;
        let persisted = ExposureRecordV1::new_persisted(derivation.attempt(), None, &[0xd1; 35])?;
        let payload = JournalPayloadV1::persisted(derivation.attempt(), None, &persisted)?;
        let entry = store.next_journal_entry(payload)?;
        store.persist_journal_entry(&entry)?;
        drop(store);

        assert!(open_store(&initialized.temporary).is_err());
        Ok(())
    }

    #[test]
    fn inventory_is_complete_before_a_snapshot_can_be_returned() -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let reservation =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x61, 0x71)?;
        append_reservations(&initialized, &[reservation])?;
        fs::write(
            initialized
                .temporary
                .path()
                .join("contracts-store")
                .join(canonical_generation_directory_name(
                    &UnauthenticatedVaultGenerationCoreV1::parse_structural(
                        initialized.core.as_bytes(),
                    )?,
                ))
                .join("reservation-authorities")
                .join(format!("{}.authority", "a".repeat(64))),
            b"invalid",
        )?;
        fs::set_permissions(
            initialized
                .temporary
                .path()
                .join("contracts-store")
                .join(canonical_generation_directory_name(
                    &UnauthenticatedVaultGenerationCoreV1::parse_structural(
                        initialized.core.as_bytes(),
                    )?,
                ))
                .join("reservation-authorities")
                .join(format!("{}.authority", "a".repeat(64))),
            fs::Permissions::from_mode(0o600),
        )?;

        assert!(open_store(&initialized.temporary).is_err());
        Ok(())
    }

    #[test]
    fn store_open_authenticates_the_ratified_master_key_sealer() -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let parent = Arc::new(Dir::from_std_file(File::open(
            initialized.temporary.path(),
        )?));
        let wrong = Passphrase::new(b"incorrect-inventory-passphrase".to_vec())?;
        assert!(matches!(
            LiveStoreInventoryV1::open(parent, "contracts-store", wrong),
            Err(InventoryError::Crypto)
        ));
        Ok(())
    }

    #[test]
    fn retained_inventory_lock_rejects_a_concurrent_process() -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let _store = open_store(&initialized.temporary)?;
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime::linux::inventory::tests::child_inventory_observes_busy_store")
            .env(
                "DOM_CONTRACTS_INVENTORY_TEST_ROOT",
                initialized.temporary.path(),
            )
            .current_dir(initialized.temporary.path())
            .status()?;
        assert!(status.success());
        Ok(())
    }

    #[test]
    fn retained_inventory_lock_allows_exactly_one_concurrent_thread() -> Result<(), Box<dyn Error>>
    {
        let initialized = initialize()?;
        let path = initialized.temporary.path().to_path_buf();
        let barrier = StdArc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = barrier.clone();
            workers.push(thread::spawn(move || -> Result<bool, InventoryError> {
                let parent = Arc::new(Dir::from_std_file(
                    File::open(path).map_err(|_| InventoryError::Filesystem)?,
                ));
                barrier.wait();
                match LiveStoreInventoryV1::open(
                    parent,
                    "contracts-store",
                    Passphrase::new(b"inventory-test-passphrase".to_vec())
                        .map_err(|_| InventoryError::Crypto)?,
                ) {
                    Ok(store) => {
                        thread::sleep(Duration::from_millis(250));
                        store.snapshot()?;
                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            }));
        }
        let mut successes = 0_u8;
        for worker in workers {
            if worker.join().map_err(|_| InventoryError::Filesystem)?? {
                successes = successes.checked_add(1).ok_or(InventoryError::Canonical)?;
            }
        }
        assert_eq!(successes, 1);
        Ok(())
    }

    #[test]
    fn abrupt_process_death_does_not_mutate_the_authenticated_inventory(
    ) -> Result<(), Box<dyn Error>> {
        let initialized = initialize()?;
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime::linux::inventory::tests::child_inventory_aborts_after_open")
            .env(
                "DOM_CONTRACTS_INVENTORY_TEST_ROOT",
                initialized.temporary.path(),
            )
            .current_dir(initialized.temporary.path())
            .status()?;
        assert!(!status.success());
        let reopened = open_store(&initialized.temporary)?;
        let snapshot = reopened.snapshot()?;
        assert_eq!(snapshot.journal_sequence, 0);
        assert_eq!(snapshot.counts.journal_entries, 0);
        Ok(())
    }

    #[test]
    fn normal_vault_process_death_matrix_reopens_at_each_durable_state_without_nonce_reuse(
    ) -> Result<(), Box<dyn Error>> {
        let cuts = [
            ("attempt-after-durable-commit-before-return", None),
            (
                "persisted-after-durable-commit-before-return",
                Some(ExposureStateV1::Persisted),
            ),
            (
                "authorized-after-durable-commit-before-permit",
                Some(ExposureStateV1::Spent),
            ),
            (
                "export-after-durable-spent-before-return",
                Some(ExposureStateV1::Spent),
            ),
        ];
        for (cut, expected_exposure) in cuts {
            let initialized = initialize()?;
            let marker = initialized
                .temporary
                .path()
                .join(format!("normal-vault-{cut}.marker"));
            let status = Command::new(std::env::current_exe()?)
                .arg("--ignored")
                .arg("--exact")
                .arg("runtime::linux::inventory::tests::child_normal_vault_aborts_at_exact_cut")
                .env(
                    "DOM_CONTRACTS_INVENTORY_TEST_ROOT",
                    initialized.temporary.path(),
                )
                .env("DOM_G1B_NORMAL_VAULT_CRASH_CUT", cut)
                .env("DOM_G1B_NORMAL_VAULT_CRASH_MARKER", &marker)
                .current_dir(initialized.temporary.path())
                .status()?;
            assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
            assert_eq!(fs::read(marker)?, cut.as_bytes());

            let mut reopened = open_store(&initialized.temporary)?;
            let (claim, charge) =
                crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x8b, 0x9b)?;
            for state in [
                ExposureStateV1::Persisted,
                ExposureStateV1::Authorized,
                ExposureStateV1::Spent,
            ] {
                assert_eq!(
                    reopened.exposure_occurs(
                        claim.identity(),
                        ArtifactKindV1::Commitment,
                        Some(state),
                    )?,
                    expected_exposure
                        .map(|last| (state as u8) <= (last as u8))
                        .unwrap_or(false),
                    "unexpected durable exposure state after {cut}",
                );
            }
            assert!(reopened.persist_reservation(&claim, &charge).is_err());
            reopened.snapshot()?;
        }
        Ok(())
    }

    #[test]
    fn new_device_restore_publication_has_one_authority_and_exact_marker_transition(
    ) -> Result<(), Box<dyn Error>> {
        let source = new_device_source_fixture()?;
        let destination = TestDirectory::create()?;
        let limits = BackupPolicyLimitsV1::new(64, 1_048_576)?;
        let policy = test_budget_policy()?;
        let vault = ContractsNonceVaultV1::publish_new_device_restore_evidence_only(
            NewDeviceRestoreEvidenceRequestV1 {
                source_parent: source.source.initialized.temporary.capability()?,
                source_root_name: "contracts-store".to_owned(),
                selected_backup_name: source.backup_name.clone(),
                source_backup_passphrase: Passphrase::new(
                    b"new-device-source-backup-passphrase".to_vec(),
                )?,
                destination_parent: destination.capability()?,
                destination_root_name: "restored-store".to_owned(),
                target_unlock_passphrase: Passphrase::new(
                    b"new-device-target-passphrase".to_vec(),
                )?,
                limits,
                budget_policy: policy.clone(),
            },
        )?;
        let snapshot = vault.store.snapshot()?;
        assert_eq!(snapshot.counts.tombstones, 2);
        let (budget_carries, permit_carries) = vault.authenticated_lifetime_carry_bytes()?;
        assert_eq!(budget_carries.len(), 2);
        assert!(permit_carries.is_empty());

        let root_path = destination.path().join("restored-store");
        assert!(!root_path.join("restore-only-root.bin").exists());
        let initialized_markers = fs::read_dir(&root_path)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("restore-initialized-")
            })
            .collect::<Vec<_>>();
        assert_eq!(initialized_markers.len(), 1);
        let marker_bytes = fs::read(initialized_markers[0].path())?;
        let marker = crate::canonical::RestoreOnlyRootV1::from_bytes(&marker_bytes)?;
        assert_eq!(
            initialized_markers[0].file_name().to_string_lossy(),
            crate::canonical_restore_initialized_marker_name(&marker),
        );
        assert!(ContractsNonceVaultV1::open_evidence_only(
            destination.capability()?,
            "restored-store",
            Passphrase::new(b"new-device-target-passphrase".to_vec())?,
            policy.clone(),
        )
        .is_err());
        drop(vault);
        let reopened = ContractsNonceVaultV1::open_evidence_only(
            destination.capability()?,
            "restored-store",
            Passphrase::new(b"new-device-target-passphrase".to_vec())?,
            policy.clone(),
        )?;
        reopened.store.snapshot()?;
        drop(reopened);

        assert!(
            ContractsNonceVaultV1::publish_new_device_restore_evidence_only(
                NewDeviceRestoreEvidenceRequestV1 {
                    source_parent: source.source.initialized.temporary.capability()?,
                    source_root_name: "contracts-store".to_owned(),
                    selected_backup_name: source.backup_name.clone(),
                    source_backup_passphrase: Passphrase::new(
                        b"new-device-source-backup-passphrase".to_vec(),
                    )?,
                    destination_parent: destination.capability()?,
                    destination_root_name: "restored-store".to_owned(),
                    target_unlock_passphrase: Passphrase::new(
                        b"second-target-passphrase".to_vec(),
                    )?,
                    limits,
                    budget_policy: policy,
                },
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn new_device_restore_only_root_is_exact_and_rejects_identity_or_bundle_substitution(
    ) -> Result<(), Box<dyn Error>> {
        for (file_name, offset) in [
            (ROOT_IDENTITY, 10_usize),
            (ROOT_IDENTITY, 42),
            (ROOT_IDENTITY, 74),
            (LOCK_IDENTITY, 10),
            ("restore-only-root.bin", 90),
        ] {
            let source = new_device_source_fixture()?;
            let selected = restore::authenticate_selected_backup(
                &source.source.initialized.root,
                &source.backup_name,
                Passphrase::new(b"new-device-source-backup-passphrase".to_vec())?,
                BackupPolicyLimitsV1::new(64, 1_048_576)?,
            )?;
            let destination = TestDirectory::create()?;
            let (initialized, preparation) = restore::initialize_new_device_restore_only_root(
                destination.capability()?,
                "restore-only-target",
                selected,
            )?;
            let mut names = BTreeSet::new();
            initialized.root().scan_independent(|name, _| {
                names.insert(name.to_owned());
                Ok(())
            })?;
            assert_eq!(
                names,
                BTreeSet::from([
                    ROOT_IDENTITY.to_owned(),
                    LOCK_IDENTITY.to_owned(),
                    "restore-only-root.bin".to_owned(),
                ])
            );
            assert!(LiveStoreInventoryV1::open(
                destination.capability()?,
                "restore-only-target",
                Passphrase::new(b"new-device-target-passphrase".to_vec())?,
            )
            .is_err());
            let path = destination
                .path()
                .join("restore-only-target")
                .join(file_name);
            let mut bytes = fs::read(&path)?;
            *bytes.get_mut(offset).ok_or(InventoryError::Canonical)? ^= 0x01;
            overwrite_immutable_test_file(&path, &bytes)?;
            let publication = restore::PreparedNewDeviceRestorePublicationV1::new(
                preparation,
                initialized.root_identity(),
                initialized.restore_only_root().clone(),
                &Passphrase::new(b"new-device-target-passphrase".to_vec())?,
                BackupPolicyLimitsV1::new(64, 1_048_576)?,
            )?;
            assert!(restore::stage_new_device_restore(&initialized, publication).is_err());
        }
        Ok(())
    }

    #[test]
    fn new_device_restore_process_death_resumes_exact_durable_prefixes(
    ) -> Result<(), Box<dyn Error>> {
        let source = new_device_source_fixture()?;
        let destination = TestDirectory::create()?;
        let cuts = [
            "step9-after-root-sync",
            "step10-after-root-sync",
            "step11-after-root-sync",
            "step13-after-root-sync",
            "step15-before-marker-rename",
            "step15-after-marker-rename",
        ];
        for (index, cut) in cuts.into_iter().enumerate() {
            let target_name = format!("restore-target-{index}");
            let marker = destination
                .path()
                .join(format!("{target_name}-{cut}.marker"));
            let status = Command::new(std::env::current_exe()?)
                .arg("--ignored")
                .arg("--exact")
                .arg("runtime::linux::inventory::tests::child_new_device_restore_aborts_at_exact_cut")
                .env("DOM_G1B_NEW_DEVICE_SOURCE_PARENT", source.source.initialized.temporary.path())
                .env("DOM_G1B_NEW_DEVICE_BACKUP_NAME", &source.backup_name)
                .env("DOM_G1B_NEW_DEVICE_TARGET_PARENT", destination.path())
                .env("DOM_G1B_NEW_DEVICE_TARGET_NAME", &target_name)
                .env("DOM_G1B_RESTORE_CRASH_CUT", cut)
                .env("DOM_G1B_RESTORE_CRASH_MARKER", &marker)
                .current_dir(destination.path())
                .status()?;
            assert_eq!(status.signal(), Some(nix::libc::SIGABRT));
            assert_eq!(fs::read(marker)?, cut.as_bytes());
            let target_path = destination.path().join(&target_name);
            if matches!(cut, "step9-after-root-sync" | "step10-after-root-sync") {
                assert!(!target_path.join(ACTIVE_GENERATION).exists());
            }

            let ordinary_before = LiveStoreInventoryV1::open(
                destination.capability()?,
                &target_name,
                Passphrase::new(b"new-device-crash-target-passphrase".to_vec())?,
            );
            // Once step 13 has atomically renamed the pending transaction to
            // completed state and synchronized the root, the canonical normal
            // Store authority is already complete.  The later marker rename
            // records restore-only initialization, not a prerequisite for
            // opening the authenticated active generation.
            if matches!(
                cut,
                "step13-after-root-sync"
                    | "step15-before-marker-rename"
                    | "step15-after-marker-rename"
            ) {
                let reopened = ordinary_before?;
                reopened.snapshot()?;
            } else {
                assert!(ordinary_before.is_err());
                let retained = ContractsNonceVaultV1::retain_restore_target(
                    destination.capability()?,
                    &target_name,
                )?;
                ContractsNonceVaultV1::resume_restore(
                    retained,
                    Passphrase::new(b"new-device-crash-target-passphrase".to_vec())?,
                )?;
                let reopened = LiveStoreInventoryV1::open(
                    destination.capability()?,
                    &target_name,
                    Passphrase::new(b"new-device-crash-target-passphrase".to_vec())?,
                )?;
                reopened.snapshot()?;
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper invoked by retained_inventory_lock_rejects_a_concurrent_process"]
    fn child_inventory_observes_busy_store() -> Result<(), Box<dyn Error>> {
        let path = std::env::var_os("DOM_CONTRACTS_INVENTORY_TEST_ROOT")
            .ok_or(InventoryError::Filesystem)?;
        let temporary = TestDirectory {
            path: PathBuf::from(path),
        };
        assert!(open_store(&temporary).is_err());
        std::mem::forget(temporary);
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper invoked by the new-device restore crash matrix"]
    fn child_new_device_restore_aborts_at_exact_cut() -> Result<(), Box<dyn Error>> {
        let source_parent = PathBuf::from(
            std::env::var_os("DOM_G1B_NEW_DEVICE_SOURCE_PARENT")
                .ok_or(InventoryError::Filesystem)?,
        );
        let target_parent = PathBuf::from(
            std::env::var_os("DOM_G1B_NEW_DEVICE_TARGET_PARENT")
                .ok_or(InventoryError::Filesystem)?,
        );
        let backup_name = std::env::var("DOM_G1B_NEW_DEVICE_BACKUP_NAME")?;
        let target_name = std::env::var("DOM_G1B_NEW_DEVICE_TARGET_NAME")?;
        let source_parent = Arc::new(Dir::from_std_file(File::open(source_parent)?));
        let target_parent = Arc::new(Dir::from_std_file(File::open(target_parent)?));
        let result = ContractsNonceVaultV1::publish_new_device_restore_evidence_only(
            NewDeviceRestoreEvidenceRequestV1 {
                source_parent,
                source_root_name: "contracts-store".to_owned(),
                selected_backup_name: backup_name,
                source_backup_passphrase: Passphrase::new(
                    b"new-device-source-backup-passphrase".to_vec(),
                )?,
                destination_parent: target_parent,
                destination_root_name: target_name,
                target_unlock_passphrase: Passphrase::new(
                    b"new-device-crash-target-passphrase".to_vec(),
                )?,
                limits: BackupPolicyLimitsV1::new(64, 1_048_576)?,
                budget_policy: test_budget_policy()?,
            },
        );
        result?;
        Err(Box::new(InventoryError::Canonical))
    }

    #[test]
    #[ignore = "subprocess helper invoked by abrupt_process_death_does_not_mutate_the_authenticated_inventory"]
    fn child_inventory_aborts_after_open() -> Result<(), Box<dyn Error>> {
        let path = std::env::var_os("DOM_CONTRACTS_INVENTORY_TEST_ROOT")
            .ok_or(InventoryError::Filesystem)?;
        let temporary = TestDirectory {
            path: PathBuf::from(path),
        };
        let _store = open_store(&temporary)?;
        std::mem::forget(temporary);
        std::process::abort();
    }

    #[test]
    #[ignore = "subprocess helper invoked by the normal-vault crash matrix"]
    fn child_normal_vault_aborts_at_exact_cut() -> Result<(), Box<dyn Error>> {
        let path = std::env::var_os("DOM_CONTRACTS_INVENTORY_TEST_ROOT")
            .ok_or(InventoryError::Filesystem)?;
        let temporary = TestDirectory {
            path: PathBuf::from(path),
        };
        let mut store = open_store(&temporary)?;
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x8b, 0x9b)?;
        let handle = store.persist_reservation(&claim, &charge)?;
        let derivation = commitment_attempt(*claim.identity(), 0xab)?;
        store.persist_nonce_derivation_attempt(&handle, &derivation)?;
        let persisted =
            store.persist_computed_public_artifact(&handle, derivation.attempt(), &[0xcb; 35])?;
        let permit = store.authorize_persisted_public_exposure(&handle, persisted)?;
        let result = store.export_public_artifact(permit);
        std::mem::forget(temporary);
        result?;
        Err(Box::new(InventoryError::Canonical))
    }

    #[test]
    #[ignore = "subprocess helper invoked by the canonical backup crash matrix"]
    fn child_backup_aborts_at_exact_cut() -> Result<(), Box<dyn Error>> {
        let path = std::env::var_os("DOM_CONTRACTS_INVENTORY_TEST_ROOT")
            .ok_or(InventoryError::Filesystem)?;
        let temporary = TestDirectory {
            path: PathBuf::from(path),
        };
        let mut store = open_store(&temporary)?;
        let result = store.create_backup(
            Passphrase::new(b"crash-matrix-backup-passphrase".to_vec())?,
            BackupPolicyLimitsV1::new(64, 1_048_576)?,
        );
        std::mem::forget(temporary);
        result?;
        Err(Box::new(InventoryError::Canonical))
    }
}

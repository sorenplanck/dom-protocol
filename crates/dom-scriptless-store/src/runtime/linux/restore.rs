//! Canonical restore selection and authenticated source material for Linux.
//!
//! This module deliberately separates source-backup authentication from every
//! destination mutation. A restore transaction may be prepared only from the
//! opaque result of this loader; ambient paths, caller-provided digests, and
//! structurally parsed bytes confer no restore authority.

#[cfg(any(test, feature = "evidence-only"))]
use super::backup::BackupPolicyLimitsV1;
use super::{
    backup::{MANIFEST_ENVELOPE_LEN, MASTER_ENVELOPE_LEN},
    inventory::TOMBSTONE_ENVELOPE_LEN,
    ExpectedNodeType, LinuxCapabilityError, RetainedDirectory, RetainedExclusiveLock, RetainedFile,
    ValidatedComponent,
};
use crate::canonical::{
    canonical_restore_record_relative_path, CompositeJournalV1, EpochAdvancePayloadV1,
    LifetimeCollisionIndexV1, RestoreJournalInputsV1, RestoreManifestV1, RestoreOnlyRootV1,
    RestorePendingIndexV1, RestoreRecordItemV1, RestoreRecordPayloadV1, RestoreRecordSetLimitsV1,
    RestoreRecordSetV1, TerminalEvidenceV1,
};
#[cfg(any(test, feature = "evidence-only"))]
use crate::canonical::{
    ActiveSecretEvidenceV1, BackupBundleV1, BackupManifestV1, RestorePendingIndexFieldsV1,
    RestoredJournalV1,
};
use crate::{
    canonical_attempt_relative_path, canonical_generation_directory_name,
    canonical_journal_filename, canonical_restore_completed_directory_name,
    canonical_restore_initialized_marker_name, canonical_restore_record_directory_name,
    canonical_restore_record_filename, ActiveVaultGenerationV1, AttemptRecordV1, BudgetChargeV1,
    ExposureRecordV1, JournalEntryV1, NonceDerivationAttemptV1, NonceIdentityV1,
    PermitRetirementV1, RestoreRecordFamilyV1, SessionClaimV1, StoreLockIdentityV1,
    StoreRootIdentityV1, TombstoneV1, UnauthenticatedJournalEntryV1,
    UnauthenticatedJournalPayloadV1, UnauthenticatedRestoreManifestV1,
    UnauthenticatedRestoreRecordItemV1, UnauthenticatedRestoreRecordKeyV1,
    UnauthenticatedVaultGenerationCoreV1, VaultGenerationCoreV1, ACTIVE_VAULT_GENERATION_LEN,
    ATTEMPT_RECORD_LEN, EXPOSURE_RECORD_MAX_LEN, JOURNAL_ENTRY_MAX_LEN,
    NONCE_DERIVATION_ATTEMPT_LEN, RESTORE_MANIFEST_LEN, RESTORE_PENDING_INDEX_LEN,
    RESTORE_RECORD_ITEM_PREFIX_LEN, RESTORE_RECORD_KEY_LEN, SESSION_CLAIM_LEN, STORE_IDENTITY_LEN,
    VAULT_GENERATION_CORE_LEN,
};
#[cfg(any(test, feature = "evidence-only"))]
use crate::{
    canonical_backup_directory_name, canonical_restore_staging_directory_name, ExposureStateV1,
    JournalEntryKindV1,
};
#[cfg(any(test, feature = "evidence-only"))]
use cap_std::fs::Dir;
use dom_adaptor::PurposeV1;
use dom_scriptless_crypto::{
    authoritative_storage_hash_v1, open_master_key, open_tombstone_v1, Passphrase,
    StorageHashDomainV1, StorageIdsV1, TombstoneRecordMetadataV1, VaultMasterKey,
    VaultMasterKeyEnvelopeV1, VaultObjectEnvelopeV1,
};
#[cfg(any(test, feature = "evidence-only"))]
use dom_scriptless_crypto::{
    generate_vault_master_key, open_backup_manifest_v1, seal_master_key, seal_tombstone_v1,
    BackupManifestMetadataV1, TombstonePlaintextV1,
};
#[cfg(any(test, feature = "evidence-only"))]
use rand_core::{OsRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(any(test, feature = "evidence-only"))]
use std::sync::Arc;
#[cfg(test)]
use std::{fs::OpenOptions, io::Write as _};

type AuthenticatedSuccessorTombstonesV1 = (
    RestoreRecordSetV1,
    BTreeMap<[u8; 105], VaultObjectEnvelopeV1>,
    BTreeMap<[u8; 105], TombstoneV1>,
);

/// Terminates a test subprocess at one exact restore durability boundary.
#[cfg(test)]
pub(super) fn test_restore_crash_hook(boundary: &str) {
    if std::env::var("DOM_G1B_RESTORE_CRASH_CUT").ok().as_deref() != Some(boundary) {
        return;
    }
    if let Some(marker) = std::env::var_os("DOM_G1B_RESTORE_CRASH_MARKER") {
        if let Ok(mut file) = OpenOptions::new().create_new(true).write(true).open(marker) {
            let _ = file.write_all(boundary.as_bytes());
            let _ = file.sync_all();
        }
    }
    std::process::abort();
}

/// Source backup bytes authenticated before any restore destination mutation.
///
/// The source master key remains non-cloneable and zeroizing. Journal entries
/// here have an authenticated hash chain and complete structural payloads, but
/// the final restore authority is granted only after the restore-aware semantic
/// projection validates the complete normal/restore history.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct SelectedBackupMaterialV1 {
    source_root: RetainedDirectory,
    selected: RetainedDirectory,
    storage_ids: StorageIdsV1,
    backup_generation: u64,
    backup_id: [u8; 32],
    backup_master_key: VaultMasterKey,
    master_envelope: VaultMasterKeyEnvelopeV1,
    manifest_envelope: VaultObjectEnvelopeV1,
    manifest: BackupManifestV1,
    bundle: BackupBundleV1,
    journal_entries: Vec<Vec<u8>>,
    record_set: RestoreRecordSetV1,
    composite_journal: AuthenticatedCompositeJournalV1,
}

/// Deterministic, mutation-free preparation for an existing-device restore.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct ExistingDeviceRestorePreparationV1 {
    source: SelectedBackupMaterialV1,
    contract_wallet_id: [u8; 32],
    target_vault_id: [u8; 32],
    target_root_identity: StoreRootIdentityV1,
    target_epoch: u64,
    target_journal_sequence: u64,
    target_journal_head_digest: [u8; 32],
    target_generation: u64,
    successor_epoch: u64,
    successor_generation: u64,
    terminal_union: Vec<RestoreRecordPayloadV1>,
    budget_carries: Vec<BudgetChargeV1>,
    permit_carries: Vec<PermitRetirementV1>,
    target_journal_entries: Vec<JournalEntryV1>,
}

#[cfg(any(test, feature = "evidence-only"))]
impl ExistingDeviceRestorePreparationV1 {
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub(super) fn new(
        source: SelectedBackupMaterialV1,
        target_root_identity: &StoreRootIdentityV1,
        target_vault_id: [u8; 32],
        target_epoch: u64,
        target_journal_sequence: u64,
        target_journal_head_digest: [u8; 32],
        target_generation: u64,
        target_journal: &AuthenticatedCompositeJournalV1,
        target_record_set: &RestoreRecordSetV1,
        active_target_secrets: &BTreeMap<[u8; 105], ActiveSecretEvidenceV1>,
    ) -> Result<Self, LinuxCapabilityError> {
        let contract_wallet_id = copy_32(target_root_identity.contract_wallet_id())?;
        let target_store_root_id = copy_32(target_root_identity.store_root_id())?;
        if contract_wallet_id == [0; 32]
            || target_store_root_id == [0; 32]
            || target_vault_id == [0; 32]
            || target_epoch == 0
            || target_generation == 0
            || source.storage_ids.contract_wallet_id() != &contract_wallet_id
            || (target_journal_sequence == 0) != (target_journal_head_digest == [0; 32])
        {
            return Err(LinuxCapabilityError::IdentityMismatch);
        }
        let successor_epoch = target_epoch
            .max(source.manifest.source_epoch())
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let successor_generation = target_generation
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let terminal_union = canonical_existing_device_terminal_union(
            target_record_set,
            source.record_set(),
            active_target_secrets,
        )?;
        let target_lifetime = AuthenticatedLifetimeEvidenceV1::from_journal(target_journal)?;
        let source_lifetime =
            AuthenticatedLifetimeEvidenceV1::from_journal(source.composite_journal())?;
        let (budget_carries, permit_carries) =
            source_lifetime.carries_absent_from(&target_lifetime)?;
        Ok(Self {
            source,
            contract_wallet_id,
            target_vault_id,
            target_root_identity: target_root_identity.clone(),
            target_epoch,
            target_journal_sequence,
            target_journal_head_digest,
            target_generation,
            successor_epoch,
            successor_generation,
            terminal_union,
            budget_carries,
            permit_carries,
            target_journal_entries: target_journal.entries().to_vec(),
        })
    }

    pub(super) const fn source(&self) -> &SelectedBackupMaterialV1 {
        &self.source
    }

    pub(super) const fn contract_wallet_id(&self) -> &[u8; 32] {
        &self.contract_wallet_id
    }

    pub(super) const fn target_vault_id(&self) -> &[u8; 32] {
        &self.target_vault_id
    }

    pub(super) fn target_store_root_id(&self) -> &[u8] {
        self.target_root_identity.store_root_id()
    }

    pub(super) fn require_target_root_identity(
        &self,
        current: &StoreRootIdentityV1,
    ) -> Result<(), LinuxCapabilityError> {
        if current.as_bytes() == self.target_root_identity.as_bytes() {
            Ok(())
        } else {
            Err(LinuxCapabilityError::IdentityMismatch)
        }
    }

    pub(super) const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    pub(super) const fn target_journal_sequence(&self) -> u64 {
        self.target_journal_sequence
    }

    pub(super) const fn target_journal_head_digest(&self) -> &[u8; 32] {
        &self.target_journal_head_digest
    }

    pub(super) const fn target_generation(&self) -> u64 {
        self.target_generation
    }

    pub(super) const fn successor_epoch(&self) -> u64 {
        self.successor_epoch
    }

    pub(super) const fn successor_generation(&self) -> u64 {
        self.successor_generation
    }

    pub(super) fn terminal_union(&self) -> &[RestoreRecordPayloadV1] {
        &self.terminal_union
    }

    pub(super) fn budget_carries(&self) -> &[BudgetChargeV1] {
        &self.budget_carries
    }

    pub(super) fn permit_carries(&self) -> &[PermitRetirementV1] {
        &self.permit_carries
    }

    pub(super) fn target_journal_entries(&self) -> &[JournalEntryV1] {
        &self.target_journal_entries
    }
}

/// Fully authenticated, mutation-free material for one existing-device restore.
///
/// This value is crate-private and grants no publication authority. It owns the
/// fresh successor secret only so the retained-capability writer can seal the
/// canonical successor generation after every cross-object equality has been
/// verified. No caller-provided serialized object participates.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct PreparedExistingRestorePublicationV1 {
    preparation: ExistingDeviceRestorePreparationV1,
    manifest: RestoreManifestV1,
    successor_storage_ids: StorageIdsV1,
    successor_master_key: VaultMasterKey,
    successor_master_envelope: VaultMasterKeyEnvelopeV1,
    successor_core: VaultGenerationCoreV1,
    successor_terminals: SuccessorTerminalMaterialV1,
    epoch_advance: EpochAdvancePayloadV1,
    journal_entries: Vec<JournalEntryV1>,
    active: ActiveVaultGenerationV1,
    pending_index: RestorePendingIndexV1,
    limits: BackupPolicyLimitsV1,
}

#[cfg(any(test, feature = "evidence-only"))]
impl PreparedExistingRestorePublicationV1 {
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub(super) fn new(
        preparation: ExistingDeviceRestorePreparationV1,
        target_unlock_passphrase: Passphrase,
        limits: BackupPolicyLimitsV1,
    ) -> Result<Self, LinuxCapabilityError> {
        let restore_transaction_id = random_nonzero::<16>()?;
        let successor_storage_ids = loop {
            let candidate =
                StorageIdsV1::new(*preparation.contract_wallet_id(), random_nonzero::<32>()?)
                    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            if candidate.vault_id() != preparation.target_vault_id()
                && candidate.vault_id() != preparation.source().storage_ids().vault_id()
            {
                break candidate;
            }
        };
        let successor_master_key =
            generate_vault_master_key().map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let successor_master_envelope = seal_master_key(
            successor_storage_ids,
            &target_unlock_passphrase,
            &successor_master_key,
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let _verified_successor_master_key = open_master_key(
            &successor_master_envelope,
            successor_storage_ids,
            &target_unlock_passphrase,
        )
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let source = preparation.source();
        let source_manifest = source.manifest();
        let manifest = RestoreManifestV1::new_existing_device(
            restore_transaction_id,
            *preparation.contract_wallet_id(),
            *preparation.target_vault_id(),
            preparation.target_epoch(),
            preparation.target_journal_sequence(),
            *preparation.target_journal_head_digest(),
            *source.storage_ids().vault_id(),
            source_manifest.source_epoch(),
            source_manifest.source_journal_sequence(),
            copy_32(source_manifest.source_journal_head_digest())?,
            source.record_set().record_count(),
            *source.record_set().record_set_digest(),
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        if manifest.successor_epoch() != preparation.successor_epoch() {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }

        let successor_master_envelope_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::MasterEnvelope,
            successor_master_envelope.as_bytes(),
        );
        let successor_core = VaultGenerationCoreV1::new(
            *preparation.contract_wallet_id(),
            copy_32(preparation.target_store_root_id())?,
            *successor_storage_ids.vault_id(),
            preparation.successor_epoch(),
            preparation.successor_generation(),
            successor_master_envelope_digest,
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let successor_terminals = SuccessorTerminalMaterialV1::new(
            preparation.terminal_union(),
            successor_storage_ids,
            &successor_master_key,
            limits,
        )?;
        let epoch_advance = EpochAdvancePayloadV1::new(
            *preparation.contract_wallet_id(),
            *preparation.target_vault_id(),
            *successor_storage_ids.vault_id(),
            preparation.target_epoch(),
            preparation.successor_epoch(),
            preparation.target_generation(),
            preparation.successor_generation(),
            restore_transaction_id,
            *successor_core.generation_core_digest(),
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let restored = RestoredJournalV1::new(
            preparation.target_journal_entries().last(),
            RestoreJournalInputsV1 {
                manifest: &manifest,
                records: preparation.terminal_union(),
                budget_carry_forwards: preparation.budget_carries(),
                permit_carry_forwards: preparation.permit_carries(),
                epoch_advance: &epoch_advance,
            },
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let mut journal_entries = preparation.target_journal_entries().to_vec();
        journal_entries.extend_from_slice(restored.entries());
        let final_head = journal_entries
            .last()
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let active = ActiveVaultGenerationV1::new(
            &successor_core,
            final_head.sequence(),
            *final_head.entry_digest(),
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let pending_index = RestorePendingIndexV1::new(RestorePendingIndexFieldsV1 {
            restore_transaction_id,
            contract_wallet_id: *preparation.contract_wallet_id(),
            restore_manifest_digest: *manifest.manifest_digest(),
            source_backup_bundle_digest: *source.bundle().bundle_digest(),
            source_backup_master_envelope_digest: copy_32(
                source.bundle().backup_master_envelope_digest(),
            )?,
            source_backup_manifest_object_envelope_digest: copy_32(
                source.bundle().backup_manifest_object_envelope_digest(),
            )?,
            source_journal_sequence: source_manifest.source_journal_sequence(),
            source_journal_head_digest: copy_32(source_manifest.source_journal_head_digest())?,
            source_record_count: source.record_set().record_count(),
            source_record_set_digest: *source.record_set().record_set_digest(),
            successor_generation_core_digest: *successor_core.generation_core_digest(),
            successor_master_envelope_digest,
            successor_final_journal_sequence: final_head.sequence(),
            successor_final_journal_head_digest: *final_head.entry_digest(),
            successor_record_count: successor_terminals.record_set().record_count(),
            successor_record_set_digest: *successor_terminals.record_set().record_set_digest(),
            successor_tombstone_envelope_set_digest: *successor_terminals.envelope_set_digest(),
            successor_active_generation_digest: *active.active_generation_digest(),
            restore_only_root_digest: [0; 32],
        })
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;

        let terminal_map = preparation
            .terminal_union()
            .iter()
            .map(|record| (*record.identity().as_bytes(), record.result().clone()))
            .collect::<BTreeMap<_, _>>();
        let encoded = journal_entries
            .iter()
            .map(|entry| entry.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let authenticated = authenticate_composite_journal(&encoded, &terminal_map)?;
        authenticated.verify_pending_activation_anchor(&successor_core, &active, &pending_index)?;

        Ok(Self {
            preparation,
            manifest,
            successor_storage_ids,
            successor_master_key,
            successor_master_envelope,
            successor_core,
            successor_terminals,
            epoch_advance,
            journal_entries,
            active,
            pending_index,
            limits,
        })
    }

    pub(super) const fn preparation(&self) -> &ExistingDeviceRestorePreparationV1 {
        &self.preparation
    }

    pub(super) const fn manifest(&self) -> &RestoreManifestV1 {
        &self.manifest
    }

    pub(super) const fn successor_storage_ids(&self) -> StorageIdsV1 {
        self.successor_storage_ids
    }

    pub(super) const fn successor_master_key(&self) -> &VaultMasterKey {
        &self.successor_master_key
    }

    pub(super) const fn successor_master_envelope(&self) -> &VaultMasterKeyEnvelopeV1 {
        &self.successor_master_envelope
    }

    pub(super) const fn successor_core(&self) -> &VaultGenerationCoreV1 {
        &self.successor_core
    }

    pub(super) const fn successor_terminals(&self) -> &SuccessorTerminalMaterialV1 {
        &self.successor_terminals
    }

    pub(super) const fn epoch_advance(&self) -> &EpochAdvancePayloadV1 {
        &self.epoch_advance
    }

    pub(super) fn journal_entries(&self) -> &[JournalEntryV1] {
        &self.journal_entries
    }

    pub(super) const fn active(&self) -> &ActiveVaultGenerationV1 {
        &self.active
    }

    pub(super) const fn pending_index(&self) -> &RestorePendingIndexV1 {
        &self.pending_index
    }

    pub(super) const fn limits(&self) -> BackupPolicyLimitsV1 {
        self.limits
    }
}

/// Fully authenticated, mutation-free new-device restore publication.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct PreparedNewDeviceRestorePublicationV1 {
    preparation: NewDeviceRestorePreparationV1,
    restore_only_root: RestoreOnlyRootV1,
    manifest: RestoreManifestV1,
    successor_storage_ids: StorageIdsV1,
    successor_master_key: VaultMasterKey,
    successor_master_envelope: VaultMasterKeyEnvelopeV1,
    successor_core: VaultGenerationCoreV1,
    successor_terminals: SuccessorTerminalMaterialV1,
    epoch_advance: EpochAdvancePayloadV1,
    journal_entries: Vec<JournalEntryV1>,
    active: ActiveVaultGenerationV1,
    pending_index: RestorePendingIndexV1,
    limits: BackupPolicyLimitsV1,
}

#[cfg(any(test, feature = "evidence-only"))]
impl PreparedNewDeviceRestorePublicationV1 {
    pub(super) fn new(
        preparation: NewDeviceRestorePreparationV1,
        root_identity: &StoreRootIdentityV1,
        restore_only_root: RestoreOnlyRootV1,
        target_unlock_passphrase: &Passphrase,
        limits: BackupPolicyLimitsV1,
    ) -> Result<Self, LinuxCapabilityError> {
        let source = preparation.source();
        if root_identity.contract_wallet_id() != source.storage_ids().contract_wallet_id()
            || restore_only_root.contract_wallet_id() != root_identity.contract_wallet_id()
            || restore_only_root.store_root_id() != root_identity.store_root_id()
            || restore_only_root.lock_instance_id() != root_identity.lock_instance_id()
            || restore_only_root.source_backup_bundle_digest() != source.bundle().bundle_digest()
            || preparation.successor_generation() != 1
        {
            return Err(LinuxCapabilityError::IdentityMismatch);
        }
        let restore_transaction_id = random_nonzero::<16>()?;
        let successor_storage_ids = loop {
            let candidate = StorageIdsV1::new(
                copy_32(root_identity.contract_wallet_id())?,
                random_nonzero::<32>()?,
            )
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            if candidate.vault_id() != source.storage_ids().vault_id() {
                break candidate;
            }
        };
        let successor_master_key =
            generate_vault_master_key().map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let successor_master_envelope = seal_master_key(
            successor_storage_ids,
            target_unlock_passphrase,
            &successor_master_key,
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let _verified_successor_master_key = open_master_key(
            &successor_master_envelope,
            successor_storage_ids,
            target_unlock_passphrase,
        )
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let source_manifest = source.manifest();
        let manifest = RestoreManifestV1::new_restore_only(
            restore_transaction_id,
            copy_32(root_identity.contract_wallet_id())?,
            *source.storage_ids().vault_id(),
            source_manifest.source_epoch(),
            source_manifest.source_journal_sequence(),
            copy_32(source_manifest.source_journal_head_digest())?,
            source.record_set().record_count(),
            *source.record_set().record_set_digest(),
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        if !manifest.is_new_device_target()
            || manifest.successor_epoch() != preparation.successor_epoch()
        {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        let successor_master_envelope_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::MasterEnvelope,
            successor_master_envelope.as_bytes(),
        );
        let successor_core = VaultGenerationCoreV1::new(
            copy_32(root_identity.contract_wallet_id())?,
            copy_32(root_identity.store_root_id())?,
            *successor_storage_ids.vault_id(),
            preparation.successor_epoch(),
            1,
            successor_master_envelope_digest,
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let successor_terminals = SuccessorTerminalMaterialV1::new(
            preparation.terminal_union(),
            successor_storage_ids,
            &successor_master_key,
            limits,
        )?;
        let epoch_advance = EpochAdvancePayloadV1::new(
            copy_32(root_identity.contract_wallet_id())?,
            [0; 32],
            *successor_storage_ids.vault_id(),
            0,
            preparation.successor_epoch(),
            0,
            1,
            restore_transaction_id,
            *successor_core.generation_core_digest(),
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let restored = RestoredJournalV1::new(
            None,
            RestoreJournalInputsV1 {
                manifest: &manifest,
                records: preparation.terminal_union(),
                budget_carry_forwards: preparation.budget_carries(),
                permit_carry_forwards: preparation.permit_carries(),
                epoch_advance: &epoch_advance,
            },
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let journal_entries = restored.entries().to_vec();
        let final_head = journal_entries
            .last()
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let active = ActiveVaultGenerationV1::new(
            &successor_core,
            final_head.sequence(),
            *final_head.entry_digest(),
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let pending_index = RestorePendingIndexV1::new(RestorePendingIndexFieldsV1 {
            restore_transaction_id,
            contract_wallet_id: copy_32(root_identity.contract_wallet_id())?,
            restore_manifest_digest: *manifest.manifest_digest(),
            source_backup_bundle_digest: *source.bundle().bundle_digest(),
            source_backup_master_envelope_digest: copy_32(
                source.bundle().backup_master_envelope_digest(),
            )?,
            source_backup_manifest_object_envelope_digest: copy_32(
                source.bundle().backup_manifest_object_envelope_digest(),
            )?,
            source_journal_sequence: source_manifest.source_journal_sequence(),
            source_journal_head_digest: copy_32(source_manifest.source_journal_head_digest())?,
            source_record_count: source.record_set().record_count(),
            source_record_set_digest: *source.record_set().record_set_digest(),
            successor_generation_core_digest: *successor_core.generation_core_digest(),
            successor_master_envelope_digest,
            successor_final_journal_sequence: final_head.sequence(),
            successor_final_journal_head_digest: *final_head.entry_digest(),
            successor_record_count: successor_terminals.record_set().record_count(),
            successor_record_set_digest: *successor_terminals.record_set().record_set_digest(),
            successor_tombstone_envelope_set_digest: *successor_terminals.envelope_set_digest(),
            successor_active_generation_digest: *active.active_generation_digest(),
            restore_only_root_digest: *restore_only_root.restore_only_root_digest(),
        })
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let terminal_map = preparation
            .terminal_union()
            .iter()
            .map(|record| (*record.identity().as_bytes(), record.result().clone()))
            .collect::<BTreeMap<_, _>>();
        let encoded = journal_entries
            .iter()
            .map(|entry| entry.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let authenticated = authenticate_composite_journal(&encoded, &terminal_map)?;
        authenticated.verify_pending_activation_anchor(&successor_core, &active, &pending_index)?;
        Ok(Self {
            preparation,
            restore_only_root,
            manifest,
            successor_storage_ids,
            successor_master_key,
            successor_master_envelope,
            successor_core,
            successor_terminals,
            epoch_advance,
            journal_entries,
            active,
            pending_index,
            limits,
        })
    }

    pub(super) const fn preparation(&self) -> &NewDeviceRestorePreparationV1 {
        &self.preparation
    }

    pub(super) const fn restore_only_root(&self) -> &RestoreOnlyRootV1 {
        &self.restore_only_root
    }

    pub(super) const fn manifest(&self) -> &RestoreManifestV1 {
        &self.manifest
    }

    pub(super) const fn successor_storage_ids(&self) -> StorageIdsV1 {
        self.successor_storage_ids
    }

    pub(super) const fn successor_master_key(&self) -> &VaultMasterKey {
        &self.successor_master_key
    }

    pub(super) const fn successor_master_envelope(&self) -> &VaultMasterKeyEnvelopeV1 {
        &self.successor_master_envelope
    }

    pub(super) const fn successor_core(&self) -> &VaultGenerationCoreV1 {
        &self.successor_core
    }

    pub(super) const fn successor_terminals(&self) -> &SuccessorTerminalMaterialV1 {
        &self.successor_terminals
    }

    pub(super) const fn epoch_advance(&self) -> &EpochAdvancePayloadV1 {
        &self.epoch_advance
    }

    pub(super) fn journal_entries(&self) -> &[JournalEntryV1] {
        &self.journal_entries
    }

    pub(super) const fn active(&self) -> &ActiveVaultGenerationV1 {
        &self.active
    }

    pub(super) const fn pending_index(&self) -> &RestorePendingIndexV1 {
        &self.pending_index
    }

    pub(super) const fn limits(&self) -> BackupPolicyLimitsV1 {
        self.limits
    }
}

#[cfg(any(test, feature = "evidence-only"))]
pub(super) trait RestorePublicationViewV1 {
    fn source(&self) -> &SelectedBackupMaterialV1;
    fn manifest(&self) -> &RestoreManifestV1;
    fn successor_storage_ids(&self) -> StorageIdsV1;
    fn successor_master_key(&self) -> &VaultMasterKey;
    fn successor_master_envelope(&self) -> &VaultMasterKeyEnvelopeV1;
    fn successor_core(&self) -> &VaultGenerationCoreV1;
    fn successor_terminals(&self) -> &SuccessorTerminalMaterialV1;
    fn epoch_advance(&self) -> &EpochAdvancePayloadV1;
    fn journal_entries(&self) -> &[JournalEntryV1];
    fn active(&self) -> &ActiveVaultGenerationV1;
    fn pending_index(&self) -> &RestorePendingIndexV1;
    fn limits(&self) -> BackupPolicyLimitsV1;
    fn terminal_union(&self) -> &[RestoreRecordPayloadV1];
}

#[cfg(any(test, feature = "evidence-only"))]
impl RestorePublicationViewV1 for PreparedExistingRestorePublicationV1 {
    fn source(&self) -> &SelectedBackupMaterialV1 {
        self.preparation().source()
    }
    fn manifest(&self) -> &RestoreManifestV1 {
        self.manifest()
    }
    fn successor_storage_ids(&self) -> StorageIdsV1 {
        self.successor_storage_ids()
    }
    fn successor_master_key(&self) -> &VaultMasterKey {
        self.successor_master_key()
    }
    fn successor_master_envelope(&self) -> &VaultMasterKeyEnvelopeV1 {
        self.successor_master_envelope()
    }
    fn successor_core(&self) -> &VaultGenerationCoreV1 {
        self.successor_core()
    }
    fn successor_terminals(&self) -> &SuccessorTerminalMaterialV1 {
        self.successor_terminals()
    }
    fn epoch_advance(&self) -> &EpochAdvancePayloadV1 {
        self.epoch_advance()
    }
    fn journal_entries(&self) -> &[JournalEntryV1] {
        self.journal_entries()
    }
    fn active(&self) -> &ActiveVaultGenerationV1 {
        self.active()
    }
    fn pending_index(&self) -> &RestorePendingIndexV1 {
        self.pending_index()
    }
    fn limits(&self) -> BackupPolicyLimitsV1 {
        self.limits()
    }
    fn terminal_union(&self) -> &[RestoreRecordPayloadV1] {
        self.preparation().terminal_union()
    }
}

#[cfg(any(test, feature = "evidence-only"))]
impl RestorePublicationViewV1 for PreparedNewDeviceRestorePublicationV1 {
    fn source(&self) -> &SelectedBackupMaterialV1 {
        self.preparation().source()
    }
    fn manifest(&self) -> &RestoreManifestV1 {
        self.manifest()
    }
    fn successor_storage_ids(&self) -> StorageIdsV1 {
        self.successor_storage_ids()
    }
    fn successor_master_key(&self) -> &VaultMasterKey {
        self.successor_master_key()
    }
    fn successor_master_envelope(&self) -> &VaultMasterKeyEnvelopeV1 {
        self.successor_master_envelope()
    }
    fn successor_core(&self) -> &VaultGenerationCoreV1 {
        self.successor_core()
    }
    fn successor_terminals(&self) -> &SuccessorTerminalMaterialV1 {
        self.successor_terminals()
    }
    fn epoch_advance(&self) -> &EpochAdvancePayloadV1 {
        self.epoch_advance()
    }
    fn journal_entries(&self) -> &[JournalEntryV1] {
        self.journal_entries()
    }
    fn active(&self) -> &ActiveVaultGenerationV1 {
        self.active()
    }
    fn pending_index(&self) -> &RestorePendingIndexV1 {
        self.pending_index()
    }
    fn limits(&self) -> BackupPolicyLimitsV1 {
        self.limits()
    }
    fn terminal_union(&self) -> &[RestoreRecordPayloadV1] {
        self.preparation().terminal_union()
    }
}

/// Retained handles for one fully verified but not yet published restore tree.
///
/// Ownership of the prepared material and every later rename capability remains
/// in this private value. Dropping it cannot publish or activate the restore.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct StagedExistingRestoreV1 {
    publication: PreparedExistingRestorePublicationV1,
    staging: RetainedDirectory,
    source_backup: RetainedDirectory,
    successor: RetainedDirectory,
    activation: RetainedDirectory,
    staged_active: RetainedFile,
}

#[cfg(any(test, feature = "evidence-only"))]
impl StagedExistingRestoreV1 {
    pub(super) const fn publication(&self) -> &PreparedExistingRestorePublicationV1 {
        &self.publication
    }

    pub(super) const fn staging(&self) -> &RetainedDirectory {
        &self.staging
    }

    pub(super) fn revalidate_retained_authorities(&self) -> Result<(), LinuxCapabilityError> {
        self.source_backup.revalidate()?;
        self.successor.revalidate()?;
        self.activation.revalidate()?;
        self.staged_active.revalidate()
    }
}

/// Retained handles for one verified new-device restore-only staging tree.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct StagedNewDeviceRestoreV1 {
    publication: PreparedNewDeviceRestorePublicationV1,
    staging: RetainedDirectory,
    source_backup: RetainedDirectory,
    successor: RetainedDirectory,
    activation: RetainedDirectory,
    staged_active: RetainedFile,
}

#[cfg(any(test, feature = "evidence-only"))]
impl StagedNewDeviceRestoreV1 {
    pub(super) const fn publication(&self) -> &PreparedNewDeviceRestorePublicationV1 {
        &self.publication
    }

    pub(super) const fn staging(&self) -> &RetainedDirectory {
        &self.staging
    }

    pub(super) fn revalidate_retained_authorities(&self) -> Result<(), LinuxCapabilityError> {
        self.source_backup.revalidate()?;
        self.successor.revalidate()?;
        self.activation.revalidate()?;
        self.staged_active.revalidate()
    }
}

/// Retained post-activation authority returned only after step 14 succeeds.
pub(super) struct CompletedExistingRestoreV1 {
    completed: RetainedDirectory,
    generation: RetainedDirectory,
    active: RetainedFile,
}

impl CompletedExistingRestoreV1 {
    pub(super) const fn completed(&self) -> &RetainedDirectory {
        &self.completed
    }

    pub(super) const fn generation(&self) -> &RetainedDirectory {
        &self.generation
    }

    pub(super) const fn active(&self) -> &RetainedFile {
        &self.active
    }
}

/// The closed set of authenticated post-step-9 restore phases.
///
/// Private staging is intentionally absent: before step 9 it is an orphan,
/// never resumable authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingRestoreDiskPhaseV1 {
    PendingNestedSuccessorPredecessor,
    PendingFinalSuccessorPredecessor,
    PendingFinalSuccessor,
    CompletedFinalSuccessor,
}

struct ExistingRestoreDiskAuthorityV1 {
    phase: ExistingRestoreDiskPhaseV1,
    transaction: RetainedDirectory,
    generation: RetainedDirectory,
    active: RetainedFile,
    manifest: RestoreManifestV1,
    pending: RestorePendingIndexV1,
    successor_core: VaultGenerationCoreV1,
    successor_live_active: ActiveVaultGenerationV1,
}

/// Resumes or recognizes an existing-device restore using only authenticated
/// objects reachable from the retained target root.
pub(super) fn resume_existing_device_restore_from_disk(
    target_root: &RetainedDirectory,
    retained_lock: &RetainedExclusiveLock,
    target_root_identity: &StoreRootIdentityV1,
    target_unlock_passphrase: &Passphrase,
) -> Result<CompletedExistingRestoreV1, LinuxCapabilityError> {
    retained_lock.revalidate()?;
    require_exact_root_identity(target_root, target_root_identity)?;
    let authority = authenticate_existing_restore_disk_authority(
        target_root,
        target_root_identity,
        target_unlock_passphrase,
    )?;
    continue_existing_restore_from_disk(
        target_root,
        retained_lock,
        target_root_identity,
        target_unlock_passphrase,
        authority,
    )
}

fn continue_existing_restore_from_disk(
    target_root: &RetainedDirectory,
    retained_lock: &RetainedExclusiveLock,
    target_root_identity: &StoreRootIdentityV1,
    target_unlock_passphrase: &Passphrase,
    authority: ExistingRestoreDiskAuthorityV1,
) -> Result<CompletedExistingRestoreV1, LinuxCapabilityError> {
    retained_lock.revalidate()?;
    match authority.phase {
        ExistingRestoreDiskPhaseV1::PendingNestedSuccessorPredecessor => {
            #[cfg(test)]
            test_restore_crash_hook("step10-before-rename");
            let structural = UnauthenticatedVaultGenerationCoreV1::parse_structural(
                authority.successor_core.as_bytes(),
            )
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let generation_name =
                ValidatedComponent::registered(&canonical_generation_directory_name(&structural))?;
            let nested = authority
                .transaction
                .open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
            target_root.activate_restore_generation_no_replace(
                &authority.transaction,
                &nested,
                &generation_name,
            )?;
            #[cfg(test)]
            test_restore_crash_hook("step10-after-root-sync");
        }
        ExistingRestoreDiskPhaseV1::PendingFinalSuccessorPredecessor => {
            #[cfg(test)]
            test_restore_crash_hook("step11-before-rename");
            let activation = authority
                .transaction
                .open_child_directory(ValidatedComponent::registered("activation")?)?;
            let staged_active = activation.open_file(
                &ValidatedComponent::registered("active-generation.bin")?,
                false,
            )?;
            target_root.activate_restore_pointer(
                &authority.transaction,
                &activation,
                &staged_active,
            )?;
            #[cfg(test)]
            test_restore_crash_hook("step11-after-root-sync");
        }
        ExistingRestoreDiskPhaseV1::PendingFinalSuccessor => {
            authority.transaction.revalidate()?;
            authority.generation.revalidate()?;
            authority.active.revalidate()?;
            #[cfg(test)]
            test_restore_crash_hook("step13-before-rename");
            let structural =
                UnauthenticatedRestoreManifestV1::parse_structural(authority.manifest.as_bytes())
                    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let completed_name = ValidatedComponent::registered(
                &canonical_restore_completed_directory_name(&structural),
            )?;
            target_root
                .retain_completed_restore_no_replace(&authority.transaction, &completed_name)?;
            #[cfg(test)]
            test_restore_crash_hook("step13-after-root-sync");
        }
        ExistingRestoreDiskPhaseV1::CompletedFinalSuccessor => {
            authority.transaction.revalidate()?;
            authority.generation.revalidate()?;
            authority.active.revalidate()?;
            require_exact_root_identity(target_root, target_root_identity)?;
            let active_bytes = target_root.read_bounded_file(
                &ValidatedComponent::registered("active-vault-generation")?,
                ACTIVE_VAULT_GENERATION_LEN,
            )?;
            let active = ActiveVaultGenerationV1::from_bytes_with_core(
                &active_bytes,
                &authority.successor_core,
            )
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if active.as_bytes() != authority.successor_live_active.as_bytes()
                || authority.pending.fields().restore_transaction_id.as_slice()
                    != authority.manifest.restore_transaction_id()
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            retained_lock.revalidate()?;
            return Ok(CompletedExistingRestoreV1 {
                completed: authority.transaction,
                generation: authority.generation,
                active: authority.active,
            });
        }
    }
    target_root.revalidate()?;
    retained_lock.revalidate()?;
    let next = authenticate_existing_restore_disk_authority(
        target_root,
        target_root_identity,
        target_unlock_passphrase,
    )?;
    continue_existing_restore_from_disk(
        target_root,
        retained_lock,
        target_root_identity,
        target_unlock_passphrase,
        next,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NewDeviceRestoreDiskPhaseV1 {
    NestedPending,
    FinalPending,
    FinalActivated,
    Completed,
}

struct NewDeviceRestoreDiskAuthorityV1 {
    phase: NewDeviceRestoreDiskPhaseV1,
    transaction: RetainedDirectory,
    generation: RetainedDirectory,
    manifest: RestoreManifestV1,
    pending: RestorePendingIndexV1,
    successor_core: VaultGenerationCoreV1,
    restore_only_root: RestoreOnlyRootV1,
}

/// Resumes a new-device restore using only the retained in-root transaction.
pub(super) fn resume_new_device_restore_from_disk(
    target_root: &RetainedDirectory,
    retained_lock: &RetainedExclusiveLock,
    target_root_identity: &StoreRootIdentityV1,
    target_unlock_passphrase: &Passphrase,
) -> Result<CompletedExistingRestoreV1, LinuxCapabilityError> {
    retained_lock.revalidate()?;
    require_exact_root_identity(target_root, target_root_identity)?;
    let authority = authenticate_new_device_restore_disk_authority(
        target_root,
        target_root_identity,
        target_unlock_passphrase,
    )?;
    continue_new_device_restore_from_disk(
        target_root,
        retained_lock,
        target_root_identity,
        target_unlock_passphrase,
        authority,
    )
}

fn continue_new_device_restore_from_disk(
    target_root: &RetainedDirectory,
    retained_lock: &RetainedExclusiveLock,
    target_root_identity: &StoreRootIdentityV1,
    target_unlock_passphrase: &Passphrase,
    authority: NewDeviceRestoreDiskAuthorityV1,
) -> Result<CompletedExistingRestoreV1, LinuxCapabilityError> {
    retained_lock.revalidate()?;
    match authority.phase {
        NewDeviceRestoreDiskPhaseV1::NestedPending => {
            let structural = UnauthenticatedVaultGenerationCoreV1::parse_structural(
                authority.successor_core.as_bytes(),
            )
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let generation_name =
                ValidatedComponent::registered(&canonical_generation_directory_name(&structural))?;
            let nested = authority
                .transaction
                .open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
            target_root.activate_restore_generation_no_replace(
                &authority.transaction,
                &nested,
                &generation_name,
            )?;
        }
        NewDeviceRestoreDiskPhaseV1::FinalPending => {
            let activation = authority
                .transaction
                .open_child_directory(ValidatedComponent::registered("activation")?)?;
            let staged_active = activation.open_file(
                &ValidatedComponent::registered("active-generation.bin")?,
                false,
            )?;
            target_root.activate_restore_pointer(
                &authority.transaction,
                &activation,
                &staged_active,
            )?;
        }
        NewDeviceRestoreDiskPhaseV1::FinalActivated => {
            let structural =
                UnauthenticatedRestoreManifestV1::parse_structural(authority.manifest.as_bytes())
                    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let completed_name = ValidatedComponent::registered(
                &canonical_restore_completed_directory_name(&structural),
            )?;
            target_root
                .retain_completed_restore_no_replace(&authority.transaction, &completed_name)?;
        }
        NewDeviceRestoreDiskPhaseV1::Completed => {
            if authority.pending.fields().restore_transaction_id.as_slice()
                != authority.manifest.restore_transaction_id()
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            transition_restore_only_marker(
                target_root,
                target_root_identity,
                &authority.restore_only_root,
            )?;
            let active = target_root.open_file(
                &ValidatedComponent::registered("active-vault-generation")?,
                false,
            )?;
            active.revalidate()?;
            authority.transaction.revalidate()?;
            authority.generation.revalidate()?;
            retained_lock.revalidate()?;
            return Ok(CompletedExistingRestoreV1 {
                completed: authority.transaction,
                generation: authority.generation,
                active,
            });
        }
    }
    target_root.revalidate()?;
    retained_lock.revalidate()?;
    let next = authenticate_new_device_restore_disk_authority(
        target_root,
        target_root_identity,
        target_unlock_passphrase,
    )?;
    continue_new_device_restore_from_disk(
        target_root,
        retained_lock,
        target_root_identity,
        target_unlock_passphrase,
        next,
    )
}

fn authenticate_new_device_restore_disk_authority(
    target_root: &RetainedDirectory,
    target_root_identity: &StoreRootIdentityV1,
    target_unlock_passphrase: &Passphrase,
) -> Result<NewDeviceRestoreDiskAuthorityV1, LinuxCapabilityError> {
    let (pending_present, completed_names, generation_names, active_present) =
        require_closed_new_device_restore_root_inventory(target_root)?;
    let marker = RestoreOnlyRootV1::from_bytes(&target_root.read_bounded_file(
        &ValidatedComponent::registered("restore-only-root.bin")?,
        crate::RESTORE_ONLY_ROOT_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    if marker.contract_wallet_id() != target_root_identity.contract_wallet_id()
        || marker.store_root_id() != target_root_identity.store_root_id()
        || marker.lock_instance_id() != target_root_identity.lock_instance_id()
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    let (transaction, completed) = if pending_present {
        (
            target_root.open_child_directory(ValidatedComponent::registered("restore-pending")?)?,
            false,
        )
    } else {
        if completed_names.len() != 1 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        (
            target_root.open_child_directory(ValidatedComponent::registered(
                completed_names
                    .first()
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?,
            )?)?,
            true,
        )
    };
    let pending = RestorePendingIndexV1::from_bytes(&transaction.read_bounded_file(
        &ValidatedComponent::registered("restore-pending.index")?,
        RESTORE_PENDING_INDEX_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let manifest = RestoreManifestV1::from_bytes(&transaction.read_bounded_file(
        &ValidatedComponent::registered("restore-manifest.bin")?,
        RESTORE_MANIFEST_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let fields = pending.fields();
    if !manifest.is_new_device_target()
        || fields.restore_transaction_id.as_slice() != manifest.restore_transaction_id()
        || fields.contract_wallet_id.as_slice() != manifest.contract_wallet_id()
        || fields.restore_manifest_digest != *manifest.manifest_digest()
        || fields.restore_only_root_digest != *marker.restore_only_root_digest()
        || marker.source_backup_bundle_digest() != fields.source_backup_bundle_digest
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let source =
        transaction.open_child_directory(ValidatedComponent::registered("source-backup")?)?;
    authenticate_copied_source_backup(&source, &manifest, &pending)?;
    let successor_name =
        successor_generation_name_from_pending(target_root, &transaction, &pending)?;
    let nested_successor = child_exists(
        &transaction,
        "successor-generation",
        ExpectedNodeType::Directory,
    )?;
    let final_successor = generation_names.iter().any(|name| name == &successor_name);
    if nested_successor == final_successor || completed && nested_successor {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    let generation = if nested_successor {
        transaction.open_child_directory(ValidatedComponent::registered("successor-generation")?)?
    } else {
        target_root.open_child_directory(ValidatedComponent::registered(&successor_name)?)?
    };
    let live_bytes = if active_present {
        target_root.read_bounded_file(
            &ValidatedComponent::registered("active-vault-generation")?,
            ACTIVE_VAULT_GENERATION_LEN,
        )?
    } else {
        Vec::new()
    };
    let (successor_core, successor_active, successor_live_active) =
        authenticate_successor_from_disk(
            &generation,
            &pending,
            &manifest,
            target_root_identity,
            target_unlock_passphrase,
            completed,
            &live_bytes,
        )?;
    if successor_core.vault_generation() != 1 || manifest.successor_epoch() == 0 {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    let activation =
        transaction.open_child_directory(ValidatedComponent::registered("activation")?)?;
    let nested_active = child_exists(
        &activation,
        "active-generation.bin",
        ExpectedNodeType::RegularFile,
    )?;
    if nested_active {
        let staged = ActiveVaultGenerationV1::from_bytes_with_core(
            &activation.read_bounded_file(
                &ValidatedComponent::registered("active-generation.bin")?,
                ACTIVE_VAULT_GENERATION_LEN,
            )?,
            &successor_core,
        )
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if staged.as_bytes() != successor_active.as_bytes() {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
    }
    let successor_live = active_present
        && ActiveVaultGenerationV1::from_bytes_with_core(&live_bytes, &successor_core)
            .is_ok_and(|active| active.as_bytes() == successor_live_active.as_bytes());
    let phase = match (
        completed,
        nested_successor,
        nested_active,
        active_present,
        successor_live,
    ) {
        (false, true, true, false, false) => NewDeviceRestoreDiskPhaseV1::NestedPending,
        (false, false, true, false, false) => NewDeviceRestoreDiskPhaseV1::FinalPending,
        (false, false, false, true, true) => NewDeviceRestoreDiskPhaseV1::FinalActivated,
        (true, false, false, true, true) => NewDeviceRestoreDiskPhaseV1::Completed,
        _ => return Err(LinuxCapabilityError::ExactBytesMismatch),
    };
    require_disk_transaction_inventory(&transaction, nested_successor, nested_active)?;
    Ok(NewDeviceRestoreDiskAuthorityV1 {
        phase,
        transaction,
        generation,
        manifest,
        pending,
        successor_core,
        restore_only_root: marker,
    })
}

fn require_closed_new_device_restore_root_inventory(
    root: &RetainedDirectory,
) -> Result<(bool, Vec<String>, Vec<String>, bool), LinuxCapabilityError> {
    let mut fixed = [false; 3];
    let mut pending = false;
    let mut completed = Vec::new();
    let mut generations = Vec::new();
    let mut active = false;
    root.scan_lexicographic(|name, identity| {
        let expected_type = match name {
            "store-root-identity.bin" => {
                fixed[0] = true;
                ExpectedNodeType::RegularFile
            }
            "store-lock-identity.bin" => {
                fixed[1] = true;
                ExpectedNodeType::RegularFile
            }
            "restore-only-root.bin" => {
                fixed[2] = true;
                ExpectedNodeType::RegularFile
            }
            "active-vault-generation" => {
                active = true;
                ExpectedNodeType::RegularFile
            }
            "restore-pending" => {
                pending = true;
                ExpectedNodeType::Directory
            }
            value if exact_decimal_hex_component(value, "generation-", 20, 64) => {
                generations.push(value.to_owned());
                ExpectedNodeType::Directory
            }
            value if exact_lower_hex_component(value, "restore-complete-", 32) => {
                completed.push(value.to_owned());
                ExpectedNodeType::Directory
            }
            _ => return Err(LinuxCapabilityError::InvalidDirectoryEntry),
        };
        if identity.node_type != expected_type {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        Ok(())
    })?;
    if fixed != [true; 3]
        || pending != completed.is_empty()
        || completed.len() > 1
        || generations.len() > 1
    {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    Ok((pending, completed, generations, active))
}

fn authenticate_existing_restore_disk_authority(
    target_root: &RetainedDirectory,
    target_root_identity: &StoreRootIdentityV1,
    target_unlock_passphrase: &Passphrase,
) -> Result<ExistingRestoreDiskAuthorityV1, LinuxCapabilityError> {
    target_root.revalidate()?;
    let (pending_present, completed_names) = require_closed_restore_root_inventory(target_root)?;
    for name in &completed_names {
        validate_completed_restore_name_and_index(target_root, name)?;
    }

    let (transaction, completed, selected_completed_name) = if pending_present {
        (
            target_root.open_child_directory(ValidatedComponent::registered("restore-pending")?)?,
            false,
            None,
        )
    } else {
        let live_bytes = target_root.read_bounded_file(
            &ValidatedComponent::registered("active-vault-generation")?,
            ACTIVE_VAULT_GENERATION_LEN,
        )?;
        crate::UnauthenticatedActiveVaultGenerationV1::parse_structural(&live_bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let mut current_matches = Vec::new();
        for name in &completed_names {
            let candidate =
                target_root.open_child_directory(ValidatedComponent::registered(name)?)?;
            let candidate_pending =
                RestorePendingIndexV1::from_bytes(&candidate.read_bounded_file(
                    &ValidatedComponent::registered("restore-pending.index")?,
                    RESTORE_PENDING_INDEX_LEN,
                )?)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let candidate_manifest = RestoreManifestV1::from_bytes(&candidate.read_bounded_file(
                &ValidatedComponent::registered("restore-manifest.bin")?,
                RESTORE_MANIFEST_LEN,
            )?)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let candidate_structural =
                UnauthenticatedRestoreManifestV1::parse_structural(candidate_manifest.as_bytes())
                    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            if canonical_restore_completed_directory_name(&candidate_structural) != *name
                || candidate_pending.fields().restore_transaction_id.as_slice()
                    != candidate_manifest.restore_transaction_id()
                || candidate_pending.fields().restore_manifest_digest
                    != *candidate_manifest.manifest_digest()
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            let successor_name = successor_generation_name_from_pending(
                target_root,
                &candidate,
                &candidate_pending,
            )?;
            let successor = target_root
                .open_child_directory(ValidatedComponent::registered(&successor_name)?)?;
            let successor_core = VaultGenerationCoreV1::from_bytes(&successor.read_bounded_file(
                &ValidatedComponent::registered("generation-core.bin")?,
                VAULT_GENERATION_CORE_LEN,
            )?)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            if ActiveVaultGenerationV1::from_bytes_with_core(&live_bytes, &successor_core).is_ok() {
                current_matches.push(name.clone());
            }
        }
        if current_matches.len() != 1 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        let selected_name = current_matches
            .first()
            .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?
            .clone();
        (
            target_root.open_child_directory(ValidatedComponent::registered(&selected_name)?)?,
            true,
            Some(selected_name),
        )
    };

    let pending = RestorePendingIndexV1::from_bytes(&transaction.read_bounded_file(
        &ValidatedComponent::registered("restore-pending.index")?,
        RESTORE_PENDING_INDEX_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let manifest = RestoreManifestV1::from_bytes(&transaction.read_bounded_file(
        &ValidatedComponent::registered("restore-manifest.bin")?,
        RESTORE_MANIFEST_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let fields = pending.fields();
    if manifest.is_new_device_target()
        || fields.restore_transaction_id.as_slice() != manifest.restore_transaction_id()
        || fields.contract_wallet_id.as_slice() != manifest.contract_wallet_id()
        || fields.restore_manifest_digest != *manifest.manifest_digest()
        || fields.restore_only_root_digest != [0; 32]
        || manifest.contract_wallet_id() != target_root_identity.contract_wallet_id()
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    let structural = UnauthenticatedRestoreManifestV1::parse_structural(manifest.as_bytes())
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let expected_completed = canonical_restore_completed_directory_name(&structural);
    if completed && selected_completed_name.as_ref() != Some(&expected_completed) {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    if !completed
        && completed_names
            .iter()
            .any(|name| name == &expected_completed)
    {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }

    let source =
        transaction.open_child_directory(ValidatedComponent::registered("source-backup")?)?;
    authenticate_copied_source_backup(&source, &manifest, &pending)?;

    let successor_name =
        successor_generation_name_from_pending(target_root, &transaction, &pending)?;
    let nested_successor = child_exists(
        &transaction,
        "successor-generation",
        ExpectedNodeType::Directory,
    )?;
    let final_successor = child_exists(target_root, &successor_name, ExpectedNodeType::Directory)?;
    if nested_successor == final_successor || completed && nested_successor {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    let generation = if nested_successor {
        transaction.open_child_directory(ValidatedComponent::registered("successor-generation")?)?
    } else {
        target_root.open_child_directory(ValidatedComponent::registered(&successor_name)?)?
    };
    let live_bytes = target_root.read_bounded_file(
        &ValidatedComponent::registered("active-vault-generation")?,
        ACTIVE_VAULT_GENERATION_LEN,
    )?;
    let (successor_core, successor_active, successor_live_active) =
        authenticate_successor_from_disk(
            &generation,
            &pending,
            &manifest,
            target_root_identity,
            target_unlock_passphrase,
            completed,
            &live_bytes,
        )?;

    let activation =
        transaction.open_child_directory(ValidatedComponent::registered("activation")?)?;
    let nested_active = child_exists(
        &activation,
        "active-generation.bin",
        ExpectedNodeType::RegularFile,
    )?;
    if nested_active {
        let staged_active_bytes = activation.read_bounded_file(
            &ValidatedComponent::registered("active-generation.bin")?,
            ACTIVE_VAULT_GENERATION_LEN,
        )?;
        let staged_active =
            ActiveVaultGenerationV1::from_bytes_with_core(&staged_active_bytes, &successor_core)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if staged_active.as_bytes() != successor_active.as_bytes() {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
    }
    let predecessor_core = authenticate_predecessor_from_disk(
        target_root,
        target_root_identity,
        &manifest,
        &successor_core,
    )?;
    let predecessor_active =
        ActiveVaultGenerationV1::from_bytes_with_core(&live_bytes, &predecessor_core)
            .ok()
            .filter(|active| {
                active.journal_sequence() == manifest.target_journal_sequence()
                    && active.journal_head_digest() == manifest.target_journal_head_digest()
            });
    let successor_live =
        ActiveVaultGenerationV1::from_bytes_with_core(&live_bytes, &successor_core)
            .ok()
            .filter(|active| active.as_bytes() == successor_live_active.as_bytes());
    let phase = match (
        completed,
        nested_successor,
        nested_active,
        predecessor_active.is_some(),
        successor_live.is_some(),
    ) {
        (false, true, true, true, false) => {
            ExistingRestoreDiskPhaseV1::PendingNestedSuccessorPredecessor
        }
        (false, false, true, true, false) => {
            ExistingRestoreDiskPhaseV1::PendingFinalSuccessorPredecessor
        }
        (false, false, false, false, true) => ExistingRestoreDiskPhaseV1::PendingFinalSuccessor,
        (true, false, false, false, true) => ExistingRestoreDiskPhaseV1::CompletedFinalSuccessor,
        _ => return Err(LinuxCapabilityError::ExactBytesMismatch),
    };
    require_disk_transaction_inventory(&transaction, nested_successor, nested_active)?;
    transaction.revalidate()?;
    generation.revalidate()?;
    let active = target_root.open_file(
        &ValidatedComponent::registered("active-vault-generation")?,
        false,
    )?;
    Ok(ExistingRestoreDiskAuthorityV1 {
        phase,
        transaction,
        generation,
        active,
        manifest,
        pending,
        successor_core,
        successor_live_active,
    })
}

fn require_closed_restore_root_inventory(
    target_root: &RetainedDirectory,
) -> Result<(bool, Vec<String>), LinuxCapabilityError> {
    let mut fixed = [false; 3];
    let mut pending_present = false;
    let mut generation_count = 0_u64;
    let mut completed_names = Vec::new();
    target_root.scan_lexicographic(|name, identity| {
        let require_type = |expected| {
            if identity.node_type == expected {
                Ok(())
            } else {
                Err(LinuxCapabilityError::InvalidObject)
            }
        };
        match name {
            "store-root-identity.bin" => {
                require_type(ExpectedNodeType::RegularFile)?;
                fixed[0] = true;
            }
            "store-lock-identity.bin" => {
                require_type(ExpectedNodeType::RegularFile)?;
                fixed[1] = true;
            }
            "active-vault-generation" => {
                require_type(ExpectedNodeType::RegularFile)?;
                fixed[2] = true;
            }
            "restore-pending" => {
                require_type(ExpectedNodeType::Directory)?;
                if pending_present {
                    return Err(LinuxCapabilityError::InvalidDirectoryEntry);
                }
                pending_present = true;
            }
            value if exact_decimal_hex_component(value, "generation-", 20, 64) => {
                require_type(ExpectedNodeType::Directory)?;
                let generation =
                    target_root.open_child_directory(ValidatedComponent::registered(value)?)?;
                let core = UnauthenticatedVaultGenerationCoreV1::parse_structural(
                    &generation.read_bounded_file(
                        &ValidatedComponent::registered("generation-core.bin")?,
                        VAULT_GENERATION_CORE_LEN,
                    )?,
                )
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
                if canonical_generation_directory_name(&core) != value {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                generation_count = generation_count
                    .checked_add(1)
                    .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            }
            value if exact_decimal_hex_component(value, "backup-", 20, 64) => {
                require_type(ExpectedNodeType::Directory)?;
            }
            value if exact_lower_hex_component(value, "restore-complete-", 32) => {
                require_type(ExpectedNodeType::Directory)?;
                completed_names.push(value.to_owned());
            }
            _ => return Err(LinuxCapabilityError::InvalidDirectoryEntry),
        }
        Ok(())
    })?;
    if fixed != [true; 3] || generation_count == 0 {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    Ok((pending_present, completed_names))
}

fn exact_decimal_hex_component(
    value: &str,
    prefix: &str,
    decimal_len: usize,
    hex_len: usize,
) -> bool {
    let Some(tail) = value.strip_prefix(prefix) else {
        return false;
    };
    let Some((decimal, hex)) = tail.split_once('-') else {
        return false;
    };
    decimal.len() == decimal_len
        && decimal.bytes().all(|byte| byte.is_ascii_digit())
        && hex.len() == hex_len
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exact_lower_hex_component(value: &str, prefix: &str, hex_len: usize) -> bool {
    let Some(hex) = value.strip_prefix(prefix) else {
        return false;
    };
    hex.len() == hex_len
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_completed_restore_name_and_index(
    target_root: &RetainedDirectory,
    name: &str,
) -> Result<(), LinuxCapabilityError> {
    let candidate = target_root.open_child_directory(ValidatedComponent::registered(name)?)?;
    let candidate_pending = RestorePendingIndexV1::from_bytes(&candidate.read_bounded_file(
        &ValidatedComponent::registered("restore-pending.index")?,
        RESTORE_PENDING_INDEX_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let candidate_manifest = RestoreManifestV1::from_bytes(&candidate.read_bounded_file(
        &ValidatedComponent::registered("restore-manifest.bin")?,
        RESTORE_MANIFEST_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let candidate_structural =
        UnauthenticatedRestoreManifestV1::parse_structural(candidate_manifest.as_bytes())
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    if canonical_restore_completed_directory_name(&candidate_structural) != name
        || candidate_pending.fields().restore_transaction_id.as_slice()
            != candidate_manifest.restore_transaction_id()
        || candidate_pending.fields().restore_manifest_digest
            != *candidate_manifest.manifest_digest()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    Ok(())
}

fn child_exists(
    directory: &RetainedDirectory,
    name: &str,
    expected: ExpectedNodeType,
) -> Result<bool, LinuxCapabilityError> {
    let mut matches = 0_u8;
    directory.scan_independent(|found, identity| {
        if found == name {
            if identity.node_type != expected {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            matches = matches
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
        }
        Ok(())
    })?;
    match matches {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(LinuxCapabilityError::InvalidDirectoryEntry),
    }
}

fn require_disk_transaction_inventory(
    transaction: &RetainedDirectory,
    successor_nested: bool,
    active_nested: bool,
) -> Result<(), LinuxCapabilityError> {
    let mut expected = vec![
        ("restore-pending.index", ExpectedNodeType::RegularFile),
        ("restore-manifest.bin", ExpectedNodeType::RegularFile),
        ("source-backup", ExpectedNodeType::Directory),
        ("activation", ExpectedNodeType::Directory),
    ];
    if successor_nested {
        expected.push(("successor-generation", ExpectedNodeType::Directory));
    }
    require_closed_inventory(transaction, &expected)?;
    let activation =
        transaction.open_child_directory(ValidatedComponent::registered("activation")?)?;
    if active_nested {
        require_closed_inventory(
            &activation,
            &[("active-generation.bin", ExpectedNodeType::RegularFile)],
        )
    } else {
        require_closed_inventory(&activation, &[])
    }
}

fn successor_generation_name_from_pending(
    target_root: &RetainedDirectory,
    transaction: &RetainedDirectory,
    pending: &RestorePendingIndexV1,
) -> Result<String, LinuxCapabilityError> {
    let fields = pending.fields();
    let mut matches = Vec::new();
    if child_exists(
        transaction,
        "successor-generation",
        ExpectedNodeType::Directory,
    )? {
        let successor = transaction
            .open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
        let core = VaultGenerationCoreV1::from_bytes(&successor.read_bounded_file(
            &ValidatedComponent::registered("generation-core.bin")?,
            VAULT_GENERATION_CORE_LEN,
        )?)
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if core.generation_core_digest() != &fields.successor_generation_core_digest {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        let structural = UnauthenticatedVaultGenerationCoreV1::parse_structural(core.as_bytes())
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        matches.push(canonical_generation_directory_name(&structural));
    }
    target_root.scan_lexicographic(|name, identity| {
        if !name.starts_with("generation-") {
            return Ok(());
        }
        if identity.node_type != ExpectedNodeType::Directory {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let generation = target_root.open_child_directory(ValidatedComponent::registered(name)?)?;
        let bytes = generation.read_bounded_file(
            &ValidatedComponent::registered("generation-core.bin")?,
            VAULT_GENERATION_CORE_LEN,
        )?;
        if let Ok(core) = VaultGenerationCoreV1::from_bytes(&bytes) {
            if core.generation_core_digest() == &fields.successor_generation_core_digest {
                matches.push(name.to_owned());
            }
        }
        Ok(())
    })?;
    if matches.len() != 1 {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    matches
        .pop()
        .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)
}

fn authenticate_copied_source_backup(
    source: &RetainedDirectory,
    manifest: &RestoreManifestV1,
    pending: &RestorePendingIndexV1,
) -> Result<(), LinuxCapabilityError> {
    require_exact_backup_inventory(source)?;
    let fields = pending.fields();
    let master_bytes = source.read_bounded_file(
        &ValidatedComponent::registered("backup-master-key.envelope")?,
        MASTER_ENVELOPE_LEN,
    )?;
    let master = VaultMasterKeyEnvelopeV1::from_bytes(&master_bytes)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let manifest_object_bytes = source.read_bounded_file(
        &ValidatedComponent::registered("backup-manifest.object")?,
        MANIFEST_ENVELOPE_LEN,
    )?;
    let manifest_object = VaultObjectEnvelopeV1::from_bytes(&manifest_object_bytes)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let bundle_digest =
        source.read_bounded_file(&ValidatedComponent::registered("backup-bundle.digest")?, 32)?;
    if authoritative_storage_hash_v1(StorageHashDomainV1::MasterEnvelope, master.as_bytes())
        != fields.source_backup_master_envelope_digest
        || manifest_object.digest() != fields.source_backup_manifest_object_envelope_digest
        || bundle_digest.as_slice() != fields.source_backup_bundle_digest
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let source_ids = storage_ids_from_master_envelope(&master)?;
    if source_ids.contract_wallet_id() != &fields.contract_wallet_id
        || source_ids.vault_id().as_slice() != manifest.source_vault_id()
        || manifest_object.as_bytes()[14..46] != fields.contract_wallet_id
        || manifest_object.as_bytes()[46..78] != manifest.source_vault_id()[..]
        || read_u64(&manifest_object.as_bytes()[78..86])? != manifest.source_epoch()
        || manifest_object.as_bytes()[86..151] != [0; 65]
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    let records = read_authenticated_record_set_declared(source, fields.source_record_count)?;
    if records.record_count() != fields.source_record_count
        || records.record_set_digest() != &fields.source_record_set_digest
        || manifest.as_bytes()[226..230] != fields.source_record_count.to_le_bytes()
        || manifest.as_bytes()[230..262] != fields.source_record_set_digest
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let journal = read_hash_authenticated_journal(source)?;
    let terminals =
        AuthenticatedRestoreProjectionV1::from_record_set(&records)?.authenticated_terminals()?;
    let authenticated = authenticate_composite_journal(&journal, &terminals)?;
    let projection_limits =
        RestoreRecordSetLimitsV1::new(records.record_count(), records.as_bytes().len())
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let projected =
        canonical_record_set_from_journal(authenticated.entries(), &terminals, &projection_limits)?;
    if projected.as_bytes() != records.as_bytes() {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let (sequence, head) = match authenticated.head() {
        Some(head) => (head.sequence(), *head.entry_digest()),
        None => (0, [0; 32]),
    };
    if sequence != fields.source_journal_sequence
        || head != fields.source_journal_head_digest
        || manifest.as_bytes()[178..186] != sequence.to_le_bytes()
        || manifest.as_bytes()[186..218] != head
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    source.revalidate()
}

fn read_authenticated_record_set_declared(
    selected: &RetainedDirectory,
    declared_count: u32,
) -> Result<RestoreRecordSetV1, LinuxCapabilityError> {
    let maximum = usize::try_from(declared_count)
        .ok()
        .and_then(|count| {
            count.checked_mul(RESTORE_RECORD_ITEM_PREFIX_LEN.checked_add(EXPOSURE_RECORD_MAX_LEN)?)
        })
        .and_then(|bytes| bytes.checked_add(4))
        .ok_or(LinuxCapabilityError::InvalidObject)?;
    let limits = RestoreRecordSetLimitsV1::new(declared_count, maximum)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let records = selected.open_child_directory(ValidatedComponent::registered("records")?)?;
    let mut items = Vec::new();
    let mut encoded_bytes = 4_usize;
    records.scan_lexicographic(|identity_name, identity_node| {
        if identity_node.node_type != ExpectedNodeType::Directory || identity_name.len() != 210 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        let identity_bytes = decode_lower_hex::<105>(identity_name)?;
        let identity_directory =
            records.open_child_directory(ValidatedComponent::registered(identity_name)?)?;
        let mut file_count = 0_u64;
        identity_directory.scan_lexicographic(|file_name, file_node| {
            if file_node.node_type != ExpectedNodeType::RegularFile {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let tail = file_name
                .strip_suffix(".record")
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            if tail.len() != 100 {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            }
            let tail_bytes = decode_lower_hex::<50>(tail)?;
            let mut key_bytes = [0_u8; RESTORE_RECORD_KEY_LEN];
            key_bytes[..105].copy_from_slice(&identity_bytes);
            key_bytes[105..].copy_from_slice(&tail_bytes);
            let key = UnauthenticatedRestoreRecordKeyV1::parse_structural(&key_bytes)
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let record_bytes = identity_directory.read_bounded_file(
                &ValidatedComponent::registered(file_name)?,
                EXPOSURE_RECORD_MAX_LEN,
            )?;
            let item = RestoreRecordItemV1::from_record_bytes(key.family(), &record_bytes)
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            if &item.as_bytes()[..RESTORE_RECORD_KEY_LEN] != key.as_bytes()
                || canonical_restore_record_directory_name(&key) != identity_name
                || canonical_restore_record_filename(&key) != file_name
                || canonical_restore_record_relative_path(&key)
                    != format!("records/{identity_name}/{file_name}")
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            encoded_bytes = encoded_bytes
                .checked_add(item.as_bytes().len())
                .ok_or(LinuxCapabilityError::InvalidObject)?;
            if encoded_bytes > maximum {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            items.push(item);
            file_count = file_count
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
            Ok(())
        })?;
        if file_count == 0 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        identity_directory.revalidate()
    })?;
    records.revalidate()?;
    if u32::try_from(items.len()).ok() != Some(declared_count) {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    RestoreRecordSetV1::new(items, &limits).map_err(|_| LinuxCapabilityError::InvalidObject)
}

fn authenticate_successor_from_disk(
    successor: &RetainedDirectory,
    pending: &RestorePendingIndexV1,
    manifest: &RestoreManifestV1,
    root_identity: &StoreRootIdentityV1,
    target_unlock_passphrase: &Passphrase,
    completed: bool,
    live_active_bytes: &[u8],
) -> Result<
    (
        VaultGenerationCoreV1,
        ActiveVaultGenerationV1,
        ActiveVaultGenerationV1,
    ),
    LinuxCapabilityError,
> {
    if completed {
        super::inventory::require_generation_inventory(successor)
            .map_err(|_| LinuxCapabilityError::InvalidDirectoryEntry)?;
    } else {
        require_closed_inventory(
            successor,
            &[
                ("generation-core.bin", ExpectedNodeType::RegularFile),
                ("master-key.envelope", ExpectedNodeType::RegularFile),
                ("journal", ExpectedNodeType::Directory),
                ("tombstones", ExpectedNodeType::Directory),
            ],
        )?;
    }
    let fields = pending.fields();
    let core = VaultGenerationCoreV1::from_bytes(&successor.read_bounded_file(
        &ValidatedComponent::registered("generation-core.bin")?,
        VAULT_GENERATION_CORE_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let core_relation = core.generation_core_digest() == &fields.successor_generation_core_digest;
    let wallet_relation = core.as_bytes()[10..42] == fields.contract_wallet_id
        && core.as_bytes()[10..42] == root_identity.contract_wallet_id()[..];
    let root_relation = core.as_bytes()[42..74] == root_identity.store_root_id()[..];
    let epoch_relation = core.nonce_epoch() == manifest.successor_epoch();
    if !core_relation
        || !wallet_relation
        || !root_relation
        || !epoch_relation
        || core.vault_generation() == 0
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    #[cfg(test)]
    let step12_semantic_authentication = !completed
        && ActiveVaultGenerationV1::from_bytes_with_core(live_active_bytes, &core).is_ok();
    #[cfg(test)]
    if completed {
        test_restore_crash_hook("step14-before-final-validation");
    } else if step12_semantic_authentication {
        test_restore_crash_hook("step12-before-full-verify");
    }
    let envelope = VaultMasterKeyEnvelopeV1::from_bytes(&successor.read_bounded_file(
        &ValidatedComponent::registered("master-key.envelope")?,
        MASTER_ENVELOPE_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let envelope_digest =
        authoritative_storage_hash_v1(StorageHashDomainV1::MasterEnvelope, envelope.as_bytes());
    if envelope_digest != fields.successor_master_envelope_digest
        || core.master_envelope_digest() != envelope_digest
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let storage_ids = storage_ids_from_master_envelope(&envelope)?;
    if storage_ids.contract_wallet_id() != &fields.contract_wallet_id
        || storage_ids.vault_id().as_slice() != core.vault_id()
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    let master_key = open_master_key(&envelope, storage_ids, target_unlock_passphrase)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    #[cfg(test)]
    if completed {
        test_restore_crash_hook("step14-during-final-validation");
    } else if step12_semantic_authentication {
        test_restore_crash_hook("step12-during-full-verify");
    }
    let (activation_record_set, tombstone_envelopes, terminals) =
        authenticate_successor_tombstones(successor, storage_ids, &master_key)?;
    let journal = read_hash_authenticated_journal(successor)?;
    let authenticated = authenticate_composite_journal(&journal, &terminals)?;
    let activation_active = ActiveVaultGenerationV1::new(
        &core,
        fields.successor_final_journal_sequence,
        fields.successor_final_journal_head_digest,
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    if activation_active.active_generation_digest() != &fields.successor_active_generation_digest {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    authenticated.verify_pending_activation_anchor(&core, &activation_active, pending)?;
    let activation_entries = authenticated
        .entries()
        .iter()
        .take_while(|entry| entry.sequence() <= fields.successor_final_journal_sequence)
        .cloned()
        .collect::<Vec<_>>();
    let activation_head_matches = match activation_entries.last() {
        Some(entry) => {
            entry.sequence() == fields.successor_final_journal_sequence
                && entry.entry_digest() == &fields.successor_final_journal_head_digest
        }
        None => false,
    };
    if !activation_head_matches {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let activation_limits = RestoreRecordSetLimitsV1::new(
        fields.successor_record_count,
        usize::try_from(fields.successor_record_count)
            .ok()
            .and_then(|count| {
                count.checked_mul(
                    RESTORE_RECORD_ITEM_PREFIX_LEN.checked_add(EXPOSURE_RECORD_MAX_LEN)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(4))
            .ok_or(LinuxCapabilityError::InvalidObject)?,
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let activation_projected =
        canonical_record_set_from_journal(&activation_entries, &terminals, &activation_limits)?;
    let activation_terminals =
        AuthenticatedRestoreProjectionV1::from_record_set(&activation_projected)?
            .authenticated_terminals()?;
    let activation_envelope_digest = tombstone_envelope_subset_digest(
        &tombstone_envelopes,
        activation_terminals.keys().copied(),
    )?;
    if activation_projected.record_count() != fields.successor_record_count
        || activation_projected.record_set_digest() != &fields.successor_record_set_digest
        || activation_envelope_digest != fields.successor_tombstone_envelope_set_digest
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }

    let live_active = ActiveVaultGenerationV1::from_bytes_with_core(live_active_bytes, &core)
        .unwrap_or_else(|_| activation_active.clone());
    if completed {
        let live_active = ActiveVaultGenerationV1::from_bytes_with_core(live_active_bytes, &core)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        authenticated.verify_current_generation_active_head(&core, &live_active)?;
        let current_record_set =
            read_current_generation_record_set(successor, storage_ids, &master_key, &terminals)?;
        let current_limits = RestoreRecordSetLimitsV1::new(
            current_record_set.record_count(),
            current_record_set.as_bytes().len(),
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let current_projected = canonical_record_set_from_journal(
            authenticated.entries(),
            &terminals,
            &current_limits,
        )?;
        if current_projected.as_bytes() != current_record_set.as_bytes() {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        successor.revalidate()?;
        return Ok((core, activation_active, live_active));
    }
    let head = authenticated
        .head()
        .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
    if head.sequence() != fields.successor_final_journal_sequence
        || head.entry_digest() != &fields.successor_final_journal_head_digest
        || activation_projected.as_bytes() != activation_record_set.as_bytes()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    successor.revalidate()?;
    #[cfg(test)]
    if step12_semantic_authentication {
        test_restore_crash_hook("step12-after-full-verify");
    }
    Ok((core, activation_active, live_active))
}

fn authenticate_successor_tombstones(
    successor: &RetainedDirectory,
    storage_ids: StorageIdsV1,
    master_key: &VaultMasterKey,
) -> Result<AuthenticatedSuccessorTombstonesV1, LinuxCapabilityError> {
    let tombstones =
        successor.open_child_directory(ValidatedComponent::registered("tombstones")?)?;
    let mut items = Vec::new();
    let mut terminals = BTreeMap::new();
    let mut envelopes = BTreeMap::<[u8; 105], VaultObjectEnvelopeV1>::new();
    tombstones.scan_lexicographic(|name, identity| {
        if identity.node_type != ExpectedNodeType::RegularFile {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let identity_hex = name
            .strip_suffix(".tombstone")
            .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
        if identity_hex.len() != 210 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        let identity_bytes = decode_lower_hex::<105>(identity_hex)?;
        let envelope = VaultObjectEnvelopeV1::from_bytes(&tombstones.read_bounded_file(
            &ValidatedComponent::registered(name)?,
            TOMBSTONE_ENVELOPE_LEN,
        )?)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let identity_epoch = read_u64(&identity_bytes[97..105])?;
        if envelope.as_bytes().len() != TOMBSTONE_ENVELOPE_LEN
            || read_u64(&envelope.as_bytes()[78..86])? != identity_epoch
            || envelope.as_bytes()[86..118] != identity_bytes[..32]
            || envelope.as_bytes()[118..150] != identity_bytes[32..64]
            || envelope.as_bytes()[150] != identity_bytes[64]
        {
            return Err(LinuxCapabilityError::IdentityMismatch);
        }
        let metadata = TombstoneRecordMetadataV1::new(
            identity_epoch,
            copy_32(&envelope.as_bytes()[86..118])?,
            copy_32(&envelope.as_bytes()[118..150])?,
            PurposeV1::try_from(envelope.as_bytes()[150])
                .map_err(|_| LinuxCapabilityError::InvalidObject)?,
            read_u64(&envelope.as_bytes()[152..160])?,
            copy_32(&envelope.as_bytes()[160..192])?,
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let plaintext = open_tombstone_v1(&envelope, storage_ids, master_key, metadata)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let tombstone = TombstoneV1::from_bytes(plaintext.as_bytes())
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        if tombstone.identity().as_bytes() != &identity_bytes {
            return Err(LinuxCapabilityError::IdentityMismatch);
        }
        let item = RestoreRecordItemV1::from_record_bytes(
            RestoreRecordFamilyV1::Tombstone,
            tombstone.as_bytes(),
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        if terminals.insert(identity_bytes, tombstone).is_some() {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        items.push(item);
        if envelopes.insert(identity_bytes, envelope).is_some() {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        Ok(())
    })?;
    tombstones.revalidate()?;
    let count = u32::try_from(items.len()).map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let maximum = items.iter().try_fold(4_usize, |total, item| {
        total
            .checked_add(item.as_bytes().len())
            .ok_or(LinuxCapabilityError::InvalidObject)
    })?;
    let limits = RestoreRecordSetLimitsV1::new(count, maximum)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let record_set =
        RestoreRecordSetV1::new(items, &limits).map_err(|_| LinuxCapabilityError::InvalidObject)?;
    Ok((record_set, envelopes, terminals))
}

fn tombstone_envelope_subset_digest(
    envelopes: &BTreeMap<[u8; 105], VaultObjectEnvelopeV1>,
    identities: impl Iterator<Item = [u8; 105]>,
) -> Result<[u8; 32], LinuxCapabilityError> {
    let selected = identities
        .map(|identity| {
            envelopes
                .get(&identity)
                .map(|envelope| (identity, envelope))
                .ok_or(LinuxCapabilityError::ExactBytesMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = u32::try_from(selected.len()).map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&count.to_le_bytes());
    for (identity, envelope) in selected {
        preimage.extend_from_slice(&identity);
        preimage.extend_from_slice(
            &u32::try_from(envelope.as_bytes().len())
                .map_err(|_| LinuxCapabilityError::InvalidObject)?
                .to_le_bytes(),
        );
        preimage.extend_from_slice(&envelope.digest());
    }
    Ok(authoritative_storage_hash_v1(
        StorageHashDomainV1::TombstoneEnvelopeSet,
        &preimage,
    ))
}

fn read_current_generation_record_set(
    generation: &RetainedDirectory,
    _storage_ids: StorageIdsV1,
    _master_key: &VaultMasterKey,
    terminals: &BTreeMap<[u8; 105], TombstoneV1>,
) -> Result<RestoreRecordSetV1, LinuxCapabilityError> {
    let mut items = Vec::new();
    {
        let mut push = |family, bytes: &[u8]| {
            items.push(
                RestoreRecordItemV1::from_record_bytes(family, bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            );
            Ok::<_, LinuxCapabilityError>(())
        };
        if child_exists(generation, "session-claims", ExpectedNodeType::Directory)? {
            let claims = generation
                .open_child_directory(ValidatedComponent::registered("session-claims")?)?;
            claims.scan_lexicographic(|name, node| {
                if node.node_type != ExpectedNodeType::RegularFile {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                let bytes = claims
                    .read_bounded_file(&ValidatedComponent::registered(name)?, SESSION_CLAIM_LEN)?;
                let claim = SessionClaimV1::from_bytes(&bytes)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                if name != format!("{}.claim", encode_lower_hex(claim.identity().session_id())) {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                push(RestoreRecordFamilyV1::SessionClaim, claim.as_bytes())
            })?;
            claims.revalidate()?;
        }
        if child_exists(generation, "attempts", ExpectedNodeType::Directory)? {
            let attempts =
                generation.open_child_directory(ValidatedComponent::registered("attempts")?)?;
            attempts.scan_lexicographic(|identity_name, identity_node| {
                if identity_node.node_type != ExpectedNodeType::Directory {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
                let identity = attempts
                    .open_child_directory(ValidatedComponent::registered(identity_name)?)?;
                let mut count = 0_u64;
                identity.scan_lexicographic(|record_name, node| {
                    if node.node_type != ExpectedNodeType::RegularFile {
                        return Err(LinuxCapabilityError::InvalidObject);
                    }
                    let bytes = identity.read_bounded_file(
                        &ValidatedComponent::registered(record_name)?,
                        NONCE_DERIVATION_ATTEMPT_LEN,
                    )?;
                    let attempt = if bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
                        let derivation = NonceDerivationAttemptV1::from_bytes(&bytes)
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                        derivation.attempt().clone()
                    } else if bytes.len() == ATTEMPT_RECORD_LEN {
                        AttemptRecordV1::from_bytes(&bytes)
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?
                    } else {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    };
                    let structural =
                        crate::UnauthenticatedAttemptRecordV1::parse_structural(attempt.as_bytes())
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    if canonical_attempt_relative_path(&structural)
                        != format!("{identity_name}/{record_name}")
                    {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                    // The canonical projection preserves the exact persisted
                    // record family representation.  In particular, a derivation
                    // attempt is not collapsed to its embedded AttemptRecordV1.
                    push(RestoreRecordFamilyV1::Attempt, &bytes)?;
                    count = count
                        .checked_add(1)
                        .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
                    Ok(())
                })?;
                if count == 0 {
                    return Err(LinuxCapabilityError::InvalidDirectoryEntry);
                }
                identity.revalidate()
            })?;
            attempts.revalidate()?;
        }
        if child_exists(generation, "exposures", ExpectedNodeType::Directory)? {
            let exposures =
                generation.open_child_directory(ValidatedComponent::registered("exposures")?)?;
            super::inventory::scan_exposure_records(&exposures, |exposure| {
                push(RestoreRecordFamilyV1::Exposure, exposure.as_bytes())
            })
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            exposures.revalidate()?;
        }
        for tombstone in terminals.values() {
            push(RestoreRecordFamilyV1::Tombstone, tombstone.as_bytes())?;
        }
    }
    let count = u32::try_from(items.len()).map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let maximum = items.iter().try_fold(4_usize, |total, item| {
        total
            .checked_add(item.as_bytes().len())
            .ok_or(LinuxCapabilityError::InvalidObject)
    })?;
    let limits = RestoreRecordSetLimitsV1::new(count, maximum)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    RestoreRecordSetV1::new(items, &limits).map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
}

fn authenticate_predecessor_from_disk(
    target_root: &RetainedDirectory,
    root_identity: &StoreRootIdentityV1,
    manifest: &RestoreManifestV1,
    successor_core: &VaultGenerationCoreV1,
) -> Result<VaultGenerationCoreV1, LinuxCapabilityError> {
    let predecessor_generation = successor_core
        .vault_generation()
        .checked_sub(1)
        .ok_or(LinuxCapabilityError::InvalidObject)?;
    let name = format!(
        "generation-{predecessor_generation:020}-{}",
        encode_lower_hex(manifest.target_vault_id())
    );
    let predecessor = target_root.open_child_directory(ValidatedComponent::registered(&name)?)?;
    let core = VaultGenerationCoreV1::from_bytes(&predecessor.read_bounded_file(
        &ValidatedComponent::registered("generation-core.bin")?,
        VAULT_GENERATION_CORE_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    if core.as_bytes()[10..42] != root_identity.contract_wallet_id()[..]
        || core.as_bytes()[42..74] != root_identity.store_root_id()[..]
        || core.vault_id() != manifest.target_vault_id()
        || core.nonce_epoch() != manifest.target_epoch()
        || core.vault_generation() != predecessor_generation
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    predecessor.revalidate()?;
    Ok(core)
}

/// Consumes one verified staging capability and executes restore steps 9--14.
///
/// The caller retains the exclusive Store lock for this entire call. Every
/// post-rename verifier reopens the canonical location from the retained root;
/// Staging handles that went out of date never grant authority after a move.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
)]
#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn publish_staged_existing_device_restore(
    target_root: &RetainedDirectory,
    retained_lock: &RetainedExclusiveLock,
    target_root_identity: &StoreRootIdentityV1,
    predecessor_core: &VaultGenerationCoreV1,
    predecessor_active: &ActiveVaultGenerationV1,
    staged: StagedExistingRestoreV1,
) -> Result<CompletedExistingRestoreV1, LinuxCapabilityError> {
    retained_lock.revalidate()?;
    staged.revalidate_retained_authorities()?;
    require_predecessor_authority(
        target_root,
        target_root_identity,
        predecessor_core,
        predecessor_active,
        staged.publication(),
    )?;
    verify_existing_restore_staging(staged.staging(), staged.publication())?;

    let manifest_structural = UnauthenticatedRestoreManifestV1::parse_structural(
        staged.publication().manifest().as_bytes(),
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let staging_name = ValidatedComponent::registered(&canonical_restore_staging_directory_name(
        &manifest_structural,
    ))?;
    let completed_name = ValidatedComponent::registered(
        &canonical_restore_completed_directory_name(&manifest_structural),
    )?;
    let successor_structural = UnauthenticatedVaultGenerationCoreV1::parse_structural(
        staged.publication().successor_core().as_bytes(),
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let generation_name = ValidatedComponent::registered(&canonical_generation_directory_name(
        &successor_structural,
    ))?;
    require_root_location(
        target_root,
        "restore-pending",
        ExpectedNodeType::Directory,
        false,
    )?;
    require_root_location(
        target_root,
        completed_name.as_str(),
        ExpectedNodeType::Directory,
        false,
    )?;
    require_root_location(
        target_root,
        generation_name.as_str(),
        ExpectedNodeType::Directory,
        false,
    )?;

    // Step 9: publish the one complete staging tree under the reserved name.
    retained_lock.revalidate()?;
    #[cfg(test)]
    test_restore_crash_hook("step9-before-rename");
    let pending =
        target_root.publish_restore_staging_no_replace(&staging_name, staged.staging())?;
    #[cfg(test)]
    test_restore_crash_hook("step9-after-root-sync");
    verify_restore_transaction_tree(&pending, staged.publication(), true, true)?;
    require_root_location(
        target_root,
        staging_name.as_str(),
        ExpectedNodeType::Directory,
        false,
    )?;
    require_root_location(
        target_root,
        generation_name.as_str(),
        ExpectedNodeType::Directory,
        false,
    )?;
    require_live_active(target_root, predecessor_core, predecessor_active)?;

    // Step 10: move only the reopened pending successor to its immutable name.
    retained_lock.revalidate()?;
    #[cfg(test)]
    test_restore_crash_hook("step10-before-rename");
    let pending_successor =
        pending.open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
    let generation = target_root.activate_restore_generation_no_replace(
        &pending,
        &pending_successor,
        &generation_name,
    )?;
    #[cfg(test)]
    test_restore_crash_hook("step10-after-root-sync");
    verify_restore_transaction_tree(&pending, staged.publication(), false, true)?;
    verify_successor_generation(&generation, staged.publication())?;
    require_root_location(
        target_root,
        generation_name.as_str(),
        ExpectedNodeType::Directory,
        true,
    )?;
    require_live_active(target_root, predecessor_core, predecessor_active)?;

    // Step 11: replace the active pointer only after final-generation sync and
    // complete re-verification at its immutable location.
    retained_lock.revalidate()?;
    #[cfg(test)]
    test_restore_crash_hook("step11-before-rename");
    let activation = pending.open_child_directory(ValidatedComponent::registered("activation")?)?;
    let staged_active = activation.open_file(
        &ValidatedComponent::registered("active-generation.bin")?,
        false,
    )?;
    require_exact_file(
        &activation,
        "active-generation.bin",
        staged.publication().active().as_bytes(),
        ACTIVE_VAULT_GENERATION_LEN,
    )?;
    target_root.activate_restore_pointer(&pending, &activation, &staged_active)?;
    #[cfg(test)]
    test_restore_crash_hook("step11-after-root-sync");

    // Step 12: all indexed successor material must verify from its final disk
    // locations before the pending quarantine marker can move.
    verify_restore_transaction_tree(&pending, staged.publication(), false, false)?;
    verify_final_activated_state(target_root, &generation, staged.publication())?;

    // Step 13: retain the exact pending transaction under its immutable name.
    retained_lock.revalidate()?;
    #[cfg(test)]
    test_restore_crash_hook("step13-before-rename");
    let completed = target_root.retain_completed_restore_no_replace(&pending, &completed_name)?;
    #[cfg(test)]
    test_restore_crash_hook("step13-after-root-sync");
    require_root_location(
        target_root,
        "restore-pending",
        ExpectedNodeType::Directory,
        false,
    )?;
    verify_restore_transaction_tree(&completed, staged.publication(), false, false)?;
    verify_final_activated_state(target_root, &generation, staged.publication())?;

    // Step 14: final root, lock, completed transaction, generation, and active
    // pointer revalidation occurs while the caller still owns the same lock.
    retained_lock.revalidate()?;
    require_exact_root_identity(target_root, target_root_identity)?;
    completed.revalidate()?;
    generation.revalidate()?;
    let active = target_root.open_file(
        &ValidatedComponent::registered("active-vault-generation")?,
        false,
    )?;
    active.revalidate()?;
    verify_restore_transaction_tree(&completed, staged.publication(), false, false)?;
    verify_final_activated_state(target_root, &generation, staged.publication())?;
    target_root.revalidate()?;
    retained_lock.revalidate()?;

    Ok(CompletedExistingRestoreV1 {
        completed,
        generation,
        active,
    })
}

/// Final new-device restore authority with the original exclusive lock still held.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct CompletedNewDeviceRestoreV1 {
    root: RetainedDirectory,
    retained_lock: RetainedExclusiveLock,
    root_identity: StoreRootIdentityV1,
    completed: RetainedDirectory,
    generation: RetainedDirectory,
    active: RetainedFile,
}

#[cfg(any(test, feature = "evidence-only"))]
impl CompletedNewDeviceRestoreV1 {
    pub(super) fn into_parts(
        self,
    ) -> (
        RetainedDirectory,
        RetainedExclusiveLock,
        StoreRootIdentityV1,
        RetainedDirectory,
        RetainedDirectory,
        RetainedFile,
    ) {
        (
            self.root,
            self.retained_lock,
            self.root_identity,
            self.completed,
            self.generation,
            self.active,
        )
    }
}

/// Executes restore steps 9--15 for a new-device restore-only root.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn publish_staged_new_device_restore(
    initialized: InitializedNewDeviceRestoreRootV1,
    staged: StagedNewDeviceRestoreV1,
) -> Result<CompletedNewDeviceRestoreV1, LinuxCapabilityError> {
    let (root, retained_lock, root_identity, restore_only_root) = initialized.into_parts();
    retained_lock.revalidate()?;
    require_restore_only_root_authority(
        &root,
        &root_identity,
        &restore_only_root,
        staged.publication().source(),
    )?;
    staged.revalidate_retained_authorities()?;
    verify_existing_restore_staging(staged.staging(), staged.publication())?;

    let manifest_structural = UnauthenticatedRestoreManifestV1::parse_structural(
        staged.publication().manifest().as_bytes(),
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    if !manifest_structural.is_new_device_target()
        || staged
            .publication()
            .pending_index()
            .fields()
            .restore_only_root_digest
            != *restore_only_root.restore_only_root_digest()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let staging_name = ValidatedComponent::registered(&canonical_restore_staging_directory_name(
        &manifest_structural,
    ))?;
    let completed_name = ValidatedComponent::registered(
        &canonical_restore_completed_directory_name(&manifest_structural),
    )?;
    let successor_structural = UnauthenticatedVaultGenerationCoreV1::parse_structural(
        staged.publication().successor_core().as_bytes(),
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let generation_name = ValidatedComponent::registered(&canonical_generation_directory_name(
        &successor_structural,
    ))?;
    for (name, kind) in [
        ("restore-pending", ExpectedNodeType::Directory),
        (completed_name.as_str(), ExpectedNodeType::Directory),
        (generation_name.as_str(), ExpectedNodeType::Directory),
        ("active-vault-generation", ExpectedNodeType::RegularFile),
    ] {
        require_root_location(&root, name, kind, false)?;
    }

    retained_lock.revalidate()?;
    #[cfg(test)]
    test_restore_crash_hook("step9-before-rename");
    let pending = root.publish_restore_staging_no_replace(&staging_name, staged.staging())?;
    #[cfg(test)]
    test_restore_crash_hook("step9-after-root-sync");
    verify_restore_transaction_tree(&pending, staged.publication(), true, true)?;
    require_root_location(
        &root,
        "active-vault-generation",
        ExpectedNodeType::RegularFile,
        false,
    )?;

    retained_lock.revalidate()?;
    #[cfg(test)]
    test_restore_crash_hook("step10-before-rename");
    let pending_successor =
        pending.open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
    let generation = root.activate_restore_generation_no_replace(
        &pending,
        &pending_successor,
        &generation_name,
    )?;
    #[cfg(test)]
    test_restore_crash_hook("step10-after-root-sync");
    verify_restore_transaction_tree(&pending, staged.publication(), false, true)?;
    verify_successor_generation(&generation, staged.publication())?;
    require_root_location(
        &root,
        "active-vault-generation",
        ExpectedNodeType::RegularFile,
        false,
    )?;

    retained_lock.revalidate()?;
    #[cfg(test)]
    test_restore_crash_hook("step11-before-rename");
    let activation = pending.open_child_directory(ValidatedComponent::registered("activation")?)?;
    let staged_active = activation.open_file(
        &ValidatedComponent::registered("active-generation.bin")?,
        false,
    )?;
    require_exact_file(
        &activation,
        "active-generation.bin",
        staged.publication().active().as_bytes(),
        ACTIVE_VAULT_GENERATION_LEN,
    )?;
    root.activate_restore_pointer(&pending, &activation, &staged_active)?;
    #[cfg(test)]
    test_restore_crash_hook("step11-after-root-sync");
    verify_restore_transaction_tree(&pending, staged.publication(), false, false)?;
    verify_final_activated_state(&root, &generation, staged.publication())?;

    retained_lock.revalidate()?;
    #[cfg(test)]
    test_restore_crash_hook("step13-before-rename");
    let completed = root.retain_completed_restore_no_replace(&pending, &completed_name)?;
    #[cfg(test)]
    test_restore_crash_hook("step13-after-root-sync");
    verify_restore_transaction_tree(&completed, staged.publication(), false, false)?;
    verify_final_activated_state(&root, &generation, staged.publication())?;

    retained_lock.revalidate()?;
    require_exact_root_identity(&root, &root_identity)?;
    transition_restore_only_marker(&root, &root_identity, &restore_only_root)?;
    let active = root.open_file(
        &ValidatedComponent::registered("active-vault-generation")?,
        false,
    )?;
    completed.revalidate()?;
    generation.revalidate()?;
    active.revalidate()?;
    retained_lock.revalidate()?;
    Ok(CompletedNewDeviceRestoreV1 {
        root,
        retained_lock,
        root_identity,
        completed,
        generation,
        active,
    })
}

fn transition_restore_only_marker(
    root: &RetainedDirectory,
    root_identity: &StoreRootIdentityV1,
    restore_only_root: &RestoreOnlyRootV1,
) -> Result<(), LinuxCapabilityError> {
    require_exact_root_identity(root, root_identity)?;
    let marker_component = ValidatedComponent::registered("restore-only-root.bin")?;
    let mut marker = root.open_file(&marker_component, false)?;
    marker.require_exact_bytes(restore_only_root.as_bytes())?;
    let initialized_name = ValidatedComponent::registered(
        &canonical_restore_initialized_marker_name(restore_only_root),
    )?;
    #[cfg(test)]
    test_restore_crash_hook("step15-before-marker-rename");
    root.rename_no_replace(&marker_component, &initialized_name, &marker)?;
    #[cfg(test)]
    test_restore_crash_hook("step15-after-marker-rename");
    require_root_location(
        root,
        "restore-only-root.bin",
        ExpectedNodeType::RegularFile,
        false,
    )?;
    require_exact_file(
        root,
        initialized_name.as_str(),
        restore_only_root.as_bytes(),
        crate::RESTORE_ONLY_ROOT_LEN,
    )?;
    root.sync()?;
    root.revalidate()
}

/// Builds and verifies the exact existing-device staging tree without
/// publishing it as `restore-pending`.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn stage_existing_device_restore(
    target_root: &RetainedDirectory,
    publication: PreparedExistingRestorePublicationV1,
) -> Result<StagedExistingRestoreV1, LinuxCapabilityError> {
    target_root.revalidate()?;
    let retained_root = StoreRootIdentityV1::from_bytes(&target_root.read_bounded_file(
        &ValidatedComponent::registered("store-root-identity.bin")?,
        STORE_IDENTITY_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    publication
        .preparation()
        .require_target_root_identity(&retained_root)?;
    publication
        .preparation()
        .source()
        .revalidate_source_authority()?;

    let structural =
        UnauthenticatedRestoreManifestV1::parse_structural(publication.manifest().as_bytes())
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let staging_component =
        ValidatedComponent::registered(&canonical_restore_staging_directory_name(&structural))?;
    let staging = target_root.create_child_directory(staging_component.clone())?;
    populate_existing_restore_staging(&staging, &publication)?;
    publication
        .preparation()
        .source()
        .revalidate_source_authority()?;
    staging.sync()?;
    target_root.sync()?;

    let reopened = target_root.open_child_directory(staging_component)?;
    staging.identity.require_same(&reopened.identity)?;
    verify_existing_restore_staging(&reopened, &publication)?;
    publication
        .preparation()
        .source()
        .revalidate_source_authority()?;
    target_root.revalidate()?;

    let source_backup =
        reopened.open_child_directory(ValidatedComponent::registered("source-backup")?)?;
    let successor =
        reopened.open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
    let activation =
        reopened.open_child_directory(ValidatedComponent::registered("activation")?)?;
    let staged_active = activation.open_file(
        &ValidatedComponent::registered("active-generation.bin")?,
        false,
    )?;
    Ok(StagedExistingRestoreV1 {
        publication,
        staging: reopened,
        source_backup,
        successor,
        activation,
        staged_active,
    })
}

/// Builds and verifies the exact new-device restore-only staging tree without
/// publishing it as `restore-pending`.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn stage_new_device_restore(
    initialized: &InitializedNewDeviceRestoreRootV1,
    publication: PreparedNewDeviceRestorePublicationV1,
) -> Result<StagedNewDeviceRestoreV1, LinuxCapabilityError> {
    initialized.retained_lock().revalidate()?;
    require_restore_only_root_inventory(initialized.root())?;
    require_restore_only_root_authority(
        initialized.root(),
        initialized.root_identity(),
        initialized.restore_only_root(),
        publication.source(),
    )?;
    if publication.restore_only_root().as_bytes() != initialized.restore_only_root().as_bytes() {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let structural =
        UnauthenticatedRestoreManifestV1::parse_structural(publication.manifest().as_bytes())
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    if !structural.is_new_device_target() {
        return Err(LinuxCapabilityError::InvalidObject);
    }
    let staging_component =
        ValidatedComponent::registered(&canonical_restore_staging_directory_name(&structural))?;
    let staging = initialized
        .root()
        .create_child_directory(staging_component.clone())?;
    populate_existing_restore_staging(&staging, &publication)?;
    publication.source().revalidate_source_authority()?;
    staging.sync()?;
    initialized.root().sync()?;
    let reopened = initialized.root().open_child_directory(staging_component)?;
    staging.identity.require_same(&reopened.identity)?;
    verify_existing_restore_staging(&reopened, &publication)?;
    require_restore_only_root_authority(
        initialized.root(),
        initialized.root_identity(),
        initialized.restore_only_root(),
        publication.source(),
    )?;
    let source_backup =
        reopened.open_child_directory(ValidatedComponent::registered("source-backup")?)?;
    let successor =
        reopened.open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
    let activation =
        reopened.open_child_directory(ValidatedComponent::registered("activation")?)?;
    let staged_active = activation.open_file(
        &ValidatedComponent::registered("active-generation.bin")?,
        false,
    )?;
    Ok(StagedNewDeviceRestoreV1 {
        publication,
        staging: reopened,
        source_backup,
        successor,
        activation,
        staged_active,
    })
}

#[cfg(any(test, feature = "evidence-only"))]
fn require_restore_only_root_authority(
    root: &RetainedDirectory,
    root_identity: &StoreRootIdentityV1,
    restore_only_root: &RestoreOnlyRootV1,
    source: &SelectedBackupMaterialV1,
) -> Result<(), LinuxCapabilityError> {
    let retained_root = StoreRootIdentityV1::from_bytes(&root.read_bounded_file(
        &ValidatedComponent::registered("store-root-identity.bin")?,
        STORE_IDENTITY_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    StoreLockIdentityV1::from_bytes_with_root(
        &root.read_bounded_file(
            &ValidatedComponent::registered("store-lock-identity.bin")?,
            STORE_IDENTITY_LEN,
        )?,
        &retained_root,
    )
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let retained_marker = RestoreOnlyRootV1::from_bytes(&root.read_bounded_file(
        &ValidatedComponent::registered("restore-only-root.bin")?,
        crate::RESTORE_ONLY_ROOT_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    if retained_root.as_bytes() != root_identity.as_bytes()
        || retained_marker.as_bytes() != restore_only_root.as_bytes()
        || retained_marker.contract_wallet_id() != root_identity.contract_wallet_id()
        || retained_marker.store_root_id() != root_identity.store_root_id()
        || retained_marker.lock_instance_id() != root_identity.lock_instance_id()
        || retained_marker.source_backup_bundle_digest() != source.bundle().bundle_digest()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    source.revalidate_source_authority()?;
    root.revalidate()
}

#[cfg(any(test, feature = "evidence-only"))]
fn populate_existing_restore_staging(
    staging: &RetainedDirectory,
    publication: &impl RestorePublicationViewV1,
) -> Result<(), LinuxCapabilityError> {
    staging.create_immutable_file(
        &ValidatedComponent::registered("restore-pending.index")?,
        publication.pending_index().as_bytes(),
    )?;
    staging.create_immutable_file(
        &ValidatedComponent::registered("restore-manifest.bin")?,
        publication.manifest().as_bytes(),
    )?;

    let source_backup =
        staging.create_child_directory(ValidatedComponent::registered("source-backup")?)?;
    populate_source_backup(&source_backup, publication.source())?;
    source_backup.sync()?;

    let successor =
        staging.create_child_directory(ValidatedComponent::registered("successor-generation")?)?;
    populate_successor_generation(&successor, publication)?;
    successor.sync()?;

    let activation =
        staging.create_child_directory(ValidatedComponent::registered("activation")?)?;
    activation.create_immutable_file(
        &ValidatedComponent::registered("active-generation.bin")?,
        publication.active().as_bytes(),
    )?;
    activation.sync()?;
    staging.sync()
}

#[cfg(any(test, feature = "evidence-only"))]
fn populate_source_backup(
    destination: &RetainedDirectory,
    source: &SelectedBackupMaterialV1,
) -> Result<(), LinuxCapabilityError> {
    source.revalidate_source_authority()?;
    destination.create_immutable_file(
        &ValidatedComponent::registered("backup-master-key.envelope")?,
        source.master_envelope().as_bytes(),
    )?;
    destination.create_immutable_file(
        &ValidatedComponent::registered("backup-manifest.object")?,
        source.manifest_envelope().as_bytes(),
    )?;
    destination.create_immutable_file(
        &ValidatedComponent::registered("backup-bundle.digest")?,
        source.bundle().bundle_digest(),
    )?;
    let journal = destination.create_child_directory(ValidatedComponent::registered("journal")?)?;
    write_journal_entries(&journal, source.journal_entries())?;
    journal.sync()?;
    let records = destination.create_child_directory(ValidatedComponent::registered("records")?)?;
    write_record_set(&records, source.record_set())?;
    records.sync()?;
    source.revalidate_source_authority()?;
    destination.sync()
}

#[cfg(any(test, feature = "evidence-only"))]
fn populate_successor_generation(
    successor: &RetainedDirectory,
    publication: &impl RestorePublicationViewV1,
) -> Result<(), LinuxCapabilityError> {
    successor.create_immutable_file(
        &ValidatedComponent::registered("generation-core.bin")?,
        publication.successor_core().as_bytes(),
    )?;
    successor.create_immutable_file(
        &ValidatedComponent::registered("master-key.envelope")?,
        publication.successor_master_envelope().as_bytes(),
    )?;
    let journal = successor.create_child_directory(ValidatedComponent::registered("journal")?)?;
    let journal_bytes = publication
        .journal_entries()
        .iter()
        .map(|entry| entry.as_bytes().to_vec())
        .collect::<Vec<_>>();
    write_journal_entries(&journal, &journal_bytes)?;
    journal.sync()?;
    let tombstones =
        successor.create_child_directory(ValidatedComponent::registered("tombstones")?)?;
    for (identity, envelope) in publication.successor_terminals().envelopes() {
        let name = format!("{}.tombstone", encode_lower_hex(identity));
        tombstones
            .create_immutable_file(&ValidatedComponent::registered(&name)?, envelope.as_bytes())?;
    }
    tombstones.sync()?;
    successor.sync()
}

#[cfg(any(test, feature = "evidence-only"))]
fn write_journal_entries(
    journal: &RetainedDirectory,
    entries: &[Vec<u8>],
) -> Result<(), LinuxCapabilityError> {
    for bytes in entries {
        let structural = UnauthenticatedJournalEntryV1::parse_structural(bytes)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let name = canonical_journal_filename(structural.envelope());
        journal.create_immutable_file(&ValidatedComponent::registered(&name)?, bytes)?;
    }
    Ok(())
}

#[cfg(any(test, feature = "evidence-only"))]
fn write_record_set(
    records: &RetainedDirectory,
    record_set: &RestoreRecordSetV1,
) -> Result<(), LinuxCapabilityError> {
    let mut cursor = 4_usize;
    let mut identity_directories = BTreeMap::<String, RetainedDirectory>::new();
    while cursor < record_set.as_bytes().len() {
        let prefix_end = cursor
            .checked_add(RESTORE_RECORD_ITEM_PREFIX_LEN)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let record_length = usize::try_from(read_u32(
            &record_set.as_bytes()[cursor + RESTORE_RECORD_KEY_LEN..prefix_end],
        )?)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let item_end = prefix_end
            .checked_add(record_length)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        if item_end > record_set.as_bytes().len() {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let key = UnauthenticatedRestoreRecordKeyV1::parse_structural(
            &record_set.as_bytes()[cursor..cursor + RESTORE_RECORD_KEY_LEN],
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let directory_name = canonical_restore_record_directory_name(&key);
        if !identity_directories.contains_key(&directory_name) {
            let directory =
                records.create_child_directory(ValidatedComponent::registered(&directory_name)?)?;
            identity_directories.insert(directory_name.clone(), directory);
        }
        let directory = identity_directories
            .get(&directory_name)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let filename = canonical_restore_record_filename(&key);
        directory.create_immutable_file(
            &ValidatedComponent::registered(&filename)?,
            &record_set.as_bytes()[prefix_end..item_end],
        )?;
        cursor = item_end;
    }
    for directory in identity_directories.values() {
        directory.sync()?;
    }
    Ok(())
}

#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn verify_existing_restore_staging(
    staging: &RetainedDirectory,
    publication: &impl RestorePublicationViewV1,
) -> Result<(), LinuxCapabilityError> {
    require_closed_inventory(
        staging,
        &[
            ("restore-pending.index", ExpectedNodeType::RegularFile),
            ("restore-manifest.bin", ExpectedNodeType::RegularFile),
            ("source-backup", ExpectedNodeType::Directory),
            ("successor-generation", ExpectedNodeType::Directory),
            ("activation", ExpectedNodeType::Directory),
        ],
    )?;
    require_exact_file(
        staging,
        "restore-pending.index",
        publication.pending_index().as_bytes(),
        RESTORE_PENDING_INDEX_LEN,
    )?;
    let parsed_pending = RestorePendingIndexV1::from_bytes(&staging.read_bounded_file(
        &ValidatedComponent::registered("restore-pending.index")?,
        RESTORE_PENDING_INDEX_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    if parsed_pending.as_bytes() != publication.pending_index().as_bytes()
        || parsed_pending.fields() != publication.pending_index().fields()
        || parsed_pending.pending_index_digest()
            != &parsed_pending.as_bytes()[RESTORE_PENDING_INDEX_LEN - 32..]
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    require_exact_file(
        staging,
        "restore-manifest.bin",
        publication.manifest().as_bytes(),
        RESTORE_MANIFEST_LEN,
    )?;

    let source_backup =
        staging.open_child_directory(ValidatedComponent::registered("source-backup")?)?;
    verify_source_backup(&source_backup, publication.source(), publication.limits())?;
    let successor =
        staging.open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
    verify_successor_generation(&successor, publication)?;
    let activation = staging.open_child_directory(ValidatedComponent::registered("activation")?)?;
    require_closed_inventory(
        &activation,
        &[("active-generation.bin", ExpectedNodeType::RegularFile)],
    )?;
    require_exact_file(
        &activation,
        "active-generation.bin",
        publication.active().as_bytes(),
        ACTIVE_VAULT_GENERATION_LEN,
    )?;
    activation.revalidate()?;
    staging.revalidate()
}

#[cfg(any(test, feature = "evidence-only"))]
fn require_predecessor_authority(
    target_root: &RetainedDirectory,
    target_root_identity: &StoreRootIdentityV1,
    predecessor_core: &VaultGenerationCoreV1,
    predecessor_active: &ActiveVaultGenerationV1,
    publication: &PreparedExistingRestorePublicationV1,
) -> Result<(), LinuxCapabilityError> {
    require_exact_root_identity(target_root, target_root_identity)?;
    let preparation = publication.preparation();
    if predecessor_core.vault_id() != preparation.target_vault_id()
        || predecessor_core.nonce_epoch() != preparation.target_epoch()
        || predecessor_core.vault_generation() != preparation.target_generation()
        || predecessor_active.journal_sequence() != preparation.target_journal_sequence()
        || predecessor_active.journal_head_digest() != preparation.target_journal_head_digest()
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    let predecessor_structural =
        UnauthenticatedVaultGenerationCoreV1::parse_structural(predecessor_core.as_bytes())
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let predecessor_name = ValidatedComponent::registered(&canonical_generation_directory_name(
        &predecessor_structural,
    ))?;
    let predecessor = target_root.open_child_directory(predecessor_name)?;
    require_exact_file(
        &predecessor,
        "generation-core.bin",
        predecessor_core.as_bytes(),
        VAULT_GENERATION_CORE_LEN,
    )?;
    predecessor.revalidate()?;
    require_live_active(target_root, predecessor_core, predecessor_active)
}

fn require_exact_root_identity(
    target_root: &RetainedDirectory,
    expected: &StoreRootIdentityV1,
) -> Result<(), LinuxCapabilityError> {
    target_root.revalidate()?;
    let root = StoreRootIdentityV1::from_bytes(&target_root.read_bounded_file(
        &ValidatedComponent::registered("store-root-identity.bin")?,
        STORE_IDENTITY_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    if root.as_bytes() != expected.as_bytes() {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    StoreLockIdentityV1::from_bytes_with_root(
        &target_root.read_bounded_file(
            &ValidatedComponent::registered("store-lock-identity.bin")?,
            STORE_IDENTITY_LEN,
        )?,
        &root,
    )
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    Ok(())
}

#[cfg(any(test, feature = "evidence-only"))]
fn require_live_active(
    target_root: &RetainedDirectory,
    core: &VaultGenerationCoreV1,
    expected: &ActiveVaultGenerationV1,
) -> Result<(), LinuxCapabilityError> {
    let bytes = target_root.read_bounded_file(
        &ValidatedComponent::registered("active-vault-generation")?,
        ACTIVE_VAULT_GENERATION_LEN,
    )?;
    let active = ActiveVaultGenerationV1::from_bytes_with_core(&bytes, core)
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    if active.as_bytes() == expected.as_bytes() {
        Ok(())
    } else {
        Err(LinuxCapabilityError::ExactBytesMismatch)
    }
}

fn require_root_location(
    target_root: &RetainedDirectory,
    expected_name: &str,
    expected_type: ExpectedNodeType,
    must_exist: bool,
) -> Result<(), LinuxCapabilityError> {
    let mut matches = 0_u8;
    target_root.scan_independent(|name, identity| {
        if name == expected_name {
            if identity.node_type != expected_type {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            matches = matches
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
        }
        Ok(())
    })?;
    if matches == u8::from(must_exist) {
        Ok(())
    } else {
        Err(LinuxCapabilityError::InvalidDirectoryEntry)
    }
}

#[cfg(any(test, feature = "evidence-only"))]
fn verify_restore_transaction_tree(
    transaction: &RetainedDirectory,
    publication: &impl RestorePublicationViewV1,
    successor_nested: bool,
    active_nested: bool,
) -> Result<(), LinuxCapabilityError> {
    let mut expected = vec![
        ("restore-pending.index", ExpectedNodeType::RegularFile),
        ("restore-manifest.bin", ExpectedNodeType::RegularFile),
        ("source-backup", ExpectedNodeType::Directory),
        ("activation", ExpectedNodeType::Directory),
    ];
    if successor_nested {
        expected.push(("successor-generation", ExpectedNodeType::Directory));
    }
    require_closed_inventory(transaction, &expected)?;
    require_exact_file(
        transaction,
        "restore-pending.index",
        publication.pending_index().as_bytes(),
        RESTORE_PENDING_INDEX_LEN,
    )?;
    require_exact_file(
        transaction,
        "restore-manifest.bin",
        publication.manifest().as_bytes(),
        RESTORE_MANIFEST_LEN,
    )?;
    let source =
        transaction.open_child_directory(ValidatedComponent::registered("source-backup")?)?;
    verify_source_backup(&source, publication.source(), publication.limits())?;
    if successor_nested {
        let successor = transaction
            .open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
        verify_successor_generation(&successor, publication)?;
    }
    let activation =
        transaction.open_child_directory(ValidatedComponent::registered("activation")?)?;
    if active_nested {
        require_closed_inventory(
            &activation,
            &[("active-generation.bin", ExpectedNodeType::RegularFile)],
        )?;
        require_exact_file(
            &activation,
            "active-generation.bin",
            publication.active().as_bytes(),
            ACTIVE_VAULT_GENERATION_LEN,
        )?;
    } else {
        require_closed_inventory(&activation, &[])?;
    }
    activation.revalidate()?;
    transaction.revalidate()
}

#[cfg(any(test, feature = "evidence-only"))]
fn verify_final_activated_state(
    target_root: &RetainedDirectory,
    retained_generation: &RetainedDirectory,
    publication: &impl RestorePublicationViewV1,
) -> Result<(), LinuxCapabilityError> {
    let structural = UnauthenticatedVaultGenerationCoreV1::parse_structural(
        publication.successor_core().as_bytes(),
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let generation_name =
        ValidatedComponent::registered(&canonical_generation_directory_name(&structural))?;
    let reopened = target_root.open_child_directory(generation_name)?;
    retained_generation
        .identity
        .require_same(&reopened.identity)?;
    verify_successor_generation(&reopened, publication)?;
    require_live_active(
        target_root,
        publication.successor_core(),
        publication.active(),
    )?;

    let terminal_map = publication
        .terminal_union()
        .iter()
        .map(|record| (*record.identity().as_bytes(), record.result().clone()))
        .collect::<BTreeMap<_, _>>();
    let journal = publication
        .journal_entries()
        .iter()
        .map(|entry| entry.as_bytes().to_vec())
        .collect::<Vec<_>>();
    authenticate_composite_journal(&journal, &terminal_map)?.verify_pending_activation_anchor(
        publication.successor_core(),
        publication.active(),
        publication.pending_index(),
    )?;
    target_root.revalidate()?;
    retained_generation.revalidate()
}

#[cfg(any(test, feature = "evidence-only"))]
fn verify_source_backup(
    source_backup: &RetainedDirectory,
    source: &SelectedBackupMaterialV1,
    limits: BackupPolicyLimitsV1,
) -> Result<(), LinuxCapabilityError> {
    require_exact_backup_inventory(source_backup)?;
    require_exact_file(
        source_backup,
        "backup-master-key.envelope",
        source.master_envelope().as_bytes(),
        MASTER_ENVELOPE_LEN,
    )?;
    require_exact_file(
        source_backup,
        "backup-manifest.object",
        source.manifest_envelope().as_bytes(),
        MANIFEST_ENVELOPE_LEN,
    )?;
    require_exact_file(
        source_backup,
        "backup-bundle.digest",
        source.bundle().bundle_digest(),
        32,
    )?;
    if read_hash_authenticated_journal(source_backup)? != source.journal_entries()
        || read_authenticated_record_set(source_backup, limits)?.as_bytes()
            != source.record_set().as_bytes()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    source_backup.revalidate()
}

#[cfg(any(test, feature = "evidence-only"))]
fn verify_successor_generation(
    successor: &RetainedDirectory,
    publication: &impl RestorePublicationViewV1,
) -> Result<(), LinuxCapabilityError> {
    require_closed_inventory(
        successor,
        &[
            ("generation-core.bin", ExpectedNodeType::RegularFile),
            ("master-key.envelope", ExpectedNodeType::RegularFile),
            ("journal", ExpectedNodeType::Directory),
            ("tombstones", ExpectedNodeType::Directory),
        ],
    )?;
    require_exact_file(
        successor,
        "generation-core.bin",
        publication.successor_core().as_bytes(),
        VAULT_GENERATION_CORE_LEN,
    )?;
    require_exact_file(
        successor,
        "master-key.envelope",
        publication.successor_master_envelope().as_bytes(),
        MASTER_ENVELOPE_LEN,
    )?;
    let parsed_storage_ids =
        storage_ids_from_master_envelope(publication.successor_master_envelope())?;
    if parsed_storage_ids != publication.successor_storage_ids()
        || parsed_storage_ids.contract_wallet_id()
            != &publication.successor_core().as_bytes()[10..42]
        || parsed_storage_ids.vault_id().as_slice() != publication.successor_core().vault_id()
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    let journal = successor.open_child_directory(ValidatedComponent::registered("journal")?)?;
    let mut expected_journal = BTreeMap::new();
    for entry in publication.journal_entries() {
        let structural = UnauthenticatedJournalEntryV1::parse_structural(entry.as_bytes())
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let name = canonical_journal_filename(structural.envelope());
        if expected_journal
            .insert(name, entry.as_bytes().to_vec())
            .is_some()
        {
            return Err(LinuxCapabilityError::InvalidObject);
        }
    }
    if expected_journal.len() != publication.journal_entries().len() {
        return Err(LinuxCapabilityError::InvalidObject);
    }
    let mut found_journal = BTreeMap::new();
    journal.scan_lexicographic(|name, identity| {
        if identity.node_type != ExpectedNodeType::RegularFile {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let bytes = journal.read_bounded_file(
            &ValidatedComponent::registered(name)?,
            JOURNAL_ENTRY_MAX_LEN,
        )?;
        let structural = UnauthenticatedJournalEntryV1::parse_structural(&bytes)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        if canonical_journal_filename(structural.envelope()) != name
            || found_journal.insert(name.to_owned(), bytes).is_some()
        {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        Ok(())
    })?;
    if found_journal != expected_journal {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let epoch_matches = publication
        .journal_entries()
        .iter()
        .filter(|entry| {
            entry.payload().kind() == JournalEntryKindV1::EpochAdvance
                && entry.payload().as_bytes() == publication.epoch_advance().as_bytes()
        })
        .count();
    if epoch_matches != 1 {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    journal.revalidate()?;

    let tombstones =
        successor.open_child_directory(ValidatedComponent::registered("tombstones")?)?;
    let expected_tombstones = publication
        .successor_terminals()
        .envelopes()
        .iter()
        .map(|(identity, envelope)| {
            (
                format!("{}.tombstone", encode_lower_hex(identity)),
                envelope.as_bytes().to_vec(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expected_names = expected_tombstones.keys().cloned().collect::<BTreeSet<_>>();
    let mut found_names = BTreeSet::new();
    tombstones.scan_lexicographic(|name, identity| {
        if identity.node_type != ExpectedNodeType::RegularFile
            || !found_names.insert(name.to_owned())
        {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let expected = expected_tombstones
            .get(name)
            .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
        let found =
            tombstones.read_bounded_file(&ValidatedComponent::registered(name)?, expected.len())?;
        if &found != expected {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        Ok(())
    })?;
    if found_names != expected_names {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    let (authenticated_records, authenticated_envelopes, authenticated_terminals) =
        authenticate_successor_tombstones(
            successor,
            publication.successor_storage_ids(),
            publication.successor_master_key(),
        )?;
    if authenticated_records.as_bytes() != publication.successor_terminals().record_set().as_bytes()
        || authenticated_envelopes.len() != publication.successor_terminals().envelopes().len()
        || authenticated_terminals.len() != publication.successor_terminals().envelopes().len()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    tombstones.revalidate()?;
    successor.revalidate()
}

fn require_closed_inventory(
    directory: &RetainedDirectory,
    expected: &[(&str, ExpectedNodeType)],
) -> Result<(), LinuxCapabilityError> {
    let expected = expected.iter().copied().collect::<BTreeMap<_, _>>();
    let mut found = BTreeMap::new();
    directory.scan_independent(|name, identity| {
        if found.insert(name.to_owned(), identity.node_type).is_some() {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        Ok(())
    })?;
    if found.len() != expected.len()
        || found
            .iter()
            .any(|(name, node_type)| expected.get(name.as_str()) != Some(node_type))
    {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    directory.revalidate()
}

fn require_exact_file(
    directory: &RetainedDirectory,
    name: &str,
    expected: &[u8],
    maximum: usize,
) -> Result<(), LinuxCapabilityError> {
    let found = directory.read_bounded_file(&ValidatedComponent::registered(name)?, maximum)?;
    if found == expected {
        Ok(())
    } else {
        Err(LinuxCapabilityError::ExactBytesMismatch)
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Deterministic, mutation-free preparation for a restore-only new device.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct NewDeviceRestorePreparationV1 {
    source: SelectedBackupMaterialV1,
    successor_epoch: u64,
    terminal_union: Vec<RestoreRecordPayloadV1>,
    budget_carries: Vec<BudgetChargeV1>,
    permit_carries: Vec<PermitRetirementV1>,
}

#[cfg(any(test, feature = "evidence-only"))]
impl NewDeviceRestorePreparationV1 {
    pub(super) fn new(source: SelectedBackupMaterialV1) -> Result<Self, LinuxCapabilityError> {
        let successor_epoch = source
            .manifest
            .source_epoch()
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let terminal_union = canonical_new_device_terminal_union(source.record_set())?;
        let source_lifetime =
            AuthenticatedLifetimeEvidenceV1::from_journal(source.composite_journal())?;
        let (budget_carries, permit_carries) = source_lifetime.into_sorted();
        Ok(Self {
            source,
            successor_epoch,
            terminal_union,
            budget_carries,
            permit_carries,
        })
    }

    pub(super) const fn source(&self) -> &SelectedBackupMaterialV1 {
        &self.source
    }

    pub(super) const fn successor_epoch(&self) -> u64 {
        self.successor_epoch
    }

    pub(super) const fn successor_generation(&self) -> u64 {
        1
    }

    pub(super) fn terminal_union(&self) -> &[RestoreRecordPayloadV1] {
        &self.terminal_union
    }

    pub(super) fn budget_carries(&self) -> &[BudgetChargeV1] {
        &self.budget_carries
    }

    pub(super) fn permit_carries(&self) -> &[PermitRetirementV1] {
        &self.permit_carries
    }
}

/// A newly created restore-only root whose lock remains continuously held.
///
/// This authority is minted only after the source backup is fully authenticated
/// and the three exact root records have been durably written and reopened.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct InitializedNewDeviceRestoreRootV1 {
    root: RetainedDirectory,
    retained_lock: RetainedExclusiveLock,
    root_identity: StoreRootIdentityV1,
    restore_only_root: RestoreOnlyRootV1,
}

#[cfg(any(test, feature = "evidence-only"))]
impl InitializedNewDeviceRestoreRootV1 {
    pub(super) const fn root(&self) -> &RetainedDirectory {
        &self.root
    }

    pub(super) const fn retained_lock(&self) -> &RetainedExclusiveLock {
        &self.retained_lock
    }

    pub(super) const fn root_identity(&self) -> &StoreRootIdentityV1 {
        &self.root_identity
    }

    pub(super) const fn restore_only_root(&self) -> &RestoreOnlyRootV1 {
        &self.restore_only_root
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        RetainedDirectory,
        RetainedExclusiveLock,
        StoreRootIdentityV1,
        RestoreOnlyRootV1,
    ) {
        (
            self.root,
            self.retained_lock,
            self.root_identity,
            self.restore_only_root,
        )
    }
}

/// Creates the signed NAR-P1-002 restore-only root without adopting an
/// existing directory or accepting caller-supplied identity bytes.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn initialize_new_device_restore_only_root(
    destination_parent: Arc<Dir>,
    destination_name: &str,
    source: SelectedBackupMaterialV1,
) -> Result<
    (
        InitializedNewDeviceRestoreRootV1,
        NewDeviceRestorePreparationV1,
    ),
    LinuxCapabilityError,
> {
    source.revalidate_source_authority()?;
    let preparation = NewDeviceRestorePreparationV1::new(source)?;
    let contract_wallet_id = *preparation.source().storage_ids().contract_wallet_id();
    let store_root_id = random_nonzero::<32>()?;
    let lock_instance_id = random_nonzero::<16>()?;
    let restore_initialization_id = random_nonzero::<16>()?;
    let root_identity =
        StoreRootIdentityV1::new(contract_wallet_id, store_root_id, lock_instance_id)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let lock_identity = StoreLockIdentityV1::from_root(&root_identity)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let restore_only_root = RestoreOnlyRootV1::new(
        contract_wallet_id,
        store_root_id,
        lock_instance_id,
        *preparation.source().bundle().bundle_digest(),
        restore_initialization_id,
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;

    let root = RetainedDirectory::create_under(
        destination_parent,
        ValidatedComponent::operator_selected_root(destination_name)?,
    )?;
    root.create_immutable_file(
        &ValidatedComponent::registered("store-root-identity.bin")?,
        root_identity.as_bytes(),
    )?;
    root.create_immutable_file(
        &ValidatedComponent::registered("store-lock-identity.bin")?,
        lock_identity.as_bytes(),
    )?;
    root.create_immutable_file(
        &ValidatedComponent::registered("restore-only-root.bin")?,
        restore_only_root.as_bytes(),
    )?;
    root.sync()?;
    let retained_lock =
        root.acquire_lock(&ValidatedComponent::registered("store-lock-identity.bin")?)?;
    retained_lock.revalidate()?;
    require_restore_only_root_inventory(&root)?;
    let reopened_root = StoreRootIdentityV1::from_bytes(&root.read_bounded_file(
        &ValidatedComponent::registered("store-root-identity.bin")?,
        STORE_IDENTITY_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let reopened_lock = StoreLockIdentityV1::from_bytes_with_root(
        &root.read_bounded_file(
            &ValidatedComponent::registered("store-lock-identity.bin")?,
            STORE_IDENTITY_LEN,
        )?,
        &reopened_root,
    )
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    let reopened_marker = RestoreOnlyRootV1::from_bytes(&root.read_bounded_file(
        &ValidatedComponent::registered("restore-only-root.bin")?,
        crate::RESTORE_ONLY_ROOT_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    if reopened_root.as_bytes() != root_identity.as_bytes()
        || reopened_lock.as_bytes() != lock_identity.as_bytes()
        || reopened_marker.as_bytes() != restore_only_root.as_bytes()
        || reopened_marker.contract_wallet_id() != reopened_root.contract_wallet_id()
        || reopened_marker.store_root_id() != reopened_root.store_root_id()
        || reopened_marker.lock_instance_id() != reopened_root.lock_instance_id()
        || reopened_marker.source_backup_bundle_digest()
            != preparation.source().bundle().bundle_digest()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    preparation.source().revalidate_source_authority()?;
    root.revalidate()?;
    retained_lock.revalidate()?;
    Ok((
        InitializedNewDeviceRestoreRootV1 {
            root,
            retained_lock,
            root_identity,
            restore_only_root,
        },
        preparation,
    ))
}

#[cfg(any(test, feature = "evidence-only"))]
fn require_restore_only_root_inventory(
    root: &RetainedDirectory,
) -> Result<(), LinuxCapabilityError> {
    let expected = BTreeMap::from([
        (
            "restore-only-root.bin".to_owned(),
            ExpectedNodeType::RegularFile,
        ),
        (
            "store-lock-identity.bin".to_owned(),
            ExpectedNodeType::RegularFile,
        ),
        (
            "store-root-identity.bin".to_owned(),
            ExpectedNodeType::RegularFile,
        ),
    ]);
    let mut found = BTreeMap::new();
    root.scan_independent(|name, identity| {
        if expected.get(name) != Some(&identity.node_type)
            || found.insert(name.to_owned(), identity.node_type).is_some()
        {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        Ok(())
    })?;
    if found == expected {
        root.revalidate()
    } else {
        Err(LinuxCapabilityError::InvalidDirectoryEntry)
    }
}

/// Collision-only lifetime evidence derived exclusively from an already
/// authenticated complete composite journal.
#[cfg(any(test, feature = "evidence-only"))]
struct AuthenticatedLifetimeEvidenceV1 {
    charges: BTreeMap<[u8; 32], AuthenticatedChargeOccurrenceV1>,
    request_origins: BTreeMap<[u8; 32], [u8; 32]>,
    session_origins: BTreeMap<[u8; 32], [u8; 32]>,
    retirements: BTreeMap<[u8; 32], PermitRetirementV1>,
}

#[cfg(any(test, feature = "evidence-only"))]
struct AuthenticatedChargeOccurrenceV1 {
    charge: BudgetChargeV1,
    origin_entry: Vec<u8>,
}

#[cfg(any(test, feature = "evidence-only"))]
impl AuthenticatedLifetimeEvidenceV1 {
    fn from_journal(
        journal: &AuthenticatedCompositeJournalV1,
    ) -> Result<Self, LinuxCapabilityError> {
        let mut evidence = Self {
            charges: BTreeMap::new(),
            request_origins: BTreeMap::new(),
            session_origins: BTreeMap::new(),
            retirements: BTreeMap::new(),
        };
        for entry in journal.entries() {
            let structural = UnauthenticatedJournalEntryV1::parse_structural(entry.as_bytes())
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            match structural.payload() {
                UnauthenticatedJournalPayloadV1::Reserve(reserve) => {
                    evidence.insert_charge(reserve.charge(), entry)?;
                }
                UnauthenticatedJournalPayloadV1::BudgetCarryForward(charge) => {
                    evidence.insert_charge(charge, entry)?;
                }
                UnauthenticatedJournalPayloadV1::ExposureAuthorized(transition) => {
                    let spent = ExposureRecordV1::from_bytes(transition.successor().as_bytes())
                        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                    if spent.state() == ExposureStateV1::Spent {
                        let retirement = PermitRetirementV1::new(&spent, entry)
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                        evidence.insert_retirement(retirement)?;
                    }
                }
                UnauthenticatedJournalPayloadV1::PermitRetirementCarryForward(retirement) => {
                    evidence.insert_retirement(
                        PermitRetirementV1::from_bytes(retirement.as_bytes())
                            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
                    )?;
                }
                _ => {}
            }
        }
        Ok(evidence)
    }

    fn insert_charge(
        &mut self,
        charge: &BudgetChargeV1,
        origin_entry: &JournalEntryV1,
    ) -> Result<(), LinuxCapabilityError> {
        let authority = charge.reservation_authority();
        let reservation = copy_32(authority.reservation_id())?;
        let request = copy_32(authority.request_lookup_id())?;
        let session = copy_32(authority.session_id())?;
        match self.charges.get(&reservation) {
            Some(existing)
                if existing.charge.as_bytes() == charge.as_bytes()
                    && existing.origin_entry.as_slice() == origin_entry.as_bytes() =>
            {
                return Ok(())
            }
            Some(_) => return Err(LinuxCapabilityError::ExactBytesMismatch),
            None => {}
        }
        if self
            .request_origins
            .get(&request)
            .is_some_and(|existing| existing != &reservation)
            || self
                .session_origins
                .get(&session)
                .is_some_and(|existing| existing != &reservation)
        {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        self.request_origins.insert(request, reservation);
        self.session_origins.insert(session, reservation);
        self.charges.insert(
            reservation,
            AuthenticatedChargeOccurrenceV1 {
                charge: charge.clone(),
                origin_entry: origin_entry.as_bytes().to_vec(),
            },
        );
        Ok(())
    }

    fn insert_retirement(
        &mut self,
        retirement: PermitRetirementV1,
    ) -> Result<(), LinuxCapabilityError> {
        let permit = copy_32(retirement.permit_id().as_bytes())?;
        self.insert_retirement_with_verified_permit(permit, retirement)
    }

    fn insert_retirement_with_verified_permit(
        &mut self,
        permit: [u8; 32],
        retirement: PermitRetirementV1,
    ) -> Result<(), LinuxCapabilityError> {
        match self.retirements.get(&permit) {
            Some(existing) if existing.as_bytes() == retirement.as_bytes() => Ok(()),
            Some(_) => Err(LinuxCapabilityError::ExactBytesMismatch),
            None => {
                self.retirements.insert(permit, retirement);
                Ok(())
            }
        }
    }

    fn carries_absent_from(
        self,
        target: &Self,
    ) -> Result<(Vec<BudgetChargeV1>, Vec<PermitRetirementV1>), LinuxCapabilityError> {
        let mut charges = Vec::new();
        for (reservation, occurrence) in self.charges {
            if let Some(existing) = target.charges.get(&reservation) {
                if existing.charge.as_bytes() != occurrence.charge.as_bytes()
                    || existing.origin_entry != occurrence.origin_entry
                {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                continue;
            }
            let charge = occurrence.charge;
            let authority = charge.reservation_authority();
            let request = copy_32(authority.request_lookup_id())?;
            let session = copy_32(authority.session_id())?;
            if target.request_origins.contains_key(&request)
                || target.session_origins.contains_key(&session)
            {
                return Err(LinuxCapabilityError::ExactBytesMismatch);
            }
            charges.push(charge);
        }
        let mut retirements = Vec::new();
        for (permit, retirement) in self.retirements {
            if let Some(existing) = target.retirements.get(&permit) {
                if existing.as_bytes() != retirement.as_bytes() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                continue;
            }
            retirements.push(retirement);
        }
        Ok((charges, retirements))
    }

    fn into_sorted(self) -> (Vec<BudgetChargeV1>, Vec<PermitRetirementV1>) {
        (
            self.charges
                .into_values()
                .map(|occurrence| occurrence.charge)
                .collect(),
            self.retirements.into_values().collect(),
        )
    }
}

/// Complete authenticated records grouped by their exact nonce identity.
///
/// This is projection material only. It grants no signing, export, resend, or
/// restore-publication authority. Every owned record is reconstructed through
/// its authenticated canonical constructor even though the enclosing record
/// set was already authenticated by the selected-backup loader.
#[derive(Default)]
struct AuthenticatedRestoreProjectionV1 {
    identities: BTreeMap<[u8; 105], AuthenticatedIdentityRecordsV1>,
}

#[derive(Default)]
struct AuthenticatedIdentityRecordsV1 {
    identity: Option<NonceIdentityV1>,
    claim: Option<SessionClaimV1>,
    attempts: Vec<AttemptRecordV1>,
    exposures: Vec<ExposureRecordV1>,
    tombstone: Option<TombstoneV1>,
}

/// Complete semantically verified journal authority across every restore hop.
///
/// This value is operation-local and non-serializable. It exposes only the
/// verified canonical entries and the read-only collision authority needed by
/// the retained Store before a fresh reservation is persisted.
pub(super) struct AuthenticatedCompositeJournalV1 {
    composite: CompositeJournalV1,
}

impl AuthenticatedCompositeJournalV1 {
    pub(super) fn entries(&self) -> &[JournalEntryV1] {
        self.composite.entries()
    }

    pub(super) fn head(&self) -> Option<&JournalEntryV1> {
        self.composite.head()
    }

    pub(super) const fn lifetime_index(&self) -> &LifetimeCollisionIndexV1 {
        self.composite.lifetime_index()
    }

    pub(super) fn has_matching_anchor(
        &self,
        core: &VaultGenerationCoreV1,
    ) -> Result<bool, LinuxCapabilityError> {
        self.composite
            .matching_anchor(core)
            .map(|anchor| anchor.is_some())
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
    }

    pub(super) fn verify_current_generation_active_head(
        &self,
        core: &VaultGenerationCoreV1,
        active: &ActiveVaultGenerationV1,
    ) -> Result<(), LinuxCapabilityError> {
        self.composite
            .verify_current_generation_active_head(core, active)
            .map(|_| ())
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
    }

    pub(super) fn verify_pending_activation_anchor(
        &self,
        core: &VaultGenerationCoreV1,
        active: &ActiveVaultGenerationV1,
        pending: &RestorePendingIndexV1,
    ) -> Result<(), LinuxCapabilityError> {
        self.composite
            .verify_pending_activation_anchor(core, active, pending)
            .map(|_| ())
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
    }
}

/// Derives the only canonical backup-record projection from an authenticated
/// composite journal and its authenticated terminal records.
///
/// Both live backup creation and restore selection call this function.  A
/// separately well-formed record set therefore cannot become restore
/// authority unless its exact canonical bytes are the projection of the
/// semantically authenticated journal.
pub(super) fn canonical_record_set_from_journal(
    entries: &[JournalEntryV1],
    terminals: &BTreeMap<[u8; 105], TombstoneV1>,
    limits: &crate::canonical::RestoreRecordSetLimitsV1,
) -> Result<RestoreRecordSetV1, LinuxCapabilityError> {
    let projected = canonical_record_items_from_journal(entries, terminals)?;
    RestoreRecordSetV1::new(projected.into_values().collect(), limits)
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)
}

/// Replays the authenticated journal into canonical record items without
/// selecting any policy limit.  Startup recovery uses this exact projection
/// to compare an already bounded, authenticated live inventory before it may
/// mutate a crash prefix; backup/restore apply their signed limits only when
/// materializing the serializable record set.
pub(super) fn canonical_record_items_from_journal(
    entries: &[JournalEntryV1],
    terminals: &BTreeMap<[u8; 105], TombstoneV1>,
) -> Result<BTreeMap<[u8; RESTORE_RECORD_KEY_LEN], RestoreRecordItemV1>, LinuxCapabilityError> {
    let mut projected = BTreeMap::<[u8; RESTORE_RECORD_KEY_LEN], RestoreRecordItemV1>::new();
    let insert = |projected: &mut BTreeMap<[u8; RESTORE_RECORD_KEY_LEN], RestoreRecordItemV1>,
                  family: RestoreRecordFamilyV1,
                  bytes: &[u8]|
     -> Result<(), LinuxCapabilityError> {
        let item = RestoreRecordItemV1::from_record_bytes(family, bytes)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let mut key = [0_u8; RESTORE_RECORD_KEY_LEN];
        key.copy_from_slice(&item.as_bytes()[..RESTORE_RECORD_KEY_LEN]);
        match projected.get(&key) {
            Some(existing) if existing.as_bytes() == item.as_bytes() => Ok(()),
            Some(_) => Err(LinuxCapabilityError::ExactBytesMismatch),
            None => {
                projected.insert(key, item);
                Ok(())
            }
        }
    };

    for entry in entries {
        let structural = UnauthenticatedJournalEntryV1::parse_structural(entry.as_bytes())
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        match structural.payload() {
            UnauthenticatedJournalPayloadV1::Reserve(reserve) => {
                let claim = SessionClaimV1::from_bytes(reserve.claim().as_bytes())
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
                insert(
                    &mut projected,
                    RestoreRecordFamilyV1::SessionClaim,
                    claim.as_bytes(),
                )?;
            }
            UnauthenticatedJournalPayloadV1::ComputationAttempt(_) => {
                insert(
                    &mut projected,
                    RestoreRecordFamilyV1::Attempt,
                    structural.envelope().payload(),
                )?;
            }
            UnauthenticatedJournalPayloadV1::CommitmentPersisted(exposure)
            | UnauthenticatedJournalPayloadV1::RevealPersisted(exposure) => {
                insert(
                    &mut projected,
                    RestoreRecordFamilyV1::Exposure,
                    exposure.as_bytes(),
                )?;
            }
            UnauthenticatedJournalPayloadV1::ExposureAuthorized(transition) => {
                insert(
                    &mut projected,
                    RestoreRecordFamilyV1::Exposure,
                    transition.successor().as_bytes(),
                )?;
            }
            UnauthenticatedJournalPayloadV1::PartialConsumed(partial) => {
                insert(
                    &mut projected,
                    RestoreRecordFamilyV1::Exposure,
                    partial.partial().as_bytes(),
                )?;
                insert(
                    &mut projected,
                    RestoreRecordFamilyV1::Tombstone,
                    partial.tombstone().as_bytes(),
                )?;
            }
            UnauthenticatedJournalPayloadV1::AbortConsumed(tombstone)
            | UnauthenticatedJournalPayloadV1::Burned(tombstone) => {
                insert(
                    &mut projected,
                    RestoreRecordFamilyV1::Tombstone,
                    tombstone.as_bytes(),
                )?;
            }
            UnauthenticatedJournalPayloadV1::RestoreBegin(_) => {
                projected.clear();
            }
            UnauthenticatedJournalPayloadV1::RestoreRecord(record) => {
                let result = terminals
                    .get(record.identity().as_bytes())
                    .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
                if result.tombstone_digest() != record.result_tombstone_digest() {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                insert(
                    &mut projected,
                    RestoreRecordFamilyV1::Tombstone,
                    result.as_bytes(),
                )?;
            }
            UnauthenticatedJournalPayloadV1::RestoreComplete(_)
            | UnauthenticatedJournalPayloadV1::EpochAdvance(_)
            | UnauthenticatedJournalPayloadV1::BudgetCarryForward(_)
            | UnauthenticatedJournalPayloadV1::PermitRetirementCarryForward(_) => {}
        }
    }

    Ok(projected)
}

/// Freshly sealed successor terminal projection.
///
/// Each envelope is bound to the fresh successor vault key hierarchy. The
/// record set contains only canonical tombstone records and the set digest
/// byte-commits every randomized complete envelope.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct SuccessorTerminalMaterialV1 {
    record_set: RestoreRecordSetV1,
    envelopes: BTreeMap<[u8; 105], VaultObjectEnvelopeV1>,
    envelope_set_digest: [u8; 32],
}

#[cfg(any(test, feature = "evidence-only"))]
impl SuccessorTerminalMaterialV1 {
    pub(super) fn new(
        terminal_union: &[RestoreRecordPayloadV1],
        successor_ids: StorageIdsV1,
        successor_master_key: &VaultMasterKey,
        limits: BackupPolicyLimitsV1,
    ) -> Result<Self, LinuxCapabilityError> {
        let mut items = Vec::with_capacity(terminal_union.len());
        let mut envelopes = BTreeMap::new();
        let mut envelope_set_preimage = Vec::new();
        let count =
            u32::try_from(terminal_union.len()).map_err(|_| LinuxCapabilityError::InvalidObject)?;
        envelope_set_preimage.extend_from_slice(&count.to_le_bytes());
        let mut sorted = terminal_union.iter().collect::<Vec<_>>();
        sorted.sort_by(|left, right| left.identity().as_bytes().cmp(right.identity().as_bytes()));
        for record in sorted {
            if !matches!(
                record.action(),
                crate::RestoreActionV1::PreserveTerminal | crate::RestoreActionV1::Burn
            ) {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let tombstone = record.result();
            let identity = *tombstone.identity().as_bytes();
            let plaintext = TombstonePlaintextV1::from_bytes(tombstone.as_bytes())
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let metadata = TombstoneRecordMetadataV1::from_tombstone(&plaintext)
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let envelope =
                seal_tombstone_v1(successor_ids, successor_master_key, metadata, plaintext)
                    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let envelope_length = u32::try_from(envelope.as_bytes().len())
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            envelope_set_preimage.extend_from_slice(&identity);
            envelope_set_preimage.extend_from_slice(&envelope_length.to_le_bytes());
            envelope_set_preimage.extend_from_slice(&envelope.digest());
            if envelopes.insert(identity, envelope).is_some() {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            items.push(
                RestoreRecordItemV1::from_record_bytes(
                    RestoreRecordFamilyV1::Tombstone,
                    tombstone.as_bytes(),
                )
                .map_err(|_| LinuxCapabilityError::InvalidObject)?,
            );
        }
        let record_set = RestoreRecordSetV1::new(items, &limits.record_set_limits()?)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        if record_set.record_count() != count || envelopes.len() != terminal_union.len() {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        Ok(Self {
            record_set,
            envelopes,
            envelope_set_digest: authoritative_storage_hash_v1(
                StorageHashDomainV1::TombstoneEnvelopeSet,
                &envelope_set_preimage,
            ),
        })
    }

    pub(super) const fn record_set(&self) -> &RestoreRecordSetV1 {
        &self.record_set
    }

    pub(super) fn envelopes(&self) -> &BTreeMap<[u8; 105], VaultObjectEnvelopeV1> {
        &self.envelopes
    }

    pub(super) const fn envelope_set_digest(&self) -> &[u8; 32] {
        &self.envelope_set_digest
    }
}

impl AuthenticatedRestoreProjectionV1 {
    fn from_record_set(record_set: &RestoreRecordSetV1) -> Result<Self, LinuxCapabilityError> {
        let bytes = record_set.as_bytes();
        let mut projection = Self::default();
        let mut cursor = 4_usize;
        while cursor < bytes.len() {
            let prefix_end = cursor
                .checked_add(RESTORE_RECORD_ITEM_PREFIX_LEN)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
            if prefix_end > bytes.len() {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let record_length = usize::try_from(read_u32(
                &bytes[cursor + RESTORE_RECORD_KEY_LEN..prefix_end],
            )?)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let item_end = prefix_end
                .checked_add(record_length)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
            if item_end > bytes.len() {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let item =
                UnauthenticatedRestoreRecordItemV1::parse_structural(&bytes[cursor..item_end])
                    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let identity = *item.key().identity();
            let records = projection
                .identities
                .entry(*identity.as_bytes())
                .or_default();
            match records.identity {
                Some(existing) if existing.as_bytes() != identity.as_bytes() => {
                    return Err(LinuxCapabilityError::IdentityMismatch);
                }
                None => records.identity = Some(identity),
                Some(_) => {}
            }
            let record_bytes = &bytes[prefix_end..item_end];
            match item.key().family() {
                RestoreRecordFamilyV1::SessionClaim => {
                    let claim = SessionClaimV1::from_bytes(record_bytes)
                        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
                    if records.claim.replace(claim).is_some() {
                        return Err(LinuxCapabilityError::InvalidObject);
                    }
                }
                RestoreRecordFamilyV1::Attempt => {
                    let attempt = if record_bytes.len() == NONCE_DERIVATION_ATTEMPT_LEN {
                        NonceDerivationAttemptV1::from_bytes(record_bytes)
                            .map_err(|_| LinuxCapabilityError::InvalidObject)?
                            .attempt()
                            .clone()
                    } else {
                        AttemptRecordV1::from_bytes(record_bytes)
                            .map_err(|_| LinuxCapabilityError::InvalidObject)?
                    };
                    records.attempts.push(attempt);
                }
                RestoreRecordFamilyV1::Exposure => records.exposures.push(
                    ExposureRecordV1::from_bytes(record_bytes)
                        .map_err(|_| LinuxCapabilityError::InvalidObject)?,
                ),
                RestoreRecordFamilyV1::Tombstone => {
                    let tombstone = TombstoneV1::from_bytes(record_bytes)
                        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
                    if records.tombstone.replace(tombstone).is_some() {
                        return Err(LinuxCapabilityError::InvalidObject);
                    }
                }
            }
            cursor = item_end;
        }
        if cursor != bytes.len()
            || projection
                .identities
                .values()
                .any(|records| records.identity.is_none())
        {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        Ok(projection)
    }

    fn authenticated_terminals(
        &self,
    ) -> Result<BTreeMap<[u8; 105], TombstoneV1>, LinuxCapabilityError> {
        let mut terminals = BTreeMap::new();
        for records in self.identities.values() {
            if let Some(tombstone) = records.tombstone.as_ref() {
                let attempts = records.attempts.iter().collect::<Vec<_>>();
                let exposures = records.exposures.iter().collect::<Vec<_>>();
                if let Some(claim) = records.claim.as_ref() {
                    match tombstone.reason() {
                        crate::TerminalReasonV1::Consumed => {
                            let attempt = attempts
                                .iter()
                                .copied()
                                .find(|attempt| {
                                    attempt.attempt_digest()
                                        == tombstone.triggering_attempt_digest()
                                })
                                .ok_or(LinuxCapabilityError::InvalidObject)?;
                            let exposure = exposures
                                .iter()
                                .copied()
                                .find(|exposure| {
                                    exposure.record_digest() == tombstone.related_exposure_digest()
                                })
                                .ok_or(LinuxCapabilityError::InvalidObject)?;
                            let expected = TombstoneV1::new_consumed(
                                attempt,
                                exposure,
                                copy_32(tombstone.deleted_secret_envelope_digest())?,
                            )
                            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
                            if expected.as_bytes() != tombstone.as_bytes() {
                                return Err(LinuxCapabilityError::ExactBytesMismatch);
                            }
                        }
                        crate::TerminalReasonV1::AbortConsumed
                        | crate::TerminalReasonV1::Burned => {
                            let evidence = TerminalEvidenceV1::select_after_authenticated_terminal(
                                claim, &attempts, &exposures, tombstone,
                            )
                            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
                            let expected = match tombstone.reason() {
                                crate::TerminalReasonV1::AbortConsumed => {
                                    TombstoneV1::new_abort(&evidence)
                                }
                                crate::TerminalReasonV1::Burned => TombstoneV1::new_burn(&evidence),
                                crate::TerminalReasonV1::Consumed => {
                                    return Err(LinuxCapabilityError::InvalidObject)
                                }
                            }
                            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
                            if expected.as_bytes() != tombstone.as_bytes() {
                                return Err(LinuxCapabilityError::ExactBytesMismatch);
                            }
                        }
                    }
                }
                if terminals
                    .insert(*tombstone.identity().as_bytes(), tombstone.clone())
                    .is_some()
                {
                    return Err(LinuxCapabilityError::InvalidObject);
                }
            }
        }
        Ok(terminals)
    }
}

/// Selects one terminal result for every source identity on a new device.
///
/// A restore-only target has no independently authenticated active secret and
/// therefore cannot preserve a nonterminal source identity as live. Existing
/// source tombstones are retained byte for byte; every other authenticated
/// identity is deterministically burned from the complete source projection.
#[cfg(any(test, feature = "evidence-only"))]
fn canonical_new_device_terminal_union(
    source: &RestoreRecordSetV1,
) -> Result<Vec<RestoreRecordPayloadV1>, LinuxCapabilityError> {
    let source = AuthenticatedRestoreProjectionV1::from_record_set(source)?;
    let mut union = Vec::with_capacity(source.identities.len());
    for records in source.identities.values() {
        if let Some(tombstone) = records.tombstone.as_ref() {
            union.push(
                RestoreRecordPayloadV1::preserve_terminal(None, Some(tombstone))
                    .map_err(|_| LinuxCapabilityError::InvalidObject)?,
            );
            continue;
        }
        let identity = records
            .identity
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let attempts = records.attempts.iter().collect::<Vec<_>>();
        let exposures = records.exposures.iter().collect::<Vec<_>>();
        let evidence = TerminalEvidenceV1::select_restore_union(
            identity,
            None,
            &[],
            &[],
            records.claim.as_ref(),
            &attempts,
            &exposures,
            None,
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let tombstone =
            TombstoneV1::new_burn(&evidence).map_err(|_| LinuxCapabilityError::InvalidObject)?;
        union.push(
            RestoreRecordPayloadV1::burn(&tombstone)
                .map_err(|_| LinuxCapabilityError::InvalidObject)?,
        );
    }
    Ok(union)
}

#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn record_set_identities(
    records: &RestoreRecordSetV1,
) -> Result<Vec<NonceIdentityV1>, LinuxCapabilityError> {
    AuthenticatedRestoreProjectionV1::from_record_set(records)?
        .identities
        .into_values()
        .map(|records| records.identity)
        .collect::<Option<Vec<_>>>()
        .ok_or(LinuxCapabilityError::InvalidObject)
}

#[cfg(any(test, feature = "evidence-only"))]
fn canonical_existing_device_terminal_union(
    target: &RestoreRecordSetV1,
    source: &RestoreRecordSetV1,
    active_target_secrets: &BTreeMap<[u8; 105], ActiveSecretEvidenceV1>,
) -> Result<Vec<RestoreRecordPayloadV1>, LinuxCapabilityError> {
    let target = AuthenticatedRestoreProjectionV1::from_record_set(target)?;
    let source = AuthenticatedRestoreProjectionV1::from_record_set(source)?;
    if active_target_secrets
        .keys()
        .any(|identity| !target.identities.contains_key(identity))
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    let identities = target
        .identities
        .keys()
        .chain(source.identities.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut union = Vec::with_capacity(identities.len());
    for identity_key in identities {
        let target_records = target.identities.get(&identity_key);
        let source_records = source.identities.get(&identity_key);
        let target_terminal = target_records.and_then(|records| records.tombstone.as_ref());
        let source_terminal = source_records.and_then(|records| records.tombstone.as_ref());
        if target_terminal.is_some() || source_terminal.is_some() {
            union.push(
                RestoreRecordPayloadV1::preserve_terminal(target_terminal, source_terminal)
                    .map_err(|_| LinuxCapabilityError::InvalidObject)?,
            );
            continue;
        }
        let identity = target_records
            .and_then(|records| records.identity)
            .or_else(|| source_records.and_then(|records| records.identity))
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let target_attempts = target_records
            .map(|records| records.attempts.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let target_exposures = target_records
            .map(|records| records.exposures.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let source_attempts = source_records
            .map(|records| records.attempts.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let source_exposures = source_records
            .map(|records| records.exposures.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let evidence = TerminalEvidenceV1::select_restore_union(
            identity,
            target_records.and_then(|records| records.claim.as_ref()),
            &target_attempts,
            &target_exposures,
            source_records.and_then(|records| records.claim.as_ref()),
            &source_attempts,
            &source_exposures,
            active_target_secrets.get(&identity_key),
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let tombstone =
            TombstoneV1::new_burn(&evidence).map_err(|_| LinuxCapabilityError::InvalidObject)?;
        union.push(
            RestoreRecordPayloadV1::burn(&tombstone)
                .map_err(|_| LinuxCapabilityError::InvalidObject)?,
        );
    }
    Ok(union)
}

/// Reconstructs the complete normal/restore journal semantics from retained
/// bytes and authenticated terminal envelopes.
///
/// The terminal map must come from the active generation's exact sealed
/// tombstone inventory. Restore-record result digests can therefore be turned
/// back into authenticated typed values without trusting the journal payload
/// or a caller-supplied record. Carry-forward entries remain collision-only.
pub(super) fn authenticate_composite_journal(
    encoded_entries: &[Vec<u8>],
    terminals: &BTreeMap<[u8; 105], TombstoneV1>,
) -> Result<AuthenticatedCompositeJournalV1, LinuxCapabilityError> {
    let mut composite = CompositeJournalV1::new();
    let mut cursor = 0_usize;
    while cursor < encoded_entries.len() {
        let structural = UnauthenticatedJournalEntryV1::parse_structural(
            encoded_entries
                .get(cursor)
                .ok_or(LinuxCapabilityError::InvalidObject)?,
        )
        .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if !matches!(
            structural.payload(),
            UnauthenticatedJournalPayloadV1::RestoreBegin(_)
        ) {
            let retained_terminal = match structural.payload() {
                UnauthenticatedJournalPayloadV1::AbortConsumed(tombstone)
                | UnauthenticatedJournalPayloadV1::Burned(tombstone) => {
                    let retained = terminals
                        .get(tombstone.identity().as_bytes())
                        .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
                    if retained.as_bytes() != tombstone.as_bytes() {
                        return Err(LinuxCapabilityError::ExactBytesMismatch);
                    }
                    Some(retained)
                }
                UnauthenticatedJournalPayloadV1::RestoreRecord(_)
                | UnauthenticatedJournalPayloadV1::RestoreComplete(_)
                | UnauthenticatedJournalPayloadV1::EpochAdvance(_)
                | UnauthenticatedJournalPayloadV1::BudgetCarryForward(_)
                | UnauthenticatedJournalPayloadV1::PermitRetirementCarryForward(_) => {
                    return Err(LinuxCapabilityError::ExactBytesMismatch);
                }
                _ => None,
            };
            composite
                .verify_normal_entry(&encoded_entries[cursor], retained_terminal)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            cursor = cursor
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
            continue;
        }

        let start = cursor;
        let manifest = RestoreManifestV1::from_bytes(structural.envelope().payload())
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        cursor = cursor
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)?;

        let mut records = Vec::<RestoreRecordPayloadV1>::new();
        while cursor < encoded_entries.len() {
            let entry = UnauthenticatedJournalEntryV1::parse_structural(&encoded_entries[cursor])
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let UnauthenticatedJournalPayloadV1::RestoreRecord(record) = entry.payload() else {
                break;
            };
            let result = terminals
                .get(record.identity().as_bytes())
                .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
            let bytes = record.as_bytes();
            let current = (bytes[105] != 0).then_some(result);
            let source = (bytes[142] != 0).then_some(result);
            records.push(
                RestoreRecordPayloadV1::from_bytes(bytes, current, source, result)
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            );
            cursor = cursor
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
        }

        let mut charges = Vec::<BudgetChargeV1>::new();
        while cursor < encoded_entries.len() {
            let entry = UnauthenticatedJournalEntryV1::parse_structural(&encoded_entries[cursor])
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let UnauthenticatedJournalPayloadV1::BudgetCarryForward(charge) = entry.payload()
            else {
                break;
            };
            charges.push(charge.clone());
            cursor = cursor
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
        }

        let mut retirements = Vec::<PermitRetirementV1>::new();
        while cursor < encoded_entries.len() {
            let entry = UnauthenticatedJournalEntryV1::parse_structural(&encoded_entries[cursor])
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
            let UnauthenticatedJournalPayloadV1::PermitRetirementCarryForward(retirement) =
                entry.payload()
            else {
                break;
            };
            retirements.push(
                PermitRetirementV1::from_bytes(retirement.as_bytes())
                    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?,
            );
            cursor = cursor
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
        }

        let epoch_entry = encoded_entries
            .get(cursor)
            .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
        let epoch_structural = UnauthenticatedJournalEntryV1::parse_structural(epoch_entry)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        let UnauthenticatedJournalPayloadV1::EpochAdvance(epoch) = epoch_structural.payload()
        else {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        };
        let epoch_advance = EpochAdvancePayloadV1::from_bytes(epoch.as_bytes())
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        cursor = cursor
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)?;

        let complete_entry = encoded_entries
            .get(cursor)
            .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
        let complete_structural = UnauthenticatedJournalEntryV1::parse_structural(complete_entry)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if !matches!(
            complete_structural.payload(),
            UnauthenticatedJournalPayloadV1::RestoreComplete(_)
        ) {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        cursor = cursor
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)?;

        let encoded_tail = encoded_entries[start..cursor]
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        composite
            .verify_restore_segment(
                &encoded_tail,
                RestoreJournalInputsV1 {
                    manifest: &manifest,
                    records: &records,
                    budget_carry_forwards: &charges,
                    permit_carry_forwards: &retirements,
                    epoch_advance: &epoch_advance,
                },
            )
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    }
    if composite.entries().len() != encoded_entries.len() {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    Ok(AuthenticatedCompositeJournalV1 { composite })
}

#[cfg(any(test, feature = "evidence-only"))]
impl SelectedBackupMaterialV1 {
    pub(super) fn revalidate_source_authority(&self) -> Result<(), LinuxCapabilityError> {
        self.source_root.revalidate()?;
        self.selected.revalidate()?;
        let reopened = self
            .source_root
            .open_child_directory(self.selected.reopen.component.clone())?;
        self.selected.identity.require_same(&reopened.identity)?;
        let ids = storage_ids_from_master_envelope(&self.master_envelope)?;
        let metadata = manifest_metadata_from_envelope(&self.manifest_envelope, ids)?;
        let opened =
            open_backup_manifest_v1(&self.manifest_envelope, &self.backup_master_key, metadata)
                .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
        if ids != self.storage_ids
            || opened.as_bytes() != self.manifest.as_bytes()
            || self.bundle.backup_generation() != self.backup_generation
            || self.bundle.backup_id() != self.backup_id.as_slice()
        {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        self.source_root.revalidate()
    }

    pub(super) const fn storage_ids(&self) -> StorageIdsV1 {
        self.storage_ids
    }

    #[cfg(test)]
    pub(super) const fn backup_generation(&self) -> u64 {
        self.backup_generation
    }

    #[cfg(test)]
    pub(super) const fn backup_id(&self) -> &[u8; 32] {
        &self.backup_id
    }

    pub(super) const fn manifest(&self) -> &BackupManifestV1 {
        &self.manifest
    }

    pub(super) const fn bundle(&self) -> &BackupBundleV1 {
        &self.bundle
    }

    pub(super) fn journal_entries(&self) -> &[Vec<u8>] {
        &self.journal_entries
    }

    pub(super) const fn composite_journal(&self) -> &AuthenticatedCompositeJournalV1 {
        &self.composite_journal
    }

    pub(super) const fn record_set(&self) -> &RestoreRecordSetV1 {
        &self.record_set
    }

    #[cfg(test)]
    pub(super) const fn backup_master_key(&self) -> &VaultMasterKey {
        &self.backup_master_key
    }

    pub(super) const fn master_envelope(&self) -> &VaultMasterKeyEnvelopeV1 {
        &self.master_envelope
    }

    pub(super) const fn manifest_envelope(&self) -> &VaultObjectEnvelopeV1 {
        &self.manifest_envelope
    }
}

/// Authenticates an exact retained completed backup without mutating any root.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn authenticate_selected_backup(
    source_root: &RetainedDirectory,
    selected_name: &str,
    backup_passphrase: Passphrase,
    limits: BackupPolicyLimitsV1,
) -> Result<SelectedBackupMaterialV1, LinuxCapabilityError> {
    source_root.revalidate()?;
    let retained_source_root = source_root.retained_alias()?;
    let selected_component = ValidatedComponent::registered(selected_name)?;
    if selected_component.expected_type != ExpectedNodeType::Directory {
        return Err(LinuxCapabilityError::InvalidComponent);
    }
    let selected = retained_source_root.open_child_directory(selected_component)?;
    require_exact_backup_inventory(&selected)?;

    let master_envelope = VaultMasterKeyEnvelopeV1::from_bytes(&selected.read_bounded_file(
        &ValidatedComponent::registered("backup-master-key.envelope")?,
        MASTER_ENVELOPE_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let storage_ids = storage_ids_from_master_envelope(&master_envelope)?;
    let backup_master_key = open_master_key(&master_envelope, storage_ids, &backup_passphrase)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;

    let manifest_envelope = VaultObjectEnvelopeV1::from_bytes(&selected.read_bounded_file(
        &ValidatedComponent::registered("backup-manifest.object")?,
        MANIFEST_ENVELOPE_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let manifest_metadata = manifest_metadata_from_envelope(&manifest_envelope, storage_ids)?;
    let plaintext =
        open_backup_manifest_v1(&manifest_envelope, &backup_master_key, manifest_metadata)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let manifest = BackupManifestV1::from_bytes(plaintext.as_bytes())
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let structural_manifest =
        crate::UnauthenticatedBackupManifestV1::parse_structural(manifest.as_bytes())
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    if structural_manifest.manifest_digest() != manifest.manifest_digest()
        || canonical_backup_directory_name(&structural_manifest) != selected_name
        || manifest.contract_wallet_id() != storage_ids.contract_wallet_id()
        || manifest.source_vault_id() != storage_ids.vault_id()
    {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }

    let journal_entries = read_hash_authenticated_journal(&selected)?;
    let (journal_sequence, journal_head_digest) = journal_head(&journal_entries)?;
    if journal_sequence != manifest.source_journal_sequence()
        || manifest.source_journal_head_digest() != journal_head_digest
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let record_set = read_authenticated_record_set(&selected, limits)?;
    let record_set = RestoreRecordSetV1::from_bytes(
        record_set.as_bytes(),
        *record_set.record_set_digest(),
        &limits.record_set_limits()?,
    )
    .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    if record_set.record_count() != manifest.record_count()
        || record_set.record_set_digest() != manifest.record_set_digest()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let source_projection = AuthenticatedRestoreProjectionV1::from_record_set(&record_set)?;
    let source_terminals = source_projection.authenticated_terminals()?;
    let composite_journal = authenticate_composite_journal(&journal_entries, &source_terminals)?;
    let semantic_head_matches = match composite_journal.head() {
        None => journal_sequence == 0 && journal_head_digest == [0; 32],
        Some(head) => {
            head.sequence() == journal_sequence && head.entry_digest() == &journal_head_digest
        }
    };
    if composite_journal.entries().len() != journal_entries.len() || !semantic_head_matches {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    let canonical_projection = canonical_record_set_from_journal(
        composite_journal.entries(),
        &source_terminals,
        &limits.record_set_limits()?,
    )?;
    if canonical_projection.as_bytes() != record_set.as_bytes()
        || canonical_projection.record_set_digest() != record_set.record_set_digest()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }

    let master_digest = authoritative_storage_hash_v1(
        StorageHashDomainV1::MasterEnvelope,
        master_envelope.as_bytes(),
    );
    let bundle = BackupBundleV1::new(
        copy_32(manifest.backup_id())?,
        manifest.backup_generation(),
        master_digest,
        manifest_envelope.digest(),
        journal_sequence,
        journal_head_digest,
        record_set.record_count(),
        *record_set.record_set_digest(),
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let stored_bundle =
        selected.read_bounded_file(&ValidatedComponent::registered("backup-bundle.digest")?, 32)?;
    let authenticated_bundle =
        BackupBundleV1::from_preimage_and_digest(bundle.preimage(), copy_32(&stored_bundle)?)
            .map_err(|_| LinuxCapabilityError::ExactBytesMismatch)?;
    if authenticated_bundle.backup_id() != manifest.backup_id()
        || authenticated_bundle.backup_generation() != manifest.backup_generation()
        || authenticated_bundle.source_journal_sequence() != manifest.source_journal_sequence()
        || authenticated_bundle.source_journal_head_digest()
            != manifest.source_journal_head_digest()
        || authenticated_bundle.source_record_count() != manifest.record_count()
        || authenticated_bundle.source_record_set_digest() != manifest.record_set_digest()
        || authenticated_bundle.bundle_digest() != bundle.bundle_digest()
    {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }
    selected.revalidate()?;
    retained_source_root.revalidate()?;

    let material = SelectedBackupMaterialV1 {
        source_root: retained_source_root,
        selected,
        storage_ids,
        backup_generation: manifest.backup_generation(),
        backup_id: copy_32(manifest.backup_id())?,
        backup_master_key,
        master_envelope,
        manifest_envelope,
        manifest,
        bundle: authenticated_bundle,
        journal_entries,
        record_set,
        composite_journal,
    };
    material.revalidate_source_authority()?;
    Ok(material)
}

fn require_exact_backup_inventory(
    selected: &RetainedDirectory,
) -> Result<(), LinuxCapabilityError> {
    let expected = BTreeSet::from([
        "backup-master-key.envelope".to_owned(),
        "backup-manifest.object".to_owned(),
        "backup-bundle.digest".to_owned(),
        "journal".to_owned(),
        "records".to_owned(),
    ]);
    let mut found = BTreeSet::new();
    selected.scan_independent(|name, identity| {
        let expected_type = match name {
            "backup-master-key.envelope" | "backup-manifest.object" | "backup-bundle.digest" => {
                ExpectedNodeType::RegularFile
            }
            "journal" | "records" => ExpectedNodeType::Directory,
            _ => return Err(LinuxCapabilityError::InvalidDirectoryEntry),
        };
        if identity.node_type != expected_type || !found.insert(name.to_owned()) {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        Ok(())
    })?;
    if found == expected {
        Ok(())
    } else {
        Err(LinuxCapabilityError::InvalidDirectoryEntry)
    }
}

fn read_hash_authenticated_journal(
    selected: &RetainedDirectory,
) -> Result<Vec<Vec<u8>>, LinuxCapabilityError> {
    let journal = selected.open_child_directory(ValidatedComponent::registered("journal")?)?;
    let mut entries = Vec::new();
    let mut previous_sequence = 0_u64;
    let mut previous_digest = [0_u8; 32];
    journal.scan_lexicographic(|name, identity| {
        if identity.node_type != ExpectedNodeType::RegularFile {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let bytes = journal.read_bounded_file(
            &ValidatedComponent::registered(name)?,
            JOURNAL_ENTRY_MAX_LEN,
        )?;
        let structural = UnauthenticatedJournalEntryV1::parse_structural(&bytes)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let envelope = structural.envelope();
        let expected_sequence = previous_sequence
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let digest_offset = bytes
            .len()
            .checked_sub(32)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let entry_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::JournalEntry,
            &bytes[..digest_offset],
        );
        if envelope.sequence() != expected_sequence
            || envelope.predecessor_digest() != previous_digest
            || envelope.entry_digest() != entry_digest
            || canonical_journal_filename(envelope) != name
        {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        previous_sequence = expected_sequence;
        previous_digest = entry_digest;
        entries.push(bytes);
        Ok(())
    })?;
    journal.revalidate()?;
    Ok(entries)
}

#[cfg(any(test, feature = "evidence-only"))]
fn read_authenticated_record_set(
    selected: &RetainedDirectory,
    limits: BackupPolicyLimitsV1,
) -> Result<RestoreRecordSetV1, LinuxCapabilityError> {
    let records = selected.open_child_directory(ValidatedComponent::registered("records")?)?;
    let mut items = Vec::new();
    let mut encoded_bytes = 4_usize;
    records.scan_lexicographic(|identity_name, identity_node| {
        if identity_node.node_type != ExpectedNodeType::Directory || identity_name.len() != 210 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        let identity_bytes = decode_lower_hex::<105>(identity_name)?;
        let identity_directory =
            records.open_child_directory(ValidatedComponent::registered(identity_name)?)?;
        let mut file_count = 0_u64;
        identity_directory.scan_lexicographic(|file_name, file_node| {
            if file_node.node_type != ExpectedNodeType::RegularFile {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let tail = file_name
                .strip_suffix(".record")
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            if tail.len() != 100 {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            }
            let tail_bytes = decode_lower_hex::<50>(tail)?;
            let mut key_bytes = [0_u8; RESTORE_RECORD_KEY_LEN];
            key_bytes[..105].copy_from_slice(&identity_bytes);
            key_bytes[105..].copy_from_slice(&tail_bytes);
            let key = UnauthenticatedRestoreRecordKeyV1::parse_structural(&key_bytes)
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let record_bytes = identity_directory.read_bounded_file(
                &ValidatedComponent::registered(file_name)?,
                EXPOSURE_RECORD_MAX_LEN,
            )?;
            let item = RestoreRecordItemV1::from_record_bytes(key.family(), &record_bytes)
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            if &item.as_bytes()[..RESTORE_RECORD_KEY_LEN] != key.as_bytes()
                || canonical_restore_record_directory_name(&key) != identity_name
                || canonical_restore_record_filename(&key) != file_name
                || canonical_restore_record_relative_path(&key)
                    != format!("records/{identity_name}/{file_name}")
                || !limits.permits_record_accumulation(
                    items.len(),
                    encoded_bytes,
                    item.as_bytes().len(),
                )
            {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            encoded_bytes = encoded_bytes
                .checked_add(item.as_bytes().len())
                .ok_or(LinuxCapabilityError::InvalidObject)?;
            items.push(item);
            file_count = file_count
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
            Ok(())
        })?;
        if file_count == 0 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        identity_directory.revalidate()?;
        Ok(())
    })?;
    records.revalidate()?;
    RestoreRecordSetV1::new(items, &limits.record_set_limits()?)
        .map_err(|_| LinuxCapabilityError::InvalidObject)
}

fn storage_ids_from_master_envelope(
    envelope: &VaultMasterKeyEnvelopeV1,
) -> Result<StorageIdsV1, LinuxCapabilityError> {
    StorageIdsV1::new(
        copy_32(&envelope.as_bytes()[12..44])?,
        copy_32(&envelope.as_bytes()[44..76])?,
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)
}

#[cfg(any(test, feature = "evidence-only"))]
fn manifest_metadata_from_envelope(
    envelope: &VaultObjectEnvelopeV1,
    expected_ids: StorageIdsV1,
) -> Result<BackupManifestMetadataV1, LinuxCapabilityError> {
    let bytes = envelope.as_bytes();
    if bytes.len() != MANIFEST_ENVELOPE_LEN {
        return Err(LinuxCapabilityError::InvalidObject);
    }
    BackupManifestMetadataV1::new(
        expected_ids,
        read_u64(&bytes[78..86])?,
        read_u64(&bytes[152..160])?,
        copy_32(&bytes[160..192])?,
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)
}

#[cfg(any(test, feature = "evidence-only"))]
fn journal_head(entries: &[Vec<u8>]) -> Result<(u64, [u8; 32]), LinuxCapabilityError> {
    let Some(last) = entries.last() else {
        return Ok((0, [0; 32]));
    };
    let structural = UnauthenticatedJournalEntryV1::parse_structural(last)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    Ok((
        structural.envelope().sequence(),
        copy_32(structural.envelope().entry_digest())?,
    ))
}

fn copy_32(input: &[u8]) -> Result<[u8; 32], LinuxCapabilityError> {
    input
        .try_into()
        .map_err(|_| LinuxCapabilityError::InvalidObject)
}

#[cfg(any(test, feature = "evidence-only"))]
fn random_nonzero<const N: usize>() -> Result<[u8; N], LinuxCapabilityError> {
    loop {
        let mut bytes = [0_u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| LinuxCapabilityError::OperationFailed {
                operation: "restore-os-random",
                os_code: None,
            })?;
        if bytes != [0; N] {
            return Ok(bytes);
        }
    }
}

fn read_u32(input: &[u8]) -> Result<u32, LinuxCapabilityError> {
    Ok(u32::from_le_bytes(
        input
            .try_into()
            .map_err(|_| LinuxCapabilityError::InvalidObject)?,
    ))
}

fn read_u64(input: &[u8]) -> Result<u64, LinuxCapabilityError> {
    Ok(u64::from_le_bytes(
        input
            .try_into()
            .map_err(|_| LinuxCapabilityError::InvalidObject)?,
    ))
}

fn decode_lower_hex<const N: usize>(input: &str) -> Result<[u8; N], LinuxCapabilityError> {
    if input.len() != N.saturating_mul(2) {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    let mut output = [0_u8; N];
    for (index, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = lower_hex_nibble(chunk[0]).ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
        let low = lower_hex_nibble(chunk[1]).ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        JournalPayloadV1, PurposeV1, SigningPhaseV1, ATTEMPT_RECORD_LEN,
        NONCE_DERIVATION_ATTEMPT_LEN,
    };

    fn empty_lifetime() -> AuthenticatedLifetimeEvidenceV1 {
        AuthenticatedLifetimeEvidenceV1 {
            charges: BTreeMap::new(),
            request_origins: BTreeMap::new(),
            session_origins: BTreeMap::new(),
            retirements: BTreeMap::new(),
        }
    }

    fn reserve_entry(
        claim: &SessionClaimV1,
        charge: &BudgetChargeV1,
    ) -> Result<JournalEntryV1, crate::CanonicalCodecError> {
        JournalEntryV1::first(JournalPayloadV1::reserve(claim, charge)?)
    }

    fn replace_charge_request_lookup(
        charge: &BudgetChargeV1,
        request_byte: u8,
    ) -> Result<BudgetChargeV1, crate::CanonicalCodecError> {
        let mut bytes = charge.as_bytes().to_vec();
        let authority_len = bytes.len() - 66;
        let authority = &mut bytes[10..10 + authority_len];
        authority[203..235].fill(request_byte);
        let binding_len = usize::try_from(u32::from_le_bytes(
            authority[275..279]
                .try_into()
                .map_err(|_| crate::CanonicalCodecError::InvalidEncoding)?,
        ))
        .map_err(|_| crate::CanonicalCodecError::InvalidEncoding)?;
        let bound_offset = 279_usize
            .checked_add(binding_len)
            .ok_or(crate::CanonicalCodecError::ArithmeticOverflow)?;
        let bound = authoritative_storage_hash_v1(
            StorageHashDomainV1::ReservationBinding,
            &authority[10..bound_offset],
        );
        authority[bound_offset..bound_offset + 32].copy_from_slice(&bound);
        let authority_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::ReservationAuthority,
            &authority[..bound_offset + 40],
        );
        authority[bound_offset + 40..].copy_from_slice(&authority_digest);
        let charge_digest_offset = bytes.len() - 32;
        let charge_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::BudgetCharge,
            &bytes[..charge_digest_offset],
        );
        bytes[charge_digest_offset..].copy_from_slice(&charge_digest);
        BudgetChargeV1::from_bytes(&bytes)
    }

    fn change_charge_timestamp(
        charge: &BudgetChargeV1,
    ) -> Result<BudgetChargeV1, crate::CanonicalCodecError> {
        let mut bytes = charge.as_bytes().to_vec();
        let authority_len = bytes.len() - 66;
        let timestamp_offset = 10 + authority_len;
        let timestamp = u64::from_le_bytes(
            bytes[timestamp_offset..timestamp_offset + 8]
                .try_into()
                .map_err(|_| crate::CanonicalCodecError::InvalidEncoding)?,
        )
        .checked_add(1)
        .ok_or(crate::CanonicalCodecError::ArithmeticOverflow)?;
        bytes[timestamp_offset..timestamp_offset + 8].copy_from_slice(&timestamp.to_le_bytes());
        let digest_offset = bytes.len() - 32;
        let digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::BudgetCharge,
            &bytes[..digest_offset],
        );
        bytes[digest_offset..].copy_from_slice(&digest);
        BudgetChargeV1::from_bytes(&bytes)
    }

    fn retirement(
        purpose: PurposeV1,
        reservation_byte: u8,
        session_byte: u8,
        outbound_byte: u8,
    ) -> Result<PermitRetirementV1, crate::CanonicalCodecError> {
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(purpose, 1, reservation_byte, session_byte)?;
        let attempt = AttemptRecordV1::new(
            *claim.identity(),
            1,
            SigningPhaseV1::SigNonceCommit,
            [outbound_byte; 32],
        )?;
        let mut derivation_bytes = [0_u8; NONCE_DERIVATION_ATTEMPT_LEN];
        derivation_bytes[..ATTEMPT_RECORD_LEN].copy_from_slice(attempt.as_bytes());
        let derivation = NonceDerivationAttemptV1::from_bytes(&derivation_bytes)?;
        let persisted = ExposureRecordV1::new_persisted(&attempt, None, &[outbound_byte; 35])?;
        let authorized = ExposureRecordV1::new_successor(&persisted, None)?;
        let spent = ExposureRecordV1::new_successor(&authorized, None)?;
        let reserve = reserve_entry(&claim, &charge)?;
        let attempt_entry = JournalEntryV1::append(
            &reserve,
            JournalPayloadV1::nonce_derivation_attempt(&derivation),
        )?;
        let persisted_entry = JournalEntryV1::append(
            &attempt_entry,
            JournalPayloadV1::persisted(&attempt, None, &persisted)?,
        )?;
        let authorized_entry = JournalEntryV1::append(
            &persisted_entry,
            JournalPayloadV1::exposure_authorized(&persisted, &authorized, None)?,
        )?;
        let spent_entry = JournalEntryV1::append(
            &authorized_entry,
            JournalPayloadV1::exposure_authorized(&authorized, &spent, None)?,
        )?;
        PermitRetirementV1::new(&spent, &spent_entry)
    }

    #[test]
    fn lifetime_charge_exact_duplicate_requires_identical_origin_entry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x11, 0x21)?;
        let exact_origin = reserve_entry(&claim, &charge)?;
        let (independent_claim, independent_charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 1, 0xf1, 0xf2)?;
        let independent_origin = reserve_entry(&independent_claim, &independent_charge)?;
        let mut exact = empty_lifetime();
        exact.insert_charge(&charge, &exact_origin)?;
        exact.insert_charge(&charge, &exact_origin)?;
        assert_eq!(exact.charges.len(), 1);
        assert!(exact.insert_charge(&charge, &independent_origin).is_err());
        Ok(())
    }

    #[test]
    fn lifetime_charge_rejects_divergent_same_reservation() -> Result<(), Box<dyn std::error::Error>>
    {
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x12, 0x22)?;
        let divergent = change_charge_timestamp(&charge)?;
        let entry = reserve_entry(&claim, &charge)?;
        let divergent_entry = reserve_entry(&claim, &divergent)?;
        let mut evidence = empty_lifetime();
        evidence.insert_charge(&charge, &entry)?;
        assert!(evidence
            .insert_charge(&divergent, &divergent_entry)
            .is_err());
        Ok(())
    }

    #[test]
    fn lifetime_charge_rejects_same_request_from_different_reservation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (left_claim, left) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x13, 0x23)?;
        let (right_claim, right) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 1, 0x14, 0x24)?;
        assert_eq!(
            left.reservation_authority().request_lookup_id(),
            right.reservation_authority().request_lookup_id()
        );
        let mut evidence = empty_lifetime();
        evidence.insert_charge(&left, &reserve_entry(&left_claim, &left)?)?;
        assert!(evidence
            .insert_charge(&right, &reserve_entry(&right_claim, &right)?)
            .is_err());
        Ok(())
    }

    #[test]
    fn lifetime_charge_rejects_same_session_from_different_reservation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (left_claim, left) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x15, 0x25)?;
        let (_right_claim, right_template) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x16, 0x25)?;
        let right = replace_charge_request_lookup(&right_template, 0x99)?;
        let right_claim = SessionClaimV1::new(right.reservation_authority().nonce_identity()?)?;
        assert_eq!(
            left.reservation_authority().session_id(),
            right.reservation_authority().session_id()
        );
        assert_ne!(
            left.reservation_authority().request_lookup_id(),
            right.reservation_authority().request_lookup_id()
        );
        let mut evidence = empty_lifetime();
        evidence.insert_charge(&left, &reserve_entry(&left_claim, &left)?)?;
        assert!(evidence
            .insert_charge(&right, &reserve_entry(&right_claim, &right)?)
            .is_err());
        Ok(())
    }

    #[test]
    fn lifetime_retirement_rejects_same_permit_with_different_complete_origin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let left = retirement(PurposeV1::Funding, 0x31, 0x41, 0x51)?;
        let right = retirement(PurposeV1::Refund, 0x32, 0x42, 0x52)?;
        assert_ne!(left.as_bytes(), right.as_bytes());
        let forced_permit = copy_32(left.permit_id().as_bytes())?;
        let mut evidence = empty_lifetime();
        evidence.insert_retirement_with_verified_permit(
            forced_permit,
            PermitRetirementV1::from_bytes(left.as_bytes())?,
        )?;
        assert!(evidence
            .insert_retirement_with_verified_permit(forced_permit, right)
            .is_err());
        Ok(())
    }

    #[test]
    fn carries_reject_same_charge_with_independent_authenticated_origin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x61, 0x71)?;
        let exact_origin = reserve_entry(&claim, &charge)?;
        let (independent_claim, independent_charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 1, 0x62, 0x72)?;
        let independent_origin = reserve_entry(&independent_claim, &independent_charge)?;
        let mut source = empty_lifetime();
        let mut target = empty_lifetime();
        source.insert_charge(&charge, &exact_origin)?;
        target.insert_charge(&charge, &independent_origin)?;
        assert!(source.carries_absent_from(&target).is_err());
        Ok(())
    }

    #[test]
    fn carries_reject_divergent_charge_for_same_reservation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (claim, charge) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x63, 0x73)?;
        let divergent = change_charge_timestamp(&charge)?;
        let mut source = empty_lifetime();
        let mut target = empty_lifetime();
        source.insert_charge(&charge, &reserve_entry(&claim, &charge)?)?;
        target.insert_charge(&divergent, &reserve_entry(&claim, &divergent)?)?;
        assert!(source.carries_absent_from(&target).is_err());
        Ok(())
    }

    #[test]
    fn carries_reject_same_request_from_different_reservation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (left_claim, left) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x64, 0x74)?;
        let (right_claim, right) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Refund, 1, 0x65, 0x75)?;
        assert_eq!(
            left.reservation_authority().request_lookup_id(),
            right.reservation_authority().request_lookup_id()
        );
        let mut source = empty_lifetime();
        let mut target = empty_lifetime();
        source.insert_charge(&left, &reserve_entry(&left_claim, &left)?)?;
        target.insert_charge(&right, &reserve_entry(&right_claim, &right)?)?;
        assert!(source.carries_absent_from(&target).is_err());
        Ok(())
    }

    #[test]
    fn carries_reject_same_session_from_different_reservation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (left_claim, left) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x66, 0x76)?;
        let (_, right_template) =
            crate::canonical::reserve_records_with_ids(PurposeV1::Funding, 1, 0x67, 0x76)?;
        let right = replace_charge_request_lookup(&right_template, 0xa9)?;
        let right_claim = SessionClaimV1::new(right.reservation_authority().nonce_identity()?)?;
        let mut source = empty_lifetime();
        let mut target = empty_lifetime();
        source.insert_charge(&left, &reserve_entry(&left_claim, &left)?)?;
        target.insert_charge(&right, &reserve_entry(&right_claim, &right)?)?;
        assert!(source.carries_absent_from(&target).is_err());
        Ok(())
    }

    #[test]
    fn carries_reject_same_permit_with_different_retirement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let left = retirement(PurposeV1::Funding, 0x68, 0x78, 0x88)?;
        let right = retirement(PurposeV1::Refund, 0x69, 0x79, 0x89)?;
        let permit = copy_32(left.permit_id().as_bytes())?;
        let mut source = empty_lifetime();
        let mut target = empty_lifetime();
        source.insert_retirement_with_verified_permit(permit, left)?;
        target.insert_retirement_with_verified_permit(permit, right)?;
        assert!(source.carries_absent_from(&target).is_err());
        Ok(())
    }

    #[test]
    fn new_device_lifetime_carries_are_sorted_collision_only_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first = retirement(PurposeV1::Funding, 0x41, 0x51, 0x61)?;
        let second = retirement(PurposeV1::Refund, 0x42, 0x52, 0x62)?;
        let mut evidence = empty_lifetime();
        evidence.insert_retirement(second)?;
        evidence.insert_retirement(PermitRetirementV1::from_bytes(first.as_bytes())?)?;
        evidence.insert_retirement(PermitRetirementV1::from_bytes(first.as_bytes())?)?;
        let (charges, retirements) = evidence.into_sorted();
        assert!(charges.is_empty());
        assert_eq!(retirements.len(), 2);
        assert!(retirements
            .windows(2)
            .all(|pair| pair[0].permit_id().as_bytes() < pair[1].permit_id().as_bytes()));
        assert!(retirements
            .iter()
            .all(|record| record.as_bytes().len() == crate::PERMIT_RETIREMENT_LEN));
        Ok(())
    }
}

//! Canonical authenticated backup transaction for the retained Linux Store.
//!
//! The transaction is intentionally constructed only by `LiveStoreInventoryV1`.
//! It receives records that were authenticated through the live retained root
//! and lock, creates the complete staging tree, reopens every object, and only
//! then performs the same-root no-replace publication.

#[cfg(any(test, feature = "evidence-only"))]
use super::{inventory::VerifiedBackupInputsV1, map_errno};
#[cfg(any(test, feature = "evidence-only"))]
use super::{
    ExpectedNodeType, LinuxCapabilityError, NodeIdentity, RetainedDirectory, ValidatedComponent,
};
#[cfg(any(test, feature = "evidence-only"))]
use crate::canonical::{
    canonical_backup_directory_name, canonical_backup_staging_directory_name,
    canonical_restore_record_relative_path, BackupBundleV1, BackupManifestV1,
    RestoreRecordSetLimitsV1, RestoreRecordSetV1,
};
#[cfg(any(test, feature = "evidence-only"))]
use crate::canonical::{
    canonical_journal_filename, canonical_restore_record_directory_name,
    canonical_restore_record_filename, RestoreRecordFamilyV1, RestoreRecordItemV1,
    UnauthenticatedJournalEntryV1, UnauthenticatedRestoreRecordKeyV1, EXPOSURE_RECORD_MAX_LEN,
    JOURNAL_ENTRY_MAX_LEN, NONCE_DERIVATION_ATTEMPT_LEN, RESTORE_RECORD_KEY_LEN, SESSION_CLAIM_LEN,
    TOMBSTONE_LEN,
};
#[cfg(any(test, feature = "evidence-only"))]
use dom_scriptless_crypto::{authoritative_storage_hash_v1, StorageHashDomainV1};
#[cfg(test)]
use dom_scriptless_crypto::{open_backup_manifest_v1, open_master_key};
#[cfg(any(test, feature = "evidence-only"))]
use dom_scriptless_crypto::{
    seal_backup_manifest_v1, seal_master_key, BackupManifestMetadataV1, BackupManifestPlaintextV1,
    Passphrase, VaultMasterKey, VaultMasterKeyEnvelopeV1, VaultObjectEnvelopeV1,
};
#[cfg(any(test, feature = "evidence-only"))]
use rustix::fs::{fsync, renameat_with, AtFlags, RenameFlags};
#[cfg(any(test, feature = "evidence-only"))]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(any(test, feature = "evidence-only"))]
use std::os::fd::AsFd;

#[cfg(test)]
use std::{cell::RefCell, fs::OpenOptions, io::Write as _};

pub(super) const MASTER_ENVELOPE_LEN: usize = 182;
pub(super) const MANIFEST_ENVELOPE_LEN: usize = 470;

#[cfg(test)]
std::thread_local! {
    static BACKUP_CRASH_SCOPE: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[cfg(test)]
struct BackupCrashScopeGuardV1 {
    previous: Option<String>,
}

#[cfg(test)]
impl BackupCrashScopeGuardV1 {
    fn install(path: &str) -> Self {
        let previous = BACKUP_CRASH_SCOPE.with(|scope| scope.replace(Some(path.to_owned())));
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for BackupCrashScopeGuardV1 {
    fn drop(&mut self) {
        BACKUP_CRASH_SCOPE.with(|scope| {
            scope.replace(self.previous.take());
        });
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum BackupCrashCutV1 {
    BeforeDirectoryCreate,
    AfterDirectoryCreateBeforeParentSync,
    AfterDirectoryParentSync,
    AfterFileCreateBeforeWrite,
    DuringProperPrefixWrite,
    AfterFullWriteBeforeFileSync,
    AfterFileSyncBeforeParentSync,
    AfterFileParentSyncBeforeReopen,
    AfterFileReopen,
    BeforeDirectorySync,
    AfterDirectorySync,
    AfterStagingVerifyBeforeRename,
    AfterRenameBeforeRootSync,
    AfterRootSyncBeforePublishedReopen,
    AfterFinalVerifyBeforeReturn,
}

#[cfg(test)]
impl BackupCrashCutV1 {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "before-directory-create" => Self::BeforeDirectoryCreate,
            "after-directory-create-before-parent-sync" => {
                Self::AfterDirectoryCreateBeforeParentSync
            }
            "after-directory-parent-sync" => Self::AfterDirectoryParentSync,
            "after-file-create-before-write" => Self::AfterFileCreateBeforeWrite,
            "during-proper-prefix-write" => Self::DuringProperPrefixWrite,
            "after-full-write-before-file-sync" => Self::AfterFullWriteBeforeFileSync,
            "after-file-sync-before-parent-sync" => Self::AfterFileSyncBeforeParentSync,
            "after-file-parent-sync-before-reopen" => Self::AfterFileParentSyncBeforeReopen,
            "after-file-reopen" => Self::AfterFileReopen,
            "before-directory-sync" => Self::BeforeDirectorySync,
            "after-directory-sync" => Self::AfterDirectorySync,
            "after-staging-verify-before-rename" => Self::AfterStagingVerifyBeforeRename,
            "after-rename-before-root-sync" => Self::AfterRenameBeforeRootSync,
            "after-root-sync-before-published-reopen" => Self::AfterRootSyncBeforePublishedReopen,
            "after-final-verify-before-return" => Self::AfterFinalVerifyBeforeReturn,
            _ => return None,
        })
    }
}

#[cfg(test)]
pub(super) fn test_crash_hook(boundary: &str) {
    let Some(expected_cut) = std::env::var_os("DOM_G1B_BACKUP_CRASH_CUT") else {
        return;
    };
    let Some(expected_path) = std::env::var_os("DOM_G1B_BACKUP_CRASH_PATH") else {
        return;
    };
    let Ok(expected_cut) = expected_cut.into_string() else {
        return;
    };
    if BackupCrashCutV1::parse(&expected_cut).is_none() || expected_cut != boundary {
        return;
    }
    if !BACKUP_CRASH_SCOPE.with(|scope| scope.borrow().as_deref() == expected_path.to_str()) {
        return;
    }
    if let Some(marker) = std::env::var_os("DOM_G1B_BACKUP_CRASH_MARKER") {
        if let Ok(mut file) = OpenOptions::new().create_new(true).write(true).open(marker) {
            let _ = file.write_all(boundary.as_bytes());
            let _ = file.sync_all();
        }
    }
    std::process::abort();
}

#[cfg(test)]
pub(super) fn test_crash_cut_matches(boundary: &str) -> bool {
    std::env::var("DOM_G1B_BACKUP_CRASH_CUT").ok().as_deref() == Some(boundary)
        && std::env::var("DOM_G1B_BACKUP_CRASH_PATH")
            .ok()
            .is_some_and(|expected| {
                BACKUP_CRASH_SCOPE
                    .with(|scope| scope.borrow().as_deref() == Some(expected.as_str()))
            })
}

#[cfg(test)]
fn with_crash_scope<T>(path: &str, operation: impl FnOnce() -> T) -> T {
    let _scope = BackupCrashScopeGuardV1::install(path);
    operation()
}

#[cfg(all(not(test), feature = "evidence-only"))]
fn with_crash_scope<T>(_path: &str, operation: impl FnOnce() -> T) -> T {
    operation()
}

#[cfg(any(test, feature = "evidence-only"))]
fn sync_scoped(
    directory: &RetainedDirectory,
    logical_path: &str,
) -> Result<(), LinuxCapabilityError> {
    with_crash_scope(logical_path, || {
        #[cfg(test)]
        test_crash_hook("before-directory-sync");
        directory.sync()?;
        #[cfg(test)]
        test_crash_hook("after-directory-sync");
        Ok(())
    })
}

#[derive(Clone, Eq, PartialEq)]
#[cfg(any(test, feature = "evidence-only"))]
struct AuthenticatedBackupDescriptorV1 {
    node_identity: NodeIdentity,
    backup_generation: u64,
    backup_id: [u8; 32],
}

/// Exact authenticated root inventory and immutable backup history.
///
/// This is operation-local evidence only. It is never serialized and grants no
/// authority outside the retained root and lock held by `LiveStoreInventoryV1`.
#[derive(Clone, Eq, PartialEq)]
#[cfg(any(test, feature = "evidence-only"))]
pub(super) struct AuthenticatedBackupHistoryV1 {
    root_entries: BTreeMap<String, NodeIdentity>,
    backups: BTreeMap<String, AuthenticatedBackupDescriptorV1>,
}

#[cfg(any(test, feature = "evidence-only"))]
impl AuthenticatedBackupHistoryV1 {
    #[cfg(any(test, feature = "evidence-only"))]
    pub(super) fn next_generation(&self) -> Result<u64, LinuxCapabilityError> {
        self.backups
            .values()
            .map(|backup| backup.backup_generation)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)
    }

    #[cfg(any(test, feature = "evidence-only"))]
    pub(super) fn contains_backup_id(&self, candidate: &[u8; 32]) -> bool {
        self.backups
            .values()
            .any(|backup| &backup.backup_id == candidate)
    }

    pub(super) fn require_same(&self, other: &Self) -> Result<(), LinuxCapabilityError> {
        if self == other {
            Ok(())
        } else {
            Err(LinuxCapabilityError::IdentityMismatch)
        }
    }

    #[cfg(any(test, feature = "evidence-only"))]
    pub(super) fn require_exact_publication(
        &self,
        after: &Self,
        completed: &CompletedBackupV1,
    ) -> Result<(), LinuxCapabilityError> {
        let expected_name = format!(
            "backup-{:020}-{}",
            completed.backup_generation,
            hex_lower(&completed.backup_id)
        );
        if after.root_entries.len() != self.root_entries.len().saturating_add(1)
            || after.backups.len() != self.backups.len().saturating_add(1)
            || self
                .root_entries
                .iter()
                .any(|(name, identity)| after.root_entries.get(name) != Some(identity))
            || self
                .backups
                .iter()
                .any(|(name, descriptor)| after.backups.get(name) != Some(descriptor))
        {
            return Err(LinuxCapabilityError::IdentityMismatch);
        }
        let added = after
            .backups
            .get(&expected_name)
            .ok_or(LinuxCapabilityError::IdentityMismatch)?;
        if added.backup_generation != completed.backup_generation
            || added.backup_id != completed.backup_id
            || after.root_entries.get(&expected_name) != Some(&added.node_identity)
        {
            return Err(LinuxCapabilityError::IdentityMismatch);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn only_backup_name(&self) -> Result<&str, LinuxCapabilityError> {
        if self.backups.len() != 1 {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        self.backups
            .keys()
            .next()
            .map(String::as_str)
            .ok_or(LinuxCapabilityError::InvalidObject)
    }
}

/// Operator-adjudicated allocation bounds for one backup operation.
///
/// The signed format deliberately defines no numeric production default. The
/// caller must obtain these values from authenticated policy before invoking
/// the Store. Encoded backup bytes can never increase them.
#[derive(Clone, Copy)]
#[cfg(any(test, feature = "evidence-only"))]
pub struct BackupPolicyLimitsV1 {
    max_record_count: u32,
    max_record_set_bytes: usize,
}

#[cfg(any(test, feature = "evidence-only"))]
impl BackupPolicyLimitsV1 {
    /// Captures already authenticated limits without selecting defaults.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn new(
        max_record_count: u32,
        max_record_set_bytes: usize,
    ) -> Result<Self, crate::CanonicalCodecError> {
        if max_record_set_bytes < 4 {
            return Err(crate::CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            max_record_count,
            max_record_set_bytes,
        })
    }

    pub(super) fn record_set_limits(
        self,
    ) -> Result<RestoreRecordSetLimitsV1, LinuxCapabilityError> {
        RestoreRecordSetLimitsV1::new(self.max_record_count, self.max_record_set_bytes)
            .map_err(|_| LinuxCapabilityError::InvalidObject)
    }

    pub(super) fn permits_record_accumulation(
        self,
        current_count: usize,
        current_encoded_bytes: usize,
        next_item_bytes: usize,
    ) -> bool {
        let Some(next_count) = current_count.checked_add(1) else {
            return false;
        };
        let Some(next_encoded_bytes) = current_encoded_bytes.checked_add(next_item_bytes) else {
            return false;
        };
        u32::try_from(next_count).ok().is_some_and(|count| {
            count <= self.max_record_count && next_encoded_bytes <= self.max_record_set_bytes
        })
    }
}

/// Public non-authoritative descriptor of one immutable completed backup.
#[cfg(any(test, feature = "evidence-only"))]
pub struct CompletedBackupV1 {
    backup_generation: u64,
    backup_id: [u8; 32],
    bundle_digest: [u8; 32],
}

#[cfg(any(test, feature = "evidence-only"))]
impl CompletedBackupV1 {
    /// Returns the checked monotonic backup generation.
    pub const fn backup_generation(&self) -> u64 {
        self.backup_generation
    }

    /// Returns the fresh public backup identifier.
    pub const fn backup_id(&self) -> &[u8; 32] {
        &self.backup_id
    }

    /// Returns the digest of the complete immutable bundle commitments.
    pub const fn bundle_digest(&self) -> &[u8; 32] {
        &self.bundle_digest
    }
}

/// Retains the exact root inventory and structurally validates completed history.
///
/// Historical master/manifest cryptography is authenticated only when restore
/// selects a backup and supplies its passphrase. This operation nevertheless
/// rejects malformed structures and content/path key mismatches, while every
/// structurally valid historical name still reserves its generation and ID.
#[cfg(any(test, feature = "evidence-only"))]
pub(super) fn authenticate_completed_history(
    root: &RetainedDirectory,
) -> Result<AuthenticatedBackupHistoryV1, LinuxCapabilityError> {
    root.revalidate()?;
    let mut root_entries = BTreeMap::new();
    let mut backups = BTreeMap::new();
    let mut generations = BTreeSet::new();
    let mut backup_ids = BTreeSet::new();
    root.scan_independent(|name, identity| {
        if root_entries.insert(name.to_owned(), identity).is_some() {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        if name.starts_with(".backup-") {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        if !name.starts_with("backup-") {
            return Ok(());
        }
        if identity.node_type != ExpectedNodeType::Directory {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        let (generation, backup_id) = parse_completed_backup_name(name)?;
        let directory = root.open_child_directory(ValidatedComponent::registered(name)?)?;
        validate_historical_backup_structure(&directory)?;
        let descriptor = AuthenticatedBackupDescriptorV1 {
            node_identity: identity,
            backup_generation: generation,
            backup_id,
        };
        if !generations.insert(descriptor.backup_generation)
            || !backup_ids.insert(descriptor.backup_id)
            || backups.insert(name.to_owned(), descriptor).is_some()
        {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        Ok(())
    })?;
    root.revalidate()?;
    Ok(AuthenticatedBackupHistoryV1 {
        root_entries,
        backups,
    })
}

/// Reopens and cryptographically authenticates one completed backup against
/// the exact live Store projection used to create it.
///
/// This exists only for the process-death evidence harness. Restore owns the
/// production import path and must independently authenticate its selected
/// backup under the operator-supplied passphrase.
#[cfg(test)]
pub(super) fn authenticate_completed_backup_for_test(
    root: &RetainedDirectory,
    completed_name: &str,
    backup_passphrase: Passphrase,
    inputs: VerifiedBackupInputsV1,
) -> Result<CompletedBackupV1, LinuxCapabilityError> {
    let (backup_generation, backup_id) = parse_completed_backup_name(completed_name)?;
    let storage_ids = inputs.storage_ids();
    let source_epoch = inputs.source_epoch();
    let source_journal_sequence = inputs.source_journal_sequence();
    let source_journal_head_digest = inputs.source_journal_head_digest();
    let (journal_entries, record_set) = inputs.into_payloads();
    let completed = root.open_child_directory(ValidatedComponent::registered(completed_name)?)?;

    let master_envelope = VaultMasterKeyEnvelopeV1::from_bytes(&completed.read_bounded_file(
        &ValidatedComponent::registered("backup-master-key.envelope")?,
        MASTER_ENVELOPE_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let backup_master_key = open_master_key(&master_envelope, storage_ids, &backup_passphrase)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let expected_manifest = BackupManifestV1::new(
        *storage_ids.contract_wallet_id(),
        *storage_ids.vault_id(),
        backup_id,
        source_epoch,
        source_journal_sequence,
        source_journal_head_digest,
        record_set.record_count(),
        *record_set.record_set_digest(),
        backup_generation,
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let expected_plaintext = BackupManifestPlaintextV1::from_bytes(expected_manifest.as_bytes())
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let metadata = BackupManifestMetadataV1::from_manifest(&expected_plaintext)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let manifest_envelope = VaultObjectEnvelopeV1::from_bytes(&completed.read_bounded_file(
        &ValidatedComponent::registered("backup-manifest.object")?,
        MANIFEST_ENVELOPE_LEN,
    )?)
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let opened_manifest = open_backup_manifest_v1(&manifest_envelope, &backup_master_key, metadata)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    if opened_manifest.as_bytes() != expected_manifest.as_bytes() {
        return Err(LinuxCapabilityError::ExactBytesMismatch);
    }

    let master_digest = authoritative_storage_hash_v1(
        StorageHashDomainV1::MasterEnvelope,
        master_envelope.as_bytes(),
    );
    let bundle = BackupBundleV1::new(
        backup_id,
        backup_generation,
        master_digest,
        manifest_envelope.digest(),
        source_journal_sequence,
        source_journal_head_digest,
        record_set.record_count(),
        *record_set.record_set_digest(),
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    verify_complete_backup(
        &completed,
        "published-verification",
        &master_envelope,
        &manifest_envelope,
        bundle.bundle_digest(),
        &journal_entries,
        &record_set,
    )?;
    Ok(CompletedBackupV1 {
        backup_generation,
        backup_id,
        bundle_digest: *bundle.bundle_digest(),
    })
}

#[cfg(any(test, feature = "evidence-only"))]
fn validate_historical_backup_structure(
    directory: &RetainedDirectory,
) -> Result<(), LinuxCapabilityError> {
    let expected = BTreeSet::from([
        "backup-master-key.envelope",
        "backup-manifest.object",
        "backup-bundle.digest",
        "journal",
        "records",
    ]);
    require_exact_names(directory, &expected)?;
    require_exact_length(directory, "backup-master-key.envelope", MASTER_ENVELOPE_LEN)?;
    require_exact_length(directory, "backup-manifest.object", MANIFEST_ENVELOPE_LEN)?;
    require_exact_length(directory, "backup-bundle.digest", 32)?;
    let journal = directory.open_child_directory(ValidatedComponent::registered("journal")?)?;
    let mut previous_sequence = 0_u64;
    let mut previous_entry_digest = [0_u8; 32];
    journal.scan_lexicographic(|name, node| {
        if node.node_type != ExpectedNodeType::RegularFile || !valid_journal_name(name) {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        let sequence = name[..20]
            .parse::<u64>()
            .map_err(|_| LinuxCapabilityError::InvalidDirectoryEntry)?;
        let expected_sequence = previous_sequence
            .checked_add(1)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        if sequence != expected_sequence {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        previous_sequence = sequence;
        let bytes = journal.read_bounded_file(
            &ValidatedComponent::registered(name)?,
            JOURNAL_ENTRY_MAX_LEN,
        )?;
        let structural = UnauthenticatedJournalEntryV1::parse_structural(&bytes)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let envelope = structural.envelope();
        let digest_offset = bytes
            .len()
            .checked_sub(32)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let entry_digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::JournalEntry,
            &bytes[..digest_offset],
        );
        if envelope.predecessor_digest() != previous_entry_digest
            || envelope.entry_digest() != entry_digest
            || canonical_journal_filename(envelope) != name
        {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        previous_entry_digest = entry_digest;
        Ok(())
    })?;
    let records = directory.open_child_directory(ValidatedComponent::registered("records")?)?;
    records.scan_lexicographic(|identity_name, identity_node| {
        if identity_node.node_type != ExpectedNodeType::Directory || identity_name.len() != 210 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        let identity_bytes = decode_lower_hex::<105>(identity_name)?;
        let identity_directory =
            records.open_child_directory(ValidatedComponent::registered(identity_name)?)?;
        let mut file_count = 0_u64;
        identity_directory.scan_lexicographic(|file_name, file_node| {
            file_count = file_count
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidObject)?;
            if file_node.node_type != ExpectedNodeType::RegularFile
                || !file_name.ends_with(".record")
            {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            }
            let suffix = file_name
                .strip_suffix(".record")
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            if suffix.len() != 100 {
                return Err(LinuxCapabilityError::InvalidDirectoryEntry);
            }
            let tail = decode_lower_hex::<50>(suffix)?;
            let mut key_bytes = [0_u8; RESTORE_RECORD_KEY_LEN];
            key_bytes[..105].copy_from_slice(&identity_bytes);
            key_bytes[105..].copy_from_slice(&tail);
            let key = UnauthenticatedRestoreRecordKeyV1::parse_structural(&key_bytes)
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            let (minimum, maximum) = match key.family() {
                RestoreRecordFamilyV1::SessionClaim => (SESSION_CLAIM_LEN, SESSION_CLAIM_LEN),
                RestoreRecordFamilyV1::Attempt => {
                    if key.subtype_byte() == 1 {
                        (NONCE_DERIVATION_ATTEMPT_LEN, NONCE_DERIVATION_ATTEMPT_LEN)
                    } else {
                        (crate::ATTEMPT_RECORD_LEN, crate::ATTEMPT_RECORD_LEN)
                    }
                }
                RestoreRecordFamilyV1::Exposure => {
                    (crate::EXPOSURE_RECORD_MIN_LEN, EXPOSURE_RECORD_MAX_LEN)
                }
                RestoreRecordFamilyV1::Tombstone => (TOMBSTONE_LEN, TOMBSTONE_LEN),
            };
            let bytes = identity_directory
                .read_bounded_file(&ValidatedComponent::registered(file_name)?, maximum)?;
            if !(minimum..=maximum).contains(&bytes.len()) {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            let item = RestoreRecordItemV1::from_record_bytes(key.family(), &bytes)
                .map_err(|_| LinuxCapabilityError::InvalidObject)?;
            if &item.as_bytes()[..RESTORE_RECORD_KEY_LEN] != key.as_bytes() {
                return Err(LinuxCapabilityError::InvalidObject);
            }
            Ok(())
        })?;
        if file_count == 0 {
            return Err(LinuxCapabilityError::InvalidDirectoryEntry);
        }
        Ok(())
    })?;
    directory.revalidate()
}

#[cfg(any(test, feature = "evidence-only"))]
fn parse_completed_backup_name(name: &str) -> Result<(u64, [u8; 32]), LinuxCapabilityError> {
    let payload = name
        .strip_prefix("backup-")
        .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
    let (generation, backup_id) = payload
        .split_once('-')
        .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
    if generation.len() != 20 || !generation.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    let generation = generation
        .parse::<u64>()
        .map_err(|_| LinuxCapabilityError::InvalidDirectoryEntry)?;
    if generation == 0 {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    Ok((generation, decode_lower_hex::<32>(backup_id)?))
}

#[cfg(any(test, feature = "evidence-only"))]
fn valid_journal_name(name: &str) -> bool {
    name.len() == 93
        && name[..20].bytes().all(|byte| byte.is_ascii_digit())
        && &name[20..21] == "-"
        && name[21..85]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && &name[85..] == ".journal"
}

#[cfg(any(test, feature = "evidence-only"))]
fn require_exact_length(
    directory: &RetainedDirectory,
    name: &str,
    length: usize,
) -> Result<(), LinuxCapabilityError> {
    let bytes = directory.read_bounded_file(&ValidatedComponent::registered(name)?, length)?;
    if bytes.len() == length {
        Ok(())
    } else {
        Err(LinuxCapabilityError::InvalidObject)
    }
}

#[cfg(any(test, feature = "evidence-only"))]
fn decode_lower_hex<const N: usize>(input: &str) -> Result<[u8; N], LinuxCapabilityError> {
    if input.len() != N.saturating_mul(2)
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LinuxCapabilityError::InvalidDirectoryEntry);
    }
    let mut output = [0_u8; N];
    for (index, destination) in output.iter_mut().enumerate() {
        let offset = index.saturating_mul(2);
        let high = decode_hex_nibble(input.as_bytes()[offset])?;
        let low = decode_hex_nibble(input.as_bytes()[offset + 1])?;
        *destination = (high << 4) | low;
    }
    Ok(output)
}

#[cfg(any(test, feature = "evidence-only"))]
fn decode_hex_nibble(value: u8) -> Result<u8, LinuxCapabilityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(LinuxCapabilityError::InvalidDirectoryEntry),
    }
}

#[cfg(any(test, feature = "evidence-only"))]
fn hex_lower(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len().saturating_mul(2));
    for byte in input {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

/// Creates, verifies, and atomically publishes one exact canonical backup.
#[cfg(any(test, feature = "evidence-only"))]
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
)]
pub(super) fn create_backup(
    root: &RetainedDirectory,
    master_key: &VaultMasterKey,
    backup_passphrase: Passphrase,
    backup_id: [u8; 32],
    backup_generation: u64,
    inputs: VerifiedBackupInputsV1,
) -> Result<CompletedBackupV1, LinuxCapabilityError> {
    if backup_generation == 0
        || backup_id == [0; 32]
        || backup_id == *inputs.storage_ids().contract_wallet_id()
        || backup_id == *inputs.storage_ids().vault_id()
    {
        return Err(LinuxCapabilityError::InvalidObject);
    }
    let storage_ids = inputs.storage_ids();
    let source_epoch = inputs.source_epoch();
    let source_journal_sequence = inputs.source_journal_sequence();
    let source_journal_head_digest = inputs.source_journal_head_digest();
    let (journal_entries, record_set) = inputs.into_payloads();
    if u64::try_from(journal_entries.len()).ok() != Some(source_journal_sequence)
        || ((source_journal_sequence == 0) != (source_journal_head_digest == [0; 32]))
    {
        return Err(LinuxCapabilityError::InvalidObject);
    }

    let manifest = BackupManifestV1::new(
        *storage_ids.contract_wallet_id(),
        *storage_ids.vault_id(),
        backup_id,
        source_epoch,
        source_journal_sequence,
        source_journal_head_digest,
        record_set.record_count(),
        *record_set.record_set_digest(),
        backup_generation,
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let backup_master_envelope = seal_master_key(storage_ids, &backup_passphrase, master_key)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let plaintext = BackupManifestPlaintextV1::from_bytes(manifest.as_bytes())
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let metadata = BackupManifestMetadataV1::from_manifest(&plaintext)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let manifest_envelope = seal_backup_manifest_v1(master_key, metadata, plaintext)
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let master_digest = authoritative_storage_hash_v1(
        StorageHashDomainV1::MasterEnvelope,
        backup_master_envelope.as_bytes(),
    );
    let manifest_object_digest = manifest_envelope.digest();
    let bundle = BackupBundleV1::new(
        backup_id,
        backup_generation,
        master_digest,
        manifest_object_digest,
        source_journal_sequence,
        source_journal_head_digest,
        record_set.record_count(),
        *record_set.record_set_digest(),
    )
    .map_err(|_| LinuxCapabilityError::InvalidObject)?;

    let structural = crate::UnauthenticatedBackupManifestV1::parse_structural(manifest.as_bytes())
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
    let staging_component =
        ValidatedComponent::registered(&canonical_backup_staging_directory_name(&structural))?;
    let final_component =
        ValidatedComponent::registered(&canonical_backup_directory_name(&structural))?;
    let staging = with_crash_scope("staging", || {
        root.create_child_directory(staging_component.clone())
    })?;
    populate_staging(
        &staging,
        &backup_master_envelope,
        &manifest_envelope,
        bundle.bundle_digest(),
        &journal_entries,
        &record_set,
    )?;
    verify_complete_backup(
        &staging,
        "staging-verification",
        &backup_master_envelope,
        &manifest_envelope,
        bundle.bundle_digest(),
        &journal_entries,
        &record_set,
    )?;
    #[cfg(test)]
    with_crash_scope("publication", || {
        test_crash_hook("after-staging-verify-before-rename")
    });
    let published =
        publish_same_root_verified(root, &staging_component, &final_component, &staging)?;
    verify_complete_backup(
        &published,
        "published-verification",
        &backup_master_envelope,
        &manifest_envelope,
        bundle.bundle_digest(),
        &journal_entries,
        &record_set,
    )?;
    #[cfg(test)]
    with_crash_scope("publication", || {
        test_crash_hook("after-final-verify-before-return")
    });
    Ok(CompletedBackupV1 {
        backup_generation,
        backup_id,
        bundle_digest: *bundle.bundle_digest(),
    })
}

#[cfg(any(test, feature = "evidence-only"))]
fn populate_staging(
    staging: &RetainedDirectory,
    master_envelope: &VaultMasterKeyEnvelopeV1,
    manifest_envelope: &VaultObjectEnvelopeV1,
    bundle_digest: &[u8; 32],
    journal_entries: &[Vec<u8>],
    record_set: &RestoreRecordSetV1,
) -> Result<(), LinuxCapabilityError> {
    with_crash_scope("backup-master-key.envelope", || {
        staging.create_immutable_file(
            &ValidatedComponent::registered("backup-master-key.envelope")?,
            master_envelope.as_bytes(),
        )
    })?;
    with_crash_scope("backup-manifest.object", || {
        staging.create_immutable_file(
            &ValidatedComponent::registered("backup-manifest.object")?,
            manifest_envelope.as_bytes(),
        )
    })?;
    with_crash_scope("backup-bundle.digest", || {
        staging.create_immutable_file(
            &ValidatedComponent::registered("backup-bundle.digest")?,
            bundle_digest,
        )
    })?;
    let journal = with_crash_scope("journal", || {
        staging.create_child_directory(ValidatedComponent::registered("journal")?)
    })?;
    for bytes in journal_entries {
        let structural = UnauthenticatedJournalEntryV1::parse_structural(bytes)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let name = canonical_journal_filename(structural.envelope());
        let logical_path = format!("journal/{name}");
        with_crash_scope(&logical_path, || {
            journal.create_immutable_file(&ValidatedComponent::registered(&name)?, bytes)
        })?;
    }
    sync_scoped(&journal, "journal")?;
    let records = with_crash_scope("records", || {
        staging.create_child_directory(ValidatedComponent::registered("records")?)
    })?;
    write_record_set(&records, record_set)?;
    sync_scoped(&records, "records")?;
    sync_scoped(staging, "staging")
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
            .checked_add(crate::RESTORE_RECORD_ITEM_PREFIX_LEN)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let length_offset = cursor + crate::RESTORE_RECORD_KEY_LEN;
        let record_length = u32::from_le_bytes(
            record_set.as_bytes()[length_offset..prefix_end]
                .try_into()
                .map_err(|_| LinuxCapabilityError::InvalidObject)?,
        ) as usize;
        let item_end = prefix_end
            .checked_add(record_length)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let key = UnauthenticatedRestoreRecordKeyV1::parse_structural(
            &record_set.as_bytes()[cursor..cursor + crate::RESTORE_RECORD_KEY_LEN],
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let directory_name = canonical_restore_record_directory_name(&key);
        if !identity_directories.contains_key(&directory_name) {
            let logical_path = format!("records/{directory_name}");
            let directory = with_crash_scope(&logical_path, || {
                records.create_child_directory(ValidatedComponent::registered(&directory_name)?)
            })?;
            identity_directories.insert(directory_name.clone(), directory);
        }
        let directory = identity_directories
            .get(&directory_name)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let file_name = canonical_restore_record_filename(&key);
        let logical_path = canonical_restore_record_relative_path(&key);
        with_crash_scope(&logical_path, || {
            directory.create_immutable_file(
                &ValidatedComponent::registered(&file_name)?,
                &record_set.as_bytes()[prefix_end..item_end],
            )
        })?;
        cursor = item_end;
    }
    for (directory_name, directory) in &identity_directories {
        sync_scoped(directory, &format!("records/{directory_name}"))?;
    }
    Ok(())
}

#[cfg(any(test, feature = "evidence-only"))]
fn verify_complete_backup(
    directory: &RetainedDirectory,
    verification_path: &str,
    master_envelope: &VaultMasterKeyEnvelopeV1,
    manifest_envelope: &VaultObjectEnvelopeV1,
    bundle_digest: &[u8; 32],
    journal_entries: &[Vec<u8>],
    record_set: &RestoreRecordSetV1,
) -> Result<(), LinuxCapabilityError> {
    let expected = BTreeSet::from([
        "backup-master-key.envelope",
        "backup-manifest.object",
        "backup-bundle.digest",
        "journal",
        "records",
    ]);
    require_exact_names(directory, &expected)?;
    require_exact_file(
        directory,
        "backup-master-key.envelope",
        master_envelope.as_bytes(),
        MASTER_ENVELOPE_LEN,
    )?;
    require_exact_file(
        directory,
        "backup-manifest.object",
        manifest_envelope.as_bytes(),
        MANIFEST_ENVELOPE_LEN,
    )?;
    require_exact_file(directory, "backup-bundle.digest", bundle_digest, 32)?;
    let journal = directory.open_child_directory(ValidatedComponent::registered("journal")?)?;
    let mut journal_names = BTreeSet::new();
    for bytes in journal_entries {
        let structural = UnauthenticatedJournalEntryV1::parse_structural(bytes)
            .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        let name = canonical_journal_filename(structural.envelope());
        journal_names.insert(name.clone());
        require_exact_file(&journal, &name, bytes, bytes.len())?;
    }
    require_exact_owned_names(&journal, &journal_names)?;

    let records = directory.open_child_directory(ValidatedComponent::registered("records")?)?;
    verify_record_tree(&records, record_set)?;
    sync_scoped(directory, verification_path)
}

#[cfg(any(test, feature = "evidence-only"))]
fn verify_record_tree(
    records: &RetainedDirectory,
    record_set: &RestoreRecordSetV1,
) -> Result<(), LinuxCapabilityError> {
    let mut cursor = 4_usize;
    let mut expected = BTreeMap::<String, BTreeMap<String, Vec<u8>>>::new();
    while cursor < record_set.as_bytes().len() {
        let prefix_end = cursor
            .checked_add(crate::RESTORE_RECORD_ITEM_PREFIX_LEN)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let record_length = u32::from_le_bytes(
            record_set.as_bytes()[cursor + crate::RESTORE_RECORD_KEY_LEN..prefix_end]
                .try_into()
                .map_err(|_| LinuxCapabilityError::InvalidObject)?,
        ) as usize;
        let item_end = prefix_end
            .checked_add(record_length)
            .ok_or(LinuxCapabilityError::InvalidObject)?;
        let key = UnauthenticatedRestoreRecordKeyV1::parse_structural(
            &record_set.as_bytes()[cursor..cursor + crate::RESTORE_RECORD_KEY_LEN],
        )
        .map_err(|_| LinuxCapabilityError::InvalidObject)?;
        expected
            .entry(canonical_restore_record_directory_name(&key))
            .or_default()
            .insert(
                canonical_restore_record_filename(&key),
                record_set.as_bytes()[prefix_end..item_end].to_vec(),
            );
        cursor = item_end;
    }
    let expected_directories: BTreeSet<String> = expected.keys().cloned().collect();
    require_exact_owned_names(records, &expected_directories)?;
    for (directory_name, files) in expected {
        let directory =
            records.open_child_directory(ValidatedComponent::registered(&directory_name)?)?;
        let expected_files: BTreeSet<String> = files.keys().cloned().collect();
        require_exact_owned_names(&directory, &expected_files)?;
        for (name, bytes) in files {
            require_exact_file(&directory, &name, &bytes, bytes.len())?;
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "evidence-only"))]
fn require_exact_file(
    directory: &RetainedDirectory,
    name: &str,
    expected: &[u8],
    maximum: usize,
) -> Result<(), LinuxCapabilityError> {
    let bytes = directory.read_bounded_file(&ValidatedComponent::registered(name)?, maximum)?;
    if bytes == expected {
        Ok(())
    } else {
        Err(LinuxCapabilityError::ExactBytesMismatch)
    }
}

#[cfg(any(test, feature = "evidence-only"))]
fn require_exact_names(
    directory: &RetainedDirectory,
    expected: &BTreeSet<&str>,
) -> Result<(), LinuxCapabilityError> {
    let mut found = BTreeSet::new();
    directory.scan_independent(|name, _| {
        found.insert(name.to_owned());
        Ok(())
    })?;
    if found == expected.iter().map(|name| (*name).to_owned()).collect() {
        Ok(())
    } else {
        Err(LinuxCapabilityError::InvalidDirectoryEntry)
    }
}

#[cfg(any(test, feature = "evidence-only"))]
fn require_exact_owned_names(
    directory: &RetainedDirectory,
    expected: &BTreeSet<String>,
) -> Result<(), LinuxCapabilityError> {
    let mut found = BTreeSet::new();
    directory.scan_independent(|name, _| {
        found.insert(name.to_owned());
        Ok(())
    })?;
    if &found == expected {
        Ok(())
    } else {
        Err(LinuxCapabilityError::InvalidDirectoryEntry)
    }
}

#[cfg(any(test, feature = "evidence-only"))]
fn publish_same_root_verified(
    root: &RetainedDirectory,
    source: &ValidatedComponent,
    destination: &ValidatedComponent,
    retained_staging: &RetainedDirectory,
) -> Result<RetainedDirectory, LinuxCapabilityError> {
    root.revalidate()?;
    retained_staging.revalidate()?;
    if !std::sync::Arc::ptr_eq(&retained_staging.reopen.parent, &root.descriptor) {
        return Err(LinuxCapabilityError::IdentityMismatch);
    }
    let source_stat = rustix::fs::statat(
        root.descriptor.as_fd(),
        source.as_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| map_errno("statat-verified-backup-staging", error))?;
    let source_identity =
        super::NodeIdentity::from_stat(&source_stat, ExpectedNodeType::Directory)?;
    retained_staging.identity.require_same(&source_identity)?;
    renameat_with(
        root.descriptor.as_fd(),
        source.as_str(),
        root.descriptor.as_fd(),
        destination.as_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| map_errno("renameat2-verified-backup", error))?;
    #[cfg(test)]
    with_crash_scope("publication", || {
        test_crash_hook("after-rename-before-root-sync")
    });
    fsync(root.descriptor.as_fd()).map_err(|error| map_errno("fsync-backup-root", error))?;
    #[cfg(test)]
    with_crash_scope("publication", || {
        test_crash_hook("after-root-sync-before-published-reopen")
    });
    let published = root.open_child_directory(destination.clone())?;
    retained_staging
        .identity
        .require_same(&published.identity)?;
    Ok(published)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::fs::Dir;
    use std::{
        fs::{self, File},
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        process,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Result<Self, Box<dyn std::error::Error>> {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "dom-contracts-backup-runtime-test-{}-{sequence}",
                    process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                        return Ok(Self(path));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(Box::new(error)),
                }
            }
        }

        fn capability(&self) -> Result<Arc<Dir>, Box<dyn std::error::Error>> {
            Ok(Arc::new(Dir::from_std_file(File::open(&self.0)?)))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn components() -> Result<(ValidatedComponent, ValidatedComponent), LinuxCapabilityError> {
        Ok((
            ValidatedComponent::registered(&format!(
                ".backup-{:020}-{}.staging",
                1,
                "11".repeat(32)
            ))?,
            ValidatedComponent::registered(&format!("backup-{:020}-{}", 1, "11".repeat(32)))?,
        ))
    }

    #[test]
    fn publication_rejects_cross_root_staging_authority() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = TestDirectory::create()?;
        let root_a = RetainedDirectory::create_under(
            temporary.capability()?,
            ValidatedComponent::operator_selected_root("root-a")?,
        )?;
        let root_b = RetainedDirectory::create_under(
            temporary.capability()?,
            ValidatedComponent::operator_selected_root("root-b")?,
        )?;
        let (staging_component, final_component) = components()?;
        let staging = root_a.create_child_directory(staging_component.clone())?;
        staging.sync()?;
        assert!(matches!(
            publish_same_root_verified(&root_b, &staging_component, &final_component, &staging,),
            Err(LinuxCapabilityError::IdentityMismatch)
        ));
        staging.revalidate()?;
        Ok(())
    }

    #[test]
    fn destination_collision_preserves_verified_staging() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = TestDirectory::create()?;
        let root = RetainedDirectory::create_under(
            temporary.capability()?,
            ValidatedComponent::operator_selected_root("root")?,
        )?;
        let (staging_component, final_component) = components()?;
        let staging = root.create_child_directory(staging_component.clone())?;
        staging.sync()?;
        root.create_child_directory(final_component.clone())?
            .sync()?;
        assert!(matches!(
            publish_same_root_verified(&root, &staging_component, &final_component, &staging,),
            Err(LinuxCapabilityError::AlreadyExists)
        ));
        staging.revalidate()?;
        Ok(())
    }

    #[test]
    fn verification_rejects_corruption_and_extra_entries() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = TestDirectory::create()?;
        let root = RetainedDirectory::create_under(
            temporary.capability()?,
            ValidatedComponent::operator_selected_root("root")?,
        )?;
        root.create_immutable_file(
            &ValidatedComponent::registered("backup-bundle.digest")?,
            &[0x21; 32],
        )?;
        assert_eq!(
            require_exact_file(&root, "backup-bundle.digest", &[0x22; 32], 32),
            Err(LinuxCapabilityError::ExactBytesMismatch)
        );
        root.create_child_directory(ValidatedComponent::registered("journal")?)?;
        root.create_child_directory(ValidatedComponent::registered("records")?)?;
        root.create_immutable_file(
            &ValidatedComponent::registered("backup-master-key.envelope")?,
            &[0x23; MASTER_ENVELOPE_LEN],
        )?;
        root.create_immutable_file(
            &ValidatedComponent::registered("backup-manifest.object")?,
            &[0x24; MANIFEST_ENVELOPE_LEN],
        )?;
        root.create_immutable_file(
            &ValidatedComponent::registered("store-root-identity.bin")?,
            b"unexpected",
        )?;
        let expected = BTreeSet::from([
            "backup-master-key.envelope",
            "backup-manifest.object",
            "backup-bundle.digest",
            "journal",
            "records",
        ]);
        assert_eq!(
            require_exact_names(&root, &expected),
            Err(LinuxCapabilityError::InvalidDirectoryEntry)
        );
        Ok(())
    }
}

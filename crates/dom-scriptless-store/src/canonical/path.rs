//! Pure canonical relative-path and filename encoders.
//!
//! These functions operate only on structurally parsed, unauthenticated
//! records. They perform no filesystem I/O and confer no authority. A future
//! store must still use retained directory capabilities, create-no-clobber,
//! authenticated digests, and the signed recovery policy.

use super::{
    RestoreOnlyRootV1, UnauthenticatedAttemptRecordV1, UnauthenticatedBackupManifestV1,
    UnauthenticatedExposureRecordV1, UnauthenticatedJournalEnvelopeV1,
    UnauthenticatedRestoreManifestV1, UnauthenticatedRestoreRecordKeyV1,
    UnauthenticatedTombstoneV1, UnauthenticatedVaultGenerationCoreV1,
};

/// Encodes the canonical relative path for one immutable exposure version.
pub fn canonical_exposure_relative_path(record: &UnauthenticatedExposureRecordV1<'_>) -> String {
    format!(
        "{}/{:020}/{:02x}-{}.exposure",
        hex_lower(record.identity().as_bytes()),
        record.sequence(),
        record.state() as u8,
        hex_lower(record.record_digest())
    )
}

/// Encodes the canonical relative path for one durable computation attempt.
pub fn canonical_attempt_relative_path(record: &UnauthenticatedAttemptRecordV1) -> String {
    format!(
        "{}/{:020}-{:02x}.attempt",
        hex_lower(record.identity().as_bytes()),
        record.expected_lifecycle_revision(),
        record.artifact() as u8
    )
}

/// Encodes the only canonical tombstone filename for an identity.
pub fn canonical_tombstone_filename(record: &UnauthenticatedTombstoneV1) -> String {
    format!("{}.tombstone", hex_lower(record.identity().as_bytes()))
}

/// Encodes the canonical tombstone staging filename.
pub fn canonical_tombstone_staging_filename(record: &UnauthenticatedTombstoneV1) -> String {
    format!(
        ".{}.tombstone.staging",
        hex_lower(record.identity().as_bytes())
    )
}

/// Encodes the canonical filename for one journal entry.
pub fn canonical_journal_filename(entry: &UnauthenticatedJournalEnvelopeV1<'_>) -> String {
    format!(
        "{:020}-{}.journal",
        entry.sequence(),
        hex_lower(entry.entry_digest())
    )
}

/// Encodes the canonical identity directory for one restore-record-set item.
pub fn canonical_restore_record_directory_name(key: &UnauthenticatedRestoreRecordKeyV1) -> String {
    hex_lower(&key.as_bytes()[..105])
}

/// Encodes the canonical tail filename for one restore-record-set item.
pub fn canonical_restore_record_filename(key: &UnauthenticatedRestoreRecordKeyV1) -> String {
    format!("{}.record", hex_lower(&key.as_bytes()[105..]))
}

/// Encodes the complete P1-004 nested restore-record relative path.
pub fn canonical_restore_record_relative_path(key: &UnauthenticatedRestoreRecordKeyV1) -> String {
    format!(
        "records/{}/{}",
        canonical_restore_record_directory_name(key),
        canonical_restore_record_filename(key)
    )
}

/// Encodes the immutable successor-generation directory name.
pub fn canonical_generation_directory_name(core: &UnauthenticatedVaultGenerationCoreV1) -> String {
    format!(
        "generation-{:020}-{}",
        core.vault_generation(),
        hex_lower(core.vault_id())
    )
}

/// Encodes the immutable completed-backup directory name.
pub fn canonical_backup_directory_name(manifest: &UnauthenticatedBackupManifestV1) -> String {
    format!(
        "backup-{:020}-{}",
        manifest.backup_generation(),
        hex_lower(manifest.backup_id())
    )
}

/// Encodes the create-no-clobber backup staging directory name.
pub fn canonical_backup_staging_directory_name(
    manifest: &UnauthenticatedBackupManifestV1,
) -> String {
    format!(
        ".backup-{:020}-{}.staging",
        manifest.backup_generation(),
        hex_lower(manifest.backup_id())
    )
}

/// Encodes the create-no-clobber restore staging directory name.
pub fn canonical_restore_staging_directory_name(
    manifest: &UnauthenticatedRestoreManifestV1,
) -> String {
    format!(
        ".restore-{}.staging",
        hex_lower(manifest.restore_transaction_id())
    )
}

/// Encodes the retained completed-restore directory name.
pub fn canonical_restore_completed_directory_name(
    manifest: &UnauthenticatedRestoreManifestV1,
) -> String {
    format!(
        "restore-complete-{}",
        hex_lower(manifest.restore_transaction_id())
    )
}

/// Encodes the finalized new-device restore marker filename.
pub fn canonical_restore_initialized_marker_name(root: &RestoreOnlyRootV1) -> String {
    format!(
        "restore-initialized-{}.bin",
        hex_lower(root.restore_initialization_id())
    )
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
        ArtifactKindV1, CanonicalCodecError, ExposureStateV1, JournalEntryKindV1, TerminalReasonV1,
        ATTEMPT_RECORD_LEN, BACKUP_MANIFEST_LEN, RESTORE_MANIFEST_LEN, RESTORE_RECORD_KEY_LEN,
        TOMBSTONE_LEN, VAULT_GENERATION_CORE_LEN,
    };

    fn identity() -> [u8; 105] {
        let mut bytes = [0_u8; 105];
        bytes[..32].fill(0x11);
        bytes[32..64].fill(0x22);
        bytes[64] = 0x02;
        bytes[65..97].fill(0x33);
        bytes[97..105].copy_from_slice(&7_u64.to_le_bytes());
        bytes
    }

    #[test]
    fn artifact_paths_match_the_signed_ascii_forms() -> Result<(), CanonicalCodecError> {
        let mut attempt_bytes = [0_u8; ATTEMPT_RECORD_LEN];
        attempt_bytes[..8].copy_from_slice(b"DOMNVAT1");
        attempt_bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        attempt_bytes[10..115].copy_from_slice(&identity());
        attempt_bytes[115..123].copy_from_slice(&9_u64.to_le_bytes());
        attempt_bytes[123..125].copy_from_slice(&0x0100_u16.to_le_bytes());
        attempt_bytes[125] = ArtifactKindV1::Commitment as u8;
        let attempt = UnauthenticatedAttemptRecordV1::parse_structural(&attempt_bytes)?;

        let mut exposure_bytes = vec![0_u8; 234];
        exposure_bytes[..8].copy_from_slice(b"DOMNVEX1");
        exposure_bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        exposure_bytes[10] = ExposureStateV1::Spent as u8;
        exposure_bytes[11] = ArtifactKindV1::Commitment as u8;
        exposure_bytes[12..117].copy_from_slice(&identity());
        exposure_bytes[117..125].copy_from_slice(&1_u64.to_le_bytes());
        exposure_bytes[125..133].copy_from_slice(&9_u64.to_le_bytes());
        exposure_bytes[197..201].copy_from_slice(&1_u32.to_le_bytes());
        exposure_bytes[201] = 0x44;
        exposure_bytes[202..234].fill(0xaa);
        let exposure = UnauthenticatedExposureRecordV1::parse_structural(&exposure_bytes)?;

        let identity_hex = hex_lower(&identity());
        assert_eq!(
            canonical_attempt_relative_path(&attempt),
            format!("{identity_hex}/00000000000000000009-01.attempt")
        );
        assert_eq!(
            canonical_exposure_relative_path(&exposure),
            format!(
                "{identity_hex}/00000000000000000001/03-{}.exposure",
                "aa".repeat(32)
            )
        );
        Ok(())
    }

    #[test]
    fn immutable_record_names_match_the_signed_ascii_forms() -> Result<(), CanonicalCodecError> {
        let mut tombstone_bytes = [0_u8; TOMBSTONE_LEN];
        tombstone_bytes[..8].copy_from_slice(b"DOMNVTS1");
        tombstone_bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        tombstone_bytes[10..115].copy_from_slice(&identity());
        tombstone_bytes[115] = TerminalReasonV1::Burned as u8;
        tombstone_bytes[119..127].copy_from_slice(&9_u64.to_le_bytes());
        tombstone_bytes[223..255].fill(0xbb);
        let tombstone = UnauthenticatedTombstoneV1::parse_structural(&tombstone_bytes)?;

        let mut key_bytes = [0_u8; RESTORE_RECORD_KEY_LEN];
        key_bytes[..105].copy_from_slice(&identity());
        key_bytes[105] = 0x04;
        key_bytes[114] = TerminalReasonV1::Burned as u8;
        key_bytes[115..123].copy_from_slice(&9_u64.to_le_bytes());
        key_bytes[123..155].fill(0xbb);
        let key = UnauthenticatedRestoreRecordKeyV1::parse_structural(&key_bytes)?;

        let identity_hex = hex_lower(&identity());
        assert_eq!(
            canonical_tombstone_filename(&tombstone),
            format!("{identity_hex}.tombstone")
        );
        assert_eq!(
            canonical_tombstone_staging_filename(&tombstone),
            format!(".{identity_hex}.tombstone.staging")
        );
        assert_eq!(
            canonical_restore_record_directory_name(&key),
            hex_lower(&key_bytes[..105])
        );
        assert_eq!(
            canonical_restore_record_filename(&key),
            format!("{}.record", hex_lower(&key_bytes[105..]))
        );
        assert_eq!(
            canonical_restore_record_relative_path(&key),
            format!(
                "records/{}/{}.record",
                hex_lower(&key_bytes[..105]),
                hex_lower(&key_bytes[105..])
            )
        );
        assert_eq!(canonical_tombstone_staging_filename(&tombstone).len(), 229);
        assert_eq!(canonical_restore_record_directory_name(&key).len(), 210);
        assert_eq!(canonical_restore_record_filename(&key).len(), 107);
        assert_eq!(canonical_restore_record_relative_path(&key).len(), 326);
        Ok(())
    }

    #[test]
    fn journal_and_generation_names_use_fixed_width_lowercase_fields(
    ) -> Result<(), CanonicalCodecError> {
        let mut journal_bytes = vec![0_u8; 88];
        journal_bytes[..8].copy_from_slice(b"DOMNVJR1");
        journal_bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        journal_bytes[10..18].copy_from_slice(&1_u64.to_le_bytes());
        journal_bytes[50] = JournalEntryKindV1::Reserve as u8;
        journal_bytes[56..88].fill(0xcc);
        let journal = UnauthenticatedJournalEnvelopeV1::parse_outer(&journal_bytes)?;

        let mut core_bytes = [0_u8; VAULT_GENERATION_CORE_LEN];
        core_bytes[..8].copy_from_slice(b"DOMNVGC1");
        core_bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        core_bytes[10..42].fill(0x11);
        core_bytes[42..74].fill(0x22);
        core_bytes[74..106].fill(0x33);
        core_bytes[106..114].copy_from_slice(&7_u64.to_le_bytes());
        core_bytes[114..122].copy_from_slice(&4_u64.to_le_bytes());
        let core = UnauthenticatedVaultGenerationCoreV1::parse_structural(&core_bytes)?;

        assert_eq!(
            canonical_journal_filename(&journal),
            format!("00000000000000000001-{}.journal", "cc".repeat(32))
        );
        assert_eq!(
            canonical_generation_directory_name(&core),
            format!("generation-00000000000000000004-{}", "33".repeat(32))
        );
        Ok(())
    }

    #[test]
    fn backup_and_restore_names_match_the_signed_ascii_forms() -> Result<(), CanonicalCodecError> {
        let mut backup_bytes = [0_u8; BACKUP_MANIFEST_LEN];
        backup_bytes[..8].copy_from_slice(b"DOMNVBM1");
        backup_bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        backup_bytes[10..42].fill(0x11);
        backup_bytes[42..74].fill(0x22);
        backup_bytes[74..106].fill(0x33);
        backup_bytes[106..114].copy_from_slice(&7_u64.to_le_bytes());
        backup_bytes[158..190].fill(0x66);
        backup_bytes[190..198].copy_from_slice(&5_u64.to_le_bytes());
        let backup = UnauthenticatedBackupManifestV1::parse_structural(&backup_bytes)?;

        let mut manifest_bytes = [0_u8; RESTORE_MANIFEST_LEN];
        manifest_bytes[..8].copy_from_slice(b"DOMNVRT1");
        manifest_bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        manifest_bytes[10..26].fill(0x44);
        manifest_bytes[26..58].fill(0x11);
        manifest_bytes[138..170].fill(0x33);
        manifest_bytes[170..178].copy_from_slice(&7_u64.to_le_bytes());
        manifest_bytes[218..226].copy_from_slice(&8_u64.to_le_bytes());
        manifest_bytes[230..262].fill(0x66);
        let manifest = UnauthenticatedRestoreManifestV1::parse_structural(&manifest_bytes)?;

        let root =
            RestoreOnlyRootV1::new([0x11; 32], [0x22; 32], [0x33; 16], [0x44; 32], [0x55; 16])?;

        assert_eq!(
            canonical_backup_directory_name(&backup),
            format!("backup-00000000000000000005-{}", "33".repeat(32))
        );
        assert_eq!(
            canonical_backup_staging_directory_name(&backup),
            format!(".backup-00000000000000000005-{}.staging", "33".repeat(32))
        );
        assert_eq!(
            canonical_restore_staging_directory_name(&manifest),
            format!(".restore-{}.staging", "44".repeat(16))
        );
        assert_eq!(
            canonical_restore_completed_directory_name(&manifest),
            format!("restore-complete-{}", "44".repeat(16))
        );
        assert_eq!(
            canonical_restore_initialized_marker_name(&root),
            format!("restore-initialized-{}.bin", "55".repeat(16))
        );
        Ok(())
    }

    #[test]
    fn hexadecimal_encoder_is_lowercase_and_byte_exact() {
        assert_eq!(
            hex_lower(&[0x00, 0x09, 0x0a, 0x7f, 0x80, 0xfe, 0xff]),
            "00090a7f80feff"
        );
    }
}

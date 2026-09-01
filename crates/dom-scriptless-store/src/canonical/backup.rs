//! Structural codecs for backup and pending-restore summaries.

use super::{
    exact, is_zero, read_u16, read_u32, read_u64, storage_hash, CanonicalCodecError,
    StorageHashDomainV1,
};

const BACKUP_MANIFEST_MAGIC: &[u8; 8] = b"DOMNVBM1";
const RESTORE_ONLY_ROOT_MAGIC: &[u8; 8] = b"DOMNVRO1";
const RESTORE_PENDING_INDEX_MAGIC: &[u8; 8] = b"DOMNVPI1";

/// Exact encoded size of `BackupManifestV1`.
pub const BACKUP_MANIFEST_LEN: usize = 230;
/// Exact byte length of the `BackupBundleDigestV1` preimage.
pub const BACKUP_BUNDLE_PREIMAGE_LEN: usize = 180;
/// Exact encoded size of `RestoreOnlyRootV1`.
pub const RESTORE_ONLY_ROOT_LEN: usize = 170;
/// Exact encoded size of `RestorePendingIndexV1`.
pub const RESTORE_PENDING_INDEX_LEN: usize = 530;

/// Authenticated canonical global backup manifest.
#[cfg(any(test, feature = "evidence-only"))]
#[derive(Clone, Eq, PartialEq)]
pub struct BackupManifestV1 {
    bytes: [u8; BACKUP_MANIFEST_LEN],
    digest: [u8; 32],
}

#[cfg(any(test, feature = "evidence-only"))]
impl BackupManifestV1 {
    /// Constructs the exact signed P1-002 backup-manifest bytes.
    #[cfg(any(test, feature = "evidence-only"))]
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub fn new(
        contract_wallet_id: [u8; 32],
        source_vault_id: [u8; 32],
        backup_id: [u8; 32],
        source_epoch: u64,
        source_journal_sequence: u64,
        source_journal_head_digest: [u8; 32],
        record_count: u32,
        record_set_digest: [u8; 32],
        backup_generation: u64,
    ) -> Result<Self, CanonicalCodecError> {
        let mut bytes = [0_u8; BACKUP_MANIFEST_LEN];
        bytes[..8].copy_from_slice(BACKUP_MANIFEST_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].copy_from_slice(&contract_wallet_id);
        bytes[42..74].copy_from_slice(&source_vault_id);
        bytes[74..106].copy_from_slice(&backup_id);
        bytes[106..114].copy_from_slice(&source_epoch.to_le_bytes());
        bytes[114..122].copy_from_slice(&source_journal_sequence.to_le_bytes());
        bytes[122..154].copy_from_slice(&source_journal_head_digest);
        bytes[154..158].copy_from_slice(&record_count.to_le_bytes());
        bytes[158..190].copy_from_slice(&record_set_digest);
        bytes[190..198].copy_from_slice(&backup_generation.to_le_bytes());
        let digest = storage_hash(StorageHashDomainV1::BackupManifest, &bytes[..198]);
        bytes[198..].copy_from_slice(&digest);
        Self::from_bytes(&bytes)
    }

    /// Parses exact bytes and authenticates the registered manifest digest.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedBackupManifestV1::parse_structural(input)?;
        let digest = storage_hash(StorageHashDomainV1::BackupManifest, &input[..198]);
        if structural.manifest_digest() != digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
            digest,
        })
    }

    /// Returns the exact authenticated bytes.
    pub const fn as_bytes(&self) -> &[u8; BACKUP_MANIFEST_LEN] {
        &self.bytes
    }

    /// Returns the authenticated manifest digest.
    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the authenticated stable Contracts wallet identifier.
    pub fn contract_wallet_id(&self) -> &[u8] {
        &self.bytes[10..42]
    }

    /// Returns the authenticated source vault identifier.
    pub fn source_vault_id(&self) -> &[u8] {
        &self.bytes[42..74]
    }

    /// Returns the fresh backup identifier.
    pub fn backup_id(&self) -> &[u8] {
        &self.bytes[74..106]
    }

    /// Returns the source nonce epoch.
    pub fn source_epoch(&self) -> u64 {
        read_u64(&self.bytes[106..114])
    }

    /// Returns the source journal sequence.
    pub fn source_journal_sequence(&self) -> u64 {
        read_u64(&self.bytes[114..122])
    }

    /// Returns the source journal head digest or its exact sequence-zero sentinel.
    pub fn source_journal_head_digest(&self) -> &[u8] {
        &self.bytes[122..154]
    }

    /// Returns the declared source record count.
    pub fn record_count(&self) -> u32 {
        read_u32(&self.bytes[154..158])
    }

    /// Returns the authenticated source record-set digest.
    pub fn record_set_digest(&self) -> &[u8] {
        &self.bytes[158..190]
    }

    /// Returns the nonzero monotonic backup generation.
    pub fn backup_generation(&self) -> u64 {
        read_u64(&self.bytes[190..198])
    }
}

/// Authenticated exact backup-bundle digest input and result.
#[cfg(any(test, feature = "evidence-only"))]
#[derive(Clone, Eq, PartialEq)]
pub struct BackupBundleV1 {
    preimage: [u8; BACKUP_BUNDLE_PREIMAGE_LEN],
    digest: [u8; 32],
}

#[cfg(any(test, feature = "evidence-only"))]
impl BackupBundleV1 {
    /// Constructs the exact 180-byte bundle preimage in signed field order.
    #[cfg(any(test, feature = "evidence-only"))]
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub fn new(
        backup_id: [u8; 32],
        backup_generation: u64,
        backup_master_envelope_digest: [u8; 32],
        backup_manifest_object_envelope_digest: [u8; 32],
        source_journal_sequence: u64,
        source_journal_head_digest: [u8; 32],
        source_record_count: u32,
        source_record_set_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        let mut preimage = [0_u8; BACKUP_BUNDLE_PREIMAGE_LEN];
        preimage[..32].copy_from_slice(&backup_id);
        preimage[32..40].copy_from_slice(&backup_generation.to_le_bytes());
        preimage[40..72].copy_from_slice(&backup_master_envelope_digest);
        preimage[72..104].copy_from_slice(&backup_manifest_object_envelope_digest);
        preimage[104..112].copy_from_slice(&source_journal_sequence.to_le_bytes());
        preimage[112..144].copy_from_slice(&source_journal_head_digest);
        preimage[144..148].copy_from_slice(&source_record_count.to_le_bytes());
        preimage[148..180].copy_from_slice(&source_record_set_digest);
        Self::from_preimage(&preimage)
    }

    /// Parses the exact preimage and computes its registered digest.
    pub fn from_preimage(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedBackupBundlePreimageV1::parse_structural(input)?;
        let preimage = *structural.as_bytes();
        let digest = storage_hash(StorageHashDomainV1::BackupBundle, &preimage);
        Ok(Self { preimage, digest })
    }

    /// Parses the exact preimage and authenticates a separately stored bundle digest.
    pub fn from_preimage_and_digest(
        input: &[u8],
        expected_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        let bundle = Self::from_preimage(input)?;
        if bundle.digest != expected_digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(bundle)
    }

    /// Returns the exact 180-byte digest preimage.
    pub const fn preimage(&self) -> &[u8; BACKUP_BUNDLE_PREIMAGE_LEN] {
        &self.preimage
    }

    /// Returns the authenticated bundle digest.
    pub const fn bundle_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the backup identifier committed by the bundle.
    pub fn backup_id(&self) -> &[u8] {
        &self.preimage[..32]
    }

    /// Returns the committed backup generation.
    pub fn backup_generation(&self) -> u64 {
        read_u64(&self.preimage[32..40])
    }

    /// Returns the complete backup master-envelope digest.
    pub fn backup_master_envelope_digest(&self) -> &[u8] {
        &self.preimage[40..72]
    }

    /// Returns the complete backup manifest-object envelope digest.
    pub fn backup_manifest_object_envelope_digest(&self) -> &[u8] {
        &self.preimage[72..104]
    }

    /// Returns the source journal sequence.
    pub fn source_journal_sequence(&self) -> u64 {
        read_u64(&self.preimage[104..112])
    }

    /// Returns the source journal head or its exact sequence-zero sentinel.
    pub fn source_journal_head_digest(&self) -> &[u8] {
        &self.preimage[112..144]
    }

    /// Returns the source canonical record count.
    pub fn source_record_count(&self) -> u32 {
        read_u32(&self.preimage[144..148])
    }

    /// Returns the source canonical record-set digest.
    pub fn source_record_set_digest(&self) -> &[u8] {
        &self.preimage[148..180]
    }
}

/// Authenticated new-device restore-only root marker.
#[derive(Clone, Eq, PartialEq)]
pub struct RestoreOnlyRootV1 {
    bytes: [u8; RESTORE_ONLY_ROOT_LEN],
    digest: [u8; 32],
}

impl RestoreOnlyRootV1 {
    /// Constructs an exact restore-only root from already authenticated public inputs.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn new(
        contract_wallet_id: [u8; 32],
        store_root_id: [u8; 32],
        lock_instance_id: [u8; 16],
        source_backup_bundle_digest: [u8; 32],
        restore_initialization_id: [u8; 16],
    ) -> Result<Self, CanonicalCodecError> {
        let mut bytes = [0_u8; RESTORE_ONLY_ROOT_LEN];
        bytes[..8].copy_from_slice(RESTORE_ONLY_ROOT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].copy_from_slice(&contract_wallet_id);
        bytes[42..74].copy_from_slice(&store_root_id);
        bytes[74..90].copy_from_slice(&lock_instance_id);
        bytes[90..122].copy_from_slice(&source_backup_bundle_digest);
        bytes[122..138].copy_from_slice(&restore_initialization_id);
        let digest = storage_hash(StorageHashDomainV1::RestoreOnlyRoot, &bytes[..138]);
        bytes[138..].copy_from_slice(&digest);
        Self::from_bytes(&bytes)
    }

    /// Parses exact bytes and authenticates the registered marker digest.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedRestoreOnlyRootV1::parse_structural(input)?;
        let digest = storage_hash(StorageHashDomainV1::RestoreOnlyRoot, &input[..138]);
        if structural.restore_only_root_digest() != digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
            digest,
        })
    }

    /// Returns the exact authenticated bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_ONLY_ROOT_LEN] {
        &self.bytes
    }

    /// Returns the authenticated marker digest.
    pub const fn restore_only_root_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the authenticated stable Contracts wallet identifier.
    pub fn contract_wallet_id(&self) -> &[u8] {
        &self.bytes[10..42]
    }

    /// Returns the fresh Store root identifier.
    pub fn store_root_id(&self) -> &[u8] {
        &self.bytes[42..74]
    }

    /// Returns the fresh retained lock-instance identifier.
    pub fn lock_instance_id(&self) -> &[u8] {
        &self.bytes[74..90]
    }

    /// Returns the verified source backup-bundle digest.
    pub fn source_backup_bundle_digest(&self) -> &[u8] {
        &self.bytes[90..122]
    }

    /// Returns the fresh restore-initialization identifier.
    pub fn restore_initialization_id(&self) -> &[u8] {
        &self.bytes[122..138]
    }
}

/// Public fields committed by one canonical restore-pending index.
#[derive(Clone, Eq, PartialEq)]
pub struct RestorePendingIndexFieldsV1 {
    pub restore_transaction_id: [u8; 16],
    pub contract_wallet_id: [u8; 32],
    pub restore_manifest_digest: [u8; 32],
    pub source_backup_bundle_digest: [u8; 32],
    pub source_backup_master_envelope_digest: [u8; 32],
    pub source_backup_manifest_object_envelope_digest: [u8; 32],
    pub source_journal_sequence: u64,
    pub source_journal_head_digest: [u8; 32],
    pub source_record_count: u32,
    pub source_record_set_digest: [u8; 32],
    pub successor_generation_core_digest: [u8; 32],
    pub successor_master_envelope_digest: [u8; 32],
    pub successor_final_journal_sequence: u64,
    pub successor_final_journal_head_digest: [u8; 32],
    pub successor_record_count: u32,
    pub successor_record_set_digest: [u8; 32],
    pub successor_tombstone_envelope_set_digest: [u8; 32],
    pub successor_active_generation_digest: [u8; 32],
    pub restore_only_root_digest: [u8; 32],
}

/// Authenticated canonical restore-pending index.
#[derive(Clone, Eq, PartialEq)]
pub struct RestorePendingIndexV1 {
    bytes: [u8; RESTORE_PENDING_INDEX_LEN],
    digest: [u8; 32],
}

impl RestorePendingIndexV1 {
    /// Constructs the exact pending index. Cross-object equality remains a Store check.
    #[cfg(any(test, feature = "evidence-only"))]
    pub fn new(fields: RestorePendingIndexFieldsV1) -> Result<Self, CanonicalCodecError> {
        let mut bytes = [0_u8; RESTORE_PENDING_INDEX_LEN];
        bytes[..8].copy_from_slice(RESTORE_PENDING_INDEX_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..26].copy_from_slice(&fields.restore_transaction_id);
        bytes[26..58].copy_from_slice(&fields.contract_wallet_id);
        bytes[58..90].copy_from_slice(&fields.restore_manifest_digest);
        bytes[90..122].copy_from_slice(&fields.source_backup_bundle_digest);
        bytes[122..154].copy_from_slice(&fields.source_backup_master_envelope_digest);
        bytes[154..186].copy_from_slice(&fields.source_backup_manifest_object_envelope_digest);
        bytes[186..194].copy_from_slice(&fields.source_journal_sequence.to_le_bytes());
        bytes[194..226].copy_from_slice(&fields.source_journal_head_digest);
        bytes[226..230].copy_from_slice(&fields.source_record_count.to_le_bytes());
        bytes[230..262].copy_from_slice(&fields.source_record_set_digest);
        bytes[262..294].copy_from_slice(&fields.successor_generation_core_digest);
        bytes[294..326].copy_from_slice(&fields.successor_master_envelope_digest);
        bytes[326..334].copy_from_slice(&fields.successor_final_journal_sequence.to_le_bytes());
        bytes[334..366].copy_from_slice(&fields.successor_final_journal_head_digest);
        bytes[366..370].copy_from_slice(&fields.successor_record_count.to_le_bytes());
        bytes[370..402].copy_from_slice(&fields.successor_record_set_digest);
        bytes[402..434].copy_from_slice(&fields.successor_tombstone_envelope_set_digest);
        bytes[434..466].copy_from_slice(&fields.successor_active_generation_digest);
        bytes[466..498].copy_from_slice(&fields.restore_only_root_digest);
        let digest = storage_hash(StorageHashDomainV1::RestorePendingIndex, &bytes[..498]);
        bytes[498..].copy_from_slice(&digest);
        Self::from_bytes(&bytes)
    }

    /// Parses exact bytes and authenticates the registered index digest.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedRestorePendingIndexV1::parse_structural(input)?;
        let digest = storage_hash(StorageHashDomainV1::RestorePendingIndex, &input[..498]);
        if structural.pending_index_digest() != digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
            digest,
        })
    }

    /// Returns the exact authenticated bytes.
    #[cfg(any(test, feature = "evidence-only"))]
    pub const fn as_bytes(&self) -> &[u8; RESTORE_PENDING_INDEX_LEN] {
        &self.bytes
    }

    /// Returns the authenticated pending-index digest.
    #[cfg(any(test, feature = "evidence-only"))]
    pub const fn pending_index_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the exact authenticated public fields committed by this index.
    pub fn fields(&self) -> RestorePendingIndexFieldsV1 {
        let array_16 = |range: core::ops::Range<usize>| {
            let mut value = [0_u8; 16];
            value.copy_from_slice(&self.bytes[range]);
            value
        };
        let array_32 = |range: core::ops::Range<usize>| {
            let mut value = [0_u8; 32];
            value.copy_from_slice(&self.bytes[range]);
            value
        };
        RestorePendingIndexFieldsV1 {
            restore_transaction_id: array_16(10..26),
            contract_wallet_id: array_32(26..58),
            restore_manifest_digest: array_32(58..90),
            source_backup_bundle_digest: array_32(90..122),
            source_backup_master_envelope_digest: array_32(122..154),
            source_backup_manifest_object_envelope_digest: array_32(154..186),
            source_journal_sequence: read_u64(&self.bytes[186..194]),
            source_journal_head_digest: array_32(194..226),
            source_record_count: read_u32(&self.bytes[226..230]),
            source_record_set_digest: array_32(230..262),
            successor_generation_core_digest: array_32(262..294),
            successor_master_envelope_digest: array_32(294..326),
            successor_final_journal_sequence: read_u64(&self.bytes[326..334]),
            successor_final_journal_head_digest: array_32(334..366),
            successor_record_count: read_u32(&self.bytes[366..370]),
            successor_record_set_digest: array_32(370..402),
            successor_tombstone_envelope_set_digest: array_32(402..434),
            successor_active_generation_digest: array_32(434..466),
            restore_only_root_digest: array_32(466..498),
        }
    }
}

/// Structurally parsed encrypted-backup manifest plaintext.
pub struct UnauthenticatedBackupManifestV1 {
    bytes: [u8; BACKUP_MANIFEST_LEN],
    source_epoch: u64,
    source_journal_sequence: u64,
    record_count: u32,
    backup_generation: u64,
}

impl UnauthenticatedBackupManifestV1 {
    /// Parses exact fields without authenticating any digest or envelope.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<BACKUP_MANIFEST_LEN>(input)?;
        let source_epoch = read_u64(&bytes[106..114]);
        let source_journal_sequence = read_u64(&bytes[114..122]);
        let record_count = read_u32(&bytes[154..158]);
        let backup_generation = read_u64(&bytes[190..198]);
        if &bytes[..8] != BACKUP_MANIFEST_MAGIC
            || read_u16(&bytes[8..10]) != 1
            || is_zero(&bytes[10..42])
            || is_zero(&bytes[42..74])
            || is_zero(&bytes[74..106])
            || bytes[10..42] == bytes[42..74]
            || bytes[10..42] == bytes[74..106]
            || bytes[42..74] == bytes[74..106]
            || source_epoch == 0
            || is_zero(&bytes[158..190])
            || (source_journal_sequence == 0) != is_zero(&bytes[122..154])
            || backup_generation == 0
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            source_epoch,
            source_journal_sequence,
            record_count,
            backup_generation,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; BACKUP_MANIFEST_LEN] {
        &self.bytes
    }

    /// Returns the nonzero source nonce epoch.
    pub const fn source_epoch(&self) -> u64 {
        self.source_epoch
    }

    /// Returns the source journal sequence.
    pub const fn source_journal_sequence(&self) -> u64 {
        self.source_journal_sequence
    }

    /// Returns the declared canonical nonce-record count.
    pub const fn record_count(&self) -> u32 {
        self.record_count
    }

    /// Returns the nonzero monotonic backup generation.
    pub const fn backup_generation(&self) -> u64 {
        self.backup_generation
    }

    /// Returns the fresh nonzero backup identifier.
    pub fn backup_id(&self) -> &[u8] {
        &self.bytes[74..106]
    }

    /// Returns the unauthenticated backup-manifest digest.
    pub fn manifest_digest(&self) -> &[u8] {
        &self.bytes[198..230]
    }
}

/// Structurally parsed exact `BackupBundleDigestV1` preimage.
pub struct UnauthenticatedBackupBundlePreimageV1 {
    bytes: [u8; BACKUP_BUNDLE_PREIMAGE_LEN],
    backup_generation: u64,
    source_journal_sequence: u64,
    source_record_count: u32,
}

impl UnauthenticatedBackupBundlePreimageV1 {
    /// Parses the exact 180-byte displayed field order.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<BACKUP_BUNDLE_PREIMAGE_LEN>(input)?;
        let backup_generation = read_u64(&bytes[32..40]);
        let source_journal_sequence = read_u64(&bytes[104..112]);
        let source_record_count = read_u32(&bytes[144..148]);
        if is_zero(&bytes[..32])
            || backup_generation == 0
            || is_zero(&bytes[40..72])
            || is_zero(&bytes[72..104])
            || is_zero(&bytes[148..180])
            || (source_journal_sequence == 0) != is_zero(&bytes[112..144])
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            backup_generation,
            source_journal_sequence,
            source_record_count,
        })
    }

    /// Returns the exact unauthenticated preimage bytes.
    pub const fn as_bytes(&self) -> &[u8; BACKUP_BUNDLE_PREIMAGE_LEN] {
        &self.bytes
    }

    /// Returns the nonzero backup generation.
    pub const fn backup_generation(&self) -> u64 {
        self.backup_generation
    }

    /// Returns the source journal sequence.
    pub const fn source_journal_sequence(&self) -> u64 {
        self.source_journal_sequence
    }

    /// Returns the source record count.
    pub const fn source_record_count(&self) -> u32 {
        self.source_record_count
    }
}

/// Structurally parsed new-device restore-only root marker.
pub struct UnauthenticatedRestoreOnlyRootV1 {
    bytes: [u8; RESTORE_ONLY_ROOT_LEN],
}

impl UnauthenticatedRestoreOnlyRootV1 {
    /// Parses exact fields without authenticating either embedded digest.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<RESTORE_ONLY_ROOT_LEN>(input)?;
        if &bytes[..8] != RESTORE_ONLY_ROOT_MAGIC
            || read_u16(&bytes[8..10]) != 1
            || is_zero(&bytes[10..42])
            || is_zero(&bytes[42..74])
            || is_zero(&bytes[74..90])
            || is_zero(&bytes[90..122])
            || is_zero(&bytes[122..138])
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self { bytes })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_ONLY_ROOT_LEN] {
        &self.bytes
    }

    /// Returns the unauthenticated source backup-bundle digest.
    pub fn source_backup_bundle_digest(&self) -> &[u8] {
        &self.bytes[90..122]
    }

    /// Returns the fresh nonzero restore-initialization identifier.
    pub fn restore_initialization_id(&self) -> &[u8] {
        &self.bytes[122..138]
    }

    /// Returns the unauthenticated restore-only-root digest.
    pub fn restore_only_root_digest(&self) -> &[u8] {
        &self.bytes[138..170]
    }
}

/// Structurally parsed restore-pending index.
///
/// Whether `restore_only_root_digest` must be zero or authenticated is a
/// cross-record property of the matching restore manifest and is deliberately
/// not selected by caller input in this structural parser.
pub struct UnauthenticatedRestorePendingIndexV1 {
    bytes: [u8; RESTORE_PENDING_INDEX_LEN],
    source_journal_sequence: u64,
    source_record_count: u32,
    successor_journal_sequence: u64,
    successor_record_count: u32,
}

impl UnauthenticatedRestorePendingIndexV1 {
    /// Parses exact fixed fields without authenticating the digest DAG.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<RESTORE_PENDING_INDEX_LEN>(input)?;
        let source_journal_sequence = read_u64(&bytes[186..194]);
        let source_record_count = read_u32(&bytes[226..230]);
        let successor_journal_sequence = read_u64(&bytes[326..334]);
        let successor_record_count = read_u32(&bytes[366..370]);
        if &bytes[..8] != RESTORE_PENDING_INDEX_MAGIC
            || read_u16(&bytes[8..10]) != 1
            || is_zero(&bytes[10..26])
            || is_zero(&bytes[26..58])
            || bytes[58..186].chunks_exact(32).any(is_zero)
            || is_zero(&bytes[230..262])
            || is_zero(&bytes[262..294])
            || is_zero(&bytes[294..326])
            || is_zero(&bytes[334..366])
            || is_zero(&bytes[370..402])
            || is_zero(&bytes[402..434])
            || is_zero(&bytes[434..466])
            || (source_journal_sequence == 0) != is_zero(&bytes[194..226])
            || successor_journal_sequence == 0
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            source_journal_sequence,
            source_record_count,
            successor_journal_sequence,
            successor_record_count,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; RESTORE_PENDING_INDEX_LEN] {
        &self.bytes
    }

    /// Returns the source journal sequence.
    pub const fn source_journal_sequence(&self) -> u64 {
        self.source_journal_sequence
    }

    /// Returns the source record count.
    pub const fn source_record_count(&self) -> u32 {
        self.source_record_count
    }

    /// Returns the nonzero successor final journal sequence.
    pub const fn successor_journal_sequence(&self) -> u64 {
        self.successor_journal_sequence
    }

    /// Returns the successor record count.
    pub const fn successor_record_count(&self) -> u32 {
        self.successor_record_count
    }

    /// Returns the context-dependent restore-only-root digest field.
    pub fn restore_only_root_digest(&self) -> &[u8] {
        &self.bytes[466..498]
    }

    /// Returns the unauthenticated pending-index digest.
    pub fn pending_index_digest(&self) -> &[u8] {
        &self.bytes[498..530]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup_manifest() -> Result<[u8; BACKUP_MANIFEST_LEN], CanonicalCodecError> {
        BackupManifestV1::new(
            [0x11; 32], [0x22; 32], [0x33; 32], 7, 0, [0; 32], 0, [0x55; 32], 1,
        )
        .map(|manifest| *manifest.as_bytes())
    }

    fn bundle_preimage() -> Result<[u8; BACKUP_BUNDLE_PREIMAGE_LEN], CanonicalCodecError> {
        BackupBundleV1::new(
            [0x33; 32], 1, [0x44; 32], [0x55; 32], 0, [0; 32], 0, [0x66; 32],
        )
        .map(|bundle| *bundle.preimage())
    }

    fn restore_only_root() -> Result<[u8; RESTORE_ONLY_ROOT_LEN], CanonicalCodecError> {
        RestoreOnlyRootV1::new([0x11; 32], [0x22; 32], [0x33; 16], [0x44; 32], [0x55; 16])
            .map(|root| *root.as_bytes())
    }

    fn pending_index() -> Result<[u8; RESTORE_PENDING_INDEX_LEN], CanonicalCodecError> {
        RestorePendingIndexV1::new(RestorePendingIndexFieldsV1 {
            restore_transaction_id: [0x11; 16],
            contract_wallet_id: [0x22; 32],
            restore_manifest_digest: [0x33; 32],
            source_backup_bundle_digest: [0x44; 32],
            source_backup_master_envelope_digest: [0x55; 32],
            source_backup_manifest_object_envelope_digest: [0x66; 32],
            source_journal_sequence: 0,
            source_journal_head_digest: [0; 32],
            source_record_count: 0,
            source_record_set_digest: [0x77; 32],
            successor_generation_core_digest: [0x88; 32],
            successor_master_envelope_digest: [0x99; 32],
            successor_final_journal_sequence: 4,
            successor_final_journal_head_digest: [0xaa; 32],
            successor_record_count: 0,
            successor_record_set_digest: [0xbb; 32],
            successor_tombstone_envelope_set_digest: [0xcc; 32],
            successor_active_generation_digest: [0xdd; 32],
            restore_only_root_digest: [0; 32],
        })
        .map(|index| *index.as_bytes())
    }

    #[test]
    fn backup_manifest_enforces_ids_epoch_and_generation() -> Result<(), CanonicalCodecError> {
        let bytes = backup_manifest()?;
        let parsed = UnauthenticatedBackupManifestV1::parse_structural(&bytes)?;
        assert_eq!(parsed.as_bytes(), &bytes);
        assert_eq!(parsed.source_epoch(), 7);
        assert_eq!(parsed.backup_generation(), 1);
        assert_ne!(parsed.manifest_digest(), &[0; 32]);

        for range in [10..42, 42..74, 74..106, 106..114, 190..198] {
            let mut invalid = bytes;
            invalid[range].fill(0);
            assert!(UnauthenticatedBackupManifestV1::parse_structural(&invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn bundle_preimage_accepts_structural_zero_hash_outputs() -> Result<(), CanonicalCodecError> {
        let mut bytes = bundle_preimage()?;
        bytes[104..112].copy_from_slice(&3_u64.to_le_bytes());
        bytes[112..144].fill(0x77);
        let parsed = UnauthenticatedBackupBundlePreimageV1::parse_structural(&bytes)?;
        assert_eq!(parsed.as_bytes(), &bytes);
        assert_eq!(parsed.source_journal_sequence(), 3);
        assert_eq!(parsed.source_record_count(), 0);
        Ok(())
    }

    #[test]
    fn restore_only_root_requires_fresh_nonzero_ids() -> Result<(), CanonicalCodecError> {
        let bytes = restore_only_root()?;
        let parsed = UnauthenticatedRestoreOnlyRootV1::parse_structural(&bytes)?;
        assert_eq!(parsed.as_bytes(), &bytes);
        assert_eq!(parsed.restore_initialization_id(), &[0x55; 16]);
        assert_ne!(parsed.restore_only_root_digest(), &[0; 32]);
        Ok(())
    }

    #[test]
    fn pending_index_enforces_framing_and_successor_sequence() -> Result<(), CanonicalCodecError> {
        let bytes = pending_index()?;
        let parsed = UnauthenticatedRestorePendingIndexV1::parse_structural(&bytes)?;
        assert_eq!(parsed.as_bytes(), &bytes);
        assert_eq!(parsed.successor_journal_sequence(), 4);
        assert_ne!(parsed.pending_index_digest(), &[0; 32]);

        let mut zero_sequence = bytes;
        zero_sequence[326..334].fill(0);
        assert!(UnauthenticatedRestorePendingIndexV1::parse_structural(&zero_sequence).is_err());
        Ok(())
    }

    #[test]
    fn fixed_backup_records_reject_truncation_and_trailing_bytes() -> Result<(), CanonicalCodecError>
    {
        let manifest = backup_manifest()?;
        assert!(UnauthenticatedBackupManifestV1::parse_structural(&manifest[..229]).is_err());
        let mut trailing = manifest.to_vec();
        trailing.push(0);
        assert!(UnauthenticatedBackupManifestV1::parse_structural(&trailing).is_err());

        let pending = pending_index()?;
        assert!(UnauthenticatedRestorePendingIndexV1::parse_structural(&pending[..529]).is_err());
        Ok(())
    }

    #[test]
    fn backup_records_reject_every_truncation_and_trailing_byte() -> Result<(), CanonicalCodecError>
    {
        let records = [
            backup_manifest()?.to_vec(),
            bundle_preimage()?.to_vec(),
            restore_only_root()?.to_vec(),
            pending_index()?.to_vec(),
        ];
        for (record_index, bytes) in records.into_iter().enumerate() {
            for end in 0..bytes.len() {
                let rejected = match record_index {
                    0 => UnauthenticatedBackupManifestV1::parse_structural(&bytes[..end]).is_err(),
                    1 => UnauthenticatedBackupBundlePreimageV1::parse_structural(&bytes[..end])
                        .is_err(),
                    2 => UnauthenticatedRestoreOnlyRootV1::parse_structural(&bytes[..end]).is_err(),
                    3 => UnauthenticatedRestorePendingIndexV1::parse_structural(&bytes[..end])
                        .is_err(),
                    _ => false,
                };
                assert!(rejected, "record {record_index}, prefix {end}");
            }
            let mut trailing = bytes;
            trailing.push(0);
            let rejected = match record_index {
                0 => UnauthenticatedBackupManifestV1::parse_structural(&trailing).is_err(),
                1 => UnauthenticatedBackupBundlePreimageV1::parse_structural(&trailing).is_err(),
                2 => UnauthenticatedRestoreOnlyRootV1::parse_structural(&trailing).is_err(),
                3 => UnauthenticatedRestorePendingIndexV1::parse_structural(&trailing).is_err(),
                _ => false,
            };
            assert!(rejected, "record {record_index}, trailing");
        }
        Ok(())
    }

    #[test]
    fn authenticated_backup_records_reject_every_byte_mutation() -> Result<(), CanonicalCodecError>
    {
        let records = [
            backup_manifest()?.to_vec(),
            restore_only_root()?.to_vec(),
            pending_index()?.to_vec(),
        ];
        for (record_index, canonical) in records.into_iter().enumerate() {
            for offset in 0..canonical.len() {
                let mut mutated = canonical.clone();
                mutated[offset] ^= 1;
                let rejected = match record_index {
                    0 => BackupManifestV1::from_bytes(&mutated).is_err(),
                    1 => RestoreOnlyRootV1::from_bytes(&mutated).is_err(),
                    2 => RestorePendingIndexV1::from_bytes(&mutated).is_err(),
                    _ => false,
                };
                assert!(rejected, "record {record_index}, mutation {offset}");
            }
        }

        let canonical_bundle = bundle_preimage()?;
        let expected = *BackupBundleV1::from_preimage(&canonical_bundle)?.bundle_digest();
        for offset in 0..canonical_bundle.len() {
            let mut mutated = canonical_bundle;
            mutated[offset] ^= 1;
            assert!(
                BackupBundleV1::from_preimage_and_digest(&mutated, expected).is_err(),
                "bundle mutation {offset}"
            );
        }
        for offset in 0..expected.len() {
            let mut wrong_digest = expected;
            wrong_digest[offset] ^= 1;
            assert!(
                BackupBundleV1::from_preimage_and_digest(&canonical_bundle, wrong_digest).is_err(),
                "bundle digest mutation {offset}"
            );
        }
        Ok(())
    }

    #[test]
    fn independent_backup_domain_kats_are_frozen() -> Result<(), CanonicalCodecError> {
        let manifest = BackupManifestV1::from_bytes(&backup_manifest()?)?;
        assert_eq!(manifest.contract_wallet_id(), &[0x11; 32]);
        assert_eq!(manifest.source_vault_id(), &[0x22; 32]);
        assert_eq!(manifest.backup_id(), &[0x33; 32]);
        assert_eq!(manifest.source_epoch(), 7);
        assert_eq!(manifest.source_journal_sequence(), 0);
        assert_eq!(manifest.source_journal_head_digest(), &[0; 32]);
        assert_eq!(manifest.record_count(), 0);
        assert_eq!(manifest.record_set_digest(), &[0x55; 32]);
        assert_eq!(manifest.backup_generation(), 1);
        assert_eq!(
            manifest.manifest_digest(),
            &[
                0xe5, 0x9a, 0x57, 0xa3, 0x02, 0x7e, 0x1e, 0xfc, 0x8a, 0xa8, 0xfa, 0xcc, 0xaf, 0xf6,
                0xc3, 0xd8, 0x42, 0xea, 0x12, 0x65, 0xe6, 0xd8, 0xa6, 0xbc, 0xfe, 0xf6, 0x1a, 0x7c,
                0xe0, 0x82, 0x4e, 0x8c,
            ]
        );
        let bundle = BackupBundleV1::from_preimage(&bundle_preimage()?)?;
        assert_eq!(bundle.backup_id(), &[0x33; 32]);
        assert_eq!(bundle.backup_generation(), 1);
        assert_eq!(bundle.backup_master_envelope_digest(), &[0x44; 32]);
        assert_eq!(bundle.backup_manifest_object_envelope_digest(), &[0x55; 32]);
        assert_eq!(bundle.source_journal_sequence(), 0);
        assert_eq!(bundle.source_journal_head_digest(), &[0; 32]);
        assert_eq!(bundle.source_record_count(), 0);
        assert_eq!(bundle.source_record_set_digest(), &[0x66; 32]);
        assert_eq!(
            bundle.bundle_digest(),
            &[
                0xbe, 0x19, 0xb9, 0x17, 0x30, 0xa6, 0xbc, 0xdd, 0x17, 0x39, 0x8b, 0xf6, 0xfa, 0xb6,
                0xa6, 0xdf, 0xe7, 0x91, 0x2a, 0x2b, 0x0c, 0xb3, 0x4e, 0xd3, 0x2b, 0xbc, 0x71, 0xd0,
                0x33, 0xe2, 0xb8, 0x84,
            ]
        );
        assert!(
            BackupBundleV1::from_preimage_and_digest(bundle.preimage(), *bundle.bundle_digest())?
                == bundle
        );
        let root = RestoreOnlyRootV1::from_bytes(&restore_only_root()?)?;
        assert_eq!(root.contract_wallet_id(), &[0x11; 32]);
        assert_eq!(root.store_root_id(), &[0x22; 32]);
        assert_eq!(root.lock_instance_id(), &[0x33; 16]);
        assert_eq!(root.source_backup_bundle_digest(), &[0x44; 32]);
        assert_eq!(root.restore_initialization_id(), &[0x55; 16]);
        assert_eq!(
            root.restore_only_root_digest(),
            &[
                0xf3, 0x5c, 0xe8, 0x3a, 0x37, 0x17, 0xc0, 0x3a, 0x20, 0x9e, 0xd8, 0x81, 0xf4, 0x1b,
                0xcb, 0xca, 0x67, 0x24, 0x48, 0xaf, 0x5a, 0x9f, 0x52, 0x7f, 0xb7, 0x6f, 0x18, 0x6b,
                0x60, 0xf5, 0x24, 0xcd,
            ]
        );
        let pending = RestorePendingIndexV1::from_bytes(&pending_index()?)?;
        assert_eq!(
            pending.pending_index_digest(),
            &[
                0x62, 0x56, 0xa5, 0x51, 0x03, 0xb7, 0xf0, 0xa6, 0xc8, 0xe3, 0x17, 0x00, 0x2b, 0xa6,
                0x0a, 0x3e, 0xd7, 0xad, 0x1f, 0x88, 0x35, 0xed, 0x86, 0x92, 0x91, 0xf3, 0x07, 0x82,
                0xbe, 0x74, 0x33, 0x37,
            ]
        );
        let fields = pending.fields();
        assert_eq!(fields.restore_transaction_id, [0x11; 16]);
        assert_eq!(fields.contract_wallet_id, [0x22; 32]);
        assert_eq!(fields.source_journal_sequence, 0);
        assert_eq!(fields.source_journal_head_digest, [0; 32]);
        assert_eq!(fields.successor_final_journal_sequence, 4);
        assert_eq!(fields.restore_only_root_digest, [0; 32]);
        Ok(())
    }
}

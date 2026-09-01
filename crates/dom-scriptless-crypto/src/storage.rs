//! Independent DOM Contracts storage-cryptography profile.

use argon2::{Algorithm, Argon2, Block as ArgonBlock, Params, Version};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use dom_adaptor::{
    audit_nonce_secret_plaintext_v1, NonceSecretTransferV1, PurposeV1,
    VaultSecretImportCapabilityV1, VaultSecretSealCapabilityV1,
};
use sha2::{compress256, digest::core_api::Block};
use std::{error::Error, fmt};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

mod collaborative;
pub use collaborative::{
    acknowledge_pending_shared_blinding_backup_v1, acknowledge_shared_blinding_backup_v1,
    audit_collaborative_secret_envelope_v1, open_collaborative_bp_finalize_record_v1,
    open_collaborative_bp_nonce_record_v1, open_collaborative_bp_proof_record_v1,
    open_collaborative_bp_round2_record_v1, open_pending_shared_blinding_record_v1,
    open_shared_blinding_record_v1, open_shared_blinding_recovery_capsule_v1,
    seal_collaborative_bp_nonce_record_v1, seal_collaborative_bp_proof_record_v1,
    seal_collaborative_bp_round2_bundle_v1, seal_shared_blinding_bundle_v1,
    upgrade_shared_blinding_bundle_restartable_v1, upgrade_shared_blinding_bundle_v1,
    CollaborativeSecretEnvelopeV1, SealedCollaborativeBpProofV1,
    SealedCollaborativeBpRound2BundleV1, SealedSharedBlindingBundleV1,
};

const MASTER_ENVELOPE_LEN: usize = 182;
const OBJECT_HEADER_LEN: usize = 224;
const AEAD_TAG_LEN: usize = 16;
const NONCE_RECORD_MIN: usize = NonceSecretTransferV1::MIN_ENCODED_LEN;
const NONCE_RECORD_MAX: usize = NonceSecretTransferV1::MAX_ENCODED_LEN;
const TOMBSTONE_RECORD_LEN: usize = 255;
const BACKUP_MANIFEST_LEN: usize = 230;
const MASTER_MAGIC: &[u8; 8] = b"DOMCVMK1";
const OBJECT_MAGIC: &[u8; 8] = b"DOMCVOB1";
const TOMBSTONE_MAGIC: &[u8; 8] = b"DOMNVTS1";
const BACKUP_MANIFEST_MAGIC: &[u8; 8] = b"DOMNVBM1";
const UNLOCK_LABEL: &str = "DOM:contracts-vault-unlock-kek:v1";
const MASTER_AAD_LABEL: &str = "DOM:contracts-vault-master-wrap:v1";
const SECRET_ROLE_LABEL: &str = "DOM:contracts-vault-secret-record-key:v1";
const TOMBSTONE_ROLE_LABEL: &str = "DOM:contracts-vault-tombstone-key:v1";
const BACKUP_ROLE_LABEL: &str = "DOM:contracts-vault-backup-key:v1";
const OBJECT_AAD_LABEL: &str = "DOM:contracts-vault-envelope-aad:v1";

/// A storage-cryptography failure that carries no secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// A passphrase violates the fixed V1 length policy.
    InvalidPassphrase,
    /// A public storage identifier is zero, duplicated, or mismatched.
    InvalidIdentifier,
    /// Randomness was unavailable or produced a prohibited identifier/key.
    RandomFailure,
    /// The fixed Argon2id or HKDF operation failed.
    KeyDerivationFailed,
    /// An envelope is malformed, noncanonical, mismatched, or unsupported.
    InvalidEnvelope,
    /// AEAD authentication failed.
    AuthenticationFailed,
    /// A nonce-secret plaintext length is outside its canonical range.
    InvalidPlaintext,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPassphrase => "invalid passphrase",
            Self::InvalidIdentifier => "invalid storage identifier",
            Self::RandomFailure => "secure randomness unavailable",
            Self::KeyDerivationFailed => "key derivation failed",
            Self::InvalidEnvelope => "invalid storage envelope",
            Self::AuthenticationFailed => "storage envelope authentication failed",
            Self::InvalidPlaintext => "invalid canonical plaintext",
        })
    }
}

impl Error for CryptoError {}

/// Closed registry of ratified DOM Contracts storage hash domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageHashDomainV1 {
    /// Complete reservation-context bindings.
    ReservationContext,
    /// Complete reservation bindings used by a persistent Nonce Vault.
    ReservationBinding,
    /// Canonical reservation-authority records.
    ReservationAuthority,
    /// Immutable local-profile budget policies.
    BudgetPolicy,
    /// Append-only local-profile budget charges.
    BudgetCharge,
    /// Lifetime permit-retirement evidence.
    PermitRetirement,
    /// Signing-key budget identifiers.
    BudgetKey,
    /// Stable counterparty budget buckets.
    Counterparty,
    /// Public lookup identifiers for already-spent exports.
    ExportPermitId,
    /// Lifetime session-claim records.
    SessionClaim,
    /// Durable computation-attempt records.
    Attempt,
    /// Immutable exposure records and their outbound bytes.
    Exposure,
    /// Predecessor-linked append-only journal entries.
    JournalEntry,
    /// Canonically ordered restore record sets.
    RecordSet,
    /// Restore transaction manifests.
    RestoreManifest,
    /// Restore completion records.
    RestoreComplete,
    /// Irreversible tombstone records.
    Tombstone,
    /// Complete authenticated object envelopes.
    ObjectEnvelope,
    /// Global backup manifests.
    BackupManifest,
    /// Complete backup bundles.
    BackupBundle,
    /// Retained store-root identity records.
    StoreRootIdentity,
    /// Retained store-lock identity records.
    StoreLockIdentity,
    /// Immutable vault-generation core records.
    VaultGenerationCore,
    /// Active vault-generation projection records.
    ActiveVaultGeneration,
    /// Master-key envelope digests.
    MasterEnvelope,
    /// Canonical tombstone-envelope sets.
    TombstoneEnvelopeSet,
    /// Pending-restore index records.
    RestorePendingIndex,
    /// New-device restore-only root records.
    RestoreOnlyRoot,
    /// Durable per-session contract records (spec §10.1 `SessionRecordV1`):
    /// the finalized bytes that are the authority for 3.3 atomic persistence.
    SessionRecord,
}

impl StorageHashDomainV1 {
    const fn tag(self) -> &'static str {
        match self {
            Self::ReservationContext => "DOM:contracts-vault-reservation-context:v1",
            Self::ReservationBinding => "DOM:contracts-vault-reservation-binding:v1",
            Self::ReservationAuthority => "DOM:contracts-vault-reservation-authority:v1",
            Self::BudgetPolicy => "DOM:contracts-vault-budget-policy:v1",
            Self::BudgetCharge => "DOM:contracts-vault-budget-charge:v1",
            Self::PermitRetirement => "DOM:contracts-vault-permit-retirement:v1",
            Self::BudgetKey => "DOM:scriptless-vault-budget-key:v1",
            Self::Counterparty => "DOM:scriptless-vault-counterparty:v1",
            Self::ExportPermitId => "DOM:contracts-vault-export-permit-id:v1",
            Self::SessionClaim => "DOM:contracts-vault-session-claim:v1",
            Self::Attempt => "DOM:contracts-vault-attempt:v1",
            Self::Exposure => "DOM:contracts-vault-exposure:v1",
            Self::JournalEntry => "DOM:contracts-vault-journal-entry:v1",
            Self::RecordSet => "DOM:contracts-vault-record-set:v1",
            Self::RestoreManifest => "DOM:contracts-vault-restore-manifest:v1",
            Self::RestoreComplete => "DOM:contracts-vault-restore-complete:v1",
            Self::Tombstone => "DOM:contracts-vault-tombstone:v1",
            Self::ObjectEnvelope => "DOM:contracts-vault-object-envelope:v1",
            Self::BackupManifest => "DOM:contracts-vault-backup-manifest:v1",
            Self::BackupBundle => "DOM:contracts-vault-backup-bundle:v1",
            Self::StoreRootIdentity => "DOM:contracts-store-root-identity:v1",
            Self::StoreLockIdentity => "DOM:contracts-store-lock-identity:v1",
            Self::VaultGenerationCore => "DOM:contracts-vault-generation-core:v1",
            Self::ActiveVaultGeneration => "DOM:contracts-vault-active-generation:v1",
            Self::MasterEnvelope => "DOM:contracts-vault-master-envelope:v1",
            Self::TombstoneEnvelopeSet => "DOM:contracts-vault-tombstone-envelope-set:v1",
            Self::RestorePendingIndex => "DOM:contracts-vault-restore-pending-index:v1",
            Self::RestoreOnlyRoot => "DOM:contracts-vault-restore-only-root:v1",
            Self::SessionRecord => "DOM:contracts-store-session-record:v1",
        }
    }
}

/// Delegates a closed storage-domain hash to the pinned authoritative DOM backend.
pub fn authoritative_storage_hash_v1(domain: StorageHashDomainV1, data: &[u8]) -> [u8; 32] {
    *dom_crypto::blake2b_256_tagged(domain.tag(), data).as_bytes()
}

/// Independent public identities for one Contracts wallet and vault.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StorageIdsV1 {
    contract_wallet_id: [u8; 32],
    vault_id: [u8; 32],
}

impl StorageIdsV1 {
    /// Validates nonzero, distinct public storage identifiers.
    pub fn new(contract_wallet_id: [u8; 32], vault_id: [u8; 32]) -> Result<Self, CryptoError> {
        if is_zero(&contract_wallet_id) || is_zero(&vault_id) || contract_wallet_id == vault_id {
            return Err(CryptoError::InvalidIdentifier);
        }
        Ok(Self {
            contract_wallet_id,
            vault_id,
        })
    }

    /// Returns the public Contracts wallet storage identifier.
    pub fn contract_wallet_id(&self) -> &[u8; 32] {
        &self.contract_wallet_id
    }

    /// Returns the public vault identifier.
    pub fn vault_id(&self) -> &[u8; 32] {
        &self.vault_id
    }
}

/// Generates independent public storage identifiers from the operating-system CSPRNG.
pub fn generate_storage_ids() -> Result<StorageIdsV1, CryptoError> {
    generate_storage_ids_with(&mut OsRandom)
}

/// An owned, non-cloneable, zeroizing UTF-8 passphrase byte buffer.
pub struct Passphrase {
    bytes: Zeroizing<Vec<u8>>,
}

impl Passphrase {
    /// Takes ownership of UTF-8 bytes and enforces the V1 `8..=1024` byte range.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        let bytes = Zeroizing::new(bytes);
        if !(8..=1024).contains(&bytes.len()) || std::str::from_utf8(bytes.as_slice()).is_err() {
            return Err(CryptoError::InvalidPassphrase);
        }
        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// A non-cloneable, non-serializable, zeroizing vault master key.
pub struct VaultMasterKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl VaultMasterKey {
    #[cfg(test)]
    fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        let bytes = Zeroizing::new(bytes);
        if secret_is_zero_32(&bytes) {
            return Err(CryptoError::RandomFailure);
        }
        Ok(Self { bytes })
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Confirms that the pinned authoritative DOM adapter and tagged-hash backend are linked.
pub fn authoritative_backend_status() -> Result<(), CryptoError> {
    let _ = authoritative_storage_hash_v1(StorageHashDomainV1::SessionClaim, &[]);
    let _ = parse_purpose(PurposeV1::Refund.to_byte())?;
    Ok(())
}

/// Generates a nonzero vault master key from the operating-system CSPRNG.
pub fn generate_vault_master_key() -> Result<VaultMasterKey, CryptoError> {
    generate_vault_master_key_with(&mut OsRandom)
}

/// The exact public 182-byte V1 master-key envelope.
pub struct VaultMasterKeyEnvelopeV1 {
    bytes: [u8; MASTER_ENVELOPE_LEN],
}

impl VaultMasterKeyEnvelopeV1 {
    /// Parses and structurally validates an exact V1 envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != MASTER_ENVELOPE_LEN {
            return Err(CryptoError::InvalidEnvelope);
        }
        let mut fixed = [0_u8; MASTER_ENVELOPE_LEN];
        fixed.copy_from_slice(bytes);
        validate_master_header(&fixed)?;
        Ok(Self { bytes: fixed })
    }

    /// Borrows the exact public envelope bytes.
    pub fn as_bytes(&self) -> &[u8; MASTER_ENVELOPE_LEN] {
        &self.bytes
    }
}

/// Seals a master key using fixed Argon2id/HKDF parameters and internal OS randomness.
pub fn seal_master_key(
    ids: StorageIdsV1,
    passphrase: &Passphrase,
    master_key: &VaultMasterKey,
) -> Result<VaultMasterKeyEnvelopeV1, CryptoError> {
    seal_master_key_with(ids, passphrase, master_key, &mut OsRandom)
}

/// Opens a master-key envelope only for the exact expected public identities.
pub fn open_master_key(
    envelope: &VaultMasterKeyEnvelopeV1,
    expected_ids: StorageIdsV1,
    passphrase: &Passphrase,
) -> Result<VaultMasterKey, CryptoError> {
    validate_master_header(&envelope.bytes)?;
    if envelope.bytes[12..44] != expected_ids.contract_wallet_id
        || envelope.bytes[44..76] != expected_ids.vault_id
    {
        return Err(CryptoError::InvalidIdentifier);
    }

    let mut salt = [0_u8; 32];
    salt.copy_from_slice(&envelope.bytes[76..108]);
    let kek = derive_kek(passphrase, &salt, expected_ids)?;
    let cipher = ChaCha20Poly1305::new((&*kek).into());
    let nonce: [u8; 12] = envelope.bytes[120..132]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let aad = tagged_bytes(MASTER_AAD_LABEL, &envelope.bytes[..134])?;
    let mut plaintext = Zeroizing::new([0_u8; 32]);
    plaintext.copy_from_slice(&envelope.bytes[134..166]);
    let tag: [u8; AEAD_TAG_LEN] = envelope.bytes[166..182]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    cipher
        .decrypt_in_place_detached((&nonce).into(), &aad, plaintext.as_mut(), (&tag).into())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    if secret_is_zero_32(&plaintext) {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(VaultMasterKey { bytes: plaintext })
}

/// Closed object-key roles for V1 storage envelopes.
#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum KeyRoleV1 {
    /// Nonce secret record encryption.
    SecretRecord = 0x01,
    /// Tombstone record encryption.
    Tombstone = 0x02,
    /// Backup manifest encryption.
    Backup = 0x03,
}

impl TryFrom<u8> for KeyRoleV1 {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SecretRecord),
            2 => Ok(Self::Tombstone),
            3 => Ok(Self::Backup),
            _ => Err(CryptoError::InvalidEnvelope),
        }
    }
}

impl KeyRoleV1 {
    fn hkdf_label(self) -> &'static str {
        match self {
            Self::SecretRecord => SECRET_ROLE_LABEL,
            Self::Tombstone => TOMBSTONE_ROLE_LABEL,
            Self::Backup => BACKUP_ROLE_LABEL,
        }
    }
}

/// Closed V1 encrypted-record kinds.
#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RecordKindV1 {
    /// Canonical nonce secret record.
    NonceSecretRecord = 0x01,
    /// Canonical irreversible tombstone.
    Tombstone = 0x02,
    /// Canonical global backup manifest.
    BackupManifest = 0x03,
}

impl TryFrom<u8> for RecordKindV1 {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::NonceSecretRecord),
            2 => Ok(Self::Tombstone),
            3 => Ok(Self::BackupManifest),
            _ => Err(CryptoError::InvalidEnvelope),
        }
    }
}

/// Owned public metadata for one encrypted nonce secret record.
///
/// The type is intentionally non-cloneable so a caller must construct the
/// exact expected context for each seal or open operation. `Sponsor` remains a
/// structurally recognized canonical codec value for quarantine, but this
/// production metadata boundary rejects it under the pinned strict Phase 1
/// policy.
///
/// ```compile_fail
/// use dom_scriptless_crypto::NonceSecretRecordMetadataV1;
///
/// fn duplicate(metadata: NonceSecretRecordMetadataV1) {
///     let _second = metadata.clone();
/// }
/// ```
pub struct NonceSecretRecordMetadataV1 {
    nonce_epoch: u64,
    session_id: [u8; 32],
    participant_id: [u8; 32],
    purpose: PurposeV1,
    revision: u64,
    bound_digest: [u8; 32],
}

/// Closed, authenticated 255-byte `TombstoneV1` envelope plaintext.
///
/// This type validates only the already-ratified canonical byte format at the
/// cryptographic boundary. It intentionally exposes no lifecycle constructor:
/// the Store remains the sole authority that selects terminal evidence and
/// creates canonical tombstones.
pub struct TombstonePlaintextV1 {
    bytes: Zeroizing<[u8; TOMBSTONE_RECORD_LEN]>,
}

impl TombstonePlaintextV1 {
    /// Parses the exact canonical tombstone bytes and authenticates their digest.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != TOMBSTONE_RECORD_LEN {
            return Err(CryptoError::InvalidPlaintext);
        }
        let mut bytes = Zeroizing::new([0_u8; TOMBSTONE_RECORD_LEN]);
        bytes.copy_from_slice(input);
        validate_tombstone_plaintext(&bytes)?;
        Ok(Self { bytes })
    }

    /// Borrows the exact canonical bytes for Store-side canonical reparsing.
    pub fn as_bytes(&self) -> &[u8; TOMBSTONE_RECORD_LEN] {
        &self.bytes
    }
}

/// Owned expected public metadata for one encrypted canonical tombstone.
///
/// The header binding is derived from the tombstone identity and terminal
/// revision. Its `bound_digest` is the authenticated tombstone digest, not the
/// nonce identity's context-bound digest.
pub struct TombstoneRecordMetadataV1 {
    nonce_epoch: u64,
    session_id: [u8; 32],
    participant_id: [u8; 32],
    purpose: PurposeV1,
    revision: u64,
    tombstone_digest: [u8; 32],
}

/// Closed, authenticated 230-byte `BackupManifestV1` envelope plaintext.
///
/// The type owns and zeroizes the complete manifest and exposes it only as the
/// exact canonical byte array required by the Store's canonical parser. It has
/// no generic plaintext or serialization conversion.
pub struct BackupManifestPlaintextV1 {
    bytes: Zeroizing<[u8; BACKUP_MANIFEST_LEN]>,
}

impl BackupManifestPlaintextV1 {
    /// Parses the exact canonical backup manifest and authenticates its digest.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != BACKUP_MANIFEST_LEN {
            return Err(CryptoError::InvalidPlaintext);
        }
        let mut bytes = Zeroizing::new([0_u8; BACKUP_MANIFEST_LEN]);
        bytes.copy_from_slice(input);
        validate_backup_manifest_plaintext(&bytes)?;
        Ok(Self { bytes })
    }

    /// Borrows the exact authenticated bytes for Store-side canonical reparsing.
    pub fn as_bytes(&self) -> &[u8; BACKUP_MANIFEST_LEN] {
        &self.bytes
    }
}

/// Owned expected public metadata for one encrypted global backup manifest.
///
/// The all-zero session, participant, and purpose sentinel fields are fixed by
/// the record kind and therefore cannot be supplied by the caller.
pub struct BackupManifestMetadataV1 {
    ids: StorageIdsV1,
    source_nonce_epoch: u64,
    backup_generation: u64,
    manifest_digest: [u8; 32],
}

impl BackupManifestMetadataV1 {
    /// Constructs the exact expected global backup-envelope metadata.
    pub fn new(
        ids: StorageIdsV1,
        source_nonce_epoch: u64,
        backup_generation: u64,
        manifest_digest: [u8; 32],
    ) -> Result<Self, CryptoError> {
        if source_nonce_epoch == 0 || backup_generation == 0 || is_zero(&manifest_digest) {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(Self {
            ids,
            source_nonce_epoch,
            backup_generation,
            manifest_digest,
        })
    }

    /// Derives the only valid envelope metadata for canonical manifest bytes.
    pub fn from_manifest(manifest: &BackupManifestPlaintextV1) -> Result<Self, CryptoError> {
        let bytes = manifest.as_bytes();
        let mut contract_wallet_id = [0_u8; 32];
        contract_wallet_id.copy_from_slice(&bytes[10..42]);
        let mut source_vault_id = [0_u8; 32];
        source_vault_id.copy_from_slice(&bytes[42..74]);
        let ids = StorageIdsV1::new(contract_wallet_id, source_vault_id)?;
        let source_nonce_epoch = read_u64(&bytes[106..114]);
        let backup_generation = read_u64(&bytes[190..198]);
        let mut manifest_digest = [0_u8; 32];
        manifest_digest.copy_from_slice(&bytes[198..230]);
        Self::new(ids, source_nonce_epoch, backup_generation, manifest_digest)
    }

    fn matches_manifest(&self, manifest: &BackupManifestPlaintextV1) -> bool {
        Self::from_manifest(manifest).is_ok_and(|derived| {
            self.ids == derived.ids
                && self.source_nonce_epoch == derived.source_nonce_epoch
                && self.backup_generation == derived.backup_generation
                && self.manifest_digest == derived.manifest_digest
        })
    }
}

impl TombstoneRecordMetadataV1 {
    /// Constructs exact expected tombstone-envelope metadata.
    pub fn new(
        nonce_epoch: u64,
        session_id: [u8; 32],
        participant_id: [u8; 32],
        purpose: PurposeV1,
        revision: u64,
        tombstone_digest: [u8; 32],
    ) -> Result<Self, CryptoError> {
        if nonce_epoch == 0
            || revision == 0
            || is_zero(&session_id)
            || is_zero(&participant_id)
            || is_zero(&tombstone_digest)
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        purpose
            .require_strict_phase1()
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        Ok(Self {
            nonce_epoch,
            session_id,
            participant_id,
            purpose,
            revision,
            tombstone_digest,
        })
    }

    /// Derives the only valid envelope metadata for canonical tombstone bytes.
    pub fn from_tombstone(tombstone: &TombstonePlaintextV1) -> Result<Self, CryptoError> {
        let bytes = tombstone.as_bytes();
        let mut session_id = [0_u8; 32];
        session_id.copy_from_slice(&bytes[10..42]);
        let mut participant_id = [0_u8; 32];
        participant_id.copy_from_slice(&bytes[42..74]);
        let purpose = parse_purpose(bytes[74])?;
        let nonce_epoch = read_u64(&bytes[107..115]);
        let revision = read_u64(&bytes[119..127]);
        let mut tombstone_digest = [0_u8; 32];
        tombstone_digest.copy_from_slice(&bytes[223..255]);
        Self::new(
            nonce_epoch,
            session_id,
            participant_id,
            purpose,
            revision,
            tombstone_digest,
        )
    }

    fn matches_tombstone(&self, tombstone: &TombstonePlaintextV1) -> bool {
        Self::from_tombstone(tombstone).is_ok_and(|derived| {
            self.nonce_epoch == derived.nonce_epoch
                && self.session_id == derived.session_id
                && self.participant_id == derived.participant_id
                && self.purpose == derived.purpose
                && self.revision == derived.revision
                && self.tombstone_digest == derived.tombstone_digest
        })
    }
}

impl NonceSecretRecordMetadataV1 {
    /// Takes ownership of and validates every fixed public header field.
    pub fn new(
        nonce_epoch: u64,
        session_id: [u8; 32],
        participant_id: [u8; 32],
        purpose: PurposeV1,
        revision: u64,
        bound_digest: [u8; 32],
    ) -> Result<Self, CryptoError> {
        if nonce_epoch == 0
            || revision == 0
            || is_zero(&session_id)
            || is_zero(&participant_id)
            || is_zero(&bound_digest)
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        purpose
            .require_strict_phase1()
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        Ok(Self {
            nonce_epoch,
            session_id,
            participant_id,
            purpose,
            revision,
            bound_digest,
        })
    }
}

/// Public structurally validated ciphertext bytes for one V1 storage object.
///
/// Parsing validates the bounded public envelope structure but does not by
/// itself authenticate the ciphertext. Authentication occurs only through a
/// record-kind-specific open operation holding the matching master key and
/// adaptor import capability.
pub struct VaultObjectEnvelopeV1 {
    bytes: Vec<u8>,
    key_role: KeyRoleV1,
    record_kind: RecordKindV1,
    plaintext_len: usize,
    complete_len: u32,
}

impl VaultObjectEnvelopeV1 {
    /// Parses the exact bounded structure of a supported V1 object envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let header = parse_object_header(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            key_role: header.key_role,
            record_kind: header.record_kind,
            plaintext_len: header.plaintext_len,
            complete_len: header.complete_len,
        })
    }

    /// Borrows the exact header, ciphertext, and tag bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the validated closed object-key role.
    pub fn key_role(&self) -> KeyRoleV1 {
        self.key_role
    }

    /// Returns the validated closed record kind.
    pub fn record_kind(&self) -> RecordKindV1 {
        self.record_kind
    }

    /// Returns the structurally declared, unauthenticated plaintext length.
    pub fn structural_plaintext_len(&self) -> usize {
        self.plaintext_len
    }

    /// Computes the authoritative digest of the length-prefixed complete envelope.
    pub fn digest(&self) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(4 + self.bytes.len());
        preimage.extend_from_slice(&self.complete_len.to_le_bytes());
        preimage.extend_from_slice(&self.bytes);
        authoritative_storage_hash_v1(StorageHashDomainV1::ObjectEnvelope, &preimage)
    }
}

/// Seals one opaque adaptor nonce secret under the exact V1 secret-record profile.
///
/// The caller cannot obtain plaintext: both the transfer and one-shot seal
/// capability are consumed, and randomness is sourced only from the operating
/// system.
pub fn seal_nonce_secret_record(
    ids: StorageIdsV1,
    master_key: &VaultMasterKey,
    metadata: NonceSecretRecordMetadataV1,
    secret: NonceSecretTransferV1,
    seal_capability: VaultSecretSealCapabilityV1,
) -> Result<VaultObjectEnvelopeV1, CryptoError> {
    let plaintext = seal_capability.into_plaintext(secret);
    let mut instance_id = [0_u8; 16];
    let mut nonce_bytes = [0_u8; 12];
    OsRandom.fill(&mut instance_id)?;
    OsRandom.fill(&mut nonce_bytes)?;
    seal_nonce_secret_plaintext(
        ids,
        master_key,
        &metadata,
        plaintext,
        instance_id,
        nonce_bytes,
    )
}

/// Authenticates and opens one V1 nonce secret into an opaque adaptor transfer.
///
/// The exact expected metadata is consumed. Opened plaintext remains inside an
/// owned zeroizing buffer and is released only through the adaptor's one-shot
/// import capability.
pub fn open_nonce_secret_record(
    envelope: &VaultObjectEnvelopeV1,
    expected_ids: StorageIdsV1,
    master_key: &VaultMasterKey,
    expected: NonceSecretRecordMetadataV1,
    import_capability: VaultSecretImportCapabilityV1,
) -> Result<NonceSecretTransferV1, CryptoError> {
    let plaintext = open_nonce_secret_plaintext(envelope, expected_ids, master_key, &expected)?;
    import_capability
        .import(plaintext)
        .map_err(|_| CryptoError::InvalidPlaintext)
}

/// Authenticates and audits one V1 nonce-secret envelope without exporting
/// plaintext, a transfer, or an adaptor import capability.
///
/// AEAD authentication and exact metadata binding are completed before the
/// consuming adaptor audit validates the canonical plaintext structure. The
/// decrypted buffer is zeroized on every return path.
pub fn audit_nonce_secret_record(
    envelope: &VaultObjectEnvelopeV1,
    expected_ids: StorageIdsV1,
    master_key: &VaultMasterKey,
    expected: NonceSecretRecordMetadataV1,
) -> Result<(), CryptoError> {
    let plaintext = open_nonce_secret_plaintext(envelope, expected_ids, master_key, &expected)?;
    audit_nonce_secret_plaintext_v1(plaintext).map_err(|_| CryptoError::InvalidPlaintext)
}

/// Seals one Store-authorized canonical tombstone under the exact V1 profile.
///
/// Random envelope instance and AEAD nonce bytes come only from the operating
/// system. The supplied metadata must be byte-for-byte derivable from the
/// authenticated tombstone plaintext.
pub fn seal_tombstone_v1(
    ids: StorageIdsV1,
    master_key: &VaultMasterKey,
    metadata: TombstoneRecordMetadataV1,
    tombstone: TombstonePlaintextV1,
) -> Result<VaultObjectEnvelopeV1, CryptoError> {
    let mut instance_id = [0_u8; 16];
    let mut nonce_bytes = [0_u8; 12];
    OsRandom.fill(&mut instance_id)?;
    OsRandom.fill(&mut nonce_bytes)?;
    seal_tombstone_plaintext(
        ids,
        master_key,
        &metadata,
        tombstone,
        instance_id,
        nonce_bytes,
    )
}

/// Authenticates and opens one exact V1 tombstone envelope.
///
/// The caller supplies only expected public metadata. Returned bytes have
/// already passed AEAD authentication and the closed canonical tombstone
/// parser, but the Store must still reparse them through its lifecycle-owned
/// `TombstoneV1` type before accepting state authority.
pub fn open_tombstone_v1(
    envelope: &VaultObjectEnvelopeV1,
    expected_ids: StorageIdsV1,
    master_key: &VaultMasterKey,
    expected: TombstoneRecordMetadataV1,
) -> Result<TombstonePlaintextV1, CryptoError> {
    let header = parse_object_header(&envelope.bytes)?;
    if header.key_role != KeyRoleV1::Tombstone
        || header.record_kind != RecordKindV1::Tombstone
        || header.ids != expected_ids
        || header.nonce_epoch != expected.nonce_epoch
        || header.session_id != expected.session_id
        || header.participant_id != expected.participant_id
        || header.purpose != Some(expected.purpose)
        || header.revision != expected.revision
        || header.bound_digest != expected.tombstone_digest
        || header.plaintext_len != TOMBSTONE_RECORD_LEN
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    expected
        .purpose
        .require_strict_phase1()
        .map_err(|_| CryptoError::InvalidEnvelope)?;

    let object_key = derive_object_key(
        master_key,
        expected_ids,
        KeyRoleV1::Tombstone,
        &envelope.bytes[..208],
    )?;
    let cipher = ChaCha20Poly1305::new((&*object_key).into());
    let nonce: [u8; 12] = envelope.bytes[208..220]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let aad = tagged_bytes(OBJECT_AAD_LABEL, &envelope.bytes[..OBJECT_HEADER_LEN])?;
    let ciphertext_end = OBJECT_HEADER_LEN + TOMBSTONE_RECORD_LEN;
    let mut plaintext = Zeroizing::new(envelope.bytes[OBJECT_HEADER_LEN..ciphertext_end].to_vec());
    let tag: [u8; AEAD_TAG_LEN] = envelope.bytes[ciphertext_end..ciphertext_end + AEAD_TAG_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    cipher
        .decrypt_in_place_detached(
            (&nonce).into(),
            &aad,
            plaintext.as_mut_slice(),
            (&tag).into(),
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let tombstone = TombstonePlaintextV1::from_bytes(plaintext.as_slice())?;
    if !expected.matches_tombstone(&tombstone) {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(tombstone)
}

/// Seals one Store-authorized canonical backup manifest under the exact V1 profile.
///
/// The metadata must be byte-for-byte derivable from the authenticated
/// manifest. Fresh envelope instance and AEAD nonce bytes come only from the
/// operating system.
pub fn seal_backup_manifest_v1(
    master_key: &VaultMasterKey,
    metadata: BackupManifestMetadataV1,
    manifest: BackupManifestPlaintextV1,
) -> Result<VaultObjectEnvelopeV1, CryptoError> {
    let mut instance_id = [0_u8; 16];
    let mut nonce_bytes = [0_u8; 12];
    OsRandom.fill(&mut instance_id)?;
    OsRandom.fill(&mut nonce_bytes)?;
    seal_backup_manifest_plaintext(master_key, &metadata, manifest, instance_id, nonce_bytes)
}

/// Authenticates and opens one exact V1 global backup-manifest envelope.
///
/// Returned bytes have passed AEAD authentication, manifest-digest validation,
/// and exact header-to-plaintext metadata binding. The Store must still reparse
/// them through its lifecycle-owned canonical backup type.
pub fn open_backup_manifest_v1(
    envelope: &VaultObjectEnvelopeV1,
    master_key: &VaultMasterKey,
    expected: BackupManifestMetadataV1,
) -> Result<BackupManifestPlaintextV1, CryptoError> {
    let header = parse_object_header(&envelope.bytes)?;
    if header.key_role != KeyRoleV1::Backup
        || header.record_kind != RecordKindV1::BackupManifest
        || header.ids != expected.ids
        || header.nonce_epoch != expected.source_nonce_epoch
        || header.session_id != [0_u8; 32]
        || header.participant_id != [0_u8; 32]
        || header.purpose.is_some()
        || header.revision != expected.backup_generation
        || header.bound_digest != expected.manifest_digest
        || header.plaintext_len != BACKUP_MANIFEST_LEN
    {
        return Err(CryptoError::InvalidEnvelope);
    }

    let object_key = derive_object_key(
        master_key,
        expected.ids,
        KeyRoleV1::Backup,
        &envelope.bytes[..208],
    )?;
    let cipher = ChaCha20Poly1305::new((&*object_key).into());
    let nonce: [u8; 12] = envelope.bytes[208..220]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let aad = tagged_bytes(OBJECT_AAD_LABEL, &envelope.bytes[..OBJECT_HEADER_LEN])?;
    let ciphertext_end = OBJECT_HEADER_LEN + BACKUP_MANIFEST_LEN;
    let mut plaintext = Zeroizing::new(envelope.bytes[OBJECT_HEADER_LEN..ciphertext_end].to_vec());
    let tag: [u8; AEAD_TAG_LEN] = envelope.bytes[ciphertext_end..ciphertext_end + AEAD_TAG_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    cipher
        .decrypt_in_place_detached(
            (&nonce).into(),
            &aad,
            plaintext.as_mut_slice(),
            (&tag).into(),
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let manifest = BackupManifestPlaintextV1::from_bytes(plaintext.as_slice())?;
    if !expected.matches_manifest(&manifest) {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(manifest)
}

fn open_nonce_secret_plaintext(
    envelope: &VaultObjectEnvelopeV1,
    expected_ids: StorageIdsV1,
    master_key: &VaultMasterKey,
    expected: &NonceSecretRecordMetadataV1,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let header = parse_nonce_header(&envelope.bytes)?;
    header
        .purpose
        .require_strict_phase1()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    if header.ids != expected_ids {
        return Err(CryptoError::InvalidIdentifier);
    }
    if header.nonce_epoch != expected.nonce_epoch
        || header.session_id != expected.session_id
        || header.participant_id != expected.participant_id
        || header.purpose != expected.purpose
        || header.revision != expected.revision
        || header.bound_digest != expected.bound_digest
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    let object_key = derive_object_key(
        master_key,
        expected_ids,
        header.key_role,
        &envelope.bytes[..208],
    )?;
    let cipher = ChaCha20Poly1305::new((&*object_key).into());
    let nonce: [u8; 12] = envelope.bytes[208..220]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let aad = tagged_bytes(OBJECT_AAD_LABEL, &envelope.bytes[..OBJECT_HEADER_LEN])?;
    let ciphertext_end = OBJECT_HEADER_LEN + header.plaintext_len;
    let mut plaintext = Zeroizing::new(envelope.bytes[OBJECT_HEADER_LEN..ciphertext_end].to_vec());
    let tag: [u8; AEAD_TAG_LEN] = envelope.bytes[ciphertext_end..ciphertext_end + AEAD_TAG_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    cipher
        .decrypt_in_place_detached(
            (&nonce).into(),
            &aad,
            plaintext.as_mut_slice(),
            (&tag).into(),
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(plaintext)
}

trait RandomSource {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError>;
}

struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
        getrandom::getrandom(destination).map_err(|_| CryptoError::RandomFailure)
    }
}

fn generate_storage_ids_with(rng: &mut impl RandomSource) -> Result<StorageIdsV1, CryptoError> {
    let mut contract_wallet_id = [0_u8; 32];
    let mut vault_id = [0_u8; 32];
    rng.fill(&mut contract_wallet_id)?;
    rng.fill(&mut vault_id)?;
    StorageIdsV1::new(contract_wallet_id, vault_id)
}

fn generate_vault_master_key_with(
    rng: &mut impl RandomSource,
) -> Result<VaultMasterKey, CryptoError> {
    let mut key = Zeroizing::new([0_u8; 32]);
    rng.fill(key.as_mut())?;
    if secret_is_zero_32(&key) {
        return Err(CryptoError::RandomFailure);
    }
    Ok(VaultMasterKey { bytes: key })
}

fn seal_master_key_with(
    ids: StorageIdsV1,
    passphrase: &Passphrase,
    master_key: &VaultMasterKey,
    rng: &mut impl RandomSource,
) -> Result<VaultMasterKeyEnvelopeV1, CryptoError> {
    let mut salt = [0_u8; 32];
    let mut nonce_bytes = [0_u8; 12];
    rng.fill(&mut salt)?;
    rng.fill(&mut nonce_bytes)?;
    let kek = derive_kek(passphrase, &salt, ids)?;

    let mut bytes = [0_u8; MASTER_ENVELOPE_LEN];
    bytes[..8].copy_from_slice(MASTER_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[10] = 1;
    bytes[11] = 1;
    bytes[12..44].copy_from_slice(ids.contract_wallet_id());
    bytes[44..76].copy_from_slice(ids.vault_id());
    bytes[76..108].copy_from_slice(&salt);
    bytes[108..112].copy_from_slice(&65_536_u32.to_le_bytes());
    bytes[112..116].copy_from_slice(&3_u32.to_le_bytes());
    bytes[116..120].copy_from_slice(&1_u32.to_le_bytes());
    bytes[120..132].copy_from_slice(&nonce_bytes);
    bytes[132..134].copy_from_slice(&48_u16.to_le_bytes());

    let cipher = ChaCha20Poly1305::new((&*kek).into());
    let nonce = (&nonce_bytes).into();
    let aad = tagged_bytes(MASTER_AAD_LABEL, &bytes[..134])?;
    let mut plaintext = Zeroizing::new([0_u8; 32]);
    plaintext.copy_from_slice(master_key.as_bytes());
    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, plaintext.as_mut())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    bytes[134..166].copy_from_slice(plaintext.as_ref());
    bytes[166..182].copy_from_slice(tag.as_ref());
    Ok(VaultMasterKeyEnvelopeV1 { bytes })
}

fn derive_kek(
    passphrase: &Passphrase,
    salt: &[u8; 32],
    ids: StorageIdsV1,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let argon_output = derive_argon_output(passphrase, salt)?;
    expand_unlock_kek(ids, salt, &argon_output)
}

fn expand_unlock_kek(
    ids: StorageIdsV1,
    salt: &[u8; 32],
    argon_output: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let info_tail = [ids.contract_wallet_id.as_slice(), ids.vault_id.as_slice()].concat();
    let info = tagged_bytes(UNLOCK_LABEL, &info_tail)?;
    derive_hkdf_sha256(salt, argon_output, &info)
}

fn derive_argon_output(
    passphrase: &Passphrase,
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let params =
        Params::new(65_536, 3, 1, Some(32)).map_err(|_| CryptoError::KeyDerivationFailed)?;
    let block_count = params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut argon_output = Zeroizing::new([0_u8; 32]);
    let mut matrix = Vec::new();
    matrix
        .try_reserve_exact(block_count)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    matrix.resize(block_count, ArgonBlock::default());
    let mut matrix = Zeroizing::new(matrix);
    argon
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            salt,
            argon_output.as_mut(),
            matrix.as_mut_slice(),
        )
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(argon_output)
}

fn validate_master_header(bytes: &[u8; MASTER_ENVELOPE_LEN]) -> Result<(), CryptoError> {
    if &bytes[..8] != MASTER_MAGIC
        || read_u16(&bytes[8..10]) != 1
        || bytes[10] != 1
        || bytes[11] != 1
        || is_zero(&bytes[12..44])
        || is_zero(&bytes[44..76])
        || bytes[12..44] == bytes[44..76]
        || read_u32(&bytes[108..112]) != 65_536
        || read_u32(&bytes[112..116]) != 3
        || read_u32(&bytes[116..120]) != 1
        || read_u16(&bytes[132..134]) != 48
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(())
}

fn seal_nonce_secret_plaintext(
    ids: StorageIdsV1,
    master_key: &VaultMasterKey,
    metadata: &NonceSecretRecordMetadataV1,
    mut plaintext: Zeroizing<Vec<u8>>,
    instance_id: [u8; 16],
    nonce_bytes: [u8; 12],
) -> Result<VaultObjectEnvelopeV1, CryptoError> {
    metadata
        .purpose
        .require_strict_phase1()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let plaintext_len = plaintext.len();
    if !(NonceSecretTransferV1::MIN_ENCODED_LEN..=NonceSecretTransferV1::MAX_ENCODED_LEN)
        .contains(&plaintext_len)
    {
        return Err(CryptoError::InvalidPlaintext);
    }
    let plaintext_len_u32 =
        u32::try_from(plaintext_len).map_err(|_| CryptoError::InvalidPlaintext)?;

    let mut header = [0_u8; OBJECT_HEADER_LEN];
    header[..8].copy_from_slice(OBJECT_MAGIC);
    header[8..10].copy_from_slice(&1_u16.to_le_bytes());
    header[10] = 1;
    header[11] = KeyRoleV1::SecretRecord as u8;
    header[12..14].copy_from_slice(&1_u16.to_le_bytes());
    header[14..46].copy_from_slice(ids.contract_wallet_id());
    header[46..78].copy_from_slice(ids.vault_id());
    header[78..86].copy_from_slice(&metadata.nonce_epoch.to_le_bytes());
    header[86..118].copy_from_slice(&metadata.session_id);
    header[118..150].copy_from_slice(&metadata.participant_id);
    header[150] = canonical_purpose_byte(metadata.purpose);
    header[151] = RecordKindV1::NonceSecretRecord as u8;
    header[152..160].copy_from_slice(&metadata.revision.to_le_bytes());
    header[160..192].copy_from_slice(&metadata.bound_digest);
    header[192..208].copy_from_slice(&instance_id);
    header[208..220].copy_from_slice(&nonce_bytes);
    header[220..224].copy_from_slice(&plaintext_len_u32.to_le_bytes());

    let object_key = derive_object_key(master_key, ids, KeyRoleV1::SecretRecord, &header[..208])?;
    let cipher = ChaCha20Poly1305::new((&*object_key).into());
    let aad = tagged_bytes(OBJECT_AAD_LABEL, &header)?;
    let nonce = (&nonce_bytes).into();
    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, plaintext.as_mut_slice())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut bytes = Vec::with_capacity(OBJECT_HEADER_LEN + plaintext_len + AEAD_TAG_LEN);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(plaintext.as_slice());
    bytes.extend_from_slice(tag.as_ref());
    VaultObjectEnvelopeV1::from_bytes(&bytes)
}

fn seal_tombstone_plaintext(
    ids: StorageIdsV1,
    master_key: &VaultMasterKey,
    metadata: &TombstoneRecordMetadataV1,
    tombstone: TombstonePlaintextV1,
    instance_id: [u8; 16],
    nonce_bytes: [u8; 12],
) -> Result<VaultObjectEnvelopeV1, CryptoError> {
    if !metadata.matches_tombstone(&tombstone) {
        return Err(CryptoError::InvalidEnvelope);
    }
    metadata
        .purpose
        .require_strict_phase1()
        .map_err(|_| CryptoError::InvalidEnvelope)?;

    let mut header = [0_u8; OBJECT_HEADER_LEN];
    header[..8].copy_from_slice(OBJECT_MAGIC);
    header[8..10].copy_from_slice(&1_u16.to_le_bytes());
    header[10] = 1;
    header[11] = KeyRoleV1::Tombstone as u8;
    header[12..14].copy_from_slice(&1_u16.to_le_bytes());
    header[14..46].copy_from_slice(ids.contract_wallet_id());
    header[46..78].copy_from_slice(ids.vault_id());
    header[78..86].copy_from_slice(&metadata.nonce_epoch.to_le_bytes());
    header[86..118].copy_from_slice(&metadata.session_id);
    header[118..150].copy_from_slice(&metadata.participant_id);
    header[150] = canonical_purpose_byte(metadata.purpose);
    header[151] = RecordKindV1::Tombstone as u8;
    header[152..160].copy_from_slice(&metadata.revision.to_le_bytes());
    header[160..192].copy_from_slice(&metadata.tombstone_digest);
    header[192..208].copy_from_slice(&instance_id);
    header[208..220].copy_from_slice(&nonce_bytes);
    header[220..224].copy_from_slice(&(TOMBSTONE_RECORD_LEN as u32).to_le_bytes());

    let object_key = derive_object_key(master_key, ids, KeyRoleV1::Tombstone, &header[..208])?;
    let cipher = ChaCha20Poly1305::new((&*object_key).into());
    let aad = tagged_bytes(OBJECT_AAD_LABEL, &header)?;
    let nonce = (&nonce_bytes).into();
    let mut plaintext = tombstone.bytes;
    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, plaintext.as_mut())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut bytes = Vec::with_capacity(OBJECT_HEADER_LEN + TOMBSTONE_RECORD_LEN + AEAD_TAG_LEN);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(plaintext.as_ref());
    bytes.extend_from_slice(tag.as_ref());
    VaultObjectEnvelopeV1::from_bytes(&bytes)
}

fn seal_backup_manifest_plaintext(
    master_key: &VaultMasterKey,
    metadata: &BackupManifestMetadataV1,
    manifest: BackupManifestPlaintextV1,
    instance_id: [u8; 16],
    nonce_bytes: [u8; 12],
) -> Result<VaultObjectEnvelopeV1, CryptoError> {
    if !metadata.matches_manifest(&manifest) {
        return Err(CryptoError::InvalidEnvelope);
    }

    let mut header = [0_u8; OBJECT_HEADER_LEN];
    header[..8].copy_from_slice(OBJECT_MAGIC);
    header[8..10].copy_from_slice(&1_u16.to_le_bytes());
    header[10] = 1;
    header[11] = KeyRoleV1::Backup as u8;
    header[12..14].copy_from_slice(&1_u16.to_le_bytes());
    header[14..46].copy_from_slice(metadata.ids.contract_wallet_id());
    header[46..78].copy_from_slice(metadata.ids.vault_id());
    header[78..86].copy_from_slice(&metadata.source_nonce_epoch.to_le_bytes());
    header[151] = RecordKindV1::BackupManifest as u8;
    header[152..160].copy_from_slice(&metadata.backup_generation.to_le_bytes());
    header[160..192].copy_from_slice(&metadata.manifest_digest);
    header[192..208].copy_from_slice(&instance_id);
    header[208..220].copy_from_slice(&nonce_bytes);
    header[220..224].copy_from_slice(&(BACKUP_MANIFEST_LEN as u32).to_le_bytes());

    let object_key =
        derive_object_key(master_key, metadata.ids, KeyRoleV1::Backup, &header[..208])?;
    let cipher = ChaCha20Poly1305::new((&*object_key).into());
    let aad = tagged_bytes(OBJECT_AAD_LABEL, &header)?;
    let nonce = (&nonce_bytes).into();
    let mut plaintext = manifest.bytes;
    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, plaintext.as_mut())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut bytes = Vec::with_capacity(OBJECT_HEADER_LEN + BACKUP_MANIFEST_LEN + AEAD_TAG_LEN);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(plaintext.as_ref());
    bytes.extend_from_slice(tag.as_ref());
    VaultObjectEnvelopeV1::from_bytes(&bytes)
}

fn derive_object_key(
    master_key: &VaultMasterKey,
    ids: StorageIdsV1,
    key_role: KeyRoleV1,
    header_prefix: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if header_prefix.len() != 208 {
        return Err(CryptoError::InvalidEnvelope);
    }
    let info = tagged_bytes(key_role.hkdf_label(), header_prefix)?;
    derive_hkdf_sha256(ids.vault_id(), master_key.as_bytes(), &info)
}

/// SHA-256 state whose persistent message block and chaining value are wiped.
///
/// Compression remains delegated to the pinned `sha2` implementation. Owning
/// the streaming state here avoids the non-zeroizing PRK/HMAC state retained by
/// `hkdf` 0.12 while keeping the standardized SHA-256 primitive unchanged.
struct WipingSha256 {
    state: Zeroizing<[u32; 8]>,
    block: Zeroizing<[u8; 64]>,
    block_len: usize,
    message_len: u64,
}

impl Zeroize for WipingSha256 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.block.zeroize();
        self.block_len.zeroize();
        self.message_len.zeroize();
    }
}

impl Drop for WipingSha256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for WipingSha256 {}

impl WipingSha256 {
    const INITIAL_STATE: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    fn new() -> Self {
        Self {
            state: Zeroizing::new(Self::INITIAL_STATE),
            block: Zeroizing::new([0_u8; 64]),
            block_len: 0,
            message_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) -> Result<(), CryptoError> {
        let input_len = u64::try_from(input.len()).map_err(|_| CryptoError::KeyDerivationFailed)?;
        self.message_len = self
            .message_len
            .checked_add(input_len)
            .ok_or(CryptoError::KeyDerivationFailed)?;

        while !input.is_empty() {
            let available = self.block.len() - self.block_len;
            let take = available.min(input.len());
            let end = self.block_len + take;
            self.block[self.block_len..end].copy_from_slice(&input[..take]);
            self.block_len = end;
            input = &input[take..];
            if self.block_len == self.block.len() {
                self.compress_block();
            }
        }
        Ok(())
    }

    fn finalize(mut self) -> Zeroizing<[u8; 32]> {
        let bit_len = self.message_len.wrapping_mul(8);
        self.block[self.block_len] = 0x80;
        self.block_len += 1;
        if self.block_len > 56 {
            self.block[self.block_len..].fill(0);
            self.compress_block();
        }
        self.block[self.block_len..56].fill(0);
        self.block[56..].copy_from_slice(&bit_len.to_be_bytes());
        self.block_len = self.block.len();
        self.compress_block();

        let mut digest = Zeroizing::new([0_u8; 32]);
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state.iter()) {
            let word_bytes = Zeroizing::new(word.to_be_bytes());
            chunk.copy_from_slice(word_bytes.as_ref());
        }
        digest
    }

    fn compress_block(&mut self) {
        let block = <&Block<sha2::Sha256>>::from(&*self.block);
        compress256(&mut self.state, std::slice::from_ref(block));
        self.block.zeroize();
        self.block_len = 0;
    }
}

fn hmac_sha256_wiping(
    key: &[u8; 32],
    message_parts: &[&[u8]],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut inner_pad = Zeroizing::new([0x36_u8; 64]);
    let mut outer_pad = Zeroizing::new([0x5c_u8; 64]);
    for ((inner, outer), key_byte) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(key.iter())
    {
        *inner ^= key_byte;
        *outer ^= key_byte;
    }

    let mut inner = WipingSha256::new();
    inner.update(inner_pad.as_ref())?;
    inner_pad.zeroize();
    for part in message_parts {
        inner.update(part)?;
    }
    let mut inner_digest = inner.finalize();

    let mut outer = WipingSha256::new();
    outer.update(outer_pad.as_ref())?;
    outer_pad.zeroize();
    outer.update(inner_digest.as_ref())?;
    inner_digest.zeroize();
    Ok(outer.finalize())
}

fn derive_hkdf_sha256(
    salt: &[u8; 32],
    ikm: &[u8; 32],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let prk = hmac_sha256_wiping(salt, &[ikm.as_slice()])?;
    let counter = [1_u8];
    hmac_sha256_wiping(&prk, &[info, &counter])
}

#[cfg(test)]
fn seal_nonce_secret_record_with(
    ids: StorageIdsV1,
    master_key: &VaultMasterKey,
    metadata: &NonceSecretRecordMetadataV1,
    plaintext: Zeroizing<Vec<u8>>,
    rng: &mut impl RandomSource,
) -> Result<VaultObjectEnvelopeV1, CryptoError> {
    if !(NonceSecretTransferV1::MIN_ENCODED_LEN..=NonceSecretTransferV1::MAX_ENCODED_LEN)
        .contains(&plaintext.len())
    {
        return Err(CryptoError::InvalidPlaintext);
    }
    let mut instance_id = [0_u8; 16];
    let mut nonce_bytes = [0_u8; 12];
    rng.fill(&mut instance_id)?;
    rng.fill(&mut nonce_bytes)?;
    seal_nonce_secret_plaintext(
        ids,
        master_key,
        metadata,
        plaintext,
        instance_id,
        nonce_bytes,
    )
}

struct ParsedObjectHeader {
    key_role: KeyRoleV1,
    record_kind: RecordKindV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    session_id: [u8; 32],
    participant_id: [u8; 32],
    purpose: Option<PurposeV1>,
    revision: u64,
    bound_digest: [u8; 32],
    plaintext_len: usize,
    complete_len: u32,
}

fn parse_object_header(bytes: &[u8]) -> Result<ParsedObjectHeader, CryptoError> {
    if bytes.len() < OBJECT_HEADER_LEN + AEAD_TAG_LEN {
        return Err(CryptoError::InvalidEnvelope);
    }
    if &bytes[..8] != OBJECT_MAGIC
        || read_u16(&bytes[8..10]) != 1
        || bytes[10] != 1
        || read_u16(&bytes[12..14]) != 1
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    let key_role = KeyRoleV1::try_from(bytes[11])?;
    let record_kind = RecordKindV1::try_from(bytes[151])?;
    let mut contract_wallet_id = [0_u8; 32];
    contract_wallet_id.copy_from_slice(&bytes[14..46]);
    let mut vault_id = [0_u8; 32];
    vault_id.copy_from_slice(&bytes[46..78]);
    let ids = StorageIdsV1::new(contract_wallet_id, vault_id)?;
    let nonce_epoch = read_u64(&bytes[78..86]);
    let mut session_id = [0_u8; 32];
    session_id.copy_from_slice(&bytes[86..118]);
    let mut participant_id = [0_u8; 32];
    participant_id.copy_from_slice(&bytes[118..150]);
    let purpose_byte = bytes[150];
    let revision = read_u64(&bytes[152..160]);
    let mut bound_digest = [0_u8; 32];
    bound_digest.copy_from_slice(&bytes[160..192]);
    let plaintext_len =
        usize::try_from(read_u32(&bytes[220..224])).map_err(|_| CryptoError::InvalidEnvelope)?;
    let expected_len = OBJECT_HEADER_LEN
        .checked_add(plaintext_len)
        .and_then(|value| value.checked_add(AEAD_TAG_LEN))
        .ok_or(CryptoError::InvalidEnvelope)?;
    let complete_len = u32::try_from(expected_len).map_err(|_| CryptoError::InvalidEnvelope)?;
    if nonce_epoch == 0 || revision == 0 || is_zero(&bound_digest) || bytes.len() != expected_len {
        return Err(CryptoError::InvalidEnvelope);
    }
    let purpose = match (key_role, record_kind) {
        (KeyRoleV1::SecretRecord, RecordKindV1::NonceSecretRecord) => {
            let purpose = parse_purpose(purpose_byte)?;
            if is_zero(&session_id)
                || is_zero(&participant_id)
                || !(NONCE_RECORD_MIN..=NONCE_RECORD_MAX).contains(&plaintext_len)
            {
                return Err(CryptoError::InvalidEnvelope);
            }
            Some(purpose)
        }
        (KeyRoleV1::Tombstone, RecordKindV1::Tombstone) => {
            let purpose = parse_purpose(purpose_byte)?;
            if is_zero(&session_id)
                || is_zero(&participant_id)
                || plaintext_len != TOMBSTONE_RECORD_LEN
            {
                return Err(CryptoError::InvalidEnvelope);
            }
            Some(purpose)
        }
        (KeyRoleV1::Backup, RecordKindV1::BackupManifest) => {
            if !is_zero(&session_id)
                || !is_zero(&participant_id)
                || purpose_byte != 0
                || plaintext_len != BACKUP_MANIFEST_LEN
            {
                return Err(CryptoError::InvalidEnvelope);
            }
            None
        }
        _ => return Err(CryptoError::InvalidEnvelope),
    };
    Ok(ParsedObjectHeader {
        key_role,
        record_kind,
        ids,
        nonce_epoch,
        session_id,
        participant_id,
        purpose,
        revision,
        bound_digest,
        plaintext_len,
        complete_len,
    })
}

struct ParsedNonceHeader {
    key_role: KeyRoleV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    session_id: [u8; 32],
    participant_id: [u8; 32],
    purpose: PurposeV1,
    revision: u64,
    bound_digest: [u8; 32],
    plaintext_len: usize,
}

fn parse_nonce_header(bytes: &[u8]) -> Result<ParsedNonceHeader, CryptoError> {
    let header = parse_object_header(bytes)?;
    if header.key_role != KeyRoleV1::SecretRecord
        || header.record_kind != RecordKindV1::NonceSecretRecord
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(ParsedNonceHeader {
        key_role: header.key_role,
        ids: header.ids,
        nonce_epoch: header.nonce_epoch,
        session_id: header.session_id,
        participant_id: header.participant_id,
        purpose: header.purpose.ok_or(CryptoError::InvalidEnvelope)?,
        revision: header.revision,
        bound_digest: header.bound_digest,
        plaintext_len: header.plaintext_len,
    })
}

fn validate_tombstone_plaintext(bytes: &[u8; TOMBSTONE_RECORD_LEN]) -> Result<(), CryptoError> {
    if &bytes[..8] != TOMBSTONE_MAGIC
        || read_u16(&bytes[8..10]) != 1
        || bytes[116..119] != [0; 3]
        || is_zero(&bytes[10..42])
        || is_zero(&bytes[42..74])
        || is_zero(&bytes[75..107])
        || read_u64(&bytes[107..115]) == 0
        || read_u64(&bytes[119..127]) == 0
    {
        return Err(CryptoError::InvalidPlaintext);
    }
    let purpose = parse_purpose(bytes[74]).map_err(|_| CryptoError::InvalidPlaintext)?;
    purpose
        .require_strict_phase1()
        .map_err(|_| CryptoError::InvalidPlaintext)?;
    match bytes[115] {
        1 => {
            if is_zero(&bytes[127..159]) || is_zero(&bytes[159..191]) || is_zero(&bytes[191..223]) {
                return Err(CryptoError::InvalidPlaintext);
            }
        }
        2 | 3 => {}
        _ => return Err(CryptoError::InvalidPlaintext),
    }
    let expected = authoritative_storage_hash_v1(StorageHashDomainV1::Tombstone, &bytes[..223]);
    if bytes[223..255] != expected {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(())
}

fn validate_backup_manifest_plaintext(
    bytes: &[u8; BACKUP_MANIFEST_LEN],
) -> Result<(), CryptoError> {
    let source_journal_sequence = read_u64(&bytes[114..122]);
    if &bytes[..8] != BACKUP_MANIFEST_MAGIC
        || read_u16(&bytes[8..10]) != 1
        || is_zero(&bytes[10..42])
        || is_zero(&bytes[42..74])
        || is_zero(&bytes[74..106])
        || bytes[10..42] == bytes[42..74]
        || bytes[10..42] == bytes[74..106]
        || bytes[42..74] == bytes[74..106]
        || read_u64(&bytes[106..114]) == 0
        || (source_journal_sequence == 0) != is_zero(&bytes[122..154])
        || is_zero(&bytes[158..190])
        || read_u64(&bytes[190..198]) == 0
    {
        return Err(CryptoError::InvalidPlaintext);
    }
    let expected =
        authoritative_storage_hash_v1(StorageHashDomainV1::BackupManifest, &bytes[..198]);
    if !bool::from(expected.ct_eq(&bytes[198..230])) {
        return Err(CryptoError::InvalidPlaintext);
    }
    Ok(())
}

fn parse_purpose(value: u8) -> Result<PurposeV1, CryptoError> {
    let purpose = PurposeV1::try_from(value).map_err(|_| CryptoError::InvalidEnvelope)?;
    match purpose {
        PurposeV1::Refund
        | PurposeV1::ClaimAdaptor
        | PurposeV1::RefundAdaptor
        | PurposeV1::Funding
        | PurposeV1::Sponsor => Ok(purpose),
    }
}

const fn canonical_purpose_byte(purpose: PurposeV1) -> u8 {
    match purpose {
        PurposeV1::Refund
        | PurposeV1::ClaimAdaptor
        | PurposeV1::RefundAdaptor
        | PurposeV1::Funding
        | PurposeV1::Sponsor => purpose.to_byte(),
    }
}

fn tagged_bytes(label: &str, tail: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let label_len = u16::try_from(label.len()).map_err(|_| CryptoError::KeyDerivationFailed)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(2 + label.len() + tail.len()));
    bytes.extend_from_slice(&label_len.to_le_bytes());
    bytes.extend_from_slice(label.as_bytes());
    bytes.extend_from_slice(tail);
    Ok(bytes)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Performs the only secret-key zero comparison in this storage boundary.
///
/// Public identifiers and public envelope fields use ordinary validation;
/// decrypted or generated master-key bytes use this constant-time equality.
fn secret_is_zero_32(bytes: &[u8; 32]) -> bool {
    bool::from(bytes.ct_eq(&[0_u8; 32]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use zeroize::Zeroize;

    struct FixedRandom {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl FixedRandom {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, offset: 0 }
        }
    }

    impl RandomSource for FixedRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            let end = self
                .offset
                .checked_add(destination.len())
                .ok_or(CryptoError::RandomFailure)?;
            let source = self
                .bytes
                .get(self.offset..end)
                .ok_or(CryptoError::RandomFailure)?;
            destination.copy_from_slice(source);
            self.offset = end;
            Ok(())
        }
    }

    struct FailingRandom;

    impl RandomSource for FailingRandom {
        fn fill(&mut self, _destination: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::RandomFailure)
        }
    }

    struct FillThenFailRandom;

    impl RandomSource for FillThenFailRandom {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), CryptoError> {
            destination.fill(0x5a);
            Err(CryptoError::RandomFailure)
        }
    }

    fn ids() -> StorageIdsV1 {
        match StorageIdsV1::new([0x11; 32], [0x22; 32]) {
            Ok(value) => value,
            Err(error) => panic!("test identifiers must be valid: {error}"),
        }
    }

    fn passphrase() -> Passphrase {
        match Passphrase::new(b"correct horse battery staple".to_vec()) {
            Ok(value) => value,
            Err(error) => panic!("test passphrase must be valid: {error}"),
        }
    }

    fn master_key() -> VaultMasterKey {
        match VaultMasterKey::from_bytes([0x33; 32]) {
            Ok(value) => value,
            Err(error) => panic!("test key must be valid: {error}"),
        }
    }

    fn metadata() -> NonceSecretRecordMetadataV1 {
        test_metadata(
            7,
            [0x44; 32],
            [0x55; 32],
            PurposeV1::ClaimAdaptor,
            9,
            [0x66; 32],
        )
    }

    fn test_metadata(
        nonce_epoch: u64,
        session_id: [u8; 32],
        participant_id: [u8; 32],
        purpose: PurposeV1,
        revision: u64,
        bound_digest: [u8; 32],
    ) -> NonceSecretRecordMetadataV1 {
        match NonceSecretRecordMetadataV1::new(
            nonce_epoch,
            session_id,
            participant_id,
            purpose,
            revision,
            bound_digest,
        ) {
            Ok(value) => value,
            Err(error) => panic!("test metadata must be valid: {error}"),
        }
    }

    fn tombstone_bytes() -> [u8; TOMBSTONE_RECORD_LEN] {
        let mut bytes = [0_u8; TOMBSTONE_RECORD_LEN];
        bytes[..8].copy_from_slice(TOMBSTONE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].fill(0x44);
        bytes[42..74].fill(0x55);
        bytes[74] = PurposeV1::ClaimAdaptor.to_byte();
        bytes[75..107].fill(0x66);
        bytes[107..115].copy_from_slice(&7_u64.to_le_bytes());
        bytes[115] = 1;
        bytes[119..127].copy_from_slice(&9_u64.to_le_bytes());
        bytes[127..159].fill(0x91);
        bytes[159..191].fill(0x92);
        bytes[191..223].fill(0x93);
        let digest = authoritative_storage_hash_v1(StorageHashDomainV1::Tombstone, &bytes[..223]);
        bytes[223..255].copy_from_slice(&digest);
        bytes
    }

    fn tombstone() -> TombstonePlaintextV1 {
        match TombstonePlaintextV1::from_bytes(&tombstone_bytes()) {
            Ok(value) => value,
            Err(error) => panic!("test tombstone must be canonical: {error}"),
        }
    }

    fn tombstone_metadata() -> TombstoneRecordMetadataV1 {
        match TombstoneRecordMetadataV1::from_tombstone(&tombstone()) {
            Ok(value) => value,
            Err(error) => panic!("test tombstone metadata must be canonical: {error}"),
        }
    }

    fn backup_manifest_bytes() -> [u8; BACKUP_MANIFEST_LEN] {
        let mut bytes = [0_u8; BACKUP_MANIFEST_LEN];
        bytes[..8].copy_from_slice(BACKUP_MANIFEST_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].fill(0x11);
        bytes[42..74].fill(0x22);
        bytes[74..106].fill(0x99);
        bytes[106..114].copy_from_slice(&7_u64.to_le_bytes());
        bytes[114..122].copy_from_slice(&3_u64.to_le_bytes());
        bytes[122..154].fill(0x44);
        bytes[154..158].copy_from_slice(&5_u32.to_le_bytes());
        bytes[158..190].fill(0x55);
        bytes[190..198].copy_from_slice(&9_u64.to_le_bytes());
        let digest =
            authoritative_storage_hash_v1(StorageHashDomainV1::BackupManifest, &bytes[..198]);
        bytes[198..230].copy_from_slice(&digest);
        bytes
    }

    fn backup_manifest() -> BackupManifestPlaintextV1 {
        BackupManifestPlaintextV1::from_bytes(&backup_manifest_bytes())
            .unwrap_or_else(|error| panic!("test backup manifest must be canonical: {error}"))
    }

    fn backup_metadata() -> BackupManifestMetadataV1 {
        BackupManifestMetadataV1::from_manifest(&backup_manifest()).unwrap_or_else(|error| {
            panic!("test backup manifest metadata must be canonical: {error}")
        })
    }

    fn structural_object_envelope(
        key_role: KeyRoleV1,
        record_kind: RecordKindV1,
        plaintext_len: usize,
    ) -> Vec<u8> {
        let total_len = match OBJECT_HEADER_LEN
            .checked_add(plaintext_len)
            .and_then(|value| value.checked_add(AEAD_TAG_LEN))
        {
            Some(value) => value,
            None => panic!("test envelope length must fit"),
        };
        let mut bytes = vec![0_u8; total_len];
        bytes[..8].copy_from_slice(OBJECT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = 1;
        bytes[11] = key_role as u8;
        bytes[12..14].copy_from_slice(&1_u16.to_le_bytes());
        bytes[14..46].fill(0x11);
        bytes[46..78].fill(0x22);
        bytes[78..86].copy_from_slice(&7_u64.to_le_bytes());
        bytes[152..160].copy_from_slice(&9_u64.to_le_bytes());
        bytes[160..192].fill(0x66);
        bytes[192..208].fill(0x77);
        bytes[208..220].fill(0x88);
        bytes[220..224].copy_from_slice(
            &u32::try_from(plaintext_len)
                .unwrap_or_else(|_| panic!("test plaintext length must fit"))
                .to_le_bytes(),
        );
        match record_kind {
            RecordKindV1::NonceSecretRecord | RecordKindV1::Tombstone => {
                bytes[86..118].fill(0x44);
                bytes[118..150].fill(0x55);
                bytes[150] = 0x02;
            }
            RecordKindV1::BackupManifest => {}
        }
        bytes[151] = record_kind as u8;
        bytes
    }

    #[test]
    fn closed_registries_reject_unknown_values() {
        for value in 0_u8..=u8::MAX {
            assert_eq!(
                KeyRoleV1::try_from(value).is_ok(),
                (0x01..=0x03).contains(&value),
                "key role {value:#04x}"
            );
            assert_eq!(
                RecordKindV1::try_from(value).is_ok(),
                (0x01..=0x03).contains(&value),
                "record kind {value:#04x}"
            );
        }
        assert!(matches!(
            KeyRoleV1::try_from(1),
            Ok(KeyRoleV1::SecretRecord)
        ));
        assert!(matches!(
            RecordKindV1::try_from(3),
            Ok(RecordKindV1::BackupManifest)
        ));
        assert_eq!(KeyRoleV1::SecretRecord.hkdf_label(), SECRET_ROLE_LABEL);
        assert_eq!(KeyRoleV1::Tombstone.hkdf_label(), TOMBSTONE_ROLE_LABEL);
        assert_eq!(KeyRoleV1::Backup.hkdf_label(), BACKUP_ROLE_LABEL);
        // The registry is closed at 0x05 since NAR-DC-P1-009 ratified the
        // refund adaptor purpose. Everything outside it is still refused, which
        // is what keeps an unknown byte from being decoded as a known purpose.
        for value in 0_u8..=u8::MAX {
            let expected = (0x01..=0x05).contains(&value);
            assert_eq!(parse_purpose(value).is_ok(), expected, "{value:#04x}");
        }
        assert!(matches!(parse_purpose(0x04), Ok(PurposeV1::Sponsor)));
        assert!(matches!(parse_purpose(0x05), Ok(PurposeV1::RefundAdaptor)));
        // Unlike Sponsor, the refund adaptor purpose is authorized: it is the
        // path that makes a DOM refund reveal its witness.
        assert!(PurposeV1::RefundAdaptor.require_strict_phase1().is_ok());
        assert!(PurposeV1::Sponsor.require_strict_phase1().is_err());
        let mut sponsor = structural_object_envelope(
            KeyRoleV1::SecretRecord,
            RecordKindV1::NonceSecretRecord,
            NONCE_RECORD_MIN,
        );
        sponsor[150] = PurposeV1::Sponsor.to_byte();
        let sponsor_envelope = match VaultObjectEnvelopeV1::from_bytes(&sponsor) {
            Ok(value) => value,
            Err(error) => panic!("Sponsor must remain structurally recognizable: {error}"),
        };
        let sponsor_expected = NonceSecretRecordMetadataV1 {
            nonce_epoch: 7,
            session_id: [0x44; 32],
            participant_id: [0x55; 32],
            purpose: PurposeV1::Sponsor,
            revision: 9,
            bound_digest: [0x66; 32],
        };
        assert!(matches!(
            seal_nonce_secret_plaintext(
                ids(),
                &master_key(),
                &sponsor_expected,
                Zeroizing::new(vec![0xa5; NONCE_RECORD_MIN]),
                [0x77; 16],
                [0x88; 12],
            ),
            Err(CryptoError::InvalidEnvelope)
        ));
        assert!(matches!(
            open_nonce_secret_plaintext(&sponsor_envelope, ids(), &master_key(), &sponsor_expected,),
            Err(CryptoError::InvalidEnvelope)
        ));
        // 0x06 is the first byte past the closed registry. It stood at 0x05
        // until the refund adaptor purpose was ratified; the property under
        // test is unchanged — a purpose outside the registry is refused.
        sponsor[150] = 0x06;
        assert!(VaultObjectEnvelopeV1::from_bytes(&sponsor).is_err());
    }

    #[test]
    fn authoritative_backend_is_the_pinned_dom_tagged_hash() {
        assert_eq!(authoritative_backend_status(), Ok(()));
        let expected = dom_crypto::blake2b_256_tagged(
            "DOM:contracts-vault-session-claim:v1",
            b"authoritative-backend-probe",
        );
        assert_eq!(
            authoritative_storage_hash_v1(
                StorageHashDomainV1::SessionClaim,
                b"authoritative-backend-probe"
            ),
            *expected.as_bytes()
        );
    }

    #[test]
    fn pinned_adaptor_secret_transfer_boundary_has_exact_types() {
        let _seal: fn(
            StorageIdsV1,
            &VaultMasterKey,
            NonceSecretRecordMetadataV1,
            NonceSecretTransferV1,
            VaultSecretSealCapabilityV1,
        ) -> Result<VaultObjectEnvelopeV1, CryptoError> = seal_nonce_secret_record;
        let _open: fn(
            &VaultObjectEnvelopeV1,
            StorageIdsV1,
            &VaultMasterKey,
            NonceSecretRecordMetadataV1,
            VaultSecretImportCapabilityV1,
        ) -> Result<NonceSecretTransferV1, CryptoError> = open_nonce_secret_record;
        let _audit: fn(
            &VaultObjectEnvelopeV1,
            StorageIdsV1,
            &VaultMasterKey,
            NonceSecretRecordMetadataV1,
        ) -> Result<(), CryptoError> = audit_nonce_secret_record;

        assert_eq!(NONCE_RECORD_MIN, 387);
        assert_eq!(NONCE_RECORD_MAX, 882);
    }

    #[test]
    fn wiping_hkdf_matches_reference_for_both_paths_and_padding_boundaries() {
        let mut info_lengths = vec![
            0, 1, 54, 55, 56, 62, 63, 64, 65, 118, 119, 120, 126, 127, 128, 129, 182, 183, 184,
            246, 247, 248, 254, 255, 256, 257,
        ];
        let unlock_info = match tagged_bytes(UNLOCK_LABEL, &[0_u8; 64]) {
            Ok(value) => value,
            Err(error) => panic!("fixed unlock info must encode: {error}"),
        };
        info_lengths.push(unlock_info.len());
        for role in [
            KeyRoleV1::SecretRecord,
            KeyRoleV1::Tombstone,
            KeyRoleV1::Backup,
        ] {
            let info = match tagged_bytes(role.hkdf_label(), &[0_u8; 208]) {
                Ok(value) => value,
                Err(error) => panic!("fixed object info must encode: {error}"),
            };
            info_lengths.push(info.len());
        }
        info_lengths.sort_unstable();
        info_lengths.dedup();

        for (path, salt, ikm) in [
            ("argon-output-to-kek", [0x21_u8; 32], [0x43_u8; 32]),
            ("master-key-to-object-key", [0x65_u8; 32], [0x87_u8; 32]),
        ] {
            for info_len in &info_lengths {
                let info: Vec<u8> = (0..*info_len)
                    .map(|index| u8::try_from(index % 251).unwrap_or_default())
                    .collect();
                let ours = match derive_hkdf_sha256(&salt, &ikm, &info) {
                    Ok(value) => value,
                    Err(error) => panic!("wiping HKDF must derive for {path}: {error}"),
                };
                let reference = Hkdf::<Sha256>::new(Some(&salt), &ikm);
                let mut expected = Zeroizing::new([0_u8; 32]);
                if let Err(error) = reference.expand(&info, expected.as_mut()) {
                    panic!("reference HKDF must derive for {path}: {error}");
                }
                assert_eq!(
                    ours.as_ref(),
                    expected.as_ref(),
                    "{path}, info length {info_len}"
                );
            }
        }
    }

    #[test]
    fn object_parser_accepts_all_exact_role_kind_schema_profiles() {
        for plaintext_len in [NONCE_RECORD_MIN, NONCE_RECORD_MAX] {
            let bytes = structural_object_envelope(
                KeyRoleV1::SecretRecord,
                RecordKindV1::NonceSecretRecord,
                plaintext_len,
            );
            let parsed = VaultObjectEnvelopeV1::from_bytes(&bytes)
                .unwrap_or_else(|error| panic!("secret envelope must parse: {error}"));
            assert!(matches!(parsed.key_role(), KeyRoleV1::SecretRecord));
            assert!(matches!(
                parsed.record_kind(),
                RecordKindV1::NonceSecretRecord
            ));
            assert_eq!(parsed.structural_plaintext_len(), plaintext_len);
            assert_eq!(parsed.as_bytes(), bytes);
        }

        let tombstone = structural_object_envelope(
            KeyRoleV1::Tombstone,
            RecordKindV1::Tombstone,
            TOMBSTONE_RECORD_LEN,
        );
        let parsed = VaultObjectEnvelopeV1::from_bytes(&tombstone)
            .unwrap_or_else(|error| panic!("tombstone envelope must parse: {error}"));
        assert!(matches!(parsed.key_role(), KeyRoleV1::Tombstone));
        assert!(matches!(parsed.record_kind(), RecordKindV1::Tombstone));
        assert_eq!(parsed.structural_plaintext_len(), TOMBSTONE_RECORD_LEN);

        let backup = structural_object_envelope(
            KeyRoleV1::Backup,
            RecordKindV1::BackupManifest,
            BACKUP_MANIFEST_LEN,
        );
        let parsed = VaultObjectEnvelopeV1::from_bytes(&backup)
            .unwrap_or_else(|error| panic!("backup envelope must parse: {error}"));
        assert!(matches!(parsed.key_role(), KeyRoleV1::Backup));
        assert!(matches!(parsed.record_kind(), RecordKindV1::BackupManifest));
        assert_eq!(parsed.structural_plaintext_len(), BACKUP_MANIFEST_LEN);
    }

    #[test]
    fn nonce_sealer_enforces_exact_length_extrema_and_digest_prefix() {
        for plaintext_len in [NONCE_RECORD_MIN, NONCE_RECORD_MAX] {
            let mut random = vec![0x77; 16];
            random.extend_from_slice(&[0x88; 12]);
            let envelope = match seal_nonce_secret_record_with(
                ids(),
                &master_key(),
                &metadata(),
                Zeroizing::new(vec![0xa5; plaintext_len]),
                &mut FixedRandom::new(random),
            ) {
                Ok(value) => value,
                Err(error) => panic!("boundary object sealing failed: {error}"),
            };
            let complete_len = OBJECT_HEADER_LEN + plaintext_len + AEAD_TAG_LEN;
            assert_eq!(envelope.as_bytes().len(), complete_len);
            assert_eq!(envelope.structural_plaintext_len(), plaintext_len);

            let complete_len = match u32::try_from(complete_len) {
                Ok(value) => value,
                Err(error) => panic!("test complete length must fit: {error}"),
            };
            let mut preimage = Vec::with_capacity(4 + envelope.as_bytes().len());
            preimage.extend_from_slice(&complete_len.to_le_bytes());
            preimage.extend_from_slice(envelope.as_bytes());
            assert_eq!(
                envelope.digest(),
                authoritative_storage_hash_v1(StorageHashDomainV1::ObjectEnvelope, &preimage)
            );

            let opened =
                match open_nonce_secret_plaintext(&envelope, ids(), &master_key(), &metadata()) {
                    Ok(value) => value,
                    Err(error) => panic!("boundary object opening failed: {error}"),
                };
            assert_eq!(opened.len(), plaintext_len);
        }
    }

    #[test]
    fn object_parser_rejects_cross_role_noncanonical_and_unbounded_inputs() {
        let role_kind_pairs = [
            (KeyRoleV1::SecretRecord, RecordKindV1::Tombstone),
            (KeyRoleV1::SecretRecord, RecordKindV1::BackupManifest),
            (KeyRoleV1::Tombstone, RecordKindV1::NonceSecretRecord),
            (KeyRoleV1::Tombstone, RecordKindV1::BackupManifest),
            (KeyRoleV1::Backup, RecordKindV1::NonceSecretRecord),
            (KeyRoleV1::Backup, RecordKindV1::Tombstone),
        ];
        for (role, kind) in role_kind_pairs {
            let length = match kind {
                RecordKindV1::NonceSecretRecord => NONCE_RECORD_MIN,
                RecordKindV1::Tombstone => TOMBSTONE_RECORD_LEN,
                RecordKindV1::BackupManifest => BACKUP_MANIFEST_LEN,
            };
            let bytes = structural_object_envelope(role, kind, length);
            assert!(VaultObjectEnvelopeV1::from_bytes(&bytes).is_err());
        }

        for invalid_length in [NONCE_RECORD_MIN - 1, NONCE_RECORD_MAX + 1] {
            let bytes = structural_object_envelope(
                KeyRoleV1::SecretRecord,
                RecordKindV1::NonceSecretRecord,
                invalid_length,
            );
            assert!(VaultObjectEnvelopeV1::from_bytes(&bytes).is_err());
        }
        for (role, kind, exact_length) in [
            (
                KeyRoleV1::Tombstone,
                RecordKindV1::Tombstone,
                TOMBSTONE_RECORD_LEN,
            ),
            (
                KeyRoleV1::Backup,
                RecordKindV1::BackupManifest,
                BACKUP_MANIFEST_LEN,
            ),
        ] {
            for invalid_length in [exact_length - 1, exact_length + 1] {
                let bytes = structural_object_envelope(role, kind, invalid_length);
                assert!(VaultObjectEnvelopeV1::from_bytes(&bytes).is_err());
            }
        }

        for schema in [0_u16, 2, u16::MAX] {
            let mut invalid_schema = structural_object_envelope(
                KeyRoleV1::Tombstone,
                RecordKindV1::Tombstone,
                TOMBSTONE_RECORD_LEN,
            );
            invalid_schema[12..14].copy_from_slice(&schema.to_le_bytes());
            assert!(VaultObjectEnvelopeV1::from_bytes(&invalid_schema).is_err());
        }

        let mut trailing = structural_object_envelope(
            KeyRoleV1::Backup,
            RecordKindV1::BackupManifest,
            BACKUP_MANIFEST_LEN,
        );
        trailing.push(0);
        assert!(VaultObjectEnvelopeV1::from_bytes(&trailing).is_err());

        let mut huge_declared = vec![0_u8; OBJECT_HEADER_LEN + AEAD_TAG_LEN];
        huge_declared[..8].copy_from_slice(OBJECT_MAGIC);
        huge_declared[8..10].copy_from_slice(&1_u16.to_le_bytes());
        huge_declared[10] = 1;
        huge_declared[11] = KeyRoleV1::SecretRecord as u8;
        huge_declared[12..14].copy_from_slice(&1_u16.to_le_bytes());
        huge_declared[14..46].fill(0x11);
        huge_declared[46..78].fill(0x22);
        huge_declared[78..86].copy_from_slice(&1_u64.to_le_bytes());
        huge_declared[86..118].fill(0x44);
        huge_declared[118..150].fill(0x55);
        huge_declared[150] = 0x02;
        huge_declared[151] = RecordKindV1::NonceSecretRecord as u8;
        huge_declared[152..160].copy_from_slice(&1_u64.to_le_bytes());
        huge_declared[160..192].fill(0x66);
        huge_declared[220..224].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(VaultObjectEnvelopeV1::from_bytes(&huge_declared).is_err());
    }

    #[test]
    fn backup_object_parser_rejects_every_truncation_and_fixed_field_violation() {
        let canonical = structural_object_envelope(
            KeyRoleV1::Backup,
            RecordKindV1::BackupManifest,
            BACKUP_MANIFEST_LEN,
        );
        assert_eq!(canonical.len(), 470);
        for end in 0..canonical.len() {
            assert!(
                VaultObjectEnvelopeV1::from_bytes(&canonical[..end]).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(VaultObjectEnvelopeV1::from_bytes(&trailing).is_err());

        for offset in 0..8 {
            let mut wrong_magic = canonical.clone();
            wrong_magic[offset] ^= 1;
            assert!(VaultObjectEnvelopeV1::from_bytes(&wrong_magic).is_err());
        }
        for (range, replacement) in [(8..10, 2_u16.to_le_bytes()), (12..14, 2_u16.to_le_bytes())] {
            let mut mutated = canonical.clone();
            mutated[range].copy_from_slice(&replacement);
            assert!(VaultObjectEnvelopeV1::from_bytes(&mutated).is_err());
        }
        for offset in [10, 11, 151] {
            let mut mutated = canonical.clone();
            mutated[offset] = 0;
            assert!(VaultObjectEnvelopeV1::from_bytes(&mutated).is_err());
        }

        for range in [14..46, 46..78, 78..86, 152..160, 160..192] {
            let mut zero = canonical.clone();
            zero[range].fill(0);
            assert!(VaultObjectEnvelopeV1::from_bytes(&zero).is_err());
        }
        let mut colliding_ids = canonical.clone();
        colliding_ids[46..78].fill(0x11);
        assert!(VaultObjectEnvelopeV1::from_bytes(&colliding_ids).is_err());

        for offset in [86, 118, 150] {
            let mut nonzero_global_sentinel = canonical.clone();
            nonzero_global_sentinel[offset] = 1;
            assert!(VaultObjectEnvelopeV1::from_bytes(&nonzero_global_sentinel).is_err());
        }
        for declared_length in [BACKUP_MANIFEST_LEN - 1, BACKUP_MANIFEST_LEN + 1] {
            let mut wrong_length = canonical.clone();
            wrong_length[220..224].copy_from_slice(
                &u32::try_from(declared_length)
                    .unwrap_or_else(|_| panic!("test length must fit"))
                    .to_le_bytes(),
            );
            assert!(VaultObjectEnvelopeV1::from_bytes(&wrong_length).is_err());
        }
    }

    #[test]
    fn invalid_public_inputs_fail_closed() {
        assert!(StorageIdsV1::new([0; 32], [1; 32]).is_err());
        assert!(StorageIdsV1::new([1; 32], [1; 32]).is_err());
        assert!(Passphrase::new(vec![1; 7]).is_err());
        assert!(Passphrase::new(vec![1; 1025]).is_err());
        assert!(Passphrase::new(vec![0xff; 8]).is_err());
        assert!(Passphrase::new(vec![b'a', b'b', b'c', b'd', b'e', b'f', 0xc3, 0x28]).is_err());
        assert!(parse_purpose(0).is_err());
        assert!(NonceSecretRecordMetadataV1::new(
            0,
            [1; 32],
            [2; 32],
            PurposeV1::Refund,
            1,
            [3; 32],
        )
        .is_err());
        assert!(NonceSecretRecordMetadataV1::new(
            1,
            [0; 32],
            [2; 32],
            PurposeV1::Refund,
            1,
            [3; 32],
        )
        .is_err());
        assert!(NonceSecretRecordMetadataV1::new(
            1,
            [1; 32],
            [0; 32],
            PurposeV1::Refund,
            1,
            [3; 32],
        )
        .is_err());
        assert!(NonceSecretRecordMetadataV1::new(
            1,
            [1; 32],
            [2; 32],
            PurposeV1::Refund,
            0,
            [3; 32],
        )
        .is_err());
        assert!(NonceSecretRecordMetadataV1::new(
            1,
            [1; 32],
            [2; 32],
            PurposeV1::Refund,
            1,
            [0; 32],
        )
        .is_err());
        assert!(NonceSecretRecordMetadataV1::new(
            1,
            [1; 32],
            [2; 32],
            PurposeV1::Sponsor,
            1,
            [3; 32],
        )
        .is_err());
    }

    #[test]
    fn master_envelope_independent_kat_and_wrong_password() {
        let random: Vec<u8> = (0_u8..44).collect();
        let mut rng = FixedRandom::new(random);
        let envelope = match seal_master_key_with(ids(), &passphrase(), &master_key(), &mut rng) {
            Ok(value) => value,
            Err(error) => panic!("master sealing failed: {error}"),
        };
        assert_eq!(envelope.as_bytes().len(), 182);
        assert_eq!(&envelope.as_bytes()[..8], MASTER_MAGIC);

        // Independently generated with system libargon2, Python HMAC-SHA256,
        // and Python cryptography ChaCha20Poly1305.
        let mut salt = [0_u8; 32];
        salt.copy_from_slice(&envelope.as_bytes()[76..108]);
        let argon_output = match derive_argon_output(&passphrase(), &salt) {
            Ok(value) => value,
            Err(error) => panic!("Argon2id KAT derivation failed: {error}"),
        };
        assert_eq!(
            argon_output.as_ref(),
            &[
                0x6e, 0xd1, 0x2d, 0x7d, 0x59, 0x4a, 0x6a, 0xe5, 0x6c, 0x7a, 0xd1, 0x72, 0x59, 0x82,
                0xae, 0x0d, 0x41, 0x31, 0x7b, 0xd2, 0xb2, 0x39, 0xdd, 0x1e, 0x09, 0x16, 0xd9, 0x13,
                0xd4, 0xda, 0x07, 0x57,
            ]
        );
        let info_tail = [
            ids().contract_wallet_id().as_slice(),
            ids().vault_id().as_slice(),
        ]
        .concat();
        let info = match tagged_bytes(UNLOCK_LABEL, &info_tail) {
            Ok(value) => value,
            Err(error) => panic!("unlock info KAT framing failed: {error}"),
        };
        assert_eq!(info.len(), 99);
        assert_eq!(
            &Sha256::digest(info.as_slice())[..],
            &[
                0x78, 0xcc, 0x70, 0x76, 0x30, 0x2d, 0xf6, 0xf7, 0x8f, 0xc0, 0xaa, 0xe0, 0xd3, 0x58,
                0x40, 0x20, 0x73, 0x30, 0x3a, 0x4d, 0x3a, 0x5a, 0x41, 0xe0, 0x55, 0x0a, 0xe1, 0xcb,
                0xc3, 0x2f, 0xa6, 0xc8,
            ]
        );
        let kek = match expand_unlock_kek(ids(), &salt, &argon_output) {
            Ok(value) => value,
            Err(error) => panic!("unlock KEK KAT derivation failed: {error}"),
        };
        assert_eq!(
            kek.as_ref(),
            &[
                0xb7, 0x9f, 0xdd, 0xd4, 0x5d, 0x91, 0x8a, 0x54, 0x9f, 0x88, 0xa3, 0x8f, 0x90, 0x31,
                0xba, 0x87, 0x0d, 0x98, 0x29, 0x22, 0x66, 0xc2, 0xb6, 0xa2, 0xa9, 0x6f, 0x47, 0xe7,
                0x72, 0x13, 0x5e, 0x7c,
            ]
        );
        let aad = match tagged_bytes(MASTER_AAD_LABEL, &envelope.as_bytes()[..134]) {
            Ok(value) => value,
            Err(error) => panic!("master AAD KAT framing failed: {error}"),
        };
        assert_eq!(aad.len(), 170);
        assert_eq!(
            &Sha256::digest(aad.as_slice())[..],
            &[
                0x4d, 0x08, 0xf8, 0x14, 0x4f, 0x96, 0x9a, 0x8d, 0xa4, 0x93, 0xf5, 0x96, 0x13, 0xe9,
                0x3b, 0xab, 0xc2, 0x1f, 0xa9, 0xd4, 0xce, 0xf4, 0x0d, 0x9f, 0xa7, 0xfc, 0xb0, 0xe3,
                0x0c, 0x54, 0x6f, 0x53,
            ]
        );
        assert_eq!(
            &envelope.as_bytes()[134..166],
            &[
                0x99, 0x9d, 0x2f, 0xc0, 0x02, 0xe9, 0x29, 0x7f, 0x3d, 0x2d, 0x1b, 0xc6, 0x87, 0x90,
                0x70, 0x83, 0x05, 0xf0, 0x85, 0x6e, 0x9d, 0xf8, 0xb9, 0x94, 0x51, 0xae, 0x76, 0x70,
                0x73, 0x10, 0xeb, 0x91,
            ]
        );
        assert_eq!(
            &envelope.as_bytes()[166..],
            &[
                0x55, 0x5a, 0xee, 0xe3, 0xd3, 0xd1, 0x9f, 0x80, 0x22, 0xe8, 0xcb, 0x27, 0x56, 0x37,
                0x84, 0x23,
            ]
        );

        let opened = match open_master_key(&envelope, ids(), &passphrase()) {
            Ok(value) => value,
            Err(error) => panic!("master opening failed: {error}"),
        };
        assert_eq!(opened.as_bytes(), &[0x33; 32]);
        let wrong = match Passphrase::new(b"incorrect password".to_vec()) {
            Ok(value) => value,
            Err(error) => panic!("wrong test passphrase construction failed: {error}"),
        };
        assert!(matches!(
            open_master_key(&envelope, ids(), &wrong),
            Err(CryptoError::AuthenticationFailed)
        ));
        let digest = Sha256::digest(envelope.as_bytes());
        assert_eq!(
            &digest[..],
            &[
                0xaa, 0xaa, 0x3d, 0x6d, 0xac, 0xc7, 0xab, 0xf6, 0x03, 0x73, 0x14, 0xb5, 0x1c, 0xb3,
                0x89, 0x07, 0x07, 0x07, 0xb2, 0x7c, 0xd4, 0x13, 0xe2, 0x10, 0xbe, 0xcf, 0x04, 0x79,
                0xc9, 0xfe, 0xe5, 0xed,
            ]
        );
    }

    #[test]
    fn master_header_and_ciphertext_mutations_fail_closed() {
        let mut rng = FixedRandom::new((0_u8..44).collect());
        let envelope = match seal_master_key_with(ids(), &passphrase(), &master_key(), &mut rng) {
            Ok(value) => value,
            Err(error) => panic!("master sealing failed: {error}"),
        };
        for offset in 0..MASTER_ENVELOPE_LEN {
            let mut mutated = *envelope.as_bytes();
            mutated[offset] ^= 1;
            let result = VaultMasterKeyEnvelopeV1::from_bytes(&mutated)
                .and_then(|parsed| open_master_key(&parsed, ids(), &passphrase()));
            assert!(result.is_err(), "mutation at {offset} was accepted");
        }
        assert!(VaultMasterKeyEnvelopeV1::from_bytes(&envelope.as_bytes()[..181]).is_err());
    }

    #[test]
    fn nonce_object_independent_kat_and_all_byte_mutations() {
        let mut random = vec![0x77; 16];
        random.extend_from_slice(&[0x88; 12]);
        let mut rng = FixedRandom::new(random);
        let plaintext_bytes = vec![0xa5; NONCE_RECORD_MIN];
        let envelope = match seal_nonce_secret_record_with(
            ids(),
            &master_key(),
            &metadata(),
            Zeroizing::new(plaintext_bytes.clone()),
            &mut rng,
        ) {
            Ok(value) => value,
            Err(error) => panic!("object sealing failed: {error}"),
        };
        assert_eq!(envelope.as_bytes().len(), 224 + NONCE_RECORD_MIN + 16);
        let opened = match open_nonce_secret_plaintext(&envelope, ids(), &master_key(), &metadata())
        {
            Ok(value) => value,
            Err(error) => panic!("object opening failed: {error}"),
        };
        assert_eq!(opened.as_slice(), plaintext_bytes.as_slice());
        // Independently cross-checked with Python hashlib, cryptography HKDF,
        // and cryptography ChaCha20Poly1305.
        assert_eq!(
            &Sha256::digest(&envelope.as_bytes()[..OBJECT_HEADER_LEN])[..],
            &[
                0xa2, 0xfe, 0x55, 0xb7, 0x04, 0x6b, 0x61, 0x68, 0xbb, 0x41, 0x37, 0x74, 0x45, 0x0c,
                0xca, 0x9c, 0xbf, 0x09, 0x68, 0xcf, 0x3f, 0x56, 0x7a, 0x38, 0x23, 0x26, 0x1a, 0x91,
                0x21, 0x53, 0x2c, 0xa8,
            ]
        );
        let hkdf_info = match tagged_bytes(SECRET_ROLE_LABEL, &envelope.as_bytes()[..208]) {
            Ok(value) => value,
            Err(error) => panic!("object HKDF framing failed: {error}"),
        };
        assert_eq!(
            &Sha256::digest(hkdf_info.as_slice())[..],
            &[
                0x12, 0xf8, 0x7f, 0x8b, 0x29, 0x1f, 0xc8, 0x23, 0xb4, 0x4c, 0x2a, 0x3f, 0xb0, 0x9d,
                0x85, 0x22, 0xc7, 0x21, 0x1b, 0xa1, 0x16, 0x3b, 0xf3, 0xa4, 0xc7, 0x58, 0xbe, 0x14,
                0x6a, 0x56, 0xed, 0x76,
            ]
        );
        let object_key = match derive_object_key(
            &master_key(),
            ids(),
            KeyRoleV1::SecretRecord,
            &envelope.as_bytes()[..208],
        ) {
            Ok(value) => value,
            Err(error) => panic!("object key derivation failed: {error}"),
        };
        assert_eq!(
            object_key.as_ref(),
            &[
                0x1e, 0x34, 0xf9, 0xe4, 0xca, 0x83, 0x58, 0x18, 0x9b, 0x43, 0x62, 0xf7, 0x87, 0x93,
                0xed, 0x0c, 0x95, 0x14, 0xf5, 0xc1, 0xff, 0xb3, 0xdc, 0xcc, 0x75, 0x3a, 0xc5, 0x0c,
                0xd5, 0x42, 0xce, 0xfc,
            ]
        );
        let aad = match tagged_bytes(OBJECT_AAD_LABEL, &envelope.as_bytes()[..OBJECT_HEADER_LEN]) {
            Ok(value) => value,
            Err(error) => panic!("object AAD framing failed: {error}"),
        };
        assert_eq!(
            &Sha256::digest(aad.as_slice())[..],
            &[
                0xde, 0xab, 0xe6, 0x60, 0x83, 0x2a, 0x13, 0x11, 0x25, 0x4e, 0x4c, 0x45, 0xf5, 0xa1,
                0xf6, 0x09, 0x88, 0x22, 0x2e, 0x9e, 0x5e, 0xa2, 0xf4, 0x5a, 0x15, 0x3d, 0xf4, 0x7e,
                0x85, 0x4a, 0xc4, 0xe7,
            ]
        );
        assert_eq!(
            &Sha256::digest(&envelope.as_bytes()[OBJECT_HEADER_LEN..])[..],
            &[
                0x1e, 0x84, 0xc7, 0xb6, 0x64, 0x06, 0x02, 0x0c, 0x95, 0x7c, 0x9c, 0x71, 0x95, 0x18,
                0x98, 0x84, 0xac, 0xeb, 0xfe, 0xb6, 0x0d, 0x8f, 0x7a, 0x4b, 0x83, 0x29, 0x00, 0x99,
                0x0a, 0x6d, 0x39, 0xed,
            ]
        );
        let digest = Sha256::digest(envelope.as_bytes());
        assert_eq!(
            &digest[..],
            &[
                0x7d, 0xdb, 0x97, 0xf9, 0x01, 0x44, 0x47, 0x37, 0xbe, 0xa8, 0x88, 0x20, 0x6b, 0xa1,
                0x6d, 0x11, 0xe0, 0x51, 0x32, 0x1a, 0xea, 0xff, 0xf8, 0x37, 0x9b, 0xe8, 0x54, 0xde,
                0x69, 0xb9, 0x23, 0x0b,
            ]
        );
        assert_eq!(
            envelope.digest(),
            [
                0x46, 0x86, 0x1d, 0x4a, 0x17, 0x6b, 0x5c, 0x61, 0x00, 0x9e, 0x9c, 0x9d, 0x68, 0x8f,
                0x56, 0x44, 0x25, 0x13, 0x52, 0x2e, 0x63, 0x46, 0x03, 0xbc, 0xa9, 0x07, 0xdd, 0xe7,
                0xd1, 0xc0, 0x71, 0x88,
            ]
        );

        for offset in 0..envelope.as_bytes().len() {
            let mut mutated = envelope.as_bytes().to_vec();
            mutated[offset] ^= 1;
            let result = VaultObjectEnvelopeV1::from_bytes(&mutated).and_then(|candidate| {
                assert_ne!(
                    candidate.digest(),
                    envelope.digest(),
                    "digest mutation {offset}"
                );
                open_nonce_secret_plaintext(&candidate, ids(), &master_key(), &metadata())
            });
            assert!(result.is_err(), "mutation at {offset} was accepted");
        }
    }

    #[test]
    fn tombstone_plaintext_is_closed_authenticated_and_strict_phase1() {
        let canonical = tombstone_bytes();
        let parsed = TombstonePlaintextV1::from_bytes(&canonical)
            .unwrap_or_else(|error| panic!("canonical tombstone must parse: {error}"));
        assert_eq!(parsed.as_bytes(), &canonical);
        assert!(TombstonePlaintextV1::from_bytes(&canonical[..254]).is_err());

        for offset in 0..canonical.len() {
            let mut mutated = canonical;
            mutated[offset] ^= 1;
            assert!(
                TombstonePlaintextV1::from_bytes(&mutated).is_err(),
                "unauthenticated mutation at {offset} was accepted"
            );
        }

        for (offset, value) in [(74, PurposeV1::Sponsor.to_byte()), (115, 0), (115, 4)] {
            let mut invalid = canonical;
            invalid[offset] = value;
            let digest =
                authoritative_storage_hash_v1(StorageHashDomainV1::Tombstone, &invalid[..223]);
            invalid[223..255].copy_from_slice(&digest);
            assert!(TombstonePlaintextV1::from_bytes(&invalid).is_err());
        }
    }

    #[test]
    fn tombstone_envelope_kat_round_trip_and_all_byte_mutations() {
        let plaintext = tombstone_bytes();
        let envelope = seal_tombstone_plaintext(
            ids(),
            &master_key(),
            &tombstone_metadata(),
            tombstone(),
            [0x77; 16],
            [0x88; 12],
        )
        .unwrap_or_else(|error| panic!("tombstone sealing failed: {error}"));
        assert_eq!(envelope.as_bytes().len(), 495);
        assert!(matches!(envelope.key_role(), KeyRoleV1::Tombstone));
        assert!(matches!(envelope.record_kind(), RecordKindV1::Tombstone));
        assert_eq!(envelope.structural_plaintext_len(), 255);
        assert_eq!(&envelope.as_bytes()[192..208], &[0x77; 16]);
        assert_eq!(&envelope.as_bytes()[208..220], &[0x88; 12]);

        let opened = open_tombstone_v1(&envelope, ids(), &master_key(), tombstone_metadata())
            .unwrap_or_else(|error| panic!("tombstone opening failed: {error}"));
        assert_eq!(opened.as_bytes(), &plaintext);

        // Independently reproducible fixed-input KAT for the complete envelope.
        assert_eq!(
            &Sha256::digest(envelope.as_bytes())[..],
            &[
                0x99, 0xbb, 0x68, 0xfb, 0x8d, 0x01, 0xc8, 0x77, 0xdf, 0xbb, 0x8d, 0x4b, 0xf3, 0xfb,
                0xcc, 0x5c, 0xa8, 0x33, 0x75, 0x8b, 0xe4, 0xd0, 0x0f, 0xbf, 0x5f, 0x78, 0xa5, 0x3b,
                0x23, 0xae, 0x1f, 0xa6,
            ]
        );

        for offset in 0..envelope.as_bytes().len() {
            let mut mutated = envelope.as_bytes().to_vec();
            mutated[offset] ^= 1;
            let result = VaultObjectEnvelopeV1::from_bytes(&mutated).and_then(|candidate| {
                open_tombstone_v1(&candidate, ids(), &master_key(), tombstone_metadata())
            });
            assert!(
                result.is_err(),
                "envelope mutation at {offset} was accepted"
            );
        }
    }

    #[test]
    fn tombstone_role_kind_and_every_metadata_mismatch_fail_closed() {
        let envelope = seal_tombstone_plaintext(
            ids(),
            &master_key(),
            &tombstone_metadata(),
            tombstone(),
            [0x77; 16],
            [0x88; 12],
        )
        .unwrap_or_else(|error| panic!("tombstone sealing failed: {error}"));
        let canonical_digest = tombstone_metadata().tombstone_digest;
        let wrong_metadata = [
            TombstoneRecordMetadataV1::new(
                8,
                [0x44; 32],
                [0x55; 32],
                PurposeV1::ClaimAdaptor,
                9,
                canonical_digest,
            ),
            TombstoneRecordMetadataV1::new(
                7,
                [0x45; 32],
                [0x55; 32],
                PurposeV1::ClaimAdaptor,
                9,
                canonical_digest,
            ),
            TombstoneRecordMetadataV1::new(
                7,
                [0x44; 32],
                [0x56; 32],
                PurposeV1::ClaimAdaptor,
                9,
                canonical_digest,
            ),
            TombstoneRecordMetadataV1::new(
                7,
                [0x44; 32],
                [0x55; 32],
                PurposeV1::Funding,
                9,
                canonical_digest,
            ),
            TombstoneRecordMetadataV1::new(
                7,
                [0x44; 32],
                [0x55; 32],
                PurposeV1::ClaimAdaptor,
                10,
                canonical_digest,
            ),
            TombstoneRecordMetadataV1::new(
                7,
                [0x44; 32],
                [0x55; 32],
                PurposeV1::ClaimAdaptor,
                9,
                [0xa4; 32],
            ),
        ];
        for wrong in wrong_metadata {
            let wrong =
                wrong.unwrap_or_else(|error| panic!("wrong metadata is structural: {error}"));
            assert!(open_tombstone_v1(&envelope, ids(), &master_key(), wrong).is_err());
        }

        for (role, kind) in [
            (KeyRoleV1::SecretRecord as u8, RecordKindV1::Tombstone as u8),
            (
                KeyRoleV1::Tombstone as u8,
                RecordKindV1::NonceSecretRecord as u8,
            ),
        ] {
            let mut invalid = envelope.as_bytes().to_vec();
            invalid[11] = role;
            invalid[151] = kind;
            assert!(VaultObjectEnvelopeV1::from_bytes(&invalid).is_err());
        }

        let mismatched = TombstoneRecordMetadataV1::new(
            7,
            [0x44; 32],
            [0x55; 32],
            PurposeV1::ClaimAdaptor,
            9,
            [0xa4; 32],
        )
        .unwrap_or_else(|error| panic!("mismatched metadata is structural: {error}"));
        assert!(seal_tombstone_plaintext(
            ids(),
            &master_key(),
            &mismatched,
            tombstone(),
            [0x77; 16],
            [0x88; 12],
        )
        .is_err());
    }

    #[test]
    fn backup_manifest_plaintext_is_closed_and_digest_authenticated() {
        let canonical = backup_manifest_bytes();
        let parsed = BackupManifestPlaintextV1::from_bytes(&canonical)
            .unwrap_or_else(|error| panic!("canonical backup manifest must parse: {error}"));
        assert_eq!(parsed.as_bytes(), &canonical);
        assert!(BackupManifestPlaintextV1::from_bytes(&canonical[..229]).is_err());

        for offset in 0..canonical.len() {
            let mut mutated = canonical;
            mutated[offset] ^= 1;
            assert!(
                BackupManifestPlaintextV1::from_bytes(&mutated).is_err(),
                "unauthenticated mutation at {offset} was accepted"
            );
        }

        for range in [10..42, 42..74, 74..106, 106..114, 158..190, 190..198] {
            let mut invalid = canonical;
            invalid[range].fill(0);
            let digest =
                authoritative_storage_hash_v1(StorageHashDomainV1::BackupManifest, &invalid[..198]);
            invalid[198..230].copy_from_slice(&digest);
            assert!(BackupManifestPlaintextV1::from_bytes(&invalid).is_err());
        }
        for source in [10..42, 42..74] {
            let mut colliding = canonical;
            let copied = colliding[source].to_vec();
            colliding[74..106].copy_from_slice(&copied);
            let digest = authoritative_storage_hash_v1(
                StorageHashDomainV1::BackupManifest,
                &colliding[..198],
            );
            colliding[198..230].copy_from_slice(&digest);
            assert!(BackupManifestPlaintextV1::from_bytes(&colliding).is_err());
        }
        let mut zero_head_violation = canonical;
        zero_head_violation[114..122].fill(0);
        let digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::BackupManifest,
            &zero_head_violation[..198],
        );
        zero_head_violation[198..230].copy_from_slice(&digest);
        assert!(BackupManifestPlaintextV1::from_bytes(&zero_head_violation).is_err());

        let mut missing_head_violation = canonical;
        missing_head_violation[122..154].fill(0);
        let digest = authoritative_storage_hash_v1(
            StorageHashDomainV1::BackupManifest,
            &missing_head_violation[..198],
        );
        missing_head_violation[198..230].copy_from_slice(&digest);
        assert!(BackupManifestPlaintextV1::from_bytes(&missing_head_violation).is_err());
    }

    #[test]
    fn backup_manifest_envelope_kat_round_trip_and_all_byte_mutations() {
        let plaintext = backup_manifest_bytes();
        let envelope = seal_backup_manifest_plaintext(
            &master_key(),
            &backup_metadata(),
            backup_manifest(),
            [0x77; 16],
            [0x88; 12],
        )
        .unwrap_or_else(|error| panic!("backup manifest sealing failed: {error}"));
        assert_eq!(envelope.as_bytes().len(), 470);
        assert!(matches!(envelope.key_role(), KeyRoleV1::Backup));
        assert!(matches!(
            envelope.record_kind(),
            RecordKindV1::BackupManifest
        ));
        assert_eq!(envelope.structural_plaintext_len(), BACKUP_MANIFEST_LEN);
        assert_eq!(&envelope.as_bytes()[86..150], &[0_u8; 64]);
        assert_eq!(envelope.as_bytes()[150], 0);
        assert_eq!(&envelope.as_bytes()[192..208], &[0x77; 16]);
        assert_eq!(&envelope.as_bytes()[208..220], &[0x88; 12]);

        let opened = open_backup_manifest_v1(&envelope, &master_key(), backup_metadata())
            .unwrap_or_else(|error| panic!("backup manifest opening failed: {error}"));
        assert_eq!(opened.as_bytes(), &plaintext);

        // Fixed-input KAT independently generated with Python 3 `hashlib`
        // BLAKE2b/SHA-256, `hmac` HKDF-SHA256, and `cryptography`'s
        // ChaCha20Poly1305. The complete generator command and output are
        // retained in the G1B command log.
        assert_eq!(
            &Sha256::digest(&envelope.as_bytes()[..OBJECT_HEADER_LEN])[..],
            &[
                0xec, 0xa7, 0x2e, 0x77, 0x08, 0xbf, 0xed, 0x0a, 0xb3, 0x3b, 0x73, 0x9d, 0x76, 0xcc,
                0x1d, 0xe5, 0xd2, 0x02, 0xb0, 0x7a, 0x9d, 0x0d, 0x70, 0x7f, 0x78, 0x45, 0xce, 0x6f,
                0xa2, 0xdc, 0x67, 0xe1,
            ]
        );
        assert_eq!(
            &Sha256::digest(envelope.as_bytes())[..],
            &[
                0xc3, 0x80, 0xeb, 0x4a, 0x68, 0xab, 0xdf, 0x2d, 0x90, 0xe0, 0x6d, 0xb0, 0x1b, 0xc1,
                0x2c, 0xb5, 0xbb, 0x11, 0xbe, 0x07, 0x0a, 0xf8, 0xf8, 0x5a, 0x9b, 0xa8, 0xd6, 0x32,
                0x21, 0x70, 0x60, 0x83,
            ]
        );

        for offset in 0..envelope.as_bytes().len() {
            let mut mutated = envelope.as_bytes().to_vec();
            mutated[offset] ^= 1;
            let result = VaultObjectEnvelopeV1::from_bytes(&mutated).and_then(|candidate| {
                open_backup_manifest_v1(&candidate, &master_key(), backup_metadata())
            });
            assert!(
                result.is_err(),
                "backup envelope mutation at {offset} was accepted"
            );
        }
        for end in 0..envelope.as_bytes().len() {
            assert!(VaultObjectEnvelopeV1::from_bytes(&envelope.as_bytes()[..end]).is_err());
        }
    }

    #[test]
    fn backup_manifest_wrong_metadata_and_public_randomness_fail_closed() {
        let envelope = seal_backup_manifest_plaintext(
            &master_key(),
            &backup_metadata(),
            backup_manifest(),
            [0x77; 16],
            [0x88; 12],
        )
        .unwrap_or_else(|error| panic!("backup manifest sealing failed: {error}"));
        let digest = backup_metadata().manifest_digest;
        let wrong = [
            BackupManifestMetadataV1::new(ids(), 8, 9, digest),
            BackupManifestMetadataV1::new(ids(), 7, 10, digest),
            BackupManifestMetadataV1::new(ids(), 7, 9, [0xa4; 32]),
            BackupManifestMetadataV1::new(
                StorageIdsV1::new([0x12; 32], [0x22; 32])
                    .unwrap_or_else(|error| panic!("test IDs must be valid: {error}")),
                7,
                9,
                digest,
            ),
        ];
        for metadata in wrong {
            let metadata =
                metadata.unwrap_or_else(|error| panic!("wrong metadata is structural: {error}"));
            assert!(open_backup_manifest_v1(&envelope, &master_key(), metadata).is_err());
        }

        let mismatched = BackupManifestMetadataV1::new(ids(), 7, 10, digest)
            .unwrap_or_else(|error| panic!("mismatched metadata is structural: {error}"));
        assert!(seal_backup_manifest_plaintext(
            &master_key(),
            &mismatched,
            backup_manifest(),
            [0x77; 16],
            [0x88; 12],
        )
        .is_err());

        let first = seal_backup_manifest_v1(&master_key(), backup_metadata(), backup_manifest())
            .unwrap_or_else(|error| panic!("first public backup seal failed: {error}"));
        let second = seal_backup_manifest_v1(&master_key(), backup_metadata(), backup_manifest())
            .unwrap_or_else(|error| panic!("second public backup seal failed: {error}"));
        assert_eq!(first.as_bytes().len(), 470);
        assert_eq!(second.as_bytes().len(), 470);
        assert_ne!(&first.as_bytes()[192..220], &second.as_bytes()[192..220]);
        assert_eq!(
            open_backup_manifest_v1(&first, &master_key(), backup_metadata())
                .unwrap_or_else(|error| panic!("first public backup open failed: {error}"))
                .as_bytes(),
            &backup_manifest_bytes()
        );
    }

    #[test]
    fn public_tombstone_sealer_uses_fresh_os_randomness_and_round_trips() {
        let first = seal_tombstone_v1(ids(), &master_key(), tombstone_metadata(), tombstone())
            .unwrap_or_else(|error| panic!("first public tombstone seal failed: {error}"));
        let second = seal_tombstone_v1(ids(), &master_key(), tombstone_metadata(), tombstone())
            .unwrap_or_else(|error| panic!("second public tombstone seal failed: {error}"));
        assert_eq!(first.as_bytes().len(), 495);
        assert_eq!(second.as_bytes().len(), 495);
        assert_ne!(&first.as_bytes()[192..220], &second.as_bytes()[192..220]);
        assert_ne!(first.as_bytes(), second.as_bytes());

        for envelope in [&first, &second] {
            let opened = open_tombstone_v1(envelope, ids(), &master_key(), tombstone_metadata())
                .unwrap_or_else(|error| panic!("public tombstone open failed: {error}"));
            assert_eq!(opened.as_bytes(), &tombstone_bytes());
        }
    }

    #[test]
    fn every_mismatched_object_context_field_fails_closed() {
        let mut random = vec![0x77; 16];
        random.extend_from_slice(&[0x88; 12]);
        let mut rng = FixedRandom::new(random);
        let envelope = match seal_nonce_secret_record_with(
            ids(),
            &master_key(),
            &metadata(),
            Zeroizing::new(vec![0xa5; NONCE_RECORD_MIN]),
            &mut rng,
        ) {
            Ok(value) => value,
            Err(error) => panic!("object sealing failed: {error}"),
        };
        let wrong_metadata = [
            test_metadata(
                8,
                [0x44; 32],
                [0x55; 32],
                PurposeV1::ClaimAdaptor,
                9,
                [0x66; 32],
            ),
            test_metadata(
                7,
                [0x45; 32],
                [0x55; 32],
                PurposeV1::ClaimAdaptor,
                9,
                [0x66; 32],
            ),
            test_metadata(
                7,
                [0x44; 32],
                [0x56; 32],
                PurposeV1::ClaimAdaptor,
                9,
                [0x66; 32],
            ),
            test_metadata(7, [0x44; 32], [0x55; 32], PurposeV1::Funding, 9, [0x66; 32]),
            test_metadata(
                7,
                [0x44; 32],
                [0x55; 32],
                PurposeV1::ClaimAdaptor,
                10,
                [0x66; 32],
            ),
            test_metadata(
                7,
                [0x44; 32],
                [0x55; 32],
                PurposeV1::ClaimAdaptor,
                9,
                [0x67; 32],
            ),
        ];
        for wrong in &wrong_metadata {
            assert!(open_nonce_secret_plaintext(&envelope, ids(), &master_key(), wrong).is_err());
        }

        let wrong_ids = match StorageIdsV1::new([0x12; 32], [0x22; 32]) {
            Ok(value) => value,
            Err(error) => panic!("wrong test identifiers must still be valid: {error}"),
        };
        assert!(matches!(
            open_nonce_secret_plaintext(&envelope, wrong_ids, &master_key(), &metadata()),
            Err(CryptoError::InvalidIdentifier)
        ));
        let wrong_key = match VaultMasterKey::from_bytes([0x34; 32]) {
            Ok(value) => value,
            Err(error) => panic!("wrong test key must still be valid: {error}"),
        };
        assert!(matches!(
            open_nonce_secret_plaintext(&envelope, ids(), &wrong_key, &metadata()),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn rng_failures_are_reported() {
        assert!(matches!(
            generate_storage_ids_with(&mut FailingRandom),
            Err(CryptoError::RandomFailure)
        ));
        assert!(matches!(
            generate_vault_master_key_with(&mut FailingRandom),
            Err(CryptoError::RandomFailure)
        ));
        assert!(matches!(
            generate_vault_master_key_with(&mut FillThenFailRandom),
            Err(CryptoError::RandomFailure)
        ));
        assert!(matches!(
            seal_master_key_with(ids(), &passphrase(), &master_key(), &mut FailingRandom),
            Err(CryptoError::RandomFailure)
        ));
        assert!(matches!(
            seal_nonce_secret_record_with(
                ids(),
                &master_key(),
                &metadata(),
                Zeroizing::new(vec![0; NONCE_RECORD_MIN]),
                &mut FailingRandom,
            ),
            Err(CryptoError::RandomFailure)
        ));
        let mut nonce_failure = FixedRandom::new(vec![0x77; 16]);
        assert!(matches!(
            seal_nonce_secret_record_with(
                ids(),
                &master_key(),
                &metadata(),
                Zeroizing::new(vec![0; NONCE_RECORD_MIN]),
                &mut nonce_failure,
            ),
            Err(CryptoError::RandomFailure)
        ));
        assert!(matches!(
            seal_nonce_secret_record_with(
                ids(),
                &master_key(),
                &metadata(),
                Zeroizing::new(vec![0; NONCE_RECORD_MIN]),
                &mut FillThenFailRandom,
            ),
            Err(CryptoError::RandomFailure)
        ));
        assert!(matches!(
            seal_nonce_secret_record_with(
                ids(),
                &master_key(),
                &metadata(),
                Zeroizing::new(vec![0; NONCE_RECORD_MIN - 1]),
                &mut FailingRandom,
            ),
            Err(CryptoError::InvalidPlaintext)
        ));
        assert!(matches!(
            seal_nonce_secret_record_with(
                ids(),
                &master_key(),
                &metadata(),
                Zeroizing::new(vec![0; NONCE_RECORD_MAX + 1]),
                &mut FailingRandom,
            ),
            Err(CryptoError::InvalidPlaintext)
        ));
    }

    #[test]
    fn fresh_object_randomness_changes_instance_nonce_ciphertext_and_digest() {
        let mut first_random = vec![0x77; 16];
        first_random.extend_from_slice(&[0x88; 12]);
        let mut second_random = vec![0x78; 16];
        second_random.extend_from_slice(&[0x89; 12]);
        let first = match seal_nonce_secret_record_with(
            ids(),
            &master_key(),
            &metadata(),
            Zeroizing::new(vec![0xa5; NONCE_RECORD_MIN]),
            &mut FixedRandom::new(first_random),
        ) {
            Ok(value) => value,
            Err(error) => panic!("first object seal failed: {error}"),
        };
        let second = match seal_nonce_secret_record_with(
            ids(),
            &master_key(),
            &metadata(),
            Zeroizing::new(vec![0xa5; NONCE_RECORD_MIN]),
            &mut FixedRandom::new(second_random),
        ) {
            Ok(value) => value,
            Err(error) => panic!("second object seal failed: {error}"),
        };
        assert_ne!(&first.as_bytes()[192..208], &second.as_bytes()[192..208]);
        assert_ne!(&first.as_bytes()[208..220], &second.as_bytes()[208..220]);
        assert_ne!(
            &first.as_bytes()[OBJECT_HEADER_LEN..],
            &second.as_bytes()[OBJECT_HEADER_LEN..]
        );
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn zero_rng_outputs_are_not_valid_identifiers_or_keys() {
        let mut ids_rng = FixedRandom::new(vec![0; 64]);
        assert!(matches!(
            generate_storage_ids_with(&mut ids_rng),
            Err(CryptoError::InvalidIdentifier)
        ));
        let mut key_rng = FixedRandom::new(vec![0; 32]);
        assert!(matches!(
            generate_vault_master_key_with(&mut key_rng),
            Err(CryptoError::RandomFailure)
        ));
    }

    #[test]
    fn secret_wrappers_and_sha_state_have_effective_zeroize_paths() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        struct DropProbe {
            bytes: [u8; 32],
            calls: Arc<AtomicUsize>,
        }

        impl Zeroize for DropProbe {
            fn zeroize(&mut self) {
                self.bytes.zeroize();
                self.calls.fetch_add(1, Ordering::SeqCst);
            }
        }

        assert_zeroize_on_drop::<WipingSha256>();
        assert_zeroize_on_drop::<Zeroizing<[u8; 32]>>();
        assert_zeroize_on_drop::<Zeroizing<[u8; 64]>>();

        let calls = Arc::new(AtomicUsize::new(0));
        {
            let _probe = Zeroizing::new(DropProbe {
                bytes: [0x5a; 32],
                calls: Arc::clone(&calls),
            });
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let mut state = WipingSha256::new();
        if let Err(error) = state.update(&[0x5a; 65]) {
            panic!("bounded SHA input must be accepted: {error}");
        }
        state.zeroize();
        assert_eq!(*state.state, [0_u32; 8]);
        assert_eq!(*state.block, [0_u8; 64]);
        assert_eq!(state.block_len, 0);
        assert_eq!(state.message_len, 0);
    }

    #[test]
    fn secret_zero_check_covers_every_byte_without_public_short_circuit_helper() {
        assert!(secret_is_zero_32(&[0_u8; 32]));
        for offset in 0..32 {
            let mut bytes = [0_u8; 32];
            bytes[offset] = 1;
            assert!(!secret_is_zero_32(&bytes), "offset {offset}");
        }
        assert!(!secret_is_zero_32(&[0xff_u8; 32]));
    }
}

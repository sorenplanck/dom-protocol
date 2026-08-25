//! F7 candidate encrypted custody for collaborative-output secrets.
//!
//! This profile is deliberately separate from the closed V1 nonce-object
//! registry. Plaintext crosses this module only through DOM-owned, one-shot
//! capabilities; no generic decrypt or raw-secret accessor is exported.

use super::{
    derive_hkdf_sha256, tagged_bytes, CryptoError, OsRandom, RandomSource, StorageIdsV1,
    VaultMasterKey,
};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use dom_adaptor::{
    BpStatementV1, CollaborativeBpFinalizeBindingV1, CollaborativeBpFinalizeContinuationV1,
    CollaborativeBpFinalizeImportCapabilityV1, CollaborativeBpNonceBindingV1,
    CollaborativeBpNonceImportCapabilityV1, CollaborativeBpNonceMaterialV1,
    CollaborativeBpNonceSealCapabilityV1, CollaborativeBpProofImportCapabilityV1,
    CollaborativeBpProofPersistenceCapabilityV1, CollaborativeBpRound2ImportCapabilityV1,
    CollaborativeBpRound2PersistenceCapabilityV1, DurableBpProofTransportV1,
    DurableBpRound2TransportV1, DurableShareBackupAckCapabilityV1, PendingSharedBlindingBindingV1,
    RangeProof739, ShareBackupAckV1, SharedBlindingBindingUpgradeCapabilityV1,
    SharedBlindingBindingV1, SharedBlindingImportCapabilityV1, SharedBlindingMaterialV1,
    SharedBlindingSealCapabilityV1, SigningShareV1,
};
use dom_crypto::{blake2b_256, blake2b_256_tagged, recovery::RecoveryCapsule, PublicKey};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"DOMF7CS1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 148;
const TAG_LEN: usize = 16;
const MAX_FINALIZER_LEN: usize = 1024 * 1024;
const KEY_LABEL: &str = "DOM:contracts-f7-collaborative-secret-key:v1";
const AAD_LABEL: &str = "DOM:contracts-f7-collaborative-secret-aad:v1";
const ENVELOPE_TAG: &str = "DOM:contracts-f7-collaborative-secret-envelope:v1";

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    SharedPrimary = 1,
    SharedBackup = 2,
    BpNonce = 3,
    BpRound2 = 4,
    BpFinalize = 5,
    BpProof = 6,
    SharedRecoveryCapsule = 7,
}

impl Kind {
    fn parse(value: u8) -> Result<Self, CryptoError> {
        match value {
            1 => Ok(Self::SharedPrimary),
            2 => Ok(Self::SharedBackup),
            3 => Ok(Self::BpNonce),
            4 => Ok(Self::BpRound2),
            5 => Ok(Self::BpFinalize),
            6 => Ok(Self::BpProof),
            7 => Ok(Self::SharedRecoveryCapsule),
            _ => Err(CryptoError::InvalidEnvelope),
        }
    }

    fn valid_plaintext_len(self, length: usize) -> bool {
        match self {
            Self::SharedPrimary | Self::SharedBackup => length == 32,
            Self::BpNonce => length == 64,
            Self::BpRound2 => length == 104,
            Self::BpFinalize => (1..=MAX_FINALIZER_LEN).contains(&length),
            Self::BpProof => length == 739,
            Self::SharedRecoveryCapsule => length == 96,
        }
    }
}

/// Structurally validated ciphertext for one F7 collaborative-custody record.
///
/// The bytes contain only public metadata and AEAD ciphertext. Authentication
/// and binding validation occur in a purpose-specific open function.
pub struct CollaborativeSecretEnvelopeV1 {
    bytes: Vec<u8>,
    kind: Kind,
    plaintext_len: usize,
}

impl CollaborativeSecretEnvelopeV1 {
    /// Parses a bounded candidate envelope without decrypting it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let (kind, plaintext_len) = parse_header(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            kind,
            plaintext_len,
        })
    }

    /// Borrows the public header, ciphertext, and authentication tag.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a domain-separated digest of the complete envelope.
    pub fn digest(&self) -> [u8; 32] {
        *blake2b_256_tagged(ENVELOPE_TAG, &self.bytes).as_bytes()
    }
}

/// AEAD-authenticates a candidate envelope and discards its zeroizing plaintext.
///
/// This is the startup-inventory audit boundary. It exposes neither plaintext
/// nor a generic decryption callback, and accepts the exact persisted binding
/// bytes whose digest is authenticated by the envelope header.
pub fn audit_collaborative_secret_envelope_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding_aad: &[u8],
) -> Result<(), CryptoError> {
    let mut binding_digest = [0u8; 32];
    binding_digest.copy_from_slice(&envelope.bytes[84..116]);
    let plaintext = open(
        envelope,
        envelope.kind,
        ids,
        nonce_epoch,
        master_key,
        binding_aad,
        binding_digest,
    )?;
    drop(plaintext);
    Ok(())
}

/// Two independently encrypted, immutable copies of one durable shared share.
///
/// The backup copy uses a distinct record kind, instance identifier, AEAD
/// nonce, and derived key context. Neither plaintext nor an import capability
/// is exposed by this value.
pub struct SealedSharedBlindingBundleV1 {
    primary: CollaborativeSecretEnvelopeV1,
    backup: CollaborativeSecretEnvelopeV1,
    recovery_capsule: Option<CollaborativeSecretEnvelopeV1>,
}

impl SealedSharedBlindingBundleV1 {
    /// Primary encrypted record that gates release of `R_i`.
    pub const fn primary(&self) -> &CollaborativeSecretEnvelopeV1 {
        &self.primary
    }

    /// Independently encrypted local backup-roundtrip record.
    pub const fn backup(&self) -> &CollaborativeSecretEnvelopeV1 {
        &self.backup
    }

    /// Authenticated exact recovery capsule present only for the additive F7
    /// restartable Pending-to-Bound transition.
    pub const fn recovery_capsule(&self) -> Option<&CollaborativeSecretEnvelopeV1> {
        self.recovery_capsule.as_ref()
    }
}

/// Encrypted round-2/finalizer records plus their one-shot import authorities.
pub struct SealedCollaborativeBpRound2BundleV1 {
    round2: CollaborativeSecretEnvelopeV1,
    finalize: CollaborativeSecretEnvelopeV1,
    finalize_import: CollaborativeBpFinalizeImportCapabilityV1,
    round2_import: CollaborativeBpRound2ImportCapabilityV1,
}

impl SealedCollaborativeBpRound2BundleV1 {
    /// Encrypted exact 104-byte round-2 transport artifact.
    pub const fn round2(&self) -> &CollaborativeSecretEnvelopeV1 {
        &self.round2
    }

    /// Encrypted opaque finalizer continuation.
    pub const fn finalize(&self) -> &CollaborativeSecretEnvelopeV1 {
        &self.finalize
    }

    /// Consumes the sealed bundle into DOM-owned readback authorities.
    pub fn into_import_capabilities(
        self,
    ) -> (
        CollaborativeBpFinalizeImportCapabilityV1,
        CollaborativeBpRound2ImportCapabilityV1,
    ) {
        (self.finalize_import, self.round2_import)
    }
}

/// Encrypted verified proof plus its one-shot readback authority.
pub struct SealedCollaborativeBpProofV1 {
    envelope: CollaborativeSecretEnvelopeV1,
    import: CollaborativeBpProofImportCapabilityV1,
}

impl SealedCollaborativeBpProofV1 {
    /// Encrypted exact verified proof record.
    pub const fn envelope(&self) -> &CollaborativeSecretEnvelopeV1 {
        &self.envelope
    }

    /// Consumes the sealed record into its DOM-owned readback authority.
    pub fn into_import_capability(self) -> CollaborativeBpProofImportCapabilityV1 {
        self.import
    }
}

/// Encrypts primary and independent backup copies of a fresh shared blinding.
pub fn seal_shared_blinding_bundle_v1(
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &PendingSharedBlindingBindingV1,
    material: SharedBlindingMaterialV1,
    capability: SharedBlindingSealCapabilityV1,
) -> Result<SealedSharedBlindingBundleV1, CryptoError> {
    let mut plaintext = capability.into_plaintext(material);
    let primary_plaintext = Zeroizing::new(plaintext.to_vec());
    let backup_plaintext = Zeroizing::new(plaintext.to_vec());
    plaintext.zeroize();
    let aad = binding.to_aad_bytes();
    let digest = binding.binding_digest_v1();
    Ok(SealedSharedBlindingBundleV1 {
        primary: seal(
            Kind::SharedPrimary,
            ids,
            nonce_epoch,
            master_key,
            &aad,
            digest,
            primary_plaintext,
        )?,
        backup: seal(
            Kind::SharedBackup,
            ids,
            nonce_epoch,
            master_key,
            &aad,
            digest,
            backup_plaintext,
        )?,
        recovery_capsule: None,
    })
}

/// Authenticates both provisional copies, proves they contain the same exact
/// share point, and re-encrypts them under the capsule-bound identity in one
/// Store-owned transition. Plaintext never crosses this module boundary.
#[allow(
    clippy::too_many_arguments,
    reason = "typed custody inputs stay explicit at this Store-owned upgrade boundary"
)]
pub fn upgrade_shared_blinding_bundle_v1(
    primary: &CollaborativeSecretEnvelopeV1,
    backup: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    pending: &PendingSharedBlindingBindingV1,
    bound: &SharedBlindingBindingV1,
    capability: SharedBlindingBindingUpgradeCapabilityV1,
) -> Result<SealedSharedBlindingBundleV1, CryptoError> {
    upgrade_shared_blinding_bundle_inner_v1(
        primary,
        backup,
        ids,
        nonce_epoch,
        master_key,
        pending,
        bound,
        None,
        capability,
    )
}

/// Authenticates and upgrades both shared-share copies while sealing the exact
/// public recovery capsule under the same bound AAD and storage epoch.
///
/// The returned three-envelope bundle is committed by Contracts as one
/// immutable filesystem record before the provisional stage is tombstoned.
#[allow(clippy::too_many_arguments)]
pub fn upgrade_shared_blinding_bundle_restartable_v1(
    primary: &CollaborativeSecretEnvelopeV1,
    backup: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    pending: &PendingSharedBlindingBindingV1,
    bound: &SharedBlindingBindingV1,
    capsule: &RecoveryCapsule,
    capability: SharedBlindingBindingUpgradeCapabilityV1,
) -> Result<SealedSharedBlindingBundleV1, CryptoError> {
    upgrade_shared_blinding_bundle_inner_v1(
        primary,
        backup,
        ids,
        nonce_epoch,
        master_key,
        pending,
        bound,
        Some(capsule),
        capability,
    )
}

#[allow(clippy::too_many_arguments)]
fn upgrade_shared_blinding_bundle_inner_v1(
    primary: &CollaborativeSecretEnvelopeV1,
    backup: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    pending: &PendingSharedBlindingBindingV1,
    bound: &SharedBlindingBindingV1,
    capsule: Option<&RecoveryCapsule>,
    capability: SharedBlindingBindingUpgradeCapabilityV1,
) -> Result<SealedSharedBlindingBundleV1, CryptoError> {
    capability
        .authorize_upgrade(pending, bound)
        .map_err(|_| CryptoError::InvalidPlaintext)?;
    if capsule
        .map(|candidate| {
            &SharedBlindingBindingV1::bind_recovery_capsule(pending, candidate) != bound
        })
        .unwrap_or(false)
    {
        return Err(CryptoError::InvalidPlaintext);
    }
    let primary_plaintext = open(
        primary,
        Kind::SharedPrimary,
        ids,
        nonce_epoch,
        master_key,
        &pending.to_aad_bytes(),
        pending.binding_digest_v1(),
    )?;
    let backup_plaintext = open(
        backup,
        Kind::SharedBackup,
        ids,
        nonce_epoch,
        master_key,
        &pending.to_aad_bytes(),
        pending.binding_digest_v1(),
    )?;
    if primary_plaintext.as_slice() != backup_plaintext.as_slice() {
        return Err(CryptoError::AuthenticationFailed);
    }
    let share = SigningShareV1::from_be_bytes(*fixed_zeroizing::<32>(Zeroizing::new(
        primary_plaintext.to_vec(),
    ))?)
    .map_err(|_| CryptoError::InvalidPlaintext)?;
    if share.public_key() != pending.share_point() || bound.pending_binding() != pending {
        return Err(CryptoError::InvalidPlaintext);
    }
    let aad = bound.to_aad_bytes();
    let digest = bound.binding_digest_v1();
    let recovery_capsule = capsule
        .map(|capsule| {
            seal(
                Kind::SharedRecoveryCapsule,
                ids,
                nonce_epoch,
                master_key,
                &aad,
                digest,
                Zeroizing::new(capsule.as_bytes().to_vec()),
            )
        })
        .transpose()?;
    Ok(SealedSharedBlindingBundleV1 {
        primary: seal(
            Kind::SharedPrimary,
            ids,
            nonce_epoch,
            master_key,
            &aad,
            digest,
            primary_plaintext,
        )?,
        backup: seal(
            Kind::SharedBackup,
            ids,
            nonce_epoch,
            master_key,
            &aad,
            digest,
            backup_plaintext,
        )?,
        recovery_capsule,
    })
}

/// Authenticates and parses the exact restart capsule from one bound record.
pub fn open_shared_blinding_recovery_capsule_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &SharedBlindingBindingV1,
) -> Result<RecoveryCapsule, CryptoError> {
    let plaintext = open(
        envelope,
        Kind::SharedRecoveryCapsule,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
    )?;
    let capsule =
        RecoveryCapsule::from_bytes(&plaintext).map_err(|_| CryptoError::InvalidPlaintext)?;
    if &SharedBlindingBindingV1::bind_recovery_capsule(binding.pending_binding(), &capsule)
        != binding
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(capsule)
}

/// Opens an authenticated provisional primary share only through a DOM import
/// capability.
pub fn open_pending_shared_blinding_record_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &PendingSharedBlindingBindingV1,
    capability: SharedBlindingImportCapabilityV1,
) -> Result<SharedBlindingMaterialV1, CryptoError> {
    let plaintext = open(
        envelope,
        Kind::SharedPrimary,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
    )?;
    capability
        .import(fixed_zeroizing::<32>(plaintext)?)
        .map_err(|_| CryptoError::InvalidPlaintext)
}

/// Opens an authenticated primary share only through a DOM import capability.
pub fn open_shared_blinding_record_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &SharedBlindingBindingV1,
    capability: SharedBlindingImportCapabilityV1,
) -> Result<SharedBlindingMaterialV1, CryptoError> {
    let plaintext = open(
        envelope,
        Kind::SharedPrimary,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
    )?;
    capability
        .import(fixed_zeroizing::<32>(plaintext)?)
        .map_err(|_| CryptoError::InvalidPlaintext)
}

/// Authenticates the independent backup and returns only its derived public point.
pub fn authenticate_shared_blinding_backup_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &SharedBlindingBindingV1,
) -> Result<PublicKey, CryptoError> {
    let plaintext = open(
        envelope,
        Kind::SharedBackup,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
    )?;
    let plaintext = fixed_zeroizing::<32>(plaintext)?;
    let share =
        SigningShareV1::from_be_bytes(*plaintext).map_err(|_| CryptoError::InvalidPlaintext)?;
    Ok(share.public_key().clone())
}

/// Authenticates the independently encrypted provisional backup and returns
/// only the corresponding public point.
pub fn authenticate_pending_shared_blinding_backup_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &PendingSharedBlindingBindingV1,
) -> Result<PublicKey, CryptoError> {
    let plaintext = open(
        envelope,
        Kind::SharedBackup,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
    )?;
    let plaintext = fixed_zeroizing::<32>(plaintext)?;
    let share =
        SigningShareV1::from_be_bytes(*plaintext).map_err(|_| CryptoError::InvalidPlaintext)?;
    Ok(share.public_key().clone())
}

/// Encrypts fresh collaborative-BP common/private nonce material.
pub fn seal_collaborative_bp_nonce_record_v1(
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &CollaborativeBpNonceBindingV1,
    material: CollaborativeBpNonceMaterialV1,
    capability: CollaborativeBpNonceSealCapabilityV1,
) -> Result<CollaborativeSecretEnvelopeV1, CryptoError> {
    let plaintext = Zeroizing::new(capability.into_plaintext(material).to_vec());
    seal(
        Kind::BpNonce,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
        plaintext,
    )
}

/// Opens exact BP nonce material only through the DOM import capability.
pub fn open_collaborative_bp_nonce_record_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &CollaborativeBpNonceBindingV1,
    capability: CollaborativeBpNonceImportCapabilityV1,
) -> Result<CollaborativeBpNonceMaterialV1, CryptoError> {
    let plaintext = open(
        envelope,
        Kind::BpNonce,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
    )?;
    capability
        .import(fixed_zeroizing::<64>(plaintext)?)
        .map_err(|_| CryptoError::InvalidPlaintext)
}

/// Encrypts round-2 and its opaque restart continuation before nonce retirement.
#[allow(
    clippy::too_many_arguments,
    reason = "typed custody inputs stay explicit at this linear BP persistence boundary"
)]
pub fn seal_collaborative_bp_round2_bundle_v1(
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &CollaborativeBpFinalizeBindingV1,
    statement: &BpStatementV1,
    continuation: CollaborativeBpFinalizeContinuationV1,
    share: dom_adaptor::BpRound2ShareV1,
    capability: CollaborativeBpRound2PersistenceCapabilityV1,
) -> Result<SealedCollaborativeBpRound2BundleV1, CryptoError> {
    let (finalize, round2, finalize_import, round2_import) = capability
        .into_plaintext(continuation, share)
        .map_err(|_| CryptoError::InvalidPlaintext)?;
    let nonce_binding = binding.nonce_binding();
    if statement.statement_hash() != *nonce_binding.statement_hash() {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(SealedCollaborativeBpRound2BundleV1 {
        round2: seal(
            Kind::BpRound2,
            ids,
            nonce_epoch,
            master_key,
            &nonce_binding.to_aad_bytes(),
            nonce_binding.binding_digest_v1(),
            Zeroizing::new(round2.to_vec()),
        )?,
        finalize: seal(
            Kind::BpFinalize,
            ids,
            nonce_epoch,
            master_key,
            &binding.to_aad_bytes(),
            binding.binding_digest_v1(),
            finalize,
        )?,
        finalize_import,
        round2_import,
    })
}

/// Reopens a byte-identical durable round-2 send attempt.
pub fn open_collaborative_bp_round2_record_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &CollaborativeBpNonceBindingV1,
    statement: &BpStatementV1,
    capability: CollaborativeBpRound2ImportCapabilityV1,
) -> Result<DurableBpRound2TransportV1, CryptoError> {
    let plaintext = open(
        envelope,
        Kind::BpRound2,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
    )?;
    capability
        .import(statement, fixed_zeroizing::<104>(plaintext)?)
        .map_err(|_| CryptoError::InvalidPlaintext)
}

/// Reopens the authenticated opaque finalizer continuation after restart.
pub fn open_collaborative_bp_finalize_record_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &CollaborativeBpFinalizeBindingV1,
    statement: &BpStatementV1,
    capability: CollaborativeBpFinalizeImportCapabilityV1,
) -> Result<CollaborativeBpFinalizeContinuationV1, CryptoError> {
    let plaintext = open(
        envelope,
        Kind::BpFinalize,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
    )?;
    capability
        .import(statement, plaintext)
        .map_err(|_| CryptoError::InvalidPlaintext)
}

/// Encrypts an already-verified final proof and retains its import authority.
pub fn seal_collaborative_bp_proof_record_v1(
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &CollaborativeBpFinalizeBindingV1,
    proof: RangeProof739,
    capability: CollaborativeBpProofPersistenceCapabilityV1,
) -> Result<SealedCollaborativeBpProofV1, CryptoError> {
    let (proof, import) = capability
        .into_plaintext(proof)
        .map_err(|_| CryptoError::InvalidPlaintext)?;
    Ok(SealedCollaborativeBpProofV1 {
        envelope: seal(
            Kind::BpProof,
            ids,
            nonce_epoch,
            master_key,
            &binding.to_aad_bytes(),
            binding.binding_digest_v1(),
            Zeroizing::new(proof.to_vec()),
        )?,
        import,
    })
}

/// Reopens one immutable, already-verified final proof authority.
pub fn open_collaborative_bp_proof_record_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &CollaborativeBpFinalizeBindingV1,
    statement: &BpStatementV1,
    capability: CollaborativeBpProofImportCapabilityV1,
) -> Result<DurableBpProofTransportV1, CryptoError> {
    let plaintext = open(
        envelope,
        Kind::BpProof,
        ids,
        nonce_epoch,
        master_key,
        &binding.to_aad_bytes(),
        binding.binding_digest_v1(),
    )?;
    let mut proof = [0u8; 739];
    if plaintext.len() != proof.len() {
        return Err(CryptoError::InvalidPlaintext);
    }
    proof.copy_from_slice(&plaintext);
    capability
        .import(statement, proof)
        .map_err(|_| CryptoError::InvalidPlaintext)
}

/// Authenticates an independent backup and mints only the DOM durable ACK.
pub fn acknowledge_shared_blinding_backup_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &SharedBlindingBindingV1,
    capability: DurableShareBackupAckCapabilityV1,
) -> Result<ShareBackupAckV1, CryptoError> {
    let point =
        authenticate_shared_blinding_backup_v1(envelope, ids, nonce_epoch, master_key, binding)?;
    capability
        .acknowledge(binding, point)
        .map_err(|_| CryptoError::InvalidPlaintext)
}

/// Authenticates a provisional independent backup and mints only the DOM
/// durable acknowledgement.
pub fn acknowledge_pending_shared_blinding_backup_v1(
    envelope: &CollaborativeSecretEnvelopeV1,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding: &PendingSharedBlindingBindingV1,
    capability: DurableShareBackupAckCapabilityV1,
) -> Result<ShareBackupAckV1, CryptoError> {
    let point = authenticate_pending_shared_blinding_backup_v1(
        envelope,
        ids,
        nonce_epoch,
        master_key,
        binding,
    )?;
    capability
        .acknowledge_pending(binding, point)
        .map_err(|_| CryptoError::InvalidPlaintext)
}

fn seal(
    kind: Kind,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding_aad: &[u8],
    binding_digest: [u8; 32],
    mut plaintext: Zeroizing<Vec<u8>>,
) -> Result<CollaborativeSecretEnvelopeV1, CryptoError> {
    if nonce_epoch == 0
        || !kind.valid_plaintext_len(plaintext.len())
        || binding_aad.is_empty()
        || binding_digest == [0; 32]
        || *blake2b_256(binding_aad).as_bytes() != binding_digest
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    let mut instance_id = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRandom.fill(&mut instance_id)?;
    OsRandom.fill(&mut nonce_bytes)?;
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_le_bytes());
    header[10] = kind as u8;
    header[12..44].copy_from_slice(ids.contract_wallet_id());
    header[44..76].copy_from_slice(ids.vault_id());
    header[76..84].copy_from_slice(&nonce_epoch.to_le_bytes());
    header[84..116].copy_from_slice(&binding_digest);
    header[116..132].copy_from_slice(&instance_id);
    header[132..144].copy_from_slice(&nonce_bytes);
    header[144..148].copy_from_slice(
        &u32::try_from(plaintext.len())
            .map_err(|_| CryptoError::InvalidPlaintext)?
            .to_le_bytes(),
    );
    let key = derive_key(master_key, ids, &header)?;
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let aad = complete_aad(&header, binding_aad)?;
    let tag = cipher
        .encrypt_in_place_detached((&nonce_bytes).into(), &aad, plaintext.as_mut_slice())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut bytes = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&plaintext);
    bytes.extend_from_slice(tag.as_ref());
    CollaborativeSecretEnvelopeV1::from_bytes(&bytes)
}

fn open(
    envelope: &CollaborativeSecretEnvelopeV1,
    expected_kind: Kind,
    ids: StorageIdsV1,
    nonce_epoch: u64,
    master_key: &VaultMasterKey,
    binding_aad: &[u8],
    binding_digest: [u8; 32],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (kind, plaintext_len) = parse_header(&envelope.bytes)?;
    if kind != expected_kind
        || envelope.kind != expected_kind
        || envelope.plaintext_len != plaintext_len
        || envelope.bytes[12..44] != *ids.contract_wallet_id()
        || envelope.bytes[44..76] != *ids.vault_id()
        || u64::from_le_bytes(
            envelope.bytes[76..84]
                .try_into()
                .map_err(|_| CryptoError::InvalidEnvelope)?,
        ) != nonce_epoch
        || envelope.bytes[84..116] != binding_digest
        || binding_aad.is_empty()
        || *blake2b_256(binding_aad).as_bytes() != binding_digest
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    let header: &[u8; HEADER_LEN] = envelope.bytes[..HEADER_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let key = derive_key(master_key, ids, header)?;
    let aad = complete_aad(header, binding_aad)?;
    let ciphertext_end = HEADER_LEN + plaintext_len;
    let mut plaintext = Zeroizing::new(envelope.bytes[HEADER_LEN..ciphertext_end].to_vec());
    cipher_decrypt(
        &key,
        &envelope.bytes[132..144],
        &aad,
        plaintext.as_mut_slice(),
        &envelope.bytes[ciphertext_end..],
    )?;
    Ok(plaintext)
}

fn cipher_decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &mut [u8],
    tag: &[u8],
) -> Result<(), CryptoError> {
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidEnvelope)?;
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| CryptoError::InvalidEnvelope)?;
    ChaCha20Poly1305::new(key.into())
        .decrypt_in_place_detached((&nonce).into(), aad, plaintext, (&tag).into())
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn derive_key(
    master_key: &VaultMasterKey,
    ids: StorageIdsV1,
    header: &[u8; HEADER_LEN],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let info = tagged_bytes(KEY_LABEL, &header[..132])?;
    derive_hkdf_sha256(ids.vault_id(), master_key.as_bytes(), &info)
}

fn complete_aad(header: &[u8; HEADER_LEN], binding_aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let binding_len = u32::try_from(binding_aad.len()).map_err(|_| CryptoError::InvalidEnvelope)?;
    let mut bytes = Vec::with_capacity(HEADER_LEN + 4 + binding_aad.len());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(&binding_len.to_le_bytes());
    bytes.extend_from_slice(binding_aad);
    let tagged = tagged_bytes(AAD_LABEL, &bytes)?;
    Ok(tagged.to_vec())
}

fn parse_header(bytes: &[u8]) -> Result<(Kind, usize), CryptoError> {
    if bytes.len() < HEADER_LEN + TAG_LEN
        || &bytes[..8] != MAGIC
        || u16::from_le_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| CryptoError::InvalidEnvelope)?,
        ) != VERSION
        || bytes[11] != 0
        || bytes[12..44] == [0; 32]
        || bytes[44..76] == [0; 32]
        || bytes[12..44] == bytes[44..76]
        || bytes[76..84] == [0; 8]
        || bytes[84..116] == [0; 32]
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    let kind = Kind::parse(bytes[10])?;
    let plaintext_len = usize::try_from(u32::from_le_bytes(
        bytes[144..148]
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)?,
    ))
    .map_err(|_| CryptoError::InvalidEnvelope)?;
    if !kind.valid_plaintext_len(plaintext_len)
        || HEADER_LEN
            .checked_add(plaintext_len)
            .and_then(|value| value.checked_add(TAG_LEN))
            != Some(bytes.len())
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok((kind, plaintext_len))
}

fn fixed_zeroizing<const N: usize>(
    mut bytes: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<[u8; N]>, CryptoError> {
    if bytes.len() != N {
        return Err(CryptoError::InvalidPlaintext);
    }
    let mut fixed = Zeroizing::new([0u8; N]);
    fixed.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(fixed)
}

/// Frozen witness of the collaborative cipher path.
///
/// Built BEFORE the `generic-array` deprecation migration and committed on
/// its own, so the migration is measured against the behaviour of the code
/// as it stands.
///
/// Why this file needed one at all: measured before writing it, this module
/// had zero `#[test]` items and was exercised only by
/// `tests/shared_output_v1.rs`, whose twelve failures are PRE-EXISTING —
/// they reproduce identically in the pre-absorption `dom-contracts` tree at
/// `105b9b00`, seven passed and twelve failed on both sides. So the six
/// generic-array sites this round migrates in this file had no green
/// witness. These tests give them one that does not depend on that target.
///
/// `seal` draws from `OsRandom` directly, so its envelope cannot be frozen
/// byte for byte without changing its signature — which this round is not
/// authorised to do. What IS frozen is `cipher_decrypt`, where every input
/// is fixed, plus the deterministic structure of a sealed envelope and the
/// exact plaintext a round trip returns.
#[cfg(test)]
mod frozen_cipher_vectors {
    #![allow(clippy::panic)]

    use super::*;

    const KEY: [u8; 32] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f,
    ];
    const NONCE: [u8; 12] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
    ];
    const AAD: &[u8] = b"DOM-F7/COLLABORATIVE/FROZEN-WITNESS/V1";
    const PLAINTEXT: [u8; 32] = [0x51; 32];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Encrypts the fixed input with the same primitive the module uses, so
    /// the ciphertext and tag below are this code's own output, recorded.
    fn frozen_ciphertext_and_tag() -> ([u8; 32], [u8; 16]) {
        let mut buffer = PLAINTEXT;
        let tag = match ChaCha20Poly1305::new((&KEY).into()).encrypt_in_place_detached(
            (&NONCE).into(),
            AAD,
            &mut buffer,
        ) {
            Ok(tag) => tag,
            Err(error) => panic!("the fixed inputs must encrypt: {error}"),
        };
        let mut tag_bytes = [0_u8; 16];
        tag_bytes.copy_from_slice(tag.as_ref());
        (buffer, tag_bytes)
    }

    /// The ciphertext and tag for the fixed inputs, byte for byte.
    #[test]
    fn the_collaborative_cipher_output_is_frozen() {
        let (ciphertext, tag) = frozen_ciphertext_and_tag();
        assert_eq!(hex(&ciphertext), FROZEN_CIPHERTEXT);
        assert_eq!(hex(&tag), FROZEN_TAG);
    }

    /// `cipher_decrypt` returns the exact plaintext for that frozen input.
    #[test]
    fn cipher_decrypt_returns_the_exact_plaintext() {
        let (ciphertext, tag) = frozen_ciphertext_and_tag();
        let mut buffer = ciphertext;
        if let Err(error) = cipher_decrypt(&KEY, &NONCE, AAD, &mut buffer, &tag) {
            panic!("the frozen envelope must open: {error}");
        }
        assert_eq!(buffer, PLAINTEXT);
    }

    /// Wrong nonce and tag lengths are refused with the typed error rather
    /// than reaching the cipher. This is the guard the migration turns into
    /// a type obligation, so it is pinned before the change.
    #[test]
    fn cipher_decrypt_refuses_every_wrong_length() {
        let (ciphertext, tag) = frozen_ciphertext_and_tag();
        for bad_nonce_len in [0_usize, 1, 11, 13, 32] {
            let mut buffer = ciphertext;
            let nonce = vec![0_u8; bad_nonce_len];
            assert_eq!(
                cipher_decrypt(&KEY, &nonce, AAD, &mut buffer, &tag).err(),
                Some(CryptoError::InvalidEnvelope),
                "nonce length {bad_nonce_len} must be refused"
            );
        }
        for bad_tag_len in [0_usize, 1, 15, 17, 32] {
            let mut buffer = ciphertext;
            let bad_tag = vec![0_u8; bad_tag_len];
            assert_eq!(
                cipher_decrypt(&KEY, &NONCE, AAD, &mut buffer, &bad_tag).err(),
                Some(CryptoError::InvalidEnvelope),
                "tag length {bad_tag_len} must be refused"
            );
        }
    }

    /// A tampered tag or nonce of the right length fails authentication —
    /// which shows the values really are the ones in use.
    #[test]
    fn cipher_decrypt_rejects_tampering() {
        let (ciphertext, tag) = frozen_ciphertext_and_tag();

        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        let mut buffer = ciphertext;
        assert_eq!(
            cipher_decrypt(&KEY, &NONCE, AAD, &mut buffer, &bad_tag).err(),
            Some(CryptoError::AuthenticationFailed)
        );

        let mut bad_nonce = NONCE;
        bad_nonce[0] ^= 0x01;
        let mut buffer = ciphertext;
        assert_eq!(
            cipher_decrypt(&KEY, &bad_nonce, AAD, &mut buffer, &tag).err(),
            Some(CryptoError::AuthenticationFailed)
        );
    }

    const FROZEN_CIPHERTEXT: &str =
        "dae0e0d0be9b8cd312ba9570836c74adec3f5b2a836da936dee0ae37777f51db";
    const FROZEN_TAG: &str = "b06e953df900d784d9cc5a355c79b534";
}

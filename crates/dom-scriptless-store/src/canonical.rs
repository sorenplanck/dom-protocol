//! Canonical V1 persistence records.
//!
//! Structural parsers retain untrusted digest fields without granting them
//! authority. Authenticated constructors and validators recompute every
//! storage digest through the pinned DOM hash boundary.

// NAR-DC-P1-006 section 5.1 intentionally removes the retained filesystem
// runtime on non-Linux targets. The canonical authenticated-record machinery
// remains compiled there so portable parsers and their tests exercise the same
// source, but its crate-private Linux runtime consumers are necessarily absent.
// Keep every other warning denied while acknowledging only those two expected
// reachability diagnostics on the unsupported runtime platforms.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::{error::Error, fmt};

pub use dom_adaptor::{DirectionV1, PermitIdV1, PurposeV1, SigningPhaseV1};
use dom_scriptless_crypto::{authoritative_storage_hash_v1, StorageHashDomainV1};

mod authority;
mod backup;
mod exposure;
mod journal;
mod path;
mod permit;
pub(crate) mod reservation;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use reservation::tests::reserve_records_with_ids;
mod restore;
mod session;
mod tombstone;

pub use authority::{
    ActiveVaultGenerationV1, StoreLockIdentityV1, StoreRootIdentityV1,
    UnauthenticatedActiveVaultGenerationV1, UnauthenticatedStoreLockIdentityV1,
    UnauthenticatedStoreRootIdentityV1, UnauthenticatedVaultGenerationCoreV1,
    VaultGenerationCoreV1, ACTIVE_VAULT_GENERATION_LEN, STORE_IDENTITY_LEN,
    VAULT_GENERATION_CORE_LEN,
};
#[cfg(any(test, feature = "evidence-only"))]
pub(crate) use backup::RestorePendingIndexFieldsV1;
#[cfg(any(test, feature = "evidence-only"))]
pub use backup::{BackupBundleV1, BackupManifestV1};
pub use backup::{
    RestoreOnlyRootV1, RestorePendingIndexV1, UnauthenticatedBackupBundlePreimageV1,
    UnauthenticatedBackupManifestV1, UnauthenticatedRestoreOnlyRootV1,
    UnauthenticatedRestorePendingIndexV1, BACKUP_BUNDLE_PREIMAGE_LEN, BACKUP_MANIFEST_LEN,
    RESTORE_ONLY_ROOT_LEN, RESTORE_PENDING_INDEX_LEN,
};
pub use exposure::{
    adaptor_outbound_digest_v1, contracts_exposure_outbound_digest_v1, ExposureRecordV1,
    ExposureVersionIdV1, UnauthenticatedExposureRecordV1, UnauthenticatedExposureVersionIdV1,
    EXPOSURE_VERSION_ID_LEN,
};
#[cfg(any(test, feature = "evidence-only"))]
pub(crate) use journal::RestoredJournalV1;
pub(crate) use journal::{CompositeJournalV1, LifetimeCollisionIndexV1, RestoreJournalInputsV1};
pub use journal::{
    ExposureAuthorizationPayloadV1, JournalEntryKindV1, JournalEntryV1, JournalPayloadEvidenceV1,
    JournalPayloadV1, MinimalJournalV1, PartialConsumedPayloadV1,
    UnauthenticatedComputationAttemptV1, UnauthenticatedExposureAuthorizationPayloadV1,
    UnauthenticatedJournalEntryV1, UnauthenticatedJournalEnvelopeV1,
    UnauthenticatedJournalPayloadV1, UnauthenticatedPartialConsumedPayloadV1,
    UnauthenticatedReservePayloadV1, UnauthenticatedRestoreCompletePayloadV1,
    JOURNAL_ENTRY_MAX_LEN, JOURNAL_ENTRY_MIN_LEN, JOURNAL_PAYLOAD_MAX_LEN,
};
pub use path::{
    canonical_attempt_relative_path, canonical_backup_directory_name,
    canonical_backup_staging_directory_name, canonical_exposure_relative_path,
    canonical_generation_directory_name, canonical_journal_filename,
    canonical_restore_completed_directory_name, canonical_restore_initialized_marker_name,
    canonical_restore_record_directory_name, canonical_restore_record_filename,
    canonical_restore_record_relative_path, canonical_restore_staging_directory_name,
    canonical_tombstone_filename, canonical_tombstone_staging_filename,
};
pub use permit::{permit_lookup_id_v1, PermitRetirementV1, PERMIT_RETIREMENT_LEN};
pub use reservation::{
    BudgetChargeV1, BudgetPolicyProfileV1, BudgetPolicyV1, NonceDerivationAttemptV1,
    ReservationAuthorityV1, ReservationContextBindingV1, UnauthenticatedNonceDerivationAttemptV1,
    BUDGET_CHARGE_ADAPTOR_LEN, BUDGET_CHARGE_NO_ADAPTOR_LEN, BUDGET_POLICY_LEN,
    NONCE_DERIVATION_ATTEMPT_LEN, RESERVATION_AUTHORITY_ADAPTOR_LEN,
    RESERVATION_AUTHORITY_NO_ADAPTOR_LEN, RESERVATION_CONTEXT_ADAPTOR_LEN,
    RESERVATION_CONTEXT_NO_ADAPTOR_LEN,
};
pub use restore::{
    EpochAdvancePayloadV1, RestoreActionV1, RestoreCompleteV1, RestoreManifestV1,
    RestoreRecordFamilyV1, RestoreRecordPayloadV1, UnauthenticatedEpochAdvancePayloadV1,
    UnauthenticatedRestoreCompleteV1, UnauthenticatedRestoreManifestV1,
    UnauthenticatedRestoreRecordItemV1, UnauthenticatedRestoreRecordKeyV1,
    UnauthenticatedRestoreRecordPayloadV1, UnauthenticatedRestoreRecordSetV1,
    UnauthenticatedRestoreRecordV1, EPOCH_ADVANCE_PAYLOAD_LEN, RESTORE_COMPLETE_LEN,
    RESTORE_MANIFEST_LEN, RESTORE_RECORD_ITEM_PREFIX_LEN, RESTORE_RECORD_KEY_LEN,
    RESTORE_RECORD_PAYLOAD_LEN, RESTORE_RECORD_SET_MIN_LEN,
};
pub(crate) use restore::{RestoreRecordItemV1, RestoreRecordSetLimitsV1, RestoreRecordSetV1};
pub use session::{
    SessionChainProjectionV1, SessionIrreversibleV1, SessionPhaseV1, SessionRecordFieldsV1,
    SessionRecordV1, SessionTxObservationV1,
};
pub(crate) use tombstone::{ActiveSecretEvidenceV1, TerminalEvidenceV1};
pub use tombstone::{TerminalReasonV1, TombstoneV1, UnauthenticatedTombstoneV1, TOMBSTONE_LEN};

/// A redacted failure to parse structurally canonical storage bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalCodecError {
    /// The input violates a fixed length, field, registry, or reserved-byte rule.
    InvalidEncoding,
    /// A stored digest does not authenticate the canonical bytes it claims.
    AuthenticationFailed,
    /// The recognized purpose is forbidden by strict Phase 1 policy.
    PurposeNotAuthorized,
    /// Authenticated records violate a lifecycle, predecessor, or state rule.
    InvalidLifecycle,
    /// A live retained Store authority is required for this operation.
    LiveStoreAuthorityRequired,
    /// A required checked sequence or revision increment overflowed.
    ArithmeticOverflow,
}

impl fmt::Display for CanonicalCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid canonical storage encoding",
            Self::AuthenticationFailed => "canonical storage authentication failed",
            Self::PurposeNotAuthorized => "purpose is not authorized by strict Phase 1 policy",
            Self::InvalidLifecycle => "invalid authenticated storage lifecycle",
            Self::LiveStoreAuthorityRequired => {
                "live retained store authority is required for this operation"
            }
            Self::ArithmeticOverflow => "canonical storage counter overflow",
        })
    }
}

impl Error for CanonicalCodecError {}

/// Exact encoded size of `NonceIdentityV1`.
pub const NONCE_IDENTITY_LEN: usize = 105;
/// Exact encoded size of `SessionClaimV1`.
pub const SESSION_CLAIM_LEN: usize = 155;
/// Exact encoded size of `AttemptRecordV1`.
pub const ATTEMPT_RECORD_LEN: usize = 193;
/// Minimum exact encoded size of `ExposureRecordV1`.
pub const EXPOSURE_RECORD_MIN_LEN: usize = 234;
/// Maximum exact encoded size of `ExposureRecordV1`.
pub const EXPOSURE_RECORD_MAX_LEN: usize = 4_329;
const CLAIM_MAGIC: &[u8; 8] = b"DOMNVSC2";
const ATTEMPT_MAGIC: &[u8; 8] = b"DOMNVAT1";

/// Closed artifact-kind registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ArtifactKindV1 {
    /// Nonce commitment.
    Commitment = 1,
    /// Nonce reveal.
    Reveal = 2,
    /// Participant partial signature.
    PartialSignature = 3,
}

impl TryFrom<u8> for ArtifactKindV1 {
    type Error = CanonicalCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Commitment),
            2 => Ok(Self::Reveal),
            3 => Ok(Self::PartialSignature),
            _ => Err(CanonicalCodecError::InvalidEncoding),
        }
    }
}

impl ArtifactKindV1 {
    /// Returns the storage artifact assigned to an adaptor signing phase.
    pub fn for_signing_phase(phase: SigningPhaseV1) -> Result<Self, CanonicalCodecError> {
        match phase {
            SigningPhaseV1::SigNonceCommit => Ok(Self::Commitment),
            SigningPhaseV1::SigNonceReveal => Ok(Self::Reveal),
            SigningPhaseV1::SigPartial => Ok(Self::PartialSignature),
            SigningPhaseV1::SigBinding | SigningPhaseV1::SigAdapt | SigningPhaseV1::SigExtract => {
                Err(CanonicalCodecError::InvalidLifecycle)
            }
        }
    }

    /// Returns the immutable exposure sequence assigned to this artifact.
    pub const fn exposure_sequence(self) -> u64 {
        match self {
            Self::Commitment => 1,
            Self::Reveal => 2,
            Self::PartialSignature => 3,
        }
    }
}

/// Closed immutable exposure-state registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExposureStateV1 {
    /// Exact outbound bytes are persisted.
    Persisted = 1,
    /// Durable authorization exists.
    Authorized = 2,
    /// The authorization was irreversibly spent.
    Spent = 3,
}

impl TryFrom<u8> for ExposureStateV1 {
    type Error = CanonicalCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Persisted),
            2 => Ok(Self::Authorized),
            3 => Ok(Self::Spent),
            _ => Err(CanonicalCodecError::InvalidEncoding),
        }
    }
}

/// Structurally validated canonical 105-byte nonce identity.
///
/// The purpose byte is restricted to the signed V1 registry. Sponsor (`0x04`)
/// remains recognized by structural parsing, while authenticated construction
/// and validation reject it through the pinned `dom-adaptor::PurposeV1`
/// strict Phase 1 policy.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct NonceIdentityV1 {
    bytes: [u8; NONCE_IDENTITY_LEN],
    purpose: PurposeV1,
}

impl NonceIdentityV1 {
    /// Constructs a canonical identity authorized by strict Phase 1 policy.
    pub fn new(
        session_id: [u8; 32],
        participant_id: [u8; 32],
        purpose: PurposeV1,
        bound_digest: [u8; 32],
        nonce_epoch: u64,
    ) -> Result<Self, CanonicalCodecError> {
        require_strict_purpose(purpose)?;
        if is_zero(&session_id)
            || is_zero(&participant_id)
            || is_zero(&bound_digest)
            || nonce_epoch == 0
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let mut bytes = [0_u8; NONCE_IDENTITY_LEN];
        bytes[..32].copy_from_slice(&session_id);
        bytes[32..64].copy_from_slice(&participant_id);
        bytes[64] = purpose.to_byte();
        bytes[65..97].copy_from_slice(&bound_digest);
        bytes[97..105].copy_from_slice(&nonce_epoch.to_le_bytes());
        Ok(Self { bytes, purpose })
    }

    /// Authenticates the purpose policy of a structurally parsed identity.
    pub fn require_strict_phase1(&self) -> Result<(), CanonicalCodecError> {
        require_strict_purpose(self.purpose)
    }

    /// Returns the canonical session identifier.
    pub fn session_id(&self) -> &[u8] {
        &self.bytes[..32]
    }

    /// Returns the canonical participant identifier.
    pub fn participant_id(&self) -> &[u8] {
        &self.bytes[32..64]
    }

    /// Returns the structurally validated V1 purpose byte.
    pub const fn purpose_byte(&self) -> u8 {
        self.bytes[64]
    }

    /// Returns the adaptor-owned canonical purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    /// Returns the context-bound digest bytes.
    pub fn bound_digest(&self) -> &[u8] {
        &self.bytes[65..97]
    }

    /// Returns the nonzero nonce epoch.
    pub fn nonce_epoch(&self) -> u64 {
        read_u64(&self.bytes[97..105])
    }

    /// Returns the exact canonical identity bytes.
    pub const fn as_bytes(&self) -> &[u8; NONCE_IDENTITY_LEN] {
        &self.bytes
    }
}

/// Parses the exact 105-byte canonical identity.
pub fn parse_nonce_identity(bytes: &[u8]) -> Result<NonceIdentityV1, CanonicalCodecError> {
    let bytes = exact::<NONCE_IDENTITY_LEN>(bytes)?;
    let purpose =
        PurposeV1::try_from(bytes[64]).map_err(|_| CanonicalCodecError::InvalidEncoding)?;
    if is_zero(&bytes[..32])
        || is_zero(&bytes[32..64])
        || is_zero(&bytes[65..97])
        || read_u64(&bytes[97..105]) == 0
    {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    Ok(NonceIdentityV1 { bytes, purpose })
}

/// Encodes the exact canonical identity bytes.
pub const fn encode_nonce_identity(identity: &NonceIdentityV1) -> [u8; NONCE_IDENTITY_LEN] {
    *identity.as_bytes()
}

/// Authenticated canonical 155-byte lifetime session claim.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionClaimV1 {
    bytes: [u8; SESSION_CLAIM_LEN],
    identity: NonceIdentityV1,
    claim_digest: [u8; 32],
}

impl SessionClaimV1 {
    /// Constructs and authenticates the unique revision-one session claim.
    pub fn new(identity: NonceIdentityV1) -> Result<Self, CanonicalCodecError> {
        identity.require_strict_phase1()?;
        let mut bytes = [0_u8; SESSION_CLAIM_LEN];
        bytes[..8].copy_from_slice(CLAIM_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..115].copy_from_slice(identity.as_bytes());
        bytes[115..123].copy_from_slice(&1_u64.to_le_bytes());
        let claim_digest = storage_hash(StorageHashDomainV1::SessionClaim, &bytes[..123]);
        bytes[123..155].copy_from_slice(&claim_digest);
        Ok(Self {
            bytes,
            identity,
            claim_digest,
        })
    }

    /// Parses exact bytes and authenticates the claim digest and purpose policy.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedSessionClaimV1::parse_structural(input)?;
        structural.identity().require_strict_phase1()?;
        let expected = storage_hash(StorageHashDomainV1::SessionClaim, &input[..123]);
        if structural.claim_digest() != expected {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
            identity: *structural.identity(),
            claim_digest: expected,
        })
    }

    /// Returns the exact authenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; SESSION_CLAIM_LEN] {
        &self.bytes
    }

    /// Returns the claimed nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the fixed claim revision, exactly one.
    pub const fn claim_revision(&self) -> u64 {
        1
    }

    /// Returns the authenticated claim digest.
    pub const fn claim_digest(&self) -> &[u8; 32] {
        &self.claim_digest
    }
}

/// Structurally parsed claim whose digest has not been authenticated.
pub struct UnauthenticatedSessionClaimV1 {
    bytes: [u8; SESSION_CLAIM_LEN],
    identity: NonceIdentityV1,
}

impl UnauthenticatedSessionClaimV1 {
    /// Parses fixed bytes, closed fields, and bounds without authenticating the digest.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<SESSION_CLAIM_LEN>(input)?;
        if &bytes[..8] != CLAIM_MAGIC || read_u16(&bytes[8..10]) != 1 {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let identity = parse_nonce_identity(&bytes[10..115])?;
        if read_u64(&bytes[115..123]) != 1 {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self { bytes, identity })
    }

    /// Returns the structurally parsed identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; SESSION_CLAIM_LEN] {
        &self.bytes
    }

    /// Returns the unauthenticated claim digest.
    pub fn claim_digest(&self) -> &[u8] {
        &self.bytes[123..155]
    }
}

/// Structurally parsed attempt whose digest has not been authenticated.
pub struct UnauthenticatedAttemptRecordV1 {
    bytes: [u8; ATTEMPT_RECORD_LEN],
    identity: NonceIdentityV1,
    phase: SigningPhaseV1,
    artifact: ArtifactKindV1,
}

impl UnauthenticatedAttemptRecordV1 {
    /// Parses exact fixed bytes and the permitted phase/artifact mapping.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<ATTEMPT_RECORD_LEN>(input)?;
        if &bytes[..8] != ATTEMPT_MAGIC
            || read_u16(&bytes[8..10]) != 1
            || read_u64(&bytes[115..123]) == 0
            || bytes[126..129] != [0; 3]
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let identity = parse_nonce_identity(&bytes[10..115])?;
        let phase = SigningPhaseV1::try_from(read_u16(&bytes[123..125]))
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        let artifact = ArtifactKindV1::try_from(bytes[125])?;
        if !matches!(
            (phase, artifact),
            (SigningPhaseV1::SigNonceCommit, ArtifactKindV1::Commitment)
                | (SigningPhaseV1::SigNonceReveal, ArtifactKindV1::Reveal)
                | (SigningPhaseV1::SigPartial, ArtifactKindV1::PartialSignature)
        ) {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            identity,
            phase,
            artifact,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; ATTEMPT_RECORD_LEN] {
        &self.bytes
    }
    /// Returns the identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }
    /// Returns the closed signing phase.
    pub const fn phase(&self) -> SigningPhaseV1 {
        self.phase
    }
    /// Returns the closed artifact kind.
    pub const fn artifact(&self) -> ArtifactKindV1 {
        self.artifact
    }

    /// Returns the nonzero expected lifecycle revision.
    pub fn expected_lifecycle_revision(&self) -> u64 {
        read_u64(&self.bytes[115..123])
    }

    /// Returns the unauthenticated attempt digest.
    pub fn attempt_digest(&self) -> &[u8] {
        &self.bytes[161..193]
    }
}

/// Authenticated canonical 193-byte computation attempt.
#[derive(Clone, Eq, PartialEq)]
pub struct AttemptRecordV1 {
    bytes: [u8; ATTEMPT_RECORD_LEN],
    identity: NonceIdentityV1,
    phase: SigningPhaseV1,
    artifact: ArtifactKindV1,
    operation_input_digest: [u8; 32],
    attempt_digest: [u8; 32],
}

impl AttemptRecordV1 {
    /// Constructs a durable attempt for one adaptor-owned secret-opening phase.
    pub fn new(
        identity: NonceIdentityV1,
        expected_lifecycle_revision: u64,
        phase: SigningPhaseV1,
        operation_input_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        identity.require_strict_phase1()?;
        if expected_lifecycle_revision == 0 {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let artifact = ArtifactKindV1::for_signing_phase(phase)?;
        let mut bytes = [0_u8; ATTEMPT_RECORD_LEN];
        bytes[..8].copy_from_slice(ATTEMPT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..115].copy_from_slice(identity.as_bytes());
        bytes[115..123].copy_from_slice(&expected_lifecycle_revision.to_le_bytes());
        bytes[123..125].copy_from_slice(&phase.to_le_bytes());
        bytes[125] = artifact as u8;
        bytes[129..161].copy_from_slice(&operation_input_digest);
        let attempt_digest = storage_hash(StorageHashDomainV1::Attempt, &bytes[..161]);
        bytes[161..193].copy_from_slice(&attempt_digest);
        Ok(Self {
            bytes,
            identity,
            phase,
            artifact,
            operation_input_digest,
            attempt_digest,
        })
    }

    /// Parses exact bytes and authenticates the attempt digest and purpose policy.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedAttemptRecordV1::parse_structural(input)?;
        structural.identity().require_strict_phase1()?;
        let expected = storage_hash(StorageHashDomainV1::Attempt, &input[..161]);
        if structural.attempt_digest() != expected {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        let mut operation_input_digest = [0_u8; 32];
        operation_input_digest.copy_from_slice(&input[129..161]);
        Ok(Self {
            bytes: *structural.as_bytes(),
            identity: *structural.identity(),
            phase: structural.phase(),
            artifact: structural.artifact(),
            operation_input_digest,
            attempt_digest: expected,
        })
    }

    /// Returns the exact authenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; ATTEMPT_RECORD_LEN] {
        &self.bytes
    }

    /// Returns the nonce identity.
    pub const fn identity(&self) -> &NonceIdentityV1 {
        &self.identity
    }

    /// Returns the adaptor-owned signing phase.
    pub const fn phase(&self) -> SigningPhaseV1 {
        self.phase
    }

    /// Returns the storage artifact assigned to the signing phase.
    pub const fn artifact(&self) -> ArtifactKindV1 {
        self.artifact
    }

    /// Returns the current lifecycle revision named by this attempt.
    pub fn expected_lifecycle_revision(&self) -> u64 {
        read_u64(&self.bytes[115..123])
    }

    /// Returns the canonical operation-input digest.
    pub const fn operation_input_digest(&self) -> &[u8; 32] {
        &self.operation_input_digest
    }

    /// Returns the authenticated attempt digest.
    pub const fn attempt_digest(&self) -> &[u8; 32] {
        &self.attempt_digest
    }
}

fn exact<const N: usize>(input: &[u8]) -> Result<[u8; N], CanonicalCodecError> {
    if input.len() != N {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(input);
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

fn storage_hash(domain: StorageHashDomainV1, bytes: &[u8]) -> [u8; 32] {
    authoritative_storage_hash_v1(domain, bytes)
}

fn require_strict_purpose(purpose: PurposeV1) -> Result<(), CanonicalCodecError> {
    purpose
        .require_strict_phase1()
        .map(|_| ())
        .map_err(|_| CanonicalCodecError::PurposeNotAuthorized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_identity(purpose: PurposeV1) -> Result<NonceIdentityV1, CanonicalCodecError> {
        NonceIdentityV1::new([0x11; 32], [0x22; 32], purpose, [0x33; 32], 7)
    }

    fn identity_bytes(purpose: u8) -> [u8; NONCE_IDENTITY_LEN] {
        let mut bytes = [0_u8; NONCE_IDENTITY_LEN];
        bytes[..32].fill(0x11);
        bytes[32..64].fill(0x22);
        bytes[64] = purpose;
        bytes[65..97].fill(0x33);
        bytes[97..105].copy_from_slice(&7_u64.to_le_bytes());
        bytes
    }

    fn claim_bytes(purpose: u8) -> [u8; SESSION_CLAIM_LEN] {
        let mut bytes = [0_u8; SESSION_CLAIM_LEN];
        bytes[..8].copy_from_slice(CLAIM_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..115].copy_from_slice(&identity_bytes(purpose));
        bytes[115..123].copy_from_slice(&1_u64.to_le_bytes());
        bytes
    }

    fn attempt_bytes(phase: SigningPhaseV1, artifact: ArtifactKindV1) -> [u8; ATTEMPT_RECORD_LEN] {
        let mut bytes = [0_u8; ATTEMPT_RECORD_LEN];
        bytes[..8].copy_from_slice(ATTEMPT_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..115].copy_from_slice(&identity_bytes(0x02));
        bytes[115..123].copy_from_slice(&9_u64.to_le_bytes());
        bytes[123..125].copy_from_slice(&(phase as u16).to_le_bytes());
        bytes[125] = artifact as u8;
        bytes
    }

    #[test]
    fn identity_accepts_only_the_closed_signed_purpose_registry() -> Result<(), CanonicalCodecError>
    {
        for purpose in 0x01..=0x04 {
            let bytes = identity_bytes(purpose);
            let identity = parse_nonce_identity(&bytes)?;
            assert_eq!(identity.purpose_byte(), purpose);
            assert_eq!(encode_nonce_identity(&identity), bytes);
        }
        assert!(parse_nonce_identity(&identity_bytes(0)).is_err());
        for purpose in 0x05..=u8::MAX {
            assert!(parse_nonce_identity(&identity_bytes(purpose)).is_err());
        }
        Ok(())
    }

    #[test]
    fn identity_rejects_zero_fixed_fields_and_non_exact_lengths() {
        let canonical = identity_bytes(0x02);
        assert!(parse_nonce_identity(&canonical[..NONCE_IDENTITY_LEN - 1]).is_err());

        for range in [0..32, 32..64, 65..97] {
            let mut bytes = canonical;
            bytes[range].fill(0);
            assert!(parse_nonce_identity(&bytes).is_err());
        }
        let mut zero_epoch = canonical;
        zero_epoch[97..105].fill(0);
        assert!(parse_nonce_identity(&zero_epoch).is_err());
    }

    #[test]
    fn claim_structural_parser_does_not_add_a_zero_digest_rule() -> Result<(), CanonicalCodecError>
    {
        let bytes = claim_bytes(0x03);
        let parsed = UnauthenticatedSessionClaimV1::parse_structural(&bytes)?;
        assert_eq!(parsed.as_bytes(), &bytes);
        assert_eq!(parsed.identity().purpose_byte(), 0x03);

        let mut wrong_revision = bytes;
        wrong_revision[115..123].copy_from_slice(&2_u64.to_le_bytes());
        assert!(UnauthenticatedSessionClaimV1::parse_structural(&wrong_revision).is_err());
        Ok(())
    }

    #[test]
    fn attempt_structural_parser_accepts_only_signed_phase_artifact_pairs(
    ) -> Result<(), CanonicalCodecError> {
        let valid = [
            (SigningPhaseV1::SigNonceCommit, ArtifactKindV1::Commitment),
            (SigningPhaseV1::SigNonceReveal, ArtifactKindV1::Reveal),
            (SigningPhaseV1::SigPartial, ArtifactKindV1::PartialSignature),
        ];
        for (phase, artifact) in valid {
            let bytes = attempt_bytes(phase, artifact);
            let parsed = UnauthenticatedAttemptRecordV1::parse_structural(&bytes)?;
            assert_eq!(parsed.as_bytes(), &bytes);
            assert_eq!(parsed.phase(), phase);
            assert_eq!(parsed.artifact(), artifact);
        }

        let phases = [
            SigningPhaseV1::SigNonceCommit,
            SigningPhaseV1::SigNonceReveal,
            SigningPhaseV1::SigBinding,
            SigningPhaseV1::SigPartial,
            SigningPhaseV1::SigAdapt,
            SigningPhaseV1::SigExtract,
        ];
        let artifacts = [
            ArtifactKindV1::Commitment,
            ArtifactKindV1::Reveal,
            ArtifactKindV1::PartialSignature,
        ];
        for phase in phases {
            for artifact in artifacts {
                let expected = matches!(
                    (phase, artifact),
                    (SigningPhaseV1::SigNonceCommit, ArtifactKindV1::Commitment)
                        | (SigningPhaseV1::SigNonceReveal, ArtifactKindV1::Reveal)
                        | (SigningPhaseV1::SigPartial, ArtifactKindV1::PartialSignature)
                );
                assert_eq!(
                    UnauthenticatedAttemptRecordV1::parse_structural(&attempt_bytes(
                        phase, artifact
                    ))
                    .is_ok(),
                    expected
                );
            }
        }
        Ok(())
    }

    #[test]
    fn all_structural_registries_reject_undefined_discriminants() {
        for value in 0_u8..=u8::MAX {
            assert_eq!(
                ArtifactKindV1::try_from(value).is_ok(),
                (0x01..=0x03).contains(&value)
            );
            assert_eq!(
                ExposureStateV1::try_from(value).is_ok(),
                (0x01..=0x03).contains(&value)
            );
        }

        for value in 0_u16..=u16::MAX {
            assert_eq!(
                SigningPhaseV1::try_from(value).is_ok(),
                (0x0100..=0x0105).contains(&value)
            );
        }
    }

    #[test]
    fn base_records_reject_every_truncation_and_trailing_byte() {
        let identity = identity_bytes(0x02);
        for end in 0..identity.len() {
            assert!(
                parse_nonce_identity(&identity[..end]).is_err(),
                "identity {end}"
            );
        }
        let mut trailing_identity = identity.to_vec();
        trailing_identity.push(0);
        assert!(parse_nonce_identity(&trailing_identity).is_err());

        let claim = claim_bytes(0x02);
        for end in 0..claim.len() {
            assert!(
                UnauthenticatedSessionClaimV1::parse_structural(&claim[..end]).is_err(),
                "claim {end}"
            );
        }
        let mut trailing_claim = claim.to_vec();
        trailing_claim.push(0);
        assert!(UnauthenticatedSessionClaimV1::parse_structural(&trailing_claim).is_err());

        let attempt = attempt_bytes(SigningPhaseV1::SigNonceCommit, ArtifactKindV1::Commitment);
        for end in 0..attempt.len() {
            assert!(
                UnauthenticatedAttemptRecordV1::parse_structural(&attempt[..end]).is_err(),
                "attempt {end}"
            );
        }
        let mut trailing_attempt = attempt.to_vec();
        trailing_attempt.push(0);
        assert!(UnauthenticatedAttemptRecordV1::parse_structural(&trailing_attempt).is_err());
    }

    #[test]
    fn authenticated_identity_uses_adaptor_purpose_policy() -> Result<(), CanonicalCodecError> {
        for purpose in [
            PurposeV1::Refund,
            PurposeV1::ClaimAdaptor,
            PurposeV1::Funding,
        ] {
            let identity = strict_identity(purpose)?;
            assert_eq!(identity.purpose(), purpose);
            assert_eq!(identity.purpose_byte(), purpose.to_byte());
            assert_eq!(
                parse_nonce_identity(identity.as_bytes())?.purpose(),
                purpose
            );
        }

        assert_eq!(
            strict_identity(PurposeV1::Sponsor).err(),
            Some(CanonicalCodecError::PurposeNotAuthorized)
        );
        let sponsor = identity_bytes(PurposeV1::Sponsor.to_byte());
        assert_eq!(
            parse_nonce_identity(&sponsor)?.require_strict_phase1(),
            Err(CanonicalCodecError::PurposeNotAuthorized)
        );
        let mut unknown = sponsor;
        unknown[64] = 0xff;
        assert!(parse_nonce_identity(&unknown).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_claim_round_trips_and_rejects_every_mutation(
    ) -> Result<(), CanonicalCodecError> {
        let claim = SessionClaimV1::new(strict_identity(PurposeV1::ClaimAdaptor)?)?;
        let parsed = SessionClaimV1::from_bytes(claim.as_bytes())?;
        assert_eq!(parsed.as_bytes(), claim.as_bytes());
        assert_eq!(parsed.claim_digest(), claim.claim_digest());

        for offset in 0..SESSION_CLAIM_LEN {
            let mut mutation = *claim.as_bytes();
            mutation[offset] ^= 1;
            assert!(
                SessionClaimV1::from_bytes(&mutation).is_err(),
                "offset {offset}"
            );
        }

        let mut sponsor = *claim.as_bytes();
        sponsor[10 + 64] = PurposeV1::Sponsor.to_byte();
        let digest = storage_hash(StorageHashDomainV1::SessionClaim, &sponsor[..123]);
        sponsor[123..155].copy_from_slice(&digest);
        assert_eq!(
            SessionClaimV1::from_bytes(&sponsor).err(),
            Some(CanonicalCodecError::PurposeNotAuthorized)
        );
        Ok(())
    }

    #[test]
    fn authenticated_attempt_uses_only_secret_opening_phase_mappings(
    ) -> Result<(), CanonicalCodecError> {
        let identity = strict_identity(PurposeV1::Refund)?;
        let valid = [
            (SigningPhaseV1::SigNonceCommit, ArtifactKindV1::Commitment),
            (SigningPhaseV1::SigNonceReveal, ArtifactKindV1::Reveal),
            (SigningPhaseV1::SigPartial, ArtifactKindV1::PartialSignature),
        ];
        for (phase, artifact) in valid {
            let attempt = AttemptRecordV1::new(identity, 9, phase, [0x44; 32])?;
            let parsed = AttemptRecordV1::from_bytes(attempt.as_bytes())?;
            assert_eq!(parsed.phase(), phase);
            assert_eq!(parsed.artifact(), artifact);
            assert_eq!(parsed.attempt_digest(), attempt.attempt_digest());
        }
        for phase in [
            SigningPhaseV1::SigBinding,
            SigningPhaseV1::SigAdapt,
            SigningPhaseV1::SigExtract,
        ] {
            assert_eq!(
                AttemptRecordV1::new(identity, 9, phase, [0x44; 32]).err(),
                Some(CanonicalCodecError::InvalidLifecycle)
            );
        }
        Ok(())
    }

    #[test]
    fn authenticated_attempt_rejects_digest_mutations_and_unknown_phase(
    ) -> Result<(), CanonicalCodecError> {
        let attempt = AttemptRecordV1::new(
            strict_identity(PurposeV1::Funding)?,
            9,
            SigningPhaseV1::SigNonceReveal,
            [0x44; 32],
        )?;
        for offset in 0..ATTEMPT_RECORD_LEN {
            let mut mutation = *attempt.as_bytes();
            mutation[offset] ^= 1;
            assert!(
                AttemptRecordV1::from_bytes(&mutation).is_err(),
                "offset {offset}"
            );
        }

        let mut unknown = *attempt.as_bytes();
        unknown[123..125].copy_from_slice(&0x0200_u16.to_le_bytes());
        let digest = storage_hash(StorageHashDomainV1::Attempt, &unknown[..161]);
        unknown[161..193].copy_from_slice(&digest);
        assert!(AttemptRecordV1::from_bytes(&unknown).is_err());
        Ok(())
    }
}

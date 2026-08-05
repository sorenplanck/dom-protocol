//! Storage-independent contract for a durable, rollback-resistant Nonce Vault.

use crate::{
    AdaptorError, BindingFactorV1, ExposureKindV1, NonceCommitmentV1, NonceRevealV1,
    PartialSignatureV1, PublicNoncePairV1, PurposeV1, SigningPhaseV1,
};
use core::fmt;
use dom_crypto::{blake2b_256_tagged, PublicKey};
use rand_core::{OsRng, RngCore};
use std::error::Error;

macro_rules! opaque_identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            #[doc = "Constructs the identifier, rejecting an empty representation."]
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, NonceVaultError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    return Err(NonceVaultError::InvalidIdentifier);
                }
                Ok(Self(bytes))
            }

            #[doc = "Returns the local opaque representation."]
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

opaque_identifier!(
    VaultKeyId,
    "Opaque local identifier for a signing key budget."
);
opaque_identifier!(
    ReservationNonceId,
    "Stable identifier for one charged nonce reservation."
);
opaque_identifier!(
    ParticipantId,
    "Stable protocol participant identity bound by an exposure permit."
);
opaque_identifier!(
    TemplateHash,
    "Canonical contract-template hash bound by an exposure permit."
);
opaque_identifier!(
    SessionId,
    "Opaque local identifier for one adaptor session."
);
opaque_identifier!(
    CounterpartyBucket,
    "Opaque local bucket used for the secondary counterparty budget."
);
opaque_identifier!(
    ReservationRequestLookupV1,
    "Public non-authoritative lookup for one prepared reservation request."
);
opaque_identifier!(
    PermitIdV1,
    "Public non-authoritative lookup for one exact already-spent exposure."
);

/// Backward-compatible semantic name for the canonical V1 purpose registry.
pub type Purpose = PurposeV1;

/// Scope in which a configured budget prevented a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetScope {
    /// The per-key lifetime budget.
    GlobalKey,
    /// The per-key and per-counterparty budget.
    Counterparty,
    /// The configured concurrent-session budget.
    Concurrent,
    /// The configured rolling-window budget.
    Window,
}

/// Monotonic state of a reserved nonce slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationState {
    /// Budget and nonce slots are durably reserved.
    Reserved,
    /// Exact public bytes are durably committed and cannot change.
    CommitmentAuthorized,
    /// Exact nonce reveal is durably authorized by the witness.
    RevealAuthorized,
    /// Secret nonce material is destroyed and the partial is authorized.
    ConsumedPartialAuthorized,
    /// No public material existed when the reservation was aborted.
    AbortedBeforePublicMaterial,
    /// Public material may have existed, so abort burned the nonce.
    ConsumedOnAbort,
    /// Ambiguous restore conservatively burned the nonce.
    Burned,
}

/// Capability state after normal startup or restoration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreState {
    /// Local journal and remote anchor evidence agree.
    Operational,
    /// Adaptor operations are fail-closed pending witness reconciliation.
    RestoreQuarantined,
}

/// Public material whose exact bytes must be persisted before exposure.
///
/// The representation is deliberately opaque: this contract does not define a
/// witness wire protocol or a cryptographic transcript.
#[derive(Clone, Eq, PartialEq)]
pub struct ExposureBytes {
    kind: ExposureKindV1,
    bytes: Box<[u8]>,
}

impl ExposureBytes {
    /// Creates an opaque byte-exact exposure value.
    pub fn from_bytes(
        kind: ExposureKindV1,
        bytes: impl Into<Box<[u8]>>,
    ) -> Result<Self, NonceVaultError> {
        let bytes = bytes.into();
        if bytes.len() != kind.outbound_len() {
            return Err(NonceVaultError::InvalidPublicMaterial);
        }
        Ok(Self { kind, bytes })
    }

    /// Returns the closed exposure kind.
    pub const fn kind(&self) -> ExposureKindV1 {
        self.kind
    }

    /// Returns the exact committed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Computes the exact stage-bound NAR-002 outbound digest.
    pub fn outbound_digest(&self) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(5 + self.bytes.len());
        preimage.push(self.kind.to_byte());
        preimage.extend_from_slice(&(self.bytes.len() as u32).to_le_bytes());
        preimage.extend_from_slice(&self.bytes);
        *blake2b_256_tagged("DOM:scriptless-vault-outbound:v1", &preimage).as_bytes()
    }
}

impl fmt::Debug for ExposureBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExposureBytes([redacted])")
    }
}

/// Durable reservation metadata returned by the vault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceReservation {
    /// Stable local reservation identifier.
    pub reservation_id: ReservationNonceId,
    /// Current monotonic lifecycle state.
    pub state: ReservationState,
}

/// Canonical public binding carried by an opaque DOM Contracts store permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposurePermitBindingV1 {
    permit_id: PermitIdV1,
    reservation_id: ReservationNonceId,
    session_id: SessionId,
    participant_id: ParticipantId,
    purpose: PurposeV1,
    template_hash: TemplateHash,
    outbound_digest: [u8; 32],
    exposure_kind: ExposureKindV1,
    epoch: u64,
    semantic_revision: u64,
    receipt_chain_hash: [u8; 32],
}

impl ExposurePermitBindingV1 {
    /// Exact canonical persisted record length.
    pub const ENCODED_LEN: usize = 252;

    /// Parse the canonical durable record without creating authorization authority.
    pub fn from_persistence_bytes(bytes: &[u8]) -> Result<Self, NonceVaultError> {
        if bytes.len() != Self::ENCODED_LEN
            || &bytes[..8] != b"DOMEXPV1"
            || u16::from_le_bytes([bytes[8], bytes[9]]) != 1
        {
            return Err(NonceVaultError::InvalidPermit);
        }
        let exposure_kind = ExposureKindV1::try_from(bytes[10])
            .map_err(|_| NonceVaultError::UnsupportedExposureKind)?;
        let purpose =
            PurposeV1::try_from(bytes[139]).map_err(|_| NonceVaultError::UnsupportedPurpose)?;
        if !purpose.is_strict_v1_authorized() {
            return Err(NonceVaultError::UnsupportedPurpose);
        }
        Self::new(
            PermitIdV1::from_bytes(permit_field(&bytes[11..43])?)?,
            ReservationNonceId::from_bytes(permit_field(&bytes[43..75])?)?,
            SessionId::from_bytes(permit_field(&bytes[75..107])?)?,
            ParticipantId::from_bytes(permit_field(&bytes[107..139])?)?,
            purpose,
            TemplateHash::from_bytes(permit_field(&bytes[140..172])?)?,
            permit_field(&bytes[172..204])?,
            exposure_kind,
            u64::from_le_bytes(permit_field(&bytes[204..212])?),
            u64::from_le_bytes(permit_field(&bytes[212..220])?),
            permit_field(&bytes[220..252])?,
        )
    }

    /// Validates the fields bound by a durable DOM Contracts store permit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        permit_id: PermitIdV1,
        reservation_id: ReservationNonceId,
        session_id: SessionId,
        participant_id: ParticipantId,
        purpose: PurposeV1,
        template_hash: TemplateHash,
        outbound_digest: [u8; 32],
        exposure_kind: ExposureKindV1,
        epoch: u64,
        semantic_revision: u64,
        receipt_chain_hash: [u8; 32],
    ) -> Result<Self, NonceVaultError> {
        if outbound_digest.iter().all(|byte| *byte == 0)
            || receipt_chain_hash.iter().all(|byte| *byte == 0)
            || epoch == 0
        {
            return Err(NonceVaultError::InvalidPermit);
        }
        Ok(Self {
            permit_id,
            reservation_id,
            session_id,
            participant_id,
            purpose,
            template_hash,
            outbound_digest,
            exposure_kind,
            epoch,
            semantic_revision,
            receipt_chain_hash,
        })
    }

    /// Returns the exact 252-byte canonical binding representation.
    pub fn persistence_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, b"DOMEXPV1");
        append(&mut bytes, &mut cursor, &1u16.to_le_bytes());
        append(&mut bytes, &mut cursor, &[self.exposure_kind as u8]);
        append(&mut bytes, &mut cursor, self.permit_id.as_bytes());
        append(&mut bytes, &mut cursor, self.reservation_id.as_bytes());
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        append(&mut bytes, &mut cursor, self.participant_id.as_bytes());
        append(&mut bytes, &mut cursor, &[self.purpose as u8]);
        append(&mut bytes, &mut cursor, self.template_hash.as_bytes());
        append(&mut bytes, &mut cursor, &self.outbound_digest);
        append(&mut bytes, &mut cursor, &self.epoch.to_le_bytes());
        append(
            &mut bytes,
            &mut cursor,
            &self.semantic_revision.to_le_bytes(),
        );
        append(&mut bytes, &mut cursor, &self.receipt_chain_hash);
        debug_assert_eq!(cursor, bytes.len());
        bytes
    }

    /// Computes the canonical permit digest.
    pub fn digest(&self) -> [u8; 32] {
        *blake2b_256_tagged(
            "DOM:scriptless-vault-exposure-permit:v1",
            &self.persistence_bytes(),
        )
        .as_bytes()
    }

    /// Return the one-shot permit identifier.
    pub const fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }

    /// Return the reservation identifier.
    pub const fn reservation_id(&self) -> &ReservationNonceId {
        &self.reservation_id
    }

    /// Return the bound session identifier.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Return the bound participant identifier.
    pub const fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    /// Return the closed purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    /// Return the template hash.
    pub const fn template_hash(&self) -> &TemplateHash {
        &self.template_hash
    }

    /// Return the exact outbound digest.
    pub const fn outbound_digest(&self) -> &[u8; 32] {
        &self.outbound_digest
    }

    /// Return the closed exposure kind.
    pub const fn exposure_kind(&self) -> ExposureKindV1 {
        self.exposure_kind
    }

    /// Return the vault epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Return the semantic revision.
    pub const fn semantic_revision(&self) -> u64 {
        self.semantic_revision
    }

    /// Return the applied receipt-chain hash.
    pub const fn receipt_chain_hash(&self) -> &[u8; 32] {
        &self.receipt_chain_hash
    }
}

fn permit_field<const N: usize>(bytes: &[u8]) -> Result<[u8; N], NonceVaultError> {
    bytes.try_into().map_err(|_| NonceVaultError::InvalidPermit)
}

/// Canonical 105-byte identity used by every durable nonce-vault record.
#[derive(Clone, Eq, PartialEq)]
pub struct NonceIdentityV1 {
    session_id: SessionId,
    participant_id: ParticipantId,
    purpose: PurposeV1,
    bound_digest: [u8; 32],
    nonce_epoch: u64,
}

impl NonceIdentityV1 {
    /// Exact canonical encoded length.
    pub const ENCODED_LEN: usize = 105;

    /// Construct a validated non-authoritative nonce identity.
    pub fn new(
        session_id: SessionId,
        participant_id: ParticipantId,
        purpose: PurposeV1,
        bound_digest: [u8; 32],
        nonce_epoch: u64,
    ) -> Result<Self, NonceVaultError> {
        if !purpose.is_strict_v1_authorized() {
            return Err(NonceVaultError::UnsupportedPurpose);
        }
        if bound_digest == [0; 32] || nonce_epoch == 0 {
            return Err(NonceVaultError::InvalidIdentifier);
        }
        Ok(Self {
            session_id,
            participant_id,
            purpose,
            bound_digest,
            nonce_epoch,
        })
    }

    /// Encode the exact canonical identity bytes.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..32].copy_from_slice(self.session_id.as_bytes());
        bytes[32..64].copy_from_slice(self.participant_id.as_bytes());
        bytes[64] = self.purpose.to_byte();
        bytes[65..97].copy_from_slice(&self.bound_digest);
        bytes[97..].copy_from_slice(&self.nonce_epoch.to_le_bytes());
        bytes
    }

    /// Return the lifetime-unique session identifier.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Return the local protocol participant identifier.
    pub const fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    /// Return the strict signing purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    /// Return the complete reservation-authority binding digest.
    pub const fn bound_digest(&self) -> &[u8; 32] {
        &self.bound_digest
    }

    /// Return the nonzero nonce epoch.
    pub const fn nonce_epoch(&self) -> u64 {
        self.nonce_epoch
    }
}

impl fmt::Debug for NonceIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NonceIdentityV1([redacted])")
    }
}

/// Non-authoritative descriptor for one exact current-generation spent artifact.
#[derive(Clone, Eq, PartialEq)]
pub struct SpentArtifactDescriptorV1 {
    nonce_identity: NonceIdentityV1,
    permit_id: PermitIdV1,
    kind: ExposureKindV1,
    adaptor_outbound_digest: [u8; 32],
}

impl SpentArtifactDescriptorV1 {
    pub(crate) fn from_snapshot(
        snapshot: &impl VaultSpentArtifactSnapshotV1,
    ) -> Result<Self, NonceVaultError> {
        let nonce_identity = snapshot.nonce_identity().clone();
        let permit_id = snapshot.permit_id().clone();
        let kind = snapshot.kind();
        let adaptor_outbound_digest = *snapshot.adaptor_outbound_digest();
        if adaptor_outbound_digest == [0; 32] || nonce_identity.bound_digest() == &[0; 32] {
            return Err(NonceVaultError::InvalidPermit);
        }
        Ok(Self {
            nonce_identity,
            permit_id,
            kind,
            adaptor_outbound_digest,
        })
    }

    /// Return the complete current-generation nonce identity.
    pub const fn nonce_identity(&self) -> &NonceIdentityV1 {
        &self.nonce_identity
    }

    /// Return the public spent-permit lookup.
    pub const fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }

    /// Return the closed persisted artifact kind.
    pub const fn kind(&self) -> ExposureKindV1 {
        self.kind
    }

    /// Return the exact adaptor-domain outbound digest.
    pub const fn adaptor_outbound_digest(&self) -> &[u8; 32] {
        &self.adaptor_outbound_digest
    }
}

impl fmt::Debug for SpentArtifactDescriptorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SpentArtifactDescriptorV1([redacted])")
    }
}

/// Closed live reservation stage reconstructed from authenticated durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationLiveStageV1 {
    /// Same-process fresh claim with no derivation permit issued.
    PreDerivation,
    /// Exact commitment successor is spent and the nonce secret remains sealed.
    AfterCommitment,
    /// Exact commitment and reveal successors are spent.
    AfterReveal,
}

/// Store-owned snapshot of one exact current-generation spent artifact.
pub trait VaultSpentArtifactSnapshotV1 {
    /// Return the complete current-generation nonce identity.
    fn nonce_identity(&self) -> &NonceIdentityV1;
    /// Return the public non-authoritative permit lookup.
    fn permit_id(&self) -> &PermitIdV1;
    /// Return the closed artifact kind.
    fn kind(&self) -> ExposureKindV1;
    /// Return the exact adaptor-domain outbound digest.
    fn adaptor_outbound_digest(&self) -> &[u8; 32];
}

/// Process-local correlation value shared by one persistence permit and artifact.
///
/// The value grants no authority by itself and has no public parser or
/// caller-bytes constructor.
pub struct ProcessComputationBindingIdV1([u8; 32]);

impl ProcessComputationBindingIdV1 {
    /// Generate a nonzero value entirely inside the operating-system CSPRNG boundary.
    pub fn generate() -> Result<Self, NonceVaultError> {
        loop {
            let mut bytes = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|_| NonceVaultError::RandomnessUnavailable)?;
            if bytes != [0; 32] {
                return Ok(Self(bytes));
            }
        }
    }

    /// Borrow the process-local correlation bytes without granting authority.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn copy_for_prepared_artifact(&self) -> Self {
        Self(self.0)
    }
}

/// Read-only binding exposed by a Store-owned one-shot persistence permit.
pub trait VaultArtifactPersistencePermitV1 {
    /// Return the Store-generated reservation identifier.
    fn reservation_nonce_id(&self) -> &ReservationNonceId;
    /// Return the complete canonical nonce identity.
    fn nonce_identity(&self) -> &NonceIdentityV1;
    /// Return the complete reservation-context binding digest.
    fn reservation_context_binding_digest(&self) -> &[u8; 32];
    /// Return the unique derivation-attempt digest.
    fn derivation_attempt_digest(&self) -> &[u8; 32];
    /// Return the exact canonical operation-input digest.
    fn operation_input_digest(&self) -> &[u8; 32];
    /// Return the final signer-owned nonce KDF retry counter.
    fn effective_retry_counter(&self) -> u64;
    /// Return the exact signing phase.
    fn phase(&self) -> SigningPhaseV1;
    /// Return the exact exposure kind.
    fn exposure_kind(&self) -> ExposureKindV1;
    /// Return the canonical exposure sequence.
    fn exposure_sequence(&self) -> u64;
    /// Return the expected lifecycle revision.
    fn expected_lifecycle_revision(&self) -> u64;
    /// Return the exact stage-context digest retained by the Store.
    fn stage_context_digest(&self) -> &[u8; 32];
    /// Return the process-local correlation value.
    fn process_computation_binding_id(&self) -> &ProcessComputationBindingIdV1;
}

struct PreparedArtifactBindingV1 {
    reservation_nonce_id: ReservationNonceId,
    nonce_identity: NonceIdentityV1,
    reservation_context_binding_digest: [u8; 32],
    derivation_attempt_digest: [u8; 32],
    operation_input_digest: [u8; 32],
    effective_retry_counter: u64,
    phase: SigningPhaseV1,
    exposure_kind: ExposureKindV1,
    exposure_sequence: u64,
    expected_lifecycle_revision: u64,
    stage_context_digest: [u8; 32],
    process_computation_binding_id: ProcessComputationBindingIdV1,
}

impl PreparedArtifactBindingV1 {
    fn from_permit(
        permit: &impl VaultArtifactPersistencePermitV1,
        operation: &crate::ValidatedVaultComputationViewV1<'_>,
    ) -> core::result::Result<Self, PreparedExposureValidationError> {
        let expected_sequence = match permit.exposure_kind() {
            ExposureKindV1::NonceCommitment => 1,
            ExposureKindV1::NonceReveal => 2,
            ExposureKindV1::PartialSignature => 3,
        };
        let expected_phase = match permit.exposure_kind() {
            ExposureKindV1::NonceCommitment => SigningPhaseV1::SigNonceCommit,
            ExposureKindV1::NonceReveal => SigningPhaseV1::SigNonceReveal,
            ExposureKindV1::PartialSignature => SigningPhaseV1::SigPartial,
        };
        let expected_stage = match permit.exposure_kind() {
            ExposureKindV1::NonceCommitment => VaultComputationStageV1::NonceDerivation,
            ExposureKindV1::NonceReveal => VaultComputationStageV1::NonceReveal,
            ExposureKindV1::PartialSignature => VaultComputationStageV1::PartialAttempt,
        };
        if permit.reservation_context_binding_digest() == &[0; 32]
            || permit.derivation_attempt_digest() == &[0; 32]
            || permit.operation_input_digest() == &[0; 32]
            || permit.stage_context_digest() == &[0; 32]
            || permit.nonce_identity().bound_digest() != permit.reservation_context_binding_digest()
            || permit.nonce_identity().session_id().as_bytes() != operation.context().session_id()
            || permit.nonce_identity().purpose() != operation.context().purpose()
            || permit.operation_input_digest() != operation.operation_input_digest()
            || permit.reservation_context_binding_digest()
                != operation.reservation_context_binding_digest()
            || permit.effective_retry_counter() != operation.effective_retry_counter()
            || permit.phase() != expected_phase
            || operation.context().signing_phase() != expected_phase
            || operation.stage() != expected_stage
            || permit.exposure_sequence() != expected_sequence
            || permit.expected_lifecycle_revision() == 0
        {
            return Err(PreparedExposureValidationError::BindingMismatch);
        }
        Ok(Self {
            reservation_nonce_id: permit.reservation_nonce_id().clone(),
            nonce_identity: permit.nonce_identity().clone(),
            reservation_context_binding_digest: *permit.reservation_context_binding_digest(),
            derivation_attempt_digest: *permit.derivation_attempt_digest(),
            operation_input_digest: *permit.operation_input_digest(),
            effective_retry_counter: permit.effective_retry_counter(),
            phase: permit.phase(),
            exposure_kind: permit.exposure_kind(),
            exposure_sequence: permit.exposure_sequence(),
            expected_lifecycle_revision: permit.expected_lifecycle_revision(),
            stage_context_digest: *permit.stage_context_digest(),
            process_computation_binding_id: permit
                .process_computation_binding_id()
                .copy_for_prepared_artifact(),
        })
    }

    fn matches(&self, permit: &impl VaultArtifactPersistencePermitV1) -> bool {
        &self.reservation_nonce_id == permit.reservation_nonce_id()
            && &self.nonce_identity == permit.nonce_identity()
            && &self.reservation_context_binding_digest
                == permit.reservation_context_binding_digest()
            && &self.derivation_attempt_digest == permit.derivation_attempt_digest()
            && &self.operation_input_digest == permit.operation_input_digest()
            && self.effective_retry_counter == permit.effective_retry_counter()
            && self.phase == permit.phase()
            && self.exposure_kind == permit.exposure_kind()
            && self.exposure_sequence == permit.exposure_sequence()
            && self.expected_lifecycle_revision == permit.expected_lifecycle_revision()
            && &self.stage_context_digest == permit.stage_context_digest()
            && self.process_computation_binding_id.as_bytes()
                == permit.process_computation_binding_id().as_bytes()
    }
}

enum PreparedExposureEvidenceV1 {
    Commitment {
        context: crate::SessionContextV1,
        public_nonces: PublicNoncePairV1,
        commitment: NonceCommitmentV1,
    },
    Reveal {
        context: crate::SessionContextV1,
        reveal: NonceRevealV1,
        prior_descriptor: SpentArtifactDescriptorV1,
        prior_commitment: NonceCommitmentV1,
    },
    PartialSignature {
        context: crate::SessionContextV1,
        partial: PartialSignatureV1,
        participant_public_key: PublicKey,
        effective_participant_nonce: PublicKey,
        binding_factor: BindingFactorV1,
        aggregate_nonce_hat: PublicKey,
        aggregate_signing_key: PublicKey,
    },
}

/// A prepared public artifact paired with one exact private computation binding.
///
/// Constructors are crate-private and no raw-byte constructor exists.
pub struct PreparedExposureV1 {
    binding: PreparedArtifactBindingV1,
    exposure: ExposureBytes,
    evidence: PreparedExposureEvidenceV1,
}

impl PreparedExposureV1 {
    pub(crate) fn commitment(
        permit: &impl VaultArtifactPersistencePermitV1,
        operation: &crate::ValidatedVaultComputationViewV1<'_>,
        public_nonces: PublicNoncePairV1,
        commitment: NonceCommitmentV1,
    ) -> core::result::Result<Self, PreparedExposureValidationError> {
        let binding = PreparedArtifactBindingV1::from_permit(permit, operation)?;
        let exposure =
            ExposureBytes::from_bytes(ExposureKindV1::NonceCommitment, commitment.to_bytes())?;
        let prepared = Self {
            binding,
            exposure,
            evidence: PreparedExposureEvidenceV1::Commitment {
                context: operation.context().clone(),
                public_nonces,
                commitment,
            },
        };
        prepared.verify_public_evidence()?;
        Ok(prepared)
    }

    pub(crate) fn reveal(
        permit: &impl VaultArtifactPersistencePermitV1,
        operation: &crate::ValidatedVaultComputationViewV1<'_>,
        reveal: NonceRevealV1,
        prior_snapshot: &impl VaultSpentArtifactSnapshotV1,
        prior_commitment: NonceCommitmentV1,
    ) -> core::result::Result<Self, PreparedExposureValidationError> {
        let binding = PreparedArtifactBindingV1::from_permit(permit, operation)?;
        let exposure = ExposureBytes::from_bytes(ExposureKindV1::NonceReveal, reveal.to_bytes())?;
        let prepared = Self {
            binding,
            exposure,
            evidence: PreparedExposureEvidenceV1::Reveal {
                context: operation.context().clone(),
                reveal,
                prior_descriptor: SpentArtifactDescriptorV1::from_snapshot(prior_snapshot)?,
                prior_commitment,
            },
        };
        prepared.verify_public_evidence()?;
        Ok(prepared)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn partial_signature(
        permit: &impl VaultArtifactPersistencePermitV1,
        operation: &crate::ValidatedVaultComputationViewV1<'_>,
        partial: PartialSignatureV1,
        participant_public_key: PublicKey,
        effective_participant_nonce: PublicKey,
        binding_factor: BindingFactorV1,
        aggregate_nonce_hat: PublicKey,
        aggregate_signing_key: PublicKey,
    ) -> core::result::Result<Self, PreparedExposureValidationError> {
        let binding = PreparedArtifactBindingV1::from_permit(permit, operation)?;
        let exposure =
            ExposureBytes::from_bytes(ExposureKindV1::PartialSignature, partial.to_bytes())?;
        let prepared = Self {
            binding,
            exposure,
            evidence: PreparedExposureEvidenceV1::PartialSignature {
                context: operation.context().clone(),
                partial,
                participant_public_key,
                effective_participant_nonce,
                binding_factor,
                aggregate_nonce_hat,
                aggregate_signing_key,
            },
        };
        prepared.verify_public_evidence()?;
        Ok(prepared)
    }

    fn verify_public_evidence(&self) -> core::result::Result<(), PreparedExposureValidationError> {
        match &self.evidence {
            PreparedExposureEvidenceV1::Commitment {
                context,
                public_nonces,
                commitment,
            } => {
                if self.exposure.kind() != ExposureKindV1::NonceCommitment
                    || self.exposure.as_bytes() != commitment.to_bytes()
                    || commitment.purpose() != context.purpose()
                    || commitment.participant_index() != context.participant_index()
                {
                    return Err(PreparedExposureValidationError::BindingMismatch);
                }
                let digest = crate::nonce_commitment_hash_v1(
                    context.chain_id(),
                    context.session_id(),
                    self.binding.nonce_identity.participant_id().as_bytes(),
                    context.purpose(),
                    context.template_hash(),
                    public_nonces.first(),
                    public_nonces.second(),
                    context.adaptor_point(),
                )?;
                if digest.as_bytes() != commitment.nonce_reveal_hash() {
                    return Err(PreparedExposureValidationError::BindingMismatch);
                }
            }
            PreparedExposureEvidenceV1::Reveal {
                context,
                reveal,
                prior_descriptor,
                prior_commitment,
            } => {
                if self.exposure.kind() != ExposureKindV1::NonceReveal
                    || self.exposure.as_bytes() != reveal.to_bytes()
                    || reveal.purpose() != context.purpose()
                    || reveal.participant_index() != context.participant_index()
                    || prior_descriptor.kind() != ExposureKindV1::NonceCommitment
                    || prior_descriptor.nonce_identity() != &self.binding.nonce_identity
                    || prior_commitment.purpose() != context.purpose()
                    || prior_commitment.participant_index() != context.participant_index()
                {
                    return Err(PreparedExposureValidationError::BindingMismatch);
                }
                let prior_outbound = crate::exposure_outbound_digest_v1(
                    ExposureKindV1::NonceCommitment,
                    &prior_commitment.to_bytes(),
                )?;
                let reveal_hash = crate::nonce_commitment_hash_v1(
                    context.chain_id(),
                    context.session_id(),
                    self.binding.nonce_identity.participant_id().as_bytes(),
                    context.purpose(),
                    context.template_hash(),
                    reveal.first(),
                    reveal.second(),
                    context.adaptor_point(),
                )?;
                if prior_outbound.as_bytes() != prior_descriptor.adaptor_outbound_digest()
                    || reveal_hash.as_bytes() != prior_commitment.nonce_reveal_hash()
                {
                    return Err(PreparedExposureValidationError::BindingMismatch);
                }
            }
            PreparedExposureEvidenceV1::PartialSignature {
                context,
                partial,
                participant_public_key,
                effective_participant_nonce,
                binding_factor,
                aggregate_nonce_hat,
                aggregate_signing_key,
            } => {
                if self.exposure.kind() != ExposureKindV1::PartialSignature
                    || self.exposure.as_bytes() != partial.to_bytes()
                    || partial.participant_index() != context.participant_index()
                    || context.participant_public_keys()[usize::from(context.participant_index())]
                        != *participant_public_key
                    || binding_factor.to_be_bytes() == [0; 32]
                    || !partial.verify_bound(
                        context.purpose(),
                        context.template_hash(),
                        effective_participant_nonce,
                        participant_public_key,
                        aggregate_nonce_hat,
                        aggregate_signing_key,
                        context.chain_id(),
                        context.message_digest(),
                    )?
                {
                    return Err(PreparedExposureValidationError::BindingMismatch);
                }
            }
        }
        Ok(())
    }
}

/// Failure returned before a prepared public artifact may be persisted.
#[derive(Debug, thiserror::Error)]
pub enum PreparedExposureValidationError {
    /// The permit and prepared artifact do not name the same computation.
    #[error("prepared exposure does not match its one-shot persistence permit")]
    BindingMismatch,
    /// Canonical DOM adaptor validation rejected the public evidence.
    #[error("prepared exposure public evidence failed canonical validation")]
    Adaptor(#[from] AdaptorError),
    /// The storage-independent vault contract rejected a non-authoritative value.
    #[error("prepared exposure contains an invalid vault value")]
    Contract(#[from] NonceVaultError),
}

/// Read-only result of authoritative prepared-artifact validation.
pub struct ValidatedPreparedExposureViewV1<'a> {
    exposure: &'a ExposureBytes,
    adaptor_outbound_digest: [u8; 32],
    process_computation_binding_id: &'a ProcessComputationBindingIdV1,
    prior_spent_artifact: Option<&'a SpentArtifactDescriptorV1>,
}

impl<'a> ValidatedPreparedExposureViewV1<'a> {
    /// Return the closed artifact kind.
    pub const fn kind(&self) -> ExposureKindV1 {
        self.exposure.kind()
    }

    /// Return the exact canonical outbound bytes.
    pub fn outbound_bytes(&self) -> &[u8] {
        self.exposure.as_bytes()
    }

    /// Return the exact adaptor-domain outbound digest.
    pub const fn adaptor_outbound_digest(&self) -> &[u8; 32] {
        &self.adaptor_outbound_digest
    }

    /// Return the process-local correlation value.
    pub const fn process_computation_binding_id(&self) -> &ProcessComputationBindingIdV1 {
        self.process_computation_binding_id
    }

    /// Return the prior spent commitment descriptor required by a reveal.
    pub const fn prior_spent_artifact(&self) -> Option<&SpentArtifactDescriptorV1> {
        self.prior_spent_artifact
    }
}

/// Compare one exact Store permit with one signer-produced prepared artifact.
pub fn validate_prepared_exposure_v1<'a, P>(
    permit: &'a P,
    artifact: &'a PreparedExposureV1,
) -> core::result::Result<ValidatedPreparedExposureViewV1<'a>, PreparedExposureValidationError>
where
    P: VaultArtifactPersistencePermitV1,
{
    if !artifact.binding.matches(permit) {
        return Err(PreparedExposureValidationError::BindingMismatch);
    }
    artifact.verify_public_evidence()?;
    let prior_spent_artifact = match &artifact.evidence {
        PreparedExposureEvidenceV1::Reveal {
            prior_descriptor, ..
        } => Some(prior_descriptor),
        PreparedExposureEvidenceV1::Commitment { .. }
        | PreparedExposureEvidenceV1::PartialSignature { .. } => None,
    };
    Ok(ValidatedPreparedExposureViewV1 {
        exposure: &artifact.exposure,
        adaptor_outbound_digest: artifact.exposure.outbound_digest(),
        process_computation_binding_id: &artifact.binding.process_computation_binding_id,
        prior_spent_artifact,
    })
}

/// Public lookup identity and bytes released after durable permit spend.
///
/// The permit ID is a non-authoritative restart lookup key. This value carries
/// neither the consumed live permit nor authority to recreate one.
pub struct AuthorizedExposureV1 {
    permit_id: PermitIdV1,
    exposure: ExposureBytes,
}

impl AuthorizedExposureV1 {
    pub(crate) fn from_vault_export(
        exported: &impl VaultExportedArtifactV1,
    ) -> Result<Self, NonceVaultError> {
        Ok(Self {
            permit_id: exported.permit_id().clone(),
            exposure: ExposureBytes::from_bytes(exported.kind(), exported.as_bytes())?,
        })
    }

    /// Return the public restart lookup identifier without export authority.
    pub const fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }

    /// Return the authorized public artifact kind.
    pub const fn kind(&self) -> ExposureKindV1 {
        self.exposure.kind()
    }

    /// Borrow the exact persisted public bytes for first send or exact resend.
    pub fn as_bytes(&self) -> &[u8] {
        self.exposure.as_bytes()
    }
}

/// Read-only view of exact persisted output owned by the DOM Contracts vault store.
///
/// The concrete production type has a private constructor and is returned only
/// after durable permit spend. `dom-adaptor` wraps its public bytes only inside
/// the integrated signer.
pub trait VaultExportedArtifactV1 {
    /// Return the public restart lookup identifier for this spent export.
    ///
    /// The identifier is not a live permit and grants no export authority.
    fn permit_id(&self) -> &PermitIdV1;
    /// Return the closed exposure kind.
    fn kind(&self) -> ExposureKindV1;
    /// Borrow the exact byte-identical persisted artifact.
    fn as_bytes(&self) -> &[u8];
}

/// Closed protocol stage for one exact byte-identical resend lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResendProtocolStageV1 {
    /// A nonce commitment was already durably spent and exported.
    Commitment,
    /// A nonce reveal was already durably spent and exported.
    Reveal,
    /// A partial signature was already durably spent and exported.
    PartialSignature,
}

impl ResendProtocolStageV1 {
    /// Return the exact closed exposure kind for this stage.
    pub const fn exposure_kind(self) -> ExposureKindV1 {
        match self {
            Self::Commitment => ExposureKindV1::NonceCommitment,
            Self::Reveal => ExposureKindV1::NonceReveal,
            Self::PartialSignature => ExposureKindV1::PartialSignature,
        }
    }
}

/// Non-authoritative lookup request constructed only from validated protocol state.
///
/// The request carries no live Store capability. A concrete Store must recover and
/// revalidate its private spent-artifact authority before returning bytes.
pub struct ResendRequestV1 {
    request_lookup: ReservationRequestLookupV1,
    nonce_identity: NonceIdentityV1,
    reservation_context_binding_digest: [u8; 32],
    permit_id: PermitIdV1,
    protocol_stage: ResendProtocolStageV1,
    adaptor_outbound_digest: [u8; 32],
}

impl ResendRequestV1 {
    pub(crate) fn from_recovered(
        authorization: crate::ValidatedResendAuthorizationV1,
        recovered: &impl VaultSpentArtifactSnapshotV1,
    ) -> core::result::Result<Self, NonceVaultError> {
        let request_lookup = authorization.request_lookup().clone();
        let nonce_identity = recovered.nonce_identity().clone();
        let reservation_context_binding_digest =
            *authorization.reservation_context_binding_digest();
        let permit_id = recovered.permit_id().clone();
        let protocol_stage = authorization.protocol_stage();
        let adaptor_outbound_digest = *authorization.adaptor_outbound_digest();
        if reservation_context_binding_digest == [0; 32]
            || adaptor_outbound_digest == [0; 32]
            || nonce_identity.bound_digest() != &reservation_context_binding_digest
            || nonce_identity.session_id() != authorization.session_id()
            || nonce_identity.purpose() != authorization.purpose()
            || recovered.kind() != protocol_stage.exposure_kind()
            || recovered.adaptor_outbound_digest() != &adaptor_outbound_digest
        {
            return Err(NonceVaultError::InvalidPermit);
        }
        Ok(Self {
            request_lookup,
            nonce_identity,
            reservation_context_binding_digest,
            permit_id,
            protocol_stage,
            adaptor_outbound_digest,
        })
    }

    /// Return the public reservation-request lookup.
    pub const fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.request_lookup
    }

    /// Return the complete canonical nonce identity.
    pub const fn nonce_identity(&self) -> &NonceIdentityV1 {
        &self.nonce_identity
    }

    /// Return the complete reservation-context binding digest.
    pub const fn reservation_context_binding_digest(&self) -> &[u8; 32] {
        &self.reservation_context_binding_digest
    }

    /// Return the public spent-permit lookup.
    pub const fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }

    /// Return the exact closed protocol stage.
    pub const fn protocol_stage(&self) -> ResendProtocolStageV1 {
        self.protocol_stage
    }

    /// Return the exact adaptor-domain digest of the persisted bytes.
    pub const fn adaptor_outbound_digest(&self) -> &[u8; 32] {
        &self.adaptor_outbound_digest
    }
}

/// One coherent Store-owned projection of a retained live reservation.
///
/// Concrete implementations construct this owned value under the retained
/// lock. It is non-authoritative: every later Store operation must revalidate
/// its handle and current durable head independently.
pub trait VaultReservationSnapshotV1 {
    /// Store-owned spent-artifact snapshot type.
    type SpentArtifact: VaultSpentArtifactSnapshotV1;

    /// Return the public request lookup retained for restart recovery.
    fn request_lookup(&self) -> &ReservationRequestLookupV1;
    /// Return the store-generated lifetime-unique reservation identifier.
    fn reservation_nonce_id(&self) -> &ReservationNonceId;
    /// Return the complete canonical reservation-context binding digest.
    fn reservation_context_binding_digest(&self) -> &[u8; 32];
    /// Return the exact authenticated live stage reconstructed by the Store.
    fn live_stage(&self) -> ReservationLiveStageV1;
    /// Return the final signer-owned retry counter after nonce derivation, if known.
    fn final_retry_counter(&self) -> Option<u64>;
    /// Return the exact current-generation spent commitment, when present.
    fn spent_commitment(&self) -> Option<&Self::SpentArtifact>;
    /// Return the exact current-generation spent reveal, when present.
    fn spent_reveal(&self) -> Option<&Self::SpentArtifact>;
}

/// Durable computation stage for one exact signer-selected attempt.
///
/// The ordering authority is
/// `NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md` section 8.3
/// (whose hash is incorporated by signed NAR-DC-P1-005 section 1). Initial
/// nonce KDF and zero-result retry selection occur privately first; the final
/// retry is then durably recorded before sealing or any public computation.
/// Reveal and partial stages are recorded before opening the sealed secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultComputationStageV1 {
    /// Private KDF selected the final retry; its durable attempt precedes sealing.
    NonceDerivation,
    /// Reveal computation is about to open the encrypted nonce record.
    NonceReveal,
    /// Partial-signature computation is about to open the record exactly once.
    PartialAttempt,
}

impl VaultComputationStageV1 {
    /// Return the exact NAR-DC-P1-004 stage byte.
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::NonceDerivation => 0x01,
            Self::NonceReveal => 0x02,
            Self::PartialAttempt => 0x03,
        }
    }
}

/// Public terminal projection returned after irreversible abort or burn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalReservationV1 {
    /// Stable reservation identifier retained for lifetime replay rejection.
    pub reservation_id: ReservationNonceId,
    /// Monotonic terminal state.
    pub state: ReservationState,
}

/// Closed result of an exact reservation restart lookup.
pub enum ReservationResumeResultV1<H> {
    /// One coherent authenticated live reservation was resumed.
    Live(H),
    /// The request resolves only to an irreversible terminal reservation.
    Terminal(TerminalReservationV1),
    /// No authenticated occurrence exists; no state was created or changed.
    RetryNotFound,
}

/// Storage-independent lifecycle authority implemented by the reviewed,
/// independent DOM Contracts store, not by the ordinary DOM Wallet.
///
/// Implementations own witness exchange, receipt verification, persistence,
/// synchronization, tombstones, and budgets. No method accepts a receipt,
/// witness-success Boolean, storage-success Boolean, raw permit, or witness key
/// from its caller. Production selects one concrete implementation statically;
/// trait objects are not the production composition boundary.
pub trait NonceVaultV1: Sized {
    /// DOM Contracts store-specific typed failure with redacted observability.
    type Error: Error + Send + Sync + 'static;
    /// Opaque reservation handle owned by the concrete vault.
    type ReservationHandle;
    /// Owned coherent projection created atomically under the retained lock.
    type ReservationSnapshot: VaultReservationSnapshotV1;
    /// Opaque one-shot proof that the nonce-derivation attempt is durable.
    type DerivationAttemptPermit;
    /// Opaque one-shot authority for the first sealed-secret open.
    type InitialSecretOpenPermit;
    /// Opaque one-shot proof that a reveal or partial attempt is durable.
    type StageComputationPermit;
    /// Opaque one-shot authority binding a secret open to exact artifact persistence.
    type ArtifactPersistencePermit: VaultArtifactPersistencePermitV1;
    /// Opaque retained live handle for one exact already-persisted artifact.
    type PersistedExposureHandle;
    /// Opaque one-shot capability with a private DOM Contracts store constructor.
    type ExposurePermit;
    /// DOM Contracts store-owned output produced only after durable permit spend.
    type ExportedArtifact: VaultExportedArtifactV1;
    /// Store-owned non-exporting descriptor recovered from the current durable head.
    type RecoveredSpentArtifact: VaultSpentArtifactSnapshotV1;

    /// Durably claim the lifetime session/reservation IDs and charge every
    /// applicable budget before any nonce secret is generated.
    fn claim_fresh_reservation(
        &mut self,
        request: crate::FreshReservationRequestV1,
    ) -> core::result::Result<Self::ReservationHandle, Self::Error>;

    /// Resume only an exact previously claimed request without fresh fallback.
    fn resume_claimed_reservation(
        &mut self,
        request: crate::ReservationResumeRequestV1,
    ) -> core::result::Result<ReservationResumeResultV1<Self::ReservationHandle>, Self::Error>;

    /// Atomically snapshot one retained live reservation under Store authority.
    fn snapshot_reservation(
        &mut self,
        reservation: &Self::ReservationHandle,
    ) -> core::result::Result<Self::ReservationSnapshot, Self::Error>;

    /// Durably mark the unique final-retry attempt after private KDF selection.
    fn begin_nonce_derivation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: crate::NonceDerivationRequestV1,
    ) -> core::result::Result<Self::DerivationAttemptPermit, Self::Error>;

    /// Seal and durably verify the first derived pair before public computation.
    fn seal_derived_secret(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        attempt: Self::DerivationAttemptPermit,
        secret: crate::NonceSecretTransferV1,
        seal_capability: crate::VaultSecretSealCapabilityV1,
    ) -> core::result::Result<Self::InitialSecretOpenPermit, Self::Error>;

    /// Open the newly sealed record exactly once for commitment computation.
    fn open_sealed_secret_for_commitment(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::InitialSecretOpenPermit,
        import_capability: crate::VaultSecretImportCapabilityV1,
    ) -> core::result::Result<
        (
            crate::NonceSecretTransferV1,
            Self::ArtifactPersistencePermit,
        ),
        Self::Error,
    >;

    /// Durably mark one reveal or partial computation attempt.
    fn begin_stage_computation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: crate::StageComputationRequestV1,
    ) -> core::result::Result<Self::StageComputationPermit, Self::Error>;

    /// Consume one later-stage attempt authority and open the sealed record.
    fn open_secret_for_stage(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::StageComputationPermit,
        import_capability: crate::VaultSecretImportCapabilityV1,
    ) -> core::result::Result<
        (
            crate::NonceSecretTransferV1,
            Self::ArtifactPersistencePermit,
        ),
        Self::Error,
    >;

    /// Persist and reverify exact computed bytes before authorization.
    fn persist_computed_artifact(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::ArtifactPersistencePermit,
        artifact: PreparedExposureV1,
    ) -> core::result::Result<Self::PersistedExposureHandle, Self::Error>;

    /// Authorize only the exact artifact named by a retained live handle.
    fn authorize_persisted_exposure(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        persisted: Self::PersistedExposureHandle,
    ) -> core::result::Result<Self::ExposurePermit, Self::Error>;

    /// Durably spend the capability before releasing the persisted artifact.
    fn export(
        &mut self,
        permit: Self::ExposurePermit,
    ) -> core::result::Result<Self::ExportedArtifact, Self::Error>;

    /// Recover one exact spent descriptor without returning bytes or authority.
    fn recover_spent_artifact(
        &mut self,
        authorization: &crate::ValidatedResendAuthorizationV1,
    ) -> core::result::Result<Self::RecoveredSpentArtifact, Self::Error>;

    /// Return only the exact persisted bytes bound to an already-spent permit.
    fn resend_exported(
        &mut self,
        request: ResendRequestV1,
    ) -> core::result::Result<Self::ExportedArtifact, Self::Error>;

    /// Irreversibly cancel using only authenticated Store-owned live state.
    fn cancel_reservation(
        &mut self,
        reservation: Self::ReservationHandle,
    ) -> core::result::Result<TerminalReservationV1, Self::Error>;

    /// Return whether adaptor operations are available after reconciliation.
    fn restore_state(&self) -> RestoreState;
}

/// Fail-closed errors shared by contract consumers and wallet implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceVaultError {
    /// An opaque identifier was empty.
    InvalidIdentifier,
    /// Public material was empty.
    InvalidPublicMaterial,
    /// A purpose byte is not in the ratified closed V1 registry.
    UnsupportedPurpose,
    /// An exposure byte is outside the closed NAR-002 registry.
    UnsupportedExposureKind,
    /// A one-shot permit field or durable binding is invalid.
    InvalidPermit,
    /// An idempotency key was reused for different inputs.
    IdempotencyConflict,
    /// The requested reservation does not exist.
    ReservationNotFound,
    /// The session ID was already claimed by the lifetime tombstone set.
    SessionIdReused,
    /// The requested transition is not monotonic from the current state.
    InvalidTransition,
    /// A configured budget was exhausted.
    BudgetExhausted(BudgetScope),
    /// The witness is unavailable for an adaptor-only operation.
    WitnessUnavailable,
    /// A receipt failed witness authentication or request binding.
    InvalidWitnessReceipt,
    /// Local state is older than independently anchored state.
    RollbackDetected,
    /// Local and witnessed chains diverged.
    DivergenceDetected,
    /// Adaptor operations are disabled pending restore reconciliation.
    RestoreQuarantined,
    /// Durable state failed structural or authentication checks.
    CorruptState,
    /// Durable storage could not complete the requested operation.
    StorageUnavailable,
    /// The operating-system CSPRNG failed to provide a process-local identifier.
    RandomnessUnavailable,
    /// A checked monotonic counter overflowed.
    CounterOverflow,
    /// The persisted schema or witness protocol version is unsupported.
    UnsupportedVersion,
}

impl fmt::Display for NonceVaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIdentifier => "invalid empty vault identifier",
            Self::InvalidPublicMaterial => "invalid canonical public material",
            Self::UnsupportedPurpose => "unsupported PurposeV1 discriminant",
            Self::UnsupportedExposureKind => "unsupported ExposureKindV1 discriminant",
            Self::InvalidPermit => "invalid one-shot exposure permit",
            Self::IdempotencyConflict => "idempotency key conflicts with prior inputs",
            Self::ReservationNotFound => "nonce reservation not found",
            Self::SessionIdReused => "Scriptless session identifier was already used",
            Self::InvalidTransition => "invalid nonce reservation transition",
            Self::BudgetExhausted(_) => "configured nonce session budget exhausted",
            Self::WitnessUnavailable => "remote witness unavailable",
            Self::InvalidWitnessReceipt => "invalid witness receipt",
            Self::RollbackDetected => "nonce vault rollback detected",
            Self::DivergenceDetected => "nonce vault divergence detected",
            Self::RestoreQuarantined => "nonce vault is restore quarantined",
            Self::CorruptState => "nonce vault durable state is corrupt",
            Self::StorageUnavailable => "nonce vault storage unavailable",
            Self::RandomnessUnavailable => "operating-system randomness unavailable",
            Self::CounterOverflow => "nonce vault monotonic counter overflow",
            Self::UnsupportedVersion => "unsupported nonce vault version",
        };
        formatter.write_str(message)
    }
}

impl Error for NonceVaultError {}

fn append<const N: usize>(output: &mut [u8; N], cursor: &mut usize, bytes: &[u8]) {
    output[*cursor..*cursor + bytes.len()].copy_from_slice(bytes);
    *cursor += bytes.len();
}

#[cfg(fuzzing)]
struct FuzzRecoveredSpentArtifactV1 {
    nonce_identity: NonceIdentityV1,
    permit_id: PermitIdV1,
    kind: ExposureKindV1,
    digest: [u8; 32],
}

#[cfg(fuzzing)]
impl VaultSpentArtifactSnapshotV1 for FuzzRecoveredSpentArtifactV1 {
    fn nonce_identity(&self) -> &NonceIdentityV1 {
        &self.nonce_identity
    }

    fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }

    fn kind(&self) -> ExposureKindV1 {
        self.kind
    }

    fn adaptor_outbound_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Fuzz-only NAR-006 recovered-descriptor binding harness.
///
/// This symbol is selected only by cargo-fuzz's `cfg(fuzzing)` build and is
/// absent from production feature resolution.
#[cfg(fuzzing)]
pub fn fuzz_nar006_runtime_bindings_v1(data: &[u8]) {
    fn field(data: &[u8], start: usize, fallback: u8) -> [u8; 32] {
        let mut value = [fallback; 32];
        if let Some(bytes) = data.get(start..start.saturating_add(32)) {
            if bytes.len() == 32 {
                value.copy_from_slice(bytes);
            }
        }
        value[0] |= 1;
        value
    }

    let selector = data.first().copied().unwrap_or_default();
    let session = SessionId::from_bytes(field(data, 1, 0x11));
    let participant = ParticipantId::from_bytes(field(data, 33, 0x12));
    let lookup = ReservationRequestLookupV1::from_bytes(field(data, 65, 0x13));
    let permit = PermitIdV1::from_bytes(field(data, 97, 0x14));
    let (Ok(session), Ok(participant), Ok(lookup), Ok(permit)) =
        (session, participant, lookup, permit)
    else {
        return;
    };
    let binding = field(data, 129, 0x15);
    let digest = field(data, 161, 0x16);
    let Ok(authorization) = crate::ValidatedResendAuthorizationV1::new(
        lookup,
        binding,
        session.clone(),
        PurposeV1::Refund,
        ResendProtocolStageV1::Commitment,
        digest,
    ) else {
        return;
    };
    let mut recovered = FuzzRecoveredSpentArtifactV1 {
        nonce_identity: match NonceIdentityV1::new(
            session,
            participant,
            PurposeV1::Refund,
            binding,
            1,
        ) {
            Ok(identity) => identity,
            Err(_) => return,
        },
        permit_id: permit,
        kind: ExposureKindV1::NonceCommitment,
        digest,
    };
    match selector % 4 {
        1 => recovered.kind = ExposureKindV1::NonceReveal,
        2 => recovered.digest[0] ^= 1,
        3 => {
            if let Ok(identity) = NonceIdentityV1::new(
                SessionId::from_bytes([0x41; 32]).expect("fixed nonzero session"),
                recovered.nonce_identity.participant_id().clone(),
                PurposeV1::Refund,
                binding,
                1,
            ) {
                recovered.nonce_identity = identity;
            }
        }
        _ => {}
    }
    let _ = ResendRequestV1::from_recovered(authorization, &recovered);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;

    fn identifier<T>(constructor: impl FnOnce([u8; 32]) -> Result<T, NonceVaultError>) -> T {
        constructor([7; 32]).expect("nonzero test identifier")
    }

    #[test]
    fn identifiers_and_exposure_are_redacted() {
        let session = identifier(SessionId::from_bytes);
        let exposure = ExposureBytes::from_bytes(ExposureKindV1::NonceCommitment, vec![1; 35])
            .expect("public bytes");
        assert_eq!(format!("{session:?}"), "SessionId([redacted])");
        assert_eq!(format!("{exposure:?}"), "ExposureBytes([redacted])");
    }

    #[test]
    fn empty_opaque_values_fail_closed() {
        assert_eq!(
            ReservationRequestLookupV1::from_bytes([0; 32]),
            Err(NonceVaultError::InvalidIdentifier)
        );
        assert_eq!(
            ExposureBytes::from_bytes(ExposureKindV1::NonceCommitment, Vec::<u8>::new()),
            Err(NonceVaultError::InvalidPublicMaterial)
        );
    }

    #[test]
    fn request_lookup_permit_and_process_bindings_are_distinct_and_nonzero() {
        assert_ne!(
            TypeId::of::<ReservationRequestLookupV1>(),
            TypeId::of::<PermitIdV1>()
        );
        let lookup = ReservationRequestLookupV1::from_bytes([1; 32]).expect("lookup");
        let permit = PermitIdV1::from_bytes([1; 32]).expect("permit");
        assert_eq!(lookup.as_bytes(), permit.as_bytes());
        let process = ProcessComputationBindingIdV1::generate().expect("OS CSPRNG");
        assert_ne!(process.as_bytes(), &[0; 32]);
    }

    #[test]
    fn nonce_identity_encoding_is_exact_and_field_bound() {
        let identity = NonceIdentityV1::new(
            SessionId::from_bytes([1; 32]).expect("session"),
            ParticipantId::from_bytes([2; 32]).expect("participant"),
            PurposeV1::Refund,
            [3; 32],
            4,
        )
        .expect("nonce identity");
        let bytes = identity.to_bytes();
        assert_eq!(bytes.len(), NonceIdentityV1::ENCODED_LEN);
        assert_eq!(&bytes[..32], &[1; 32]);
        assert_eq!(&bytes[32..64], &[2; 32]);
        assert_eq!(bytes[64], PurposeV1::Refund.to_byte());
        assert_eq!(&bytes[65..97], &[3; 32]);
        assert_eq!(&bytes[97..], &4u64.to_le_bytes());
        assert!(NonceIdentityV1::new(
            SessionId::from_bytes([1; 32]).expect("session"),
            ParticipantId::from_bytes([2; 32]).expect("participant"),
            PurposeV1::Sponsor,
            [3; 32],
            4,
        )
        .is_err());
    }

    struct TestRecoveredSpentArtifact {
        nonce_identity: NonceIdentityV1,
        permit_id: PermitIdV1,
        kind: ExposureKindV1,
        digest: [u8; 32],
    }

    impl VaultSpentArtifactSnapshotV1 for TestRecoveredSpentArtifact {
        fn nonce_identity(&self) -> &NonceIdentityV1 {
            &self.nonce_identity
        }

        fn permit_id(&self) -> &PermitIdV1 {
            &self.permit_id
        }

        fn kind(&self) -> ExposureKindV1 {
            self.kind
        }

        fn adaptor_outbound_digest(&self) -> &[u8; 32] {
            &self.digest
        }
    }

    fn recovered_resend_fixture() -> (
        crate::ValidatedResendAuthorizationV1,
        TestRecoveredSpentArtifact,
    ) {
        let session = SessionId::from_bytes([0x21; 32]).expect("session");
        let binding = [0x22; 32];
        let digest = [0x23; 32];
        let authorization = crate::ValidatedResendAuthorizationV1::new(
            ReservationRequestLookupV1::from_bytes([0x24; 32]).expect("request lookup"),
            binding,
            session.clone(),
            PurposeV1::Refund,
            ResendProtocolStageV1::Commitment,
            digest,
        )
        .expect("authorization");
        let recovered = TestRecoveredSpentArtifact {
            nonce_identity: NonceIdentityV1::new(
                session,
                ParticipantId::from_bytes([0x25; 32]).expect("participant"),
                PurposeV1::Refund,
                binding,
                7,
            )
            .expect("nonce identity"),
            permit_id: PermitIdV1::from_bytes([0x26; 32]).expect("permit"),
            kind: ExposureKindV1::NonceCommitment,
            digest,
        };
        (authorization, recovered)
    }

    #[test]
    fn recovered_resend_binds_complete_identity_kind_and_digest() {
        let (authorization, recovered) = recovered_resend_fixture();
        let request = ResendRequestV1::from_recovered(authorization, &recovered)
            .expect("bound resend request");
        assert_eq!(request.nonce_identity(), recovered.nonce_identity());
        assert_eq!(request.permit_id(), recovered.permit_id());
        assert_eq!(request.protocol_stage(), ResendProtocolStageV1::Commitment);
        assert_eq!(request.adaptor_outbound_digest(), &recovered.digest);
    }

    #[test]
    fn recovered_resend_rejects_mutated_identity_kind_and_digest() {
        let (authorization, mut recovered) = recovered_resend_fixture();
        recovered.kind = ExposureKindV1::NonceReveal;
        assert!(ResendRequestV1::from_recovered(authorization, &recovered).is_err());

        let (authorization, mut recovered) = recovered_resend_fixture();
        recovered.digest[0] ^= 1;
        assert!(ResendRequestV1::from_recovered(authorization, &recovered).is_err());

        let (authorization, mut recovered) = recovered_resend_fixture();
        recovered.nonce_identity = NonceIdentityV1::new(
            SessionId::from_bytes([0x31; 32]).expect("mutated session"),
            ParticipantId::from_bytes([0x25; 32]).expect("participant"),
            PurposeV1::Refund,
            [0x22; 32],
            7,
        )
        .expect("mutated identity");
        assert!(ResendRequestV1::from_recovered(authorization, &recovered).is_err());

        let (authorization, mut recovered) = recovered_resend_fixture();
        recovered.nonce_identity = NonceIdentityV1::new(
            SessionId::from_bytes([0x21; 32]).expect("session"),
            ParticipantId::from_bytes([0x25; 32]).expect("participant"),
            PurposeV1::Funding,
            [0x22; 32],
            7,
        )
        .expect("mutated identity");
        assert!(ResendRequestV1::from_recovered(authorization, &recovered).is_err());
    }

    #[test]
    fn purpose_set_is_closed() {
        let purposes = [
            PurposeV1::Refund,
            PurposeV1::ClaimAdaptor,
            PurposeV1::Funding,
            PurposeV1::Sponsor,
        ];
        assert_eq!(purposes.len(), 4);
        assert!(purposes[..3]
            .iter()
            .all(|purpose| purpose.is_strict_v1_authorized()));
        assert!(!PurposeV1::Sponsor.is_strict_v1_authorized());
        for (byte, purpose) in [
            (1, PurposeV1::Refund),
            (2, PurposeV1::ClaimAdaptor),
            (3, PurposeV1::Funding),
            (4, PurposeV1::Sponsor),
        ] {
            assert_eq!(PurposeV1::try_from(byte), Ok(purpose));
            assert_eq!(purpose.to_byte(), byte);
        }
        assert!(PurposeV1::try_from(0).is_err());
        assert!(PurposeV1::try_from(5).is_err());
    }
}

//! Durable implementation of [`dom_adaptor::NonceVaultV1`] on top of the `store`.
//!
//! The whole module sits behind the `real-dom-adaptor` feature: without the
//! pin, the crate still compiles and exposes no path that fakes success.
//!
//! # One-shot capabilities
//!
//! No capability type in this module derives `Clone` or `Copy`. Uniqueness is
//! enforced exclusively by Rust's move semantics: an accidental `Clone` would
//! silently destroy the protocol, because the same permit could authorize two
//! distinct exposures of the same nonce.
//!
//! # Primitives
//!
//! No hash, tag or verification is written here. The digests come ready-made
//! from the canonical `dom-adaptor` requests, and the only cryptographic
//! check is done by [`dom_adaptor::exposure_outbound_digest_v1`] and
//! [`dom_adaptor::validate_prepared_exposure_v1`] (I15).

use dom_adaptor::{
    exposure_outbound_digest_v1, validate_prepared_exposure_v1, ExposureKindV1,
    FreshReservationRequestV1, NonceDerivationRequestV1, NonceIdentityV1, NonceSecretTransferV1,
    NonceVaultV1, ParticipantId, PermitIdV1, PreparedExposureV1, ProcessComputationBindingIdV1,
    PurposeV1, ResendRequestV1, ReservationLiveStageV1, ReservationNonceId,
    ReservationRequestLookupV1, ReservationResumeRequestV1, ReservationResumeResultV1,
    ReservationState, RestoreState, SessionId, SigningPhaseV1, StageComputationRequestV1,
    TerminalReservationV1, ValidatedResendAuthorizationV1, VaultArtifactPersistencePermitV1,
    VaultComputationStageV1, VaultExportedArtifactV1, VaultReservationSnapshotV1,
    VaultSecretImportCapabilityV1, VaultSecretSealCapabilityV1, VaultSpentArtifactSnapshotV1,
};

use crate::durable::{
    ArtifactRecord, BudgetScopeLocal, DurableVaultCore, ReservationIdentity, ReservationRecord,
    SpentRef, StateCode, VaultLimits, JOURNAL_AUTHORIZE, JOURNAL_DERIVATION_ATTEMPT, JOURNAL_OPEN,
    JOURNAL_PERSIST, JOURNAL_SEAL, JOURNAL_SPEND, JOURNAL_STAGE_ATTEMPT, JOURNAL_TERMINAL,
};
use crate::{Result, VaultError};

/// Local redacted-`Debug` macro, in the same style as `dom-adaptor` (I6).
macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {
        $(
            impl core::fmt::Debug for $name {
                fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    formatter.write_str(concat!(stringify!($name), "([redacted])"))
                }
            }
        )+
    };
}

/// Opaque handle to a live reservation. Not `Clone`: one reservation, one owner.
pub struct ReservationHandle {
    reservation_id: [u8; 32],
}

/// One-shot proof that the derivation attempt is durable.
pub struct DerivationAttemptPermit {
    reservation_id: [u8; 32],
    revision: u64,
    retry_counter: u64,
    operation_input_digest: [u8; 32],
}

/// One-shot authority for the first opening of the sealed record.
pub struct InitialSecretOpenPermit {
    reservation_id: [u8; 32],
    revision: u64,
    retry_counter: u64,
    operation_input_digest: [u8; 32],
}

/// One-shot proof that the reveal or partial attempt is durable.
pub struct StageComputationPermit {
    reservation_id: [u8; 32],
    revision: u64,
    retry_counter: u64,
    operation_input_digest: [u8; 32],
    exposure_kind: ExposureKindV1,
}

/// One-shot authority binding a secret opening to the exact persistence.
pub struct ArtifactPersistencePermit {
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

/// Live retained handle for an artifact already persisted and not yet authorized.
pub struct PersistedExposureHandle {
    reservation_id: [u8; 32],
    revision: u64,
    exposure_kind: ExposureKindV1,
    permit_id: [u8; 32],
    outbound_digest: [u8; 32],
}

/// One-shot exposure capability, spent durably before any bytes are released.
pub struct ExposurePermit {
    reservation_id: [u8; 32],
    exposure_kind: ExposureKindV1,
    permit_id: [u8; 32],
}

/// Exact output from the store, produced only after the permit's durable spend.
pub struct ExportedArtifact {
    permit_id: PermitIdV1,
    kind: ExposureKindV1,
    bytes: Vec<u8>,
}

/// Non-authoritative projection of a spent artifact from the current generation.
pub struct SpentArtifactSnapshot {
    nonce_identity: NonceIdentityV1,
    permit_id: PermitIdV1,
    kind: ExposureKindV1,
    adaptor_outbound_digest: [u8; 32],
}

/// Coherent projection of a live reservation, created under the held lock.
pub struct ReservationSnapshot {
    request_lookup: ReservationRequestLookupV1,
    reservation_nonce_id: ReservationNonceId,
    reservation_context_binding_digest: [u8; 32],
    live_stage: ReservationLiveStageV1,
    final_retry_counter: Option<u64>,
    spent_commitment: Option<SpentArtifactSnapshot>,
    spent_reveal: Option<SpentArtifactSnapshot>,
}

redacted_debug!(
    ReservationHandle,
    DerivationAttemptPermit,
    InitialSecretOpenPermit,
    StageComputationPermit,
    ArtifactPersistencePermit,
    PersistedExposureHandle,
    ExposurePermit,
    ExportedArtifact,
    SpentArtifactSnapshot,
    ReservationSnapshot,
);

impl VaultArtifactPersistencePermitV1 for ArtifactPersistencePermit {
    fn reservation_nonce_id(&self) -> &ReservationNonceId {
        &self.reservation_nonce_id
    }
    fn nonce_identity(&self) -> &NonceIdentityV1 {
        &self.nonce_identity
    }
    fn reservation_context_binding_digest(&self) -> &[u8; 32] {
        &self.reservation_context_binding_digest
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
        &self.process_computation_binding_id
    }
}

impl VaultExportedArtifactV1 for ExportedArtifact {
    fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }
    fn kind(&self) -> ExposureKindV1 {
        self.kind
    }
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl VaultSpentArtifactSnapshotV1 for SpentArtifactSnapshot {
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
        &self.adaptor_outbound_digest
    }
}

impl VaultReservationSnapshotV1 for ReservationSnapshot {
    type SpentArtifact = SpentArtifactSnapshot;

    fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.request_lookup
    }
    fn reservation_nonce_id(&self) -> &ReservationNonceId {
        &self.reservation_nonce_id
    }
    fn reservation_context_binding_digest(&self) -> &[u8; 32] {
        &self.reservation_context_binding_digest
    }
    fn live_stage(&self) -> ReservationLiveStageV1 {
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

/// Durable, rollback-resistant vault, backed by the neutral `store`.
#[derive(Debug)]
pub struct DurableNonceVault {
    core: DurableVaultCore,
}

impl DurableNonceVault {
    /// Builds the vault on top of an already-open `store`.
    pub fn new(store: store::Store) -> Self {
        Self {
            core: DurableVaultCore::new(store),
        }
    }

    /// Builds the vault with configured budget caps.
    pub fn with_limits(store: store::Store, limits: VaultLimits) -> Self {
        Self {
            core: DurableVaultCore::with_limits(store, limits),
        }
    }

    /// Lends out the durable core, without exposing the `store`.
    ///
    /// Test-only: production paths reach the core through the typed contract
    /// methods, never a raw mutable handle.
    #[cfg(test)]
    pub(crate) fn core_mut(&mut self) -> &mut DurableVaultCore {
        &mut self.core
    }

    fn require_operational(&self) -> Result<()> {
        if self.core.is_quarantined() {
            return Err(VaultError::RestoreQuarantined);
        }
        Ok(())
    }

    /// Thirty-two nonzero bytes from the operating system's CSPRNG.
    ///
    /// The source is the already-audited generator of `dom-adaptor`; this
    /// crate neither chooses nor implements its own RNG.
    fn random_identifier() -> Result<[u8; 32]> {
        let generated = ProcessComputationBindingIdV1::generate()
            .map_err(|_| VaultError::RandomnessUnavailable)?;
        Ok(*generated.as_bytes())
    }

    fn identity_of(record: &ReservationRecord) -> Result<NonceIdentityV1> {
        let purpose =
            PurposeV1::try_from(record.identity.purpose).map_err(|_| VaultError::CorruptState)?;
        NonceIdentityV1::new(
            SessionId::from_bytes(record.identity.session_id)
                .map_err(|_| VaultError::CorruptState)?,
            ParticipantId::from_bytes(record.identity.participant_id)
                .map_err(|_| VaultError::CorruptState)?,
            purpose,
            record.identity.context_binding_digest,
            record.identity.nonce_epoch,
        )
        .map_err(|_| VaultError::CorruptState)
    }

    fn identity_of_artifact(record: &ArtifactRecord) -> Result<NonceIdentityV1> {
        let purpose = PurposeV1::try_from(record.purpose).map_err(|_| VaultError::CorruptState)?;
        NonceIdentityV1::new(
            SessionId::from_bytes(record.session_id).map_err(|_| VaultError::CorruptState)?,
            ParticipantId::from_bytes(record.participant_id)
                .map_err(|_| VaultError::CorruptState)?,
            purpose,
            record.bound_digest,
            record.nonce_epoch,
        )
        .map_err(|_| VaultError::CorruptState)
    }

    fn spent_snapshot(
        record: &ReservationRecord,
        reference: &SpentRef,
        kind: ExposureKindV1,
    ) -> Result<SpentArtifactSnapshot> {
        Ok(SpentArtifactSnapshot {
            nonce_identity: Self::identity_of(record)?,
            permit_id: PermitIdV1::from_bytes(reference.permit_id)
                .map_err(|_| VaultError::CorruptState)?,
            kind,
            adaptor_outbound_digest: reference.outbound_digest,
        })
    }

    fn terminal_state(state: StateCode) -> ReservationState {
        match state {
            StateCode::Reserved => ReservationState::Reserved,
            StateCode::CommitmentAuthorized => ReservationState::CommitmentAuthorized,
            StateCode::RevealAuthorized => ReservationState::RevealAuthorized,
            StateCode::ConsumedPartialAuthorized => ReservationState::ConsumedPartialAuthorized,
            StateCode::AbortedBeforePublicMaterial => ReservationState::AbortedBeforePublicMaterial,
            StateCode::ConsumedOnAbort => ReservationState::ConsumedOnAbort,
            StateCode::Burned => ReservationState::Burned,
        }
    }

    fn reservation_id(record: &ReservationRecord) -> Result<ReservationNonceId> {
        ReservationNonceId::from_bytes(record.identity.reservation_id)
            .map_err(|_| VaultError::CorruptState)
    }

    /// Verifies that the exact artifact really produces the recorded digest.
    ///
    /// The verification uses the pin's primitive, never a local reimplementation.
    fn reverify_outbound(record: &ArtifactRecord) -> Result<()> {
        let kind = ExposureKindV1::try_from(record.kind).map_err(|_| VaultError::CorruptState)?;
        let digest = exposure_outbound_digest_v1(kind, &record.bytes)
            .map_err(|_| VaultError::CorruptState)?;
        if digest.as_bytes() != &record.outbound_digest {
            return Err(VaultError::CorruptState);
        }
        Ok(())
    }

    fn artifact_from_view(
        record: &ReservationRecord,
        permit_id: [u8; 32],
        kind: ExposureKindV1,
        outbound_digest: [u8; 32],
        bytes: Vec<u8>,
    ) -> ArtifactRecord {
        ArtifactRecord {
            permit_id,
            reservation_id: record.identity.reservation_id,
            request_lookup: record.identity.request_lookup,
            kind: kind.to_byte(),
            outbound_digest,
            session_id: record.identity.session_id,
            participant_id: record.identity.participant_id,
            purpose: record.identity.purpose,
            bound_digest: record.identity.context_binding_digest,
            nonce_epoch: record.identity.nonce_epoch,
            bytes,
        }
    }

    /// Opens the sealed record and returns the transferred pair plus the exact permit.
    #[allow(clippy::too_many_arguments)]
    fn open_and_bind(
        &mut self,
        reservation_id: [u8; 32],
        expected_revision: u64,
        retry_counter: u64,
        operation_input_digest: [u8; 32],
        exposure_kind: ExposureKindV1,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<(NonceSecretTransferV1, ArtifactPersistencePermit)> {
        self.require_operational()?;
        let mut record = self.core.load(&reservation_id)?;
        if record.revision != expected_revision {
            return Err(VaultError::RevisionConflict);
        }
        if !record.sealed || record.state.is_terminal() {
            return Err(VaultError::InvalidTransition);
        }
        if record.spent(exposure_kind.to_byte()).is_some() {
            return Err(VaultError::InvalidTransition);
        }
        let attempt_digest = record.attempt_digest.ok_or(VaultError::InvalidTransition)?;
        if record.retry_counter != Some(retry_counter) {
            return Err(VaultError::InvalidPermit);
        }
        let plaintext = self.core.open_secret(&reservation_id)?;
        let transfer = import_capability
            .import(plaintext)
            .map_err(|_| VaultError::CorruptState)?;
        // The opening is itself a durable effect: it advances the revision
        // before any public computation over the secret.
        self.core.commit(&mut record, JOURNAL_OPEN)?;
        let (phase, sequence) = match exposure_kind {
            ExposureKindV1::NonceCommitment => (SigningPhaseV1::SigNonceCommit, 1),
            ExposureKindV1::NonceReveal => (SigningPhaseV1::SigNonceReveal, 2),
            ExposureKindV1::PartialSignature => (SigningPhaseV1::SigPartial, 3),
        };
        let permit = ArtifactPersistencePermit {
            reservation_nonce_id: Self::reservation_id(&record)?,
            nonce_identity: Self::identity_of(&record)?,
            reservation_context_binding_digest: record.identity.context_binding_digest,
            derivation_attempt_digest: attempt_digest,
            operation_input_digest,
            effective_retry_counter: retry_counter,
            phase,
            exposure_kind,
            exposure_sequence: sequence,
            expected_lifecycle_revision: record.revision,
            stage_context_digest: operation_input_digest,
            process_computation_binding_id: ProcessComputationBindingIdV1::generate()
                .map_err(|_| VaultError::RandomnessUnavailable)?,
        };
        Ok((transfer, permit))
    }
}

impl NonceVaultV1 for DurableNonceVault {
    type Error = VaultError;
    type ReservationHandle = ReservationHandle;
    type ReservationSnapshot = ReservationSnapshot;
    type DerivationAttemptPermit = DerivationAttemptPermit;
    type InitialSecretOpenPermit = InitialSecretOpenPermit;
    type StageComputationPermit = StageComputationPermit;
    type ArtifactPersistencePermit = ArtifactPersistencePermit;
    type PersistedExposureHandle = PersistedExposureHandle;
    type ExposurePermit = ExposurePermit;
    type ExportedArtifact = ExportedArtifact;
    type RecoveredSpentArtifact = SpentArtifactSnapshot;

    fn claim_fresh_reservation(
        &mut self,
        request: FreshReservationRequestV1,
    ) -> Result<Self::ReservationHandle> {
        self.require_operational()?;
        if !request.purpose().is_strict_v1_authorized() {
            return Err(VaultError::UnsupportedPurpose);
        }
        // Permanent tombstone before any charge: a reused session identifier
        // can never spend budget.
        self.core
            .claim_session_id(request.session_id().as_bytes())?;
        self.core
            .charge_budgets(
                request.key_id().as_bytes(),
                request.counterparty().as_bytes(),
            )
            .map_err(|(error, scope)| match scope {
                Some(BudgetScopeLocal::Key) | Some(BudgetScopeLocal::Counterparty) => {
                    VaultError::BudgetExhausted
                }
                None => error,
            })?;
        let nonce_epoch = self.core.next_nonce_epoch()?;
        let identity = ReservationIdentity {
            reservation_id: Self::random_identifier()?,
            request_lookup: *request.request_lookup().as_bytes(),
            session_id: *request.session_id().as_bytes(),
            participant_id: *request.participant_id().as_bytes(),
            purpose: request.purpose().to_byte(),
            template_hash: *request.template_hash().as_bytes(),
            key_id: *request.key_id().as_bytes(),
            counterparty: *request.counterparty().as_bytes(),
            context_binding_digest: *request.context_binding().digest(),
            nonce_epoch,
        };
        let record = self.core.insert_reservation(identity)?;
        Ok(ReservationHandle {
            reservation_id: record.identity.reservation_id,
        })
    }

    fn resume_claimed_reservation(
        &mut self,
        request: ReservationResumeRequestV1,
    ) -> Result<ReservationResumeResultV1<Self::ReservationHandle>> {
        self.require_operational()?;
        let Some(record) = self
            .core
            .load_by_lookup(request.request_lookup().as_bytes())?
        else {
            // No authenticated occurrence: nothing was created or changed.
            return Ok(ReservationResumeResultV1::RetryNotFound);
        };
        if &record.identity.session_id != request.session_id().as_bytes()
            || &record.identity.participant_id != request.participant_id().as_bytes()
            || record.identity.purpose != request.purpose().to_byte()
            || &record.identity.template_hash != request.template_hash().as_bytes()
            || &record.identity.key_id != request.key_id().as_bytes()
            || &record.identity.counterparty != request.counterparty().as_bytes()
            || &record.identity.context_binding_digest != request.context_binding().digest()
        {
            self.core.quarantine();
            return Err(VaultError::CorruptState);
        }
        if record.state.is_terminal() {
            return Ok(ReservationResumeResultV1::Terminal(TerminalReservationV1 {
                reservation_id: Self::reservation_id(&record)?,
                state: Self::terminal_state(record.state),
            }));
        }
        Ok(ReservationResumeResultV1::Live(ReservationHandle {
            reservation_id: record.identity.reservation_id,
        }))
    }

    fn snapshot_reservation(
        &mut self,
        reservation: &Self::ReservationHandle,
    ) -> Result<Self::ReservationSnapshot> {
        self.require_operational()?;
        let record = self.core.load(&reservation.reservation_id)?;
        if record.state.is_terminal() {
            return Err(VaultError::InvalidTransition);
        }
        let spent_commitment = match record.spent_commitment.as_ref() {
            Some(reference) => Some(Self::spent_snapshot(
                &record,
                reference,
                ExposureKindV1::NonceCommitment,
            )?),
            None => None,
        };
        let spent_reveal = match record.spent_reveal.as_ref() {
            Some(reference) => Some(Self::spent_snapshot(
                &record,
                reference,
                ExposureKindV1::NonceReveal,
            )?),
            None => None,
        };
        // The live stage is rebuilt only from what is durable and spent. The
        // final retry is only projected after the commitment is spent, because
        // the signer's validation requires
        // `PreDerivation ⇒ final_retry_counter().is_none()`.
        let (live_stage, final_retry_counter) = match (&spent_commitment, &spent_reveal) {
            (None, None) => (ReservationLiveStageV1::PreDerivation, None),
            (Some(_), None) => (
                ReservationLiveStageV1::AfterCommitment,
                Some(record.retry_counter.ok_or(VaultError::CorruptState)?),
            ),
            (Some(_), Some(_)) => (
                ReservationLiveStageV1::AfterReveal,
                Some(record.retry_counter.ok_or(VaultError::CorruptState)?),
            ),
            // A spent reveal without a spent commitment is an impossible state.
            (None, Some(_)) => {
                self.core.quarantine();
                return Err(VaultError::CorruptState);
            }
        };
        Ok(ReservationSnapshot {
            request_lookup: ReservationRequestLookupV1::from_bytes(record.identity.request_lookup)
                .map_err(|_| VaultError::CorruptState)?,
            reservation_nonce_id: Self::reservation_id(&record)?,
            reservation_context_binding_digest: record.identity.context_binding_digest,
            live_stage,
            final_retry_counter,
            spent_commitment,
            spent_reveal,
        })
    }

    fn begin_nonce_derivation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: NonceDerivationRequestV1,
    ) -> Result<Self::DerivationAttemptPermit> {
        self.require_operational()?;
        let view = request.validated_view();
        if view.stage() != VaultComputationStageV1::NonceDerivation
            || view.context().signing_phase() != SigningPhaseV1::SigNonceCommit
        {
            return Err(VaultError::InvalidTransition);
        }
        let mut record = self.core.load(&reservation.reservation_id)?;
        if record.state != StateCode::Reserved || record.attempt_digest.is_some() {
            // The final retry attempt is unique: issuing a second permit would
            // allow two distinct nonces for the same reservation.
            return Err(VaultError::InvalidTransition);
        }
        if view.reservation_context_binding_digest() != &record.identity.context_binding_digest
            || view.context().session_id() != &record.identity.session_id
            || view.context().purpose().to_byte() != record.identity.purpose
            || view.context().template_hash() != &record.identity.template_hash
        {
            return Err(VaultError::InvalidPermit);
        }
        let retry_counter = view.effective_retry_counter();
        let operation_input_digest = *view.operation_input_digest();
        record.retry_counter = Some(retry_counter);
        record.attempt_digest = Some(operation_input_digest);
        self.core.commit(&mut record, JOURNAL_DERIVATION_ATTEMPT)?;
        Ok(DerivationAttemptPermit {
            reservation_id: record.identity.reservation_id,
            revision: record.revision,
            retry_counter,
            operation_input_digest,
        })
    }

    fn seal_derived_secret(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        attempt: Self::DerivationAttemptPermit,
        secret: NonceSecretTransferV1,
        seal_capability: VaultSecretSealCapabilityV1,
    ) -> Result<Self::InitialSecretOpenPermit> {
        self.require_operational()?;
        if attempt.reservation_id != reservation.reservation_id {
            return Err(VaultError::InvalidPermit);
        }
        let mut record = self.core.load(&reservation.reservation_id)?;
        if record.revision != attempt.revision {
            return Err(VaultError::RevisionConflict);
        }
        if record.sealed || record.state.is_terminal() {
            return Err(VaultError::InvalidTransition);
        }
        // The plaintext is obtained and immediately sealed; the `Zeroizing`
        // from `dom-adaptor` wipes the buffer on all drop paths.
        let plaintext = seal_capability.into_plaintext(secret);
        self.core
            .seal_secret(&reservation.reservation_id, &plaintext)?;
        drop(plaintext);
        record.sealed = true;
        self.core.commit(&mut record, JOURNAL_SEAL)?;
        Ok(InitialSecretOpenPermit {
            reservation_id: record.identity.reservation_id,
            revision: record.revision,
            retry_counter: attempt.retry_counter,
            operation_input_digest: attempt.operation_input_digest,
        })
    }

    fn open_sealed_secret_for_commitment(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::InitialSecretOpenPermit,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<(NonceSecretTransferV1, Self::ArtifactPersistencePermit)> {
        if permit.reservation_id != reservation.reservation_id {
            return Err(VaultError::InvalidPermit);
        }
        self.open_and_bind(
            permit.reservation_id,
            permit.revision,
            permit.retry_counter,
            permit.operation_input_digest,
            ExposureKindV1::NonceCommitment,
            import_capability,
        )
    }

    fn begin_stage_computation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: StageComputationRequestV1,
    ) -> Result<Self::StageComputationPermit> {
        self.require_operational()?;
        let view = request.validated_view();
        let (exposure_kind, phase) = match view.stage() {
            VaultComputationStageV1::NonceReveal => {
                (ExposureKindV1::NonceReveal, SigningPhaseV1::SigNonceReveal)
            }
            VaultComputationStageV1::PartialAttempt => {
                (ExposureKindV1::PartialSignature, SigningPhaseV1::SigPartial)
            }
            VaultComputationStageV1::NonceDerivation => {
                return Err(VaultError::InvalidTransition);
            }
        };
        if view.context().signing_phase() != phase {
            return Err(VaultError::InvalidTransition);
        }
        let mut record = self.core.load(&reservation.reservation_id)?;
        if record.state.is_terminal() {
            return Err(VaultError::InvalidTransition);
        }
        // The normative ordering is enforced here, not by the caller.
        let ordered = match exposure_kind {
            ExposureKindV1::NonceReveal => {
                record.spent_commitment.is_some() && record.spent_reveal.is_none()
            }
            ExposureKindV1::PartialSignature => {
                record.spent_reveal.is_some() && record.spent_partial.is_none()
            }
            ExposureKindV1::NonceCommitment => false,
        };
        if !ordered {
            return Err(VaultError::InvalidTransition);
        }
        if view.reservation_context_binding_digest() != &record.identity.context_binding_digest
            || view.context().session_id() != &record.identity.session_id
            || view.context().purpose().to_byte() != record.identity.purpose
            || view.context().template_hash() != &record.identity.template_hash
        {
            return Err(VaultError::InvalidPermit);
        }
        let retry_counter = view.effective_retry_counter();
        if record.retry_counter != Some(retry_counter) {
            // The final retry was fixed at derivation and cannot change between stages.
            return Err(VaultError::InvalidPermit);
        }
        let operation_input_digest = *view.operation_input_digest();
        record.stage_digest = Some(operation_input_digest);
        self.core.commit(&mut record, JOURNAL_STAGE_ATTEMPT)?;
        Ok(StageComputationPermit {
            reservation_id: record.identity.reservation_id,
            revision: record.revision,
            retry_counter,
            operation_input_digest,
            exposure_kind,
        })
    }

    fn open_secret_for_stage(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::StageComputationPermit,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<(NonceSecretTransferV1, Self::ArtifactPersistencePermit)> {
        if permit.reservation_id != reservation.reservation_id {
            return Err(VaultError::InvalidPermit);
        }
        self.open_and_bind(
            permit.reservation_id,
            permit.revision,
            permit.retry_counter,
            permit.operation_input_digest,
            permit.exposure_kind,
            import_capability,
        )
    }

    fn persist_computed_artifact(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::ArtifactPersistencePermit,
        artifact: PreparedExposureV1,
    ) -> Result<Self::PersistedExposureHandle> {
        self.require_operational()?;
        if permit.reservation_nonce_id.as_bytes() != &reservation.reservation_id {
            return Err(VaultError::InvalidPermit);
        }
        // Authoritative revalidation by the pin's primitive, never local.
        let view = validate_prepared_exposure_v1(&permit, &artifact)
            .map_err(|_| VaultError::InvalidPermit)?;
        let kind = view.kind();
        if kind != permit.exposure_kind {
            return Err(VaultError::InvalidPermit);
        }
        let mut record = self.core.load(&reservation.reservation_id)?;
        if record.revision != permit.expected_lifecycle_revision {
            return Err(VaultError::RevisionConflict);
        }
        if record.spent(kind.to_byte()).is_some() {
            return Err(VaultError::InvalidTransition);
        }
        if kind == ExposureKindV1::NonceReveal {
            let prior = view
                .prior_spent_artifact()
                .ok_or(VaultError::InvalidPermit)?;
            let spent = record
                .spent_commitment
                .as_ref()
                .ok_or(VaultError::InvalidTransition)?;
            if prior.permit_id().as_bytes() != &spent.permit_id
                || prior.adaptor_outbound_digest() != &spent.outbound_digest
            {
                return Err(VaultError::InvalidPermit);
            }
        }
        let artifact_record = Self::artifact_from_view(
            &record,
            Self::random_identifier()?,
            kind,
            *view.adaptor_outbound_digest(),
            view.outbound_bytes().to_vec(),
        );
        Self::reverify_outbound(&artifact_record)?;
        // Durable persistence BEFORE any authorization or external effect.
        self.core.put_persisted_artifact(&artifact_record)?;
        self.core.commit(&mut record, JOURNAL_PERSIST)?;
        Ok(PersistedExposureHandle {
            reservation_id: record.identity.reservation_id,
            revision: record.revision,
            exposure_kind: kind,
            permit_id: artifact_record.permit_id,
            outbound_digest: artifact_record.outbound_digest,
        })
    }

    fn authorize_persisted_exposure(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        persisted: Self::PersistedExposureHandle,
    ) -> Result<Self::ExposurePermit> {
        self.require_operational()?;
        if persisted.reservation_id != reservation.reservation_id {
            return Err(VaultError::InvalidPermit);
        }
        let mut record = self.core.load(&reservation.reservation_id)?;
        if record.revision != persisted.revision {
            return Err(VaultError::RevisionConflict);
        }
        let artifact = self
            .core
            .persisted_artifact(&persisted.reservation_id, persisted.exposure_kind.to_byte())?;
        if artifact.permit_id != persisted.permit_id
            || artifact.outbound_digest != persisted.outbound_digest
        {
            self.core.quarantine();
            return Err(VaultError::CorruptState);
        }
        Self::reverify_outbound(&artifact)?;
        self.core.authorize_artifact(&artifact)?;
        self.core.commit(&mut record, JOURNAL_AUTHORIZE)?;
        Ok(ExposurePermit {
            reservation_id: persisted.reservation_id,
            exposure_kind: persisted.exposure_kind,
            permit_id: persisted.permit_id,
        })
    }

    fn export(&mut self, permit: Self::ExposurePermit) -> Result<Self::ExportedArtifact> {
        self.require_operational()?;
        let mut record = self.core.load(&permit.reservation_id)?;
        if record.state.is_terminal() || record.spent(permit.exposure_kind.to_byte()).is_some() {
            return Err(VaultError::InvalidTransition);
        }
        let artifact = self
            .core
            .authorized_artifact(&permit.reservation_id, permit.exposure_kind.to_byte())?;
        if artifact.permit_id != permit.permit_id {
            return Err(VaultError::InvalidPermit);
        }
        Self::reverify_outbound(&artifact)?;
        // DURABLE SPEND FIRST. `spend_artifact` writes, indexes and re-reads;
        // no byte is returned before that.
        let spent = self.core.spend_artifact(&artifact)?;
        let reference = SpentRef {
            permit_id: spent.permit_id,
            outbound_digest: spent.outbound_digest,
        };
        match permit.exposure_kind {
            ExposureKindV1::NonceCommitment => {
                record.spent_commitment = Some(reference);
                record.state = StateCode::CommitmentAuthorized;
            }
            ExposureKindV1::NonceReveal => {
                record.spent_reveal = Some(reference);
                record.state = StateCode::RevealAuthorized;
            }
            ExposureKindV1::PartialSignature => {
                record.spent_partial = Some(reference);
                record.state = StateCode::ConsumedPartialAuthorized;
                // Terminal: the secret material is closed off forever.
                self.core.burn_secret(&permit.reservation_id)?;
            }
        }
        self.core.commit(&mut record, JOURNAL_SPEND)?;
        Ok(ExportedArtifact {
            permit_id: PermitIdV1::from_bytes(spent.permit_id)
                .map_err(|_| VaultError::CorruptState)?,
            kind: ExposureKindV1::try_from(spent.kind).map_err(|_| VaultError::CorruptState)?,
            bytes: spent.bytes,
        })
    }

    fn recover_spent_artifact(
        &mut self,
        authorization: &ValidatedResendAuthorizationV1,
    ) -> Result<Self::RecoveredSpentArtifact> {
        self.require_operational()?;
        let kind = authorization.protocol_stage().exposure_kind();
        let permit_id = self
            .core
            .spent_permit_for_stage(authorization.request_lookup().as_bytes(), kind.to_byte())?;
        let artifact = self.core.spent_artifact(&permit_id)?;
        if artifact.kind != kind.to_byte()
            || &artifact.session_id != authorization.session_id().as_bytes()
            || artifact.purpose != authorization.purpose().to_byte()
            || &artifact.bound_digest != authorization.reservation_context_binding_digest()
            || &artifact.outbound_digest != authorization.adaptor_outbound_digest()
        {
            return Err(VaultError::InvalidPermit);
        }
        Ok(SpentArtifactSnapshot {
            nonce_identity: Self::identity_of_artifact(&artifact)?,
            permit_id: PermitIdV1::from_bytes(artifact.permit_id)
                .map_err(|_| VaultError::CorruptState)?,
            kind,
            adaptor_outbound_digest: artifact.outbound_digest,
        })
    }

    fn resend_exported(&mut self, request: ResendRequestV1) -> Result<Self::ExportedArtifact> {
        self.require_operational()?;
        let kind = request.protocol_stage().exposure_kind();
        let artifact = self.core.spent_artifact(request.permit_id().as_bytes())?;
        let identity = Self::identity_of_artifact(&artifact)?;
        if artifact.kind != kind.to_byte()
            || &artifact.outbound_digest != request.adaptor_outbound_digest()
            || &artifact.bound_digest != request.reservation_context_binding_digest()
            || &identity != request.nonce_identity()
        {
            return Err(VaultError::InvalidPermit);
        }
        // Verbatim bytes from the spent record. Nothing is recomputed here:
        // no nonce, no partial, no pre-signature, no payload.
        Ok(ExportedArtifact {
            permit_id: PermitIdV1::from_bytes(artifact.permit_id)
                .map_err(|_| VaultError::CorruptState)?,
            kind,
            bytes: artifact.bytes,
        })
    }

    fn cancel_reservation(
        &mut self,
        reservation: Self::ReservationHandle,
    ) -> Result<TerminalReservationV1> {
        let mut record = self.core.load(&reservation.reservation_id)?;
        if record.state.is_terminal() {
            return Ok(TerminalReservationV1 {
                reservation_id: Self::reservation_id(&record)?,
                state: Self::terminal_state(record.state),
            });
        }
        // If public material could have existed, the abort burns the nonce.
        let public_material_possible = record.attempt_digest.is_some()
            || record.sealed
            || record.spent_commitment.is_some()
            || record.spent_reveal.is_some();
        record.state = if public_material_possible {
            StateCode::ConsumedOnAbort
        } else {
            StateCode::AbortedBeforePublicMaterial
        };
        self.core.burn_secret(&reservation.reservation_id)?;
        self.core.commit(&mut record, JOURNAL_TERMINAL)?;
        Ok(TerminalReservationV1 {
            reservation_id: Self::reservation_id(&record)?,
            state: Self::terminal_state(record.state),
        })
    }

    fn restore_state(&self) -> RestoreState {
        if self.core.is_quarantined() {
            RestoreState::RestoreQuarantined
        } else {
            RestoreState::Operational
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// `Clone`/`Copy` probe without a negative bound.
    ///
    /// The inherent impl only exists when the type is `Clone` (or `Copy`) and
    /// takes priority in method resolution; without it, the call falls back
    /// to the trait's blanket impl, which returns `false`. If anyone derives
    /// `Clone` on a one-shot capability, this suite breaks immediately —
    /// which is the point, because uniqueness is enforced only by Rust's move
    /// semantics.
    struct Probe<T>(core::marker::PhantomData<T>);

    trait CloneFallback {
        fn probe_is_clone(&self) -> bool {
            false
        }
    }

    impl<T> CloneFallback for T {}

    impl<T: Clone> Probe<T> {
        fn probe_is_clone(&self) -> bool {
            true
        }
    }

    trait CopyFallback {
        fn probe_is_copy(&self) -> bool {
            false
        }
    }

    impl<T> CopyFallback for T {}

    impl<T: Copy> Probe<T> {
        fn probe_is_copy(&self) -> bool {
            true
        }
    }

    macro_rules! assert_one_shot {
        ($($name:ty),+ $(,)?) => {
            $(
                let probe = Probe::<$name>(core::marker::PhantomData);
                assert!(
                    !probe.probe_is_clone(),
                    concat!(stringify!($name), " can never be Clone")
                );
                assert!(
                    !probe.probe_is_copy(),
                    concat!(stringify!($name), " can never be Copy")
                );
            )+
        };
    }

    #[test]
    fn capability_types_are_never_clone_or_copy() {
        assert_one_shot!(
            ReservationHandle,
            DerivationAttemptPermit,
            InitialSecretOpenPermit,
            StageComputationPermit,
            ArtifactPersistencePermit,
            PersistedExposureHandle,
            ExposurePermit,
        );
        // Negative control: the probe really does detect a cloneable type.
        let control = Probe::<u8>(core::marker::PhantomData);
        assert!(control.probe_is_clone());
        assert!(control.probe_is_copy());
    }

    const RESERVATION_ID: [u8; 32] = [0x21; 32];

    fn open_vault(path: &Path) -> DurableNonceVault {
        DurableNonceVault::new(store::Store::open(path).expect("open store"))
    }

    fn identity() -> ReservationIdentity {
        ReservationIdentity {
            reservation_id: RESERVATION_ID,
            request_lookup: [0x22; 32],
            session_id: [0x23; 32],
            participant_id: [0x24; 32],
            purpose: PurposeV1::Refund.to_byte(),
            template_hash: [0x25; 32],
            key_id: [0x26; 32],
            counterparty: [0x27; 32],
            context_binding_digest: [0x28; 32],
            nonce_epoch: 3,
        }
    }

    fn handle() -> ReservationHandle {
        ReservationHandle {
            reservation_id: RESERVATION_ID,
        }
    }

    /// Exact public artifact with the digest computed by the pin's primitive.
    fn artifact(kind: ExposureKindV1, permit_id: [u8; 32], filler: u8) -> ArtifactRecord {
        let bytes = vec![filler; kind.outbound_len()];
        let outbound_digest = *exposure_outbound_digest_v1(kind, &bytes)
            .expect("canonical outbound digest")
            .as_bytes();
        let identity = identity();
        ArtifactRecord {
            permit_id,
            reservation_id: identity.reservation_id,
            request_lookup: identity.request_lookup,
            kind: kind.to_byte(),
            outbound_digest,
            session_id: identity.session_id,
            participant_id: identity.participant_id,
            purpose: identity.purpose,
            bound_digest: identity.context_binding_digest,
            nonce_epoch: identity.nonce_epoch,
            bytes,
        }
    }

    fn mutate(vault: &mut DurableNonceVault, change: impl FnOnce(&mut ReservationRecord)) {
        let mut record = vault.core_mut().load(&RESERVATION_ID).expect("load");
        change(&mut record);
        vault
            .core_mut()
            .commit(&mut record, JOURNAL_SPEND)
            .expect("commit");
    }

    #[test]
    fn a_fresh_vault_is_operational_and_quarantines_after_rollback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vault = open_vault(&dir.path().join("vault.db"));
        vault
            .core_mut()
            .insert_reservation(identity())
            .expect("claim");
        assert_eq!(vault.restore_state(), RestoreState::Operational);
        vault.core_mut().quarantine();
        assert_eq!(vault.restore_state(), RestoreState::RestoreQuarantined);
        // Under quarantine, no adaptor operation runs again.
        assert!(matches!(
            vault.snapshot_reservation(&handle()),
            Err(VaultError::RestoreQuarantined)
        ));
    }

    #[test]
    fn pre_derivation_snapshot_obeys_the_signer_revalidation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vault = open_vault(&dir.path().join("vault.db"));
        vault
            .core_mut()
            .insert_reservation(identity())
            .expect("claim");
        // Even with the retry already durable, PreDerivation must not project it.
        mutate(&mut vault, |record| {
            record.retry_counter = Some(4);
            record.attempt_digest = Some([0x31; 32]);
            record.sealed = true;
        });
        let snapshot = vault.snapshot_reservation(&handle()).expect("snapshot");
        assert_eq!(snapshot.live_stage(), ReservationLiveStageV1::PreDerivation);
        assert!(snapshot.final_retry_counter().is_none());
        assert!(snapshot.spent_commitment().is_none());
        assert!(snapshot.spent_reveal().is_none());
        assert_eq!(
            snapshot.reservation_context_binding_digest(),
            &identity().context_binding_digest
        );
        assert_eq!(
            snapshot.request_lookup().as_bytes(),
            &identity().request_lookup
        );
    }

    #[test]
    fn after_commitment_and_after_reveal_snapshots_bind_one_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vault = open_vault(&dir.path().join("vault.db"));
        vault
            .core_mut()
            .insert_reservation(identity())
            .expect("claim");
        mutate(&mut vault, |record| {
            record.retry_counter = Some(4);
            record.sealed = true;
            record.spent_commitment = Some(SpentRef {
                permit_id: [0x41; 32],
                outbound_digest: [0x42; 32],
            });
            record.state = StateCode::CommitmentAuthorized;
        });
        let snapshot = vault.snapshot_reservation(&handle()).expect("snapshot");
        assert_eq!(
            snapshot.live_stage(),
            ReservationLiveStageV1::AfterCommitment
        );
        assert_eq!(snapshot.final_retry_counter(), Some(4));
        let commitment = snapshot.spent_commitment().expect("commitment");
        assert_eq!(commitment.kind(), ExposureKindV1::NonceCommitment);
        assert_ne!(commitment.adaptor_outbound_digest(), &[0; 32]);
        assert_eq!(
            commitment.nonce_identity().bound_digest(),
            &identity().context_binding_digest
        );
        assert_eq!(
            commitment.nonce_identity().session_id().as_bytes(),
            &identity().session_id
        );
        assert_eq!(
            commitment.nonce_identity().participant_id().as_bytes(),
            &identity().participant_id
        );
        assert_eq!(commitment.nonce_identity().purpose(), PurposeV1::Refund);
        assert!(snapshot.spent_reveal().is_none());

        mutate(&mut vault, |record| {
            record.spent_reveal = Some(SpentRef {
                permit_id: [0x43; 32],
                outbound_digest: [0x44; 32],
            });
            record.state = StateCode::RevealAuthorized;
        });
        let snapshot = vault.snapshot_reservation(&handle()).expect("snapshot");
        assert_eq!(snapshot.live_stage(), ReservationLiveStageV1::AfterReveal);
        let commitment = snapshot.spent_commitment().expect("commitment");
        let reveal = snapshot.spent_reveal().expect("reveal");
        assert_eq!(reveal.kind(), ExposureKindV1::NonceReveal);
        assert_eq!(
            commitment.nonce_identity(),
            reveal.nonce_identity(),
            "commitment and reveal must name the same nonce identity"
        );
    }

    #[test]
    fn a_reveal_spent_without_a_commitment_is_corrupt_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vault = open_vault(&dir.path().join("vault.db"));
        vault
            .core_mut()
            .insert_reservation(identity())
            .expect("claim");
        mutate(&mut vault, |record| {
            record.retry_counter = Some(1);
            record.spent_reveal = Some(SpentRef {
                permit_id: [0x51; 32],
                outbound_digest: [0x52; 32],
            });
        });
        assert!(matches!(
            vault.snapshot_reservation(&handle()),
            Err(VaultError::CorruptState)
        ));
        assert_eq!(vault.restore_state(), RestoreState::RestoreQuarantined);
    }

    #[test]
    fn export_spends_durably_before_it_returns_any_byte() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        let record = artifact(ExposureKindV1::NonceCommitment, [0x61; 32], 0xAB);
        let exported_bytes = {
            let mut vault = open_vault(&path);
            vault
                .core_mut()
                .insert_reservation(identity())
                .expect("claim");
            mutate(&mut vault, |reservation| {
                reservation.retry_counter = Some(2);
                reservation.sealed = true;
            });
            vault
                .core_mut()
                .put_persisted_artifact(&record)
                .expect("persist");
            vault
                .core_mut()
                .authorize_artifact(&record)
                .expect("authorize");
            let permit = ExposurePermit {
                reservation_id: RESERVATION_ID,
                exposure_kind: ExposureKindV1::NonceCommitment,
                permit_id: record.permit_id,
            };
            let exported = vault.export(permit).expect("export");
            assert_eq!(exported.kind(), ExposureKindV1::NonceCommitment);
            assert_eq!(exported.permit_id().as_bytes(), &record.permit_id);

            // A second export of the same stage fails closed.
            let replay = ExposurePermit {
                reservation_id: RESERVATION_ID,
                exposure_kind: ExposureKindV1::NonceCommitment,
                permit_id: record.permit_id,
            };
            assert!(matches!(
                vault.export(replay),
                Err(VaultError::InvalidTransition)
            ));
            exported.as_bytes().to_vec()
        };
        assert_eq!(exported_bytes, record.bytes);

        // The released bytes were already durable: reopening the database returns them identical.
        let mut vault = open_vault(&path);
        let spent = vault
            .core_mut()
            .spent_artifact(&record.permit_id)
            .expect("spent after restart");
        assert_eq!(spent.bytes, exported_bytes);
        let snapshot = vault.snapshot_reservation(&handle()).expect("snapshot");
        assert_eq!(
            snapshot.live_stage(),
            ReservationLiveStageV1::AfterCommitment
        );
    }

    #[test]
    fn authorization_requires_the_exact_persisted_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vault = open_vault(&dir.path().join("vault.db"));
        vault
            .core_mut()
            .insert_reservation(identity())
            .expect("claim");
        let record = artifact(ExposureKindV1::NonceCommitment, [0x71; 32], 0xCD);
        vault
            .core_mut()
            .put_persisted_artifact(&record)
            .expect("persist");
        let mut reservation = handle();
        let revision = vault
            .core_mut()
            .load(&RESERVATION_ID)
            .expect("load")
            .revision;
        // A handle naming another permit cannot authorize this artifact.
        let forged = PersistedExposureHandle {
            reservation_id: RESERVATION_ID,
            revision,
            exposure_kind: ExposureKindV1::NonceCommitment,
            permit_id: [0x72; 32],
            outbound_digest: record.outbound_digest,
        };
        assert!(matches!(
            vault.authorize_persisted_exposure(&mut reservation, forged),
            Err(VaultError::CorruptState)
        ));
    }

    #[test]
    fn cancelling_burns_the_secret_and_stays_terminal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        let mut vault = open_vault(&path);
        vault
            .core_mut()
            .insert_reservation(identity())
            .expect("claim");
        mutate(&mut vault, |record| {
            record.sealed = true;
            record.attempt_digest = Some([0x81; 32]);
            record.retry_counter = Some(1);
        });
        let terminal = vault.cancel_reservation(handle()).expect("cancel");
        assert_eq!(terminal.state, ReservationState::ConsumedOnAbort);
        assert_eq!(terminal.reservation_id.as_bytes(), &RESERVATION_ID);
        // The secret becomes inaccessible forever and the reservation never lives again.
        assert!(vault.core_mut().open_secret(&RESERVATION_ID).is_err());
        assert!(matches!(
            vault.snapshot_reservation(&handle()),
            Err(VaultError::InvalidTransition)
        ));

        drop(vault);
        let mut vault = open_vault(&path);
        let repeated = vault.cancel_reservation(handle()).expect("idempotent");
        assert_eq!(repeated.state, ReservationState::ConsumedOnAbort);
    }

    #[test]
    fn cancelling_before_any_public_material_does_not_burn_the_nonce() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut vault = open_vault(&dir.path().join("vault.db"));
        vault
            .core_mut()
            .insert_reservation(identity())
            .expect("claim");
        let terminal = vault.cancel_reservation(handle()).expect("cancel");
        assert_eq!(
            terminal.state,
            ReservationState::AbortedBeforePublicMaterial
        );
    }
}

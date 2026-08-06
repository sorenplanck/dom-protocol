//! Public-API composition seam proof for signed NAR-DC-P1-007.

use dom_adaptor::{
    advance_transcript_hash_v1, aggregate_public_nonces_v1, initial_transcript_hash_v1,
    session_message_digest_v1, validate_prepared_exposure_v1, AcceptedMessageDispositionV1,
    AcceptedSigningSessionV1, ContractKindV1, DurableReservationLookupV1, ExposureKindV1,
    FreshReservationRequestV1, NonceDerivationRequestV1, NonceIdentityV1, NonceVaultV1,
    ParticipantId, ParticipantIdentityV1, ParticipantRosterV1, PermitIdV1, PreparedExposureV1,
    ProcessComputationBindingIdV1, PurposeV1, ResendRequestV1, ResentArtifactV1,
    ReservationLiveStageV1, ReservationLookupCustodyV1, ReservationNonceId,
    ReservationRequestLookupV1, ReservationResumeRequestV1, ReservationResumeResultV1,
    ReservationState, RestoreState, SessionId, SigningPhaseV1, SigningSessionAuthorityV1,
    SigningShareV1, StageComputationRequestV1, TerminalReservationV1, TrustedChainIdV1,
    ValidatedResendAuthorizationV1, VaultArtifactPersistencePermitV1, VaultBackedSignerV1,
    VaultComputationStageV1, VaultExportedArtifactV1, VaultReservationSnapshotV1,
    VaultSecretImportCapabilityV1, VaultSecretSealCapabilityV1, VaultSpentArtifactSnapshotV1,
};
use dom_consensus::{Transaction, TransactionKernel};
use dom_core::{Amount, Hash256};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{schnorr_sign, PublicKey, SecretKey};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

const KIND_COMMITMENT: u8 = 0x0c;
const KIND_REVEAL: u8 = 0x0d;
const KIND_PARTIAL: u8 = 0x0e;

#[derive(Debug)]
struct TestBoundaryError(&'static str);

impl fmt::Display for TestBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for TestBoundaryError {}

fn lock<T>(value: &Mutex<T>) -> Result<MutexGuard<'_, T>, TestBoundaryError> {
    value
        .lock()
        .map_err(|_| TestBoundaryError("test authority lock poisoned"))
}

#[derive(Clone)]
struct TestSpentArtifact {
    nonce_identity: NonceIdentityV1,
    permit_id: PermitIdV1,
    kind: ExposureKindV1,
    digest: [u8; 32],
    bytes: Vec<u8>,
    exported: bool,
}

impl VaultSpentArtifactSnapshotV1 for TestSpentArtifact {
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

struct TestSnapshot {
    lookup: ReservationRequestLookupV1,
    reservation_id: ReservationNonceId,
    binding: [u8; 32],
    stage: ReservationLiveStageV1,
    retry: Option<u64>,
    commitment: Option<TestSpentArtifact>,
    reveal: Option<TestSpentArtifact>,
}

impl VaultReservationSnapshotV1 for TestSnapshot {
    type SpentArtifact = TestSpentArtifact;

    fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.lookup
    }

    fn reservation_nonce_id(&self) -> &ReservationNonceId {
        &self.reservation_id
    }

    fn reservation_context_binding_digest(&self) -> &[u8; 32] {
        &self.binding
    }

    fn live_stage(&self) -> ReservationLiveStageV1 {
        self.stage
    }

    fn final_retry_counter(&self) -> Option<u64> {
        self.retry
    }

    fn spent_commitment(&self) -> Option<&Self::SpentArtifact> {
        self.commitment.as_ref()
    }

    fn spent_reveal(&self) -> Option<&Self::SpentArtifact> {
        self.reveal.as_ref()
    }
}

struct TestPersistencePermit {
    reservation_id: ReservationNonceId,
    nonce_identity: NonceIdentityV1,
    binding: [u8; 32],
    attempt_digest: [u8; 32],
    operation_digest: [u8; 32],
    retry: u64,
    phase: SigningPhaseV1,
    kind: ExposureKindV1,
    sequence: u64,
    revision: u64,
    stage_digest: [u8; 32],
    process_binding: ProcessComputationBindingIdV1,
}

impl VaultArtifactPersistencePermitV1 for TestPersistencePermit {
    fn reservation_nonce_id(&self) -> &ReservationNonceId {
        &self.reservation_id
    }

    fn nonce_identity(&self) -> &NonceIdentityV1 {
        &self.nonce_identity
    }

    fn reservation_context_binding_digest(&self) -> &[u8; 32] {
        &self.binding
    }

    fn derivation_attempt_digest(&self) -> &[u8; 32] {
        &self.attempt_digest
    }

    fn operation_input_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }

    fn effective_retry_counter(&self) -> u64 {
        self.retry
    }

    fn phase(&self) -> SigningPhaseV1 {
        self.phase
    }

    fn exposure_kind(&self) -> ExposureKindV1 {
        self.kind
    }

    fn exposure_sequence(&self) -> u64 {
        self.sequence
    }

    fn expected_lifecycle_revision(&self) -> u64 {
        self.revision
    }

    fn stage_context_digest(&self) -> &[u8; 32] {
        &self.stage_digest
    }

    fn process_computation_binding_id(&self) -> &ProcessComputationBindingIdV1 {
        &self.process_binding
    }
}

struct TestDerivationAttempt(TestPersistencePermit);
struct TestInitialOpen(TestPersistencePermit);
struct TestStageAttempt(TestPersistencePermit);

struct TestPersisted {
    permit_id: PermitIdV1,
}

struct TestExposurePermit {
    permit_id: PermitIdV1,
}

struct TestExported {
    artifact: TestSpentArtifact,
}

impl VaultExportedArtifactV1 for TestExported {
    fn permit_id(&self) -> &PermitIdV1 {
        &self.artifact.permit_id
    }

    fn kind(&self) -> ExposureKindV1 {
        self.artifact.kind
    }

    fn as_bytes(&self) -> &[u8] {
        &self.artifact.bytes
    }
}

struct TestRecord {
    lookup: ReservationRequestLookupV1,
    reservation_id: ReservationNonceId,
    session_id: SessionId,
    participant_id: ParticipantId,
    purpose: PurposeV1,
    binding: [u8; 32],
    nonce_identity: NonceIdentityV1,
    stage: ReservationLiveStageV1,
    retry: Option<u64>,
    secret: Option<Zeroizing<Vec<u8>>>,
    pending: Option<TestSpentArtifact>,
    spent: Vec<TestSpentArtifact>,
    terminal: bool,
}

#[derive(Clone)]
struct TestVault {
    state: Arc<Mutex<Option<TestRecord>>>,
    reservation_byte: u8,
}

impl TestVault {
    fn new(reservation_byte: u8) -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            reservation_byte,
        }
    }

    fn restarted(&self) -> Self {
        self.clone()
    }

    fn record(guard: &mut Option<TestRecord>) -> Result<&mut TestRecord, TestBoundaryError> {
        guard
            .as_mut()
            .ok_or(TestBoundaryError("reservation not found"))
    }

    fn permit_from_view(
        record: &TestRecord,
        view: dom_adaptor::ValidatedVaultComputationViewV1<'_>,
    ) -> Result<TestPersistencePermit, TestBoundaryError> {
        let (kind, sequence) = match view.stage() {
            VaultComputationStageV1::NonceDerivation => (ExposureKindV1::NonceCommitment, 1),
            VaultComputationStageV1::NonceReveal => (ExposureKindV1::NonceReveal, 2),
            VaultComputationStageV1::PartialAttempt => (ExposureKindV1::PartialSignature, 3),
        };
        let operation_digest = *view.operation_input_digest();
        if operation_digest == [0; 32] {
            return Err(TestBoundaryError("zero operation digest"));
        }
        Ok(TestPersistencePermit {
            reservation_id: record.reservation_id.clone(),
            nonce_identity: record.nonce_identity.clone(),
            binding: *view.reservation_context_binding_digest(),
            attempt_digest: operation_digest,
            operation_digest,
            retry: view.effective_retry_counter(),
            phase: view.context().signing_phase(),
            kind,
            sequence,
            revision: sequence,
            stage_digest: operation_digest,
            process_binding: ProcessComputationBindingIdV1::generate()
                .map_err(|_| TestBoundaryError("process binding generation failed"))?,
        })
    }

    fn matching_spent(
        record: &TestRecord,
        permit_id: &PermitIdV1,
        kind: ExposureKindV1,
        digest: &[u8; 32],
    ) -> Result<TestSpentArtifact, TestBoundaryError> {
        record
            .spent
            .iter()
            .find(|artifact| {
                artifact.exported
                    && &artifact.permit_id == permit_id
                    && artifact.kind == kind
                    && &artifact.digest == digest
            })
            .cloned()
            .ok_or(TestBoundaryError("spent artifact not found"))
    }
}

impl NonceVaultV1 for TestVault {
    type Error = TestBoundaryError;
    type ReservationHandle = ReservationNonceId;
    type ReservationSnapshot = TestSnapshot;
    type DerivationAttemptPermit = TestDerivationAttempt;
    type InitialSecretOpenPermit = TestInitialOpen;
    type StageComputationPermit = TestStageAttempt;
    type ArtifactPersistencePermit = TestPersistencePermit;
    type PersistedExposureHandle = TestPersisted;
    type ExposurePermit = TestExposurePermit;
    type ExportedArtifact = TestExported;
    type RecoveredSpentArtifact = TestSpentArtifact;

    fn claim_fresh_reservation(
        &mut self,
        request: FreshReservationRequestV1,
    ) -> Result<Self::ReservationHandle, Self::Error> {
        let mut state = lock(&self.state)?;
        if state.is_some() {
            return Err(TestBoundaryError("reservation already exists"));
        }
        let reservation_id = ReservationNonceId::from_bytes([self.reservation_byte; 32])
            .map_err(|_| TestBoundaryError("reservation identifier invalid"))?;
        let binding = *request.context_binding().digest();
        let nonce_identity = NonceIdentityV1::new(
            request.session_id().clone(),
            request.participant_id().clone(),
            request.purpose(),
            binding,
            1,
        )
        .map_err(|_| TestBoundaryError("nonce identity invalid"))?;
        *state = Some(TestRecord {
            lookup: request.request_lookup().clone(),
            reservation_id: reservation_id.clone(),
            session_id: request.session_id().clone(),
            participant_id: request.participant_id().clone(),
            purpose: request.purpose(),
            binding,
            nonce_identity,
            stage: ReservationLiveStageV1::PreDerivation,
            retry: None,
            secret: None,
            pending: None,
            spent: Vec::new(),
            terminal: false,
        });
        Ok(reservation_id)
    }

    fn resume_claimed_reservation(
        &mut self,
        request: ReservationResumeRequestV1,
    ) -> Result<ReservationResumeResultV1<Self::ReservationHandle>, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if record.lookup != *request.request_lookup()
            || record.session_id != *request.session_id()
            || record.participant_id != *request.participant_id()
            || record.purpose != request.purpose()
            || record.binding != *request.context_binding().digest()
        {
            return Err(TestBoundaryError("resume binding mismatch"));
        }
        if record.terminal {
            return Ok(ReservationResumeResultV1::Terminal(TerminalReservationV1 {
                reservation_id: record.reservation_id.clone(),
                state: ReservationState::ConsumedPartialAuthorized,
            }));
        }
        Ok(ReservationResumeResultV1::Live(
            record.reservation_id.clone(),
        ))
    }

    fn snapshot_reservation(
        &mut self,
        reservation: &Self::ReservationHandle,
    ) -> Result<Self::ReservationSnapshot, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if &record.reservation_id != reservation || record.terminal {
            return Err(TestBoundaryError("snapshot handle mismatch"));
        }
        Ok(TestSnapshot {
            lookup: record.lookup.clone(),
            reservation_id: record.reservation_id.clone(),
            binding: record.binding,
            stage: record.stage,
            retry: record.retry,
            commitment: record
                .spent
                .iter()
                .find(|artifact| artifact.kind == ExposureKindV1::NonceCommitment)
                .cloned(),
            reveal: record
                .spent
                .iter()
                .find(|artifact| artifact.kind == ExposureKindV1::NonceReveal)
                .cloned(),
        })
    }

    fn begin_nonce_derivation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: NonceDerivationRequestV1,
    ) -> Result<Self::DerivationAttemptPermit, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if &record.reservation_id != reservation
            || record.stage != ReservationLiveStageV1::PreDerivation
            || record.secret.is_some()
        {
            return Err(TestBoundaryError("invalid derivation transition"));
        }
        let permit = Self::permit_from_view(record, request.validated_view())?;
        record.retry = Some(permit.retry);
        Ok(TestDerivationAttempt(permit))
    }

    fn seal_derived_secret(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        attempt: Self::DerivationAttemptPermit,
        secret: dom_adaptor::NonceSecretTransferV1,
        seal_capability: VaultSecretSealCapabilityV1,
    ) -> Result<Self::InitialSecretOpenPermit, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if &record.reservation_id != reservation || record.secret.is_some() {
            return Err(TestBoundaryError("secret already sealed"));
        }
        record.secret = Some(seal_capability.into_plaintext(secret));
        Ok(TestInitialOpen(attempt.0))
    }

    fn open_sealed_secret_for_commitment(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::InitialSecretOpenPermit,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<
        (
            dom_adaptor::NonceSecretTransferV1,
            Self::ArtifactPersistencePermit,
        ),
        Self::Error,
    > {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if &record.reservation_id != reservation {
            return Err(TestBoundaryError("secret-open handle mismatch"));
        }
        let plaintext = record
            .secret
            .as_ref()
            .ok_or(TestBoundaryError("sealed secret missing"))?;
        let transfer = import_capability
            .import(Zeroizing::new(plaintext.to_vec()))
            .map_err(|_| TestBoundaryError("secret import rejected"))?;
        Ok((transfer, permit.0))
    }

    fn begin_stage_computation(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        request: StageComputationRequestV1,
    ) -> Result<Self::StageComputationPermit, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if &record.reservation_id != reservation || record.secret.is_none() {
            return Err(TestBoundaryError("invalid stage transition"));
        }
        let permit = Self::permit_from_view(record, request.validated_view())?;
        Ok(TestStageAttempt(permit))
    }

    fn open_secret_for_stage(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::StageComputationPermit,
        import_capability: VaultSecretImportCapabilityV1,
    ) -> Result<
        (
            dom_adaptor::NonceSecretTransferV1,
            Self::ArtifactPersistencePermit,
        ),
        Self::Error,
    > {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if &record.reservation_id != reservation {
            return Err(TestBoundaryError("stage-open handle mismatch"));
        }
        let plaintext = record
            .secret
            .as_ref()
            .ok_or(TestBoundaryError("sealed secret missing"))?;
        let transfer = import_capability
            .import(Zeroizing::new(plaintext.to_vec()))
            .map_err(|_| TestBoundaryError("secret import rejected"))?;
        Ok((transfer, permit.0))
    }

    fn persist_computed_artifact(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        permit: Self::ArtifactPersistencePermit,
        artifact: PreparedExposureV1,
    ) -> Result<Self::PersistedExposureHandle, Self::Error> {
        let view = validate_prepared_exposure_v1(&permit, &artifact)
            .map_err(|_| TestBoundaryError("prepared exposure rejected"))?;
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if &record.reservation_id != reservation || record.pending.is_some() {
            return Err(TestBoundaryError("artifact persistence conflict"));
        }
        let permit_id = PermitIdV1::from_bytes([permit.sequence as u8; 32])
            .map_err(|_| TestBoundaryError("permit identifier invalid"))?;
        record.pending = Some(TestSpentArtifact {
            nonce_identity: permit.nonce_identity.clone(),
            permit_id: permit_id.clone(),
            kind: view.kind(),
            digest: *view.adaptor_outbound_digest(),
            bytes: view.outbound_bytes().to_vec(),
            exported: false,
        });
        Ok(TestPersisted { permit_id })
    }

    fn authorize_persisted_exposure(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        persisted: Self::PersistedExposureHandle,
    ) -> Result<Self::ExposurePermit, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if &record.reservation_id != reservation {
            return Err(TestBoundaryError("authorization handle mismatch"));
        }
        let artifact = record
            .pending
            .take()
            .ok_or(TestBoundaryError("persisted artifact missing"))?;
        if artifact.permit_id != persisted.permit_id {
            return Err(TestBoundaryError("persisted permit mismatch"));
        }
        record.stage = match artifact.kind {
            ExposureKindV1::NonceCommitment => ReservationLiveStageV1::AfterCommitment,
            ExposureKindV1::NonceReveal => ReservationLiveStageV1::AfterReveal,
            ExposureKindV1::PartialSignature => {
                record.secret = None;
                record.terminal = true;
                ReservationLiveStageV1::AfterReveal
            }
        };
        record.spent.push(artifact);
        Ok(TestExposurePermit {
            permit_id: persisted.permit_id,
        })
    }

    fn export(
        &mut self,
        permit: Self::ExposurePermit,
    ) -> Result<Self::ExportedArtifact, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        let artifact = record
            .spent
            .iter_mut()
            .find(|artifact| artifact.permit_id == permit.permit_id)
            .ok_or(TestBoundaryError("spent permit missing"))?;
        if artifact.exported {
            return Err(TestBoundaryError("second export rejected"));
        }
        artifact.exported = true;
        Ok(TestExported {
            artifact: artifact.clone(),
        })
    }

    fn recover_spent_artifact(
        &mut self,
        authorization: &ValidatedResendAuthorizationV1,
    ) -> Result<Self::RecoveredSpentArtifact, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if record.lookup != *authorization.request_lookup()
            || record.binding != *authorization.reservation_context_binding_digest()
            || record.session_id != *authorization.session_id()
            || record.purpose != authorization.purpose()
        {
            return Err(TestBoundaryError("resend authorization mismatch"));
        }
        record
            .spent
            .iter()
            .find(|artifact| {
                artifact.exported
                    && artifact.kind == authorization.protocol_stage().exposure_kind()
                    && artifact.digest == *authorization.adaptor_outbound_digest()
            })
            .cloned()
            .ok_or(TestBoundaryError("authorized spent artifact not found"))
    }

    fn resend_exported(
        &mut self,
        request: ResendRequestV1,
    ) -> Result<Self::ExportedArtifact, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if record.lookup != *request.request_lookup()
            || record.nonce_identity != *request.nonce_identity()
            || record.binding != *request.reservation_context_binding_digest()
        {
            return Err(TestBoundaryError("resend request mismatch"));
        }
        let artifact = Self::matching_spent(
            record,
            request.permit_id(),
            request.protocol_stage().exposure_kind(),
            request.adaptor_outbound_digest(),
        )?;
        Ok(TestExported { artifact })
    }

    fn cancel_reservation(
        &mut self,
        reservation: Self::ReservationHandle,
    ) -> Result<TerminalReservationV1, Self::Error> {
        let mut state = lock(&self.state)?;
        let record = Self::record(&mut state)?;
        if record.reservation_id != reservation {
            return Err(TestBoundaryError("cancel handle mismatch"));
        }
        record.terminal = true;
        record.secret = None;
        Ok(TerminalReservationV1 {
            reservation_id: reservation,
            state: ReservationState::ConsumedOnAbort,
        })
    }

    fn restore_state(&self) -> RestoreState {
        RestoreState::Operational
    }
}

#[derive(Clone)]
struct TestCustody {
    retained: Arc<Mutex<Option<TestDurableLookup>>>,
}

impl TestCustody {
    fn new() -> Self {
        Self {
            retained: Arc::new(Mutex::new(None)),
        }
    }

    fn restarted(&self) -> Self {
        self.clone()
    }

    fn lookup(&self) -> Result<ReservationRequestLookupV1, TestBoundaryError> {
        lock(&self.retained)?
            .as_ref()
            .map(|value| value.lookup.clone())
            .ok_or(TestBoundaryError("retained lookup missing"))
    }
}

#[derive(Clone)]
struct TestDurableLookup {
    lookup: ReservationRequestLookupV1,
    binding: [u8; 32],
    session_id: SessionId,
}

impl DurableReservationLookupV1 for TestDurableLookup {
    fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.lookup
    }

    fn context_binding_digest(&self) -> &[u8; 32] {
        &self.binding
    }

    fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

impl ReservationLookupCustodyV1 for TestCustody {
    type Error = TestBoundaryError;
    type DurableLookup = TestDurableLookup;

    fn persist_prepared_lookup(
        &mut self,
        prepared: &dom_adaptor::PreparedFreshReservationV1,
    ) -> Result<Self::DurableLookup, Self::Error> {
        let durable = TestDurableLookup {
            lookup: prepared.request_lookup().clone(),
            binding: *prepared.context_binding_digest(),
            session_id: prepared.session_id().clone(),
        };
        *lock(&self.retained)? = Some(durable.clone());
        Ok(durable)
    }

    fn abandon_before_vault_claim(
        &mut self,
        _lookup: &ReservationRequestLookupV1,
        _session_id: &SessionId,
        _context_binding_digest: &[u8; 32],
    ) -> Result<(), Self::Error> {
        Err(TestBoundaryError("unexpected retry abandonment"))
    }
}

struct TestAcceptedSession {
    chain: TrustedChainIdV1,
    session_id: [u8; 32],
    roster: ParticipantRosterV1,
    transaction: Transaction,
    transcript: [u8; 32],
}

impl AcceptedSigningSessionV1 for TestAcceptedSession {
    fn trusted_chain_id(&self) -> &TrustedChainIdV1 {
        &self.chain
    }

    fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    fn contract_kind(&self) -> ContractKindV1 {
        ContractKindV1::WitnessOrTimeout
    }

    fn purpose(&self) -> PurposeV1 {
        PurposeV1::Refund
    }

    fn roster(&self) -> &ParticipantRosterV1 {
        &self.roster
    }

    fn transaction_template(&self) -> &Transaction {
        &self.transaction
    }

    fn kernel_index(&self) -> usize {
        0
    }

    fn adaptor_point(&self) -> Option<&PublicKey> {
        None
    }

    fn initial_transcript_hash(&self) -> &[u8; 32] {
        &self.transcript
    }

    fn accepted_signing_messages(&self) -> impl Iterator<Item = &[u8]> {
        core::iter::empty()
    }
}

struct TestSessionAuthority;

impl SigningSessionAuthorityV1 for TestSessionAuthority {
    type Error = TestBoundaryError;
    type AcceptedSession = TestAcceptedSession;
}

struct ParticipantFixture {
    identity_secret: [u8; 32],
    signing_share: [u8; 32],
}

struct SessionFixture {
    chain: TrustedChainIdV1,
    session_id: [u8; 32],
    roster: ParticipantRosterV1,
    transaction: Transaction,
    transcript: [u8; 32],
    participants: [ParticipantFixture; 2],
}

impl SessionFixture {
    fn new() -> Self {
        let chain = TrustedChainIdV1::from_authenticated_genesis(
            0x5031_3037,
            &Hash256::from_bytes([0x71; 32]),
        );
        let raw = [
            ([0x72; 32], [0x74; 32], dom_adaptor::DirectionV1::Initiator),
            ([0x73; 32], [0x75; 32], dom_adaptor::DirectionV1::Responder),
        ];
        let mut entries = Vec::new();
        for (identity_bytes, share_bytes, direction) in raw {
            let identity = SecretKey::from_bytes(&identity_bytes).expect("test identity");
            let share = SigningShareV1::from_be_bytes(share_bytes).expect("test share");
            entries.push(
                ParticipantIdentityV1::new(
                    &chain,
                    identity.public_key(),
                    share.public_key().clone(),
                    direction,
                )
                .expect("test participant"),
            );
        }
        entries.sort_by_key(|entry| *entry.participant_id());
        let roster = ParticipantRosterV1::new(entries).expect("test roster");
        let participants = core::array::from_fn(|index| {
            let key = roster.entries()[index].signing_public_key();
            let source = raw
                .iter()
                .find(|(_, share_bytes, _)| {
                    SigningShareV1::from_be_bytes(*share_bytes)
                        .map(|share| share.public_key() == key)
                        .unwrap_or(false)
                })
                .expect("test participant source");
            ParticipantFixture {
                identity_secret: source.0,
                signing_share: source.1,
            }
        });
        let mut signing_keys: Vec<_> = roster
            .entries()
            .iter()
            .map(|entry| entry.signing_public_key().clone())
            .collect();
        signing_keys.sort_by_key(PublicKey::to_compressed_bytes);
        let aggregate = aggregate_public_nonces_v1(&signing_keys).expect("aggregate signing key");
        let transaction = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            kernels: vec![TransactionKernel {
                features: 0,
                fee: Amount::ZERO,
                lock_height: 0,
                excess: Commitment::from_compressed_bytes(&aggregate.to_compressed_bytes())
                    .expect("aggregate excess"),
                excess_signature: [0; 65],
            }],
            offset: [0x76; 32],
        };
        let session_id = [0x77; 32];
        let transcript = initial_transcript_hash_v1(
            &chain,
            &session_id,
            ContractKindV1::WitnessOrTimeout,
            &roster,
        );
        Self {
            chain,
            session_id,
            roster,
            transaction,
            transcript,
            participants,
        }
    }

    fn accepted(&self) -> TestAcceptedSession {
        TestAcceptedSession {
            chain: self.chain,
            session_id: self.session_id,
            roster: self.roster.clone(),
            transaction: self.transaction.clone(),
            transcript: self.transcript,
        }
    }

    fn share(&self, index: usize) -> SigningShareV1 {
        SigningShareV1::from_be_bytes(self.participants[index].signing_share)
            .expect("test signing share")
    }

    fn identity(&self, index: usize) -> SecretKey {
        SecretKey::from_bytes(&self.participants[index].identity_secret).expect("test identity")
    }
}

fn signed_message(
    fixture: &SessionFixture,
    sender_index: usize,
    sequence: u64,
    previous_transcript: [u8; 32],
    kind: u8,
    phase: SigningPhaseV1,
    payload: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let sender = &fixture.roster.entries()[sender_index];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"DSC1");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(kind);
    bytes.push(0);
    bytes.extend_from_slice(fixture.chain.as_bytes());
    bytes.extend_from_slice(&fixture.session_id);
    bytes.extend_from_slice(sender.participant_id());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&previous_transcript);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    let digest = session_message_digest_v1(&bytes);
    let signature = schnorr_sign(
        &fixture.identity(sender_index),
        &digest,
        fixture.chain.as_bytes(),
    )
    .expect("test transport signature");
    bytes.extend_from_slice(&signature.to_bytes());
    let next = advance_transcript_hash_v1(&previous_transcript, &digest, sender.direction(), phase);
    (bytes, next)
}

fn signer(
    vault: TestVault,
    custody: TestCustody,
    fixture: &SessionFixture,
    participant: usize,
) -> VaultBackedSignerV1<TestVault, TestCustody, TestSessionAuthority> {
    VaultBackedSignerV1::new(
        vault,
        custody,
        TestSessionAuthority,
        fixture.chain,
        fixture.share(participant),
    )
}

#[test]
fn public_associated_session_seam_drives_complete_signer_lifecycle() {
    let fixture = SessionFixture::new();
    let vaults = [TestVault::new(0x91), TestVault::new(0x92)];
    let custody = [TestCustody::new(), TestCustody::new()];
    let mut signers = [
        signer(vaults[0].clone(), custody[0].clone(), &fixture, 0),
        signer(vaults[1].clone(), custody[1].clone(), &fixture, 1),
    ];
    let mut rounds = [
        signers[0]
            .begin_accepted_signing_round(fixture.accepted())
            .expect("accepted round A"),
        signers[1]
            .begin_accepted_signing_round(fixture.accepted())
            .expect("accepted round B"),
    ];
    let [derivation_a, derivation_b] = [
        rounds[0].take_derivation_base().expect("derivation A"),
        rounds[1].take_derivation_base().expect("derivation B"),
    ];
    let reserved_a = signers[0].claim_fresh(derivation_a).expect("claim A");
    let reserved_b = signers[1].claim_fresh(derivation_b).expect("claim B");
    let (_lost_commitment_state_a, commitment_a) = signers[0]
        .derive_and_export_commitment(reserved_a)
        .expect("commitment A");
    let (commitment_state_b, commitment_b) = signers[1]
        .derive_and_export_commitment(reserved_b)
        .expect("commitment B");
    let mut transcript = fixture.transcript;
    let (commitment_message_a, next) = signed_message(
        &fixture,
        0,
        0,
        transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commitment_a.to_bytes(),
    );
    transcript = next;
    let (commitment_message_b, next) = signed_message(
        &fixture,
        1,
        0,
        transcript,
        KIND_COMMITMENT,
        SigningPhaseV1::SigNonceCommit,
        &commitment_b.to_bytes(),
    );
    transcript = next;
    for round in &mut rounds {
        assert_eq!(
            round
                .accept_message(&commitment_message_a)
                .expect("accept commitment A"),
            AcceptedMessageDispositionV1::Advanced
        );
        assert_eq!(
            round
                .accept_message(&commitment_message_a)
                .expect("idempotent commitment A"),
            AcceptedMessageDispositionV1::Idempotent
        );
        assert_eq!(
            round
                .accept_message(&commitment_message_b)
                .expect("accept commitment B"),
            AcceptedMessageDispositionV1::Advanced
        );
    }

    let restart_lookup = custody[0].lookup().expect("restart lookup");
    signers[0] = signer(vaults[0].restarted(), custody[0].restarted(), &fixture, 0);
    let mut restarted_round = signers[0]
        .begin_accepted_signing_round(fixture.accepted())
        .expect("restart accepted round");
    let restart_derivation = restarted_round
        .take_derivation_base()
        .expect("restart derivation");
    let resumed = signers[0]
        .resume_claimed(restart_derivation, restart_lookup)
        .expect("resume claimed reservation");
    let commitment_state_a = match resumed {
        ReservationResumeResultV1::Live(dom_adaptor::ResumedReservationV1::AfterCommitment(
            state,
        )) => state,
        _ => panic!("unexpected restart state"),
    };
    restarted_round
        .accept_message(&commitment_message_a)
        .expect("restart commitment A");
    restarted_round
        .accept_message(&commitment_message_b)
        .expect("restart commitment B");
    let resend_authority = commitment_state_a
        .authorize_resend(&mut restarted_round)
        .expect("commitment resend authority");
    let resent = signers[0]
        .resend_commitment(&commitment_state_a, resend_authority)
        .expect("exact commitment resend");
    match resent {
        ResentArtifactV1::NonceCommitment(value) => assert_eq!(value, commitment_a),
        _ => panic!("wrong resent artifact kind"),
    }
    rounds[0] = restarted_round;

    let reveal_authority_a = rounds[0]
        .take_commitment_round()
        .expect("reveal authority A");
    let (reveal_state_a, reveal_a) = signers[0]
        .export_reveal(commitment_state_a, reveal_authority_a)
        .expect("reveal A");
    let (reveal_message_a, next) = signed_message(
        &fixture,
        0,
        1,
        transcript,
        KIND_REVEAL,
        SigningPhaseV1::SigNonceReveal,
        &reveal_a.to_bytes(),
    );
    transcript = next;
    for round in &mut rounds {
        round
            .accept_message(&reveal_message_a)
            .expect("accept reveal A");
    }
    let reveal_authority_b = rounds[1]
        .take_commitment_round()
        .expect("reveal authority B");
    let (reveal_state_b, reveal_b) = signers[1]
        .export_reveal(commitment_state_b, reveal_authority_b)
        .expect("reveal B");
    let (reveal_message_b, next) = signed_message(
        &fixture,
        1,
        1,
        transcript,
        KIND_REVEAL,
        SigningPhaseV1::SigNonceReveal,
        &reveal_b.to_bytes(),
    );
    transcript = next;
    for round in &mut rounds {
        round
            .accept_message(&reveal_message_b)
            .expect("accept reveal B");
    }

    let partial_authority_a = rounds[0].take_reveal_round().expect("partial authority A");
    let (terminal_a, partial_a) = signers[0]
        .sign_and_export_partial(reveal_state_a, partial_authority_a)
        .expect("partial A");
    let (partial_message_a, next) = signed_message(
        &fixture,
        0,
        2,
        transcript,
        KIND_PARTIAL,
        SigningPhaseV1::SigPartial,
        &partial_a.to_bytes(),
    );
    transcript = next;
    for round in &mut rounds {
        round
            .accept_message(&partial_message_a)
            .expect("accept partial A");
    }
    let partial_authority_b = rounds[1].take_reveal_round().expect("partial authority B");
    let (_terminal_b, partial_b) = signers[1]
        .sign_and_export_partial(reveal_state_b, partial_authority_b)
        .expect("partial B");
    let (partial_message_b, _next) = signed_message(
        &fixture,
        1,
        2,
        transcript,
        KIND_PARTIAL,
        SigningPhaseV1::SigPartial,
        &partial_b.to_bytes(),
    );
    for round in &mut rounds {
        round
            .accept_message(&partial_message_b)
            .expect("accept partial B");
    }
    let partial_resend = terminal_a
        .authorize_resend(&mut rounds[0])
        .expect("partial resend authority");
    let resent = signers[0]
        .resend_partial(&terminal_a, partial_resend)
        .expect("exact partial resend");
    match resent {
        ResentArtifactV1::PartialSignature(value) => {
            assert_eq!(value.to_bytes(), partial_a.to_bytes())
        }
        _ => panic!("wrong resent partial kind"),
    }
    assert!(terminal_a.authorize_resend(&mut rounds[0]).is_err());
}

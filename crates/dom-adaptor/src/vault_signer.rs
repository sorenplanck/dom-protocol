//! Non-bypassable high-level G1a/G1b signer composition.

use crate::secret_nonce::SecretNonceDerivationV1;
use crate::{
    nonce_commitment_hash_v1, AdaptorError, AuthorizedExposureV1, ExposureKindV1,
    NonceCommitmentV1, NonceDerivationRequestV1, NonceRevealV1, NonceSecretTransferV1,
    NonceVaultError, NonceVaultV1, PartialSignatureV1, PreparedExposureV1, PublicNoncePairV1,
    ResendProtocolStageV1, ResendRequestV1, ReservationContextBindingV1, ReservationLiveStageV1,
    ReservationLookupCustodyV1, ReservationRequestLookupV1, ReservationResumeRequestV1,
    ReservationResumeResultV1, RestoreState, SessionContextV1, SigningSessionAuthorityV1,
    SigningShareV1, TerminalReservationV1, TrustedChainIdV1, ValidatedCommitmentRoundV1,
    ValidatedDerivationBaseV1, ValidatedResendAuthorizationV1, ValidatedRevealRoundV1,
    VaultArtifactPersistencePermitV1, VaultExportedArtifactV1, VaultReservationSnapshotV1,
    VaultSecretImportCapabilityV1, VaultSecretSealCapabilityV1, VaultSpentArtifactSnapshotV1,
};
use core::fmt;
use dom_crypto::{schnorr_challenge, PartialSig};
use std::error::Error;

/// Typed failure from the integrated cryptographic and durable-authority path.
pub enum VaultBackedSignerError<VaultError, CustodyError> {
    /// Canonical parsing, binding, or cryptographic failure.
    Adaptor(AdaptorError),
    /// Storage-independent vault contract validation failure.
    Contract(NonceVaultError),
    /// Failure reported by the statically selected DOM Contracts vault store.
    Vault(VaultError),
    /// Failure reported by the statically selected trusted session store.
    Custody(CustodyError),
    /// The vault returned bytes other than the exact prepared persisted artifact.
    AuthorizedArtifactMismatch,
}

impl<VaultError, CustodyError> fmt::Debug for VaultBackedSignerError<VaultError, CustodyError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adaptor(error) => formatter.debug_tuple("Adaptor").field(error).finish(),
            Self::Contract(error) => formatter.debug_tuple("Contract").field(error).finish(),
            Self::Vault(_) => formatter.write_str("Vault([redacted])"),
            Self::Custody(_) => formatter.write_str("Custody([redacted])"),
            Self::AuthorizedArtifactMismatch => formatter.write_str("AuthorizedArtifactMismatch"),
        }
    }
}

impl<VaultError, CustodyError> fmt::Display for VaultBackedSignerError<VaultError, CustodyError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adaptor(error) => error.fmt(formatter),
            Self::Contract(error) => error.fmt(formatter),
            Self::Vault(_) => formatter.write_str("vault operation failed (details redacted)"),
            Self::Custody(_) => formatter.write_str("lookup custody failed (details redacted)"),
            Self::AuthorizedArtifactMismatch => {
                formatter.write_str("vault returned a different authorized artifact")
            }
        }
    }
}

impl<VaultError: 'static, CustodyError: 'static> Error
    for VaultBackedSignerError<VaultError, CustodyError>
{
}

impl<VaultError, CustodyError> From<AdaptorError>
    for VaultBackedSignerError<VaultError, CustodyError>
{
    fn from(error: AdaptorError) -> Self {
        Self::Adaptor(error)
    }
}

impl<VaultError, CustodyError> From<NonceVaultError>
    for VaultBackedSignerError<VaultError, CustodyError>
{
    fn from(error: NonceVaultError) -> Self {
        Self::Contract(error)
    }
}

impl<VaultError, CustodyError> From<crate::PreparedExposureValidationError>
    for VaultBackedSignerError<VaultError, CustodyError>
{
    fn from(error: crate::PreparedExposureValidationError) -> Self {
        match error {
            crate::PreparedExposureValidationError::BindingMismatch => {
                Self::AuthorizedArtifactMismatch
            }
            crate::PreparedExposureValidationError::Adaptor(error) => Self::Adaptor(error),
            crate::PreparedExposureValidationError::Contract(error) => Self::Contract(error),
        }
    }
}

impl<VaultError, CustodyError> From<dom_core::DomError>
    for VaultBackedSignerError<VaultError, CustodyError>
{
    fn from(error: dom_core::DomError) -> Self {
        Self::Adaptor(error.into())
    }
}

/// Opaque freshly claimed state. No nonce derivation permit has been issued.
pub struct ReservedNonceV1<Handle> {
    handle: Handle,
    request_lookup: ReservationRequestLookupV1,
    reservation_nonce_id: crate::ReservationNonceId,
    context: SessionContextV1,
    participant_id: [u8; 32],
    context_binding_digest: [u8; 32],
}

/// State after durable authorization and exact commitment export.
pub struct CommitmentExportedV1<Handle> {
    handle: Handle,
    request_lookup: ReservationRequestLookupV1,
    reservation_nonce_id: crate::ReservationNonceId,
    context: SessionContextV1,
    participant_id: [u8; 32],
    context_binding_digest: [u8; 32],
    nonce_identity: crate::NonceIdentityV1,
    permit_id: crate::PermitIdV1,
}

impl<Handle> CommitmentExportedV1<Handle> {
    /// Return the public non-authoritative lookup for the exported commitment.
    pub const fn permit_id(&self) -> &crate::PermitIdV1 {
        &self.permit_id
    }
}

/// State after durable authorization and exact nonce-reveal export.
pub struct RevealExportedV1<Handle> {
    handle: Handle,
    request_lookup: ReservationRequestLookupV1,
    reservation_nonce_id: crate::ReservationNonceId,
    context: SessionContextV1,
    participant_id: [u8; 32],
    context_binding_digest: [u8; 32],
    nonce_identity: crate::NonceIdentityV1,
    permit_id: crate::PermitIdV1,
}

impl<Handle> RevealExportedV1<Handle> {
    /// Return the public non-authoritative lookup for the exported nonce reveal.
    pub const fn permit_id(&self) -> &crate::PermitIdV1 {
        &self.permit_id
    }
}

/// Terminal marker after exactly one partial-signature export.
pub struct PartialExportedTerminalV1 {
    permit_id: crate::PermitIdV1,
    request_lookup: ReservationRequestLookupV1,
    reservation_nonce_id: crate::ReservationNonceId,
    nonce_identity: crate::NonceIdentityV1,
    context_binding_digest: [u8; 32],
}

impl PartialExportedTerminalV1 {
    /// Return the public non-authoritative lookup for the exported partial.
    pub const fn permit_id(&self) -> &crate::PermitIdV1 {
        &self.permit_id
    }
}

/// Exhaustive live state reconstructed from one exact authenticated Store prefix.
pub enum ResumedReservationV1<Handle> {
    /// Same-process fresh claim for which no nonce derivation may have started.
    PreDerivation(ReservedNonceV1<Handle>),
    /// Exact spent commitment successor with a verified sealed secret.
    AfterCommitment(CommitmentExportedV1<Handle>),
    /// Exact spent commitment and reveal successors with a verified sealed secret.
    AfterReveal(RevealExportedV1<Handle>),
}

/// Closed typed result of a validated restart resend lookup.
pub enum ResentArtifactV1 {
    /// Exact canonical nonce commitment.
    NonceCommitment(NonceCommitmentV1),
    /// Exact canonical two-nonce reveal.
    NonceReveal(NonceRevealV1),
    /// Exact canonical participant partial signature.
    PartialSignature(PartialSignatureV1),
}

impl ResentArtifactV1 {
    /// Return the closed kind of the exact typed artifact.
    pub const fn kind(&self) -> ExposureKindV1 {
        match self {
            Self::NonceCommitment(_) => ExposureKindV1::NonceCommitment,
            Self::NonceReveal(_) => ExposureKindV1::NonceReveal,
            Self::PartialSignature(_) => ExposureKindV1::PartialSignature,
        }
    }
}

/// High-level signer owning one statically selected vault, custody store, and share.
pub struct VaultBackedSignerV1<Vault, Custody, Sessions>
where
    Vault: NonceVaultV1,
    Custody: ReservationLookupCustodyV1,
    Sessions: SigningSessionAuthorityV1,
{
    vault: Vault,
    custody: Custody,
    _sessions: Sessions,
    trusted_chain_id: TrustedChainIdV1,
    signing_share: SigningShareV1,
}

type SignerResult<Vault, Custody, Value> = core::result::Result<
    Value,
    VaultBackedSignerError<
        <Vault as NonceVaultV1>::Error,
        <Custody as ReservationLookupCustodyV1>::Error,
    >,
>;

impl<Vault, Custody, Sessions> VaultBackedSignerV1<Vault, Custody, Sessions>
where
    Vault: NonceVaultV1,
    Custody: ReservationLookupCustodyV1,
    Sessions: SigningSessionAuthorityV1,
{
    /// Bind all security-critical dependencies statically at the composition root.
    pub fn new(
        vault: Vault,
        custody: Custody,
        sessions: Sessions,
        trusted_chain_id: TrustedChainIdV1,
        signing_share: SigningShareV1,
    ) -> Self {
        Self {
            vault,
            custody,
            _sessions: sessions,
            trusted_chain_id,
            signing_share,
        }
    }

    /// Delegate the reconciled read-only recovery state of the concrete vault.
    pub fn restore_state(&self) -> RestoreState {
        self.vault.restore_state()
    }

    /// Durably retain request lookup custody and then claim one fresh reservation.
    pub fn claim_fresh(
        &mut self,
        authority: ValidatedDerivationBaseV1,
    ) -> SignerResult<Vault, Custody, ReservedNonceV1<Vault::ReservationHandle>> {
        let binding = ReservationContextBindingV1::new(
            authority.context(),
            authority.roster(),
            authority.local_protocol_index(),
            &self.signing_share,
        )?;
        let participant_id = *binding.local_participant_id();
        let prepared = crate::PreparedFreshReservationV1::new(
            authority.context(),
            &self.signing_share,
            binding,
        )?;
        let custody = self
            .custody
            .persist_prepared_lookup(&prepared)
            .map_err(VaultBackedSignerError::Custody)?;
        let request = prepared.into_request(custody)?;
        let expected_lookup = request.request_lookup().clone();
        let expected_binding = *request.context_binding().digest();
        let context = authority.context().clone();
        let handle = self
            .vault
            .claim_fresh_reservation(request)
            .map_err(VaultBackedSignerError::Vault)?;
        let snapshot = self
            .vault
            .snapshot_reservation(&handle)
            .map_err(VaultBackedSignerError::Vault)?;
        validate_live_snapshot(
            &snapshot,
            &expected_lookup,
            &expected_binding,
            ReservationLiveStageV1::PreDerivation,
            None,
        )?;
        let reservation_nonce_id = snapshot.reservation_nonce_id().clone();
        Ok(ReservedNonceV1 {
            handle,
            request_lookup: expected_lookup,
            reservation_nonce_id,
            context,
            participant_id,
            context_binding_digest: expected_binding,
        })
    }

    /// Resolve only an exact previously claimed request; there is no fresh fallback.
    pub fn resume_claimed(
        &mut self,
        authority: ValidatedDerivationBaseV1,
        request_lookup: ReservationRequestLookupV1,
    ) -> SignerResult<
        Vault,
        Custody,
        ReservationResumeResultV1<ResumedReservationV1<Vault::ReservationHandle>>,
    > {
        let binding = ReservationContextBindingV1::new(
            authority.context(),
            authority.roster(),
            authority.local_protocol_index(),
            &self.signing_share,
        )?;
        let participant_id = *binding.local_participant_id();
        let binding_digest = *binding.digest();
        let context = authority.context().clone();
        let request = ReservationResumeRequestV1::from_trusted_state(
            &context,
            &self.signing_share,
            request_lookup.clone(),
            binding,
        )?;
        match self
            .vault
            .resume_claimed_reservation(request)
            .map_err(VaultBackedSignerError::Vault)?
        {
            ReservationResumeResultV1::RetryNotFound => {
                self.custody
                    .abandon_before_vault_claim(
                        &request_lookup,
                        &crate::SessionId::from_bytes(*context.session_id())?,
                        &binding_digest,
                    )
                    .map_err(VaultBackedSignerError::Custody)?;
                Ok(ReservationResumeResultV1::RetryNotFound)
            }
            ReservationResumeResultV1::Terminal(terminal) => {
                Ok(ReservationResumeResultV1::Terminal(terminal))
            }
            ReservationResumeResultV1::Live(handle) => {
                let snapshot = self
                    .vault
                    .snapshot_reservation(&handle)
                    .map_err(VaultBackedSignerError::Vault)?;
                validate_live_snapshot(
                    &snapshot,
                    &request_lookup,
                    &binding_digest,
                    snapshot.live_stage(),
                    snapshot.final_retry_counter(),
                )?;
                let reservation_nonce_id = snapshot.reservation_nonce_id().clone();
                let state = match snapshot.live_stage() {
                    ReservationLiveStageV1::PreDerivation => {
                        ResumedReservationV1::PreDerivation(ReservedNonceV1 {
                            handle,
                            request_lookup,
                            reservation_nonce_id,
                            context,
                            participant_id,
                            context_binding_digest: binding_digest,
                        })
                    }
                    ReservationLiveStageV1::AfterCommitment => {
                        let resumed_context = context.with_retry_counter(
                            snapshot
                                .final_retry_counter()
                                .ok_or(NonceVaultError::CorruptState)?,
                        );
                        let permit_id = snapshot
                            .spent_commitment()
                            .ok_or(NonceVaultError::CorruptState)?
                            .permit_id()
                            .clone();
                        let nonce_identity = snapshot
                            .spent_commitment()
                            .ok_or(NonceVaultError::CorruptState)?
                            .nonce_identity()
                            .clone();
                        ResumedReservationV1::AfterCommitment(CommitmentExportedV1 {
                            handle,
                            request_lookup,
                            reservation_nonce_id,
                            context: resumed_context,
                            participant_id,
                            context_binding_digest: binding_digest,
                            nonce_identity,
                            permit_id,
                        })
                    }
                    ReservationLiveStageV1::AfterReveal => {
                        let resumed_context = context.with_retry_counter(
                            snapshot
                                .final_retry_counter()
                                .ok_or(NonceVaultError::CorruptState)?,
                        );
                        let permit_id = snapshot
                            .spent_reveal()
                            .ok_or(NonceVaultError::CorruptState)?
                            .permit_id()
                            .clone();
                        let nonce_identity = snapshot
                            .spent_reveal()
                            .ok_or(NonceVaultError::CorruptState)?
                            .nonce_identity()
                            .clone();
                        ResumedReservationV1::AfterReveal(RevealExportedV1 {
                            handle,
                            request_lookup,
                            reservation_nonce_id,
                            context: resumed_context,
                            participant_id,
                            context_binding_digest: binding_digest,
                            nonce_identity,
                            permit_id,
                        })
                    }
                };
                Ok(ReservationResumeResultV1::Live(state))
            }
        }
    }

    /// Derive, seal, reopen, persist, authorize, and export one commitment.
    pub fn derive_and_export_commitment(
        &mut self,
        mut state: ReservedNonceV1<Vault::ReservationHandle>,
    ) -> SignerResult<
        Vault,
        Custody,
        (
            CommitmentExportedV1<Vault::ReservationHandle>,
            NonceCommitmentV1,
        ),
    > {
        let (effective_context, pair, request) = prepare_private_nonce_derivation_attempt(
            SecretNonceDerivationV1::from_os_rng()?,
            &self.signing_share,
            &state.context,
            state.context_binding_digest,
        )?;
        let operation_evidence = request.evidence();
        let attempt = self
            .vault
            .begin_nonce_derivation(&mut state.handle, request)
            .map_err(VaultBackedSignerError::Vault)?;
        let transfer = NonceSecretTransferV1::from_nonce_pair(
            *state.reservation_nonce_id.as_bytes(),
            state.participant_id,
            &effective_context,
            pair,
        )?;
        let open = self
            .vault
            .seal_derived_secret(
                &mut state.handle,
                attempt,
                transfer,
                VaultSecretSealCapabilityV1::new(),
            )
            .map_err(VaultBackedSignerError::Vault)?;
        let (transfer, persistence_permit) = self
            .vault
            .open_sealed_secret_for_commitment(
                &mut state.handle,
                open,
                VaultSecretImportCapabilityV1::new(),
            )
            .map_err(VaultBackedSignerError::Vault)?;
        let pair = transfer.into_validated_pair(
            state.reservation_nonce_id.as_bytes(),
            &state.participant_id,
            &effective_context,
            &self.trusted_chain_id,
            &self.signing_share,
        )?;
        let (first, second) = pair.public_keys()?;
        let public_nonces = PublicNoncePairV1::new(first, second);
        let commitment_hash = nonce_commitment_hash_v1(
            effective_context.chain_id(),
            effective_context.session_id(),
            &state.participant_id,
            effective_context.purpose(),
            effective_context.template_hash(),
            public_nonces.first(),
            public_nonces.second(),
            effective_context.adaptor_point(),
        )?;
        let commitment = NonceCommitmentV1::new(
            effective_context.purpose(),
            effective_context.participant_index(),
            *commitment_hash.as_bytes(),
        );
        let nonce_identity = persistence_permit.nonce_identity().clone();
        let prepared = PreparedExposureV1::commitment(
            &persistence_permit,
            &operation_evidence.validated_view(),
            public_nonces,
            commitment,
        )?;
        let persisted = self
            .vault
            .persist_computed_artifact(&mut state.handle, persistence_permit, prepared)
            .map_err(VaultBackedSignerError::Vault)?;
        let permit = self
            .vault
            .authorize_persisted_exposure(&mut state.handle, persisted)
            .map_err(VaultBackedSignerError::Vault)?;
        let exported = self
            .vault
            .export(permit)
            .map_err(VaultBackedSignerError::Vault)?;
        let authorized = validate_exported_artifact(&exported, ExposureKindV1::NonceCommitment)?;
        let parsed = NonceCommitmentV1::from_bytes(authorized.as_bytes())?;
        if parsed != commitment {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        let permit_id = authorized.permit_id().clone();
        let snapshot = self
            .vault
            .snapshot_reservation(&state.handle)
            .map_err(VaultBackedSignerError::Vault)?;
        validate_live_snapshot(
            &snapshot,
            &state.request_lookup,
            &state.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
            Some(effective_context.retry_counter()),
        )?;
        validate_spent_projection(
            &snapshot,
            ExposureKindV1::NonceCommitment,
            &permit_id,
            crate::exposure_outbound_digest_v1(
                ExposureKindV1::NonceCommitment,
                authorized.as_bytes(),
            )?
            .as_bytes(),
        )?;
        Ok((
            CommitmentExportedV1 {
                handle: state.handle,
                request_lookup: state.request_lookup,
                reservation_nonce_id: state.reservation_nonce_id,
                context: effective_context,
                participant_id: state.participant_id,
                context_binding_digest: state.context_binding_digest,
                nonce_identity,
                permit_id,
            },
            parsed,
        ))
    }

    /// Persist and authorize the exact local nonce reveal derived from a complete round.
    pub fn export_reveal(
        &mut self,
        mut state: CommitmentExportedV1<Vault::ReservationHandle>,
        authority: ValidatedCommitmentRoundV1,
    ) -> SignerResult<Vault, Custody, (RevealExportedV1<Vault::ReservationHandle>, NonceRevealV1)>
    {
        let request =
            authority.into_request(state.context_binding_digest, state.context.retry_counter())?;
        let stage_context = request.validated_view().context().clone();
        let operation_evidence = request.evidence();
        let attempt = self
            .vault
            .begin_stage_computation(&mut state.handle, request)
            .map_err(VaultBackedSignerError::Vault)?;
        let (transfer, persistence_permit) = self
            .vault
            .open_secret_for_stage(
                &mut state.handle,
                attempt,
                VaultSecretImportCapabilityV1::new(),
            )
            .map_err(VaultBackedSignerError::Vault)?;
        let pair = transfer.into_validated_pair(
            state.reservation_nonce_id.as_bytes(),
            &state.participant_id,
            &stage_context,
            &self.trusted_chain_id,
            &self.signing_share,
        )?;
        let (first, second) = pair.public_keys()?;
        let reveal = NonceRevealV1::new(
            stage_context.purpose(),
            stage_context.participant_index(),
            first,
            second,
        );
        let prior_snapshot = self
            .vault
            .snapshot_reservation(&state.handle)
            .map_err(VaultBackedSignerError::Vault)?;
        validate_live_snapshot(
            &prior_snapshot,
            &state.request_lookup,
            &state.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
            Some(stage_context.retry_counter()),
        )?;
        let prior = prior_snapshot
            .spent_commitment()
            .ok_or(NonceVaultError::CorruptState)?;
        let commitment =
            nonce_commitment_from_reveal(&stage_context, &state.participant_id, &reveal)?;
        let nonce_identity = persistence_permit.nonce_identity().clone();
        let prepared = PreparedExposureV1::reveal(
            &persistence_permit,
            &operation_evidence.validated_view(),
            reveal.clone(),
            prior,
            commitment,
        )?;
        let persisted = self
            .vault
            .persist_computed_artifact(&mut state.handle, persistence_permit, prepared)
            .map_err(VaultBackedSignerError::Vault)?;
        let permit = self
            .vault
            .authorize_persisted_exposure(&mut state.handle, persisted)
            .map_err(VaultBackedSignerError::Vault)?;
        let exported = self
            .vault
            .export(permit)
            .map_err(VaultBackedSignerError::Vault)?;
        let authorized = validate_exported_artifact(&exported, ExposureKindV1::NonceReveal)?;
        let parsed = NonceRevealV1::from_bytes(authorized.as_bytes())?;
        if parsed != reveal {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        let permit_id = authorized.permit_id().clone();
        let snapshot = self
            .vault
            .snapshot_reservation(&state.handle)
            .map_err(VaultBackedSignerError::Vault)?;
        validate_live_snapshot(
            &snapshot,
            &state.request_lookup,
            &state.context_binding_digest,
            ReservationLiveStageV1::AfterReveal,
            Some(stage_context.retry_counter()),
        )?;
        validate_spent_projection(
            &snapshot,
            ExposureKindV1::NonceReveal,
            &permit_id,
            crate::exposure_outbound_digest_v1(ExposureKindV1::NonceReveal, authorized.as_bytes())?
                .as_bytes(),
        )?;
        Ok((
            RevealExportedV1 {
                handle: state.handle,
                request_lookup: state.request_lookup,
                reservation_nonce_id: state.reservation_nonce_id,
                context: stage_context,
                participant_id: state.participant_id,
                context_binding_digest: state.context_binding_digest,
                nonce_identity,
                permit_id,
            },
            parsed,
        ))
    }

    /// Sign exactly once and persist/authorize/export the local participant partial.
    pub fn sign_and_export_partial(
        &mut self,
        mut state: RevealExportedV1<Vault::ReservationHandle>,
        authority: ValidatedRevealRoundV1,
    ) -> SignerResult<Vault, Custody, (PartialExportedTerminalV1, PartialSignatureV1)> {
        let (request, signing_inputs) = authority
            .into_operation(state.context_binding_digest, state.context.retry_counter())?;
        let operation_evidence = request.evidence();
        let attempt = self
            .vault
            .begin_stage_computation(&mut state.handle, request)
            .map_err(VaultBackedSignerError::Vault)?;
        let (transfer, persistence_permit) = self
            .vault
            .open_secret_for_stage(
                &mut state.handle,
                attempt,
                VaultSecretImportCapabilityV1::new(),
            )
            .map_err(VaultBackedSignerError::Vault)?;
        let pair = transfer.into_validated_pair(
            state.reservation_nonce_id.as_bytes(),
            &state.participant_id,
            signing_inputs.context(),
            &self.trusted_chain_id,
            &self.signing_share,
        )?;
        let challenge = schnorr_challenge(
            &signing_inputs.aggregate_nonce_hat().to_compressed_bytes(),
            signing_inputs.aggregate_signing_key(),
            self.trusted_chain_id.as_bytes(),
            signing_inputs.context().message_digest(),
        );
        let binding = PartialSig::from_bytes(&signing_inputs.binding_factor().to_be_bytes())?;
        let scalar =
            pair.sign_bound_partial(&binding, challenge.as_bytes(), &self.signing_share)?;
        let partial = PartialSignatureV1::new(
            signing_inputs.context().purpose(),
            signing_inputs.context().participant_index(),
            *signing_inputs.context().template_hash(),
            scalar,
        );
        let expected_partial_bytes = partial.to_bytes();
        let nonce_identity = persistence_permit.nonce_identity().clone();
        let request_lookup = state.request_lookup;
        let reservation_nonce_id = state.reservation_nonce_id;
        let prepared = PreparedExposureV1::partial_signature(
            &persistence_permit,
            &operation_evidence.validated_view(),
            partial,
            self.signing_share.public_key().clone(),
            signing_inputs.local_effective_nonce().clone(),
            signing_inputs.binding_factor().clone(),
            signing_inputs.aggregate_nonce_hat().clone(),
            signing_inputs.aggregate_signing_key().clone(),
        )?;
        let persisted = self
            .vault
            .persist_computed_artifact(&mut state.handle, persistence_permit, prepared)
            .map_err(VaultBackedSignerError::Vault)?;
        let permit = self
            .vault
            .authorize_persisted_exposure(&mut state.handle, persisted)
            .map_err(VaultBackedSignerError::Vault)?;
        let exported = self
            .vault
            .export(permit)
            .map_err(VaultBackedSignerError::Vault)?;
        let authorized = validate_exported_artifact(&exported, ExposureKindV1::PartialSignature)?;
        if authorized.as_bytes() != expected_partial_bytes {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        let permit_id = authorized.permit_id().clone();
        let partial = PartialSignatureV1::from_bytes(authorized.as_bytes())?;
        Ok((
            PartialExportedTerminalV1 {
                permit_id,
                request_lookup,
                reservation_nonce_id,
                nonce_identity,
                context_binding_digest: state.context_binding_digest,
            },
            partial,
        ))
    }

    /// Resend an exact commitment without accepting caller-provided binding fields.
    pub fn resend_commitment(
        &mut self,
        state: &CommitmentExportedV1<Vault::ReservationHandle>,
        authority: ValidatedResendAuthorizationV1,
    ) -> SignerResult<Vault, Custody, ResentArtifactV1> {
        self.resend_bound(
            state.request_lookup.clone(),
            state.reservation_nonce_id.clone(),
            state.nonce_identity.clone(),
            state.context_binding_digest,
            state.permit_id.clone(),
            authority,
            ResendProtocolStageV1::Commitment,
        )
    }

    /// Resend an exact reveal without accepting caller-provided binding fields.
    pub fn resend_reveal(
        &mut self,
        state: &RevealExportedV1<Vault::ReservationHandle>,
        authority: ValidatedResendAuthorizationV1,
    ) -> SignerResult<Vault, Custody, ResentArtifactV1> {
        self.resend_bound(
            state.request_lookup.clone(),
            state.reservation_nonce_id.clone(),
            state.nonce_identity.clone(),
            state.context_binding_digest,
            state.permit_id.clone(),
            authority,
            ResendProtocolStageV1::Reveal,
        )
    }

    /// Resend an exact terminal partial without caller-provided binding fields.
    pub fn resend_partial(
        &mut self,
        state: &PartialExportedTerminalV1,
        authority: ValidatedResendAuthorizationV1,
    ) -> SignerResult<Vault, Custody, ResentArtifactV1> {
        self.resend_bound(
            state.request_lookup.clone(),
            state.reservation_nonce_id.clone(),
            state.nonce_identity.clone(),
            state.context_binding_digest,
            state.permit_id.clone(),
            authority,
            ResendProtocolStageV1::PartialSignature,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resend_bound(
        &mut self,
        request_lookup: ReservationRequestLookupV1,
        reservation_nonce_id: crate::ReservationNonceId,
        nonce_identity: crate::NonceIdentityV1,
        context_binding_digest: [u8; 32],
        permit_id: crate::PermitIdV1,
        authority: ValidatedResendAuthorizationV1,
        required_stage: ResendProtocolStageV1,
    ) -> SignerResult<Vault, Custody, ResentArtifactV1> {
        if authority.protocol_stage() != required_stage {
            return Err(AdaptorError::AuthorizationMismatch.into());
        }
        let request = ResendRequestV1::new(
            request_lookup,
            reservation_nonce_id,
            nonce_identity,
            context_binding_digest,
            permit_id,
            authority.protocol_stage(),
            *authority.adaptor_outbound_digest(),
        )?;
        let expected_kind = request.protocol_stage().exposure_kind();
        let expected_digest = *request.adaptor_outbound_digest();
        let exported = self
            .vault
            .resend_exported(request)
            .map_err(VaultBackedSignerError::Vault)?;
        let authorized = validate_exported_artifact(&exported, expected_kind)?;
        if crate::exposure_outbound_digest_v1(expected_kind, authorized.as_bytes())?.as_bytes()
            != &expected_digest
        {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        match expected_kind {
            ExposureKindV1::NonceCommitment => Ok(ResentArtifactV1::NonceCommitment(
                NonceCommitmentV1::from_bytes(authorized.as_bytes())?,
            )),
            ExposureKindV1::NonceReveal => Ok(ResentArtifactV1::NonceReveal(
                NonceRevealV1::from_bytes(authorized.as_bytes())?,
            )),
            ExposureKindV1::PartialSignature => Ok(ResentArtifactV1::PartialSignature(
                PartialSignatureV1::from_bytes(authorized.as_bytes())?,
            )),
        }
    }

    /// Cancel a fresh reservation using only authenticated Store-owned state.
    pub fn cancel_reserved(
        &mut self,
        state: ReservedNonceV1<Vault::ReservationHandle>,
    ) -> SignerResult<Vault, Custody, TerminalReservationV1> {
        self.vault
            .cancel_reservation(state.handle)
            .map_err(VaultBackedSignerError::Vault)
    }

    /// Cancel after commitment without accepting a caller-selected reason.
    pub fn cancel_after_commitment(
        &mut self,
        state: CommitmentExportedV1<Vault::ReservationHandle>,
    ) -> SignerResult<Vault, Custody, TerminalReservationV1> {
        self.vault
            .cancel_reservation(state.handle)
            .map_err(VaultBackedSignerError::Vault)
    }

    /// Cancel after reveal without accepting a caller-selected reason.
    pub fn cancel_after_reveal(
        &mut self,
        state: RevealExportedV1<Vault::ReservationHandle>,
    ) -> SignerResult<Vault, Custody, TerminalReservationV1> {
        self.vault
            .cancel_reservation(state.handle)
            .map_err(VaultBackedSignerError::Vault)
    }
}

fn prepare_private_nonce_derivation_attempt(
    derivation: SecretNonceDerivationV1,
    signing_share: &SigningShareV1,
    base_context: &SessionContextV1,
    context_binding_digest: [u8; 32],
) -> crate::Result<(
    SessionContextV1,
    crate::secret_nonce::SecretNoncePairV1,
    NonceDerivationRequestV1,
)> {
    let mut retry = base_context.retry_counter();
    let (effective_context, pair) = loop {
        let candidate = base_context.with_retry_counter(retry);
        if let Some(pair) = derivation.derive_pair(signing_share, &candidate.to_bytes()) {
            break (candidate, pair);
        }
        retry = retry
            .checked_add(1)
            .ok_or(AdaptorError::RetryCounterOverflow)?;
    };
    drop(derivation);
    let request = NonceDerivationRequestV1::new(context_binding_digest, effective_context.clone())?;
    Ok((effective_context, pair, request))
}

fn validate_live_snapshot<Snapshot>(
    snapshot: &Snapshot,
    request_lookup: &ReservationRequestLookupV1,
    context_binding_digest: &[u8; 32],
    expected_stage: ReservationLiveStageV1,
    expected_retry_counter: Option<u64>,
) -> core::result::Result<(), NonceVaultError>
where
    Snapshot: VaultReservationSnapshotV1,
{
    if snapshot.request_lookup() != request_lookup
        || snapshot.reservation_context_binding_digest() != context_binding_digest
        || snapshot.live_stage() != expected_stage
        || snapshot.final_retry_counter() != expected_retry_counter
    {
        return Err(NonceVaultError::CorruptState);
    }
    match expected_stage {
        ReservationLiveStageV1::PreDerivation
            if snapshot.final_retry_counter().is_none()
                && snapshot.spent_commitment().is_none()
                && snapshot.spent_reveal().is_none() => {}
        ReservationLiveStageV1::AfterCommitment
            if snapshot.final_retry_counter().is_some()
                && snapshot.spent_commitment().is_some_and(|spent| {
                    spent.kind() == ExposureKindV1::NonceCommitment
                        && spent.adaptor_outbound_digest() != &[0; 32]
                        && spent.nonce_identity().bound_digest() == context_binding_digest
                })
                && snapshot.spent_reveal().is_none() => {}
        ReservationLiveStageV1::AfterReveal
            if snapshot.final_retry_counter().is_some()
                && snapshot.spent_commitment().is_some_and(|spent| {
                    spent.kind() == ExposureKindV1::NonceCommitment
                        && spent.adaptor_outbound_digest() != &[0; 32]
                        && spent.nonce_identity().bound_digest() == context_binding_digest
                })
                && snapshot.spent_reveal().is_some_and(|spent| {
                    spent.kind() == ExposureKindV1::NonceReveal
                        && spent.adaptor_outbound_digest() != &[0; 32]
                        && spent.nonce_identity().bound_digest() == context_binding_digest
                        && snapshot.spent_commitment().is_some_and(|commitment| {
                            commitment.nonce_identity() == spent.nonce_identity()
                        })
                }) => {}
        _ => return Err(NonceVaultError::CorruptState),
    }
    Ok(())
}

fn validate_exported_artifact(
    exported: &impl VaultExportedArtifactV1,
    expected_kind: ExposureKindV1,
) -> core::result::Result<AuthorizedExposureV1, NonceVaultError> {
    let authorized = AuthorizedExposureV1::from_vault_export(exported)?;
    if authorized.kind() != expected_kind {
        return Err(NonceVaultError::InvalidPublicMaterial);
    }
    Ok(authorized)
}

fn validate_spent_projection<Snapshot>(
    snapshot: &Snapshot,
    kind: ExposureKindV1,
    permit_id: &crate::PermitIdV1,
    outbound_digest: &[u8; 32],
) -> core::result::Result<(), NonceVaultError>
where
    Snapshot: VaultReservationSnapshotV1,
{
    let spent = match kind {
        ExposureKindV1::NonceCommitment => snapshot.spent_commitment(),
        ExposureKindV1::NonceReveal => snapshot.spent_reveal(),
        ExposureKindV1::PartialSignature => return Err(NonceVaultError::InvalidTransition),
    }
    .ok_or(NonceVaultError::CorruptState)?;
    if spent.kind() != kind
        || spent.permit_id() != permit_id
        || spent.adaptor_outbound_digest() != outbound_digest
    {
        return Err(NonceVaultError::CorruptState);
    }
    Ok(())
}

fn nonce_commitment_from_reveal(
    context: &SessionContextV1,
    participant_id: &[u8; 32],
    reveal: &NonceRevealV1,
) -> core::result::Result<NonceCommitmentV1, AdaptorError> {
    let digest = nonce_commitment_hash_v1(
        context.chain_id(),
        context.session_id(),
        participant_id,
        context.purpose(),
        context.template_hash(),
        reveal.first(),
        reveal.second(),
        context.adaptor_point(),
    )?;
    Ok(NonceCommitmentV1::new(
        context.purpose(),
        context.participant_index(),
        *digest.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn nonce_derivation_context() -> (SigningShareV1, SessionContextV1) {
        let signing_share = SigningShareV1::from_be_bytes([0x41; 32]).expect("signing share");
        let remote_share = SigningShareV1::from_be_bytes([0x42; 32]).expect("remote share");
        let mut participant_public_keys = vec![
            signing_share.public_key().clone(),
            remote_share.public_key().clone(),
        ];
        participant_public_keys.sort_by_key(dom_crypto::PublicKey::to_compressed_bytes);
        let participant_index = participant_public_keys
            .iter()
            .position(|key| key == signing_share.public_key())
            .and_then(|index| u16::try_from(index).ok())
            .expect("participant index");
        let context = SessionContextV1::new(
            crate::SessionContextInputsV1 {
                chain_id: [0x43; 32],
                session_id: [0x44; 32],
                purpose: crate::PurposeV1::Refund,
                direction: crate::DirectionV1::Initiator,
                signing_phase: crate::SigningPhaseV1::SigNonceCommit,
                template_hash: [0x45; 32],
                message_digest: [0x46; 32],
                transcript_hash: [0x47; 32],
                retry_counter: 9,
                participant_public_keys,
                participant_index,
                adaptor_point: None,
            },
            &signing_share,
        )
        .expect("nonce derivation context");
        (signing_share, context)
    }

    struct TestSpentArtifact {
        nonce_identity: crate::NonceIdentityV1,
        permit_id: crate::PermitIdV1,
        kind: ExposureKindV1,
        digest: [u8; 32],
    }

    impl crate::VaultSpentArtifactSnapshotV1 for TestSpentArtifact {
        fn nonce_identity(&self) -> &crate::NonceIdentityV1 {
            &self.nonce_identity
        }

        fn permit_id(&self) -> &crate::PermitIdV1 {
            &self.permit_id
        }

        fn kind(&self) -> ExposureKindV1 {
            self.kind
        }

        fn adaptor_outbound_digest(&self) -> &[u8; 32] {
            &self.digest
        }
    }

    struct TestReservationSnapshot {
        reservation_nonce_id: crate::ReservationNonceId,
        request_lookup: ReservationRequestLookupV1,
        context_binding_digest: [u8; 32],
        stage: ReservationLiveStageV1,
        final_retry_counter: Option<u64>,
        commitment: Option<TestSpentArtifact>,
        reveal: Option<TestSpentArtifact>,
    }

    impl VaultReservationSnapshotV1 for TestReservationSnapshot {
        type SpentArtifact = TestSpentArtifact;

        fn request_lookup(&self) -> &ReservationRequestLookupV1 {
            &self.request_lookup
        }

        fn reservation_nonce_id(&self) -> &crate::ReservationNonceId {
            &self.reservation_nonce_id
        }

        fn reservation_context_binding_digest(&self) -> &[u8; 32] {
            &self.context_binding_digest
        }

        fn live_stage(&self) -> ReservationLiveStageV1 {
            self.stage
        }

        fn final_retry_counter(&self) -> Option<u64> {
            self.final_retry_counter
        }

        fn spent_commitment(&self) -> Option<&Self::SpentArtifact> {
            self.commitment.as_ref()
        }

        fn spent_reveal(&self) -> Option<&Self::SpentArtifact> {
            self.reveal.as_ref()
        }
    }

    fn test_snapshot(stage: ReservationLiveStageV1, reveal: bool) -> TestReservationSnapshot {
        let nonce_identity = crate::NonceIdentityV1::new(
            crate::SessionId::from_bytes([8; 32]).expect("session ID"),
            crate::ParticipantId::from_bytes([9; 32]).expect("participant ID"),
            crate::PurposeV1::Refund,
            [3; 32],
            1,
        )
        .expect("nonce identity");
        TestReservationSnapshot {
            reservation_nonce_id: crate::ReservationNonceId::from_bytes([1; 32])
                .expect("reservation ID"),
            request_lookup: ReservationRequestLookupV1::from_bytes([2; 32])
                .expect("request lookup"),
            context_binding_digest: [3; 32],
            stage,
            final_retry_counter: Some(7),
            commitment: Some(TestSpentArtifact {
                nonce_identity: nonce_identity.clone(),
                permit_id: crate::PermitIdV1::from_bytes([4; 32]).expect("permit ID"),
                kind: ExposureKindV1::NonceCommitment,
                digest: [5; 32],
            }),
            reveal: reveal.then(|| TestSpentArtifact {
                nonce_identity,
                permit_id: crate::PermitIdV1::from_bytes([6; 32]).expect("permit ID"),
                kind: ExposureKindV1::NonceReveal,
                digest: [7; 32],
            }),
        }
    }

    #[test]
    fn owned_snapshot_validates_as_one_coherent_dispatch_projection() {
        let snapshot = test_snapshot(ReservationLiveStageV1::AfterCommitment, false);
        assert_eq!(
            snapshot.live_stage(),
            ReservationLiveStageV1::AfterCommitment
        );
        validate_live_snapshot(
            &snapshot,
            &snapshot.request_lookup,
            &snapshot.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
            Some(7),
        )
        .expect("valid snapshot");
    }

    #[test]
    fn live_projection_rejects_presence_table_inconsistency() {
        let snapshot = test_snapshot(ReservationLiveStageV1::AfterCommitment, true);
        assert!(validate_live_snapshot(
            &snapshot,
            &snapshot.request_lookup,
            &snapshot.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
            Some(7),
        )
        .is_err());
    }

    #[test]
    fn live_projection_rejects_wrong_retry_spent_kind_and_identity() {
        let snapshot = test_snapshot(ReservationLiveStageV1::AfterCommitment, false);
        assert!(validate_live_snapshot(
            &snapshot,
            &snapshot.request_lookup,
            &snapshot.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
            Some(8),
        )
        .is_err());

        let mut wrong_kind = test_snapshot(ReservationLiveStageV1::AfterCommitment, false);
        wrong_kind
            .commitment
            .as_mut()
            .expect("commitment descriptor")
            .kind = ExposureKindV1::NonceReveal;
        assert!(validate_live_snapshot(
            &wrong_kind,
            &wrong_kind.request_lookup,
            &wrong_kind.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
            Some(7),
        )
        .is_err());

        let mut wrong_identity = test_snapshot(ReservationLiveStageV1::AfterCommitment, false);
        wrong_identity
            .commitment
            .as_mut()
            .expect("commitment descriptor")
            .nonce_identity = crate::NonceIdentityV1::new(
            crate::SessionId::from_bytes([8; 32]).expect("session ID"),
            crate::ParticipantId::from_bytes([9; 32]).expect("participant ID"),
            crate::PurposeV1::Refund,
            [0x55; 32],
            1,
        )
        .expect("mutated identity");
        assert!(validate_live_snapshot(
            &wrong_identity,
            &wrong_identity.request_lookup,
            &wrong_identity.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
            Some(7),
        )
        .is_err());
    }

    #[test]
    fn private_kdf_finishes_before_the_final_retry_request_is_constructed() {
        let (signing_share, context) = nonce_derivation_context();
        let context_binding_digest = [0x48; 32];
        let (effective_context, pair, request) = prepare_private_nonce_derivation_attempt(
            SecretNonceDerivationV1::from_aux_for_test([0x49; 32]),
            &signing_share,
            &context,
            context_binding_digest,
        )
        .expect("private derivation and request");
        assert_eq!(effective_context.retry_counter(), 9);
        assert_eq!(
            request.validated_view().effective_retry_counter(),
            effective_context.retry_counter()
        );
        assert_eq!(
            request
                .validated_view()
                .reservation_context_binding_digest(),
            &context_binding_digest
        );
        let scalars = pair.into_record_scalars();
        assert_ne!(&scalars[..32], &[0; 32]);
        assert_ne!(&scalars[32..], &[0; 32]);
    }
}

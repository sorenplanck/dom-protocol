//! Non-bypassable high-level G1a/G1b signer composition.

use crate::secret_nonce::SecretNonceDerivationV1;
use crate::{
    nonce_commitment_hash_v1, AdaptorError, AuthorizedExposureV1, ExposureKindV1,
    NonceCommitmentV1, NonceDerivationRequestV1, NonceRevealV1, NonceSecretTransferV1,
    NonceVaultError, NonceVaultV1, PartialSignatureV1, PreparedExposureV1, PublicNoncePairV1,
    ResendProtocolStageV1, ResendRequestV1, ReservationContextBindingV1, ReservationLiveStageV1,
    ReservationLookupCustodyV1, ReservationRequestLookupV1, ReservationResumeRequestV1,
    ReservationResumeResultV1, RestoreState, SessionContextV1, SigningRoundSessionRequestV1,
    SigningShareV1, SpentArtifactDescriptorV1, TerminalReservationV1, TrustedChainIdV1,
    ValidatedCommitmentRoundV1, ValidatedDerivationBaseV1, ValidatedResendAuthorizationV1,
    ValidatedRevealRoundV1, ValidatedSigningRoundStateV1, VaultArtifactPersistencePermitV1,
    VaultExportedArtifactV1, VaultReservationHandleV1, VaultSecretImportCapabilityV1,
    VaultSecretSealCapabilityV1,
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
    context: SessionContextV1,
    participant_id: [u8; 32],
    context_binding_digest: [u8; 32],
}

/// State after durable authorization and exact commitment export.
pub struct CommitmentExportedV1<Handle> {
    handle: Handle,
    request_lookup: ReservationRequestLookupV1,
    context: SessionContextV1,
    participant_id: [u8; 32],
    context_binding_digest: [u8; 32],
    nonce_identity: Option<crate::NonceIdentityV1>,
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
    context: SessionContextV1,
    participant_id: [u8; 32],
    context_binding_digest: [u8; 32],
    nonce_identity: Option<crate::NonceIdentityV1>,
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
pub struct VaultBackedSignerV1<Vault, Custody>
where
    Vault: NonceVaultV1,
    Custody: ReservationLookupCustodyV1,
{
    vault: Vault,
    custody: Custody,
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

impl<Vault, Custody> VaultBackedSignerV1<Vault, Custody>
where
    Vault: NonceVaultV1,
    Custody: ReservationLookupCustodyV1,
{
    /// Bind all security-critical dependencies statically at the composition root.
    pub fn new(
        vault: Vault,
        custody: Custody,
        trusted_chain_id: TrustedChainIdV1,
        signing_share: SigningShareV1,
    ) -> Self {
        Self {
            vault,
            custody,
            trusted_chain_id,
            signing_share,
        }
    }

    /// Construct the opaque signing-round owner from validated canonical inputs.
    pub fn begin_signing_round(
        &self,
        request: SigningRoundSessionRequestV1,
    ) -> SignerResult<Vault, Custody, ValidatedSigningRoundStateV1> {
        let bootstrap =
            crate::signing_round::ValidatedSigningRoundBootstrapV1::from_session_request(
                self.trusted_chain_id,
                request,
                &self.signing_share,
            )?;
        ValidatedSigningRoundStateV1::from_bootstrap(bootstrap, &self.signing_share)
            .map_err(Into::into)
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
        validate_live_handle(
            &handle,
            &expected_lookup,
            &expected_binding,
            ReservationLiveStageV1::PreDerivation,
        )?;
        Ok(ReservedNonceV1 {
            handle,
            request_lookup: expected_lookup,
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
                let snapshot = snapshot_live_handle(&handle)?;
                validate_live_snapshot(
                    &snapshot,
                    &request_lookup,
                    &binding_digest,
                    snapshot.stage,
                )?;
                let state = match snapshot.stage {
                    ReservationLiveStageV1::PreDerivation => {
                        ResumedReservationV1::PreDerivation(ReservedNonceV1 {
                            handle,
                            request_lookup,
                            context,
                            participant_id,
                            context_binding_digest: binding_digest,
                        })
                    }
                    ReservationLiveStageV1::AfterCommitment => {
                        let permit_id = snapshot
                            .spent_commitment
                            .as_ref()
                            .ok_or(NonceVaultError::CorruptState)?
                            .permit_id()
                            .clone();
                        ResumedReservationV1::AfterCommitment(CommitmentExportedV1 {
                            handle,
                            request_lookup,
                            context,
                            participant_id,
                            context_binding_digest: binding_digest,
                            nonce_identity: None,
                            permit_id,
                        })
                    }
                    ReservationLiveStageV1::AfterReveal => {
                        let permit_id = snapshot
                            .spent_reveal
                            .as_ref()
                            .ok_or(NonceVaultError::CorruptState)?
                            .permit_id()
                            .clone();
                        ResumedReservationV1::AfterReveal(RevealExportedV1 {
                            handle,
                            request_lookup,
                            context,
                            participant_id,
                            context_binding_digest: binding_digest,
                            nonce_identity: None,
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
        let derivation = SecretNonceDerivationV1::from_os_rng()?;
        let mut retry = state.context.retry_counter();
        let (effective_context, pair) = loop {
            let candidate = state.context.with_retry_counter(retry);
            if let Some(pair) = derivation.derive_pair(&self.signing_share, &candidate.to_bytes()) {
                break (candidate, pair);
            }
            retry = retry
                .checked_add(1)
                .ok_or(AdaptorError::RetryCounterOverflow)?;
        };
        let request =
            NonceDerivationRequestV1::new(state.context_binding_digest, effective_context.clone())?;
        let operation_evidence = request.evidence();
        let attempt = self
            .vault
            .begin_nonce_derivation(&mut state.handle, request)
            .map_err(VaultBackedSignerError::Vault)?;
        let transfer = NonceSecretTransferV1::from_nonce_pair(
            *state.handle.reservation_nonce_id().as_bytes(),
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
            state.handle.reservation_nonce_id().as_bytes(),
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
        let snapshot = snapshot_live_handle(&state.handle)?;
        validate_live_snapshot(
            &snapshot,
            &state.request_lookup,
            &state.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
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
                context: effective_context,
                participant_id: state.participant_id,
                context_binding_digest: state.context_binding_digest,
                nonce_identity: Some(nonce_identity),
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
            state.handle.reservation_nonce_id().as_bytes(),
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
        let prior = state
            .handle
            .spent_commitment()
            .ok_or(NonceVaultError::CorruptState)?;
        let commitment =
            nonce_commitment_from_reveal(&stage_context, &state.participant_id, &reveal)?;
        let nonce_identity = persistence_permit.nonce_identity().clone();
        let prepared = PreparedExposureV1::reveal(
            &persistence_permit,
            &operation_evidence.validated_view(),
            reveal.clone(),
            &prior,
            commitment,
        )?;
        drop(prior);
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
        let snapshot = snapshot_live_handle(&state.handle)?;
        validate_live_snapshot(
            &snapshot,
            &state.request_lookup,
            &state.context_binding_digest,
            ReservationLiveStageV1::AfterReveal,
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
                context: stage_context,
                participant_id: state.participant_id,
                context_binding_digest: state.context_binding_digest,
                nonce_identity: Some(nonce_identity),
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
            state.handle.reservation_nonce_id().as_bytes(),
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
        let reservation_nonce_id = state.handle.reservation_nonce_id().clone();
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
            state.handle.reservation_nonce_id().clone(),
            state
                .nonce_identity
                .clone()
                .ok_or(NonceVaultError::CorruptState)?,
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
            state.handle.reservation_nonce_id().clone(),
            state
                .nonce_identity
                .clone()
                .ok_or(NonceVaultError::CorruptState)?,
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

struct LiveHandleSnapshotV1 {
    request_lookup: ReservationRequestLookupV1,
    context_binding_digest: [u8; 32],
    stage: ReservationLiveStageV1,
    final_retry_counter: Option<u64>,
    spent_commitment: Option<SpentArtifactDescriptorV1>,
    spent_reveal: Option<SpentArtifactDescriptorV1>,
}

fn snapshot_live_handle<Handle: VaultReservationHandleV1>(
    handle: &Handle,
) -> core::result::Result<LiveHandleSnapshotV1, NonceVaultError> {
    let request_lookup = handle.request_lookup().clone();
    let context_binding_digest = *handle.reservation_context_binding_digest();
    let stage = handle.live_stage();
    let final_retry_counter = handle.final_retry_counter();
    let spent_commitment = handle
        .spent_commitment()
        .map(|view| SpentArtifactDescriptorV1::from_view(&view))
        .transpose()?;
    let spent_reveal = handle
        .spent_reveal()
        .map(|view| SpentArtifactDescriptorV1::from_view(&view))
        .transpose()?;
    Ok(LiveHandleSnapshotV1 {
        request_lookup,
        context_binding_digest,
        stage,
        final_retry_counter,
        spent_commitment,
        spent_reveal,
    })
}

fn validate_live_handle<Handle: VaultReservationHandleV1>(
    handle: &Handle,
    request_lookup: &ReservationRequestLookupV1,
    context_binding_digest: &[u8; 32],
    expected_stage: ReservationLiveStageV1,
) -> core::result::Result<(), NonceVaultError> {
    let snapshot = snapshot_live_handle(handle)?;
    validate_live_snapshot(
        &snapshot,
        request_lookup,
        context_binding_digest,
        expected_stage,
    )
}

fn validate_live_snapshot(
    snapshot: &LiveHandleSnapshotV1,
    request_lookup: &ReservationRequestLookupV1,
    context_binding_digest: &[u8; 32],
    expected_stage: ReservationLiveStageV1,
) -> core::result::Result<(), NonceVaultError> {
    if &snapshot.request_lookup != request_lookup
        || &snapshot.context_binding_digest != context_binding_digest
        || snapshot.stage != expected_stage
    {
        return Err(NonceVaultError::CorruptState);
    }
    match expected_stage {
        ReservationLiveStageV1::PreDerivation
            if snapshot.final_retry_counter.is_none()
                && snapshot.spent_commitment.is_none()
                && snapshot.spent_reveal.is_none() => {}
        ReservationLiveStageV1::AfterCommitment
            if snapshot.final_retry_counter.is_some()
                && snapshot.spent_commitment.is_some()
                && snapshot.spent_reveal.is_none() => {}
        ReservationLiveStageV1::AfterReveal
            if snapshot.final_retry_counter.is_some()
                && snapshot.spent_commitment.is_some()
                && snapshot.spent_reveal.is_some() => {}
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

fn validate_spent_projection(
    snapshot: &LiveHandleSnapshotV1,
    kind: ExposureKindV1,
    permit_id: &crate::PermitIdV1,
    outbound_digest: &[u8; 32],
) -> core::result::Result<(), NonceVaultError> {
    let spent = match kind {
        ExposureKindV1::NonceCommitment => snapshot.spent_commitment.as_ref(),
        ExposureKindV1::NonceReveal => snapshot.spent_reveal.as_ref(),
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
    use core::cell::Cell;

    struct TestSpentArtifact {
        permit_id: crate::PermitIdV1,
        kind: ExposureKindV1,
        digest: [u8; 32],
    }

    struct TestSpentView<'a>(&'a TestSpentArtifact);

    impl crate::VaultSpentArtifactViewV1 for TestSpentView<'_> {
        fn permit_id(&self) -> &crate::PermitIdV1 {
            &self.0.permit_id
        }

        fn kind(&self) -> ExposureKindV1 {
            self.0.kind
        }

        fn adaptor_outbound_digest(&self) -> &[u8; 32] {
            &self.0.digest
        }
    }

    struct ChangingStageHandle {
        reservation_nonce_id: crate::ReservationNonceId,
        request_lookup: ReservationRequestLookupV1,
        context_binding_digest: [u8; 32],
        stage_reads: Cell<usize>,
        first_stage: ReservationLiveStageV1,
        later_stage: ReservationLiveStageV1,
        final_retry_counter: Option<u64>,
        commitment: Option<TestSpentArtifact>,
        reveal: Option<TestSpentArtifact>,
    }

    impl VaultReservationHandleV1 for ChangingStageHandle {
        type SpentArtifactView<'a> = TestSpentView<'a>;

        fn reservation_nonce_id(&self) -> &crate::ReservationNonceId {
            &self.reservation_nonce_id
        }

        fn request_lookup(&self) -> &ReservationRequestLookupV1 {
            &self.request_lookup
        }

        fn reservation_context_binding_digest(&self) -> &[u8; 32] {
            &self.context_binding_digest
        }

        fn live_stage(&self) -> ReservationLiveStageV1 {
            let reads = self.stage_reads.get();
            self.stage_reads.set(reads + 1);
            if reads == 0 {
                self.first_stage
            } else {
                self.later_stage
            }
        }

        fn final_retry_counter(&self) -> Option<u64> {
            self.final_retry_counter
        }

        fn spent_commitment(&self) -> Option<Self::SpentArtifactView<'_>> {
            self.commitment.as_ref().map(TestSpentView)
        }

        fn spent_reveal(&self) -> Option<Self::SpentArtifactView<'_>> {
            self.reveal.as_ref().map(TestSpentView)
        }
    }

    fn changing_handle(
        first_stage: ReservationLiveStageV1,
        later_stage: ReservationLiveStageV1,
        reveal: bool,
    ) -> ChangingStageHandle {
        ChangingStageHandle {
            reservation_nonce_id: crate::ReservationNonceId::from_bytes([1; 32])
                .expect("reservation ID"),
            request_lookup: ReservationRequestLookupV1::from_bytes([2; 32])
                .expect("request lookup"),
            context_binding_digest: [3; 32],
            stage_reads: Cell::new(0),
            first_stage,
            later_stage,
            final_retry_counter: Some(7),
            commitment: Some(TestSpentArtifact {
                permit_id: crate::PermitIdV1::from_bytes([4; 32]).expect("permit ID"),
                kind: ExposureKindV1::NonceCommitment,
                digest: [5; 32],
            }),
            reveal: reveal.then(|| TestSpentArtifact {
                permit_id: crate::PermitIdV1::from_bytes([6; 32]).expect("permit ID"),
                kind: ExposureKindV1::NonceReveal,
                digest: [7; 32],
            }),
        }
    }

    #[test]
    fn live_projection_snapshots_stage_once_before_validation_and_dispatch() {
        let handle = changing_handle(
            ReservationLiveStageV1::AfterCommitment,
            ReservationLiveStageV1::AfterReveal,
            false,
        );
        let snapshot = snapshot_live_handle(&handle).expect("coherent snapshot");
        assert_eq!(handle.stage_reads.get(), 1);
        assert_eq!(snapshot.stage, ReservationLiveStageV1::AfterCommitment);
        validate_live_snapshot(
            &snapshot,
            &handle.request_lookup,
            &handle.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
        )
        .expect("valid snapshot");
        assert_eq!(handle.stage_reads.get(), 1);
    }

    #[test]
    fn live_projection_rejects_presence_table_inconsistency() {
        let handle = changing_handle(
            ReservationLiveStageV1::AfterCommitment,
            ReservationLiveStageV1::AfterCommitment,
            true,
        );
        let snapshot = snapshot_live_handle(&handle).expect("snapshot");
        assert!(validate_live_snapshot(
            &snapshot,
            &handle.request_lookup,
            &handle.context_binding_digest,
            ReservationLiveStageV1::AfterCommitment,
        )
        .is_err());
    }
}

//! Non-bypassable high-level G1a/G1b signer composition.

use crate::secret_nonce::SecretNonceDerivationV1;
use crate::{
    exposure_outbound_digest_v1, nonce_commitment_hash_v1, AbortReasonV1, AdaptorError,
    BindingFactorV1, ExposureBytes, ExposureKindV1, IdempotencyKey, NonceCommitmentV1,
    NonceRevealV1, NonceSecretTransferV1, NonceVaultV1, PartialSignatureV1, PermitIdV1,
    PreparedExposureV1, PublicNoncePairV1, ReservationIntentV1, ReservationNonceId,
    ReservationRequestV1, RestoreState, SessionContextV1, SessionId, SigningShareV1,
    TerminalReservationV1, TrustedChainIdV1, VaultComputationStageV1,
    VaultSecretImportCapabilityV1, VaultSecretSealCapabilityV1,
};
use core::fmt;
use dom_crypto::{schnorr_challenge, PartialSig, PublicKey};
use rand_core::{OsRng, RngCore};
use std::error::Error;

/// Typed failure from the integrated cryptographic and durable-authority path.
pub enum VaultBackedSignerError<E> {
    /// Canonical parsing, binding, or cryptographic failure.
    Adaptor(AdaptorError),
    /// Storage-independent vault contract validation failure.
    Contract(crate::NonceVaultError),
    /// Failure reported by the statically selected DOM Contracts vault store.
    Vault(E),
    /// The vault returned bytes other than the exact prepared persisted artifact.
    AuthorizedArtifactMismatch,
}

impl<E> fmt::Debug for VaultBackedSignerError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adaptor(error) => formatter.debug_tuple("Adaptor").field(error).finish(),
            Self::Contract(error) => formatter.debug_tuple("Contract").field(error).finish(),
            Self::Vault(_) => formatter.write_str("Vault(Redacted)"),
            Self::AuthorizedArtifactMismatch => formatter.write_str("AuthorizedArtifactMismatch"),
        }
    }
}

impl<E> fmt::Display for VaultBackedSignerError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adaptor(error) => error.fmt(formatter),
            Self::Contract(error) => error.fmt(formatter),
            Self::Vault(_) => formatter.write_str("vault operation failed (details redacted)"),
            Self::AuthorizedArtifactMismatch => {
                formatter.write_str("vault returned a different authorized artifact")
            }
        }
    }
}

impl<E: 'static> Error for VaultBackedSignerError<E> {}

impl<E> From<AdaptorError> for VaultBackedSignerError<E> {
    fn from(error: AdaptorError) -> Self {
        Self::Adaptor(error)
    }
}

impl<E> From<crate::NonceVaultError> for VaultBackedSignerError<E> {
    fn from(error: crate::NonceVaultError) -> Self {
        Self::Contract(error)
    }
}

impl<E> From<dom_core::DomError> for VaultBackedSignerError<E> {
    fn from(error: dom_core::DomError) -> Self {
        Self::Adaptor(error.into())
    }
}

/// Opaque reserved state. No commitment bytes have crossed the boundary.
pub struct ReservedNonceV1<H> {
    handle: H,
    context: SessionContextV1,
    reservation_nonce_id: [u8; 32],
    participant_id: [u8; 32],
    commitment: NonceCommitmentV1,
}

/// State after durable authorization and exact commitment export.
pub struct CommitmentExportedV1<H> {
    handle: H,
    context: SessionContextV1,
    reservation_nonce_id: [u8; 32],
    participant_id: [u8; 32],
    permit_id: PermitIdV1,
}

impl<H> CommitmentExportedV1<H> {
    /// Return the public lookup ID for the exported commitment.
    pub const fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }
}

/// State after durable authorization and exact nonce-reveal export.
pub struct RevealExportedV1<H> {
    handle: H,
    context: SessionContextV1,
    reservation_nonce_id: [u8; 32],
    participant_id: [u8; 32],
    public_nonces: PublicNoncePairV1,
    permit_id: PermitIdV1,
}

impl<H> RevealExportedV1<H> {
    /// Return the public lookup ID for the exported nonce reveal.
    pub const fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }
}

/// Terminal marker after exactly one partial-signature export.
pub struct PartialExportedTerminalV1 {
    permit_id: PermitIdV1,
}

impl PartialExportedTerminalV1 {
    /// Return the public lookup ID for the exported partial signature.
    pub const fn permit_id(&self) -> &PermitIdV1 {
        &self.permit_id
    }
}

/// Closed typed result of a validated restart resend lookup.
///
/// No variant contains a live permit, vault handle, or untyped byte buffer.
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

/// High-level signer owning one statically selected concrete vault type.
///
/// Application callers provide session intent and public protocol inputs. They
/// never provide nonce material, permit bytes, receipts, witness acceptance,
/// or persistence-success claims.
pub struct VaultBackedSignerV1<V: NonceVaultV1> {
    vault: V,
}

type SignerResult<V, T> =
    core::result::Result<T, VaultBackedSignerError<<V as NonceVaultV1>::Error>>;
type CommitmentExportResult<H> = (CommitmentExportedV1<H>, NonceCommitmentV1);
type RevealExportResult<H> = (RevealExportedV1<H>, NonceRevealV1);
type PartialExportResult = (PartialExportedTerminalV1, PartialSignatureV1);

impl<V: NonceVaultV1> VaultBackedSignerV1<V> {
    /// Bind the signer to one concrete production vault at the composition root.
    pub fn new(vault: V) -> Self {
        Self { vault }
    }

    /// Delegate the reconciled read-only recovery state of the concrete vault.
    pub fn restore_state(&self) -> RestoreState {
        self.vault.restore_state()
    }

    /// Abort a reservation before any high-level public artifact was exported.
    ///
    /// The state and concrete reservation handle are consumed even if the
    /// durable vault reports an error.
    pub fn abort_reserved(
        &mut self,
        state: ReservedNonceV1<V::ReservationHandle>,
        reason: AbortReasonV1,
    ) -> SignerResult<V, TerminalReservationV1> {
        self.vault
            .abort(state.handle, reason)
            .map_err(VaultBackedSignerError::Vault)
    }

    /// Abort after commitment export, conservatively preserving public exposure.
    pub fn abort_after_commitment(
        &mut self,
        state: CommitmentExportedV1<V::ReservationHandle>,
        reason: AbortReasonV1,
    ) -> SignerResult<V, TerminalReservationV1> {
        self.vault
            .abort(state.handle, public_material_abort_reason(reason))
            .map_err(VaultBackedSignerError::Vault)
    }

    /// Abort after reveal export, conservatively burning the complete nonce pair.
    pub fn abort_after_reveal(
        &mut self,
        state: RevealExportedV1<V::ReservationHandle>,
        reason: AbortReasonV1,
    ) -> SignerResult<V, TerminalReservationV1> {
        self.vault
            .abort(state.handle, public_material_abort_reason(reason))
            .map_err(VaultBackedSignerError::Vault)
    }

    /// Reopen and validate one exact already-spent artifact for restart resend.
    ///
    /// The public lookup ID grants no authority by itself. The concrete vault
    /// must revalidate its retained authority before returning an artifact, and
    /// this boundary then checks the returned ID, closed kind, trusted adaptor
    /// outbound digest, canonical length, strict purpose, and typed codec.
    pub fn resend_exported(
        &self,
        permit_id: PermitIdV1,
        expected_kind: ExposureKindV1,
        expected_outbound_digest: [u8; 32],
    ) -> SignerResult<V, ResentArtifactV1> {
        if expected_outbound_digest == [0; 32] {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        let exported = self
            .vault
            .resend_exported(permit_id.clone())
            .map_err(VaultBackedSignerError::Vault)?;
        let authorized = crate::AuthorizedExposureV1::from_vault_export(&exported)?;
        if authorized.permit_id() != &permit_id || authorized.kind() != expected_kind {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        let actual_digest = exposure_outbound_digest_v1(expected_kind, authorized.as_bytes())?;
        if actual_digest.as_bytes() != &expected_outbound_digest {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        match expected_kind {
            ExposureKindV1::NonceCommitment => {
                let artifact = NonceCommitmentV1::from_bytes(authorized.as_bytes())?;
                artifact.purpose().require_strict_phase1()?;
                Ok(ResentArtifactV1::NonceCommitment(artifact))
            }
            ExposureKindV1::NonceReveal => {
                let artifact = NonceRevealV1::from_bytes(authorized.as_bytes())?;
                artifact.purpose().require_strict_phase1()?;
                Ok(ResentArtifactV1::NonceReveal(artifact))
            }
            ExposureKindV1::PartialSignature => {
                let artifact = PartialSignatureV1::from_bytes(authorized.as_bytes())?;
                artifact.purpose().require_strict_phase1()?;
                Ok(ResentArtifactV1::PartialSignature(artifact))
            }
        }
    }

    /// Derive, seal, charge, witness, and durably reserve one nonce pair.
    pub fn reserve(
        &mut self,
        intent: ReservationIntentV1,
        context: SessionContextV1,
        signing_share: &SigningShareV1,
    ) -> SignerResult<V, ReservedNonceV1<V::ReservationHandle>> {
        context.purpose().require_strict_phase1()?;
        if intent.purpose != context.purpose()
            || intent.template_hash.as_bytes() != context.template_hash()
        {
            return Err(AdaptorError::AuthorizationMismatch.into());
        }

        let reservation_id = ReservationNonceId::from_bytes(random_nonzero_id::<V::Error>()?)?;
        let reservation_nonce_id = *reservation_id.as_bytes();
        let participant_id = *intent.participant_id.as_bytes();
        let request_id = IdempotencyKey::from_bytes(random_nonzero_id::<V::Error>()?)?;
        let request = ReservationRequestV1::new(
            reservation_id,
            intent.key_id,
            SessionId::from_bytes(*context.session_id())?,
            intent.counterparty,
            intent.purpose,
            intent.participant_id,
            intent.template_hash,
            request_id,
        );

        let mut handle = self
            .vault
            .claim_reservation(request)
            .map_err(VaultBackedSignerError::Vault)?;
        let derivation_attempt = self
            .vault
            .begin_computation(&mut handle, VaultComputationStageV1::NonceDerivation)
            .map_err(VaultBackedSignerError::Vault)?;

        let derivation = SecretNonceDerivationV1::from_os_rng()?;
        let mut retry_counter = context.retry_counter();
        let (effective_context, pair) = loop {
            let candidate = context.with_retry_counter(retry_counter);
            if let Some(pair) = derivation.derive_pair(signing_share, &candidate.to_bytes()) {
                break (candidate, pair);
            }
            retry_counter = retry_counter
                .checked_add(1)
                .ok_or(AdaptorError::RetryCounterOverflow)?;
        };
        let (first, second) = pair.public_keys()?;
        let commitment_hash = nonce_commitment_hash_v1(
            effective_context.chain_id(),
            effective_context.session_id(),
            &participant_id,
            effective_context.purpose(),
            effective_context.template_hash(),
            &first,
            &second,
            effective_context.adaptor_point(),
        )?;
        let commitment = NonceCommitmentV1::new(
            effective_context.purpose(),
            effective_context.participant_index(),
            *commitment_hash.as_bytes(),
        );
        let secret = NonceSecretTransferV1::from_nonce_pair(
            reservation_nonce_id,
            participant_id,
            &effective_context,
            pair,
        )?;
        self.vault
            .store_reserved_secret(
                &mut handle,
                derivation_attempt,
                secret,
                VaultSecretSealCapabilityV1::new(),
                commitment,
            )
            .map_err(VaultBackedSignerError::Vault)?;
        Ok(ReservedNonceV1 {
            handle,
            context: effective_context,
            reservation_nonce_id,
            participant_id,
            commitment,
        })
    }

    /// Authorize and export the exact previously persisted commitment.
    pub fn export_commitment(
        &mut self,
        mut state: ReservedNonceV1<V::ReservationHandle>,
    ) -> SignerResult<V, CommitmentExportResult<V::ReservationHandle>> {
        let expected = state.commitment.to_bytes();
        let prepared = PreparedExposureV1::new(ExposureBytes::from_bytes(
            ExposureKindV1::NonceCommitment,
            expected,
        )?);
        let permit = self
            .vault
            .authorize_exposure(&mut state.handle, prepared)
            .map_err(VaultBackedSignerError::Vault)?;
        let exported = self
            .vault
            .export(permit)
            .map_err(VaultBackedSignerError::Vault)?;
        let authorized = crate::AuthorizedExposureV1::from_vault_export(&exported)?;
        if authorized.kind() != ExposureKindV1::NonceCommitment || authorized.as_bytes() != expected
        {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        let permit_id = authorized.permit_id().clone();
        let commitment = NonceCommitmentV1::from_bytes(authorized.as_bytes())?;
        Ok((
            CommitmentExportedV1 {
                handle: state.handle,
                context: state.context,
                reservation_nonce_id: state.reservation_nonce_id,
                participant_id: state.participant_id,
                permit_id,
            },
            commitment,
        ))
    }

    /// Reopen under reveal policy, persist exact bytes, authorize, and export once.
    pub fn export_reveal(
        &mut self,
        mut state: CommitmentExportedV1<V::ReservationHandle>,
        trusted_chain_id: &TrustedChainIdV1,
        signing_share: &SigningShareV1,
    ) -> SignerResult<V, RevealExportResult<V::ReservationHandle>> {
        let attempt = self
            .vault
            .begin_computation(&mut state.handle, VaultComputationStageV1::NonceReveal)
            .map_err(VaultBackedSignerError::Vault)?;
        let transfer = self
            .vault
            .open_secret(
                &mut state.handle,
                attempt,
                VaultSecretImportCapabilityV1::new(),
            )
            .map_err(VaultBackedSignerError::Vault)?;
        let pair = transfer.into_validated_pair(
            &state.reservation_nonce_id,
            &state.participant_id,
            &state.context,
            trusted_chain_id,
            signing_share,
        )?;
        let (first, second) = pair.public_keys()?;
        let public_nonces = PublicNoncePairV1::new(first.clone(), second.clone());
        let reveal = NonceRevealV1::new(
            state.context.purpose(),
            state.context.participant_index(),
            first,
            second,
        );
        let expected = reveal.to_bytes();
        let prepared = PreparedExposureV1::new(ExposureBytes::from_bytes(
            ExposureKindV1::NonceReveal,
            expected,
        )?);
        let permit = self
            .vault
            .authorize_exposure(&mut state.handle, prepared)
            .map_err(VaultBackedSignerError::Vault)?;
        let exported = self
            .vault
            .export(permit)
            .map_err(VaultBackedSignerError::Vault)?;
        let authorized = crate::AuthorizedExposureV1::from_vault_export(&exported)?;
        if authorized.kind() != ExposureKindV1::NonceReveal || authorized.as_bytes() != expected {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        let permit_id = authorized.permit_id().clone();
        let reveal = NonceRevealV1::from_bytes(authorized.as_bytes())?;
        Ok((
            RevealExportedV1 {
                handle: state.handle,
                context: state.context,
                reservation_nonce_id: state.reservation_nonce_id,
                participant_id: state.participant_id,
                public_nonces,
                permit_id,
            },
            reveal,
        ))
    }

    /// Mark the partial attempt, sign once, tombstone, spend, and export exact bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_and_export_partial(
        &mut self,
        mut state: RevealExportedV1<V::ReservationHandle>,
        trusted_chain_id: &TrustedChainIdV1,
        binding_factor: &BindingFactorV1,
        aggregate_nonce_hat: &PublicKey,
        aggregate_signing_key: &PublicKey,
        signing_share: &SigningShareV1,
        kernel_message_digest: &[u8; 32],
    ) -> SignerResult<V, PartialExportResult> {
        if trusted_chain_id.as_bytes() != state.context.chain_id()
            || kernel_message_digest != state.context.message_digest()
        {
            return Err(AdaptorError::AuthorizationMismatch.into());
        }
        let attempt = self
            .vault
            .begin_computation(&mut state.handle, VaultComputationStageV1::PartialAttempt)
            .map_err(VaultBackedSignerError::Vault)?;
        let transfer = self
            .vault
            .open_secret(
                &mut state.handle,
                attempt,
                VaultSecretImportCapabilityV1::new(),
            )
            .map_err(VaultBackedSignerError::Vault)?;
        let pair = transfer.into_validated_pair(
            &state.reservation_nonce_id,
            &state.participant_id,
            &state.context,
            trusted_chain_id,
            signing_share,
        )?;
        let challenge = schnorr_challenge(
            &aggregate_nonce_hat.to_compressed_bytes(),
            aggregate_signing_key,
            trusted_chain_id.as_bytes(),
            kernel_message_digest,
        );
        let binding = PartialSig::from_bytes(&binding_factor.to_be_bytes())?;
        let partial_scalar =
            pair.sign_bound_partial(&binding, challenge.as_bytes(), signing_share)?;
        let partial = PartialSignatureV1::new(
            state.context.purpose(),
            state.context.participant_index(),
            *state.context.template_hash(),
            partial_scalar,
        );
        let bound_public_nonce = state.public_nonces.bind(binding_factor)?;
        let participant_key = &state.context.participant_public_keys()
            [usize::from(state.context.participant_index())];
        if !partial.verify_bound(
            state.context.purpose(),
            state.context.template_hash(),
            &bound_public_nonce,
            participant_key,
            aggregate_nonce_hat,
            aggregate_signing_key,
            trusted_chain_id.as_bytes(),
            kernel_message_digest,
        )? {
            return Err(AdaptorError::VerificationFailed("local participant partial").into());
        }
        let expected = partial.to_bytes();
        let expected_digest =
            exposure_outbound_digest_v1(ExposureKindV1::PartialSignature, &expected)?;
        if expected_digest.as_bytes() == &[0; 32] {
            return Err(AdaptorError::InvalidTranscript("zero outbound digest").into());
        }
        let prepared = PreparedExposureV1::new(ExposureBytes::from_bytes(
            ExposureKindV1::PartialSignature,
            expected,
        )?);
        let permit = self
            .vault
            .authorize_exposure(&mut state.handle, prepared)
            .map_err(VaultBackedSignerError::Vault)?;
        let exported = self
            .vault
            .export(permit)
            .map_err(VaultBackedSignerError::Vault)?;
        let authorized = crate::AuthorizedExposureV1::from_vault_export(&exported)?;
        if authorized.kind() != ExposureKindV1::PartialSignature
            || authorized.as_bytes() != expected
        {
            return Err(VaultBackedSignerError::AuthorizedArtifactMismatch);
        }
        let permit_id = authorized.permit_id().clone();
        let partial = PartialSignatureV1::from_bytes(authorized.as_bytes())?;
        Ok((PartialExportedTerminalV1 { permit_id }, partial))
    }
}

const fn public_material_abort_reason(reason: AbortReasonV1) -> AbortReasonV1 {
    match reason {
        AbortReasonV1::BeforePublicMaterial | AbortReasonV1::PublicMaterialMayHaveExisted => {
            AbortReasonV1::PublicMaterialMayHaveExisted
        }
        AbortReasonV1::CrashAmbiguity => AbortReasonV1::CrashAmbiguity,
        AbortReasonV1::RestoreAmbiguity => AbortReasonV1::RestoreAmbiguity,
    }
}

fn random_nonzero_id<E>() -> core::result::Result<[u8; 32], VaultBackedSignerError<E>> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AdaptorError::RandomnessFailure)?;
    if bytes == [0; 32] {
        return Err(AdaptorError::RandomnessFailure.into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregate_public_nonces_v1, binding_factor_v1, AbortReasonV1, CounterpartyBucket,
        NonceVaultError, ParticipantId, ParticipantPublicNoncesV1, PurposeV1, RestoreState,
        TemplateHash, TerminalReservationV1, VaultExportedArtifactV1, VaultKeyId,
        VaultSecretImportCapabilityV1, VaultSecretSealCapabilityV1,
    };
    use dom_crypto::schnorr_add_public_keys;
    use zeroize::Zeroizing;

    struct TestHandle(ReservationNonceId);
    struct TestComputationPermit(VaultComputationStageV1);
    struct TestPermit {
        permit_id: PermitIdV1,
        exposure: ExposureBytes,
    }
    struct TestExport {
        permit_id: PermitIdV1,
        exposure: ExposureBytes,
    }

    impl VaultExportedArtifactV1 for TestExport {
        fn permit_id(&self) -> &PermitIdV1 {
            &self.permit_id
        }

        fn kind(&self) -> ExposureKindV1 {
            self.exposure.kind()
        }

        fn as_bytes(&self) -> &[u8] {
            self.exposure.as_bytes()
        }
    }

    struct TestVault {
        plaintext: Option<Zeroizing<Vec<u8>>>,
        events: Vec<&'static str>,
        exports: Vec<(PermitIdV1, ExposureBytes)>,
        next_permit: u8,
        restore_state: RestoreState,
        resend_returned_id: Option<PermitIdV1>,
    }

    impl TestVault {
        fn new() -> Self {
            Self {
                plaintext: None,
                events: Vec::new(),
                exports: Vec::new(),
                next_permit: 1,
                restore_state: RestoreState::Operational,
                resend_returned_id: None,
            }
        }
    }

    impl NonceVaultV1 for TestVault {
        type Error = NonceVaultError;
        type ReservationHandle = TestHandle;
        type ComputationPermit = TestComputationPermit;
        type ExposurePermit = TestPermit;
        type ExportedArtifact = TestExport;

        fn claim_reservation(
            &mut self,
            request: ReservationRequestV1,
        ) -> core::result::Result<Self::ReservationHandle, Self::Error> {
            self.events.push("claim");
            Ok(TestHandle(request.reservation_id().clone()))
        }

        fn begin_computation(
            &mut self,
            _reservation: &mut Self::ReservationHandle,
            stage: VaultComputationStageV1,
        ) -> core::result::Result<Self::ComputationPermit, Self::Error> {
            self.events.push(match stage {
                VaultComputationStageV1::NonceDerivation => "begin:derivation",
                VaultComputationStageV1::NonceReveal => "begin:reveal",
                VaultComputationStageV1::PartialAttempt => "begin:partial",
            });
            Ok(TestComputationPermit(stage))
        }

        fn store_reserved_secret(
            &mut self,
            _reservation: &mut Self::ReservationHandle,
            attempt: Self::ComputationPermit,
            secret: NonceSecretTransferV1,
            seal_capability: VaultSecretSealCapabilityV1,
            _commitment: NonceCommitmentV1,
        ) -> core::result::Result<(), Self::Error> {
            if attempt.0 != VaultComputationStageV1::NonceDerivation {
                return Err(NonceVaultError::InvalidTransition);
            }
            self.events.push("store-secret");
            self.plaintext = Some(seal_capability.into_plaintext(secret));
            Ok(())
        }

        fn authorize_exposure(
            &mut self,
            _reservation: &mut Self::ReservationHandle,
            artifact: PreparedExposureV1,
        ) -> core::result::Result<Self::ExposurePermit, Self::Error> {
            self.events.push("authorize");
            let mut permit_id = [0u8; 32];
            permit_id[31] = self.next_permit;
            self.next_permit = self
                .next_permit
                .checked_add(1)
                .ok_or(NonceVaultError::CounterOverflow)?;
            Ok(TestPermit {
                permit_id: PermitIdV1::from_bytes(permit_id)?,
                exposure: artifact.exposure().clone(),
            })
        }

        fn open_secret(
            &mut self,
            _reservation: &mut Self::ReservationHandle,
            attempt: Self::ComputationPermit,
            import_capability: VaultSecretImportCapabilityV1,
        ) -> core::result::Result<NonceSecretTransferV1, Self::Error> {
            if !matches!(
                attempt.0,
                VaultComputationStageV1::NonceReveal | VaultComputationStageV1::PartialAttempt
            ) {
                return Err(NonceVaultError::InvalidTransition);
            }
            self.events.push("open-secret");
            let opened = Zeroizing::new(
                self.plaintext
                    .as_ref()
                    .ok_or(NonceVaultError::ReservationNotFound)?
                    .to_vec(),
            );
            import_capability
                .import(opened)
                .map_err(|_| NonceVaultError::CorruptState)
        }

        fn export(
            &mut self,
            permit: Self::ExposurePermit,
        ) -> core::result::Result<Self::ExportedArtifact, Self::Error> {
            self.events.push("export");
            self.exports
                .push((permit.permit_id.clone(), permit.exposure.clone()));
            Ok(TestExport {
                permit_id: permit.permit_id,
                exposure: permit.exposure,
            })
        }

        fn resend_exported(
            &self,
            permit_id: crate::PermitIdV1,
        ) -> core::result::Result<Self::ExportedArtifact, Self::Error> {
            let (_, exposure) = self
                .exports
                .iter()
                .find(|(candidate, _)| candidate == &permit_id)
                .ok_or(NonceVaultError::ReservationNotFound)?;
            Ok(TestExport {
                permit_id: self
                    .resend_returned_id
                    .as_ref()
                    .cloned()
                    .unwrap_or(permit_id),
                exposure: exposure.clone(),
            })
        }

        fn abort(
            &mut self,
            reservation: Self::ReservationHandle,
            reason: AbortReasonV1,
        ) -> core::result::Result<TerminalReservationV1, Self::Error> {
            self.events.push(match reason {
                AbortReasonV1::BeforePublicMaterial => "abort:before-public",
                AbortReasonV1::PublicMaterialMayHaveExisted => "abort:public",
                AbortReasonV1::CrashAmbiguity => "abort:crash",
                AbortReasonV1::RestoreAmbiguity => "abort:restore",
            });
            let state = match reason {
                AbortReasonV1::BeforePublicMaterial => {
                    crate::ReservationState::AbortedBeforePublicMaterial
                }
                AbortReasonV1::PublicMaterialMayHaveExisted => {
                    crate::ReservationState::ConsumedOnAbort
                }
                AbortReasonV1::CrashAmbiguity | AbortReasonV1::RestoreAmbiguity => {
                    crate::ReservationState::Burned
                }
            };
            Ok(TerminalReservationV1 {
                reservation_id: reservation.0,
                state,
            })
        }

        fn restore_state(&self) -> RestoreState {
            self.restore_state
        }
    }

    fn scalar(value: u8) -> SigningShareV1 {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        SigningShareV1::from_be_bytes(bytes).expect("canonical scalar")
    }

    fn point(secret: &SigningShareV1) -> PublicKey {
        secret.public_key().clone()
    }

    fn test_context() -> SessionContextV1 {
        let local_share = scalar(3);
        let remote_share = scalar(5);
        let mut roster = vec![point(&local_share), point(&remote_share)];
        roster.sort_by_key(PublicKey::to_compressed_bytes);
        let local_index = roster
            .iter()
            .position(|key| key == &point(&local_share))
            .expect("local roster member") as u16;
        SessionContextV1::new(
            crate::SessionContextInputsV1 {
                chain_id: [1; 32],
                session_id: [2; 32],
                purpose: PurposeV1::Funding,
                direction: crate::DirectionV1::Initiator,
                signing_phase: crate::SigningPhaseV1::SigNonceCommit,
                template_hash: [3; 32],
                message_digest: [4; 32],
                transcript_hash: [5; 32],
                retry_counter: 0,
                participant_public_keys: roster,
                participant_index: local_index,
                adaptor_point: None,
            },
            &local_share,
        )
        .expect("context")
    }

    struct SecretBearingVaultError;

    impl fmt::Debug for SecretBearingVaultError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("DO_NOT_LEAK_VAULT_SECRET")
        }
    }

    impl fmt::Display for SecretBearingVaultError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("DO_NOT_LEAK_VAULT_SECRET")
        }
    }

    #[test]
    fn vault_errors_are_redacted_from_debug_and_display() {
        let error = VaultBackedSignerError::Vault(SecretBearingVaultError);
        let debug = format!("{error:?}");
        let display = format!("{error}");
        assert_eq!(debug, "Vault(Redacted)");
        assert_eq!(display, "vault operation failed (details redacted)");
        assert!(!debug.contains("DO_NOT_LEAK_VAULT_SECRET"));
        assert!(!display.contains("DO_NOT_LEAK_VAULT_SECRET"));
    }

    #[test]
    fn every_live_state_aborts_terminally_and_restore_state_delegates() {
        let context = test_context();
        let first_id = ReservationNonceId::from_bytes([0x11; 32]).expect("reservation ID");
        let second_id = ReservationNonceId::from_bytes([0x12; 32]).expect("reservation ID");
        let third_id = ReservationNonceId::from_bytes([0x13; 32]).expect("reservation ID");
        let mut vault = TestVault::new();
        vault.restore_state = RestoreState::RestoreQuarantined;
        let mut signer = VaultBackedSignerV1::new(vault);
        assert_eq!(signer.restore_state(), RestoreState::RestoreQuarantined);

        let reserved = ReservedNonceV1 {
            handle: TestHandle(first_id.clone()),
            context: context.clone(),
            reservation_nonce_id: *first_id.as_bytes(),
            participant_id: [0x21; 32],
            commitment: NonceCommitmentV1::new(PurposeV1::Funding, 0, [0x31; 32]),
        };
        let terminal = signer
            .abort_reserved(reserved, AbortReasonV1::BeforePublicMaterial)
            .expect("reserved abort");
        assert_eq!(terminal.reservation_id, first_id);
        assert_eq!(
            terminal.state,
            crate::ReservationState::AbortedBeforePublicMaterial
        );

        let commitment_exported = CommitmentExportedV1 {
            handle: TestHandle(second_id.clone()),
            context: context.clone(),
            reservation_nonce_id: *second_id.as_bytes(),
            participant_id: [0x22; 32],
            permit_id: PermitIdV1::from_bytes([0x41; 32]).expect("permit ID"),
        };
        let terminal = signer
            .abort_after_commitment(commitment_exported, AbortReasonV1::BeforePublicMaterial)
            .expect("commitment abort");
        assert_eq!(terminal.reservation_id, second_id);
        assert_eq!(terminal.state, crate::ReservationState::ConsumedOnAbort);

        let reveal_exported = RevealExportedV1 {
            handle: TestHandle(third_id.clone()),
            context,
            reservation_nonce_id: *third_id.as_bytes(),
            participant_id: [0x23; 32],
            public_nonces: PublicNoncePairV1::new(point(&scalar(11)), point(&scalar(13))),
            permit_id: PermitIdV1::from_bytes([0x42; 32]).expect("permit ID"),
        };
        let terminal = signer
            .abort_after_reveal(reveal_exported, AbortReasonV1::CrashAmbiguity)
            .expect("reveal abort");
        assert_eq!(terminal.reservation_id, third_id);
        assert_eq!(terminal.state, crate::ReservationState::Burned);
        assert_eq!(
            signer.vault.events,
            ["abort:before-public", "abort:public", "abort:crash"]
        );
    }

    #[test]
    fn vault_backed_type_state_exports_commit_reveal_and_partial() {
        let local_share = scalar(3);
        let remote_share = scalar(5);
        let mut roster = vec![point(&local_share), point(&remote_share)];
        roster.sort_by_key(PublicKey::to_compressed_bytes);
        let local_index = roster
            .iter()
            .position(|key| key == &point(&local_share))
            .expect("local roster member") as u16;
        let context = SessionContextV1::new(
            crate::SessionContextInputsV1 {
                chain_id: [1; 32],
                session_id: [2; 32],
                purpose: PurposeV1::Funding,
                direction: crate::DirectionV1::Initiator,
                signing_phase: crate::SigningPhaseV1::SigNonceCommit,
                template_hash: [3; 32],
                message_digest: [4; 32],
                transcript_hash: [5; 32],
                retry_counter: 0,
                participant_public_keys: roster.clone(),
                participant_index: local_index,
                adaptor_point: None,
            },
            &local_share,
        )
        .expect("context");
        let intent = ReservationIntentV1::new(
            VaultKeyId::from_bytes([6; 32]).expect("key ID"),
            CounterpartyBucket::from_bytes([7; 32]).expect("bucket"),
            PurposeV1::Funding,
            ParticipantId::from_bytes([8; 32]).expect("participant"),
            TemplateHash::from_bytes([3; 32]).expect("template"),
        )
        .expect("intent");
        let trusted = TrustedChainIdV1::from_signed_fixture([1; 32]);
        let mut signer = VaultBackedSignerV1::new(TestVault::new());
        let reserved = signer
            .reserve(intent, context.clone(), &local_share)
            .expect("reserve");
        let (commitment_state, commitment) = signer
            .export_commitment(reserved)
            .expect("commitment export");
        let commitment_permit_id = commitment_state.permit_id().clone();
        assert_eq!(commitment.purpose(), PurposeV1::Funding);
        let (reveal_state, reveal) = signer
            .export_reveal(commitment_state, &trusted, &local_share)
            .expect("reveal export");
        let reveal_permit_id = reveal_state.permit_id().clone();

        let remote_first = point(&scalar(11));
        let remote_second = point(&scalar(13));
        let local_nonces = reveal_state.public_nonces.clone();
        let mut participants = Vec::with_capacity(2);
        for (index, signing_key) in roster.iter().enumerate() {
            let (first_nonce, second_nonce) = if index as u16 == local_index {
                (local_nonces.first().clone(), local_nonces.second().clone())
            } else {
                (remote_first.clone(), remote_second.clone())
            };
            participants.push(ParticipantPublicNoncesV1 {
                participant_index: index as u16,
                signing_key: signing_key.clone(),
                first_nonce,
                second_nonce,
            });
        }
        let binding = binding_factor_v1(
            &crate::BindingContextV1 {
                chain_id: [1; 32],
                session_id: [2; 32],
                purpose: PurposeV1::Funding,
                template_hash: [3; 32],
            },
            &participants,
            None,
        )
        .expect("binding");
        let effective: Vec<PublicKey> = participants
            .iter()
            .map(|entry| {
                binding
                    .bind_public_nonces(&entry.first_nonce, &entry.second_nonce)
                    .expect("effective nonce")
            })
            .collect();
        let aggregate_nonce = aggregate_public_nonces_v1(&effective).expect("aggregate nonce");
        let aggregate_key = schnorr_add_public_keys(&roster).expect("aggregate key");
        let (terminal, partial) = signer
            .sign_and_export_partial(
                reveal_state,
                &trusted,
                &binding,
                &aggregate_nonce,
                &aggregate_key,
                &local_share,
                &[4; 32],
            )
            .expect("partial export");
        let partial_permit_id = terminal.permit_id().clone();
        assert_eq!(partial.purpose(), PurposeV1::Funding);
        assert_eq!(partial.participant_index(), local_index);
        assert_eq!(reveal.purpose(), PurposeV1::Funding);
        assert_ne!(commitment_permit_id, reveal_permit_id);
        assert_ne!(reveal_permit_id, partial_permit_id);

        let commitment_digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceCommitment, &commitment.to_bytes())
                .expect("commitment digest");
        let resent = signer
            .resend_exported(
                commitment_permit_id.clone(),
                ExposureKindV1::NonceCommitment,
                *commitment_digest.as_bytes(),
            )
            .expect("commitment resend");
        match resent {
            ResentArtifactV1::NonceCommitment(value) => {
                assert_eq!(value.to_bytes(), commitment.to_bytes());
            }
            _ => panic!("closed resend kind must match commitment"),
        }

        let reveal_digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceReveal, &reveal.to_bytes())
                .expect("reveal digest");
        let resent = signer
            .resend_exported(
                reveal_permit_id.clone(),
                ExposureKindV1::NonceReveal,
                *reveal_digest.as_bytes(),
            )
            .expect("reveal resend");
        match resent {
            ResentArtifactV1::NonceReveal(value) => {
                assert_eq!(value.to_bytes(), reveal.to_bytes());
            }
            _ => panic!("closed resend kind must match reveal"),
        }

        let partial_digest =
            exposure_outbound_digest_v1(ExposureKindV1::PartialSignature, &partial.to_bytes())
                .expect("partial digest");
        let resent = signer
            .resend_exported(
                partial_permit_id,
                ExposureKindV1::PartialSignature,
                *partial_digest.as_bytes(),
            )
            .expect("partial resend");
        match resent {
            ResentArtifactV1::PartialSignature(value) => {
                assert_eq!(value.to_bytes(), partial.to_bytes());
            }
            _ => panic!("closed resend kind must match partial"),
        }

        assert!(matches!(
            signer.resend_exported(
                commitment_permit_id.clone(),
                ExposureKindV1::NonceReveal,
                *reveal_digest.as_bytes(),
            ),
            Err(VaultBackedSignerError::AuthorizedArtifactMismatch)
        ));
        assert!(matches!(
            signer.resend_exported(
                commitment_permit_id.clone(),
                ExposureKindV1::NonceCommitment,
                [0x99; 32],
            ),
            Err(VaultBackedSignerError::AuthorizedArtifactMismatch)
        ));
        signer.vault.resend_returned_id =
            Some(PermitIdV1::from_bytes([0x55; 32]).expect("mismatched permit ID"));
        assert!(matches!(
            signer.resend_exported(
                commitment_permit_id.clone(),
                ExposureKindV1::NonceCommitment,
                *commitment_digest.as_bytes(),
            ),
            Err(VaultBackedSignerError::AuthorizedArtifactMismatch)
        ));
        signer.vault.resend_returned_id = None;
        assert!(matches!(
            signer.resend_exported(
                commitment_permit_id,
                ExposureKindV1::NonceCommitment,
                [0; 32],
            ),
            Err(VaultBackedSignerError::AuthorizedArtifactMismatch)
        ));
        assert!(matches!(
            signer.resend_exported(
                PermitIdV1::from_bytes([0x56; 32]).expect("unknown permit ID"),
                ExposureKindV1::NonceCommitment,
                *commitment_digest.as_bytes(),
            ),
            Err(VaultBackedSignerError::Vault(
                NonceVaultError::ReservationNotFound
            ))
        ));
        let sponsor_permit_id = PermitIdV1::from_bytes([0x66; 32]).expect("Sponsor permit ID");
        let sponsor_bytes =
            NonceCommitmentV1::new(PurposeV1::Sponsor, local_index, [0x77; 32]).to_bytes();
        signer.vault.exports.push((
            sponsor_permit_id.clone(),
            ExposureBytes::from_bytes(ExposureKindV1::NonceCommitment, sponsor_bytes)
                .expect("Sponsor is codec-recognized"),
        ));
        let sponsor_digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceCommitment, &sponsor_bytes)
                .expect("Sponsor codec digest");
        assert!(matches!(
            signer.resend_exported(
                sponsor_permit_id,
                ExposureKindV1::NonceCommitment,
                *sponsor_digest.as_bytes(),
            ),
            Err(VaultBackedSignerError::Adaptor(
                AdaptorError::PurposeNotAuthorized(0x04)
            ))
        ));
        assert_eq!(signer.restore_state(), RestoreState::Operational);
        assert_eq!(
            signer.vault.events,
            [
                "claim",
                "begin:derivation",
                "store-secret",
                "authorize",
                "export",
                "begin:reveal",
                "open-secret",
                "authorize",
                "export",
                "begin:partial",
                "open-secret",
                "authorize",
                "export",
            ]
        );
    }
}

//! Non-bypassable high-level G1a/G1b signer composition.

use crate::{
    exposure_outbound_digest_v1, nonce_commitment_hash_v1, AdaptorError, BindingFactorV1,
    ExposureBytes, ExposureKindV1, IdempotencyKey, NonceCommitmentV1, NonceRevealV1,
    NonceSecretTransferV1, NonceVaultV1, PartialSignatureV1, PreparedExposureV1, PublicNoncePairV1,
    ReservationIntentV1, ReservationNonceId, ReservationRequestV1, SecretOpenStageV1,
    SessionContextV1, SessionId, TrustedChainIdV1, VaultSecretImportCapabilityV1,
    VaultSecretSealCapabilityV1,
};
use core::fmt;
use dom_crypto::{
    schnorr_challenge, PartialSig, PublicKey, ScriptlessNonceDerivationV1, ScriptlessSecretScalar,
};
use rand_core::{OsRng, RngCore};
use std::error::Error;

/// Typed failure from the integrated cryptographic and durable-authority path.
pub enum VaultBackedSignerError<E> {
    /// Canonical parsing, binding, or cryptographic failure.
    Adaptor(AdaptorError),
    /// Storage-independent vault contract validation failure.
    Contract(crate::NonceVaultError),
    /// Failure reported by the statically selected concrete Wallet vault.
    Vault(E),
    /// The vault returned bytes other than the exact prepared persisted artifact.
    AuthorizedArtifactMismatch,
}

impl<E: fmt::Debug> fmt::Debug for VaultBackedSignerError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adaptor(error) => formatter.debug_tuple("Adaptor").field(error).finish(),
            Self::Contract(error) => formatter.debug_tuple("Contract").field(error).finish(),
            Self::Vault(error) => formatter.debug_tuple("Vault").field(error).finish(),
            Self::AuthorizedArtifactMismatch => formatter.write_str("AuthorizedArtifactMismatch"),
        }
    }
}

impl<E: fmt::Display> fmt::Display for VaultBackedSignerError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adaptor(error) => error.fmt(formatter),
            Self::Contract(error) => error.fmt(formatter),
            Self::Vault(error) => error.fmt(formatter),
            Self::AuthorizedArtifactMismatch => {
                formatter.write_str("vault returned a different authorized artifact")
            }
        }
    }
}

impl<E: Error + 'static> Error for VaultBackedSignerError<E> {}

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
}

/// State after durable authorization and exact nonce-reveal export.
pub struct RevealExportedV1<H> {
    handle: H,
    context: SessionContextV1,
    reservation_nonce_id: [u8; 32],
    participant_id: [u8; 32],
    public_nonces: PublicNoncePairV1,
}

/// Terminal marker after exactly one partial-signature export.
pub struct PartialExportedTerminalV1 {
    _private: (),
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

    /// Derive, seal, charge, witness, and durably reserve one nonce pair.
    pub fn reserve(
        &mut self,
        intent: ReservationIntentV1,
        context: SessionContextV1,
        signing_share: &ScriptlessSecretScalar,
    ) -> SignerResult<V, ReservedNonceV1<V::ReservationHandle>> {
        context.purpose().require_strict_phase1()?;
        if intent.purpose != context.purpose()
            || intent.template_hash.as_bytes() != context.template_hash()
        {
            return Err(AdaptorError::AuthorizationMismatch.into());
        }

        let reservation_id = ReservationNonceId::from_bytes(random_nonzero_id::<V::Error>()?)?;
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

        let derivation = ScriptlessNonceDerivationV1::from_os_rng()
            .map_err(|_| AdaptorError::RandomnessFailure)?;
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
        let (first, second) = pair.public_keys();
        let commitment_hash = nonce_commitment_hash_v1(
            effective_context.chain_id(),
            effective_context.session_id(),
            request.participant_id().as_bytes(),
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
        let reservation_nonce_id = *request.reservation_id().as_bytes();
        let participant_id = *request.participant_id().as_bytes();
        let secret = NonceSecretTransferV1::from_nonce_pair(
            reservation_nonce_id,
            participant_id,
            &effective_context,
            pair,
        )?;
        let handle = self
            .vault
            .reserve(
                request,
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
        let commitment = NonceCommitmentV1::from_bytes(authorized.as_bytes())?;
        Ok((
            CommitmentExportedV1 {
                handle: state.handle,
                context: state.context,
                reservation_nonce_id: state.reservation_nonce_id,
                participant_id: state.participant_id,
            },
            commitment,
        ))
    }

    /// Reopen under reveal policy, persist exact bytes, authorize, and export once.
    pub fn export_reveal(
        &mut self,
        mut state: CommitmentExportedV1<V::ReservationHandle>,
        trusted_chain_id: &TrustedChainIdV1,
        signing_share: &ScriptlessSecretScalar,
    ) -> SignerResult<V, RevealExportResult<V::ReservationHandle>> {
        let transfer = self
            .vault
            .open_secret(
                &mut state.handle,
                SecretOpenStageV1::NonceReveal,
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
        let (first, second) = pair.public_keys();
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
        let reveal = NonceRevealV1::from_bytes(authorized.as_bytes())?;
        Ok((
            RevealExportedV1 {
                handle: state.handle,
                context: state.context,
                reservation_nonce_id: state.reservation_nonce_id,
                participant_id: state.participant_id,
                public_nonces,
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
        signing_share: &ScriptlessSecretScalar,
        kernel_message_digest: &[u8; 32],
    ) -> SignerResult<V, PartialExportResult> {
        if trusted_chain_id.as_bytes() != state.context.chain_id()
            || kernel_message_digest != state.context.message_digest()
        {
            return Err(AdaptorError::AuthorizationMismatch.into());
        }
        let transfer = self
            .vault
            .open_secret(
                &mut state.handle,
                SecretOpenStageV1::PartialAttempt,
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
        let partial = PartialSignatureV1::from_bytes(authorized.as_bytes())?;
        Ok((PartialExportedTerminalV1 { _private: () }, partial))
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
    use dom_crypto::{schnorr_add_public_keys, ScriptlessSecretScalar};
    use zeroize::Zeroizing;

    struct TestHandle;
    struct TestPermit(ExposureBytes);
    struct TestExport(ExposureBytes);

    impl VaultExportedArtifactV1 for TestExport {
        fn kind(&self) -> ExposureKindV1 {
            self.0.kind()
        }

        fn as_bytes(&self) -> &[u8] {
            self.0.as_bytes()
        }
    }

    struct TestVault {
        plaintext: Option<Zeroizing<Vec<u8>>>,
    }

    impl NonceVaultV1 for TestVault {
        type Error = NonceVaultError;
        type ReservationHandle = TestHandle;
        type ExposurePermit = TestPermit;
        type ExportedArtifact = TestExport;

        fn reserve(
            &mut self,
            _request: ReservationRequestV1,
            secret: NonceSecretTransferV1,
            seal_capability: VaultSecretSealCapabilityV1,
            _commitment: NonceCommitmentV1,
        ) -> core::result::Result<Self::ReservationHandle, Self::Error> {
            self.plaintext = Some(seal_capability.into_plaintext(secret));
            Ok(TestHandle)
        }

        fn authorize_exposure(
            &mut self,
            _reservation: &mut Self::ReservationHandle,
            artifact: PreparedExposureV1,
        ) -> core::result::Result<Self::ExposurePermit, Self::Error> {
            Ok(TestPermit(artifact.exposure().clone()))
        }

        fn open_secret(
            &mut self,
            _reservation: &mut Self::ReservationHandle,
            _stage: SecretOpenStageV1,
            import_capability: VaultSecretImportCapabilityV1,
        ) -> core::result::Result<NonceSecretTransferV1, Self::Error> {
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
            Ok(TestExport(permit.0))
        }

        fn resend_exported(
            &self,
            _permit_id: crate::PermitIdV1,
        ) -> core::result::Result<Self::ExportedArtifact, Self::Error> {
            Err(NonceVaultError::ReservationNotFound)
        }

        fn abort(
            &mut self,
            _reservation: Self::ReservationHandle,
            _reason: AbortReasonV1,
        ) -> core::result::Result<TerminalReservationV1, Self::Error> {
            Err(NonceVaultError::InvalidTransition)
        }

        fn restore_state(&self) -> RestoreState {
            RestoreState::Operational
        }
    }

    fn scalar(value: u8) -> ScriptlessSecretScalar {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        ScriptlessSecretScalar::from_be_bytes(bytes).expect("canonical scalar")
    }

    #[test]
    fn vault_backed_type_state_exports_commit_reveal_and_partial() {
        let local_share = scalar(3);
        let remote_share = scalar(5);
        let mut roster = vec![local_share.public_key(), remote_share.public_key()];
        roster.sort_by_key(PublicKey::to_compressed_bytes);
        let local_index = roster
            .iter()
            .position(|key| key == &local_share.public_key())
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
        let mut signer = VaultBackedSignerV1::new(TestVault { plaintext: None });
        let reserved = signer
            .reserve(intent, context.clone(), &local_share)
            .expect("reserve");
        let (commitment_state, commitment) = signer
            .export_commitment(reserved)
            .expect("commitment export");
        assert_eq!(commitment.purpose(), PurposeV1::Funding);
        let (reveal_state, reveal) = signer
            .export_reveal(commitment_state, &trusted, &local_share)
            .expect("reveal export");

        let remote_first = scalar(11).public_key();
        let remote_second = scalar(13).public_key();
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
        let (_terminal, partial) = signer
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
        assert_eq!(partial.purpose(), PurposeV1::Funding);
        assert_eq!(partial.participant_index(), local_index);
        assert_eq!(reveal.purpose(), PurposeV1::Funding);
    }
}

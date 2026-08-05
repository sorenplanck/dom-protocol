//! Non-bypassable high-level G1a/G1b signer composition.

use crate::{
    exposure_outbound_digest_v1, nonce_commitment_hash_v1, AdaptorError, BindingFactorV1,
    ExposureBytes, ExposureKindV1, IdempotencyKey, NonceCommitmentV1, NonceRevealV1,
    NonceSecretTransferV1, NonceVaultV1, PartialSignatureV1, PreparedExposureV1, PublicNoncePairV1,
    ReservationIntentV1, ReservationNonceId, ReservationRequestV1, SecretOpenStageV1,
    SessionContextV1, SessionId, TrustedChainIdV1,
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
            .reserve(request, secret, commitment)
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
            .open_secret(&mut state.handle, SecretOpenStageV1::NonceReveal)
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
            .open_secret(&mut state.handle, SecretOpenStageV1::PartialAttempt)
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

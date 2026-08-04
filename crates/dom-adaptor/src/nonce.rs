//! Opaque one-shot secret two-nonce ownership and participant signing.

use crate::{
    nonce_commitment_hash_v1, AdaptorError, BindingFactorV1, ExposureKindV1, ExposurePermitV1,
    PartialSignatureV1, PurposeV1, Result, SessionContextV1,
};
use dom_crypto::{
    schnorr_aggregate_sigs, schnorr_challenge, scriptless_add_public_points,
    scriptless_aggregate_partial_scalars, scriptless_derive_secret_nonce_pair_v1,
    scriptless_sign_bound_partial, scriptless_verify_final_signature, Hash256, PartialSig,
    PublicKey, SchnorrSignature, ScriptlessSecretScalar,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Public identifiers durably bound to a reserved nonce before derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceReservationBindingV1 {
    nonce_id: [u8; 32],
    participant_id: [u8; 32],
    outbound_digest: [u8; 32],
}

impl NonceReservationBindingV1 {
    /// Construct a reservation binding from nonzero canonical identifiers.
    pub fn new(
        nonce_id: [u8; 32],
        participant_id: [u8; 32],
        outbound_digest: [u8; 32],
    ) -> Result<Self> {
        if nonce_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext("nonce ID must be nonzero"));
        }
        if participant_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "participant ID must be nonzero",
            ));
        }
        Ok(Self {
            nonce_id,
            participant_id,
            outbound_digest,
        })
    }

    /// Return the nonce identifier.
    pub const fn nonce_id(&self) -> &[u8; 32] {
        &self.nonce_id
    }
    /// Return the participant identifier.
    pub const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }
    /// Return the digest of the outbound canonical bytes.
    pub const fn outbound_digest(&self) -> &[u8; 32] {
        &self.outbound_digest
    }
}

/// Canonical public two-nonce pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicNoncePairV1 {
    first: PublicKey,
    second: PublicKey,
}

impl PublicNoncePairV1 {
    /// Return the first public nonce `R_i1`.
    pub const fn first(&self) -> &PublicKey {
        &self.first
    }
    /// Return the second public nonce `R_i2`.
    pub const fn second(&self) -> &PublicKey {
        &self.second
    }
    /// Compute `R_i1 + b*R_i2` through the authoritative DOM boundary.
    pub fn bind(&self, binding_factor: &BindingFactorV1) -> Result<PublicKey> {
        binding_factor.bind_public_nonces(&self.first, &self.second)
    }
}

/// Opaque secret nonce pair before durable exposure authorization.
///
/// This type deliberately implements no cloning, copying, debugging, display,
/// equality, ordering, or generic serialization. Its scalar fields zeroize on
/// drop. No public nonce accessor exists before authorization.
pub struct SecretNoncePairV1 {
    first: ScriptlessSecretScalar,
    second: ScriptlessSecretScalar,
    public: PublicNoncePairV1,
    context: SessionContextV1,
    reservation: NonceReservationBindingV1,
    effective_retry_counter: u64,
}

impl SecretNoncePairV1 {
    /// Derive a fresh pair from the operating-system CSPRNG.
    pub fn derive(
        context: SessionContextV1,
        signing_share: &ScriptlessSecretScalar,
        reservation: NonceReservationBindingV1,
    ) -> Result<Self> {
        let mut aux_rand_32 = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(aux_rand_32.as_mut())
            .map_err(|_| AdaptorError::RandomnessFailure)?;
        Self::derive_owned_aux(context, signing_share, reservation, &aux_rand_32)
    }

    fn derive_owned_aux(
        context: SessionContextV1,
        signing_share: &ScriptlessSecretScalar,
        reservation: NonceReservationBindingV1,
        aux_rand_32: &[u8; 32],
    ) -> Result<Self> {
        let mut retry_counter = context.retry_counter();
        loop {
            let context_bytes = context.encode_with_retry_counter(retry_counter);
            if let Some((first, second)) =
                scriptless_derive_secret_nonce_pair_v1(signing_share, aux_rand_32, &context_bytes)
            {
                let public = PublicNoncePairV1 {
                    first: first.public_key(),
                    second: second.public_key(),
                };
                return Ok(Self {
                    first,
                    second,
                    public,
                    context,
                    reservation,
                    effective_retry_counter: retry_counter,
                });
            }
            retry_counter = retry_counter
                .checked_add(1)
                .ok_or(AdaptorError::RetryCounterOverflow)?;
        }
    }

    /// Return the retry counter that produced this pair. This is public state,
    /// not nonce material.
    pub const fn effective_retry_counter(&self) -> u64 {
        self.effective_retry_counter
    }

    /// Compute the public nonce commitment without exposing either point.
    pub fn commitment(&self) -> Result<Hash256> {
        nonce_commitment_hash_v1(
            self.context.chain_id(),
            self.context.session_id(),
            self.reservation.participant_id(),
            self.context.purpose(),
            self.context.template_hash(),
            &self.public.first,
            &self.public.second,
            self.context.adaptor_point(),
        )
    }

    /// Consume this pre-authorization pair and bind it to one durable permit.
    pub fn authorize(self, permit: ExposurePermitV1) -> Result<AuthorizedSecretNoncePairV1> {
        let matches = permit.exposure_kind() == ExposureKindV1::NonceReveal
            && permit.reservation_nonce_id() == self.reservation.nonce_id()
            && permit.session_id() == self.context.session_id()
            && permit.participant_id() == self.reservation.participant_id()
            && permit.purpose() == self.context.purpose()
            && permit.template_hash() == self.context.template_hash()
            && permit.outbound_digest() == self.reservation.outbound_digest();
        if !matches {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(AuthorizedSecretNoncePairV1 {
            pair: self,
            _permit: permit,
        })
    }

    #[cfg(test)]
    fn derive_with_aux_for_test(
        context: SessionContextV1,
        signing_share: &ScriptlessSecretScalar,
        reservation: NonceReservationBindingV1,
        aux_rand_32: [u8; 32],
    ) -> Result<Self> {
        let aux_rand_32 = Zeroizing::new(aux_rand_32);
        Self::derive_owned_aux(context, signing_share, reservation, &aux_rand_32)
    }
}

/// Opaque pair after durable authorization; public export and one partial-sign
/// operation are now available. Partial signing consumes this value.
pub struct AuthorizedSecretNoncePairV1 {
    pair: SecretNoncePairV1,
    _permit: ExposurePermitV1,
}

impl AuthorizedSecretNoncePairV1 {
    /// Export the exact authorized public nonce pair.
    pub const fn public_nonces(&self) -> &PublicNoncePairV1 {
        &self.pair.public
    }

    /// Consume the nonce pair and produce exactly one participant-bound partial.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_partial(
        self,
        binding_factor: &BindingFactorV1,
        aggregate_nonce_hat: &PublicKey,
        aggregate_signing_key: &PublicKey,
        signing_share: &ScriptlessSecretScalar,
        chain_id: &[u8; 32],
        kernel_message_digest: &[u8; 32],
    ) -> Result<PartialSignatureV1> {
        if chain_id != self.pair.context.chain_id()
            || kernel_message_digest != self.pair.context.message_digest()
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let local_key = signing_share.public_key();
        if self.pair.context.participant_public_keys()
            [usize::from(self.pair.context.participant_index())]
            != local_key
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let challenge = schnorr_challenge(
            &aggregate_nonce_hat.to_compressed_bytes(),
            aggregate_signing_key,
            chain_id,
            kernel_message_digest,
        );
        let binding = PartialSig::from_bytes(&binding_factor.to_be_bytes())?;
        let partial = scriptless_sign_bound_partial(
            &self.pair.first,
            &self.pair.second,
            &binding,
            challenge.as_bytes(),
            signing_share,
        )?;
        Ok(PartialSignatureV1::new(
            self.pair.context.purpose(),
            self.pair.context.participant_index(),
            *self.pair.context.template_hash(),
            partial,
        ))
    }
}

/// Aggregate canonical public nonces and reject an identity result.
pub fn aggregate_public_nonces_v1(nonces: &[PublicKey]) -> Result<PublicKey> {
    scriptless_add_public_points(nonces).map_err(Into::into)
}

/// Aggregate participant partial scalars after checking common purpose and
/// template bindings.
pub fn aggregate_partial_signatures_v1(
    partials: &[PartialSignatureV1],
    purpose: PurposeV1,
    template_hash: &[u8; 32],
) -> Result<PartialSig> {
    purpose.require_strict_phase1()?;
    if partials.is_empty() {
        return Err(AdaptorError::InvalidTranscript(
            "partial signature set must not be empty",
        ));
    }
    let mut indexes = Vec::with_capacity(partials.len());
    let mut scalars = Vec::with_capacity(partials.len());
    for partial in partials {
        if partial.purpose() != purpose || partial.template_hash() != template_hash {
            return Err(AdaptorError::InvalidTranscript(
                "partial signature binding differs from the aggregate session",
            ));
        }
        if indexes.contains(&partial.participant_index()) {
            return Err(AdaptorError::InvalidTranscript(
                "duplicate participant partial signature",
            ));
        }
        indexes.push(partial.participant_index());
        scalars.push(partial.partial().clone());
    }
    scriptless_aggregate_partial_scalars(&scalars).map_err(Into::into)
}

/// Finalize a Funding or Refund partial aggregate into the unchanged 65-byte
/// DOM Schnorr signature and verify it through the authoritative verifier.
#[allow(clippy::too_many_arguments)]
pub fn finalize_plain_signature_v1(
    partials: &[PartialSignatureV1],
    purpose: PurposeV1,
    template_hash: &[u8; 32],
    aggregate_nonce: &PublicKey,
    aggregate_signing_key: &PublicKey,
    chain_id: &[u8; 32],
    kernel_message_digest: &[u8; 32],
) -> Result<SchnorrSignature> {
    match purpose {
        PurposeV1::Funding | PurposeV1::Refund => {}
        PurposeV1::ClaimAdaptor | PurposeV1::Sponsor => {
            return Err(AdaptorError::InvalidTranscript(
                "plain finalization is restricted to Funding and Refund",
            ));
        }
    }
    let aggregate = aggregate_partial_signatures_v1(partials, purpose, template_hash)?;
    let signature = schnorr_aggregate_sigs(&[aggregate], aggregate_nonce)?;
    if !scriptless_verify_final_signature(
        &signature,
        aggregate_signing_key,
        chain_id,
        kernel_message_digest,
    )? {
        return Err(AdaptorError::VerificationFailed(
            "aggregated plain DOM Schnorr signature",
        ));
    }
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        binding_factor_v1, AdaptorPreSignatureV1, AdaptorSecret, BindingContextV1, DirectionV1,
        ParticipantPublicNoncesV1, SessionContextInputsV1, SigningPhaseV1,
    };
    use dom_crypto::schnorr_add_public_keys;

    fn secret(byte: u8) -> ScriptlessSecretScalar {
        ScriptlessSecretScalar::from_be_bytes([byte; 32]).expect("fixture scalar is canonical")
    }

    fn small_secret(value: u8) -> ScriptlessSecretScalar {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        ScriptlessSecretScalar::from_be_bytes(bytes).expect("small scalar is canonical")
    }

    fn context(
        share: &ScriptlessSecretScalar,
        participant_index: u16,
        purpose: PurposeV1,
        direction: DirectionV1,
        phase: SigningPhaseV1,
        session_id: [u8; 32],
    ) -> SessionContextV1 {
        let first_key = secret(0x07).public_key();
        let second_key = small_secret(0x03).public_key();
        let mut roster = vec![first_key, second_key];
        roster.sort_by_key(|key| key.to_compressed_bytes());
        let actual_index = roster
            .iter()
            .position(|key| *key == share.public_key())
            .expect("share is in roster") as u16;
        assert_eq!(participant_index, actual_index);
        SessionContextV1::new(
            SessionContextInputsV1 {
                chain_id: [0xaa; 32],
                session_id,
                purpose,
                direction,
                signing_phase: phase,
                template_hash: [0xcc; 32],
                message_digest: [0xdd; 32],
                transcript_hash: [0xee; 32],
                retry_counter: 0,
                participant_public_keys: roster,
                participant_index,
                adaptor_point: (purpose == PurposeV1::ClaimAdaptor)
                    .then(|| small_secret(0x05).public_key()),
            },
            share,
        )
        .expect("valid context")
    }

    fn reservation(byte: u8) -> NonceReservationBindingV1 {
        NonceReservationBindingV1::new([byte; 32], [byte + 1; 32], [byte + 2; 32]).expect("binding")
    }

    fn permit(
        context: &SessionContextV1,
        reservation: &NonceReservationBindingV1,
    ) -> ExposurePermitV1 {
        permit_with_nonce(context, reservation, *reservation.nonce_id())
    }

    fn permit_with_nonce(
        context: &SessionContextV1,
        reservation: &NonceReservationBindingV1,
        nonce_id: [u8; 32],
    ) -> ExposurePermitV1 {
        let mut bytes = [0u8; ExposurePermitV1::ENCODED_LEN];
        bytes[..8].copy_from_slice(b"DOMEXPV1");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10] = ExposureKindV1::NonceReveal.to_byte();
        bytes[11..43].fill(0x91);
        bytes[43..75].copy_from_slice(&nonce_id);
        bytes[75..107].copy_from_slice(context.session_id());
        bytes[107..139].copy_from_slice(reservation.participant_id());
        bytes[139] = context.purpose().to_byte();
        bytes[140..172].copy_from_slice(context.template_hash());
        bytes[172..204].copy_from_slice(reservation.outbound_digest());
        bytes[204..212].copy_from_slice(&1u64.to_le_bytes());
        bytes[212..220].copy_from_slice(&2u64.to_le_bytes());
        bytes[220..252].fill(0x92);
        ExposurePermitV1::from_durable_bytes(&bytes).expect("permit")
    }

    #[test]
    fn ratified_kdf_changes_with_every_bound_field() {
        let share = secret(0x07);
        let aux = [0x09; 32];
        let base = context(
            &share,
            0,
            PurposeV1::Refund,
            DirectionV1::Initiator,
            SigningPhaseV1::SigNonceCommit,
            [1; 32],
        );
        let binding = reservation(10);
        let pair =
            SecretNoncePairV1::derive_with_aux_for_test(base.clone(), &share, binding.clone(), aux)
                .expect("base pair");
        let public = pair
            .authorize(permit(&base, &binding))
            .expect("authorized")
            .public_nonces()
            .clone();

        let variants = [
            context(
                &share,
                0,
                PurposeV1::Refund,
                DirectionV1::Responder,
                SigningPhaseV1::SigNonceCommit,
                [1; 32],
            ),
            context(
                &share,
                0,
                PurposeV1::Refund,
                DirectionV1::Initiator,
                SigningPhaseV1::SigNonceReveal,
                [1; 32],
            ),
            context(
                &share,
                0,
                PurposeV1::Refund,
                DirectionV1::Initiator,
                SigningPhaseV1::SigNonceCommit,
                [2; 32],
            ),
        ];
        for (index, variant) in variants.into_iter().enumerate() {
            let binding = reservation(20 + index as u8);
            let variant_public = SecretNoncePairV1::derive_with_aux_for_test(
                variant.clone(),
                &share,
                binding.clone(),
                aux,
            )
            .expect("variant pair")
            .authorize(permit(&variant, &binding))
            .expect("authorized")
            .public_nonces()
            .clone();
            assert_ne!(variant_public, public, "variant {index}");
        }
    }

    #[test]
    fn ratified_kdf_separates_nonce_index_aux_share_and_context_fields() {
        fn derive_public(
            share: &ScriptlessSecretScalar,
            aux: &[u8; 32],
            context_bytes: &[u8],
        ) -> PublicNoncePairV1 {
            let (first, second) = scriptless_derive_secret_nonce_pair_v1(share, aux, context_bytes)
                .expect("fixture does not reduce to zero");
            PublicNoncePairV1 {
                first: first.public_key(),
                second: second.public_key(),
            }
        }

        let share = secret(0x07);
        let context = context(
            &share,
            0,
            PurposeV1::Refund,
            DirectionV1::Initiator,
            SigningPhaseV1::SigNonceCommit,
            [1; 32],
        );
        let canonical = context.to_bytes();
        let base = derive_public(&share, &[9; 32], &canonical);
        assert_ne!(base.first(), base.second(), "k1 and k2 are separated");

        let mutations = [
            (66usize, 0x03u8),
            (67, 0x02),
            (68, 0x01),
            (34, 0x02),
            (70, 0x12),
            (102, 0x13),
            (134, 0x14),
            (166, 0x01),
        ];
        for (offset, value) in mutations {
            let mut changed = canonical.clone();
            changed[offset] = value;
            let changed = derive_public(&share, &[9; 32], &changed);
            assert_ne!(changed.first(), base.first(), "first nonce offset {offset}");
            assert_ne!(
                changed.second(),
                base.second(),
                "second nonce offset {offset}"
            );
        }

        let changed_aux = derive_public(&share, &[10; 32], &canonical);
        assert_ne!(changed_aux.first(), base.first());
        assert_ne!(changed_aux.second(), base.second());
        let changed_share = derive_public(&secret(0x08), &[9; 32], &canonical);
        assert_ne!(changed_share.first(), base.first());
        assert_ne!(changed_share.second(), base.second());
    }

    #[test]
    fn authorization_is_exact_and_nonce_pair_is_one_shot() {
        let share = secret(0x07);
        let context = context(
            &share,
            0,
            PurposeV1::Refund,
            DirectionV1::Initiator,
            SigningPhaseV1::SigNonceCommit,
            [1; 32],
        );
        let binding = reservation(10);
        let pair = SecretNoncePairV1::derive_with_aux_for_test(
            context.clone(),
            &share,
            binding.clone(),
            [9; 32],
        )
        .expect("pair");
        assert_ne!(pair.commitment().expect("commitment"), Hash256::ZERO);
        let wrong = permit_with_nonce(&context, &binding, [99; 32]);
        assert_eq!(
            pair.authorize(wrong).err().expect("mismatch"),
            AdaptorError::AuthorizationMismatch
        );
    }

    #[test]
    fn production_derivation_uses_fresh_operating_system_randomness() {
        let share = secret(0x07);
        let context = context(
            &share,
            0,
            PurposeV1::Refund,
            DirectionV1::Initiator,
            SigningPhaseV1::SigNonceCommit,
            [1; 32],
        );
        let first = SecretNoncePairV1::derive(context.clone(), &share, reservation(30))
            .expect("first OS-random pair")
            .commitment()
            .expect("first commitment");
        let second = SecretNoncePairV1::derive(context, &share, reservation(30))
            .expect("second OS-random pair")
            .commitment()
            .expect("second commitment");
        assert_ne!(first, second);
    }

    #[test]
    fn two_participant_claim_workflow_passes_real_dom_verifier() {
        let share_a = secret(0x07);
        let share_b = small_secret(0x03);
        let context_a = context(
            &share_a,
            0,
            PurposeV1::ClaimAdaptor,
            DirectionV1::Initiator,
            SigningPhaseV1::SigPartial,
            [2; 32],
        );
        let context_b = context(
            &share_b,
            1,
            PurposeV1::ClaimAdaptor,
            DirectionV1::Initiator,
            SigningPhaseV1::SigPartial,
            [2; 32],
        );
        let reservation_a = reservation(10);
        let reservation_b = reservation(20);
        let pair_a = SecretNoncePairV1::derive_with_aux_for_test(
            context_a.clone(),
            &share_a,
            reservation_a.clone(),
            [9; 32],
        )
        .expect("pair A");
        let pair_b = SecretNoncePairV1::derive_with_aux_for_test(
            context_b.clone(),
            &share_b,
            reservation_b.clone(),
            [10; 32],
        )
        .expect("pair B");
        let authorized_a = pair_a
            .authorize(permit(&context_a, &reservation_a))
            .expect("authorize A");
        let authorized_b = pair_b
            .authorize(permit(&context_b, &reservation_b))
            .expect("authorize B");
        let public_a = authorized_a.public_nonces().clone();
        let public_b = authorized_b.public_nonces().clone();
        let adaptor_secret = AdaptorSecret::from_be_bytes({
            let mut value = [0u8; 32];
            value[31] = 5;
            value
        })
        .expect("adaptor secret");
        let adaptor_point = adaptor_secret.public_point();
        let participants = vec![
            ParticipantPublicNoncesV1 {
                participant_index: 0,
                signing_key: share_a.public_key(),
                first_nonce: public_a.first().clone(),
                second_nonce: public_a.second().clone(),
            },
            ParticipantPublicNoncesV1 {
                participant_index: 1,
                signing_key: share_b.public_key(),
                first_nonce: public_b.first().clone(),
                second_nonce: public_b.second().clone(),
            },
        ];
        let binding_factor = binding_factor_v1(
            &BindingContextV1 {
                chain_id: *context_a.chain_id(),
                session_id: *context_a.session_id(),
                purpose: context_a.purpose(),
                template_hash: *context_a.template_hash(),
            },
            &participants,
            Some(&adaptor_point),
        )
        .expect("binding factor");
        let bound_a = public_a.bind(&binding_factor).expect("bound A");
        let bound_b = public_b.bind(&binding_factor).expect("bound B");
        let aggregate_nonce =
            aggregate_public_nonces_v1(&[bound_a.clone(), bound_b.clone()]).expect("R");
        let aggregate_nonce_hat =
            aggregate_public_nonces_v1(&[aggregate_nonce, adaptor_point.clone()]).expect("R_hat");
        let aggregate_key = schnorr_add_public_keys(&[share_a.public_key(), share_b.public_key()])
            .expect("aggregate key");
        let partial_a = authorized_a
            .sign_partial(
                &binding_factor,
                &aggregate_nonce_hat,
                &aggregate_key,
                &share_a,
                context_a.chain_id(),
                context_a.message_digest(),
            )
            .expect("partial A");
        let partial_b = authorized_b
            .sign_partial(
                &binding_factor,
                &aggregate_nonce_hat,
                &aggregate_key,
                &share_b,
                context_b.chain_id(),
                context_b.message_digest(),
            )
            .expect("partial B");
        assert!(partial_a
            .verify_bound(
                PurposeV1::ClaimAdaptor,
                context_a.template_hash(),
                &bound_a,
                &share_a.public_key(),
                &aggregate_nonce_hat,
                &aggregate_key,
                context_a.chain_id(),
                context_a.message_digest(),
            )
            .expect("verify A"));
        assert!(partial_b
            .verify_bound(
                PurposeV1::ClaimAdaptor,
                context_b.template_hash(),
                &bound_b,
                &share_b.public_key(),
                &aggregate_nonce_hat,
                &aggregate_key,
                context_b.chain_id(),
                context_b.message_digest(),
            )
            .expect("verify B"));
        let scalar_hat = aggregate_partial_signatures_v1(
            &[partial_a, partial_b],
            PurposeV1::ClaimAdaptor,
            context_a.template_hash(),
        )
        .expect("aggregate partials");
        let pre_signature = AdaptorPreSignatureV1::new(
            *context_a.template_hash(),
            adaptor_point,
            aggregate_nonce_hat,
            scalar_hat,
            *context_a.transcript_hash(),
        );
        assert!(pre_signature
            .verify(
                context_a.template_hash(),
                context_a.transcript_hash(),
                &aggregate_key,
                context_a.chain_id(),
                context_a.message_digest(),
            )
            .expect("pre-signature"));
        let final_signature = pre_signature
            .adapt(
                &adaptor_secret,
                context_a.template_hash(),
                context_a.transcript_hash(),
                &aggregate_key,
                context_a.chain_id(),
                context_a.message_digest(),
            )
            .expect("adapted signature");
        let extracted = pre_signature
            .extract(
                &final_signature,
                context_a.template_hash(),
                context_a.transcript_hash(),
                &aggregate_key,
                context_a.chain_id(),
                context_a.message_digest(),
            )
            .expect("extracted secret");
        assert_eq!(extracted.public_point(), adaptor_secret.public_point());
    }

    #[test]
    fn funding_and_refund_two_nonce_workflows_pass_real_dom_verifier() {
        for (case, purpose) in [PurposeV1::Funding, PurposeV1::Refund]
            .into_iter()
            .enumerate()
        {
            let share_a = secret(0x07);
            let share_b = small_secret(0x03);
            let session_id = [30 + case as u8; 32];
            let context_a = context(
                &share_a,
                0,
                purpose,
                DirectionV1::Initiator,
                SigningPhaseV1::SigPartial,
                session_id,
            );
            let context_b = context(
                &share_b,
                1,
                purpose,
                DirectionV1::Initiator,
                SigningPhaseV1::SigPartial,
                session_id,
            );
            let reservation_a = reservation(40 + case as u8 * 4);
            let reservation_b = reservation(42 + case as u8 * 4);
            let authorized_a = SecretNoncePairV1::derive_with_aux_for_test(
                context_a.clone(),
                &share_a,
                reservation_a.clone(),
                [50 + case as u8; 32],
            )
            .expect("pair A")
            .authorize(permit(&context_a, &reservation_a))
            .expect("authorize A");
            let authorized_b = SecretNoncePairV1::derive_with_aux_for_test(
                context_b.clone(),
                &share_b,
                reservation_b.clone(),
                [60 + case as u8; 32],
            )
            .expect("pair B")
            .authorize(permit(&context_b, &reservation_b))
            .expect("authorize B");
            let public_a = authorized_a.public_nonces().clone();
            let public_b = authorized_b.public_nonces().clone();
            let participants = vec![
                ParticipantPublicNoncesV1 {
                    participant_index: 0,
                    signing_key: share_a.public_key(),
                    first_nonce: public_a.first().clone(),
                    second_nonce: public_a.second().clone(),
                },
                ParticipantPublicNoncesV1 {
                    participant_index: 1,
                    signing_key: share_b.public_key(),
                    first_nonce: public_b.first().clone(),
                    second_nonce: public_b.second().clone(),
                },
            ];
            let binding_factor = binding_factor_v1(
                &BindingContextV1 {
                    chain_id: *context_a.chain_id(),
                    session_id: *context_a.session_id(),
                    purpose,
                    template_hash: *context_a.template_hash(),
                },
                &participants,
                None,
            )
            .expect("binding factor");
            let bound_a = public_a.bind(&binding_factor).expect("bound A");
            let bound_b = public_b.bind(&binding_factor).expect("bound B");
            let aggregate_nonce =
                aggregate_public_nonces_v1(&[bound_a, bound_b]).expect("aggregate nonce");
            let aggregate_key =
                schnorr_add_public_keys(&[share_a.public_key(), share_b.public_key()])
                    .expect("aggregate key");
            let partial_a = authorized_a
                .sign_partial(
                    &binding_factor,
                    &aggregate_nonce,
                    &aggregate_key,
                    &share_a,
                    context_a.chain_id(),
                    context_a.message_digest(),
                )
                .expect("partial A");
            let partial_b = authorized_b
                .sign_partial(
                    &binding_factor,
                    &aggregate_nonce,
                    &aggregate_key,
                    &share_b,
                    context_b.chain_id(),
                    context_b.message_digest(),
                )
                .expect("partial B");
            let signature = finalize_plain_signature_v1(
                &[partial_a, partial_b],
                purpose,
                context_a.template_hash(),
                &aggregate_nonce,
                &aggregate_key,
                context_a.chain_id(),
                context_a.message_digest(),
            )
            .expect("real DOM signature");
            assert_eq!(
                signature.r_compressed(),
                &aggregate_nonce.to_compressed_bytes()
            );
        }
    }
}

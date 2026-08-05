//! Opaque one-shot secret two-nonce ownership and participant signing.
#![allow(
    dead_code,
    reason = "NAR-002 keeps secret/export capabilities crate-sealed until G1b integration"
)]

use crate::permit::ExposurePermitV1;
use crate::{
    exposure_outbound_digest_v1, nonce_commitment_hash_v1, ExposureKindV1, NonceCommitmentV1,
    NonceRevealV1, SessionContextV1,
};
use crate::{AdaptorError, BindingFactorV1, PartialSignatureV1, PurposeV1, Result};
use dom_crypto::{
    schnorr_aggregate_sigs, scriptless_add_public_points, scriptless_aggregate_partial_scalars,
    scriptless_verify_final_signature, PartialSig, PublicKey, SchnorrSignature,
};
use dom_crypto::{
    schnorr_challenge, Hash256, ScriptlessNonceDerivationV1, ScriptlessSecretNoncePairV1,
    ScriptlessSecretScalar,
};

/// Public identifiers durably bound to a reserved nonce before derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NonceReservationBindingV1 {
    nonce_id: [u8; 32],
    participant_id: [u8; 32],
}

impl NonceReservationBindingV1 {
    /// Construct a reservation binding from nonzero canonical identifiers.
    pub(crate) fn new(nonce_id: [u8; 32], participant_id: [u8; 32]) -> Result<Self> {
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
        })
    }

    /// Return the nonce identifier.
    pub(crate) const fn nonce_id(&self) -> &[u8; 32] {
        &self.nonce_id
    }
    /// Return the participant identifier.
    pub(crate) const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }
}

/// Canonical public two-nonce pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicNoncePairV1 {
    first: PublicKey,
    second: PublicKey,
}

impl PublicNoncePairV1 {
    pub(crate) const fn new(first: PublicKey, second: PublicKey) -> Self {
        Self { first, second }
    }
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
    secret_pair: ScriptlessSecretNoncePairV1,
    public: PublicNoncePairV1,
    context: SessionContextV1,
    reservation: NonceReservationBindingV1,
    effective_retry_counter: u64,
    commitment_exported: bool,
}

impl SecretNoncePairV1 {
    /// Derive a fresh pair from the operating-system CSPRNG.
    pub(crate) fn derive(
        context: SessionContextV1,
        signing_share: &ScriptlessSecretScalar,
        reservation: NonceReservationBindingV1,
    ) -> Result<Self> {
        let derivation = ScriptlessNonceDerivationV1::from_os_rng()
            .map_err(|_| AdaptorError::RandomnessFailure)?;
        Self::derive_with_state(context, signing_share, reservation, &derivation)
    }

    fn derive_with_state(
        context: SessionContextV1,
        signing_share: &ScriptlessSecretScalar,
        reservation: NonceReservationBindingV1,
        derivation: &ScriptlessNonceDerivationV1,
    ) -> Result<Self> {
        let mut retry_counter = context.retry_counter();
        loop {
            let context_bytes = context.encode_with_retry_counter(retry_counter);
            if let Some(secret_pair) = derivation.derive_pair(signing_share, &context_bytes) {
                let (first, second) = secret_pair.public_keys();
                let public = PublicNoncePairV1 { first, second };
                return Ok(Self {
                    secret_pair,
                    public,
                    context,
                    reservation,
                    effective_retry_counter: retry_counter,
                    commitment_exported: false,
                });
            }
            retry_counter = retry_counter
                .checked_add(1)
                .ok_or(AdaptorError::RetryCounterOverflow)?;
        }
    }

    /// Return the retry counter that produced this pair. This is public state,
    /// not nonce material.
    pub(crate) const fn effective_retry_counter(&self) -> u64 {
        self.effective_retry_counter
    }

    /// Compute the public nonce commitment without exposing either point.
    fn commitment_hash(&self) -> Result<Hash256> {
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

    fn commitment_payload(&self) -> Result<NonceCommitmentV1> {
        Ok(NonceCommitmentV1::new(
            self.context.purpose(),
            self.context.participant_index(),
            *self.commitment_hash()?.as_bytes(),
        ))
    }

    /// Export exactly one commitment after a matching durable permit.
    pub(crate) fn export_commitment(
        &mut self,
        permit: ExposurePermitV1,
    ) -> Result<NonceCommitmentV1> {
        if self.commitment_exported {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let payload = self.commitment_payload()?;
        let digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceCommitment, &payload.to_bytes())?;
        if !self.permit_matches(&permit, ExposureKindV1::NonceCommitment, digest.as_bytes()) {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        self.commitment_exported = true;
        Ok(payload)
    }

    fn permit_matches(
        &self,
        permit: &ExposurePermitV1,
        kind: ExposureKindV1,
        outbound_digest: &[u8; 32],
    ) -> bool {
        permit.exposure_kind() == kind
            && permit.reservation_nonce_id() == self.reservation.nonce_id()
            && permit.session_id() == self.context.session_id()
            && permit.participant_id() == self.reservation.participant_id()
            && permit.purpose() == self.context.purpose()
            && permit.template_hash() == self.context.template_hash()
            && permit.outbound_digest() == outbound_digest
    }

    /// Consume this pre-authorization pair and bind it to one durable permit.
    pub(crate) fn authorize_reveal(
        self,
        permit: ExposurePermitV1,
    ) -> Result<AuthorizedSecretNoncePairV1> {
        if !self.commitment_exported {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let reveal = NonceRevealV1::new(
            self.context.purpose(),
            self.context.participant_index(),
            self.public.first.clone(),
            self.public.second.clone(),
        );
        let digest = exposure_outbound_digest_v1(ExposureKindV1::NonceReveal, &reveal.to_bytes())?;
        if !self.permit_matches(&permit, ExposureKindV1::NonceReveal, digest.as_bytes()) {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(AuthorizedSecretNoncePairV1 {
            pair: self,
            _permit: permit,
            reveal: Some(reveal),
        })
    }

    #[cfg(test)]
    fn derive_with_aux_for_test(
        context: SessionContextV1,
        signing_share: &ScriptlessSecretScalar,
        reservation: NonceReservationBindingV1,
        aux_rand_32: [u8; 32],
    ) -> Result<Self> {
        let derivation = ScriptlessNonceDerivationV1::from_aux_for_test(aux_rand_32);
        Self::derive_with_state(context, signing_share, reservation, &derivation)
    }
}

/// Opaque pair after durable authorization; public export and one partial-sign
/// operation are now available. Partial signing consumes this value.
pub struct AuthorizedSecretNoncePairV1 {
    pair: SecretNoncePairV1,
    _permit: ExposurePermitV1,
    reveal: Option<NonceRevealV1>,
}

impl AuthorizedSecretNoncePairV1 {
    /// Export the exact authorized public nonce pair.
    pub(crate) fn take_public_nonces(&mut self) -> Result<PublicNoncePairV1> {
        self.reveal
            .take()
            .map(|reveal| PublicNoncePairV1 {
                first: reveal.first().clone(),
                second: reveal.second().clone(),
            })
            .ok_or(AdaptorError::AuthorizationMismatch)
    }

    /// Consume the nonce pair and produce exactly one participant-bound partial.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sign_partial(
        self,
        binding_factor: &BindingFactorV1,
        aggregate_nonce_hat: &PublicKey,
        aggregate_signing_key: &PublicKey,
        signing_share: &ScriptlessSecretScalar,
        chain_id: &[u8; 32],
        kernel_message_digest: &[u8; 32],
    ) -> Result<PreparedPartialSignatureV1> {
        if self.reveal.is_some() {
            return Err(AdaptorError::AuthorizationMismatch);
        }
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
        let partial = self.pair.secret_pair.sign_bound_partial(
            &binding,
            challenge.as_bytes(),
            signing_share,
        )?;
        Ok(PreparedPartialSignatureV1 {
            partial: PartialSignatureV1::new(
                self.pair.context.purpose(),
                self.pair.context.participant_index(),
                *self.pair.context.template_hash(),
                partial,
            ),
            nonce_id: *self.pair.reservation.nonce_id(),
            session_id: *self.pair.context.session_id(),
            participant_id: *self.pair.reservation.participant_id(),
        })
    }
}

/// Prepared partial signature that remains unexportable until a distinct
/// durable partial-signature permit is consumed.
pub(crate) struct PreparedPartialSignatureV1 {
    partial: PartialSignatureV1,
    nonce_id: [u8; 32],
    session_id: [u8; 32],
    participant_id: [u8; 32],
}

impl PreparedPartialSignatureV1 {
    pub(crate) fn outbound_digest(&self) -> Result<Hash256> {
        exposure_outbound_digest_v1(ExposureKindV1::PartialSignature, &self.partial.to_bytes())
    }

    pub(crate) fn authorize_export(self, permit: ExposurePermitV1) -> Result<PartialSignatureV1> {
        let digest = self.outbound_digest()?;
        let matches = permit.exposure_kind() == ExposureKindV1::PartialSignature
            && permit.reservation_nonce_id() == &self.nonce_id
            && permit.session_id() == &self.session_id
            && permit.participant_id() == &self.participant_id
            && permit.purpose() == self.partial.purpose()
            && permit.template_hash() == self.partial.template_hash()
            && permit.outbound_digest() == digest.as_bytes();
        if !matches {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(self.partial)
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
        NonceReservationBindingV1::new([byte; 32], [byte + 1; 32]).expect("binding")
    }

    fn permit(
        context: &SessionContextV1,
        reservation: &NonceReservationBindingV1,
        kind: ExposureKindV1,
        outbound_digest: [u8; 32],
    ) -> ExposurePermitV1 {
        permit_with_nonce(
            context,
            reservation,
            kind,
            outbound_digest,
            *reservation.nonce_id(),
        )
    }

    fn permit_with_nonce(
        context: &SessionContextV1,
        reservation: &NonceReservationBindingV1,
        kind: ExposureKindV1,
        outbound_digest: [u8; 32],
        nonce_id: [u8; 32],
    ) -> ExposurePermitV1 {
        let mut bytes = [0u8; ExposurePermitV1::ENCODED_LEN];
        bytes[..8].copy_from_slice(b"DOMEXPV1");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10] = kind.to_byte();
        bytes[11..43].fill(0x91);
        bytes[43..75].copy_from_slice(&nonce_id);
        bytes[75..107].copy_from_slice(context.session_id());
        bytes[107..139].copy_from_slice(reservation.participant_id());
        bytes[139] = context.purpose().to_byte();
        bytes[140..172].copy_from_slice(context.template_hash());
        bytes[172..204].copy_from_slice(&outbound_digest);
        bytes[204..212].copy_from_slice(&1u64.to_le_bytes());
        bytes[212..220].copy_from_slice(&2u64.to_le_bytes());
        bytes[220..252].fill(0x92);
        ExposurePermitV1::from_durable_bytes(&bytes).expect("permit")
    }

    fn authorize_reveal_for_test(
        mut pair: SecretNoncePairV1,
        context: &SessionContextV1,
        reservation: &NonceReservationBindingV1,
    ) -> (AuthorizedSecretNoncePairV1, PublicNoncePairV1) {
        let commitment = pair.commitment_payload().expect("commitment");
        let commitment_digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceCommitment, &commitment.to_bytes())
                .expect("commitment digest");
        pair.export_commitment(permit(
            context,
            reservation,
            ExposureKindV1::NonceCommitment,
            *commitment_digest.as_bytes(),
        ))
        .expect("commitment authorization");

        let reveal = NonceRevealV1::new(
            context.purpose(),
            context.participant_index(),
            pair.public.first.clone(),
            pair.public.second.clone(),
        );
        let reveal_digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceReveal, &reveal.to_bytes())
                .expect("reveal digest");
        let mut authorized = pair
            .authorize_reveal(permit(
                context,
                reservation,
                ExposureKindV1::NonceReveal,
                *reveal_digest.as_bytes(),
            ))
            .expect("reveal authorization");
        let public = authorized.take_public_nonces().expect("one reveal");
        assert_eq!(
            authorized
                .take_public_nonces()
                .expect_err("second reveal must fail"),
            AdaptorError::AuthorizationMismatch
        );
        (authorized, public)
    }

    fn authorize_partial_for_test(
        prepared: PreparedPartialSignatureV1,
        context: &SessionContextV1,
        reservation: &NonceReservationBindingV1,
    ) -> PartialSignatureV1 {
        let digest = prepared.outbound_digest().expect("partial digest");
        prepared
            .authorize_export(permit(
                context,
                reservation,
                ExposureKindV1::PartialSignature,
                *digest.as_bytes(),
            ))
            .expect("partial authorization")
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
        let (_, public) = authorize_reveal_for_test(pair, &base, &binding);

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
            let pair = SecretNoncePairV1::derive_with_aux_for_test(
                variant.clone(),
                &share,
                binding.clone(),
                aux,
            )
            .expect("variant pair");
            let (_, variant_public) = authorize_reveal_for_test(pair, &variant, &binding);
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
            let derivation = ScriptlessNonceDerivationV1::from_aux_for_test(*aux);
            let pair = derivation
                .derive_pair(share, context_bytes)
                .expect("fixture does not reduce to zero");
            let (first, second) = pair.public_keys();
            PublicNoncePairV1 { first, second }
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
        let uncommitted = SecretNoncePairV1::derive_with_aux_for_test(
            context.clone(),
            &share,
            binding.clone(),
            [8; 32],
        )
        .expect("uncommitted pair");
        let premature_reveal = NonceRevealV1::new(
            context.purpose(),
            context.participant_index(),
            uncommitted.public.first.clone(),
            uncommitted.public.second.clone(),
        );
        let premature_digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceReveal, &premature_reveal.to_bytes())
                .expect("premature digest");
        assert_eq!(
            uncommitted
                .authorize_reveal(permit(
                    &context,
                    &binding,
                    ExposureKindV1::NonceReveal,
                    *premature_digest.as_bytes(),
                ))
                .err()
                .expect("reveal before commitment"),
            AdaptorError::AuthorizationMismatch
        );
        let mut pair = SecretNoncePairV1::derive_with_aux_for_test(
            context.clone(),
            &share,
            binding.clone(),
            [9; 32],
        )
        .expect("pair");
        let commitment = pair.commitment_payload().expect("commitment");
        let commitment_digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceCommitment, &commitment.to_bytes())
                .expect("commitment digest");
        pair.export_commitment(permit(
            &context,
            &binding,
            ExposureKindV1::NonceCommitment,
            *commitment_digest.as_bytes(),
        ))
        .expect("commitment export");
        assert_eq!(
            pair.export_commitment(permit(
                &context,
                &binding,
                ExposureKindV1::NonceCommitment,
                *commitment_digest.as_bytes(),
            ))
            .expect_err("second commitment export"),
            AdaptorError::AuthorizationMismatch
        );
        let reveal = NonceRevealV1::new(
            context.purpose(),
            context.participant_index(),
            pair.public.first.clone(),
            pair.public.second.clone(),
        );
        let reveal_digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceReveal, &reveal.to_bytes())
                .expect("reveal digest");
        let wrong = permit_with_nonce(
            &context,
            &binding,
            ExposureKindV1::NonceReveal,
            *reveal_digest.as_bytes(),
            [99; 32],
        );
        assert_eq!(
            pair.authorize_reveal(wrong).err().expect("mismatch"),
            AdaptorError::AuthorizationMismatch
        );

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[31] = 1;
        let make_prepared = || PreparedPartialSignatureV1 {
            partial: PartialSignatureV1::new(
                context.purpose(),
                context.participant_index(),
                *context.template_hash(),
                PartialSig::from_bytes(&scalar_bytes).expect("partial scalar"),
            ),
            nonce_id: *binding.nonce_id(),
            session_id: *context.session_id(),
            participant_id: *binding.participant_id(),
        };
        let prepared = make_prepared();
        let partial_digest = prepared.outbound_digest().expect("partial digest");
        let wrong_kind = permit(
            &context,
            &binding,
            ExposureKindV1::NonceReveal,
            *partial_digest.as_bytes(),
        );
        assert_eq!(
            prepared
                .authorize_export(wrong_kind)
                .err()
                .expect("wrong partial permit kind"),
            AdaptorError::AuthorizationMismatch
        );
        assert!(make_prepared()
            .authorize_export(permit(
                &context,
                &binding,
                ExposureKindV1::PartialSignature,
                *partial_digest.as_bytes(),
            ))
            .is_ok());
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
            .commitment_hash()
            .expect("first commitment");
        let second = SecretNoncePairV1::derive(context, &share, reservation(30))
            .expect("second OS-random pair")
            .commitment_hash()
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
        let (authorized_a, public_a) =
            authorize_reveal_for_test(pair_a, &context_a, &reservation_a);
        let (authorized_b, public_b) =
            authorize_reveal_for_test(pair_b, &context_b, &reservation_b);
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
        let prepared_a = authorized_a
            .sign_partial(
                &binding_factor,
                &aggregate_nonce_hat,
                &aggregate_key,
                &share_a,
                context_a.chain_id(),
                context_a.message_digest(),
            )
            .expect("prepared partial A");
        let prepared_b = authorized_b
            .sign_partial(
                &binding_factor,
                &aggregate_nonce_hat,
                &aggregate_key,
                &share_b,
                context_b.chain_id(),
                context_b.message_digest(),
            )
            .expect("prepared partial B");
        let partial_a = authorize_partial_for_test(prepared_a, &context_a, &reservation_a);
        let partial_b = authorize_partial_for_test(prepared_b, &context_b, &reservation_b);
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
            let pair_a = SecretNoncePairV1::derive_with_aux_for_test(
                context_a.clone(),
                &share_a,
                reservation_a.clone(),
                [50 + case as u8; 32],
            )
            .expect("pair A");
            let pair_b = SecretNoncePairV1::derive_with_aux_for_test(
                context_b.clone(),
                &share_b,
                reservation_b.clone(),
                [60 + case as u8; 32],
            )
            .expect("pair B");
            let (authorized_a, public_a) =
                authorize_reveal_for_test(pair_a, &context_a, &reservation_a);
            let (authorized_b, public_b) =
                authorize_reveal_for_test(pair_b, &context_b, &reservation_b);
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
            let prepared_a = authorized_a
                .sign_partial(
                    &binding_factor,
                    &aggregate_nonce,
                    &aggregate_key,
                    &share_a,
                    context_a.chain_id(),
                    context_a.message_digest(),
                )
                .expect("prepared partial A");
            let prepared_b = authorized_b
                .sign_partial(
                    &binding_factor,
                    &aggregate_nonce,
                    &aggregate_key,
                    &share_b,
                    context_b.chain_id(),
                    context_b.message_digest(),
                )
                .expect("prepared partial B");
            let partial_a = authorize_partial_for_test(prepared_a, &context_a, &reservation_a);
            let partial_b = authorize_partial_for_test(prepared_b, &context_b, &reservation_b);
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

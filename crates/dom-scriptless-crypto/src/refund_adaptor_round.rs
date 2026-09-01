//! Two-nonce Refund adaptor composition over the pinned DOM backend.
//!
//! # Why this exists
//!
//! The Claim adaptor round makes a DOM claim reveal a witness. That is what
//! binds a cross-curve leg: the counterparty claims DOM, the witness appears on
//! chain, and the party waiting on the other chain can finally act.
//!
//! The refund direction had no such round. `PurposeV1::Refund` is the plain
//! timelock refund and reveals nothing, so a route whose claim never happened
//! left the other side with no enforceable recovery — for a Monero leg, funds
//! sitting in a shared output that no timelock can open, because Monero has no
//! script that could carry one.
//!
//! This module is the mirror. It composes the same pinned primitives under
//! [`PurposeV1::RefundAdaptor`], so completing a refund exposes the refund
//! witness exactly as completing a claim exposes the claim witness:
//!
//! ```text
//!   claim  round :  DOM claim  reveals  t   (PurposeV1::ClaimAdaptor  = 0x02)
//!   refund round :  DOM refund reveals  u   (PurposeV1::RefundAdaptor = 0x05)
//! ```
//!
//! With both paths adaptor-bound exactly one completes, and either completion
//! teaches the waiting party the share they lacked. Neither party can take both
//! legs, and neither can strand the other.
//!
//! # The frozen relation between `R`, `U` and `R̂`
//!
//! Identical to the claim round, and for the same reason: these are the pinned
//! equations, named by the pinned function that computes them.
//!
//! ```text
//! R_i = R1_i + R2_i · b     dom_scriptless_primitives::scriptless_bind_public_nonces
//! R   = Σ R_i               dom_adaptor::aggregate_public_nonces_v1
//! R̂   = R + U               dom_adaptor::aggregate_public_nonces_v1([R, U])
//! ```
//!
//! `b` is [`dom_adaptor::binding_factor_v1`], which commits to the chain
//! identifier, session identifier, **purpose**, template hash, the ordered
//! signing keys, the ordered nonce pairs, and the adaptor point. Because the
//! purpose is inside the transcript, a refund round and a claim round over
//! otherwise identical inputs derive different binding factors, and a partial
//! signature produced for one does not satisfy the other.
//!
//! # Nonces must not be shared with the claim round
//!
//! This is the sharpest requirement in the module, and it is a property of
//! Schnorr, not a policy choice. Two signatures over the same nonce with
//! different challenges expose the signing key by subtraction. The claim round
//! and the refund round are two signatures by the same participants over the
//! same aggregate key, so **a participant that reuses a nonce pair across the
//! two rounds leaks its share**.
//!
//! [`RefundAdaptorRoundV1::require_nonces_distinct_from_claim`] refuses a
//! roster that reuses any published nonce from the claim round. It is the
//! caller's duty to invoke it whenever both rounds exist for one settlement;
//! this module cannot see the claim round on its own.
//!
//! # The Stage 4 limit is preserved
//!
//! As in the claim round, the template hash and the transcript hash are
//! protocol provenance, not intrinsic cryptographic binding of the final
//! kernel signature. They are compared for equality; they are not inputs to
//! the challenge.
//!
//! # Boundaries
//!
//! Nothing here generates a nonce, and no public entry point accepts one
//! chosen by the caller: participants supply already-published public nonces,
//! and secret nonces never enter this module. Funding, broadcast, executor,
//! events, chain I/O and shared-output work are absent.
//!
//! [`CompletedRefundAdaptorCycleV1`] is not an authority token. It authorises
//! no mutation, no funding and no broadcast.
//!
//! ```text
//! PRODUCTION = NOT_AUTHORIZED
//! MAINNET = DISABLED
//! REAL_FUNDS = PROHIBITED
//! PHASE2 = NOT_AUTHORIZED
//! ```

use core::fmt;
use std::error::Error;

use dom_adaptor::{
    aggregate_partial_signatures_v1, aggregate_public_nonces_v1, binding_factor_v1,
    AdaptorPreSignatureV1, AdaptorSecret, BindingContextV1, PartialSignatureV1,
    ParticipantPublicNoncesV1, PurposeV1,
};
use dom_crypto::{PublicKey, SchnorrSignature};

/// Exactly two participants, as NAR-DC-P1-007 §3 ratified for this product.
pub const REFUND_ADAPTOR_PARTICIPANTS: usize = 2;

/// Canonical pre-signature payload length, the pinned
/// `dom_adaptor::AdaptorPreSignatureV1::ENCODED_LEN`.
pub const REFUND_ADAPTOR_PRE_SIGNATURE_LEN: usize = 162;

/// Everything the round is stated over.
///
/// The caller supplies published public values only. No secret, and in
/// particular no secret nonce, is accepted here.
pub struct RefundAdaptorRoundInputsV1<'a> {
    /// Chain identifier, session identifier, purpose and template hash, in the
    /// pinned binding-context form. The purpose must be
    /// [`PurposeV1::RefundAdaptor`].
    pub binding_context: BindingContextV1,
    /// The published nonce pairs, in canonical roster order.
    pub participants: &'a [ParticipantPublicNoncesV1],
    /// The refund adaptor point `U`.
    pub refund_adaptor_point: PublicKey,
    /// The aggregate signing key `X`.
    pub aggregate_signing_key: PublicKey,
    /// The session transcript hash.
    pub transcript_hash: [u8; 32],
    /// The 32-byte kernel message digest the DOM verifier signs over.
    pub kernel_message_digest: [u8; 32],
}

/// Why a Refund adaptor round was refused.
///
/// Every variant is a refusal. There is no variant meaning "accepted": the only
/// evidence of success is a value this module alone can issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RefundAdaptorRoundError {
    /// The purpose is not `RefundAdaptor`.
    ///
    /// In particular a plain `Refund` is refused here: it reveals nothing, and
    /// accepting it would produce a round that looks adaptor-bound and is not.
    WrongPurpose,
    /// The roster is not exactly two distinct participants in canonical order.
    NonCanonicalRoster,
    /// The chain identifier is all zero, which identifies no network.
    ZeroChainId,
    /// The pinned binding-factor transcript refused the inputs.
    BindingRefused,
    /// A public nonce or point is not canonical, or an aggregate is identity.
    NonCanonicalPoint,
    /// A nonce is shared with the claim round for the same settlement, which
    /// would expose the signing share.
    NonceReusedAcrossRounds,
    /// The refund adaptor point equals the claim adaptor point, so completing
    /// either round would reveal the other's witness.
    AdaptorPointCollision,
    /// The partial signature set does not match the roster one for one.
    PartialSetMismatch,
    /// A partial signature failed the pinned per-participant equation.
    PartialRejected,
    /// The pinned aggregation refused the partial set.
    AggregationRefused,
    /// The assembled pre-signature did not verify through the pinned verifier.
    PreSignatureRejected,
    /// Adaptation with the supplied secret did not produce a valid signature.
    AdaptationRejected,
    /// The final signature did not verify through the pinned DOM verifier.
    FinalSignatureRejected,
    /// Extraction did not return the refund secret that matches `U`.
    ExtractionRejected,
    /// The pinned backend could not complete and reached no verdict.
    BackendRefused,
}

impl fmt::Display for RefundAdaptorRoundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongPurpose => "the round purpose is not RefundAdaptor",
            Self::NonCanonicalRoster => "the participant roster is not canonical",
            Self::ZeroChainId => "the chain identifier is zero",
            Self::BindingRefused => "the pinned binding transcript refused the inputs",
            Self::NonCanonicalPoint => "a point is not canonical or aggregates to identity",
            Self::NonceReusedAcrossRounds => "a nonce is reused from the claim round",
            Self::AdaptorPointCollision => "the refund and claim adaptor points are equal",
            Self::PartialSetMismatch => "the partial set does not match the roster",
            Self::PartialRejected => "a partial signature failed its participant equation",
            Self::AggregationRefused => "the pinned aggregation refused the partial set",
            Self::PreSignatureRejected => "the assembled pre-signature did not verify",
            Self::AdaptationRejected => "adaptation did not produce a valid signature",
            Self::FinalSignatureRejected => "the final signature did not verify",
            Self::ExtractionRejected => "extraction did not return the secret matching U",
            Self::BackendRefused => "the pinned backend could not reach a verdict",
        })
    }
}

impl Error for RefundAdaptorRoundError {}

/// The derived public values of one Refund adaptor round.
pub struct RefundAdaptorRoundV1 {
    binding_factor: [u8; 32],
    participants: Vec<ParticipantPublicNoncesV1>,
    effective_nonces: Vec<PublicKey>,
    aggregate_nonce: PublicKey,
    aggregate_nonce_hat: PublicKey,
    refund_adaptor_point: PublicKey,
    aggregate_signing_key: PublicKey,
    chain_id: [u8; 32],
    template_hash: [u8; 32],
    transcript_hash: [u8; 32],
    kernel_message_digest: [u8; 32],
}

impl RefundAdaptorRoundV1 {
    /// The pinned binding factor `b`, as canonical big-endian bytes.
    #[must_use]
    pub const fn binding_factor(&self) -> &[u8; 32] {
        &self.binding_factor
    }

    /// The per-participant effective nonces `R_i`, in roster order.
    #[must_use]
    pub fn effective_nonces(&self) -> &[PublicKey] {
        &self.effective_nonces
    }

    /// The aggregate nonce `R`, before the refund adaptor point is added.
    #[must_use]
    pub const fn aggregate_nonce(&self) -> &PublicKey {
        &self.aggregate_nonce
    }

    /// The aggregate nonce `R̂ = R + U` the challenge is computed over.
    #[must_use]
    pub const fn aggregate_nonce_hat(&self) -> &PublicKey {
        &self.aggregate_nonce_hat
    }

    /// The refund adaptor point `U`.
    #[must_use]
    pub const fn refund_adaptor_point(&self) -> &PublicKey {
        &self.refund_adaptor_point
    }

    /// Refuse a roster that reuses any nonce published for the claim round, and
    /// a refund point equal to the claim point.
    ///
    /// Two signatures over one nonce with different challenges expose the
    /// signing key by subtraction, and the claim and refund rounds are exactly
    /// that pair. This module cannot see the claim round, so the caller must
    /// present it whenever both exist for one settlement.
    ///
    /// # Errors
    ///
    /// [`RefundAdaptorRoundError::NonceReusedAcrossRounds`] if any published
    /// nonce appears in both rosters, or
    /// [`RefundAdaptorRoundError::AdaptorPointCollision`] if the two adaptor
    /// points are equal.
    pub fn require_nonces_distinct_from_claim(
        &self,
        claim_participants: &[ParticipantPublicNoncesV1],
        claim_adaptor_point: &PublicKey,
    ) -> Result<(), RefundAdaptorRoundError> {
        if claim_adaptor_point.to_compressed_bytes()
            == self.refund_adaptor_point.to_compressed_bytes()
        {
            return Err(RefundAdaptorRoundError::AdaptorPointCollision);
        }
        for refund in &self.participants {
            for claim in claim_participants {
                for refund_nonce in [&refund.first_nonce, &refund.second_nonce] {
                    for claim_nonce in [&claim.first_nonce, &claim.second_nonce] {
                        if refund_nonce.to_compressed_bytes() == claim_nonce.to_compressed_bytes() {
                            return Err(RefundAdaptorRoundError::NonceReusedAcrossRounds);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Derive the public round values with the pinned binding and aggregation.
///
/// # Errors
///
/// Returns the specific [`RefundAdaptorRoundError`] for the first unsatisfied
/// requirement. Nothing is computed locally: the binding factor, the nonce
/// binding and both aggregations are the pinned functions.
pub fn begin_refund_adaptor_round_v1(
    inputs: &RefundAdaptorRoundInputsV1<'_>,
) -> Result<RefundAdaptorRoundV1, RefundAdaptorRoundError> {
    if inputs.binding_context.purpose != PurposeV1::RefundAdaptor {
        return Err(RefundAdaptorRoundError::WrongPurpose);
    }
    if inputs.binding_context.chain_id == [0_u8; 32] {
        return Err(RefundAdaptorRoundError::ZeroChainId);
    }
    if inputs.participants.len() != REFUND_ADAPTOR_PARTICIPANTS {
        return Err(RefundAdaptorRoundError::NonCanonicalRoster);
    }

    // The pinned transcript enforces canonical ordering, uniqueness of signing
    // keys and uniqueness of nonces across participants, and commits to the
    // purpose — which is what separates this round from the claim round.
    let factor = binding_factor_v1(
        &inputs.binding_context,
        inputs.participants,
        Some(&inputs.refund_adaptor_point),
    )
    .map_err(|_| RefundAdaptorRoundError::BindingRefused)?;

    let mut effective_nonces = Vec::with_capacity(inputs.participants.len());
    for participant in inputs.participants {
        let bound = factor
            .bind_public_nonces(&participant.first_nonce, &participant.second_nonce)
            .map_err(|_| RefundAdaptorRoundError::NonCanonicalPoint)?;
        effective_nonces.push(bound);
    }

    let aggregate_nonce = aggregate_public_nonces_v1(&effective_nonces)
        .map_err(|_| RefundAdaptorRoundError::NonCanonicalPoint)?;

    // R_hat = R + U. The refund adaptor point is added here and subtracted
    // again by the pinned pre-signature verifier.
    let aggregate_nonce_hat =
        aggregate_public_nonces_v1(&[aggregate_nonce.clone(), inputs.refund_adaptor_point.clone()])
            .map_err(|_| RefundAdaptorRoundError::NonCanonicalPoint)?;

    Ok(RefundAdaptorRoundV1 {
        binding_factor: factor.to_be_bytes(),
        participants: inputs.participants.to_vec(),
        effective_nonces,
        aggregate_nonce,
        aggregate_nonce_hat,
        refund_adaptor_point: inputs.refund_adaptor_point.clone(),
        aggregate_signing_key: inputs.aggregate_signing_key.clone(),
        chain_id: inputs.binding_context.chain_id,
        template_hash: inputs.binding_context.template_hash,
        transcript_hash: inputs.transcript_hash,
        kernel_message_digest: inputs.kernel_message_digest,
    })
}

/// Opaque evidence that one full Refund adaptor cycle completed.
///
/// Issued only by [`RefundAdaptorRoundV1::complete_cycle_v1`]. The fields and
/// the constructor are private, and the type implements neither `Clone`,
/// `Copy`, `Debug`, `Default`, nor any serialization, so it cannot be forged,
/// copied, logged, or decoded.
///
/// It is evidence, not authority.
pub struct CompletedRefundAdaptorCycleV1 {
    final_signature: [u8; 65],
    refund_adaptor_point: [u8; 33],
    aggregate_nonce_hat: [u8; 33],
    revealed_refund_secret: [u8; 32],
}

impl CompletedRefundAdaptorCycleV1 {
    /// The finalized 65-byte DOM Schnorr signature.
    #[must_use]
    pub const fn final_signature(&self) -> &[u8; 65] {
        &self.final_signature
    }

    /// The refund adaptor point `U` the extracted secret was checked against.
    #[must_use]
    pub const fn refund_adaptor_point(&self) -> &[u8; 33] {
        &self.refund_adaptor_point
    }

    /// The aggregate nonce `R̂` the final signature is stated over.
    #[must_use]
    pub const fn aggregate_nonce_hat(&self) -> &[u8; 33] {
        &self.aggregate_nonce_hat
    }

    /// The refund witness this completed refund exposed.
    ///
    /// This is the value the whole round exists to produce: once the refund is
    /// on chain, any observer can extract it, and the party waiting on the
    /// other chain uses it to recover their leg. It is returned here because it
    /// is public the moment the refund is published — withholding it would not
    /// make it secret, only harder for the honest counterparty to act on.
    #[must_use]
    pub const fn revealed_refund_secret(&self) -> &[u8; 32] {
        &self.revealed_refund_secret
    }
}

impl RefundAdaptorRoundV1 {
    /// Verify every partial against its own participant, then aggregate.
    fn aggregate_checked_partials(
        &self,
        partials: &[PartialSignatureV1],
    ) -> Result<[u8; 32], RefundAdaptorRoundError> {
        if partials.len() != self.participants.len()
            || partials.len() != self.effective_nonces.len()
        {
            return Err(RefundAdaptorRoundError::PartialSetMismatch);
        }
        for (position, participant) in self.participants.iter().enumerate() {
            let partial = partials
                .get(position)
                .ok_or(RefundAdaptorRoundError::PartialSetMismatch)?;
            if partial.participant_index() != participant.participant_index {
                return Err(RefundAdaptorRoundError::PartialSetMismatch);
            }
            let bound = self
                .effective_nonces
                .get(position)
                .ok_or(RefundAdaptorRoundError::PartialSetMismatch)?;
            match partial.verify_bound(
                PurposeV1::RefundAdaptor,
                &self.template_hash,
                bound,
                &participant.signing_key,
                &self.aggregate_nonce_hat,
                &self.aggregate_signing_key,
                &self.chain_id,
                &self.kernel_message_digest,
            ) {
                Ok(true) => {}
                Ok(false) => return Err(RefundAdaptorRoundError::PartialRejected),
                Err(_) => return Err(RefundAdaptorRoundError::BackendRefused),
            }
        }
        let aggregate = aggregate_partial_signatures_v1(
            partials,
            PurposeV1::RefundAdaptor,
            &self.template_hash,
        )
        .map_err(|_| RefundAdaptorRoundError::AggregationRefused)?;
        Ok(aggregate.to_bytes())
    }

    /// Run the complete cycle: pre-sign, verify, adapt, verify natively,
    /// extract, and check `u·G == U`.
    ///
    /// # Errors
    ///
    /// Returns the specific [`RefundAdaptorRoundError`] for the first
    /// unsatisfied requirement. No path returns evidence without every pinned
    /// check having returned a positive verdict.
    pub fn complete_cycle_v1(
        &self,
        partials: &[PartialSignatureV1],
        adaptor_secret: &AdaptorSecret,
    ) -> Result<CompletedRefundAdaptorCycleV1, RefundAdaptorRoundError> {
        let scalar_hat = self.aggregate_checked_partials(partials)?;

        let scalar = dom_crypto::PartialSig::from_bytes(&scalar_hat)
            .map_err(|_| RefundAdaptorRoundError::AggregationRefused)?;
        let pre_signature = AdaptorPreSignatureV1::new(
            self.template_hash,
            self.refund_adaptor_point.clone(),
            self.aggregate_nonce_hat.clone(),
            scalar,
            self.transcript_hash,
        );

        // The pinned verifier owns the pre-signature equation. It is given the
        // bindings rather than deriving them.
        match pre_signature.verify(
            &self.template_hash,
            &self.transcript_hash,
            &self.aggregate_signing_key,
            &self.chain_id,
            &self.kernel_message_digest,
        ) {
            Ok(true) => {}
            Ok(false) => return Err(RefundAdaptorRoundError::PreSignatureRejected),
            Err(_) => return Err(RefundAdaptorRoundError::BackendRefused),
        }

        // Adapt through the pinned path, which verifies the resulting standard
        // DOM signature before returning it.
        let final_signature: SchnorrSignature = pre_signature
            .adapt(
                adaptor_secret,
                &self.template_hash,
                &self.transcript_hash,
                &self.aggregate_signing_key,
                &self.chain_id,
                &self.kernel_message_digest,
            )
            .map_err(|_| RefundAdaptorRoundError::AdaptationRejected)?;

        // Independent native DOM verification of the finalized 65 bytes.
        match dom_scriptless_primitives::scriptless_verify_final_signature(
            &final_signature,
            &self.aggregate_signing_key,
            &self.chain_id,
            &self.kernel_message_digest,
        ) {
            Ok(true) => {}
            Ok(false) => return Err(RefundAdaptorRoundError::FinalSignatureRejected),
            Err(_) => return Err(RefundAdaptorRoundError::BackendRefused),
        }

        // Extract and close the loop: u·G must equal U. This is the step that
        // makes the refund revealing: the same extraction any observer of the
        // published refund can perform.
        let extracted = pre_signature
            .extract(
                &final_signature,
                &self.template_hash,
                &self.transcript_hash,
                &self.aggregate_signing_key,
                &self.chain_id,
                &self.kernel_message_digest,
            )
            .map_err(|_| RefundAdaptorRoundError::ExtractionRejected)?;
        let recovered_point = extracted
            .public_point()
            .map_err(|_| RefundAdaptorRoundError::ExtractionRejected)?;
        if recovered_point.to_compressed_bytes() != self.refund_adaptor_point.to_compressed_bytes()
        {
            return Err(RefundAdaptorRoundError::ExtractionRejected);
        }

        // The same pinned extraction, returning the scalar as canonical
        // big-endian bytes in a zeroizing buffer. It is public by construction
        // once both signatures are known.
        let revealed = pre_signature
            .extract_revealed_secret_be_bytes(
                &final_signature,
                &self.template_hash,
                &self.transcript_hash,
                &self.aggregate_signing_key,
                &self.chain_id,
                &self.kernel_message_digest,
            )
            .map_err(|_| RefundAdaptorRoundError::ExtractionRejected)?;

        Ok(CompletedRefundAdaptorCycleV1 {
            final_signature: final_signature.to_bytes(),
            refund_adaptor_point: self.refund_adaptor_point.to_compressed_bytes(),
            aggregate_nonce_hat: self.aggregate_nonce_hat.to_compressed_bytes(),
            revealed_refund_secret: *revealed,
        })
    }
}

//! Two-nonce Claim adaptor composition over the pinned DOM backend.
//!
//! This module composes primitives that the pinned DOM Protocol revision
//! already owns. It defines no curve arithmetic, no hash, no codec, and no
//! normalisation of its own. Every equation below is the pinned one, named by
//! the pinned function that computes it.
//!
//! # The frozen relation between `R`, `T` and `R̂`
//!
//! Read from the pinned code, not derived from prose:
//!
//! ```text
//! R_i = R1_i + R2_i · b     dom_scriptless_primitives::scriptless_bind_public_nonces
//! R   = Σ R_i               dom_adaptor::aggregate_public_nonces_v1
//! R̂   = R + T               dom_adaptor::aggregate_public_nonces_v1([R, T])
//! ```
//!
//! `b` is [`dom_adaptor::binding_factor_v1`], which commits to the chain
//! identifier, session identifier, purpose, template hash, the ordered signing
//! keys, the ordered nonce pairs, and the adaptor point.
//!
//! The adaptor point is **added** when forming `R̂`, and subtracted again by
//! the pinned verifier, which checks `ŝ·G == R̂ + e·X − T` with
//! `e = H(R̂, X, chain_id, kernel_message)`. The two halves agree because the
//! partial signatures are plain — the pinned `verify_bound` checks
//! `s_i·G == R_i + X_i·e` — so their sum satisfies
//!
//! ```text
//! ŝ·G = R + e·X = (R̂ − T) + e·X = R̂ + e·X − T
//! ```
//!
//! and after adaptation `s = ŝ + t` gives `s·G = R̂ + e·X`, which is an
//! ordinary DOM signature over the nonce `R̂`. `claim_adaptor_round_v1.rs`
//! freezes this with byte-exact known-answer tests against the pinned backend.
//!
//! # Rogue-key resistance is delegated, and is not complete here
//!
//! Participant signing keys are accepted as published points and aggregated by
//! plain sum, which is what the pinned backend does. Plain-sum aggregation is
//! only safe once each participant has proved possession of its share; the
//! pinned revision owns that proof in `dom_adaptor::prove_share_knowledge_v1`
//! and `verify_share_knowledge_v1`, and, like the pinned signing round, this
//! module does not verify it.
//!
//! That is a deliberate boundary, not an oversight, and it is recorded because
//! a reader could otherwise take this module for a complete protocol: proof of
//! possession is a required composition step that is still owed, and nothing
//! here should be taken as evidence it has been performed.
//!
//! # Boundaries
//!
//! Nothing here generates a nonce, and no public entry point accepts one
//! chosen by the caller: participants supply already-published public nonces,
//! and secret nonces never enter this module. Funding, refund, broadcast,
//! executor, events, chain I/O and shared-output work are absent.
//!
//! The Stage 4 limit is preserved and not weakened: the template hash and the
//! transcript hash are protocol provenance, not intrinsic cryptographic
//! binding of the final kernel signature. They are compared for equality; they
//! are not inputs to the challenge. See [`crate::claim_adaptor`].
//!
//! [`VerifiedClaimAdaptorPreSignatureV1`] is not an authority token. It
//! authorises no mutation, no funding and no broadcast.
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

use crate::claim_adaptor::{
    verify_claim_adaptor_pre_signature_v1, ClaimAdaptorVerificationError,
    ClaimAdaptorVerificationRequestV1, VerifiedClaimAdaptorPreSignatureV1,
    CLAIM_ADAPTOR_PRE_SIGNATURE_LEN,
};

/// Exactly two participants, as NAR-DC-P1-007 §3 ratified for this product.
pub const CLAIM_ADAPTOR_PARTICIPANTS: usize = 2;

/// Everything the round is stated over.
///
/// The caller supplies published public values only. No secret, and in
/// particular no secret nonce, is accepted here.
pub struct ClaimAdaptorRoundInputsV1<'a> {
    /// Chain identifier, session identifier, purpose and template hash, in the
    /// pinned binding-context form.
    pub binding_context: BindingContextV1,
    /// The published nonce pairs, in canonical roster order.
    pub participants: &'a [ParticipantPublicNoncesV1],
    /// The adaptor point `T`.
    pub adaptor_point: PublicKey,
    /// The aggregate signing key `X`.
    pub aggregate_signing_key: PublicKey,
    /// The session transcript hash.
    pub transcript_hash: [u8; 32],
    /// The 32-byte kernel message digest the DOM verifier signs over.
    pub kernel_message_digest: [u8; 32],
}

/// Why a Claim adaptor round was refused.
///
/// Every variant is a refusal. There is no variant meaning "accepted": the
/// only evidence of success is a value this module alone can issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClaimAdaptorRoundError {
    /// The purpose is not `ClaimAdaptor`.
    ///
    /// A Claim adaptor round is the only thing this module composes. Funding
    /// and Refund finalisation is a different pinned path and is out of scope.
    WrongPurpose,
    /// The roster is not exactly two distinct participants in canonical order.
    NonCanonicalRoster,
    /// The chain identifier is all zero, which identifies no network.
    ZeroChainId,
    /// The pinned binding-factor transcript refused the inputs.
    BindingRefused,
    /// A public nonce or point is not canonical, or an aggregate is identity.
    NonCanonicalPoint,
    /// The partial signature set does not match the roster one for one.
    PartialSetMismatch,
    /// A partial signature failed the pinned per-participant equation.
    ///
    /// Every partial is checked against its own participant before any
    /// aggregation, so a bad share is named rather than absorbed into a sum.
    PartialRejected,
    /// The pinned aggregation refused the partial set.
    AggregationRefused,
    /// The assembled pre-signature did not verify through the pinned verifier.
    PreSignatureRejected,
    /// Adaptation with the supplied secret did not produce a valid signature.
    AdaptationRejected,
    /// The final signature did not verify through the pinned DOM verifier.
    FinalSignatureRejected,
    /// Extraction did not return the adaptor secret that matches `T`.
    ExtractionRejected,
    /// The pinned backend could not complete and reached no verdict.
    BackendRefused,
}

impl fmt::Display for ClaimAdaptorRoundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongPurpose => "the round purpose is not ClaimAdaptor",
            Self::NonCanonicalRoster => "the participant roster is not canonical",
            Self::ZeroChainId => "the chain identifier is zero",
            Self::BindingRefused => "the pinned binding transcript refused the inputs",
            Self::NonCanonicalPoint => "a point is not canonical or aggregates to identity",
            Self::PartialSetMismatch => "the partial set does not match the roster",
            Self::PartialRejected => "a partial signature failed its participant equation",
            Self::AggregationRefused => "the pinned aggregation refused the partial set",
            Self::PreSignatureRejected => "the assembled pre-signature did not verify",
            Self::AdaptationRejected => "adaptation did not produce a valid signature",
            Self::FinalSignatureRejected => "the final signature did not verify",
            Self::ExtractionRejected => "extraction did not return the secret matching T",
            Self::BackendRefused => "the pinned backend could not reach a verdict",
        })
    }
}

impl Error for ClaimAdaptorRoundError {}

/// The derived public values of one Claim adaptor round.
///
/// Every field is a public value derived by a pinned function. Holding them
/// together keeps the caller from recomputing any of them differently.
pub struct ClaimAdaptorRoundV1 {
    binding_factor: [u8; 32],
    /// The roster the binding factor and the effective nonces were derived
    /// from, retained so completion cannot be told a different one.
    participants: Vec<ParticipantPublicNoncesV1>,
    effective_nonces: Vec<PublicKey>,
    aggregate_nonce: PublicKey,
    aggregate_nonce_hat: PublicKey,
    adaptor_point: PublicKey,
    aggregate_signing_key: PublicKey,
    chain_id: [u8; 32],
    template_hash: [u8; 32],
    transcript_hash: [u8; 32],
    kernel_message_digest: [u8; 32],
}

impl ClaimAdaptorRoundV1 {
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

    /// The aggregate nonce `R`, before the adaptor point is added.
    #[must_use]
    pub const fn aggregate_nonce(&self) -> &PublicKey {
        &self.aggregate_nonce
    }

    /// The aggregate nonce `R̂ = R + T` the challenge is computed over.
    #[must_use]
    pub const fn aggregate_nonce_hat(&self) -> &PublicKey {
        &self.aggregate_nonce_hat
    }
}

/// Derive the public round values with the pinned binding and aggregation.
///
/// # Errors
///
/// Returns the specific [`ClaimAdaptorRoundError`] for the first unsatisfied
/// requirement. Nothing is computed locally: the binding factor, the nonce
/// binding and both aggregations are the pinned functions.
pub fn begin_claim_adaptor_round_v1(
    inputs: &ClaimAdaptorRoundInputsV1<'_>,
) -> Result<ClaimAdaptorRoundV1, ClaimAdaptorRoundError> {
    if inputs.binding_context.purpose != PurposeV1::ClaimAdaptor {
        return Err(ClaimAdaptorRoundError::WrongPurpose);
    }
    if inputs.binding_context.chain_id == [0_u8; 32] {
        return Err(ClaimAdaptorRoundError::ZeroChainId);
    }
    if inputs.participants.len() != CLAIM_ADAPTOR_PARTICIPANTS {
        return Err(ClaimAdaptorRoundError::NonCanonicalRoster);
    }

    // The pinned transcript enforces canonical ordering, uniqueness of signing
    // keys and uniqueness of nonces across participants. Restating those rules
    // here would be a second roster policy for the same bytes.
    let factor = binding_factor_v1(
        &inputs.binding_context,
        inputs.participants,
        Some(&inputs.adaptor_point),
    )
    .map_err(|_| ClaimAdaptorRoundError::BindingRefused)?;

    // `BindingFactorV1::bind_public_nonces` is the pinned wrapper over
    // `dom_scriptless_primitives::scriptless_bind_public_nonces`. Going through the wrapper
    // keeps the factor and the binding in one pinned type rather than passing
    // a loose scalar into a lower-level primitive.
    let mut effective_nonces = Vec::with_capacity(inputs.participants.len());
    for participant in inputs.participants {
        let bound = factor
            .bind_public_nonces(&participant.first_nonce, &participant.second_nonce)
            .map_err(|_| ClaimAdaptorRoundError::NonCanonicalPoint)?;
        effective_nonces.push(bound);
    }

    let aggregate_nonce = aggregate_public_nonces_v1(&effective_nonces)
        .map_err(|_| ClaimAdaptorRoundError::NonCanonicalPoint)?;

    // R_hat = R + T. The adaptor point is added here and subtracted again by
    // the pinned pre-signature verifier.
    let aggregate_nonce_hat =
        aggregate_public_nonces_v1(&[aggregate_nonce.clone(), inputs.adaptor_point.clone()])
            .map_err(|_| ClaimAdaptorRoundError::NonCanonicalPoint)?;

    Ok(ClaimAdaptorRoundV1 {
        binding_factor: factor.to_be_bytes(),
        participants: inputs.participants.to_vec(),
        effective_nonces,
        aggregate_nonce,
        aggregate_nonce_hat,
        adaptor_point: inputs.adaptor_point.clone(),
        aggregate_signing_key: inputs.aggregate_signing_key.clone(),
        chain_id: inputs.binding_context.chain_id,
        template_hash: inputs.binding_context.template_hash,
        transcript_hash: inputs.transcript_hash,
        kernel_message_digest: inputs.kernel_message_digest,
    })
}

/// Opaque evidence that one full Claim adaptor cycle completed.
///
/// Issued only by [`ClaimAdaptorRoundV1::complete_cycle_v1`]. The fields and
/// the constructor are private, and the type implements neither `Clone`,
/// `Copy`, `Debug`, `Default`, nor any serialization, so it cannot be forged,
/// copied, logged, or decoded.
///
/// It is evidence, not authority. It authorises no mutation, no funding and no
/// broadcast, and it is not a one-time token.
pub struct CompletedClaimAdaptorCycleV1 {
    pre_signature: VerifiedClaimAdaptorPreSignatureV1,
    final_signature: [u8; 65],
    adaptor_point: [u8; 33],
    aggregate_nonce_hat: [u8; 33],
}

impl CompletedClaimAdaptorCycleV1 {
    /// The Stage 4 evidence for the pre-signature this cycle adapted.
    #[must_use]
    pub const fn pre_signature(&self) -> &VerifiedClaimAdaptorPreSignatureV1 {
        &self.pre_signature
    }

    /// The finalized 65-byte DOM Schnorr signature.
    #[must_use]
    pub const fn final_signature(&self) -> &[u8; 65] {
        &self.final_signature
    }

    /// The adaptor point `T` the extracted secret was checked against.
    #[must_use]
    pub const fn adaptor_point(&self) -> &[u8; 33] {
        &self.adaptor_point
    }

    /// The aggregate nonce `R̂` the final signature is stated over.
    #[must_use]
    pub const fn aggregate_nonce_hat(&self) -> &[u8; 33] {
        &self.aggregate_nonce_hat
    }
}

impl ClaimAdaptorRoundV1 {
    /// Verify every partial against its own participant, then aggregate.
    ///
    /// Each partial is checked with the pinned per-participant equation before
    /// it contributes to the sum, so a bad share is refused by name rather than
    /// disappearing into an aggregate that fails later for no stated reason.
    ///
    /// # Errors
    ///
    /// Returns the specific [`ClaimAdaptorRoundError`] for the first
    /// unsatisfied requirement.
    fn aggregate_checked_partials(
        &self,
        partials: &[PartialSignatureV1],
    ) -> Result<[u8; 32], ClaimAdaptorRoundError> {
        if partials.len() != self.participants.len()
            || partials.len() != self.effective_nonces.len()
        {
            return Err(ClaimAdaptorRoundError::PartialSetMismatch);
        }
        for (position, participant) in self.participants.iter().enumerate() {
            let partial = partials
                .get(position)
                .ok_or(ClaimAdaptorRoundError::PartialSetMismatch)?;
            if partial.participant_index() != participant.participant_index {
                return Err(ClaimAdaptorRoundError::PartialSetMismatch);
            }
            let bound = self
                .effective_nonces
                .get(position)
                .ok_or(ClaimAdaptorRoundError::PartialSetMismatch)?;
            match partial.verify_bound(
                PurposeV1::ClaimAdaptor,
                &self.template_hash,
                bound,
                &participant.signing_key,
                &self.aggregate_nonce_hat,
                &self.aggregate_signing_key,
                &self.chain_id,
                &self.kernel_message_digest,
            ) {
                Ok(true) => {}
                Ok(false) => return Err(ClaimAdaptorRoundError::PartialRejected),
                Err(_) => return Err(ClaimAdaptorRoundError::BackendRefused),
            }
        }
        let aggregate =
            aggregate_partial_signatures_v1(partials, PurposeV1::ClaimAdaptor, &self.template_hash)
                .map_err(|_| ClaimAdaptorRoundError::AggregationRefused)?;
        Ok(aggregate.to_bytes())
    }

    /// Assemble the canonical 162-byte pre-signature payload.
    ///
    /// The layout is the pinned one, produced by the pinned encoder rather than
    /// written out here: `AdaptorPreSignatureV1::new(...).to_bytes()`.
    fn assemble_payload(
        &self,
        scalar_hat: [u8; 32],
    ) -> Result<
        (AdaptorPreSignatureV1, [u8; CLAIM_ADAPTOR_PRE_SIGNATURE_LEN]),
        ClaimAdaptorRoundError,
    > {
        let scalar = dom_crypto::PartialSig::from_bytes(&scalar_hat)
            .map_err(|_| ClaimAdaptorRoundError::AggregationRefused)?;
        let pre_signature = AdaptorPreSignatureV1::new(
            self.template_hash,
            self.adaptor_point.clone(),
            self.aggregate_nonce_hat.clone(),
            scalar,
            self.transcript_hash,
        );
        let bytes = pre_signature.to_bytes();
        Ok((pre_signature, bytes))
    }

    /// Run the complete cycle: pre-sign, verify, adapt, verify natively,
    /// extract, and check `t·G == T`.
    ///
    /// The adaptor secret is consumed for adaptation only. It is never stored,
    /// returned, logged, or compared outside the pinned equality check, and the
    /// extracted secret is checked against `T` through the pinned point
    /// derivation rather than by comparing scalars here.
    ///
    /// # Errors
    ///
    /// Returns the specific [`ClaimAdaptorRoundError`] for the first
    /// unsatisfied requirement. No path returns evidence without every pinned
    /// check having returned a positive verdict.
    pub fn complete_cycle_v1(
        &self,
        partials: &[PartialSignatureV1],
        adaptor_secret: &AdaptorSecret,
    ) -> Result<CompletedClaimAdaptorCycleV1, ClaimAdaptorRoundError> {
        let scalar_hat = self.aggregate_checked_partials(partials)?;
        let (pre_signature, payload) = self.assemble_payload(scalar_hat)?;

        // Stage 4's opaque verifier is the only route to pre-signature
        // evidence. It is reused rather than duplicated.
        let request = ClaimAdaptorVerificationRequestV1 {
            pre_signature: &payload,
            claim_template_hash: self.template_hash,
            transcript_hash: self.transcript_hash,
            aggregate_signing_key: self.aggregate_signing_key.to_compressed_bytes(),
            chain_id: self.chain_id,
            kernel_message_digest: self.kernel_message_digest,
        };
        // A backend that could not reach a verdict is not a refuted signature.
        // Stage 4 keeps those apart on purpose, and collapsing them here would
        // undo that distinction at the first caller.
        let verified =
            verify_claim_adaptor_pre_signature_v1(&request).map_err(|error| match error {
                ClaimAdaptorVerificationError::BackendRefused => {
                    ClaimAdaptorRoundError::BackendRefused
                }
                _ => ClaimAdaptorRoundError::PreSignatureRejected,
            })?;

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
            .map_err(|_| ClaimAdaptorRoundError::AdaptationRejected)?;

        // Independent native DOM verification of the finalized 65 bytes.
        match dom_scriptless_primitives::scriptless_verify_final_signature(
            &final_signature,
            &self.aggregate_signing_key,
            &self.chain_id,
            &self.kernel_message_digest,
        ) {
            Ok(true) => {}
            Ok(false) => return Err(ClaimAdaptorRoundError::FinalSignatureRejected),
            Err(_) => return Err(ClaimAdaptorRoundError::BackendRefused),
        }

        // Extract and close the loop: t·G must equal T.
        let extracted = pre_signature
            .extract(
                &final_signature,
                &self.template_hash,
                &self.transcript_hash,
                &self.aggregate_signing_key,
                &self.chain_id,
                &self.kernel_message_digest,
            )
            .map_err(|_| ClaimAdaptorRoundError::ExtractionRejected)?;
        let recovered_point = extracted
            .public_point()
            .map_err(|_| ClaimAdaptorRoundError::ExtractionRejected)?;
        if recovered_point.to_compressed_bytes() != self.adaptor_point.to_compressed_bytes() {
            return Err(ClaimAdaptorRoundError::ExtractionRejected);
        }

        Ok(CompletedClaimAdaptorCycleV1 {
            pre_signature: verified,
            final_signature: final_signature.to_bytes(),
            adaptor_point: self.adaptor_point.to_compressed_bytes(),
            aggregate_nonce_hat: self.aggregate_nonce_hat.to_compressed_bytes(),
        })
    }
}

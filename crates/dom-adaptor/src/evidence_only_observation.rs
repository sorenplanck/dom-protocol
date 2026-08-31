//! Laboratory convenience for assembling one claim observation from public
//! material, without standing up a DOM node.
//!
//! What this module is NOT: a privilege. The capability it returns is **not**
//! sealed behind the observation source trait. [`AdaptorPreSignatureV1::new`],
//! [`AdaptorPreSignatureV1::prove_observed_claim_opens_adaptor_point_v1`] and
//! [`VerifiedDomClaimObservationV1::from_verified_opening_v1`] are all public,
//! because `adapters/dom-real` lives in a different crate and could not
//! implement [`crate::ExactDomClaimObservationSourceV1`] otherwise.
//! Crate-splitting forces that surface open, so anyone holding the public
//! pre-signature material and a real final signature can already mint an
//! observation. This module only spares every test suite from rewriting the
//! same five-line assembly; enabling the feature grants no authority that a
//! caller did not already have.
//!
//! What actually carries the invariant is therefore **not** in this crate. The
//! DOM Contracts store must verify, against the frozen pre-funding role
//! binding, that the local participant really is `final_claim_receiver_id`
//! before any observation drives an irreversible exposure marker. This crate
//! has no roster and cannot check it: [`DomClaimObservationTagV1`] is a
//! caller-declared role kept for auditing, never authority — the same warning
//! already carried by
//! [`VerifiedDomClaimObservationV1::from_verified_opening_v1`].
//!
//! What the seam does preserve is the proof. It runs the production
//! [`AdaptorPreSignatureV1::prove_observed_claim_opens_adaptor_point_v1`]
//! verbatim: pre-signature equation, final DOM signature, canonical nonzero
//! extracted scalar, `t*G == T`, zeroizing secret dropped before return. A
//! signature that does not open the committed adaptor point is refused here
//! exactly as it is on chain. Every input is public protocol data, so the seam
//! cannot leak anything the chain does not already publish, and it never
//! touches the adaptor secret `t`.
//!
//! One boundary the seam does **not** exercise, by construction: the caller
//! supplies `claim_template_hash` and `transcript_hash`, and those same two
//! values feed both the assembled pre-signature and the opening context. The
//! `InvalidTranscript` gates in
//! [`AdaptorPreSignatureV1::verify`] (`adaptor.rs:180-189`), which reject a
//! pre-signature whose template or transcript disagrees with the session, are
//! therefore tautologically satisfied here — the seam cannot make them
//! disagree. A test that needs those two frontiers exercised has to build the
//! pre-signature and the context from independent sources, as the production
//! path does.
//!
//! The module compiles only under the `evidence-only` feature, which no shipped
//! feature enables and which is a hard compile error in a release build.

use dom_crypto::{PartialSig, PublicKey, SchnorrSignature};

use crate::adaptor::{AdaptorPreSignatureV1, FinalSignatureOpeningContextV1};
use crate::error::{AdaptorError, Result};
use crate::transaction_lifecycle::{
    DomClaimObservationTagV1, ObservedClaimBindingV1, ObservedClaimFactsV1,
    VerifiedDomClaimObservationV1,
};

/// Public pre-signature material and session context for one observed claim.
///
/// Every field is public protocol data. None of it is secret, and none of it is
/// trusted on its own: the opening proof below verifies the relation they claim.
pub struct EvidenceOnlyClaimOpeningV1<'material> {
    /// Signature-omitting claim template hash committed by the session.
    pub claim_template_hash: [u8; 32],
    /// Authenticated transcript hash committed by the session.
    pub transcript_hash: [u8; 32],
    /// Committed adaptor point `T`.
    pub adaptor_point: PublicKey,
    /// Aggregate nonce `R_hat` of the adaptor pre-signature.
    pub aggregate_nonce_hat: PublicKey,
    /// Partial scalar `s_hat` of the adaptor pre-signature.
    pub scalar_hat: PartialSig,
    /// Aggregate signing key bound to the claim kernel.
    pub signing_key: &'material PublicKey,
    /// Trusted DOM chain identifier.
    pub chain_id: [u8; 32],
    /// Exact DOM kernel message covered by the signature challenge.
    pub kernel_message: &'material [u8],
}

/// Assemble one observation capability from public material and a crypto-real
/// opening.
///
/// This grants no authority a caller lacked: the three functions it composes
/// are public, as the module documentation explains. It is a convenience, and
/// the proof below is what makes it safe.
///
/// This runs the production proof path verbatim: it builds the adaptor
/// pre-signature from the supplied public material and calls
/// [`AdaptorPreSignatureV1::prove_observed_claim_opens_adaptor_point_v1`], which
/// verifies the pre-signature equation, verifies the final DOM signature,
/// requires a canonical nonzero extracted scalar, proves `t*G == T`, and drops
/// the zeroizing secret before returning. Only then are the observed facts
/// cross-checked against the sealed proof.
///
/// A final signature that does not open the committed adaptor point, or facts
/// that contradict the proof, fail closed here exactly as they do in production.
pub fn evidence_only_verified_claim_observation_v1(
    opening: EvidenceOnlyClaimOpeningV1<'_>,
    final_signature: &SchnorrSignature,
    tag: DomClaimObservationTagV1,
    facts: ObservedClaimFactsV1,
    kernel_index: u32,
) -> Result<VerifiedDomClaimObservationV1> {
    let pre_signature = AdaptorPreSignatureV1::new(
        opening.claim_template_hash,
        opening.adaptor_point,
        opening.aggregate_nonce_hat,
        opening.scalar_hat,
        opening.transcript_hash,
    );
    let proof = pre_signature.prove_observed_claim_opens_adaptor_point_v1(
        final_signature,
        &FinalSignatureOpeningContextV1 {
            expected_claim_template_hash: &opening.claim_template_hash,
            expected_transcript_hash: &opening.transcript_hash,
            signing_key: opening.signing_key,
            chain_id: &opening.chain_id,
            kernel_message: opening.kernel_message,
        },
        ObservedClaimBindingV1 {
            tx_hash: facts.tx_hash,
            shared_output_commitment: facts.shared_output_commitment,
            kernel_index,
        },
    )?;
    VerifiedDomClaimObservationV1::from_verified_opening_v1(proof, tag, facts).map_err(|_| {
        AdaptorError::VerificationFailed("observed facts contradict the proved adaptor opening")
    })
}

#[cfg(test)]
mod tests {
    use dom_consensus::TransactionKernel;
    use dom_scriptless_consensus::scriptless_kernel_message_digest_v1;
    use dom_serialization::DomDeserialize;

    use super::*;

    const CHAIN_ID: [u8; 32] = [0xAD; 32];
    /// The kernel message frozen by the SCAD0 corpus.
    ///
    /// The test below derives the same value from the observed kernel through
    /// [`scriptless_kernel_message_digest_v1`] and asserts equality, so the
    /// relation is proved rather than assumed. If the corpus ever decouples the
    /// two, that assertion fails loudly instead of silently weakening the
    /// opening context this seam verifies against.
    const MESSAGE: [u8; 32] = [
        0x10, 0xd4, 0x3a, 0x5a, 0xc3, 0x16, 0x0f, 0xdb, 0xc6, 0x7a, 0x1f, 0x8a, 0x29, 0x3f, 0x97,
        0x50, 0x55, 0x8e, 0x53, 0xc1, 0x8f, 0xa3, 0x7f, 0x58, 0xd3, 0x40, 0xdf, 0x3f, 0xdd, 0x41,
        0xaa, 0x34,
    ];

    type SeamResult<T> = core::result::Result<T, Box<dyn std::error::Error>>;

    fn decode_array<const N: usize>(value: &str) -> SeamResult<[u8; N]> {
        let bytes = hex::decode(value)?;
        bytes
            .try_into()
            .map_err(|_| AdaptorError::InvalidLength {
                object: "SCAD0 fixture field",
                expected: N,
                actual: 0,
            })
            .map_err(Into::into)
    }

    fn scad0_vector(index: usize) -> SeamResult<Vec<String>> {
        let fields =
            include_str!("../../dom-consensus/tests/fixtures/scad0_adaptor_vectors_v1.txt")
                .lines()
                .filter(|line| line.starts_with('V'))
                .nth(index)
                .ok_or(AdaptorError::VerificationFailed("SCAD0 vector is absent"))?
                .split('|')
                .map(str::to_owned)
                .collect();
        Ok(fields)
    }

    fn facts() -> ObservedClaimFactsV1 {
        ObservedClaimFactsV1 {
            chain_id: CHAIN_ID,
            session_id: [0x42; 32],
            tx_hash: [0x41; 32],
            template_hash: [0x22; 32],
            shared_output_commitment: [0x02; 33],
            location: crate::transaction_lifecycle::ObservedClaimLocationV1 {
                block_height: 9,
                block_hash: [0x43; 32],
                transaction_index: 1,
            },
            // The seam stands in for the scanner, so it also stands in for the
            // tip that scanner's ancestry walk would have terminated at.
            observed_tip_height: 13,
            observed_tip_id: [0x44; 32],
        }
    }

    #[test]
    fn the_seam_accepts_the_exact_opening_and_refuses_a_foreign_adaptor_point() -> SeamResult<()> {
        let first = scad0_vector(0)?;
        let second = scad0_vector(1)?;
        let kernel = TransactionKernel::from_bytes(&hex::decode(&first[4])?)?;
        let final_signature = SchnorrSignature::from_bytes(&kernel.excess_signature)?;
        let signing_key = PublicKey::from_compressed_bytes(kernel.excess.as_bytes())?;
        let nonce_hat = PublicKey::from_compressed_bytes(final_signature.r_compressed())?;
        let scalar_hat = PartialSig::from_bytes(&decode_array::<32>(&first[3])?)?;
        assert_eq!(
            scriptless_kernel_message_digest_v1(&kernel).as_bytes(),
            &MESSAGE,
            "the SCAD0 kernel message must be the observed kernel's own digest"
        );

        let honest = EvidenceOnlyClaimOpeningV1 {
            claim_template_hash: [0x22; 32],
            transcript_hash: [0x33; 32],
            adaptor_point: PublicKey::from_compressed_bytes(&decode_array::<33>(&first[2])?)?,
            aggregate_nonce_hat: nonce_hat.clone(),
            scalar_hat: scalar_hat.clone(),
            signing_key: &signing_key,
            chain_id: CHAIN_ID,
            kernel_message: &MESSAGE,
        };
        let observed = evidence_only_verified_claim_observation_v1(
            honest,
            &final_signature,
            DomClaimObservationTagV1::CounterpartyClaimObserved,
            facts(),
            0,
        )?;
        assert_eq!(observed.tx_hash(), &facts().tx_hash);
        assert_eq!(observed.kernel_index(), 0);

        // The same real final signature paired with a different committed
        // adaptor point must fail closed: the seam removes the node, not the
        // proof that `t*G == T`.
        let foreign = EvidenceOnlyClaimOpeningV1 {
            claim_template_hash: [0x22; 32],
            transcript_hash: [0x33; 32],
            adaptor_point: PublicKey::from_compressed_bytes(&decode_array::<33>(&second[2])?)?,
            aggregate_nonce_hat: nonce_hat,
            scalar_hat,
            signing_key: &signing_key,
            chain_id: CHAIN_ID,
            kernel_message: &MESSAGE,
        };
        // `AdaptorError` derives `PartialEq` and the capability deliberately has
        // no `Debug`, so the refusal is bound by let-else and then compared by
        // its exact variant rather than reduced to `is_err`.
        let Err(error) = evidence_only_verified_claim_observation_v1(
            foreign,
            &final_signature,
            DomClaimObservationTagV1::CounterpartyClaimObserved,
            facts(),
            0,
        ) else {
            return Err(AdaptorError::VerificationFailed(
                "a foreign adaptor point must never open the observed signature",
            )
            .into());
        };
        // Derived by reading, not by running. With only `adaptor_point` changed,
        // `extract` fails at its first gate: `verify_both_signatures`
        // (`adaptor.rs:367-376`) evaluates the pre-signature equation, which
        // commits to `T`, and a foreign point makes it false. The deeper
        // `"extracted scalar does not match the adaptor point"` check in
        // `dom-scriptless-primitives` (`lib.rs:281-284`) is therefore never
        // reached on this path.
        assert_eq!(
            error,
            AdaptorError::VerificationFailed("adaptor pre-signature equation")
        );
        Ok(())
    }
}

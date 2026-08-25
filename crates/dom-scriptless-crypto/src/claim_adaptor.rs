//! Claim adaptor pre-signature verification through the pinned DOM adaptor.
//!
//! Master §6.3 defines `verify_adaptor_presignature` as the check that the
//! pre-signature satisfies `ŝ·G == R̂ + e·X − T` against the authoritative DOM
//! challenge, and §6.6 requires that no normalisation be reinvented locally.
//! This module therefore computes nothing: it parses with
//! [`dom_adaptor::AdaptorPreSignatureV1`] and calls that type's own `verify`,
//! which reaches `dom_crypto::scriptless_verify_pre_signature`. No challenge,
//! curve operation, or verifier is reimplemented here.
//!
//! # What a success proves, and what it does not
//!
//! NAR-DC-P1-007 §4 records that the funding-authorisation surface is a model
//! rather than production authority, and lists what production would require:
//! opaque verifier-issued capabilities, atomic durable compare-and-swap,
//! one-time issuance across concurrency and restart, and a non-duplicable
//! broadcast capability.
//!
//! [`VerifiedClaimAdaptorPreSignatureV1`] is the first of those four and only
//! the first. It is opaque and issued solely by the verifier, so a caller
//! cannot assert it. It proves exactly one thing: that these exact
//! pre-signature bytes satisfied the pinned adaptor equation for this exact
//! signing key, chain identifier and kernel message, at the moment of the call.
//!
//! # The session bindings are byte equality, not cryptographic binding
//!
//! The Claim template hash and the transcript hash are **not** inputs to the
//! adaptor challenge. The pinned `scriptless_verify_pre_signature` computes the
//! challenge over `R̂`, `X`, the chain identifier and the kernel message; the
//! pinned `verify` compares the two hashes for equality and nothing more.
//!
//! So a cryptographically valid core — `T`, `R̂` and `ŝ` — can be re-bound to
//! any template and transcript a caller chooses, by rewriting the payload's
//! first and last 32 bytes and presenting a request that agrees with them. It
//! will verify, and this module will issue evidence for it.
//!
//! That is not a defect in the pinned verifier, and this module deliberately
//! does not paper over it: what the returned evidence records about the two
//! hashes is that the payload carried these bytes and the caller asked for
//! these bytes. Whatever guarantees a template hash is the *right* one must
//! come from the transcript that produced it, which is outside this module.
//! Master §7.3's gate and the §7 session machinery are where that belongs.
//!
//! It is **not** an authority. It does not authorise funding, broadcast,
//! adaptation, extraction, a state transition, or the movement of funds; it is
//! not one-time, carries no durable state, and outliving the state it was
//! computed against does not make it stale-safe. Master §7.3's single-use
//! funding token is a different object with different requirements, and this
//! type is deliberately not named after it.
//!
//! # Boundaries
//!
//! Nothing here signs, generates a nonce, adapts, or extracts. The adaptor
//! secret never appears. Master §7.5's extraction path and §7.3's gate are
//! absent, and this module holds no store, clock, transport, or randomness.
//!
//! ```text
//! PRODUCTION = NOT_AUTHORIZED
//! MAINNET = DISABLED
//! REAL_FUNDS = PROHIBITED
//! PHASE2 = NOT_AUTHORIZED
//! ```
//!
//! # The capability cannot be forged or copied
//!
//! It has no public constructor:
//!
//! ```compile_fail
//! use dom_scriptless_crypto::VerifiedClaimAdaptorPreSignatureV1;
//!
//! let _forged = VerifiedClaimAdaptorPreSignatureV1 {
//!     claim_template_hash: [0u8; 32],
//!     transcript_hash: [0u8; 32],
//!     aggregate_signing_key: [0u8; 33],
//!     chain_id: [0u8; 32],
//!     kernel_message_digest: [0u8; 32],
//!     adaptor_point: [0u8; 33],
//!     aggregate_nonce_hat: [0u8; 33],
//! };
//! ```
//!
//! it cannot be cloned:
//!
//! ```compile_fail
//! use dom_scriptless_crypto::VerifiedClaimAdaptorPreSignatureV1;
//!
//! fn duplicate(value: VerifiedClaimAdaptorPreSignatureV1) {
//!     let _ = value.clone();
//! }
//! ```
//!
//! it cannot be printed into a log:
//!
//! ```compile_fail
//! use dom_scriptless_crypto::VerifiedClaimAdaptorPreSignatureV1;
//!
//! fn leak(value: &VerifiedClaimAdaptorPreSignatureV1) {
//!     println!("{value:?}");
//! }
//! ```
//!
//! it has no default:
//!
//! ```compile_fail
//! use dom_scriptless_crypto::VerifiedClaimAdaptorPreSignatureV1;
//!
//! let _ = VerifiedClaimAdaptorPreSignatureV1::default();
//! ```
//!
//! and there is no route back to the inner pre-signature or its scalar:
//!
//! ```compile_fail
//! use dom_scriptless_crypto::VerifiedClaimAdaptorPreSignatureV1;
//!
//! fn extract(value: &VerifiedClaimAdaptorPreSignatureV1) -> &[u8] {
//!     value.scalar_hat()
//! }
//! ```
//!
//! ```compile_fail
//! use dom_scriptless_crypto::VerifiedClaimAdaptorPreSignatureV1;
//!
//! fn extract(value: VerifiedClaimAdaptorPreSignatureV1) -> dom_adaptor::AdaptorPreSignatureV1 {
//!     value.into_inner()
//! }
//! ```
//!
//! It cannot be serialized. Evidence that survived a round trip through bytes
//! would be evidence a caller could store, replay, and hand to someone who
//! never ran the check:
//!
//! ```compile_fail
//! use dom_scriptless_crypto::VerifiedClaimAdaptorPreSignatureV1;
//!
//! fn encode<T: serde::Serialize>(value: &T) {}
//!
//! fn leak(value: &VerifiedClaimAdaptorPreSignatureV1) {
//!     encode(value);
//! }
//! ```
//!
//! and it cannot be compared, so it cannot be used as a lookup key or matched
//! against a remembered value:
//!
//! ```compile_fail
//! use dom_scriptless_crypto::VerifiedClaimAdaptorPreSignatureV1;
//!
//! fn same(a: &VerifiedClaimAdaptorPreSignatureV1, b: &VerifiedClaimAdaptorPreSignatureV1) -> bool {
//!     a == b
//! }
//! ```

use core::fmt;
use std::error::Error;

use dom_adaptor::AdaptorPreSignatureV1;
use dom_crypto::PublicKey;

/// Exact encoded length of the canonical Claim adaptor pre-signature payload.
///
/// Restated from the pinned `dom_adaptor::AdaptorPreSignatureV1::ENCODED_LEN`
/// so a caller can size a buffer without depending on the adaptor crate
/// directly. The two are asserted equal by the crate's tests; the pinned parser
/// remains the only thing that enforces the length at run time.
pub const CLAIM_ADAPTOR_PRE_SIGNATURE_LEN: usize = 162;

/// Compressed SEC1 point length.
const COMPRESSED_POINT_LEN: usize = 33;

/// Everything the §6.3 verification is stated over.
///
/// Every field is a binding: the pre-signature must agree with all of them, and
/// the pinned verifier is given each one rather than deriving it.
pub struct ClaimAdaptorVerificationRequestV1<'a> {
    /// The exact canonical pre-signature payload, which must be
    /// [`CLAIM_ADAPTOR_PRE_SIGNATURE_LEN`] bytes.
    pub pre_signature: &'a [u8],
    /// Hash of the exact Claim template this pre-signature is bound to.
    pub claim_template_hash: [u8; 32],
    /// Hash of the authenticated transcript at the point of pre-signature.
    pub transcript_hash: [u8; 32],
    /// The canonical compressed aggregate signing key, `X`.
    pub aggregate_signing_key: [u8; COMPRESSED_POINT_LEN],
    /// The exact network identifier. Master Appendix E.1 derives it from the
    /// chain adapter, never from a peer, and a zero value is not a network.
    pub chain_id: [u8; 32],
    /// The exact 32-byte kernel message digest the DOM verifier signs over.
    pub kernel_message_digest: [u8; 32],
}

/// Why a Claim adaptor pre-signature was not verified.
///
/// Every variant is a refusal. There is no variant meaning "verified", because
/// the only evidence of verification is
/// [`VerifiedClaimAdaptorPreSignatureV1`], which this module alone can issue.
/// Marked `#[non_exhaustive]` so a future refusal can be added without a
/// breaking change. Without it, every downstream `match` is exhaustive over
/// today's variants, which pressures a future author into collapsing a new
/// refusal into an existing one rather than distinguishing it — and the
/// distinctions here are the point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClaimAdaptorVerificationError {
    /// The payload is not a canonical pre-signature: wrong length, a
    /// non-canonical point, or a non-canonical scalar.
    MalformedPreSignature,
    /// The aggregate signing key is not a canonical compressed point.
    NonCanonicalSigningKey,
    /// The chain identifier is all zero, which identifies no network.
    ZeroChainId,
    /// The payload's Claim template hash is not the requested one.
    ClaimTemplateMismatch,
    /// The payload's transcript hash is not the requested one.
    TranscriptMismatch,
    /// The pinned verifier ran and rejected the adaptor equation.
    ///
    /// The pinned `verify` reports this outcome as `Ok(false)`. Returning it as
    /// a typed refusal is deliberate: a boolean that a caller could ignore, or
    /// store, or pass on, is exactly the shape NAR-DC-P1-007 §4 records as
    /// model rather than authority.
    VerificationRejected,
    /// The pinned verifier could not complete, and reached no verdict.
    ///
    /// Distinct from [`Self::VerificationRejected`]: "the equation is false"
    /// and "the check did not run" are different facts, and collapsing them
    /// would report an unavailable verifier as a refuted signature.
    BackendRefused,
}

impl fmt::Display for ClaimAdaptorVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedPreSignature => "the Claim adaptor pre-signature is not canonical",
            Self::NonCanonicalSigningKey => {
                "the aggregate signing key is not a canonical compressed point"
            }
            Self::ZeroChainId => "the chain identifier is zero",
            Self::ClaimTemplateMismatch => {
                "the pre-signature is bound to a different Claim template"
            }
            Self::TranscriptMismatch => "the pre-signature is bound to a different transcript",
            Self::VerificationRejected => "the DOM adaptor verifier rejected the pre-signature",
            Self::BackendRefused => "the DOM adaptor verifier could not reach a verdict",
        })
    }
}

impl Error for ClaimAdaptorVerificationError {}

/// Evidence that one exact pre-signature verified against one exact set of
/// bindings.
///
/// Issued only by [`verify_claim_adaptor_pre_signature_v1`]. The fields and the
/// constructor are private, and the type implements neither `Clone`, `Copy`,
/// `Debug`, `Default`, nor any serialization, so it cannot be forged, copied,
/// logged, or decoded back into the pre-signature it was computed from.
///
/// The readers below return the bindings that were verified, all of them public
/// values. The pre-signature scalar is signing material and is never exposed.
///
/// This is evidence, not authority. See the module documentation: it authorises
/// no funding, broadcast, adaptation, extraction, state change, or movement of
/// funds, and it is not a one-time token.
pub struct VerifiedClaimAdaptorPreSignatureV1 {
    claim_template_hash: [u8; 32],
    transcript_hash: [u8; 32],
    aggregate_signing_key: [u8; COMPRESSED_POINT_LEN],
    chain_id: [u8; 32],
    kernel_message_digest: [u8; 32],
    adaptor_point: [u8; COMPRESSED_POINT_LEN],
    aggregate_nonce_hat: [u8; COMPRESSED_POINT_LEN],
}

impl VerifiedClaimAdaptorPreSignatureV1 {
    /// The Claim template hash that was verified.
    #[must_use]
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }

    /// The transcript hash that was verified.
    #[must_use]
    pub const fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// The aggregate signing key the equation was checked against.
    #[must_use]
    pub const fn aggregate_signing_key(&self) -> &[u8; COMPRESSED_POINT_LEN] {
        &self.aggregate_signing_key
    }

    /// The chain identifier that was bound into the challenge.
    #[must_use]
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// The kernel message digest that was bound into the challenge.
    #[must_use]
    pub const fn kernel_message_digest(&self) -> &[u8; 32] {
        &self.kernel_message_digest
    }

    /// The adaptor point `T` carried by the verified pre-signature.
    #[must_use]
    pub const fn adaptor_point(&self) -> &[u8; COMPRESSED_POINT_LEN] {
        &self.adaptor_point
    }

    /// The aggregate nonce `R̂` carried by the verified pre-signature.
    #[must_use]
    pub const fn aggregate_nonce_hat(&self) -> &[u8; COMPRESSED_POINT_LEN] {
        &self.aggregate_nonce_hat
    }
}

/// Verify a Claim adaptor pre-signature through the pinned DOM adaptor.
///
/// The order is: reject what can be rejected without cryptography, parse with
/// the pinned codec, confirm the payload is bound to the requested session, and
/// only then run the pinned verifier. Nothing is computed locally.
///
/// # Errors
///
/// Returns the specific [`ClaimAdaptorVerificationError`] for the first
/// unsatisfied requirement. A rejected equation and an unavailable verifier are
/// separate refusals, and no path returns evidence without a `true` verdict
/// from the pinned verifier.
pub fn verify_claim_adaptor_pre_signature_v1(
    request: &ClaimAdaptorVerificationRequestV1<'_>,
) -> Result<VerifiedClaimAdaptorPreSignatureV1, ClaimAdaptorVerificationError> {
    if request.chain_id == [0_u8; 32] {
        return Err(ClaimAdaptorVerificationError::ZeroChainId);
    }

    let signing_key = PublicKey::from_compressed_bytes(&request.aggregate_signing_key)
        .map_err(|_| ClaimAdaptorVerificationError::NonCanonicalSigningKey)?;

    // The pinned codec owns the length, point and scalar canonicalisation
    // rules. Restating them here would be a second parser for signed bytes.
    let parsed = AdaptorPreSignatureV1::from_bytes(request.pre_signature)
        .map_err(|_| ClaimAdaptorVerificationError::MalformedPreSignature)?;

    // The pinned `verify` checks both bindings too, and is given them below.
    // Checking them first separates "bound to another session" from "the
    // equation is false", which the pinned error type reports as one variant.
    if parsed.claim_template_hash() != &request.claim_template_hash {
        return Err(ClaimAdaptorVerificationError::ClaimTemplateMismatch);
    }
    if parsed.transcript_hash() != &request.transcript_hash {
        return Err(ClaimAdaptorVerificationError::TranscriptMismatch);
    }

    let adaptor_point = parsed.adaptor_point().to_compressed_bytes();
    let aggregate_nonce_hat = parsed.aggregate_nonce_hat().to_compressed_bytes();

    match parsed.verify(
        &request.claim_template_hash,
        &request.transcript_hash,
        &signing_key,
        &request.chain_id,
        &request.kernel_message_digest,
    ) {
        Ok(true) => Ok(VerifiedClaimAdaptorPreSignatureV1 {
            claim_template_hash: request.claim_template_hash,
            transcript_hash: request.transcript_hash,
            aggregate_signing_key: request.aggregate_signing_key,
            chain_id: request.chain_id,
            kernel_message_digest: request.kernel_message_digest,
            adaptor_point,
            aggregate_nonce_hat,
        }),
        Ok(false) => Err(ClaimAdaptorVerificationError::VerificationRejected),
        Err(_) => Err(ClaimAdaptorVerificationError::BackendRefused),
    }
}

//! DOM leg of the settlement — the ONLY gateway to the `dom-adaptor`.
//!
//! DOM Interop Foundation Document v0.2 §2.2 and §4.4.
//!
//! ## Two configurations
//!
//! - `--features real-dom-adaptor`: REAL 2-of-2 round over `dom-adaptor`, which
//!   is now a member of this workspace rather than a git pin — the DOM and its
//!   interoperability layer are one tree. The audited revision it was absorbed
//!   at was commit `6f8a947dee0e54c3421caa295755b1746c178137`, kept here as
//!   provenance and not as a resolution target. Mandatory in the conformance
//!   CI (§9.1) and in F1+. See [`round`].
//! - default: compiles without a C toolchain. The BOUNDARY (names and argument
//!   order) is the same, but every cryptographic operation returns
//!   [`LegError::CryptoBackendDisabled`]. No default path fakes cryptographic
//!   success — I13/anti-theater.
//!
//! ## Prohibitions in this crate (§4.4)
//! - no constructor that accepts `claim_template_hash`/`transcript_hash`
//!   "from outside" without revalidating against the session;
//! - no path that finalizes `ClaimAdaptor` as a plain signature
//!   (the real crate already rejects it — do not "fix" that);
//! - no storage of adaptor secrets outside the flow (I1);
//! - no reimplementation of any primitive, challenge, or verifier (I15):
//!   the purpose registry, the transcripts, the binding factor, the
//!   aggregation, and the verifiers are ALWAYS the pin's.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use counterparty_api::AdaptorPointBytes;

// Always compiled, so a caller can name the backendless leg explicitly even in
// a build where the real backend is present. The root re-export below stays
// feature-gated: without the backend, `dom_leg::DomLegSession` *is* this one.
pub mod disabled;
#[cfg(feature = "f7-wallet-compositor-evidence-only")]
mod f7_live_wallet;
#[cfg(feature = "f7-wallet-compositor-evidence-only")]
mod f7_route;
#[cfg(feature = "f7-wallet-compositor-evidence-only")]
pub mod f7_wallet;
#[cfg(feature = "real-dom-adaptor")]
pub mod round;

#[cfg(not(feature = "real-dom-adaptor"))]
pub use disabled::{scalar_is_canonical, DomLegSession, SessionBindings, SECP256K1_ORDER};

#[cfg(feature = "f7-wallet-compositor-evidence-only")]
pub use f7_live_wallet::{
    F7OfficialWalletError, F7OfficialWalletFundingReceiptV1, F7OfficialWalletPairV1,
    F7OfficialWalletParticipantConfigV1,
};
#[cfg(feature = "f7-wallet-compositor-evidence-only")]
pub use f7_route::{
    F7DomFundingShapeV1, F7DomPayoutShapeV1, F7DomRoutePreparationErrorV1,
    F7DomRoutePreparationRequestV1, F7FreshDomRoutePreparationRequestV1,
    F7PreparedProductionDomFundingV1, F7PreparedProductionDomRouteV1,
    F7ProductionDomFundingReceiptV1, F7ProductionDomPostFundingOwnerV1,
    F7ProductionDomRouteAuthorityFactoryV1,
};
#[cfg(feature = "f7-wallet-compositor-evidence-only")]
pub use f7_wallet::{
    bind_wallet_pair_claim_template_v1, compose_wallet_pair_claim_template_v1,
    compose_wallet_pair_funding_template_v1, compose_wallet_pair_refund_template_v1,
    F7ContractsOperationalSignerV1, F7DomDsc1CheckpointV1, F7DomDsc1FaultControllerV1,
    F7DomDsc1FaultDirectiveV1, F7DomDsc1PurposeV1, F7OperationalSigningContextV1,
    F7ProductionContractsCompositionV1, F7ProductionParticipantAuthoritiesV1,
    F7VerifiedDomClaimArtifactV1, F7VerifiedDomRefundArtifactV1, F7WalletBoundDomClaimV1,
    F7WalletBoundDomFundingV1, F7WalletBoundDomRefundV1, F7WalletCompositorError,
    F7WalletDomClaimExtractionV1, F7WalletPreSignedDomClaimV1,
};
#[cfg(feature = "real-dom-adaptor")]
pub use round::{
    scalar_is_canonical, AggregateSigningKey, BoundRound, CallerSuppliedIdentitySessionRequestV1,
    DomLegSession, ExtractedAdaptorSecret, LegParticipant, LocalSigningShare, RoundNonces,
    SessionBindings, SessionOpenRequest,
};

/// Purpose registry.
///
/// [AUTHORITY: dom-adaptor 6f8a947d] with `real-dom-adaptor` this is the pin's
/// REAL registry; the DOM leg keeps no local copy (I15). Without the feature
/// there is no registry here: the purpose travels as an opaque byte and no
/// cryptographic operation is possible.
#[cfg(feature = "real-dom-adaptor")]
pub use dom_adaptor::PurposeV1;

/// DOM leg errors.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LegError {
    /// Cryptographic backend disabled (build without `real-dom-adaptor`).
    #[error("dom crypto backend disabled: build with --features real-dom-adaptor")]
    CryptoBackendDisabled,
    /// Claim template diverges from the session.
    #[error("claim template does not match the session")]
    TemplateMismatch,
    /// Transcript diverges from the session.
    #[error("transcript does not match the session")]
    TranscriptMismatch,
    /// Secret does not match the committed point.
    #[error("adaptor secret does not match the committed point")]
    SecretPointMismatch,
    /// Invalid pre-signature equation.
    #[error("adaptor pre-signature verification failed")]
    VerificationFailed,
    /// Non-canonical scalar.
    #[error("non-canonical scalar")]
    NonCanonicalScalar,
    /// Encoding with an invalid length.
    #[error("invalid encoding length: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected length.
        expected: usize,
        /// Received length.
        got: usize,
    },
    /// The operating-system CSPRNG failed.
    #[error("operating-system CSPRNG failed")]
    Randomness,
    /// Identity, key, or index does not match the session roster.
    #[error("participant does not match the session roster")]
    RosterMismatch,
    /// A counterparty's share PoK is missing.
    ///
    /// §2.2.6: verification happens before ANY aggregation of public points,
    /// without exception.
    #[error("counterparty share proof is missing")]
    MissingShareProof,
    /// The received PoK statement is not this session's canonical statement.
    #[error("share proof statement does not match the session")]
    ShareStatementMismatch,
    /// The share PoK did not verify.
    #[error("share proof rejected")]
    ShareProofRejected,
    /// The reveal does not open the previously sent nonce commitment.
    #[error("nonce reveal does not open the commitment")]
    CommitmentMismatch,
    /// Purpose diverges from the session's frozen purpose.
    #[error("purpose does not match the session")]
    PurposeMismatch,
    /// `ClaimAdaptor` session without an adaptor point.
    #[error("ClaimAdaptor session has no adaptor point")]
    AdaptorPointMissing,
    /// Partial rejected by the real verifier before any export.
    #[error("partial signature rejected by the DOM verifier")]
    PartialRejected,
    /// Participant index outside the roster.
    #[error("participant index is outside the roster")]
    IndexOutOfRange,
    /// Retained session facts that are structurally impossible for any round.
    ///
    /// Raised only by `SessionBindings::open_with_caller_supplied_identity_v1`,
    /// for a field the caller failed to populate. It is an accident detector
    /// and nothing more: a caller that chooses its own inputs chooses non-zero
    /// ones at the same cost, so this refusal is worth nothing against one.
    #[error("retained session facts are structurally incomplete")]
    MalformedRetainedFacts,
    /// Rejection coming from the pinned crate, propagated without
    /// reinterpretation.
    ///
    /// I6: `AdaptorError` only carries static strings and `DomError`
    /// messages; no secret material crosses this variant.
    #[cfg(feature = "real-dom-adaptor")]
    #[error("{0}")]
    Adaptor(#[from] dom_adaptor::AdaptorError),
}

/// Canonical layout of the adaptor pre-signature.
///
/// [AUTHORITY: dom-adaptor a182563]
/// `AdaptorPreSignatureV1::ENCODED_LEN == 162`:
///
/// ```text
/// [  0.. 32) claim_template_hash
/// [ 32.. 65) adaptor_point T          (SEC1 comprimido, 33)
/// [ 65.. 98) aggregate_nonce_hat R̂    (SEC1 comprimido, 33)
/// [ 98..130) scalar_hat ŝ
/// [130..162) transcript_hash
/// ```
pub mod pre_signature_layout {
    /// Total encoding length.
    pub const ENCODED_LEN: usize = 162;
    /// Offset of the claim template hash.
    pub const CLAIM_TEMPLATE_HASH: core::ops::Range<usize> = 0..32;
    /// Offset of the adaptor point.
    pub const ADAPTOR_POINT: core::ops::Range<usize> = 32..65;
    /// Offset of the aggregate nonce.
    pub const AGGREGATE_NONCE_HAT: core::ops::Range<usize> = 65..98;
    /// Offset of the scalar.
    pub const SCALAR_HAT: core::ops::Range<usize> = 98..130;
    /// Offset of the transcript hash.
    pub const TRANSCRIPT_HASH: core::ops::Range<usize> = 130..162;
}

/// Raw bytes of a pre-signature, validated only for length.
///
/// Exists so the transport can resend IDENTICAL bytes (I7) without ever
/// recomputing a signature or nonce. Cryptographic validation always belongs
/// to the real `AdaptorPreSignatureV1`.
#[derive(Clone, PartialEq, Eq)]
pub struct PreSignatureBytes([u8; pre_signature_layout::ENCODED_LEN]);

impl core::fmt::Debug for PreSignatureBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PreSignatureBytes(<162 bytes>)")
    }
}

impl PreSignatureBytes {
    /// Validates the exact length before any allocation (I14).
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LegError> {
        if bytes.len() != pre_signature_layout::ENCODED_LEN {
            return Err(LegError::InvalidLength {
                expected: pre_signature_layout::ENCODED_LEN,
                got: bytes.len(),
            });
        }
        let mut buf = [0u8; pre_signature_layout::ENCODED_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    /// Adaptor point `T` embedded in the encoding.
    pub fn adaptor_point(&self) -> AdaptorPointBytes {
        let mut t = [0u8; 33];
        t.copy_from_slice(&self.0[pre_signature_layout::ADAPTOR_POINT]);
        AdaptorPointBytes(t)
    }

    /// Embedded claim template hash.
    pub fn claim_template_hash(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.0[pre_signature_layout::CLAIM_TEMPLATE_HASH]);
        h
    }

    /// Embedded transcript hash.
    pub fn transcript_hash(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.0[pre_signature_layout::TRANSCRIPT_HASH]);
        h
    }

    /// Raw bytes (for byte-identical resend, I7).
    pub fn as_bytes(&self) -> &[u8; pre_signature_layout::ENCODED_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_layout_matches_the_pinned_crate() {
        // [AUTHORITY] ENCODED_LEN = 162 and the fields are contiguous.
        assert_eq!(pre_signature_layout::ENCODED_LEN, 162);
        assert_eq!(
            pre_signature_layout::CLAIM_TEMPLATE_HASH.len()
                + pre_signature_layout::ADAPTOR_POINT.len()
                + pre_signature_layout::AGGREGATE_NONCE_HAT.len()
                + pre_signature_layout::SCALAR_HAT.len()
                + pre_signature_layout::TRANSCRIPT_HASH.len(),
            162
        );
        assert_eq!(pre_signature_layout::ADAPTOR_POINT.start, 32);
        assert_eq!(pre_signature_layout::TRANSCRIPT_HASH.end, 162);
    }

    #[cfg(feature = "real-dom-adaptor")]
    #[test]
    fn layout_and_registry_come_from_the_pinned_crate() {
        assert_eq!(
            pre_signature_layout::ENCODED_LEN,
            dom_adaptor::AdaptorPreSignatureV1::ENCODED_LEN
        );
        // The registry is the pin's; dom-leg has no copy to diverge.
        assert_eq!(PurposeV1::Refund.to_byte(), 0x01);
        assert_eq!(PurposeV1::ClaimAdaptor.to_byte(), 0x02);
        assert_eq!(PurposeV1::Funding.to_byte(), 0x03);
        assert!(PurposeV1::try_from(0x04u8)
            .map(|purpose| !purpose.is_strict_v1_authorized())
            .unwrap_or(false));
    }

    #[test]
    fn wrong_length_is_rejected_before_allocation() {
        assert_eq!(
            PreSignatureBytes::from_slice(&[0u8; 161]).unwrap_err(),
            LegError::InvalidLength {
                expected: 162,
                got: 161
            }
        );
        assert!(PreSignatureBytes::from_slice(&[0u8; 163]).is_err());
    }

    #[test]
    fn debug_never_leaks_material() {
        let mut buf = [0u8; pre_signature_layout::ENCODED_LEN];
        buf[pre_signature_layout::SCALAR_HAT].fill(5);
        let pre = PreSignatureBytes::from_slice(&buf).unwrap();
        let rendered = format!("{pre:?}");
        assert!(!rendered.contains("05"), "I6");
        assert!(rendered.contains("162 bytes"));
    }
}

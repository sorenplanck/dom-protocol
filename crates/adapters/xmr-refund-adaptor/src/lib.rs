//! Non-cooperative XMR refund: the mirror of the claim path.
//!
//! # Why this exists
//!
//! The claim path alone is not an atomic swap. In a DOM→XMR route the XMR
//! funder places Monero in an output whose spend key is the sum of two shares:
//! the one they hold and the one the counterparty proves, through the
//! cross-curve DLEQ, to be the same witness as the DOM adaptor point. When the
//! counterparty claims the DOM leg they reveal that witness on the DOM chain,
//! and the funder combines it with their own share and sweeps. That is the
//! happy path, and `xmr-kaystra-bridge` implements it.
//!
//! If the counterparty simply never claims, the funder is stuck: the Monero is
//! in a shared output they cannot open alone, and no timelock on the Monero
//! side helps, because Monero has no script that could enforce one. The funds
//! are recoverable only if the *other* share also becomes learnable.
//!
//! # The construction
//!
//! This crate is the symmetric half. Exactly as the DOM **claim** reveals the
//! counterparty's share, the DOM **refund** reveals the funder-side share:
//!
//! ```text
//!   claim  path :  DOM claim  reveals  t  (ROLE_XMR_SHARED_SPEND)
//!   refund path :  DOM refund reveals  u  (ROLE_XMR_REFUND_SHARE)
//! ```
//!
//! Both `t` and `u` are 252-bit cross-curve secrets: each has a secp256k1
//! point that serves as a DOM adaptor point, and an ed25519 scalar that is a
//! Monero spend share, tied together by the same audited DLEQ construction the
//! claim path uses. The two proofs carry different role tags, so a proof minted
//! for one path does not verify for the other.
//!
//! With both paths adaptor-bound, exactly one of them can complete, and either
//! completion teaches the waiting party the share they were missing:
//!
//! - counterparty claims DOM → funder learns `t` → funder sweeps the Monero;
//! - funder refunds DOM after the deadline → counterparty learns `u` → the
//!   counterparty sweeps the Monero back.
//!
//! Neither party can take both legs, and neither can strand the other.
//!
//! # What this crate does and does not do
//!
//! It supplies the refund-side secret, its bound proof, and a concrete
//! [`NonCooperativeRefundCapability`] that validates a frozen refund artifact
//! against that proof — the executor whose absence made every production route
//! fail closed.
//!
//! It does **not** by itself make the DOM refund path adaptor-bound. That is a
//! change in the DOM scriptless core: `dom-scriptless-crypto` today has
//! `claim_adaptor_round` and no refund equivalent, so the DOM refund is
//! timelock-only and reveals nothing. Until a refund adaptor round exists and
//! is ratified, [`DomRefundAdaptorExecutor::validate_artifact`] accepts an
//! artifact only when its refund point matches this proof — it can prove the
//! share is recoverable *given* a revealing refund, but it cannot make the DOM
//! refund reveal. See `docs/specifications/normative/NAR-DC-P1-009`.

#![forbid(unsafe_code)]

use blake2::{digest::consts::U32, Blake2b, Digest};
use counterparty_api::AdaptorPointBytes;
use rand::{CryptoRng, RngCore};
use xmr_crypto::XmrSpendShare;
use xmr_dleq_sigma::{
    prove_bound, revealed_dom_secret_to_xmr_scalar, verify_bound, BoundCrossCurveProofV1,
    CrossCurvePublicClaim, CrossCurveSecret252, DleqError, ROLE_XMR_REFUND_SHARE,
};
use xmr_refund_policy::{NonCooperativeRefundCapability, RefundPolicyError, XmrRefundArtifactV1};

type Blake2b256 = Blake2b<U32>;

/// Domain separator for this executor's implementation-profile hash.
const EXECUTOR_PROFILE_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-REFUND-ADAPTOR/V1\0";

/// Refund-adaptor failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefundAdaptorError {
    /// Cross-curve proof failed.
    #[error("cross-curve refund secret: {0}")]
    Dleq(#[from] DleqError),
    /// The revealed scalar is not the witness this proof commits to.
    #[error("revealed refund witness does not match the proof")]
    WitnessMismatch,
    /// The recovered share is not a canonical Monero scalar.
    #[error("recovered refund share is not a canonical XMR scalar")]
    NonCanonicalShare,
}

/// The refund-side secret and its bound proof.
///
/// Held by the party who funds the Monero leg. `Debug` never shows the secret.
pub struct XmrRefundSecret {
    secret: CrossCurveSecret252,
    proof: BoundCrossCurveProofV1,
}

impl core::fmt::Debug for XmrRefundSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("XmrRefundSecret")
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl XmrRefundSecret {
    /// Generates the refund secret bound to this settlement and context under
    /// [`ROLE_XMR_REFUND_SHARE`].
    pub fn generate(
        settlement_id: [u8; 32],
        context_hash: [u8; 32],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, RefundAdaptorError> {
        let secret = CrossCurveSecret252::generate(rng);
        let proof = prove_bound(
            &secret,
            settlement_id,
            context_hash,
            ROLE_XMR_REFUND_SHARE,
            rng,
        )?;
        Ok(Self { secret, proof })
    }

    /// The public bound proof, published so the counterparty can verify that
    /// the refund point and the refund share are the same witness.
    pub fn proof(&self) -> &BoundCrossCurveProofV1 {
        &self.proof
    }

    /// The DOM adaptor point the refund path must be bound to.
    pub fn dom_refund_point(&self) -> AdaptorPointBytes {
        AdaptorPointBytes(self.proof.bundle.claim.secp_compressed)
    }

    /// Runs an operation with the canonical Monero refund share.
    pub fn with_xmr_share<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        let share = self.secret.xmr_share_little_endian();
        operation(&share)
    }
}

/// Verifies a counterparty's refund proof and returns the only admissible
/// refund point.
///
/// The role tag is [`ROLE_XMR_REFUND_SHARE`], so a proof minted for the claim
/// path is refused here.
pub fn verify_refund_bundle(
    proof: &BoundCrossCurveProofV1,
    settlement_id: &[u8; 32],
    context_hash: &[u8; 32],
) -> Result<CrossCurvePublicClaim, RefundAdaptorError> {
    Ok(verify_bound(
        proof,
        settlement_id,
        context_hash,
        ROLE_XMR_REFUND_SHARE,
    )?)
}

/// Recovers the Monero refund share from the scalar a DOM refund revealed.
///
/// This is the refund-path mirror of the claim-path conversion: the big-endian
/// secp scalar the DOM chain exposed is mapped onto ed25519 and checked against
/// the claim the proof commits to, so a scalar that is not this settlement's
/// refund witness is refused before it can be combined into a spend key.
pub fn refund_share_from_revealed_dom_secret(
    revealed_big_endian: [u8; 32],
    claim: &CrossCurvePublicClaim,
) -> Result<XmrSpendShare, RefundAdaptorError> {
    let share_bytes = revealed_dom_secret_to_xmr_scalar(revealed_big_endian, claim)
        .map_err(|_| RefundAdaptorError::WitnessMismatch)?;
    XmrSpendShare::from_canonical_bytes(share_bytes)
        .map_err(|_| RefundAdaptorError::NonCanonicalShare)
}

/// The concrete non-cooperative refund executor.
///
/// It is bound to one settlement's refund proof. `validate_artifact` admits an
/// artifact only when the artifact's refund point is exactly the point this
/// proof commits to, so a route cannot be admitted for production against a
/// refund construction that this executor could not actually perform.
#[derive(Debug)]
pub struct DomRefundAdaptorExecutor {
    claim: CrossCurvePublicClaim,
    profile_hash: [u8; 32],
}

impl DomRefundAdaptorExecutor {
    /// Builds an executor from a verified refund claim.
    ///
    /// The profile hash commits to this crate's domain and to the exact refund
    /// point, so two settlements never share an executor identity and the
    /// artifact's `executor_profile_hash` cannot be satisfied by an executor
    /// bound to a different route.
    pub fn new(claim: CrossCurvePublicClaim) -> Self {
        let profile_hash = Blake2b256::new()
            .chain_update(EXECUTOR_PROFILE_DOMAIN)
            .chain_update(claim.secp_compressed)
            .chain_update(claim.ed_compressed)
            .finalize()
            .into();
        Self {
            claim,
            profile_hash,
        }
    }

    /// The refund claim this executor can act on.
    pub fn claim(&self) -> &CrossCurvePublicClaim {
        &self.claim
    }

    /// Recovers the Monero refund share once a DOM refund has revealed it.
    pub fn recover_share(
        &self,
        revealed_big_endian: [u8; 32],
    ) -> Result<XmrSpendShare, RefundAdaptorError> {
        refund_share_from_revealed_dom_secret(revealed_big_endian, &self.claim)
    }
}

impl NonCooperativeRefundCapability for DomRefundAdaptorExecutor {
    fn profile_hash(&self) -> [u8; 32] {
        self.profile_hash
    }

    fn validate_artifact(&self, artifact: &XmrRefundArtifactV1) -> Result<(), RefundPolicyError> {
        // The artifact must name the refund point this executor holds the
        // witness relationship for. Anything else describes a refund this
        // executor cannot carry out, and admitting it would let a route reach
        // production with a recovery path that does not exist.
        if artifact.adaptor_point_sec1 != self.claim.secp_compressed {
            return Err(RefundPolicyError::ArtifactNotExecutable);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETTLEMENT: [u8; 32] = [9; 32];
    const CONTEXT: [u8; 32] = [7; 32];

    fn refund_secret() -> XmrRefundSecret {
        XmrRefundSecret::generate(SETTLEMENT, CONTEXT, &mut rand::thread_rng())
            .expect("refund secret generates")
    }

    fn artifact_for(point: [u8; 33], executor_profile_hash: [u8; 32]) -> XmrRefundArtifactV1 {
        XmrRefundArtifactV1 {
            template_hash: [0x22; 32],
            adaptor_point_sec1: point,
            executor_profile_hash,
            deadline: 500,
        }
    }

    #[test]
    fn a_refund_proof_verifies_only_under_the_refund_role() {
        let secret = refund_secret();
        verify_refund_bundle(secret.proof(), &SETTLEMENT, &CONTEXT).expect("refund role verifies");
        // The claim path must not accept this proof: the two paths carry
        // different witnesses and confusing them would let one completion
        // satisfy both legs.
        assert!(verify_bound(
            secret.proof(),
            &SETTLEMENT,
            &CONTEXT,
            xmr_dleq_sigma::ROLE_XMR_SHARED_SPEND,
        )
        .is_err());
    }

    #[test]
    fn a_refund_proof_does_not_verify_under_another_settlement_or_context() {
        let secret = refund_secret();
        assert!(verify_refund_bundle(secret.proof(), &[1; 32], &CONTEXT).is_err());
        assert!(verify_refund_bundle(secret.proof(), &SETTLEMENT, &[1; 32]).is_err());
    }

    #[test]
    fn the_executor_admits_only_its_own_refund_point() {
        let secret = refund_secret();
        let claim = verify_refund_bundle(secret.proof(), &SETTLEMENT, &CONTEXT).expect("verifies");
        let executor = DomRefundAdaptorExecutor::new(claim);

        executor
            .validate_artifact(&artifact_for(
                claim.secp_compressed,
                executor.profile_hash(),
            ))
            .expect("its own point is executable");

        // A different settlement's refund point describes a recovery this
        // executor cannot perform.
        let other = refund_secret();
        let other_claim =
            verify_refund_bundle(other.proof(), &SETTLEMENT, &CONTEXT).expect("verifies");
        assert_eq!(
            executor
                .validate_artifact(&artifact_for(
                    other_claim.secp_compressed,
                    executor.profile_hash()
                ))
                .unwrap_err(),
            RefundPolicyError::ArtifactNotExecutable
        );
    }

    #[test]
    fn two_settlements_never_share_an_executor_identity() {
        let first = refund_secret();
        let second = refund_secret();
        let first_claim =
            verify_refund_bundle(first.proof(), &SETTLEMENT, &CONTEXT).expect("verifies");
        let second_claim =
            verify_refund_bundle(second.proof(), &SETTLEMENT, &CONTEXT).expect("verifies");
        assert_ne!(
            DomRefundAdaptorExecutor::new(first_claim).profile_hash(),
            DomRefundAdaptorExecutor::new(second_claim).profile_hash()
        );
    }

    #[test]
    fn a_scalar_that_is_not_the_refund_witness_is_refused() {
        let secret = refund_secret();
        let claim = verify_refund_bundle(secret.proof(), &SETTLEMENT, &CONTEXT).expect("verifies");
        let executor = DomRefundAdaptorExecutor::new(claim);
        // Well-formed but unrelated: it must be refused before it can be
        // combined into a spend key.
        let mut wrong = [0u8; 32];
        wrong[31] = 42;
        assert_eq!(
            executor.recover_share(wrong).unwrap_err(),
            RefundAdaptorError::WitnessMismatch
        );
    }

    #[test]
    fn the_secret_debug_never_shows_the_witness() {
        let rendered = format!("{:?}", refund_secret());
        assert!(rendered.contains("redacted"));
    }
}

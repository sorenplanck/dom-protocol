//! One-shot route secret whose secp claim is the existing DOM adaptor point.

#![forbid(unsafe_code)]

use counterparty_api::{AdaptorPointBytes, RevealedSecretBytes};
use rand::{CryptoRng, RngCore};
use xmr_dleq_sigma::{
    prove_bound, verify_bound, BoundCrossCurveProofV1, CrossCurveSecret252, DleqError,
    ROLE_XMR_SHARED_SPEND,
};

/// Route-secret failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteSecretError {
    /// Cross-curve proof failed.
    #[error("cross-curve route secret: {0}")]
    Dleq(#[from] DleqError),
}

/// Secret plus its public bound proof. Secret `Debug` is redacted by construction.
pub struct XmrRouteSecret {
    secret: CrossCurveSecret252,
    proof: BoundCrossCurveProofV1,
}

impl core::fmt::Debug for XmrRouteSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XmrRouteSecret")
            .field("secret", &"<redacted>")
            .field("settlement_id", &"<public-id>")
            .finish_non_exhaustive()
    }
}

impl XmrRouteSecret {
    /// Generates a one-shot secret and setup proof.
    pub fn generate(
        settlement_id: [u8; 32],
        context_hash: [u8; 32],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, RouteSecretError> {
        let secret = CrossCurveSecret252::generate(rng);
        let proof = prove_bound(
            &secret,
            settlement_id,
            context_hash,
            ROLE_XMR_SHARED_SPEND,
            rng,
        )?;
        Ok(Self { secret, proof })
    }

    /// Public proof package.
    pub fn proof(&self) -> &BoundCrossCurveProofV1 {
        &self.proof
    }

    /// Exact DOM adaptor point `T`.
    pub fn dom_adaptor_point(&self) -> AdaptorPointBytes {
        AdaptorPointBytes(self.proof.bundle.claim.secp_compressed)
    }

    /// Runs a test/DOM-adaptor operation with the revealed big-endian scalar.
    pub fn with_revealed_dom_secret<R>(
        &self,
        operation: impl FnOnce(&RevealedSecretBytes) -> R,
    ) -> R {
        let revealed = RevealedSecretBytes::new(self.secret.dom_secret_big_endian());
        operation(&revealed)
    }

    /// Runs a local setup operation with the canonical XMR share.
    pub fn with_xmr_share<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        let share = self.secret.xmr_share_little_endian();
        operation(&share)
    }
}

/// Verifies the counterparty proof and returns the only admissible DOM point.
pub fn verify_counterparty_bundle(
    proof: &BoundCrossCurveProofV1,
    settlement_id: &[u8; 32],
    context_hash: &[u8; 32],
) -> Result<AdaptorPointBytes, RouteSecretError> {
    let claim = verify_bound(proof, settlement_id, context_hash, ROLE_XMR_SHARED_SPEND)?;
    Ok(AdaptorPointBytes(claim.secp_compressed))
}

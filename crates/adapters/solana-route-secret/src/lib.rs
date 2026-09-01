//! One-shot route secret binding the DOM secp256k1 point to Solana ed25519.

#![forbid(unsafe_code)]

use counterparty_api::{AdaptorPointBytes, RevealedSecretBytes};
use rand::{CryptoRng, RngCore};
use xmr_dleq_sigma::{
    prove_bound, verify_bound, BoundCrossCurveProofV1, CrossCurvePublicClaim, CrossCurveSecret252,
    DleqError,
};

// The role byte is drawn from the closed registry in `xmr_dleq_sigma`, never
// minted locally: the local byte this crate used to define collided with
// `ROLE_XMR_REFUND_SHARE`.
pub use xmr_dleq_sigma::ROLE_SOLANA_CONDITION_LOCK;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteSecretError {
    #[error("Solana cross-curve route secret: {0}")]
    Dleq(#[from] DleqError),
    #[error("restored witness does not open the stored proof's claim")]
    WitnessClaimMismatch,
}

/// Secret plus public settlement-bound proof.
pub struct SolanaRouteSecret {
    secret: CrossCurveSecret252,
    proof: BoundCrossCurveProofV1,
}

impl core::fmt::Debug for SolanaRouteSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SolanaRouteSecret")
            .field("secret", &"<redacted>")
            .field("settlement_id", &"<public-id>")
            .finish_non_exhaustive()
    }
}

impl SolanaRouteSecret {
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
            ROLE_SOLANA_CONDITION_LOCK,
            rng,
        )?;
        Ok(Self { secret, proof })
    }

    /// Rebuilds the session secret from the persisted witness and the
    /// registered proof, after a restart.
    ///
    /// The witness alone does not name a settlement and the proof alone does
    /// not carry a secret, so both are demanded and checked against each
    /// other: the proof must verify for its own binding, and re-proving with
    /// the restored witness must reproduce exactly the registered public
    /// claim. A store that returns the wrong row, or a proof swapped for a
    /// different settlement's, is refused rather than resumed.
    pub fn restore(
        witness_little_endian: [u8; 32],
        proof: BoundCrossCurveProofV1,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, RouteSecretError> {
        let secret = CrossCurveSecret252::from_little_endian(witness_little_endian)?;
        let registered = verify_bound(
            &proof,
            &proof.settlement_id,
            &proof.context_hash,
            ROLE_SOLANA_CONDITION_LOCK,
        )?;
        let reproved = prove_bound(
            &secret,
            proof.settlement_id,
            proof.context_hash,
            ROLE_SOLANA_CONDITION_LOCK,
            rng,
        )?;
        if reproved.bundle.claim != registered {
            return Err(RouteSecretError::WitnessClaimMismatch);
        }
        Ok(Self { secret, proof })
    }

    /// Closure-only access to the canonical little-endian witness, for the
    /// encrypted store.
    pub fn with_witness_little_endian<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.secret.xmr_share_little_endian())
    }

    pub fn proof(&self) -> &BoundCrossCurveProofV1 {
        &self.proof
    }

    pub fn dom_adaptor_point(&self) -> AdaptorPointBytes {
        AdaptorPointBytes(self.proof.bundle.claim.secp_compressed)
    }

    pub fn solana_claim_point(&self) -> [u8; 32] {
        self.proof.bundle.claim.ed_compressed
    }

    pub fn with_revealed_dom_secret<R>(
        &self,
        operation: impl FnOnce(&RevealedSecretBytes) -> R,
    ) -> R {
        operation(&RevealedSecretBytes::new(
            self.secret.dom_secret_big_endian(),
        ))
    }
}

pub fn verify_counterparty_bundle(
    proof: &BoundCrossCurveProofV1,
    settlement_id: &[u8; 32],
    context_hash: &[u8; 32],
) -> Result<CrossCurvePublicClaim, RouteSecretError> {
    Ok(verify_bound(
        proof,
        settlement_id,
        context_hash,
        ROLE_SOLANA_CONDITION_LOCK,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_round_trips_and_refuses_a_foreign_witness() {
        let mut rng = rand::thread_rng();
        let route = SolanaRouteSecret::generate([1; 32], [2; 32], &mut rng).unwrap();
        let witness = route.with_witness_little_endian(|w| *w);
        let restored =
            SolanaRouteSecret::restore(witness, route.proof().clone(), &mut rng).unwrap();
        assert_eq!(restored.solana_claim_point(), route.solana_claim_point());

        let other = SolanaRouteSecret::generate([1; 32], [2; 32], &mut rng).unwrap();
        let foreign = other.with_witness_little_endian(|w| *w);
        assert_eq!(
            SolanaRouteSecret::restore(foreign, route.proof().clone(), &mut rng).unwrap_err(),
            RouteSecretError::WitnessClaimMismatch
        );
    }

    #[test]
    fn point_is_shared_with_dom() {
        let mut rng = rand::thread_rng();
        let route = SolanaRouteSecret::generate([1; 32], [2; 32], &mut rng).unwrap();
        let claim = verify_counterparty_bundle(route.proof(), &[1; 32], &[2; 32]).unwrap();
        assert_eq!(route.dom_adaptor_point().0, claim.secp_compressed);
        assert_eq!(route.solana_claim_point(), claim.ed_compressed);
    }
}

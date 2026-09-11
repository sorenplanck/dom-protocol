//! Level-1 per-leg witness authority — the §7.4 materializer seam.
//!
//! One value of [`RouteLegWitnessAuthorityV1`] is the daemon's ONLY path
//! from a downstream reveal to the upstream leg's witness under the V3
//! blinded-route family:
//!
//! ```text
//! exposing child reveals bytes
//!   → verify_revealed_leg_scalar(Downstream, bytes)      // w_dn
//!   → translate with δ derived from the provisioned seed // w_up
//!   → consuming child receives an ordinary witness
//! ```
//!
//! The leg offset δ is DERIVED here, per call, from the route derivation
//! seed the V4 secret stream provisions — it is never transported, never
//! stored, and zeroizes when the call returns (I2). The relation the
//! translation lands on is the one the composed binding's offset-relation
//! proof committed to: a wrong seed or a foreign offset produces a sum
//! that does not open the upstream lock point and refuses before any
//! claim path sees it. No child, actuator, contract or program learns
//! that blinding exists — each leg sees an ordinary witness.

use std::rc::Rc;

use route_composer::leg_blinding::{derive_leg_offset_v1, LegWitnessV1};
use route_composer::{ComposedBindingV3, ComposedLeg};
use zeroize::Zeroizing;

/// Leg byte of the downstream leg (reveals first) in the derivation
/// context, pinned for the whole V3 family: the two endpoint daemons must
/// agree on these bytes or they derive different offsets.
pub const LEG_BLINDING_DOWNSTREAM_LEG_BYTE_V1: u8 = 0;
/// Leg byte of the upstream leg (consumes the translation), pinned.
pub const LEG_BLINDING_UPSTREAM_LEG_BYTE_V1: u8 = 1;

/// Why the leg-witness authority refused, by name. Every refusal is
/// terminal for the attempted hand-off; nothing partial is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LegWitnessAuthorityRefusalV1 {
    /// The route id or the derivation seed was all-zero.
    #[error("leg-witness authority scope is invalid")]
    InvalidScope,
    /// The observed bytes do not open the downstream leg's lock point.
    #[error("observed scalar does not open the downstream leg")]
    WrongLegScalar,
    /// The offset derivation refused (unreachable for a valid seed; a
    /// refusal proves corrupted material and stops the route).
    #[error("leg offset derivation refused")]
    OffsetDerivation,
    /// The translated sum does not open the upstream leg's committed
    /// lock point: the seed does not derive the offset this binding's
    /// relation proof committed to.
    #[error("witness translation refused")]
    TranslationRefused,
}

/// The one authority that turns a downstream reveal into the upstream
/// witness for one V3 route. Holds the route derivation seed; neither
/// the seed nor any derived value is exposed, logged or encoded.
pub struct RouteLegWitnessAuthorityV1 {
    route_id: [u8; 32],
    composition: Rc<ComposedBindingV3>,
    route_derivation_seed: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for RouteLegWitnessAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RouteLegWitnessAuthorityV1([redacted])")
    }
}

impl RouteLegWitnessAuthorityV1 {
    /// Binds the authority to one route and one admitted V3 composition.
    ///
    /// The composition is the type-state evidence that the per-leg points
    /// and the offset-relation proof were verified at admission; this
    /// constructor only refuses degenerate scope material.
    pub fn new(
        route_id: [u8; 32],
        composition: Rc<ComposedBindingV3>,
        route_derivation_seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, LegWitnessAuthorityRefusalV1> {
        if route_id == [0_u8; 32] || route_derivation_seed.iter().all(|byte| *byte == 0) {
            return Err(LegWitnessAuthorityRefusalV1::InvalidScope);
        }
        Ok(Self {
            route_id,
            composition,
            route_derivation_seed,
        })
    }

    /// The sealed-retention identity of a downstream exposure under the
    /// V3 family (the plan-source seam's vault half).
    ///
    /// Adjudication, recorded here because the vault type predates V3:
    /// [`route_secret_vault::RouteSecretBindingsV2`] binds "the adaptor
    /// point the sealed scalar opens". Under V3 the observed downstream
    /// reveal opens the DOWNSTREAM leg's own lock point, and the V3
    /// binding digest already pins the whole route (both leg points and
    /// the offset-relation proof) — so the existing bindings type is
    /// exactly right with `A_dn` in the point slot, and the vault grows
    /// no second format.
    #[cfg(feature = "production")]
    pub fn retention_bindings_for_downstream_exposure(
        &self,
        exposure: route_secret_vault::RouteSecretExposureV2,
    ) -> Result<route_secret_vault::RouteSecretBindingsV2, LegWitnessAuthorityRefusalV1> {
        route_secret_vault::RouteSecretBindingsV2::new(
            self.route_id,
            self.composition.binding_digest(),
            exposure,
            self.composition.downstream_lock_point_sec1(),
        )
        .map_err(|_| LegWitnessAuthorityRefusalV1::InvalidScope)
    }

    /// The §7.4 flow, whole: verify a downstream reveal against the
    /// downstream lock point, derive δ locally, translate, and hand back
    /// the upstream leg's ordinary witness — or refuse by name.
    pub fn translate_downstream_exposure(
        &self,
        observed: &[u8; 32],
    ) -> Result<LegWitnessV1, LegWitnessAuthorityRefusalV1> {
        let revealed = self
            .composition
            .verify_revealed_leg_scalar(ComposedLeg::Downstream, observed)
            .map_err(|_| LegWitnessAuthorityRefusalV1::WrongLegScalar)?;
        let delta = derive_leg_offset_v1(
            &self.route_derivation_seed,
            &self.route_id,
            LEG_BLINDING_DOWNSTREAM_LEG_BYTE_V1,
            LEG_BLINDING_UPSTREAM_LEG_BYTE_V1,
        )
        .map_err(|_| LegWitnessAuthorityRefusalV1::OffsetDerivation)?;
        self.composition
            .translate_revealed_downstream_witness(&revealed, &delta)
            .map_err(|_| LegWitnessAuthorityRefusalV1::TranslationRefused)
    }
}

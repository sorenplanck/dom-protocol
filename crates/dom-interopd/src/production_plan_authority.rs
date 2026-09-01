//! Production base plan authority for the settlement coordinator.
//!
//! The coordinator installs a composite settlement plan only against an
//! authorization from a `SettlementPlanAuthorityV1` whose identity it has
//! pinned. This is that authority: it re-authenticates every plan the
//! materializer produced against the frozen, threshold-authenticated route
//! facts — route identity, per-leg terms, the registry manifest, and the DOM
//! and counterparty profile/deployment digests — and only then issues an
//! authorization committing to exactly those facts. It receives no
//! transaction bytes and no secret material; it is a narrow authenticator,
//! not a signer.
//!
//! It is the independent second check on the same authenticated inputs the
//! materializer used: a plan whose bindings drift from the frozen route is
//! refused here even though it reached the coordinator, so a materializer
//! defect cannot install an off-route plan.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use settlement_coordinator::{
    Digest32, PlanAuthorityRefusalV1, PlanAuthorizationRequestV1, PlanAuthorizationV1,
    SettlementActionV1, SettlementLegV1, SettlementPlanAuthorityV1,
};

const ZERO_DIGEST: Digest32 = [0; 32];
const EVIDENCE_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/PLAN-AUTHORITY/EVIDENCE/V1\0";

/// Trusted clock boundary for authorization validity windows.
pub(crate) trait ProductionPlanAuthorityClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, PlanAuthorityRefusalV1>;
}

/// Host wall-time adapter.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemProductionPlanAuthorityClockV1;

impl ProductionPlanAuthorityClockV1 for SystemProductionPlanAuthorityClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, PlanAuthorityRefusalV1> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PlanAuthorityRefusalV1::Unavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| PlanAuthorityRefusalV1::Unavailable)
    }
}

/// The authenticated facts one route leg's plan must reproduce exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionPlanLegPinsV1 {
    pub(crate) settlement_id: Digest32,
    pub(crate) terms_digest: Digest32,
    pub(crate) counterparty_profile_digest: Digest32,
    pub(crate) counterparty_deployment_digest: Digest32,
}

/// Route-scoped authenticated pins shared by both legs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionPlanAuthorityPinsV1 {
    pub(crate) authority_id: Digest32,
    pub(crate) route_id: Digest32,
    pub(crate) registry_digest: Digest32,
    pub(crate) dom_profile_digest: Digest32,
    pub(crate) dom_deployment_digest: Digest32,
    pub(crate) upstream: ProductionPlanLegPinsV1,
    pub(crate) downstream: ProductionPlanLegPinsV1,
}

impl ProductionPlanAuthorityPinsV1 {
    fn all_nonzero(&self) -> bool {
        let legs = [self.upstream, self.downstream];
        self.authority_id != ZERO_DIGEST
            && self.route_id != ZERO_DIGEST
            && self.registry_digest != ZERO_DIGEST
            && self.dom_profile_digest != ZERO_DIGEST
            && self.dom_deployment_digest != ZERO_DIGEST
            && legs.iter().all(|leg| {
                leg.settlement_id != ZERO_DIGEST
                    && leg.terms_digest != ZERO_DIGEST
                    && leg.counterparty_profile_digest != ZERO_DIGEST
                    && leg.counterparty_deployment_digest != ZERO_DIGEST
            })
    }

    const fn leg(&self, leg: SettlementLegV1) -> ProductionPlanLegPinsV1 {
        match leg {
            SettlementLegV1::Upstream => self.upstream,
            SettlementLegV1::Downstream => self.downstream,
        }
    }
}

/// Durable authorization-window bound, in milliseconds. A plan authorization
/// is valid only for this long after it is issued; the coordinator installs
/// plans immediately, so a short window is safe and bounds replay.
pub(crate) const PLAN_AUTHORIZATION_WINDOW_MS_V1: u64 = 120_000;

/// Production base plan authority.
pub(crate) struct ProductionRoutePlanAuthorityV1<C> {
    pins: ProductionPlanAuthorityPinsV1,
    clock: C,
}

impl<C> core::fmt::Debug for ProductionRoutePlanAuthorityV1<C> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRoutePlanAuthorityV1([pins redacted])")
    }
}

impl<C: ProductionPlanAuthorityClockV1> ProductionRoutePlanAuthorityV1<C> {
    /// Builds the authority from authenticated pins. Any zero pin refuses at
    /// construction: an authority that cannot name its route authenticates
    /// nothing.
    pub(crate) fn new(
        pins: ProductionPlanAuthorityPinsV1,
        clock: C,
    ) -> Result<Self, PlanAuthorityRefusalV1> {
        if !pins.all_nonzero() {
            return Err(PlanAuthorityRefusalV1::Refused);
        }
        Ok(Self { pins, clock })
    }

    fn evidence_digest(
        &self,
        plan_digest: Digest32,
        leg: SettlementLegV1,
        action: SettlementActionV1,
        effect_id: Digest32,
        leg_pins: ProductionPlanLegPinsV1,
    ) -> Result<Digest32, PlanAuthorityRefusalV1> {
        let mut hasher = Blake2bVar::new(32).map_err(|_| PlanAuthorityRefusalV1::Unavailable)?;
        let leg_tag = [match leg {
            SettlementLegV1::Upstream => 1u8,
            SettlementLegV1::Downstream => 2,
        }];
        let action_tag = [match action {
            SettlementActionV1::Funding => 1u8,
            SettlementActionV1::Claim => 2,
            SettlementActionV1::Refund => 3,
        }];
        for part in [
            EVIDENCE_DOMAIN_V1,
            self.pins.authority_id.as_slice(),
            plan_digest.as_slice(),
            self.pins.route_id.as_slice(),
            leg_tag.as_slice(),
            action_tag.as_slice(),
            effect_id.as_slice(),
            self.pins.registry_digest.as_slice(),
            self.pins.dom_profile_digest.as_slice(),
            self.pins.dom_deployment_digest.as_slice(),
            leg_pins.settlement_id.as_slice(),
            leg_pins.terms_digest.as_slice(),
            leg_pins.counterparty_profile_digest.as_slice(),
            leg_pins.counterparty_deployment_digest.as_slice(),
        ] {
            let length =
                u64::try_from(part.len()).map_err(|_| PlanAuthorityRefusalV1::Unavailable)?;
            hasher.update(&length.to_be_bytes());
            hasher.update(part);
        }
        let mut output = ZERO_DIGEST;
        hasher
            .finalize_variable(&mut output)
            .map_err(|_| PlanAuthorityRefusalV1::Unavailable)?;
        if output == ZERO_DIGEST {
            return Err(PlanAuthorityRefusalV1::Unavailable);
        }
        Ok(output)
    }
}

impl<C: ProductionPlanAuthorityClockV1> ProductionRoutePlanAuthorityV1<C> {
    /// The authentication core, over the plan's public bindings. Separated so
    /// it can be exercised directly without the coordinator-sealed request.
    fn authorize_bindings(
        &mut self,
        bindings: &settlement_coordinator::SettlementPlanBindingsV1,
        plan_digest: Digest32,
    ) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
        let leg_pins = self.pins.leg(bindings.leg);
        // Every authenticated fact the plan carries must reproduce the frozen
        // route exactly. A single mismatch refuses: the coordinator would
        // otherwise install a plan the route never authorized.
        if plan_digest == ZERO_DIGEST
            || bindings.route_id != self.pins.route_id
            || bindings.registry_digest != self.pins.registry_digest
            || bindings.dom_profile_digest != self.pins.dom_profile_digest
            || bindings.dom_deployment_digest != self.pins.dom_deployment_digest
            || bindings.settlement_id != leg_pins.settlement_id
            || bindings.terms_digest != leg_pins.terms_digest
            || bindings.counterparty_profile_digest != leg_pins.counterparty_profile_digest
            || bindings.counterparty_deployment_digest != leg_pins.counterparty_deployment_digest
        {
            return Err(PlanAuthorityRefusalV1::Refused);
        }
        let evidence_digest = self.evidence_digest(
            plan_digest,
            bindings.leg,
            bindings.action,
            bindings.effect_id,
            leg_pins,
        )?;
        let now = self.clock.now_unix_ms()?;
        let valid_until = now
            .checked_add(PLAN_AUTHORIZATION_WINDOW_MS_V1)
            .ok_or(PlanAuthorityRefusalV1::Unavailable)?;
        PlanAuthorizationV1::new(
            self.pins.authority_id,
            plan_digest,
            evidence_digest,
            valid_until,
        )
        .map_err(|_| PlanAuthorityRefusalV1::Refused)
    }
}

impl<C: ProductionPlanAuthorityClockV1> SettlementPlanAuthorityV1
    for ProductionRoutePlanAuthorityV1<C>
{
    fn authorize_plan(
        &mut self,
        request: PlanAuthorizationRequestV1<'_>,
    ) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
        self.authorize_bindings(request.plan().bindings(), request.plan_digest())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use settlement_coordinator::SettlementPlanBindingsV1;

    struct FixedClock(u64);
    impl ProductionPlanAuthorityClockV1 for FixedClock {
        fn now_unix_ms(&mut self) -> Result<u64, PlanAuthorityRefusalV1> {
            Ok(self.0)
        }
    }

    fn pins() -> ProductionPlanAuthorityPinsV1 {
        ProductionPlanAuthorityPinsV1 {
            authority_id: [0xA1; 32],
            route_id: [0xB2; 32],
            registry_digest: [0xC3; 32],
            dom_profile_digest: [0xD4; 32],
            dom_deployment_digest: [0xD5; 32],
            upstream: ProductionPlanLegPinsV1 {
                settlement_id: [0xE1; 32],
                terms_digest: [0xE2; 32],
                counterparty_profile_digest: [0xE3; 32],
                counterparty_deployment_digest: [0xE4; 32],
            },
            downstream: ProductionPlanLegPinsV1 {
                settlement_id: [0xF1; 32],
                terms_digest: [0xF2; 32],
                counterparty_profile_digest: [0xF3; 32],
                counterparty_deployment_digest: [0xF4; 32],
            },
        }
    }

    fn bindings_for(
        leg: SettlementLegV1,
        pins: &ProductionPlanAuthorityPinsV1,
    ) -> SettlementPlanBindingsV1 {
        let leg_pins = pins.leg(leg);
        SettlementPlanBindingsV1 {
            route_id: pins.route_id,
            effect_id: [0x21; 32],
            settlement_id: leg_pins.settlement_id,
            leg,
            action: SettlementActionV1::Funding,
            fencing_epoch: 7,
            semantic_digest: [0x22; 32],
            terms_digest: leg_pins.terms_digest,
            registry_digest: pins.registry_digest,
            dom_profile_digest: pins.dom_profile_digest,
            dom_deployment_digest: pins.dom_deployment_digest,
            counterparty_profile_digest: leg_pins.counterparty_profile_digest,
            counterparty_deployment_digest: leg_pins.counterparty_deployment_digest,
        }
    }

    #[test]
    fn authorizes_bindings_that_reproduce_the_frozen_route() {
        let pins = pins();
        let mut authority =
            ProductionRoutePlanAuthorityV1::new(pins, FixedClock(1_000)).expect("authority");
        let bindings = bindings_for(SettlementLegV1::Downstream, &pins);
        let authorization = authority
            .authorize_bindings(&bindings, [0x77; 32])
            .expect("authorize");
        assert_eq!(authorization.authority_id(), pins.authority_id);
        assert_eq!(authorization.plan_digest(), [0x77; 32]);
        assert_ne!(authorization.evidence_digest(), ZERO_DIGEST);
        assert_eq!(
            authorization.valid_until_unix_ms(),
            1_000 + PLAN_AUTHORIZATION_WINDOW_MS_V1
        );
    }

    #[test]
    fn refuses_every_single_pin_transplant() {
        let pins = pins();
        let mut authority =
            ProductionRoutePlanAuthorityV1::new(pins, FixedClock(1_000)).expect("authority");
        // Each field, transplanted one at a time, must refuse.
        let mutate: [fn(&mut SettlementPlanBindingsV1); 8] = [
            |b| b.route_id = [0x01; 32],
            |b| b.registry_digest = [0x01; 32],
            |b| b.dom_profile_digest = [0x01; 32],
            |b| b.dom_deployment_digest = [0x01; 32],
            |b| b.settlement_id = [0x01; 32],
            |b| b.terms_digest = [0x01; 32],
            |b| b.counterparty_profile_digest = [0x01; 32],
            |b| b.counterparty_deployment_digest = [0x01; 32],
        ];
        for apply in mutate {
            let mut bindings = bindings_for(SettlementLegV1::Downstream, &pins);
            apply(&mut bindings);
            assert!(matches!(
                authority.authorize_bindings(&bindings, [0x77; 32]),
                Err(PlanAuthorityRefusalV1::Refused)
            ));
        }
    }

    #[test]
    fn refuses_a_leg_pin_swap() {
        let pins = pins();
        let mut authority =
            ProductionRoutePlanAuthorityV1::new(pins, FixedClock(1_000)).expect("authority");
        // A downstream binding carrying the upstream leg's settlement id must
        // refuse: the per-leg pin is selected by the binding's own leg.
        let mut bindings = bindings_for(SettlementLegV1::Downstream, &pins);
        bindings.settlement_id = pins.upstream.settlement_id;
        assert!(matches!(
            authority.authorize_bindings(&bindings, [0x77; 32]),
            Err(PlanAuthorityRefusalV1::Refused)
        ));
    }

    #[test]
    fn evidence_is_leg_and_digest_separated() {
        let pins = pins();
        let mut authority =
            ProductionRoutePlanAuthorityV1::new(pins, FixedClock(1_000)).expect("authority");
        let up = authority
            .authorize_bindings(&bindings_for(SettlementLegV1::Upstream, &pins), [0x77; 32])
            .expect("up");
        let down = authority
            .authorize_bindings(
                &bindings_for(SettlementLegV1::Downstream, &pins),
                [0x77; 32],
            )
            .expect("down");
        assert_ne!(up.evidence_digest(), down.evidence_digest());
        let other_digest = authority
            .authorize_bindings(&bindings_for(SettlementLegV1::Upstream, &pins), [0x88; 32])
            .expect("other digest");
        assert_ne!(up.evidence_digest(), other_digest.evidence_digest());
    }

    #[test]
    fn zero_digest_and_zero_pin_refuse() {
        let pins = pins();
        let mut authority =
            ProductionRoutePlanAuthorityV1::new(pins, FixedClock(1_000)).expect("authority");
        assert!(matches!(
            authority
                .authorize_bindings(&bindings_for(SettlementLegV1::Upstream, &pins), ZERO_DIGEST),
            Err(PlanAuthorityRefusalV1::Refused)
        ));
        let mut bad = pins;
        bad.route_id = ZERO_DIGEST;
        assert!(ProductionRoutePlanAuthorityV1::new(bad, FixedClock(1_000)).is_err());
    }
}

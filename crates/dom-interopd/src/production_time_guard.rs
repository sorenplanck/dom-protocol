//! Production-only revalidation of V2 time authority at new-funding
//! boundaries.
//!
//! Admission freezes an authenticated checkpoint, not a reusable license.
//! This authority keeps the route-scoped durable time store and all of its
//! verification context together. Every *new* funding plan must synchronously
//! consume a fresh one-shot token while the store remains exclusively
//! borrowed. Claim, refund and already-committed funding recovery never enter
//! this gate and therefore cannot be disabled by later time-proof expiry.

#![forbid(unsafe_code)]

use std::{marker::PhantomData, rc::Rc};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use btc_crypto::SecpContext;
use deployment_registry::{AuthoritySetV1, ResolvedRegistryV1};
use kaystra_core::terms::SettlementTermsV1;
use route_executor::{ActionKindV1, ActionProgressV1, EffectIdV1, EventIdV1, LegIdV1, RouteIdV1};
use route_time_anchor::{
    route_scope_digest, CurrentRouteTimeLadderV2, DurableRouteTimeAnchorStoreV2,
    EvidenceInstallOutcomeV2, FrozenRouteTimeCheckpointV2, RouteTimeAnchorErrorV2,
    RouteTimeEvidenceVerificationContextV2, RouteTimePolicyVerificationContextV2,
    SignedRouteTimeEvidenceV2,
};

use crate::admission::{AuthenticatedRouteAdmissionV1, AuthenticatedRouteTimeBindingV2};

#[cfg(feature = "production")]
use route_executor::derive_effect_id_v1;
#[cfg(feature = "production")]
use settlement_coordinator::{
    AggregateStageV1, CanonicalSettlementPlanV1, ChildStageV1, CompositeSettlementPlanV1,
    CoordinatorErrorV1, CoordinatorLeaseV1, CustodyTakeoverStatusV1,
    DurableSettlementCoordinatorV1, PlanAuthorityRefusalV1, PlanAuthorizationRequestV1,
    PlanAuthorizationV1, SettlementActionV1, SettlementLegV1, SettlementPlanAuthorityV1,
    SettlementPlanViewV1, StoredSettlementPlanV1,
};

#[cfg(feature = "production")]
use crate::{
    production_settlement::ProductionSettlementPlanPersistenceV1, supervisor::AuthorityRefusalV1,
};

const FUNDING_TIME_AUTHORIZATION_DOMAIN_V2: &[u8] = b"DOM-INTEROPD/FUNDING-TIME-AUTHORIZATION/V2\0";
#[cfg(feature = "production")]
const FUNDING_PLAN_AUTHORIZATION_EVIDENCE_DOMAIN_V2: &[u8] =
    b"DOM-INTEROPD/FUNDING-PLAN-AUTHORIZATION-EVIDENCE/V2\0";
const ZERO_DIGEST: [u8; 32] = [0; 32];

/// Whether an economic action needs a newly-current time capability.
///
/// Only a funding action with no committed effect crosses the gate. Once the
/// route store committed funding, exact replay/reconciliation is recovery.
/// Claim and refund are always exits and remain available after expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EconomicBoundaryTimeRequirementV2 {
    /// Obtain and synchronously consume a current one-shot authorization.
    CurrentCapabilityForNewFunding,
    /// Do not consult the expiring time authority for this recovery path.
    RecoveryExitWithoutTimeGate,
}

/// Classifies an exact route action without consulting a clock or a mutable
/// authority.
#[expect(
    dead_code,
    reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
)]
pub(crate) const fn economic_boundary_time_requirement_v2(
    action: ActionKindV1,
    progress: ActionProgressV1,
) -> EconomicBoundaryTimeRequirementV2 {
    if matches!(action, ActionKindV1::Funding) && matches!(progress, ActionProgressV1::NotPrepared)
    {
        EconomicBoundaryTimeRequirementV2::CurrentCapabilityForNewFunding
    } else {
        EconomicBoundaryTimeRequirementV2::RecoveryExitWithoutTimeGate
    }
}

/// Exact route-action identity to which a current authorization is bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FundingTimeAuthorizationScopeV2 {
    route_id: RouteIdV1,
    leg: LegIdV1,
    action: ActionKindV1,
    fencing_epoch: u64,
    effect_id: EffectIdV1,
    event_id: EventIdV1,
    plan_digest: [u8; 32],
}

impl FundingTimeAuthorizationScopeV2 {
    /// Constructs only a new-funding scope. Claim/refund cannot be smuggled
    /// through the expiring gate.
    pub(crate) fn new(
        route_id: RouteIdV1,
        leg: LegIdV1,
        action: ActionKindV1,
        fencing_epoch: u64,
        effect_id: EffectIdV1,
        event_id: EventIdV1,
        plan_digest: [u8; 32],
    ) -> Result<Self, ProductionTimeGuardErrorV2> {
        if route_id == ZERO_DIGEST
            || effect_id == ZERO_DIGEST
            || event_id == ZERO_DIGEST
            || plan_digest == ZERO_DIGEST
            || fencing_epoch == 0
        {
            return Err(ProductionTimeGuardErrorV2::InvalidFundingBoundary);
        }
        if action != ActionKindV1::Funding {
            return Err(ProductionTimeGuardErrorV2::RecoveryActionMustNotUseTimeGate);
        }
        Ok(Self {
            route_id,
            leg,
            action,
            fencing_epoch,
            effect_id,
            event_id,
            plan_digest,
        })
    }

    pub(crate) const fn route_id(self) -> RouteIdV1 {
        self.route_id
    }

    pub(crate) const fn leg(self) -> LegIdV1 {
        self.leg
    }

    pub(crate) const fn action(self) -> ActionKindV1 {
        self.action
    }

    pub(crate) const fn fencing_epoch(self) -> u64 {
        self.fencing_epoch
    }

    pub(crate) const fn effect_id(self) -> EffectIdV1 {
        self.effect_id
    }

    pub(crate) const fn event_id(self) -> EventIdV1 {
        self.event_id
    }

    pub(crate) const fn plan_digest(self) -> [u8; 32] {
        self.plan_digest
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FundingTimeAuthorizationFactsV2 {
    scope: FundingTimeAuthorizationScopeV2,
    route_scope_digest: [u8; 32],
    policy_digest: [u8; 32],
    admission_evidence_digest: [u8; 32],
    admission_evidence_sequence: u64,
    admission_proof_digest: [u8; 32],
    admission_issued_at_seconds: u64,
    admission_validated_at_seconds: u64,
    admission_valid_until_seconds: u64,
    current_evidence_digest: [u8; 32],
    current_evidence_sequence: u64,
    current_proof_digest: [u8; 32],
    issued_at_seconds: u64,
    validated_at_seconds: u64,
    valid_until_seconds: u64,
    authorization_digest: [u8; 32],
}

/// Linear current-time authorization passed only to the synchronous funding
/// plan callback.
///
/// It intentionally implements neither `Clone`, `Copy`, `Debug`, a codec nor
/// serialization. Its lifetime is tied to the exclusive durable-store borrow,
/// and the `Rc` marker also prevents moving it to another thread.
pub(crate) struct FundingTimeAuthorizationV2<'authority> {
    facts: FundingTimeAuthorizationFactsV2,
    _exclusive_time_authority: PhantomData<&'authority mut ()>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl<'authority> FundingTimeAuthorizationV2<'authority> {
    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) const fn scope(&self) -> FundingTimeAuthorizationScopeV2 {
        self.facts.scope
    }

    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) const fn route_scope_digest(&self) -> [u8; 32] {
        self.facts.route_scope_digest
    }

    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) const fn policy_digest(&self) -> [u8; 32] {
        self.facts.policy_digest
    }

    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) const fn admission_evidence_digest(&self) -> [u8; 32] {
        self.facts.admission_evidence_digest
    }

    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) const fn admission_evidence_sequence(&self) -> u64 {
        self.facts.admission_evidence_sequence
    }

    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) const fn admission_proof_digest(&self) -> [u8; 32] {
        self.facts.admission_proof_digest
    }

    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) const fn admission_issued_at_seconds(&self) -> u64 {
        self.facts.admission_issued_at_seconds
    }

    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) const fn admission_validated_at_seconds(&self) -> u64 {
        self.facts.admission_validated_at_seconds
    }

    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) const fn admission_valid_until_seconds(&self) -> u64 {
        self.facts.admission_valid_until_seconds
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
        )
    )]
    pub(crate) const fn current_evidence_digest(&self) -> [u8; 32] {
        self.facts.current_evidence_digest
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
        )
    )]
    pub(crate) const fn current_evidence_sequence(&self) -> u64 {
        self.facts.current_evidence_sequence
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
        )
    )]
    pub(crate) const fn current_proof_digest(&self) -> [u8; 32] {
        self.facts.current_proof_digest
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
        )
    )]
    pub(crate) const fn issued_at_seconds(&self) -> u64 {
        self.facts.issued_at_seconds
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
        )
    )]
    pub(crate) const fn validated_at_seconds(&self) -> u64 {
        self.facts.validated_at_seconds
    }

    pub(crate) const fn valid_until_seconds(&self) -> u64 {
        self.facts.valid_until_seconds
    }

    /// Commitment the plan authority must durably bind before returning.
    pub(crate) const fn authorization_digest(&self) -> [u8; 32] {
        self.facts.authorization_digest
    }

    /// Consumes this token only after the plan authority has installed or
    /// revalidated the exact plan committed by this scope. The returned
    /// wrapper is the only success type accepted by the guard's synchronous
    /// callback.
    pub(crate) fn consume_after_verified_plan<T>(
        self,
        verified_scope: FundingTimeAuthorizationScopeV2,
        value: T,
    ) -> Result<ConsumedFundingTimeAuthorizationV2<T>, ProductionTimeGuardErrorV2> {
        if verified_scope != self.facts.scope {
            return Err(ProductionTimeGuardErrorV2::PlanConsumptionMismatch);
        }
        Ok(ConsumedFundingTimeAuthorizationV2 {
            facts: self.facts,
            value,
        })
    }
}

/// Successful synchronous consumption. It has no public constructor and does
/// not retain the store-borrow lifetime or an unconsumed token.
pub(crate) struct ConsumedFundingTimeAuthorizationV2<T> {
    facts: FundingTimeAuthorizationFactsV2,
    value: T,
}

/// Production time-guard refusal. Messages contain no path, endpoint, terms
/// bytes or chain evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionTimeGuardErrorV2 {
    #[error("durable route time authority refused the operation")]
    TimeAuthority(#[from] RouteTimeAnchorErrorV2),
    #[error("route admission has no authenticated V2 time checkpoint")]
    MissingAuthenticatedTimeBinding,
    #[error("authenticated route, registry or terms context is inconsistent")]
    AuthenticatedContextMismatch,
    #[error("invalid new-funding action boundary")]
    InvalidFundingBoundary,
    #[error("claim, refund or committed funding must not use the expiring time gate")]
    RecoveryActionMustNotUseTimeGate,
    #[error("new-funding request belongs to another authenticated route")]
    CrossRouteFundingBoundary,
    #[error("trusted funding time precedes the frozen admission checkpoint")]
    AdmissionClockRollback,
    #[error("current time proof does not descend from the frozen admission policy")]
    FrozenCheckpointMismatch,
    #[error("funding plan did not consume the exact one-shot time authorization")]
    PlanConsumptionMismatch,
    #[error("funding time authorization digest could not be constructed")]
    DigestFailure,
}

/// Move-only production authority for one admitted V2 route.
pub(crate) struct ProductionRouteTimeGuardV2 {
    store: DurableRouteTimeAnchorStoreV2,
    policy_authorities: AuthoritySetV1,
    evidence_authorities: AuthoritySetV1,
    secp: SecpContext,
    registry: ResolvedRegistryV1,
    upstream: SettlementTermsV1,
    downstream: SettlementTermsV1,
    route_id: RouteIdV1,
    frozen_binding: AuthenticatedRouteTimeBindingV2,
    frozen_checkpoint: FrozenRouteTimeCheckpointV2,
}

/// Exact immutable inputs used to bind a route-time authority.
pub(crate) struct ProductionRouteTimeGuardContextV2 {
    pub(crate) policy_authorities: AuthoritySetV1,
    pub(crate) evidence_authorities: AuthoritySetV1,
    pub(crate) secp: SecpContext,
    pub(crate) registry: ResolvedRegistryV1,
    pub(crate) upstream: SettlementTermsV1,
    pub(crate) downstream: SettlementTermsV1,
}

impl core::fmt::Debug for ProductionRouteTimeGuardV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRouteTimeGuardV2([redacted])")
    }
}

impl ProductionRouteTimeGuardV2 {
    /// Binds an already-open route-time store to the exact authenticated route
    /// admission, registry and ordered settlement terms. Construction does not
    /// inspect expiry so recovery can reopen after the admission window.
    pub(crate) fn new(
        store: DurableRouteTimeAnchorStoreV2,
        admission: &AuthenticatedRouteAdmissionV1,
        context: ProductionRouteTimeGuardContextV2,
    ) -> Result<Self, ProductionTimeGuardErrorV2> {
        let ProductionRouteTimeGuardContextV2 {
            policy_authorities,
            evidence_authorities,
            secp,
            registry,
            upstream,
            downstream,
        } = context;
        let frozen_binding = admission
            .route_time_binding_v2()
            .ok_or(ProductionTimeGuardErrorV2::MissingAuthenticatedTimeBinding)?;
        let exact_scope = route_scope_digest(&upstream, &downstream)?;
        if admission.route_id() == ZERO_DIGEST
            || admission.registry_digest() != registry.manifest_digest()
            || exact_scope != frozen_binding.route_scope_digest()
            || frozen_binding.policy_digest() == ZERO_DIGEST
            || frozen_binding.evidence_digest() == ZERO_DIGEST
            || frozen_binding.proof_digest() == ZERO_DIGEST
            || frozen_binding.evidence_sequence() == 0
            || frozen_binding.issued_at_seconds() == 0
            || frozen_binding.validated_at_seconds() < frozen_binding.issued_at_seconds()
            || frozen_binding.validated_at_seconds() >= frozen_binding.valid_until_seconds()
        {
            return Err(ProductionTimeGuardErrorV2::AuthenticatedContextMismatch);
        }
        let frozen_checkpoint = FrozenRouteTimeCheckpointV2::new(
            exact_scope,
            frozen_binding.policy_digest(),
            frozen_binding.evidence_digest(),
            frozen_binding.evidence_sequence(),
        )?;
        Ok(Self {
            store,
            policy_authorities,
            evidence_authorities,
            secp,
            registry,
            upstream,
            downstream,
            route_id: admission.route_id(),
            frozen_binding,
            frozen_checkpoint,
        })
    }

    /// Installs one threshold-authenticated evidence refresh. The durable
    /// store itself enforces sequence, fixed anchors, extending tips and
    /// fail-closed invalidation before a later funding can use it.
    pub(crate) fn install_evidence(
        &mut self,
        signed: &SignedRouteTimeEvidenceV2,
        now: u64,
    ) -> Result<EvidenceInstallOutcomeV2, ProductionTimeGuardErrorV2> {
        self.store
            .install_evidence(
                signed,
                RouteTimeEvidenceVerificationContextV2::new(
                    RouteTimePolicyVerificationContextV2::new(
                        &self.policy_authorities,
                        &self.secp,
                        &self.registry,
                        &self.upstream,
                        &self.downstream,
                    ),
                    &self.evidence_authorities,
                ),
                now,
            )
            .map_err(ProductionTimeGuardErrorV2::from)
    }

    /// Obtains a current proof and lends its one-shot token only to one
    /// synchronous plan callback.
    ///
    /// The nested result keeps time-authority failures distinct from a plan
    /// factory's own refusal. `T` and `E` are fixed outside the higher-ranked
    /// callback lifetime, so neither can contain or leak the borrowed token.
    /// A plan retained only by the settlement coordinator is not proof that
    /// the parent route committed Funding. If a crash leaves the route action
    /// `NotPrepared`, retry must enter this method again and revalidate that
    /// exact preinstalled plan. Only a committed route action is recovery and
    /// bypasses this expiring gate.
    pub(crate) fn authorize_new_funding_with<T, E, F>(
        &mut self,
        now: u64,
        scope: FundingTimeAuthorizationScopeV2,
        consume: F,
    ) -> Result<Result<T, E>, ProductionTimeGuardErrorV2>
    where
        F: for<'authorization> FnOnce(
            FundingTimeAuthorizationV2<'authorization>,
        ) -> Result<ConsumedFundingTimeAuthorizationV2<T>, E>,
    {
        if scope.route_id() != self.route_id {
            return Err(ProductionTimeGuardErrorV2::CrossRouteFundingBoundary);
        }
        if scope.action() != ActionKindV1::Funding {
            return Err(ProductionTimeGuardErrorV2::RecoveryActionMustNotUseTimeGate);
        }
        if now < self.frozen_binding.validated_at_seconds() {
            return Err(ProductionTimeGuardErrorV2::AdmissionClockRollback);
        }

        let current = self.store.prove_current_route_ladder_from_checkpoint(
            self.frozen_checkpoint,
            RouteTimeEvidenceVerificationContextV2::new(
                RouteTimePolicyVerificationContextV2::new(
                    &self.policy_authorities,
                    &self.secp,
                    &self.registry,
                    &self.upstream,
                    &self.downstream,
                ),
                &self.evidence_authorities,
            ),
            now,
        )?;
        if current.route_scope_digest() != self.frozen_binding.route_scope_digest()
            || current.policy_digest() != self.frozen_binding.policy_digest()
            || current.evidence_sequence() < self.frozen_binding.evidence_sequence()
            || (current.evidence_sequence() == self.frozen_binding.evidence_sequence()
                && current.evidence_digest() != self.frozen_binding.evidence_digest())
            || current.validated_at_seconds() != now
            || current.issued_at_seconds() > now
            || now >= current.valid_until_seconds()
        {
            return Err(ProductionTimeGuardErrorV2::FrozenCheckpointMismatch);
        }

        let mut facts = FundingTimeAuthorizationFactsV2 {
            scope,
            route_scope_digest: current.route_scope_digest(),
            policy_digest: current.policy_digest(),
            admission_evidence_digest: self.frozen_binding.evidence_digest(),
            admission_evidence_sequence: self.frozen_binding.evidence_sequence(),
            admission_proof_digest: self.frozen_binding.proof_digest(),
            admission_issued_at_seconds: self.frozen_binding.issued_at_seconds(),
            admission_validated_at_seconds: self.frozen_binding.validated_at_seconds(),
            admission_valid_until_seconds: self.frozen_binding.valid_until_seconds(),
            current_evidence_digest: current.evidence_digest(),
            current_evidence_sequence: current.evidence_sequence(),
            current_proof_digest: current.binding_digest(),
            issued_at_seconds: current.issued_at_seconds(),
            validated_at_seconds: current.validated_at_seconds(),
            valid_until_seconds: current.valid_until_seconds(),
            authorization_digest: ZERO_DIGEST,
        };
        facts.authorization_digest = funding_time_authorization_digest(&facts)?;
        let expected = facts;
        let token = funding_time_authorization_token(&current, facts);
        let consumed = match consume(token) {
            Ok(value) => value,
            Err(error) => return Ok(Err(error)),
        };
        if consumed.facts != expected {
            return Err(ProductionTimeGuardErrorV2::PlanConsumptionMismatch);
        }
        Ok(Ok(consumed.value))
    }
}

/// Production-only persistence adapter that combines the authenticated plan
/// authority with a current route-time authorization for new Funding.
///
/// The adapter owns both authorities. This prevents a composition root from
/// accidentally installing a new Funding plan through the base plan authority
/// alone. Claim/refund installation and refencing of an already-committed plan
/// deliberately bypass only the *temporal* authority; they still require the
/// authenticated base plan authority.
#[cfg(feature = "production")]
pub(crate) struct ProductionTimeGuardedPlanPersistenceV2<A> {
    time_guard: ProductionRouteTimeGuardV2,
    base_plan_authority: A,
}

#[cfg(feature = "production")]
impl<A> core::fmt::Debug for ProductionTimeGuardedPlanPersistenceV2<A> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionTimeGuardedPlanPersistenceV2([redacted])")
    }
}

#[cfg(feature = "production")]
impl<A> ProductionTimeGuardedPlanPersistenceV2<A>
where
    A: SettlementPlanAuthorityV1,
{
    /// Moves the route-scoped time authority and the authenticated base plan
    /// authority behind one non-bypassable persistence boundary.
    #[expect(
        dead_code,
        reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
    )]
    pub(crate) fn new(time_guard: ProductionRouteTimeGuardV2, base_plan_authority: A) -> Self {
        Self {
            time_guard,
            base_plan_authority,
        }
    }

    /// Installs a threshold-authenticated current evidence refresh through the
    /// same durable authority later used by Funding boundaries.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "frozen funding-time economic guard surface (F7/M8); fails the build when first wired"
        )
    )]
    pub(crate) fn install_time_evidence(
        &mut self,
        signed: &SignedRouteTimeEvidenceV2,
        trusted_now_seconds: u64,
    ) -> Result<EvidenceInstallOutcomeV2, ProductionTimeGuardErrorV2> {
        self.time_guard
            .install_evidence(signed, trusted_now_seconds)
    }

    fn install_with_base_authority(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        plan: CompositeSettlementPlanV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
        let expected = plan.clone();
        let expected_effect = plan.bindings().effect_id;
        let installed = coordinator
            .install_plan(&mut self.base_plan_authority, plan, trusted_now_unix_ms)
            .map_err(map_plan_persistence_coordinator_error)?;
        let reloaded = coordinator
            .load_plan_for_effect(expected_effect)
            .map_err(map_plan_persistence_coordinator_error)?;
        let verified = verify_exact_stored_plan(&reloaded, &expected)?;
        if installed != verified {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(verified)
    }

    fn install_new_funding(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        plan: CompositeSettlementPlanV1,
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
        let scope = funding_scope_from_plan(&plan, route_event_id)?;
        let trusted_now_seconds = trusted_now_unix_ms / 1_000;
        let expected = plan.clone();
        let base_plan_authority = &mut self.base_plan_authority;
        let result = self.time_guard.authorize_new_funding_with(
            trusted_now_seconds,
            scope,
            |authorization| {
                let temporal_last_valid_unix_ms = temporal_last_valid_unix_ms(&authorization)?;
                let installed = {
                    let mut combined_authority = FundingBoundPlanAuthorityV2 {
                        base: base_plan_authority,
                        temporal: &authorization,
                        scope,
                        temporal_last_valid_unix_ms,
                    };
                    coordinator
                        .install_plan(&mut combined_authority, plan, trusted_now_unix_ms)
                        .map_err(map_plan_persistence_coordinator_error)?
                };
                let reloaded = coordinator
                    .load_plan_for_effect(scope.effect_id())
                    .map_err(map_plan_persistence_coordinator_error)?;
                let verified = verify_exact_stored_plan(&reloaded, &expected)?;
                if installed != verified {
                    return Err(AuthorityRefusalV1::Inconsistent);
                }
                authorization
                    .consume_after_verified_plan(scope, verified)
                    .map_err(map_time_guard_error)
            },
        );
        flatten_time_guard_result(result)
    }

    fn refence_new_funding(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        lease: CoordinatorLeaseV1,
        replacement: CompositeSettlementPlanV1,
        progress_evidence_digest: [u8; 32],
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
        let retained = coordinator
            .load_plan(lease.plan_id())
            .map_err(map_plan_persistence_coordinator_error)?;
        let retained = coordinator
            .load_plan_for_effect(retained.effect_id)
            .map_err(map_plan_persistence_coordinator_error)?;
        validate_pristine_funding_plan(&retained)?;
        let old_scope = funding_scope_from_plan(retained.plan(), route_event_id)?;
        let new_scope = funding_scope_from_plan(&replacement, route_event_id)?;
        if old_scope.route_id() != new_scope.route_id()
            || old_scope.leg() != new_scope.leg()
            || old_scope.action() != new_scope.action()
            || old_scope.fencing_epoch() >= new_scope.fencing_epoch()
            || lease.route_fencing_epoch() != new_scope.fencing_epoch()
            || retained.view().plan_id != lease.plan_id()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        match coordinator
            .takeover_status(lease, trusted_now_unix_ms)
            .map_err(map_plan_persistence_coordinator_error)?
        {
            CustodyTakeoverStatusV1::NothingExternalized { evidence_digest }
                if evidence_digest == progress_evidence_digest
                    && evidence_digest != ZERO_DIGEST => {}
            CustodyTakeoverStatusV1::NothingExternalized { .. }
            | CustodyTakeoverStatusV1::SafeToResumeCustody(_)
            | CustodyTakeoverStatusV1::SecretPublicPartial(_)
            | CustodyTakeoverStatusV1::AggregateExternalized(_)
            | CustodyTakeoverStatusV1::Unknown { .. } => {
                return Err(AuthorityRefusalV1::Inconsistent)
            }
        }

        let trusted_now_seconds = trusted_now_unix_ms / 1_000;
        let expected = replacement.clone();
        let base_plan_authority = &mut self.base_plan_authority;
        let result = self.time_guard.authorize_new_funding_with(
            trusted_now_seconds,
            new_scope,
            |authorization| {
                let temporal_last_valid_unix_ms = temporal_last_valid_unix_ms(&authorization)?;
                let refenced = {
                    let mut combined_authority = FundingBoundPlanAuthorityV2 {
                        base: base_plan_authority,
                        temporal: &authorization,
                        scope: new_scope,
                        temporal_last_valid_unix_ms,
                    };
                    coordinator
                        .refence_plan(
                            lease,
                            replacement,
                            progress_evidence_digest,
                            &mut combined_authority,
                            trusted_now_unix_ms,
                        )
                        .map_err(map_plan_persistence_coordinator_error)?
                };
                let reloaded = coordinator
                    .load_plan_for_effect(new_scope.effect_id())
                    .map_err(map_plan_persistence_coordinator_error)?;
                let verified = verify_exact_stored_plan(&reloaded, &expected)?;
                if refenced != verified {
                    return Err(AuthorityRefusalV1::Inconsistent);
                }
                authorization
                    .consume_after_verified_plan(new_scope, verified)
                    .map_err(map_time_guard_error)
            },
        );
        flatten_time_guard_result(result)
    }
}

#[cfg(feature = "production")]
impl<A> ProductionSettlementPlanPersistenceV1 for ProductionTimeGuardedPlanPersistenceV2<A>
where
    A: SettlementPlanAuthorityV1,
{
    fn install_new_plan(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        plan: CompositeSettlementPlanV1,
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
        match plan.bindings().action {
            SettlementActionV1::Funding => {
                self.install_new_funding(coordinator, plan, route_event_id, trusted_now_unix_ms)
            }
            SettlementActionV1::Claim | SettlementActionV1::Refund => {
                self.install_with_base_authority(coordinator, plan, trusted_now_unix_ms)
            }
        }
    }

    fn revalidate_preinstalled_new_plan(
        &mut self,
        stored: &StoredSettlementPlanV1,
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AuthorityRefusalV1> {
        validate_pristine_funding_plan(stored)?;
        let scope = funding_scope_from_plan(stored.plan(), route_event_id)?;
        let trusted_now_seconds = trusted_now_unix_ms / 1_000;
        let result = self.time_guard.authorize_new_funding_with(
            trusted_now_seconds,
            scope,
            |authorization| {
                validate_pristine_funding_plan(stored)?;
                if funding_scope_from_plan(stored.plan(), route_event_id)? != scope {
                    return Err(AuthorityRefusalV1::Inconsistent);
                }
                authorization
                    .consume_after_verified_plan(scope, ())
                    .map_err(map_time_guard_error)
            },
        );
        flatten_time_guard_result(result)
    }

    fn refence_preinstalled_new_plan(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        lease: CoordinatorLeaseV1,
        replacement: CompositeSettlementPlanV1,
        progress_evidence_digest: [u8; 32],
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
        self.refence_new_funding(
            coordinator,
            lease,
            replacement,
            progress_evidence_digest,
            route_event_id,
            trusted_now_unix_ms,
        )
    }

    fn refence_existing_plan(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        lease: CoordinatorLeaseV1,
        replacement: CompositeSettlementPlanV1,
        progress_evidence_digest: [u8; 32],
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
        let expected = replacement.clone();
        let expected_effect = replacement.bindings().effect_id;
        let refenced = coordinator
            .refence_plan(
                lease,
                replacement,
                progress_evidence_digest,
                &mut self.base_plan_authority,
                trusted_now_unix_ms,
            )
            .map_err(map_plan_persistence_coordinator_error)?;
        let reloaded = coordinator
            .load_plan_for_effect(expected_effect)
            .map_err(map_plan_persistence_coordinator_error)?;
        let verified = verify_exact_stored_plan(&reloaded, &expected)?;
        if refenced != verified {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(verified)
    }
}

#[cfg(feature = "production")]
struct FundingBoundPlanAuthorityV2<'base, 'authorization, A>
where
    A: SettlementPlanAuthorityV1,
{
    base: &'base mut A,
    temporal: &'base FundingTimeAuthorizationV2<'authorization>,
    scope: FundingTimeAuthorizationScopeV2,
    temporal_last_valid_unix_ms: u64,
}

#[cfg(feature = "production")]
impl<A> SettlementPlanAuthorityV1 for FundingBoundPlanAuthorityV2<'_, '_, A>
where
    A: SettlementPlanAuthorityV1,
{
    fn authorize_plan(
        &mut self,
        request: PlanAuthorizationRequestV1<'_>,
    ) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
        let exact_scope = funding_scope_from_plan(request.plan(), self.scope.event_id())
            .map_err(|_| PlanAuthorityRefusalV1::Conflict)?;
        if exact_scope != self.scope || request.plan_digest() != self.scope.plan_digest() {
            return Err(PlanAuthorityRefusalV1::Conflict);
        }
        let base = self.base.authorize_plan(request)?;
        if base.plan_digest() != self.scope.plan_digest()
            || base.authority_id() == ZERO_DIGEST
            || base.evidence_digest() == ZERO_DIGEST
        {
            return Err(PlanAuthorityRefusalV1::Conflict);
        }
        combine_plan_authorization(
            base,
            self.temporal.authorization_digest(),
            self.temporal_last_valid_unix_ms,
        )
    }
}

#[cfg(feature = "production")]
/// Domain-separates and binds the base plan evidence to one temporal token.
pub(crate) fn combine_plan_authorization(
    base: PlanAuthorizationV1,
    temporal_authorization_digest: [u8; 32],
    temporal_last_valid_unix_ms: u64,
) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
    if temporal_authorization_digest == ZERO_DIGEST || temporal_last_valid_unix_ms == 0 {
        return Err(PlanAuthorityRefusalV1::Conflict);
    }
    let base_valid_until = base.valid_until_unix_ms();
    let combined_valid_until = core::cmp::min(base_valid_until, temporal_last_valid_unix_ms);
    if combined_valid_until == 0 {
        return Err(PlanAuthorityRefusalV1::Conflict);
    }
    let base_valid_until_bytes = base_valid_until.to_be_bytes();
    let temporal_last_valid_bytes = temporal_last_valid_unix_ms.to_be_bytes();
    let combined_valid_until_bytes = combined_valid_until.to_be_bytes();
    let evidence_digest = digest_parts(
        FUNDING_PLAN_AUTHORIZATION_EVIDENCE_DOMAIN_V2,
        &[
            &base.authority_id(),
            &base.plan_digest(),
            &base.evidence_digest(),
            &base_valid_until_bytes,
            &temporal_authorization_digest,
            &temporal_last_valid_bytes,
            &combined_valid_until_bytes,
        ],
    )
    .map_err(|_| PlanAuthorityRefusalV1::Conflict)?;
    PlanAuthorizationV1::new(
        base.authority_id(),
        base.plan_digest(),
        evidence_digest,
        combined_valid_until,
    )
    .map_err(|_| PlanAuthorityRefusalV1::Conflict)
}

#[cfg(feature = "production")]
fn temporal_last_valid_unix_ms(
    authorization: &FundingTimeAuthorizationV2<'_>,
) -> Result<u64, AuthorityRefusalV1> {
    authorization
        .valid_until_seconds()
        .checked_mul(1_000)
        .and_then(|exclusive| exclusive.checked_sub(1))
        .filter(|last_valid| *last_valid != 0)
        .ok_or(AuthorityRefusalV1::Inconsistent)
}

#[cfg(feature = "production")]
fn funding_scope_from_plan(
    plan: &CompositeSettlementPlanV1,
    route_event_id: EventIdV1,
) -> Result<FundingTimeAuthorizationScopeV2, AuthorityRefusalV1> {
    let bindings = plan.bindings();
    if bindings.action != SettlementActionV1::Funding {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    let leg = match bindings.leg {
        SettlementLegV1::Upstream => LegIdV1::Upstream,
        SettlementLegV1::Downstream => LegIdV1::Downstream,
    };
    let expected_effect = derive_effect_id_v1(
        bindings.route_id,
        route_event_id,
        bindings.fencing_epoch,
        leg,
        ActionKindV1::Funding,
        bindings.semantic_digest,
    );
    if expected_effect != bindings.effect_id {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    let plan_digest = plan
        .canonical_digest()
        .map_err(map_plan_persistence_coordinator_error)?;
    FundingTimeAuthorizationScopeV2::new(
        bindings.route_id,
        leg,
        ActionKindV1::Funding,
        bindings.fencing_epoch,
        bindings.effect_id,
        route_event_id,
        plan_digest,
    )
    .map_err(map_time_guard_error)
}

#[cfg(feature = "production")]
fn validate_pristine_funding_plan(
    stored: &StoredSettlementPlanV1,
) -> Result<(), AuthorityRefusalV1> {
    let view = stored.view();
    if stored.plan().bindings().action != SettlementActionV1::Funding
        || view.stage != AggregateStageV1::Active
        || view.completed_prefix != 0
        || view.children.iter().any(|child| {
            child.stage != ChildStageV1::Planned
                || child.call_attempts != 0
                || child.externalization_evidence_digest.is_some()
                || child.finality_evidence_digest.is_some()
                || child.reorg_evidence_digest.is_some()
        })
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

#[cfg(feature = "production")]
fn verify_exact_stored_plan(
    stored: &StoredSettlementPlanV1,
    expected: &CompositeSettlementPlanV1,
) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
    let expected_digest = expected
        .canonical_digest()
        .map_err(map_plan_persistence_coordinator_error)?;
    if stored.plan() != expected
        || stored.view().plan_digest != expected_digest
        || stored.view().effect_id != expected.bindings().effect_id
        || stored.view().fencing_epoch != expected.bindings().fencing_epoch
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(stored.view().clone())
}

#[cfg(feature = "production")]
fn flatten_time_guard_result<T>(
    result: Result<Result<T, AuthorityRefusalV1>, ProductionTimeGuardErrorV2>,
) -> Result<T, AuthorityRefusalV1> {
    result.map_err(map_time_guard_error)?
}

#[cfg(feature = "production")]
fn map_time_guard_error(error: ProductionTimeGuardErrorV2) -> AuthorityRefusalV1 {
    match error {
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::StorageUnavailable) => {
            AuthorityRefusalV1::Unavailable
        }
        ProductionTimeGuardErrorV2::TimeAuthority(
            RouteTimeAnchorErrorV2::PolicyExpired
            | RouteTimeAnchorErrorV2::EvidenceFromFuture
            | RouteTimeAnchorErrorV2::EvidenceStale
            | RouteTimeAnchorErrorV2::AnchorStale
            | RouteTimeAnchorErrorV2::DeadlinePassed
            | RouteTimeAnchorErrorV2::ImpossibleInterval
            | RouteTimeAnchorErrorV2::UnsafeWindow,
        ) => AuthorityRefusalV1::Refused,
        ProductionTimeGuardErrorV2::TimeAuthority(_)
        | ProductionTimeGuardErrorV2::MissingAuthenticatedTimeBinding
        | ProductionTimeGuardErrorV2::AuthenticatedContextMismatch
        | ProductionTimeGuardErrorV2::InvalidFundingBoundary
        | ProductionTimeGuardErrorV2::RecoveryActionMustNotUseTimeGate
        | ProductionTimeGuardErrorV2::CrossRouteFundingBoundary
        | ProductionTimeGuardErrorV2::AdmissionClockRollback
        | ProductionTimeGuardErrorV2::FrozenCheckpointMismatch
        | ProductionTimeGuardErrorV2::PlanConsumptionMismatch
        | ProductionTimeGuardErrorV2::DigestFailure => AuthorityRefusalV1::Inconsistent,
    }
}

#[cfg(feature = "production")]
fn map_plan_persistence_coordinator_error(error: CoordinatorErrorV1) -> AuthorityRefusalV1 {
    match error {
        CoordinatorErrorV1::StorageUnavailable
        | CoordinatorErrorV1::LeaseHeld
        | CoordinatorErrorV1::PlanAuthorityRefused
        | CoordinatorErrorV1::ChildAuthorityRefused
        | CoordinatorErrorV1::ChildObserverRefused => AuthorityRefusalV1::Unavailable,
        CoordinatorErrorV1::InvalidPlan
        | CoordinatorErrorV1::InvalidCanonicalMaterial
        | CoordinatorErrorV1::InvalidPlanAuthorization
        | CoordinatorErrorV1::DatabasePresent
        | CoordinatorErrorV1::DatabaseMissing
        | CoordinatorErrorV1::InvalidStorageAuthority
        | CoordinatorErrorV1::UnsupportedFormat
        | CoordinatorErrorV1::CreationIncomplete
        | CoordinatorErrorV1::CorruptState
        | CoordinatorErrorV1::PlanNotFound
        | CoordinatorErrorV1::IdempotencyConflict
        | CoordinatorErrorV1::FailedClosed
        | CoordinatorErrorV1::StaleFencing
        | CoordinatorErrorV1::LeaseExpired
        | CoordinatorErrorV1::InvalidBound
        | CoordinatorErrorV1::InvalidState
        | CoordinatorErrorV1::ChildReceiptMismatch
        | CoordinatorErrorV1::ReconciliationRequired => AuthorityRefusalV1::Inconsistent,
    }
}

fn funding_time_authorization_token<'authority>(
    _current: &CurrentRouteTimeLadderV2<'authority>,
    facts: FundingTimeAuthorizationFactsV2,
) -> FundingTimeAuthorizationV2<'authority> {
    FundingTimeAuthorizationV2 {
        facts,
        _exclusive_time_authority: PhantomData,
        _not_send_or_sync: PhantomData,
    }
}

fn funding_time_authorization_digest(
    facts: &FundingTimeAuthorizationFactsV2,
) -> Result<[u8; 32], ProductionTimeGuardErrorV2> {
    let leg_tag = [match facts.scope.leg() {
        LegIdV1::Upstream => 1,
        LegIdV1::Downstream => 2,
    }];
    let action_tag = [1u8];
    let fencing_epoch = facts.scope.fencing_epoch().to_be_bytes();
    let admission_sequence = facts.admission_evidence_sequence.to_be_bytes();
    let admission_issued_at = facts.admission_issued_at_seconds.to_be_bytes();
    let admission_validated_at = facts.admission_validated_at_seconds.to_be_bytes();
    let admission_valid_until = facts.admission_valid_until_seconds.to_be_bytes();
    let current_sequence = facts.current_evidence_sequence.to_be_bytes();
    let issued_at = facts.issued_at_seconds.to_be_bytes();
    let validated_at = facts.validated_at_seconds.to_be_bytes();
    let valid_until = facts.valid_until_seconds.to_be_bytes();
    digest_parts(
        FUNDING_TIME_AUTHORIZATION_DOMAIN_V2,
        &[
            &facts.scope.route_id(),
            &leg_tag,
            &action_tag,
            &fencing_epoch,
            &facts.scope.effect_id(),
            &facts.scope.event_id(),
            &facts.scope.plan_digest(),
            &facts.route_scope_digest,
            &facts.policy_digest,
            &facts.admission_evidence_digest,
            &admission_sequence,
            &facts.admission_proof_digest,
            &admission_issued_at,
            &admission_validated_at,
            &admission_valid_until,
            &facts.current_evidence_digest,
            &current_sequence,
            &facts.current_proof_digest,
            &issued_at,
            &validated_at,
            &valid_until,
        ],
    )
}

fn digest_parts(domain: &[u8], fields: &[&[u8]]) -> Result<[u8; 32], ProductionTimeGuardErrorV2> {
    let mut hash = Blake2bVar::new(32).map_err(|_| ProductionTimeGuardErrorV2::DigestFailure)?;
    hash.update(domain);
    for field in fields {
        let length =
            u64::try_from(field.len()).map_err(|_| ProductionTimeGuardErrorV2::DigestFailure)?;
        hash.update(&length.to_be_bytes());
        hash.update(field);
    }
    let mut output = [0; 32];
    hash.finalize_variable(&mut output)
        .map_err(|_| ProductionTimeGuardErrorV2::DigestFailure)?;
    if output == ZERO_DIGEST {
        return Err(ProductionTimeGuardErrorV2::DigestFailure);
    }
    Ok(output)
}

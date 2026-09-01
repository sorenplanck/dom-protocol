//! Production-only bridge between the route supervisor and the durable
//! two-face settlement coordinator.
//!
//! This module deliberately remains crate-private.  It accepts only typed,
//! secret-free plan/child authorities owned by the composition root and never
//! exposes a generic transaction-signing or raw-byte boundary.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use route_executor::{
    derive_effect_id_v1, ActionIntentV1, ActionKindV1, ActionProgressV1, EffectDispatchV1,
    EventIdV1, ExposureSourceV1, LegIdV1, PublicExposureV1, RouteSecretRetirementCapabilityV1,
    SecretVisibilityV1,
};
use settlement_coordinator::{
    AggregateExternalizationReceiptV1, AggregateStageV1, AuthenticatedCoordinatorExposureV1,
    ChildAuthorityRefusalV1, ChildObservationOutcomeV1, ChildObservationRequestV1,
    ChildPublicExposureV1, ChildStageV1, CompositeSettlementPlanV1, CoordinatorDriveOutcomeV1,
    CoordinatorErrorV1, CoordinatorLeaseV1, CoordinatorObservationOutcomeV1,
    CustodyTakeoverStatusV1, DeferredChildMaterializationCapabilityV1,
    DeferredChildMaterializationResultV1, Digest32, DurableSettlementCoordinatorV1,
    PartialCustodyProgressV1, SecretRequirementV1, SettlementActionV1, SettlementChildAuthorityV1,
    SettlementChildObserverV1, SettlementChildrenV1, SettlementDeferredChildAuthorityV1,
    SettlementLegV1, SettlementPlanBindingsV1, SettlementPlanViewV1, StoredSettlementPlanV1,
};

#[cfg(not(any(feature = "development", feature = "simulation", test)))]
use crate::supervisor::authority_seal;
use crate::supervisor::{
    ActionExternalizationReceiptV1, AuthorityRefusalV1, ChainObservationAuthority,
    ChainObservationQueryV1, ChainObservationRequestV1, CustodyDispatchOutcomeV1,
    ExternalCustodyActionRequestV1, ExternalCustodyAuthority, ReconciliationRequestV1,
    RouteActionAuthority, RouteActionAuthorizationRequestV1, RouteSecretRetirementAuthority,
    SignerCapabilityV1, TakeoverReconciliationAuthority, TakeoverReconciliationOutcomeV1,
    VerifiedChainObservationV1,
};

const ZERO_DIGEST: Digest32 = [0; 32];
const TAKEOVER_EVIDENCE_DOMAIN: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-SETTLEMENT/TAKEOVER-EVIDENCE/V1\0";
const PREINSTALLED_TAKEOVER_EVIDENCE_DOMAIN: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-SETTLEMENT/PREINSTALLED-TAKEOVER-EVIDENCE/V1\0";

/// Immutable secret-free draft supplied by the authenticated route/deployment
/// planner.  Route identity, effect identity, fence, leg, action and terms are
/// always derived by this bridge rather than accepted from the draft.
pub(crate) struct ProductionSettlementPlanDraftV1 {
    pub settlement_id: Digest32,
    pub semantic_digest: Digest32,
    pub registry_digest: Digest32,
    pub expected_route_profile_bundle_digest: Digest32,
    pub expected_route_deployment_bundle_digest: Digest32,
    pub dom_profile_digest: Digest32,
    pub dom_deployment_digest: Digest32,
    pub counterparty_profile_digest: Digest32,
    pub counterparty_deployment_digest: Digest32,
    pub secret_requirement: SecretRequirementV1,
    pub preexisting_secret_evidence_digest: Option<Digest32>,
    pub children: SettlementChildrenV1,
}

impl core::fmt::Debug for ProductionSettlementPlanDraftV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSettlementPlanDraftV1([public commitments redacted])")
    }
}

/// Authenticated, route-aware source for a two-face settlement plan.  This is
/// crate-private so an external plugin cannot inject child-shaped receipts or
/// bypass the supervisor seal.
pub(crate) trait ProductionSettlementPlanSourceV1 {
    /// Stable identity committed by staged plans for deferred materialization.
    fn deferred_materializer_authority_id(&self) -> Digest32;

    fn draft_for_action(
        &mut self,
        request: &RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ProductionSettlementPlanDraftV1, AuthorityRefusalV1>;

    /// Re-extracts, verifies and durably seals the exact first exposure before
    /// the bridge may return it to the route supervisor. Replays repeat this
    /// operation idempotently before returning the same public receipt.
    fn seal_first_public_exposure(
        &mut self,
        exposure: AuthenticatedCoordinatorExposureV1,
    ) -> Result<(), AuthorityRefusalV1>;

    /// Re-extracts the exact scalar from the route-acknowledged public
    /// exposure and materializes only the coordinator-authenticated deferred
    /// child.  The returned child is retained by its face actuator but not
    /// broadcast.
    fn materialize_deferred_child(
        &mut self,
        capability: DeferredChildMaterializationCapabilityV1,
        route_exposure: &PublicExposureV1,
    ) -> Result<DeferredChildMaterializationResultV1, AuthorityRefusalV1>;

    /// Retires the exact recovery seal only after the route Store has replayed
    /// a public, fully terminal route with no open funds.
    fn retire_public_secret(
        &mut self,
        capability: RouteSecretRetirementCapabilityV1,
    ) -> Result<(), AuthorityRefusalV1>;
}

struct ProductionDeferredChildAuthorityAdapterV1<'owner> {
    source: &'owner mut dyn ProductionSettlementPlanSourceV1,
    route_exposure: &'owner PublicExposureV1,
}

impl SettlementDeferredChildAuthorityV1 for ProductionDeferredChildAuthorityAdapterV1<'_> {
    fn authority_id(&self) -> Digest32 {
        self.source.deferred_materializer_authority_id()
    }

    fn materialize_deferred_child(
        &mut self,
        capability: DeferredChildMaterializationCapabilityV1,
    ) -> Result<DeferredChildMaterializationResultV1, ChildAuthorityRefusalV1> {
        self.source
            .materialize_deferred_child(capability, self.route_exposure)
            .map_err(|error| match error {
                AuthorityRefusalV1::Unavailable => ChildAuthorityRefusalV1::Unavailable,
                AuthorityRefusalV1::Refused => ChildAuthorityRefusalV1::Refused,
                AuthorityRefusalV1::Inconsistent => ChildAuthorityRefusalV1::Conflict,
            })
    }
}

/// Only composition-root boundary allowed to persist a coordinator plan.
///
/// New plans receive the authenticated route event identity so the production
/// adapter can consume the current temporal authorization for a new Funding
/// action.  Re-fencing is deliberately separate: it resumes an already
/// committed/recovery plan and must never request a fresh funding-time token.
/// This trait has no permissive implementation in product code.
pub(crate) trait ProductionSettlementPlanPersistenceV1 {
    fn install_new_plan(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        plan: CompositeSettlementPlanV1,
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1>;

    /// Revalidates a plan installed before the parent route committed its
    /// Funding event.  Presence in the coordinator is not proof that Funding
    /// became committed; the current time gate must be consumed again.
    fn revalidate_preinstalled_new_plan(
        &mut self,
        stored: &StoredSettlementPlanV1,
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AuthorityRefusalV1>;

    /// Re-fences a new Funding plan that was durably installed before its
    /// parent route event, but whose route lease advanced after a crash. This
    /// path must consume a current time authorization for the replacement
    /// plan; it is not the ungated recovery/refence path below.
    fn refence_preinstalled_new_plan(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        lease: CoordinatorLeaseV1,
        replacement: CompositeSettlementPlanV1,
        progress_evidence_digest: Digest32,
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1>;

    fn refence_existing_plan(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        lease: CoordinatorLeaseV1,
        replacement: CompositeSettlementPlanV1,
        progress_evidence_digest: Digest32,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1>;
}

/// Coordinator ownership and lease bounds retained by all bridge handles.
#[derive(Clone, Copy)]
pub(crate) struct ProductionSettlementBridgeConfigV1 {
    owner_id: Digest32,
    coordinator_lease_duration_ms: u64,
}

impl core::fmt::Debug for ProductionSettlementBridgeConfigV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionSettlementBridgeConfigV1")
            .field("owner_id", &"<redacted>")
            .field(
                "coordinator_lease_duration_ms",
                &self.coordinator_lease_duration_ms,
            )
            .finish()
    }
}

impl ProductionSettlementBridgeConfigV1 {
    pub fn new(
        owner_id: Digest32,
        coordinator_lease_duration_ms: u64,
    ) -> Result<Self, AuthorityRefusalV1> {
        if owner_id == ZERO_DIGEST || coordinator_lease_duration_ms == 0 {
            return Err(AuthorityRefusalV1::Refused);
        }
        Ok(Self {
            owner_id,
            coordinator_lease_duration_ms,
        })
    }
}

trait SettlementBridgeClockV1 {
    fn now_unix_ms(&self) -> Result<u64, AuthorityRefusalV1>;
}

struct SystemSettlementBridgeClockV1;

impl SettlementBridgeClockV1 for SystemSettlementBridgeClockV1 {
    fn now_unix_ms(&self) -> Result<u64, AuthorityRefusalV1> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        let now =
            u64::try_from(elapsed.as_millis()).map_err(|_| AuthorityRefusalV1::Unavailable)?;
        if now == 0 {
            return Err(AuthorityRefusalV1::Unavailable);
        }
        Ok(now)
    }
}

/// One owner for both mutation and observation of the coordinator's child
/// effects.  Production routing must not split these traits across two DOM
/// ports: doing so would require either reopening a Store or duplicating the
/// per-session action/verifier state.
trait SettlementChildPortAuthorityV1: SettlementChildAuthorityV1 + SettlementChildObserverV1 {}

impl<T> SettlementChildPortAuthorityV1 for T where
    T: SettlementChildAuthorityV1 + SettlementChildObserverV1
{
}

struct BoxedChildPortAuthorityV1(Box<dyn SettlementChildPortAuthorityV1>);

impl SettlementChildAuthorityV1 for BoxedChildPortAuthorityV1 {
    fn externalize_child(
        &mut self,
        request: &settlement_coordinator::ChildDispatchRequestV1,
    ) -> Result<settlement_coordinator::ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        self.0.externalize_child(request)
    }

    fn reconcile_child(
        &mut self,
        request: &settlement_coordinator::ChildReconciliationRequestV1,
    ) -> Result<settlement_coordinator::ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        self.0.reconcile_child(request)
    }
}

impl SettlementChildObserverV1 for BoxedChildPortAuthorityV1 {
    fn observe_child(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.0.observe_child(request)
    }
}

/// Compatibility composition for callers whose dispatch and observation
/// implementations are separate values.  It is still one owned child port in
/// the bridge and holds no `RefCell`/lock across chain RPC.
#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
struct SplitSettlementChildPortV1<C, O> {
    authority: C,
    observer: O,
}

impl<C, O> SettlementChildAuthorityV1 for SplitSettlementChildPortV1<C, O>
where
    C: SettlementChildAuthorityV1,
    O: SettlementChildObserverV1,
{
    fn externalize_child(
        &mut self,
        request: &settlement_coordinator::ChildDispatchRequestV1,
    ) -> Result<settlement_coordinator::ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        self.authority.externalize_child(request)
    }

    fn reconcile_child(
        &mut self,
        request: &settlement_coordinator::ChildReconciliationRequestV1,
    ) -> Result<settlement_coordinator::ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        self.authority.reconcile_child(request)
    }
}

impl<C, O> SettlementChildObserverV1 for SplitSettlementChildPortV1<C, O>
where
    C: SettlementChildAuthorityV1,
    O: SettlementChildObserverV1,
{
    fn observe_child(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.observer.observe_child(request)
    }
}

struct ProductionSettlementBridgeCoreV1 {
    coordinator: DurableSettlementCoordinatorV1,
    config: ProductionSettlementBridgeConfigV1,
    plan_source: Box<dyn ProductionSettlementPlanSourceV1>,
    plan_persistence: Box<dyn ProductionSettlementPlanPersistenceV1>,
    child_port: BoxedChildPortAuthorityV1,
    clock: Box<dyn SettlementBridgeClockV1>,
}

impl core::fmt::Debug for ProductionSettlementBridgeCoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSettlementBridgeCoreV1([redacted])")
    }
}

type SharedProductionSettlementBridgeV1 = Rc<RefCell<ProductionSettlementBridgeCoreV1>>;

/// Route action-plan authority handle owned by the production runtime.
pub(crate) struct ProductionSettlementActionAuthorityV1(SharedProductionSettlementBridgeV1);
/// External-custody authority handle owned by the production runtime.
pub(crate) struct ProductionSettlementCustodyAuthorityV1(SharedProductionSettlementBridgeV1);
/// Aggregate finality/reorg observer handle owned by the production runtime.
pub(crate) struct ProductionSettlementObservationAuthorityV1(SharedProductionSettlementBridgeV1);
/// Stale-fence reconciliation handle owned by the production runtime.
pub(crate) struct ProductionSettlementTakeoverAuthorityV1(SharedProductionSettlementBridgeV1);
/// Terminal route-secret retirement handle owned by the production runtime.
pub(crate) struct ProductionSettlementRetirementAuthorityV1(SharedProductionSettlementBridgeV1);

macro_rules! impl_redacted_debug {
    ($($type_name:ty),+ $(,)?) => {$(
        impl core::fmt::Debug for $type_name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str(concat!(stringify!($type_name), "([redacted])"))
            }
        }
    )+};
}

impl_redacted_debug!(
    ProductionSettlementActionAuthorityV1,
    ProductionSettlementCustodyAuthorityV1,
    ProductionSettlementObservationAuthorityV1,
    ProductionSettlementTakeoverAuthorityV1,
    ProductionSettlementRetirementAuthorityV1,
);

/// Five non-public supervisor-authority handles sharing one coordinator.  The
/// `RefCell` boundary is always entered with `try_borrow_mut`; reentrancy is a
/// typed inconsistency, never a panic.
pub(crate) struct ProductionSettlementAuthoritiesV1 {
    pub action: ProductionSettlementActionAuthorityV1,
    pub custody: ProductionSettlementCustodyAuthorityV1,
    pub observer: ProductionSettlementObservationAuthorityV1,
    pub takeover: ProductionSettlementTakeoverAuthorityV1,
    pub retirement: ProductionSettlementRetirementAuthorityV1,
}

impl core::fmt::Debug for ProductionSettlementAuthoritiesV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSettlementAuthoritiesV1([redacted])")
    }
}

/// Assembles the crate-private production bridge with the system clock.
#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
pub(crate) fn assemble_production_settlement_authorities_v1<P, I, C, O>(
    coordinator: DurableSettlementCoordinatorV1,
    config: ProductionSettlementBridgeConfigV1,
    plan_source: P,
    plan_persistence: I,
    child_authority: C,
    child_observer: O,
) -> ProductionSettlementAuthoritiesV1
where
    P: ProductionSettlementPlanSourceV1 + 'static,
    I: ProductionSettlementPlanPersistenceV1 + 'static,
    C: SettlementChildAuthorityV1 + 'static,
    O: SettlementChildObserverV1 + 'static,
{
    assemble_production_settlement_authorities_with_clock_v1(ProductionSettlementBridgePartsV1 {
        coordinator,
        config,
        plan_source,
        plan_persistence,
        child_authority,
        child_observer,
        clock: SystemSettlementBridgeClockV1,
    })
}

/// Assembles production settlement authorities around one exact child router.
///
/// This is the production composition seam for the route journal's
/// dispatch/reconciliation/observation flow.  A DOM route port therefore owns
/// both route legs and is moved here once; no clone, second Store opening or
/// `RefCell` proxy is introduced to satisfy the two coordinator traits.
pub(crate) fn assemble_production_settlement_authorities_with_child_port_v1<P, I, C>(
    coordinator: DurableSettlementCoordinatorV1,
    config: ProductionSettlementBridgeConfigV1,
    plan_source: P,
    plan_persistence: I,
    child_port: C,
) -> ProductionSettlementAuthoritiesV1
where
    P: ProductionSettlementPlanSourceV1 + 'static,
    I: ProductionSettlementPlanPersistenceV1 + 'static,
    C: SettlementChildAuthorityV1 + SettlementChildObserverV1 + 'static,
{
    assemble_production_settlement_authorities_with_child_port_and_clock_v1(
        coordinator,
        config,
        plan_source,
        plan_persistence,
        child_port,
        SystemSettlementBridgeClockV1,
    )
}

fn assemble_production_settlement_authorities_with_child_port_and_clock_v1<P, I, C, K>(
    coordinator: DurableSettlementCoordinatorV1,
    config: ProductionSettlementBridgeConfigV1,
    plan_source: P,
    plan_persistence: I,
    child_port: C,
    clock: K,
) -> ProductionSettlementAuthoritiesV1
where
    P: ProductionSettlementPlanSourceV1 + 'static,
    I: ProductionSettlementPlanPersistenceV1 + 'static,
    C: SettlementChildAuthorityV1 + SettlementChildObserverV1 + 'static,
    K: SettlementBridgeClockV1 + 'static,
{
    assemble_production_settlement_authorities_with_boxed_child_v1(
        coordinator,
        config,
        plan_source,
        plan_persistence,
        BoxedChildPortAuthorityV1(Box::new(child_port)),
        clock,
    )
}

#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
struct ProductionSettlementBridgePartsV1<P, I, C, O, K> {
    coordinator: DurableSettlementCoordinatorV1,
    config: ProductionSettlementBridgeConfigV1,
    plan_source: P,
    plan_persistence: I,
    child_authority: C,
    child_observer: O,
    clock: K,
}

#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
fn assemble_production_settlement_authorities_with_clock_v1<P, I, C, O, K>(
    parts: ProductionSettlementBridgePartsV1<P, I, C, O, K>,
) -> ProductionSettlementAuthoritiesV1
where
    P: ProductionSettlementPlanSourceV1 + 'static,
    I: ProductionSettlementPlanPersistenceV1 + 'static,
    C: SettlementChildAuthorityV1 + 'static,
    O: SettlementChildObserverV1 + 'static,
    K: SettlementBridgeClockV1 + 'static,
{
    let ProductionSettlementBridgePartsV1 {
        coordinator,
        config,
        plan_source,
        plan_persistence,
        child_authority,
        child_observer,
        clock,
    } = parts;
    let child_port = SplitSettlementChildPortV1 {
        authority: child_authority,
        observer: child_observer,
    };
    assemble_production_settlement_authorities_with_boxed_child_v1(
        coordinator,
        config,
        plan_source,
        plan_persistence,
        BoxedChildPortAuthorityV1(Box::new(child_port)),
        clock,
    )
}

fn assemble_production_settlement_authorities_with_boxed_child_v1<P, I, K>(
    coordinator: DurableSettlementCoordinatorV1,
    config: ProductionSettlementBridgeConfigV1,
    plan_source: P,
    plan_persistence: I,
    child_port: BoxedChildPortAuthorityV1,
    clock: K,
) -> ProductionSettlementAuthoritiesV1
where
    P: ProductionSettlementPlanSourceV1 + 'static,
    I: ProductionSettlementPlanPersistenceV1 + 'static,
    K: SettlementBridgeClockV1 + 'static,
{
    let shared = Rc::new(RefCell::new(ProductionSettlementBridgeCoreV1 {
        coordinator,
        config,
        plan_source: Box::new(plan_source),
        plan_persistence: Box::new(plan_persistence),
        child_port,
        clock: Box::new(clock),
    }));
    ProductionSettlementAuthoritiesV1 {
        action: ProductionSettlementActionAuthorityV1(Rc::clone(&shared)),
        custody: ProductionSettlementCustodyAuthorityV1(Rc::clone(&shared)),
        observer: ProductionSettlementObservationAuthorityV1(Rc::clone(&shared)),
        takeover: ProductionSettlementTakeoverAuthorityV1(Rc::clone(&shared)),
        retirement: ProductionSettlementRetirementAuthorityV1(shared),
    }
}

#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl authority_seal::Sealed for ProductionSettlementActionAuthorityV1 {}
#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl authority_seal::Sealed for ProductionSettlementCustodyAuthorityV1 {}
#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl authority_seal::Sealed for ProductionSettlementObservationAuthorityV1 {}
#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl authority_seal::Sealed for ProductionSettlementTakeoverAuthorityV1 {}
#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl authority_seal::Sealed for ProductionSettlementRetirementAuthorityV1 {}

impl RouteActionAuthority for ProductionSettlementActionAuthorityV1 {
    fn authorize_route_action(
        &mut self,
        request: RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ActionIntentV1, AuthorityRefusalV1> {
        let mut core = self
            .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        core.authorize_route_action(&request)
    }
}

impl ExternalCustodyAuthority for ProductionSettlementCustodyAuthorityV1 {
    fn externalize_custodied_action(
        &mut self,
        request: ExternalCustodyActionRequestV1,
    ) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1> {
        let mut core = self
            .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        core.externalize_custodied_action(request.capability())
    }
}

impl ChainObservationAuthority for ProductionSettlementObservationAuthorityV1 {
    fn verify_chain_observation(
        &mut self,
        request: ChainObservationRequestV1<'_>,
    ) -> Result<VerifiedChainObservationV1, AuthorityRefusalV1> {
        let mut core = self
            .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        core.verify_chain_observation(&request)
    }
}

impl TakeoverReconciliationAuthority for ProductionSettlementTakeoverAuthorityV1 {
    fn reconcile_committed_action(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        let mut core = self
            .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        core.reconcile_committed_action(&request)
    }
}

impl RouteSecretRetirementAuthority for ProductionSettlementRetirementAuthorityV1 {
    fn retire_route_secret(
        &mut self,
        capability: RouteSecretRetirementCapabilityV1,
    ) -> Result<(), AuthorityRefusalV1> {
        let mut core = self
            .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        core.plan_source.retire_public_secret(capability)
    }
}

impl ProductionSettlementBridgeCoreV1 {
    fn now(&self) -> Result<u64, AuthorityRefusalV1> {
        self.clock.now_unix_ms()
    }

    fn authorize_route_action(
        &mut self,
        request: &RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ActionIntentV1, AuthorityRefusalV1> {
        let now = self.now()?;
        let draft = self.plan_source.draft_for_action(request)?;
        validate_plan_draft(request, &draft)?;
        let effect_id = derive_effect_id_v1(
            request.route_id(),
            request.event_id(),
            request.fencing_epoch(),
            request.leg(),
            request.action(),
            draft.semantic_digest,
        );
        let bindings = SettlementPlanBindingsV1 {
            route_id: request.route_id(),
            effect_id,
            settlement_id: draft.settlement_id,
            leg: settlement_leg(request.leg()),
            action: settlement_action(request.action()),
            fencing_epoch: request.fencing_epoch(),
            semantic_digest: draft.semantic_digest,
            terms_digest: request.bindings().terms_digest,
            registry_digest: draft.registry_digest,
            dom_profile_digest: draft.dom_profile_digest,
            dom_deployment_digest: draft.dom_deployment_digest,
            counterparty_profile_digest: draft.counterparty_profile_digest,
            counterparty_deployment_digest: draft.counterparty_deployment_digest,
        };
        let plan = match draft.children {
            SettlementChildrenV1::Materialized(children) => CompositeSettlementPlanV1::new(
                bindings,
                draft.secret_requirement,
                draft.preexisting_secret_evidence_digest,
                children,
            ),
            SettlementChildrenV1::FirstExposureStaged { first, deferred } => {
                CompositeSettlementPlanV1::new_first_exposure_staged(bindings, first, deferred)
            }
        }
        .map_err(map_coordinator_error)?;

        let is_precommitted_funding = request.action() == ActionKindV1::Funding
            && request
                .snapshot()
                .leg(request.leg())
                .action(ActionKindV1::Funding)
                .progress()
                == ActionProgressV1::NotPrepared;

        let stored = match self.coordinator.load_plan_for_effect(effect_id) {
            Ok(stored) => {
                if stored.plan() != &plan {
                    return Err(AuthorityRefusalV1::Inconsistent);
                }
                if is_precommitted_funding {
                    validate_pristine_preinstalled_plan(&stored)?;
                    self.plan_persistence.revalidate_preinstalled_new_plan(
                        &stored,
                        request.event_id(),
                        now,
                    )?;
                }
                stored
            }
            Err(CoordinatorErrorV1::PlanNotFound) => {
                if is_precommitted_funding {
                    match self.coordinator.load_plan_for_stable_replacement(&plan) {
                        Ok(preinstalled) => {
                            self.refence_preinstalled_new_funding(request, preinstalled, plan, now)?
                        }
                        Err(CoordinatorErrorV1::PlanNotFound) => {
                            self.install_new_action_plan(plan, request.event_id(), effect_id, now)?
                        }
                        Err(error) => return Err(map_coordinator_error(error)),
                    }
                } else {
                    self.install_new_action_plan(plan, request.event_id(), effect_id, now)?
                }
            }
            Err(error) => return Err(map_coordinator_error(error)),
        };
        validate_stored_action_plan(request, &stored)?;
        Ok(action_intent_from_stored(&stored))
    }

    fn install_new_action_plan(
        &mut self,
        plan: CompositeSettlementPlanV1,
        route_event_id: EventIdV1,
        effect_id: Digest32,
        now: u64,
    ) -> Result<StoredSettlementPlanV1, AuthorityRefusalV1> {
        self.plan_persistence
            .install_new_plan(&mut self.coordinator, plan, route_event_id, now)?;
        self.coordinator
            .load_plan_for_effect(effect_id)
            .map_err(map_coordinator_error)
    }

    fn refence_preinstalled_new_funding(
        &mut self,
        request: &RouteActionAuthorizationRequestV1<'_>,
        preinstalled: StoredSettlementPlanV1,
        replacement: CompositeSettlementPlanV1,
        now: u64,
    ) -> Result<StoredSettlementPlanV1, AuthorityRefusalV1> {
        let old_fence = preinstalled.view().fencing_epoch;
        let new_fence = replacement.bindings().fencing_epoch;
        let expected_old_effect = derive_effect_id_v1(
            request.route_id(),
            request.event_id(),
            old_fence,
            request.leg(),
            request.action(),
            replacement.bindings().semantic_digest,
        );
        let expected_new_effect = derive_effect_id_v1(
            request.route_id(),
            request.event_id(),
            request.fencing_epoch(),
            request.leg(),
            request.action(),
            replacement.bindings().semantic_digest,
        );
        if request.action() != ActionKindV1::Funding
            || request
                .snapshot()
                .leg(request.leg())
                .action(ActionKindV1::Funding)
                .progress()
                != ActionProgressV1::NotPrepared
            || old_fence >= new_fence
            || new_fence != request.fencing_epoch()
            || preinstalled.view().effect_id != expected_old_effect
            || replacement.bindings().effect_id != expected_new_effect
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        validate_pristine_preinstalled_plan(&preinstalled)?;
        let takeover_evidence =
            preinstalled_takeover_evidence(request, &preinstalled, &replacement)?;
        let lease = self.acquire_or_resume_takeover_lease(
            preinstalled.view().plan_id,
            new_fence,
            takeover_evidence,
            now,
        )?;
        let progress_evidence = match self
            .coordinator
            .takeover_status(lease, now)
            .map_err(map_coordinator_error)?
        {
            CustodyTakeoverStatusV1::NothingExternalized { evidence_digest }
                if evidence_digest != ZERO_DIGEST =>
            {
                evidence_digest
            }
            CustodyTakeoverStatusV1::NothingExternalized { .. }
            | CustodyTakeoverStatusV1::SafeToResumeCustody(_)
            | CustodyTakeoverStatusV1::SecretPublicPartial(_)
            | CustodyTakeoverStatusV1::AggregateExternalized(_)
            | CustodyTakeoverStatusV1::Unknown { .. } => {
                return Err(AuthorityRefusalV1::Inconsistent)
            }
        };
        let expected = replacement.clone();
        let replacement_effect = replacement.bindings().effect_id;
        self.plan_persistence.refence_preinstalled_new_plan(
            &mut self.coordinator,
            lease,
            replacement,
            progress_evidence,
            request.event_id(),
            now,
        )?;
        let current = self
            .coordinator
            .load_plan_for_effect(replacement_effect)
            .map_err(map_coordinator_error)?;
        if current.plan() != &expected {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        validate_pristine_preinstalled_plan(&current)?;
        Ok(current)
    }

    fn externalize_custodied_action(
        &mut self,
        capability: &SignerCapabilityV1,
    ) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1> {
        let now = self.now()?;
        if capability.expires_at_unix_ms() < now {
            return Err(AuthorityRefusalV1::Refused);
        }
        let (stored, lease) = self.load_or_refence_for_capability(capability, now)?;
        validate_capability_against_stored(capability, &stored)?;

        // The audited current outcome is checked before another child can run.
        // In particular, a secret-bearing prefix whose response was lost is
        // replayed to the route until its exact public checkpoint appears in a
        // later capability.
        let current = self
            .coordinator
            .current_custody_progress(lease, now)
            .map_err(map_coordinator_error)?;
        if matches!(current, CoordinatorDriveOutcomeV1::Unknown { .. }) {
            let outcome = self
                .coordinator
                .reconcile_current_child_one(lease, &mut self.child_port, now)
                .map_err(map_coordinator_error)?;
            self.seal_drive_outcome_before_release(&stored, &outcome)?;
            return map_drive_outcome(capability, outcome);
        }
        self.seal_drive_outcome_before_release(&stored, &current)?;
        if let Some(replay) = replay_unacknowledged_progress(capability, current)? {
            return Ok(replay);
        }

        // A private downstream claim is intentionally installed with only
        // its DOM first-exposure child.  The route must acknowledge the exact
        // public exposure in a later capability before the counterparty claim
        // may even be materialized.  Materialization is its own durable tick:
        // this call commits the retained child facts and returns the existing
        // partial progress; only a subsequent custody call may broadcast it.
        if deferred_child_requires_materialization(&stored, &current)? {
            let route_exposure = capability
                .route_first_public_exposure()
                .ok_or(AuthorityRefusalV1::Inconsistent)?;
            let prior_view = stored.view().clone();
            let plan_source = self.plan_source.as_mut();
            let clock = self.clock.as_ref();
            let capability_expires_at = capability.expires_at_unix_ms();
            let mut authority = ProductionDeferredChildAuthorityAdapterV1 {
                source: plan_source,
                route_exposure,
            };
            let materialized = self
                .coordinator
                .materialize_deferred_child_one(lease, &mut authority, now, || {
                    let fresh_now = clock
                        .now_unix_ms()
                        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
                    if capability_expires_at < fresh_now {
                        return Err(CoordinatorErrorV1::LeaseExpired);
                    }
                    Ok(fresh_now)
                })
                .map_err(map_coordinator_error)?;
            validate_deferred_materialization_transition(&prior_view, &materialized)?;
            let post_materialization_now = clock.now_unix_ms()?;
            if capability_expires_at < post_materialization_now {
                return Err(AuthorityRefusalV1::Refused);
            }
            let retained_progress = self
                .coordinator
                .current_custody_progress(lease, post_materialization_now)
                .map_err(map_coordinator_error)?;
            return map_drive_outcome(capability, retained_progress);
        }

        let outcome = self
            .coordinator
            .drive_one(lease, &mut self.child_port, now)
            .map_err(map_coordinator_error)?;
        self.seal_drive_outcome_before_release(&stored, &outcome)?;
        map_drive_outcome(capability, outcome)
    }

    fn reconcile_committed_action(
        &mut self,
        request: &ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        let now = self.now()?;
        let stored = self
            .coordinator
            .load_plan_for_effect(request.effect_id())
            .map_err(map_coordinator_error)?;
        validate_reconciliation_request(request, &stored)?;
        let evidence = takeover_evidence(request)?;
        let lease = self.acquire_or_resume_takeover_lease(
            stored.view().plan_id,
            request.current_fence(),
            evidence,
            now,
        )?;
        let mut status = self
            .coordinator
            .takeover_status(lease, now)
            .map_err(map_coordinator_error)?;
        if matches!(status, CustodyTakeoverStatusV1::Unknown { .. }) {
            status = self
                .coordinator
                .reconcile_takeover_one(lease, &mut self.child_port, now)
                .map_err(map_coordinator_error)?;
        }
        self.seal_takeover_status_before_release(&stored, &status)?;
        map_takeover_status(request.intent().clone(), stored.plan(), status)
    }

    fn seal_drive_outcome_before_release(
        &mut self,
        stored: &StoredSettlementPlanV1,
        outcome: &CoordinatorDriveOutcomeV1,
    ) -> Result<(), AuthorityRefusalV1> {
        let exposure = match outcome {
            CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress.exposure,
            CoordinatorDriveOutcomeV1::AggregateExternalized(receipt) => receipt.first_exposure,
            CoordinatorDriveOutcomeV1::Waiting { .. }
            | CoordinatorDriveOutcomeV1::Unknown { .. } => None,
        };
        self.seal_child_exposure_before_release(stored, exposure)
    }

    fn seal_takeover_status_before_release(
        &mut self,
        stored: &StoredSettlementPlanV1,
        status: &CustodyTakeoverStatusV1,
    ) -> Result<(), AuthorityRefusalV1> {
        let exposure = match status {
            CustodyTakeoverStatusV1::SecretPublicPartial(progress) => progress.exposure,
            CustodyTakeoverStatusV1::AggregateExternalized(receipt) => receipt.first_exposure,
            CustodyTakeoverStatusV1::NothingExternalized { .. }
            | CustodyTakeoverStatusV1::SafeToResumeCustody(_)
            | CustodyTakeoverStatusV1::Unknown { .. } => None,
        };
        self.seal_child_exposure_before_release(stored, exposure)
    }

    fn seal_child_exposure_before_release(
        &mut self,
        stored: &StoredSettlementPlanV1,
        exposure: Option<ChildPublicExposureV1>,
    ) -> Result<(), AuthorityRefusalV1> {
        let Some(exposure) = exposure else {
            return Ok(());
        };
        let plan = stored.plan();
        if plan.bindings().action != SettlementActionV1::Claim
            || plan.secret_requirement() != SecretRequirementV1::FirstExposureRequired
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let authenticated = self
            .coordinator
            .authenticate_first_public_exposure(stored.view().plan_id)
            .map_err(map_coordinator_error)?;
        if authenticated.plan_id() != stored.view().plan_id
            || authenticated.route_id() != plan.bindings().route_id
            || authenticated.settlement_id() != plan.bindings().settlement_id
            || authenticated.exposure() != &exposure
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        self.plan_source.seal_first_public_exposure(authenticated)
    }

    fn verify_chain_observation(
        &mut self,
        request: &ChainObservationRequestV1<'_>,
    ) -> Result<VerifiedChainObservationV1, AuthorityRefusalV1> {
        let now = self.now()?;
        let (leg, action, aggregate_action_id) = match request.query() {
            ChainObservationQueryV1::Finality {
                leg,
                action,
                transaction_id,
            }
            | ChainObservationQueryV1::Invalidation {
                leg,
                action,
                transaction_id,
            } => (leg, action, transaction_id),
            ChainObservationQueryV1::SecretExposure { .. } => {
                // Independent scalar extraction remains a chain-specific
                // observer boundary; the coordinator only owns aggregate
                // child finality/reorg after its own custody receipts.
                return Err(AuthorityRefusalV1::Refused);
            }
        };
        let stored = self
            .coordinator
            .load_plan_for_aggregate_action(aggregate_action_id)
            .map_err(map_coordinator_error)?;
        validate_observation_request(request, leg, action, &stored)?;
        let lease = self.acquire_observation_lease(request, &stored, now)?;
        let child_index = select_observation_child(request.query(), stored.view())?;
        let outcome = self
            .coordinator
            .observe_child_once(lease, child_index, &mut self.child_port, now)
            .map_err(map_coordinator_error)?;
        map_observation_outcome(request.query(), outcome)
    }

    fn load_or_refence_for_capability(
        &mut self,
        capability: &SignerCapabilityV1,
        now: u64,
    ) -> Result<(StoredSettlementPlanV1, CoordinatorLeaseV1), AuthorityRefusalV1> {
        let stored = match self
            .coordinator
            .load_plan_for_effect(capability.effect_id())
        {
            Ok(stored) => stored,
            Err(CoordinatorErrorV1::PlanNotFound | CoordinatorErrorV1::StaleFencing) => {
                let aggregate = capability
                    .expected_transaction_id()
                    .ok_or(AuthorityRefusalV1::Inconsistent)?;
                self.coordinator
                    .load_plan_for_aggregate(aggregate, capability.dispatch_digest())
                    .map_err(map_coordinator_error)?
            }
            Err(error) => return Err(map_coordinator_error(error)),
        };

        if stored.view().fencing_epoch == capability.fencing_epoch()
            && stored.view().effect_id == capability.effect_id()
        {
            let lease = self
                .coordinator
                .acquire_lease(
                    stored.view().plan_id,
                    self.config.owner_id,
                    capability.fencing_epoch(),
                    now,
                    self.config.coordinator_lease_duration_ms,
                )
                .map_err(map_coordinator_error)?
                .lease();
            return Ok((stored, lease));
        }
        if stored.view().fencing_epoch >= capability.fencing_epoch() {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        validate_stable_capability(capability, &stored)?;
        let lease = self
            .coordinator
            .resume_takeover_lease(
                stored.view().plan_id,
                self.config.owner_id,
                capability.fencing_epoch(),
                now,
                self.config.coordinator_lease_duration_ms,
            )
            .map_err(map_coordinator_error)?
            .lease();
        let status = self
            .coordinator
            .takeover_status(lease, now)
            .map_err(map_coordinator_error)?;
        let progress_evidence = takeover_progress_evidence(status)?;
        let replacement = replacement_plan(
            stored.plan(),
            capability.effect_id(),
            capability.fencing_epoch(),
        )?;
        self.plan_persistence.refence_existing_plan(
            &mut self.coordinator,
            lease,
            replacement,
            progress_evidence,
            now,
        )?;
        let current = self
            .coordinator
            .load_plan_for_effect(capability.effect_id())
            .map_err(map_coordinator_error)?;
        Ok((current, lease))
    }

    fn acquire_observation_lease(
        &mut self,
        request: &ChainObservationRequestV1<'_>,
        stored: &StoredSettlementPlanV1,
        now: u64,
    ) -> Result<CoordinatorLeaseV1, AuthorityRefusalV1> {
        if request.fencing_epoch() < stored.view().fencing_epoch {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        // Observation cannot externalize a new transaction.  An aggregate
        // that already left custody therefore remains observed under its
        // authenticated plan fence even when the parent route acquired a
        // newer fence after restart.  This is exactly why the coordinator
        // offers the action-only lookup; no in-memory effect map is needed.
        Ok(self
            .coordinator
            .acquire_lease(
                stored.view().plan_id,
                self.config.owner_id,
                stored.view().fencing_epoch,
                now,
                self.config.coordinator_lease_duration_ms,
            )
            .map_err(map_coordinator_error)?
            .lease())
    }

    fn acquire_or_resume_takeover_lease(
        &mut self,
        plan_id: Digest32,
        route_fencing_epoch: u64,
        takeover_evidence_digest: Digest32,
        now: u64,
    ) -> Result<CoordinatorLeaseV1, AuthorityRefusalV1> {
        match self.coordinator.acquire_takeover_lease(
            plan_id,
            self.config.owner_id,
            route_fencing_epoch,
            takeover_evidence_digest,
            now,
            self.config.coordinator_lease_duration_ms,
        ) {
            Ok(acquired) => Ok(acquired.lease()),
            Err(CoordinatorErrorV1::StaleFencing) => self
                .coordinator
                .resume_takeover_lease(
                    plan_id,
                    self.config.owner_id,
                    route_fencing_epoch,
                    now,
                    self.config.coordinator_lease_duration_ms,
                )
                .map(settlement_coordinator::CoordinatorLeaseAcquireV1::lease)
                .map_err(map_coordinator_error),
            Err(error) => Err(map_coordinator_error(error)),
        }
    }
}

fn validate_pristine_preinstalled_plan(
    stored: &StoredSettlementPlanV1,
) -> Result<(), AuthorityRefusalV1> {
    let view = stored.view();
    if view.stage != AggregateStageV1::Active
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

fn validate_plan_draft(
    request: &RouteActionAuthorizationRequestV1<'_>,
    draft: &ProductionSettlementPlanDraftV1,
) -> Result<(), AuthorityRefusalV1> {
    if draft.expected_route_profile_bundle_digest != request.bindings().profile_bundle_digest
        || draft.expected_route_deployment_bundle_digest
            != request.bindings().deployment_bundle_digest
        || [
            draft.settlement_id,
            draft.semantic_digest,
            draft.registry_digest,
            draft.dom_profile_digest,
            draft.dom_deployment_digest,
            draft.counterparty_profile_digest,
            draft.counterparty_deployment_digest,
        ]
        .contains(&ZERO_DIGEST)
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    match (
        request.action(),
        &request.snapshot().secret_visibility,
        draft.secret_requirement,
        draft.preexisting_secret_evidence_digest,
    ) {
        (ActionKindV1::Funding | ActionKindV1::Refund, _, SecretRequirementV1::None, None) => {
            Ok(())
        }
        (
            ActionKindV1::Claim,
            SecretVisibilityV1::Private,
            SecretRequirementV1::FirstExposureRequired,
            None,
        ) => Ok(()),
        (
            ActionKindV1::Claim,
            SecretVisibilityV1::Public { first_exposure },
            SecretRequirementV1::AlreadyPublic,
            Some(evidence),
        ) if evidence == first_exposure.evidence_digest => Ok(()),
        _ => Err(AuthorityRefusalV1::Inconsistent),
    }
}

fn validate_stored_action_plan(
    request: &RouteActionAuthorizationRequestV1<'_>,
    stored: &StoredSettlementPlanV1,
) -> Result<(), AuthorityRefusalV1> {
    let bindings = stored.plan().bindings();
    if bindings.route_id != request.route_id()
        || bindings.fencing_epoch != request.fencing_epoch()
        || bindings.leg != settlement_leg(request.leg())
        || bindings.action != settlement_action(request.action())
        || bindings.terms_digest != request.bindings().terms_digest
        || stored.view().effect_id != bindings.effect_id
        || stored.view().fencing_epoch != bindings.fencing_epoch
        || stored.view().aggregate_action_id == ZERO_DIGEST
        || stored.view().aggregate_custody_digest == ZERO_DIGEST
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

fn action_intent_from_stored(stored: &StoredSettlementPlanV1) -> ActionIntentV1 {
    ActionIntentV1 {
        leg: route_leg(stored.plan().bindings().leg),
        kind: route_action(stored.plan().bindings().action),
        semantic_digest: stored.plan().bindings().semantic_digest,
        contains_route_secret: stored.plan().bindings().action == SettlementActionV1::Claim,
        dispatch: EffectDispatchV1::ExternalCustody {
            custody_digest: stored.view().aggregate_custody_digest,
            transaction_id: stored.view().aggregate_action_id,
        },
    }
}

fn validate_stable_capability(
    capability: &SignerCapabilityV1,
    stored: &StoredSettlementPlanV1,
) -> Result<(), AuthorityRefusalV1> {
    let bindings = stored.plan().bindings();
    if capability.route_id() != bindings.route_id
        || settlement_leg(capability.leg()) != bindings.leg
        || settlement_action(capability.action()) != bindings.action
        || capability.semantic_digest() != bindings.semantic_digest
        || capability.terms_digest() != bindings.terms_digest
        || capability.dispatch_digest() != stored.view().aggregate_custody_digest
        || capability.expected_transaction_id() != Some(stored.view().aggregate_action_id)
        || capability.contains_route_secret() != (bindings.action == SettlementActionV1::Claim)
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

fn validate_capability_against_stored(
    capability: &SignerCapabilityV1,
    stored: &StoredSettlementPlanV1,
) -> Result<(), AuthorityRefusalV1> {
    validate_stable_capability(capability, stored)?;
    if capability.effect_id() != stored.view().effect_id
        || capability.fencing_epoch() != stored.view().fencing_epoch
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    match stored.plan().secret_requirement() {
        SecretRequirementV1::None => {}
        SecretRequirementV1::FirstExposureRequired => {
            if let Some(acknowledged) = capability
                .acknowledged_custody_progress()
                .and_then(crate::AcknowledgedCustodyProgressV1::exposure)
            {
                let Some(route_exposure) = capability.route_first_public_exposure() else {
                    return Err(AuthorityRefusalV1::Inconsistent);
                };
                if !same_public_exposure(acknowledged, route_exposure) {
                    return Err(AuthorityRefusalV1::Inconsistent);
                }
            }
        }
        SecretRequirementV1::AlreadyPublic => {
            let route_exposure = capability
                .route_first_public_exposure()
                .ok_or(AuthorityRefusalV1::Inconsistent)?;
            if Some(route_exposure.evidence_digest)
                != stored.plan().preexisting_secret_evidence_digest()
            {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
        }
    }
    Ok(())
}

fn validate_reconciliation_request(
    request: &ReconciliationRequestV1<'_>,
    stored: &StoredSettlementPlanV1,
) -> Result<(), AuthorityRefusalV1> {
    let intent = request.intent();
    let (custody, aggregate) = match intent.dispatch {
        EffectDispatchV1::ExternalCustody {
            custody_digest,
            transaction_id,
        } => (custody_digest, transaction_id),
        EffectDispatchV1::RunnerPayload { .. } => return Err(AuthorityRefusalV1::Refused),
    };
    let bindings = stored.plan().bindings();
    if request.route_id() != bindings.route_id
        || request.effect_id() != bindings.effect_id
        || request.prior_fence() != bindings.fencing_epoch
        || request.current_fence() <= request.prior_fence()
        || request.bindings().terms_digest != bindings.terms_digest
        || route_leg(bindings.leg) != intent.leg
        || route_action(bindings.action) != intent.kind
        || bindings.semantic_digest != intent.semantic_digest
        || intent.contains_route_secret != (bindings.action == SettlementActionV1::Claim)
        || request.dispatch_digest() != custody
        || request.expected_transaction_id() != Some(aggregate)
        || custody != stored.view().aggregate_custody_digest
        || aggregate != stored.view().aggregate_action_id
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

fn validate_observation_request(
    request: &ChainObservationRequestV1<'_>,
    leg: LegIdV1,
    action: ActionKindV1,
    stored: &StoredSettlementPlanV1,
) -> Result<(), AuthorityRefusalV1> {
    let bindings = stored.plan().bindings();
    if request.route_id() != bindings.route_id
        || request.bindings().terms_digest != bindings.terms_digest
        || settlement_leg(leg) != bindings.leg
        || settlement_action(action) != bindings.action
        || !matches!(
            stored.view().stage,
            settlement_coordinator::AggregateStageV1::Externalized
                | settlement_coordinator::AggregateStageV1::Final
                | settlement_coordinator::AggregateStageV1::FinalityInvalidated
        )
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

fn replay_unacknowledged_progress(
    capability: &SignerCapabilityV1,
    current: CoordinatorDriveOutcomeV1,
) -> Result<Option<CustodyDispatchOutcomeV1>, AuthorityRefusalV1> {
    match current {
        CoordinatorDriveOutcomeV1::Waiting { .. } => Ok(None),
        CoordinatorDriveOutcomeV1::Unknown { .. } => Ok(Some(CustodyDispatchOutcomeV1::Unknown)),
        CoordinatorDriveOutcomeV1::PartialProgress(progress) => {
            validate_progress_identity(capability, &progress)?;
            let exposure = progress.exposure.map(public_exposure_from_child);
            if acknowledged_progress_matches(
                capability,
                progress.progress_evidence_digest,
                exposure.as_ref(),
            ) {
                Ok(None)
            } else {
                Ok(Some(CustodyDispatchOutcomeV1::PartialProgress {
                    progress_evidence_digest: progress.progress_evidence_digest,
                    exposure,
                }))
            }
        }
        CoordinatorDriveOutcomeV1::AggregateExternalized(receipt) => {
            validate_aggregate_identity(capability, &receipt)?;
            let exposure = receipt.first_exposure.map(public_exposure_from_child);
            if exposure.is_some()
                && !acknowledged_progress_matches(
                    capability,
                    receipt.child_receipts_digest,
                    exposure.as_ref(),
                )
            {
                Ok(Some(CustodyDispatchOutcomeV1::PartialProgress {
                    progress_evidence_digest: receipt.child_receipts_digest,
                    exposure,
                }))
            } else {
                Ok(Some(CustodyDispatchOutcomeV1::AggregateExternalized(
                    ActionExternalizationReceiptV1::public(receipt.aggregate_action_id),
                )))
            }
        }
    }
}

fn deferred_child_requires_materialization(
    stored: &StoredSettlementPlanV1,
    current: &CoordinatorDriveOutcomeV1,
) -> Result<bool, AuthorityRefusalV1> {
    let SettlementChildrenV1::FirstExposureStaged { deferred, .. } = stored.plan().child_layout()
    else {
        return Ok(false);
    };
    let view = stored.view();
    let [first, second] = &view.children;
    if second.stage != ChildStageV1::Deferred {
        return Ok(false);
    }
    let deferred_child_is_pristine = second.child_index == 1
        && second.face == deferred.face
        && second.exposure == settlement_coordinator::ChildExposureV1::UsesPublicSecret
        && second.call_attempts == 0
        && second.transaction_id.is_none()
        && second.externalization_evidence_digest.is_none()
        && second.finality_evidence_digest.is_none()
        && second.reorg_evidence_digest.is_none();
    if let CoordinatorDriveOutcomeV1::Waiting { evidence_digest } = current {
        if view.stage != AggregateStageV1::Active
            || view.completed_prefix != 0
            || *evidence_digest == ZERO_DIGEST
            || first.child_index != 0
            || first.stage != ChildStageV1::Planned
            || first.exposure != settlement_coordinator::ChildExposureV1::FirstSecretExposure
            || first.transaction_id.is_none()
            || first.externalization_evidence_digest.is_some()
            || first.finality_evidence_digest.is_some()
            || first.reorg_evidence_digest.is_some()
            || !deferred_child_is_pristine
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        return Ok(false);
    }
    let CoordinatorDriveOutcomeV1::PartialProgress(progress) = current else {
        return Err(AuthorityRefusalV1::Inconsistent);
    };
    if view.stage != AggregateStageV1::Active
        || view.completed_prefix != 1
        || progress.plan_id != view.plan_id
        || progress.aggregate_action_id != view.aggregate_action_id
        || progress.aggregate_custody_digest != view.aggregate_custody_digest
        || progress.completed_prefix != 1
        || progress.exposure.is_none()
        || first.child_index != 0
        || !matches!(
            first.stage,
            ChildStageV1::Externalized | ChildStageV1::Final | ChildStageV1::FinalityInvalidated
        )
        || first.exposure != settlement_coordinator::ChildExposureV1::FirstSecretExposure
        || !deferred_child_is_pristine
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(true)
}

fn validate_deferred_materialization_transition(
    before: &SettlementPlanViewV1,
    after: &SettlementPlanViewV1,
) -> Result<(), AuthorityRefusalV1> {
    let [before_first, before_second] = &before.children;
    let [after_first, after_second] = &after.children;
    if before.plan_id != after.plan_id
        || before.plan_digest != after.plan_digest
        || before.effect_id != after.effect_id
        || before.fencing_epoch != after.fencing_epoch
        || before.stage != AggregateStageV1::Active
        || after.stage != AggregateStageV1::Active
        || before.aggregate_action_id != after.aggregate_action_id
        || before.aggregate_custody_digest != after.aggregate_custody_digest
        || before.completed_prefix != 1
        || after.completed_prefix != 1
        || after.revision <= before.revision
        || before_first != after_first
        || before_second.stage != ChildStageV1::Deferred
        || after_second.stage != ChildStageV1::Planned
        || before_second.child_index != after_second.child_index
        || before_second.face != after_second.face
        || before_second.exposure != after_second.exposure
        || before_second.call_attempts != 0
        || after_second.call_attempts != 0
        || before_second.transaction_id.is_some()
        || !matches!(
            after_second.transaction_id,
            Some(transaction_id) if transaction_id != ZERO_DIGEST
        )
        || before_second.externalization_evidence_digest.is_some()
        || after_second.externalization_evidence_digest.is_some()
        || before_second.finality_evidence_digest.is_some()
        || after_second.finality_evidence_digest.is_some()
        || before_second.reorg_evidence_digest.is_some()
        || after_second.reorg_evidence_digest.is_some()
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

fn map_drive_outcome(
    capability: &SignerCapabilityV1,
    outcome: CoordinatorDriveOutcomeV1,
) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1> {
    match outcome {
        // The supervisor has no truthful retryable/no-externalization custody
        // variant. Retaining its dispatch lease as Unknown is conservative.
        CoordinatorDriveOutcomeV1::Waiting { .. } | CoordinatorDriveOutcomeV1::Unknown { .. } => {
            Ok(CustodyDispatchOutcomeV1::Unknown)
        }
        CoordinatorDriveOutcomeV1::PartialProgress(progress) => {
            validate_progress_identity(capability, &progress)?;
            Ok(CustodyDispatchOutcomeV1::PartialProgress {
                progress_evidence_digest: progress.progress_evidence_digest,
                exposure: progress.exposure.map(public_exposure_from_child),
            })
        }
        CoordinatorDriveOutcomeV1::AggregateExternalized(receipt) => {
            validate_aggregate_identity(capability, &receipt)?;
            // Reaching aggregate here is permitted only after any preceding
            // exposure checkpoint passed `replay_unacknowledged_progress`.
            Ok(CustodyDispatchOutcomeV1::AggregateExternalized(
                ActionExternalizationReceiptV1::public(receipt.aggregate_action_id),
            ))
        }
    }
}

fn map_takeover_status(
    intent: ActionIntentV1,
    plan: &CompositeSettlementPlanV1,
    status: CustodyTakeoverStatusV1,
) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
    match status {
        CustodyTakeoverStatusV1::NothingExternalized { evidence_digest } => {
            Ok(TakeoverReconciliationOutcomeV1::ProvenNotExternalized {
                intent,
                evidence_digest,
            })
        }
        CustodyTakeoverStatusV1::SafeToResumeCustody(progress) => {
            Ok(TakeoverReconciliationOutcomeV1::SafeToResumeCustody {
                intent,
                evidence_digest: progress.progress_evidence_digest,
            })
        }
        CustodyTakeoverStatusV1::SecretPublicPartial(progress) => {
            let exposure = progress.exposure.ok_or(AuthorityRefusalV1::Inconsistent)?;
            Ok(
                TakeoverReconciliationOutcomeV1::SecretPublicPartialCustody {
                    intent,
                    progress_evidence_digest: progress.progress_evidence_digest,
                    exposure: public_exposure_from_child(exposure),
                },
            )
        }
        CustodyTakeoverStatusV1::AggregateExternalized(receipt) => {
            if plan.secret_requirement() == SecretRequirementV1::FirstExposureRequired {
                // Conservatively journal the real child exposure before route
                // aggregate closure. The next refenced custody call returns the
                // already durable aggregate receipt without another child call.
                let exposure = receipt
                    .first_exposure
                    .ok_or(AuthorityRefusalV1::Inconsistent)?;
                Ok(
                    TakeoverReconciliationOutcomeV1::SecretPublicPartialCustody {
                        intent,
                        progress_evidence_digest: receipt.child_receipts_digest,
                        exposure: public_exposure_from_child(exposure),
                    },
                )
            } else {
                Ok(TakeoverReconciliationOutcomeV1::Externalized(
                    ActionExternalizationReceiptV1::public(receipt.aggregate_action_id),
                ))
            }
        }
        CustodyTakeoverStatusV1::Unknown { .. } => Ok(TakeoverReconciliationOutcomeV1::Unknown),
    }
}

fn map_observation_outcome(
    query: ChainObservationQueryV1,
    outcome: CoordinatorObservationOutcomeV1,
) -> Result<VerifiedChainObservationV1, AuthorityRefusalV1> {
    match (query, outcome) {
        (
            ChainObservationQueryV1::Finality { .. },
            CoordinatorObservationOutcomeV1::AggregateFinal(finality),
        ) => Ok(VerifiedChainObservationV1::Finality {
            evidence_digest: finality.evidence_digest,
        }),
        (
            ChainObservationQueryV1::Invalidation { .. },
            CoordinatorObservationOutcomeV1::AggregateInvalidated(reorg),
        ) => Ok(VerifiedChainObservationV1::Invalidation {
            reorg_evidence_digest: reorg.evidence_digest,
        }),
        (
            ChainObservationQueryV1::Finality { .. },
            CoordinatorObservationOutcomeV1::Pending { .. }
            | CoordinatorObservationOutcomeV1::ChildFinalized { .. },
        )
        | (
            ChainObservationQueryV1::Invalidation { .. },
            CoordinatorObservationOutcomeV1::Pending { .. }
            | CoordinatorObservationOutcomeV1::ChildFinalized { .. }
            | CoordinatorObservationOutcomeV1::AggregateFinal(_),
        ) => Err(AuthorityRefusalV1::Unavailable),
        _ => Err(AuthorityRefusalV1::Inconsistent),
    }
}

fn select_observation_child(
    query: ChainObservationQueryV1,
    view: &settlement_coordinator::SettlementPlanViewV1,
) -> Result<u8, AuthorityRefusalV1> {
    use settlement_coordinator::ChildStageV1;
    match query {
        ChainObservationQueryV1::Finality { .. } => view
            .children
            .iter()
            .find(|child| !matches!(child.stage, ChildStageV1::Final | ChildStageV1::Deferred))
            .map(|child| child.child_index)
            .or_else(|| {
                let index = usize::try_from(view.revision % 2).ok()?;
                Some(view.children[index].child_index)
            })
            .ok_or(AuthorityRefusalV1::Inconsistent),
        ChainObservationQueryV1::Invalidation { .. } => {
            let first =
                usize::try_from(view.revision % 2).map_err(|_| AuthorityRefusalV1::Inconsistent)?;
            for index in [first, 1usize.wrapping_sub(first)] {
                if view.children[index].stage == ChildStageV1::Final {
                    return Ok(view.children[index].child_index);
                }
            }
            Err(AuthorityRefusalV1::Inconsistent)
        }
        ChainObservationQueryV1::SecretExposure { .. } => Err(AuthorityRefusalV1::Refused),
    }
}

fn validate_progress_identity(
    capability: &SignerCapabilityV1,
    progress: &PartialCustodyProgressV1,
) -> Result<(), AuthorityRefusalV1> {
    if progress.aggregate_action_id != capability.expected_transaction_id().unwrap_or(ZERO_DIGEST)
        || progress.aggregate_custody_digest != capability.dispatch_digest()
        || progress.progress_evidence_digest == ZERO_DIGEST
        || progress.completed_prefix == 0
        || progress.completed_prefix >= 2
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

fn validate_aggregate_identity(
    capability: &SignerCapabilityV1,
    receipt: &AggregateExternalizationReceiptV1,
) -> Result<(), AuthorityRefusalV1> {
    if receipt.aggregate_action_id != capability.expected_transaction_id().unwrap_or(ZERO_DIGEST)
        || receipt.aggregate_custody_digest != capability.dispatch_digest()
        || receipt.child_receipts_digest == ZERO_DIGEST
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

fn replacement_plan(
    current: &CompositeSettlementPlanV1,
    effect_id: Digest32,
    fencing_epoch: u64,
) -> Result<CompositeSettlementPlanV1, AuthorityRefusalV1> {
    let mut bindings = current.bindings().clone();
    bindings.effect_id = effect_id;
    bindings.fencing_epoch = fencing_epoch;
    match current.child_layout().clone() {
        SettlementChildrenV1::Materialized(children) => CompositeSettlementPlanV1::new(
            bindings,
            current.secret_requirement(),
            current.preexisting_secret_evidence_digest(),
            children,
        ),
        SettlementChildrenV1::FirstExposureStaged { first, deferred } => {
            CompositeSettlementPlanV1::new_first_exposure_staged(bindings, first, deferred)
        }
    }
    .map_err(map_coordinator_error)
}

fn takeover_progress_evidence(
    status: CustodyTakeoverStatusV1,
) -> Result<Digest32, AuthorityRefusalV1> {
    let evidence = match status {
        CustodyTakeoverStatusV1::NothingExternalized { evidence_digest }
        | CustodyTakeoverStatusV1::Unknown { evidence_digest } => evidence_digest,
        CustodyTakeoverStatusV1::SafeToResumeCustody(progress)
        | CustodyTakeoverStatusV1::SecretPublicPartial(progress) => {
            progress.progress_evidence_digest
        }
        CustodyTakeoverStatusV1::AggregateExternalized(receipt) => receipt.child_receipts_digest,
    };
    if evidence == ZERO_DIGEST {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(evidence)
}

fn public_exposure_from_child(exposure: ChildPublicExposureV1) -> PublicExposureV1 {
    PublicExposureV1 {
        source: ExposureSourceV1::Externalized,
        chain_id: exposure.chain_id,
        transaction_id: exposure.transaction_id,
        evidence_digest: exposure.evidence_digest,
        observed_at_unix_ms: exposure.observed_at_unix_ms,
    }
}

fn acknowledged_progress_matches(
    capability: &SignerCapabilityV1,
    progress_evidence_digest: Digest32,
    exposure: Option<&PublicExposureV1>,
) -> bool {
    let Some(acknowledged) = capability.acknowledged_custody_progress() else {
        return false;
    };
    if acknowledged.progress_evidence_digest() != progress_evidence_digest {
        return false;
    }
    match (acknowledged.exposure(), exposure) {
        (None, None) => true,
        (Some(left), Some(right)) => same_public_exposure(left, right),
        _ => false,
    }
}

fn same_public_exposure(left: &PublicExposureV1, right: &PublicExposureV1) -> bool {
    left.source == ExposureSourceV1::Externalized
        && right.source == ExposureSourceV1::Externalized
        && left.chain_id == right.chain_id
        && left.transaction_id == right.transaction_id
        && left.evidence_digest == right.evidence_digest
        && left.observed_at_unix_ms == right.observed_at_unix_ms
}

fn settlement_leg(value: LegIdV1) -> SettlementLegV1 {
    match value {
        LegIdV1::Upstream => SettlementLegV1::Upstream,
        LegIdV1::Downstream => SettlementLegV1::Downstream,
    }
}

fn route_leg(value: SettlementLegV1) -> LegIdV1 {
    match value {
        SettlementLegV1::Upstream => LegIdV1::Upstream,
        SettlementLegV1::Downstream => LegIdV1::Downstream,
    }
}

fn settlement_action(value: ActionKindV1) -> SettlementActionV1 {
    match value {
        ActionKindV1::Funding => SettlementActionV1::Funding,
        ActionKindV1::Claim => SettlementActionV1::Claim,
        ActionKindV1::Refund => SettlementActionV1::Refund,
    }
}

fn route_action(value: SettlementActionV1) -> ActionKindV1 {
    match value {
        SettlementActionV1::Funding => ActionKindV1::Funding,
        SettlementActionV1::Claim => ActionKindV1::Claim,
        SettlementActionV1::Refund => ActionKindV1::Refund,
    }
}

fn takeover_evidence(
    request: &ReconciliationRequestV1<'_>,
) -> Result<Digest32, AuthorityRefusalV1> {
    domain_digest(
        TAKEOVER_EVIDENCE_DOMAIN,
        &[
            &request.route_id(),
            &request.effect_id(),
            &request.prior_fence().to_be_bytes(),
            &request.current_fence().to_be_bytes(),
            &request.dispatch_digest(),
            &request.expected_transaction_id().unwrap_or(ZERO_DIGEST),
        ],
    )
}

fn preinstalled_takeover_evidence(
    request: &RouteActionAuthorizationRequestV1<'_>,
    current: &StoredSettlementPlanV1,
    replacement: &CompositeSettlementPlanV1,
) -> Result<Digest32, AuthorityRefusalV1> {
    domain_digest(
        PREINSTALLED_TAKEOVER_EVIDENCE_DOMAIN,
        &[
            &request.route_id(),
            &request.event_id(),
            &current.view().effect_id,
            &replacement.bindings().effect_id,
            &current.view().fencing_epoch.to_be_bytes(),
            &replacement.bindings().fencing_epoch.to_be_bytes(),
            &current.view().plan_id,
            &current.view().aggregate_action_id,
            &current.view().aggregate_custody_digest,
            &current.view().plan_digest,
        ],
    )
}

fn domain_digest(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, AuthorityRefusalV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| AuthorityRefusalV1::Inconsistent)?;
    hasher.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
    if output == ZERO_DIGEST {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(output)
}

pub(crate) fn map_coordinator_error(error: CoordinatorErrorV1) -> AuthorityRefusalV1 {
    match error {
        CoordinatorErrorV1::StorageUnavailable
        | CoordinatorErrorV1::LeaseHeld
        | CoordinatorErrorV1::ChildAuthorityRefused
        | CoordinatorErrorV1::ChildObserverRefused
        | CoordinatorErrorV1::PlanAuthorityRefused => AuthorityRefusalV1::Unavailable,
        CoordinatorErrorV1::CorruptState
        | CoordinatorErrorV1::CreationIncomplete
        | CoordinatorErrorV1::IdempotencyConflict
        | CoordinatorErrorV1::FailedClosed
        | CoordinatorErrorV1::ChildReceiptMismatch => AuthorityRefusalV1::Inconsistent,
        CoordinatorErrorV1::InvalidPlan
        | CoordinatorErrorV1::InvalidCanonicalMaterial
        | CoordinatorErrorV1::InvalidPlanAuthorization
        | CoordinatorErrorV1::DatabasePresent
        | CoordinatorErrorV1::DatabaseMissing
        | CoordinatorErrorV1::InvalidStorageAuthority
        | CoordinatorErrorV1::UnsupportedFormat
        | CoordinatorErrorV1::PlanNotFound
        | CoordinatorErrorV1::StaleFencing
        | CoordinatorErrorV1::LeaseExpired
        | CoordinatorErrorV1::InvalidBound
        | CoordinatorErrorV1::InvalidState
        | CoordinatorErrorV1::ReconciliationRequired => AuthorityRefusalV1::Refused,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    use route_executor::{
        digest_bytes_v1, ActionStateV1, CommitOutcomeV1, DurableRouteStoreV1, FrozenBindingsV1,
        RefundBindingsV1, RouteEventV1, RouteLeaseV1,
    };
    use settlement_coordinator::{
        AggregateStageV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1, ChildExposureV1,
        ChildExternalizationReceiptV1, ChildObservationOutcomeV1, ChildReconciliationOutcomeV1,
        ChildReconciliationRequestV1, DeferredSettlementChildV1, PlanAuthorityRefusalV1,
        PlanAuthorizationRequestV1, PlanAuthorizationV1, SettlementChildPlanV1, SettlementFaceV1,
        SettlementPlanAuthorityV1,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::supervisor::{
        Clock, ManualClockV1, RouteSupervisorConfigV1, RouteSupervisorErrorV1, RouteSupervisorV1,
        RunnerActionAuthority, RunnerActionRequestV1,
    };

    const ROUTE_ID: Digest32 = [1; 32];
    const ROUTE_OWNER_A: Digest32 = [2; 32];
    const ROUTE_OWNER_B: Digest32 = [3; 32];
    const COORDINATOR_ID: Digest32 = [4; 32];
    const PLAN_AUTHORITY_ID: Digest32 = [5; 32];
    const COORDINATOR_OWNER_A: Digest32 = [6; 32];
    const COORDINATOR_OWNER_B: Digest32 = [7; 32];
    const DEFERRED_MATERIALIZER_AUTHORITY_ID: Digest32 = [0xd1; 32];
    const TERMS_DIGEST: Digest32 = [8; 32];
    const PROFILE_BUNDLE_DIGEST: Digest32 = [9; 32];
    const DEPLOYMENT_BUNDLE_DIGEST: Digest32 = [10; 32];
    const TEST_NOW: u64 = 1_100;
    const TAKEOVER_NOW: u64 = 3_000;

    fn digest(value: u8) -> Digest32 {
        [value; 32]
    }

    #[derive(Clone)]
    struct TestSettlementClockV1(ManualClockV1);

    impl SettlementBridgeClockV1 for TestSettlementClockV1 {
        fn now_unix_ms(&self) -> Result<u64, AuthorityRefusalV1> {
            self.0
                .now_unix_ms()
                .map_err(|_| AuthorityRefusalV1::Unavailable)
        }
    }

    #[derive(Default)]
    struct PersistenceLogV1 {
        installs: Vec<EventIdV1>,
        revalidations: Vec<EventIdV1>,
        preinstalled_refences: Vec<EventIdV1>,
        refences: usize,
    }

    struct TestPlanAuthorityV1;

    impl SettlementPlanAuthorityV1 for TestPlanAuthorityV1 {
        fn authorize_plan(
            &mut self,
            request: PlanAuthorizationRequestV1<'_>,
        ) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
            PlanAuthorizationV1::new(
                PLAN_AUTHORITY_ID,
                request.plan_digest(),
                digest(240),
                u64::MAX,
            )
            .map_err(|_| PlanAuthorityRefusalV1::Refused)
        }
    }

    struct TestPlanPersistenceV1 {
        log: Rc<RefCell<PersistenceLogV1>>,
    }

    impl ProductionSettlementPlanPersistenceV1 for TestPlanPersistenceV1 {
        fn install_new_plan(
            &mut self,
            coordinator: &mut DurableSettlementCoordinatorV1,
            plan: CompositeSettlementPlanV1,
            route_event_id: EventIdV1,
            trusted_now_unix_ms: u64,
        ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
            self.log.borrow_mut().installs.push(route_event_id);
            coordinator
                .install_plan(&mut TestPlanAuthorityV1, plan, trusted_now_unix_ms)
                .map_err(map_coordinator_error)
        }

        fn revalidate_preinstalled_new_plan(
            &mut self,
            stored: &StoredSettlementPlanV1,
            route_event_id: EventIdV1,
            _trusted_now_unix_ms: u64,
        ) -> Result<(), AuthorityRefusalV1> {
            if stored.plan().bindings().action != SettlementActionV1::Funding {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
            self.log.borrow_mut().revalidations.push(route_event_id);
            Ok(())
        }

        fn refence_preinstalled_new_plan(
            &mut self,
            coordinator: &mut DurableSettlementCoordinatorV1,
            lease: CoordinatorLeaseV1,
            replacement: CompositeSettlementPlanV1,
            progress_evidence_digest: Digest32,
            route_event_id: EventIdV1,
            trusted_now_unix_ms: u64,
        ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
            if replacement.bindings().action != SettlementActionV1::Funding {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
            self.log
                .borrow_mut()
                .preinstalled_refences
                .push(route_event_id);
            coordinator
                .refence_plan(
                    lease,
                    replacement,
                    progress_evidence_digest,
                    &mut TestPlanAuthorityV1,
                    trusted_now_unix_ms,
                )
                .map_err(map_coordinator_error)
        }

        fn refence_existing_plan(
            &mut self,
            coordinator: &mut DurableSettlementCoordinatorV1,
            lease: CoordinatorLeaseV1,
            replacement: CompositeSettlementPlanV1,
            progress_evidence_digest: Digest32,
            trusted_now_unix_ms: u64,
        ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
            self.log.borrow_mut().refences += 1;
            coordinator
                .refence_plan(
                    lease,
                    replacement,
                    progress_evidence_digest,
                    &mut TestPlanAuthorityV1,
                    trusted_now_unix_ms,
                )
                .map_err(map_coordinator_error)
        }
    }

    #[derive(Default)]
    struct TestPlanSourceV1 {
        materialization_calls: Rc<Cell<u64>>,
        materialization_attempts: Rc<RefCell<Vec<Digest32>>>,
        materialization_clock: Option<ManualClockV1>,
        advance_materialization_to: Rc<Cell<Option<u64>>>,
    }

    impl ProductionSettlementPlanSourceV1 for TestPlanSourceV1 {
        fn deferred_materializer_authority_id(&self) -> Digest32 {
            DEFERRED_MATERIALIZER_AUTHORITY_ID
        }

        fn draft_for_action(
            &mut self,
            request: &RouteActionAuthorizationRequestV1<'_>,
        ) -> Result<ProductionSettlementPlanDraftV1, AuthorityRefusalV1> {
            Ok(test_plan_draft(
                request.leg(),
                request.action(),
                &request.snapshot().secret_visibility,
                request.bindings(),
            ))
        }

        fn seal_first_public_exposure(
            &mut self,
            authority: AuthenticatedCoordinatorExposureV1,
        ) -> Result<(), AuthorityRefusalV1> {
            let exposure = authority.exposure();
            if authority.route_id() != ROUTE_ID
                || exposure.chain_id == ZERO_DIGEST
                || exposure.transaction_id == ZERO_DIGEST
                || exposure.evidence_digest == ZERO_DIGEST
                || exposure.observed_at_unix_ms == 0
            {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
            Ok(())
        }

        fn materialize_deferred_child(
            &mut self,
            capability: DeferredChildMaterializationCapabilityV1,
            route_exposure: &PublicExposureV1,
        ) -> Result<DeferredChildMaterializationResultV1, AuthorityRefusalV1> {
            self.materialization_calls
                .set(self.materialization_calls.get().saturating_add(1));
            self.materialization_attempts
                .borrow_mut()
                .push(capability.attempt_id());
            if let (Some(clock), Some(advance_to)) = (
                self.materialization_clock.as_ref(),
                self.advance_materialization_to.take(),
            ) {
                clock
                    .set(advance_to)
                    .map_err(|_| AuthorityRefusalV1::Unavailable)?;
            }
            let descriptor = capability.descriptor().clone();
            let exposure = *capability.exposure();
            if capability.route_id() != ROUTE_ID
                || descriptor.materializer_authority_id != DEFERRED_MATERIALIZER_AUTHORITY_ID
                || route_exposure.chain_id != exposure.chain_id
                || route_exposure.transaction_id != exposure.transaction_id
                || route_exposure.evidence_digest != exposure.evidence_digest
                || route_exposure.observed_at_unix_ms != exposure.observed_at_unix_ms
            {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
            DeferredChildMaterializationResultV1::complete(
                capability,
                DEFERRED_MATERIALIZER_AUTHORITY_ID,
                SettlementChildPlanV1 {
                    face: descriptor.face,
                    exposure: ChildExposureV1::UsesPublicSecret,
                    chain_id: descriptor.chain_id,
                    expected_transaction_id: digest(0xd2),
                    intent_digest: digest(0xd3),
                    custody_digest: digest(0xd4),
                },
            )
            .map_err(map_coordinator_error)
        }

        fn retire_public_secret(
            &mut self,
            _capability: RouteSecretRetirementCapabilityV1,
        ) -> Result<(), AuthorityRefusalV1> {
            Ok(())
        }
    }

    struct RefusingSealPlanSourceV1 {
        seal_calls: Rc<RefCell<Vec<PublicExposureV1>>>,
    }

    impl ProductionSettlementPlanSourceV1 for RefusingSealPlanSourceV1 {
        fn deferred_materializer_authority_id(&self) -> Digest32 {
            DEFERRED_MATERIALIZER_AUTHORITY_ID
        }

        fn draft_for_action(
            &mut self,
            request: &RouteActionAuthorizationRequestV1<'_>,
        ) -> Result<ProductionSettlementPlanDraftV1, AuthorityRefusalV1> {
            Ok(test_plan_draft(
                request.leg(),
                request.action(),
                &request.snapshot().secret_visibility,
                request.bindings(),
            ))
        }

        fn seal_first_public_exposure(
            &mut self,
            authority: AuthenticatedCoordinatorExposureV1,
        ) -> Result<(), AuthorityRefusalV1> {
            if authority.route_id() != ROUTE_ID {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
            self.seal_calls
                .borrow_mut()
                .push(public_exposure_from_child(*authority.exposure()));
            Err(AuthorityRefusalV1::Unavailable)
        }

        fn materialize_deferred_child(
            &mut self,
            _capability: DeferredChildMaterializationCapabilityV1,
            _route_exposure: &PublicExposureV1,
        ) -> Result<DeferredChildMaterializationResultV1, AuthorityRefusalV1> {
            Err(AuthorityRefusalV1::Refused)
        }

        fn retire_public_secret(
            &mut self,
            _capability: RouteSecretRetirementCapabilityV1,
        ) -> Result<(), AuthorityRefusalV1> {
            Ok(())
        }
    }

    fn test_plan_draft(
        leg: LegIdV1,
        action: ActionKindV1,
        visibility: &SecretVisibilityV1,
        bindings: &FrozenBindingsV1,
    ) -> ProductionSettlementPlanDraftV1 {
        let leg_offset = match leg {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 40,
        };
        let action_offset = match action {
            ActionKindV1::Funding => 0,
            ActionKindV1::Claim => 10,
            ActionKindV1::Refund => 20,
        };
        let base = 30_u8
            .checked_add(leg_offset)
            .and_then(|value| value.checked_add(action_offset))
            .expect("fixture digest range");
        let (secret_requirement, preexisting, exposures) = match (action, visibility) {
            (ActionKindV1::Funding | ActionKindV1::Refund, _) => (
                SecretRequirementV1::None,
                None,
                [ChildExposureV1::NonSecret, ChildExposureV1::NonSecret],
            ),
            (ActionKindV1::Claim, SecretVisibilityV1::Private) => (
                SecretRequirementV1::FirstExposureRequired,
                None,
                [
                    ChildExposureV1::FirstSecretExposure,
                    ChildExposureV1::UsesPublicSecret,
                ],
            ),
            (ActionKindV1::Claim, SecretVisibilityV1::Public { first_exposure }) => (
                SecretRequirementV1::AlreadyPublic,
                Some(first_exposure.evidence_digest),
                [
                    ChildExposureV1::UsesPublicSecret,
                    ChildExposureV1::UsesPublicSecret,
                ],
            ),
        };
        let materialized = [
            SettlementChildPlanV1 {
                face: SettlementFaceV1::Evm,
                exposure: exposures[0],
                chain_id: digest(base.wrapping_add(2)),
                expected_transaction_id: digest(base.wrapping_add(3)),
                intent_digest: digest(base.wrapping_add(4)),
                custody_digest: digest(base.wrapping_add(5)),
            },
            SettlementChildPlanV1 {
                face: SettlementFaceV1::Dom,
                exposure: exposures[1],
                chain_id: digest(base.wrapping_add(6)),
                expected_transaction_id: digest(base.wrapping_add(7)),
                intent_digest: digest(base.wrapping_add(8)),
                custody_digest: digest(base.wrapping_add(9)),
            },
        ];
        let children = if leg == LegIdV1::Downstream
            && action == ActionKindV1::Claim
            && matches!(visibility, SecretVisibilityV1::Private)
        {
            SettlementChildrenV1::FirstExposureStaged {
                first: SettlementChildPlanV1 {
                    exposure: ChildExposureV1::FirstSecretExposure,
                    ..materialized[1].clone()
                },
                deferred: DeferredSettlementChildV1 {
                    face: SettlementFaceV1::Evm,
                    chain_id: materialized[0].chain_id,
                    route_scope_digest: digest(0xc1),
                    composition_digest: digest(0xc2),
                    role_plan_digest: digest(0xc3),
                    source_scope_digest: digest(0xc4),
                    materializer_authority_id: DEFERRED_MATERIALIZER_AUTHORITY_ID,
                },
            }
        } else {
            SettlementChildrenV1::Materialized(materialized)
        };
        ProductionSettlementPlanDraftV1 {
            settlement_id: digest(base),
            semantic_digest: digest(base.wrapping_add(1)),
            registry_digest: digest(200),
            expected_route_profile_bundle_digest: bindings.profile_bundle_digest,
            expected_route_deployment_bundle_digest: bindings.deployment_bundle_digest,
            dom_profile_digest: digest(201),
            dom_deployment_digest: digest(202),
            counterparty_profile_digest: digest(203),
            counterparty_deployment_digest: digest(204),
            secret_requirement,
            preexisting_secret_evidence_digest: preexisting,
            children,
        }
    }

    fn test_plan(
        route_id: Digest32,
        event_id: EventIdV1,
        fence: u64,
        leg: LegIdV1,
        action: ActionKindV1,
        visibility: &SecretVisibilityV1,
        bindings: &FrozenBindingsV1,
    ) -> CompositeSettlementPlanV1 {
        let draft = test_plan_draft(leg, action, visibility, bindings);
        let effect_id = derive_effect_id_v1(
            route_id,
            event_id,
            fence,
            leg,
            action,
            draft.semantic_digest,
        );
        let plan_bindings = SettlementPlanBindingsV1 {
            route_id,
            effect_id,
            settlement_id: draft.settlement_id,
            leg: settlement_leg(leg),
            action: settlement_action(action),
            fencing_epoch: fence,
            semantic_digest: draft.semantic_digest,
            terms_digest: bindings.terms_digest,
            registry_digest: draft.registry_digest,
            dom_profile_digest: draft.dom_profile_digest,
            dom_deployment_digest: draft.dom_deployment_digest,
            counterparty_profile_digest: draft.counterparty_profile_digest,
            counterparty_deployment_digest: draft.counterparty_deployment_digest,
        };
        match draft.children {
            SettlementChildrenV1::Materialized(children) => CompositeSettlementPlanV1::new(
                plan_bindings,
                draft.secret_requirement,
                draft.preexisting_secret_evidence_digest,
                children,
            ),
            SettlementChildrenV1::FirstExposureStaged { first, deferred } => {
                CompositeSettlementPlanV1::new_first_exposure_staged(plan_bindings, first, deferred)
            }
        }
        .expect("valid fixture plan")
    }

    #[derive(Clone, Copy)]
    enum DispatchModeV1 {
        Externalized(u8),
        RetryableBeforeExternalization(u8),
        Unknown(u8),
    }

    #[derive(Clone, Copy)]
    enum ReconcileModeV1 {
        Externalized(u8),
        NotExternalized(u8),
        Unknown(u8),
    }

    #[derive(Default)]
    struct ChildStateV1 {
        dispatch: VecDeque<DispatchModeV1>,
        reconcile: VecDeque<ReconcileModeV1>,
        calls: Vec<(SettlementLegV1, SettlementActionV1, u8)>,
        effects: Vec<Digest32>,
        reconciliations: Vec<Digest32>,
    }

    #[derive(Clone)]
    struct TestChildAuthorityV1(Rc<RefCell<ChildStateV1>>);

    impl TestChildAuthorityV1 {
        fn receipt(
            request: &ChildDispatchRequestV1,
            evidence: u8,
        ) -> ChildExternalizationReceiptV1 {
            ChildExternalizationReceiptV1 {
                plan_id: request.plan_id(),
                child_index: request.child_index(),
                face: request.face(),
                chain_id: request.chain_id(),
                transaction_id: request.expected_transaction_id(),
                intent_digest: request.intent_digest(),
                custody_digest: request.custody_digest(),
                externalization_evidence_digest: digest(evidence),
                first_exposure_evidence_digest: (request.exposure()
                    == ChildExposureV1::FirstSecretExposure)
                    .then(|| digest(evidence.wrapping_add(80))),
            }
        }
    }

    impl SettlementChildAuthorityV1 for TestChildAuthorityV1 {
        fn externalize_child(
            &mut self,
            request: &ChildDispatchRequestV1,
        ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
            let mut state = self.0.borrow_mut();
            state
                .calls
                .push((request.leg(), request.action(), request.child_index()));
            state.effects.push(request.effect_id());
            match state
                .dispatch
                .pop_front()
                .ok_or(ChildAuthorityRefusalV1::Unavailable)?
            {
                DispatchModeV1::Externalized(evidence) => Ok(
                    ChildExecutionOutcomeV1::Externalized(Self::receipt(request, evidence)),
                ),
                DispatchModeV1::RetryableBeforeExternalization(evidence) => {
                    Ok(ChildExecutionOutcomeV1::RetryableBeforeExternalization {
                        evidence_digest: digest(evidence),
                    })
                }
                DispatchModeV1::Unknown(evidence) => Ok(ChildExecutionOutcomeV1::Unknown {
                    evidence_digest: digest(evidence),
                }),
            }
        }

        fn reconcile_child(
            &mut self,
            request: &ChildReconciliationRequestV1,
        ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
            let mut state = self.0.borrow_mut();
            state
                .reconciliations
                .push(request.reconciliation_attempt_id);
            match state
                .reconcile
                .pop_front()
                .ok_or(ChildAuthorityRefusalV1::Unavailable)?
            {
                ReconcileModeV1::Externalized(evidence) => {
                    Ok(ChildReconciliationOutcomeV1::Externalized(Self::receipt(
                        &request.dispatch,
                        evidence,
                    )))
                }
                ReconcileModeV1::NotExternalized(evidence) => {
                    Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized {
                        evidence_digest: digest(evidence),
                    })
                }
                ReconcileModeV1::Unknown(evidence) => Ok(ChildReconciliationOutcomeV1::Unknown {
                    evidence_digest: digest(evidence),
                }),
            }
        }
    }

    #[derive(Clone, Copy)]
    enum ObservationModeV1 {
        Final(u8),
        Invalidate(u8),
    }

    #[derive(Default)]
    struct ObserverStateV1 {
        outcomes: VecDeque<ObservationModeV1>,
        requests: Vec<ChildObservationRequestV1>,
    }

    #[derive(Clone)]
    struct TestObserverV1(Rc<RefCell<ObserverStateV1>>);

    impl SettlementChildObserverV1 for TestObserverV1 {
        fn observe_child(
            &mut self,
            request: &ChildObservationRequestV1,
        ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
            let mut state = self.0.borrow_mut();
            state.requests.push(*request);
            match state
                .outcomes
                .pop_front()
                .ok_or(ChildAuthorityRefusalV1::Unavailable)?
            {
                ObservationModeV1::Final(evidence) => Ok(ChildObservationOutcomeV1::Final {
                    evidence_digest: digest(evidence),
                }),
                ObservationModeV1::Invalidate(evidence) => {
                    Ok(ChildObservationOutcomeV1::FinalityInvalidated {
                        prior_finality_evidence_digest: request
                            .prior_finality_evidence_digest
                            .ok_or(ChildAuthorityRefusalV1::Conflict)?,
                        reorg_evidence_digest: digest(evidence),
                    })
                }
            }
        }
    }

    /// Test analogue of the production router: one owned value serves
    /// dispatch, reconciliation and observation for both settlement legs.
    /// There is no clone or `RefCell` around the port itself.
    struct TestCombinedChildPortV1 {
        authority: TestChildAuthorityV1,
        observer: TestObserverV1,
    }

    impl SettlementChildAuthorityV1 for TestCombinedChildPortV1 {
        fn externalize_child(
            &mut self,
            request: &ChildDispatchRequestV1,
        ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
            self.authority.externalize_child(request)
        }

        fn reconcile_child(
            &mut self,
            request: &ChildReconciliationRequestV1,
        ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
            self.authority.reconcile_child(request)
        }
    }

    impl SettlementChildObserverV1 for TestCombinedChildPortV1 {
        fn observe_child(
            &mut self,
            request: &ChildObservationRequestV1,
        ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
            self.observer.observe_child(request)
        }
    }

    struct RefusingRunnerV1;

    impl RunnerActionAuthority for RefusingRunnerV1 {
        fn externalize_runner_action(
            &mut self,
            _request: RunnerActionRequestV1<'_>,
        ) -> Result<ActionExternalizationReceiptV1, AuthorityRefusalV1> {
            Err(AuthorityRefusalV1::Refused)
        }
    }

    struct TestRouteV1 {
        _root: TempDir,
        route_path: PathBuf,
        coordinator_path: PathBuf,
        clock: ManualClockV1,
        supervisor: RouteSupervisorV1<ManualClockV1>,
    }

    fn supervisor_config() -> RouteSupervisorConfigV1 {
        RouteSupervisorConfigV1::new(1_000, 200, 100, 1).expect("supervisor config")
    }

    fn raw_apply(
        store: &mut DurableRouteStoreV1,
        lease: RouteLeaseV1,
        revision: &mut u64,
        now: &mut u64,
        event: RouteEventV1,
        next_event: &mut u8,
    ) {
        *now += 1;
        let outcome = store
            .apply_event(lease, *revision, digest(*next_event), &event, *now)
            .expect("seed route event");
        *next_event = next_event.checked_add(1).expect("fixture event range");
        match outcome {
            CommitOutcomeV1::Committed {
                revision: committed,
                ..
            } => *revision = committed,
            CommitOutcomeV1::DuplicateSameBytes { .. } => panic!("unexpected seed duplicate"),
        }
    }

    fn seed_funding(
        store: &mut DurableRouteStoreV1,
        lease: RouteLeaseV1,
        revision: &mut u64,
        now: &mut u64,
        next_event: &mut u8,
        leg: LegIdV1,
        value: u8,
    ) {
        let payload = vec![value; 16];
        raw_apply(
            store,
            lease,
            revision,
            now,
            RouteEventV1::CommitAction(ActionIntentV1 {
                leg,
                kind: ActionKindV1::Funding,
                semantic_digest: digest(value),
                contains_route_secret: false,
                dispatch: EffectDispatchV1::RunnerPayload {
                    payload_digest: digest_bytes_v1(&payload),
                    payload,
                },
            }),
            next_event,
        );
        let snapshot = store.load_snapshot(ROUTE_ID).expect("funding snapshot");
        let effect_id = snapshot
            .leg(leg)
            .funding
            .effect()
            .expect("funding effect")
            .effect_id;
        let transaction_id = digest(value.wrapping_add(1));
        raw_apply(
            store,
            lease,
            revision,
            now,
            RouteEventV1::ActionExternalized {
                leg,
                kind: ActionKindV1::Funding,
                effect_id,
                transaction_id,
                exposure: None,
            },
            next_event,
        );
        raw_apply(
            store,
            lease,
            revision,
            now,
            RouteEventV1::ActionFinalized {
                leg,
                kind: ActionKindV1::Funding,
                transaction_id,
                evidence_digest: digest(value.wrapping_add(2)),
            },
            next_event,
        );
    }

    fn seeded_route(funded: bool) -> TestRouteV1 {
        let root = tempfile::tempdir().expect("route tempdir");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only test root");
        let canonical = fs::canonicalize(root.path()).expect("canonical test root");
        let route_path = canonical.join("route.sqlite3");
        let coordinator_path = canonical.join("coordinator.sqlite3");
        let mut store = DurableRouteStoreV1::create(&route_path).expect("create route store");
        store.create_route(ROUTE_ID, 1_000).expect("create route");
        let lease = store
            .acquire_lease(ROUTE_ID, ROUTE_OWNER_A, 1_001, 1_000)
            .expect("seed lease")
            .lease();
        let mut revision = 0;
        let mut now = 1_001;
        let mut next_event = 11;
        raw_apply(
            &mut store,
            lease,
            &mut revision,
            &mut now,
            RouteEventV1::FreezeTerms(FrozenBindingsV1 {
                terms_digest: TERMS_DIGEST,
                profile_bundle_digest: PROFILE_BUNDLE_DIGEST,
                deployment_bundle_digest: DEPLOYMENT_BUNDLE_DIGEST,
            }),
            &mut next_event,
        );
        raw_apply(
            &mut store,
            lease,
            &mut revision,
            &mut now,
            RouteEventV1::ArmRefunds(RefundBindingsV1 {
                upstream_refund_digest: digest(12),
                downstream_refund_digest: digest(13),
            }),
            &mut next_event,
        );
        if funded {
            seed_funding(
                &mut store,
                lease,
                &mut revision,
                &mut now,
                &mut next_event,
                LegIdV1::Upstream,
                14,
            );
            seed_funding(
                &mut store,
                lease,
                &mut revision,
                &mut now,
                &mut next_event,
                LegIdV1::Downstream,
                18,
            );
        }
        drop(store);
        let clock = ManualClockV1::new(TEST_NOW).expect("manual clock");
        let supervisor = RouteSupervisorV1::acquire(
            DurableRouteStoreV1::open_existing(&route_path).expect("reopen route"),
            ROUTE_ID,
            ROUTE_OWNER_A,
            supervisor_config(),
            clock.clone(),
        )
        .expect("supervisor");
        TestRouteV1 {
            _root: root,
            route_path,
            coordinator_path,
            clock,
            supervisor,
        }
    }

    fn create_coordinator(path: &Path) -> DurableSettlementCoordinatorV1 {
        DurableSettlementCoordinatorV1::create(path, COORDINATOR_ID, PLAN_AUTHORITY_ID, 1_000)
            .expect("create coordinator")
    }

    fn open_coordinator(path: &Path) -> DurableSettlementCoordinatorV1 {
        DurableSettlementCoordinatorV1::open_existing(path, COORDINATOR_ID, PLAN_AUTHORITY_ID)
            .expect("open coordinator")
    }

    fn preinstall_upstream_funding(
        route: &TestRouteV1,
        event_id: EventIdV1,
        persistence_log: Rc<RefCell<PersistenceLogV1>>,
    ) -> (DurableSettlementCoordinatorV1, Digest32, u64) {
        let snapshot = route.supervisor.snapshot().expect("armed snapshot");
        assert_eq!(
            snapshot.upstream.funding.progress(),
            ActionProgressV1::NotPrepared
        );
        let route_fence = route.supervisor.lease_status().fencing_epoch();
        let plan = test_plan(
            ROUTE_ID,
            event_id,
            route_fence,
            LegIdV1::Upstream,
            ActionKindV1::Funding,
            &snapshot.secret_visibility,
            snapshot.bindings.as_ref().expect("frozen bindings"),
        );
        let effect_id = plan.bindings().effect_id;
        let mut coordinator = create_coordinator(&route.coordinator_path);
        TestPlanPersistenceV1 {
            log: persistence_log,
        }
        .install_new_plan(&mut coordinator, plan, event_id, TEST_NOW)
        .expect("simulate crash after coordinator install");
        (coordinator, effect_id, route_fence)
    }

    fn reopen_route_after_takeover(
        route_path: &Path,
        clock: &ManualClockV1,
    ) -> RouteSupervisorV1<ManualClockV1> {
        RouteSupervisorV1::acquire(
            DurableRouteStoreV1::open_existing(route_path).expect("reopen route"),
            ROUTE_ID,
            ROUTE_OWNER_B,
            supervisor_config(),
            clock.clone(),
        )
        .expect("takeover supervisor")
    }

    fn assemble_test_bridge(
        coordinator: DurableSettlementCoordinatorV1,
        owner: Digest32,
        clock: &ManualClockV1,
        persistence_log: Rc<RefCell<PersistenceLogV1>>,
        child_state: Rc<RefCell<ChildStateV1>>,
        observer_state: Rc<RefCell<ObserverStateV1>>,
    ) -> ProductionSettlementAuthoritiesV1 {
        assemble_production_settlement_authorities_with_child_port_and_clock_v1(
            coordinator,
            ProductionSettlementBridgeConfigV1::new(owner, 500).expect("bridge config"),
            TestPlanSourceV1::default(),
            TestPlanPersistenceV1 {
                log: persistence_log,
            },
            TestCombinedChildPortV1 {
                authority: TestChildAuthorityV1(child_state),
                observer: TestObserverV1(observer_state),
            },
            TestSettlementClockV1(clock.clone()),
        )
    }

    fn committed_effect(
        supervisor: &RouteSupervisorV1<ManualClockV1>,
        leg: LegIdV1,
        action: ActionKindV1,
    ) -> (Digest32, Digest32) {
        let snapshot = supervisor.snapshot().expect("route snapshot");
        let reference = match snapshot.leg(leg).action(action) {
            ActionStateV1::Committed(reference) => reference,
            other => panic!("expected committed action, got {other:?}"),
        };
        (
            reference.effect_id,
            reference
                .expected_transaction_id
                .expect("aggregate transaction id"),
        )
    }

    fn drive_child_without_route_ack(
        authorities: &ProductionSettlementAuthoritiesV1,
        effect_id: Digest32,
        now: u64,
    ) -> (CoordinatorDriveOutcomeV1, CoordinatorLeaseV1) {
        let mut core = authorities
            .custody
            .0
            .try_borrow_mut()
            .expect("exclusive bridge core");
        let stored = core
            .coordinator
            .load_plan_for_effect(effect_id)
            .expect("stored plan");
        let owner = core.config.owner_id;
        let duration = core.config.coordinator_lease_duration_ms;
        let fence = stored.view().fencing_epoch;
        let lease = core
            .coordinator
            .acquire_lease(stored.view().plan_id, owner, fence, now, duration)
            .expect("coordinator lease")
            .lease();
        let core = &mut *core;
        let outcome = core
            .coordinator
            .drive_one(lease, &mut core.child_port, now)
            .expect("direct child drive");
        (outcome, lease)
    }

    fn reconcile_child_without_route_ack(
        authorities: &ProductionSettlementAuthoritiesV1,
        lease: CoordinatorLeaseV1,
        now: u64,
    ) -> CoordinatorDriveOutcomeV1 {
        let mut core = authorities
            .custody
            .0
            .try_borrow_mut()
            .expect("exclusive bridge core");
        let core = &mut *core;
        core.coordinator
            .reconcile_current_child_one(lease, &mut core.child_port, now)
            .expect("direct child reconciliation")
    }

    fn record_finality_until_route_commit(
        supervisor: &mut RouteSupervisorV1<ManualClockV1>,
        observer: &mut ProductionSettlementObservationAuthorityV1,
        event_id: EventIdV1,
        leg: LegIdV1,
        action: ActionKindV1,
        aggregate_action_id: Digest32,
    ) {
        let first = supervisor.record_chain_observation(
            event_id,
            ChainObservationQueryV1::Finality {
                leg,
                action,
                transaction_id: aggregate_action_id,
            },
            observer,
        );
        assert!(matches!(
            first,
            Err(RouteSupervisorErrorV1::ChainObservationAuthority(
                AuthorityRefusalV1::Unavailable
            ))
        ));
        supervisor
            .record_chain_observation(
                event_id,
                ChainObservationQueryV1::Finality {
                    leg,
                    action,
                    transaction_id: aggregate_action_id,
                },
                observer,
            )
            .expect("aggregate finality route commit");
    }

    #[test]
    fn first_exposure_cannot_reach_public_journal_until_seal_succeeds_and_replay_reseals() {
        let retry_after_dispatch_lease = supervisor_config()
            .dispatch_lease_ms()
            .checked_add(1)
            .expect("test dispatch lease retry time");
        let mut route = seeded_route(true);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [DispatchModeV1::Externalized(39)].into(),
            ..ChildStateV1::default()
        }));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let seal_calls = Rc::new(RefCell::new(Vec::new()));
        let mut authorities = assemble_production_settlement_authorities_with_clock_v1(
            ProductionSettlementBridgePartsV1 {
                coordinator: create_coordinator(&route.coordinator_path),
                config: ProductionSettlementBridgeConfigV1::new(COORDINATOR_OWNER_A, 500)
                    .expect("bridge config"),
                plan_source: RefusingSealPlanSourceV1 {
                    seal_calls: Rc::clone(&seal_calls),
                },
                plan_persistence: TestPlanPersistenceV1 {
                    log: persistence_log,
                },
                child_authority: TestChildAuthorityV1(Rc::clone(&child_state)),
                child_observer: TestObserverV1(observer_state),
                clock: TestSettlementClockV1(route.clock.clone()),
            },
        );
        route
            .supervisor
            .authorize_action(
                digest(99),
                LegIdV1::Downstream,
                ActionKindV1::Claim,
                &mut authorities.action,
            )
            .expect("authorize first-exposure claim");

        for expected_seal_calls in 1..=2 {
            let dispatch = route
                .supervisor
                .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody);
            assert!(
                matches!(
                    &dispatch,
                    Err(RouteSupervisorErrorV1::ExternalCustodyAuthority(
                        AuthorityRefusalV1::Unavailable
                    ))
                ),
                "unexpected dispatch result: {dispatch:?}"
            );
            assert_eq!(seal_calls.borrow().len(), expected_seal_calls);
            assert_eq!(
                child_state.borrow().calls.len(),
                1,
                "replay cannot run child 2"
            );
            assert!(matches!(
                route
                    .supervisor
                    .snapshot()
                    .expect("route snapshot")
                    .secret_visibility,
                SecretVisibilityV1::Private
            ));
            if expected_seal_calls == 1 {
                route
                    .clock
                    .set(TEST_NOW + retry_after_dispatch_lease)
                    .expect("expire failed custody dispatch lease for replay");
            }
        }
        assert_eq!(seal_calls.borrow()[0], seal_calls.borrow()[1]);
    }

    #[test]
    fn deferred_counterparty_claim_materializes_only_on_public_tick_and_dispatches_later() {
        let mut route = seeded_route(true);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [
                DispatchModeV1::Externalized(39),
                DispatchModeV1::Externalized(40),
            ]
            .into(),
            ..ChildStateV1::default()
        }));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let materialization_calls = Rc::new(Cell::new(0));
        let mut authorities = assemble_production_settlement_authorities_with_clock_v1(
            ProductionSettlementBridgePartsV1 {
                coordinator: create_coordinator(&route.coordinator_path),
                config: ProductionSettlementBridgeConfigV1::new(COORDINATOR_OWNER_A, 500)
                    .expect("bridge config"),
                plan_source: TestPlanSourceV1 {
                    materialization_calls: Rc::clone(&materialization_calls),
                    ..TestPlanSourceV1::default()
                },
                plan_persistence: TestPlanPersistenceV1 {
                    log: persistence_log,
                },
                child_authority: TestChildAuthorityV1(Rc::clone(&child_state)),
                child_observer: TestObserverV1(observer_state),
                clock: TestSettlementClockV1(route.clock.clone()),
            },
        );
        route
            .supervisor
            .authorize_action(
                digest(0xa1),
                LegIdV1::Downstream,
                ActionKindV1::Claim,
                &mut authorities.action,
            )
            .expect("authorize staged downstream claim");
        let (effect_id, _) =
            committed_effect(&route.supervisor, LegIdV1::Downstream, ActionKindV1::Claim);

        let first = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("externalize only DOM first exposure");
        assert_eq!(first.custody_partial_progress, 1);
        assert_eq!(materialization_calls.get(), 0);
        assert_eq!(child_state.borrow().calls.len(), 1);
        assert!(matches!(
            route
                .supervisor
                .snapshot()
                .expect("public route snapshot")
                .secret_visibility,
            SecretVisibilityV1::Public { .. }
        ));
        {
            let core = authorities
                .custody
                .0
                .try_borrow()
                .expect("read bridge after first tick");
            let staged = core
                .coordinator
                .load_plan_for_effect(effect_id)
                .expect("load staged plan");
            assert_eq!(staged.view().children[1].stage, ChildStageV1::Deferred);
            assert!(staged.view().children[1].transaction_id.is_none());
        }

        let second = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("materialize after exact Public acknowledgement");
        assert_eq!(second.custody_partial_progress, 1);
        assert_eq!(second.custody_progress_unchanged, 0);
        assert_eq!(materialization_calls.get(), 1);
        assert_eq!(
            child_state.borrow().calls.len(),
            1,
            "materialization tick must not broadcast child 1"
        );
        {
            let core = authorities
                .custody
                .0
                .try_borrow()
                .expect("read bridge after materialization tick");
            let materialized = core
                .coordinator
                .load_plan_for_effect(effect_id)
                .expect("load materialized child");
            assert_eq!(materialized.view().children[1].stage, ChildStageV1::Planned);
            assert!(materialized.view().children[1].transaction_id.is_some());
            assert_eq!(materialized.view().children[1].call_attempts, 0);
        }

        let third = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("dispatch retained counterparty child on later tick");
        assert_eq!(materialization_calls.get(), 1);
        assert_eq!(
            child_state.borrow().calls.len(),
            2,
            "third tick report: {third:?}"
        );
        let core = authorities
            .custody
            .0
            .try_borrow()
            .expect("read completed bridge");
        let completed = core
            .coordinator
            .load_plan_for_effect(effect_id)
            .expect("load completed aggregate");
        assert_eq!(completed.view().stage, AggregateStageV1::Externalized);
    }

    #[test]
    fn staged_first_child_retries_only_after_proven_pre_externalization_failure() {
        let mut route = seeded_route(true);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [
                DispatchModeV1::RetryableBeforeExternalization(38),
                DispatchModeV1::Externalized(39),
                DispatchModeV1::Externalized(40),
            ]
            .into(),
            ..ChildStateV1::default()
        }));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let materialization_calls = Rc::new(Cell::new(0));
        let mut authorities = assemble_production_settlement_authorities_with_clock_v1(
            ProductionSettlementBridgePartsV1 {
                coordinator: create_coordinator(&route.coordinator_path),
                config: ProductionSettlementBridgeConfigV1::new(COORDINATOR_OWNER_A, 500)
                    .expect("bridge config"),
                plan_source: TestPlanSourceV1 {
                    materialization_calls: Rc::clone(&materialization_calls),
                    ..TestPlanSourceV1::default()
                },
                plan_persistence: TestPlanPersistenceV1 {
                    log: persistence_log,
                },
                child_authority: TestChildAuthorityV1(Rc::clone(&child_state)),
                child_observer: TestObserverV1(observer_state),
                clock: TestSettlementClockV1(route.clock.clone()),
            },
        );
        route
            .supervisor
            .authorize_action(
                digest(0xa3),
                LegIdV1::Downstream,
                ActionKindV1::Claim,
                &mut authorities.action,
            )
            .expect("authorize staged downstream claim");
        let (effect_id, _) =
            committed_effect(&route.supervisor, LegIdV1::Downstream, ActionKindV1::Claim);

        let retryable = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("record proof of no first-child externalization");
        assert_eq!(retryable.custody_unknown, 1);
        assert_eq!(materialization_calls.get(), 0);
        assert_eq!(child_state.borrow().calls.len(), 1);
        assert!(matches!(
            route
                .supervisor
                .snapshot()
                .expect("private route after retryable outcome")
                .secret_visibility,
            SecretVisibilityV1::Private
        ));
        {
            let core = authorities
                .custody
                .0
                .try_borrow()
                .expect("read retryable staged plan");
            let retryable_plan = core
                .coordinator
                .load_plan_for_effect(effect_id)
                .expect("audit retryable staged plan");
            assert_eq!(retryable_plan.view().completed_prefix, 0);
            assert_eq!(
                retryable_plan.view().children[0].stage,
                ChildStageV1::Planned
            );
            assert_eq!(retryable_plan.view().children[0].call_attempts, 1);
            assert!(retryable_plan.view().children[0]
                .externalization_evidence_digest
                .is_none());
            assert_eq!(
                retryable_plan.view().children[1].stage,
                ChildStageV1::Deferred
            );
        }

        route
            .clock
            .set(TEST_NOW + supervisor_config().dispatch_lease_ms() + 1)
            .expect("expire first route dispatch lease");
        let exposed = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("retry first child after audited no-externalization proof");
        assert_eq!(exposed.custody_partial_progress, 1);
        assert_eq!(materialization_calls.get(), 0);
        assert_eq!(child_state.borrow().calls.len(), 2);
        assert!(matches!(
            route
                .supervisor
                .snapshot()
                .expect("public route after exact retry")
                .secret_visibility,
            SecretVisibilityV1::Public { .. }
        ));

        let materialized = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("materialize only after retried exposure is Public");
        assert_eq!(materialized.custody_partial_progress, 1);
        assert_eq!(materialization_calls.get(), 1);
        assert_eq!(child_state.borrow().calls.len(), 2);

        let completed = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("dispatch retained child only on later tick");
        assert_eq!(completed.custody_externalized, 1);
        assert_eq!(materialization_calls.get(), 1);
        assert_eq!(child_state.borrow().calls.len(), 3);
    }

    #[test]
    fn deferred_materialization_crossing_route_capability_expiry_stays_pending_and_retries_exactly()
    {
        let mut route = seeded_route(true);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [
                DispatchModeV1::Externalized(39),
                DispatchModeV1::Externalized(40),
            ]
            .into(),
            ..ChildStateV1::default()
        }));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let materialization_calls = Rc::new(Cell::new(0));
        let materialization_attempts = Rc::new(RefCell::new(Vec::new()));
        let advance_materialization_to = Rc::new(Cell::new(Some(
            TEST_NOW + supervisor_config().dispatch_lease_ms() + 1,
        )));
        let mut authorities = assemble_production_settlement_authorities_with_clock_v1(
            ProductionSettlementBridgePartsV1 {
                coordinator: create_coordinator(&route.coordinator_path),
                config: ProductionSettlementBridgeConfigV1::new(COORDINATOR_OWNER_A, 500)
                    .expect("bridge config"),
                plan_source: TestPlanSourceV1 {
                    materialization_calls: Rc::clone(&materialization_calls),
                    materialization_attempts: Rc::clone(&materialization_attempts),
                    materialization_clock: Some(route.clock.clone()),
                    advance_materialization_to: Rc::clone(&advance_materialization_to),
                },
                plan_persistence: TestPlanPersistenceV1 {
                    log: persistence_log,
                },
                child_authority: TestChildAuthorityV1(Rc::clone(&child_state)),
                child_observer: TestObserverV1(observer_state),
                clock: TestSettlementClockV1(route.clock.clone()),
            },
        );
        route
            .supervisor
            .authorize_action(
                digest(0xa2),
                LegIdV1::Downstream,
                ActionKindV1::Claim,
                &mut authorities.action,
            )
            .expect("authorize staged downstream claim");
        let (effect_id, _) =
            committed_effect(&route.supervisor, LegIdV1::Downstream, ActionKindV1::Claim);

        let first = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("externalize first exposure");
        assert_eq!(first.custody_partial_progress, 1);
        let route_before_expired_materialization = route
            .supervisor
            .snapshot()
            .expect("snapshot before expired materialization");
        let revision_before_pending = {
            let core = authorities
                .custody
                .0
                .try_borrow()
                .expect("read staged bridge");
            core.coordinator
                .load_plan_for_effect(effect_id)
                .expect("load exposed staged plan")
                .view()
                .revision
        };

        let expired = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect_err("expired route capability must not commit materialization");
        assert!(matches!(
            expired,
            RouteSupervisorErrorV1::ExternalCustodyAuthority(AuthorityRefusalV1::Refused)
        ));
        let route_after_expired_materialization = route
            .supervisor
            .snapshot()
            .expect("snapshot after expired materialization");
        assert_eq!(
            route_after_expired_materialization.revision,
            route_before_expired_materialization.revision
        );
        assert_eq!(
            route_after_expired_materialization.secret_visibility,
            route_before_expired_materialization.secret_visibility
        );
        assert_eq!(materialization_calls.get(), 1);
        assert_eq!(child_state.borrow().calls.len(), 1);
        let pending_revision = {
            let core = authorities
                .custody
                .0
                .try_borrow()
                .expect("read pending materialization");
            let pending = core
                .coordinator
                .load_plan_for_effect(effect_id)
                .expect("audit pending materialization");
            assert_eq!(pending.view().children[1].stage, ChildStageV1::Deferred);
            assert!(pending.view().children[1].transaction_id.is_none());
            assert_eq!(pending.view().children[1].call_attempts, 0);
            pending.view().revision
        };
        assert!(pending_revision > revision_before_pending);
        assert!(advance_materialization_to.get().is_none());

        let pending_acknowledgement = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("acknowledge the durable pending-materialization digest");
        assert_eq!(pending_acknowledgement.custody_partial_progress, 1);
        assert_eq!(materialization_calls.get(), 1);
        assert_eq!(materialization_attempts.borrow().len(), 1);
        assert_eq!(child_state.borrow().calls.len(), 1);

        let retried = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("retry exact pending materialization under fresh route capability");
        assert_eq!(retried.custody_partial_progress, 1);
        assert_eq!(materialization_calls.get(), 2);
        let attempts = materialization_attempts.borrow();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0], attempts[1]);
        drop(attempts);
        assert_eq!(child_state.borrow().calls.len(), 1);
        {
            let core = authorities
                .custody
                .0
                .try_borrow()
                .expect("read completed materialization");
            let materialized = core
                .coordinator
                .load_plan_for_effect(effect_id)
                .expect("load completed materialization");
            assert_eq!(materialized.view().children[1].stage, ChildStageV1::Planned);
            assert_eq!(materialized.view().children[1].call_attempts, 0);
        }

        let dispatched = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("dispatch materialized child on later tick");
        assert_eq!(dispatched.custody_externalized, 1);
        assert_eq!(child_state.borrow().calls.len(), 2);
        let core = authorities
            .custody
            .0
            .try_borrow()
            .expect("read completed aggregate");
        let completed = core
            .coordinator
            .load_plan_for_effect(effect_id)
            .expect("load completed aggregate");
        assert_eq!(completed.view().stage, AggregateStageV1::Externalized);
    }

    #[test]
    fn unified_child_port_drives_two_legs_reconcile_restart_observe_and_reorg() {
        let mut route = seeded_route(true);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [
                DispatchModeV1::Unknown(39),
                DispatchModeV1::Externalized(41),
                DispatchModeV1::Externalized(42),
                DispatchModeV1::Externalized(43),
            ]
            .into(),
            reconcile: [ReconcileModeV1::Externalized(40)].into(),
            ..ChildStateV1::default()
        }));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let coordinator = create_coordinator(&route.coordinator_path);
        let mut authorities = assemble_test_bridge(
            coordinator,
            COORDINATOR_OWNER_A,
            &route.clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            Rc::clone(&observer_state),
        );

        route
            .supervisor
            .authorize_action(
                digest(100),
                LegIdV1::Downstream,
                ActionKindV1::Claim,
                &mut authorities.action,
            )
            .expect("authorize downstream claim");
        let (downstream_effect, downstream_aggregate) =
            committed_effect(&route.supervisor, LegIdV1::Downstream, ActionKindV1::Claim);

        let (ambiguous, coordinator_lease) = drive_child_without_route_ack(
            &authorities,
            downstream_effect,
            route.clock.now_unix_ms().expect("clock"),
        );
        assert!(matches!(
            ambiguous,
            CoordinatorDriveOutcomeV1::Unknown { .. }
        ));
        let lost = reconcile_child_without_route_ack(
            &authorities,
            coordinator_lease,
            route.clock.now_unix_ms().expect("clock"),
        );
        let lost_progress = match lost {
            CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress,
            other => panic!("expected lost partial receipt, got {other:?}"),
        };
        let lost_exposure = lost_progress.exposure.expect("lost child exposure");
        assert_eq!(lost_exposure.observed_at_unix_ms, TEST_NOW);
        assert_eq!(child_state.borrow().calls.len(), 1);
        assert_eq!(child_state.borrow().reconciliations.len(), 1);

        route.clock.set(TEST_NOW + 1).expect("advance replay clock");
        let report = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("replay lost secret prefix");
        assert_eq!(report.custody_partial_progress, 1);
        assert_eq!(child_state.borrow().calls.len(), 1, "must not run child 2");
        let first_exposure = match route
            .supervisor
            .snapshot()
            .expect("partial snapshot")
            .secret_visibility
        {
            SecretVisibilityV1::Public { first_exposure } => first_exposure,
            SecretVisibilityV1::Private => panic!("secret exposure was not journaled"),
        };
        assert_eq!(first_exposure.chain_id, lost_exposure.chain_id);
        assert_eq!(first_exposure.transaction_id, lost_exposure.transaction_id);
        assert_eq!(
            first_exposure.evidence_digest,
            lost_exposure.evidence_digest
        );
        assert_eq!(
            first_exposure.observed_at_unix_ms,
            lost_exposure.observed_at_unix_ms
        );
        assert_ne!(first_exposure.transaction_id, downstream_aggregate);

        route
            .supervisor
            .authorize_action(
                digest(101),
                LegIdV1::Upstream,
                ActionKindV1::Claim,
                &mut authorities.action,
            )
            .expect("authorize urgent upstream claim");
        let (_, upstream_aggregate) =
            committed_effect(&route.supervisor, LegIdV1::Upstream, ActionKindV1::Claim);
        let first_upstream = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("upstream first child");
        assert_eq!(first_upstream.custody_partial_progress, 1);
        let second_upstream = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("upstream aggregate");
        assert_eq!(second_upstream.urgent_externalized, 1);

        observer_state
            .borrow_mut()
            .outcomes
            .extend([ObservationModeV1::Final(110), ObservationModeV1::Final(111)]);
        record_finality_until_route_commit(
            &mut route.supervisor,
            &mut authorities.observer,
            digest(102),
            LegIdV1::Upstream,
            ActionKindV1::Claim,
            upstream_aggregate,
        );

        let downstream_materialized = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("materialize downstream child after upstream finality");
        assert_eq!(downstream_materialized.custody_partial_progress, 1);
        assert_eq!(child_state.borrow().calls.len(), 3);
        let downstream_finish = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("downstream aggregate on later tick");
        assert_eq!(downstream_finish.custody_externalized, 1);
        assert_eq!(
            child_state.borrow().calls,
            [
                (SettlementLegV1::Downstream, SettlementActionV1::Claim, 0),
                (SettlementLegV1::Upstream, SettlementActionV1::Claim, 0),
                (SettlementLegV1::Upstream, SettlementActionV1::Claim, 1),
                (SettlementLegV1::Downstream, SettlementActionV1::Claim, 1),
            ]
        );

        drop(authorities);
        observer_state
            .borrow_mut()
            .outcomes
            .extend([ObservationModeV1::Final(112), ObservationModeV1::Final(113)]);
        let mut reopened = assemble_test_bridge(
            open_coordinator(&route.coordinator_path),
            COORDINATOR_OWNER_A,
            &route.clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            Rc::clone(&observer_state),
        );
        record_finality_until_route_commit(
            &mut route.supervisor,
            &mut reopened.observer,
            digest(103),
            LegIdV1::Downstream,
            ActionKindV1::Claim,
            downstream_aggregate,
        );
        assert_eq!(
            route
                .supervisor
                .snapshot()
                .expect("terminal snapshot")
                .downstream
                .claim
                .progress(),
            ActionProgressV1::Final
        );

        observer_state
            .borrow_mut()
            .outcomes
            .push_back(ObservationModeV1::Invalidate(114));
        route
            .supervisor
            .record_chain_observation(
                digest(104),
                ChainObservationQueryV1::Invalidation {
                    leg: LegIdV1::Downstream,
                    action: ActionKindV1::Claim,
                    transaction_id: downstream_aggregate,
                },
                &mut reopened.observer,
            )
            .expect("aggregate reorg");
        assert_eq!(
            route
                .supervisor
                .snapshot()
                .expect("reorg snapshot")
                .downstream
                .claim
                .progress(),
            ActionProgressV1::Externalized
        );
        observer_state
            .borrow_mut()
            .outcomes
            .push_back(ObservationModeV1::Final(115));
        route
            .supervisor
            .record_chain_observation(
                digest(105),
                ChainObservationQueryV1::Finality {
                    leg: LegIdV1::Downstream,
                    action: ActionKindV1::Claim,
                    transaction_id: downstream_aggregate,
                },
                &mut reopened.observer,
            )
            .expect("aggregate re-finality");
        assert_eq!(
            route
                .supervisor
                .snapshot()
                .expect("re-final snapshot")
                .downstream
                .claim
                .progress(),
            ActionProgressV1::Final
        );
    }

    #[test]
    fn same_fence_unknown_reconciliation_externalizes_once_and_surfaces_secret_urgently() {
        let retry_after_dispatch_lease = supervisor_config()
            .dispatch_lease_ms()
            .checked_add(1)
            .expect("test dispatch lease retry time");
        let mut route = seeded_route(true);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [DispatchModeV1::Unknown(44)].into(),
            reconcile: [
                ReconcileModeV1::Unknown(45),
                ReconcileModeV1::Externalized(46),
            ]
            .into(),
            ..ChildStateV1::default()
        }));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let mut authorities = assemble_test_bridge(
            create_coordinator(&route.coordinator_path),
            COORDINATOR_OWNER_A,
            &route.clock,
            persistence_log,
            Rc::clone(&child_state),
            observer_state,
        );

        route
            .supervisor
            .authorize_action(
                digest(106),
                LegIdV1::Downstream,
                ActionKindV1::Claim,
                &mut authorities.action,
            )
            .expect("authorize downstream claim");

        let original = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("original ambiguity");
        assert_eq!(original.custody_unknown, 1);
        route
            .clock
            .set(TEST_NOW + retry_after_dispatch_lease)
            .expect("expire first unknown dispatch lease");
        let still_unknown = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("first reconciliation ambiguity");
        assert_eq!(still_unknown.custody_unknown, 1);
        route
            .clock
            .set(TEST_NOW + (2 * retry_after_dispatch_lease))
            .expect("expire second unknown dispatch lease");
        let resolved = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("second reconciliation externalization");
        assert_eq!(resolved.custody_partial_progress, 1);

        let state = child_state.borrow();
        assert_eq!(state.calls.len(), 1, "original child must never replay");
        assert_eq!(state.reconciliations.len(), 2);
        assert_ne!(state.reconciliations[0], state.reconciliations[1]);
        assert_eq!(state.calls[0].2, 0, "child two must remain blocked");
        drop(state);

        let first_exposure = match route
            .supervisor
            .snapshot()
            .expect("resolved route snapshot")
            .secret_visibility
        {
            SecretVisibilityV1::Public { first_exposure } => first_exposure,
            SecretVisibilityV1::Private => panic!("resolved exposure was not surfaced urgently"),
        };
        assert_eq!(
            first_exposure.observed_at_unix_ms,
            TEST_NOW + (2 * retry_after_dispatch_lease)
        );
    }

    #[test]
    fn nonsecret_partial_takeover_refences_exact_pair_and_rejects_stale_lease() {
        let mut route = seeded_route(false);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [
                DispatchModeV1::Externalized(50),
                DispatchModeV1::Externalized(51),
            ]
            .into(),
            ..ChildStateV1::default()
        }));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let mut authorities = assemble_test_bridge(
            create_coordinator(&route.coordinator_path),
            COORDINATOR_OWNER_A,
            &route.clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            Rc::clone(&observer_state),
        );
        route
            .supervisor
            .authorize_action(
                digest(120),
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .expect("authorize funding");
        let (old_effect, aggregate_action) =
            committed_effect(&route.supervisor, LegIdV1::Upstream, ActionKindV1::Funding);
        let (lost, old_coordinator_lease) =
            drive_child_without_route_ack(&authorities, old_effect, TEST_NOW);
        let partial = match lost {
            CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress,
            other => panic!("expected nonsecret prefix, got {other:?}"),
        };
        assert!(partial.exposure.is_none());
        {
            let core = authorities.custody.0.try_borrow().expect("bridge read");
            assert_eq!(
                core.coordinator
                    .load_plan_for_aggregate(aggregate_action, digest(222))
                    .unwrap_err(),
                CoordinatorErrorV1::IdempotencyConflict
            );
            assert_eq!(
                core.coordinator
                    .load_plan_for_aggregate(aggregate_action, partial.aggregate_custody_digest)
                    .expect("exact aggregate pair")
                    .view()
                    .effect_id,
                old_effect
            );
        }

        let route_path = route.route_path.clone();
        let coordinator_path = route.coordinator_path.clone();
        let clock = route.clock.clone();
        drop(authorities);
        drop(route.supervisor);
        clock.set(TAKEOVER_NOW).expect("advance takeover clock");
        let mut supervisor = RouteSupervisorV1::acquire(
            DurableRouteStoreV1::open_existing(&route_path).expect("reopen route"),
            ROUTE_ID,
            ROUTE_OWNER_B,
            supervisor_config(),
            clock.clone(),
        )
        .expect("takeover supervisor");
        let mut reopened = assemble_test_bridge(
            open_coordinator(&coordinator_path),
            COORDINATOR_OWNER_B,
            &clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            observer_state,
        );
        let report = supervisor
            .reconcile_takeover(&mut reopened.takeover)
            .expect("safe partial takeover");
        assert_eq!(report.partial_custody_resumed, 1);
        assert!(matches!(
            supervisor
                .snapshot()
                .expect("takeover snapshot")
                .secret_visibility,
            SecretVisibilityV1::Private
        ));

        let finish = supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut reopened.custody)
            .expect("late refence progress acknowledgement");
        assert_eq!(
            finish.custody_partial_progress,
            1,
            "unexpected dispatch report: {finish:?}; calls={:?}",
            child_state.borrow().calls
        );
        assert_eq!(child_state.borrow().calls.len(), 1);
        let finish = supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut reopened.custody)
            .expect("second child after progress acknowledgement");
        assert_eq!(finish.custody_externalized, 1);
        assert_eq!(persistence_log.borrow().refences, 1);
        assert_eq!(child_state.borrow().calls.len(), 2);
        let mut core = reopened.custody.0.try_borrow_mut().expect("bridge core");
        assert_eq!(
            core.coordinator
                .current_custody_progress(old_coordinator_lease, TAKEOVER_NOW)
                .unwrap_err(),
            CoordinatorErrorV1::StaleFencing
        );
    }

    #[test]
    fn secret_partial_takeover_journals_exposure_before_refence_and_child_two() {
        let mut route = seeded_route(true);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [
                DispatchModeV1::Externalized(52),
                DispatchModeV1::Externalized(53),
                DispatchModeV1::Externalized(54),
                DispatchModeV1::Externalized(55),
            ]
            .into(),
            ..ChildStateV1::default()
        }));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let mut authorities = assemble_test_bridge(
            create_coordinator(&route.coordinator_path),
            COORDINATOR_OWNER_A,
            &route.clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            Rc::clone(&observer_state),
        );
        route
            .supervisor
            .authorize_action(
                digest(121),
                LegIdV1::Downstream,
                ActionKindV1::Claim,
                &mut authorities.action,
            )
            .expect("authorize downstream claim");
        let (old_effect, downstream_aggregate) =
            committed_effect(&route.supervisor, LegIdV1::Downstream, ActionKindV1::Claim);
        let (lost, _) = drive_child_without_route_ack(&authorities, old_effect, TEST_NOW);
        let child_exposure = match lost {
            CoordinatorDriveOutcomeV1::PartialProgress(progress) => {
                progress.exposure.expect("secret child exposure")
            }
            other => panic!("expected secret prefix, got {other:?}"),
        };

        let route_path = route.route_path.clone();
        let coordinator_path = route.coordinator_path.clone();
        let clock = route.clock.clone();
        drop(authorities);
        drop(route.supervisor);
        clock.set(TAKEOVER_NOW).expect("advance takeover clock");
        let mut supervisor = RouteSupervisorV1::acquire(
            DurableRouteStoreV1::open_existing(&route_path).expect("reopen route"),
            ROUTE_ID,
            ROUTE_OWNER_B,
            supervisor_config(),
            clock.clone(),
        )
        .expect("takeover supervisor");
        let mut reopened = assemble_test_bridge(
            open_coordinator(&coordinator_path),
            COORDINATOR_OWNER_B,
            &clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            Rc::clone(&observer_state),
        );
        let report = supervisor
            .reconcile_takeover(&mut reopened.takeover)
            .expect("secret partial takeover");
        assert_eq!(report.partial_secret_custody_resumed, 1);
        let route_exposure = match supervisor
            .snapshot()
            .expect("takeover snapshot")
            .secret_visibility
        {
            SecretVisibilityV1::Public { first_exposure } => first_exposure,
            SecretVisibilityV1::Private => panic!("takeover did not journal exposure"),
        };
        assert_eq!(route_exposure.transaction_id, child_exposure.transaction_id);
        assert_ne!(route_exposure.transaction_id, downstream_aggregate);

        let blocked = supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut reopened.custody)
            .expect("downstream must wait for urgent upstream claim");
        assert_eq!(blocked.custody_externalized, 0);
        assert_eq!(
            blocked.custody_partial_progress,
            1,
            "unexpected pre-urgent dispatch report: {blocked:?}; calls={:?}",
            child_state.borrow().calls
        );
        assert_eq!(child_state.borrow().calls.len(), 1);

        supervisor
            .authorize_action(
                digest(122),
                LegIdV1::Upstream,
                ActionKindV1::Claim,
                &mut reopened.action,
            )
            .expect("authorize urgent upstream claim");
        let (_, upstream_aggregate) =
            committed_effect(&supervisor, LegIdV1::Upstream, ActionKindV1::Claim);
        assert_eq!(
            supervisor
                .dispatch_one_effect(&mut RefusingRunnerV1, &mut reopened.custody)
                .expect("urgent child one")
                .custody_partial_progress,
            1
        );
        assert_eq!(
            supervisor
                .dispatch_one_effect(&mut RefusingRunnerV1, &mut reopened.custody)
                .expect("urgent aggregate")
                .urgent_externalized,
            1
        );
        observer_state
            .borrow_mut()
            .outcomes
            .extend([ObservationModeV1::Final(116), ObservationModeV1::Final(117)]);
        record_finality_until_route_commit(
            &mut supervisor,
            &mut reopened.observer,
            digest(123),
            LegIdV1::Upstream,
            ActionKindV1::Claim,
            upstream_aggregate,
        );
        let downstream_materialized = supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut reopened.custody)
            .expect("materialize refenced downstream child after upstream finality");
        assert_eq!(downstream_materialized.custody_partial_progress, 1);
        assert_eq!(child_state.borrow().calls.len(), 3);
        assert_eq!(
            supervisor
                .dispatch_one_effect(&mut RefusingRunnerV1, &mut reopened.custody)
                .expect("dispatch refenced downstream child on later tick")
                .custody_externalized,
            1
        );
        assert_eq!(persistence_log.borrow().refences, 1);
        assert_eq!(
            child_state.borrow().calls,
            [
                (SettlementLegV1::Downstream, SettlementActionV1::Claim, 0),
                (SettlementLegV1::Upstream, SettlementActionV1::Claim, 0),
                (SettlementLegV1::Upstream, SettlementActionV1::Claim, 1),
                (SettlementLegV1::Downstream, SettlementActionV1::Claim, 1),
            ]
        );
    }

    #[test]
    fn unknown_takeover_stays_inert_until_proven_not_externalized() {
        let mut route = seeded_route(false);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [DispatchModeV1::Unknown(60)].into(),
            reconcile: [
                ReconcileModeV1::Unknown(61),
                ReconcileModeV1::NotExternalized(62),
            ]
            .into(),
            ..ChildStateV1::default()
        }));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let mut authorities = assemble_test_bridge(
            create_coordinator(&route.coordinator_path),
            COORDINATOR_OWNER_A,
            &route.clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            Rc::clone(&observer_state),
        );
        route
            .supervisor
            .authorize_action(
                digest(130),
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .expect("authorize funding");
        let first = route
            .supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("ambiguous child");
        assert_eq!(first.custody_unknown, 1);

        let route_path = route.route_path.clone();
        let coordinator_path = route.coordinator_path.clone();
        let clock = route.clock.clone();
        drop(authorities);
        drop(route.supervisor);
        clock.set(TAKEOVER_NOW).expect("advance takeover clock");
        let mut supervisor = RouteSupervisorV1::acquire(
            DurableRouteStoreV1::open_existing(&route_path).expect("reopen route"),
            ROUTE_ID,
            ROUTE_OWNER_B,
            supervisor_config(),
            clock.clone(),
        )
        .expect("takeover supervisor");
        let mut reopened = assemble_test_bridge(
            open_coordinator(&coordinator_path),
            COORDINATOR_OWNER_B,
            &clock,
            persistence_log,
            child_state,
            observer_state,
        );
        let unknown = supervisor
            .reconcile_takeover(&mut reopened.takeover)
            .expect("unknown takeover");
        assert_eq!(unknown.unknown, 1);
        assert_eq!(unknown.reauthorized, 0);
        let resolved = supervisor
            .reconcile_takeover(&mut reopened.takeover)
            .expect("proven absent takeover");
        assert_eq!(resolved.reauthorized, 1);
        assert_eq!(resolved.unknown, 0);
    }

    #[test]
    fn nothing_externalized_takeover_reauthorizes_without_child_call() {
        let mut route = seeded_route(false);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1::default()));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let mut authorities = assemble_test_bridge(
            create_coordinator(&route.coordinator_path),
            COORDINATOR_OWNER_A,
            &route.clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            Rc::clone(&observer_state),
        );
        route
            .supervisor
            .authorize_action(
                digest(140),
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .expect("authorize funding");
        let route_path = route.route_path.clone();
        let coordinator_path = route.coordinator_path.clone();
        let clock = route.clock.clone();
        drop(authorities);
        drop(route.supervisor);
        clock.set(TAKEOVER_NOW).expect("advance takeover clock");
        let mut supervisor = RouteSupervisorV1::acquire(
            DurableRouteStoreV1::open_existing(&route_path).expect("reopen route"),
            ROUTE_ID,
            ROUTE_OWNER_B,
            supervisor_config(),
            clock.clone(),
        )
        .expect("takeover supervisor");
        let mut reopened = assemble_test_bridge(
            open_coordinator(&coordinator_path),
            COORDINATOR_OWNER_B,
            &clock,
            persistence_log,
            Rc::clone(&child_state),
            observer_state,
        );
        let report = supervisor
            .reconcile_takeover(&mut reopened.takeover)
            .expect("nothing externalized");
        assert_eq!(report.reauthorized, 1);
        assert!(child_state.borrow().calls.is_empty());
    }

    #[test]
    fn preinstalled_new_funding_is_revalidated_and_exact_duplicate_is_idempotent() {
        let mut route = seeded_route(false);
        let event_id = digest(150);
        let snapshot = route.supervisor.snapshot().expect("armed snapshot");
        let bindings = snapshot.bindings.as_ref().expect("frozen bindings");
        let plan = test_plan(
            ROUTE_ID,
            event_id,
            route.supervisor.lease_status().fencing_epoch(),
            LegIdV1::Upstream,
            ActionKindV1::Funding,
            &snapshot.secret_visibility,
            bindings,
        );
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let mut persistence = TestPlanPersistenceV1 {
            log: Rc::clone(&persistence_log),
        };
        let mut coordinator = create_coordinator(&route.coordinator_path);
        persistence
            .install_new_plan(&mut coordinator, plan, event_id, TEST_NOW)
            .expect("simulate crash after coordinator install");
        let child_state = Rc::new(RefCell::new(ChildStateV1::default()));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let mut authorities = assemble_production_settlement_authorities_with_clock_v1(
            ProductionSettlementBridgePartsV1 {
                coordinator,
                config: ProductionSettlementBridgeConfigV1::new(COORDINATOR_OWNER_A, 500)
                    .expect("bridge config"),
                plan_source: TestPlanSourceV1::default(),
                plan_persistence: persistence,
                child_authority: TestChildAuthorityV1(child_state),
                child_observer: TestObserverV1(observer_state),
                clock: TestSettlementClockV1(route.clock.clone()),
            },
        );
        route
            .supervisor
            .authorize_action(
                event_id,
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .expect("revalidate preinstalled funding");
        assert_eq!(persistence_log.borrow().installs, [event_id]);
        assert_eq!(persistence_log.borrow().revalidations, [event_id]);
        let duplicate = route
            .supervisor
            .authorize_action(
                event_id,
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .expect("exact duplicate");
        assert!(matches!(
            duplicate,
            CommitOutcomeV1::DuplicateSameBytes { .. }
        ));
        assert_eq!(persistence_log.borrow().installs.len(), 1);
        assert_eq!(persistence_log.borrow().revalidations.len(), 1);
    }

    #[test]
    fn preinstalled_funding_refences_after_route_fence_restart_before_commit() {
        let route = seeded_route(false);
        let event_id = digest(180);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let (coordinator, old_effect, old_fence) =
            preinstall_upstream_funding(&route, event_id, Rc::clone(&persistence_log));
        let route_path = route.route_path.clone();
        let coordinator_path = route.coordinator_path.clone();
        let clock = route.clock.clone();
        drop(coordinator);
        drop(route.supervisor);

        clock.set(TAKEOVER_NOW).expect("advance takeover clock");
        let mut supervisor = reopen_route_after_takeover(&route_path, &clock);
        let new_fence = supervisor.lease_status().fencing_epoch();
        assert!(new_fence > old_fence);
        assert_eq!(
            supervisor
                .snapshot()
                .expect("uncommitted route snapshot")
                .upstream
                .funding
                .progress(),
            ActionProgressV1::NotPrepared
        );
        let child_state = Rc::new(RefCell::new(ChildStateV1::default()));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let mut authorities = assemble_test_bridge(
            open_coordinator(&coordinator_path),
            COORDINATOR_OWNER_B,
            &clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            observer_state,
        );

        let committed = supervisor
            .authorize_action(
                event_id,
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .expect("guarded refence and route commit");
        assert!(matches!(committed, CommitOutcomeV1::Committed { .. }));
        let (new_effect, _) =
            committed_effect(&supervisor, LegIdV1::Upstream, ActionKindV1::Funding);
        assert_ne!(new_effect, old_effect);
        assert_eq!(persistence_log.borrow().installs, [event_id]);
        assert!(persistence_log.borrow().revalidations.is_empty());
        assert_eq!(persistence_log.borrow().preinstalled_refences, [event_id]);
        assert_eq!(persistence_log.borrow().refences, 0);
        assert!(child_state.borrow().calls.is_empty());

        let core = authorities.custody.0.try_borrow().expect("bridge core");
        assert_eq!(
            core.coordinator
                .load_plan_for_effect(old_effect)
                .unwrap_err(),
            CoordinatorErrorV1::StaleFencing
        );
        let current = core
            .coordinator
            .load_plan_for_effect(new_effect)
            .expect("refenced current plan");
        assert_eq!(current.view().fencing_epoch, new_fence);
        validate_pristine_preinstalled_plan(&current).expect("refenced plan stays pristine");
    }

    #[test]
    fn ambiguous_preinstalled_child_is_refused_after_route_fence_restart() {
        let route = seeded_route(false);
        let event_id = digest(181);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let (mut coordinator, old_effect, old_fence) =
            preinstall_upstream_funding(&route, event_id, Rc::clone(&persistence_log));
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [DispatchModeV1::Unknown(81)].into(),
            ..ChildStateV1::default()
        }));
        let old_plan = coordinator
            .load_plan_for_effect(old_effect)
            .expect("old preinstalled plan");
        let old_lease = coordinator
            .acquire_lease(
                old_plan.view().plan_id,
                COORDINATOR_OWNER_A,
                old_fence,
                TEST_NOW,
                500,
            )
            .expect("old coordinator lease")
            .lease();
        assert!(matches!(
            coordinator
                .drive_one(
                    old_lease,
                    &mut TestChildAuthorityV1(Rc::clone(&child_state)),
                    TEST_NOW,
                )
                .expect("persist ambiguous old child"),
            CoordinatorDriveOutcomeV1::Unknown { evidence_digest } if evidence_digest == digest(81)
        ));
        let route_path = route.route_path.clone();
        let coordinator_path = route.coordinator_path.clone();
        let clock = route.clock.clone();
        drop(coordinator);
        drop(route.supervisor);

        clock.set(TAKEOVER_NOW).expect("advance takeover clock");
        let mut supervisor = reopen_route_after_takeover(&route_path, &clock);
        let mut authorities = assemble_test_bridge(
            open_coordinator(&coordinator_path),
            COORDINATOR_OWNER_B,
            &clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            Rc::new(RefCell::new(ObserverStateV1::default())),
        );
        let error = supervisor
            .authorize_action(
                event_id,
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            RouteSupervisorErrorV1::RouteActionAuthority(AuthorityRefusalV1::Inconsistent)
        ));
        assert_eq!(
            supervisor
                .snapshot()
                .expect("unchanged route")
                .upstream
                .funding
                .progress(),
            ActionProgressV1::NotPrepared
        );
        assert!(persistence_log.borrow().preinstalled_refences.is_empty());
        assert_eq!(child_state.borrow().effects, [old_effect]);
        let core = authorities.custody.0.try_borrow().expect("bridge core");
        let retained = core
            .coordinator
            .load_plan_for_effect(old_effect)
            .expect("ambiguous plan stays under old effect");
        assert_eq!(retained.view().fencing_epoch, old_fence);
        assert_eq!(retained.view().children[0].stage, ChildStageV1::CallPending);
        assert_eq!(retained.view().children[0].call_attempts, 1);
    }

    #[test]
    fn guarded_preinstall_refence_dispatches_only_the_new_effect_after_commit() {
        let route = seeded_route(false);
        let event_id = digest(182);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let (coordinator, old_effect, old_fence) =
            preinstall_upstream_funding(&route, event_id, Rc::clone(&persistence_log));
        let route_path = route.route_path.clone();
        let coordinator_path = route.coordinator_path.clone();
        let clock = route.clock.clone();
        drop(coordinator);
        drop(route.supervisor);

        clock.set(TAKEOVER_NOW).expect("advance takeover clock");
        let mut supervisor = reopen_route_after_takeover(&route_path, &clock);
        assert!(supervisor.lease_status().fencing_epoch() > old_fence);
        let child_state = Rc::new(RefCell::new(ChildStateV1 {
            dispatch: [DispatchModeV1::Externalized(82)].into(),
            ..ChildStateV1::default()
        }));
        let mut authorities = assemble_test_bridge(
            open_coordinator(&coordinator_path),
            COORDINATOR_OWNER_B,
            &clock,
            persistence_log,
            Rc::clone(&child_state),
            Rc::new(RefCell::new(ObserverStateV1::default())),
        );
        supervisor
            .authorize_action(
                event_id,
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .expect("guarded preinstall refence");
        let (new_effect, _) =
            committed_effect(&supervisor, LegIdV1::Upstream, ActionKindV1::Funding);
        assert_ne!(new_effect, old_effect);
        assert!(child_state.borrow().calls.is_empty());
        let progress = supervisor
            .dispatch_one_effect(&mut RefusingRunnerV1, &mut authorities.custody)
            .expect("dispatch refenced child");
        assert_eq!(progress.custody_partial_progress, 1);
        assert_eq!(progress.custody_externalized, 0);
        assert_eq!(child_state.borrow().effects, [new_effect]);
        assert!(!child_state.borrow().effects.contains(&old_effect));
        let core = authorities.custody.0.try_borrow().expect("bridge core");
        assert_eq!(
            core.coordinator
                .load_plan_for_effect(old_effect)
                .unwrap_err(),
            CoordinatorErrorV1::StaleFencing
        );
        let current = core
            .coordinator
            .load_plan_for_effect(new_effect)
            .expect("current refenced plan");
        assert_eq!(current.view().children[0].stage, ChildStageV1::Externalized);
        assert_eq!(current.view().children[1].stage, ChildStageV1::Planned);
    }

    #[test]
    fn preinstalled_plan_from_another_route_event_is_never_reused() {
        let route = seeded_route(false);
        let old_event_id = digest(183);
        let new_event_id = digest(184);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let (coordinator, old_effect, _) =
            preinstall_upstream_funding(&route, old_event_id, Rc::clone(&persistence_log));
        let route_path = route.route_path.clone();
        let coordinator_path = route.coordinator_path.clone();
        let clock = route.clock.clone();
        drop(coordinator);
        drop(route.supervisor);

        clock.set(TAKEOVER_NOW).expect("advance takeover clock");
        let mut supervisor = reopen_route_after_takeover(&route_path, &clock);
        let child_state = Rc::new(RefCell::new(ChildStateV1::default()));
        let mut authorities = assemble_test_bridge(
            open_coordinator(&coordinator_path),
            COORDINATOR_OWNER_B,
            &clock,
            Rc::clone(&persistence_log),
            Rc::clone(&child_state),
            Rc::new(RefCell::new(ObserverStateV1::default())),
        );
        let error = supervisor
            .authorize_action(
                new_event_id,
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            RouteSupervisorErrorV1::RouteActionAuthority(AuthorityRefusalV1::Inconsistent)
        ));
        assert_eq!(
            supervisor
                .snapshot()
                .expect("unchanged route")
                .upstream
                .funding
                .progress(),
            ActionProgressV1::NotPrepared
        );
        assert!(persistence_log.borrow().preinstalled_refences.is_empty());
        assert!(child_state.borrow().calls.is_empty());
        let core = authorities.custody.0.try_borrow().expect("bridge core");
        let retained = core
            .coordinator
            .load_plan_for_effect(old_effect)
            .expect("unrelated preinstall remains untouched");
        validate_pristine_preinstalled_plan(&retained).expect("old plan stays pristine");
    }

    #[test]
    fn child_outcome_duplicate_tokens_are_stable_and_equivocation_fails_closed() {
        let mut route = seeded_route(false);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1::default()));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let mut authorities = assemble_test_bridge(
            create_coordinator(&route.coordinator_path),
            COORDINATOR_OWNER_A,
            &route.clock,
            persistence_log,
            Rc::clone(&child_state),
            observer_state,
        );
        route
            .supervisor
            .authorize_action(
                digest(160),
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .expect("authorize funding");
        let (effect_id, aggregate_action) =
            committed_effect(&route.supervisor, LegIdV1::Upstream, ActionKindV1::Funding);
        let mut core = authorities.custody.0.try_borrow_mut().expect("bridge core");
        let stored = core
            .coordinator
            .load_plan_for_effect(effect_id)
            .expect("stored plan");
        assert_eq!(
            core.coordinator
                .load_plan_for_aggregate(aggregate_action, digest(223))
                .unwrap_err(),
            CoordinatorErrorV1::IdempotencyConflict
        );
        let lease = core
            .coordinator
            .acquire_lease(
                stored.view().plan_id,
                COORDINATOR_OWNER_A,
                stored.view().fencing_epoch,
                TEST_NOW,
                500,
            )
            .expect("coordinator lease")
            .lease();
        let first = core
            .coordinator
            .prepare_next_child_call(lease, TEST_NOW)
            .expect("first original token");
        let exact_duplicate = core
            .coordinator
            .prepare_next_child_call(lease, TEST_NOW)
            .expect("exact duplicate token");
        let conflicting_duplicate = core
            .coordinator
            .prepare_next_child_call(lease, TEST_NOW)
            .expect("conflicting duplicate token");
        assert!(matches!(
            core.coordinator
                .complete_child_call(
                    lease,
                    first,
                    ChildExecutionOutcomeV1::Unknown {
                        evidence_digest: digest(70),
                    },
                    TEST_NOW,
                )
                .expect("first unknown"),
            CoordinatorDriveOutcomeV1::Unknown { evidence_digest } if evidence_digest == digest(70)
        ));
        assert!(matches!(
            core.coordinator
                .complete_child_call(
                    lease,
                    exact_duplicate,
                    ChildExecutionOutcomeV1::Unknown {
                        evidence_digest: digest(70),
                    },
                    TEST_NOW,
                )
                .expect("exact duplicate unknown"),
            CoordinatorDriveOutcomeV1::Unknown { evidence_digest } if evidence_digest == digest(70)
        ));
        let conflicting_receipt =
            TestChildAuthorityV1::receipt(conflicting_duplicate.request(), 71);
        assert_eq!(
            core.coordinator
                .complete_child_call(
                    lease,
                    conflicting_duplicate,
                    ChildExecutionOutcomeV1::Externalized(conflicting_receipt),
                    TEST_NOW,
                )
                .unwrap_err(),
            CoordinatorErrorV1::IdempotencyConflict
        );
        assert_eq!(
            core.coordinator
                .load_plan(stored.view().plan_id)
                .expect("failed-closed view")
                .stage,
            AggregateStageV1::FailedClosed
        );
        assert!(
            child_state.borrow().calls.is_empty(),
            "duplicate outcome handling must not invoke the child authority"
        );
    }

    #[test]
    fn nested_bridge_call_returns_typed_inconsistency_without_panic() {
        let mut route = seeded_route(false);
        let persistence_log = Rc::new(RefCell::new(PersistenceLogV1::default()));
        let child_state = Rc::new(RefCell::new(ChildStateV1::default()));
        let observer_state = Rc::new(RefCell::new(ObserverStateV1::default()));
        let mut authorities = assemble_test_bridge(
            create_coordinator(&route.coordinator_path),
            COORDINATOR_OWNER_A,
            &route.clock,
            Rc::clone(&persistence_log),
            child_state,
            observer_state,
        );
        let held = authorities
            .custody
            .0
            .try_borrow_mut()
            .expect("hold bridge core");
        let error = route
            .supervisor
            .authorize_action(
                digest(170),
                LegIdV1::Upstream,
                ActionKindV1::Funding,
                &mut authorities.action,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            RouteSupervisorErrorV1::RouteActionAuthority(AuthorityRefusalV1::Inconsistent)
        ));
        drop(held);
        assert_eq!(
            route
                .supervisor
                .snapshot()
                .expect("unchanged snapshot")
                .upstream
                .funding
                .progress(),
            ActionProgressV1::NotPrepared
        );
        assert!(persistence_log.borrow().installs.is_empty());
    }
}

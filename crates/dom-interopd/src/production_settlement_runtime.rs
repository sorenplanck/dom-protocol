//! Phase-2 composition: the settlement runtime over the negotiated role plan.
//!
//! Everything here is assembly of authorities that already exist; nothing is
//! invented. The entry condition is the authenticated role-plan artifact —
//! the one composed-route fact only the Contracts/F7 negotiation can produce
//! — plus the phase-1 service plane and the counterparty children. The
//! output is one `ProductionRouteRuntimeV1` whose eight authority slots are
//! all production implementations (the runner slot deliberately stays the
//! documented fail-closed refusal: composed interop routes emit no
//! `RunnerPayload` effects).

use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use adapter_dom_real::{RealDomClaimConsumerV1, RealDomRpcRuntimeV1};
use dom_actuator::DomSessionBindingV1;
use dom_adaptor::TrustedChainIdV1;
use dom_core::Hash256;
use dom_scriptless_chain_adapter::BearerTokenV1;
use route_executor::{Digest32, LegIdV1};

use crate::production_chain_signers::ProductionChainSignerAuthoritiesV1;
use crate::production_child_dom::{
    compose_production_dom_child_port_v1, ProductionDomChildBindingsV1,
    ProductionDomChildSessionBindingsV1, ProductionDomMaterializationScopeV1,
};
use crate::production_children::ProductionCounterpartyChildrenV1;
use crate::production_config::ValidatedProductionBootstrapV1;
use crate::production_contracts::ProductionContractsV1;
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::production_materializer::{
    authenticate_leg, ProductionCustodiedFirstExposureClaimAuthorityV1,
    ProductionSettlementMaterializationOwnerV1,
};
use crate::production_node::load_production_node_config_v1;
use crate::production_plan_authority::{
    ProductionPlanAuthorityPinsV1, ProductionPlanLegPinsV1, ProductionRoutePlanAuthorityV1,
    SystemProductionPlanAuthorityClockV1,
};
use crate::production_plan_source::{
    ProductionPublicSecretRetentionV1, ProductionPublicSecretSourceRouterV1,
    VerifiedProductionSettlementPlanSourceV1,
};
use crate::production_refund_arming::{
    ProductionRefundArmingAuthorityV1, ProductionRefundArmingCredentialV1,
    ProductionRefundArmingSourcesV1, ProductionRefundLegV1,
};
use crate::production_role_plan::AuthenticatedProductionRolePlanV1;
use crate::production_run::UnavailableRunnerAuthorityV1;
use crate::production_service::ProductionRouteServiceV1;
use crate::production_settlement::{
    assemble_production_settlement_authorities_with_child_port_v1,
    ProductionSettlementActionAuthorityV1, ProductionSettlementBridgeConfigV1,
    ProductionSettlementCustodyAuthorityV1, ProductionSettlementObservationAuthorityV1,
    ProductionSettlementRetirementAuthorityV1, ProductionSettlementTakeoverAuthorityV1,
};
use crate::production_time_guard::{
    ProductionRouteTimeGuardContextV2, ProductionRouteTimeGuardV2,
    ProductionTimeGuardedPlanPersistenceV2,
};
use crate::production_timer::ProductionDeadlineTimerAuthorityV1;
use crate::relay_worker::UnavailableF6AuthorityV1;
use crate::runtime::{
    ProductionRouteRuntimeV1, RouteRuntimeAuthoritiesV1, RouteRuntimeConfigV1,
    RouteRuntimeOperationalAuthoritiesV1, RouteRuntimeRecoveryAuthoritiesV1,
};
use crate::supervisor::{RouteSupervisorConfigV1, RouteSupervisorV1, SystemClockV1};
use settlement_coordinator::DurableSettlementCoordinatorV1;

const ZERO_DIGEST: Digest32 = [0; 32];

/// Fixed refund-arming journal name under the trusted state directory.
const PRODUCTION_REFUND_ARMING_FILE_V1: &str = "refund-arming.v1.sqlite3";

/// The refund-arming authority epoch for the sole composition root. There is
/// exactly one arming authority per route state directory; epochs above one
/// belong to explicit operator-run takeover tooling, which does not exist
/// yet and must not be improvised here.
const PRODUCTION_REFUND_ARMING_EPOCH_V1: u64 = 1;

/// The fully composed route runtime type produced by this module.
pub(crate) type ComposedProductionRouteRuntimeV1 = ProductionRouteRuntimeV1<
    SystemClockV1,
    ProductionRefundArmingAuthorityV1,
    ProductionSettlementActionAuthorityV1,
    ProductionSettlementObservationAuthorityV1,
    UnavailableRunnerAuthorityV1,
    ProductionSettlementCustodyAuthorityV1,
    ProductionDeadlineTimerAuthorityV1,
    ProductionSettlementTakeoverAuthorityV1,
    ProductionSettlementRetirementAuthorityV1,
>;

/// Named, redacted phase-2 composition refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProductionSettlementRuntimeErrorV1 {
    /// The node configuration, its identity or the authenticated client
    /// refused, or it does not bind the admitted DOM deployment.
    #[error("production DOM node runtime unavailable")]
    NodeRuntime,
    /// A DOM lease, session binding or the child store authority refused.
    #[error("production DOM child bindings refused")]
    DomChild,
    /// The counterparty children or their refund faces are incomplete.
    #[error("production counterparty children incomplete")]
    CounterpartyChildren,
    /// The refund-arming journal could not be created or reopened.
    #[error("production refund arming unavailable")]
    RefundArming,
    /// The materialization owner, plan source or secret router refused.
    #[error("production materialization authorities refused")]
    Materialization,
    /// The plan authority, time guard or persistence boundary refused.
    #[error("production plan persistence refused")]
    PlanPersistence,
    /// The route supervisor or runtime constructor refused.
    #[error("production route runtime refused")]
    RouteRuntime,
    /// The trusted host clock refused.
    #[error("production host clock refused")]
    HostClock,
}

/// Everything phase 2 consumes, all of it already authenticated upstream.
pub(crate) struct ProductionSettlementRuntimeRequestV1 {
    pub(crate) inputs: AuthenticatedProductionInputsV1,
    pub(crate) role_plan: AuthenticatedProductionRolePlanV1,
    pub(crate) service: ProductionRouteServiceV1,
    pub(crate) children: ProductionCounterpartyChildrenV1,
    pub(crate) deadline_timer: ProductionDeadlineTimerAuthorityV1,
    pub(crate) retention: ProductionPublicSecretRetentionV1,
    pub(crate) coordinator: DurableSettlementCoordinatorV1,
    pub(crate) dom_actuator_store: dom_actuator::DomActuatorStoreV1,
    pub(crate) bearer: BearerTokenV1,
    pub(crate) refund_arming_credential: ProductionRefundArmingCredentialV1,
    pub(crate) trusted_now_seconds: u64,
    pub(crate) now_unix_ms: u64,
}

/// The composed runtime plus the live service plane it must outlive.
pub(crate) struct ComposedProductionRouteV1 {
    pub(crate) runtime: ComposedProductionRouteRuntimeV1,
    pub(crate) upstream_contracts: ProductionContractsV1<UnavailableF6AuthorityV1>,
    pub(crate) downstream_contracts: ProductionContractsV1<UnavailableF6AuthorityV1>,
    pub(crate) relay_queue: relay::production::ProductionRelayV1,
}

impl core::fmt::Debug for ComposedProductionRouteV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ComposedProductionRouteV1([authorities redacted])")
    }
}

/// Composes the full settlement runtime for one admitted, negotiated route.
pub(crate) fn compose_production_settlement_runtime_v1(
    bootstrap: &ValidatedProductionBootstrapV1,
    signers: &ProductionChainSignerAuthoritiesV1,
    request: ProductionSettlementRuntimeRequestV1,
) -> Result<ComposedProductionRouteV1, ProductionSettlementRuntimeErrorV1> {
    let ProductionSettlementRuntimeRequestV1 {
        inputs,
        role_plan,
        service,
        children,
        deadline_timer,
        retention,
        coordinator,
        mut dom_actuator_store,
        bearer,
        refund_arming_credential,
        trusted_now_seconds,
        now_unix_ms,
    } = request;
    let AuthenticatedProductionRolePlanV1 {
        role_plan,
        upstream_scope,
        downstream_scope,
    } = role_plan;
    let ProductionRouteServiceV1 {
        upstream_contracts,
        downstream_contracts,
        relay_queue,
    } = service;
    let pins = bootstrap.config().pins();
    let bounds = bootstrap.config().bounds();
    let state_dir = bootstrap.layout().state_dir();

    // 1. The sole authenticated DOM node runtime, twice over the same frozen
    //    identity: one owned client drives the child port, one shared client
    //    backs the claim consumer used by the public-secret source. The
    //    trusted chain id is recomputed from the node's authenticated
    //    network magic and genesis and must equal both the node's own pinned
    //    chain id and every DOM session binding below.
    let node = load_production_node_config_v1(state_dir)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::NodeRuntime)?;
    let identity = node.expected_identity();
    let history_limit = node.history_limit();
    let genesis = Hash256::from_bytes(identity.genesis_hash);
    let trusted_chain_id =
        TrustedChainIdV1::from_authenticated_genesis(identity.network_magic, &genesis);
    if trusted_chain_id.as_bytes() != &identity.chain_id {
        return Err(ProductionSettlementRuntimeErrorV1::NodeRuntime);
    }
    let adapter = node
        .into_dom_chain_adapter(bearer)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::NodeRuntime)?;
    let node_runtime = Arc::new(
        RealDomRpcRuntimeV1::new(adapter, history_limit)
            .map_err(|_| ProductionSettlementRuntimeErrorV1::NodeRuntime)?,
    );

    // 2. DOM session bindings and the one participant lease over the control
    //    store shared by both legs.
    let upstream_binding: DomSessionBindingV1 = signers.dom_binding(LegIdV1::Upstream);
    let downstream_binding: DomSessionBindingV1 = signers.dom_binding(LegIdV1::Downstream);
    if upstream_binding.chain_id() != *trusted_chain_id.as_bytes()
        || downstream_binding.chain_id() != *trusted_chain_id.as_bytes()
    {
        return Err(ProductionSettlementRuntimeErrorV1::NodeRuntime);
    }
    let lease = dom_actuator_store
        .acquire_lease(
            signers.participant_id().0,
            pins.process_owner_id,
            now_unix_ms,
            bounds.actuator_lease_ms,
        )
        .map_err(|_| ProductionSettlementRuntimeErrorV1::DomChild)?;

    // 3. The two one-shot DOM child store authorities, each bound to its
    //    leg's frozen DOM deadline.
    let composition_upstream_terms = inputs.composition().upstream().clone();
    let composition_downstream_terms = inputs.composition().downstream().clone();
    let upstream_store_authority = upstream_contracts
        .dom_child_store_authority(
            upstream_binding,
            composition_upstream_terms.dom_leg.deadline,
        )
        .map_err(|_| ProductionSettlementRuntimeErrorV1::DomChild)?;
    let downstream_store_authority = downstream_contracts
        .dom_child_store_authority(
            downstream_binding,
            composition_downstream_terms.dom_leg.deadline,
        )
        .map_err(|_| ProductionSettlementRuntimeErrorV1::DomChild)?;

    // 4. The composition-root DOM public-secret source: the receiver custody
    //    of the downstream session (the leg whose DOM claim reveals first),
    //    corroborated at extraction against the route journal's exposure.
    let claim_verifier = Arc::new(
        downstream_store_authority
            .build_claim_verifier(&trusted_chain_id)
            .map_err(|_| ProductionSettlementRuntimeErrorV1::DomChild)?,
    );
    let dom_secret_source = downstream_contracts
        .dom_public_secret_source_v2(
            inputs.composition().binding_digest(),
            downstream_binding,
            trusted_chain_id,
            RealDomClaimConsumerV1::new(Arc::clone(&node_runtime), claim_verifier),
        )
        .map_err(|_| ProductionSettlementRuntimeErrorV1::Materialization)?;

    // 5. Refund arming: DOM face per leg from the retained Contracts stores,
    //    counterparty face per leg from the composed children.
    let mut children = children;
    let [upstream_counterparty_face, downstream_counterparty_face] =
        core::mem::take(&mut children.refund_faces);
    let upstream_counterparty_face = upstream_counterparty_face
        .ok_or(ProductionSettlementRuntimeErrorV1::CounterpartyChildren)?;
    let downstream_counterparty_face = downstream_counterparty_face
        .ok_or(ProductionSettlementRuntimeErrorV1::CounterpartyChildren)?;
    let upstream_dom_face = upstream_contracts
        .dom_refund_face(upstream_binding, trusted_chain_id)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::RefundArming)?;
    let downstream_dom_face = downstream_contracts
        .dom_refund_face(downstream_binding, trusted_chain_id)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::RefundArming)?;
    let refund_sources = ProductionRefundArmingSourcesV1::new(
        inputs.admission(),
        inputs.composition(),
        pins.process_owner_id,
        PRODUCTION_REFUND_ARMING_EPOCH_V1,
        ProductionRefundLegV1::new(upstream_dom_face, upstream_counterparty_face),
        ProductionRefundLegV1::new(downstream_dom_face, downstream_counterparty_face),
    )
    .map_err(|_| ProductionSettlementRuntimeErrorV1::RefundArming)?;
    let credential = refund_arming_credential;
    let refund_arming_path = state_dir.join(PRODUCTION_REFUND_ARMING_FILE_V1);
    let refund_arming = open_refund_arming(&refund_arming_path, credential, refund_sources)?;

    // 6. Materialization scope, DOM child port and the completed router.
    let materialization_scope = ProductionDomMaterializationScopeV1::authenticate(
        &inputs,
        &role_plan,
        upstream_scope.clone(),
        downstream_scope.clone(),
    )
    .map_err(|_| ProductionSettlementRuntimeErrorV1::Materialization)?;
    let dom_child_bindings = ProductionDomChildBindingsV1 {
        sessions: [
            ProductionDomChildSessionBindingsV1 {
                leg: settlement_coordinator::SettlementLegV1::Upstream,
                settlement_id: composition_upstream_terms.settlement_id.0,
                binding: upstream_binding,
                contracts: upstream_store_authority,
            },
            ProductionDomChildSessionBindingsV1 {
                leg: settlement_coordinator::SettlementLegV1::Downstream,
                settlement_id: composition_downstream_terms.settlement_id.0,
                binding: downstream_binding,
                contracts: downstream_store_authority,
            },
        ],
        lease,
        trusted_chain_id,
        runtime: node_runtime,
        route_terms_digest: inputs.admission().frozen_bindings().terms_digest,
        materialization_scope,
    };
    let dom_port = compose_production_dom_child_port_v1(dom_actuator_store, dom_child_bindings)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::DomChild)?;
    let router = children
        .into_router(dom_port)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::CounterpartyChildren)?;

    // 7. First-exposure authority, materialization owner, plan authority
    //    pins from the authenticated per-leg bindings.
    let first_exposure =
        ProductionCustodiedFirstExposureClaimAuthorityV1::bind(&inputs, &role_plan)
            .map_err(|_| ProductionSettlementRuntimeErrorV1::Materialization)?;
    let upstream_leg = authenticate_leg(&inputs, &role_plan, LegIdV1::Upstream)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::Materialization)?;
    let downstream_leg = authenticate_leg(&inputs, &role_plan, LegIdV1::Downstream)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::Materialization)?;
    let owner = ProductionSettlementMaterializationOwnerV1::authenticate(
        &inputs,
        role_plan,
        upstream_scope,
        downstream_scope,
        router,
        first_exposure,
    )
    .map_err(|_| ProductionSettlementRuntimeErrorV1::Materialization)?;
    let (materializer, child_handle) = owner.split();

    let plan_pins = ProductionPlanAuthorityPinsV1 {
        authority_id: pins.coordinator_plan_authority_id,
        route_id: inputs.admission().route_id(),
        registry_digest: inputs.admission().registry_digest(),
        dom_profile_digest: inputs.admission().dom_profile_digest(),
        dom_deployment_digest: materializer_dom_deployment_digest(&inputs)?,
        upstream: ProductionPlanLegPinsV1 {
            settlement_id: upstream_leg.settlement_id,
            terms_digest: bootstrap.config().pins().upstream_terms_digest,
            counterparty_profile_digest: upstream_leg.counterparty_profile_digest,
            counterparty_deployment_digest: upstream_leg.counterparty_deployment_digest,
        },
        downstream: ProductionPlanLegPinsV1 {
            settlement_id: downstream_leg.settlement_id,
            terms_digest: bootstrap.config().pins().downstream_terms_digest,
            counterparty_profile_digest: downstream_leg.counterparty_profile_digest,
            counterparty_deployment_digest: downstream_leg.counterparty_deployment_digest,
        },
    };
    let plan_authority =
        ProductionRoutePlanAuthorityV1::new(plan_pins, SystemProductionPlanAuthorityClockV1)
            .map_err(|_| ProductionSettlementRuntimeErrorV1::PlanPersistence)?;

    // 8. Everything below needs owned pieces of the inputs: destructure once
    //    all borrows above have resolved.
    let AuthenticatedProductionInputsV1 {
        admission,
        composition,
        resolved_registry,
        route_store,
        time_store,
        time_policy_authorities,
        time_evidence_authorities,
        time_verification_context,
        signed_time_evidence,
        ..
    } = inputs;
    let route_id = admission.route_id();
    let frozen_bindings = admission.frozen_bindings().clone();
    let composition = Rc::new(composition);

    let secret_router = ProductionPublicSecretSourceRouterV1::new(
        dom_secret_source,
        None::<crate::production_plan_source::ProductionDomPublicSecretSourceV2>,
        None::<crate::production_plan_source::ProductionDomPublicSecretSourceV2>,
        None::<crate::production_plan_source::ProductionDomPublicSecretSourceV2>,
    )
    .map_err(|_| ProductionSettlementRuntimeErrorV1::Materialization)?;
    let plan_source = VerifiedProductionSettlementPlanSourceV1::new(
        route_id,
        frozen_bindings,
        Rc::clone(&composition),
        secret_router,
        retention,
        materializer,
    )
    .map_err(|_| ProductionSettlementRuntimeErrorV1::Materialization)?;

    // 9. The time-guarded persistence over the base plan authority.
    let time_guard_context = ProductionRouteTimeGuardContextV2 {
        policy_authorities: time_policy_authorities,
        evidence_authorities: time_evidence_authorities,
        secp: time_verification_context,
        registry: resolved_registry,
        upstream: composition.upstream().clone(),
        downstream: composition.downstream().clone(),
    };
    let time_guard = ProductionRouteTimeGuardV2::new(time_store, &admission, time_guard_context)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::PlanPersistence)?;
    let mut persistence = ProductionTimeGuardedPlanPersistenceV2::new(time_guard, plan_authority);
    persistence
        .install_time_evidence(&signed_time_evidence, trusted_now_seconds)
        .map_err(|_| ProductionSettlementRuntimeErrorV1::PlanPersistence)?;

    // 10. The settlement bridge over the durable coordinator.
    let bridge_config =
        ProductionSettlementBridgeConfigV1::new(pins.process_owner_id, bounds.coordinator_lease_ms)
            .map_err(|_| ProductionSettlementRuntimeErrorV1::PlanPersistence)?;
    let authorities = assemble_production_settlement_authorities_with_child_port_v1(
        coordinator,
        bridge_config,
        plan_source,
        persistence,
        child_handle,
    );

    // 11. The supervisor over the sole route store, and the runtime.
    let supervisor_config = RouteSupervisorConfigV1::new(
        bounds.lease_duration_ms,
        bounds.renew_before_ms,
        bounds.dispatch_lease_ms,
        usize::try_from(bounds.per_queue_batch_limit)
            .map_err(|_| ProductionSettlementRuntimeErrorV1::RouteRuntime)?,
    )
    .map_err(|_| ProductionSettlementRuntimeErrorV1::RouteRuntime)?;
    let supervisor = RouteSupervisorV1::acquire(
        route_store,
        route_id,
        pins.process_owner_id,
        supervisor_config,
        SystemClockV1,
    )
    .map_err(|_| ProductionSettlementRuntimeErrorV1::RouteRuntime)?;
    let runtime_config = RouteRuntimeConfigV1::new(
        bounds.waiting_backoff_ms,
        bounds.recovery_backoff_ms,
        supervisor_config,
    )
    .map_err(|_| ProductionSettlementRuntimeErrorV1::RouteRuntime)?;
    let runtime = ProductionRouteRuntimeV1::new(
        supervisor,
        admission,
        RouteRuntimeAuthoritiesV1::new(
            RouteRuntimeOperationalAuthoritiesV1 {
                refund: refund_arming,
                action: authorities.action,
                observer: authorities.observer,
                runner: UnavailableRunnerAuthorityV1,
            },
            RouteRuntimeRecoveryAuthoritiesV1 {
                custody: authorities.custody,
                timers: deadline_timer,
                reconciler: authorities.takeover,
                retirement: authorities.retirement,
            },
        ),
        runtime_config,
    )
    .map_err(|_| ProductionSettlementRuntimeErrorV1::RouteRuntime)?;

    Ok(ComposedProductionRouteV1 {
        runtime,
        upstream_contracts,
        downstream_contracts,
        relay_queue,
    })
}

fn materializer_dom_deployment_digest(
    inputs: &AuthenticatedProductionInputsV1,
) -> Result<Digest32, ProductionSettlementRuntimeErrorV1> {
    let capability = inputs
        .admission()
        .dom_deployment_capability()
        .map_err(|_| ProductionSettlementRuntimeErrorV1::Materialization)?;
    let digest = capability.registry_digest();
    if digest == ZERO_DIGEST {
        return Err(ProductionSettlementRuntimeErrorV1::Materialization);
    }
    Ok(digest)
}

fn open_refund_arming(
    path: &Path,
    credential: ProductionRefundArmingCredentialV1,
    sources: ProductionRefundArmingSourcesV1<'_>,
) -> Result<ProductionRefundArmingAuthorityV1, ProductionSettlementRuntimeErrorV1> {
    if path.exists() {
        ProductionRefundArmingAuthorityV1::open_existing(path, credential, sources)
            .map_err(|_| ProductionSettlementRuntimeErrorV1::RefundArming)
    } else {
        ProductionRefundArmingAuthorityV1::create(path, credential, sources)
            .map_err(|_| ProductionSettlementRuntimeErrorV1::RefundArming)
    }
}

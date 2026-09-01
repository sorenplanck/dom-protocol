//! Durable, route-authenticated settlement plan materialization.
//!
//! This module is the sole owner/split seam between the plan source and the
//! chain router. Both handles operate on one physical set of actuator/store
//! authorities; no child store is reopened and no caller may supply child
//! transaction identities.

use std::cell::Cell;
use std::rc::Rc;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use route_composer::{
    ComposedBindingV2, ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1,
    FinalClaimRevealModeV1, FinalClaimSecretSourceScopeV1, FinalClaimSecretSourceV1, RouteScalar,
};
use route_executor::{derive_effect_id_v1, ActionKindV1, LegIdV1, SecretVisibilityV1};
use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1, ChildExposureV1,
    ChildObservationOutcomeV1, ChildObservationRequestV1, ChildReconciliationOutcomeV1,
    ChildReconciliationRequestV1, DeferredChildMaterializationCapabilityV1,
    DeferredSettlementChildV1, SecretRequirementV1, SettlementActionV1, SettlementChildAuthorityV1,
    SettlementChildObserverV1, SettlementChildPlanV1, SettlementChildrenV1, SettlementFaceV1,
    SettlementLegV1,
};

use crate::production_child_router::{
    ProductionChildMaterializationRequestV1, ProductionSettlementChildRouterV1,
};
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::production_plan_source::ProductionSettlementDraftMaterializerV1;
use crate::production_settlement::ProductionSettlementPlanDraftV1;
use crate::supervisor::{AuthorityRefusalV1, RouteActionAuthorizationRequestV1};

type Digest32 = [u8; 32];

const ZERO_DIGEST: Digest32 = [0; 32];
const SEMANTIC_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/PRODUCTION-SETTLEMENT-MATERIALIZER/SEMANTIC/V1\0";
const FIRST_EXPOSURE_REQUEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-FIRST-EXPOSURE/REQUEST/V1\0";
const CHILD_MATERIALIZATION_REQUEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-CHILD-MATERIALIZATION/REQUEST/V1\0";
const DEFERRED_MATERIALIZER_AUTHORITY_DOMAIN_V1: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-DEFERRED-MATERIALIZER/AUTHORITY/V1\0";

#[derive(Clone, Copy)]
struct ProductionLegMaterializationBindingsV1 {
    settlement_id: Digest32,
    counterparty_face: SettlementFaceV1,
    counterparty_chain_id: Digest32,
    counterparty_profile_digest: Digest32,
    counterparty_deployment_digest: Digest32,
    source_scope_digest: Digest32,
    reveal_mode: FinalClaimRevealModeV1,
    secret_source: FinalClaimSecretSourceV1,
}

/// Exact private-claim request passed to the sole local-origin secret owner.
/// It contains no scalar and no raw transaction bytes.
#[derive(Clone, Copy)]
pub(crate) struct ProductionFirstExposureClaimRequestV1 {
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
    first_face: SettlementFaceV1,
    counterparty_face: SettlementFaceV1,
    dom: ProductionChildMaterializationRequestV1,
    counterparty: ProductionChildMaterializationRequestV1,
}

impl ProductionFirstExposureClaimRequestV1 {
    pub(crate) const fn role_plan_digest(&self) -> Digest32 {
        self.role_plan_digest
    }

    pub(crate) const fn source_scope_digest(&self) -> Digest32 {
        self.source_scope_digest
    }

    pub(crate) const fn first_face(&self) -> SettlementFaceV1 {
        self.first_face
    }

    pub(crate) const fn counterparty_face(&self) -> SettlementFaceV1 {
        self.counterparty_face
    }

    pub(crate) const fn dom_request(&self) -> ProductionChildMaterializationRequestV1 {
        self.dom
    }

    pub(crate) const fn counterparty_request(&self) -> ProductionChildMaterializationRequestV1 {
        self.counterparty
    }
}

/// Production authority for the first-exposure DOM descriptor.  It never
/// receives or retains the route scalar; DOM's adaptor transaction is prepared
/// without revealing `t`, and the counterparty child remains deferred.
pub(crate) struct ProductionCustodiedFirstExposureClaimAuthorityV1 {
    route_id: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
    route_scope_digest: Digest32,
    terms_digest: Digest32,
    registry_digest: Digest32,
    reveal_mode: FinalClaimRevealModeV1,
}

#[derive(Clone, Copy)]
struct FirstExposureAuthorityBindingsV1 {
    route_id: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
    route_scope_digest: Digest32,
    terms_digest: Digest32,
    registry_digest: Digest32,
    reveal_mode: FinalClaimRevealModeV1,
}

impl ProductionCustodiedFirstExposureClaimAuthorityV1 {
    pub(crate) fn bind(
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: &ComposedFinalClaimRolePlanV1,
    ) -> Result<Self, AuthorityRefusalV1> {
        let composition = inputs.composition();
        let admission = inputs.admission();
        let downstream = role_plan.entry(ComposedSettlementLegV1::Downstream);
        if role_plan.route_id() == ZERO_DIGEST
            || role_plan.route_scope_digest() != composition.route_scope_digest()
            || role_plan.composition_binding_digest() != composition.binding_digest()
            || downstream.settlement_id().0 != composition.downstream().settlement_id.0
            || downstream.session_id().0 != composition.downstream().session_id.0
            || downstream.secret_source() != FinalClaimSecretSourceV1::LocalOrigin
            || downstream.reveal_mode() != FinalClaimRevealModeV1::DomRevealsFirst
            || downstream.secret_source_scope_digest() == ZERO_DIGEST
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(Self {
            route_id: role_plan.route_id(),
            composition_digest: composition.binding_digest(),
            role_plan_digest: role_plan.digest(),
            source_scope_digest: downstream.secret_source_scope_digest(),
            route_scope_digest: composition.route_scope_digest(),
            terms_digest: admission.frozen_bindings().terms_digest,
            registry_digest: admission.registry_digest(),
            reveal_mode: downstream.reveal_mode(),
        })
    }
    fn materialize_first_exposure(
        &mut self,
        request: ProductionFirstExposureClaimRequestV1,
        router: &mut ProductionSettlementChildRouterV1,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let dom = request.dom;
        let counterparty = request.counterparty;
        validate_first_exposure_scope(
            FirstExposureAuthorityBindingsV1 {
                route_id: self.route_id,
                composition_digest: self.composition_digest,
                role_plan_digest: self.role_plan_digest,
                source_scope_digest: self.source_scope_digest,
                route_scope_digest: self.route_scope_digest,
                terms_digest: self.terms_digest,
                registry_digest: self.registry_digest,
                reveal_mode: self.reveal_mode,
            },
            &request,
        )?;
        let _request_digest = first_exposure_request_digest(&request)?;
        match self.reveal_mode {
            FinalClaimRevealModeV1::DomRevealsFirst => {
                if dom.exposure != ChildExposureV1::FirstSecretExposure
                    || counterparty.exposure != ChildExposureV1::UsesPublicSecret
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                router.materialize_child(SettlementFaceV1::Dom, dom, None)
            }
            FinalClaimRevealModeV1::DomReactsToCounterpartyReveal => {
                Err(ChildAuthorityRefusalV1::Conflict)
            }
        }
    }
}

fn validate_first_exposure_scope(
    expected: FirstExposureAuthorityBindingsV1,
    request: &ProductionFirstExposureClaimRequestV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    let dom = request.dom;
    let counterparty = request.counterparty;
    if !matches!(
        request.counterparty_face,
        SettlementFaceV1::Evm | SettlementFaceV1::Bitcoin
    ) {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let expected_first = match expected.reveal_mode {
        FinalClaimRevealModeV1::DomRevealsFirst => SettlementFaceV1::Dom,
        FinalClaimRevealModeV1::DomReactsToCounterpartyReveal => request.counterparty_face,
    };
    if request.role_plan_digest != expected.role_plan_digest
        || request.source_scope_digest != expected.source_scope_digest
        || request.first_face != expected_first
        || dom.route_id != expected.route_id
        || counterparty.route_id != expected.route_id
        || dom.composition_digest != expected.composition_digest
        || counterparty.composition_digest != expected.composition_digest
        || dom.role_plan_digest != expected.role_plan_digest
        || counterparty.role_plan_digest != expected.role_plan_digest
        || dom.source_scope_digest != expected.source_scope_digest
        || counterparty.source_scope_digest != expected.source_scope_digest
        || dom.route_scope_digest != expected.route_scope_digest
        || counterparty.route_scope_digest != expected.route_scope_digest
        || dom.terms_digest != expected.terms_digest
        || counterparty.terms_digest != expected.terms_digest
        || dom.registry_digest != expected.registry_digest
        || counterparty.registry_digest != expected.registry_digest
        || dom.leg != SettlementLegV1::Downstream
        || counterparty.leg != SettlementLegV1::Downstream
        || dom.action != SettlementActionV1::Claim
        || counterparty.action != SettlementActionV1::Claim
        || dom.effect_id != counterparty.effect_id
        || dom.fencing_epoch != counterparty.fencing_epoch
        || dom.semantic_digest != counterparty.semantic_digest
        || dom.settlement_id != counterparty.settlement_id
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

struct SharedProductionSettlementRouterV1 {
    slot: Rc<Cell<Option<ProductionSettlementChildRouterV1>>>,
}

struct ProductionRouterRestoreGuardV1<'owner> {
    slot: &'owner Cell<Option<ProductionSettlementChildRouterV1>>,
    router: Option<ProductionSettlementChildRouterV1>,
}

impl ProductionRouterRestoreGuardV1<'_> {
    fn router(
        &mut self,
    ) -> Result<&mut ProductionSettlementChildRouterV1, ChildAuthorityRefusalV1> {
        self.router
            .as_mut()
            .ok_or(ChildAuthorityRefusalV1::Conflict)
    }
}

impl Drop for ProductionRouterRestoreGuardV1<'_> {
    fn drop(&mut self) {
        if let Some(router) = self.router.take() {
            self.slot.set(Some(router));
        }
    }
}

impl SharedProductionSettlementRouterV1 {
    fn with_router<T>(
        &self,
        operation: impl FnOnce(
            &mut ProductionSettlementChildRouterV1,
        ) -> Result<T, ChildAuthorityRefusalV1>,
    ) -> Result<T, ChildAuthorityRefusalV1> {
        let router = self
            .slot
            .take()
            .ok_or(ChildAuthorityRefusalV1::Unavailable)?;
        let mut guard = ProductionRouterRestoreGuardV1 {
            slot: self.slot.as_ref(),
            router: Some(router),
        };
        operation(guard.router()?)
    }
}

/// One-shot owner of the single materializer/router authority graph.
pub(crate) struct ProductionSettlementMaterializationOwnerV1 {
    materializer: ProductionSettlementDraftMaterializerV2,
    runtime: ProductionSettlementChildRuntimeHandleV1,
}

impl ProductionSettlementMaterializationOwnerV1 {
    pub(crate) fn authenticate(
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: ComposedFinalClaimRolePlanV1,
        upstream_scope: FinalClaimSecretSourceScopeV1,
        downstream_scope: FinalClaimSecretSourceScopeV1,
        router: ProductionSettlementChildRouterV1,
        first_exposure: ProductionCustodiedFirstExposureClaimAuthorityV1,
    ) -> Result<Self, AuthorityRefusalV1> {
        let admission = inputs.admission();
        let composition = inputs.composition();
        if role_plan.route_id() != admission.route_id()
            || role_plan.route_scope_digest() != composition.route_scope_digest()
            || role_plan.composition_binding_digest() != composition.binding_digest()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        role_plan
            .authenticate(
                composition.upstream(),
                composition.downstream(),
                upstream_scope,
                downstream_scope,
            )
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        let dom = admission
            .dom_deployment_capability()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        let upstream = authenticate_leg(inputs, &role_plan, LegIdV1::Upstream)?;
        let downstream = authenticate_leg(inputs, &role_plan, LegIdV1::Downstream)?;
        if upstream.secret_source != FinalClaimSecretSourceV1::VerifiedCounterpartyClaim
            || upstream.reveal_mode != FinalClaimRevealModeV1::DomReactsToCounterpartyReveal
            || downstream.secret_source != FinalClaimSecretSourceV1::LocalOrigin
            || downstream.reveal_mode != FinalClaimRevealModeV1::DomRevealsFirst
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let route_id = admission.route_id();
        let route_scope_digest = composition.route_scope_digest();
        let composition_digest = composition.binding_digest();
        let role_plan_digest = role_plan.digest();
        let materializer_authority_id = digest_parts(
            DEFERRED_MATERIALIZER_AUTHORITY_DOMAIN_V1,
            &[
                &route_id,
                &route_scope_digest,
                &composition_digest,
                &role_plan_digest,
                &downstream.settlement_id,
                &downstream.counterparty_chain_id,
                &downstream.counterparty_profile_digest,
                &downstream.counterparty_deployment_digest,
                &downstream.source_scope_digest,
            ],
        )?;
        let shared = Rc::new(Cell::new(Some(router)));
        Ok(Self {
            materializer: ProductionSettlementDraftMaterializerV2 {
                route_id,
                frozen_terms_digest: admission.frozen_bindings().terms_digest,
                expected_profile_bundle_digest: admission.frozen_bindings().profile_bundle_digest,
                expected_deployment_bundle_digest: admission
                    .frozen_bindings()
                    .deployment_bundle_digest,
                registry_digest: admission.registry_digest(),
                dom_profile_digest: admission.dom_profile_digest(),
                dom_deployment_digest: dom.registry_digest(),
                route_scope_digest,
                composition_digest,
                role_plan_digest,
                materializer_authority_id,
                legs: [upstream, downstream],
                router: SharedProductionSettlementRouterV1 {
                    slot: Rc::clone(&shared),
                },
                first_exposure,
            },
            runtime: ProductionSettlementChildRuntimeHandleV1 {
                router: SharedProductionSettlementRouterV1 { slot: shared },
            },
        })
    }

    pub(crate) fn split(
        self,
    ) -> (
        ProductionSettlementDraftMaterializerV2,
        ProductionSettlementChildRuntimeHandleV1,
    ) {
        (self.materializer, self.runtime)
    }
}

/// Concrete durable materializer consumed by the verified plan source.
pub(crate) struct ProductionSettlementDraftMaterializerV2 {
    route_id: Digest32,
    frozen_terms_digest: Digest32,
    expected_profile_bundle_digest: Digest32,
    expected_deployment_bundle_digest: Digest32,
    registry_digest: Digest32,
    dom_profile_digest: Digest32,
    dom_deployment_digest: Digest32,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    materializer_authority_id: Digest32,
    legs: [ProductionLegMaterializationBindingsV1; 2],
    router: SharedProductionSettlementRouterV1,
    first_exposure: ProductionCustodiedFirstExposureClaimAuthorityV1,
}

impl core::fmt::Debug for ProductionSettlementDraftMaterializerV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSettlementDraftMaterializerV2([authorities redacted])")
    }
}

/// Runtime-only handle sharing the same physical router used for preparation.
pub(crate) struct ProductionSettlementChildRuntimeHandleV1 {
    router: SharedProductionSettlementRouterV1,
}

impl SettlementChildAuthorityV1 for ProductionSettlementChildRuntimeHandleV1 {
    fn externalize_child(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        self.router
            .with_router(|router| router.externalize_child(request))
    }

    fn reconcile_child(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        self.router
            .with_router(|router| router.reconcile_child(request))
    }
}

impl SettlementChildObserverV1 for ProductionSettlementChildRuntimeHandleV1 {
    fn observe_child(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.router
            .with_router(|router| router.observe_child(request))
    }
}

impl ProductionSettlementDraftMaterializerV1 for ProductionSettlementDraftMaterializerV2 {
    fn deferred_materializer_authority_id(&self) -> Digest32 {
        self.materializer_authority_id
    }

    fn materialize_without_preexisting_secret(
        &mut self,
        composition: &ComposedBindingV2,
        request: &RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ProductionSettlementPlanDraftV1, AuthorityRefusalV1> {
        self.require_scope(composition, request)?;
        let leg = self.leg(request.leg());
        let semantic = self.semantic_digest(request.leg(), request.action(), leg)?;
        let effect = derive_effect_id_v1(
            request.route_id(),
            request.event_id(),
            request.fencing_epoch(),
            request.leg(),
            request.action(),
            semantic,
        );
        let (secret_requirement, children) = match request.action() {
            ActionKindV1::Funding | ActionKindV1::Refund => {
                let pair = self.materialize_nonsecret_pair(request, leg, semantic, effect)?;
                (
                    SecretRequirementV1::None,
                    SettlementChildrenV1::Materialized(pair),
                )
            }
            ActionKindV1::Claim => {
                if request.snapshot().secret_visibility != SecretVisibilityV1::Private
                    || request.leg() != LegIdV1::Downstream
                    || leg.secret_source != FinalClaimSecretSourceV1::LocalOrigin
                {
                    return Err(AuthorityRefusalV1::Inconsistent);
                }
                let staged = self.materialize_first_exposure(request, leg, semantic, effect)?;
                (SecretRequirementV1::FirstExposureRequired, staged)
            }
        };
        self.draft(leg, semantic, secret_requirement, None, children)
    }

    fn materialize_with_verified_public_secret(
        &mut self,
        composition: &ComposedBindingV2,
        request: &RouteActionAuthorizationRequestV1<'_>,
        scalar: RouteScalar,
    ) -> Result<ProductionSettlementPlanDraftV1, AuthorityRefusalV1> {
        self.require_scope(composition, request)?;
        let SecretVisibilityV1::Public { first_exposure } = &request.snapshot().secret_visibility
        else {
            return Err(AuthorityRefusalV1::Inconsistent);
        };
        if request.action() != ActionKindV1::Claim || request.leg() != LegIdV1::Upstream {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let leg = self.leg(request.leg());
        if leg.secret_source != FinalClaimSecretSourceV1::VerifiedCounterpartyClaim {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let semantic = self.semantic_digest(request.leg(), request.action(), leg)?;
        let effect = derive_effect_id_v1(
            request.route_id(),
            request.event_id(),
            request.fencing_epoch(),
            request.leg(),
            request.action(),
            semantic,
        );
        let counterparty = self.child_request(
            request,
            leg,
            semantic,
            effect,
            ChildExposureV1::UsesPublicSecret,
            false,
        );
        let dom = self.child_request(
            request,
            leg,
            semantic,
            effect,
            ChildExposureV1::UsesPublicSecret,
            true,
        );
        let children = self
            .router
            .with_router(|router| {
                let counterparty_plan =
                    router.materialize_child(leg.counterparty_face, counterparty, Some(&scalar))?;
                let dom_plan =
                    router.materialize_child(SettlementFaceV1::Dom, dom, Some(&scalar))?;
                Ok([counterparty_plan, dom_plan])
            })
            .map_err(map_child_refusal)?;
        self.validate_pair(
            leg,
            &children,
            [
                ChildExposureV1::UsesPublicSecret,
                ChildExposureV1::UsesPublicSecret,
            ],
            leg.counterparty_face,
        )?;
        self.draft(
            leg,
            semantic,
            SecretRequirementV1::AlreadyPublic,
            Some(first_exposure.evidence_digest),
            SettlementChildrenV1::Materialized(children),
        )
    }

    fn materialize_deferred_with_verified_public_secret(
        &mut self,
        composition: &ComposedBindingV2,
        capability: &DeferredChildMaterializationCapabilityV1,
        scalar: RouteScalar,
    ) -> Result<SettlementChildPlanV1, AuthorityRefusalV1> {
        let bindings = capability.bindings();
        let descriptor = capability.descriptor();
        if capability.route_id() != self.route_id
            || bindings.route_id != self.route_id
            || bindings.leg != SettlementLegV1::Downstream
            || bindings.action != SettlementActionV1::Claim
            || bindings.settlement_id != self.legs[1].settlement_id
            || bindings.terms_digest != self.frozen_terms_digest
            || bindings.registry_digest != self.registry_digest
            || bindings.dom_profile_digest != self.dom_profile_digest
            || bindings.dom_deployment_digest != self.dom_deployment_digest
            || bindings.counterparty_profile_digest != self.legs[1].counterparty_profile_digest
            || bindings.counterparty_deployment_digest
                != self.legs[1].counterparty_deployment_digest
            || descriptor.face != self.legs[1].counterparty_face
            || descriptor.chain_id != self.legs[1].counterparty_chain_id
            || descriptor.route_scope_digest != self.route_scope_digest
            || descriptor.composition_digest != self.composition_digest
            || descriptor.role_plan_digest != self.role_plan_digest
            || descriptor.source_scope_digest != self.legs[1].source_scope_digest
            || descriptor.materializer_authority_id != self.materializer_authority_id
            || composition.binding_digest() != self.composition_digest
            || composition.route_scope_digest() != self.route_scope_digest
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let rebound = composition
            .verify_revealed_scalar(scalar.expose())
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        let request = ProductionChildMaterializationRequestV1 {
            route_id: bindings.route_id,
            effect_id: bindings.effect_id,
            settlement_id: bindings.settlement_id,
            leg: bindings.leg,
            action: bindings.action,
            fencing_epoch: bindings.fencing_epoch,
            semantic_digest: bindings.semantic_digest,
            terms_digest: bindings.terms_digest,
            registry_digest: bindings.registry_digest,
            profile_digest: bindings.counterparty_profile_digest,
            deployment_digest: bindings.counterparty_deployment_digest,
            route_scope_digest: descriptor.route_scope_digest,
            composition_digest: descriptor.composition_digest,
            role_plan_digest: descriptor.role_plan_digest,
            source_scope_digest: descriptor.source_scope_digest,
            exposure: ChildExposureV1::UsesPublicSecret,
        };
        let result = self
            .router
            .with_router(|router| {
                router.materialize_child(descriptor.face, request, Some(&rebound))
            })
            .map_err(map_child_refusal)?;
        if result.face != descriptor.face
            || result.exposure != ChildExposureV1::UsesPublicSecret
            || result.chain_id != descriptor.chain_id
            || result.expected_transaction_id == ZERO_DIGEST
            || result.intent_digest == ZERO_DIGEST
            || result.custody_digest == ZERO_DIGEST
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(result)
    }
}

impl ProductionSettlementDraftMaterializerV2 {
    fn require_scope(
        &self,
        composition: &ComposedBindingV2,
        request: &RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<(), AuthorityRefusalV1> {
        if request.route_id() != self.route_id
            || request.snapshot().route_id != self.route_id
            || request.bindings().terms_digest != self.frozen_terms_digest
            || request.bindings().profile_bundle_digest != self.expected_profile_bundle_digest
            || request.bindings().deployment_bundle_digest != self.expected_deployment_bundle_digest
            || composition.binding_digest() != self.composition_digest
            || composition.route_scope_digest() != self.route_scope_digest
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(())
    }

    const fn leg(&self, leg: LegIdV1) -> ProductionLegMaterializationBindingsV1 {
        match leg {
            LegIdV1::Upstream => self.legs[0],
            LegIdV1::Downstream => self.legs[1],
        }
    }

    fn semantic_digest(
        &self,
        route_leg: LegIdV1,
        action: ActionKindV1,
        leg: ProductionLegMaterializationBindingsV1,
    ) -> Result<Digest32, AuthorityRefusalV1> {
        digest_parts(
            SEMANTIC_DOMAIN_V1,
            &[
                &self.route_id,
                &self.route_scope_digest,
                &self.composition_digest,
                &self.role_plan_digest,
                &leg.settlement_id,
                &[route_leg_tag(route_leg)],
                &[action_tag(action)],
                &self.frozen_terms_digest,
                &self.registry_digest,
                &self.dom_profile_digest,
                &self.dom_deployment_digest,
                &leg.counterparty_profile_digest,
                &leg.counterparty_deployment_digest,
                &leg.source_scope_digest,
            ],
        )
    }

    fn child_request(
        &self,
        request: &RouteActionAuthorizationRequestV1<'_>,
        leg: ProductionLegMaterializationBindingsV1,
        semantic_digest: Digest32,
        effect_id: Digest32,
        exposure: ChildExposureV1,
        dom: bool,
    ) -> ProductionChildMaterializationRequestV1 {
        ProductionChildMaterializationRequestV1 {
            route_id: self.route_id,
            effect_id,
            settlement_id: leg.settlement_id,
            leg: settlement_leg(request.leg()),
            action: settlement_action(request.action()),
            fencing_epoch: request.fencing_epoch(),
            semantic_digest,
            terms_digest: self.frozen_terms_digest,
            registry_digest: self.registry_digest,
            profile_digest: if dom {
                self.dom_profile_digest
            } else {
                leg.counterparty_profile_digest
            },
            deployment_digest: if dom {
                self.dom_deployment_digest
            } else {
                leg.counterparty_deployment_digest
            },
            route_scope_digest: self.route_scope_digest,
            composition_digest: self.composition_digest,
            role_plan_digest: self.role_plan_digest,
            source_scope_digest: leg.source_scope_digest,
            exposure,
        }
    }

    fn materialize_nonsecret_pair(
        &self,
        request: &RouteActionAuthorizationRequestV1<'_>,
        leg: ProductionLegMaterializationBindingsV1,
        semantic: Digest32,
        effect: Digest32,
    ) -> Result<[SettlementChildPlanV1; 2], AuthorityRefusalV1> {
        let counterparty = self.child_request(
            request,
            leg,
            semantic,
            effect,
            ChildExposureV1::NonSecret,
            false,
        );
        let dom = self.child_request(
            request,
            leg,
            semantic,
            effect,
            ChildExposureV1::NonSecret,
            true,
        );
        let children = self
            .router
            .with_router(|router| {
                let first = router.materialize_child(leg.counterparty_face, counterparty, None)?;
                let second = router.materialize_child(SettlementFaceV1::Dom, dom, None)?;
                Ok([first, second])
            })
            .map_err(map_child_refusal)?;
        self.validate_pair(
            leg,
            &children,
            [ChildExposureV1::NonSecret, ChildExposureV1::NonSecret],
            leg.counterparty_face,
        )?;
        Ok(children)
    }

    fn materialize_first_exposure(
        &mut self,
        request: &RouteActionAuthorizationRequestV1<'_>,
        leg: ProductionLegMaterializationBindingsV1,
        semantic: Digest32,
        effect: Digest32,
    ) -> Result<SettlementChildrenV1, AuthorityRefusalV1> {
        let first_face = match leg.reveal_mode {
            FinalClaimRevealModeV1::DomRevealsFirst => SettlementFaceV1::Dom,
            FinalClaimRevealModeV1::DomReactsToCounterpartyReveal => leg.counterparty_face,
        };
        let dom_exposure = if first_face == SettlementFaceV1::Dom {
            ChildExposureV1::FirstSecretExposure
        } else {
            ChildExposureV1::UsesPublicSecret
        };
        let counterparty_exposure = if first_face == leg.counterparty_face {
            ChildExposureV1::FirstSecretExposure
        } else {
            ChildExposureV1::UsesPublicSecret
        };
        let authority_request = ProductionFirstExposureClaimRequestV1 {
            role_plan_digest: self.role_plan_digest,
            source_scope_digest: leg.source_scope_digest,
            first_face,
            counterparty_face: leg.counterparty_face,
            dom: self.child_request(request, leg, semantic, effect, dom_exposure, true),
            counterparty: self.child_request(
                request,
                leg,
                semantic,
                effect,
                counterparty_exposure,
                false,
            ),
        };
        let first_exposure = &mut self.first_exposure;
        let first = self
            .router
            .with_router(|router| {
                first_exposure.materialize_first_exposure(authority_request, router)
            })
            .map_err(map_child_refusal)?;
        if first.face != SettlementFaceV1::Dom
            || first.exposure != ChildExposureV1::FirstSecretExposure
            || first.chain_id == ZERO_DIGEST
            || first.expected_transaction_id == ZERO_DIGEST
            || first.intent_digest == ZERO_DIGEST
            || first.custody_digest == ZERO_DIGEST
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(SettlementChildrenV1::FirstExposureStaged {
            first,
            deferred: DeferredSettlementChildV1 {
                face: leg.counterparty_face,
                chain_id: leg.counterparty_chain_id,
                route_scope_digest: self.route_scope_digest,
                composition_digest: self.composition_digest,
                role_plan_digest: self.role_plan_digest,
                source_scope_digest: leg.source_scope_digest,
                materializer_authority_id: self.materializer_authority_id,
            },
        })
    }

    fn validate_pair(
        &self,
        leg: ProductionLegMaterializationBindingsV1,
        children: &[SettlementChildPlanV1; 2],
        exposures: [ChildExposureV1; 2],
        first_face: SettlementFaceV1,
    ) -> Result<(), AuthorityRefusalV1> {
        let expected_second = if first_face == SettlementFaceV1::Dom {
            leg.counterparty_face
        } else {
            SettlementFaceV1::Dom
        };
        if children[0].face != first_face
            || children[1].face != expected_second
            || children[0].exposure != exposures[0]
            || children[1].exposure != exposures[1]
            || children.iter().any(|child| {
                child.chain_id == ZERO_DIGEST
                    || child.expected_transaction_id == ZERO_DIGEST
                    || child.intent_digest == ZERO_DIGEST
                    || child.custody_digest == ZERO_DIGEST
            })
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(())
    }

    fn draft(
        &self,
        leg: ProductionLegMaterializationBindingsV1,
        semantic_digest: Digest32,
        secret_requirement: SecretRequirementV1,
        preexisting_secret_evidence_digest: Option<Digest32>,
        children: SettlementChildrenV1,
    ) -> Result<ProductionSettlementPlanDraftV1, AuthorityRefusalV1> {
        if preexisting_secret_evidence_digest.is_some_and(|digest| digest == ZERO_DIGEST) {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(ProductionSettlementPlanDraftV1 {
            settlement_id: leg.settlement_id,
            semantic_digest,
            registry_digest: self.registry_digest,
            expected_route_profile_bundle_digest: self.expected_profile_bundle_digest,
            expected_route_deployment_bundle_digest: self.expected_deployment_bundle_digest,
            dom_profile_digest: self.dom_profile_digest,
            dom_deployment_digest: self.dom_deployment_digest,
            counterparty_profile_digest: leg.counterparty_profile_digest,
            counterparty_deployment_digest: leg.counterparty_deployment_digest,
            secret_requirement,
            preexisting_secret_evidence_digest,
            children,
        })
    }
}

fn authenticate_leg(
    inputs: &AuthenticatedProductionInputsV1,
    role_plan: &ComposedFinalClaimRolePlanV1,
    leg: LegIdV1,
) -> Result<ProductionLegMaterializationBindingsV1, AuthorityRefusalV1> {
    let admission = inputs.admission();
    let composition = inputs.composition();
    let (settlement, plan_leg) = match leg {
        LegIdV1::Upstream => (composition.upstream(), ComposedSettlementLegV1::Upstream),
        LegIdV1::Downstream => (
            composition.downstream(),
            ComposedSettlementLegV1::Downstream,
        ),
    };
    let entry = role_plan.entry(plan_leg);
    if entry.settlement_id().0 != settlement.settlement_id.0
        || entry.session_id().0 != settlement.session_id.0
        || !matches!(
            (entry.reveal_mode(), entry.secret_source()),
            (
                FinalClaimRevealModeV1::DomRevealsFirst,
                FinalClaimSecretSourceV1::LocalOrigin
            ) | (
                FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
                FinalClaimSecretSourceV1::VerifiedCounterpartyClaim
            )
        )
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    let (counterparty_face, profile, deployment) = if let Some(session) = inputs.evm_session(leg) {
        let resolved = admission
            .evm_deployment_capability(leg, session)
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        (
            SettlementFaceV1::Evm,
            resolved.profile_digest(),
            resolved.deployment().deployment_digest,
        )
    } else if inputs.bitcoin_session(leg).is_some() {
        let resolved = admission
            .bitcoin_deployment_capability(leg)
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        (
            SettlementFaceV1::Bitcoin,
            resolved.profile_digest(),
            btc_actuator::resolved_bitcoin_deployment_digest_v1(&resolved)
                .map_err(|_| AuthorityRefusalV1::Inconsistent)?,
        )
    } else {
        return Err(AuthorityRefusalV1::Inconsistent);
    };
    let admission_profile = match leg {
        LegIdV1::Upstream => admission.upstream_profile_digest(),
        LegIdV1::Downstream => admission.downstream_profile_digest(),
    };
    if profile != admission_profile || entry.secret_source_scope_digest() == ZERO_DIGEST {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(ProductionLegMaterializationBindingsV1 {
        settlement_id: settlement.settlement_id.0,
        counterparty_face,
        counterparty_chain_id: settlement.counterparty_leg.chain_id.0,
        counterparty_profile_digest: profile,
        counterparty_deployment_digest: deployment,
        source_scope_digest: entry.secret_source_scope_digest(),
        reveal_mode: entry.reveal_mode(),
        secret_source: entry.secret_source(),
    })
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, AuthorityRefusalV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| AuthorityRefusalV1::Unavailable)?;
    hasher.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| AuthorityRefusalV1::Unavailable)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| AuthorityRefusalV1::Unavailable)?;
    if output == ZERO_DIGEST {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(output)
}

fn first_exposure_request_digest(
    request: &ProductionFirstExposureClaimRequestV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let first_face = [face_tag(request.first_face)];
    let counterparty_face = [face_tag(request.counterparty_face)];
    let dom = child_materialization_digest(&request.dom)?;
    let counterparty = child_materialization_digest(&request.counterparty)?;
    digest_parts(
        FIRST_EXPOSURE_REQUEST_DOMAIN_V1,
        &[
            &request.role_plan_digest,
            &request.source_scope_digest,
            first_face.as_slice(),
            counterparty_face.as_slice(),
            &dom,
            &counterparty,
        ],
    )
    .map_err(|error| match error {
        AuthorityRefusalV1::Unavailable => ChildAuthorityRefusalV1::Unavailable,
        AuthorityRefusalV1::Refused => ChildAuthorityRefusalV1::Refused,
        AuthorityRefusalV1::Inconsistent => ChildAuthorityRefusalV1::Conflict,
    })
}

fn child_materialization_digest(
    request: &ProductionChildMaterializationRequestV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let leg = [settlement_leg_tag(request.leg)];
    let action = [settlement_action_tag(request.action)];
    let exposure = [exposure_tag(request.exposure)];
    let fencing = request.fencing_epoch.to_be_bytes();
    digest_parts(
        CHILD_MATERIALIZATION_REQUEST_DOMAIN_V1,
        &[
            &request.route_id,
            &request.effect_id,
            &request.settlement_id,
            leg.as_slice(),
            action.as_slice(),
            fencing.as_slice(),
            &request.semantic_digest,
            &request.terms_digest,
            &request.registry_digest,
            &request.profile_digest,
            &request.deployment_digest,
            &request.route_scope_digest,
            &request.composition_digest,
            &request.role_plan_digest,
            &request.source_scope_digest,
            exposure.as_slice(),
        ],
    )
    .map_err(|error| match error {
        AuthorityRefusalV1::Unavailable => ChildAuthorityRefusalV1::Unavailable,
        AuthorityRefusalV1::Refused => ChildAuthorityRefusalV1::Refused,
        AuthorityRefusalV1::Inconsistent => ChildAuthorityRefusalV1::Conflict,
    })
}

const fn route_leg_tag(leg: LegIdV1) -> u8 {
    match leg {
        LegIdV1::Upstream => 1,
        LegIdV1::Downstream => 2,
    }
}

const fn action_tag(action: ActionKindV1) -> u8 {
    match action {
        ActionKindV1::Funding => 1,
        ActionKindV1::Claim => 2,
        ActionKindV1::Refund => 3,
    }
}

const fn settlement_leg(leg: LegIdV1) -> SettlementLegV1 {
    match leg {
        LegIdV1::Upstream => SettlementLegV1::Upstream,
        LegIdV1::Downstream => SettlementLegV1::Downstream,
    }
}

const fn settlement_action(action: ActionKindV1) -> SettlementActionV1 {
    match action {
        ActionKindV1::Funding => SettlementActionV1::Funding,
        ActionKindV1::Claim => SettlementActionV1::Claim,
        ActionKindV1::Refund => SettlementActionV1::Refund,
    }
}

const fn settlement_leg_tag(leg: SettlementLegV1) -> u8 {
    match leg {
        SettlementLegV1::Upstream => 1,
        SettlementLegV1::Downstream => 2,
    }
}

const fn settlement_action_tag(action: SettlementActionV1) -> u8 {
    match action {
        SettlementActionV1::Funding => 1,
        SettlementActionV1::Claim => 2,
        SettlementActionV1::Refund => 3,
    }
}

const fn exposure_tag(exposure: ChildExposureV1) -> u8 {
    match exposure {
        ChildExposureV1::NonSecret => 1,
        ChildExposureV1::FirstSecretExposure => 2,
        ChildExposureV1::UsesPublicSecret => 3,
    }
}

const fn face_tag(face: SettlementFaceV1) -> u8 {
    match face {
        SettlementFaceV1::Dom => 1,
        SettlementFaceV1::Evm => 2,
        SettlementFaceV1::Bitcoin => 3,
        SettlementFaceV1::Monero => 4,
        SettlementFaceV1::Solana => 5,
    }
}

const fn map_child_refusal(error: ChildAuthorityRefusalV1) -> AuthorityRefusalV1 {
    match error {
        ChildAuthorityRefusalV1::Unavailable => AuthorityRefusalV1::Unavailable,
        ChildAuthorityRefusalV1::Refused => AuthorityRefusalV1::Refused,
        ChildAuthorityRefusalV1::Conflict => AuthorityRefusalV1::Inconsistent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(ProductionCustodiedFirstExposureClaimAuthorityV1: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(ProductionSettlementMaterializationOwnerV1: Clone, Copy);
    assert_not_impl_any!(ProductionSettlementDraftMaterializerV2: Clone, Copy);
    assert_not_impl_any!(ProductionSettlementChildRuntimeHandleV1: Clone, Copy);

    struct MaterializingPortV1 {
        face: SettlementFaceV1,
        calls: Rc<Cell<u64>>,
    }

    impl crate::production_child_router::ProductionSettlementChildPortV1 for MaterializingPortV1 {
        fn face(&self) -> SettlementFaceV1 {
            self.face
        }

        fn materialize(
            &mut self,
            request: ProductionChildMaterializationRequestV1,
            _public_scalar: Option<&RouteScalar>,
        ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
            self.calls.set(self.calls.get().saturating_add(1));
            Ok(SettlementChildPlanV1 {
                face: self.face,
                exposure: request.exposure,
                chain_id: [0x51; 32],
                expected_transaction_id: [0x52; 32],
                intent_digest: [0x53; 32],
                custody_digest: [0x54; 32],
            })
        }

        fn externalize(
            &mut self,
            _request: &ChildDispatchRequestV1,
        ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
            Err(ChildAuthorityRefusalV1::Refused)
        }

        fn reconcile(
            &mut self,
            _request: &ChildReconciliationRequestV1,
        ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
            Err(ChildAuthorityRefusalV1::Refused)
        }

        fn observe(
            &mut self,
            _request: &ChildObservationRequestV1,
        ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
            Err(ChildAuthorityRefusalV1::Refused)
        }
    }

    fn request(face_seed: u8) -> ProductionChildMaterializationRequestV1 {
        ProductionChildMaterializationRequestV1 {
            route_id: [1; 32],
            effect_id: [2; 32],
            settlement_id: [3; 32],
            leg: SettlementLegV1::Downstream,
            action: SettlementActionV1::Claim,
            fencing_epoch: 4,
            semantic_digest: [5; 32],
            terms_digest: [6; 32],
            registry_digest: [7; 32],
            profile_digest: [face_seed; 32],
            deployment_digest: [9; 32],
            route_scope_digest: [10; 32],
            composition_digest: [11; 32],
            role_plan_digest: [12; 32],
            source_scope_digest: [13; 32],
            exposure: ChildExposureV1::FirstSecretExposure,
        }
    }

    #[test]
    fn router_is_restored_after_operation_error_and_reentrant_call_refuses(
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let dom_calls = Rc::new(Cell::new(0));
        let evm_calls = Rc::new(Cell::new(0));
        let router = ProductionSettlementChildRouterV1::new_test(
            Box::new(MaterializingPortV1 {
                face: SettlementFaceV1::Dom,
                calls: Rc::clone(&dom_calls),
            }),
            Some(Box::new(MaterializingPortV1 {
                face: SettlementFaceV1::Evm,
                calls: Rc::clone(&evm_calls),
            })),
            None,
        )?;
        let slot = Rc::new(Cell::new(Some(router)));
        let shared = SharedProductionSettlementRouterV1 {
            slot: Rc::clone(&slot),
        };
        let reentrant = SharedProductionSettlementRouterV1 { slot };
        let first: Result<(), ChildAuthorityRefusalV1> = shared.with_router(|_| {
            assert_eq!(
                reentrant.with_router(|_| Ok(())),
                Err(ChildAuthorityRefusalV1::Unavailable)
            );
            Err(ChildAuthorityRefusalV1::Conflict)
        });
        assert_eq!(first, Err(ChildAuthorityRefusalV1::Conflict));
        let second = shared.with_router(|router| {
            router.materialize_child(SettlementFaceV1::Dom, request(8), None)
        });
        assert!(second.is_ok());
        assert_eq!(dom_calls.get(), 1);
        assert_eq!(evm_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn first_exposure_request_digest_rejects_every_scope_transplant() {
        let baseline = ProductionFirstExposureClaimRequestV1 {
            role_plan_digest: [21; 32],
            source_scope_digest: [22; 32],
            first_face: SettlementFaceV1::Dom,
            counterparty_face: SettlementFaceV1::Evm,
            dom: request(23),
            counterparty: ProductionChildMaterializationRequestV1 {
                exposure: ChildExposureV1::UsesPublicSecret,
                ..request(24)
            },
        };
        let first = first_exposure_request_digest(&baseline);
        assert!(first.is_ok());
        let mut transplanted = baseline;
        transplanted.counterparty.fencing_epoch = 5;
        assert_ne!(
            first,
            first_exposure_request_digest(&transplanted),
            "fencing transplant must alter the exact authority request"
        );
        transplanted = baseline;
        transplanted.dom.effect_id = [25; 32];
        assert_ne!(first, first_exposure_request_digest(&transplanted));
        transplanted = baseline;
        transplanted.source_scope_digest = [26; 32];
        assert_ne!(first, first_exposure_request_digest(&transplanted));
        transplanted = baseline;
        transplanted.counterparty_face = SettlementFaceV1::Bitcoin;
        assert_ne!(first, first_exposure_request_digest(&transplanted));
    }

    #[test]
    fn first_exposure_authority_rejects_each_common_scope_transplant() {
        let baseline = ProductionFirstExposureClaimRequestV1 {
            role_plan_digest: [12; 32],
            source_scope_digest: [13; 32],
            first_face: SettlementFaceV1::Dom,
            counterparty_face: SettlementFaceV1::Evm,
            dom: request(23),
            counterparty: ProductionChildMaterializationRequestV1 {
                exposure: ChildExposureV1::UsesPublicSecret,
                ..request(24)
            },
        };
        let expected = FirstExposureAuthorityBindingsV1 {
            route_id: [1; 32],
            composition_digest: [11; 32],
            role_plan_digest: [12; 32],
            source_scope_digest: [13; 32],
            route_scope_digest: [10; 32],
            terms_digest: [6; 32],
            registry_digest: [7; 32],
            reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
        };
        assert_eq!(validate_first_exposure_scope(expected, &baseline), Ok(()));

        let mut variants = Vec::new();
        let mut transplanted = baseline;
        transplanted.dom.route_scope_digest = [31; 32];
        variants.push(transplanted);
        transplanted = baseline;
        transplanted.counterparty.route_scope_digest = [32; 32];
        variants.push(transplanted);
        transplanted = baseline;
        transplanted.dom.terms_digest = [33; 32];
        variants.push(transplanted);
        transplanted = baseline;
        transplanted.counterparty.terms_digest = [34; 32];
        variants.push(transplanted);
        transplanted = baseline;
        transplanted.dom.registry_digest = [35; 32];
        variants.push(transplanted);
        transplanted = baseline;
        transplanted.counterparty.registry_digest = [36; 32];
        variants.push(transplanted);
        transplanted = baseline;
        transplanted.dom.composition_digest = [37; 32];
        variants.push(transplanted);
        transplanted = baseline;
        transplanted.counterparty.source_scope_digest = [38; 32];
        variants.push(transplanted);

        for variant in variants {
            assert_eq!(
                validate_first_exposure_scope(expected, &variant),
                Err(ChildAuthorityRefusalV1::Conflict)
            );
        }
    }

    #[test]
    fn private_first_exposure_materializes_only_dom_and_never_borrows_a_scalar(
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let dom_calls = Rc::new(Cell::new(0));
        let evm_calls = Rc::new(Cell::new(0));
        let mut router = ProductionSettlementChildRouterV1::new_test(
            Box::new(MaterializingPortV1 {
                face: SettlementFaceV1::Dom,
                calls: Rc::clone(&dom_calls),
            }),
            Some(Box::new(MaterializingPortV1 {
                face: SettlementFaceV1::Evm,
                calls: Rc::clone(&evm_calls),
            })),
            None,
        )?;
        let mut authority = ProductionCustodiedFirstExposureClaimAuthorityV1 {
            route_id: [1; 32],
            composition_digest: [11; 32],
            role_plan_digest: [12; 32],
            source_scope_digest: [13; 32],
            route_scope_digest: [10; 32],
            terms_digest: [6; 32],
            registry_digest: [7; 32],
            reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
        };
        let request = ProductionFirstExposureClaimRequestV1 {
            role_plan_digest: [12; 32],
            source_scope_digest: [13; 32],
            first_face: SettlementFaceV1::Dom,
            counterparty_face: SettlementFaceV1::Evm,
            dom: request(23),
            counterparty: ProductionChildMaterializationRequestV1 {
                exposure: ChildExposureV1::UsesPublicSecret,
                ..request(24)
            },
        };

        let first = authority.materialize_first_exposure(request, &mut router)?;
        assert_eq!(first.face, SettlementFaceV1::Dom);
        assert_eq!(first.exposure, ChildExposureV1::FirstSecretExposure);
        assert_eq!(dom_calls.get(), 1);
        assert_eq!(evm_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn outer_and_child_materialization_domains_are_distinct() {
        assert_ne!(
            FIRST_EXPOSURE_REQUEST_DOMAIN_V1,
            CHILD_MATERIALIZATION_REQUEST_DOMAIN_V1
        );
        assert_ne!(
            DEFERRED_MATERIALIZER_AUTHORITY_DOMAIN_V1,
            CHILD_MATERIALIZATION_REQUEST_DOMAIN_V1
        );
    }
}

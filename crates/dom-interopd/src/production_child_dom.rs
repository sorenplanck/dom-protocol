//! Production settlement-child authority for the DOM face.
//!
//! One instance owns the sole DOM control Store and borrows the sole
//! Scriptless Contracts Store through `DomContractsActuatorV1`. Coordinator
//! facts are frozen into an atomic cross-store binding before any action is
//! attempted, and every stable result is committed to the control Store's
//! port-call journal before it is returned.

use std::time::{SystemTime, UNIX_EPOCH};

use adapter_dom_real::{RealDomClaimVerifierV1, RealDomError, RealDomRpcRuntimeV1};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use dom_actuator::{
    DomActionV1, DomActuatorCapabilityV1, DomActuatorError, DomActuatorStoreV1,
    DomClaimCustodyClassificationV1, DomContractsActuatorV1, DomFinalClaimAdmissionBundleV2,
    DomFinalityObservationV1, DomFinalityRevalidationV1, DomLeaseV1, DomOperationDispositionV1,
    DomSessionBindingV1, DomSettlementChildBindingRequestV1, DomSettlementChildBindingV1,
    DomSettlementChildExposureV1, DomSettlementChildPortCallJournalStatusV1,
    DomSettlementChildPortCallKeyV1, DomSettlementChildPortCallKindV1,
    DomSettlementChildPortCallOutcomeV1, PersistedRefundTakeoverRequestV1,
    SameOwnerFinalClaimRecoveryRequestV2, ScopedDomActionV1,
};
use dom_adaptor::TrustedChainIdV1;
use dom_scriptless_chain_adapter::ChainAdapterError;
use dom_scriptless_identity_store::IdentityStoreError;
use dom_scriptless_store::{
    ConsumedClaimSigningAuthorizationV2, DomTransactionValidationContextV1, SessionStoreError,
};
use kaystra_core::state::EvidenceRefV1;
use kaystra_core::types::ChainId;
use route_composer::{
    ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1, FinalClaimSecretSourceScopeV1,
};
use route_transport::DurableRelaySenderErrorV1;
use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1, ChildExposureV1,
    ChildExternalizationReceiptV1, ChildObservationOutcomeV1, ChildObservationRequestV1,
    ChildReconciliationOutcomeV1, ChildReconciliationRequestV1, Digest32, SettlementActionV1,
    SettlementChildPlanV1, SettlementFaceV1, SettlementLegV1,
};

use crate::production_child_evidence::{
    externalization_evidence_v1, first_exposure_evidence_v1, observation_final_evidence_v1,
    observation_pending_evidence_v1, observation_reorg_evidence_v1,
    proven_not_externalized_evidence_v1, retryable_before_externalization_evidence_v1,
    unknown_evidence_v1, ChildEvidenceBindingV1, ChildFinalityFactsV1,
    ChildObservationEvidenceBindingV1,
};
use crate::production_child_router::{
    AuthenticatedDomChildPortV1, ProductionChildMaterializationRequestV1,
    ProductionSettlementChildPortV1, ProductionSettlementChildRouterV1,
};
use crate::production_contracts::{
    ProductionContractsOutboundErrorV1, ProductionDomChildStoreAuthorityV1,
    ProductionDomFinalClaimTransportRecoveryV1,
};
use crate::production_inputs::AuthenticatedProductionInputsV1;
use crate::relay_worker::RelayWorkerOutboundErrorV1;

const ZERO_DIGEST: Digest32 = [0; 32];
const DISPATCH_REQUEST_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/DOM-CHILD/DISPATCH-REQUEST/V1\0";
const RECONCILIATION_REQUEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/DOM-CHILD/RECONCILIATION-REQUEST/V1\0";
const OBSERVATION_REQUEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/DOM-CHILD/OBSERVATION-REQUEST/V1\0";
const MATERIALIZED_INTENT_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/DOM-CHILD/MATERIALIZED-INTENT/V1\0";
const MATERIALIZED_CUSTODY_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/DOM-CHILD/MATERIALIZED-CUSTODY/V1\0";

/// Trusted clock used for the actuator lease and durable journal timestamps.
pub(crate) trait ProductionDomChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1>;
}

/// Host wall-time boundary for production composition.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemProductionDomChildClockV1;

impl ProductionDomChildClockV1 for SystemProductionDomChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ChildAuthorityRefusalV1::Unavailable)
    }
}

/// Move-only proof that one exact dispatch request was crossed against both
/// DOM Stores under the live participant lease.
pub(crate) struct AuthenticatedDomDispatchCallV1 {
    binding: DomSettlementChildBindingV1,
    coordinator_attempt_id: Digest32,
    request_digest: Digest32,
    refund_context: Option<DomTransactionValidationContextV1>,
}

impl core::fmt::Debug for AuthenticatedDomDispatchCallV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedDomDispatchCallV1([authority redacted])")
    }
}

impl AuthenticatedDomDispatchCallV1 {
    pub(crate) const fn binding(&self) -> &DomSettlementChildBindingV1 {
        &self.binding
    }

    pub(crate) const fn coordinator_attempt_id(&self) -> Digest32 {
        self.coordinator_attempt_id
    }

    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    /// Authenticated live refund context, present only for a refund call.
    pub(crate) const fn refund_context(&self) -> Option<DomTransactionValidationContextV1> {
        self.refund_context
    }
}

/// Move-only proof for an exact reconciliation request.
pub(crate) struct AuthenticatedDomReconciliationCallV1 {
    binding: DomSettlementChildBindingV1,
    coordinator_attempt_id: Digest32,
    request_digest: Digest32,
    refund_context: Option<DomTransactionValidationContextV1>,
}

impl core::fmt::Debug for AuthenticatedDomReconciliationCallV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedDomReconciliationCallV1([authority redacted])")
    }
}

impl AuthenticatedDomReconciliationCallV1 {
    pub(crate) const fn binding(&self) -> &DomSettlementChildBindingV1 {
        &self.binding
    }

    pub(crate) const fn coordinator_attempt_id(&self) -> Digest32 {
        self.coordinator_attempt_id
    }

    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }

    pub(crate) const fn refund_context(&self) -> Option<DomTransactionValidationContextV1> {
        self.refund_context
    }
}

/// Composition seam for the additional linear authorities needed to dispatch
/// retained DOM funding, V2 claim and refund transactions.
///
/// The implementation receives no transaction bytes, scalar or caller-shaped
/// chain fact. It can act only after consuming a move-only token minted from an
/// authenticated Contracts+control binding. The concrete composition owns the
/// action capabilities and exact broadcaster; this port owns idempotency and
/// rejects every returned classification whose evidence is not the canonical
/// request-derived value.
pub(crate) trait ProductionDomActionAuthorityV1 {
    fn externalize(
        &mut self,
        contracts: &DomContractsActuatorV1<'_>,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        runtime: &RealDomRpcRuntimeV1,
        call: AuthenticatedDomDispatchCallV1,
        now_unix_ms: u64,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1>;

    fn reconcile(
        &mut self,
        contracts: &DomContractsActuatorV1<'_>,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        runtime: &RealDomRpcRuntimeV1,
        call: AuthenticatedDomReconciliationCallV1,
        now_unix_ms: u64,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1>;
}

/// Receipt-free result from the sole concrete DOM action authority.
///
/// Stable evidence is derived by the child port from its authenticated
/// coordinator request. The authority cannot choose an evidence digest or
/// claim `ProvenNotExternalized`.
pub(crate) enum ProductionDomActionResultV1 {
    Externalized,
    FinalClaimAdmitted(DomFinalClaimAdmissionBundleV2),
    FinalClaimTransportStarted,
    Unknown,
}

enum CompletedDomCapabilityV1 {
    Current(DomActuatorCapabilityV1),
    NeedsRefence,
}

/// Exact production dispatcher over the already-open Contracts/control pair.
/// It lazily rehydrates the one process-bound claim authorization from that
/// same Contracts opening and never owns transaction bytes or a second RPC
/// client.
pub(crate) struct ConcreteProductionDomActionAuthorityV1 {
    claim_authorization: Option<ConsumedClaimSigningAuthorizationV2>,
}

impl ConcreteProductionDomActionAuthorityV1 {
    pub(crate) const fn new() -> Self {
        Self {
            claim_authorization: None,
        }
    }

    fn claim_authorization<'authorization>(
        &'authorization mut self,
        contracts: &DomContractsActuatorV1<'_>,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> Result<&'authorization ConsumedClaimSigningAuthorizationV2, ChildAuthorityRefusalV1> {
        if self.claim_authorization.is_none() {
            self.claim_authorization = Some(
                contracts
                    .resume_consumed_final_claim_authority_v2(trusted_chain_id)
                    .map_err(map_actuator_error)?,
            );
        }
        self.claim_authorization
            .as_ref()
            .ok_or(ChildAuthorityRefusalV1::Unavailable)
    }

    fn completed_capability(
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        binding: &DomSettlementChildBindingV1,
        now_unix_ms: u64,
    ) -> Result<CompletedDomCapabilityV1, ChildAuthorityRefusalV1> {
        let scope = binding.request().scope();
        match control.authorize_action(
            lease,
            scope,
            binding.operation_evidence_digest(),
            None,
            now_unix_ms,
        ) {
            Ok((capability, DomOperationDispositionV1::AlreadyCompleted)) => {
                Ok(CompletedDomCapabilityV1::Current(capability))
            }
            Ok(_) => Err(ChildAuthorityRefusalV1::Conflict),
            Err(DomActuatorError::ReconciliationRequired) => {
                Ok(CompletedDomCapabilityV1::NeedsRefence)
            }
            Err(error) => Err(map_actuator_error(error)),
        }
    }

    fn rpc_result(
        result: Result<dom_scriptless_chain_adapter::SubmissionReceiptV1, DomActuatorError>,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
        match result {
            Ok(_) => Ok(ProductionDomActionResultV1::Externalized),
            Err(DomActuatorError::RpcAuthorityUnavailable) => {
                Ok(ProductionDomActionResultV1::Unknown)
            }
            Err(error) => Err(map_actuator_error(error)),
        }
    }

    fn execute(
        &mut self,
        contracts: &DomContractsActuatorV1<'_>,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        runtime: &RealDomRpcRuntimeV1,
        binding: &DomSettlementChildBindingV1,
        refund_context: Option<DomTransactionValidationContextV1>,
        now_unix_ms: u64,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
        let scope = binding.request().scope();
        match scope.action() {
            DomActionV1::BroadcastFunding => {
                if refund_context.is_some() {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let broadcast =
                    match Self::completed_capability(control, lease, binding, now_unix_ms)? {
                        CompletedDomCapabilityV1::Current(capability) => contracts
                            .resume_persisted_funding_broadcast(
                                control,
                                lease,
                                capability,
                                now_unix_ms,
                            ),
                        CompletedDomCapabilityV1::NeedsRefence => contracts
                            .adopt_persisted_funding_after_takeover(
                                control,
                                lease,
                                scope,
                                binding.operation_authorization_digest(),
                                now_unix_ms,
                            ),
                    }
                    .map_err(map_actuator_error)?;
                Self::rpc_result(contracts.dispatch_funding_broadcast(runtime, broadcast))
            }
            DomActionV1::BroadcastRefund => {
                let current_context = refund_context.ok_or(ChildAuthorityRefusalV1::Conflict)?;
                let broadcast =
                    match Self::completed_capability(control, lease, binding, now_unix_ms)? {
                        CompletedDomCapabilityV1::Current(capability) => contracts
                            .resume_persisted_refund_broadcast(
                                control,
                                lease,
                                capability,
                                current_context,
                                now_unix_ms,
                            ),
                        CompletedDomCapabilityV1::NeedsRefence => contracts
                            .adopt_persisted_refund_after_takeover(
                                control,
                                lease,
                                PersistedRefundTakeoverRequestV1 {
                                    scope,
                                    previous_authorization_digest: binding
                                        .operation_authorization_digest(),
                                    current_context,
                                    now_unix_ms,
                                },
                            ),
                    }
                    .map_err(map_actuator_error)?;
                Self::rpc_result(contracts.dispatch_refund_broadcast(runtime, broadcast))
            }
            DomActionV1::BroadcastClaim => {
                if refund_context.is_some() {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                match contracts
                    .classify_final_claim_custody_v2(control, lease, trusted_chain_id, now_unix_ms)
                    .map_err(map_actuator_error)?
                {
                    DomClaimCustodyClassificationV1::Admitted => {
                        if contracts
                            .final_claim_transport_started_v2(trusted_chain_id)
                            .map_err(map_actuator_error)?
                        {
                            return Ok(ProductionDomActionResultV1::FinalClaimTransportStarted);
                        }
                        let bundle = contracts
                            .resume_final_claim_admission_bundle_v2(
                                control,
                                lease,
                                trusted_chain_id,
                                now_unix_ms,
                            )
                            .map_err(map_actuator_error)?;
                        Ok(ProductionDomActionResultV1::FinalClaimAdmitted(bundle))
                    }
                    DomClaimCustodyClassificationV1::PotentiallyExposed => {
                        let authorization =
                            self.claim_authorization(contracts, trusted_chain_id)?;
                        let (prepared, latched) = contracts
                            .resume_final_claim_broadcast_after_same_owner_recovery_v2(
                                control,
                                lease,
                                SameOwnerFinalClaimRecoveryRequestV2 {
                                    scope,
                                    previous_authorization_digest: binding
                                        .operation_authorization_digest(),
                                    now_unix_ms,
                                },
                                trusted_chain_id,
                                authorization,
                            )
                            .map_err(map_actuator_error)?;
                        let receipt = match contracts
                            .dispatch_final_claim_broadcast_v2(runtime, &prepared, &latched)
                        {
                            Ok(receipt) => receipt,
                            Err(DomActuatorError::RpcAuthorityUnavailable) => {
                                return Ok(ProductionDomActionResultV1::Unknown);
                            }
                            Err(error) => return Err(map_actuator_error(error)),
                        };
                        match contracts.commit_final_claim_admission_v2(
                            control,
                            lease,
                            prepared,
                            receipt,
                            now_unix_ms,
                        ) {
                            Ok(bundle) => {
                                Ok(ProductionDomActionResultV1::FinalClaimAdmitted(bundle))
                            }
                            Err(error)
                                if map_actuator_error(error)
                                    == ChildAuthorityRefusalV1::Unavailable =>
                            {
                                Ok(ProductionDomActionResultV1::Unknown)
                            }
                            Err(error) => Err(map_actuator_error(error)),
                        }
                    }
                    DomClaimCustodyClassificationV1::Unattempted => {
                        Err(ChildAuthorityRefusalV1::Conflict)
                    }
                }
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }
}

impl ProductionDomActionAuthorityV1 for ConcreteProductionDomActionAuthorityV1 {
    fn externalize(
        &mut self,
        contracts: &DomContractsActuatorV1<'_>,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        runtime: &RealDomRpcRuntimeV1,
        call: AuthenticatedDomDispatchCallV1,
        now_unix_ms: u64,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
        self.execute(
            contracts,
            control,
            lease,
            trusted_chain_id,
            runtime,
            call.binding(),
            call.refund_context(),
            now_unix_ms,
        )
    }

    fn reconcile(
        &mut self,
        contracts: &DomContractsActuatorV1<'_>,
        control: &mut DomActuatorStoreV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        runtime: &RealDomRpcRuntimeV1,
        call: AuthenticatedDomReconciliationCallV1,
        now_unix_ms: u64,
    ) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
        self.execute(
            contracts,
            control,
            lease,
            trusted_chain_id,
            runtime,
            call.binding(),
            call.refund_context(),
            now_unix_ms,
        )
    }
}

/// Owner-scoped bridge from coordinator calls to the exact DOM authorities.
pub(crate) struct ProductionDomChildPortV1<C, A> {
    control: DomActuatorStoreV1,
    sessions: [ProductionDomChildSessionV1<A>; 2],
    lease: DomLeaseV1,
    trusted_chain_id: TrustedChainIdV1,
    runtime: RealDomRpcRuntimeV1,
    clock: C,
    route_terms_digest: Digest32,
    materialization_scope: ProductionDomMaterializationScopeV1,
}

/// Fully authenticated route/composition/source commitments for both DOM
/// legs.  This is derived from admitted inputs and cannot be caller-shaped.
pub(crate) struct ProductionDomMaterializationScopeV1 {
    route_id: Digest32,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digests: [Digest32; 2],
}

impl ProductionDomMaterializationScopeV1 {
    pub(crate) fn authenticate(
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: &ComposedFinalClaimRolePlanV1,
        upstream_scope: FinalClaimSecretSourceScopeV1,
        downstream_scope: FinalClaimSecretSourceScopeV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let composition = inputs.composition();
        role_plan
            .authenticate(
                composition.upstream(),
                composition.downstream(),
                upstream_scope,
                downstream_scope,
            )
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let upstream = role_plan.entry(ComposedSettlementLegV1::Upstream);
        let downstream = role_plan.entry(ComposedSettlementLegV1::Downstream);
        if role_plan.route_id() != inputs.admission().route_id()
            || role_plan.route_scope_digest() != composition.route_scope_digest()
            || role_plan.composition_binding_digest() != composition.binding_digest()
            || upstream.secret_source_scope_digest() == ZERO_DIGEST
            || downstream.secret_source_scope_digest() == ZERO_DIGEST
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            route_id: role_plan.route_id(),
            route_scope_digest: composition.route_scope_digest(),
            composition_digest: composition.binding_digest(),
            role_plan_digest: role_plan.digest(),
            source_scope_digests: [
                upstream.secret_source_scope_digest(),
                downstream.secret_source_scope_digest(),
            ],
        })
    }

    const fn source_scope(&self, leg: SettlementLegV1) -> Digest32 {
        match leg {
            SettlementLegV1::Upstream => self.source_scope_digests[0],
            SettlementLegV1::Downstream => self.source_scope_digests[1],
        }
    }
}

struct ProductionDomChildSessionV1<A> {
    leg: SettlementLegV1,
    settlement_id: Digest32,
    binding: DomSessionBindingV1,
    contracts: ProductionDomChildStoreAuthorityV1,
    claim_verifier: RealDomClaimVerifierV1,
    actions: A,
}

/// One exact DOM settlement context owned by the composed route port.
pub(crate) struct ProductionDomChildSessionBindingsV1 {
    pub(crate) leg: SettlementLegV1,
    pub(crate) settlement_id: Digest32,
    pub(crate) binding: DomSessionBindingV1,
    pub(crate) contracts: ProductionDomChildStoreAuthorityV1,
}

/// Exact route, lease and node authorities bound to both DOM settlements.
pub(crate) struct ProductionDomChildBindingsV1 {
    pub(crate) sessions: [ProductionDomChildSessionBindingsV1; 2],
    pub(crate) lease: DomLeaseV1,
    pub(crate) trusted_chain_id: TrustedChainIdV1,
    pub(crate) runtime: RealDomRpcRuntimeV1,
    pub(crate) route_terms_digest: Digest32,
    pub(crate) materialization_scope: ProductionDomMaterializationScopeV1,
}

/// Compose the owned concrete DOM child port from the sole retained Store
/// authorities and the registry-bound node/verifier bundle.
///
/// The returned trait object is owned and `'static` without reopening either
/// Store: its Contracts authority is an `Rc` handoff from
/// `ProductionContractsV1`, so the type remains deliberately `!Send + !Sync`.
pub(crate) fn compose_production_dom_child_port_v1(
    control: DomActuatorStoreV1,
    bindings: ProductionDomChildBindingsV1,
) -> Result<AuthenticatedDomChildPortV1, ChildAuthorityRefusalV1> {
    let port = ProductionDomChildPortV1::new(
        control,
        bindings,
        SystemProductionDomChildClockV1,
        [
            ConcreteProductionDomActionAuthorityV1::new(),
            ConcreteProductionDomActionAuthorityV1::new(),
        ],
    )?;
    Ok(ProductionSettlementChildRouterV1::authenticate_dom(port))
}

impl<C, A> core::fmt::Debug for ProductionDomChildPortV1<C, A> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionDomChildPortV1([authorities redacted])")
    }
}

impl<C, A> ProductionDomChildPortV1<C, A>
where
    C: ProductionDomChildClockV1,
    A: ProductionDomActionAuthorityV1,
{
    pub(crate) fn new(
        control: DomActuatorStoreV1,
        bindings: ProductionDomChildBindingsV1,
        clock: C,
        actions: [A; 2],
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let ProductionDomChildBindingsV1 {
            sessions,
            lease,
            trusted_chain_id,
            runtime,
            route_terms_digest,
            materialization_scope,
        } = bindings;
        let [upstream, downstream] = sessions;
        let [upstream_actions, downstream_actions] = actions;
        if upstream.leg != SettlementLegV1::Upstream
            || downstream.leg != SettlementLegV1::Downstream
            || upstream.settlement_id == ZERO_DIGEST
            || downstream.settlement_id == ZERO_DIGEST
            || route_terms_digest == ZERO_DIGEST
            || upstream.settlement_id == downstream.settlement_id
            || upstream.binding.session_id() == downstream.binding.session_id()
            || upstream.binding.route_id() != downstream.binding.route_id()
            || upstream.binding.participant() != downstream.binding.participant()
            || upstream.binding.chain_id() != downstream.binding.chain_id()
            || upstream.binding.profile_digest() != downstream.binding.profile_digest()
            || upstream.binding.deployment_digest() != downstream.binding.deployment_digest()
            || materialization_scope.route_id != upstream.binding.route_id()
            || materialization_scope.route_scope_digest == ZERO_DIGEST
            || materialization_scope.composition_digest == ZERO_DIGEST
            || materialization_scope.role_plan_digest == ZERO_DIGEST
            || materialization_scope
                .source_scope_digests
                .iter()
                .any(|digest| *digest == ZERO_DIGEST)
            || lease.participant_id() != upstream.binding.participant().participant_id()
            || lease.fencing_epoch() == 0
            || lease.lease_until_unix_ms() == 0
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        for session in [&upstream, &downstream] {
            let head = session
                .contracts
                .bind()
                .and_then(|actuator| actuator.session_head())
                .map_err(map_actuator_error)?;
            let expected_identity = session
                .binding
                .expected_dom_identity()
                .map_err(map_actuator_error)?;
            if trusted_chain_id.as_bytes() != &session.binding.chain_id()
                || runtime.expected_identity() != &expected_identity
                || head.session_id() != session.binding.session_id()
                || head.terms_hash() != session.binding.terms_digest()
            {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
        }
        let upstream_claim_verifier = upstream
            .contracts
            .build_claim_verifier(&trusted_chain_id)
            .map_err(map_actuator_error)?;
        let downstream_claim_verifier = downstream
            .contracts
            .build_claim_verifier(&trusted_chain_id)
            .map_err(map_actuator_error)?;
        Ok(Self {
            control,
            sessions: [
                ProductionDomChildSessionV1 {
                    leg: upstream.leg,
                    settlement_id: upstream.settlement_id,
                    binding: upstream.binding,
                    contracts: upstream.contracts,
                    claim_verifier: upstream_claim_verifier,
                    actions: upstream_actions,
                },
                ProductionDomChildSessionV1 {
                    leg: downstream.leg,
                    settlement_id: downstream.settlement_id,
                    binding: downstream.binding,
                    contracts: downstream.contracts,
                    claim_verifier: downstream_claim_verifier,
                    actions: downstream_actions,
                },
            ],
            lease,
            trusted_chain_id,
            runtime,
            clock,
            route_terms_digest,
            materialization_scope,
        })
    }

    fn session_index(
        &self,
        settlement_id: Digest32,
        leg: SettlementLegV1,
    ) -> Result<usize, ChildAuthorityRefusalV1> {
        exact_dom_session_index_v1(
            &[
                (self.sessions[0].leg, self.sessions[0].settlement_id),
                (self.sessions[1].leg, self.sessions[1].settlement_id),
            ],
            settlement_id,
            leg,
        )
    }

    fn validate_dispatch(
        &mut self,
        request: &ChildDispatchRequestV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedDomOperationV1, ChildAuthorityRefusalV1> {
        validate_dispatch_request_shape(request)?;
        self.validate_operation(ExpectedDomBindingsV1::from_dispatch(request), now_unix_ms)
    }

    fn validate_observation(
        &mut self,
        request: &ChildObservationRequestV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedDomOperationV1, ChildAuthorityRefusalV1> {
        validate_observation_request_shape(request)?;
        self.validate_operation(
            ExpectedDomBindingsV1::from_observation(request),
            now_unix_ms,
        )
    }

    fn validate_operation(
        &mut self,
        expected: ExpectedDomBindingsV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedDomOperationV1, ChildAuthorityRefusalV1> {
        let session_index = self.session_index(expected.settlement_id, expected.leg)?;
        let session = &self.sessions[session_index];
        expected.validate_static(
            session.settlement_id,
            self.route_terms_digest,
            session.binding,
            self.lease,
            &self.trusted_chain_id,
            &self.runtime,
        )?;
        let scope = ScopedDomActionV1::new(
            session.binding,
            expected.effect_id,
            dom_action(expected.action),
        )
        .map_err(map_actuator_error)?;
        let binding_request = DomSettlementChildBindingRequestV1::new(
            scope,
            expected.semantic_digest,
            expected.registry_digest,
            expected.intent_digest,
            expected.custody_digest,
            dom_exposure(expected.exposure),
        )
        .map_err(map_actuator_error)?;
        let refund_context = if expected.action == SettlementActionV1::Refund {
            Some(
                self.runtime
                    .current_transaction_validation_context()
                    .map_err(map_runtime_binding_error)?,
            )
        } else {
            None
        };
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let retained = match expected.action {
            SettlementActionV1::Funding => contracts.bind_funding_settlement_child(
                &mut self.control,
                self.lease,
                binding_request,
                now_unix_ms,
            ),
            SettlementActionV1::Claim => contracts.bind_final_claim_settlement_child_v2(
                &mut self.control,
                self.lease,
                &self.trusted_chain_id,
                binding_request,
                now_unix_ms,
            ),
            SettlementActionV1::Refund => contracts.bind_refund_settlement_child(
                &mut self.control,
                self.lease,
                binding_request,
                refund_context.ok_or(ChildAuthorityRefusalV1::Conflict)?,
                now_unix_ms,
            ),
        }
        .map_err(map_actuator_error)?;
        expected.validate_retained(session.binding, self.lease, &retained)?;
        Ok(ValidatedDomOperationV1 {
            session_index,
            expected,
            binding: retained,
            refund_context,
        })
    }

    fn externalized_receipt(
        request: &ChildDispatchRequestV1,
        evidence_digest: Digest32,
        first_exposure_evidence_digest: Option<Digest32>,
    ) -> ChildExternalizationReceiptV1 {
        ChildExternalizationReceiptV1 {
            plan_id: request.plan_id(),
            child_index: request.child_index(),
            face: request.face(),
            chain_id: request.chain_id(),
            transaction_id: request.expected_transaction_id(),
            intent_digest: request.intent_digest(),
            custody_digest: request.custody_digest(),
            externalization_evidence_digest: evidence_digest,
            first_exposure_evidence_digest,
        }
    }

    fn exact_externalized_outcome(
        request: &ChildDispatchRequestV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
        Ok(DomSettlementChildPortCallOutcomeV1::Externalized {
            evidence_digest: externalization_evidence_v1(&evidence)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            first_exposure_evidence_digest: first_exposure_evidence_v1(&evidence)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        })
    }

    fn normalize_dispatch_outcome(
        request: &ChildDispatchRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
        let expected = match outcome {
            DomSettlementChildPortCallOutcomeV1::Externalized { .. } => {
                Self::exact_externalized_outcome(request)?
            }
            DomSettlementChildPortCallOutcomeV1::RetryableBeforeExternalization { .. } => {
                DomSettlementChildPortCallOutcomeV1::RetryableBeforeExternalization {
                    evidence_digest: retryable_before_externalization_evidence_v1(&evidence)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                }
            }
            DomSettlementChildPortCallOutcomeV1::Unknown { .. } => {
                DomSettlementChildPortCallOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&evidence)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                }
            }
            _ => return Err(ChildAuthorityRefusalV1::Conflict),
        };
        if outcome != expected {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(expected)
    }

    fn normalize_reconciliation_outcome(
        request: &ChildDispatchRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
        let expected = match outcome {
            DomSettlementChildPortCallOutcomeV1::Externalized { .. } => {
                Self::exact_externalized_outcome(request)?
            }
            DomSettlementChildPortCallOutcomeV1::ProvenNotExternalized { .. }
                if reconciliation_may_prove_not_externalized(request.action()) =>
            {
                DomSettlementChildPortCallOutcomeV1::ProvenNotExternalized {
                    evidence_digest: proven_not_externalized_evidence_v1(&evidence)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                }
            }
            DomSettlementChildPortCallOutcomeV1::Unknown { .. } => {
                DomSettlementChildPortCallOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&evidence)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                }
            }
            _ => return Err(ChildAuthorityRefusalV1::Conflict),
        };
        if outcome != expected {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(expected)
    }

    fn dispatch_authority_outcome(
        request: &ChildDispatchRequestV1,
        result: ProductionDomActionResultV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        match result {
            ProductionDomActionResultV1::Externalized => Self::exact_externalized_outcome(request),
            ProductionDomActionResultV1::FinalClaimAdmitted(_) => {
                Err(ChildAuthorityRefusalV1::Conflict)
            }
            ProductionDomActionResultV1::FinalClaimTransportStarted => {
                Err(ChildAuthorityRefusalV1::Conflict)
            }
            ProductionDomActionResultV1::Unknown => {
                let evidence = ChildEvidenceBindingV1::from_dispatch(request);
                Ok(DomSettlementChildPortCallOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&evidence)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
        }
    }

    fn dispatch_outcome(
        request: &ChildDispatchRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        match Self::normalize_dispatch_outcome(request, outcome)? {
            DomSettlementChildPortCallOutcomeV1::Externalized {
                evidence_digest,
                first_exposure_evidence_digest,
            } => Ok(ChildExecutionOutcomeV1::Externalized(
                Self::externalized_receipt(
                    request,
                    evidence_digest,
                    first_exposure_evidence_digest,
                ),
            )),
            DomSettlementChildPortCallOutcomeV1::RetryableBeforeExternalization {
                evidence_digest,
            } => Ok(ChildExecutionOutcomeV1::RetryableBeforeExternalization { evidence_digest }),
            DomSettlementChildPortCallOutcomeV1::Unknown { evidence_digest } => {
                Ok(ChildExecutionOutcomeV1::Unknown { evidence_digest })
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }

    fn reconciliation_outcome(
        request: &ChildDispatchRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        match Self::normalize_reconciliation_outcome(request, outcome)? {
            DomSettlementChildPortCallOutcomeV1::Externalized {
                evidence_digest,
                first_exposure_evidence_digest,
            } => Ok(ChildReconciliationOutcomeV1::Externalized(
                Self::externalized_receipt(
                    request,
                    evidence_digest,
                    first_exposure_evidence_digest,
                ),
            )),
            DomSettlementChildPortCallOutcomeV1::ProvenNotExternalized { evidence_digest } => {
                Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized { evidence_digest })
            }
            DomSettlementChildPortCallOutcomeV1::Unknown { evidence_digest } => {
                Ok(ChildReconciliationOutcomeV1::Unknown { evidence_digest })
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }

    fn pending_observation(
        request: &ChildObservationRequestV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let binding = ChildObservationEvidenceBindingV1::from_observation(request);
        Ok(DomSettlementChildPortCallOutcomeV1::Pending {
            evidence_digest: observation_pending_evidence_v1(&binding)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        })
    }

    fn final_observation(
        request: &ChildObservationRequestV1,
        observation: DomFinalityObservationV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        if observation.transaction_id() != request.transaction_id {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let binding = ChildObservationEvidenceBindingV1::from_observation(request);
        let facts = ChildFinalityFactsV1 {
            final_evidence_digest: observation.evidence_digest(),
            final_block_hash: observation.block_hash(),
            final_block_number: observation.block_height(),
        };
        Ok(DomSettlementChildPortCallOutcomeV1::Final {
            evidence_digest: observation_final_evidence_v1(&binding, &facts)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        })
    }

    fn revalidation_observation(
        request: &ChildObservationRequestV1,
        revalidation: DomFinalityRevalidationV1,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        match revalidation {
            DomFinalityRevalidationV1::StillFinal(observation) => {
                let outcome = Self::final_observation(request, observation)?;
                if let Some(prior) = request.prior_finality_evidence_digest {
                    if outcome
                        != (DomSettlementChildPortCallOutcomeV1::Final {
                            evidence_digest: prior,
                        })
                    {
                        return Err(ChildAuthorityRefusalV1::Conflict);
                    }
                }
                Ok(outcome)
            }
            DomFinalityRevalidationV1::Invalidated {
                transaction_id,
                prior_evidence_digest,
                prior_block_height,
                prior_block_hash,
                reorg_evidence_digest,
            } => {
                if transaction_id != request.transaction_id {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let binding = ChildObservationEvidenceBindingV1::from_observation(request);
                let prior_facts = ChildFinalityFactsV1 {
                    final_evidence_digest: prior_evidence_digest,
                    final_block_hash: prior_block_hash,
                    final_block_number: prior_block_height,
                };
                let prior = observation_final_evidence_v1(&binding, &prior_facts)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                if request.prior_finality_evidence_digest != Some(prior) {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(DomSettlementChildPortCallOutcomeV1::FinalityInvalidated {
                    prior_finality_evidence_digest: prior,
                    reorg_evidence_digest: observation_reorg_evidence_v1(
                        &binding,
                        prior,
                        reorg_evidence_digest,
                    )
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
        }
    }

    fn evidence_ref(validated: &ValidatedDomOperationV1) -> EvidenceRefV1 {
        EvidenceRefV1 {
            chain_id: ChainId(validated.expected.chain_id),
            tx_id: validated.binding.transaction_id(),
            event_index: 0,
            block_height: 0,
            block_anchor: ZERO_DIGEST,
        }
    }

    fn observe_fresh(
        &mut self,
        request: &ChildObservationRequestV1,
        validated: &ValidatedDomOperationV1,
        now_unix_ms: u64,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = Self::evidence_ref(validated);
        let session = &self.sessions[validated.session_index];
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let observed = match validated.expected.action {
            SettlementActionV1::Funding => contracts.observe_funding_finality(
                &mut self.control,
                self.lease,
                &self.runtime,
                &self.trusted_chain_id,
                &evidence,
                now_unix_ms,
            ),
            SettlementActionV1::Claim => contracts.observe_final_claim_settlement_finality_v2(
                &mut self.control,
                self.lease,
                &self.runtime,
                &session.claim_verifier,
                &evidence,
                now_unix_ms,
            ),
            SettlementActionV1::Refund => contracts.observe_refund_settlement_finality(
                &mut self.control,
                self.lease,
                &self.runtime,
                &evidence,
                now_unix_ms,
            ),
        };
        match observed {
            Ok(observation) => Self::final_observation(request, observation),
            Err(DomActuatorError::FinalityPending) => Self::pending_observation(request),
            Err(error) => Err(map_actuator_error(error)),
        }
    }

    fn revalidate(
        &mut self,
        validated: &ValidatedDomOperationV1,
        now_unix_ms: u64,
    ) -> Result<DomFinalityRevalidationV1, DomActuatorError> {
        let contracts = self.sessions[validated.session_index].contracts.bind()?;
        match validated.expected.action {
            SettlementActionV1::Funding => contracts.revalidate_funding_settlement_finality(
                &mut self.control,
                self.lease,
                &self.runtime,
                &self.trusted_chain_id,
                now_unix_ms,
            ),
            SettlementActionV1::Claim => contracts.revalidate_final_claim_settlement_finality_v2(
                &mut self.control,
                self.lease,
                &self.runtime,
                now_unix_ms,
            ),
            SettlementActionV1::Refund => contracts.revalidate_refund_settlement_finality(
                &mut self.control,
                self.lease,
                &self.runtime,
                now_unix_ms,
            ),
        }
    }

    fn recover_invalidation(
        &mut self,
        validated: &ValidatedDomOperationV1,
        now_unix_ms: u64,
    ) -> Result<Option<DomFinalityRevalidationV1>, DomActuatorError> {
        let contracts = self.sessions[validated.session_index].contracts.bind()?;
        match validated.expected.action {
            SettlementActionV1::Funding => contracts.recover_funding_settlement_invalidation(
                &mut self.control,
                self.lease,
                &self.trusted_chain_id,
                now_unix_ms,
            ),
            SettlementActionV1::Claim => contracts.recover_final_claim_settlement_invalidation_v2(
                &mut self.control,
                self.lease,
                &self.trusted_chain_id,
                now_unix_ms,
            ),
            SettlementActionV1::Refund => contracts.recover_refund_settlement_invalidation(
                &mut self.control,
                self.lease,
                validated
                    .refund_context
                    .ok_or(DomActuatorError::CapabilityMismatch)?,
                now_unix_ms,
            ),
        }
    }

    fn observe_result(
        &mut self,
        request: &ChildObservationRequestV1,
        validated: &ValidatedDomOperationV1,
        now_unix_ms: u64,
    ) -> Result<DomSettlementChildPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let prior = request.prior_finality_evidence_digest;
        match self.revalidate(validated, now_unix_ms) {
            Ok(revalidation) if prior.is_some() => {
                return Self::revalidation_observation(request, revalidation);
            }
            Ok(DomFinalityRevalidationV1::StillFinal(observation)) => {
                return Self::final_observation(request, observation);
            }
            Ok(DomFinalityRevalidationV1::Invalidated { .. }) => {
                // The coordinator never received the old finality result. The
                // invalidation is durable, but this call must now prove the
                // replacement inclusion afresh or report Pending.
            }
            Err(DomActuatorError::FinalityPending) => {
                return Self::pending_observation(request);
            }
            Err(DomActuatorError::InvalidStage | DomActuatorError::ReorgEvidenceRequired) => {
                let recovered = self
                    .recover_invalidation(validated, now_unix_ms)
                    .map_err(map_actuator_error)?;
                if prior.is_some() {
                    return recovered
                        .ok_or(ChildAuthorityRefusalV1::Conflict)
                        .and_then(|value| Self::revalidation_observation(request, value));
                }
            }
            Err(error) => return Err(map_actuator_error(error)),
        }
        self.observe_fresh(request, validated, now_unix_ms)
    }

    fn observation_outcome(
        request: &ChildObservationRequestV1,
        outcome: DomSettlementChildPortCallOutcomeV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        match outcome {
            DomSettlementChildPortCallOutcomeV1::Pending { evidence_digest } => {
                if outcome != Self::pending_observation(request)? {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildObservationOutcomeV1::Pending { evidence_digest })
            }
            DomSettlementChildPortCallOutcomeV1::Final { evidence_digest } => {
                if request
                    .prior_finality_evidence_digest
                    .is_some_and(|prior| prior != evidence_digest)
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildObservationOutcomeV1::Final { evidence_digest })
            }
            DomSettlementChildPortCallOutcomeV1::FinalityInvalidated {
                prior_finality_evidence_digest,
                reorg_evidence_digest,
            } => {
                if request.prior_finality_evidence_digest != Some(prior_finality_evidence_digest) {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildObservationOutcomeV1::FinalityInvalidated {
                    prior_finality_evidence_digest,
                    reorg_evidence_digest,
                })
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }
}

impl<C, A> ProductionSettlementChildPortV1 for ProductionDomChildPortV1<C, A>
where
    C: ProductionDomChildClockV1,
    A: ProductionDomActionAuthorityV1,
{
    fn face(&self) -> SettlementFaceV1 {
        SettlementFaceV1::Dom
    }

    fn materialize(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&route_composer::RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let scalar_shape_is_valid = match (request.action, request.exposure, public_scalar) {
            (
                SettlementActionV1::Funding | SettlementActionV1::Refund,
                ChildExposureV1::NonSecret,
                None,
            )
            | (SettlementActionV1::Claim, ChildExposureV1::FirstSecretExposure, None)
            | (SettlementActionV1::Claim, ChildExposureV1::UsesPublicSecret, Some(_)) => true,
            _ => false,
        };
        if !scalar_shape_is_valid
            || request.route_id == ZERO_DIGEST
            || request.effect_id == ZERO_DIGEST
            || request.settlement_id == ZERO_DIGEST
            || request.fencing_epoch == 0
            || request.semantic_digest == ZERO_DIGEST
            || request.terms_digest == ZERO_DIGEST
            || request.registry_digest == ZERO_DIGEST
            || request.profile_digest == ZERO_DIGEST
            || request.deployment_digest == ZERO_DIGEST
            || request.route_scope_digest == ZERO_DIGEST
            || request.composition_digest == ZERO_DIGEST
            || request.role_plan_digest == ZERO_DIGEST
            || request.source_scope_digest == ZERO_DIGEST
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let session_index = self.session_index(request.settlement_id, request.leg)?;
        let session = &self.sessions[session_index];
        if session.binding.route_id() != request.route_id
            || session.settlement_id != request.settlement_id
            || request.terms_digest != self.route_terms_digest
            || session.binding.profile_digest() != request.profile_digest
            || session.binding.deployment_digest() != request.deployment_digest
            || session.binding.deployment_digest() != request.registry_digest
            || self.lease.fencing_epoch() != request.fencing_epoch
            || request.route_id != self.materialization_scope.route_id
            || request.route_scope_digest != self.materialization_scope.route_scope_digest
            || request.composition_digest != self.materialization_scope.composition_digest
            || request.role_plan_digest != self.materialization_scope.role_plan_digest
            || request.source_scope_digest != self.materialization_scope.source_scope(request.leg)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let leg = [leg_tag(request.leg)];
        let action = [action_tag(request.action)];
        let fencing_epoch = request.fencing_epoch.to_be_bytes();
        let exposure = [exposure_tag(request.exposure)];
        let common = [
            request.route_id.as_slice(),
            request.effect_id.as_slice(),
            request.settlement_id.as_slice(),
            leg.as_slice(),
            action.as_slice(),
            fencing_epoch.as_slice(),
            request.semantic_digest.as_slice(),
            request.terms_digest.as_slice(),
            request.registry_digest.as_slice(),
            request.profile_digest.as_slice(),
            request.deployment_digest.as_slice(),
            request.route_scope_digest.as_slice(),
            request.composition_digest.as_slice(),
            request.role_plan_digest.as_slice(),
            request.source_scope_digest.as_slice(),
            exposure.as_slice(),
        ];
        let intent_digest = request_digest(MATERIALIZED_INTENT_DOMAIN_V1, &common)?;
        let custody_digest = request_digest(
            MATERIALIZED_CUSTODY_DOMAIN_V1,
            &[intent_digest.as_slice(), request.effect_id.as_slice()],
        )?;
        let scope = ScopedDomActionV1::new(
            session.binding,
            request.effect_id,
            dom_action(request.action),
        )
        .map_err(map_actuator_error)?;
        let binding_request = DomSettlementChildBindingRequestV1::new(
            scope,
            request.semantic_digest,
            request.registry_digest,
            intent_digest,
            custody_digest,
            dom_exposure(request.exposure),
        )
        .map_err(map_actuator_error)?;
        let pre_context_now = self.clock.now_unix_ms()?;
        let refund_context = if request.action == SettlementActionV1::Refund {
            Some(
                self.runtime
                    .current_transaction_validation_context()
                    .map_err(map_runtime_binding_error)?,
            )
        } else {
            None
        };
        let now = if request.action == SettlementActionV1::Refund {
            fresh_dom_time(&mut self.clock, pre_context_now)?
        } else {
            pre_context_now
        };
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let retained = match request.action {
            SettlementActionV1::Funding => contracts.bind_funding_settlement_child(
                &mut self.control,
                self.lease,
                binding_request,
                now,
            ),
            SettlementActionV1::Claim => contracts.bind_final_claim_settlement_child_v2(
                &mut self.control,
                self.lease,
                &self.trusted_chain_id,
                binding_request,
                now,
            ),
            SettlementActionV1::Refund => contracts.bind_refund_settlement_child(
                &mut self.control,
                self.lease,
                binding_request,
                refund_context.ok_or(ChildAuthorityRefusalV1::Conflict)?,
                now,
            ),
        }
        .map_err(map_actuator_error)?;
        if retained.request() != binding_request
            || retained.locator().effect_id() != request.effect_id
            || retained.locator().custody_digest() != custody_digest
            || retained.transaction_id() == ZERO_DIGEST
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(SettlementChildPlanV1 {
            face: SettlementFaceV1::Dom,
            exposure: request.exposure,
            chain_id: session.binding.chain_id(),
            expected_transaction_id: retained.transaction_id(),
            intent_digest,
            custody_digest,
        })
    }

    fn externalize(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        let now = self.clock.now_unix_ms()?;
        let validated = self.validate_dispatch(request, now)?;
        let request_digest = dispatch_request_digest(request)?;
        let key = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Dispatch,
            request.attempt_id(),
            request_digest,
            &validated.binding,
        )
        .map_err(map_actuator_error)?;
        if let DomSettlementChildPortCallJournalStatusV1::Committed(outcome) = self
            .control
            .begin_settlement_child_port_call(self.lease, key, now)
            .map_err(map_actuator_error)?
        {
            return Self::dispatch_outcome(request, outcome);
        }
        let call = AuthenticatedDomDispatchCallV1 {
            binding: validated.binding,
            coordinator_attempt_id: request.attempt_id(),
            request_digest,
            refund_context: validated.refund_context,
        };
        let session = &mut self.sessions[validated.session_index];
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let returned = session.actions.externalize(
            &contracts,
            &mut self.control,
            self.lease,
            &self.trusted_chain_id,
            &self.runtime,
            call,
            now,
        )?;
        let returned = stage_final_claim_transport_v1(
            &mut session.contracts,
            &self.trusted_chain_id,
            returned,
        )?;
        let outcome = Self::dispatch_authority_outcome(request, returned)?;
        let post_authority_now = fresh_dom_time(&mut self.clock, now)?;
        let committed = self
            .control
            .commit_settlement_child_port_call_outcome(self.lease, key, outcome, post_authority_now)
            .map_err(map_actuator_error)?;
        Self::dispatch_outcome(request, committed)
    }

    fn reconcile(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        let now = self.clock.now_unix_ms()?;
        if request.current_route_fencing_epoch != request.dispatch.route_fencing_epoch()
            || request.current_coordinator_fencing_epoch
                < request.dispatch.coordinator_fencing_epoch()
            || request.reconciliation_attempt_id == ZERO_DIGEST
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let validated = self.validate_dispatch(&request.dispatch, now)?;
        let request_digest = reconciliation_request_digest(request)?;
        let key = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Reconciliation,
            request.reconciliation_attempt_id,
            request_digest,
            &validated.binding,
        )
        .map_err(map_actuator_error)?;
        if let DomSettlementChildPortCallJournalStatusV1::Committed(outcome) = self
            .control
            .begin_settlement_child_port_call(self.lease, key, now)
            .map_err(map_actuator_error)?
        {
            return Self::reconciliation_outcome(&request.dispatch, outcome);
        }
        let call = AuthenticatedDomReconciliationCallV1 {
            binding: validated.binding,
            coordinator_attempt_id: request.reconciliation_attempt_id,
            request_digest,
            refund_context: validated.refund_context,
        };
        let session = &mut self.sessions[validated.session_index];
        let contracts = session.contracts.bind().map_err(map_actuator_error)?;
        let returned = session.actions.reconcile(
            &contracts,
            &mut self.control,
            self.lease,
            &self.trusted_chain_id,
            &self.runtime,
            call,
            now,
        )?;
        let returned = stage_final_claim_transport_v1(
            &mut session.contracts,
            &self.trusted_chain_id,
            returned,
        )?;
        let outcome = Self::dispatch_authority_outcome(&request.dispatch, returned)?;
        let post_authority_now = fresh_dom_time(&mut self.clock, now)?;
        let committed = self
            .control
            .commit_settlement_child_port_call_outcome(self.lease, key, outcome, post_authority_now)
            .map_err(map_actuator_error)?;
        Self::reconciliation_outcome(&request.dispatch, committed)
    }

    fn observe(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        let now = self.clock.now_unix_ms()?;
        let validated = self.validate_observation(request, now)?;
        let request_digest = observation_request_digest(request)?;
        let key = DomSettlementChildPortCallKeyV1::new(
            DomSettlementChildPortCallKindV1::Observation,
            request.observation_attempt_id,
            request_digest,
            &validated.binding,
        )
        .map_err(map_actuator_error)?;
        if let DomSettlementChildPortCallJournalStatusV1::Committed(outcome) = self
            .control
            .begin_settlement_child_port_call(self.lease, key, now)
            .map_err(map_actuator_error)?
        {
            return Self::observation_outcome(request, outcome);
        }
        let outcome = self.observe_result(request, &validated, now)?;
        let post_observation_now = fresh_dom_time(&mut self.clock, now)?;
        let committed = self
            .control
            .commit_settlement_child_port_call_outcome(
                self.lease,
                key,
                outcome,
                post_observation_now,
            )
            .map_err(map_actuator_error)?;
        Self::observation_outcome(request, committed)
    }
}

#[derive(Clone, Copy)]
struct ExpectedDomBindingsV1 {
    route_id: Digest32,
    effect_id: Digest32,
    settlement_id: Digest32,
    leg: SettlementLegV1,
    action: SettlementActionV1,
    exposure: ChildExposureV1,
    semantic_digest: Digest32,
    intent_digest: Digest32,
    custody_digest: Digest32,
    transaction_id: Digest32,
    terms_digest: Digest32,
    registry_digest: Digest32,
    profile_digest: Digest32,
    deployment_digest: Digest32,
    chain_id: Digest32,
    route_fencing_epoch: u64,
    coordinator_fencing_epoch: Option<u64>,
    face: SettlementFaceV1,
}

impl ExpectedDomBindingsV1 {
    fn from_dispatch(request: &ChildDispatchRequestV1) -> Self {
        Self {
            route_id: request.route_id(),
            effect_id: request.effect_id(),
            settlement_id: request.settlement_id(),
            leg: request.leg(),
            action: request.action(),
            exposure: request.exposure(),
            semantic_digest: request.semantic_digest(),
            intent_digest: request.intent_digest(),
            custody_digest: request.custody_digest(),
            transaction_id: request.expected_transaction_id(),
            terms_digest: request.terms_digest(),
            registry_digest: request.registry_digest(),
            profile_digest: request.profile_digest(),
            deployment_digest: request.deployment_digest(),
            chain_id: request.chain_id(),
            route_fencing_epoch: request.route_fencing_epoch(),
            coordinator_fencing_epoch: Some(request.coordinator_fencing_epoch()),
            face: request.face(),
        }
    }

    fn from_observation(request: &ChildObservationRequestV1) -> Self {
        Self {
            route_id: request.route_id,
            effect_id: request.effect_id,
            settlement_id: request.settlement_id,
            leg: request.leg,
            action: request.action,
            exposure: request.exposure,
            semantic_digest: request.semantic_digest,
            intent_digest: request.intent_digest,
            custody_digest: request.custody_digest,
            transaction_id: request.transaction_id,
            terms_digest: request.terms_digest,
            registry_digest: request.registry_digest,
            profile_digest: request.profile_digest,
            deployment_digest: request.deployment_digest,
            chain_id: request.chain_id,
            route_fencing_epoch: request.route_fencing_epoch,
            coordinator_fencing_epoch: None,
            face: request.face,
        }
    }

    fn validate_static(
        &self,
        settlement_id: Digest32,
        route_terms_digest: Digest32,
        binding: DomSessionBindingV1,
        lease: DomLeaseV1,
        trusted_chain_id: &TrustedChainIdV1,
        runtime: &RealDomRpcRuntimeV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let exposure_valid = match self.action {
            SettlementActionV1::Funding | SettlementActionV1::Refund => {
                self.exposure == ChildExposureV1::NonSecret
            }
            SettlementActionV1::Claim => matches!(
                self.exposure,
                ChildExposureV1::FirstSecretExposure | ChildExposureV1::UsesPublicSecret
            ),
        };
        let expected_identity = binding
            .expected_dom_identity()
            .map_err(map_actuator_error)?;
        if self.face != SettlementFaceV1::Dom
            || !exposure_valid
            || [
                self.route_id,
                self.effect_id,
                self.settlement_id,
                self.semantic_digest,
                self.intent_digest,
                self.custody_digest,
                self.transaction_id,
                self.terms_digest,
                self.registry_digest,
                self.profile_digest,
                self.deployment_digest,
                self.chain_id,
            ]
            .contains(&ZERO_DIGEST)
            || self.route_fencing_epoch == 0
            || self.route_fencing_epoch != lease.fencing_epoch()
            || self
                .coordinator_fencing_epoch
                .is_some_and(|epoch| epoch == 0)
            || lease.participant_id() != binding.participant().participant_id()
            || binding.route_id() != self.route_id
            || settlement_id != self.settlement_id
            || route_terms_digest != self.terms_digest
            || binding.profile_digest() != self.profile_digest
            || binding.deployment_digest() != self.deployment_digest
            || binding.deployment_digest() != self.registry_digest
            || binding.chain_id() != self.chain_id
            || trusted_chain_id.as_bytes() != &self.chain_id
            || runtime.expected_identity() != &expected_identity
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    fn validate_retained(
        &self,
        binding: DomSessionBindingV1,
        lease: DomLeaseV1,
        retained: &DomSettlementChildBindingV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let request = retained.request();
        let scope = request.scope();
        let locator = retained.locator();
        if scope.binding() != binding
            || scope.effect_id() != self.effect_id
            || scope.action() != dom_action(self.action)
            || request.semantic_digest() != self.semantic_digest
            || request.registry_digest() != self.registry_digest
            || request.intent_digest() != self.intent_digest
            || request.custody_digest() != self.custody_digest
            || request.exposure() != dom_exposure(self.exposure)
            || retained.transaction_id() != self.transaction_id
            || retained.operation_fencing_epoch() == 0
            || retained.operation_fencing_epoch() > lease.fencing_epoch()
            || retained.operation_evidence_digest() == ZERO_DIGEST
            || retained.operation_authorization_digest() == ZERO_DIGEST
            || locator.effect_id() != self.effect_id
            || locator.custody_digest() != self.custody_digest
            || locator.binding_record_digest() == ZERO_DIGEST
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }
}

struct ValidatedDomOperationV1 {
    session_index: usize,
    expected: ExpectedDomBindingsV1,
    binding: DomSettlementChildBindingV1,
    refund_context: Option<DomTransactionValidationContextV1>,
}

fn exact_dom_session_index_v1(
    sessions: &[(SettlementLegV1, Digest32); 2],
    settlement_id: Digest32,
    leg: SettlementLegV1,
) -> Result<usize, ChildAuthorityRefusalV1> {
    let mut matches = sessions
        .iter()
        .enumerate()
        .filter(|(_, session)| session.1 == settlement_id);
    let (index, (retained_leg, _)) = matches.next().ok_or(ChildAuthorityRefusalV1::Conflict)?;
    if matches.next().is_some() || *retained_leg != leg {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(index)
}

const fn dom_action(action: SettlementActionV1) -> DomActionV1 {
    match action {
        SettlementActionV1::Funding => DomActionV1::BroadcastFunding,
        SettlementActionV1::Claim => DomActionV1::BroadcastClaim,
        SettlementActionV1::Refund => DomActionV1::BroadcastRefund,
    }
}

const fn dom_exposure(exposure: ChildExposureV1) -> DomSettlementChildExposureV1 {
    match exposure {
        ChildExposureV1::NonSecret => DomSettlementChildExposureV1::NonSecret,
        ChildExposureV1::FirstSecretExposure => DomSettlementChildExposureV1::FirstSecretExposure,
        ChildExposureV1::UsesPublicSecret => DomSettlementChildExposureV1::UsesPublicSecret,
    }
}

const fn reconciliation_may_prove_not_externalized(_action: SettlementActionV1) -> bool {
    // Every DOM action reaches this reconciliation boundary only after its
    // exact outbox artifact has been made durable.  The retained chain
    // scanner can prove canonical inclusion, but neither an absent scan nor a
    // node refusal proves that an earlier RPC attempt never reached another
    // mempool.  Claim is even stricter: its secret exposure is irreversible.
    // A ProvenNotExternalized outcome therefore requires a future move-only
    // never-started capability; no currently composed authority can mint it.
    false
}

fn stage_final_claim_transport_v1(
    contracts: &mut ProductionDomChildStoreAuthorityV1,
    trusted_chain_id: &TrustedChainIdV1,
    result: ProductionDomActionResultV1,
) -> Result<ProductionDomActionResultV1, ChildAuthorityRefusalV1> {
    match result {
        ProductionDomActionResultV1::FinalClaimAdmitted(bundle) => {
            contracts
                .stage_final_claim_admission_bundle(bundle)
                .map_err(map_contracts_outbound_error)?;
            Ok(ProductionDomActionResultV1::Externalized)
        }
        ProductionDomActionResultV1::FinalClaimTransportStarted => {
            match contracts
                .recover_final_claim_transport(trusted_chain_id)
                .map_err(map_contracts_outbound_error)?
            {
                ProductionDomFinalClaimTransportRecoveryV1::Staged => {
                    Ok(ProductionDomActionResultV1::Externalized)
                }
                ProductionDomFinalClaimTransportRecoveryV1::NotStarted => {
                    Err(ChildAuthorityRefusalV1::Conflict)
                }
            }
        }
        other => Ok(other),
    }
}

fn map_contracts_outbound_error(
    error: ProductionContractsOutboundErrorV1,
) -> ChildAuthorityRefusalV1 {
    match error {
        ProductionContractsOutboundErrorV1::OwnerBusy => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Identity(
            IdentityStoreError::Filesystem
            | IdentityStoreError::RandomFailure
            | IdentityStoreError::KeyDerivation
            | IdentityStoreError::StoreBusy
            | IdentityStoreError::SigningFailed,
        ) => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Identity(
            IdentityStoreError::InvalidInput
            | IdentityStoreError::AuthenticationFailed
            | IdentityStoreError::InvalidKey
            | IdentityStoreError::StoreRejected,
        ) => ChildAuthorityRefusalV1::Conflict,
        ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::Filesystem
            | SessionStoreError::StoreBusy
            | SessionStoreError::CapacityExceeded
            | SessionStoreError::RandomFailure,
        ) => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::Conflict
            | SessionStoreError::Canonical
            | SessionStoreError::PolicyProfile
            | SessionStoreError::Quarantined
            | SessionStoreError::InvalidDomTransaction
            | SessionStoreError::SessionNotFound
            | SessionStoreError::InvalidTransition
            | SessionStoreError::FundingAuthorityUnavailable
            | SessionStoreError::ClaimSigningAuthorityUnavailable
            | SessionStoreError::LegacyV1RecoveryOnly,
        ) => ChildAuthorityRefusalV1::Conflict,
        ProductionContractsOutboundErrorV1::Relay(
            RelayWorkerOutboundErrorV1::OwnerBusy | RelayWorkerOutboundErrorV1::EntropyUnavailable,
        ) => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Relay(RelayWorkerOutboundErrorV1::Sender(
            DurableRelaySenderErrorV1::StorageUnavailable
            | DurableRelaySenderErrorV1::PendingEnvelopeExists
            | DurableRelaySenderErrorV1::FramedTransferActive
            | DurableRelaySenderErrorV1::Queue(_),
        )) => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Relay(
            RelayWorkerOutboundErrorV1::Sender(_)
            | RelayWorkerOutboundErrorV1::StoreRejected
            | RelayWorkerOutboundErrorV1::InvalidDsc1
            | RelayWorkerOutboundErrorV1::WrongDsc1Scope,
        ) => ChildAuthorityRefusalV1::Conflict,
    }
}

fn validate_dispatch_request_shape(
    request: &ChildDispatchRequestV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    if [
        request.plan_id(),
        request.plan_digest(),
        request.aggregate_action_id(),
        request.aggregate_custody_digest(),
        request.route_id(),
        request.effect_id(),
        request.settlement_id(),
        request.semantic_digest(),
        request.terms_digest(),
        request.registry_digest(),
        request.profile_digest(),
        request.deployment_digest(),
        request.chain_id(),
        request.expected_transaction_id(),
        request.intent_digest(),
        request.custody_digest(),
        request.attempt_id(),
    ]
    .contains(&ZERO_DIGEST)
        || request.route_fencing_epoch() == 0
        || request.coordinator_fencing_epoch() == 0
        || request.attempt() == 0
        || request.child_index() >= 2
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

fn validate_observation_request_shape(
    request: &ChildObservationRequestV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    if [
        request.plan_id,
        request.plan_digest,
        request.route_id,
        request.effect_id,
        request.settlement_id,
        request.semantic_digest,
        request.terms_digest,
        request.registry_digest,
        request.profile_digest,
        request.deployment_digest,
        request.chain_id,
        request.transaction_id,
        request.intent_digest,
        request.custody_digest,
        request.observation_attempt_id,
    ]
    .contains(&ZERO_DIGEST)
        || request.route_fencing_epoch == 0
        || request.child_index >= 2
        || request
            .prior_finality_evidence_digest
            .is_some_and(|digest| digest == ZERO_DIGEST)
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

fn dispatch_request_digest(
    request: &ChildDispatchRequestV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    request_digest(
        DISPATCH_REQUEST_DOMAIN_V1,
        &[
            &request.plan_id(),
            &request.plan_digest(),
            &request.aggregate_action_id(),
            &request.aggregate_custody_digest(),
            &request.route_id(),
            &request.effect_id(),
            &request.settlement_id(),
            &[leg_tag(request.leg())],
            &[action_tag(request.action())],
            &request.semantic_digest(),
            &request.terms_digest(),
            &request.registry_digest(),
            &request.profile_digest(),
            &request.deployment_digest(),
            &request.route_fencing_epoch().to_be_bytes(),
            &request.coordinator_fencing_epoch().to_be_bytes(),
            &[request.child_index()],
            &[face_tag(request.face())],
            &[exposure_tag(request.exposure())],
            &request.chain_id(),
            &request.expected_transaction_id(),
            &request.intent_digest(),
            &request.custody_digest(),
            &request.attempt().to_be_bytes(),
            &request.attempt_id(),
        ],
    )
}

fn reconciliation_request_digest(
    request: &ChildReconciliationRequestV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let dispatch = dispatch_request_digest(&request.dispatch)?;
    request_digest(
        RECONCILIATION_REQUEST_DOMAIN_V1,
        &[
            &dispatch,
            &request.current_route_fencing_epoch.to_be_bytes(),
            &request.current_coordinator_fencing_epoch.to_be_bytes(),
            &request.reconciliation_attempt_id,
        ],
    )
}

fn observation_request_digest(
    request: &ChildObservationRequestV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let prior_tag = [u8::from(request.prior_finality_evidence_digest.is_some())];
    let prior = request
        .prior_finality_evidence_digest
        .unwrap_or(ZERO_DIGEST);
    request_digest(
        OBSERVATION_REQUEST_DOMAIN_V1,
        &[
            &request.plan_id,
            &request.plan_digest,
            &request.route_id,
            &request.effect_id,
            &request.settlement_id,
            &[leg_tag(request.leg)],
            &[action_tag(request.action)],
            &request.semantic_digest,
            &request.route_fencing_epoch.to_be_bytes(),
            &request.terms_digest,
            &request.registry_digest,
            &request.profile_digest,
            &request.deployment_digest,
            &[request.child_index],
            &[face_tag(request.face)],
            &[exposure_tag(request.exposure)],
            &request.chain_id,
            &request.transaction_id,
            &request.intent_digest,
            &request.custody_digest,
            &prior_tag,
            &prior,
            &request.observation_attempt_id,
        ],
    )
}

fn request_digest(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    hasher.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    if output == ZERO_DIGEST {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(output)
}

const fn face_tag(value: SettlementFaceV1) -> u8 {
    match value {
        SettlementFaceV1::Dom => 1,
        SettlementFaceV1::Evm => 2,
        SettlementFaceV1::Bitcoin => 3,
    }
}

const fn leg_tag(value: SettlementLegV1) -> u8 {
    match value {
        SettlementLegV1::Upstream => 1,
        SettlementLegV1::Downstream => 2,
    }
}

const fn action_tag(value: SettlementActionV1) -> u8 {
    match value {
        SettlementActionV1::Funding => 1,
        SettlementActionV1::Claim => 2,
        SettlementActionV1::Refund => 3,
    }
}

const fn exposure_tag(value: ChildExposureV1) -> u8 {
    match value {
        ChildExposureV1::NonSecret => 1,
        ChildExposureV1::FirstSecretExposure => 2,
        ChildExposureV1::UsesPublicSecret => 3,
    }
}

fn map_runtime_binding_error(error: RealDomError) -> ChildAuthorityRefusalV1 {
    match error {
        RealDomError::Chain(
            ChainAdapterError::AuthenticationFailed
            | ChainAdapterError::CapabilityUnavailable
            | ChainAdapterError::TemporarilyUnavailable
            | ChainAdapterError::HttpStatus(_),
        )
        | RealDomError::Store(_)
        | RealDomError::LockPoisoned
        | RealDomError::EvidenceNotFound => ChildAuthorityRefusalV1::Unavailable,
        RealDomError::Chain(
            ChainAdapterError::InvalidConfiguration
            | ChainAdapterError::BoundsExceeded
            | ChainAdapterError::MalformedResponse
            | ChainAdapterError::IdentityMismatch
            | ChainAdapterError::ReorgDetected
            | ChainAdapterError::InvalidEvidence
            | ChainAdapterError::TransactionRejected
            | ChainAdapterError::InvalidTransaction,
        )
        | RealDomError::Leg(_)
        | RealDomError::InvalidEvidence
        | RealDomError::Observation(_)
        | RealDomError::BoundsExceeded
        | RealDomError::FinalityPolicyInvalid
        | RealDomError::InsufficientConfirmations
        | RealDomError::TransactionStillCanonical
        | RealDomError::ReorgBeyondPolicy => ChildAuthorityRefusalV1::Conflict,
    }
}

fn map_actuator_error(error: DomActuatorError) -> ChildAuthorityRefusalV1 {
    match error {
        DomActuatorError::StorageUnavailable
        | DomActuatorError::ProcessLocked
        | DomActuatorError::LeaseHeld
        | DomActuatorError::LeaseExpired
        | DomActuatorError::RpcAuthorityUnavailable
        | DomActuatorError::ContractsAuthorityUnavailable
        | DomActuatorError::CryptoAuthorityUnavailable
        | DomActuatorError::WalletUnavailable
        | DomActuatorError::SharedOutputRecoveryIndeterminate => {
            ChildAuthorityRefusalV1::Unavailable
        }
        DomActuatorError::RefundNotArmed
        | DomActuatorError::ClaimNotPrepared
        | DomActuatorError::InsufficientFunds
        | DomActuatorError::ReconciliationRequired
        | DomActuatorError::ReorgEvidenceRequired
        | DomActuatorError::FinalityPending
        | DomActuatorError::TerminalStillCanonical => ChildAuthorityRefusalV1::Refused,
        DomActuatorError::LinuxRequired
        | DomActuatorError::InvalidStorageAuthority
        | DomActuatorError::DatabasePresent
        | DomActuatorError::DatabaseMissing
        | DomActuatorError::CreationIncomplete
        | DomActuatorError::UnsupportedFormat
        | DomActuatorError::InvalidBinding
        | DomActuatorError::CapabilityMismatch
        | DomActuatorError::StaleFence
        | DomActuatorError::RevisionConflict
        | DomActuatorError::IdempotencyConflict
        | DomActuatorError::InvalidStage
        | DomActuatorError::OutputReservationConflict
        | DomActuatorError::WalletChainMismatch
        | DomActuatorError::SecretReuseDetected
        | DomActuatorError::FinalityEvidenceInvalid
        | DomActuatorError::FinalityPolicyUnsupported
        | DomActuatorError::ReorgBeyondPolicy => ChildAuthorityRefusalV1::Conflict,
    }
}

fn fresh_dom_time<C: ProductionDomChildClockV1>(
    clock: &mut C,
    prior_unix_ms: u64,
) -> Result<u64, ChildAuthorityRefusalV1> {
    let fresh = clock.now_unix_ms()?;
    if fresh < prior_unix_ms {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(fresh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(AuthenticatedDomDispatchCallV1: Clone, Copy);
    assert_not_impl_any!(AuthenticatedDomReconciliationCallV1: Clone, Copy);
    assert_not_impl_any!(ProductionDomChildStoreAuthorityV1: Clone, Send, Sync);

    const fn digest(tag: u8) -> Digest32 {
        [tag; 32]
    }

    struct OneTimeClock(Option<u64>);

    impl ProductionDomChildClockV1 for OneTimeClock {
        fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1> {
            self.0.take().ok_or(ChildAuthorityRefusalV1::Unavailable)
        }
    }

    fn funding_observation_request() -> ChildObservationRequestV1 {
        ChildObservationRequestV1 {
            plan_id: digest(1),
            plan_digest: digest(2),
            route_id: digest(3),
            effect_id: digest(4),
            settlement_id: digest(5),
            leg: SettlementLegV1::Upstream,
            action: SettlementActionV1::Funding,
            semantic_digest: digest(6),
            route_fencing_epoch: 7,
            terms_digest: digest(8),
            registry_digest: digest(9),
            profile_digest: digest(10),
            deployment_digest: digest(11),
            child_index: 0,
            face: SettlementFaceV1::Dom,
            exposure: ChildExposureV1::NonSecret,
            chain_id: digest(12),
            transaction_id: digest(13),
            intent_digest: digest(14),
            custody_digest: digest(15),
            prior_finality_evidence_digest: None,
            observation_attempt_id: digest(16),
        }
    }

    #[test]
    fn action_and_exposure_mappings_are_closed() {
        assert_eq!(
            dom_action(SettlementActionV1::Funding),
            DomActionV1::BroadcastFunding
        );
        assert_eq!(
            dom_action(SettlementActionV1::Claim),
            DomActionV1::BroadcastClaim
        );
        assert_eq!(
            dom_action(SettlementActionV1::Refund),
            DomActionV1::BroadcastRefund
        );
        assert_eq!(
            dom_exposure(ChildExposureV1::FirstSecretExposure),
            DomSettlementChildExposureV1::FirstSecretExposure
        );
    }

    #[test]
    fn post_authority_time_must_not_regress() {
        assert_eq!(
            fresh_dom_time(&mut OneTimeClock(Some(99)), 100),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        assert_eq!(fresh_dom_time(&mut OneTimeClock(Some(100)), 100), Ok(100));
    }

    #[test]
    fn actuator_error_taxonomy_never_treats_partial_creation_as_transient() {
        assert_eq!(
            map_actuator_error(DomActuatorError::CreationIncomplete),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(DomActuatorError::InvalidStorageAuthority),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(DomActuatorError::StorageUnavailable),
            ChildAuthorityRefusalV1::Unavailable
        );
        assert_eq!(
            map_actuator_error(DomActuatorError::RefundNotArmed),
            ChildAuthorityRefusalV1::Refused
        );
    }

    #[test]
    fn request_digest_is_replay_stable_and_call_family_separated() {
        let dispatch =
            request_digest(DISPATCH_REQUEST_DOMAIN_V1, &[&[1; 32], &[2]]).expect("dispatch digest");
        assert_eq!(
            dispatch,
            request_digest(DISPATCH_REQUEST_DOMAIN_V1, &[&[1; 32], &[2]]).expect("dispatch replay")
        );
        assert_ne!(
            dispatch,
            request_digest(RECONCILIATION_REQUEST_DOMAIN_V1, &[&[1; 32], &[2]])
                .expect("reconciliation digest")
        );
        assert_ne!(dispatch, ZERO_DIGEST);
    }

    #[test]
    fn pending_and_invalid_evidence_remain_distinct_refusals() {
        assert_eq!(
            map_actuator_error(DomActuatorError::FinalityPending),
            ChildAuthorityRefusalV1::Refused
        );
        assert_eq!(
            map_actuator_error(DomActuatorError::FinalityEvidenceInvalid),
            ChildAuthorityRefusalV1::Conflict
        );
    }

    #[test]
    fn canonical_absence_never_becomes_proven_not_externalized() {
        assert!(!reconciliation_may_prove_not_externalized(
            SettlementActionV1::Funding
        ));
        assert!(!reconciliation_may_prove_not_externalized(
            SettlementActionV1::Claim
        ));
        assert!(!reconciliation_may_prove_not_externalized(
            SettlementActionV1::Refund
        ));
    }

    #[test]
    fn invariant_failure_never_becomes_an_ambiguous_rpc_outcome() {
        assert!(matches!(
            ConcreteProductionDomActionAuthorityV1::rpc_result(Err(
                DomActuatorError::CapabilityMismatch
            )),
            Err(ChildAuthorityRefusalV1::Conflict)
        ));
        assert!(matches!(
            ConcreteProductionDomActionAuthorityV1::rpc_result(Err(
                DomActuatorError::RpcAuthorityUnavailable
            )),
            Ok(ProductionDomActionResultV1::Unknown)
        ));
    }

    #[test]
    fn dom_route_port_selects_exactly_two_legs_and_rejects_transplants() {
        let sessions = [
            (SettlementLegV1::Upstream, digest(31)),
            (SettlementLegV1::Downstream, digest(32)),
        ];
        assert_eq!(
            exact_dom_session_index_v1(&sessions, digest(31), SettlementLegV1::Upstream),
            Ok(0)
        );
        assert_eq!(
            exact_dom_session_index_v1(&sessions, digest(32), SettlementLegV1::Downstream),
            Ok(1)
        );
        for refused in [
            exact_dom_session_index_v1(&sessions, digest(31), SettlementLegV1::Downstream),
            exact_dom_session_index_v1(&sessions, digest(32), SettlementLegV1::Upstream),
            exact_dom_session_index_v1(&sessions, digest(33), SettlementLegV1::Upstream),
            exact_dom_session_index_v1(
                &[
                    (SettlementLegV1::Upstream, digest(31)),
                    (SettlementLegV1::Downstream, digest(31)),
                ],
                digest(31),
                SettlementLegV1::Upstream,
            ),
        ] {
            assert_eq!(refused, Err(ChildAuthorityRefusalV1::Conflict));
        }
    }

    #[test]
    fn funding_reorg_recovery_is_stable_and_rejects_prior_transplant() {
        let mut request = funding_observation_request();
        let low_level_prior = digest(20);
        let prior_block_hash = digest(21);
        let low_level_reorg = digest(22);
        let facts = ChildFinalityFactsV1 {
            final_evidence_digest: low_level_prior,
            final_block_hash: prior_block_hash,
            final_block_number: 144,
        };
        let binding = ChildObservationEvidenceBindingV1::from_observation(&request);
        let coordinator_prior = observation_final_evidence_v1(&binding, &facts)
            .expect("canonical prior funding finality evidence");
        request.prior_finality_evidence_digest = Some(coordinator_prior);
        let revalidation = DomFinalityRevalidationV1::Invalidated {
            transaction_id: request.transaction_id,
            prior_evidence_digest: low_level_prior,
            prior_block_height: facts.final_block_number,
            prior_block_hash,
            reorg_evidence_digest: low_level_reorg,
        };
        let first = ProductionDomChildPortV1::<
            SystemProductionDomChildClockV1,
            ConcreteProductionDomActionAuthorityV1,
        >::revalidation_observation(&request, revalidation)
        .expect("first recovery");
        let replay = ProductionDomChildPortV1::<
            SystemProductionDomChildClockV1,
            ConcreteProductionDomActionAuthorityV1,
        >::revalidation_observation(&request, revalidation)
        .expect("byte-stable crash replay");
        assert_eq!(first, replay);
        assert!(matches!(
            first,
            DomSettlementChildPortCallOutcomeV1::FinalityInvalidated {
                prior_finality_evidence_digest,
                ..
            } if prior_finality_evidence_digest == coordinator_prior
        ));

        let mut transplanted = request;
        transplanted.prior_finality_evidence_digest = Some(digest(23));
        assert!(matches!(
            ProductionDomChildPortV1::<
                SystemProductionDomChildClockV1,
                ConcreteProductionDomActionAuthorityV1,
            >::revalidation_observation(&transplanted, revalidation),
            Err(ChildAuthorityRefusalV1::Conflict)
        ));
    }
}

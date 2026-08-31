//! Production settlement-child authority for the EVM face.
//!
//! The coordinator journals every dispatch before this boundary. When the
//! materialization owner is installed, this port also owns two independently
//! scoped EIP-1559 signer handles and imports a composition-verified scalar
//! only into an exact claim scope; the scalar is immediately zeroized after
//! the actuator durably retains its calldata. Raw transactions never leave the
//! actuator.

use std::time::{SystemTime, UNIX_EPOCH};

use adapter_evm::{
    abi::{concat_words, selector, SIG_OPEN},
    binding::adaptor_address,
    derive_binding, derive_lock_id, LockTerms, UnsignedEvmCall,
};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use deployment_registry::AssetRepresentationV1;
use deployment_registry::ResolvedEvmDeploymentV1;
use evm_actuator::{
    BroadcastDispositionV1, DurableEvmActuatorV1, EvmActuatorErrorV1, EvmActuatorLeaseV1,
    EvmClaimSecretV1, EvmFeesV1, EvmObservationMutationRequestV1, EvmOperationBindingViewV1,
    EvmOperationKindV1, EvmOperationMutationRequestV1, EvmOperationPreparationRequestV1,
    EvmOperationViewV1, EvmRetainedMutationKindV1, EvmRpcV1, EvmSignerRoleV1, EvmTxStageV1,
    ReconciliationKindV1, ScopedEip1559SignerV1, ScopedEvmClaimV1, ScopedEvmOpenV1,
    ScopedEvmRefundV1,
};
use kaystra_core::{terms::SettlementTermsV1, types::TimelockSpec};
use route_composer::{
    ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1, FinalClaimSecretSourceScopeV1,
};
use route_executor::LegIdV1;
use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1, ChildExposureV1,
    ChildExternalizationReceiptV1, ChildObservationOutcomeV1, ChildObservationRequestV1,
    ChildReconciliationOutcomeV1, ChildReconciliationRequestV1, Digest32, SettlementActionV1,
    SettlementChildPlanV1, SettlementFaceV1,
};
use zeroize::Zeroize;

use crate::production_child_evidence::{
    externalization_evidence_v1, first_exposure_evidence_v1, observation_final_evidence_v1,
    observation_pending_evidence_v1, observation_reorg_evidence_v1,
    proven_not_externalized_evidence_v1, unknown_evidence_v1, ChildEvidenceBindingV1,
    ChildFinalityFactsV1, ChildObservationEvidenceBindingV1,
};
use crate::production_child_router::{
    ProductionChildMaterializationRequestV1, ProductionSettlementChildPortV1,
};
use crate::production_inputs::AuthenticatedProductionInputsV1;

const ZERO_DIGEST: Digest32 = [0; 32];
const ADOPT_MUTATION_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/EVM-CHILD/ADOPT-RECONCILED/V1\0";
const MATERIALIZATION_ID_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/EVM-CHILD/MATERIALIZATION-ID/V1\0";
const NONCE_REFRESH_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/EVM-CHILD/NONCE-REFRESH-ID/V1\0";
const PREPARE_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/EVM-CHILD/PREPARE-ID/V1\0";
const SIGN_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/EVM-CHILD/SIGN-ID/V1\0";
const ZERO_U256: Digest32 = [0; 32];

struct ProductionEvmMaterializationAuthorityV1 {
    opening_call: UnsignedEvmCall,
    fees: EvmFeesV1,
    observation_valid_for_ms: u64,
    funder_signer: Box<dyn ScopedEip1559SignerV1>,
    beneficiary_signer: Box<dyn ScopedEip1559SignerV1>,
    route_id: Digest32,
    leg: settlement_coordinator::SettlementLegV1,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
}

/// Authenticated, non-fabricable scope used to install EVM materialization.
/// Its fields are derived from admitted inputs and a fully authenticated role
/// plan; callers cannot supply route/composition/source commitments directly.
pub(crate) struct ProductionEvmMaterializationScopeV1 {
    route_id: Digest32,
    leg: settlement_coordinator::SettlementLegV1,
    settlement_id: Digest32,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
}

impl ProductionEvmMaterializationScopeV1 {
    pub(crate) fn authenticate(
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: &ComposedFinalClaimRolePlanV1,
        upstream_scope: &FinalClaimSecretSourceScopeV1,
        downstream_scope: &FinalClaimSecretSourceScopeV1,
        leg: LegIdV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let composition = inputs.composition();
        role_plan
            .authenticate(
                composition.upstream(),
                composition.downstream(),
                upstream_scope.clone(),
                downstream_scope.clone(),
            )
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let (settlement, plan_leg, coordinator_leg) = match leg {
            LegIdV1::Upstream => (
                composition.upstream(),
                ComposedSettlementLegV1::Upstream,
                settlement_coordinator::SettlementLegV1::Upstream,
            ),
            LegIdV1::Downstream => (
                composition.downstream(),
                ComposedSettlementLegV1::Downstream,
                settlement_coordinator::SettlementLegV1::Downstream,
            ),
        };
        let entry = role_plan.entry(plan_leg);
        if role_plan.route_id() != inputs.admission().route_id()
            || role_plan.route_scope_digest() != composition.route_scope_digest()
            || role_plan.composition_binding_digest() != composition.binding_digest()
            || inputs.evm_session(leg).is_none()
            || entry.settlement_id().0 != settlement.settlement_id.0
            || entry.session_id().0 != settlement.session_id.0
            || entry.secret_source_scope_digest() == ZERO_DIGEST
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            route_id: role_plan.route_id(),
            leg: coordinator_leg,
            settlement_id: settlement.settlement_id.0,
            route_scope_digest: composition.route_scope_digest(),
            composition_digest: composition.binding_digest(),
            role_plan_digest: role_plan.digest(),
            source_scope_digest: entry.secret_source_scope_digest(),
        })
    }
}

/// Trusted clock boundary used for actuator lease and monotonic-time checks.
pub(crate) trait ProductionEvmChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1>;
}

/// Host monotonic-wall-time adapter for the production composition root.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemProductionEvmChildClockV1;

impl ProductionEvmChildClockV1 for SystemProductionEvmChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ChildAuthorityRefusalV1::Unavailable)
    }
}

/// Owner-scoped production bridge from coordinator calls to one EVM actuator.
pub(crate) struct ProductionEvmChildPortV1<R, C> {
    actuator: DurableEvmActuatorV1,
    rpc: R,
    deployment: ResolvedEvmDeploymentV1,
    funder_lease: EvmActuatorLeaseV1,
    beneficiary_lease: EvmActuatorLeaseV1,
    clock: C,
    settlement_id: Digest32,
    materialization: Option<ProductionEvmMaterializationAuthorityV1>,
}

impl<R, C> core::fmt::Debug for ProductionEvmChildPortV1<R, C> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionEvmChildPortV1([authorities redacted])")
    }
}

impl<R: EvmRpcV1, C: ProductionEvmChildClockV1> ProductionEvmChildPortV1<R, C> {
    pub(crate) fn new(
        actuator: DurableEvmActuatorV1,
        rpc: R,
        deployment: ResolvedEvmDeploymentV1,
        funder_lease: EvmActuatorLeaseV1,
        beneficiary_lease: EvmActuatorLeaseV1,
        clock: C,
        settlement_id: Digest32,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let config = deployment.adapter_config();
        if funder_lease.chain_id() != config.chain_id
            || beneficiary_lease.chain_id() != config.chain_id
            || funder_lease.account() != config.funder
            || beneficiary_lease.account() != config.beneficiary
            || funder_lease.owner_id() == ZERO_DIGEST
            || funder_lease.owner_id() != beneficiary_lease.owner_id()
            || funder_lease.fencing_epoch() == 0
            || beneficiary_lease.fencing_epoch() == 0
            || funder_lease.lease_until_unix_ms() == 0
            || beneficiary_lease.lease_until_unix_ms() == 0
            || settlement_id == ZERO_DIGEST
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            actuator,
            rpc,
            deployment,
            funder_lease,
            beneficiary_lease,
            clock,
            settlement_id,
            materialization: None,
        })
    }

    pub(crate) fn new_materializing(
        actuator: DurableEvmActuatorV1,
        rpc: R,
        deployment: ResolvedEvmDeploymentV1,
        funder_lease: EvmActuatorLeaseV1,
        beneficiary_lease: EvmActuatorLeaseV1,
        clock: C,
        settlement: &SettlementTermsV1,
        fees: EvmFeesV1,
        observation_valid_for_ms: u64,
        funder_signer: Box<dyn ScopedEip1559SignerV1>,
        beneficiary_signer: Box<dyn ScopedEip1559SignerV1>,
        scope: ProductionEvmMaterializationScopeV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if observation_valid_for_ms == 0 || scope.settlement_id != settlement.settlement_id.0 {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let opening_call = authenticated_opening_call(&deployment, settlement)?;
        let mut port = Self::new(
            actuator,
            rpc,
            deployment,
            funder_lease,
            beneficiary_lease,
            clock,
            settlement.settlement_id.0,
        )?;
        port.materialization = Some(ProductionEvmMaterializationAuthorityV1 {
            opening_call,
            fees,
            observation_valid_for_ms,
            funder_signer,
            beneficiary_signer,
            route_id: scope.route_id,
            leg: scope.leg,
            route_scope_digest: scope.route_scope_digest,
            composition_digest: scope.composition_digest,
            role_plan_digest: scope.role_plan_digest,
            source_scope_digest: scope.source_scope_digest,
        });
        Ok(port)
    }

    fn validate_dispatch(
        &mut self,
        request: &ChildDispatchRequestV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedEvmOperationV1, ChildAuthorityRefusalV1> {
        let expected = ExpectedEvmBindingsV1::from_dispatch(request);
        self.validate_operation(expected, now_unix_ms)
    }

    fn validate_observation(
        &mut self,
        request: &ChildObservationRequestV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedEvmOperationV1, ChildAuthorityRefusalV1> {
        let expected = ExpectedEvmBindingsV1::from_observation(request);
        self.validate_operation(expected, now_unix_ms)
    }

    fn validate_operation(
        &mut self,
        expected: ExpectedEvmBindingsV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedEvmOperationV1, ChildAuthorityRefusalV1> {
        expected.validate_static(&self.deployment, self.settlement_id)?;
        let (_, role) = operation_for_action(expected.action);
        let lease = self.lease(role);
        let retained = self
            .actuator
            .operation_binding(lease, expected.custody_digest, now_unix_ms)
            .map_err(map_actuator_error)?;
        let view = retained.operation().clone();
        expected.validate_retained(&self.deployment, lease, &view, retained.intent_digest())?;
        Ok(ValidatedEvmOperationV1 {
            expected,
            lease,
            view,
            retained_intent_digest: retained.intent_digest(),
        })
    }

    const fn lease(&self, role: EvmSignerRoleV1) -> EvmActuatorLeaseV1 {
        match role {
            EvmSignerRoleV1::Funder => self.funder_lease,
            EvmSignerRoleV1::Beneficiary => self.beneficiary_lease,
        }
    }

    fn externalized_receipt(
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExternalizationReceiptV1, ChildAuthorityRefusalV1> {
        let binding = ChildEvidenceBindingV1::from_dispatch(request);
        Ok(ChildExternalizationReceiptV1 {
            plan_id: request.plan_id(),
            child_index: request.child_index(),
            face: request.face(),
            chain_id: request.chain_id(),
            transaction_id: request.expected_transaction_id(),
            intent_digest: request.intent_digest(),
            custody_digest: request.custody_digest(),
            externalization_evidence_digest: externalization_evidence_v1(&binding)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            first_exposure_evidence_digest: first_exposure_evidence_v1(&binding)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        })
    }

    fn reconcile_current_fence(
        &mut self,
        request: &ChildReconciliationRequestV1,
        validated: &ValidatedEvmOperationV1,
        now_unix_ms: u64,
    ) -> Result<EvmOperationViewV1, ChildAuthorityRefusalV1> {
        match validated.view.stage {
            EvmTxStageV1::Signed => Ok(validated.view.clone()),
            EvmTxStageV1::SendAttempted => {
                let revision = self.replay_revision_or_current(
                    validated.lease,
                    EvmRetainedMutationKindV1::ObserveCurrent,
                    request.reconciliation_attempt_id,
                    validated.expected.custody_digest,
                    validated.view.revision,
                    now_unix_ms,
                )?;
                let mut clock_refusal = None;
                let outcome = self.actuator.observe_current(
                    EvmOperationMutationRequestV1::new(
                        validated.lease,
                        request.reconciliation_attempt_id,
                        validated.expected.custody_digest,
                        revision,
                        now_unix_ms,
                    ),
                    &mut self.rpc,
                    || match self.clock.now_unix_ms() {
                        Ok(value) => Ok(value),
                        Err(error) => {
                            clock_refusal = Some(error);
                            Err(EvmActuatorErrorV1::InvalidTime)
                        }
                    },
                );
                if let Some(error) = clock_refusal {
                    return Err(error);
                }
                outcome
                    .map(|outcome| outcome.value)
                    .map_err(map_actuator_error)
            }
            EvmTxStageV1::Observed | EvmTxStageV1::Final | EvmTxStageV1::FinalityInvalidated => {
                Ok(validated.view.clone())
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }

    fn reconcile_takeover(
        &mut self,
        request: &ChildReconciliationRequestV1,
        validated: &ValidatedEvmOperationV1,
        now_unix_ms: u64,
    ) -> Result<EvmOperationViewV1, ChildAuthorityRefusalV1> {
        let revision = self.replay_revision_or_current(
            validated.lease,
            EvmRetainedMutationKindV1::ReconcileTakeover,
            request.reconciliation_attempt_id,
            validated.expected.custody_digest,
            validated.view.revision,
            now_unix_ms,
        )?;
        let mut clock_refusal = None;
        let mut commit_now_unix_ms = now_unix_ms;
        let reconciled = self.actuator.reconcile_takeover(
            EvmOperationMutationRequestV1::new(
                validated.lease,
                request.reconciliation_attempt_id,
                validated.expected.custody_digest,
                revision,
                now_unix_ms,
            ),
            &mut self.rpc,
            || match self.clock.now_unix_ms() {
                Ok(value) => {
                    commit_now_unix_ms = value;
                    Ok(value)
                }
                Err(error) => {
                    clock_refusal = Some(error);
                    Err(EvmActuatorErrorV1::InvalidTime)
                }
            },
        );
        if let Some(error) = clock_refusal {
            return Err(error);
        }
        let reconciled = reconciled.map_err(map_actuator_error)?.value;
        if reconciled.stage != EvmTxStageV1::Reconciled
            || reconciled.reconciliation_kind == Some(ReconciliationKindV1::Unknown)
        {
            return Ok(reconciled);
        }
        let adopt_id = adopt_mutation_id(request.reconciliation_attempt_id)?;
        self.actuator
            .adopt_reconciled(
                validated.lease,
                adopt_id,
                validated.expected.custody_digest,
                reconciled.revision,
                commit_now_unix_ms,
            )
            .map(|outcome| outcome.value)
            .map_err(map_actuator_error)
    }

    fn replay_revision_or_current(
        &mut self,
        lease: EvmActuatorLeaseV1,
        kind: EvmRetainedMutationKindV1,
        mutation_id: Digest32,
        operation_id: Digest32,
        current_revision: u64,
        now_unix_ms: u64,
    ) -> Result<u64, ChildAuthorityRefusalV1> {
        self.actuator
            .retained_mutation_input_revision(lease, kind, mutation_id, operation_id, now_unix_ms)
            .map(|retained| retained.unwrap_or(current_revision))
            .map_err(map_actuator_error)
    }

    fn materialize_evm_child(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&route_composer::RouteScalar>,
        authority: &mut ProductionEvmMaterializationAuthorityV1,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        validate_materialization_request(
            &self.deployment,
            self.settlement_id,
            &request,
            public_scalar,
            authority,
        )?;
        let (_, role) = operation_for_action(request.action);
        let lease = self.lease(role);
        if lease.fencing_epoch() != request.fencing_epoch {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let operation_id = materialization_digest(MATERIALIZATION_ID_DOMAIN_V1, &request, role)?;
        let now = self.clock.now_unix_ms()?;
        match self.actuator.operation_binding(lease, operation_id, now) {
            Ok(binding) if binding.operation().stage == EvmTxStageV1::Prepared => {
                validate_prepared_evm_materialization(
                    &self.deployment,
                    &request,
                    role,
                    operation_id,
                    &binding,
                )?;
                return self.sign_materialized_evm_child(
                    request,
                    role,
                    lease,
                    operation_id,
                    binding.operation().revision,
                    authority,
                );
            }
            Ok(binding) => {
                return materialized_evm_plan(&self.deployment, lease, &request, role, binding)
            }
            Err(EvmActuatorErrorV1::OperationNotFound) => {}
            Err(error) => return Err(map_actuator_error(error)),
        }
        let observed = match self.actuator.nonce_snapshot(lease, now) {
            Ok(snapshot) if now < snapshot.valid_until_unix_ms() => snapshot,
            Ok(snapshot) => {
                self.actuator
                    .refresh_pending_nonce(
                        EvmObservationMutationRequestV1::new(
                            lease,
                            materialization_digest(NONCE_REFRESH_ID_DOMAIN_V1, &request, role)?,
                            snapshot.observation_revision(),
                            now,
                            authority.observation_valid_for_ms,
                        ),
                        &self.deployment,
                        &mut self.rpc,
                        || {
                            self.clock
                                .now_unix_ms()
                                .map_err(|_| EvmActuatorErrorV1::InvalidTime)
                        },
                    )
                    .map_err(map_actuator_error)?
                    .value
            }
            Err(EvmActuatorErrorV1::MissingNonceObservation) => {
                self.actuator
                    .refresh_pending_nonce(
                        EvmObservationMutationRequestV1::new(
                            lease,
                            materialization_digest(NONCE_REFRESH_ID_DOMAIN_V1, &request, role)?,
                            0,
                            now,
                            authority.observation_valid_for_ms,
                        ),
                        &self.deployment,
                        &mut self.rpc,
                        || {
                            self.clock
                                .now_unix_ms()
                                .map_err(|_| EvmActuatorErrorV1::InvalidTime)
                        },
                    )
                    .map_err(map_actuator_error)?
                    .value
            }
            Err(error) => return Err(map_actuator_error(error)),
        };
        let preparation = EvmOperationPreparationRequestV1::new(
            lease,
            materialization_digest(PREPARE_ID_DOMAIN_V1, &request, role)?,
            operation_id,
            observed,
            authority.fees,
            now,
        );
        let prepared = match request.action {
            SettlementActionV1::Funding => {
                let scope = ScopedEvmOpenV1::new(
                    request.route_id,
                    request.effect_id,
                    request.semantic_digest,
                    self.deployment,
                    authority.opening_call.clone(),
                )
                .map_err(map_actuator_error)?;
                self.actuator.prepare_open(preparation, &scope)
            }
            SettlementActionV1::Claim => {
                let scalar = public_scalar.ok_or(ChildAuthorityRefusalV1::Refused)?;
                let mut bytes = *scalar.expose();
                let secret =
                    EvmClaimSecretV1::import_and_zeroize(&mut bytes).map_err(map_actuator_error)?;
                bytes.zeroize();
                let scope = ScopedEvmClaimV1::new(
                    request.route_id,
                    request.effect_id,
                    request.semantic_digest,
                    self.deployment,
                    authority.opening_call.clone(),
                    secret,
                )
                .map_err(map_actuator_error)?;
                self.actuator.prepare_claim(preparation, scope)
            }
            SettlementActionV1::Refund => {
                let scope = ScopedEvmRefundV1::new(
                    request.route_id,
                    request.effect_id,
                    request.semantic_digest,
                    self.deployment,
                    authority.opening_call.clone(),
                )
                .map_err(map_actuator_error)?;
                self.actuator
                    .prepare_refund(preparation, &scope, &mut self.rpc, || {
                        self.clock
                            .now_unix_ms()
                            .map_err(|_| EvmActuatorErrorV1::InvalidTime)
                    })
            }
        }
        .map_err(map_actuator_error)?
        .value;
        if prepared.operation_id != operation_id
            || prepared.stage != EvmTxStageV1::Prepared
            || prepared.signer_role != role
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.sign_materialized_evm_child(
            request,
            role,
            lease,
            operation_id,
            prepared.revision,
            authority,
        )
    }

    fn sign_materialized_evm_child(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        role: EvmSignerRoleV1,
        lease: EvmActuatorLeaseV1,
        operation_id: Digest32,
        prepared_revision: u64,
        authority: &mut ProductionEvmMaterializationAuthorityV1,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let signer = match role {
            EvmSignerRoleV1::Funder => authority.funder_signer.as_mut(),
            EvmSignerRoleV1::Beneficiary => authority.beneficiary_signer.as_mut(),
        };
        let now = self.clock.now_unix_ms()?;
        let clock = &mut self.clock;
        let signed = self
            .actuator
            .sign_prepared(
                EvmOperationMutationRequestV1::new(
                    lease,
                    materialization_digest(SIGN_ID_DOMAIN_V1, &request, role)?,
                    operation_id,
                    prepared_revision,
                    now,
                ),
                signer,
                || {
                    clock
                        .now_unix_ms()
                        .map_err(|_| EvmActuatorErrorV1::InvalidTime)
                },
            )
            .map_err(map_actuator_error)?
            .value;
        if signed.stage != EvmTxStageV1::Signed || signed.transaction_hash.is_none() {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        // Signing is an external-authority boundary.  The actuator validates
        // and advances its monotonic clock using the callback above, so the
        // readback must use a new observation rather than the timestamp from
        // before signer I/O.
        let post_sign_now = self.clock.now_unix_ms()?;
        let binding = self
            .actuator
            .operation_binding(lease, operation_id, post_sign_now)
            .map_err(map_actuator_error)?;
        materialized_evm_plan(&self.deployment, lease, &request, role, binding)
    }
}

impl<R: EvmRpcV1, C: ProductionEvmChildClockV1> ProductionSettlementChildPortV1
    for ProductionEvmChildPortV1<R, C>
{
    fn face(&self) -> SettlementFaceV1 {
        SettlementFaceV1::Evm
    }

    fn materialize(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&route_composer::RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let mut authority = self
            .materialization
            .take()
            .ok_or(ChildAuthorityRefusalV1::Refused)?;
        let result = self.materialize_evm_child(request, public_scalar, &mut authority);
        self.materialization = Some(authority);
        result
    }

    fn externalize(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        let now = self.clock.now_unix_ms()?;
        let validated = self.validate_dispatch(request, now)?;
        if validated.view.fencing_epoch != validated.lease.fencing_epoch()
            || !matches!(
                validated.view.stage,
                EvmTxStageV1::Signed | EvmTxStageV1::SendAttempted
            )
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let revision = self.replay_revision_or_current(
            validated.lease,
            EvmRetainedMutationKindV1::BroadcastCurrent,
            request.attempt_id(),
            validated.expected.custody_digest,
            validated.view.revision,
            now,
        )?;
        let mut clock_refusal = None;
        let mut post_rpc_now = now;
        let broadcast = self.actuator.broadcast_current(
            EvmOperationMutationRequestV1::new(
                validated.lease,
                request.attempt_id(),
                validated.expected.custody_digest,
                revision,
                now,
            ),
            &mut self.rpc,
            || match self.clock.now_unix_ms() {
                Ok(value) => {
                    post_rpc_now = value;
                    Ok(value)
                }
                Err(error) => {
                    clock_refusal = Some(error);
                    Err(EvmActuatorErrorV1::InvalidTime)
                }
            },
        );
        if let Some(error) = clock_refusal {
            return Err(error);
        }
        let broadcast = broadcast.map_err(map_actuator_error)?;
        if broadcast.transaction_hash != validated.expected.transaction_id {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        match broadcast.disposition {
            BroadcastDispositionV1::Accepted => {
                let post = self.validate_dispatch(request, post_rpc_now)?;
                let (kind, _) = operation_for_action(post.expected.action);
                if post.view.stage != EvmTxStageV1::SendAttempted
                    || !post.view.ambiguous_after_send
                    || post.view.secret_exposed != (kind == EvmOperationKindV1::Claim)
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildExecutionOutcomeV1::Externalized(
                    Self::externalized_receipt(request)?,
                ))
            }
            BroadcastDispositionV1::Ambiguous => {
                let binding = ChildEvidenceBindingV1::from_dispatch(request);
                Ok(ChildExecutionOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
        }
    }

    fn reconcile(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        let now = self.clock.now_unix_ms()?;
        let validated = self.validate_dispatch(&request.dispatch, now)?;
        if request.current_route_fencing_epoch < request.dispatch.route_fencing_epoch()
            || request.current_coordinator_fencing_epoch
                < request.dispatch.coordinator_fencing_epoch()
            || validated.view.fencing_epoch > validated.lease.fencing_epoch()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let view = if validated.view.fencing_epoch == validated.lease.fencing_epoch() {
            self.reconcile_current_fence(request, &validated, now)?
        } else {
            self.reconcile_takeover(request, &validated, now)?
        };
        validated.expected.validate_retained(
            &self.deployment,
            validated.lease,
            &view,
            validated.retained_intent_digest,
        )?;
        let binding = ChildEvidenceBindingV1::from_dispatch(&request.dispatch);
        match view.stage {
            EvmTxStageV1::Signed => Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized {
                evidence_digest: proven_not_externalized_evidence_v1(&binding)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            }),
            EvmTxStageV1::SendAttempted => Ok(ChildReconciliationOutcomeV1::Unknown {
                evidence_digest: unknown_evidence_v1(&binding)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            }),
            EvmTxStageV1::Observed | EvmTxStageV1::Final | EvmTxStageV1::FinalityInvalidated => {
                Ok(ChildReconciliationOutcomeV1::Externalized(
                    Self::externalized_receipt(&request.dispatch)?,
                ))
            }
            EvmTxStageV1::Reconciled
                if view.reconciliation_kind == Some(ReconciliationKindV1::Unknown) =>
            {
                Ok(ChildReconciliationOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }

    fn observe(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        let now = self.clock.now_unix_ms()?;
        let validated = self.validate_observation(request, now)?;
        if validated.view.fencing_epoch != validated.lease.fencing_epoch()
            || !matches!(
                validated.view.stage,
                EvmTxStageV1::SendAttempted
                    | EvmTxStageV1::Observed
                    | EvmTxStageV1::Final
                    | EvmTxStageV1::FinalityInvalidated
            )
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let revision = self.replay_revision_or_current(
            validated.lease,
            EvmRetainedMutationKindV1::ObserveCurrent,
            request.observation_attempt_id,
            validated.expected.custody_digest,
            validated.view.revision,
            now,
        )?;
        let mut clock_refusal = None;
        let view = self.actuator.observe_current(
            EvmOperationMutationRequestV1::new(
                validated.lease,
                request.observation_attempt_id,
                validated.expected.custody_digest,
                revision,
                now,
            ),
            &mut self.rpc,
            || match self.clock.now_unix_ms() {
                Ok(value) => Ok(value),
                Err(error) => {
                    clock_refusal = Some(error);
                    Err(EvmActuatorErrorV1::InvalidTime)
                }
            },
        );
        if let Some(error) = clock_refusal {
            return Err(error);
        }
        let view = view.map_err(map_actuator_error)?.value;
        validated.expected.validate_retained(
            &self.deployment,
            validated.lease,
            &view,
            validated.retained_intent_digest,
        )?;
        observation_outcome(request, &view)
    }
}

#[derive(Clone, Copy)]
struct ExpectedEvmBindingsV1 {
    route_id: Digest32,
    effect_id: Digest32,
    settlement_id: Digest32,
    semantic_digest: Digest32,
    intent_digest: Digest32,
    custody_digest: Digest32,
    transaction_id: Digest32,
    terms_digest: Digest32,
    registry_digest: Digest32,
    profile_digest: Digest32,
    deployment_digest: Digest32,
    chain_id: Digest32,
    face: SettlementFaceV1,
    action: SettlementActionV1,
    exposure: ChildExposureV1,
}

impl ExpectedEvmBindingsV1 {
    fn from_dispatch(request: &ChildDispatchRequestV1) -> Self {
        Self {
            route_id: request.route_id(),
            effect_id: request.effect_id(),
            settlement_id: request.settlement_id(),
            semantic_digest: request.semantic_digest(),
            intent_digest: request.intent_digest(),
            custody_digest: request.custody_digest(),
            transaction_id: request.expected_transaction_id(),
            terms_digest: request.terms_digest(),
            registry_digest: request.registry_digest(),
            profile_digest: request.profile_digest(),
            deployment_digest: request.deployment_digest(),
            chain_id: request.chain_id(),
            face: request.face(),
            action: request.action(),
            exposure: request.exposure(),
        }
    }

    fn from_observation(request: &ChildObservationRequestV1) -> Self {
        Self {
            route_id: request.route_id,
            effect_id: request.effect_id,
            settlement_id: request.settlement_id,
            semantic_digest: request.semantic_digest,
            intent_digest: request.intent_digest,
            custody_digest: request.custody_digest,
            transaction_id: request.transaction_id,
            terms_digest: request.terms_digest,
            registry_digest: request.registry_digest,
            profile_digest: request.profile_digest,
            deployment_digest: request.deployment_digest,
            chain_id: request.chain_id,
            face: request.face,
            action: request.action,
            exposure: request.exposure,
        }
    }

    fn validate_static(
        &self,
        deployment: &ResolvedEvmDeploymentV1,
        settlement_id: Digest32,
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
        if self.face != SettlementFaceV1::Evm
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
            || self.registry_digest != deployment.registry_digest()
            || self.settlement_id != settlement_id
            || self.profile_digest != deployment.profile_digest()
            || self.deployment_digest != deployment.deployment().deployment_digest
            || self.chain_id != deployment.asset_binding().chain_id.0
            || self.terms_digest != deployment.adapter_config().terms_hash
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    fn validate_retained(
        &self,
        deployment: &ResolvedEvmDeploymentV1,
        lease: EvmActuatorLeaseV1,
        view: &EvmOperationViewV1,
        retained_intent_digest: Digest32,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let config = deployment.adapter_config();
        let (kind, role) = operation_for_action(self.action);
        let account = match role {
            EvmSignerRoleV1::Funder => config.funder,
            EvmSignerRoleV1::Beneficiary => config.beneficiary,
        };
        if view.kind != kind
            || view.signer_role != role
            || lease.account() != account
            || view.signing_account != account
            || view.route_id != self.route_id
            || view.effect_id != self.effect_id
            || view.semantic_digest != self.semantic_digest
            || retained_intent_digest != self.intent_digest
            || view.registry_digest != self.registry_digest
            || view.profile_digest != self.profile_digest
            || view.asset_binding_digest != deployment.asset_binding_digest()
            || view.deployment_digest != self.deployment_digest
            || view.terms_digest != self.terms_digest
            || view.chain_id != config.chain_id
            || view.contract != config.contract
            || view.beneficiary != config.beneficiary
            || view.funder != config.funder
            || view.transaction_hash != Some(self.transaction_id)
            || view.operation_id != self.custody_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }
}

struct ValidatedEvmOperationV1 {
    expected: ExpectedEvmBindingsV1,
    lease: EvmActuatorLeaseV1,
    view: EvmOperationViewV1,
    retained_intent_digest: Digest32,
}

fn validate_materialization_request(
    deployment: &ResolvedEvmDeploymentV1,
    settlement_id: Digest32,
    request: &ProductionChildMaterializationRequestV1,
    scalar: Option<&route_composer::RouteScalar>,
    authority: &ProductionEvmMaterializationAuthorityV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    let scalar_shape = match (request.action, request.exposure, scalar) {
        (
            SettlementActionV1::Funding | SettlementActionV1::Refund,
            ChildExposureV1::NonSecret,
            None,
        )
        | (
            SettlementActionV1::Claim,
            ChildExposureV1::FirstSecretExposure | ChildExposureV1::UsesPublicSecret,
            Some(_),
        ) => true,
        _ => false,
    };
    if !scalar_shape
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
        || request.registry_digest != deployment.registry_digest()
        || request.profile_digest != deployment.profile_digest()
        || request.deployment_digest != deployment.deployment().deployment_digest
        || request.terms_digest != deployment.adapter_config().terms_hash
        || request.settlement_id != settlement_id
        || request.route_id != authority.route_id
        || request.leg != authority.leg
        || request.route_scope_digest != authority.route_scope_digest
        || request.composition_digest != authority.composition_digest
        || request.role_plan_digest != authority.role_plan_digest
        || request.source_scope_digest != authority.source_scope_digest
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

fn validate_prepared_evm_materialization(
    deployment: &ResolvedEvmDeploymentV1,
    request: &ProductionChildMaterializationRequestV1,
    role: EvmSignerRoleV1,
    operation_id: Digest32,
    binding: &EvmOperationBindingViewV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    let view = binding.operation();
    let (kind, expected_role) = operation_for_action(request.action);
    let signing_account = match role {
        EvmSignerRoleV1::Funder => deployment.adapter_config().funder,
        EvmSignerRoleV1::Beneficiary => deployment.adapter_config().beneficiary,
    };
    if role != expected_role
        || view.stage != EvmTxStageV1::Prepared
        || view.kind != kind
        || view.signer_role != role
        || view.signing_account != signing_account
        || view.operation_id != operation_id
        || view.route_id != request.route_id
        || view.effect_id != request.effect_id
        || view.semantic_digest != request.semantic_digest
        || view.registry_digest != request.registry_digest
        || view.profile_digest != request.profile_digest
        || view.deployment_digest != request.deployment_digest
        || view.terms_digest != request.terms_digest
        || view.fencing_epoch != request.fencing_epoch
        || view.transaction_hash.is_some()
        || binding.intent_digest() == ZERO_DIGEST
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

fn materialization_digest(
    domain: &[u8],
    request: &ProductionChildMaterializationRequestV1,
    role: EvmSignerRoleV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    hasher.update(domain);
    let fencing_epoch = request.fencing_epoch.to_be_bytes();
    let leg = [settlement_leg_tag(request.leg)];
    let action = [settlement_action_tag(request.action)];
    let exposure = [child_exposure_tag(request.exposure)];
    let signer_role = [evm_role_tag(role)];
    for part in [
        request.route_id.as_slice(),
        request.effect_id.as_slice(),
        request.settlement_id.as_slice(),
        request.semantic_digest.as_slice(),
        request.terms_digest.as_slice(),
        request.registry_digest.as_slice(),
        request.profile_digest.as_slice(),
        request.deployment_digest.as_slice(),
        request.route_scope_digest.as_slice(),
        request.composition_digest.as_slice(),
        request.role_plan_digest.as_slice(),
        request.source_scope_digest.as_slice(),
        fencing_epoch.as_slice(),
        leg.as_slice(),
        action.as_slice(),
        exposure.as_slice(),
        signer_role.as_slice(),
    ] {
        let length = u64::try_from(part.len()).map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
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

fn materialized_evm_plan(
    deployment: &ResolvedEvmDeploymentV1,
    lease: EvmActuatorLeaseV1,
    request: &ProductionChildMaterializationRequestV1,
    role: EvmSignerRoleV1,
    binding: EvmOperationBindingViewV1,
) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
    let view = binding.operation();
    let expected = ExpectedEvmBindingsV1 {
        route_id: request.route_id,
        effect_id: request.effect_id,
        settlement_id: request.settlement_id,
        semantic_digest: request.semantic_digest,
        intent_digest: binding.intent_digest(),
        custody_digest: view.operation_id,
        transaction_id: view
            .transaction_hash
            .ok_or(ChildAuthorityRefusalV1::Conflict)?,
        terms_digest: request.terms_digest,
        registry_digest: request.registry_digest,
        profile_digest: request.profile_digest,
        deployment_digest: request.deployment_digest,
        chain_id: deployment.asset_binding().chain_id.0,
        face: SettlementFaceV1::Evm,
        action: request.action,
        exposure: request.exposure,
    };
    if view.stage != EvmTxStageV1::Signed || view.signer_role != role {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    expected.validate_static(deployment, request.settlement_id)?;
    let lease_account = match role {
        EvmSignerRoleV1::Funder => deployment.adapter_config().funder,
        EvmSignerRoleV1::Beneficiary => deployment.adapter_config().beneficiary,
    };
    if view.signing_account != lease_account
        || view.route_id != request.route_id
        || view.effect_id != request.effect_id
        || view.semantic_digest != request.semantic_digest
        || view.fencing_epoch != request.fencing_epoch
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    expected.validate_retained(deployment, lease, view, binding.intent_digest())?;
    Ok(SettlementChildPlanV1 {
        face: SettlementFaceV1::Evm,
        exposure: request.exposure,
        chain_id: expected.chain_id,
        expected_transaction_id: expected.transaction_id,
        intent_digest: expected.intent_digest,
        custody_digest: expected.custody_digest,
    })
}

fn authenticated_opening_call(
    deployment: &ResolvedEvmDeploymentV1,
    settlement: &SettlementTermsV1,
) -> Result<UnsignedEvmCall, ChildAuthorityRefusalV1> {
    let config = deployment.adapter_config();
    let _settlement_terms_digest = settlement
        .terms_hash()
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    if settlement.session_id.0 != config.session_id
        || settlement.dom_leg.chain_id.0 != config.dom_chain_id
        || settlement.counterparty_leg.adapter_profile_hash != deployment.profile_digest()
        || settlement.counterparty_leg.asset_id != deployment.asset_binding().asset_id
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let deadline = match settlement.counterparty_leg.deadline {
        TimelockSpec::TimestampSeconds { value } if value != 0 => value,
        _ => return Err(ChildAuthorityRefusalV1::Conflict),
    };
    let mut amount = ZERO_U256;
    amount[16..].copy_from_slice(&settlement.counterparty_leg.amount.to_be_bytes());
    let lock_terms = LockTerms {
        dom_chain_id: config.dom_chain_id,
        direction: config.direction.as_u8(),
        session_id: config.session_id,
        terms_hash: config.terms_hash,
        participants_hash: config.participants_hash,
        asset: config.asset,
        amount,
        beneficiary: config.beneficiary,
        adaptor_address: adaptor_address(&settlement.adaptor_point_sec1)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        deadline,
    };
    if !config.binds_terms(&lock_terms) {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let binding = derive_binding(config.chain_id, &config.contract, &lock_terms)
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let lock_id =
        derive_lock_id(&binding, &config.funder).map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let value = match deployment.asset_binding().representation {
        AssetRepresentationV1::Native => amount,
        AssetRepresentationV1::EvmErc20 { token, .. } if token == config.asset => ZERO_U256,
        _ => return Err(ChildAuthorityRefusalV1::Conflict),
    };
    Ok(UnsignedEvmCall {
        version: 1,
        chain_id: config.chain_id,
        to: config.contract,
        value,
        gas_limit_hint: config.gas_limit_hint,
        lock_id,
        binding,
        calldata: {
            let mut calldata = Vec::with_capacity(324);
            calldata.extend_from_slice(&selector(SIG_OPEN));
            calldata.extend_from_slice(
                &concat_words(&lock_terms.abi_words())
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            );
            calldata
        },
    })
}

const fn settlement_leg_tag(leg: settlement_coordinator::SettlementLegV1) -> u8 {
    match leg {
        settlement_coordinator::SettlementLegV1::Upstream => 1,
        settlement_coordinator::SettlementLegV1::Downstream => 2,
    }
}

const fn settlement_action_tag(action: SettlementActionV1) -> u8 {
    match action {
        SettlementActionV1::Funding => 1,
        SettlementActionV1::Claim => 2,
        SettlementActionV1::Refund => 3,
    }
}

const fn child_exposure_tag(exposure: ChildExposureV1) -> u8 {
    match exposure {
        ChildExposureV1::NonSecret => 1,
        ChildExposureV1::FirstSecretExposure => 2,
        ChildExposureV1::UsesPublicSecret => 3,
    }
}

const fn evm_role_tag(role: EvmSignerRoleV1) -> u8 {
    match role {
        EvmSignerRoleV1::Funder => 1,
        EvmSignerRoleV1::Beneficiary => 2,
    }
}

const fn operation_for_action(action: SettlementActionV1) -> (EvmOperationKindV1, EvmSignerRoleV1) {
    match action {
        SettlementActionV1::Funding => (EvmOperationKindV1::Open, EvmSignerRoleV1::Funder),
        SettlementActionV1::Claim => (EvmOperationKindV1::Claim, EvmSignerRoleV1::Beneficiary),
        SettlementActionV1::Refund => (EvmOperationKindV1::Refund, EvmSignerRoleV1::Funder),
    }
}

fn observation_outcome(
    request: &ChildObservationRequestV1,
    view: &EvmOperationViewV1,
) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
    let binding = ChildObservationEvidenceBindingV1::from_observation(request);
    match view.stage {
        EvmTxStageV1::SendAttempted | EvmTxStageV1::Observed => {
            Ok(ChildObservationOutcomeV1::Pending {
                evidence_digest: observation_pending_evidence_v1(&binding)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            })
        }
        EvmTxStageV1::Final => {
            if view.execution_success != Some(true) {
                return Err(ChildAuthorityRefusalV1::Conflict);
            }
            let facts = ChildFinalityFactsV1 {
                final_evidence_digest: view
                    .final_evidence_digest
                    .ok_or(ChildAuthorityRefusalV1::Conflict)?,
                final_block_hash: view
                    .final_block_hash
                    .ok_or(ChildAuthorityRefusalV1::Conflict)?,
                final_block_number: view
                    .final_block_number
                    .ok_or(ChildAuthorityRefusalV1::Conflict)?,
            };
            Ok(ChildObservationOutcomeV1::Final {
                evidence_digest: observation_final_evidence_v1(&binding, &facts)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            })
        }
        EvmTxStageV1::FinalityInvalidated => {
            let Some(prior) = request.prior_finality_evidence_digest else {
                return Ok(ChildObservationOutcomeV1::Pending {
                    evidence_digest: observation_pending_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                });
            };
            let invalidation = view
                .finality_invalidation_evidence_digest
                .ok_or(ChildAuthorityRefusalV1::Conflict)?;
            Ok(ChildObservationOutcomeV1::FinalityInvalidated {
                prior_finality_evidence_digest: prior,
                reorg_evidence_digest: observation_reorg_evidence_v1(&binding, prior, invalidation)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            })
        }
        _ => Err(ChildAuthorityRefusalV1::Conflict),
    }
}

fn adopt_mutation_id(
    reconciliation_attempt_id: Digest32,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    if reconciliation_attempt_id == ZERO_DIGEST {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let mut hasher = Blake2bVar::new(32).map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    hasher.update(ADOPT_MUTATION_DOMAIN_V1);
    let length = u64::try_from(reconciliation_attempt_id.len())
        .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    hasher.update(&length.to_be_bytes());
    hasher.update(&reconciliation_attempt_id);
    let mut output = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    if output == ZERO_DIGEST {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(output)
}

fn map_actuator_error(error: EvmActuatorErrorV1) -> ChildAuthorityRefusalV1 {
    match error {
        EvmActuatorErrorV1::Storage(_)
        | EvmActuatorErrorV1::Rpc(_)
        | EvmActuatorErrorV1::LeaseHeld
        | EvmActuatorErrorV1::RevisionConflict
        | EvmActuatorErrorV1::ReconciliationUnknown => ChildAuthorityRefusalV1::Unavailable,
        EvmActuatorErrorV1::OperationNotFound
        | EvmActuatorErrorV1::RefundDeadlineNotReached
        | EvmActuatorErrorV1::MissingNonceObservation
        | EvmActuatorErrorV1::StaleObservation
        | EvmActuatorErrorV1::AllowanceRequired
        | EvmActuatorErrorV1::InvalidState
        | EvmActuatorErrorV1::ReconciliationRequired => ChildAuthorityRefusalV1::Refused,
        EvmActuatorErrorV1::InvalidScope
        | EvmActuatorErrorV1::CallScopeMismatch
        | EvmActuatorErrorV1::InvalidFeePolicy
        | EvmActuatorErrorV1::InvalidTransaction
        | EvmActuatorErrorV1::InvalidSignature
        | EvmActuatorErrorV1::HighSignatureS
        | EvmActuatorErrorV1::WrongSigner
        | EvmActuatorErrorV1::InvalidClaimSecret
        | EvmActuatorErrorV1::BoundExceeded
        | EvmActuatorErrorV1::DatabasePresent
        | EvmActuatorErrorV1::DatabaseMissing
        | EvmActuatorErrorV1::CreationIncomplete
        | EvmActuatorErrorV1::ProcessLocked
        | EvmActuatorErrorV1::LinuxRequired
        | EvmActuatorErrorV1::InvalidStorageAuthority
        | EvmActuatorErrorV1::CorruptState
        | EvmActuatorErrorV1::StaleFencing
        | EvmActuatorErrorV1::InvalidTime
        | EvmActuatorErrorV1::RpcScopeMismatch
        | EvmActuatorErrorV1::TerminalEventMismatch
        | EvmActuatorErrorV1::IdempotencyConflict
        | EvmActuatorErrorV1::ObservationMismatch
        | EvmActuatorErrorV1::TransactionReverted
        | EvmActuatorErrorV1::InvalidReplacement
        | EvmActuatorErrorV1::Signer(_) => ChildAuthorityRefusalV1::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_mapping_never_assigns_claim_to_the_funder() {
        assert_eq!(
            operation_for_action(SettlementActionV1::Funding),
            (EvmOperationKindV1::Open, EvmSignerRoleV1::Funder)
        );
        assert_eq!(
            operation_for_action(SettlementActionV1::Claim),
            (EvmOperationKindV1::Claim, EvmSignerRoleV1::Beneficiary)
        );
        assert_eq!(
            operation_for_action(SettlementActionV1::Refund),
            (EvmOperationKindV1::Refund, EvmSignerRoleV1::Funder)
        );
    }

    #[test]
    fn adopt_mutation_identity_is_domain_separated_and_stable() {
        let attempt = [7; 32];
        let first = adopt_mutation_id(attempt).expect("first");
        assert_eq!(first, adopt_mutation_id(attempt).expect("replay"));
        assert_ne!(first, attempt);
        assert_ne!(first, ZERO_DIGEST);
        assert_ne!(first, adopt_mutation_id([8; 32]).expect("other"));
        assert!(matches!(
            adopt_mutation_id(ZERO_DIGEST),
            Err(ChildAuthorityRefusalV1::Conflict)
        ));
    }

    #[test]
    fn actuator_error_taxonomy_never_retries_partial_creation_or_stale_capabilities() {
        assert_eq!(
            map_actuator_error(EvmActuatorErrorV1::CreationIncomplete),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(EvmActuatorErrorV1::StaleFencing),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(EvmActuatorErrorV1::ReconciliationUnknown),
            ChildAuthorityRefusalV1::Unavailable
        );
    }
}

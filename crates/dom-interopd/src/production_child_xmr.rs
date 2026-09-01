//! Production settlement-child authority for the Monero face.
//!
//! The coordinator journals every dispatch before this boundary. The port
//! owns one durable Monero actuator plus the exact-broadcast and quorum
//! observation ports; sweep construction — the only step that touches the
//! combined private spend scalar — stays behind a scoped sweep authority
//! that can build exactly this settlement's claim or refund sweep and
//! nothing else. Raw bytes never leave the actuator, and every retained
//! transaction is re-verified against its consensus hash before it is
//! trusted again.
//!
//! Funding is **external custody**: the XMR funder places the shared
//! output named by the DLEQ-authenticated setup. The child never holds
//! funding bytes; it verifies the pinned funding transaction through the
//! view-key scan and the quorum observation boundary, exactly as the
//! Bitcoin child treats its external funding.

use std::time::{SystemTime, UNIX_EPOCH};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use deployment_registry::ResolvedMoneroDeploymentV1;
use route_composer::{
    ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1, FinalClaimSecretSourceScopeV1,
    RouteScalar,
};
use route_executor::LegIdV1;
use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1, ChildExposureV1,
    ChildExternalizationReceiptV1, ChildObservationOutcomeV1, ChildObservationRequestV1,
    ChildReconciliationOutcomeV1, ChildReconciliationRequestV1, Digest32, SettlementActionV1,
    SettlementChildPlanV1, SettlementFaceV1,
};
use xmr_actuator::{
    DurableXmrActuatorV1, XmrActuatorErrorV1, XmrActuatorLeaseV1, XmrObservationPortV1,
    XmrOperationKindV1, XmrOperationLocatorV1, XmrOperationViewV1, XmrReconciliationKindV1,
    XmrTxStageV1,
};
use xmr_raw_tx_verify::verify_exact_raw_transaction;
use xmr_setup_profile::ValidatedXmrSetup;
use xmr_spend_port::ExactBroadcastPort;

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
const TRANSACTION_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/TRANSACTION-ID/V1\0";
const INTENT_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/INTENT/V1\0";
const INVALIDATION_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/INVALIDATION/V1\0";
const FUNDING_CUSTODY_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/FUNDING-CUSTODY/V1\0";
const FUNDING_EVIDENCE_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/XMR-CHILD/FUNDING-EVIDENCE/V1\0";
const XMR_DEPLOYMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/XMR-CHILD/DEPLOYMENT-DIGEST/V1\0";

/// One exact signed sweep built by the scoped sweep authority.
pub(crate) struct XmrBuiltSweepV1 {
    /// Consensus transaction hash of the exact bytes.
    pub(crate) tx_hash: Digest32,
    /// The sweep's own key image, for the absence statement.
    pub(crate) key_image: Digest32,
    /// Exact signed transaction bytes.
    pub(crate) raw_transaction: Vec<u8>,
}

/// Verified external funding facts from the view-key scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct XmrExternalFundingFactsV1 {
    /// Exact amount found spendable, in piconero.
    pub(crate) received_amount_piconero: u64,
    /// False for an additionally timelocked or unspendable output.
    pub(crate) spendable: bool,
}

/// Scoped sweep and funding-scan authority for exactly one settlement.
///
/// Implementations own the sidecar session, the local share store and the
/// view key. They combine scalars only inside `build_claim_sweep`, and the
/// child hands the composition-verified route scalar in by borrow — it is
/// never retained here or in the child.
pub(crate) trait ScopedXmrSweepAuthorityV1 {
    /// Builds the exact claim sweep for this settlement from the revealed
    /// route scalar combined with the local share.
    fn build_claim_sweep(
        &mut self,
        request_nonce: Digest32,
        scalar: &RouteScalar,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1>;

    /// Builds the exact refund sweep for this settlement from the refund
    /// share revealed by the DOM refund adaptor round.
    fn build_refund_sweep(
        &mut self,
        request_nonce: Digest32,
    ) -> Result<XmrBuiltSweepV1, ChildAuthorityRefusalV1>;

    /// Verifies the pinned external funding output with the view key.
    fn verify_external_funding(
        &mut self,
        request_nonce: Digest32,
    ) -> Result<XmrExternalFundingFactsV1, ChildAuthorityRefusalV1>;
}

/// Trusted clock boundary used for actuator lease checks.
pub(crate) trait ProductionXmrChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1>;
}

/// Host wall-time adapter for the production composition root.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemProductionXmrChildClockV1;

impl ProductionXmrChildClockV1 for SystemProductionXmrChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ChildAuthorityRefusalV1::Unavailable)
    }
}

/// Authenticated, non-fabricable scope used to install Monero
/// materialization; mirrors the Solana child's scope authentication.
pub(crate) struct ProductionXmrMaterializationScopeV1 {
    route_id: Digest32,
    leg: settlement_coordinator::SettlementLegV1,
    settlement_id: Digest32,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
}

impl ProductionXmrMaterializationScopeV1 {
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
            || inputs.monero_session(leg).is_none()
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

struct ProductionXmrMaterializationAuthorityV1 {
    sweep_authority: Box<dyn ScopedXmrSweepAuthorityV1>,
    route_id: Digest32,
    leg: settlement_coordinator::SettlementLegV1,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
}

/// Owner-scoped production bridge from coordinator calls to one Monero
/// actuator over one DLEQ-authenticated shared-spend setup.
pub(crate) struct ProductionXmrChildPortV1<B, O, C> {
    actuator: DurableXmrActuatorV1,
    broadcast: B,
    observation: O,
    deployment: ResolvedMoneroDeploymentV1,
    setup: ValidatedXmrSetup,
    lease: XmrActuatorLeaseV1,
    min_confirmations: u64,
    clock: C,
    settlement_id: Digest32,
    materialization: Option<ProductionXmrMaterializationAuthorityV1>,
}

impl<B, O, C> core::fmt::Debug for ProductionXmrChildPortV1<B, O, C> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionXmrChildPortV1([authorities redacted])")
    }
}

const fn operation_for_action(action: SettlementActionV1) -> Option<XmrOperationKindV1> {
    match action {
        SettlementActionV1::Funding => None,
        SettlementActionV1::Claim => Some(XmrOperationKindV1::Claim),
        SettlementActionV1::Refund => Some(XmrOperationKindV1::Refund),
    }
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
    hasher.update(domain);
    for part in parts {
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

/// Public transaction identity of one exact Monero txid.
fn transaction_id_v1(tx_hash: Digest32) -> Result<Digest32, ChildAuthorityRefusalV1> {
    digest_parts(TRANSACTION_ID_DOMAIN_V1, &[tx_hash.as_slice()])
}

/// Intent commitment derived from durable facts, recomputable at any stage.
fn intent_digest_v1(
    settlement_id: Digest32,
    action: SettlementActionV1,
    custody_digest: Digest32,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let action_tag = [match action {
        SettlementActionV1::Funding => 1u8,
        SettlementActionV1::Claim => 2,
        SettlementActionV1::Refund => 3,
    }];
    digest_parts(
        INTENT_DOMAIN_V1,
        &[&settlement_id, &action_tag, &custody_digest],
    )
}

/// Deterministic commitment to the exact resolved Monero deployment.
pub(crate) fn resolved_monero_deployment_digest_v1(
    deployment: &ResolvedMoneroDeploymentV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    digest_parts(
        XMR_DEPLOYMENT_DIGEST_DOMAIN_V1,
        &[
            &deployment.registry_digest(),
            &deployment.registry_epoch().to_be_bytes(),
            &deployment.profile_digest(),
            &deployment.asset_binding_digest(),
            &deployment.profile().chain_id.0,
            &deployment.deployment().genesis_hash,
            &deployment.deployment().max_fee_piconero.to_be_bytes(),
        ],
    )
}

fn map_actuator_error(error: XmrActuatorErrorV1) -> ChildAuthorityRefusalV1 {
    match error {
        XmrActuatorErrorV1::StorageUnavailable | XmrActuatorErrorV1::ObservationUnavailable => {
            ChildAuthorityRefusalV1::Unavailable
        }
        XmrActuatorErrorV1::NotFound => ChildAuthorityRefusalV1::Refused,
        XmrActuatorErrorV1::InvalidLease
        | XmrActuatorErrorV1::LeaseExpired
        | XmrActuatorErrorV1::Corrupt
        | XmrActuatorErrorV1::Conflict
        | XmrActuatorErrorV1::InvalidInput
        | XmrActuatorErrorV1::InvalidTime => ChildAuthorityRefusalV1::Conflict,
    }
}

impl<B, O, C> ProductionXmrChildPortV1<B, O, C>
where
    B: ExactBroadcastPort,
    O: XmrObservationPortV1,
    C: ProductionXmrChildClockV1,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        actuator: DurableXmrActuatorV1,
        broadcast: B,
        observation: O,
        deployment: ResolvedMoneroDeploymentV1,
        setup: ValidatedXmrSetup,
        lease: XmrActuatorLeaseV1,
        min_confirmations: u64,
        clock: C,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let settlement_id = setup.settlement_id();
        if settlement_id == ZERO_DIGEST
            || min_confirmations == 0
            || lease.network_id() != deployment.deployment().genesis_hash
            || lease.fencing_epoch() == 0
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            actuator,
            broadcast,
            observation,
            deployment,
            setup,
            lease,
            min_confirmations,
            clock,
            settlement_id,
            materialization: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_materializing(
        actuator: DurableXmrActuatorV1,
        broadcast: B,
        observation: O,
        deployment: ResolvedMoneroDeploymentV1,
        setup: ValidatedXmrSetup,
        lease: XmrActuatorLeaseV1,
        min_confirmations: u64,
        clock: C,
        sweep_authority: Box<dyn ScopedXmrSweepAuthorityV1>,
        scope: ProductionXmrMaterializationScopeV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if scope.settlement_id != setup.settlement_id() {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let mut port = Self::new(
            actuator,
            broadcast,
            observation,
            deployment,
            setup,
            lease,
            min_confirmations,
            clock,
        )?;
        port.materialization = Some(ProductionXmrMaterializationAuthorityV1 {
            sweep_authority,
            route_id: scope.route_id,
            leg: scope.leg,
            route_scope_digest: scope.route_scope_digest,
            composition_digest: scope.composition_digest,
            role_plan_digest: scope.role_plan_digest,
            source_scope_digest: scope.source_scope_digest,
        });
        Ok(port)
    }

    fn locator(&self, kind: XmrOperationKindV1) -> XmrOperationLocatorV1 {
        XmrOperationLocatorV1 {
            settlement_id: self.settlement_id,
            kind,
        }
    }

    /// Custody commitment of the external funding statement: there are no
    /// local bytes to commit to, so the commitment names the exact pinned
    /// funding facts from the DLEQ-authenticated setup.
    fn funding_custody_digest(&self) -> Result<Digest32, ChildAuthorityRefusalV1> {
        digest_parts(
            FUNDING_CUSTODY_DOMAIN_V1,
            &[
                &self.settlement_id,
                &self.setup.funding_tx_hash(),
                &self.setup.expected_amount_piconero().to_be_bytes(),
                &self.setup.combined_spend_public_key(),
            ],
        )
    }

    fn validate_common_bindings(
        &self,
        face: SettlementFaceV1,
        action: SettlementActionV1,
        exposure: ChildExposureV1,
        settlement_id: Digest32,
        terms_digest: Digest32,
        registry_digest: Digest32,
        profile_digest: Digest32,
        deployment_digest: Digest32,
        chain_id: Digest32,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        // A Monero claim sweep publishes no witness on-chain: the DOM leg
        // reveals first, and the sweep merely uses what is already public.
        let exposure_valid = match action {
            SettlementActionV1::Funding | SettlementActionV1::Refund => {
                exposure == ChildExposureV1::NonSecret
            }
            SettlementActionV1::Claim => exposure == ChildExposureV1::UsesPublicSecret,
        };
        if face != SettlementFaceV1::Monero
            || !exposure_valid
            || settlement_id != self.settlement_id
            || registry_digest != self.deployment.registry_digest()
            || profile_digest != self.deployment.profile_digest()
            || deployment_digest != resolved_monero_deployment_digest_v1(&self.deployment)?
            || chain_id != self.deployment.profile().chain_id.0
            || terms_digest != self.setup.terms_hash()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    /// Validates a durable sweep view against dispatch expectations and
    /// re-verifies the retained bytes' consensus hash.
    fn validated_view(
        &self,
        kind: XmrOperationKindV1,
        action: SettlementActionV1,
        expected_transaction_id: Digest32,
        expected_custody_digest: Digest32,
        expected_intent_digest: Digest32,
    ) -> Result<XmrOperationViewV1, ChildAuthorityRefusalV1> {
        let view = self
            .actuator
            .view(self.locator(kind))
            .map_err(map_actuator_error)?;
        if view.custody_digest != expected_custody_digest
            || transaction_id_v1(view.tx_hash)? != expected_transaction_id
            || intent_digest_v1(self.settlement_id, action, view.custody_digest)?
                != expected_intent_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let raw = self
            .actuator
            .retained(view.locator)
            .map_err(map_actuator_error)?;
        if xmr_actuator::custody_digest_v1(&raw).map_err(map_actuator_error)? != view.custody_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        verify_exact_raw_transaction(&raw, view.tx_hash)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        Ok(view)
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

    fn materialize_xmr_child(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        public_scalar: Option<&RouteScalar>,
        authority: &mut ProductionXmrMaterializationAuthorityV1,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let scalar_shape = matches!(
            (request.action, request.exposure, public_scalar),
            (
                SettlementActionV1::Funding | SettlementActionV1::Refund,
                ChildExposureV1::NonSecret,
                None,
            ) | (
                SettlementActionV1::Claim,
                ChildExposureV1::UsesPublicSecret,
                Some(_),
            )
        );
        if !scalar_shape
            || request.route_id == ZERO_DIGEST
            || request.effect_id == ZERO_DIGEST
            || request.fencing_epoch == 0
            || request.semantic_digest == ZERO_DIGEST
            || request.settlement_id != self.settlement_id
            || request.route_id != authority.route_id
            || request.leg != authority.leg
            || request.route_scope_digest != authority.route_scope_digest
            || request.composition_digest != authority.composition_digest
            || request.role_plan_digest != authority.role_plan_digest
            || request.source_scope_digest != authority.source_scope_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.validate_common_bindings(
            SettlementFaceV1::Monero,
            request.action,
            request.exposure,
            request.settlement_id,
            request.terms_digest,
            request.registry_digest,
            request.profile_digest,
            request.deployment_digest,
            self.deployment.profile().chain_id.0,
        )?;
        let action = request.action;
        let Some(kind) = operation_for_action(action) else {
            // External custody: the plan names the pinned funding facts.
            let custody = self.funding_custody_digest()?;
            return Ok(SettlementChildPlanV1 {
                face: SettlementFaceV1::Monero,
                exposure: ChildExposureV1::NonSecret,
                chain_id: self.deployment.profile().chain_id.0,
                expected_transaction_id: transaction_id_v1(self.setup.funding_tx_hash())?,
                intent_digest: intent_digest_v1(self.settlement_id, action, custody)?,
                custody_digest: custody,
            });
        };
        let locator = self.locator(kind);
        let now = self.clock.now_unix_ms()?;
        let view = match self.actuator.view(locator) {
            Ok(view) => {
                // Idempotent reopen: re-verify the retained bytes' consensus
                // hash rather than rebuilding a sweep (the sidecar owns
                // construction and is not byte-deterministic across calls).
                let raw = self
                    .actuator
                    .retained(locator)
                    .map_err(map_actuator_error)?;
                verify_exact_raw_transaction(&raw, view.tx_hash)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                view
            }
            Err(XmrActuatorErrorV1::NotFound) => {
                let built = match (kind, public_scalar) {
                    (XmrOperationKindV1::Claim, Some(scalar)) => authority
                        .sweep_authority
                        .build_claim_sweep(request.effect_id, scalar)?,
                    (XmrOperationKindV1::Refund, None) => authority
                        .sweep_authority
                        .build_refund_sweep(request.effect_id)?,
                    _ => return Err(ChildAuthorityRefusalV1::Conflict),
                };
                // Independent consensus-hash verification before anything is
                // retained: the sidecar's answer is never trusted bare.
                verify_exact_raw_transaction(&built.raw_transaction, built.tx_hash)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                self.actuator
                    .prepare_signed(
                        &self.lease,
                        locator,
                        built.tx_hash,
                        built.key_image,
                        &built.raw_transaction,
                        now,
                    )
                    .map_err(map_actuator_error)?
            }
            Err(error) => return Err(map_actuator_error(error)),
        };
        if view.stage == XmrTxStageV1::FinalityInvalidated {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(SettlementChildPlanV1 {
            face: SettlementFaceV1::Monero,
            exposure: if action == SettlementActionV1::Claim {
                ChildExposureV1::UsesPublicSecret
            } else {
                ChildExposureV1::NonSecret
            },
            chain_id: self.deployment.profile().chain_id.0,
            expected_transaction_id: transaction_id_v1(view.tx_hash)?,
            intent_digest: intent_digest_v1(self.settlement_id, action, view.custody_digest)?,
            custody_digest: view.custody_digest,
        })
    }

    /// Funding-path observation shared by observe and reconcile: the pinned
    /// external funding transaction looked up at the quorum boundary.
    fn funding_inclusion(
        &mut self,
    ) -> Result<Option<xmr_actuator::XmrTxInclusionV1>, ChildAuthorityRefusalV1> {
        self.observation
            .transaction_inclusion(self.setup.funding_tx_hash())
            .map_err(map_actuator_error)
    }

    fn validate_funding_request(
        &self,
        expected_transaction_id: Digest32,
        expected_custody_digest: Digest32,
        expected_intent_digest: Digest32,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let custody = self.funding_custody_digest()?;
        if expected_custody_digest != custody
            || expected_transaction_id != transaction_id_v1(self.setup.funding_tx_hash())?
            || expected_intent_digest
                != intent_digest_v1(self.settlement_id, SettlementActionV1::Funding, custody)?
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }
}

impl<B, O, C> ProductionSettlementChildPortV1 for ProductionXmrChildPortV1<B, O, C>
where
    B: ExactBroadcastPort,
    O: XmrObservationPortV1,
    C: ProductionXmrChildClockV1,
{
    fn face(&self) -> SettlementFaceV1 {
        SettlementFaceV1::Monero
    }

    fn materialize(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let mut authority = self
            .materialization
            .take()
            .ok_or(ChildAuthorityRefusalV1::Refused)?;
        let result = self.materialize_xmr_child(&request, public_scalar, &mut authority);
        self.materialization = Some(authority);
        result
    }

    fn externalize(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        self.validate_common_bindings(
            request.face(),
            request.action(),
            request.exposure(),
            request.settlement_id(),
            request.terms_digest(),
            request.registry_digest(),
            request.profile_digest(),
            request.deployment_digest(),
            request.chain_id(),
        )?;
        let action = request.action();
        let Some(kind) = operation_for_action(action) else {
            // External funding: the child verifies, it never broadcasts.
            self.validate_funding_request(
                request.expected_transaction_id(),
                request.custody_digest(),
                request.intent_digest(),
            )?;
            let mut authority = self
                .materialization
                .take()
                .ok_or(ChildAuthorityRefusalV1::Refused)?;
            let facts = authority
                .sweep_authority
                .verify_external_funding(request.attempt_id());
            self.materialization = Some(authority);
            let facts = facts?;
            if facts.spendable
                && facts.received_amount_piconero == self.setup.expected_amount_piconero()
            {
                return Ok(ChildExecutionOutcomeV1::Externalized(
                    Self::externalized_receipt(request)?,
                ));
            }
            let binding = ChildEvidenceBindingV1::from_dispatch(request);
            return Ok(ChildExecutionOutcomeV1::Unknown {
                evidence_digest: unknown_evidence_v1(&binding)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            });
        };
        let view = self.validated_view(
            kind,
            action,
            request.expected_transaction_id(),
            request.custody_digest(),
            request.intent_digest(),
        )?;
        if !matches!(
            view.stage,
            XmrTxStageV1::Signed | XmrTxStageV1::SendAttempted
        ) {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let now = self.clock.now_unix_ms()?;
        let outcome = self
            .actuator
            .broadcast_current(
                &self.lease,
                self.locator(kind),
                request.attempt_id(),
                &mut self.broadcast,
                now,
            )
            .map_err(map_actuator_error)?;
        if outcome.accepted {
            Ok(ChildExecutionOutcomeV1::Externalized(
                Self::externalized_receipt(request)?,
            ))
        } else {
            let binding = ChildEvidenceBindingV1::from_dispatch(request);
            Ok(ChildExecutionOutcomeV1::Unknown {
                evidence_digest: unknown_evidence_v1(&binding)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            })
        }
    }

    fn reconcile(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        let dispatch = &request.dispatch;
        if request.current_route_fencing_epoch < dispatch.route_fencing_epoch()
            || request.current_coordinator_fencing_epoch < dispatch.coordinator_fencing_epoch()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.validate_common_bindings(
            dispatch.face(),
            dispatch.action(),
            dispatch.exposure(),
            dispatch.settlement_id(),
            dispatch.terms_digest(),
            dispatch.registry_digest(),
            dispatch.profile_digest(),
            dispatch.deployment_digest(),
            dispatch.chain_id(),
        )?;
        let action = dispatch.action();
        let binding = ChildEvidenceBindingV1::from_dispatch(dispatch);
        let Some(kind) = operation_for_action(action) else {
            // External funding: presence at depth externalizes; absence
            // proves nothing about an external funder and stays Unknown.
            self.validate_funding_request(
                dispatch.expected_transaction_id(),
                dispatch.custody_digest(),
                dispatch.intent_digest(),
            )?;
            let min_confirmations = self.min_confirmations;
            return match self.funding_inclusion()? {
                Some(inclusion) if inclusion.confirmations >= min_confirmations => {
                    Ok(ChildReconciliationOutcomeV1::Externalized(
                        Self::externalized_receipt(dispatch)?,
                    ))
                }
                _ => Ok(ChildReconciliationOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                }),
            };
        };
        let view = self.validated_view(
            kind,
            action,
            dispatch.expected_transaction_id(),
            dispatch.custody_digest(),
            dispatch.intent_digest(),
        )?;
        // Bytes retained but never offered to any daemon cannot have crossed
        // the boundary: the stage moves to SendAttempted before first send.
        if view.stage == XmrTxStageV1::Signed {
            return Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized {
                evidence_digest: proven_not_externalized_evidence_v1(&binding)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            });
        }
        let now = self.clock.now_unix_ms()?;
        let outcome = self
            .actuator
            .reconcile_takeover(
                &self.lease,
                self.locator(kind),
                request.reconciliation_attempt_id,
                &mut self.observation,
                self.min_confirmations,
                now,
            )
            .map_err(map_actuator_error)?;
        match outcome.kind {
            // Txid absent with the sweep's own key image unspent: the
            // adjudicated Monero absence statement (CHILD_SOCKETS_DESIGN §5).
            // Point-in-time — the coordinator treats it exactly as it treats
            // the Bitcoin child's not-externalized proof.
            XmrReconciliationKindV1::KeyImageUnspentAbsent => {
                Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized {
                    evidence_digest: proven_not_externalized_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            XmrReconciliationKindV1::Observed | XmrReconciliationKindV1::Final => Ok(
                ChildReconciliationOutcomeV1::Externalized(Self::externalized_receipt(dispatch)?),
            ),
            XmrReconciliationKindV1::Unknown => Ok(ChildReconciliationOutcomeV1::Unknown {
                evidence_digest: unknown_evidence_v1(&binding)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            }),
        }
    }

    fn observe(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.validate_common_bindings(
            request.face,
            request.action,
            request.exposure,
            request.settlement_id,
            request.terms_digest,
            request.registry_digest,
            request.profile_digest,
            request.deployment_digest,
            request.chain_id,
        )?;
        let action = request.action;
        let binding = ChildObservationEvidenceBindingV1::from_observation(request);
        let Some(kind) = operation_for_action(action) else {
            self.validate_funding_request(
                request.transaction_id,
                request.custody_digest,
                request.intent_digest,
            )?;
            let min_confirmations = self.min_confirmations;
            let funding_tx_hash = self.setup.funding_tx_hash();
            return match self.funding_inclusion()? {
                Some(inclusion) if inclusion.confirmations >= min_confirmations => {
                    let facts = ChildFinalityFactsV1 {
                        final_evidence_digest: digest_parts(
                            FUNDING_EVIDENCE_DOMAIN_V1,
                            &[
                                funding_tx_hash.as_slice(),
                                &inclusion.height.to_be_bytes(),
                                inclusion.block_hash.as_slice(),
                                &inclusion.confirmations.to_be_bytes(),
                            ],
                        )?,
                        final_block_hash: inclusion.block_hash,
                        final_block_number: inclusion.height,
                    };
                    Ok(ChildObservationOutcomeV1::Final {
                        evidence_digest: observation_final_evidence_v1(&binding, &facts)
                            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                    })
                }
                _ => Ok(ChildObservationOutcomeV1::Pending {
                    evidence_digest: observation_pending_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                }),
            };
        };
        let view = self.validated_view(
            kind,
            action,
            request.transaction_id,
            request.custody_digest,
            request.intent_digest,
        )?;
        if !matches!(
            view.stage,
            XmrTxStageV1::SendAttempted
                | XmrTxStageV1::Observed
                | XmrTxStageV1::Final
                | XmrTxStageV1::FinalityInvalidated
        ) {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let now = self.clock.now_unix_ms()?;
        let view = self
            .actuator
            .observe_current(
                &self.lease,
                self.locator(kind),
                request.observation_attempt_id,
                &mut self.observation,
                self.min_confirmations,
                now,
            )
            .map_err(map_actuator_error)?;
        match view.stage {
            XmrTxStageV1::SendAttempted | XmrTxStageV1::Observed => {
                Ok(ChildObservationOutcomeV1::Pending {
                    evidence_digest: observation_pending_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            XmrTxStageV1::Final => {
                let finality = view.finality.ok_or(ChildAuthorityRefusalV1::Conflict)?;
                let facts = ChildFinalityFactsV1 {
                    final_evidence_digest: finality.final_evidence_digest,
                    final_block_hash: finality.final_block_hash,
                    final_block_number: finality.final_height,
                };
                Ok(ChildObservationOutcomeV1::Final {
                    evidence_digest: observation_final_evidence_v1(&binding, &facts)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            XmrTxStageV1::FinalityInvalidated => {
                let Some(prior) = request.prior_finality_evidence_digest else {
                    return Ok(ChildObservationOutcomeV1::Pending {
                        evidence_digest: observation_pending_evidence_v1(&binding)
                            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                    });
                };
                let invalidation = digest_parts(
                    INVALIDATION_DOMAIN_V1,
                    &[view.tx_hash.as_slice(), &view.revision.to_be_bytes()],
                )?;
                Ok(ChildObservationOutcomeV1::FinalityInvalidated {
                    prior_finality_evidence_digest: prior,
                    reorg_evidence_digest: observation_reorg_evidence_v1(
                        &binding,
                        prior,
                        invalidation,
                    )
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funding_has_no_actuator_row_and_sweeps_map_one_to_one() {
        assert_eq!(operation_for_action(SettlementActionV1::Funding), None);
        assert_eq!(
            operation_for_action(SettlementActionV1::Claim),
            Some(XmrOperationKindV1::Claim)
        );
        assert_eq!(
            operation_for_action(SettlementActionV1::Refund),
            Some(XmrOperationKindV1::Refund)
        );
    }

    #[test]
    fn transaction_and_intent_identities_are_domain_separated_and_stable() {
        let first = transaction_id_v1([7; 32]).expect("transaction id");
        assert_eq!(first, transaction_id_v1([7; 32]).expect("replay"));
        assert_ne!(first, ZERO_DIGEST);
        assert_ne!(first, transaction_id_v1([8; 32]).expect("other"));
        let intent = intent_digest_v1([1; 32], SettlementActionV1::Claim, [2; 32]).expect("intent");
        assert_ne!(
            intent,
            intent_digest_v1([1; 32], SettlementActionV1::Refund, [2; 32]).expect("other action")
        );
        assert_ne!(
            intent,
            intent_digest_v1([1; 32], SettlementActionV1::Funding, [2; 32]).expect("funding")
        );
    }

    #[test]
    fn actuator_error_taxonomy_fails_closed() {
        assert_eq!(
            map_actuator_error(XmrActuatorErrorV1::ObservationUnavailable),
            ChildAuthorityRefusalV1::Unavailable
        );
        assert_eq!(
            map_actuator_error(XmrActuatorErrorV1::NotFound),
            ChildAuthorityRefusalV1::Refused
        );
        assert_eq!(
            map_actuator_error(XmrActuatorErrorV1::Corrupt),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(XmrActuatorErrorV1::LeaseExpired),
            ChildAuthorityRefusalV1::Conflict
        );
    }
}

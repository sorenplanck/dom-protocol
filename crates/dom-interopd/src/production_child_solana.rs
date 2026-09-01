//! Production settlement-child authority for the Solana face.
//!
//! The coordinator journals every dispatch before this boundary. The port
//! owns one durable Solana actuator plus a quorum RPC pool; the fee-payer
//! signing keys stay behind scoped signer handles that can only sign the
//! exact legacy message this module built from the DLEQ-authenticated escrow
//! setup. Raw transactions never leave the actuator, and a composition
//! verified route scalar is borrowed only for an exact claim message, then
//! zeroized as soon as the actuator durably retains the signed bytes.
//!
//! Every escrow transaction here has exactly one signer — its fee payer —
//! because the escrow program's own accounts are PDAs. That collapses the
//! signature set to one ed25519 signature over the exact message bytes,
//! which is re-verified whenever retained custody is revalidated.

use std::time::{SystemTime, UNIX_EPOCH};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use deployment_registry::ResolvedSolanaDeploymentV1;
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
use solana_actuator::{
    DurableSolanaActuatorV1, SolanaActuatorErrorV1, SolanaActuatorLeaseV1, SolanaOperationKindV1,
    SolanaOperationLocatorV1, SolanaOperationViewV1, SolanaReconciliationKindV1, SolanaTxStageV1,
};
use solana_profile::ValidatedSolanaSetup;
use solana_rpc::SolanaRpc;
use solana_rpc_pool::SolanaRpcPool;
use solana_transaction_builder::{
    assemble_signed_transaction, build_legacy_message, primary_signature,
};
use solana_types::{SolanaHash, SolanaInstruction, SolanaPubkey, SolanaSignature};
use xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar;
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
const TRANSACTION_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/SOLANA-CHILD/TRANSACTION-ID/V1\0";
const INTENT_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/SOLANA-CHILD/INTENT/V1\0";
const INVALIDATION_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/SOLANA-CHILD/INVALIDATION/V1\0";
const SOLANA_DEPLOYMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/SOLANA-CHILD/DEPLOYMENT-DIGEST/V1\0";
/// Widest tolerated spread between quorum finalized-height readings.
const MAX_QUORUM_HEIGHT_SPREAD_V1: u64 = 64;
/// A fresh blockhash's validity must sit inside this many blocks above the
/// quorum finalized floor (~150-block cluster window plus quorum drift). A
/// node quoting a farther horizon is inventing one, and an invented horizon
/// would postpone the expiry proof indefinitely.
const MAX_BLOCKHASH_HORIZON_V1: u64 = 512;

/// One ed25519 fee-payer signing handle, scoped to a single account.
///
/// The port hands it exact message bytes it built itself; the signer never
/// sees a secret scalar and cannot choose what it signs.
pub(crate) trait ScopedSolanaSignerV1 {
    /// The only account this handle may sign for.
    fn account(&self) -> SolanaPubkey;
    /// Signs the exact message bytes.
    fn sign_message(&mut self, message: &[u8]) -> Result<SolanaSignature, ChildAuthorityRefusalV1>;
}

/// Trusted clock boundary used for actuator lease checks.
pub(crate) trait ProductionSolanaChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1>;
}

/// Host wall-time adapter for the production composition root.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemProductionSolanaChildClockV1;

impl ProductionSolanaChildClockV1 for SystemProductionSolanaChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ChildAuthorityRefusalV1::Unavailable)
    }
}

/// Authenticated, non-fabricable scope used to install Solana materialization.
/// Its fields are derived from admitted inputs and a fully authenticated role
/// plan; callers cannot supply route/composition/source commitments directly.
pub(crate) struct ProductionSolanaMaterializationScopeV1 {
    route_id: Digest32,
    leg: settlement_coordinator::SettlementLegV1,
    settlement_id: Digest32,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
}

impl ProductionSolanaMaterializationScopeV1 {
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
            || inputs.solana_session(leg).is_none()
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

struct ProductionSolanaMaterializationAuthorityV1 {
    funder_signer: Box<dyn ScopedSolanaSignerV1>,
    beneficiary_signer: Box<dyn ScopedSolanaSignerV1>,
    route_id: Digest32,
    leg: settlement_coordinator::SettlementLegV1,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
}

/// Owner-scoped production bridge from coordinator calls to one Solana
/// actuator over one DLEQ-authenticated escrow setup.
pub(crate) struct ProductionSolanaChildPortV1<R, C> {
    actuator: DurableSolanaActuatorV1,
    pool: SolanaRpcPool<R>,
    deployment: ResolvedSolanaDeploymentV1,
    setup: ValidatedSolanaSetup,
    funder_lease: SolanaActuatorLeaseV1,
    beneficiary_lease: SolanaActuatorLeaseV1,
    clock: C,
    settlement_id: Digest32,
    materialization: Option<ProductionSolanaMaterializationAuthorityV1>,
}

impl<R, C> core::fmt::Debug for ProductionSolanaChildPortV1<R, C> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSolanaChildPortV1([authorities redacted])")
    }
}

const fn operation_for_action(action: SettlementActionV1) -> SolanaOperationKindV1 {
    match action {
        SettlementActionV1::Funding => SolanaOperationKindV1::Fund,
        SettlementActionV1::Claim => SolanaOperationKindV1::Claim,
        SettlementActionV1::Refund => SolanaOperationKindV1::Refund,
    }
}

const fn action_uses_beneficiary(action: SettlementActionV1) -> bool {
    matches!(action, SettlementActionV1::Claim)
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

/// Public transaction identity of the retained signature.
fn transaction_id_v1(signature: SolanaSignature) -> Result<Digest32, ChildAuthorityRefusalV1> {
    digest_parts(TRANSACTION_ID_DOMAIN_V1, &[signature.0.as_slice()])
}

/// Intent commitment derived from durable facts, recomputable at any stage
/// without the claim scalar: it binds action and settlement to the exact
/// retained byte custody.
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

/// Deterministic commitment to the exact resolved Solana deployment: the
/// registry identity, the chain profile, the cluster genesis, the fee bound
/// and the pinned escrow program. `SolanaDeploymentV1` carries no digest of
/// its own, so this is the one place that derives it.
pub(crate) fn resolved_solana_deployment_digest_v1(
    deployment: &ResolvedSolanaDeploymentV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let (escrow_program, program_data_hash) = match deployment.profile().kind {
        chain_profile::ChainKindV1::Solana {
            escrow_program,
            program_data_hash,
            ..
        } => (escrow_program, program_data_hash),
        _ => return Err(ChildAuthorityRefusalV1::Conflict),
    };
    digest_parts(
        SOLANA_DEPLOYMENT_DIGEST_DOMAIN_V1,
        &[
            &deployment.registry_digest(),
            &deployment.registry_epoch().to_be_bytes(),
            &deployment.profile_digest(),
            &deployment.asset_binding_digest(),
            &deployment.profile().chain_id.0,
            &deployment.deployment().genesis_hash,
            &deployment.deployment().max_fee_lamports.to_be_bytes(),
            &escrow_program,
            &program_data_hash,
        ],
    )
}

fn map_actuator_error(error: SolanaActuatorErrorV1) -> ChildAuthorityRefusalV1 {
    match error {
        SolanaActuatorErrorV1::StorageUnavailable | SolanaActuatorErrorV1::QuorumUnavailable => {
            ChildAuthorityRefusalV1::Unavailable
        }
        SolanaActuatorErrorV1::NotFound => ChildAuthorityRefusalV1::Refused,
        SolanaActuatorErrorV1::InvalidLease
        | SolanaActuatorErrorV1::LeaseExpired
        | SolanaActuatorErrorV1::Corrupt
        | SolanaActuatorErrorV1::Conflict
        | SolanaActuatorErrorV1::InvalidInput
        | SolanaActuatorErrorV1::InvalidTime => ChildAuthorityRefusalV1::Conflict,
    }
}

impl<R: SolanaRpc, C: ProductionSolanaChildClockV1> ProductionSolanaChildPortV1<R, C> {
    pub(crate) fn new(
        actuator: DurableSolanaActuatorV1,
        pool: SolanaRpcPool<R>,
        deployment: ResolvedSolanaDeploymentV1,
        setup: ValidatedSolanaSetup,
        funder_lease: SolanaActuatorLeaseV1,
        beneficiary_lease: SolanaActuatorLeaseV1,
        clock: C,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let settlement_id = setup.settlement_id();
        if settlement_id == ZERO_DIGEST
            || funder_lease.genesis_hash() != deployment.deployment().genesis_hash
            || beneficiary_lease.genesis_hash() != deployment.deployment().genesis_hash
            || funder_lease.fee_payer() != setup.funder()
            || beneficiary_lease.fee_payer() != setup.recipient()
            || funder_lease.fencing_epoch() == 0
            || beneficiary_lease.fencing_epoch() == 0
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            actuator,
            pool,
            deployment,
            setup,
            funder_lease,
            beneficiary_lease,
            clock,
            settlement_id,
            materialization: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_materializing(
        actuator: DurableSolanaActuatorV1,
        pool: SolanaRpcPool<R>,
        deployment: ResolvedSolanaDeploymentV1,
        setup: ValidatedSolanaSetup,
        funder_lease: SolanaActuatorLeaseV1,
        beneficiary_lease: SolanaActuatorLeaseV1,
        clock: C,
        funder_signer: Box<dyn ScopedSolanaSignerV1>,
        beneficiary_signer: Box<dyn ScopedSolanaSignerV1>,
        scope: ProductionSolanaMaterializationScopeV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if scope.settlement_id != setup.settlement_id()
            || funder_signer.account() != setup.funder()
            || beneficiary_signer.account() != setup.recipient()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let mut port = Self::new(
            actuator,
            pool,
            deployment,
            setup,
            funder_lease,
            beneficiary_lease,
            clock,
        )?;
        port.materialization = Some(ProductionSolanaMaterializationAuthorityV1 {
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

    const fn lease(&self, action: SettlementActionV1) -> SolanaActuatorLeaseV1 {
        if action_uses_beneficiary(action) {
            self.beneficiary_lease
        } else {
            self.funder_lease
        }
    }

    fn locator(&self, action: SettlementActionV1) -> SolanaOperationLocatorV1 {
        SolanaOperationLocatorV1 {
            settlement_id: self.settlement_id,
            kind: operation_for_action(action),
        }
    }

    /// The exact authenticated instruction set for one economic action.
    ///
    /// Funding is initialize-plus-fund in one atomic transaction, so a
    /// half-created escrow can never strand the funder's lamports.
    fn instructions_for_action(
        &self,
        action: SettlementActionV1,
        claim_secret_be: Option<[u8; 32]>,
    ) -> Result<Vec<SolanaInstruction>, ChildAuthorityRefusalV1> {
        match (action, claim_secret_be) {
            (SettlementActionV1::Funding, None) => Ok(vec![
                solana_program_client::initialize(&self.setup),
                solana_program_client::fund(&self.setup, None)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            ]),
            (SettlementActionV1::Claim, Some(secret)) => {
                Ok(vec![solana_program_client::claim(&self.setup, secret, None)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?])
            }
            (SettlementActionV1::Refund, None) => {
                Ok(vec![solana_program_client::refund(&self.setup, None)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?])
            }
            _ => Err(ChildAuthorityRefusalV1::Refused),
        }
    }

    /// A fresh finalized blockhash whose validity horizon the quorum bounds.
    fn bounded_recent_blockhash(&self) -> Result<(SolanaHash, u64), ChildAuthorityRefusalV1> {
        let floor = self
            .pool
            .finalized_block_height_floor(MAX_QUORUM_HEIGHT_SPREAD_V1)
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        for node in self.pool.nodes() {
            if let Ok((hash, last_valid_block_height)) = node.get_latest_blockhash_with_validity()
            {
                if hash.0 != [0; 32]
                    && last_valid_block_height > floor
                    && last_valid_block_height <= floor.saturating_add(MAX_BLOCKHASH_HORIZON_V1)
                {
                    return Ok((hash, last_valid_block_height));
                }
            }
        }
        Err(ChildAuthorityRefusalV1::Unavailable)
    }

    /// Proves retained bytes are exactly the signed authenticated message.
    ///
    /// Rebuilds the deterministic message from durable facts and re-verifies
    /// the retained ed25519 signature over it. Claims are validated through
    /// their custody digest instead, which materialization bound to the
    /// exact secret-bearing bytes before anything left this port.
    fn validate_retained_transaction(
        &self,
        action: SettlementActionV1,
        view: &SolanaOperationViewV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let raw = self.retained(view.locator).map_err(map_actuator_error)?;
        if solana_actuator::custody_digest_v1(&raw).map_err(map_actuator_error)?
            != view.custody_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        if action == SettlementActionV1::Claim {
            return Ok(());
        }
        let fee_payer = self.lease(action).fee_payer();
        let instructions = self.instructions_for_action(action, None)?;
        let plan = build_legacy_message(fee_payer, view.recent_blockhash, &instructions)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let expected = assemble_signed_transaction(&plan, &[(fee_payer, view.signature)])
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if expected != raw {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    fn retained(
        &self,
        locator: SolanaOperationLocatorV1,
    ) -> Result<Vec<u8>, SolanaActuatorErrorV1> {
        self.actuator.retained(locator)
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
        let exposure_valid = match action {
            SettlementActionV1::Funding | SettlementActionV1::Refund => {
                exposure == ChildExposureV1::NonSecret
            }
            SettlementActionV1::Claim => matches!(
                exposure,
                ChildExposureV1::FirstSecretExposure | ChildExposureV1::UsesPublicSecret
            ),
        };
        if face != SettlementFaceV1::Solana
            || !exposure_valid
            || settlement_id != self.settlement_id
            || registry_digest != self.deployment.registry_digest()
            || profile_digest != self.deployment.profile_digest()
            || deployment_digest != resolved_solana_deployment_digest_v1(&self.deployment)?
            || chain_id != self.deployment.profile().chain_id.0
            || terms_digest != self.setup.terms_hash()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    fn validated_view(
        &self,
        action: SettlementActionV1,
        expected_transaction_id: Digest32,
        expected_custody_digest: Digest32,
        expected_intent_digest: Digest32,
    ) -> Result<SolanaOperationViewV1, ChildAuthorityRefusalV1> {
        let view = self
            .actuator
            .view(self.locator(action))
            .map_err(map_actuator_error)?;
        if view.custody_digest != expected_custody_digest
            || transaction_id_v1(view.signature)? != expected_transaction_id
            || intent_digest_v1(self.settlement_id, action, view.custody_digest)?
                != expected_intent_digest
            || view.secret_exposed != (operation_for_action(action) == SolanaOperationKindV1::Claim)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.validate_retained_transaction(action, &view)?;
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

    fn materialize_solana_child(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        public_scalar: Option<&RouteScalar>,
        authority: &mut ProductionSolanaMaterializationAuthorityV1,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let scalar_shape = matches!(
            (request.action, request.exposure, public_scalar),
            (
                SettlementActionV1::Funding | SettlementActionV1::Refund,
                ChildExposureV1::NonSecret,
                None,
            ) | (
                SettlementActionV1::Claim,
                ChildExposureV1::FirstSecretExposure | ChildExposureV1::UsesPublicSecret,
                Some(_),
            )
        );
        if !scalar_shape
            || request.route_id == ZERO_DIGEST
            || request.effect_id == ZERO_DIGEST
            || request.fencing_epoch == 0
            || request.semantic_digest == ZERO_DIGEST
            || request.deployment_digest == ZERO_DIGEST
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
            SettlementFaceV1::Solana,
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
        let lease = self.lease(action);
        let locator = self.locator(action);
        // A verified route scalar is borrowed only into exact claim message
        // bytes; the local copy is zeroized before this function returns.
        let mut claim_secret = [0u8; 32];
        let claim_secret_arg = match public_scalar {
            Some(scalar) => {
                claim_secret.copy_from_slice(scalar.expose());
                if revealed_dom_secret_to_xmr_scalar(claim_secret, &self.setup.claim()).is_err() {
                    claim_secret.zeroize();
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Some(claim_secret)
            }
            None => None,
        };
        let result = self.materialize_with_secret(action, lease, locator, claim_secret_arg, authority);
        claim_secret.zeroize();
        result
    }

    fn materialize_with_secret(
        &mut self,
        action: SettlementActionV1,
        lease: SolanaActuatorLeaseV1,
        locator: SolanaOperationLocatorV1,
        claim_secret_be: Option<[u8; 32]>,
        authority: &mut ProductionSolanaMaterializationAuthorityV1,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let mut instructions = self.instructions_for_action(action, claim_secret_be)?;
        let fee_payer = lease.fee_payer();
        let now = self.clock.now_unix_ms()?;
        let view = match self.actuator.view(locator) {
            Ok(view) => {
                // Idempotent reopen: the exact bytes are already retained.
                // Re-verify custody against the authenticated instruction
                // set at the retained blockhash before answering.
                let plan =
                    build_legacy_message(fee_payer, view.recent_blockhash, &instructions)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                let expected =
                    assemble_signed_transaction(&plan, &[(fee_payer, view.signature)])
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                let retained = self.retained(locator).map_err(map_actuator_error)?;
                if expected != retained {
                    zeroize_instruction_data(&mut instructions);
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                view
            }
            Err(SolanaActuatorErrorV1::NotFound) => {
                let (recent_blockhash, last_valid_block_height) =
                    self.bounded_recent_blockhash()?;
                let plan = build_legacy_message(fee_payer, recent_blockhash, &instructions)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                let signer = if action_uses_beneficiary(action) {
                    authority.beneficiary_signer.as_mut()
                } else {
                    authority.funder_signer.as_mut()
                };
                if signer.account() != fee_payer {
                    zeroize_instruction_data(&mut instructions);
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let signature = signer.sign_message(&plan.message)?;
                let raw = assemble_signed_transaction(&plan, &[(fee_payer, signature)])
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                let primary = primary_signature(&plan, &[(fee_payer, signature)])
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
                self.actuator
                    .prepare_signed(
                        &lease,
                        locator,
                        primary,
                        &raw,
                        recent_blockhash,
                        last_valid_block_height,
                        now,
                    )
                    .map_err(map_actuator_error)?
            }
            Err(error) => {
                zeroize_instruction_data(&mut instructions);
                return Err(map_actuator_error(error));
            }
        };
        zeroize_instruction_data(&mut instructions);
        if view.stage == SolanaTxStageV1::FinalityInvalidated {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(SettlementChildPlanV1 {
            face: SettlementFaceV1::Solana,
            exposure: if action == SettlementActionV1::Claim {
                if view.stage == SolanaTxStageV1::Signed {
                    ChildExposureV1::FirstSecretExposure
                } else {
                    ChildExposureV1::UsesPublicSecret
                }
            } else {
                ChildExposureV1::NonSecret
            },
            chain_id: self.deployment.profile().chain_id.0,
            expected_transaction_id: transaction_id_v1(view.signature)?,
            intent_digest: intent_digest_v1(self.settlement_id, action, view.custody_digest)?,
            custody_digest: view.custody_digest,
        })
    }
}

/// Best-effort scrub of instruction data buffers that may carry the claim
/// scalar. The exact signed bytes live on only inside the actuator's custody.
fn zeroize_instruction_data(instructions: &mut [SolanaInstruction]) {
    for instruction in instructions {
        instruction.data.zeroize();
    }
}

impl<R: SolanaRpc, C: ProductionSolanaChildClockV1> ProductionSettlementChildPortV1
    for ProductionSolanaChildPortV1<R, C>
{
    fn face(&self) -> SettlementFaceV1 {
        SettlementFaceV1::Solana
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
        let result = self.materialize_solana_child(&request, public_scalar, &mut authority);
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
        let view = self.validated_view(
            action,
            request.expected_transaction_id(),
            request.custody_digest(),
            request.intent_digest(),
        )?;
        if !matches!(
            view.stage,
            SolanaTxStageV1::Signed | SolanaTxStageV1::SendAttempted
        ) {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let lease = self.lease(action);
        let now = self.clock.now_unix_ms()?;
        let outcome = self
            .actuator
            .broadcast_current(
                &lease,
                self.locator(action),
                request.attempt_id(),
                &self.pool,
                now,
            )
            .map_err(map_actuator_error)?;
        if outcome.accepted > 0 {
            Ok(ChildExecutionOutcomeV1::Externalized(
                Self::externalized_receipt(request)?,
            ))
        } else {
            // Every node refused or was unreachable, but the durable stage is
            // already SendAttempted: bytes may still be in flight somewhere.
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
        let view = self.validated_view(
            action,
            dispatch.expected_transaction_id(),
            dispatch.custody_digest(),
            dispatch.intent_digest(),
        )?;
        let binding = ChildEvidenceBindingV1::from_dispatch(dispatch);
        // Bytes retained but never offered to any node cannot have crossed
        // the boundary: the durable stage moves to SendAttempted before the
        // first send, so Signed is itself the proof.
        if view.stage == SolanaTxStageV1::Signed {
            return Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized {
                evidence_digest: proven_not_externalized_evidence_v1(&binding)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            });
        }
        let lease = self.lease(action);
        let now = self.clock.now_unix_ms()?;
        let outcome = self
            .actuator
            .reconcile_takeover(
                &lease,
                self.locator(action),
                request.reconciliation_attempt_id,
                &self.pool,
                now,
            )
            .map_err(map_actuator_error)?;
        match outcome.kind {
            // The blockhash expired with the signature absent at the quorum:
            // Solana's positive proof that the exact bytes can never land.
            SolanaReconciliationKindV1::ExpiredNeverLanded => {
                Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized {
                    evidence_digest: proven_not_externalized_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            SolanaReconciliationKindV1::Observed | SolanaReconciliationKindV1::Final => {
                Ok(ChildReconciliationOutcomeV1::Externalized(
                    Self::externalized_receipt(dispatch)?,
                ))
            }
            SolanaReconciliationKindV1::Unknown => {
                if outcome.view.stage == SolanaTxStageV1::FinalityInvalidated {
                    // Landed and failed: the bytes are public even though the
                    // program refused them.
                    return Ok(ChildReconciliationOutcomeV1::Externalized(
                        Self::externalized_receipt(dispatch)?,
                    ));
                }
                Ok(ChildReconciliationOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
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
        let view = self.validated_view(
            action,
            request.transaction_id,
            request.custody_digest,
            request.intent_digest,
        )?;
        if !matches!(
            view.stage,
            SolanaTxStageV1::SendAttempted
                | SolanaTxStageV1::Observed
                | SolanaTxStageV1::Final
                | SolanaTxStageV1::FinalityInvalidated
        ) {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let lease = self.lease(action);
        let now = self.clock.now_unix_ms()?;
        let view = self
            .actuator
            .observe_current(
                &lease,
                self.locator(action),
                request.observation_attempt_id,
                &self.pool,
                now,
            )
            .map_err(map_actuator_error)?;
        let binding = ChildObservationEvidenceBindingV1::from_observation(request);
        match view.stage {
            SolanaTxStageV1::SendAttempted | SolanaTxStageV1::Observed => {
                Ok(ChildObservationOutcomeV1::Pending {
                    evidence_digest: observation_pending_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            SolanaTxStageV1::Final => {
                let finality = view.finality.ok_or(ChildAuthorityRefusalV1::Conflict)?;
                let facts = ChildFinalityFactsV1 {
                    final_evidence_digest: finality.final_evidence_digest,
                    final_block_hash: finality.final_blockhash.0,
                    final_block_number: finality.final_slot,
                };
                Ok(ChildObservationOutcomeV1::Final {
                    evidence_digest: observation_final_evidence_v1(&binding, &facts)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            SolanaTxStageV1::FinalityInvalidated => {
                let Some(prior) = request.prior_finality_evidence_digest else {
                    return Ok(ChildObservationOutcomeV1::Pending {
                        evidence_digest: observation_pending_evidence_v1(&binding)
                            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                    });
                };
                let invalidation = digest_parts(
                    INVALIDATION_DOMAIN_V1,
                    &[view.signature.0.as_slice(), &view.revision.to_be_bytes()],
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
    fn action_mapping_assigns_the_claim_to_the_beneficiary_alone() {
        assert_eq!(
            operation_for_action(SettlementActionV1::Funding),
            SolanaOperationKindV1::Fund
        );
        assert_eq!(
            operation_for_action(SettlementActionV1::Claim),
            SolanaOperationKindV1::Claim
        );
        assert_eq!(
            operation_for_action(SettlementActionV1::Refund),
            SolanaOperationKindV1::Refund
        );
        assert!(action_uses_beneficiary(SettlementActionV1::Claim));
        assert!(!action_uses_beneficiary(SettlementActionV1::Funding));
        assert!(!action_uses_beneficiary(SettlementActionV1::Refund));
    }

    #[test]
    fn transaction_and_intent_identities_are_domain_separated_and_stable() {
        let signature = SolanaSignature([7; 64]);
        let first = transaction_id_v1(signature).expect("transaction id");
        assert_eq!(first, transaction_id_v1(signature).expect("replay"));
        assert_ne!(first, ZERO_DIGEST);
        assert_ne!(
            first,
            transaction_id_v1(SolanaSignature([8; 64])).expect("other")
        );
        let intent = intent_digest_v1([1; 32], SettlementActionV1::Claim, [2; 32]).expect("intent");
        assert_ne!(
            intent,
            intent_digest_v1([1; 32], SettlementActionV1::Refund, [2; 32]).expect("other action")
        );
        assert_ne!(
            intent,
            intent_digest_v1([1; 32], SettlementActionV1::Claim, [3; 32]).expect("other custody")
        );
    }

    #[test]
    fn actuator_error_taxonomy_fails_closed() {
        assert_eq!(
            map_actuator_error(SolanaActuatorErrorV1::QuorumUnavailable),
            ChildAuthorityRefusalV1::Unavailable
        );
        assert_eq!(
            map_actuator_error(SolanaActuatorErrorV1::NotFound),
            ChildAuthorityRefusalV1::Refused
        );
        assert_eq!(
            map_actuator_error(SolanaActuatorErrorV1::Corrupt),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(SolanaActuatorErrorV1::LeaseExpired),
            ChildAuthorityRefusalV1::Conflict
        );
    }
}

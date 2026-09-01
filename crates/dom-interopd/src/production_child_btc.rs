//! Production settlement-child authority for the Bitcoin face.
//!
//! Exact transaction bytes, funding PSBTs and route scalars remain inside the
//! Bitcoin authorities. Every coordinator result is committed to the
//! actuator's durable port-call journal before crossing this boundary.

use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use adapter_btc::timelock::BitcoinCsvDelayV1;
use adapter_btc::types::BitcoinNetworkV1;
use adapter_btc_live::{
    ArmedBitcoinFundingV1, BitcoinCoreNetworkV1, BitcoinCoreRpcClientV1,
    BitcoinExternalFundingCustodyV1, BitcoinPrebroadcastStoreV1, BitcoinRefundDelayV1,
    FreshBitcoinClaimExtractionAuthorityV1, FreshBitcoinPreparedClaimPublicV1,
    FreshBitcoinRevealedSecretV1, LiveBitcoinError, ReopenedBitcoinFundingV1,
    ReopenedFreshBitcoinClaimV1,
};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_actuator::{
    resolved_bitcoin_deployment_digest_v1, BitcoinActionV1, BitcoinActuationScopeAuthorizationV1,
    BitcoinActuationScopeV1, BitcoinActuatorErrorV1, BitcoinAdaptorSecretV1, BitcoinClaimSessionV1,
    BitcoinDurableOperationViewV1, BitcoinFeeBumpPolicyV1, BitcoinFundingCustodyViewV1,
    BitcoinOperationBindingViewV1, BitcoinOperationKindV1, BitcoinOperationLocatorV1,
    BitcoinOperationStageV1, BitcoinOperationViewV1, BitcoinPortCallJournalStatusV1,
    BitcoinPortCallKeyV1, BitcoinPortCallKindV1, BitcoinPortCallOutcomeV1, BitcoinPreSignatureV1,
    BitcoinReconciliationV1, BitcoinRpcV1, BitcoinStorageLeaseStatusV1, DurableBitcoinActuatorV1,
    ExactBitcoinTransactionV1,
};
use deployment_registry::ResolvedBitcoinDeploymentV1;
use route_composer::{
    ComposedBindingV2, ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1,
    FinalClaimSecretSourceScopeV1,
};
use route_executor::LegIdV1;
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
    ProductionBitcoinExtractionHandoffScopeV1, ProductionChildMaterializationRequestV1,
    ProductionSettlementChildPortV1,
};
use crate::production_refund_arming::production_bitcoin_refund_route_binding_v1;
use crate::{AuthenticatedProductionInputsV1, AuthenticatedRouteAdmissionV1};

const ZERO_DIGEST: Digest32 = [0; 32];
const DISPATCH_REQUEST_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/BTC-CHILD/DISPATCH-REQUEST/V1\0";
const RECONCILIATION_REQUEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/BTC-CHILD/RECONCILIATION-REQUEST/V1\0";
const OBSERVATION_REQUEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/BTC-CHILD/OBSERVATION-REQUEST/V1\0";
#[expect(
    dead_code,
    reason = "bitcoin claim path frozen until the authenticated M8 round"
)]
const FRESH_CLAIM_FUNDING_OWNER_DOMAIN_V1: &[u8] =
    b"DOM-INTEROP/INTEROPD/BTC-CHILD/FRESH-CLAIM-FUNDING-OWNER/V1\0";

/// Concrete, move-only owner of one exact Bitcoin adaptor pre-signature.
/// It retains a finalized claim for idempotent retry but has no byte/scalar
/// getter, codec, clone or generic signing surface.
pub(crate) struct ProductionBitcoinClaimMaterializationAuthorityV1 {
    session: BitcoinClaimSessionV1,
    state: ProductionBitcoinClaimMaterializationStateV1,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
    #[expect(
        dead_code,
        reason = "bitcoin claim path frozen until the authenticated M8 round"
    )]
    fresh_funding_owner_digest: Option<Digest32>,
    fresh_public: Option<FreshBitcoinPreparedClaimPublicV1>,
}

enum ProductionBitcoinClaimMaterializationStateV1 {
    #[expect(
        dead_code,
        reason = "bitcoin claim path frozen until the authenticated M8 round"
    )]
    ActuatorReady(BitcoinPreSignatureV1),
    Finalized {
        exact: ExactBitcoinTransactionV1,
        fresh_extraction: Option<FreshBitcoinClaimExtractionAuthorityV1>,
        durably_retained: bool,
    },
    RecoveryExtractionOnly {
        expected_txid: Digest32,
        fresh_extraction: Option<FreshBitcoinClaimExtractionAuthorityV1>,
        durably_retained: bool,
    },
    FailedClosed,
}

/// Sole same-process handoff from a finalized fresh claim to canonical public
/// extraction. It retains the already-open Bitcoin Core authority by `Rc`; no
/// second RPC client, credential, or store is opened.
pub(crate) struct ProductionBitcoinPublicExtractionHandoffV1 {
    route_id: Digest32,
    composition_digest: Digest32,
    chain_id: Digest32,
    minimum_confirmations: u32,
    store: Rc<BitcoinPrebroadcastStoreV1>,
    rpc: Rc<BitcoinCoreRpcClientV1>,
    extraction: FreshBitcoinClaimExtractionAuthorityV1,
}

impl core::fmt::Debug for ProductionBitcoinPublicExtractionHandoffV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionBitcoinPublicExtractionHandoffV1([authority redacted])")
    }
}

impl ProductionBitcoinPublicExtractionHandoffV1 {
    /// Exact canonical claim transaction id in internal byte order.
    pub(crate) const fn expected_txid(&self) -> Digest32 {
        self.extraction.expected_txid()
    }

    pub(crate) const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    pub(crate) const fn composition_digest(&self) -> Digest32 {
        self.composition_digest
    }

    pub(crate) const fn chain_id(&self) -> Digest32 {
        self.chain_id
    }

    /// Extracts only after the retained Core authority proves the exact claim
    /// canonical with the requested nonzero confirmation depth.
    pub(crate) fn extract_confirmed(
        &mut self,
    ) -> Result<FreshBitcoinRevealedSecretV1, ChildAuthorityRefusalV1> {
        self.extraction
            .extract_confirmed(&self.store, &self.rpc, self.minimum_confirmations)
            .map_err(map_live_bitcoin_error)
    }
}

impl ProductionBitcoinClaimMaterializationAuthorityV1 {
    #[expect(
        dead_code,
        reason = "bitcoin claim path frozen until the authenticated M8 round"
    )]
    pub(crate) fn bind(
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: &ComposedFinalClaimRolePlanV1,
        upstream_scope: &FinalClaimSecretSourceScopeV1,
        downstream_scope: &FinalClaimSecretSourceScopeV1,
        leg: LegIdV1,
        session: BitcoinClaimSessionV1,
        pre_signature: BitcoinPreSignatureV1,
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
        let (settlement, plan_leg) = match leg {
            LegIdV1::Upstream => (composition.upstream(), ComposedSettlementLegV1::Upstream),
            LegIdV1::Downstream => (
                composition.downstream(),
                ComposedSettlementLegV1::Downstream,
            ),
        };
        let entry = role_plan.entry(plan_leg);
        let deployment = inputs
            .admission()
            .bitcoin_deployment_capability(leg)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if role_plan.route_id() != inputs.admission().route_id()
            || role_plan.route_scope_digest() != composition.route_scope_digest()
            || role_plan.composition_binding_digest() != composition.binding_digest()
            || entry.settlement_id().0 != settlement.settlement_id.0
            || entry.session_id().0 != settlement.session_id.0
            || entry.secret_source_scope_digest() == ZERO_DIGEST
            || session.route_id != role_plan.route_id()
            || session.settlement_id != settlement.settlement_id.0
            || session.session_id != settlement.session_id.0
            || session.terms_digest != inputs.admission().frozen_bindings().terms_digest
            || session.registry_digest != deployment.registry_digest()
            || session.profile_digest != deployment.profile_digest()
            || session.deployment_digest
                != resolved_bitcoin_deployment_digest_v1(&deployment).map_err(map_actuator_error)?
            || session.adaptor_point != composition.adaptor_point_sec1()
            || session.session_digest().map_err(map_actuator_error)?
                != pre_signature.session_digest()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            session,
            state: ProductionBitcoinClaimMaterializationStateV1::ActuatorReady(pre_signature),
            route_scope_digest: composition.route_scope_digest(),
            composition_digest: composition.binding_digest(),
            role_plan_digest: role_plan.digest(),
            source_scope_digest: entry.secret_source_scope_digest(),
            fresh_funding_owner_digest: None,
            fresh_public: None,
        })
    }

    /// Imports only a secret-free V1 claim recovery stage from durable storage.
    ///
    /// Fresh V1 retains both signer secrets and is therefore never a
    /// production signing path. A merely Prepared record is refused. A durable
    /// finalization intent may recover extraction without `t`, but only after
    /// the actuator proves the exact Terminal transaction is retained.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
    )]
    pub(crate) fn bind_recovered_fresh_v1(
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: &ComposedFinalClaimRolePlanV1,
        upstream_scope: &FinalClaimSecretSourceScopeV1,
        downstream_scope: &FinalClaimSecretSourceScopeV1,
        leg: LegIdV1,
        session: BitcoinClaimSessionV1,
        recovered: ReopenedFreshBitcoinClaimV1,
        funding: &ProductionBitcoinFundingAuthorityV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let (public, prepared_record_digest, authenticates_store, state) = match recovered {
            ReopenedFreshBitcoinClaimV1::Prepared(_) => {
                return Err(ChildAuthorityRefusalV1::Refused)
            }
            ReopenedFreshBitcoinClaimV1::ExtractionReady(prepared) => {
                let public = prepared.public().clone();
                let prepared_record_digest = prepared.prepared_record_digest();
                let authenticates_store = prepared.authenticates_store(&funding.store);
                let (_stored_public, extraction) = prepared
                    .into_recovery_extraction_parts()
                    .map_err(map_live_bitcoin_error)?;
                let expected_txid = extraction.expected_txid();
                (
                    public,
                    prepared_record_digest,
                    authenticates_store,
                    ProductionBitcoinClaimMaterializationStateV1::RecoveryExtractionOnly {
                        expected_txid,
                        fresh_extraction: Some(extraction),
                        durably_retained: false,
                    },
                )
            }
            ReopenedFreshBitcoinClaimV1::Finalized(finalized) => {
                let public = finalized.public().clone();
                let prepared_record_digest = finalized.prepared_record_digest();
                let authenticates_store = finalized.authenticates_store(&funding.store);
                let (_stored_public, canonical_transaction, extraction) = finalized.into_parts();
                let exact = ExactBitcoinTransactionV1::from_consensus_bytes(canonical_transaction)
                    .map_err(map_actuator_error)?;
                if exact.txid() != extraction.expected_txid() {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                (
                    public,
                    prepared_record_digest,
                    authenticates_store,
                    ProductionBitcoinClaimMaterializationStateV1::Finalized {
                        exact,
                        fresh_extraction: Some(extraction),
                        durably_retained: false,
                    },
                )
            }
        };
        let fresh_funding_owner_digest = authenticate_fresh_claim_funding_owner_fields(
            &public,
            prepared_record_digest,
            authenticates_store,
            funding,
        )?;
        validate_fresh_claim_session(&session, &public)?;
        let composition = inputs.composition();
        role_plan
            .authenticate(
                composition.upstream(),
                composition.downstream(),
                upstream_scope.clone(),
                downstream_scope.clone(),
            )
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let (settlement, plan_leg) = match leg {
            LegIdV1::Upstream => (composition.upstream(), ComposedSettlementLegV1::Upstream),
            LegIdV1::Downstream => (
                composition.downstream(),
                ComposedSettlementLegV1::Downstream,
            ),
        };
        let entry = role_plan.entry(plan_leg);
        let deployment = inputs
            .admission()
            .bitcoin_deployment_capability(leg)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if role_plan.route_id() != inputs.admission().route_id()
            || role_plan.route_scope_digest() != composition.route_scope_digest()
            || role_plan.composition_binding_digest() != composition.binding_digest()
            || entry.settlement_id().0 != settlement.settlement_id.0
            || entry.session_id().0 != settlement.session_id.0
            || entry.secret_source_scope_digest() == ZERO_DIGEST
            || session.route_id != role_plan.route_id()
            || session.settlement_id != settlement.settlement_id.0
            || session.session_id != settlement.session_id.0
            || session.terms_digest != inputs.admission().frozen_bindings().terms_digest
            || funding.route_id != role_plan.route_id()
            || funding.leg != leg
            || funding.terms_digest != session.terms_digest
            || funding.deployment.registry_digest() != deployment.registry_digest()
            || funding.deployment.profile_digest() != deployment.profile_digest()
            || resolved_bitcoin_deployment_digest_v1(&funding.deployment)
                .map_err(map_actuator_error)?
                != session.deployment_digest
            || session.registry_digest != deployment.registry_digest()
            || session.profile_digest != deployment.profile_digest()
            || session.deployment_digest
                != resolved_bitcoin_deployment_digest_v1(&deployment).map_err(map_actuator_error)?
            || session.adaptor_point != composition.adaptor_point_sec1()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            session,
            state,
            route_scope_digest: composition.route_scope_digest(),
            composition_digest: composition.binding_digest(),
            role_plan_digest: role_plan.digest(),
            source_scope_digest: entry.secret_source_scope_digest(),
            fresh_funding_owner_digest: Some(fresh_funding_owner_digest),
            fresh_public: Some(public),
        })
    }

    fn authenticates_fresh_funding_owner(
        &self,
        funding: &ProductionBitcoinFundingAuthorityV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let (Some(expected), Some(public)) =
            (self.fresh_funding_owner_digest, self.fresh_public.as_ref())
        else {
            return match &self.state {
                ProductionBitcoinClaimMaterializationStateV1::ActuatorReady(_) => Ok(()),
                _ => Err(ChildAuthorityRefusalV1::Conflict),
            };
        };
        let (prepared_record_digest, authenticates_store) = match &self.state {
            ProductionBitcoinClaimMaterializationStateV1::Finalized {
                fresh_extraction: Some(extraction),
                ..
            }
            | ProductionBitcoinClaimMaterializationStateV1::RecoveryExtractionOnly {
                fresh_extraction: Some(extraction),
                ..
            } => (
                extraction.prepared_record_digest(),
                extraction.authenticates_store(&funding.store),
            ),
            _ => return Err(ChildAuthorityRefusalV1::Conflict),
        };
        if authenticate_fresh_claim_funding_owner_fields(
            public,
            prepared_record_digest,
            authenticates_store,
            funding,
        )? == expected
        {
            Ok(())
        } else {
            Err(ChildAuthorityRefusalV1::Conflict)
        }
    }

    fn ensure_exact_claim(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &route_composer::RouteScalar,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        if request.action != SettlementActionV1::Claim
            || request.route_id != self.session.route_id
            || request.effect_id != self.session.effect_id
            || request.settlement_id != self.session.settlement_id
            || request.fencing_epoch != self.session.fence_epoch
            || request.terms_digest != self.session.terms_digest
            || request.registry_digest != self.session.registry_digest
            || request.profile_digest != self.session.profile_digest
            || request.deployment_digest != self.session.deployment_digest
            || request.route_scope_digest != self.route_scope_digest
            || request.composition_digest != self.composition_digest
            || request.role_plan_digest != self.role_plan_digest
            || request.source_scope_digest != self.source_scope_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let mut scalar_bytes = *scalar.expose();
        let secret = BitcoinAdaptorSecretV1::verify(&mut scalar_bytes, self.session.adaptor_point)
            .map_err(map_actuator_error)?;
        if matches!(
            self.state,
            ProductionBitcoinClaimMaterializationStateV1::Finalized { .. }
                | ProductionBitcoinClaimMaterializationStateV1::RecoveryExtractionOnly { .. }
        ) {
            return Ok(());
        }
        let state = core::mem::replace(
            &mut self.state,
            ProductionBitcoinClaimMaterializationStateV1::FailedClosed,
        );
        let finalized = match state {
            ProductionBitcoinClaimMaterializationStateV1::ActuatorReady(pre_signature) => {
                let exact = pre_signature
                    .finalize_claim(secret)
                    .map_err(map_actuator_error)?;
                ProductionBitcoinClaimMaterializationStateV1::Finalized {
                    exact,
                    fresh_extraction: None,
                    durably_retained: false,
                }
            }
            ProductionBitcoinClaimMaterializationStateV1::Finalized { .. }
            | ProductionBitcoinClaimMaterializationStateV1::RecoveryExtractionOnly { .. }
            | ProductionBitcoinClaimMaterializationStateV1::FailedClosed => {
                return Err(ChildAuthorityRefusalV1::Conflict)
            }
        };
        self.state = finalized;
        Ok(())
    }

    fn exact(&self) -> Result<&ExactBitcoinTransactionV1, ChildAuthorityRefusalV1> {
        match &self.state {
            ProductionBitcoinClaimMaterializationStateV1::Finalized { exact, .. } => Ok(exact),
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }

    fn expected_txid(&self) -> Result<Digest32, ChildAuthorityRefusalV1> {
        match &self.state {
            ProductionBitcoinClaimMaterializationStateV1::Finalized { exact, .. } => {
                Ok(exact.txid())
            }
            ProductionBitcoinClaimMaterializationStateV1::RecoveryExtractionOnly {
                expected_txid,
                ..
            } => Ok(*expected_txid),
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }

    fn exact_intent_digest(&self) -> Option<Digest32> {
        match &self.state {
            ProductionBitcoinClaimMaterializationStateV1::Finalized { exact, .. } => {
                Some(exact.intent_digest())
            }
            _ => None,
        }
    }

    fn take_fresh_extraction(
        &mut self,
        expected_txid: Digest32,
    ) -> Result<FreshBitcoinClaimExtractionAuthorityV1, ChildAuthorityRefusalV1> {
        match &mut self.state {
            ProductionBitcoinClaimMaterializationStateV1::Finalized {
                exact,
                fresh_extraction,
                durably_retained: true,
                ..
            } => {
                let authenticated = exact.txid() == expected_txid
                    && fresh_extraction
                        .as_ref()
                        .is_some_and(|extraction| extraction.expected_txid() == expected_txid);
                take_validated_handoff_authority(fresh_extraction, authenticated)
            }
            ProductionBitcoinClaimMaterializationStateV1::RecoveryExtractionOnly {
                expected_txid: retained_txid,
                fresh_extraction,
                durably_retained: true,
            } => {
                let authenticated = *retained_txid == expected_txid
                    && fresh_extraction
                        .as_ref()
                        .is_some_and(|extraction| extraction.expected_txid() == expected_txid);
                take_validated_handoff_authority(fresh_extraction, authenticated)
            }
            _ => Err(ChildAuthorityRefusalV1::Refused),
        }
    }

    fn fresh_extraction_expected_txid(&self) -> Result<Digest32, ChildAuthorityRefusalV1> {
        match &self.state {
            ProductionBitcoinClaimMaterializationStateV1::Finalized {
                exact,
                fresh_extraction: Some(extraction),
                ..
            } if exact.txid() == extraction.expected_txid() => Ok(exact.txid()),
            ProductionBitcoinClaimMaterializationStateV1::RecoveryExtractionOnly {
                expected_txid,
                fresh_extraction: Some(extraction),
                ..
            } if *expected_txid == extraction.expected_txid() => Ok(*expected_txid),
            _ => Err(ChildAuthorityRefusalV1::Refused),
        }
    }

    fn mark_exact_durably_retained(
        &mut self,
        expected_txid: Digest32,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        match &mut self.state {
            ProductionBitcoinClaimMaterializationStateV1::Finalized {
                exact,
                durably_retained,
                ..
            } if exact.txid() == expected_txid => {
                *durably_retained = true;
                Ok(())
            }
            ProductionBitcoinClaimMaterializationStateV1::RecoveryExtractionOnly {
                expected_txid: retained_txid,
                durably_retained,
                ..
            } if *retained_txid == expected_txid => {
                *durably_retained = true;
                Ok(())
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }
}

#[expect(
    dead_code,
    reason = "bitcoin claim path frozen until the authenticated M8 round"
)]
fn validate_fresh_claim_session(
    session: &BitcoinClaimSessionV1,
    public: &FreshBitcoinPreparedClaimPublicV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    let network_matches = matches!(
        (session.network, public.network),
        (BitcoinNetworkV1::Regtest, BitcoinCoreNetworkV1::Regtest)
            | (
                BitcoinNetworkV1::PublicSignet,
                BitcoinCoreNetworkV1::PublicSignet
            )
            | (
                BitcoinNetworkV1::CustomSignet,
                BitcoinCoreNetworkV1::CustomSignet
            )
    );
    let delay_matches = matches!(
        (session.refund_delay, public.refund_delay),
        (BitcoinCsvDelayV1::Blocks(left), BitcoinRefundDelayV1::Blocks(right)) if left == right
    ) || matches!(
        (session.refund_delay, public.refund_delay),
        (
            BitcoinCsvDelayV1::Time512s(left),
            BitcoinRefundDelayV1::Time512Seconds(right)
        ) if left == right
    );
    if !network_matches
        || !delay_matches
        || session.route_id == ZERO_DIGEST
        || session.effect_id == ZERO_DIGEST
        || session.fence_epoch == 0
        || session.attempt != 0
        || session.settlement_id != public.settlement_id
        || session.session_id != public.session_id
        || session.terms_digest != public.terms_hash
        || session.funding_txid != public.funding_txid
        || session.funding_vout != public.funding_vout
        || session.funding_amount_sat != public.funding_amount_sat
        || session.roster != public.roster
        || session.contract_script_pubkey != public.contract_script_pubkey
        || session.refund_key_xonly != public.refund_key_xonly
        || session.destination_script_pubkey != public.destination_script_pubkey
        || session.fee_sat != public.fee_sat
        || session.expected_template_hash != public.template_digest
        || session.adaptor_point != public.adaptor_point
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

pub(crate) struct ProductionBitcoinMaterializationScopeV1 {
    route_id: Digest32,
    leg: SettlementLegV1,
    settlement_id: Digest32,
    route_scope_digest: Digest32,
    composition_digest: Digest32,
    role_plan_digest: Digest32,
    source_scope_digest: Digest32,
}

impl ProductionBitcoinMaterializationScopeV1 {
    #[expect(
        dead_code,
        reason = "bitcoin claim path frozen until the authenticated M8 round"
    )]
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
                SettlementLegV1::Upstream,
            ),
            LegIdV1::Downstream => (
                composition.downstream(),
                ComposedSettlementLegV1::Downstream,
                SettlementLegV1::Downstream,
            ),
        };
        let entry = role_plan.entry(plan_leg);
        inputs
            .admission()
            .bitcoin_deployment_capability(leg)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        if role_plan.route_id() != inputs.admission().route_id()
            || role_plan.route_scope_digest() != composition.route_scope_digest()
            || role_plan.composition_binding_digest() != composition.binding_digest()
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

    fn validates(&self, request: &ProductionChildMaterializationRequestV1) -> bool {
        request.route_id == self.route_id
            && request.leg == self.leg
            && request.settlement_id == self.settlement_id
            && request.route_scope_digest == self.route_scope_digest
            && request.composition_digest == self.composition_digest
            && request.role_plan_digest == self.role_plan_digest
            && request.source_scope_digest == self.source_scope_digest
    }
}

/// Trusted clock boundary used for actuator lease and monotonic-time checks.
pub(crate) trait ProductionBitcoinChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1>;
}

/// Host wall-time adapter for the production composition root.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemProductionBitcoinChildClockV1;

impl ProductionBitcoinChildClockV1 for SystemProductionBitcoinChildClockV1 {
    fn now_unix_ms(&mut self) -> Result<u64, ChildAuthorityRefusalV1> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChildAuthorityRefusalV1::Unavailable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| ChildAuthorityRefusalV1::Unavailable)
    }
}

/// Move-only funding capability created only after the durable funding row,
/// scope and coordinator request have been checked atomically.
pub(crate) struct AuthenticatedBitcoinFundingCallV1 {
    binding: BitcoinOperationBindingViewV1,
    coordinator_attempt_id: Digest32,
    request_digest: Digest32,
}

impl core::fmt::Debug for AuthenticatedBitcoinFundingCallV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedBitcoinFundingCallV1([authority redacted])")
    }
}

impl AuthenticatedBitcoinFundingCallV1 {
    /// Exact authenticated funding locator. It can never name a terminal row.
    pub(crate) const fn locator(&self) -> BitcoinOperationLocatorV1 {
        self.binding.locator()
    }

    /// Opaque funding scope needed by the armed-funding authority.
    pub(crate) const fn scope(&self) -> &BitcoinActuationScopeV1 {
        self.binding.scope()
    }

    /// Exact coordinator dispatch attempt.
    pub(crate) const fn coordinator_attempt_id(&self) -> Digest32 {
        self.coordinator_attempt_id
    }

    /// Commitment to every public coordinator request field.
    pub(crate) const fn request_digest(&self) -> Digest32 {
        self.request_digest
    }
}

enum ProductionBitcoinFundingResultV1 {
    Externalized(btc_actuator::BitcoinBroadcastReceiptV1),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FundingReconciliationDispositionV1 {
    Externalized,
    Unknown,
}

/// Sole production owner of one exact armed Bitcoin funding transaction.
///
/// Construction consumes an unforgeable `btc-live` armed capability and
/// reopens the exact owner-locked prebroadcast store against the retained Core
/// RPC identity. The authority has no codec, `Clone`, raw-byte getter or
/// alternate broadcaster.
pub(crate) struct ProductionBitcoinFundingAuthorityV1 {
    store: Rc<BitcoinPrebroadcastStoreV1>,
    rpc: Rc<BitcoinCoreRpcClientV1>,
    armed: ArmedBitcoinFundingV1,
    custody: BitcoinExternalFundingCustodyV1,
    route_id: Digest32,
    leg: LegIdV1,
    terms_digest: Digest32,
    deployment: ResolvedBitcoinDeploymentV1,
    refund_exact: ExactBitcoinTransactionV1,
    refund_fee_policy: BitcoinFeeBumpPolicyV1,
}

impl core::fmt::Debug for ProductionBitcoinFundingAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionBitcoinFundingAuthorityV1([authority redacted])")
    }
}

impl ProductionBitcoinFundingAuthorityV1 {
    pub(crate) fn new(
        store: Rc<BitcoinPrebroadcastStoreV1>,
        rpc: Rc<BitcoinCoreRpcClientV1>,
        armed: ArmedBitcoinFundingV1,
        admission: &AuthenticatedRouteAdmissionV1,
        composition: &ComposedBindingV2,
        leg: LegIdV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        validate_admitted_bitcoin_funding(admission, composition, leg)?;
        let deployment = admission
            .bitcoin_deployment_capability(leg)
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let route_id = admission.route_id();
        let settlement = match leg {
            LegIdV1::Upstream => composition.upstream(),
            LegIdV1::Downstream => composition.downstream(),
        };
        settlement
            .terms_hash()
            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let terms_digest = admission.frozen_bindings().terms_digest;
        if terms_digest == ZERO_DIGEST {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let expected_route_binding =
            production_bitcoin_refund_route_binding_v1(route_id, composition, leg, &deployment)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
        let supplied_custody = armed
            .external_funding_custody()
            .map_err(map_live_bitcoin_error)?;
        validate_external_funding_custody(&supplied_custody)?;
        if supplied_custody.route_binding() != expected_route_binding {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let reopened = store
            .reopen(&rpc, expected_route_binding)
            .map_err(map_live_bitcoin_error)?
            .ok_or(ChildAuthorityRefusalV1::Refused)?;
        let ReopenedBitcoinFundingV1::Armed(authoritative) = reopened else {
            return Err(ChildAuthorityRefusalV1::Refused);
        };
        let authoritative_custody = authoritative
            .external_funding_custody()
            .map_err(map_live_bitcoin_error)?;
        if authoritative_custody != supplied_custody
            || authoritative.funding_summary() != armed.funding_summary()
            || authoritative.refund_txid() != armed.refund_txid()
            || authoritative.was_broadcast() != armed.was_broadcast()
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let refund_bytes = authoritative.canonical_refund_transaction().to_vec();
        let refund_exact = ExactBitcoinTransactionV1::from_consensus_bytes(refund_bytes)
            .map_err(map_actuator_error)?;
        let refund_output_sat = refund_exact
            .output_value_sat()
            .map_err(map_actuator_error)?;
        let refund_fee_sat = authoritative_custody
            .contract_amount_sat()
            .checked_sub(refund_output_sat)
            .filter(|fee| *fee != 0)
            .ok_or(ChildAuthorityRefusalV1::Conflict)?;
        let maximum_fee_rate_sat_vbyte = deployment.deployment().max_fee_rate_sat_vbyte;
        let maximum_fee_sat = maximum_fee_rate_sat_vbyte
            .checked_mul(
                u64::try_from(refund_exact.byte_len())
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            )
            .ok_or(ChildAuthorityRefusalV1::Conflict)?;
        if refund_exact.txid() != authoritative_custody.refund_txid()
            || maximum_fee_sat < refund_fee_sat
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            store,
            rpc,
            armed: authoritative,
            custody: authoritative_custody,
            route_id,
            leg,
            terms_digest,
            deployment,
            refund_exact,
            refund_fee_policy: BitcoinFeeBumpPolicyV1 {
                initial_fee_sat: refund_fee_sat,
                maximum_fee_sat,
                maximum_fee_rate_sat_vbyte,
                change_vout: None,
            },
        })
    }

    fn externalize_funding(
        &mut self,
        actuator: &mut DurableBitcoinActuatorV1,
        call: AuthenticatedBitcoinFundingCallV1,
        now_unix_ms: u64,
    ) -> Result<ProductionBitcoinFundingResultV1, ChildAuthorityRefusalV1> {
        validate_funding_call(
            &call,
            &self.custody,
            self.route_id,
            self.leg,
            self.terms_digest,
            &self.deployment,
        )?;
        let recorded = actuator
            .record_armed_funding(call.scope(), &self.armed, now_unix_ms)
            .map_err(map_actuator_error)?;
        validate_recorded_funding(&call, &self.custody, recorded)?;
        match actuator.broadcast_armed_funding(
            call.scope(),
            &self.store,
            &self.rpc,
            &mut self.armed,
            now_unix_ms,
        ) {
            Ok(receipt) => {
                validate_funding_receipt(&call, &self.custody, receipt)?;
                Ok(ProductionBitcoinFundingResultV1::Externalized(receipt))
            }
            Err(error) => funding_broadcast_failure(error),
        }
    }
}

/// Owner-scoped production bridge from coordinator calls to one BTC actuator.
pub(crate) struct ProductionBitcoinChildPortV1<R, C> {
    actuator: DurableBitcoinActuatorV1,
    rpc: R,
    lease: BitcoinStorageLeaseStatusV1,
    clock: C,
    funding: ProductionBitcoinFundingAuthorityV1,
    claim: Option<ProductionBitcoinClaimMaterializationAuthorityV1>,
    returned_extraction_handoff: Option<ProductionBitcoinPublicExtractionHandoffV1>,
    materialization_scope: Option<ProductionBitcoinMaterializationScopeV1>,
}

impl<R, C> core::fmt::Debug for ProductionBitcoinChildPortV1<R, C> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionBitcoinChildPortV1([authorities redacted])")
    }
}

impl<R, C> ProductionBitcoinChildPortV1<R, C>
where
    R: BitcoinRpcV1,
    C: ProductionBitcoinChildClockV1,
{
    pub(crate) fn new(
        actuator: DurableBitcoinActuatorV1,
        rpc: R,
        lease: BitcoinStorageLeaseStatusV1,
        clock: C,
        funding: ProductionBitcoinFundingAuthorityV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if lease.fence_epoch() == 0 || lease.expires_at_ms() == 0 {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Self {
            actuator,
            rpc,
            lease,
            clock,
            funding,
            claim: None,
            returned_extraction_handoff: None,
            materialization_scope: None,
        })
    }

    #[expect(
        dead_code,
        reason = "bitcoin claim path frozen until the authenticated M8 round"
    )]
    pub(crate) fn new_materializing(
        actuator: DurableBitcoinActuatorV1,
        rpc: R,
        lease: BitcoinStorageLeaseStatusV1,
        clock: C,
        funding: ProductionBitcoinFundingAuthorityV1,
        scope: ProductionBitcoinMaterializationScopeV1,
        claim: ProductionBitcoinClaimMaterializationAuthorityV1,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let mut port = Self::new(actuator, rpc, lease, clock, funding)?;
        if scope.route_id != claim.session.route_id
            || scope.settlement_id != claim.session.settlement_id
            || scope.route_scope_digest != claim.route_scope_digest
            || scope.composition_digest != claim.composition_digest
            || scope.role_plan_digest != claim.role_plan_digest
            || scope.source_scope_digest != claim.source_scope_digest
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        claim.authenticates_fresh_funding_owner(&port.funding)?;
        port.claim = Some(claim);
        port.materialization_scope = Some(scope);
        Ok(port)
    }

    /// Moves the sole fresh public-extraction authority out only after the
    /// exact claim has been finalized and retained by the durable actuator.
    /// The handoff shares the already-open Core client owned by the funding
    /// authority and cannot create another RPC or nonce session.
    pub(crate) fn take_fresh_public_extraction_handoff(
        &mut self,
        expected: ProductionBitcoinExtractionHandoffScopeV1,
    ) -> Result<ProductionBitcoinPublicExtractionHandoffV1, ChildAuthorityRefusalV1> {
        if let Some(handoff) = self.returned_extraction_handoff.as_ref() {
            let authenticated = handoff_authenticates_expected(handoff, expected);
            return take_validated_handoff_authority(
                &mut self.returned_extraction_handoff,
                authenticated,
            );
        }
        let now = self.clock.now_unix_ms()?;
        let claim = self
            .claim
            .as_ref()
            .ok_or(ChildAuthorityRefusalV1::Refused)?;
        let exact_txid = claim.expected_txid()?;
        let exact_intent_digest = claim.exact_intent_digest();
        let extraction_txid = claim.fresh_extraction_expected_txid()?;
        let chain_id = self.funding.deployment.profile().chain_id.0;
        let minimum_confirmations = self.funding.deployment.profile().finality.min_confirmations;
        if claim.session.route_id != self.funding.route_id
            || claim.composition_digest == ZERO_DIGEST
            || chain_id == ZERO_DIGEST
            || minimum_confirmations == 0
            || extraction_txid != exact_txid
            || expected.route_id != claim.session.route_id
            || expected.composition_digest != claim.composition_digest
            || expected.chain_id != chain_id
            || expected
                .expected_txid
                .is_some_and(|expected_txid| expected_txid != exact_txid)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let binding = self
            .actuator
            .operation_binding(
                self.lease,
                BitcoinOperationKindV1::Terminal,
                claim.session.effect_id,
                now,
            )
            .map_err(map_actuator_error)?;
        validate_existing_exact_claim_binding(&binding, exact_txid, exact_intent_digest)?;
        self.claim
            .as_mut()
            .ok_or(ChildAuthorityRefusalV1::Refused)?
            .mark_exact_durably_retained(exact_txid)?;
        let extraction = self
            .claim
            .as_mut()
            .ok_or(ChildAuthorityRefusalV1::Refused)?
            .take_fresh_extraction(exact_txid)?;
        Ok(ProductionBitcoinPublicExtractionHandoffV1 {
            route_id: expected.route_id,
            composition_digest: expected.composition_digest,
            chain_id,
            minimum_confirmations,
            store: Rc::clone(&self.funding.store),
            rpc: Rc::clone(&self.funding.rpc),
            extraction,
        })
    }

    pub(crate) fn restore_fresh_public_extraction_handoff(
        &mut self,
        handoff: ProductionBitcoinPublicExtractionHandoffV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let chain_id = self.funding.deployment.profile().chain_id.0;
        if self.returned_extraction_handoff.is_some()
            || handoff.route_id != self.funding.route_id
            || handoff.chain_id != chain_id
            || handoff.composition_digest == ZERO_DIGEST
            || handoff.minimum_confirmations == 0
            || !Rc::ptr_eq(&handoff.store, &self.funding.store)
            || !Rc::ptr_eq(&handoff.rpc, &self.funding.rpc)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        self.returned_extraction_handoff = Some(handoff);
        Ok(())
    }

    fn validate_dispatch(
        &mut self,
        request: &ChildDispatchRequestV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedBitcoinOperationV1, ChildAuthorityRefusalV1> {
        validate_dispatch_request_shape(request)?;
        let expected = ExpectedBitcoinBindingsV1::from_dispatch(request);
        self.validate_operation(expected, now_unix_ms)
    }

    fn validate_observation(
        &mut self,
        request: &ChildObservationRequestV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedBitcoinOperationV1, ChildAuthorityRefusalV1> {
        validate_observation_request_shape(request)?;
        let expected = ExpectedBitcoinBindingsV1::from_observation(request);
        self.validate_operation(expected, now_unix_ms)
    }

    fn validate_operation(
        &mut self,
        expected: ExpectedBitcoinBindingsV1,
        now_unix_ms: u64,
    ) -> Result<ValidatedBitcoinOperationV1, ChildAuthorityRefusalV1> {
        // Settlement identity, semantic digest and coordinator fence are
        // coordinator-owned facts: the exact request digest below retains
        // them in the actuator journal. Every overlapping actuator-owned fact
        // is checked here against the reopened scope and row before that bind.
        expected.validate_static(self.lease)?;
        let kind = operation_kind(expected.action);
        let binding = self
            .actuator
            .operation_binding(self.lease, kind, expected.effect_id, now_unix_ms)
            .map_err(map_actuator_error)?;
        expected.validate_retained(self.lease, &binding)?;
        Ok(ValidatedBitcoinOperationV1 { expected, binding })
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

    fn dispatch_outcome(
        request: &ChildDispatchRequestV1,
        outcome: BitcoinPortCallOutcomeV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        let binding = ChildEvidenceBindingV1::from_dispatch(request);
        match outcome {
            BitcoinPortCallOutcomeV1::Externalized {
                evidence_digest,
                first_exposure_evidence_digest,
            } => {
                if outcome != Self::exact_externalized_outcome(request)? {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildExecutionOutcomeV1::Externalized(
                    Self::externalized_receipt(
                        request,
                        evidence_digest,
                        first_exposure_evidence_digest,
                    ),
                ))
            }
            BitcoinPortCallOutcomeV1::RetryableBeforeExternalization { evidence_digest } => {
                if evidence_digest
                    != retryable_before_externalization_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildExecutionOutcomeV1::RetryableBeforeExternalization { evidence_digest })
            }
            BitcoinPortCallOutcomeV1::Unknown { evidence_digest } => {
                if evidence_digest
                    != unknown_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildExecutionOutcomeV1::Unknown { evidence_digest })
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }

    fn reconciliation_outcome(
        request: &ChildDispatchRequestV1,
        outcome: BitcoinPortCallOutcomeV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        let binding = ChildEvidenceBindingV1::from_dispatch(request);
        match outcome {
            BitcoinPortCallOutcomeV1::Externalized {
                evidence_digest,
                first_exposure_evidence_digest,
            } => {
                if outcome != Self::exact_externalized_outcome(request)? {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildReconciliationOutcomeV1::Externalized(
                    Self::externalized_receipt(
                        request,
                        evidence_digest,
                        first_exposure_evidence_digest,
                    ),
                ))
            }
            BitcoinPortCallOutcomeV1::ProvenNotExternalized { evidence_digest } => {
                if evidence_digest
                    != proven_not_externalized_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized { evidence_digest })
            }
            BitcoinPortCallOutcomeV1::Unknown { evidence_digest } => {
                if evidence_digest
                    != unknown_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildReconciliationOutcomeV1::Unknown { evidence_digest })
            }
            _ => Err(ChildAuthorityRefusalV1::Conflict),
        }
    }

    fn observation_outcome(
        request: &ChildObservationRequestV1,
        outcome: BitcoinPortCallOutcomeV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        match outcome {
            BitcoinPortCallOutcomeV1::Pending { evidence_digest } => {
                let binding = ChildObservationEvidenceBindingV1::from_observation(request);
                if evidence_digest
                    != observation_pending_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?
                {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                Ok(ChildObservationOutcomeV1::Pending { evidence_digest })
            }
            BitcoinPortCallOutcomeV1::Final { evidence_digest } => {
                Ok(ChildObservationOutcomeV1::Final { evidence_digest })
            }
            BitcoinPortCallOutcomeV1::FinalityInvalidated {
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

    fn exact_externalized_outcome(
        request: &ChildDispatchRequestV1,
    ) -> Result<BitcoinPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
        Ok(BitcoinPortCallOutcomeV1::Externalized {
            evidence_digest: externalization_evidence_v1(&evidence)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            first_exposure_evidence_digest: first_exposure_evidence_v1(&evidence)
                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
        })
    }

    fn funding_dispatch_outcome(
        request: &ChildDispatchRequestV1,
        receipt: btc_actuator::BitcoinBroadcastReceiptV1,
    ) -> Result<BitcoinPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        if receipt.effect_id != request.effect_id()
            || receipt.txid != request.expected_transaction_id()
            || receipt.intent_digest != request.intent_digest()
            || receipt.attempt == 0
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Self::exact_externalized_outcome(request)
    }

    fn reconciliation_result(
        request: &ChildDispatchRequestV1,
        result: BitcoinReconciliationV1,
    ) -> Result<BitcoinPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
        match result {
            BitcoinReconciliationV1::ProvenNotExternalized => {
                Ok(BitcoinPortCallOutcomeV1::ProvenNotExternalized {
                    evidence_digest: proven_not_externalized_evidence_v1(&evidence)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            BitcoinReconciliationV1::ExactMempool
            | BitcoinReconciliationV1::ExactConfirmed { .. }
            | BitcoinReconciliationV1::ExactFinal { .. } => {
                Self::exact_externalized_outcome(request)
            }
            BitcoinReconciliationV1::Ambiguous => Ok(BitcoinPortCallOutcomeV1::Unknown {
                evidence_digest: unknown_evidence_v1(&evidence)
                    .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
            }),
        }
    }

    fn funding_reconciliation_result(
        request: &ChildDispatchRequestV1,
        result: BitcoinReconciliationV1,
    ) -> Result<BitcoinPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        match funding_reconciliation_disposition(result) {
            FundingReconciliationDispositionV1::Externalized => {
                Self::exact_externalized_outcome(request)
            }
            FundingReconciliationDispositionV1::Unknown => {
                let evidence = ChildEvidenceBindingV1::from_dispatch(request);
                Ok(BitcoinPortCallOutcomeV1::Unknown {
                    evidence_digest: unknown_evidence_v1(&evidence)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
        }
    }

    fn observe_result(
        request: &ChildObservationRequestV1,
        operation: BitcoinDurableOperationViewV1,
    ) -> Result<BitcoinPortCallOutcomeV1, ChildAuthorityRefusalV1> {
        let view = ObservedBitcoinViewV1::from_operation(operation);
        let binding = ChildObservationEvidenceBindingV1::from_observation(request);
        match view.stage {
            BitcoinOperationStageV1::Final => {
                let facts = ChildFinalityFactsV1 {
                    final_evidence_digest: view
                        .evidence_digest
                        .ok_or(ChildAuthorityRefusalV1::Conflict)?,
                    final_block_hash: view.block_hash.ok_or(ChildAuthorityRefusalV1::Conflict)?,
                    final_block_number: view
                        .block_height
                        .ok_or(ChildAuthorityRefusalV1::Conflict)?,
                };
                Ok(BitcoinPortCallOutcomeV1::Final {
                    evidence_digest: observation_final_evidence_v1(&binding, &facts)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                })
            }
            BitcoinOperationStageV1::Prepared => Err(ChildAuthorityRefusalV1::Conflict),
            _ => match request.prior_finality_evidence_digest {
                Some(prior) => {
                    let invalidation = view
                        .evidence_digest
                        .ok_or(ChildAuthorityRefusalV1::Conflict)?;
                    Ok(BitcoinPortCallOutcomeV1::FinalityInvalidated {
                        prior_finality_evidence_digest: prior,
                        reorg_evidence_digest: observation_reorg_evidence_v1(
                            &binding,
                            prior,
                            invalidation,
                        )
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                    })
                }
                None => Ok(BitcoinPortCallOutcomeV1::Pending {
                    evidence_digest: observation_pending_evidence_v1(&binding)
                        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                }),
            },
        }
    }
}

fn take_validated_handoff_authority<T>(
    authority: &mut Option<T>,
    authenticated: bool,
) -> Result<T, ChildAuthorityRefusalV1> {
    if !authenticated {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    authority.take().ok_or(ChildAuthorityRefusalV1::Refused)
}

const fn funding_reconciliation_disposition(
    result: BitcoinReconciliationV1,
) -> FundingReconciliationDispositionV1 {
    match result {
        BitcoinReconciliationV1::ExactMempool
        | BitcoinReconciliationV1::ExactConfirmed { .. }
        | BitcoinReconciliationV1::ExactFinal { .. } => {
            FundingReconciliationDispositionV1::Externalized
        }
        // The funding bytes are held by a separate durable broadcaster. An
        // absent node lookup cannot prove that this coordinator did not cross,
        // or lose acknowledgement at, that boundary.
        BitcoinReconciliationV1::ProvenNotExternalized | BitcoinReconciliationV1::Ambiguous => {
            FundingReconciliationDispositionV1::Unknown
        }
    }
}

fn funding_broadcast_failure(
    error: BitcoinActuatorErrorV1,
) -> Result<ProductionBitcoinFundingResultV1, ChildAuthorityRefusalV1> {
    match error {
        BitcoinActuatorErrorV1::LiveFunding | BitcoinActuatorErrorV1::ExternalizationAmbiguous => {
            Ok(ProductionBitcoinFundingResultV1::Unknown)
        }
        other => Err(map_actuator_error(other)),
    }
}

impl<R, C> ProductionBitcoinChildPortV1<R, C>
where
    R: BitcoinRpcV1,
    C: ProductionBitcoinChildClockV1,
{
    fn recover_existing_exact_claim(
        &mut self,
        request: &ProductionChildMaterializationRequestV1,
        scalar: &route_composer::RouteScalar,
        binding: &BitcoinOperationBindingViewV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let claim = self
            .claim
            .as_mut()
            .ok_or(ChildAuthorityRefusalV1::Refused)?;
        claim.ensure_exact_claim(request, scalar)?;
        let exact_txid = claim.expected_txid()?;
        let exact_intent_digest = claim.exact_intent_digest();
        validate_existing_exact_claim_binding(binding, exact_txid, exact_intent_digest)?;
        claim.mark_exact_durably_retained(exact_txid)
    }
}

impl<R, C> ProductionSettlementChildPortV1 for ProductionBitcoinChildPortV1<R, C>
where
    R: BitcoinRpcV1,
    C: ProductionBitcoinChildClockV1,
{
    fn face(&self) -> SettlementFaceV1 {
        SettlementFaceV1::Bitcoin
    }

    fn materialize(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&route_composer::RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let materialization_scope = self
            .materialization_scope
            .as_ref()
            .ok_or(ChildAuthorityRefusalV1::Refused)?;
        if !materialization_scope.validates(&request) {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
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
        let deployment = &self.funding.deployment;
        if !scalar_shape
            || request.route_id != self.funding.route_id
            || route_leg(request.leg) != self.funding.leg
            || request.terms_digest != self.funding.terms_digest
            || request.registry_digest != deployment.registry_digest()
            || request.profile_digest != deployment.profile_digest()
            || request.deployment_digest
                != resolved_bitcoin_deployment_digest_v1(deployment).map_err(map_actuator_error)?
            || request.fencing_epoch != self.lease.fence_epoch()
            || request.settlement_id == ZERO_DIGEST
            || request.effect_id == ZERO_DIGEST
            || request.semantic_digest == ZERO_DIGEST
            || request.route_scope_digest == ZERO_DIGEST
            || request.composition_digest == ZERO_DIGEST
            || request.role_plan_digest == ZERO_DIGEST
            || request.source_scope_digest == ZERO_DIGEST
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let now = self.clock.now_unix_ms()?;
        if now >= self.lease.expires_at_ms() {
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        let operation_kind = operation_kind(request.action);
        match self
            .actuator
            .operation_binding(self.lease, operation_kind, request.effect_id, now)
        {
            Ok(binding) => {
                let plan = materialized_bitcoin_plan(deployment, self.lease, &request, &binding)?;
                if request.action == SettlementActionV1::Claim {
                    let scalar = public_scalar.ok_or(ChildAuthorityRefusalV1::Refused)?;
                    self.recover_existing_exact_claim(&request, scalar, &binding)?;
                }
                return Ok(plan);
            }
            Err(BitcoinActuatorErrorV1::EffectNotFound) => {}
            Err(error) => return Err(map_actuator_error(error)),
        }
        let bitcoin_leg = match request.leg {
            SettlementLegV1::Upstream => btc_actuator::BitcoinLegV1::Upstream,
            SettlementLegV1::Downstream => btc_actuator::BitcoinLegV1::Downstream,
        };
        let binding = match request.action {
            SettlementActionV1::Funding => {
                let custody = self.funding.custody;
                let maximum_fee_sat = deployment
                    .deployment()
                    .max_fee_rate_sat_vbyte
                    .checked_mul(custody.virtual_size_vb())
                    .ok_or(ChildAuthorityRefusalV1::Conflict)?;
                let scope =
                    BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
                        deployment,
                        route_id: request.route_id,
                        effect_id: request.effect_id,
                        leg: bitcoin_leg,
                        action: BitcoinActionV1::Funding,
                        fence_epoch: request.fencing_epoch,
                        terms_digest: request.terms_digest,
                        expected_txid: custody.funding_txid(),
                        intent_digest: custody.custody_digest(),
                        contract_outpoint: None,
                        contract_amount_sat: custody.contract_amount_sat(),
                        refund_record_digest: Some(custody.refund_record_digest()),
                        fee_policy: BitcoinFeeBumpPolicyV1 {
                            initial_fee_sat: custody.actual_fee_sat(),
                            maximum_fee_sat,
                            maximum_fee_rate_sat_vbyte: deployment
                                .deployment()
                                .max_fee_rate_sat_vbyte,
                            change_vout: None,
                        },
                        valid_until_ms: self.lease.expires_at_ms(),
                    })
                    .map_err(map_actuator_error)?;
                self.actuator
                    .record_armed_funding(&scope, &self.funding.armed, now)
                    .map_err(map_actuator_error)?;
                self.actuator
                    .operation_binding(
                        self.lease,
                        BitcoinOperationKindV1::Funding,
                        request.effect_id,
                        now,
                    )
                    .map_err(map_actuator_error)?
            }
            SettlementActionV1::Claim => {
                let scalar = public_scalar.ok_or(ChildAuthorityRefusalV1::Refused)?;
                let claim = self
                    .claim
                    .as_mut()
                    .ok_or(ChildAuthorityRefusalV1::Refused)?;
                claim.ensure_exact_claim(&request, scalar)?;
                let post_authority_now = self.clock.now_unix_ms()?;
                if post_authority_now >= self.lease.expires_at_ms() {
                    return Err(ChildAuthorityRefusalV1::Unavailable);
                }
                let exact = claim.exact()?;
                let maximum_fee_rate_sat_vbyte = deployment.deployment().max_fee_rate_sat_vbyte;
                let maximum_fee_sat = maximum_fee_rate_sat_vbyte
                    .checked_mul(
                        u64::try_from(exact.byte_len())
                            .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                    )
                    .ok_or(ChildAuthorityRefusalV1::Conflict)?;
                let fee_policy = BitcoinFeeBumpPolicyV1 {
                    initial_fee_sat: claim.session.fee_sat,
                    maximum_fee_sat,
                    maximum_fee_rate_sat_vbyte,
                    change_vout: None,
                };
                if maximum_fee_sat < claim.session.fee_sat {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let scope =
                    BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
                        deployment,
                        route_id: request.route_id,
                        effect_id: request.effect_id,
                        leg: bitcoin_leg,
                        action: BitcoinActionV1::Claim,
                        fence_epoch: request.fencing_epoch,
                        terms_digest: request.terms_digest,
                        expected_txid: exact.txid(),
                        intent_digest: exact.intent_digest(),
                        contract_outpoint: Some(btc_actuator::BitcoinOutpointV1 {
                            txid: claim.session.funding_txid,
                            vout: claim.session.funding_vout,
                        }),
                        contract_amount_sat: claim.session.funding_amount_sat,
                        refund_record_digest: None,
                        fee_policy,
                        valid_until_ms: self.lease.expires_at_ms(),
                    })
                    .map_err(map_actuator_error)?;
                self.actuator
                    .prepare_terminal_retained(&scope, exact, post_authority_now)
                    .map_err(map_actuator_error)?;
                claim.mark_exact_durably_retained(scope.expected_txid())?;
                self.actuator
                    .operation_binding(
                        self.lease,
                        BitcoinOperationKindV1::Terminal,
                        request.effect_id,
                        post_authority_now,
                    )
                    .map_err(map_actuator_error)?
            }
            SettlementActionV1::Refund => {
                let exact = &self.funding.refund_exact;
                let scope =
                    BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
                        deployment,
                        route_id: request.route_id,
                        effect_id: request.effect_id,
                        leg: bitcoin_leg,
                        action: BitcoinActionV1::Refund,
                        fence_epoch: request.fencing_epoch,
                        terms_digest: request.terms_digest,
                        expected_txid: exact.txid(),
                        intent_digest: exact.intent_digest(),
                        contract_outpoint: Some(btc_actuator::BitcoinOutpointV1 {
                            txid: self.funding.custody.funding_txid(),
                            vout: self.funding.custody.contract_vout(),
                        }),
                        contract_amount_sat: self.funding.custody.contract_amount_sat(),
                        refund_record_digest: None,
                        fee_policy: self.funding.refund_fee_policy,
                        valid_until_ms: self.lease.expires_at_ms(),
                    })
                    .map_err(map_actuator_error)?;
                self.actuator
                    .prepare_terminal_retained(&scope, exact, now)
                    .map_err(map_actuator_error)?;
                self.actuator
                    .operation_binding(
                        self.lease,
                        BitcoinOperationKindV1::Terminal,
                        request.effect_id,
                        now,
                    )
                    .map_err(map_actuator_error)?
            }
        };
        materialized_bitcoin_plan(deployment, self.lease, &request, &binding)
    }

    fn externalize(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        let now = self.clock.now_unix_ms()?;
        let validated = self.validate_dispatch(request, now)?;
        let request_digest = dispatch_request_digest(request)?;
        let key = BitcoinPortCallKeyV1::new(
            BitcoinPortCallKindV1::Dispatch,
            request.attempt_id(),
            request_digest,
            &validated.binding,
        )
        .map_err(map_actuator_error)?;
        if let BitcoinPortCallJournalStatusV1::Committed(outcome) = self
            .actuator
            .begin_port_call(self.lease, key, now)
            .map_err(map_actuator_error)?
        {
            return Self::dispatch_outcome(request, outcome);
        }

        let outcome = match validated.expected.action {
            SettlementActionV1::Funding => {
                if validated.binding.locator().kind() != BitcoinOperationKindV1::Funding {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                let call = AuthenticatedBitcoinFundingCallV1 {
                    binding: validated.binding,
                    coordinator_attempt_id: request.attempt_id(),
                    request_digest,
                };
                match self
                    .funding
                    .externalize_funding(&mut self.actuator, call, now)?
                {
                    ProductionBitcoinFundingResultV1::Externalized(receipt) => {
                        Self::funding_dispatch_outcome(request, receipt)?
                    }
                    ProductionBitcoinFundingResultV1::Unknown => {
                        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
                        BitcoinPortCallOutcomeV1::Unknown {
                            evidence_digest: unknown_evidence_v1(&evidence)
                                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                        }
                    }
                }
            }
            SettlementActionV1::Claim | SettlementActionV1::Refund => {
                if validated.binding.locator().kind() != BitcoinOperationKindV1::Terminal {
                    return Err(ChildAuthorityRefusalV1::Conflict);
                }
                match self.actuator.broadcast_terminal(
                    validated.binding.scope(),
                    &mut self.rpc,
                    now,
                ) {
                    Ok(receipt)
                        if receipt.effect_id == request.effect_id()
                            && receipt.txid == request.expected_transaction_id()
                            && receipt.intent_digest == request.intent_digest() =>
                    {
                        Self::exact_externalized_outcome(request)?
                    }
                    Ok(_) => return Err(ChildAuthorityRefusalV1::Conflict),
                    Err(BitcoinActuatorErrorV1::ExternalizationAmbiguous) => {
                        let evidence = ChildEvidenceBindingV1::from_dispatch(request);
                        BitcoinPortCallOutcomeV1::Unknown {
                            evidence_digest: unknown_evidence_v1(&evidence)
                                .map_err(|_| ChildAuthorityRefusalV1::Conflict)?,
                        }
                    }
                    Err(error) => return Err(map_actuator_error(error)),
                }
            }
        };
        let committed = self
            .actuator
            .commit_port_call_outcome(self.lease, key, outcome, now)
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
        let key = BitcoinPortCallKeyV1::new(
            BitcoinPortCallKindV1::Reconciliation,
            request.reconciliation_attempt_id,
            request_digest,
            &validated.binding,
        )
        .map_err(map_actuator_error)?;
        if let BitcoinPortCallJournalStatusV1::Committed(outcome) = self
            .actuator
            .begin_port_call(self.lease, key, now)
            .map_err(map_actuator_error)?
        {
            return Self::reconciliation_outcome(&request.dispatch, outcome);
        }
        let clock = &mut self.clock;
        let result = match validated.expected.action {
            SettlementActionV1::Funding => self.actuator.reconcile_funding(
                validated.binding.scope(),
                &mut self.rpc,
                now,
                || {
                    clock
                        .now_unix_ms()
                        .map_err(|_| BitcoinActuatorErrorV1::InvalidTime)
                },
            ),
            SettlementActionV1::Claim | SettlementActionV1::Refund => self
                .actuator
                .reconcile_terminal(validated.binding.scope(), &mut self.rpc, now, || {
                    clock
                        .now_unix_ms()
                        .map_err(|_| BitcoinActuatorErrorV1::InvalidTime)
                }),
        }
        .map_err(map_actuator_error)?;
        let outcome = match validated.expected.action {
            SettlementActionV1::Funding => {
                Self::funding_reconciliation_result(&request.dispatch, result)?
            }
            SettlementActionV1::Claim | SettlementActionV1::Refund => {
                Self::reconciliation_result(&request.dispatch, result)?
            }
        };
        let committed_at = self.clock.now_unix_ms()?;
        let committed = self
            .actuator
            .commit_port_call_outcome(self.lease, key, outcome, committed_at)
            .map_err(map_actuator_error)?;
        Self::reconciliation_outcome(&request.dispatch, committed)
    }

    fn observe(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        let now = self.clock.now_unix_ms()?;
        let validated = self.validate_observation(request, now)?;
        if matches!(
            validated.binding.operation(),
            BitcoinDurableOperationViewV1::Terminal(BitcoinOperationViewV1 {
                stage: BitcoinOperationStageV1::Prepared,
                ..
            }) | BitcoinDurableOperationViewV1::Funding(BitcoinFundingCustodyViewV1 {
                stage: BitcoinOperationStageV1::Prepared,
                ..
            })
        ) {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        let request_digest = observation_request_digest(request)?;
        let key = BitcoinPortCallKeyV1::new(
            BitcoinPortCallKindV1::Observation,
            request.observation_attempt_id,
            request_digest,
            &validated.binding,
        )
        .map_err(map_actuator_error)?;
        if let BitcoinPortCallJournalStatusV1::Committed(outcome) = self
            .actuator
            .begin_port_call(self.lease, key, now)
            .map_err(map_actuator_error)?
        {
            return Self::observation_outcome(request, outcome);
        }
        let clock = &mut self.clock;
        match validated.expected.action {
            SettlementActionV1::Funding => self.actuator.reconcile_funding(
                validated.binding.scope(),
                &mut self.rpc,
                now,
                || {
                    clock
                        .now_unix_ms()
                        .map_err(|_| BitcoinActuatorErrorV1::InvalidTime)
                },
            ),
            SettlementActionV1::Claim | SettlementActionV1::Refund => self
                .actuator
                .reconcile_terminal(validated.binding.scope(), &mut self.rpc, now, || {
                    clock
                        .now_unix_ms()
                        .map_err(|_| BitcoinActuatorErrorV1::InvalidTime)
                }),
        }
        .map_err(map_actuator_error)?;
        let post_rpc_now = self.clock.now_unix_ms()?;
        let post = self
            .actuator
            .operation_binding(
                self.lease,
                operation_kind(validated.expected.action),
                validated.expected.effect_id,
                post_rpc_now,
            )
            .map_err(map_actuator_error)?;
        validated.expected.validate_retained(self.lease, &post)?;
        let outcome = Self::observe_result(request, post.operation())?;
        let committed_at = self.clock.now_unix_ms()?;
        let committed = self
            .actuator
            .commit_port_call_outcome(self.lease, key, outcome, committed_at)
            .map_err(map_actuator_error)?;
        Self::observation_outcome(request, committed)
    }

    fn take_bitcoin_public_extraction_handoff(
        &mut self,
        expected: ProductionBitcoinExtractionHandoffScopeV1,
    ) -> Result<ProductionBitcoinPublicExtractionHandoffV1, ChildAuthorityRefusalV1> {
        ProductionBitcoinChildPortV1::take_fresh_public_extraction_handoff(self, expected)
    }

    fn restore_bitcoin_public_extraction_handoff(
        &mut self,
        handoff: ProductionBitcoinPublicExtractionHandoffV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        ProductionBitcoinChildPortV1::restore_fresh_public_extraction_handoff(self, handoff)
    }
}

fn handoff_authenticates_expected(
    handoff: &ProductionBitcoinPublicExtractionHandoffV1,
    expected: ProductionBitcoinExtractionHandoffScopeV1,
) -> bool {
    handoff.route_id == expected.route_id
        && handoff.composition_digest == expected.composition_digest
        && handoff.chain_id == expected.chain_id
        && expected.expected_txid.map_or(true, |expected_txid| {
            expected_txid == handoff.expected_txid()
        })
}

fn validate_existing_exact_claim_binding(
    binding: &BitcoinOperationBindingViewV1,
    exact_txid: Digest32,
    exact_intent_digest: Option<Digest32>,
) -> Result<(), ChildAuthorityRefusalV1> {
    match binding.operation() {
        BitcoinDurableOperationViewV1::Terminal(view)
            if view.action == BitcoinActionV1::Claim
                && view.txid == exact_txid
                && binding.scope().expected_txid() == exact_txid
                && view.intent_digest == binding.scope().intent_digest()
                && exact_intent_digest.map_or(true, |intent_digest| {
                    view.intent_digest == intent_digest
                        && binding.scope().intent_digest() == intent_digest
                }) =>
        {
            Ok(())
        }
        BitcoinDurableOperationViewV1::Terminal(_) | BitcoinDurableOperationViewV1::Funding(_) => {
            Err(ChildAuthorityRefusalV1::Conflict)
        }
    }
}

fn materialized_bitcoin_plan(
    deployment: &ResolvedBitcoinDeploymentV1,
    lease: BitcoinStorageLeaseStatusV1,
    request: &ProductionChildMaterializationRequestV1,
    binding: &BitcoinOperationBindingViewV1,
) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
    let (transaction_id, intent_digest) = match binding.operation() {
        BitcoinDurableOperationViewV1::Funding(view) => {
            (view.txid, binding.scope().intent_digest())
        }
        BitcoinDurableOperationViewV1::Terminal(view) => (view.txid, view.intent_digest),
    };
    let expected = ExpectedBitcoinBindingsV1 {
        route_id: request.route_id,
        effect_id: request.effect_id,
        settlement_id: request.settlement_id,
        leg: request.leg,
        action: request.action,
        exposure: request.exposure,
        semantic_digest: request.semantic_digest,
        intent_digest,
        custody_digest: binding.custody_locator(),
        transaction_id,
        terms_digest: request.terms_digest,
        registry_digest: request.registry_digest,
        profile_digest: request.profile_digest,
        deployment_digest: request.deployment_digest,
        chain_id: deployment.profile().chain_id.0,
        route_fencing_epoch: request.fencing_epoch,
        coordinator_fencing_epoch: None,
        face: SettlementFaceV1::Bitcoin,
    };
    expected.validate_static(lease)?;
    expected.validate_retained(lease, binding)?;
    Ok(SettlementChildPlanV1 {
        face: SettlementFaceV1::Bitcoin,
        exposure: request.exposure,
        chain_id: expected.chain_id,
        expected_transaction_id: expected.transaction_id,
        intent_digest: expected.intent_digest,
        custody_digest: expected.custody_digest,
    })
}

#[derive(Clone, Copy)]
struct ExpectedBitcoinBindingsV1 {
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

impl ExpectedBitcoinBindingsV1 {
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
        lease: BitcoinStorageLeaseStatusV1,
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
        if self.face != SettlementFaceV1::Bitcoin
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
            || self.route_fencing_epoch != lease.fence_epoch()
            || self
                .coordinator_fencing_epoch
                .is_some_and(|epoch| epoch == 0)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }

    fn validate_retained(
        &self,
        lease: BitcoinStorageLeaseStatusV1,
        binding: &BitcoinOperationBindingViewV1,
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let scope = binding.scope();
        let leg = match self.leg {
            SettlementLegV1::Upstream => btc_actuator::BitcoinLegV1::Upstream,
            SettlementLegV1::Downstream => btc_actuator::BitcoinLegV1::Downstream,
        };
        let action = bitcoin_action(self.action);
        if binding.locator().kind() != operation_kind(self.action)
            || binding.locator().effect_id() != self.effect_id
            || binding.locator().scope_digest() != scope.scope_digest()
            || binding.custody_locator() != self.custody_digest
            || !chain_bindings_match(
                scope.chain_id(),
                binding.chain_identity_digest(),
                self.chain_id,
            )
            || binding.leg() != leg
            || binding.terms_digest() != self.terms_digest
            || binding.registry_digest() != self.registry_digest
            || binding.profile_digest() != self.profile_digest
            || binding.deployment_digest() != self.deployment_digest
            || scope.route_id() != self.route_id
            || scope.effect_id() != self.effect_id
            || scope.leg() != leg
            || scope.action() != action
            || scope.fence_epoch() != self.route_fencing_epoch
            || scope.fence_epoch() != lease.fence_epoch()
            || scope.terms_digest() != self.terms_digest
            || scope.registry_digest() != self.registry_digest
            || scope.profile_digest() != self.profile_digest
            || scope.deployment_digest() != self.deployment_digest
            || scope.expected_txid() != self.transaction_id
            || scope.intent_digest() != self.intent_digest
            || !operation_matches(self, binding.operation())
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(())
    }
}

struct ValidatedBitcoinOperationV1 {
    expected: ExpectedBitcoinBindingsV1,
    binding: BitcoinOperationBindingViewV1,
}

#[derive(Clone, Copy)]
struct ObservedBitcoinViewV1 {
    stage: BitcoinOperationStageV1,
    block_hash: Option<Digest32>,
    block_height: Option<u64>,
    evidence_digest: Option<Digest32>,
}

impl ObservedBitcoinViewV1 {
    const fn from_operation(operation: BitcoinDurableOperationViewV1) -> Self {
        match operation {
            BitcoinDurableOperationViewV1::Terminal(view) => Self {
                stage: view.stage,
                block_hash: view.block_hash,
                block_height: view.block_height,
                evidence_digest: view.evidence_digest,
            },
            BitcoinDurableOperationViewV1::Funding(view) => Self {
                stage: view.stage,
                block_hash: view.block_hash,
                block_height: view.block_height,
                evidence_digest: view.evidence_digest,
            },
        }
    }
}

const fn operation_kind(action: SettlementActionV1) -> BitcoinOperationKindV1 {
    match action {
        SettlementActionV1::Funding => BitcoinOperationKindV1::Funding,
        SettlementActionV1::Claim | SettlementActionV1::Refund => BitcoinOperationKindV1::Terminal,
    }
}

const fn bitcoin_action(action: SettlementActionV1) -> BitcoinActionV1 {
    match action {
        SettlementActionV1::Funding => BitcoinActionV1::Funding,
        SettlementActionV1::Claim => BitcoinActionV1::Claim,
        SettlementActionV1::Refund => BitcoinActionV1::Refund,
    }
}

const fn route_leg(leg: SettlementLegV1) -> LegIdV1 {
    match leg {
        SettlementLegV1::Upstream => LegIdV1::Upstream,
        SettlementLegV1::Downstream => LegIdV1::Downstream,
    }
}

fn operation_matches(
    expected: &ExpectedBitcoinBindingsV1,
    operation: BitcoinDurableOperationViewV1,
) -> bool {
    match operation {
        BitcoinDurableOperationViewV1::Terminal(view) => {
            expected.action != SettlementActionV1::Funding
                && view.route_id == expected.route_id
                && view.effect_id == expected.effect_id
                && view.action == bitcoin_action(expected.action)
                && view.fence_epoch == expected.route_fencing_epoch
                && view.txid == expected.transaction_id
                && view.intent_digest == expected.intent_digest
        }
        BitcoinDurableOperationViewV1::Funding(view) => {
            expected.action == SettlementActionV1::Funding
                && view.route_id == expected.route_id
                && view.effect_id == expected.effect_id
                && view.fence_epoch == expected.route_fencing_epoch
                && view.txid == expected.transaction_id
                && view.custody_digest == expected.intent_digest
        }
    }
}

fn validate_admitted_bitcoin_funding(
    admission: &AuthenticatedRouteAdmissionV1,
    composition: &ComposedBindingV2,
    leg: LegIdV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    let time = admission
        .route_time_binding_v2()
        .ok_or(ChildAuthorityRefusalV1::Conflict)?;
    let deployment = admission
        .bitcoin_deployment_capability(leg)
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)?;
    let (profile_digest, asset_binding_digest) = match leg {
        LegIdV1::Upstream => (
            admission.upstream_profile_digest(),
            admission.upstream_asset_binding_digest(),
        ),
        LegIdV1::Downstream => (
            admission.downstream_profile_digest(),
            admission.downstream_asset_binding_digest(),
        ),
    };
    if admission.route_id() == ZERO_DIGEST
        || composition.binding_digest() == ZERO_DIGEST
        || time.route_scope_digest() != composition.route_scope_digest()
        || time.policy_digest() != composition.time_policy_digest()
        || time.evidence_digest() != composition.time_evidence_digest()
        || time.proof_digest() != composition.time_proof_digest()
        || time.evidence_sequence() != composition.evidence_sequence()
        || time.issued_at_seconds() != composition.time_proof_issued_at_seconds()
        || time.valid_until_seconds() != composition.time_proof_valid_until_seconds()
        || time.validated_at_seconds() != composition.time_proof_validated_at_seconds()
        || deployment.registry_digest() != admission.registry_digest()
        || deployment.registry_epoch() != admission.registry_epoch()
        || deployment.profile_digest() != profile_digest
        || deployment.asset_binding_digest() != asset_binding_digest
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

fn validate_external_funding_custody(
    custody: &BitcoinExternalFundingCustodyV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    if [
        custody.genesis_hash(),
        custody.route_binding(),
        custody.plan_digest(),
        custody.prepared_record_digest(),
        custody.summary_record_digest(),
        custody.refund_record_digest(),
        custody.funding_txid(),
        custody.refund_txid(),
        custody.custody_digest(),
    ]
    .contains(&ZERO_DIGEST)
        || custody.contract_amount_sat() == 0
        || custody.actual_fee_sat() == 0
        || custody.virtual_size_vb() == 0
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

#[expect(
    dead_code,
    reason = "bitcoin claim path frozen until the authenticated M8 round"
)]
fn authenticate_fresh_claim_funding_owner_fields(
    public: &FreshBitcoinPreparedClaimPublicV1,
    prepared_record_digest: Digest32,
    authenticates_store: bool,
    funding: &ProductionBitcoinFundingAuthorityV1,
) -> Result<Digest32, ChildAuthorityRefusalV1> {
    let custody = &funding.custody;
    if !authenticates_store
        || public.route_binding != custody.route_binding()
        || public.plan_digest != custody.plan_digest()
        || public.receipt_digest == ZERO_DIGEST
        || prepared_record_digest == ZERO_DIGEST
        || public.funding_txid != custody.funding_txid()
        || public.funding_vout != custody.contract_vout()
        || public.funding_amount_sat != custody.contract_amount_sat()
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    request_digest(
        FRESH_CLAIM_FUNDING_OWNER_DOMAIN_V1,
        &[
            &funding.route_id,
            &[match funding.leg {
                LegIdV1::Upstream => 1,
                LegIdV1::Downstream => 2,
            }],
            &public.route_binding,
            &public.plan_digest,
            &public.receipt_digest,
            &prepared_record_digest,
            &custody.prepared_record_digest(),
            &custody.summary_record_digest(),
            &custody.refund_record_digest(),
            &custody.custody_digest(),
            &public.funding_txid,
            &public.funding_vout.to_be_bytes(),
            &public.funding_amount_sat.to_be_bytes(),
        ],
    )
}

fn validate_funding_call(
    call: &AuthenticatedBitcoinFundingCallV1,
    custody: &BitcoinExternalFundingCustodyV1,
    route_id: Digest32,
    leg: LegIdV1,
    terms_digest: Digest32,
    deployment: &ResolvedBitcoinDeploymentV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    let expected_leg = match leg {
        LegIdV1::Upstream => btc_actuator::BitcoinLegV1::Upstream,
        LegIdV1::Downstream => btc_actuator::BitcoinLegV1::Downstream,
    };
    let scope = call.scope();
    if call.coordinator_attempt_id() == ZERO_DIGEST
        || call.request_digest() == ZERO_DIGEST
        || call.locator().kind() != BitcoinOperationKindV1::Funding
        || call.locator().effect_id() != scope.effect_id()
        || call.locator().scope_digest() != scope.scope_digest()
        || scope.route_id() != route_id
        || scope.leg() != expected_leg
        || scope.action() != BitcoinActionV1::Funding
        || scope.terms_digest() != terms_digest
        || scope.expected_txid() != custody.funding_txid()
        || scope.intent_digest() != custody.custody_digest()
        || scope.refund_record_digest() != Some(custody.refund_record_digest())
        || scope.contract_amount_sat() != custody.contract_amount_sat()
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let rebuilt = BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
        deployment,
        route_id: scope.route_id(),
        effect_id: scope.effect_id(),
        leg: scope.leg(),
        action: scope.action(),
        fence_epoch: scope.fence_epoch(),
        terms_digest: scope.terms_digest(),
        expected_txid: scope.expected_txid(),
        intent_digest: scope.intent_digest(),
        contract_outpoint: scope.contract_outpoint(),
        contract_amount_sat: scope.contract_amount_sat(),
        refund_record_digest: scope.refund_record_digest(),
        fee_policy: scope.fee_policy(),
        valid_until_ms: scope.valid_until_ms(),
    })
    .map_err(map_actuator_error)?;
    if rebuilt.scope_digest() != scope.scope_digest() {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    let BitcoinDurableOperationViewV1::Funding(view) = call.binding.operation() else {
        return Err(ChildAuthorityRefusalV1::Conflict);
    };
    validate_funding_view(scope, custody, view)
}

fn validate_recorded_funding(
    call: &AuthenticatedBitcoinFundingCallV1,
    custody: &BitcoinExternalFundingCustodyV1,
    recorded: BitcoinFundingCustodyViewV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    validate_funding_view(call.scope(), custody, recorded)
}

fn validate_funding_view(
    scope: &BitcoinActuationScopeV1,
    custody: &BitcoinExternalFundingCustodyV1,
    view: BitcoinFundingCustodyViewV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    if view.route_id != scope.route_id()
        || view.effect_id != scope.effect_id()
        || view.txid != custody.funding_txid()
        || view.refund_record_digest != custody.refund_record_digest()
        || view.custody_digest != custody.custody_digest()
        || view.fence_epoch != scope.fence_epoch()
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

fn validate_funding_receipt(
    call: &AuthenticatedBitcoinFundingCallV1,
    custody: &BitcoinExternalFundingCustodyV1,
    receipt: btc_actuator::BitcoinBroadcastReceiptV1,
) -> Result<(), ChildAuthorityRefusalV1> {
    if receipt.effect_id != call.locator().effect_id()
        || receipt.txid != custody.funding_txid()
        || receipt.intent_digest != custody.custody_digest()
        || receipt.attempt == 0
    {
        return Err(ChildAuthorityRefusalV1::Conflict);
    }
    Ok(())
}

fn chain_bindings_match(
    scope_chain_id: Digest32,
    chain_identity_digest: Digest32,
    request_chain_id: Digest32,
) -> bool {
    scope_chain_id != ZERO_DIGEST
        && chain_identity_digest != ZERO_DIGEST
        && request_chain_id == scope_chain_id
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

fn map_actuator_error(error: BitcoinActuatorErrorV1) -> ChildAuthorityRefusalV1 {
    match error {
        BitcoinActuatorErrorV1::Storage(_)
        | BitcoinActuatorErrorV1::Rpc(_)
        | BitcoinActuatorErrorV1::LeaseHeld => ChildAuthorityRefusalV1::Unavailable,
        BitcoinActuatorErrorV1::EffectNotFound
        | BitcoinActuatorErrorV1::FundingNotArmed
        | BitcoinActuatorErrorV1::LiveFunding => ChildAuthorityRefusalV1::Refused,
        BitcoinActuatorErrorV1::StaleFencing | BitcoinActuatorErrorV1::InvalidTime => {
            ChildAuthorityRefusalV1::Conflict
        }
        BitcoinActuatorErrorV1::InvalidScope
        | BitcoinActuatorErrorV1::InvalidTransaction
        | BitcoinActuatorErrorV1::TransactionMismatch
        | BitcoinActuatorErrorV1::UnsafeReplacement
        | BitcoinActuatorErrorV1::DatabasePresent
        | BitcoinActuatorErrorV1::DatabaseMissing
        | BitcoinActuatorErrorV1::CreationIncomplete
        | BitcoinActuatorErrorV1::InvalidStorageAuthority
        | BitcoinActuatorErrorV1::CorruptState
        | BitcoinActuatorErrorV1::IdempotencyConflict
        | BitcoinActuatorErrorV1::InvalidState
        | BitcoinActuatorErrorV1::TerminalConflict
        | BitcoinActuatorErrorV1::ExternalizationAmbiguous
        | BitcoinActuatorErrorV1::ReconciliationRequired
        | BitcoinActuatorErrorV1::RpcScopeMismatch
        | BitcoinActuatorErrorV1::ClaimAuthorityMismatch
        | BitcoinActuatorErrorV1::ClaimNonceCustody
        | BitcoinActuatorErrorV1::ClaimCryptography => ChildAuthorityRefusalV1::Conflict,
    }
}

fn map_live_bitcoin_error(error: LiveBitcoinError) -> ChildAuthorityRefusalV1 {
    match error {
        LiveBitcoinError::Rpc
        | LiveBitcoinError::CredentialUnavailable
        | LiveBitcoinError::StoreUnavailable
        | LiveBitcoinError::SnapshotChanged => ChildAuthorityRefusalV1::Unavailable,
        LiveBitcoinError::FundingNotArmed
        | LiveBitcoinError::FundingIncomplete
        | LiveBitcoinError::FundingInputUnavailable
        | LiveBitcoinError::TransactionUnavailable
        | LiveBitcoinError::InsufficientConfirmations => ChildAuthorityRefusalV1::Refused,
        LiveBitcoinError::InvalidRequest
        | LiveBitcoinError::IdentityMismatch
        | LiveBitcoinError::InvalidRpcResponse
        | LiveBitcoinError::FundingMismatch
        | LiveBitcoinError::RefundMismatch
        | LiveBitcoinError::ClaimMismatch
        | LiveBitcoinError::ClaimNonceCustody
        | LiveBitcoinError::CorruptRecord
        | LiveBitcoinError::StateConflict
        | LiveBitcoinError::BoundsExceeded => ChildAuthorityRefusalV1::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use adapter_btc::roster::{BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(ProductionBitcoinPublicExtractionHandoffV1: Clone, Copy);
    assert_not_impl_any!(FreshBitcoinClaimExtractionAuthorityV1: Clone, Copy, core::fmt::Debug);

    #[test]
    fn rejected_handoff_authentication_preserves_authority_for_exact_retry() {
        let mut authority = Some(0x51_u8);
        assert_eq!(
            take_validated_handoff_authority(&mut authority, false),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
        assert_eq!(authority, Some(0x51));
        assert_eq!(
            take_validated_handoff_authority(&mut authority, true),
            Ok(0x51)
        );
        assert_eq!(authority, None);
    }

    fn fresh_session_fixture() -> (BitcoinClaimSessionV1, FreshBitcoinPreparedClaimPublicV1) {
        let secp = Secp256k1::new();
        let maker = SecretKey::from_slice(&[1; 32]).unwrap_or_else(|_| std::process::abort());
        let taker = SecretKey::from_slice(&[2; 32]).unwrap_or_else(|_| std::process::abort());
        let roster = ParticipantKeyRosterV1::new([
            ParticipantKeyV1 {
                participant_id: [0x11; 32],
                role: BitcoinSignerRoleV1::Maker,
                compressed_key: PublicKey::from_secret_key(&secp, &maker).serialize(),
            },
            ParticipantKeyV1 {
                participant_id: [0x12; 32],
                role: BitcoinSignerRoleV1::Taker,
                compressed_key: PublicKey::from_secret_key(&secp, &taker).serialize(),
            },
        ])
        .unwrap_or_else(|_| std::process::abort());
        let public = FreshBitcoinPreparedClaimPublicV1 {
            route_binding: [0x21; 32],
            plan_digest: [0x22; 32],
            receipt_digest: [0x23; 32],
            network: BitcoinCoreNetworkV1::Regtest,
            settlement_id: [0x24; 32],
            session_id: [0x25; 32],
            terms_hash: [0x26; 32],
            funding_txid: [0x27; 32],
            funding_vout: 3,
            funding_amount_sat: 80_000,
            roster,
            contract_script_pubkey: vec![0x51, 0x20, 0x31],
            refund_key_xonly: [0x32; 32],
            refund_delay: BitcoinRefundDelayV1::Blocks(18),
            destination_script_pubkey: vec![0x51, 0x20, 0x33],
            fee_sat: 900,
            template_digest: [0x34; 32],
            adaptor_point: PublicKey::from_secret_key(&secp, &maker).serialize(),
        };
        let session = BitcoinClaimSessionV1 {
            route_id: [0x41; 32],
            effect_id: [0x42; 32],
            fence_epoch: 7,
            settlement_id: public.settlement_id,
            session_id: public.session_id,
            terms_digest: public.terms_hash,
            registry_digest: [0x43; 32],
            profile_digest: [0x44; 32],
            deployment_digest: [0x45; 32],
            network: BitcoinNetworkV1::Regtest,
            roster: public.roster,
            funding_txid: public.funding_txid,
            funding_vout: public.funding_vout,
            funding_amount_sat: public.funding_amount_sat,
            contract_script_pubkey: public.contract_script_pubkey.clone(),
            refund_key_xonly: public.refund_key_xonly,
            refund_delay: BitcoinCsvDelayV1::Blocks(18),
            destination_script_pubkey: public.destination_script_pubkey.clone(),
            fee_sat: public.fee_sat,
            expected_template_hash: public.template_digest,
            adaptor_point: public.adaptor_point,
            attempt: 0,
        };
        (session, public)
    }

    #[test]
    fn action_mapping_separates_funding_from_both_terminal_paths() {
        assert_eq!(
            operation_kind(SettlementActionV1::Funding),
            BitcoinOperationKindV1::Funding
        );
        assert_eq!(
            operation_kind(SettlementActionV1::Claim),
            BitcoinOperationKindV1::Terminal
        );
        assert_eq!(
            operation_kind(SettlementActionV1::Refund),
            BitcoinOperationKindV1::Terminal
        );
        assert_eq!(
            bitcoin_action(SettlementActionV1::Funding),
            BitcoinActionV1::Funding
        );
        assert_eq!(
            bitcoin_action(SettlementActionV1::Claim),
            BitcoinActionV1::Claim
        );
        assert_eq!(
            bitcoin_action(SettlementActionV1::Refund),
            BitcoinActionV1::Refund
        );
    }

    #[test]
    fn request_digest_is_bounded_domain_separated_and_rejects_zero_output(
    ) -> Result<(), ChildAuthorityRefusalV1> {
        let first = request_digest(DISPATCH_REQUEST_DOMAIN_V1, &[&[1; 32], &[2]])?;
        assert_eq!(
            first,
            request_digest(DISPATCH_REQUEST_DOMAIN_V1, &[&[1; 32], &[2]])?
        );
        assert_ne!(
            first,
            request_digest(RECONCILIATION_REQUEST_DOMAIN_V1, &[&[1; 32], &[2]])?
        );
        assert_ne!(first, ZERO_DIGEST);
        Ok(())
    }

    #[test]
    fn rpc_unavailability_is_mapped_only_to_unavailable() {
        assert_eq!(
            map_actuator_error(BitcoinActuatorErrorV1::Rpc(
                btc_actuator::BitcoinRpcErrorV1::TransportUnavailable
            )),
            ChildAuthorityRefusalV1::Unavailable
        );
    }

    #[test]
    fn stale_fence_and_invalid_time_are_conflicts_not_retryable_unavailability() {
        assert_eq!(
            map_actuator_error(BitcoinActuatorErrorV1::StaleFencing),
            ChildAuthorityRefusalV1::Conflict
        );
        assert_eq!(
            map_actuator_error(BitcoinActuatorErrorV1::InvalidTime),
            ChildAuthorityRefusalV1::Conflict
        );
    }

    #[test]
    fn registry_chain_id_is_not_the_network_identity_commitment() {
        let registry_chain_id = [0x02; 32];
        let chain_identity_digest = [0x93; 32];
        assert_ne!(registry_chain_id, chain_identity_digest);
        assert!(chain_bindings_match(
            registry_chain_id,
            chain_identity_digest,
            registry_chain_id
        ));
        assert!(!chain_bindings_match(
            registry_chain_id,
            chain_identity_digest,
            chain_identity_digest
        ));
    }

    #[test]
    fn funding_absence_and_rpc_ambiguity_can_never_mint_non_externalization() {
        assert_eq!(
            funding_reconciliation_disposition(BitcoinReconciliationV1::ProvenNotExternalized),
            FundingReconciliationDispositionV1::Unknown
        );
        assert_eq!(
            funding_reconciliation_disposition(BitcoinReconciliationV1::Ambiguous),
            FundingReconciliationDispositionV1::Unknown
        );
        assert!(matches!(
            funding_broadcast_failure(BitcoinActuatorErrorV1::LiveFunding),
            Ok(ProductionBitcoinFundingResultV1::Unknown)
        ));
        assert!(matches!(
            funding_broadcast_failure(BitcoinActuatorErrorV1::ExternalizationAmbiguous),
            Ok(ProductionBitcoinFundingResultV1::Unknown)
        ));
    }

    #[test]
    fn funding_before_armed_is_refused_not_reclassified_as_ambiguous() {
        assert!(matches!(
            funding_broadcast_failure(BitcoinActuatorErrorV1::FundingNotArmed),
            Err(ChildAuthorityRefusalV1::Refused)
        ));
    }

    #[test]
    fn exact_funding_observation_is_the_only_externalized_reconciliation_class() {
        assert_eq!(
            funding_reconciliation_disposition(BitcoinReconciliationV1::ExactMempool),
            FundingReconciliationDispositionV1::Externalized
        );
        assert_eq!(
            funding_reconciliation_disposition(BitcoinReconciliationV1::ExactConfirmed {
                confirmations: 1,
                block_height: 9,
            }),
            FundingReconciliationDispositionV1::Externalized
        );
        assert_eq!(
            funding_reconciliation_disposition(BitcoinReconciliationV1::ExactFinal {
                confirmations: 6,
                block_height: 9,
            }),
            FundingReconciliationDispositionV1::Externalized
        );
    }

    #[test]
    fn fresh_claim_session_refuses_transplant_attempt_network_and_template_changes() {
        let (session, public) = fresh_session_fixture();
        assert_eq!(validate_fresh_claim_session(&session, &public), Ok(()));

        let mut changed_attempt = session.clone();
        changed_attempt.attempt = 1;
        assert_eq!(
            validate_fresh_claim_session(&changed_attempt, &public),
            Err(ChildAuthorityRefusalV1::Conflict)
        );

        let mut changed_network = session.clone();
        changed_network.network = BitcoinNetworkV1::PublicSignet;
        assert_eq!(
            validate_fresh_claim_session(&changed_network, &public),
            Err(ChildAuthorityRefusalV1::Conflict)
        );

        let mut changed_template = public.clone();
        changed_template.template_digest[0] ^= 0x80;
        assert_eq!(
            validate_fresh_claim_session(&session, &changed_template),
            Err(ChildAuthorityRefusalV1::Conflict)
        );

        let mut transplanted = public.clone();
        transplanted.session_id[0] ^= 0x40;
        assert_eq!(
            validate_fresh_claim_session(&session, &transplanted),
            Err(ChildAuthorityRefusalV1::Conflict)
        );
    }
}

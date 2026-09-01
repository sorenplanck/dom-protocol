//! Sole production owner of externally prepared Bitcoin funding custody.
//!
//! Bitcoin wallet selection and refund signing happen before the final route
//! bootstrap because their public receipt is an input to F6.  The daemon must
//! therefore consume an existing authority, never create a replacement.  This
//! module opens that authority once, reauthenticates every route and Taproot
//! pin, and then lends the same physical store to refund proof before moving
//! its opaque `ArmedBitcoinFundingV1` into the Bitcoin child port.

use std::rc::Rc;

use adapter_btc_live::{
    ArmedBitcoinFundingV1, AuthenticatedBitcoinPayoutFaceV1, BitcoinCoreRpcClientV1,
    BitcoinFreshClaimBindingV1, BitcoinPrebroadcastStoreV1, LiveBitcoinError,
    ReopenedFreshBitcoinClaimV1,
};
use btc_actuator::{resolved_bitcoin_deployment_digest_v1, BitcoinClaimSessionV1};
use kaystra_core::types::LockMechanism;
use route_composer::{ComposedFinalClaimRolePlanV1, FinalClaimSecretSourceScopeV1};
use route_executor::LegIdV1;

use crate::production_child_btc::{
    ProductionBitcoinClaimMaterializationAuthorityV1, ProductionBitcoinFundingAuthorityV1,
};
use crate::production_config::{
    bitcoin_prebroadcast_script_digest_v7, ProductionBitcoinPrebroadcastPinsV7,
    ProductionRoutePinsV1, ValidatedProductionBootstrapV1,
};
use crate::production_refund_arming::{
    production_bitcoin_refund_route_binding_v1, ProductionBitcoinRefundFaceV1,
};
use crate::{AuthenticatedProductionInputsV1, ProductionRoutePositionV1};

/// Redacted refusal from the V7 external Bitcoin custody boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionBitcoinPrebroadcastErrorV7 {
    /// V7 path/pins do not match the authenticated route and deployment.
    #[error("Bitcoin prebroadcast configuration is inconsistent")]
    InvalidConfiguration,
    /// The externally provisioned owner authority is absent or already locked.
    #[error("Bitcoin prebroadcast authority is unavailable")]
    AuthorityUnavailable,
    /// The store is not refund-armed or its durable state disagrees with V7.
    #[error("Bitcoin prebroadcast authority is inconsistent")]
    Inconsistent,
    /// F6 has not consumed the one-shot payout proof before child construction.
    #[error("Bitcoin payout authority has not been consumed")]
    PayoutNotConsumed,
    /// A durably recovered exact Bitcoin claim was found, but the production
    /// composition root has no authenticated M.8 participant round yet, so it
    /// cannot rebind that claim without inventing its session facts.
    #[error("Bitcoin claim recovery is not composable in this build")]
    ClaimRecoveryNotComposable,
}

/// Final move-only handoff to the concrete Bitcoin settlement child.
#[must_use = "the exact funding custody must move into the Bitcoin child"]
pub(crate) struct ProductionBitcoinPrebroadcastChildHandoffV7 {
    pub(crate) funding: ProductionBitcoinFundingAuthorityV1,
    recovered_claim: Option<ReopenedFreshBitcoinClaimV1>,
    leg: LegIdV1,
}

/// Funding plus an optional restart-authenticated exact claim, bound to the
/// final role plan and ready for construction of the sole Bitcoin child.
#[must_use = "the bound authorities must move into the same Bitcoin child"]
#[expect(
    dead_code,
    reason = "bitcoin claim path frozen until the authenticated M8 round"
)]
pub(crate) struct ProductionBitcoinBoundChildHandoffV7 {
    pub(crate) funding: ProductionBitcoinFundingAuthorityV1,
    pub(crate) recovered_claim: Option<ProductionBitcoinClaimMaterializationAuthorityV1>,
}

impl ProductionBitcoinPrebroadcastChildHandoffV7 {
    /// Releases the funding authority for a child that will never materialize
    /// a claim in this process.
    ///
    /// This is the composition root's only Bitcoin path while the
    /// authenticated M.8 participant round is absent: funding and refund are
    /// real, and every claim materialization is refused by the child. A
    /// durably recovered claim is a contradiction with that policy, so it
    /// fails closed here instead of being silently dropped or rebound from a
    /// caller-shaped session.
    pub(crate) fn into_funding_only(
        self,
    ) -> Result<ProductionBitcoinFundingAuthorityV1, ProductionBitcoinPrebroadcastErrorV7> {
        if self.recovered_claim.is_some() {
            return Err(ProductionBitcoinPrebroadcastErrorV7::ClaimRecoveryNotComposable);
        }
        Ok(self.funding)
    }

    /// Binds a recovered Finalized claim to the complete authenticated route.
    /// No Prepared V1 authority can cross this boundary.
    #[expect(
        dead_code,
        reason = "bitcoin claim path frozen until the authenticated M8 round"
    )]
    pub(crate) fn bind_recovered_claim(
        self,
        inputs: &AuthenticatedProductionInputsV1,
        role_plan: &ComposedFinalClaimRolePlanV1,
        upstream_scope: &FinalClaimSecretSourceScopeV1,
        downstream_scope: &FinalClaimSecretSourceScopeV1,
        session: BitcoinClaimSessionV1,
    ) -> Result<ProductionBitcoinBoundChildHandoffV7, ProductionBitcoinPrebroadcastErrorV7> {
        let recovered_claim = self
            .recovered_claim
            .map(|finalized| {
                ProductionBitcoinClaimMaterializationAuthorityV1::bind_recovered_fresh_v1(
                    inputs,
                    role_plan,
                    upstream_scope,
                    downstream_scope,
                    self.leg,
                    session,
                    finalized,
                    &self.funding,
                )
            })
            .transpose()
            .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::Inconsistent)?;
        Ok(ProductionBitcoinBoundChildHandoffV7 {
            funding: self.funding,
            recovered_claim,
        })
    }
}

/// Sole retained owner of one exact, already armed Bitcoin route.
///
/// It has no `Clone`, codec, raw transaction getter or generic broadcaster.
#[must_use = "the external custody owner must be consumed into its exact route authorities"]
pub(crate) struct ProductionBitcoinPrebroadcastOwnerV7 {
    store: Rc<BitcoinPrebroadcastStoreV1>,
    rpc: Rc<BitcoinCoreRpcClientV1>,
    armed: ArmedBitcoinFundingV1,
    payout_face: Option<AuthenticatedBitcoinPayoutFaceV1>,
    recovered_claim: Option<ReopenedFreshBitcoinClaimV1>,
    leg: LegIdV1,
}

impl core::fmt::Debug for ProductionBitcoinPrebroadcastOwnerV7 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionBitcoinPrebroadcastOwnerV7([authority redacted])")
    }
}

impl ProductionBitcoinPrebroadcastOwnerV7 {
    /// Opens only the V7 external authority and reconstructs only an Armed stage.
    pub(crate) fn open_existing(
        bootstrap: &ValidatedProductionBootstrapV1,
        inputs: &AuthenticatedProductionInputsV1,
        rpc: Rc<BitcoinCoreRpcClientV1>,
    ) -> Result<Self, ProductionBitcoinPrebroadcastErrorV7> {
        let path = bootstrap
            .layout()
            .bitcoin_prebroadcast_store_v7()
            .ok_or(ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
        let pins = bootstrap
            .config()
            .bitcoin_prebroadcast_pins_v7()
            .ok_or(ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
        validate_authenticated_scope(inputs, bootstrap.config().pins(), pins)?;

        let store =
            Rc::new(BitcoinPrebroadcastStoreV1::open_existing(path).map_err(map_open_error)?);
        let mut reopened = store
            .reopen_fresh_funding_route(&rpc, pins.route_binding)
            .map_err(map_reopen_error)?;
        validate_reopened_route(inputs, pins, &reopened)?;
        let claim_binding = recovered_claim_binding(inputs, pins, reopened.receipt())?;
        let recovered_claim = match store
            .reopen_fresh_claim(&claim_binding)
            .map_err(map_reopen_error)?
        {
            None => None,
            Some(recovered @ ReopenedFreshBitcoinClaimV1::Finalized(_))
            | Some(recovered @ ReopenedFreshBitcoinClaimV1::ExtractionReady(_)) => Some(recovered),
            Some(ReopenedFreshBitcoinClaimV1::Prepared(_)) => {
                return Err(ProductionBitcoinPrebroadcastErrorV7::Inconsistent)
            }
        };
        let payout_face = reopened
            .take_payout_face_evidence()
            .map_err(map_reopen_error)?;
        let (plan, receipt, armed) = reopened.into_parts();
        if plan.canonical_digest().map_err(map_reopen_error)? != pins.plan_digest
            || receipt.receipt_digest() != pins.receipt_digest
            || armed.funding_summary().route_binding() != pins.route_binding
            || armed.funding_summary().plan_digest() != pins.plan_digest
        {
            return Err(ProductionBitcoinPrebroadcastErrorV7::Inconsistent);
        }
        Ok(Self {
            store,
            rpc,
            armed,
            payout_face: Some(payout_face),
            recovered_claim,
            leg: pins.leg,
        })
    }

    /// Takes the owner-authenticated payout face exactly once for F6 Terms.
    pub(crate) fn take_payout_face(
        &mut self,
    ) -> Result<AuthenticatedBitcoinPayoutFaceV1, ProductionBitcoinPrebroadcastErrorV7> {
        self.payout_face
            .take()
            .ok_or(ProductionBitcoinPrebroadcastErrorV7::Inconsistent)
    }

    /// Constructs the refund verifier over the same retained physical store.
    pub(crate) fn refund_face(
        &self,
        inputs: &AuthenticatedProductionInputsV1,
    ) -> Result<ProductionBitcoinRefundFaceV1, ProductionBitcoinPrebroadcastErrorV7> {
        let deployment = inputs
            .admission()
            .bitcoin_deployment_capability(self.leg)
            .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
        ProductionBitcoinRefundFaceV1::new(
            Rc::clone(&self.store),
            Rc::clone(&self.rpc),
            deployment,
            &self.armed,
        )
        .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::Inconsistent)
    }

    /// Moves the sole Armed handle into the concrete Bitcoin child authority.
    /// F6 must already have consumed its payout proof, preserving the ordering
    /// `authenticated terms -> refunds armed -> funding child`.
    pub(crate) fn into_child_handoff(
        self,
        inputs: &AuthenticatedProductionInputsV1,
    ) -> Result<ProductionBitcoinPrebroadcastChildHandoffV7, ProductionBitcoinPrebroadcastErrorV7>
    {
        if self.payout_face.is_some() {
            return Err(ProductionBitcoinPrebroadcastErrorV7::PayoutNotConsumed);
        }
        let funding = ProductionBitcoinFundingAuthorityV1::new(
            self.store,
            self.rpc,
            self.armed,
            inputs.admission(),
            inputs.composition(),
            self.leg,
        )
        .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::Inconsistent)?;
        Ok(ProductionBitcoinPrebroadcastChildHandoffV7 {
            funding,
            recovered_claim: self.recovered_claim,
            leg: self.leg,
        })
    }
}

fn validate_authenticated_scope(
    inputs: &AuthenticatedProductionInputsV1,
    route_pins: ProductionRoutePinsV1,
    pins: ProductionBitcoinPrebroadcastPinsV7,
) -> Result<(), ProductionBitcoinPrebroadcastErrorV7> {
    let session = inputs
        .bitcoin_session(pins.leg)
        .ok_or(ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
    let other_leg = match pins.leg {
        LegIdV1::Upstream => LegIdV1::Downstream,
        LegIdV1::Downstream => LegIdV1::Upstream,
    };
    if inputs.bitcoin_session(other_leg).is_some() {
        return Err(ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration);
    }
    let settlement = match pins.leg {
        LegIdV1::Upstream => inputs.composition().upstream(),
        LegIdV1::Downstream => inputs.composition().downstream(),
    };
    let terms_digest = settlement
        .terms_hash()
        .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
    let deployment = inputs
        .admission()
        .bitcoin_deployment_capability(pins.leg)
        .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
    let deployment_digest = resolved_bitcoin_deployment_digest_v1(&deployment)
        .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
    let route_binding = production_bitcoin_refund_route_binding_v1(
        inputs.admission().route_id(),
        inputs.composition(),
        pins.leg,
        &deployment,
    )
    .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
    let position_matches = matches!(
        (session.position(), pins.leg),
        (ProductionRoutePositionV1::Upstream, LegIdV1::Upstream)
            | (ProductionRoutePositionV1::Downstream, LegIdV1::Downstream)
    );
    if route_pins.route_id != inputs.admission().route_id()
        || route_pins.network_id != session.network_id()
        || inputs.admission().route_id() != session.route_id()
        || !position_matches
        || session.session_id() != pins.session_id
        || session.terms_digest() != pins.terms_digest
        || session.deployment() != &deployment
        || settlement.settlement_id.0 != pins.settlement_id
        || settlement.session_id.0 != pins.session_id
        || terms_digest != pins.terms_digest
        || deployment_digest != pins.deployment_digest
        || route_binding != pins.route_binding
        || settlement.counterparty_leg.mechanism != LockMechanism::SchnorrAdaptor
        || !settlement.recovery.refund_before_funding
    {
        return Err(ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration);
    }
    Ok(())
}

fn validate_reopened_route(
    inputs: &AuthenticatedProductionInputsV1,
    pins: ProductionBitcoinPrebroadcastPinsV7,
    reopened: &adapter_btc_live::ReopenedFreshBitcoinFundingRouteV1,
) -> Result<(), ProductionBitcoinPrebroadcastErrorV7> {
    let settlement = match pins.leg {
        LegIdV1::Upstream => inputs.composition().upstream(),
        LegIdV1::Downstream => inputs.composition().downstream(),
    };
    let session = inputs
        .bitcoin_session(pins.leg)
        .ok_or(ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
    let receipt = reopened.receipt();
    let plan = reopened.plan();
    let amount = u64::try_from(settlement.counterparty_leg.amount)
        .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?;
    let actual_fee = receipt.actual_funding_fee_sat();
    if receipt.route_binding() != pins.route_binding
        || receipt.plan_digest() != pins.plan_digest
        || receipt.receipt_digest() != pins.receipt_digest
        || receipt.claim_roster() != *session.roster()
        || receipt.contract_amount_sat() != amount
        || u128::from(actual_fee) > settlement.fee_limit.counterparty_max
        || plan.route_binding != pins.route_binding
        || plan.amount_sat != amount
        || plan.canonical_digest().map_err(map_reopen_error)? != pins.plan_digest
        || plan.contract_script_pubkey.as_slice() != receipt.contract_script_pubkey()
        || plan.refund_contract.refund_key_xonly != receipt.refund_key_xonly()
        || plan.refund_outputs.len() != 1
        || plan.refund_outputs[0].script_pubkey.as_slice()
            != receipt.refund_destination_script_pubkey()
        || plan.refund_outputs[0].amount_sat != receipt.refund_output_amount_sat()
        || authenticated_script_digest(receipt.contract_script_pubkey())?
            != pins.contract_script_pubkey_digest
        || authenticated_script_digest(receipt.claim_destination_script_pubkey())?
            != pins.claim_destination_script_pubkey_digest
        || authenticated_script_digest(receipt.refund_destination_script_pubkey())?
            != pins.refund_destination_script_pubkey_digest
        || receipt.refund_key_xonly() != pins.refund_key_xonly
        || receipt.funding_template_hash() != pins.funding_template_hash
        || receipt.claim_template_hash() != pins.claim_template_hash
        || receipt.refund_template_hash() != pins.refund_template_hash
    {
        return Err(ProductionBitcoinPrebroadcastErrorV7::Inconsistent);
    }
    Ok(())
}

fn recovered_claim_binding(
    inputs: &AuthenticatedProductionInputsV1,
    pins: ProductionBitcoinPrebroadcastPinsV7,
    receipt: &adapter_btc_live::BitcoinFreshRouteReceiptV1,
) -> Result<BitcoinFreshClaimBindingV1, ProductionBitcoinPrebroadcastErrorV7> {
    let settlement = match pins.leg {
        LegIdV1::Upstream => inputs.composition().upstream(),
        LegIdV1::Downstream => inputs.composition().downstream(),
    };
    let fee_sat = receipt
        .contract_amount_sat()
        .checked_sub(receipt.claim_output_amount_sat())
        .filter(|fee| *fee != 0)
        .ok_or(ProductionBitcoinPrebroadcastErrorV7::Inconsistent)?;
    let binding = BitcoinFreshClaimBindingV1 {
        settlement_id: settlement.settlement_id.0,
        session_id: settlement.session_id.0,
        terms_hash: settlement
            .terms_hash()
            .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)?,
        funding_txid: receipt.funding_txid(),
        funding_vout: receipt.contract_vout(),
        funding_amount_sat: receipt.contract_amount_sat(),
        destination_script_pubkey: receipt.claim_destination_script_pubkey().to_vec(),
        fee_sat,
        expected_template_hash: receipt.claim_template_hash(),
        adaptor_point: inputs.composition().adaptor_point_sec1(),
    };
    if binding.settlement_id != pins.settlement_id
        || binding.session_id != pins.session_id
        || binding.terms_hash != pins.terms_digest
        || binding.expected_template_hash != pins.claim_template_hash
    {
        return Err(ProductionBitcoinPrebroadcastErrorV7::Inconsistent);
    }
    Ok(binding)
}

fn authenticated_script_digest(
    script: &[u8],
) -> Result<[u8; 32], ProductionBitcoinPrebroadcastErrorV7> {
    bitcoin_prebroadcast_script_digest_v7(script)
        .map_err(|_| ProductionBitcoinPrebroadcastErrorV7::InvalidConfiguration)
}

fn map_open_error(error: LiveBitcoinError) -> ProductionBitcoinPrebroadcastErrorV7 {
    match error {
        LiveBitcoinError::StoreUnavailable | LiveBitcoinError::CredentialUnavailable => {
            ProductionBitcoinPrebroadcastErrorV7::AuthorityUnavailable
        }
        _ => ProductionBitcoinPrebroadcastErrorV7::Inconsistent,
    }
}

fn map_reopen_error(error: LiveBitcoinError) -> ProductionBitcoinPrebroadcastErrorV7 {
    match error {
        LiveBitcoinError::StoreUnavailable
        | LiveBitcoinError::CredentialUnavailable
        | LiveBitcoinError::Rpc => ProductionBitcoinPrebroadcastErrorV7::AuthorityUnavailable,
        LiveBitcoinError::FundingNotArmed
        | LiveBitcoinError::StateConflict
        | LiveBitcoinError::CorruptRecord
        | LiveBitcoinError::InvalidRequest
        | LiveBitcoinError::IdentityMismatch
        | LiveBitcoinError::InvalidRpcResponse
        | LiveBitcoinError::FundingIncomplete
        | LiveBitcoinError::FundingMismatch
        | LiveBitcoinError::FundingInputUnavailable
        | LiveBitcoinError::RefundMismatch
        | LiveBitcoinError::ClaimMismatch
        | LiveBitcoinError::ClaimNonceCustody
        | LiveBitcoinError::TransactionUnavailable
        | LiveBitcoinError::SnapshotChanged
        | LiveBitcoinError::InsufficientConfirmations
        | LiveBitcoinError::BoundsExceeded => ProductionBitcoinPrebroadcastErrorV7::Inconsistent,
    }
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_not_impl_any;

    use super::*;

    assert_not_impl_any!(ProductionBitcoinPrebroadcastOwnerV7: Clone, Copy);
    assert_not_impl_any!(ProductionBitcoinPrebroadcastChildHandoffV7: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(ProductionBitcoinBoundChildHandoffV7: Clone, Copy, core::fmt::Debug);
}

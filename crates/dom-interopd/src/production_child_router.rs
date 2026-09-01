//! Face-exact routing from the settlement coordinator to production actuators.
//!
//! The coordinator persists every call before this boundary.  This module
//! performs no signing, RPC or evidence synthesis itself; it only prevents a
//! request for one authenticated face from reaching another face's authority.

use settlement_coordinator::{
    ChildAuthorityRefusalV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1,
    ChildObservationOutcomeV1, ChildObservationRequestV1, ChildReconciliationOutcomeV1,
    ChildReconciliationRequestV1, SettlementActionV1, SettlementChildAuthorityV1,
    SettlementChildObserverV1, SettlementChildPlanV1, SettlementFaceV1, SettlementLegV1,
};

use route_composer::RouteScalar;

use crate::production_child_btc::{ProductionBitcoinChildClockV1, ProductionBitcoinChildPortV1};
use crate::production_child_dom::{
    ProductionDomActionAuthorityV1, ProductionDomChildClockV1, ProductionDomChildPortV1,
};
use crate::production_child_evm::{ProductionEvmChildClockV1, ProductionEvmChildPortV1};
use crate::production_child_solana::{ProductionSolanaChildClockV1, ProductionSolanaChildPortV1};
use crate::production_child_xmr::{ProductionXmrChildClockV1, ProductionXmrChildPortV1};
use btc_actuator::BitcoinRpcV1;
use evm_actuator::EvmRpcV1;

/// Complete public scope from which a chain authority may materialize one
/// exact retained child. No raw transaction or signer-selected fact crosses
/// this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionChildMaterializationRequestV1 {
    pub(crate) route_id: [u8; 32],
    pub(crate) effect_id: [u8; 32],
    pub(crate) settlement_id: [u8; 32],
    pub(crate) leg: SettlementLegV1,
    pub(crate) action: SettlementActionV1,
    pub(crate) fencing_epoch: u64,
    pub(crate) semantic_digest: [u8; 32],
    pub(crate) terms_digest: [u8; 32],
    pub(crate) registry_digest: [u8; 32],
    pub(crate) profile_digest: [u8; 32],
    pub(crate) deployment_digest: [u8; 32],
    pub(crate) route_scope_digest: [u8; 32],
    pub(crate) composition_digest: [u8; 32],
    pub(crate) role_plan_digest: [u8; 32],
    pub(crate) source_scope_digest: [u8; 32],
    pub(crate) exposure: settlement_coordinator::ChildExposureV1,
}

/// One chain-specific, owner-scoped production child authority.
///
/// Implementations own their durable actuator and RPC/signer boundaries. Raw
/// transactions and keys never cross this trait. A verified route scalar may
/// be borrowed only for a `UsesPublicSecret` claim after the parent route has
/// durably acknowledged the exact first-public-exposure evidence.
pub(crate) trait ProductionSettlementChildPortV1 {
    /// The single chain face accepted by this authority.
    fn face(&self) -> SettlementFaceV1;

    /// Prepares or reopens the exact transaction under this port's existing
    /// durable owner. The optional scalar is accepted only for an already
    /// public upstream claim and is never retained outside the actuator's
    /// opaque transaction custody.
    fn materialize(
        &mut self,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1>;

    /// Idempotently progresses one already-journaled child call.
    fn externalize(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1>;

    /// Reconciles one pending call without dispatching different bytes.
    fn reconcile(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1>;

    /// Observes finality or invalidation for one exact child transaction.
    fn observe(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1>;
}

pub(crate) struct AuthenticatedDomChildPortV1(Box<dyn ProductionSettlementChildPortV1>);
pub(crate) struct AuthenticatedEvmChildPortV1(Box<dyn ProductionSettlementChildPortV1>);
pub(crate) struct AuthenticatedBitcoinChildPortV1(Box<dyn ProductionSettlementChildPortV1>);
pub(crate) struct AuthenticatedSolanaChildPortV1(Box<dyn ProductionSettlementChildPortV1>);
pub(crate) struct AuthenticatedXmrChildPortV1(Box<dyn ProductionSettlementChildPortV1>);

/// Exact face router owned by the production settlement bridge.
///
/// DOM is mandatory because every settlement plan contains one DOM child.
/// EVM and Bitcoin are optional independently so a deployment need not open
/// credentials for an unused counterparty chain. A request for an uninstalled
/// face fails closed; it is never redirected to the installed one.
pub(crate) struct ProductionSettlementChildRouterV1 {
    dom: Box<dyn ProductionSettlementChildPortV1>,
    evm: Option<Box<dyn ProductionSettlementChildPortV1>>,
    bitcoin: Option<Box<dyn ProductionSettlementChildPortV1>>,
    monero: Option<Box<dyn ProductionSettlementChildPortV1>>,
    solana: Option<Box<dyn ProductionSettlementChildPortV1>>,
}

impl core::fmt::Debug for ProductionSettlementChildRouterV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSettlementChildRouterV1([authorities redacted])")
    }
}

impl ProductionSettlementChildRouterV1 {
    pub(crate) fn new(
        dom: AuthenticatedDomChildPortV1,
        evm: Option<AuthenticatedEvmChildPortV1>,
        bitcoin: Option<AuthenticatedBitcoinChildPortV1>,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        Self::new_with_counterparties(dom, evm, bitcoin, None)
    }

    pub(crate) fn new_with_counterparties(
        dom: AuthenticatedDomChildPortV1,
        evm: Option<AuthenticatedEvmChildPortV1>,
        bitcoin: Option<AuthenticatedBitcoinChildPortV1>,
        solana: Option<AuthenticatedSolanaChildPortV1>,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        Self::new_with_all_counterparties(dom, evm, bitcoin, solana, None)
    }

    pub(crate) fn new_with_all_counterparties(
        dom: AuthenticatedDomChildPortV1,
        evm: Option<AuthenticatedEvmChildPortV1>,
        bitcoin: Option<AuthenticatedBitcoinChildPortV1>,
        solana: Option<AuthenticatedSolanaChildPortV1>,
        monero: Option<AuthenticatedXmrChildPortV1>,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        let AuthenticatedDomChildPortV1(dom) = dom;
        let evm = evm.map(|AuthenticatedEvmChildPortV1(port)| port);
        let bitcoin = bitcoin.map(|AuthenticatedBitcoinChildPortV1(port)| port);
        let solana = solana.map(|AuthenticatedSolanaChildPortV1(port)| port);
        let monero = monero.map(|AuthenticatedXmrChildPortV1(port)| port);
        if dom.face() != SettlementFaceV1::Dom
            || evm
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Evm)
            || bitcoin
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Bitcoin)
            || solana
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Solana)
            || monero
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Monero)
            || (evm.is_none() && bitcoin.is_none() && solana.is_none() && monero.is_none())
        {
            return Err(ChildAuthorityRefusalV1::Refused);
        }
        Ok(Self {
            dom,
            evm,
            bitcoin,
            monero,
            solana,
        })
    }

    pub(crate) fn authenticate_dom<C, A>(
        port: ProductionDomChildPortV1<C, A>,
    ) -> AuthenticatedDomChildPortV1
    where
        C: ProductionDomChildClockV1 + 'static,
        A: ProductionDomActionAuthorityV1 + 'static,
    {
        AuthenticatedDomChildPortV1(Box::new(port))
    }

    pub(crate) fn authenticate_evm<R, C>(
        port: ProductionEvmChildPortV1<R, C>,
    ) -> AuthenticatedEvmChildPortV1
    where
        R: EvmRpcV1 + 'static,
        C: ProductionEvmChildClockV1 + 'static,
    {
        AuthenticatedEvmChildPortV1(Box::new(port))
    }

    pub(crate) fn authenticate_bitcoin<R, C>(
        port: ProductionBitcoinChildPortV1<R, C>,
    ) -> AuthenticatedBitcoinChildPortV1
    where
        R: BitcoinRpcV1 + 'static,
        C: ProductionBitcoinChildClockV1 + 'static,
    {
        AuthenticatedBitcoinChildPortV1(Box::new(port))
    }

    pub(crate) fn authenticate_solana<R, C>(
        port: ProductionSolanaChildPortV1<R, C>,
    ) -> AuthenticatedSolanaChildPortV1
    where
        R: solana_rpc::SolanaRpc + 'static,
        C: ProductionSolanaChildClockV1 + 'static,
    {
        AuthenticatedSolanaChildPortV1(Box::new(port))
    }

    pub(crate) fn authenticate_monero<B, O, C>(
        port: ProductionXmrChildPortV1<B, O, C>,
    ) -> AuthenticatedXmrChildPortV1
    where
        B: xmr_spend_port::ExactBroadcastPort + 'static,
        O: xmr_actuator::XmrObservationPortV1 + 'static,
        C: ProductionXmrChildClockV1 + 'static,
    {
        AuthenticatedXmrChildPortV1(Box::new(port))
    }

    #[cfg(test)]
    pub(crate) fn new_test(
        dom: Box<dyn ProductionSettlementChildPortV1>,
        evm: Option<Box<dyn ProductionSettlementChildPortV1>>,
        bitcoin: Option<Box<dyn ProductionSettlementChildPortV1>>,
    ) -> Result<Self, ChildAuthorityRefusalV1> {
        if dom.face() != SettlementFaceV1::Dom
            || evm
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Evm)
            || bitcoin
                .as_ref()
                .is_some_and(|port| port.face() != SettlementFaceV1::Bitcoin)
            || (evm.is_none() && bitcoin.is_none())
        {
            return Err(ChildAuthorityRefusalV1::Refused);
        }
        Ok(Self {
            dom,
            evm,
            bitcoin,
            monero: None,
            solana: None,
        })
    }

    fn port(
        &mut self,
        face: SettlementFaceV1,
    ) -> Result<&mut (dyn ProductionSettlementChildPortV1 + '_), ChildAuthorityRefusalV1> {
        match face {
            SettlementFaceV1::Dom => Ok(self.dom.as_mut()),
            SettlementFaceV1::Evm => match self.evm.as_mut() {
                Some(port) => Ok(port.as_mut()),
                None => Err(ChildAuthorityRefusalV1::Refused),
            },
            SettlementFaceV1::Bitcoin => match self.bitcoin.as_mut() {
                Some(port) => Ok(port.as_mut()),
                None => Err(ChildAuthorityRefusalV1::Refused),
            },
            // An uninstalled child refuses, exactly as an uninstalled EVM
            // or Bitcoin child does; nothing is ever redirected.
            SettlementFaceV1::Monero => match self.monero.as_mut() {
                Some(port) => Ok(port.as_mut()),
                None => Err(ChildAuthorityRefusalV1::Refused),
            },
            SettlementFaceV1::Solana => match self.solana.as_mut() {
                Some(port) => Ok(port.as_mut()),
                None => Err(ChildAuthorityRefusalV1::Refused),
            },
        }
    }

    pub(crate) fn materialize_child(
        &mut self,
        face: SettlementFaceV1,
        request: ProductionChildMaterializationRequestV1,
        public_scalar: Option<&RouteScalar>,
    ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
        let port = self.port(face)?;
        if port.face() != face {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.materialize(request, public_scalar)
    }
}

impl SettlementChildAuthorityV1 for ProductionSettlementChildRouterV1 {
    fn externalize_child(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        let expected = request.face();
        let port = self.port(expected)?;
        if port.face() != expected {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.externalize(request)
    }

    fn reconcile_child(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        let expected = request.dispatch.face();
        let port = self.port(expected)?;
        if port.face() != expected {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.reconcile(request)
    }
}

impl SettlementChildObserverV1 for ProductionSettlementChildRouterV1 {
    fn observe_child(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        let expected = request.face;
        let port = self.port(expected)?;
        if port.face() != expected {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        port.observe(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RefusingPort(SettlementFaceV1);

    impl ProductionSettlementChildPortV1 for RefusingPort {
        fn face(&self) -> SettlementFaceV1 {
            self.0
        }

        fn materialize(
            &mut self,
            _request: ProductionChildMaterializationRequestV1,
            _public_scalar: Option<&RouteScalar>,
        ) -> Result<SettlementChildPlanV1, ChildAuthorityRefusalV1> {
            Err(ChildAuthorityRefusalV1::Refused)
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

    fn port(face: SettlementFaceV1) -> Box<dyn ProductionSettlementChildPortV1> {
        Box::new(RefusingPort(face))
    }

    #[test]
    fn construction_requires_dom_and_one_exact_counterparty_face() {
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            Some(port(SettlementFaceV1::Evm)),
            None,
        )
        .is_ok());
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            None,
            Some(port(SettlementFaceV1::Bitcoin)),
        )
        .is_ok());
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            None,
            None,
        )
        .is_err());
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Evm),
            Some(port(SettlementFaceV1::Evm)),
            None,
        )
        .is_err());
        assert!(ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            Some(port(SettlementFaceV1::Bitcoin)),
            None,
        )
        .is_err());
    }

    #[test]
    fn debug_never_enumerates_installed_authorities() {
        let router = ProductionSettlementChildRouterV1::new_test(
            port(SettlementFaceV1::Dom),
            Some(port(SettlementFaceV1::Evm)),
            Some(port(SettlementFaceV1::Bitcoin)),
        )
        .expect("valid router");
        assert_eq!(
            format!("{router:?}"),
            "ProductionSettlementChildRouterV1([authorities redacted])"
        );
    }
}

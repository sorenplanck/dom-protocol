//! Private single-opening composition for production Contracts authorities.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adapter_dom_real::{RealDomClaimConsumerV1, RealDomClaimVerifierV1, RealDomError};
use dom_actuator::{
    participant_contracts_signer_v1, ContractsDomSignerV1, DomActuatorError, DomActuatorResult,
    DomContractsActuatorV1, DomFinalClaimAdmissionBundleV2, DomParticipantSigningShareV1,
    DomSessionBindingV1,
};
use dom_adaptor::TrustedChainIdV1;
use dom_core::Hash256;
use dom_scriptless_identity_store::{ContractsTransportIdentityStoreV1, IdentityStoreError};
use dom_scriptless_store::{
    ClaimSigningAuthorizationV2, ConsumedClaimSigningAuthorizationV2, ContractsNonceVaultV1,
    ContractsSessionStoreV1, OutboundDsc1RecoveryV1, PreparedDsc1SigningRequestV1,
    PreparedEvmSignedActionImportV1, PreparedOperationalFinalRefundTransportAuthorityV1,
    PreparedOperationalM8FundingGateV2, PreparedPostAnchorClaimPreSignatureTransportAuthorityV2,
    SessionStoreError,
};
use f7_anchor_authority::VerifiedF7AnchorAuthorizationV2;
use kaystra_core::state::EvidenceRefV1;
use relay::auth::RosterRegistryV1;
use relay::{SenderRoleV1, TimelockSpec};
use route_executor::{FrozenBindingsV1, LegIdV1};
use route_transport::{
    F6AppliedReplayErrorV1, F6AppliedReplayReportV1, F6TransportPortV1, RelaySubmitQueueV1,
    RouteApplicationDispositionV2,
};
use settlement_coordinator::ChildAuthorityRefusalV1;

use crate::production_evm_remote_signer::{
    ProductionEvmRemoteRequestV1, ProductionEvmRemoteSignerBindingV1,
    ProductionEvmRemoteTransportV1,
};
use crate::production_f6_lifecycle::{ProductionF6LifecycleErrorV2, ProductionF6LifecyclePortV2};
use crate::production_plan_source::{
    ProductionDomPublicSecretConsumerAuthorityV1, ProductionDomPublicSecretInstallerV1,
    ProductionDomPublicSecretSourceScopeV1, ProductionDomPublicSecretSourceV1,
};
use crate::production_refund_arming::{
    ProductionDomRefundFaceScopeV1, ProductionDomRefundFaceV1, ProductionRefundArmingOpenErrorV1,
};
use crate::relay_worker::{
    ContractsRelayIngressErrorV1, ContractsSessionStatusV1, DurableRelayWorkerV1,
    PreparedContractsIngressV1, RelayInboundPollReportV1, RelayOutboundStepV1, RelayWorkerConfigV1,
    RelayWorkerInboundErrorV1, RelayWorkerOpenErrorV1, RelayWorkerOutboundErrorV1,
    RelayWorkerPathsV1,
};
use crate::supervisor::AuthorityRefusalV1;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionContractsOpenErrorV1 {
    #[error("Contracts DSC1 and Relay signing identities must be distinct")]
    IdentityKeyReuse,
    #[error("Contracts Store rejected composition")]
    StoreRejected,
    #[error("Contracts Relay worker rejected composition")]
    Relay(#[source] RelayWorkerOpenErrorV1),
}

impl From<SessionStoreError> for ProductionContractsOpenErrorV1 {
    fn from(_: SessionStoreError) -> Self {
        Self::StoreRejected
    }
}

impl From<RelayWorkerOpenErrorV1> for ProductionContractsOpenErrorV1 {
    fn from(error: RelayWorkerOpenErrorV1) -> Self {
        Self::Relay(error)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionContractsOutboundErrorV1 {
    #[error("Contracts identity rejected Store-issued DSC1 signing")]
    Identity(#[source] IdentityStoreError),
    #[error("Contracts Store rejected outbound DSC1 recovery")]
    Store(#[source] SessionStoreError),
    #[error("Contracts Relay worker rejected outbound DSC1 staging")]
    Relay(#[source] RelayWorkerOutboundErrorV1),
    #[error("Contracts Relay owner is already executing another operation")]
    OwnerBusy,
}

#[derive(Debug, thiserror::Error)]
#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
pub(crate) enum ProductionContractsInboundErrorV1 {
    #[error("real DOM observation failed closed")]
    Observation(#[source] RealDomError),
    #[error("DOM Contracts observation transition failed closed")]
    Actuator(#[source] DomActuatorError),
    #[error("Contracts Store refused FinalClaim ingress authority")]
    Store(#[source] SessionStoreError),
    #[error("Contracts Relay refused FinalClaim ingress authority")]
    Relay(#[source] ContractsRelayIngressErrorV1),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionContractsF6RecoveryErrorV2 {
    #[error("Contracts Relay owner is already executing another operation")]
    OwnerBusy,
    #[error("production F6 applied history failed authentication")]
    Replay(#[source] F6AppliedReplayErrorV1<ProductionF6LifecycleErrorV2>),
}

/// Redacted refusal from the productive F7/M.8 Contracts boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
pub(crate) enum ProductionContractsPostAnchorErrorV2 {
    /// The verified authorization does not belong to this retained owner or
    /// the durable Store refused its exact post-anchor transition.
    #[error("Contracts Store refused productive post-anchor authority")]
    StoreRefused,
}

/// Move-only post-anchor authority over the same physical Contracts Store.
///
/// This wrapper cannot be built from public anchor facts. Its only constructor
/// is [`ProductionContractsV1::issue_post_anchor_v2`], which consumes the
/// opaque result of the real F7 V2 verifier into this owner's retained Store.
/// Keeping the `Rc` beside the linear authorization prevents a later stage
/// from reopening or substituting a different Contracts authority.
#[must_use = "the productive post-anchor Contracts authority is linear"]
#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
pub(crate) struct ProductionContractsPostAnchorV2 {
    store: Rc<ContractsSessionStoreV1>,
    authorization: ClaimSigningAuthorizationV2,
}

impl core::fmt::Debug for ProductionContractsPostAnchorV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionContractsPostAnchorV2([authority redacted])")
    }
}

/// Durable consumed form retained with the same physical Contracts Store.
#[must_use = "the consumed post-anchor Contracts authority remains linear"]
#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
pub(crate) struct ProductionContractsConsumedPostAnchorV2 {
    store: Rc<ContractsSessionStoreV1>,
    authorization: ConsumedClaimSigningAuthorizationV2,
}

impl core::fmt::Debug for ProductionContractsConsumedPostAnchorV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionContractsConsumedPostAnchorV2([authority redacted])")
    }
}

impl ProductionContractsPostAnchorV2 {
    /// Durably consumes issuance before any DOM claim nonce or signature use.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn consume(
        self,
    ) -> Result<ProductionContractsConsumedPostAnchorV2, ProductionContractsPostAnchorErrorV2> {
        let authorization = self
            .store
            .consume_post_anchor_dom_claim_signing_v2(self.authorization)
            .map_err(|_| ProductionContractsPostAnchorErrorV2::StoreRefused)?;
        Ok(ProductionContractsConsumedPostAnchorV2 {
            store: self.store,
            authorization,
        })
    }
}

impl ProductionContractsConsumedPostAnchorV2 {
    /// Reauthenticates the consumed capability against its retained Store.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn revalidate(&self) -> Result<(), ProductionContractsPostAnchorErrorV2> {
        self.store
            .revalidate_consumed_post_anchor_dom_claim_signing_v2(&self.authorization)
            .map_err(|_| ProductionContractsPostAnchorErrorV2::StoreRefused)
    }

    /// Borrows the Store-authenticated capability without separating it from
    /// the retained physical owner. This is the only intended DOM signer edge.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn authorization(&self) -> &ConsumedClaimSigningAuthorizationV2 {
        &self.authorization
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionContractsPollErrorV1<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    #[error("Contracts Relay owner is already executing another operation")]
    OwnerBusy,
    #[error("Contracts Relay inbound step failed closed")]
    Worker(#[source] RelayWorkerInboundErrorV1<E>),
}

impl From<F6AppliedReplayErrorV1<ProductionF6LifecycleErrorV2>>
    for ProductionContractsF6RecoveryErrorV2
{
    fn from(error: F6AppliedReplayErrorV1<ProductionF6LifecycleErrorV2>) -> Self {
        Self::Replay(error)
    }
}

impl From<RealDomError> for ProductionContractsInboundErrorV1 {
    fn from(error: RealDomError) -> Self {
        Self::Observation(error)
    }
}

impl From<DomActuatorError> for ProductionContractsInboundErrorV1 {
    fn from(error: DomActuatorError) -> Self {
        Self::Actuator(error)
    }
}

impl From<SessionStoreError> for ProductionContractsInboundErrorV1 {
    fn from(error: SessionStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<ContractsRelayIngressErrorV1> for ProductionContractsInboundErrorV1 {
    fn from(error: ContractsRelayIngressErrorV1) -> Self {
        Self::Relay(error)
    }
}

impl From<IdentityStoreError> for ProductionContractsOutboundErrorV1 {
    fn from(error: IdentityStoreError) -> Self {
        Self::Identity(error)
    }
}

impl From<SessionStoreError> for ProductionContractsOutboundErrorV1 {
    fn from(error: SessionStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<RelayWorkerOutboundErrorV1> for ProductionContractsOutboundErrorV1 {
    fn from(error: RelayWorkerOutboundErrorV1) -> Self {
        Self::Relay(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    dead_code,
    reason = "retained surface not yet wired by the stage-7 composition root"
)]
pub(crate) enum ProductionContractsResumeV1 {
    Idle,
    Staged(RouteApplicationDispositionV2),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionDomFinalClaimTransportRecoveryV1 {
    NotStarted,
    Staged,
}

/// Restart-safe state of one exact counterparty EVM signature response.
pub(crate) enum ProductionEvmRemoteResponseV1 {
    /// The authenticated `0x16` has not reached this Contracts Store yet.
    Pending,
    /// The Store consumed the exact response into its one-shot import grant.
    Prepared(Box<PreparedEvmSignedActionImportV1>),
}

impl core::fmt::Debug for ProductionEvmRemoteResponseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pending => formatter.write_str("ProductionEvmRemoteResponseV1::Pending"),
            Self::Prepared(_) => formatter
                .write_str("ProductionEvmRemoteResponseV1::Prepared([raw transaction redacted])"),
        }
    }
}

/// Narrow, move-only view of the one Contracts/Relay opening used by an EVM
/// child whose signing key belongs to the counterparty.
pub(crate) struct ProductionEvmRemoteContractsAuthorityV1<F>
where
    F: F6TransportPortV1,
{
    session_id: [u8; 32],
    route_id: [u8; 32],
    local_participant: [u8; 32],
    remote_participant: [u8; 32],
    store: Rc<ContractsSessionStoreV1>,
    identity: Rc<ContractsTransportIdentityStoreV1>,
    relay: Rc<RefCell<DurableRelayWorkerV1<F>>>,
    expiry: TimelockSpec,
}

impl<F> core::fmt::Debug for ProductionEvmRemoteContractsAuthorityV1<F>
where
    F: F6TransportPortV1,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionEvmRemoteContractsAuthorityV1([authority redacted])")
    }
}

impl<F> ProductionEvmRemoteTransportV1 for ProductionEvmRemoteContractsAuthorityV1<F>
where
    F: F6TransportPortV1,
{
    fn stage_request(
        &mut self,
        request: &ProductionEvmRemoteRequestV1,
    ) -> Result<[u8; 32], ChildAuthorityRefusalV1> {
        prepare_and_stage_evm_remote_action_request_shared(
            EvmRemoteContractsSharedV1 {
                session_id: self.session_id,
                route_id: self.route_id,
                local_participant: self.local_participant,
                remote_participant: self.remote_participant,
                store: self.store.as_ref(),
                identity: self.identity.as_ref(),
                relay: &self.relay,
            },
            request,
            self.expiry,
        )
        .map_err(map_evm_remote_transport_error)
    }

    fn take_response(
        &mut self,
        request: &ProductionEvmRemoteRequestV1,
        request_message_digest: [u8; 32],
    ) -> Result<Option<PreparedEvmSignedActionImportV1>, ChildAuthorityRefusalV1> {
        match take_evm_remote_signed_response_shared(
            self.session_id,
            self.route_id,
            self.local_participant,
            self.remote_participant,
            self.store.as_ref(),
            request,
            request_message_digest,
        )
        .map_err(map_evm_remote_transport_error)?
        {
            ProductionEvmRemoteResponseV1::Pending => Ok(None),
            ProductionEvmRemoteResponseV1::Prepared(prepared) => Ok(Some(*prepared)),
        }
    }
}

fn map_evm_remote_transport_error(
    error: ProductionContractsOutboundErrorV1,
) -> ChildAuthorityRefusalV1 {
    match error {
        ProductionContractsOutboundErrorV1::Relay(_)
        | ProductionContractsOutboundErrorV1::OwnerBusy => ChildAuthorityRefusalV1::Unavailable,
        ProductionContractsOutboundErrorV1::Identity(_)
        | ProductionContractsOutboundErrorV1::Store(_) => ChildAuthorityRefusalV1::Conflict,
    }
}

/// Validated one-opening handoff into the DOM public-secret source.
///
/// This remains private to the composition module. It has no store accessor;
/// its only production consumer moves the retained [`Rc`] into the concrete
/// source after all owner and chain checks have passed.
struct ProductionDomPublicSecretOpeningV1 {
    store: Rc<ContractsSessionStoreV1>,
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    binding: DomSessionBindingV1,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    trusted_chain_id: TrustedChainIdV1,
}

/// Opaque, purpose-specific ownership handoff for one DOM refund face.
///
/// Only [`ProductionContractsV1`] can construct this value.  Its operations
/// deliberately expose neither the retained [`Rc`] nor the Store itself.
pub(crate) struct ProductionDomRefundStoreFaceV1 {
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    trusted_chain_id: TrustedChainIdV1,
    position: LegIdV1,
    owner_id: [u8; 32],
    authority_epoch: u64,
    composition_digest: [u8; 32],
    frozen_bindings: FrozenBindingsV1,
}

impl core::fmt::Debug for ProductionDomRefundStoreFaceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionDomRefundStoreFaceV1([authority redacted])")
    }
}

impl ProductionDomRefundStoreFaceV1 {
    pub(crate) const fn binding(&self) -> DomSessionBindingV1 {
        self.binding
    }

    pub(crate) fn bind(&self) -> DomActuatorResult<DomContractsActuatorV1<'_>> {
        DomContractsActuatorV1::bind(self.store.as_ref(), self.binding)
    }

    pub(crate) fn prepare_final_refund(
        &self,
    ) -> Result<PreparedOperationalFinalRefundTransportAuthorityV1, SessionStoreError> {
        self.store
            .prepare_operational_final_refund_transport_authority(
                self.trusted_chain_id,
                self.binding.session_id(),
            )
    }

    pub(crate) fn authenticates_scope(
        &self,
        position: LegIdV1,
        owner_id: [u8; 32],
        authority_epoch: u64,
        composition_digest: [u8; 32],
        frozen_bindings: &FrozenBindingsV1,
    ) -> bool {
        self.position == position
            && self.owner_id == owner_id
            && self.authority_epoch == authority_epoch
            && self.composition_digest == composition_digest
            && &self.frozen_bindings == frozen_bindings
    }
}

/// Owned, purpose-specific handoff of the sole Contracts opening to the DOM
/// settlement child port.
///
/// The handoff exposes neither the Store nor a reopen path.  It owns one `Rc`
/// clone of the exact single-threaded production opening and can only mint a
/// short-lived actuator borrow for its frozen session binding.  This avoids a
/// self-referential port while retaining the process lock and physical opening.
pub(crate) struct ProductionDomChildStoreAuthorityV1 {
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    final_claim_transport: Box<dyn ProductionDomFinalClaimTransportV1>,
}

impl core::fmt::Debug for ProductionDomChildStoreAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionDomChildStoreAuthorityV1([authority redacted])")
    }
}

impl ProductionDomChildStoreAuthorityV1 {
    pub(crate) fn bind(&self) -> DomActuatorResult<DomContractsActuatorV1<'_>> {
        DomContractsActuatorV1::bind(self.store.as_ref(), self.binding)
    }

    /// Derive the only claim verifier accepted by the DOM child port from
    /// this exact Contracts opening and its already-consumed claim authority.
    ///
    /// No caller-provided verifier crosses the production composition seam:
    /// the retained round, roles, terms and trusted chain are all recovered
    /// and revalidated by the actuator bound to this frozen session.
    pub(crate) fn build_claim_verifier(
        &self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> DomActuatorResult<RealDomClaimVerifierV1> {
        let actuator = self.bind()?;
        let authorization = actuator.resume_consumed_final_claim_authority_v2(trusted_chain_id)?;
        actuator.build_retained_claim_verifier_v2(trusted_chain_id, &authorization)
    }

    /// Consume an admitted claim bundle at the real Contracts/Relay `0x12`
    /// boundary. Economic externalization is not reported to the coordinator
    /// until this returns after durable Relay staging.
    pub(crate) fn stage_final_claim_admission_bundle(
        &mut self,
        bundle: DomFinalClaimAdmissionBundleV2,
    ) -> Result<(), ProductionContractsOutboundErrorV1> {
        self.final_claim_transport.stage(bundle)
    }

    /// Resume only an already-committed or already-reconciled `0x12` handoff.
    /// A merely prepared request remains `NotStarted` here so the normal
    /// admission bundle path still consumes the linear transport authority.
    pub(crate) fn recover_final_claim_transport(
        &mut self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> Result<ProductionDomFinalClaimTransportRecoveryV1, ProductionContractsOutboundErrorV1>
    {
        self.final_claim_transport.recover(trusted_chain_id)
    }
}

trait ProductionDomFinalClaimTransportV1 {
    fn stage(
        &mut self,
        bundle: DomFinalClaimAdmissionBundleV2,
    ) -> Result<(), ProductionContractsOutboundErrorV1>;

    fn recover(
        &mut self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> Result<ProductionDomFinalClaimTransportRecoveryV1, ProductionContractsOutboundErrorV1>;
}

struct SharedProductionDomFinalClaimTransportV1<F>
where
    F: F6TransportPortV1,
{
    session_id: [u8; 32],
    local_participant: [u8; 32],
    store: Rc<ContractsSessionStoreV1>,
    identity: Rc<ContractsTransportIdentityStoreV1>,
    relay: Rc<RefCell<DurableRelayWorkerV1<F>>>,
    expiry: TimelockSpec,
}

impl<F> ProductionDomFinalClaimTransportV1 for SharedProductionDomFinalClaimTransportV1<F>
where
    F: F6TransportPortV1,
{
    fn stage(
        &mut self,
        bundle: DomFinalClaimAdmissionBundleV2,
    ) -> Result<(), ProductionContractsOutboundErrorV1> {
        prepare_and_stage_final_claim_bundle_with_shared_relay(
            self.session_id,
            self.local_participant,
            self.store.as_ref(),
            self.identity.as_ref(),
            &self.relay,
            bundle,
            self.expiry,
        )
    }

    fn recover(
        &mut self,
        trusted_chain_id: &TrustedChainIdV1,
    ) -> Result<ProductionDomFinalClaimTransportRecoveryV1, ProductionContractsOutboundErrorV1>
    {
        match self.store.resume_outbound_dsc1(self.session_id)? {
            OutboundDsc1RecoveryV1::SigningRequest(_) => {
                Ok(ProductionDomFinalClaimTransportRecoveryV1::NotStarted)
            }
            OutboundDsc1RecoveryV1::Committed(outbound) => {
                self.store
                    .revalidate_committed_operational_final_claim_transport_v2(
                        *trusted_chain_id,
                        &outbound,
                    )?;
                self.relay
                    .try_borrow_mut()
                    .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                    .stage_store_outbound_dsc1(*outbound, self.expiry)?;
                Ok(ProductionDomFinalClaimTransportRecoveryV1::Staged)
            }
            OutboundDsc1RecoveryV1::None => {
                match self
                    .store
                    .resume_reconciled_operational_final_claim_transport_v2(
                        *trusted_chain_id,
                        self.session_id,
                    ) {
                    Ok(proof)
                        if proof.session_id() == &self.session_id
                            && proof.dom_claim_sender_id() == &self.local_participant
                            && proof.final_claim_receiver_id() != &self.local_participant
                            && proof.application_id() != &[0; 32]
                            && proof.message_digest() != &[0; 32] =>
                    {
                        Ok(ProductionDomFinalClaimTransportRecoveryV1::Staged)
                    }
                    Ok(_) => Err(ProductionContractsOutboundErrorV1::Store(
                        SessionStoreError::InvalidTransition,
                    )),
                    Err(SessionStoreError::SessionNotFound) => {
                        Ok(ProductionDomFinalClaimTransportRecoveryV1::NotStarted)
                    }
                    Err(error) => Err(ProductionContractsOutboundErrorV1::Store(error)),
                }
            }
        }
    }
}

fn prepare_and_stage_final_claim_bundle_with_shared_relay<F>(
    session_id: [u8; 32],
    local_participant: [u8; 32],
    store: &ContractsSessionStoreV1,
    identity: &ContractsTransportIdentityStoreV1,
    relay: &Rc<RefCell<DurableRelayWorkerV1<F>>>,
    bundle: DomFinalClaimAdmissionBundleV2,
    expiry: TimelockSpec,
) -> Result<(), ProductionContractsOutboundErrorV1>
where
    F: F6TransportPortV1,
{
    if !valid_timelock(expiry) {
        return Err(ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::InvalidTransition,
        ));
    }
    let authority = bundle.into_transport_authority();
    if authority.session_id() != &session_id
        || authority.dom_claim_sender_id() != &local_participant
    {
        return Err(ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::InvalidTransition,
        ));
    }
    let request = store
        .prepare_final_claim_dsc1_signing_request_v2(&authority)?
        .ok_or(ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::InvalidTransition,
        ))?;
    sign_commit_and_stage_with_shared_relay(
        session_id,
        local_participant,
        store,
        identity,
        relay,
        request,
        expiry,
    )?;
    Ok(())
}

fn sign_commit_and_stage_with_shared_relay<F>(
    session_id: [u8; 32],
    local_participant: [u8; 32],
    store: &ContractsSessionStoreV1,
    identity: &ContractsTransportIdentityStoreV1,
    relay: &Rc<RefCell<DurableRelayWorkerV1<F>>>,
    request: PreparedDsc1SigningRequestV1,
    expiry: TimelockSpec,
) -> Result<RouteApplicationDispositionV2, ProductionContractsOutboundErrorV1>
where
    F: F6TransportPortV1,
{
    if request.session_id() != &session_id || request.sender_id() != &local_participant {
        return Err(ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::InvalidTransition,
        ));
    }
    let outbound = identity.sign_and_commit_store_prepared_dsc1(store, request)?;
    relay
        .try_borrow_mut()
        .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
        .stage_store_outbound_dsc1(outbound, expiry)
        .map_err(ProductionContractsOutboundErrorV1::from)
}

struct EvmRemoteContractsSharedV1<'owner, F>
where
    F: F6TransportPortV1,
{
    session_id: [u8; 32],
    route_id: [u8; 32],
    local_participant: [u8; 32],
    remote_participant: [u8; 32],
    store: &'owner ContractsSessionStoreV1,
    identity: &'owner ContractsTransportIdentityStoreV1,
    relay: &'owner Rc<RefCell<DurableRelayWorkerV1<F>>>,
}

fn prepare_and_stage_evm_remote_action_request_shared<F>(
    shared: EvmRemoteContractsSharedV1<'_, F>,
    request: &ProductionEvmRemoteRequestV1,
    expiry: TimelockSpec,
) -> Result<[u8; 32], ProductionContractsOutboundErrorV1>
where
    F: F6TransportPortV1,
{
    let EvmRemoteContractsSharedV1 {
        session_id,
        route_id,
        local_participant,
        remote_participant,
        store,
        identity,
        relay,
    } = shared;
    let payload = request.payload();
    if request.session_id() != session_id
        || payload.route_id() != &route_id
        || payload.requester_id() != &local_participant
        || payload.signer_id() != &remote_participant
    {
        return Err(ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::InvalidTransition,
        ));
    }
    let payload_bytes = request.payload_bytes();
    match store.resume_evm_action_request_exact(session_id, local_participant, payload_bytes) {
        Ok(accepted) => {
            let message_digest = *accepted.message_digest();
            match store.resume_outbound_dsc1(session_id)? {
                OutboundDsc1RecoveryV1::SigningRequest(prepared)
                    if prepared.message_type() == 0x15
                        && prepared.unsigned_message_digest() == &message_digest
                        && prepared.payload() == payload_bytes =>
                {
                    sign_commit_and_stage_with_shared_relay(
                        session_id,
                        local_participant,
                        store,
                        identity,
                        relay,
                        *prepared,
                        expiry,
                    )?;
                }
                OutboundDsc1RecoveryV1::Committed(committed)
                    if committed.message_digest() == &message_digest =>
                {
                    relay
                        .try_borrow_mut()
                        .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                        .stage_store_outbound_dsc1(*committed, expiry)?;
                }
                // A later outbound head can exist only after this exact
                // request completed its Relay handoff. `None` has the same
                // meaning. The authenticated message row above is the durable
                // proof; no request is recreated.
                OutboundDsc1RecoveryV1::SigningRequest(_)
                | OutboundDsc1RecoveryV1::Committed(_)
                | OutboundDsc1RecoveryV1::None => {}
            }
            return Ok(message_digest);
        }
        Err(SessionStoreError::SessionNotFound) => {}
        Err(error) => return Err(ProductionContractsOutboundErrorV1::Store(error)),
    }
    let prepared = store
        .prepare_evm_action_request_dsc1_signing_request(session_id, payload_bytes)?
        .ok_or(ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::InvalidTransition,
        ))?;
    let message_digest = *prepared.unsigned_message_digest();
    sign_commit_and_stage_with_shared_relay(
        session_id,
        local_participant,
        store,
        identity,
        relay,
        prepared,
        expiry,
    )?;
    Ok(message_digest)
}

fn take_evm_remote_signed_response_shared(
    session_id: [u8; 32],
    route_id: [u8; 32],
    local_participant: [u8; 32],
    remote_participant: [u8; 32],
    store: &ContractsSessionStoreV1,
    request: &ProductionEvmRemoteRequestV1,
    request_message_digest: [u8; 32],
) -> Result<ProductionEvmRemoteResponseV1, ProductionContractsOutboundErrorV1> {
    let payload = request.payload();
    if request.session_id() != session_id
        || payload.route_id() != &route_id
        || payload.requester_id() != &local_participant
        || payload.signer_id() != &remote_participant
        || request_message_digest == [0; 32]
    {
        return Err(ProductionContractsOutboundErrorV1::Store(
            SessionStoreError::InvalidTransition,
        ));
    }
    let accepted = match store.resume_evm_signed_action_for_request(
        session_id,
        remote_participant,
        request_message_digest,
    ) {
        Ok(accepted) => accepted,
        Err(SessionStoreError::SessionNotFound) => {
            return Ok(ProductionEvmRemoteResponseV1::Pending)
        }
        Err(error) => return Err(ProductionContractsOutboundErrorV1::Store(error)),
    };
    let prepared = store.take_evm_signed_action_for_import(accepted)?;
    Ok(ProductionEvmRemoteResponseV1::Prepared(Box::new(prepared)))
}

/// One physical Contracts Store opening shared only with typed authorities.
/// Owner-only composition of the production Contracts authorities for one
/// route and one participant.
///
/// The production `run` command and authenticated bootstrap now exist. This
/// owner is composed only after the ordered Relay and Contracts provisioning
/// stages retain their exact stores and identities; it must never be replaced
/// by an independently reopened session store.
pub(crate) struct ProductionContractsV1<F>
where
    F: F6TransportPortV1,
{
    session_id: [u8; 32],
    route_id: [u8; 32],
    local_participant: [u8; 32],
    remote_participant: [u8; 32],
    local_protocol_index: u8,
    store: Rc<ContractsSessionStoreV1>,
    identity: Rc<ContractsTransportIdentityStoreV1>,
    relay: Rc<RefCell<DurableRelayWorkerV1<F>>>,
    dom_child_store_authority_issued: Cell<bool>,
    dom_refund_face_issued: Cell<bool>,
    evm_remote_transport_authority_issued: Cell<bool>,
}

impl<F> ProductionContractsV1<F>
where
    F: F6TransportPortV1,
{
    pub(crate) fn create<I>(
        store: ContractsSessionStoreV1,
        identity: I,
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        rosters: RosterRegistryV1,
        f6: F,
        relay_signing_secret: [u8; 32],
    ) -> Result<Self, ProductionContractsOpenErrorV1>
    where
        I: Into<Rc<ContractsTransportIdentityStoreV1>>,
    {
        if !config.is_production_v6_bound() {
            return Err(ProductionContractsOpenErrorV1::Relay(
                RelayWorkerOpenErrorV1::InvalidConfiguration,
            ));
        }
        let identity = identity.into();
        let wire = config.wire_context();
        let session_id = wire.session_id;
        let route_id = wire.route_id;
        let local_participant = config.local_participant().0;
        let remote_participant = config.remote_participant().0;
        let relay_keys = validate_relay_roster(&rosters, &config)?;
        let local_protocol_index =
            validate_and_bind_identity(&store, &identity, &config, &relay_keys)?;
        let store = Rc::new(store);
        let relay = DurableRelayWorkerV1::create(
            paths,
            config,
            Rc::clone(&store),
            rosters,
            f6,
            relay_signing_secret,
        )?;
        Ok(Self {
            session_id,
            route_id,
            local_participant,
            remote_participant,
            local_protocol_index,
            store,
            identity,
            relay: Rc::new(RefCell::new(relay)),
            dom_child_store_authority_issued: Cell::new(false),
            dom_refund_face_issued: Cell::new(false),
            evm_remote_transport_authority_issued: Cell::new(false),
        })
    }

    pub(crate) fn open_existing<I>(
        store: ContractsSessionStoreV1,
        identity: I,
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        rosters: RosterRegistryV1,
        f6: F,
        relay_signing_secret: [u8; 32],
    ) -> Result<Self, ProductionContractsOpenErrorV1>
    where
        I: Into<Rc<ContractsTransportIdentityStoreV1>>,
    {
        if !config.is_production_v6_bound() {
            return Err(ProductionContractsOpenErrorV1::Relay(
                RelayWorkerOpenErrorV1::InvalidConfiguration,
            ));
        }
        let identity = identity.into();
        let wire = config.wire_context();
        let session_id = wire.session_id;
        let route_id = wire.route_id;
        let local_participant = config.local_participant().0;
        let remote_participant = config.remote_participant().0;
        let relay_keys = validate_relay_roster(&rosters, &config)?;
        let local_protocol_index =
            validate_and_bind_identity(&store, &identity, &config, &relay_keys)?;
        let store = Rc::new(store);
        let relay = DurableRelayWorkerV1::open_existing(
            paths,
            config,
            Rc::clone(&store),
            rosters,
            f6,
            relay_signing_secret,
        )?;
        Ok(Self {
            session_id,
            route_id,
            local_participant,
            remote_participant,
            local_protocol_index,
            store,
            identity,
            relay: Rc::new(RefCell::new(relay)),
            dom_child_store_authority_issued: Cell::new(false),
            dom_refund_face_issued: Cell::new(false),
            evm_remote_transport_authority_issued: Cell::new(false),
        })
    }

    pub(crate) fn resume_create_production<I>(
        store: ContractsSessionStoreV1,
        identity: I,
        paths: &RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        rosters: RosterRegistryV1,
        f6: F,
        relay_signing_secret: [u8; 32],
    ) -> Result<Self, ProductionContractsOpenErrorV1>
    where
        I: Into<Rc<ContractsTransportIdentityStoreV1>>,
    {
        if !config.is_production_v6_bound() {
            return Err(ProductionContractsOpenErrorV1::Relay(
                RelayWorkerOpenErrorV1::InvalidConfiguration,
            ));
        }
        let identity = identity.into();
        let wire = config.wire_context();
        let session_id = wire.session_id;
        let route_id = wire.route_id;
        let local_participant = config.local_participant().0;
        let remote_participant = config.remote_participant().0;
        let relay_keys = validate_relay_roster(&rosters, &config)?;
        let local_protocol_index =
            validate_and_bind_identity(&store, &identity, &config, &relay_keys)?;
        let store = Rc::new(store);
        let relay = DurableRelayWorkerV1::resume_create_production(
            paths,
            config,
            Rc::clone(&store),
            rosters,
            f6,
            relay_signing_secret,
        )?;
        Ok(Self {
            session_id,
            route_id,
            local_participant,
            remote_participant,
            local_protocol_index,
            store,
            identity,
            relay: Rc::new(RefCell::new(relay)),
            dom_child_store_authority_issued: Cell::new(false),
            dom_refund_face_issued: Cell::new(false),
            evm_remote_transport_authority_issued: Cell::new(false),
        })
    }

    /// Consumes the Contracts share of one real F7 V2 aggregate into this
    /// owner's exact Store, or reauthenticates the same durable issuance after
    /// a publication-boundary crash, and retains that opening beside it.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn issue_post_anchor_v2(
        &self,
        verified_anchors: VerifiedF7AnchorAuthorizationV2,
    ) -> Result<ProductionContractsPostAnchorV2, ProductionContractsPostAnchorErrorV2> {
        if verified_anchors.session_id() != &self.session_id
            || verified_anchors.route_id() != &self.route_id
        {
            return Err(ProductionContractsPostAnchorErrorV2::StoreRefused);
        }
        let authorization = self
            .store
            .issue_or_resume_post_anchor_dom_claim_signing_v2(verified_anchors)
            .map_err(|_| ProductionContractsPostAnchorErrorV2::StoreRefused)?;
        if authorization.session_id() != &self.session_id {
            return Err(ProductionContractsPostAnchorErrorV2::StoreRefused);
        }
        Ok(ProductionContractsPostAnchorV2 {
            store: Rc::clone(&self.store),
            authorization,
        })
    }

    /// Re-enables the exact post-anchor chain projection only from a fresh
    /// real-verifier capability, never from caller-shaped anchor fields.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn revalidate_post_anchor_projection_v2(
        &self,
        expected_revision: u64,
        verified_anchors: VerifiedF7AnchorAuthorizationV2,
    ) -> Result<(), ProductionContractsPostAnchorErrorV2> {
        self.store
            .revalidate_post_anchor_dom_claim_chain_projection_v2(
                expected_revision,
                verified_anchors,
            )
            .map(|_| ())
            .map_err(|_| ProductionContractsPostAnchorErrorV2::StoreRefused)
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn bind_dom_actuator(
        &self,
        binding: DomSessionBindingV1,
    ) -> DomActuatorResult<DomContractsActuatorV1<'_>> {
        self.validate_dom_binding(binding)?;
        DomContractsActuatorV1::bind(self.store.as_ref(), binding)
    }

    /// Transfer a purpose-specific owned reference to the DOM child port.
    ///
    /// The returned authority retains this exact physical Store opening; a
    /// second `open_production` remains refused by the Store process lock.
    pub(crate) fn dom_child_store_authority(
        &self,
        binding: DomSessionBindingV1,
        final_claim_expiry: TimelockSpec,
    ) -> DomActuatorResult<ProductionDomChildStoreAuthorityV1>
    where
        F: 'static,
    {
        if !valid_timelock(final_claim_expiry) {
            return Err(DomActuatorError::InvalidBinding);
        }
        if self.dom_child_store_authority_issued.replace(true) {
            return Err(DomActuatorError::InvalidStage);
        }
        if let Err(error) = self.validate_dom_binding(binding) {
            self.dom_child_store_authority_issued.set(false);
            return Err(error);
        }
        let authority = ProductionDomChildStoreAuthorityV1 {
            store: Rc::clone(&self.store),
            binding,
            final_claim_transport: Box::new(SharedProductionDomFinalClaimTransportV1 {
                session_id: self.session_id,
                local_participant: self.local_participant,
                store: Rc::clone(&self.store),
                identity: Rc::clone(&self.identity),
                relay: Rc::clone(&self.relay),
                expiry: final_claim_expiry,
            }),
        };
        if let Err(error) = authority.bind() {
            self.dom_child_store_authority_issued.set(false);
            return Err(error);
        }
        Ok(authority)
    }

    /// Issues the sole DOM refund verifier backed by this owner's exact Store
    /// opening. All route facts come from the authenticated admission and V2
    /// composition; the caller cannot supply a detached session or chain.
    pub(crate) fn dom_refund_face(
        &self,
        scope: ProductionDomRefundFaceScopeV1<'_>,
        binding: DomSessionBindingV1,
    ) -> Result<ProductionDomRefundFaceV1, ProductionRefundArmingOpenErrorV1> {
        self.issue_dom_refund_face_once(|| self.authenticate_dom_refund_scope(scope, binding))
    }

    fn issue_dom_refund_face_once(
        &self,
        authenticate: impl FnOnce() -> Result<
            ProductionDomRefundStoreFaceV1,
            ProductionRefundArmingOpenErrorV1,
        >,
    ) -> Result<ProductionDomRefundFaceV1, ProductionRefundArmingOpenErrorV1> {
        if self.dom_refund_face_issued.replace(true) {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
        }
        let authority = match authenticate() {
            Ok(authority) => authority,
            Err(error) => {
                self.dom_refund_face_issued.set(false);
                return Err(error);
            }
        };
        Ok(ProductionDomRefundFaceV1::from_contracts_owner(authority))
    }

    fn authenticate_dom_refund_scope(
        &self,
        scope: ProductionDomRefundFaceScopeV1<'_>,
        binding: DomSessionBindingV1,
    ) -> Result<ProductionDomRefundStoreFaceV1, ProductionRefundArmingOpenErrorV1> {
        let admission = scope.admission();
        let composition = scope.composition();
        let position = scope.position();
        let owner_id = scope.owner_id();
        let authority_epoch = scope.authority_epoch();
        let settlement = match position {
            LegIdV1::Upstream => composition.upstream(),
            LegIdV1::Downstream => composition.downstream(),
        };
        let terms_digest = settlement
            .terms_hash()
            .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
        let time = admission
            .route_time_binding_v2()
            .ok_or(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
        let deployment = admission
            .dom_deployment_capability()
            .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
        let dom = deployment.deployment();
        let trusted_chain_id = TrustedChainIdV1::from_authenticated_genesis(
            binding.runtime_identity().network_magic,
            &Hash256::from_bytes(binding.genesis_hash()),
        );
        if owner_id == [0; 32]
            || authority_epoch == 0
            || admission.route_id() != self.route_id
            || binding.route_id() != admission.route_id()
            || binding.session_id() != self.session_id
            || binding.session_id() != settlement.session_id.0
            || binding.terms_digest() != terms_digest
            || binding.chain_id() != settlement.dom_leg.chain_id.0
            || binding.profile_digest() != settlement.dom_leg.adapter_profile_hash
            || binding.chain_id() != dom.chain_id.0
            || binding.genesis_hash() != dom.genesis_hash
            || binding.runtime_identity() != dom.runtime_identity
            || binding.profile_digest() != dom.consensus_rules_digest
            || binding.deployment_digest() != deployment.registry_digest()
            || binding.asset_binding_digest() != deployment.native_asset_binding_digest()
            || binding.registry_epoch() != deployment.registry_epoch()
            || binding.min_confirmations() != dom.finality.min_confirmations
            || binding.max_reorg_depth() != dom.finality.max_reorg_depth
            || trusted_chain_id.as_bytes() != &binding.chain_id()
            || time.route_scope_digest() != composition.route_scope_digest()
            || time.policy_digest() != composition.time_policy_digest()
            || time.evidence_digest() != composition.time_evidence_digest()
            || time.proof_digest() != composition.time_proof_digest()
            || time.evidence_sequence() != composition.evidence_sequence()
            || time.issued_at_seconds() != composition.time_proof_issued_at_seconds()
            || time.valid_until_seconds() != composition.time_proof_valid_until_seconds()
            || time.validated_at_seconds() != composition.time_proof_validated_at_seconds()
            || self.validate_dom_binding(binding).is_err()
            || DomContractsActuatorV1::bind(self.store.as_ref(), binding).is_err()
        {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
        }
        Ok(ProductionDomRefundStoreFaceV1 {
            store: Rc::clone(&self.store),
            binding,
            trusted_chain_id,
            position,
            owner_id,
            authority_epoch,
            composition_digest: composition.binding_digest(),
            frozen_bindings: admission.frozen_bindings().clone(),
        })
    }

    /// Issues the sole purpose-limited remote EVM transport view while
    /// retaining this exact physical Contracts Store and Relay opening.
    pub(crate) fn evm_remote_transport_authority(
        &self,
        binding: &ProductionEvmRemoteSignerBindingV1,
        expiry: TimelockSpec,
    ) -> Result<Box<dyn ProductionEvmRemoteTransportV1>, ChildAuthorityRefusalV1>
    where
        F: 'static,
    {
        if !valid_timelock(expiry)
            || !binding.binds_contracts_owner(
                self.route_id,
                self.session_id,
                self.local_participant,
                self.remote_participant,
            )
            || self.evm_remote_transport_authority_issued.replace(true)
        {
            return Err(ChildAuthorityRefusalV1::Conflict);
        }
        Ok(Box::new(ProductionEvmRemoteContractsAuthorityV1 {
            session_id: self.session_id,
            route_id: self.route_id,
            local_participant: self.local_participant,
            remote_participant: self.remote_participant,
            store: Rc::clone(&self.store),
            identity: Rc::clone(&self.identity),
            relay: Rc::clone(&self.relay),
            expiry,
        }))
    }

    /// Build the startup-safe DOM public-secret source/installer pair from this
    /// owner's one already-open Contracts Store. The source cannot re-extract
    /// until the installer sees the real downstream DOM child plan; neither
    /// half accepts a caller-shaped transaction identity.
    pub(crate) fn dom_public_secret_source(
        &self,
        scope: ProductionDomPublicSecretSourceScopeV1,
        authority: ProductionDomPublicSecretConsumerAuthorityV1,
    ) -> Result<
        (
            ProductionDomPublicSecretSourceV1,
            ProductionDomPublicSecretInstallerV1,
        ),
        AuthorityRefusalV1,
    > {
        let opening =
            self.prepare_dom_public_secret_opening(scope.binding(), scope.trusted_chain_id())?;
        ProductionDomPublicSecretSourceV1::new_installable(opening.store, scope, authority)
    }

    fn prepare_dom_public_secret_opening(
        &self,
        binding: DomSessionBindingV1,
        trusted_chain_id: TrustedChainIdV1,
    ) -> Result<ProductionDomPublicSecretOpeningV1, AuthorityRefusalV1> {
        self.validate_dom_binding(binding)
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        if trusted_chain_id.as_bytes() != &binding.chain_id() {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(ProductionDomPublicSecretOpeningV1 {
            store: Rc::clone(&self.store),
            binding,
            trusted_chain_id,
        })
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn participant_signer(
        &self,
        binding: DomSessionBindingV1,
        nonce_vault: ContractsNonceVaultV1,
        trusted_chain_id: TrustedChainIdV1,
        local_share: DomParticipantSigningShareV1,
    ) -> DomActuatorResult<ContractsDomSignerV1<'_>> {
        self.validate_dom_binding(binding)?;
        if trusted_chain_id.as_bytes() != &binding.chain_id() {
            return Err(DomActuatorError::InvalidBinding);
        }
        participant_contracts_signer_v1(
            nonce_vault,
            self.store.as_ref(),
            binding,
            trusted_chain_id,
            local_share,
        )
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn sign_commit_and_stage(
        &mut self,
        request: PreparedDsc1SigningRequestV1,
        expiry: TimelockSpec,
    ) -> Result<RouteApplicationDispositionV2, ProductionContractsOutboundErrorV1> {
        sign_commit_and_stage_with_shared_relay(
            self.session_id,
            self.local_participant,
            self.store.as_ref(),
            self.identity.as_ref(),
            &self.relay,
            request,
            expiry,
        )
    }

    /// Persists, signs and Relay-stages the exact public `0x15` request issued
    /// by the authenticated remote EVM role boundary.
    ///
    /// Only the fixed public request crosses Contracts. The counterparty key,
    /// unsigned transaction, calldata and route scalar are absent. The Store
    /// commits the DSC1 request before Relay submission and returns its exact
    /// digest for later `0x16` pairing.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn prepare_and_stage_evm_remote_action_request(
        &mut self,
        request: &ProductionEvmRemoteRequestV1,
        expiry: TimelockSpec,
    ) -> Result<[u8; 32], ProductionContractsOutboundErrorV1> {
        prepare_and_stage_evm_remote_action_request_shared(
            EvmRemoteContractsSharedV1 {
                session_id: self.session_id,
                route_id: self.route_id,
                local_participant: self.local_participant,
                remote_participant: self.remote_participant,
                store: self.store.as_ref(),
                identity: self.identity.as_ref(),
                relay: &self.relay,
            },
            request,
            expiry,
        )
    }

    /// Recovers the unique authenticated `0x16` by its exact `0x15` digest
    /// and consumes it into the Store's move-only actuator import grant.
    ///
    /// `SessionNotFound` is the sole pending classification. Corruption,
    /// equivocation, participant transplant and duplicate in-process take all
    /// remain typed refusals.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn take_evm_remote_signed_response(
        &self,
        request: &ProductionEvmRemoteRequestV1,
        request_message_digest: [u8; 32],
    ) -> Result<ProductionEvmRemoteResponseV1, ProductionContractsOutboundErrorV1> {
        take_evm_remote_signed_response_shared(
            self.session_id,
            self.route_id,
            self.local_participant,
            self.remote_participant,
            self.store.as_ref(),
            request,
            request_message_digest,
        )
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn prepare_and_stage_m8_ready_to_fund_v2(
        &mut self,
        gate: &PreparedOperationalM8FundingGateV2,
        expiry: TimelockSpec,
    ) -> Result<Option<RouteApplicationDispositionV2>, ProductionContractsOutboundErrorV1> {
        let Some(vote) = self
            .store
            .prepare_next_operational_m8_ready_to_fund_vote_v2(gate)?
        else {
            return Ok(None);
        };
        let Some(request) = self
            .store
            .prepare_m8_ready_to_fund_dsc1_signing_request_v2(gate, vote)?
        else {
            return Ok(None);
        };
        self.sign_commit_and_stage(request, expiry).map(Some)
    }

    /// Emits, signs, commits and stages the exact V2 post-anchor Claim
    /// pre-signature edge (`0x0f`) when this leg holds the canonical sender.
    ///
    /// The Store owns the decision: it returns `None` when the bound local
    /// signer is not the canonical sender for this edge, so the owner never
    /// infers a sender and never shapes the payload.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn prepare_and_stage_post_anchor_claim_pre_signature_v2(
        &mut self,
        authority: &PreparedPostAnchorClaimPreSignatureTransportAuthorityV2,
        expiry: TimelockSpec,
    ) -> Result<Option<RouteApplicationDispositionV2>, ProductionContractsOutboundErrorV1> {
        let Some(request) = self
            .store
            .prepare_post_anchor_claim_pre_signature_dsc1_signing_request_v2(authority)?
        else {
            return Ok(None);
        };
        self.sign_commit_and_stage(request, expiry).map(Some)
    }

    /// Emits, signs, commits and stages the exact FinalClaim (`0x12`) once a
    /// node has economically admitted it.
    ///
    /// The owner consumes the actuator's dual-admission bundle and never
    /// accepts a naked transport authority. That bundle exists only where both
    /// the Contracts admission and owner-only mirror are durable. A receiver
    /// cannot obtain it and therefore cannot enter this emitter boundary.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn prepare_and_stage_final_claim_v2(
        &mut self,
        bundle: DomFinalClaimAdmissionBundleV2,
        expiry: TimelockSpec,
    ) -> Result<(), ProductionContractsOutboundErrorV1> {
        prepare_and_stage_final_claim_bundle_with_shared_relay(
            self.session_id,
            self.local_participant,
            self.store.as_ref(),
            self.identity.as_ref(),
            &self.relay,
            bundle,
            expiry,
        )
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn resume_and_stage(
        &mut self,
        expiry: TimelockSpec,
    ) -> Result<ProductionContractsResumeV1, ProductionContractsOutboundErrorV1> {
        match self.store.resume_outbound_dsc1(self.session_id)? {
            OutboundDsc1RecoveryV1::SigningRequest(request) => self
                .sign_commit_and_stage(*request, expiry)
                .map(ProductionContractsResumeV1::Staged),
            OutboundDsc1RecoveryV1::Committed(outbound) => {
                if outbound.session_id() != &self.session_id
                    || outbound.sender_id() != &self.local_participant
                {
                    return Err(ProductionContractsOutboundErrorV1::Store(
                        SessionStoreError::InvalidTransition,
                    ));
                }
                self.relay
                    .try_borrow_mut()
                    .map_err(|_| ProductionContractsOutboundErrorV1::OwnerBusy)?
                    .stage_store_outbound_dsc1(*outbound, expiry)
                    .map(ProductionContractsResumeV1::Staged)
                    .map_err(ProductionContractsOutboundErrorV1::from)
            }
            OutboundDsc1RecoveryV1::None => Ok(ProductionContractsResumeV1::Idle),
        }
    }

    /// Observe the receiver-side DOM FinalClaim through the real canonical
    /// scanner, persist its irreversible exposure marker, mint the exact
    /// Store-owned `0x12` ingress capability and install it into this owner's
    /// Relay worker.
    ///
    /// The evidence reference is only a lookup request. It is never authority:
    /// `RealDomClaimConsumerV1::observe` refetches and proves the canonical
    /// transaction and adaptor opening, while the actuator binds the resulting
    /// linear observation to this exact session revision before the Store can
    /// mint the ingress capability. No Relay borrow is held during RPC.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn observe_and_install_final_claim_ingress_v2(
        &mut self,
        binding: DomSessionBindingV1,
        trusted_chain_id: TrustedChainIdV1,
        consumer: &RealDomClaimConsumerV1,
        evidence: &EvidenceRefV1,
    ) -> Result<(), ProductionContractsInboundErrorV1> {
        self.validate_dom_binding(binding)?;
        if trusted_chain_id.as_bytes() != &binding.chain_id()
            || evidence.chain_id.0 != binding.chain_id()
        {
            return Err(ProductionContractsInboundErrorV1::Actuator(
                DomActuatorError::InvalidBinding,
            ));
        }
        let expected_revision = self.store.load_session(self.session_id)?.revision();
        let observation = consumer.observe(evidence)?;
        {
            let actuator = DomContractsActuatorV1::bind(self.store.as_ref(), binding)?;
            let _observed = actuator
                .persist_observed_final_claim_exposure_v2(expected_revision, observation)?;
        }
        self.resume_and_install_final_claim_ingress_v2(binding, trusted_chain_id)
    }

    /// Reissue and install the receiver-side `0x12` capability after a crash
    /// that occurred after the observation marker became durable. The Store
    /// reauthenticates roles, transcript, chain and exact observed claim; the
    /// worker receives no caller-shaped payload or identity.
    pub(crate) fn resume_and_install_final_claim_ingress_v2(
        &mut self,
        binding: DomSessionBindingV1,
        trusted_chain_id: TrustedChainIdV1,
    ) -> Result<(), ProductionContractsInboundErrorV1> {
        self.validate_dom_binding(binding)?;
        if trusted_chain_id.as_bytes() != &binding.chain_id() {
            return Err(ProductionContractsInboundErrorV1::Actuator(
                DomActuatorError::InvalidBinding,
            ));
        }
        let authority = self
            .store
            .prepare_operational_final_claim_ingress_authority_v2(
                trusted_chain_id,
                self.session_id,
            )?;
        self.install_contracts_ingress(PreparedContractsIngressV1::final_claim_ingress_v2(
            authority,
        ))?;
        Ok(())
    }

    pub(crate) fn install_contracts_ingress(
        &mut self,
        authority: PreparedContractsIngressV1,
    ) -> Result<(), ContractsRelayIngressErrorV1> {
        self.relay
            .try_borrow_mut()
            .map_err(|_| ContractsRelayIngressErrorV1::OwnerBusy)?
            .install_contracts_ingress(authority)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn take_contracts_ingress(
        &mut self,
    ) -> Result<Option<PreparedContractsIngressV1>, ContractsRelayIngressErrorV1> {
        Ok(self
            .relay
            .try_borrow_mut()
            .map_err(|_| ContractsRelayIngressErrorV1::OwnerBusy)?
            .take_contracts_ingress())
    }

    pub(crate) fn submit_outbound_once<Q: RelaySubmitQueueV1>(
        &mut self,
        queue: &mut Q,
    ) -> Result<RelayOutboundStepV1, RelayWorkerOutboundErrorV1> {
        self.relay
            .try_borrow_mut()
            .map_err(|_| RelayWorkerOutboundErrorV1::OwnerBusy)?
            .submit_outbound_once(queue)
    }

    /// Pull and dispatch one bounded production Relay page through this
    /// owner's sole worker opening.
    ///
    /// The concrete queue keeps the V2 bounded/cursor/ACK contract on the
    /// production path. The worker itself never escapes this owner, so callers
    /// cannot split the shared transcript or install an independent inbox.
    pub(crate) fn poll_inbound(
        &mut self,
        queue: &mut relay::production::ProductionRelayV1,
        now: TimelockSpec,
    ) -> Result<RelayInboundPollReportV1, ProductionContractsPollErrorV1<F::Error>> {
        self.relay
            .try_borrow_mut()
            .map_err(|_| ProductionContractsPollErrorV1::OwnerBusy)?
            .poll_inbound(queue, now)
            .map_err(ProductionContractsPollErrorV1::Worker)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn contracts_session_status(
        &mut self,
    ) -> Result<ContractsSessionStatusV1, SessionStoreError> {
        self.relay
            .try_borrow_mut()
            .map_err(|_| SessionStoreError::StoreBusy)?
            .contracts_session_status()
    }

    /// Highest timestamp-domain Relay time already authenticated and committed
    /// by this exact worker opening.
    pub(crate) fn retained_relay_timestamp_floor(
        &self,
    ) -> Result<Option<u64>, route_transport::DurableInboxError> {
        self.relay
            .try_borrow()
            .map_err(|_| route_transport::DurableInboxError::StorageUnavailable)?
            .retained_timestamp_floor()
    }

    fn validate_dom_binding(&self, binding: DomSessionBindingV1) -> DomActuatorResult<()> {
        if binding.session_id() != self.session_id
            || binding.route_id() != self.route_id
            || binding.participant().participant_id() != self.local_participant
            || binding.participant().protocol_index() != self.local_protocol_index
        {
            return Err(DomActuatorError::InvalidBinding);
        }
        Ok(())
    }
}

impl ProductionContractsV1<ProductionF6LifecyclePortV2> {
    /// Reauthenticates retained applied F6 history through the exact Relay
    /// worker and lifecycle owned by this Contracts composition.
    ///
    /// Startup must complete this boundary before it marks the surrounding
    /// provisioning journal complete or exposes inbound polling. A failed
    /// replay mutates neither the inbox nor that caller-owned journal, and the
    /// lifecycle continues refusing pending F6 with `RecoveryRequired`.
    pub(crate) fn recover_production_f6_applied_history(
        &self,
    ) -> Result<F6AppliedReplayReportV1, ProductionContractsF6RecoveryErrorV2> {
        self.relay
            .try_borrow_mut()
            .map_err(|_| ProductionContractsF6RecoveryErrorV2::OwnerBusy)?
            .recover_production_f6_applied_history()
            .map_err(ProductionContractsF6RecoveryErrorV2::from)
    }
}

const fn valid_timelock(expiry: TimelockSpec) -> bool {
    match expiry {
        TimelockSpec::BlockHeight { value }
        | TimelockSpec::TimestampSeconds { value }
        | TimelockSpec::BtcTime512s { value } => value != 0,
    }
}

fn validate_and_bind_identity(
    store: &ContractsSessionStoreV1,
    identity: &ContractsTransportIdentityStoreV1,
    config: &RelayWorkerConfigV1,
    relay_keys: &[[u8; 32]; 2],
) -> Result<u8, ProductionContractsOpenErrorV1> {
    let session_id = config.wire_context().session_id;
    let local_participant = config.local_participant().0;
    let remote_participant = config.remote_participant().0;
    if local_participant == remote_participant {
        return Err(ProductionContractsOpenErrorV1::StoreRejected);
    }
    let identity_reference = identity.reference();
    let references = store.transport_identity_references(session_id)?;
    let roles_match_store = match config.relay_sender_role() {
        SenderRoleV1::Initiator => {
            references[0].participant_id() == &local_participant
                && references[1].participant_id() == &remote_participant
        }
        SenderRoleV1::Solver => {
            references[0].participant_id() == &remote_participant
                && references[1].participant_id() == &local_participant
        }
        SenderRoleV1::Observer => false,
    };
    if references
        .iter()
        .filter(|reference| reference.participant_id() == &local_participant)
        .count()
        != 1
        || references
            .iter()
            .filter(|reference| reference.participant_id() == &remote_participant)
            .count()
            != 1
        || references.iter().any(|reference| {
            reference.participant_id() != &local_participant
                && reference.participant_id() != &remote_participant
        })
        || !roles_match_store
    {
        return Err(ProductionContractsOpenErrorV1::StoreRejected);
    }
    let mut matching = None;
    for reference in &references {
        let exact = reference.key_reference() == identity_reference.key_reference()
            && reference.noise_public_key() == identity_reference.noise_public_key()
            && reference.schnorr_public_key().to_compressed_bytes()
                == *identity_reference.schnorr_public_key();
        if exact && matching.replace(reference).is_some() {
            return Err(ProductionContractsOpenErrorV1::StoreRejected);
        }
    }
    let matching = matching.ok_or(ProductionContractsOpenErrorV1::StoreRejected)?;
    if matching.participant_id() != &local_participant {
        return Err(ProductionContractsOpenErrorV1::StoreRejected);
    }
    if references.iter().any(|reference| {
        let schnorr = reference.schnorr_public_key().to_compressed_bytes();
        relay_keys
            .iter()
            .any(|relay_key| schnorr[1..] == relay_key[..])
    }) {
        return Err(ProductionContractsOpenErrorV1::IdentityKeyReuse);
    }
    store.bind_local_transport_signer(session_id, *identity_reference.key_reference())?;
    Ok(if local_participant < remote_participant {
        0
    } else {
        1
    })
}

fn validate_relay_roster(
    rosters: &RosterRegistryV1,
    config: &RelayWorkerConfigV1,
) -> Result<[[u8; 32]; 2], ProductionContractsOpenErrorV1> {
    let snapshot = rosters
        .snapshot(&config.wire_context().roster_snapshot)
        .ok_or(ProductionContractsOpenErrorV1::Relay(
            RelayWorkerOpenErrorV1::InvalidConfiguration,
        ))?;
    let local = snapshot.member(&config.local_participant()).ok_or(
        ProductionContractsOpenErrorV1::Relay(RelayWorkerOpenErrorV1::InvalidConfiguration),
    )?;
    let remote = snapshot.member(&config.remote_participant()).ok_or(
        ProductionContractsOpenErrorV1::Relay(RelayWorkerOpenErrorV1::InvalidConfiguration),
    )?;
    let roles_are_canonical = matches!(
        (local.role, remote.role),
        (SenderRoleV1::Initiator, SenderRoleV1::Solver)
            | (SenderRoleV1::Solver, SenderRoleV1::Initiator)
    );
    if local.role != config.relay_sender_role()
        || !roles_are_canonical
        || local.xonly_key != *config.relay_signer_xonly()
        || local.xonly_key == remote.xonly_key
    {
        return Err(ProductionContractsOpenErrorV1::Relay(
            RelayWorkerOpenErrorV1::InvalidConfiguration,
        ));
    }
    Ok([local.xonly_key, remote.xonly_key])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        error::Error,
        fs::{self, File},
        os::unix::fs::PermissionsExt,
        path::Path,
        sync::Arc,
    };

    use adapter_btc::timelock::ChainTimingBoundsV1;
    use btc_crypto::SecpContext;
    use cap_std::fs::Dir;
    use chain_profile::{ChainKindV1, ChainProfileV1};
    use deployment_registry::{
        AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, ChainDeploymentV1, DomDeploymentV1,
        DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, RegistryChainProfileV1,
        RegistryManifestV1, RegistrySignatureV1, RegistryValidationPolicyV1, SignedRegistryV1,
    };
    use dom_actuator::DomParticipantV1;
    use dom_core::configured_genesis_hash_for_network_magic;
    use dom_crypto::{PublicKey, SecretKey};
    use dom_scriptless_identity_store::ContractsIdentityPassphraseV1;
    use dom_scriptless_store::{
        BudgetPolicyProfileV1, BudgetPolicyV1, DirectionV1, PreparedDsc1SigningRequestV1,
        SessionChainProjectionV1, SessionIrreversibleV1, SessionPhaseV1, SessionRecordFieldsV1,
        SessionRecordV1, SessionTransportIdentityReferenceV1, SessionTransportParticipantV1,
        SessionTxObservationV1, BUDGET_POLICY_LEN,
    };
    use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
    use relay::auth::{RosterMemberV1, RosterSnapshotV1};
    use relay::production::{ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1};
    use relay::server::{AckV1, RelayV1};
    use relay::ParticipantId;
    use route_executor::LegIdV1;
    use route_transport::{
        BridgeRefusal, DurableFrameReassemblerConfigV2, DurableInboxConfigV1,
        DurableRelaySenderConfigV1, RelayQueueV1, RouteApplicationStateV2, RouteWireContextV1,
    };
    use static_assertions::assert_not_impl_any;

    use crate::production_evm_remote_signer::ProductionEvmRemoteSignerPinsV1;
    use crate::relay_worker::{RelayOutboundStepV1, UnavailableF6AuthorityV1};

    const SESSION: [u8; 32] = [0x31; 32];
    const OTHER_SESSION: [u8; 32] = [0x32; 32];
    const LOCAL: ParticipantId = ParticipantId([0x41; 32]);
    const REMOTE: ParticipantId = ParticipantId([0x51; 32]);
    const LOCAL_RELAY_SECRET: [u8; 32] = [0x61; 32];

    assert_not_impl_any!(ProductionContractsPostAnchorV2: Clone, Copy, Default);
    assert_not_impl_any!(ProductionContractsConsumedPostAnchorV2: Clone, Copy, Default);
    const REMOTE_RELAY_SECRET: [u8; 32] = [0x62; 32];

    type TestOwner = ProductionContractsV1<UnavailableF6AuthorityV1>;
    type TestResult = Result<(), Box<dyn Error>>;

    #[derive(Clone, Copy)]
    enum IdentityPlacement {
        Local,
        Remote,
        Absent,
    }

    #[derive(Clone, Copy)]
    struct TestTransportScope {
        session_id: [u8; 32],
        local: ParticipantId,
        remote: ParticipantId,
        local_is_initiator: bool,
    }

    struct TestFixture {
        _directory: tempfile::TempDir,
        parent: Arc<Dir>,
        passphrase: ContractsIdentityPassphraseV1,
        store: ContractsSessionStoreV1,
        identity: ContractsTransportIdentityStoreV1,
        local_key_reference: [u8; 32],
        remote_key_reference: [u8; 32],
        paths: RelayWorkerPathsV1,
        config: RelayWorkerConfigV1,
        remote_relay_xonly: [u8; 32],
        chain: TrustedChainIdV1,
    }

    impl TestFixture {
        fn new(
            placement: IdentityPlacement,
            reuse_relay_key: bool,
        ) -> Result<Self, Box<dyn Error>> {
            let directory = tempfile::Builder::new()
                .prefix("dom-production-contracts-")
                .tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            let parent = parent_capability(directory.path())?;
            let passphrase = ContractsIdentityPassphraseV1::new(
                b"production-contracts-test-passphrase".to_vec(),
            )?;
            let identity = ContractsTransportIdentityStoreV1::create_production(
                Arc::clone(&parent),
                "identity",
                &passphrase,
            )?;
            let chain = trusted_dom_chain()?;
            let BoundTestStore {
                store,
                local_key_reference,
                remote_key_reference,
            } = create_bound_store(
                Arc::clone(&parent),
                "contracts",
                identity.reference(),
                placement,
                chain,
            )?;
            let relay_xonly = if reuse_relay_key {
                identity.reference().schnorr_public_key()[1..]
                    .try_into()
                    .map_err(|_| SessionStoreError::Canonical)?
            } else {
                xonly(&LOCAL_RELAY_SECRET)
            };
            let config = relay_config(relay_xonly)?;
            let paths = RelayWorkerPathsV1::new(
                directory.path().join("relay-sender"),
                directory.path().join("relay-inbox"),
                directory.path().join("relay-frames"),
            );
            Ok(Self {
                _directory: directory,
                parent,
                passphrase,
                store,
                identity,
                local_key_reference,
                remote_key_reference,
                paths,
                config,
                remote_relay_xonly: xonly(&REMOTE_RELAY_SECRET),
                chain,
            })
        }

        fn relay_rosters(&self) -> RosterRegistryV1 {
            relay_rosters_for(
                self.config.local_participant(),
                self.config.remote_participant(),
                self.config.relay_sender_role(),
                *self.config.relay_signer_xonly(),
                self.remote_relay_xonly,
            )
        }
    }

    struct ReentrantQueue {
        relay: RelayV1,
        store: Option<Rc<ContractsSessionStoreV1>>,
        lose_next_ack: bool,
        attempts: Vec<Vec<u8>>,
    }

    impl ReentrantQueue {
        fn new() -> Self {
            Self {
                relay: RelayV1::default(),
                store: None,
                lose_next_ack: false,
                attempts: Vec::new(),
            }
        }
    }

    impl RelayQueueV1 for ReentrantQueue {
        fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal> {
            if let Some(store) = &self.store {
                store
                    .load_session(SESSION)
                    .expect("Store remains reentrant while Relay submission runs");
            }
            self.attempts.push(raw.to_vec());
            let ack = self.relay.submit(raw).map_err(BridgeRefusal::Relay)?;
            if self.lose_next_ack {
                self.lose_next_ack = false;
                Err(BridgeRefusal::AckDigestMismatch)
            } else {
                Ok(ack)
            }
        }

        fn queue_deliver_ephemeral_v1(
            &self,
            recipient: &ParticipantId,
        ) -> Result<Vec<Vec<u8>>, BridgeRefusal> {
            Ok(self.relay.deliver(recipient))
        }
    }

    #[test]
    fn production_owner_exposes_only_the_purpose_specific_f6_recovery_boundary() {
        let _recover: fn(
            &ProductionContractsV1<ProductionF6LifecyclePortV2>,
        ) -> Result<F6AppliedReplayReportV1, ProductionContractsF6RecoveryErrorV2> =
            ProductionContractsV1::<
                ProductionF6LifecyclePortV2,
            >::recover_production_f6_applied_history;
    }

    #[test]
    fn owner_retains_exactly_one_physical_store_opening() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            parent,
            passphrase: _,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        assert!(matches!(
            ContractsSessionStoreV1::open_production(
                Arc::clone(&parent),
                "contracts",
                production_policy()?,
            ),
            Err(SessionStoreError::StoreBusy)
        ));
        drop(owner);
        let reopened =
            ContractsSessionStoreV1::open_production(parent, "contracts", production_policy()?)?;
        assert_eq!(reopened.load_session(SESSION)?.session_id(), SESSION);
        Ok(())
    }

    #[test]
    fn owner_resume_preserves_one_opening_and_refuses_roster_before_relay_mutation() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            parent,
            passphrase,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        drop(owner);
        let store = ContractsSessionStoreV1::open_production(
            Arc::clone(&parent),
            "contracts",
            production_policy()?,
        )?;
        let identity = ContractsTransportIdentityStoreV1::open_production(
            Arc::clone(&parent),
            "identity",
            &passphrase,
        )?;
        let resumed = TestOwner::resume_create_production(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        assert!(matches!(
            ContractsSessionStoreV1::open_production(
                Arc::clone(&parent),
                "contracts",
                production_policy()?,
            ),
            Err(SessionStoreError::StoreBusy)
        ));
        drop(resumed);

        let wrong = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory: wrong_directory,
            store,
            identity,
            paths,
            config,
            ..
        } = wrong;
        let wrong_roster = relay_rosters(xonly(&REMOTE_RELAY_SECRET));
        assert!(matches!(
            TestOwner::resume_create_production(
                store,
                identity,
                &paths,
                config,
                wrong_roster,
                UnavailableF6AuthorityV1,
                LOCAL_RELAY_SECRET,
            ),
            Err(ProductionContractsOpenErrorV1::Relay(
                RelayWorkerOpenErrorV1::InvalidConfiguration
            ))
        ));
        assert!(!paths.sender_root().exists());
        assert!(!paths.inbox_root().exists());
        assert!(!paths.frame_reassembly_root().exists());
        drop(wrong_directory);

        let wrong_binding = TestFixture::new(IdentityPlacement::Absent, false)?;
        let TestFixture {
            _directory: wrong_binding_directory,
            store,
            identity,
            paths,
            config,
            ..
        } = wrong_binding;
        assert!(matches!(
            TestOwner::resume_create_production(
                store,
                identity,
                &paths,
                config,
                relay_rosters(*config.relay_signer_xonly()),
                UnavailableF6AuthorityV1,
                LOCAL_RELAY_SECRET,
            ),
            Err(ProductionContractsOpenErrorV1::StoreRejected)
        ));
        assert!(!paths.sender_root().exists());
        assert!(!paths.inbox_root().exists());
        assert!(!paths.frame_reassembly_root().exists());
        drop(wrong_binding_directory);
        Ok(())
    }

    #[test]
    fn two_leg_owners_share_one_physical_transport_identity() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            parent,
            passphrase,
            store,
            identity,
            paths,
            config,
            chain,
            ..
        } = fixture;
        let identity = Rc::new(identity);
        let first = TestOwner::create(
            store,
            Rc::clone(&identity),
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let BoundTestStore { store, .. } = create_bound_store(
            Arc::clone(&parent),
            "contracts-second-leg",
            identity.reference(),
            IdentityPlacement::Local,
            chain,
        )?;
        let second_paths = RelayWorkerPathsV1::new(
            _directory.path().join("relay-sender-second"),
            _directory.path().join("relay-inbox-second"),
            _directory.path().join("relay-frames-second"),
        );
        let second = TestOwner::create(
            store,
            Rc::clone(&identity),
            &second_paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        assert!(Rc::ptr_eq(&first.identity, &second.identity));
        assert!(matches!(
            ContractsTransportIdentityStoreV1::open_production(
                Arc::clone(&parent),
                "identity",
                &passphrase,
            ),
            Err(IdentityStoreError::StoreBusy)
        ));
        drop(first);
        drop(second);
        drop(identity);
        assert!(ContractsTransportIdentityStoreV1::open_production(
            parent,
            "identity",
            &passphrase,
        )
        .is_ok());
        Ok(())
    }

    #[test]
    fn dom_secret_source_opening_reuses_owner_store_and_refuses_wrong_binding() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            parent,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let baseline_references = Rc::strong_count(&owner.store);
        let opening = owner
            .prepare_dom_public_secret_opening(
                dom_binding(SESSION, LOCAL.0, 0)?,
                trusted_dom_chain()?,
            )
            .expect("valid DOM secret-source opening");
        assert!(Rc::ptr_eq(&opening.store, &owner.store));
        assert_eq!(Rc::strong_count(&owner.store), baseline_references + 1);
        assert!(matches!(
            ContractsSessionStoreV1::open_production(parent, "contracts", production_policy()?,),
            Err(SessionStoreError::StoreBusy)
        ));
        drop(opening);

        assert!(matches!(
            owner.prepare_dom_public_secret_opening(
                dom_binding_for([0x82; 32], SESSION, LOCAL.0, 0)?,
                trusted_dom_chain()?,
            ),
            Err(AuthorityRefusalV1::Inconsistent)
        ));
        Ok(())
    }

    #[test]
    fn dom_child_handoff_retains_one_physical_opening_and_process_lock() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            parent,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let mut owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let binding = dom_binding(SESSION, LOCAL.0, 0)?;
        let baseline_references = Rc::strong_count(&owner.store);
        let baseline_relay_references = Rc::strong_count(&owner.relay);
        let child = owner.dom_child_store_authority(binding, expiry())?;
        assert!(Rc::ptr_eq(&child.store, &owner.store));
        assert_eq!(Rc::strong_count(&owner.store), baseline_references + 2);
        assert_eq!(
            Rc::strong_count(&owner.relay),
            baseline_relay_references + 1
        );
        assert!(matches!(
            owner.dom_child_store_authority(binding, expiry()),
            Err(DomActuatorError::InvalidStage)
        ));

        let child_actuator = child.bind()?;
        let sibling_actuator = owner.bind_dom_actuator(binding)?;
        assert_eq!(
            child_actuator.session_head()?.session_id(),
            sibling_actuator.session_head()?.session_id()
        );
        let relay = Rc::clone(&owner.relay);
        let relay_guard = relay.borrow_mut();
        assert!(matches!(
            owner.contracts_session_status(),
            Err(SessionStoreError::StoreBusy)
        ));
        drop(relay_guard);
        assert!(matches!(
            ContractsSessionStoreV1::open_production(parent, "contracts", production_policy()?),
            Err(SessionStoreError::StoreBusy)
        ));
        Ok(())
    }

    #[test]
    fn dom_child_handoff_rejects_zero_final_claim_expiry_without_consuming_issue() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let binding = dom_binding(SESSION, LOCAL.0, 0)?;
        assert!(matches!(
            owner.dom_child_store_authority(binding, TimelockSpec::BlockHeight { value: 0 }),
            Err(DomActuatorError::InvalidBinding)
        ));
        owner.dom_child_store_authority(binding, expiry())?;
        Ok(())
    }

    #[test]
    fn worker_child_and_refund_share_one_store_while_refund_issue_is_one_shot_and_reentrant_closed(
    ) -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let binding = dom_binding(SESSION, LOCAL.0, 0)?;
        let _child = owner.dom_child_store_authority(binding, expiry())?;
        let baseline_store_references = Rc::strong_count(&owner.store);
        let relay = Rc::clone(&owner.relay);
        let worker_guard = relay.borrow_mut();
        let face = owner.issue_dom_refund_face_once(|| {
            assert!(matches!(
                owner.issue_dom_refund_face_once(|| panic!("reentrant issuer executed")),
                Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
            ));
            Ok(test_dom_refund_store_face(
                &owner,
                binding,
                LegIdV1::Upstream,
            ))
        })?;
        assert_eq!(
            Rc::strong_count(&owner.store),
            baseline_store_references + 1
        );
        assert!(matches!(
            owner.issue_dom_refund_face_once(|| panic!("second issuer executed")),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        ));
        drop(worker_guard);
        drop(face);
        assert_eq!(Rc::strong_count(&owner.store), baseline_store_references);
        Ok(())
    }

    #[test]
    fn refund_face_scope_refuses_position_owner_epoch_composition_and_binding_transplants(
    ) -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let authority = test_dom_refund_store_face(
            &owner,
            dom_binding(SESSION, LOCAL.0, 0)?,
            LegIdV1::Upstream,
        );
        let frozen = test_refund_frozen_bindings();
        assert!(authority.authenticates_scope(
            LegIdV1::Upstream,
            [0xa1; 32],
            7,
            [0xa2; 32],
            &frozen,
        ));
        assert!(!authority.authenticates_scope(
            LegIdV1::Downstream,
            [0xa1; 32],
            7,
            [0xa2; 32],
            &frozen,
        ));
        assert!(!authority.authenticates_scope(
            LegIdV1::Upstream,
            [0xb1; 32],
            7,
            [0xa2; 32],
            &frozen,
        ));
        assert!(!authority.authenticates_scope(
            LegIdV1::Upstream,
            [0xa1; 32],
            8,
            [0xa2; 32],
            &frozen,
        ));
        assert!(!authority.authenticates_scope(
            LegIdV1::Upstream,
            [0xa1; 32],
            7,
            [0xb2; 32],
            &frozen,
        ));
        let mut wrong_frozen = frozen;
        wrong_frozen.deployment_bundle_digest = [0xb3; 32];
        assert!(!authority.authenticates_scope(
            LegIdV1::Upstream,
            [0xa1; 32],
            7,
            [0xa2; 32],
            &wrong_frozen,
        ));
        Ok(())
    }

    #[test]
    fn refund_face_reissues_only_from_the_reauthenticated_restart_opening() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            parent,
            passphrase,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let binding = dom_binding(SESSION, LOCAL.0, 0)?;
        let face = owner.issue_dom_refund_face_once(|| {
            Ok(test_dom_refund_store_face(
                &owner,
                binding,
                LegIdV1::Upstream,
            ))
        })?;
        drop(face);
        drop(owner);

        let store = ContractsSessionStoreV1::open_production(
            Arc::clone(&parent),
            "contracts",
            production_policy()?,
        )?;
        let identity = ContractsTransportIdentityStoreV1::open_production(
            Arc::clone(&parent),
            "identity",
            &passphrase,
        )?;
        let resumed = TestOwner::open_existing(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let resumed_face = resumed.issue_dom_refund_face_once(|| {
            Ok(test_dom_refund_store_face(
                &resumed,
                binding,
                LegIdV1::Upstream,
            ))
        })?;
        assert!(matches!(
            ContractsSessionStoreV1::open_production(parent, "contracts", production_policy()?,),
            Err(SessionStoreError::StoreBusy)
        ));
        drop(resumed_face);
        Ok(())
    }

    #[test]
    fn evm_remote_handoff_is_single_owner_bound_and_invalid_issue_is_non_consuming() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let pins = ProductionEvmRemoteSignerPinsV1 {
            route_id: wire().route_id,
            session_id: SESSION,
            settlement_id: [0x71; 32],
            terms_digest: [0x72; 32],
            registry_digest: [0x73; 32],
            profile_digest: [0x74; 32],
            deployment_digest: [0x75; 32],
            composition_digest: [0x76; 32],
            chain_id: 31_337,
            contract: [0x77; 20],
            signer_account: [0x78; 20],
            role: evm_actuator::EvmSignerRoleV1::Beneficiary,
            requester_id: LOCAL.0,
            signer_id: REMOTE.0,
            owner_id: [0x79; 32],
        };
        let wrong = ProductionEvmRemoteSignerBindingV1::new(ProductionEvmRemoteSignerPinsV1 {
            route_id: [0x7a; 32],
            ..pins
        })?;
        assert!(matches!(
            owner.evm_remote_transport_authority(&wrong, expiry()),
            Err(ChildAuthorityRefusalV1::Conflict)
        ));
        let correct = ProductionEvmRemoteSignerBindingV1::new(pins)?;
        assert!(matches!(
            owner.evm_remote_transport_authority(
                &correct,
                TimelockSpec::TimestampSeconds { value: 0 },
            ),
            Err(ChildAuthorityRefusalV1::Conflict)
        ));
        let authority = owner.evm_remote_transport_authority(&correct, expiry())?;
        assert!(!format!("{authority:?}").contains("7878"));
        assert!(matches!(
            owner.evm_remote_transport_authority(&correct, expiry()),
            Err(ChildAuthorityRefusalV1::Conflict)
        ));
        Ok(())
    }

    #[test]
    fn owner_scopes_actuator_to_the_frozen_session_and_participant() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let local = dom_binding(SESSION, LOCAL.0, 0)?;
        let other_session = dom_binding(OTHER_SESSION, LOCAL.0, 0)?;
        let remote = dom_binding(SESSION, REMOTE.0, 1)?;
        let other_route = dom_binding_for([0x82; 32], SESSION, LOCAL.0, 0)?;
        let opposite_index = dom_binding(SESSION, LOCAL.0, 1)?;
        let TestFixture {
            _directory,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let actuator = owner.bind_dom_actuator(local)?;
        assert!(
            actuator.session_head()?.session_id()
                == owner.store.load_session(SESSION)?.session_id()
        );
        assert!(matches!(
            owner.bind_dom_actuator(other_session),
            Err(DomActuatorError::InvalidBinding)
        ));
        assert!(matches!(
            owner.bind_dom_actuator(remote),
            Err(DomActuatorError::InvalidBinding)
        ));
        assert!(matches!(
            owner.bind_dom_actuator(other_route),
            Err(DomActuatorError::InvalidBinding)
        ));
        assert!(matches!(
            owner.bind_dom_actuator(opposite_index),
            Err(DomActuatorError::InvalidBinding)
        ));
        Ok(())
    }

    #[test]
    fn owner_derives_protocol_index_from_participant_id_order_not_transport_role() -> TestResult {
        assert_ordered_owner_binding(
            ParticipantId([0x21; 32]),
            ParticipantId([0x71; 32]),
            false,
            0,
        )?;
        assert_ordered_owner_binding(
            ParticipantId([0x71; 32]),
            ParticipantId([0x21; 32]),
            true,
            1,
        )?;
        Ok(())
    }

    #[test]
    fn owner_rejects_wrong_remote_reused_and_prebound_identities_before_relay_creation(
    ) -> TestResult {
        for placement in [IdentityPlacement::Absent, IdentityPlacement::Remote] {
            let fixture = TestFixture::new(placement, false)?;
            let error = create_error(fixture)?;
            assert!(matches!(
                error,
                ProductionContractsOpenErrorV1::StoreRejected
            ));
        }

        let fixture = TestFixture::new(IdentityPlacement::Local, true)?;
        let error = create_error(fixture)?;
        assert!(matches!(
            error,
            ProductionContractsOpenErrorV1::IdentityKeyReuse
        ));

        let mut fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        fixture.config = relay_config(xonly(&[0x22; 32]))?;
        let error = create_error(fixture)?;
        assert!(matches!(
            error,
            ProductionContractsOpenErrorV1::IdentityKeyReuse
        ));

        let mut fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        fixture.remote_relay_xonly = fixture.identity.reference().schnorr_public_key()[1..]
            .try_into()
            .map_err(|_| SessionStoreError::Canonical)?;
        let error = create_error(fixture)?;
        assert!(matches!(
            error,
            ProductionContractsOpenErrorV1::IdentityKeyReuse
        ));

        let mut fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        fixture.remote_relay_xonly = xonly(&[0x22; 32]);
        let error = create_error(fixture)?;
        assert!(matches!(
            error,
            ProductionContractsOpenErrorV1::IdentityKeyReuse
        ));

        let mut fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        fixture.remote_relay_xonly = *fixture.config.relay_signer_xonly();
        let error = create_error(fixture)?;
        assert!(matches!(
            error,
            ProductionContractsOpenErrorV1::Relay(RelayWorkerOpenErrorV1::InvalidConfiguration)
        ));

        let mut fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        fixture.config = relay_config_for(
            LOCAL,
            ParticipantId([0x59; 32]),
            SenderRoleV1::Initiator,
            *fixture.config.relay_signer_xonly(),
        )?;
        let error = create_error(fixture)?;
        assert!(matches!(
            error,
            ProductionContractsOpenErrorV1::StoreRejected
        ));

        let mut fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        fixture.config = relay_config_for(
            LOCAL,
            REMOTE,
            SenderRoleV1::Solver,
            *fixture.config.relay_signer_xonly(),
        )?;
        let error = create_error(fixture)?;
        assert!(matches!(
            error,
            ProductionContractsOpenErrorV1::StoreRejected
        ));

        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        fixture
            .store
            .bind_local_transport_signer(SESSION, fixture.remote_key_reference)?;
        let error = create_error(fixture)?;
        assert!(matches!(
            error,
            ProductionContractsOpenErrorV1::StoreRejected
        ));
        Ok(())
    }

    #[test]
    fn sign_commit_stage_accepts_only_the_same_store_opening() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        fixture
            .store
            .bind_local_transport_signer(SESSION, fixture.local_key_reference)?;
        let correct = prepare_abort_request(&fixture.store, fixture.chain, SESSION, [0x81; 32])?;
        let wrong_bound = create_bound_store(
            Arc::clone(&fixture.parent),
            "wrong-contracts",
            fixture.identity.reference(),
            IdentityPlacement::Local,
            fixture.chain,
        )?;
        wrong_bound
            .store
            .bind_local_transport_signer(SESSION, wrong_bound.local_key_reference)?;
        let wrong = prepare_abort_request(&wrong_bound.store, fixture.chain, SESSION, [0x82; 32])?;
        fixture
            .store
            .create_session(&initial_record(OTHER_SESSION)?)?;
        let other_session_references = bind_session_transport(
            &fixture.store,
            fixture.identity.reference(),
            IdentityPlacement::Local,
            fixture.chain,
            TestTransportScope {
                session_id: OTHER_SESSION,
                local: LOCAL,
                remote: REMOTE,
                local_is_initiator: true,
            },
        )?;
        fixture.store.bind_local_transport_signer(
            OTHER_SESSION,
            other_session_references.local_key_reference,
        )?;
        let other_session =
            prepare_abort_request(&fixture.store, fixture.chain, OTHER_SESSION, [0x83; 32])?;
        let rosters = fixture.relay_rosters();

        let mut owner = TestOwner::create(
            fixture.store,
            fixture.identity,
            &fixture.paths,
            fixture.config,
            rosters,
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let error = owner
            .sign_commit_and_stage(wrong, expiry())
            .expect_err("another Store opening cannot authorize signing");
        assert!(matches!(
            error,
            ProductionContractsOutboundErrorV1::Identity(IdentityStoreError::StoreRejected)
        ));
        assert!(matches!(
            wrong_bound.store.resume_outbound_dsc1(SESSION)?,
            OutboundDsc1RecoveryV1::SigningRequest(_)
        ));
        let mut queue = ReentrantQueue::new();
        assert!(matches!(
            owner.submit_outbound_once(&mut queue)?,
            RelayOutboundStepV1::Idle
        ));
        let error = owner
            .sign_commit_and_stage(other_session, expiry())
            .expect_err("another session in the same Store cannot authorize signing");
        assert!(matches!(
            error,
            ProductionContractsOutboundErrorV1::Store(SessionStoreError::InvalidTransition)
        ));
        assert!(matches!(
            owner.store.resume_outbound_dsc1(OTHER_SESSION)?,
            OutboundDsc1RecoveryV1::SigningRequest(_)
        ));
        assert!(matches!(
            owner.submit_outbound_once(&mut queue)?,
            RelayOutboundStepV1::Idle
        ));

        let staged = owner.sign_commit_and_stage(correct, expiry())?;
        assert_eq!(staged.status().state(), RouteApplicationStateV2::Pending);
        assert_eq!(staged.status().frame_count(), 1);
        Ok(())
    }

    #[test]
    fn ack_loss_reopens_same_application_and_store_is_reentrant_during_submission() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        fixture
            .store
            .bind_local_transport_signer(SESSION, fixture.local_key_reference)?;
        let request = prepare_abort_request(&fixture.store, fixture.chain, SESSION, [0x91; 32])?;
        let TestFixture {
            _directory,
            parent,
            passphrase,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let mut owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let staged = owner.sign_commit_and_stage(request, expiry())?;
        let initial_status = staged.status();
        let mut queue = ReentrantQueue::new();
        queue.store = Some(Rc::clone(&owner.store));
        queue.lose_next_ack = true;
        assert!(matches!(
            owner.submit_outbound_once(&mut queue),
            Err(RelayWorkerOutboundErrorV1::Sender(_))
        ));
        assert_eq!(queue.attempts.len(), 1);
        let first_attempt = queue.attempts[0].clone();
        queue.store = None;
        drop(owner);

        let store = ContractsSessionStoreV1::open_production(
            Arc::clone(&parent),
            "contracts",
            production_policy()?,
        )?;
        let identity =
            ContractsTransportIdentityStoreV1::open_production(parent, "identity", &passphrase)?;
        let mut owner = TestOwner::open_existing(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let resumed = owner.resume_and_stage(expiry())?;
        let ProductionContractsResumeV1::Staged(resumed) = resumed else {
            panic!("committed application must resume");
        };
        assert_eq!(resumed.status(), initial_status);
        queue.store = Some(Rc::clone(&owner.store));
        assert!(matches!(
            owner.submit_outbound_once(&mut queue)?,
            RelayOutboundStepV1::Acked { .. }
        ));
        assert_eq!(queue.attempts.len(), 2);
        assert_eq!(queue.attempts[1], first_attempt);

        let reconciled = owner.resume_and_stage(expiry())?;
        let ProductionContractsResumeV1::Staged(reconciled) = reconciled else {
            panic!("ACKed application must reconcile through its Store handle");
        };
        assert_eq!(
            reconciled.status().application_id(),
            initial_status.application_id()
        );
        assert_eq!(reconciled.status().state(), RouteApplicationStateV2::Acked);
        assert_eq!(
            owner.resume_and_stage(expiry())?,
            ProductionContractsResumeV1::Idle
        );
        Ok(())
    }

    #[test]
    fn owner_surface_exposes_only_purpose_specific_borrows_and_committed_progress() {
        let _actuator = TestOwner::bind_dom_actuator;
        let _signer = TestOwner::participant_signer;
        let source = include_str!("production_contracts.rs");
        let productive = source
            .split("#[cfg(test)]")
            .next()
            .expect("productive module prefix");
        // Interior ownership is deliberately private: the one Relay opening
        // is shared with the narrow final-claim authority, but neither that
        // authority nor `ProductionContractsV1` exposes the cell or a raw
        // Relay/Store/identity accessor.  Guard the callable surface rather
        // than rejecting the private implementation mechanism by name.
        let mut checked_returns = 0usize;
        for prefix in ["pub(crate) fn ", "pub(crate) const fn "] {
            for (offset, _) in productive.match_indices(prefix) {
                let signature = productive[offset..]
                    .split_once('{')
                    .map(|(signature, _)| signature)
                    .expect("pub(crate) function signature must have a body");
                let Some((_, returned_and_bounds)) = signature.split_once("->") else {
                    continue;
                };
                let returned = returned_and_bounds
                    .split_once("\n    where")
                    .map_or(returned_and_bounds, |(returned, _)| returned);
                checked_returns += 1;
                for forbidden_return in [
                    "RefCell",
                    "DurableRelayWorkerV1",
                    "ContractsSessionStoreV1",
                    "ContractsTransportIdentityStoreV1",
                ] {
                    assert!(
                        !returned.contains(forbidden_return),
                        "productive owner returned raw authority `{forbidden_return}` in `{signature}`"
                    );
                }
            }
        }
        assert!(
            checked_returns >= 10,
            "surface guard did not inspect the expected production API"
        );
        for forbidden in [
            "SignedMessage",
            "Vec<u8>",
            "fn store(",
            "fn relay(",
            "fn identity(",
            "relay_mut",
            "ContractsSessionStoreV1::open_",
        ] {
            assert!(
                !productive.contains(forbidden),
                "productive owner restored forbidden surface: {forbidden}"
            );
        }
        for required_receiver_edge in [
            "consumer.observe(evidence)?",
            "persist_observed_final_claim_exposure_v2(expected_revision, observation)?",
            ".prepare_operational_final_claim_ingress_authority_v2(",
            "PreparedContractsIngressV1::final_claim_ingress_v2(",
        ] {
            assert!(
                productive.contains(required_receiver_edge),
                "productive FinalClaim receiver lost `{required_receiver_edge}`"
            );
        }
    }

    #[test]
    fn inbound_poll_keeps_the_worker_private_and_refuses_reentrant_owner_borrow() -> TestResult {
        let fixture = TestFixture::new(IdentityPlacement::Local, false)?;
        let TestFixture {
            _directory,
            store,
            identity,
            paths,
            config,
            ..
        } = fixture;
        let mut owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            relay_rosters(*config.relay_signer_xonly()),
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let relay_root = _directory.path().join("production-relay");
        let relay_config = RelayDatabaseConfigV1::new(RelayDatabaseIdV1::new([0xd1; 32])?, 256)?;
        let mut relay = ProductionRelayV1::create(&relay_root, relay_config)?;

        let retained_worker = Rc::clone(&owner.relay);
        let _active_operation = retained_worker
            .try_borrow_mut()
            .map_err(|_| "test worker borrow must be available")?;
        assert!(matches!(
            owner.poll_inbound(&mut relay, expiry()),
            Err(ProductionContractsPollErrorV1::OwnerBusy)
        ));
        Ok(())
    }

    fn create_error(
        fixture: TestFixture,
    ) -> Result<ProductionContractsOpenErrorV1, Box<dyn Error>> {
        let sender_root = fixture.paths.sender_root().to_path_buf();
        let inbox_root = fixture.paths.inbox_root().to_path_buf();
        let frame_root = fixture.paths.frame_reassembly_root().to_path_buf();
        let rosters = fixture.relay_rosters();
        let result = TestOwner::create(
            fixture.store,
            fixture.identity,
            &fixture.paths,
            fixture.config,
            rosters,
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        );
        let error = match result {
            Ok(_) => return Err(Box::new(SessionStoreError::Quarantined)),
            Err(error) => error,
        };
        assert!(!sender_root.exists());
        assert!(!inbox_root.exists());
        assert!(!frame_root.exists());
        Ok(error)
    }

    fn assert_ordered_owner_binding(
        local: ParticipantId,
        remote: ParticipantId,
        local_is_initiator: bool,
        expected_protocol_index: u8,
    ) -> TestResult {
        let directory = tempfile::Builder::new()
            .prefix("dom-production-contracts-order-")
            .tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let parent = parent_capability(directory.path())?;
        let passphrase =
            ContractsIdentityPassphraseV1::new(b"production-contracts-order-passphrase".to_vec())?;
        let identity = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "identity",
            &passphrase,
        )?;
        let chain = trusted_dom_chain()?;
        let store =
            ContractsSessionStoreV1::create_production(parent, "contracts", production_policy()?)?;
        store.create_session(&initial_record(SESSION)?)?;
        bind_session_transport(
            &store,
            identity.reference(),
            IdentityPlacement::Local,
            chain,
            TestTransportScope {
                session_id: SESSION,
                local,
                remote,
                local_is_initiator,
            },
        )?;
        let local_role = if local_is_initiator {
            SenderRoleV1::Initiator
        } else {
            SenderRoleV1::Solver
        };
        let config = relay_config_for(local, remote, local_role, xonly(&LOCAL_RELAY_SECRET))?;
        let paths = RelayWorkerPathsV1::new(
            directory.path().join("relay-sender"),
            directory.path().join("relay-inbox"),
            directory.path().join("relay-frames"),
        );
        let rosters = relay_rosters_for(
            local,
            remote,
            local_role,
            xonly(&LOCAL_RELAY_SECRET),
            xonly(&REMOTE_RELAY_SECRET),
        );
        let owner = TestOwner::create(
            store,
            identity,
            &paths,
            config,
            rosters,
            UnavailableF6AuthorityV1,
            LOCAL_RELAY_SECRET,
        )?;
        let binding = dom_binding(SESSION, local.0, expected_protocol_index)?;
        assert!(owner.bind_dom_actuator(binding).is_ok());
        Ok(())
    }

    fn parent_capability(path: &Path) -> Result<Arc<Dir>, Box<dyn Error>> {
        Ok(Arc::new(Dir::from_std_file(File::open(path)?)))
    }

    fn trusted_dom_chain() -> Result<TrustedChainIdV1, Box<dyn Error>> {
        let runtime = DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest);
        let genesis = configured_genesis_hash_for_network_magic(runtime.network_magic)?;
        Ok(TrustedChainIdV1::from_authenticated_genesis(
            runtime.network_magic,
            &genesis,
        ))
    }

    fn test_refund_frozen_bindings() -> FrozenBindingsV1 {
        FrozenBindingsV1 {
            terms_digest: [0xa3; 32],
            profile_bundle_digest: [0xa4; 32],
            deployment_bundle_digest: [0xa5; 32],
        }
    }

    fn test_dom_refund_store_face(
        owner: &TestOwner,
        binding: DomSessionBindingV1,
        position: LegIdV1,
    ) -> ProductionDomRefundStoreFaceV1 {
        ProductionDomRefundStoreFaceV1 {
            store: Rc::clone(&owner.store),
            binding,
            trusted_chain_id: trusted_dom_chain().expect("trusted test chain"),
            position,
            owner_id: [0xa1; 32],
            authority_epoch: 7,
            composition_digest: [0xa2; 32],
            frozen_bindings: test_refund_frozen_bindings(),
        }
    }

    fn dom_binding(
        session_id: [u8; 32],
        participant_id: [u8; 32],
        protocol_index: u8,
    ) -> Result<DomSessionBindingV1, Box<dyn Error>> {
        dom_binding_for(wire().route_id, session_id, participant_id, protocol_index)
    }

    fn dom_binding_for(
        route_id: [u8; 32],
        session_id: [u8; 32],
        participant_id: [u8; 32],
        protocol_index: u8,
    ) -> Result<DomSessionBindingV1, Box<dyn Error>> {
        let network_id = [0x90; 32];
        let runtime = DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest);
        let genesis = configured_genesis_hash_for_network_magic(runtime.network_magic)?;
        let trusted_chain =
            TrustedChainIdV1::from_authenticated_genesis(runtime.network_magic, &genesis);
        let dom_chain = ChainId(*trusted_chain.as_bytes());
        let evm_chain = ChainId(if dom_chain.0 == [0xee; 32] {
            [0xed; 32]
        } else {
            [0xee; 32]
        });
        let dom_asset = AssetId([0x11; 32]);
        let evm_asset = AssetId([0x12; 32]);
        let timing = ChainTimingBoundsV1 {
            min_block_seconds: 5,
            max_block_seconds: 20,
            max_reorg_seconds: 200,
            observation_seconds: 30,
            broadcast_seconds: 20,
        };
        let finality = FinalityPolicyV1 {
            min_confirmations: 2,
            max_reorg_depth: 3,
        };
        let mut assets = vec![
            AssetBindingV1 {
                chain_id: dom_chain,
                asset_id: dom_asset,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: evm_chain,
                asset_id: evm_asset,
                decimals: 18,
                representation: AssetRepresentationV1::Native,
            },
        ];
        assets.sort_by_key(|asset| (asset.chain_id.0, asset.asset_id.0));
        let manifest = RegistryManifestV1 {
            network_id,
            epoch: 1,
            valid_from: 1_000,
            expires_at: 10_000,
            dom: DomDeploymentV1 {
                chain_id: dom_chain,
                genesis_hash: *genesis.as_bytes(),
                runtime_identity: runtime,
                consensus_rules_digest: [0x22; 32],
                scriptless_api_version: 1,
                timing,
                finality,
                native_asset: dom_asset,
            },
            chains: vec![RegistryChainProfileV1 {
                profile: ChainProfileV1 {
                    chain_id: evm_chain,
                    kind: ChainKindV1::Evm {
                        evm_chain_id: 31_337,
                        native_lock_contract: [0x31; 20],
                        native_code_hash: [0x32; 32],
                        erc20_lock_contract: None,
                    },
                    timing,
                    finality,
                    native_asset: evm_asset,
                    allowed_assets: Vec::new(),
                },
                deployment: ChainDeploymentV1::Evm(EvmDeploymentV1 {
                    genesis_hash: [0x35; 32],
                    native_start_block: 10,
                    erc20_start_block: None,
                    abi_digest: [0x36; 32],
                    compiler_digest: [0x37; 32],
                    source_digest: [0x38; 32],
                    deployment_digest: [0x39; 32],
                    finalized_tag_required: true,
                    page_size: 256,
                    gas_limit_hint: 300_000,
                    max_fee_per_gas: 100_000_000_000,
                    max_priority_fee_per_gas: 2_000_000_000,
                }),
            }],
            assets,
        };
        let secp = SecpContext::new(&[0x70; 32]);
        let digest = manifest.manifest_digest()?;
        let (signature, authority_key) = secp.sign_bip340(&[0x73; 32], &digest, &[0x74; 32])?;
        let authorities = AuthoritySetV1::new(1, vec![authority_key])?;
        let signed = SignedRegistryV1::new(
            &manifest,
            vec![RegistrySignatureV1 {
                signer_index: 0,
                signature,
            }],
        )?;
        let resolved = signed.verify(
            &authorities,
            &secp,
            RegistryValidationPolicyV1 {
                now_seconds: 2_000,
                expected_network_id: network_id,
                minimum_epoch: 1,
            },
        )?;
        Ok(DomSessionBindingV1::from_resolved_deployment(
            route_id,
            session_id,
            DomParticipantV1::new(participant_id, protocol_index)?,
            [0x32; 32],
            resolved.resolve_dom()?,
        )?)
    }

    fn production_policy() -> Result<BudgetPolicyV1, Box<dyn Error>> {
        let mut bytes = [0; BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(b"DOMNVBP1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = BudgetPolicyProfileV1::ProductionRatified as u8;
        bytes[11] = 1;
        bytes[16..48].fill(0x41);
        bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
        let digest = dom_scriptless_crypto::authoritative_storage_hash_v1(
            dom_scriptless_crypto::StorageHashDomainV1::BudgetPolicy,
            &bytes[..112],
        );
        bytes[112..].copy_from_slice(&digest);
        Ok(BudgetPolicyV1::from_bytes(&bytes)?)
    }

    fn initial_record(session_id: [u8; 32]) -> Result<SessionRecordV1, SessionStoreError> {
        Ok(SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id,
                revision: 0,
                phase: SessionPhaseV1::Created,
                terms_hash: [0x32; 32],
                transcript_hash: [0x33; 32],
                irreversible: SessionIrreversibleV1 {
                    any_signing_share_sent: true,
                    funding_authorized: false,
                    adaptor_secret_exposed: false,
                    nonce_epoch: 7,
                },
                chain: SessionChainProjectionV1 {
                    tip_id: [0x34; 32],
                    tip_height: 100,
                    funding: SessionTxObservationV1::Unknown,
                    claim: SessionTxObservationV1::Unknown,
                    refund: SessionTxObservationV1::Unknown,
                },
            },
            b"sealed-production-contracts-test",
        )?)
    }

    /// A store and the two transport key references bound to it.
    ///
    /// Named rather than returned as a three-tuple, and the lint is the smaller
    /// half of the reason. The two references are both `[u8; 32]` and sat side
    /// by side in the return position, which is exactly the shape that lets a
    /// caller take them in the wrong order with nothing to notice — neither the
    /// compiler nor a reader. Field names are what close that, and the type is
    /// what makes the names unavoidable.
    struct BoundTestStore {
        store: ContractsSessionStoreV1,
        local_key_reference: [u8; 32],
        remote_key_reference: [u8; 32],
    }

    fn create_bound_store(
        parent: Arc<Dir>,
        name: &str,
        identity: &dom_scriptless_identity_store::ContractsTransportIdentityReferenceV1,
        placement: IdentityPlacement,
        chain: TrustedChainIdV1,
    ) -> Result<BoundTestStore, Box<dyn Error>> {
        let store = ContractsSessionStoreV1::create_production(parent, name, production_policy()?)?;
        store.create_session(&initial_record(SESSION)?)?;
        let TransportKeyReferences {
            local_key_reference,
            remote_key_reference,
        } = bind_session_transport(
            &store,
            identity,
            placement,
            chain,
            TestTransportScope {
                session_id: SESSION,
                local: LOCAL,
                remote: REMOTE,
                local_is_initiator: true,
            },
        )?;
        Ok(BoundTestStore {
            store,
            local_key_reference,
            remote_key_reference,
        })
    }

    /// The two transport key references a bound session ends up with.
    ///
    /// **There is no lint behind this one, and that is the point of writing it
    /// down.** `BoundTestStore` above was named because Clippy refused a
    /// three-element tuple as too complex; this return was a two-element tuple
    /// and no lint reaches it. The reason is the same either way and has
    /// nothing to do with either lint: both values are `[u8; 32]`, they sat
    /// side by side and anonymous, and this is where they are born — so a
    /// caller taking them in the wrong order compiled, read correctly, and was
    /// wrong. One caller already discarded the second and kept the first by
    /// position alone.
    ///
    /// Naming the fields is what closes it. If a future edit finds a reason to
    /// go back to a tuple here, the reason has to beat that one.
    struct TransportKeyReferences {
        local_key_reference: [u8; 32],
        remote_key_reference: [u8; 32],
    }

    fn bind_session_transport(
        store: &ContractsSessionStoreV1,
        identity: &dom_scriptless_identity_store::ContractsTransportIdentityReferenceV1,
        placement: IdentityPlacement,
        chain: TrustedChainIdV1,
        scope: TestTransportScope,
    ) -> Result<TransportKeyReferences, Box<dyn Error>> {
        let identity_public = PublicKey::from_compressed_bytes(identity.schnorr_public_key())?;
        let alternate_local = SecretKey::from_bytes(&[0x21; 32])?.public_key();
        let alternate_remote = SecretKey::from_bytes(&[0x22; 32])?.public_key();
        let (local_public, remote_public) = match placement {
            IdentityPlacement::Local => (identity_public, alternate_remote),
            IdentityPlacement::Remote => (alternate_local, identity_public),
            IdentityPlacement::Absent => (alternate_local, alternate_remote),
        };
        let local_direction = if scope.local_is_initiator {
            DirectionV1::Initiator
        } else {
            DirectionV1::Responder
        };
        let remote_direction = if scope.local_is_initiator {
            DirectionV1::Responder
        } else {
            DirectionV1::Initiator
        };
        let local_transport = SessionTransportParticipantV1::new(
            scope.local.0,
            local_public.clone(),
            local_direction,
        )?;
        let remote_transport = SessionTransportParticipantV1::new(
            scope.remote.0,
            remote_public.clone(),
            remote_direction,
        )?;
        let local_fallback = SessionTransportIdentityReferenceV1::new(
            scope.local.0,
            [0x41; 32],
            [0x42; 32],
            local_public,
        )?;
        let remote_fallback = SessionTransportIdentityReferenceV1::new(
            scope.remote.0,
            [0x51; 32],
            [0x52; 32],
            remote_public,
        )?;
        let local_reference = match placement {
            IdentityPlacement::Local => identity.bind_session_participant(scope.local.0)?,
            IdentityPlacement::Remote | IdentityPlacement::Absent => local_fallback,
        };
        let remote_reference = match placement {
            IdentityPlacement::Remote => identity.bind_session_participant(scope.remote.0)?,
            IdentityPlacement::Local | IdentityPlacement::Absent => remote_fallback,
        };
        let local_key_reference = *local_reference.key_reference();
        let remote_key_reference = *remote_reference.key_reference();
        let (participants, references) = if scope.local_is_initiator {
            (
                [local_transport, remote_transport],
                [local_reference, remote_reference],
            )
        } else {
            (
                [remote_transport, local_transport],
                [remote_reference, local_reference],
            )
        };
        store.bind_transport_roster(scope.session_id, *chain.as_bytes(), participants)?;
        store.bind_transport_identity_references(scope.session_id, references)?;
        Ok(TransportKeyReferences {
            local_key_reference,
            remote_key_reference,
        })
    }

    fn prepare_abort_request(
        store: &ContractsSessionStoreV1,
        chain: TrustedChainIdV1,
        session_id: [u8; 32],
        decision_digest: [u8; 32],
    ) -> Result<PreparedDsc1SigningRequestV1, Box<dyn Error>> {
        let authority = store.prepare_operational_abort_transport_authority(
            chain,
            session_id,
            decision_digest,
        )?;
        store
            .prepare_abort_dsc1_signing_request(&authority)?
            .ok_or_else(|| Box::<dyn Error>::from(SessionStoreError::InvalidTransition))
    }

    fn xonly(secret: &[u8; 32]) -> [u8; 32] {
        SecpContext::new(&[0x19; 32])
            .sign_bip340(secret, &[0; 32], &[0; 32])
            .expect("public test Relay secret")
            .1
    }

    fn wire() -> RouteWireContextV1 {
        RouteWireContextV1 {
            network_id: [0x11; 32],
            session_id: SESSION,
            route_id: [0x12; 32],
            roster_snapshot: [0x13; 32],
            policy_version: 1,
        }
    }

    fn relay_config(signer_xonly: [u8; 32]) -> Result<RelayWorkerConfigV1, Box<dyn Error>> {
        relay_config_for(LOCAL, REMOTE, SenderRoleV1::Initiator, signer_xonly)
    }

    fn relay_config_for(
        local: ParticipantId,
        remote: ParticipantId,
        local_role: SenderRoleV1,
        signer_xonly: [u8; 32],
    ) -> Result<RelayWorkerConfigV1, Box<dyn Error>> {
        let sender = DurableRelaySenderConfigV1::new(
            [0x14; 32],
            wire(),
            local,
            remote,
            local_role,
            signer_xonly,
            128,
        )?;
        let inbox = DurableInboxConfigV1::new([0x15; 32], [0xd1; 32], wire(), local, 128)?;
        let frames = DurableFrameReassemblerConfigV2::new(
            [0x16; 32],
            wire(),
            local,
            16,
            2 * 1024 * 1024,
            128,
        )?;
        let pins = crate::production_config::ProductionRelayAuthorityPinsV6 {
            relay_database_id: [0xd1; 32],
            upstream_sender_store_id: [0x14; 32],
            upstream_inbox_id: [0x15; 32],
            upstream_reassembler_id: [0x16; 32],
            downstream_sender_store_id: [0x17; 32],
            downstream_inbox_id: [0x18; 32],
            downstream_reassembler_id: [0x19; 32],
            relay_max_envelopes: 256,
            sender_max_envelopes: 128,
            inbox_max_entries: 128,
            frame_max_messages: 16,
            frame_max_active_bytes: 2 * 1024 * 1024,
            frame_max_active_chunks: 128,
        };
        Ok(RelayWorkerConfigV1::new_production_v6(
            sender,
            inbox,
            frames,
            pins,
            LegIdV1::Upstream,
        )?)
    }

    fn relay_rosters(local_xonly: [u8; 32]) -> RosterRegistryV1 {
        relay_rosters_for(
            LOCAL,
            REMOTE,
            SenderRoleV1::Initiator,
            local_xonly,
            xonly(&REMOTE_RELAY_SECRET),
        )
    }

    fn relay_rosters_for(
        local: ParticipantId,
        remote: ParticipantId,
        local_role: SenderRoleV1,
        local_xonly: [u8; 32],
        remote_xonly: [u8; 32],
    ) -> RosterRegistryV1 {
        let remote_role = match local_role {
            SenderRoleV1::Initiator => SenderRoleV1::Solver,
            SenderRoleV1::Solver | SenderRoleV1::Observer => SenderRoleV1::Initiator,
        };
        RosterRegistryV1::new().with_snapshot(
            wire().roster_snapshot,
            RosterSnapshotV1::new()
                .with_member(
                    local,
                    RosterMemberV1 {
                        xonly_key: local_xonly,
                        role: local_role,
                    },
                )
                .with_member(
                    remote,
                    RosterMemberV1 {
                        xonly_key: remote_xonly,
                        role: remote_role,
                    },
                ),
        )
    }

    fn expiry() -> TimelockSpec {
        TimelockSpec::BlockHeight { value: 10_000 }
    }
}

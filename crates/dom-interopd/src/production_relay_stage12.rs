//! Stage-12 production ownership for the central Relay and both Contracts workers.
//!
//! Stage 10 hands this module the only two physical Contracts Store openings and
//! their linear early-ingress authorities. Stage 11 hands it the two real F6
//! activation authorities. This boundary derives every Relay fact again from
//! the authenticated V8 inputs, opens the seven Relay authorities in their
//! canonical order, and then embeds each Store in exactly one
//! [`ProductionContractsV1`] owner.
//!
//! Construction deliberately does not complete the provisioning journal. The
//! returned value remains opaque until both retained F6 histories have been
//! reauthenticated, the caller has durably completed Stage 12, and
//! [`ProductionRelayStage12RecoveredV1::finish`] has re-read that fact from the
//! same journal.

use std::{path::Path, rc::Rc};

use dom_adaptor::{SharedBlindingBindingV1, TrustedChainIdV1};
use dom_scriptless_chain_adapter::DomHttpChainAdapterV1;
use dom_scriptless_identity_store::ContractsTransportIdentityStoreV1;
use dom_scriptless_store::SessionTransportIdentityReferenceV1;
use kaystra_core::types::ParticipantId;
use relay::{
    production::{
        ProductionRelayCreationStateV1, ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1,
    },
    SenderRoleV1,
};
use rfq::v2::SettlementPositionV2;
use route_executor::LegIdV1;
use route_transport::{
    DurableFrameReassemblerConfigV2, DurableInboxConfigV1, DurableRelaySenderConfigV1,
    RouteWireContextV1,
};
use zeroize::Zeroizing;

use crate::{
    production_chain_signers::ProductionChainSignerAuthoritiesV1,
    production_config::{
        ProductionPathRoleV1, ProductionRelayAuthorityPinsV6, ValidatedProductionBootstrapV1,
        ValidatedProductionLayoutV1,
    },
    production_contracts::ProductionContractsV1,
    production_contracts_session_bootstrap::{
        ProductionContractsSessionBootstrapV1, ProductionContractsSessionLegBootstrapV1,
    },
    production_f6_activation::ProductionF6PairActivationAuthorityV2,
    production_f6_activation::{ProductionF6PairProvenanceV2, ProductionF6PairRuntimeReceiverV2},
    production_f6_lifecycle::{ProductionAwaitingF6PinsV2, ProductionF6LifecyclePortV2},
    production_inputs::{
        AuthenticatedProductionInputsV1, ProductionRosterLegV1, ProductionRoutePositionV1,
    },
    production_provisioning::{
        DurableProductionProvisioningJournalV1, ProductionProvisioningStageStateV1,
        ProductionProvisioningStageV1,
    },
    relay_worker::{PreparedContractsIngressV1, RelayWorkerConfigV1, RelayWorkerPathsV1},
};

/// Stage-12 open intent supplied by the composition root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionRelayStage12ModeV1 {
    /// Provision or resume only a pristine journaled creation prefix.
    CreateOrResume,
    /// Reopen only the complete retained authorities.
    ReopenExisting,
}

/// Redacted Stage-12 refusal. No variant carries a path, key, roster member or
/// nested storage error into the operator-facing surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionRelayStage12ErrorV1 {
    #[error("authenticated Stage-12 Relay binding is inconsistent")]
    InvalidBinding,
    #[error("Stage-12 provisioning state is inconsistent")]
    ProvisioningRefused,
    #[error("central production Relay authority is unavailable")]
    RelayRefused,
    #[error("production Contracts/Relay owner is unavailable")]
    ContractsRefused,
    #[error("production F6 lifecycle authority is unavailable")]
    F6Refused,
}

/// Move-only Stage-12 construction request.
///
/// The relay signing secrets remain zeroizing owners until the exact
/// `ProductionContractsV1` constructors consume their unavoidable fixed-size
/// copies. No secret is retained in the returned owner.
pub(crate) struct ProductionRelayStage12RequestV1<'authority> {
    pub(crate) bootstrap: &'authority ValidatedProductionBootstrapV1,
    pub(crate) inputs: &'authority AuthenticatedProductionInputsV1,
    pub(crate) chain_signers: &'authority ProductionChainSignerAuthoritiesV1,
    pub(crate) contracts: ProductionContractsSessionBootstrapV1,
    pub(crate) upstream_activation: ProductionF6PairActivationAuthorityV2,
    pub(crate) downstream_activation: ProductionF6PairActivationAuthorityV2,
    pub(crate) upstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    pub(crate) downstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    pub(crate) mode: ProductionRelayStage12ModeV1,
    pub(crate) stage_before_begin: ProductionProvisioningStageStateV1,
    pub(crate) stage: ProductionProvisioningStageStateV1,
}

/// One live Contracts owner and the exact public material retained beside it.
///
/// Fields remain private so later stages cannot bypass the single owner with a
/// raw Store reopen or reconstruct Noise identities from caller-shaped bytes.
pub(crate) struct ProductionRelayStage12LegOwnerV1 {
    contracts: ProductionContractsV1<ProductionF6LifecyclePortV2>,
    wire: RouteWireContextV1,
    trusted_chain_id: TrustedChainIdV1,
    shared_blinding_bindings: [SharedBlindingBindingV1; 2],
    noise_identity_references: [SessionTransportIdentityReferenceV1; 2],
    f6_pair_provenance: ProductionF6PairProvenanceV2,
}

impl ProductionRelayStage12LegOwnerV1 {
    pub(crate) const fn wire(&self) -> RouteWireContextV1 {
        self.wire
    }

    pub(crate) const fn trusted_chain_id(&self) -> TrustedChainIdV1 {
        self.trusted_chain_id
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn shared_blinding_bindings(&self) -> &[SharedBlindingBindingV1; 2] {
        &self.shared_blinding_bindings
    }

    /// Local reference first, exact remote reference second. Both values came
    /// from the retained Store after Stage-10 convergence.
    pub(crate) const fn noise_identity_references(
        &self,
    ) -> &[SessionTransportIdentityReferenceV1; 2] {
        &self.noise_identity_references
    }

    pub(crate) fn contracts_mut(
        &mut self,
    ) -> &mut ProductionContractsV1<ProductionF6LifecyclePortV2> {
        &mut self.contracts
    }
}

/// Sole live owner produced by Stage 12.
///
/// It intentionally implements neither `Clone` nor `Debug`. The central Relay,
/// both Contracts workers, the shared transport identity and the live DOM
/// adapter cannot be separated into independently reopened graphs.
pub(crate) struct ProductionRelayStage12OwnerV1 {
    relay: ProductionRelayV1,
    identity: Rc<ContractsTransportIdentityStoreV1>,
    dom_chain_adapter: Option<DomHttpChainAdapterV1>,
    upstream: ProductionRelayStage12LegOwnerV1,
    downstream: ProductionRelayStage12LegOwnerV1,
    initial_relay_time_floor_seconds: u64,
}

impl ProductionRelayStage12OwnerV1 {
    /// Proves that the retained pair receiver was minted by the exact split
    /// whose two activation handles were installed into these two legs.
    pub(crate) fn matches_f6_pair_receiver(
        &self,
        receiver: &ProductionF6PairRuntimeReceiverV2,
    ) -> bool {
        receiver.matches_provenance(&self.upstream.f6_pair_provenance)
            && receiver.matches_provenance(&self.downstream.f6_pair_provenance)
            && self
                .upstream
                .f6_pair_provenance
                .matches(&self.downstream.f6_pair_provenance)
    }

    /// Durable rollback floor from the authenticated composition anchor and
    /// both retained Relay inbox journals.
    pub(crate) fn retained_relay_timestamp_floor(
        &self,
    ) -> Result<u64, ProductionRelayStage12ErrorV1> {
        let upstream = self
            .upstream
            .contracts
            .retained_relay_timestamp_floor()
            .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
        let downstream = self
            .downstream
            .contracts
            .retained_relay_timestamp_floor()
            .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
        Ok(self
            .initial_relay_time_floor_seconds
            .max(upstream.unwrap_or(0))
            .max(downstream.unwrap_or(0)))
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn identity(&self) -> &ContractsTransportIdentityStoreV1 {
        self.identity.as_ref()
    }

    pub(crate) const fn leg(&self, leg: LegIdV1) -> &ProductionRelayStage12LegOwnerV1 {
        match leg {
            LegIdV1::Upstream => &self.upstream,
            LegIdV1::Downstream => &self.downstream,
        }
    }

    pub(crate) fn leg_mut(&mut self, leg: LegIdV1) -> &mut ProductionRelayStage12LegOwnerV1 {
        match leg {
            LegIdV1::Upstream => &mut self.upstream,
            LegIdV1::Downstream => &mut self.downstream,
        }
    }

    pub(crate) const fn relay(&self) -> &ProductionRelayV1 {
        &self.relay
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn relay_mut(&mut self) -> &mut ProductionRelayV1 {
        &mut self.relay
    }

    /// Joint borrow used by one authenticated Noise exchange. Keeping this
    /// operation on the sole Stage-12 owner prevents callers from reopening
    /// either authority merely to satisfy Rust's borrowing rules.
    pub(crate) fn identity_and_relay_mut(
        &mut self,
    ) -> (&ContractsTransportIdentityStoreV1, &mut ProductionRelayV1) {
        (self.identity.as_ref(), &mut self.relay)
    }

    /// Joint borrow used by one bounded upstream poll without splitting the
    /// central Relay from the Contracts owner that consumes its mailbox.
    pub(crate) fn upstream_and_relay_mut(
        &mut self,
    ) -> (
        &mut ProductionContractsV1<ProductionF6LifecyclePortV2>,
        &mut ProductionRelayV1,
    ) {
        (&mut self.upstream.contracts, &mut self.relay)
    }

    /// Joint borrow used by one bounded downstream poll without splitting the
    /// central Relay from the Contracts owner that consumes its mailbox.
    pub(crate) fn downstream_and_relay_mut(
        &mut self,
    ) -> (
        &mut ProductionContractsV1<ProductionF6LifecyclePortV2>,
        &mut ProductionRelayV1,
    ) {
        (&mut self.downstream.contracts, &mut self.relay)
    }

    /// Transfers the sole live adapter into the later child/runtime graph.
    /// A second request fails closed rather than fabricating another observer.
    pub(crate) fn take_dom_chain_adapter(
        &mut self,
    ) -> Result<DomHttpChainAdapterV1, ProductionRelayStage12ErrorV1> {
        self.dom_chain_adapter
            .take()
            .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)
    }
}

/// Fully constructed but not yet journal-authorized Stage-12 graph.
///
/// There is intentionally no owner accessor. The composition root must first
/// durably complete `RelayAuthorities`, then call `finish` with that same
/// retained journal.
pub(crate) struct ProductionRelayStage12ConstructedV1 {
    owner: ProductionRelayStage12OwnerV1,
}

impl ProductionRelayStage12ConstructedV1 {
    /// Reauthenticate both retained F6 applied histories before the caller is
    /// allowed to complete the Stage-12 journal.
    ///
    /// This consumes the constructed typestate. A failure therefore exposes
    /// neither inbound polling nor the finished owner, while a retry must
    /// reopen/resume the same physical authorities through the journaled
    /// Stage-12 path.
    pub(crate) fn recover_production_f6_applied_history(
        self,
    ) -> Result<ProductionRelayStage12RecoveredV1, ProductionRelayStage12ErrorV1> {
        self.owner
            .upstream
            .contracts
            .recover_production_f6_applied_history()
            .map_err(|_| ProductionRelayStage12ErrorV1::F6Refused)?;
        self.owner
            .downstream
            .contracts
            .recover_production_f6_applied_history()
            .map_err(|_| ProductionRelayStage12ErrorV1::F6Refused)?;
        Ok(ProductionRelayStage12RecoveredV1 { owner: self.owner })
    }
}

/// Stage-12 graph whose two F6 histories were reauthenticated on the exact
/// retained Contracts/Relay owners.
///
/// Only this typestate can consume a completed provisioning journal into the
/// live owner, making recovery-before-completion mandatory at the API level.
pub(crate) struct ProductionRelayStage12RecoveredV1 {
    owner: ProductionRelayStage12OwnerV1,
}

impl ProductionRelayStage12RecoveredV1 {
    pub(crate) fn finish(
        self,
        journal: &DurableProductionProvisioningJournalV1,
    ) -> Result<ProductionRelayStage12OwnerV1, ProductionRelayStage12ErrorV1> {
        if journal
            .stage_state(ProductionProvisioningStageV1::RelayAuthorities)
            .map_err(|_| ProductionRelayStage12ErrorV1::ProvisioningRefused)?
            != ProductionProvisioningStageStateV1::Complete
        {
            return Err(ProductionRelayStage12ErrorV1::ProvisioningRefused);
        }
        Ok(self.owner)
    }
}

struct PreparedStage12LegV1 {
    bootstrap: ProductionContractsSessionLegBootstrapV1,
    paths: RelayWorkerPathsV1,
    config: RelayWorkerConfigV1,
    rosters: relay::auth::RosterRegistryV1,
    lifecycle: ProductionF6LifecyclePortV2,
    wire: RouteWireContextV1,
    noise_identity_references: [SessionTransportIdentityReferenceV1; 2],
    f6_pair_provenance: ProductionF6PairProvenanceV2,
}

#[derive(Clone, Copy)]
enum AuthorityOpenModeV1 {
    Create,
    ResumeCreate,
    OpenExisting,
}

/// Construct the central Relay and the two Store-sharing Contracts owners.
///
/// Every pure binding check is completed before the Relay queue is touched.
/// Durable effects then occur only in this order: central Relay, upstream
/// sender/inbox/frames, upstream early ingress, downstream
/// sender/inbox/frames, downstream early ingress.
pub(crate) fn construct_production_relay_stage12_v1(
    request: ProductionRelayStage12RequestV1<'_>,
) -> Result<ProductionRelayStage12ConstructedV1, ProductionRelayStage12ErrorV1> {
    let ProductionRelayStage12RequestV1 {
        bootstrap,
        inputs,
        chain_signers,
        contracts,
        upstream_activation,
        downstream_activation,
        upstream_relay_signing_secret,
        downstream_relay_signing_secret,
        mode,
        stage_before_begin,
        stage,
    } = request;
    let open_mode = authority_open_mode(mode, stage_before_begin, stage)?;
    let relay_pins = bootstrap
        .config()
        .relay_authority_pins_v6()
        .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let roster_bundle = inputs.roster_bundle();
    if roster_bundle.network_id() != bootstrap.config().pins().network_id
        || roster_bundle.route_id() != bootstrap.config().pins().route_id
        || chain_signers.participant_id().0 == [0; 32]
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }

    let ProductionContractsSessionBootstrapV1 {
        dom_chain_adapter,
        identity,
        upstream,
        downstream,
    } = contracts;
    let upstream = prepare_leg(
        LegIdV1::Upstream,
        &roster_bundle.legs()[0],
        bootstrap.layout(),
        relay_pins,
        inputs,
        chain_signers,
        upstream,
        upstream_activation,
    )?;
    let downstream = prepare_leg(
        LegIdV1::Downstream,
        &roster_bundle.legs()[1],
        bootstrap.layout(),
        relay_pins,
        inputs,
        chain_signers,
        downstream,
        downstream_activation,
    )?;
    if upstream.wire.network_id != downstream.wire.network_id
        || upstream.wire.route_id != downstream.wire.route_id
        || upstream.wire.session_id == downstream.wire.session_id
        || upstream.wire.roster_snapshot == downstream.wire.roster_snapshot
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }

    let relay_config = relay_database_config(relay_pins)?;
    let relay = open_central_relay(
        open_mode,
        bootstrap.layout().path(ProductionPathRoleV1::RelayQueue),
        relay_config,
    )?;
    let upstream = open_leg(
        open_mode,
        Rc::clone(&identity),
        upstream,
        upstream_relay_signing_secret,
    )?;
    let downstream = open_leg(
        open_mode,
        Rc::clone(&identity),
        downstream,
        downstream_relay_signing_secret,
    )?;

    Ok(ProductionRelayStage12ConstructedV1 {
        owner: ProductionRelayStage12OwnerV1 {
            relay,
            identity,
            dom_chain_adapter: Some(dom_chain_adapter),
            upstream,
            downstream,
            initial_relay_time_floor_seconds: inputs
                .composition()
                .time_proof_validated_at_seconds(),
        },
    })
}

fn authority_open_mode(
    mode: ProductionRelayStage12ModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
) -> Result<AuthorityOpenModeV1, ProductionRelayStage12ErrorV1> {
    match (mode, stage_before_begin, stage) {
        (
            ProductionRelayStage12ModeV1::CreateOrResume,
            ProductionProvisioningStageStateV1::Absent,
            ProductionProvisioningStageStateV1::Started,
        ) => Ok(AuthorityOpenModeV1::Create),
        (
            ProductionRelayStage12ModeV1::CreateOrResume,
            ProductionProvisioningStageStateV1::Started,
            ProductionProvisioningStageStateV1::Started,
        ) => Ok(AuthorityOpenModeV1::ResumeCreate),
        (
            ProductionRelayStage12ModeV1::CreateOrResume
            | ProductionRelayStage12ModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
            ProductionProvisioningStageStateV1::Complete,
        ) => Ok(AuthorityOpenModeV1::OpenExisting),
        _ => Err(ProductionRelayStage12ErrorV1::ProvisioningRefused),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
)]
fn prepare_leg(
    leg: LegIdV1,
    roster_leg: &ProductionRosterLegV1,
    layout: &ValidatedProductionLayoutV1,
    relay_pins: ProductionRelayAuthorityPinsV6,
    inputs: &AuthenticatedProductionInputsV1,
    chain_signers: &ProductionChainSignerAuthoritiesV1,
    bootstrap: ProductionContractsSessionLegBootstrapV1,
    activation: ProductionF6PairActivationAuthorityV2,
) -> Result<PreparedStage12LegV1, ProductionRelayStage12ErrorV1> {
    let expected_position = match leg {
        LegIdV1::Upstream => ProductionRoutePositionV1::Upstream,
        LegIdV1::Downstream => ProductionRoutePositionV1::Downstream,
    };
    if roster_leg.position != expected_position {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }
    let local = chain_signers.participant_id();
    let mut local_member = None;
    let mut remote_member = None;
    for member in roster_leg.members {
        if member.participant_id == local {
            if local_member.replace(member).is_some() {
                return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
            }
        } else if remote_member.replace(member).is_some() {
            return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
        }
    }
    let local_member = local_member.ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let remote_member = remote_member.ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let roles_are_exact = matches!(
        (local_member.role, remote_member.role),
        (SenderRoleV1::Initiator, SenderRoleV1::Solver)
            | (SenderRoleV1::Solver, SenderRoleV1::Initiator)
    );
    if !roles_are_exact
        || local_member.role != chain_signers.relay_role()
        || local_member.xonly_key != chain_signers.relay_xonly_key(leg)
        || local_member.xonly_key == remote_member.xonly_key
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }

    let wire = RouteWireContextV1 {
        network_id: inputs.roster_bundle().network_id(),
        session_id: roster_leg.session_id,
        route_id: inputs.roster_bundle().route_id(),
        roster_snapshot: roster_leg.roster_snapshot,
        policy_version: roster_leg.policy_version,
    };
    let (sender_store_id, inbox_id, reassembler_id, sender_path, inbox_path, frames_path) =
        leg_relay_facts(leg, layout, relay_pins);
    let sender = DurableRelaySenderConfigV1::new(
        sender_store_id,
        wire,
        local,
        remote_member.participant_id,
        local_member.role,
        local_member.xonly_key,
        relay_pins.sender_max_envelopes,
    )
    .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let inbox = DurableInboxConfigV1::new(
        inbox_id,
        relay_pins.relay_database_id,
        wire,
        local,
        relay_pins.inbox_max_entries,
    )
    .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let frames = DurableFrameReassemblerConfigV2::new(
        reassembler_id,
        wire,
        local,
        relay_pins.frame_max_messages,
        relay_pins.frame_max_active_bytes,
        relay_pins.frame_max_active_chunks,
    )
    .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let config = RelayWorkerConfigV1::new_production_v6(sender, inbox, frames, relay_pins, leg)
        .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let initiator = if local_member.role == SenderRoleV1::Initiator {
        local
    } else {
        remote_member.participant_id
    };
    let position = match leg {
        LegIdV1::Upstream => SettlementPositionV2::Upstream,
        LegIdV1::Downstream => SettlementPositionV2::Downstream,
    };
    let pins = ProductionAwaitingF6PinsV2::new(wire, position, initiator)
        .map_err(|_| ProductionRelayStage12ErrorV1::F6Refused)?;
    let f6_pair_provenance = activation.provenance();
    let mut lifecycle = ProductionF6LifecyclePortV2::awaiting(pins);
    lifecycle
        .install_activation_authority(activation)
        .map_err(|_| ProductionRelayStage12ErrorV1::F6Refused)?;

    let references = bootstrap
        .store
        .transport_identity_references(wire.session_id)
        .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
    let noise_identity_references =
        order_identity_references(references, local, remote_member.participant_id)?;
    Ok(PreparedStage12LegV1 {
        bootstrap,
        paths: RelayWorkerPathsV1::new(sender_path, inbox_path, frames_path),
        config,
        rosters: inputs.roster_registry().clone(),
        lifecycle,
        wire,
        noise_identity_references,
        f6_pair_provenance,
    })
}

fn leg_relay_facts(
    leg: LegIdV1,
    layout: &ValidatedProductionLayoutV1,
    pins: ProductionRelayAuthorityPinsV6,
) -> ([u8; 32], [u8; 32], [u8; 32], &Path, &Path, &Path) {
    match leg {
        LegIdV1::Upstream => (
            pins.upstream_sender_store_id,
            pins.upstream_inbox_id,
            pins.upstream_reassembler_id,
            layout.path(ProductionPathRoleV1::UpstreamRelaySender),
            layout.path(ProductionPathRoleV1::UpstreamRelayInbox),
            layout.path(ProductionPathRoleV1::UpstreamRelayFrames),
        ),
        LegIdV1::Downstream => (
            pins.downstream_sender_store_id,
            pins.downstream_inbox_id,
            pins.downstream_reassembler_id,
            layout.path(ProductionPathRoleV1::DownstreamRelaySender),
            layout.path(ProductionPathRoleV1::DownstreamRelayInbox),
            layout.path(ProductionPathRoleV1::DownstreamRelayFrames),
        ),
    }
}

fn order_identity_references(
    references: [SessionTransportIdentityReferenceV1; 2],
    local: ParticipantId,
    remote: ParticipantId,
) -> Result<[SessionTransportIdentityReferenceV1; 2], ProductionRelayStage12ErrorV1> {
    if local == remote
        || references
            .iter()
            .filter(|reference| reference.participant_id() == &local.0)
            .count()
            != 1
        || references
            .iter()
            .filter(|reference| reference.participant_id() == &remote.0)
            .count()
            != 1
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }
    let local_reference = references
        .iter()
        .find(|reference| reference.participant_id() == &local.0)
        .cloned()
        .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    let remote_reference = references
        .iter()
        .find(|reference| reference.participant_id() == &remote.0)
        .cloned()
        .ok_or(ProductionRelayStage12ErrorV1::InvalidBinding)?;
    if local_reference.key_reference() == remote_reference.key_reference()
        || local_reference.noise_public_key() == remote_reference.noise_public_key()
    {
        return Err(ProductionRelayStage12ErrorV1::InvalidBinding);
    }
    Ok([local_reference, remote_reference])
}

fn relay_database_config(
    pins: ProductionRelayAuthorityPinsV6,
) -> Result<RelayDatabaseConfigV1, ProductionRelayStage12ErrorV1> {
    let id = RelayDatabaseIdV1::new(pins.relay_database_id)
        .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)?;
    RelayDatabaseConfigV1::new(id, pins.relay_max_envelopes)
        .map_err(|_| ProductionRelayStage12ErrorV1::InvalidBinding)
}

fn open_central_relay(
    mode: AuthorityOpenModeV1,
    root: &Path,
    config: RelayDatabaseConfigV1,
) -> Result<ProductionRelayV1, ProductionRelayStage12ErrorV1> {
    let relay = match mode {
        AuthorityOpenModeV1::Create => ProductionRelayV1::create(root, config),
        AuthorityOpenModeV1::ResumeCreate => {
            match ProductionRelayV1::production_creation_state(root, config)
                .map_err(|_| ProductionRelayStage12ErrorV1::RelayRefused)?
            {
                ProductionRelayCreationStateV1::Missing => ProductionRelayV1::create(root, config),
                ProductionRelayCreationStateV1::Incomplete
                | ProductionRelayCreationStateV1::InitializedPristine => {
                    ProductionRelayV1::resume_create_production(root, config)
                }
            }
        }
        AuthorityOpenModeV1::OpenExisting => ProductionRelayV1::open(root, config),
    };
    relay.map_err(|_| ProductionRelayStage12ErrorV1::RelayRefused)
}

fn open_leg(
    mode: AuthorityOpenModeV1,
    identity: Rc<ContractsTransportIdentityStoreV1>,
    prepared: PreparedStage12LegV1,
    signing_secret: Zeroizing<[u8; 32]>,
) -> Result<ProductionRelayStage12LegOwnerV1, ProductionRelayStage12ErrorV1> {
    let PreparedStage12LegV1 {
        bootstrap,
        paths,
        config,
        rosters,
        lifecycle,
        wire,
        noise_identity_references,
        f6_pair_provenance,
    } = prepared;
    let ProductionContractsSessionLegBootstrapV1 {
        store,
        trusted_chain_id,
        shared_blinding_bindings,
        early_transport_authority,
    } = bootstrap;
    let mut contracts = match mode {
        AuthorityOpenModeV1::Create => ProductionContractsV1::create(
            store,
            identity,
            &paths,
            config,
            rosters,
            lifecycle,
            *signing_secret,
        ),
        AuthorityOpenModeV1::ResumeCreate => ProductionContractsV1::resume_create_production(
            store,
            identity,
            &paths,
            config,
            rosters,
            lifecycle,
            *signing_secret,
        ),
        AuthorityOpenModeV1::OpenExisting => ProductionContractsV1::open_existing(
            store,
            identity,
            &paths,
            config,
            rosters,
            lifecycle,
            *signing_secret,
        ),
    }
    .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
    contracts
        .install_contracts_ingress(PreparedContractsIngressV1::early(early_transport_authority))
        .map_err(|_| ProductionRelayStage12ErrorV1::ContractsRefused)?;
    Ok(ProductionRelayStage12LegOwnerV1 {
        contracts,
        wire,
        trusted_chain_id,
        shared_blinding_bindings,
        noise_identity_references,
        f6_pair_provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::SecretKey;

    #[test]
    fn authority_open_mode_accepts_only_journal_consistent_transitions() {
        let modes = [
            ProductionRelayStage12ModeV1::CreateOrResume,
            ProductionRelayStage12ModeV1::ReopenExisting,
        ];
        let states = [
            ProductionProvisioningStageStateV1::Absent,
            ProductionProvisioningStageStateV1::Started,
            ProductionProvisioningStageStateV1::Complete,
        ];
        for mode in modes {
            for before in states {
                for current in states {
                    let accepted = matches!(
                        (mode, before, current),
                        (
                            ProductionRelayStage12ModeV1::CreateOrResume,
                            ProductionProvisioningStageStateV1::Absent,
                            ProductionProvisioningStageStateV1::Started,
                        ) | (
                            ProductionRelayStage12ModeV1::CreateOrResume,
                            ProductionProvisioningStageStateV1::Started,
                            ProductionProvisioningStageStateV1::Started,
                        ) | (
                            ProductionRelayStage12ModeV1::CreateOrResume
                                | ProductionRelayStage12ModeV1::ReopenExisting,
                            ProductionProvisioningStageStateV1::Complete,
                            ProductionProvisioningStageStateV1::Complete,
                        )
                    );
                    assert_eq!(
                        authority_open_mode(mode, before, current).is_ok(),
                        accepted,
                        "unexpected Stage-12 journal transition acceptance"
                    );
                }
            }
        }
    }

    #[test]
    fn identity_references_are_local_first_and_refuse_transplants() {
        let local = ParticipantId([0x41; 32]);
        let remote = ParticipantId([0x42; 32]);
        let foreign = ParticipantId([0x43; 32]);
        let local_reference = identity_reference(local, 0x51, 0x61, 1);
        let remote_reference = identity_reference(remote, 0x52, 0x62, 2);
        let ordered = order_identity_references(
            [remote_reference.clone(), local_reference.clone()],
            local,
            remote,
        )
        .expect("authenticated references must be reordered local-first");
        assert_eq!(ordered[0].participant_id(), &local.0);
        assert_eq!(ordered[1].participant_id(), &remote.0);

        let participant_transplant = identity_reference(foreign, 0x53, 0x63, 3);
        assert_eq!(
            order_identity_references(
                [local_reference.clone(), participant_transplant],
                local,
                remote,
            )
            .err(),
            Some(ProductionRelayStage12ErrorV1::InvalidBinding)
        );

        let duplicate_local = identity_reference(local, 0x54, 0x64, 4);
        assert_eq!(
            order_identity_references([local_reference.clone(), duplicate_local], local, remote,)
                .err(),
            Some(ProductionRelayStage12ErrorV1::InvalidBinding)
        );

        let key_reference_transplant = SessionTransportIdentityReferenceV1::new(
            remote.0,
            *local_reference.key_reference(),
            [0x65; 32],
            SecretKey::from_bytes(&[5; 32])
                .expect("valid test secret")
                .public_key(),
        )
        .expect("public test identity reference");
        assert_eq!(
            order_identity_references(
                [local_reference.clone(), key_reference_transplant],
                local,
                remote,
            )
            .err(),
            Some(ProductionRelayStage12ErrorV1::InvalidBinding)
        );

        let noise_key_transplant = SessionTransportIdentityReferenceV1::new(
            remote.0,
            [0x55; 32],
            *local_reference.noise_public_key(),
            SecretKey::from_bytes(&[6; 32])
                .expect("valid test secret")
                .public_key(),
        )
        .expect("public test identity reference");
        assert_eq!(
            order_identity_references([local_reference, noise_key_transplant], local, remote).err(),
            Some(ProductionRelayStage12ErrorV1::InvalidBinding)
        );
    }

    #[test]
    fn constructed_owner_requires_f6_recovery_typestate_before_finish() {
        let _recover: fn(
            ProductionRelayStage12ConstructedV1,
        ) -> Result<
            ProductionRelayStage12RecoveredV1,
            ProductionRelayStage12ErrorV1,
        > = ProductionRelayStage12ConstructedV1::recover_production_f6_applied_history;
        let _finish: fn(
            ProductionRelayStage12RecoveredV1,
            &DurableProductionProvisioningJournalV1,
        )
            -> Result<ProductionRelayStage12OwnerV1, ProductionRelayStage12ErrorV1> =
            ProductionRelayStage12RecoveredV1::finish;
    }

    fn identity_reference(
        participant: ParticipantId,
        key_reference: u8,
        noise_public_key: u8,
        secret: u8,
    ) -> SessionTransportIdentityReferenceV1 {
        SessionTransportIdentityReferenceV1::new(
            participant.0,
            [key_reference; 32],
            [noise_public_key; 32],
            SecretKey::from_bytes(&[secret; 32])
                .expect("valid test secret")
                .public_key(),
        )
        .expect("public test identity reference")
    }
}

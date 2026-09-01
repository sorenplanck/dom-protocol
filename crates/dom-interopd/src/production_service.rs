//! Phase-1 production service plane: transport identity, fail-closed F6 and
//! the two Relay-backed Contracts owners.
//!
//! This module composes everything below the settlement runtime that exists
//! on a fresh route: the Contracts transport identity store, the durable
//! Relay queue, and one `ProductionContractsV1` owner per settlement leg,
//! each carrying its own Relay worker over the sanctioned fail-closed
//! [`UnavailableF6AuthorityV1`]. Provisioning stages 11 (`F6Authorities`)
//! and 12 (`RelayAuthorities`) complete here, in journal order, so a reopen
//! audits the same monotone prefix the creation wrote.
//!
//! What deliberately does NOT compose here: the DOM settlement child, the
//! role plan and the settlement bridge. Those need the negotiated Contracts
//! session state (frozen claim templates, session heads), which a fresh
//! route does not have yet — see `production_run` for the phase-2 gate.

use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use blake2::digest::{consts::U32, KeyInit, Mac};
use blake2::Blake2bMac;
use cap_std::fs::Dir;
use dom_scriptless_identity_store::{
    ContractsIdentityPassphraseV1, ContractsTransportIdentityStoreV1,
};
use dom_scriptless_store::ContractsSessionStoreV1;
use relay::production::{ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1};
use route_executor::{Digest32, RouteIdV1};
use route_transport::{
    DurableFrameReassemblerConfigV2, DurableInboxConfigV1, DurableRelaySenderConfigV1,
    RouteWireContextV1,
};
use zeroize::Zeroizing;

use crate::production_chain_signers::ProductionChainSignerAuthoritiesV1;
use crate::production_config::{ProductionPathRoleV1, ValidatedProductionBootstrapV1};
use crate::production_contracts::ProductionContractsV1;
use crate::production_inputs::{AuthenticatedProductionInputsV1, ProductionRosterLegV1};
use crate::production_provisioning::{
    DurableProductionProvisioningJournalV1, ProductionProvisioningStageStateV1,
    ProductionProvisioningStageV1,
};
use crate::production_run::ProductionRunModeV1;
use crate::relay_worker::{RelayWorkerConfigV1, RelayWorkerPathsV1, UnavailableF6AuthorityV1};
use route_executor::LegIdV1;

const ZERO_DIGEST: Digest32 = [0; 32];

/// Domain for the deterministic per-leg Relay authority store identities.
const RELAY_STORE_ID_DOMAIN_V1: &[u8] = b"DOM-INTEROP/INTEROPD/RELAY-STORE-ID/V1\0";

/// Frozen Relay bounds. These are hard caps of the daemon composition, not
/// negotiable configuration: the wire protocol carries its own stricter
/// ceilings and every store revalidates them independently.
const RELAY_MAX_ENVELOPES_V1: u32 = 128;
const RELAY_MAX_FRAME_MESSAGES_V1: u16 = 16;
const RELAY_MAX_REASSEMBLED_BYTES_V1: u64 = 2 * 1024 * 1024;
const RELAY_MAX_ACTIVE_CHUNKS_V1: u32 = 128;

/// Everything the phase-1 service plane owns after composition.
pub(crate) struct ProductionRouteServiceV1 {
    pub(crate) upstream_contracts: ProductionContractsV1<UnavailableF6AuthorityV1>,
    pub(crate) downstream_contracts: ProductionContractsV1<UnavailableF6AuthorityV1>,
    pub(crate) relay_queue: ProductionRelayV1,
}

impl core::fmt::Debug for ProductionRouteServiceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRouteServiceV1([authorities redacted])")
    }
}

/// Named, redacted service-plane composition refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProductionServiceErrorV1 {
    /// The V4 bootstrap does not name the identity-store path, the state
    /// capability refused it, or the sealed identity refused the passphrase.
    #[error("production transport identity store unavailable")]
    IdentityStore,
    /// The durable Relay queue could not be created or reopened.
    #[error("production relay queue unavailable")]
    RelayQueue,
    /// A Relay worker configuration could not be derived from the
    /// authenticated roster bundle and signer authorities.
    #[error("production relay configuration refused")]
    RelayConfiguration,
    /// A Contracts owner (store + identity + relay worker) refused to
    /// create, resume or reopen.
    #[error("production contracts owner unavailable")]
    ContractsOwner,
    /// The provisioning journal refused a stage transition.
    #[error("production provisioning journal refused")]
    Provisioning,
}

/// One-shot request carrying every already-provisioned dependency by move.
pub(crate) struct ProductionRouteServiceRequestV1<'a> {
    pub(crate) mode: ProductionRunModeV1,
    pub(crate) bootstrap: &'a ValidatedProductionBootstrapV1,
    pub(crate) inputs: &'a AuthenticatedProductionInputsV1,
    pub(crate) signers: &'a ProductionChainSignerAuthoritiesV1,
    pub(crate) state_capability: Arc<Dir>,
    pub(crate) upstream_store: ContractsSessionStoreV1,
    pub(crate) downstream_store: ContractsSessionStoreV1,
    pub(crate) identity_passphrase: Zeroizing<Vec<u8>>,
    pub(crate) upstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    pub(crate) downstream_relay_signing_secret: Zeroizing<[u8; 32]>,
}

/// Composes the service plane and completes provisioning stages 11 and 12.
pub(crate) fn compose_production_route_service_v1(
    request: ProductionRouteServiceRequestV1<'_>,
    provisioning: &mut DurableProductionProvisioningJournalV1,
) -> Result<ProductionRouteServiceV1, ProductionServiceErrorV1> {
    let bundle = request.inputs.roster_bundle();
    let route_id = bundle.route_id();

    // Stage 11: the F6 authority pair. The engine (`ProductionSolverF6AuthorityV2`)
    // exists, but the real terms authority does not, so the sanctioned
    // fail-closed `UnavailableF6AuthorityV1` composes here: it refuses every
    // negotiation while the Relay transport, the Contracts owners and the
    // chain settlements below stay fully operational. There is nothing
    // durable to provision for it, and the journal stage records exactly
    // that decision so a reopen audits the same composition.
    let f6_stage = advance_stage(
        request.mode,
        ProductionProvisioningStageV1::F6Authorities,
        provisioning,
    )?;
    let upstream_f6 = UnavailableF6AuthorityV1;
    let downstream_f6 = UnavailableF6AuthorityV1;
    complete_stage(
        request.mode,
        f6_stage,
        ProductionProvisioningStageV1::F6Authorities,
        provisioning,
    )?;

    // Stage 12: the Relay authorities — identity store, durable queue and
    // one worker per leg, all under the same journal stage because they are
    // one transport plane and a partial creation must resume as one unit.
    let relay_stage = advance_stage(
        request.mode,
        ProductionProvisioningStageV1::RelayAuthorities,
        provisioning,
    )?;

    let identity = open_transport_identity_store(
        request.mode,
        relay_stage,
        request.bootstrap,
        Arc::clone(&request.state_capability),
        &request.identity_passphrase,
    )?;
    let identity = Rc::new(identity);

    let relay_queue = open_relay_queue(request.mode, relay_stage, request.bootstrap, route_id)?;

    let legs = bundle.legs();
    let upstream_config = relay_worker_config_v1(
        bundle.network_id(),
        route_id,
        &legs[0],
        LegIdV1::Upstream,
        request.signers,
    )?;
    let downstream_config = relay_worker_config_v1(
        bundle.network_id(),
        route_id,
        &legs[1],
        LegIdV1::Downstream,
        request.signers,
    )?;

    let upstream_paths = relay_worker_paths(request.bootstrap, LegIdV1::Upstream);
    let downstream_paths = relay_worker_paths(request.bootstrap, LegIdV1::Downstream);
    let registry = request.inputs.roster_registry().clone();

    let upstream_contracts = compose_contracts_owner(
        request.mode,
        relay_stage,
        request.upstream_store,
        Rc::clone(&identity),
        &upstream_paths,
        upstream_config,
        registry.clone(),
        upstream_f6,
        *request.upstream_relay_signing_secret,
    )?;
    let downstream_contracts = compose_contracts_owner(
        request.mode,
        relay_stage,
        request.downstream_store,
        identity,
        &downstream_paths,
        downstream_config,
        registry,
        downstream_f6,
        *request.downstream_relay_signing_secret,
    )?;

    complete_stage(
        request.mode,
        relay_stage,
        ProductionProvisioningStageV1::RelayAuthorities,
        provisioning,
    )?;

    Ok(ProductionRouteServiceV1 {
        upstream_contracts,
        downstream_contracts,
        relay_queue,
    })
}

fn advance_stage(
    mode: ProductionRunModeV1,
    stage: ProductionProvisioningStageV1,
    provisioning: &mut DurableProductionProvisioningJournalV1,
) -> Result<ProductionProvisioningStageStateV1, ProductionServiceErrorV1> {
    match mode {
        ProductionRunModeV1::Create => provisioning
            .begin(stage)
            .map_err(|_| ProductionServiceErrorV1::Provisioning),
        ProductionRunModeV1::ReopenExisting => provisioning
            .stage_state(stage)
            .map_err(|_| ProductionServiceErrorV1::Provisioning),
    }
}

fn complete_stage(
    mode: ProductionRunModeV1,
    stage_state: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageV1,
    provisioning: &mut DurableProductionProvisioningJournalV1,
) -> Result<(), ProductionServiceErrorV1> {
    if mode == ProductionRunModeV1::Create
        && stage_state != ProductionProvisioningStageStateV1::Complete
    {
        provisioning
            .complete(stage)
            .map_err(|_| ProductionServiceErrorV1::Provisioning)
    } else if stage_state != ProductionProvisioningStageStateV1::Complete {
        Err(ProductionServiceErrorV1::Provisioning)
    } else {
        Ok(())
    }
}

fn open_transport_identity_store(
    mode: ProductionRunModeV1,
    relay_stage: ProductionProvisioningStageStateV1,
    bootstrap: &ValidatedProductionBootstrapV1,
    parent: Arc<Dir>,
    passphrase: &Zeroizing<Vec<u8>>,
) -> Result<ContractsTransportIdentityStoreV1, ProductionServiceErrorV1> {
    let path = bootstrap
        .layout()
        .contracts_transport_identity_store()
        .ok_or(ProductionServiceErrorV1::IdentityStore)?;
    let root_name = child_root_name(bootstrap.layout().state_dir(), path)
        .ok_or(ProductionServiceErrorV1::IdentityStore)?;
    let passphrase = ContractsIdentityPassphraseV1::new(passphrase.to_vec())
        .map_err(|_| ProductionServiceErrorV1::IdentityStore)?;
    match (mode, relay_stage) {
        // Fresh creation: the stage was just begun for the first time.
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started)
            if !path.exists() =>
        {
            ContractsTransportIdentityStoreV1::create_production(parent, root_name, &passphrase)
                .map_err(|_| ProductionServiceErrorV1::IdentityStore)
        }
        // Creation resume after a crash, or any reopen: the sealed identity
        // must already exist and must authenticate under the passphrase.
        _ => ContractsTransportIdentityStoreV1::open_production(parent, root_name, &passphrase)
            .map_err(|_| ProductionServiceErrorV1::IdentityStore),
    }
}

fn open_relay_queue(
    mode: ProductionRunModeV1,
    relay_stage: ProductionProvisioningStageStateV1,
    bootstrap: &ValidatedProductionBootstrapV1,
    route_id: RouteIdV1,
) -> Result<ProductionRelayV1, ProductionServiceErrorV1> {
    let root = bootstrap.layout().path(ProductionPathRoleV1::RelayQueue);
    let database_id = RelayDatabaseIdV1::new(relay_store_id_v1(route_id, 0xFF, b"queue"))
        .map_err(|_| ProductionServiceErrorV1::RelayQueue)?;
    let config = RelayDatabaseConfigV1::new(database_id, RELAY_MAX_ENVELOPES_V1)
        .map_err(|_| ProductionServiceErrorV1::RelayQueue)?;
    match (mode, relay_stage) {
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started)
            if !root.exists() =>
        {
            ProductionRelayV1::create(root, config)
                .map_err(|_| ProductionServiceErrorV1::RelayQueue)
        }
        _ => {
            ProductionRelayV1::open(root, config).map_err(|_| ProductionServiceErrorV1::RelayQueue)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compose_contracts_owner(
    mode: ProductionRunModeV1,
    relay_stage: ProductionProvisioningStageStateV1,
    store: ContractsSessionStoreV1,
    identity: Rc<ContractsTransportIdentityStoreV1>,
    paths: &RelayWorkerPathsV1,
    config: RelayWorkerConfigV1,
    rosters: relay::auth::RosterRegistryV1,
    f6: UnavailableF6AuthorityV1,
    relay_signing_secret: [u8; 32],
) -> Result<ProductionContractsV1<UnavailableF6AuthorityV1>, ProductionServiceErrorV1> {
    let owner = match (mode, relay_stage) {
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started)
            if !paths.sender_root().exists() =>
        {
            ProductionContractsV1::create(
                store,
                identity,
                paths,
                config,
                rosters,
                f6,
                relay_signing_secret,
            )
        }
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started) => {
            ProductionContractsV1::resume_create_production(
                store,
                identity,
                paths,
                config,
                rosters,
                f6,
                relay_signing_secret,
            )
        }
        _ => ProductionContractsV1::open_existing(
            store,
            identity,
            paths,
            config,
            rosters,
            f6,
            relay_signing_secret,
        ),
    };
    owner.map_err(|_| ProductionServiceErrorV1::ContractsOwner)
}

fn relay_worker_paths(
    bootstrap: &ValidatedProductionBootstrapV1,
    leg: LegIdV1,
) -> RelayWorkerPathsV1 {
    let (sender, inbox, frames) = match leg {
        LegIdV1::Upstream => (
            ProductionPathRoleV1::UpstreamRelaySender,
            ProductionPathRoleV1::UpstreamRelayInbox,
            ProductionPathRoleV1::UpstreamRelayFrames,
        ),
        LegIdV1::Downstream => (
            ProductionPathRoleV1::DownstreamRelaySender,
            ProductionPathRoleV1::DownstreamRelayInbox,
            ProductionPathRoleV1::DownstreamRelayFrames,
        ),
    };
    RelayWorkerPathsV1::new(
        bootstrap.layout().path(sender),
        bootstrap.layout().path(inbox),
        bootstrap.layout().path(frames),
    )
}

/// Builds the frozen Relay worker configuration for one authenticated leg.
fn relay_worker_config_v1(
    network_id: Digest32,
    route_id: RouteIdV1,
    leg: &ProductionRosterLegV1,
    leg_id: LegIdV1,
    signers: &ProductionChainSignerAuthoritiesV1,
) -> Result<RelayWorkerConfigV1, ProductionServiceErrorV1> {
    let local = signers.participant_id();
    let local_role = signers.relay_role();
    let signer_xonly = signers.relay_xonly_key(leg_id);
    let remote = leg
        .members
        .iter()
        .find(|member| member.participant_id != local)
        .ok_or(ProductionServiceErrorV1::RelayConfiguration)?;
    let local_member = leg
        .members
        .iter()
        .find(|member| member.participant_id == local)
        .ok_or(ProductionServiceErrorV1::RelayConfiguration)?;
    if local_member.role != local_role || local_member.xonly_key != signer_xonly {
        return Err(ProductionServiceErrorV1::RelayConfiguration);
    }
    let wire = RouteWireContextV1 {
        network_id,
        session_id: leg.session_id,
        route_id,
        roster_snapshot: leg.roster_snapshot,
        policy_version: leg.policy_version,
    };
    let leg_tag = match leg_id {
        LegIdV1::Upstream => 1u8,
        LegIdV1::Downstream => 2,
    };
    let sender = DurableRelaySenderConfigV1::new(
        relay_store_id_v1(route_id, leg_tag, b"sender"),
        wire,
        local,
        remote.participant_id,
        local_role,
        signer_xonly,
        RELAY_MAX_ENVELOPES_V1,
    )
    .map_err(|_| ProductionServiceErrorV1::RelayConfiguration)?;
    let inbox = DurableInboxConfigV1::new(
        relay_store_id_v1(route_id, leg_tag, b"inbox"),
        wire,
        local,
        RELAY_MAX_ENVELOPES_V1,
    )
    .map_err(|_| ProductionServiceErrorV1::RelayConfiguration)?;
    let frames = DurableFrameReassemblerConfigV2::new(
        relay_store_id_v1(route_id, leg_tag, b"frames"),
        wire,
        local,
        RELAY_MAX_FRAME_MESSAGES_V1,
        RELAY_MAX_REASSEMBLED_BYTES_V1,
        RELAY_MAX_ACTIVE_CHUNKS_V1,
    )
    .map_err(|_| ProductionServiceErrorV1::RelayConfiguration)?;
    RelayWorkerConfigV1::new(sender, inbox, frames)
        .map_err(|_| ProductionServiceErrorV1::RelayConfiguration)
}

/// Deterministic, domain-separated store identity for one Relay authority.
fn relay_store_id_v1(route_id: RouteIdV1, leg_tag: u8, kind: &[u8]) -> Digest32 {
    let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(RELAY_STORE_ID_DOMAIN_V1)
        .expect("the compile-time domain fits the Blake2b key bound");
    Mac::update(&mut mac, &route_id);
    Mac::update(&mut mac, &[leg_tag]);
    Mac::update(&mut mac, &(kind.len() as u64).to_be_bytes());
    Mac::update(&mut mac, kind);
    let digest: Digest32 = mac.finalize().into_bytes().into();
    debug_assert_ne!(digest, ZERO_DIGEST);
    digest
}

/// Returns the file name of `path` when it is a direct child of `state_dir`.
fn child_root_name<'p>(state_dir: &Path, path: &'p Path) -> Option<&'p str> {
    if path.parent()? != state_dir {
        return None;
    }
    path.file_name()?.to_str()
}

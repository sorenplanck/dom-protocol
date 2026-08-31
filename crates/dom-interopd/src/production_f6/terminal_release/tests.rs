use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use kaystra_core::types::{ChainId, ParticipantId};
use rfq::v2::{NativeClockKindV2, NegotiationClockV2, SettlementPositionV2};
use route_executor::{
    CommitOutcomeV1, FrozenBindingsV1, FrozenRouteAdmissionCheckpointV2, FrozenRouteTimeFactsV2,
    RouteEventV1, RouteInventoryReleaseDispositionV1, RouteStoreErrorV1,
};
use route_transport::RouteWireContextV1;

use super::*;
use crate::production_f6::ProductionF6PinsV2;
use crate::{ManualClockV1, RouteSupervisorConfigV1, RouteSupervisorErrorV1, RouteSupervisorV1};

fn id(value: u8) -> [u8; 32] {
    [value; 32]
}

fn binding(position: SettlementPositionV2) -> ProductionSolverF6BindingV2 {
    ProductionSolverF6BindingV2 {
        wire: RouteWireContextV1 {
            network_id: id(1),
            session_id: id(2),
            route_id: id(3),
            roster_snapshot: id(4),
            policy_version: 1,
        },
        rfq_id: match position {
            SettlementPositionV2::Upstream => id(5),
            SettlementPositionV2::Downstream => id(6),
        },
        composition_id: id(7),
        position,
        initiator: ParticipantId(id(8)),
        solver: ParticipantId(id(9)),
        dom_chain_id: ChainId(id(10)),
        negotiation_clock: NegotiationClockV2 {
            chain_id: ChainId(id(10)),
            profile_digest: id(11),
            authority_scope: id(12),
            kind: NativeClockKindV2::BlockHeight,
        },
        pins: ProductionF6PinsV2 {
            inventory_binding_digest: id(13),
            registry_digest: id(14),
            registry_epoch: 1,
            profile_bundle_digest: id(15),
            bond_policy_hash: id(16),
            bond_asset_binding_digest: id(17),
            required_collateral: 10,
            bond_attestation_authority_set_digest: id(18),
            remote_status_authority_set_digest: id(19),
            solver_status_scope_digest: id(20),
            pre_f6_time_scope_digest: id(21),
        },
    }
}

fn checkpoint() -> FrozenRouteAdmissionCheckpointV2 {
    FrozenRouteAdmissionCheckpointV2 {
        network_id: id(1),
        route_id: id(3),
        bindings: FrozenBindingsV1 {
            terms_digest: id(22),
            profile_bundle_digest: id(23),
            deployment_bundle_digest: id(26),
        },
        composition_v2_digest: id(25),
        registry_epoch: 1,
        registry_manifest_digest: id(26),
        upstream_terms_digest: id(27),
        downstream_terms_digest: id(28),
        upstream_roster_snapshot: id(29),
        downstream_roster_snapshot: id(30),
        participant_bindings_digest: id(31),
        relay_binding_digest: id(32),
        registry_authority_set_digest: id(33),
        time_policy_authority_set_digest: id(34),
        time_evidence_authority_set_digest: id(35),
        time: FrozenRouteTimeFactsV2 {
            route_scope_digest: id(36),
            policy_digest: id(37),
            evidence_digest: id(38),
            proof_digest: id(39),
            evidence_sequence: 1,
            issued_at_seconds: 100,
            valid_until_seconds: 200,
            validated_at_seconds: 110,
        },
    }
}

fn create_store() -> Result<DurableRouteStoreV1, Box<dyn Error>> {
    create_store_with_path().map(|(_, store)| store)
}

fn create_store_with_path() -> Result<(PathBuf, DurableRouteStoreV1), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.keep().join("route.sqlite3");
    let mut store = DurableRouteStoreV1::create(&path)?;
    store.create_route(id(3), 1)?;
    let lease = store.acquire_lease(id(3), id(40), 2, 10_000)?.lease();
    let outcome = store.apply_event(
        lease,
        0,
        id(41),
        &RouteEventV1::FreezeTermsV2(Box::new(checkpoint())),
        3,
    )?;
    if !matches!(outcome, CommitOutcomeV1::Committed { revision: 1, .. }) {
        return Err(io::Error::other("unexpected freeze outcome").into());
    }
    Ok((path, store))
}

fn supervisor_config() -> Result<RouteSupervisorConfigV1, RouteSupervisorErrorV1> {
    RouteSupervisorConfigV1::new(10_000, 2_000, 1_000, 4)
}

#[test]
fn terminal_release_is_route_replayed_position_bound_and_busy_fail_closed(
) -> Result<(), Box<dyn Error>> {
    let upstream_binding = binding(SettlementPositionV2::Upstream);
    let downstream_binding = binding(SettlementPositionV2::Downstream);
    let (path, store) = create_store_with_path()?;
    let owner = ProductionRouteTerminalAuthorityOwnerV2::new(
        store,
        id(3),
        id(25),
        7,
        upstream_binding,
        downstream_binding,
    )?;
    let (runtime, mut upstream, mut downstream) = owner.into_handles();
    assert_eq!(runtime.route_id(), id(3));
    assert_eq!(runtime.verify_replay()?.revision, 1);
    let clock = ManualClockV1::new(4)?;
    let mut supervisor = RouteSupervisorV1::acquire_production_route_store(
        runtime,
        id(3),
        id(40),
        supervisor_config()?,
        clock,
    )?;
    assert!(matches!(
        upstream.prove_terminal_release(&upstream_binding, id(44)),
        Err(ProductionF6ErrorV2::TerminalUnavailable)
    ));
    let outcome = supervisor.abort_unfunded(id(42), id(43))?;
    assert!(matches!(
        outcome,
        CommitOutcomeV1::Committed { revision: 2, .. }
    ));
    let upstream_proof = upstream.prove_terminal_release(&upstream_binding, id(44))?;
    assert_eq!(upstream_proof.composition_id, id(7));
    assert_eq!(upstream_proof.position, SettlementPositionV2::Upstream);
    assert_eq!(upstream_proof.rfq_id, id(5));
    assert_eq!(upstream_proof.reservation_id, id(44));
    assert_eq!(upstream_proof.terminal_revision, 2);
    assert_eq!(upstream_proof.fencing_epoch, 7);
    assert_ne!(upstream_proof.evidence_digest, ZERO_DIGEST);

    let downstream_proof = downstream.prove_terminal_release(&downstream_binding, id(45))?;
    assert_eq!(downstream_proof.position, SettlementPositionV2::Downstream);
    assert_ne!(
        upstream_proof.evidence_digest,
        downstream_proof.evidence_digest
    );
    assert!(matches!(
        upstream.prove_terminal_release(&downstream_binding, id(44)),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    assert!(matches!(
        upstream.prove_terminal_release(&upstream_binding, ZERO_DIGEST),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));

    assert!(matches!(
        DurableRouteStoreV1::open_existing(&path),
        Err(RouteStoreErrorV1::StorageUnavailable)
    ));

    let held = upstream
        .store
        .try_borrow_mut()
        .map_err(|_| io::Error::other("route store unexpectedly busy"))?;
    assert!(matches!(
        supervisor.snapshot(),
        Err(RouteSupervisorErrorV1::StoreAuthorityBusy)
    ));
    drop(held);

    drop(supervisor);
    drop(upstream);
    drop(downstream);
    let reopened = DurableRouteStoreV1::open_existing(&path)?;
    let recovery_owner = ProductionRouteTerminalAuthorityOwnerV2::new(
        reopened,
        id(3),
        id(25),
        7,
        upstream_binding,
        downstream_binding,
    )?;
    let (recovery_runtime, mut recovery_upstream, recovery_downstream) =
        recovery_owner.into_handles();
    let recovery_clock = ManualClockV1::new(6)?;
    let recovery_supervisor = RouteSupervisorV1::acquire_production_route_store(
        recovery_runtime,
        id(3),
        id(40),
        supervisor_config()?,
        recovery_clock,
    )?;
    assert_eq!(recovery_supervisor.snapshot()?.revision, 2);
    assert_eq!(
        recovery_upstream
            .prove_terminal_release(&upstream_binding, id(44))?
            .evidence_digest,
        upstream_proof.evidence_digest
    );
    drop(recovery_supervisor);
    drop(recovery_upstream);
    drop(recovery_downstream);
    Ok(())
}

#[test]
fn production_route_store_surface_never_exposes_raw_store_or_shared_interior() {
    let source = include_str!("../terminal_release.rs");
    for forbidden in [
        "pub(crate) store:",
        "pub store:",
        "pub(crate) fn store(",
        "pub(crate) fn with_store",
        "pub(crate) fn read_store",
        "pub(crate) fn write_store",
        "-> Rc<",
        "-> Ref<",
        "-> RefMut<",
    ] {
        assert!(
            !source.contains(forbidden),
            "route-store authority surface exposes forbidden fragment: {forbidden}"
        );
    }
}

#[test]
fn owner_rejects_position_route_and_composition_transplants() -> Result<(), Box<dyn Error>> {
    let upstream = binding(SettlementPositionV2::Upstream);
    let downstream = binding(SettlementPositionV2::Downstream);
    assert!(matches!(
        ProductionRouteTerminalAuthorityOwnerV2::new(
            create_store()?,
            id(3),
            id(25),
            7,
            downstream,
            upstream,
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    let mut foreign_route = upstream;
    foreign_route.wire.route_id = id(46);
    assert!(matches!(
        ProductionRouteTerminalAuthorityOwnerV2::new(
            create_store()?,
            id(3),
            id(25),
            7,
            foreign_route,
            downstream,
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    let mut foreign_composition = downstream;
    foreign_composition.composition_id = id(47);
    assert!(matches!(
        ProductionRouteTerminalAuthorityOwnerV2::new(
            create_store()?,
            id(3),
            id(25),
            7,
            upstream,
            foreign_composition,
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    assert!(matches!(
        ProductionRouteTerminalAuthorityOwnerV2::new(
            create_store()?,
            id(3),
            id(48),
            7,
            upstream,
            downstream,
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    Ok(())
}

#[test]
fn release_capability_explicitly_reports_unfunded_abort() -> Result<(), Box<dyn Error>> {
    let mut store = create_store()?;
    let lease = store.acquire_lease(id(3), id(40), 4, 10_000)?.lease();
    store.apply_event(
        lease,
        1,
        id(42),
        &RouteEventV1::AbortUnfunded {
            reason_digest: id(43),
        },
        5,
    )?;
    let capability = store.mint_route_inventory_release_capability_v1(id(3))?;
    assert_eq!(
        capability.disposition(),
        RouteInventoryReleaseDispositionV1::AbortedUnfunded
    );
    Ok(())
}

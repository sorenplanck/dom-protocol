//! Route-replay-owned terminal inventory release authority.

use std::cell::RefCell;
use std::rc::Rc;

use rfq::v2::SettlementPositionV2;
use route_executor::{
    ActionIntentV1, ClaimedExternalCustodyEffectV1, ClaimedRouteEffectV1, ClaimedRouteTimerV1,
    ClaimedRouteWorkV1, CommitOutcomeV1, CompletionOutcomeV1, Digest32, DurableRouteStoreV1,
    EffectIdV1, EventIdV1, RouteEventV1, RouteIdV1, RouteInventoryReleaseDispositionV1,
    RouteJournalEntryV1, RouteLeaseV1, RouteSnapshotV1, RouteStoreErrorV1, TimerIdV1,
};

use super::{
    digest_parts, source_seal, ProductionF6ErrorV2, ProductionF6TerminalAuthorityV2,
    ProductionSolverF6BindingV2, TerminalInventoryReleaseV2, ZERO_DIGEST,
};
use crate::supervisor::{RouteSupervisorErrorV1, RouteSupervisorStoreAuthorityV1};

const TERMINAL_RELEASE_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-TERMINAL-RELEASE/V2\0";

/// Sole physical owner used to derive the route runtime and both position-
/// scoped terminal authorities without reopening the route store.
pub(crate) struct ProductionRouteTerminalAuthorityOwnerV2 {
    store: DurableRouteStoreV1,
    route_id: RouteIdV1,
    composition_v2_digest: [u8; 32],
    inventory_fencing_epoch: u64,
    upstream: ProductionSolverF6BindingV2,
    downstream: ProductionSolverF6BindingV2,
}

/// Move-only handle retaining the same physical route-store opening for the
/// route runtime. It deliberately exposes no raw store accessor.
pub(crate) struct ProductionRouteStoreRuntimeAuthorityV2 {
    store: Rc<RefCell<DurableRouteStoreV1>>,
    route_id: RouteIdV1,
}

/// Position-scoped terminal proof producer backed by authenticated replay of
/// the same physical route store used by the runtime.
pub(crate) struct ProductionRouteTerminalAuthorityV2 {
    store: Rc<RefCell<DurableRouteStoreV1>>,
    route_id: RouteIdV1,
    composition_v2_digest: [u8; 32],
    inventory_fencing_epoch: u64,
    binding: ProductionSolverF6BindingV2,
}

impl core::fmt::Debug for ProductionRouteTerminalAuthorityOwnerV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRouteTerminalAuthorityOwnerV2([authority redacted])")
    }
}

impl core::fmt::Debug for ProductionRouteStoreRuntimeAuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRouteStoreRuntimeAuthorityV2([authority redacted])")
    }
}

impl core::fmt::Debug for ProductionRouteTerminalAuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRouteTerminalAuthorityV2([authority redacted])")
    }
}

impl ProductionRouteTerminalAuthorityOwnerV2 {
    /// Freezes the one route store, composition and inventory fencing epoch
    /// before any position-scoped handle exists.
    pub(crate) fn new(
        store: DurableRouteStoreV1,
        route_id: RouteIdV1,
        composition_v2_digest: [u8; 32],
        inventory_fencing_epoch: u64,
        upstream: ProductionSolverF6BindingV2,
        downstream: ProductionSolverF6BindingV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        if route_id == ZERO_DIGEST
            || composition_v2_digest == ZERO_DIGEST
            || inventory_fencing_epoch == 0
            || upstream.wire.route_id != route_id
            || downstream.wire.route_id != route_id
            || upstream.position != SettlementPositionV2::Upstream
            || downstream.position != SettlementPositionV2::Downstream
            || upstream.composition_id != downstream.composition_id
            || upstream.composition_id != composition_v2_digest
            || upstream.wire.network_id != downstream.wire.network_id
            || upstream.wire.session_id == downstream.wire.session_id
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        upstream.validate()?;
        downstream.validate()?;
        let checkpoint = store
            .audit_frozen_admission_checkpoint_v2(route_id)
            .map_err(map_route_error)?;
        if checkpoint.composition_v2_digest != composition_v2_digest
            || checkpoint.network_id != upstream.wire.network_id
            || checkpoint.network_id != downstream.wire.network_id
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        Ok(Self {
            store,
            route_id,
            composition_v2_digest,
            inventory_fencing_epoch,
            upstream,
            downstream,
        })
    }

    /// Consumes the sole owner and emits exactly one runtime handle and the
    /// two fixed-position terminal producers. The handles cannot be split.
    pub(crate) fn into_handles(
        self,
    ) -> (
        ProductionRouteStoreRuntimeAuthorityV2,
        ProductionRouteTerminalAuthorityV2,
        ProductionRouteTerminalAuthorityV2,
    ) {
        let shared = Rc::new(RefCell::new(self.store));
        (
            ProductionRouteStoreRuntimeAuthorityV2 {
                store: Rc::clone(&shared),
                route_id: self.route_id,
            },
            ProductionRouteTerminalAuthorityV2 {
                store: Rc::clone(&shared),
                route_id: self.route_id,
                composition_v2_digest: self.composition_v2_digest,
                inventory_fencing_epoch: self.inventory_fencing_epoch,
                binding: self.upstream,
            },
            ProductionRouteTerminalAuthorityV2 {
                store: shared,
                route_id: self.route_id,
                composition_v2_digest: self.composition_v2_digest,
                inventory_fencing_epoch: self.inventory_fencing_epoch,
                binding: self.downstream,
            },
        )
    }
}

impl ProductionRouteStoreRuntimeAuthorityV2 {
    /// Exact route owned by this runtime handle.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    /// Replays the exact retained route store without exposing the raw store.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn verify_replay(
        &self,
    ) -> Result<route_executor::RouteSnapshotV1, ProductionF6ErrorV2> {
        self.store
            .try_borrow()
            .map_err(|_| ProductionF6ErrorV2::TerminalUnavailable)?
            .verify_replay(self.route_id)
            .map_err(map_route_error)
    }

    /// Full-history audit proving every committed action is an
    /// external-custody descriptor. The composition root must run it before
    /// installing the closed production runner; a route whose journal already
    /// carries a generic runner action cannot be driven by that policy.
    pub(crate) fn audit_external_custody_only_v1(
        &self,
    ) -> Result<route_executor::RouteSnapshotV1, ProductionF6ErrorV2> {
        self.store
            .try_borrow()
            .map_err(|_| ProductionF6ErrorV2::TerminalUnavailable)?
            .audit_external_custody_only_v1(self.route_id)
            .map_err(map_route_error)
    }

    fn read_store<T>(
        &self,
        operation: impl FnOnce(&DurableRouteStoreV1) -> Result<T, RouteStoreErrorV1>,
    ) -> Result<T, RouteSupervisorErrorV1> {
        let store = self
            .store
            .try_borrow()
            .map_err(|_| RouteSupervisorErrorV1::StoreAuthorityBusy)?;
        operation(&store).map_err(RouteSupervisorErrorV1::Store)
    }

    fn write_store<T>(
        &mut self,
        operation: impl FnOnce(&mut DurableRouteStoreV1) -> Result<T, RouteStoreErrorV1>,
    ) -> Result<T, RouteSupervisorErrorV1> {
        let mut store = self
            .store
            .try_borrow_mut()
            .map_err(|_| RouteSupervisorErrorV1::StoreAuthorityBusy)?;
        operation(&mut store).map_err(RouteSupervisorErrorV1::Store)
    }
}

impl RouteSupervisorStoreAuthorityV1 for ProductionRouteStoreRuntimeAuthorityV2 {
    fn acquire_route_lease(
        &mut self,
        route_id: RouteIdV1,
        owner_id: Digest32,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<RouteLeaseV1, RouteSupervisorErrorV1> {
        self.write_store(|store| {
            Ok(store
                .acquire_lease(route_id, owner_id, now_unix_ms, duration_ms)?
                .lease())
        })
    }

    fn load_snapshot(
        &self,
        route_id: RouteIdV1,
    ) -> Result<RouteSnapshotV1, RouteSupervisorErrorV1> {
        self.read_store(|store| store.load_snapshot(route_id))
    }

    fn journal(
        &self,
        route_id: RouteIdV1,
    ) -> Result<Vec<RouteJournalEntryV1>, RouteSupervisorErrorV1> {
        self.read_store(|store| store.journal(route_id))
    }

    fn pending_effect_count(&self, route_id: RouteIdV1) -> Result<u64, RouteSupervisorErrorV1> {
        self.read_store(|store| store.pending_effect_count(route_id))
    }

    fn active_timer_count(&self, route_id: RouteIdV1) -> Result<u64, RouteSupervisorErrorV1> {
        self.read_store(|store| store.active_timer_count(route_id))
    }

    fn mint_route_secret_retirement_capability(
        &self,
        route_id: RouteIdV1,
    ) -> Result<route_executor::RouteSecretRetirementCapabilityV1, RouteSupervisorErrorV1> {
        self.read_store(|store| store.mint_route_secret_retirement_capability_v1(route_id))
    }

    fn renew_lease(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<RouteLeaseV1, RouteSupervisorErrorV1> {
        self.write_store(|store| store.renew_lease(lease, now_unix_ms, duration_ms))
    }

    fn apply_event(
        &mut self,
        lease: RouteLeaseV1,
        expected_revision: u64,
        event_id: EventIdV1,
        event: &RouteEventV1,
        now_unix_ms: u64,
    ) -> Result<CommitOutcomeV1, RouteSupervisorErrorV1> {
        self.write_store(|store| {
            store.apply_event(lease, expected_revision, event_id, event, now_unix_ms)
        })
    }

    fn claim_due_timers(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedRouteTimerV1>, RouteSupervisorErrorV1> {
        self.write_store(|store| {
            store.claim_due_timers(lease, now_unix_ms, dispatch_lease_ms, limit)
        })
    }

    fn claim_external_custody_effect_by_id(
        &mut self,
        lease: RouteLeaseV1,
        effect_id: EffectIdV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
    ) -> Result<Option<ClaimedExternalCustodyEffectV1>, RouteSupervisorErrorV1> {
        self.write_store(|store| {
            store.claim_external_custody_effect_by_id(
                lease,
                effect_id,
                now_unix_ms,
                dispatch_lease_ms,
            )
        })
    }

    fn claim_next_effect(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
    ) -> Result<Option<ClaimedRouteWorkV1>, RouteSupervisorErrorV1> {
        self.write_store(|store| store.claim_next_effect(lease, now_unix_ms, dispatch_lease_ms))
    }

    fn committed_action_intent(
        &mut self,
        lease: RouteLeaseV1,
        effect_id: EffectIdV1,
        now_unix_ms: u64,
    ) -> Result<ActionIntentV1, RouteSupervisorErrorV1> {
        self.write_store(|store| store.committed_action_intent(lease, effect_id, now_unix_ms))
    }

    fn claim_effects(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedRouteEffectV1>, RouteSupervisorErrorV1> {
        self.write_store(|store| store.claim_effects(lease, now_unix_ms, dispatch_lease_ms, limit))
    }

    fn claim_external_custody_effects(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedExternalCustodyEffectV1>, RouteSupervisorErrorV1> {
        self.write_store(|store| {
            store.claim_external_custody_effects(lease, now_unix_ms, dispatch_lease_ms, limit)
        })
    }

    fn complete_timer(
        &mut self,
        lease: RouteLeaseV1,
        timer_id: TimerIdV1,
        timer_hash: Digest32,
        now_unix_ms: u64,
    ) -> Result<CompletionOutcomeV1, RouteSupervisorErrorV1> {
        self.write_store(|store| store.complete_timer(lease, timer_id, timer_hash, now_unix_ms))
    }
}

impl source_seal::Sealed for ProductionRouteTerminalAuthorityV2 {}

impl ProductionF6TerminalAuthorityV2 for ProductionRouteTerminalAuthorityV2 {
    fn prove_terminal_release(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
        reservation_id: [u8; 32],
    ) -> Result<TerminalInventoryReleaseV2, ProductionF6ErrorV2> {
        if *binding != self.binding || reservation_id == ZERO_DIGEST {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let capability = self
            .store
            .try_borrow()
            .map_err(|_| ProductionF6ErrorV2::TerminalUnavailable)?
            .mint_route_inventory_release_capability_v1(self.route_id)
            .map_err(map_route_error)?;
        if capability.route_id() != self.route_id
            || capability.composition_v2_digest() != self.composition_v2_digest
            || capability.revision() == 0
            || capability.release_evidence_digest() == ZERO_DIGEST
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let disposition = match capability.disposition() {
            RouteInventoryReleaseDispositionV1::BothLegsTerminal => [1_u8],
            RouteInventoryReleaseDispositionV1::AbortedUnfunded => [2_u8],
        };
        let evidence_digest = digest_parts(&[
            TERMINAL_RELEASE_DOMAIN,
            &binding.authority_digest(TERMINAL_RELEASE_DOMAIN)?,
            &reservation_id,
            &self.inventory_fencing_epoch.to_be_bytes(),
            &disposition,
            &capability.revision().to_be_bytes(),
            &capability.release_evidence_digest(),
        ])?;
        Ok(TerminalInventoryReleaseV2 {
            composition_id: binding.composition_id,
            position: binding.position,
            rfq_id: binding.rfq_id,
            reservation_id,
            evidence_digest,
            terminal_revision: capability.revision(),
            fencing_epoch: self.inventory_fencing_epoch,
        })
    }
}

fn map_route_error(error: RouteStoreErrorV1) -> ProductionF6ErrorV2 {
    match error {
        RouteStoreErrorV1::StorageUnavailable | RouteStoreErrorV1::InventoryReleaseUnavailable => {
            ProductionF6ErrorV2::TerminalUnavailable
        }
        RouteStoreErrorV1::UnsupportedFormat
        | RouteStoreErrorV1::DatabasePresent
        | RouteStoreErrorV1::DatabaseMissing
        | RouteStoreErrorV1::CreationIncomplete
        | RouteStoreErrorV1::InvalidStorageAuthority
        | RouteStoreErrorV1::InvalidMaterial
        | RouteStoreErrorV1::TransitionRejected
        | RouteStoreErrorV1::RouteNotFound
        | RouteStoreErrorV1::RouteAlreadyExists
        | RouteStoreErrorV1::RevisionConflict
        | RouteStoreErrorV1::IdempotencyConflict
        | RouteStoreErrorV1::LeaseHeld
        | RouteStoreErrorV1::StaleFencing
        | RouteStoreErrorV1::LeaseExpired
        | RouteStoreErrorV1::InvalidBound
        | RouteStoreErrorV1::CorruptState
        | RouteStoreErrorV1::EffectNotFound
        | RouteStoreErrorV1::TimerNotFound
        | RouteStoreErrorV1::AdmissionCheckpointUnavailable
        | RouteStoreErrorV1::SecretRetirementUnavailable
        | RouteStoreErrorV1::DispatchLeaseMismatch => ProductionF6ErrorV2::InvalidBinding,
    }
}

#[cfg(test)]
mod tests;

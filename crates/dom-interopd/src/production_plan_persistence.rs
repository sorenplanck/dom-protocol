//! Production persistence policy for settlement plans.
//!
//! Until this module existed the only implementor of
//! [`ProductionSettlementPlanPersistenceV1`] was the test double in
//! `production_settlement`, so the composition root could not assemble the
//! settlement bridge without dressing a test object as policy. This owner
//! carries the one authenticated plan authority minted by
//! `ProductionSettlementMaterializationOwnerV1::split` and forwards every
//! install/refence to the durable coordinator through it. No plan can be
//! installed here from caller-supplied facts: the authority itself refuses
//! anything outside the exact route/composition/role-plan scope it was
//! derived from.
//!
//! **Time policy.** Every entrypoint receives a trusted `now` from the bridge
//! (the same clock the coordinator lease is renewed with). This owner retains
//! a process-local high-water mark and refuses regression: a plan may be
//! installed, revalidated or re-fenced only with a time that is not earlier
//! than the last time it accepted. Durable non-regression across restarts is
//! owned by the route supervisor and coordinator leases, not duplicated here.

use route_executor::EventIdV1;
use settlement_coordinator::{
    CompositeSettlementPlanV1, CoordinatorLeaseV1, Digest32, DurableSettlementCoordinatorV1,
    SettlementActionV1, SettlementPlanViewV1, StoredSettlementPlanV1,
};

use crate::production_materializer::ProductionAuthenticatedSettlementPlanAuthorityV1;
use crate::production_settlement::{map_coordinator_error, ProductionSettlementPlanPersistenceV1};
use crate::supervisor::AuthorityRefusalV1;

const ZERO_DIGEST: Digest32 = [0u8; 32];

/// Sole production plan persistence owner.
///
/// Move-only: it owns the authenticated plan authority and is itself moved
/// into the settlement bridge exactly once.
#[must_use = "the plan persistence owner must be moved into the settlement bridge"]
pub(crate) struct ProductionSettlementPlanPersistenceOwnerV1 {
    authority: ProductionAuthenticatedSettlementPlanAuthorityV1,
    last_accepted_unix_ms: u64,
}

impl core::fmt::Debug for ProductionSettlementPlanPersistenceOwnerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSettlementPlanPersistenceOwnerV1([authority redacted])")
    }
}

impl ProductionSettlementPlanPersistenceOwnerV1 {
    /// Binds the exact plan authority and the trusted composition time.
    pub(crate) fn new(
        authority: ProductionAuthenticatedSettlementPlanAuthorityV1,
        trusted_now_unix_ms: u64,
    ) -> Result<Self, AuthorityRefusalV1> {
        if trusted_now_unix_ms == 0 {
            return Err(AuthorityRefusalV1::Refused);
        }
        Ok(Self {
            authority,
            last_accepted_unix_ms: trusted_now_unix_ms,
        })
    }

    fn accept_time(&mut self, trusted_now_unix_ms: u64) -> Result<(), AuthorityRefusalV1> {
        if trusted_now_unix_ms == 0 || trusted_now_unix_ms < self.last_accepted_unix_ms {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        self.last_accepted_unix_ms = trusted_now_unix_ms;
        Ok(())
    }

    fn require_route_event(route_event_id: EventIdV1) -> Result<(), AuthorityRefusalV1> {
        if route_event_id == ZERO_DIGEST {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(())
    }
}

impl ProductionSettlementPlanPersistenceV1 for ProductionSettlementPlanPersistenceOwnerV1 {
    fn install_new_plan(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        plan: CompositeSettlementPlanV1,
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
        Self::require_route_event(route_event_id)?;
        self.accept_time(trusted_now_unix_ms)?;
        coordinator
            .install_plan(&mut self.authority, plan, trusted_now_unix_ms)
            .map_err(map_coordinator_error)
    }

    fn revalidate_preinstalled_new_plan(
        &mut self,
        stored: &StoredSettlementPlanV1,
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AuthorityRefusalV1> {
        Self::require_route_event(route_event_id)?;
        // Presence in the coordinator is not proof that Funding committed; the
        // time gate is consumed again, and only a Funding plan may be
        // preinstalled ahead of its parent route event.
        if stored.plan().bindings().action != SettlementActionV1::Funding {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        self.accept_time(trusted_now_unix_ms)
    }

    fn refence_preinstalled_new_plan(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        lease: CoordinatorLeaseV1,
        replacement: CompositeSettlementPlanV1,
        progress_evidence_digest: Digest32,
        route_event_id: EventIdV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
        Self::require_route_event(route_event_id)?;
        if replacement.bindings().action != SettlementActionV1::Funding
            || progress_evidence_digest == ZERO_DIGEST
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        self.accept_time(trusted_now_unix_ms)?;
        coordinator
            .refence_plan(
                lease,
                replacement,
                progress_evidence_digest,
                &mut self.authority,
                trusted_now_unix_ms,
            )
            .map_err(map_coordinator_error)
    }

    fn refence_existing_plan(
        &mut self,
        coordinator: &mut DurableSettlementCoordinatorV1,
        lease: CoordinatorLeaseV1,
        replacement: CompositeSettlementPlanV1,
        progress_evidence_digest: Digest32,
        trusted_now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1> {
        if progress_evidence_digest == ZERO_DIGEST {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        self.accept_time(trusted_now_unix_ms)?;
        coordinator
            .refence_plan(
                lease,
                replacement,
                progress_evidence_digest,
                &mut self.authority,
                trusted_now_unix_ms,
            )
            .map_err(map_coordinator_error)
    }
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_not_impl_any;

    use super::*;

    assert_not_impl_any!(ProductionSettlementPlanPersistenceOwnerV1: Clone, Copy, Default);
}

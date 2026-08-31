//! Route-bound production deadline authority.
//!
//! A due row from the durable route store is not, by itself, permission to
//! manufacture an arbitrary route event.  This authority accepts only the
//! exact `(context_digest, deadline)` pairs frozen by the composition root for
//! one route.  Every accepted deadline moves the route into `RecoveryOnly`;
//! economic refund actions are still authorized and externalized through the
//! normal typed settlement authorities.

use std::collections::BTreeMap;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use route_executor::{
    Digest32, EventIdV1, HealthStateV1, RouteEventV1, RouteIdV1, TimerIdV1, TimerKindV1,
};

#[cfg(not(any(feature = "development", feature = "simulation", test)))]
use crate::supervisor::authority_seal;
use crate::supervisor::{AuthorityRefusalV1, TimerAuthority, TimerDispatchV1};

const ZERO_DIGEST: Digest32 = [0; 32];
const DEADLINE_REASON_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/DEADLINE-RECOVERY/V1\0";

/// One deadline identity admitted by the authenticated route composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionDeadlineBindingV1 {
    context_digest: Digest32,
    deadline_unix_ms: u64,
}

impl ProductionDeadlineBindingV1 {
    pub(crate) fn new(
        context_digest: Digest32,
        deadline_unix_ms: u64,
    ) -> Result<Self, AuthorityRefusalV1> {
        if context_digest == ZERO_DIGEST || deadline_unix_ms == 0 {
            return Err(AuthorityRefusalV1::Refused);
        }
        Ok(Self {
            context_digest,
            deadline_unix_ms,
        })
    }
}

/// Deterministic, route-scoped authority for durable deadline delivery.
pub(crate) struct ProductionDeadlineTimerAuthorityV1 {
    route_id: RouteIdV1,
    deadlines: BTreeMap<Digest32, u64>,
}

impl core::fmt::Debug for ProductionDeadlineTimerAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionDeadlineTimerAuthorityV1")
            .field("route_id", &self.route_id)
            .field("deadline_count", &self.deadlines.len())
            .finish()
    }
}

impl ProductionDeadlineTimerAuthorityV1 {
    pub(crate) fn new<I>(route_id: RouteIdV1, bindings: I) -> Result<Self, AuthorityRefusalV1>
    where
        I: IntoIterator<Item = ProductionDeadlineBindingV1>,
    {
        if route_id == ZERO_DIGEST {
            return Err(AuthorityRefusalV1::Refused);
        }
        let mut deadlines = BTreeMap::new();
        for binding in bindings {
            if deadlines
                .insert(binding.context_digest, binding.deadline_unix_ms)
                .is_some()
            {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
        }
        if deadlines.is_empty() {
            return Err(AuthorityRefusalV1::Refused);
        }
        Ok(Self {
            route_id,
            deadlines,
        })
    }

    fn event_for_facts(
        &self,
        facts: DeadlineDispatchFactsV1,
    ) -> Result<RouteEventV1, AuthorityRefusalV1> {
        if facts.route_id != self.route_id
            || facts.timer_id == ZERO_DIGEST
            || facts.event_id == ZERO_DIGEST
            || facts.kind != TimerKindV1::Deadline
            || facts.deadline_unix_ms == 0
            || facts.context_digest == ZERO_DIGEST
            || facts.scheduling_fence == 0
            || facts.current_fence < facts.scheduling_fence
            || facts.attempt == 0
            || self.deadlines.get(&facts.context_digest) != Some(&facts.deadline_unix_ms)
        {
            return Err(AuthorityRefusalV1::Refused);
        }
        let reason_digest = deadline_reason_digest_v1(&facts)?;
        Ok(RouteEventV1::SetHealth {
            target: HealthStateV1::RecoveryOnly,
            reason_digest,
        })
    }
}

#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl authority_seal::Sealed for ProductionDeadlineTimerAuthorityV1 {}

impl TimerAuthority for ProductionDeadlineTimerAuthorityV1 {
    fn event_for_due_timer(
        &mut self,
        timer: TimerDispatchV1,
    ) -> Result<RouteEventV1, AuthorityRefusalV1> {
        self.event_for_facts(DeadlineDispatchFactsV1 {
            route_id: timer.route_id(),
            timer_id: timer.timer_id(),
            kind: timer.kind(),
            deadline_unix_ms: timer.deadline_unix_ms(),
            context_digest: timer.context_digest(),
            scheduling_fence: timer.scheduling_fence(),
            current_fence: timer.current_fence(),
            attempt: timer.attempt(),
            event_id: timer.event_id(),
        })
    }
}

#[derive(Clone, Copy)]
struct DeadlineDispatchFactsV1 {
    route_id: RouteIdV1,
    timer_id: TimerIdV1,
    kind: TimerKindV1,
    deadline_unix_ms: u64,
    context_digest: Digest32,
    scheduling_fence: u64,
    current_fence: u64,
    attempt: u64,
    event_id: EventIdV1,
}

fn deadline_reason_digest_v1(
    facts: &DeadlineDispatchFactsV1,
) -> Result<Digest32, AuthorityRefusalV1> {
    let mut hash = Blake2bVar::new(32).map_err(|_| AuthorityRefusalV1::Inconsistent)?;
    hash.update(DEADLINE_REASON_DOMAIN_V1);
    hash.update(&facts.route_id);
    hash.update(&facts.timer_id);
    hash.update(&[timer_kind_tag(facts.kind)]);
    hash.update(&facts.deadline_unix_ms.to_be_bytes());
    hash.update(&facts.context_digest);
    hash.update(&facts.scheduling_fence.to_be_bytes());
    // `current_fence` is intentionally not committed: takeover may advance it
    // between two deliveries of the same durable timer.  The event id and all
    // timer-owned fields remain stable, as required by `TimerAuthority`.
    hash.update(&facts.event_id);
    let mut digest = [0; 32];
    hash.finalize_variable(&mut digest)
        .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
    if digest == ZERO_DIGEST {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(digest)
}

const fn timer_kind_tag(kind: TimerKindV1) -> u8 {
    match kind {
        TimerKindV1::Deadline => 0,
        TimerKindV1::Retry => 1,
        TimerKindV1::Reconcile => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: Digest32 = [0x11; 32];
    const TIMER: Digest32 = [0x22; 32];
    const CONTEXT: Digest32 = [0x33; 32];
    const EVENT: Digest32 = [0x44; 32];
    const DEADLINE: u64 = 50_000;

    fn authority() -> ProductionDeadlineTimerAuthorityV1 {
        ProductionDeadlineTimerAuthorityV1::new(
            ROUTE,
            [ProductionDeadlineBindingV1::new(CONTEXT, DEADLINE).unwrap()],
        )
        .unwrap()
    }

    fn facts() -> DeadlineDispatchFactsV1 {
        DeadlineDispatchFactsV1 {
            route_id: ROUTE,
            timer_id: TIMER,
            kind: TimerKindV1::Deadline,
            deadline_unix_ms: DEADLINE,
            context_digest: CONTEXT,
            scheduling_fence: 7,
            current_fence: 8,
            attempt: 1,
            event_id: EVENT,
        }
    }

    #[test]
    fn exact_deadline_is_deterministic_and_only_enters_recovery() {
        let authority = authority();
        let first = authority.event_for_facts(facts()).unwrap();
        let second = authority
            .event_for_facts(DeadlineDispatchFactsV1 {
                current_fence: 19,
                attempt: 7,
                ..facts()
            })
            .unwrap();
        assert_eq!(first, second);
        assert!(matches!(
            first,
            RouteEventV1::SetHealth {
                target: HealthStateV1::RecoveryOnly,
                reason_digest
            } if reason_digest != ZERO_DIGEST
        ));
    }

    #[test]
    fn wrong_scope_or_delivery_fails_closed() {
        let authority = authority();
        let mutations = [
            DeadlineDispatchFactsV1 {
                route_id: [0x12; 32],
                ..facts()
            },
            DeadlineDispatchFactsV1 {
                context_digest: [0x34; 32],
                ..facts()
            },
            DeadlineDispatchFactsV1 {
                deadline_unix_ms: DEADLINE + 1,
                ..facts()
            },
            DeadlineDispatchFactsV1 {
                current_fence: 6,
                ..facts()
            },
            DeadlineDispatchFactsV1 {
                kind: TimerKindV1::Retry,
                ..facts()
            },
            DeadlineDispatchFactsV1 {
                attempt: 0,
                ..facts()
            },
        ];
        for mutation in mutations {
            assert_eq!(
                authority.event_for_facts(mutation),
                Err(AuthorityRefusalV1::Refused)
            );
        }
    }

    #[test]
    fn duplicate_context_and_empty_configuration_are_refused() {
        let binding = ProductionDeadlineBindingV1::new(CONTEXT, DEADLINE).unwrap();
        assert!(matches!(
            ProductionDeadlineTimerAuthorityV1::new(ROUTE, [binding, binding]),
            Err(AuthorityRefusalV1::Inconsistent)
        ));
        assert!(matches!(
            ProductionDeadlineTimerAuthorityV1::new(ROUTE, []),
            Err(AuthorityRefusalV1::Refused)
        ));
    }
}

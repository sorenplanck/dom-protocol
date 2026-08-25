//! Consolidated DOM↔X settlement state machine (F2 spec §7, DECIDED).
//!
//! The transition function is PURE: no I/O, no persistence, no adapters.
//! It returns the next context and the effects the engine must enqueue —
//! and persistence is NOT one of those effects: every accepted transition
//! is written in one store transaction BEFORE any effect becomes visible
//! to the dispatcher (spec §7.3). That is the load-bearing difference from
//! the audited prototype (now [`crate::legacy`]), where `PersistState` was
//! itself an effect.
//!
//! Secret material never enters these types (spec §18): events carry only
//! [`EvidenceRefV1`] — a reference the adapter can re-fetch from the chain
//! and hand to the cryptographic leg. The core stores the reference and
//! the verified result, never `t`.
//!
//! Invariants:
//! - I4: `Settled` and `Refunded` are mutually exclusive terminals.
//! - I5: no funding authorization before the refund path is armed.
//! - I11 / D-003: reorg regresses the OBSERVATION, never the economic
//!   outcome; at most one terminal outcome per settlement.
//! - D-004: `RefundConfirmed` is accepted without a prior
//!   `TimelockExpired` — the CHAIN enforces the timelock; the machine
//!   records observed reality. Do not "fix" this by adding a second
//!   authority over the timelock.

use crate::types::{ChainId, Digest32};

/// Settlement states (spec §7.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum SettlementState {
    /// Session created; terms and roster frozen; refund not yet armed.
    Preparing,
    /// Pre-signed refund finalized, validated and persisted (I5).
    ReadyToFund,
    /// Funding observed, awaiting the finality policy.
    Confirming,
    /// Funding confirmed; awaiting verified claim evidence.
    Settling,
    /// Terminal: claim confirmed.
    Settled,
    /// Terminal: refund confirmed.
    Refunded,
}

impl SettlementState {
    /// Terminal economic state (I11): immutable once reached.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Refunded)
    }
}

/// Reference to one verifiable piece of public on-chain evidence
/// (spec §7.2). The core never holds the evidence itself — the adapter
/// re-fetches it from the chain and delivers it to the cryptographic leg.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvidenceRefV1 {
    /// Chain the evidence lives on (32-byte registry id).
    pub chain_id: ChainId,
    /// Transaction identifier on that chain.
    pub tx_id: Digest32,
    /// Index of the event inside the transaction.
    pub event_index: u32,
    /// Height of the block carrying the evidence.
    pub block_height: u64,
    /// Anchor (block hash) the observation is pinned to — reorg detection.
    pub block_anchor: Digest32,
}

/// Events accepted by the machine (spec §7.2). No secret bytes, ever.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SettlementEvent {
    /// Pre-signed refund finalized, validated and persisted (I5).
    RefundArmed,
    /// Funding observed on chain (still subject to reorg).
    FundingObserved {
        /// Reference to the observed funding inclusion.
        evidence: EvidenceRefV1,
    },
    /// Funding reached the finality policy.
    FundingConfirmed {
        /// Reference that must match the accepted observation.
        evidence: EvidenceRefV1,
    },
    /// Post-reorg revalidation concluded the funding is NOT on the
    /// canonical chain; scanning restarts from the height.
    FundingAbsent {
        /// First height the revalidation re-scanned from.
        revalidation_from: u64,
    },
    /// The cryptographic leg verified claim evidence (verify/extract ran
    /// inside the F1 boundary; only the public reference comes back).
    ClaimEvidenceVerified {
        /// Reference to the verified claim evidence.
        evidence: EvidenceRefV1,
    },
    /// Claim confirmed on the leg that closes the settlement.
    ClaimConfirmed {
        /// Reference to the confirmed claim inclusion.
        evidence: EvidenceRefV1,
    },
    /// Timelock expired: the refund becomes executable.
    TimelockExpired,
    /// Refund confirmed (D-004: accepted without prior `TimelockExpired`).
    RefundConfirmed {
        /// Reference to the confirmed refund inclusion.
        evidence: EvidenceRefV1,
    },
    /// Reorg invalidated observations starting at the height.
    ReorgInvalidated {
        /// First invalidated height.
        from_height: u64,
        /// Anchor of the abandoned branch (audited by the store layer).
        old_anchor: Digest32,
    },
}

/// Persisted settlement context (spec §7.2).
///
/// `revision` increments on EVERY accepted transition and is the CAS key
/// of the durable snapshot: economic idempotency is adjudicated by the
/// envelope/event-id dedupe in the store, not by context equality.
/// `last_observed_height` is the observation's idempotency key (I7):
/// without it, redelivering the same `ReorgInvalidated` would regress the
/// state twice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SettlementContext {
    /// Current state.
    pub state: SettlementState,
    /// Monotonic revision, CAS key of the snapshot.
    pub revision: u64,
    /// Height of the last accepted chain observation, if any.
    pub last_observed_height: Option<u64>,
    /// Whether the cryptographic leg verified claim evidence.
    pub claim_evidence_verified: bool,
    /// Whether the refund path is armed (I5 precondition).
    pub refund_path_armed: bool,
}

impl SettlementContext {
    /// Initial context: `Preparing`, revision 0, nothing observed.
    pub const fn new() -> Self {
        Self {
            state: SettlementState::Preparing,
            revision: 0,
            last_observed_height: None,
            claim_evidence_verified: false,
            refund_path_armed: false,
        }
    }
}

impl Default for SettlementContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Effects enqueued AFTER the transition commits (spec §7.3).
///
/// Persistence is not listed here on purpose: every accepted transition is
/// written in one store transaction before the dispatcher sees any effect.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Authorize the funding broadcast (only once I5 is satisfied).
    AuthorizeFunding,
    /// Deliver the verified claim evidence to the cryptographic leg for
    /// consumption (verify/adapt/extract run inside the F1 boundary).
    RequestClaimConsumption {
        /// Reference the leg re-fetches and consumes.
        evidence: EvidenceRefV1,
    },
    /// Enable the refund path (timelock expired).
    ArmRefundPath,
    /// Revalidate observations starting at the height (I11).
    RevalidateFrom {
        /// First height to revalidate.
        height: u64,
    },
    /// Record the terminal economic outcome — at most one per settlement,
    /// enforced by a unique terminal row + CAS in the store.
    RecordTerminalOutcome(SettlementState),
}

/// Result of an accepted transition.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transition {
    /// Next context (revision already incremented).
    pub next: SettlementContext,
    /// Effects to enqueue after commit, in order.
    pub effects: Vec<Effect>,
}

/// Transition errors — all fail closed (spec §7.4).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TransitionError {
    /// Illegal event for the current state.
    #[error("illegal event")]
    IllegalEvent,
    /// Terminal state accepts no further events (I11).
    #[error("terminal state is immutable")]
    TerminalState,
    /// Event delivered before its precondition (e.g. `ClaimConfirmed`
    /// without verified claim evidence).
    #[error("event precondition unsatisfied")]
    PreconditionUnsatisfied,
    /// Evidence does not match the accepted observation.
    #[error("evidence does not match observation")]
    EvidenceMismatch,
    /// Revision counter would overflow.
    #[error("revision overflow")]
    RevisionOverflow,
}

/// Pure transition function (spec §7.4, verbatim semantics).
pub fn transition(
    ctx: SettlementContext,
    event: &SettlementEvent,
) -> Result<Transition, TransitionError> {
    use SettlementEvent as E;
    use SettlementState as S;

    if ctx.state.is_terminal() {
        return Err(TransitionError::TerminalState);
    }

    let mut next = ctx;
    next.revision = ctx
        .revision
        .checked_add(1)
        .ok_or(TransitionError::RevisionOverflow)?;
    let mut effects = Vec::new();

    match (ctx.state, event) {
        (S::Preparing, E::RefundArmed) => {
            next.state = S::ReadyToFund;
            next.refund_path_armed = true;
            effects.push(Effect::AuthorizeFunding);
        }
        (S::ReadyToFund, E::FundingObserved { evidence }) => {
            next.state = S::Confirming;
            next.last_observed_height = Some(evidence.block_height);
        }
        // Re-observation in Confirming: idempotent refresh (same height)
        // or idempotency-key update (new height after a reorg regression).
        (S::Confirming, E::FundingObserved { evidence }) => {
            next.last_observed_height = Some(evidence.block_height);
        }
        (S::Confirming, E::FundingAbsent { .. }) => {
            next.state = S::ReadyToFund;
            next.last_observed_height = None;
        }
        (S::Confirming, E::FundingConfirmed { evidence }) => {
            if ctx.last_observed_height != Some(evidence.block_height) {
                return Err(TransitionError::EvidenceMismatch);
            }
            next.state = S::Settling;
        }
        (S::Settling, E::ClaimEvidenceVerified { evidence }) => {
            next.claim_evidence_verified = true;
            effects.push(Effect::RequestClaimConsumption {
                evidence: *evidence,
            });
        }
        (S::Settling, E::ClaimConfirmed { .. }) => {
            if !ctx.claim_evidence_verified {
                return Err(TransitionError::PreconditionUnsatisfied);
            }
            next.state = S::Settled;
            effects.push(Effect::RecordTerminalOutcome(S::Settled));
        }
        (S::Confirming | S::Settling, E::TimelockExpired) => {
            next.refund_path_armed = true;
            effects.push(Effect::ArmRefundPath);
        }
        // D-004: the chain, not the machine, proves the refund was valid.
        (S::Confirming | S::Settling, E::RefundConfirmed { .. }) => {
            next.state = S::Refunded;
            effects.push(Effect::RecordTerminalOutcome(S::Refunded));
        }
        // I11 + I7: a reorg regresses the affected OBSERVATION exactly
        // once; redelivery is a no-op because the observation is gone.
        (S::Confirming | S::Settling, E::ReorgInvalidated { from_height, .. }) => {
            let affected = ctx.last_observed_height.is_some_and(|h| h >= *from_height);
            if affected {
                next.state = if ctx.state == S::Settling {
                    S::Confirming
                } else {
                    S::ReadyToFund
                };
                next.last_observed_height = None;
                next.claim_evidence_verified = false;
                effects.push(Effect::RevalidateFrom {
                    height: *from_height,
                });
            }
        }
        // Before any observation, a reorg has nothing to invalidate.
        (S::Preparing | S::ReadyToFund, E::ReorgInvalidated { .. }) => {}
        _ => return Err(TransitionError::IllegalEvent),
    }

    Ok(Transition { next, effects })
}

#[cfg(test)]
mod tests {
    use super::*;
    use SettlementEvent as E;
    use SettlementState as S;

    fn evidence(height: u64) -> EvidenceRefV1 {
        EvidenceRefV1 {
            chain_id: ChainId([0xC0; 32]),
            tx_id: [0x71; 32],
            event_index: 0,
            block_height: height,
            block_anchor: [0xA0; 32],
        }
    }

    const ALL_STATES: [S; 6] = [
        S::Preparing,
        S::ReadyToFund,
        S::Confirming,
        S::Settling,
        S::Settled,
        S::Refunded,
    ];

    fn all_events() -> Vec<E> {
        vec![
            E::RefundArmed,
            E::FundingObserved {
                evidence: evidence(10),
            },
            E::FundingObserved {
                evidence: evidence(12),
            },
            E::FundingConfirmed {
                evidence: evidence(10),
            },
            E::FundingConfirmed {
                evidence: evidence(12),
            },
            E::FundingAbsent {
                revalidation_from: 5,
            },
            E::ClaimEvidenceVerified {
                evidence: evidence(11),
            },
            E::ClaimConfirmed {
                evidence: evidence(11),
            },
            E::TimelockExpired,
            E::RefundConfirmed {
                evidence: evidence(13),
            },
            E::ReorgInvalidated {
                from_height: 10,
                old_anchor: [0xA0; 32],
            },
            E::ReorgInvalidated {
                from_height: 5,
                old_anchor: [0xA0; 32],
            },
            E::ReorgInvalidated {
                from_height: 50,
                old_anchor: [0xA0; 32],
            },
        ]
    }

    fn ctx(state: S, height: Option<u64>, verified: bool) -> SettlementContext {
        SettlementContext {
            state,
            revision: 7,
            last_observed_height: height,
            claim_evidence_verified: verified,
            refund_path_armed: !matches!(state, S::Preparing),
        }
    }

    fn all_contexts() -> Vec<SettlementContext> {
        let mut v = Vec::new();
        for s in ALL_STATES {
            for h in [None, Some(3u64), Some(10u64), Some(50u64)] {
                for verified in [false, true] {
                    v.push(ctx(s, h, verified));
                }
            }
        }
        v
    }

    /// Everything except the revision: what "economically identical" means.
    fn projection(c: SettlementContext) -> (S, Option<u64>, bool, bool) {
        (
            c.state,
            c.last_observed_height,
            c.claim_evidence_verified,
            c.refund_path_armed,
        )
    }

    fn happy_path_to(target: S) -> SettlementContext {
        let mut c = SettlementContext::new();
        let script: Vec<E> = match target {
            S::Preparing => vec![],
            S::ReadyToFund => vec![E::RefundArmed],
            S::Confirming => vec![
                E::RefundArmed,
                E::FundingObserved {
                    evidence: evidence(10),
                },
            ],
            _ => vec![
                E::RefundArmed,
                E::FundingObserved {
                    evidence: evidence(10),
                },
                E::FundingConfirmed {
                    evidence: evidence(10),
                },
            ],
        };
        for e in &script {
            c = transition(c, e).expect("happy path").next;
        }
        c
    }

    #[test]
    fn revision_strictly_increments_on_every_accepted_transition() {
        for c in all_contexts() {
            for e in all_events() {
                if let Ok(t) = transition(c, &e) {
                    assert_eq!(t.next.revision, c.revision + 1, "({c:?}, {e:?})");
                }
            }
        }
    }

    #[test]
    fn revision_overflow_fails_closed() {
        let mut c = happy_path_to(S::Confirming);
        c.revision = u64::MAX;
        assert_eq!(
            transition(c, &E::TimelockExpired).unwrap_err(),
            TransitionError::RevisionOverflow
        );
    }

    #[test]
    fn funding_is_never_authorized_before_refund_is_armed() {
        // I5: no path out of Preparing authorizes funding without
        // RefundArmed, and the accepting transition arms the flag.
        for e in all_events() {
            if matches!(e, E::RefundArmed) {
                continue;
            }
            if let Ok(t) = transition(SettlementContext::new(), &e) {
                assert!(
                    !t.effects.contains(&Effect::AuthorizeFunding),
                    "I5 violated by {e:?}"
                );
            }
        }
        let t = transition(SettlementContext::new(), &E::RefundArmed).unwrap();
        assert!(t.effects.contains(&Effect::AuthorizeFunding));
        assert!(t.next.refund_path_armed);
    }

    #[test]
    fn settled_and_refunded_are_mutually_exclusive_and_terminal() {
        // I4 + I11: no event moves a settlement out of a terminal.
        for terminal in [S::Settled, S::Refunded] {
            for e in all_events() {
                assert_eq!(
                    transition(ctx(terminal, Some(10), true), &e).unwrap_err(),
                    TransitionError::TerminalState,
                    "terminal {terminal:?} accepted {e:?}"
                );
            }
        }
    }

    #[test]
    fn at_most_one_terminal_outcome_exhaustive() {
        // Exhaustive depth-7 search over all event sequences from the
        // initial context: never more than one RecordTerminalOutcome.
        fn walk(c: SettlementContext, depth: usize, terminals: usize, worst: &mut usize) {
            *worst = (*worst).max(terminals);
            if depth == 0 {
                return;
            }
            for e in all_events() {
                if let Ok(t) = transition(c, &e) {
                    let add = t
                        .effects
                        .iter()
                        .filter(|f| matches!(f, Effect::RecordTerminalOutcome(_)))
                        .count();
                    walk(t.next, depth - 1, terminals + add, worst);
                }
            }
        }
        let mut worst = 0;
        walk(SettlementContext::new(), 7, 0, &mut worst);
        assert_eq!(worst, 1, "more than one terminal economic outcome");
    }

    #[test]
    fn claim_without_verified_evidence_fails_closed() {
        let c = happy_path_to(S::Settling);
        assert!(!c.claim_evidence_verified);
        assert_eq!(
            transition(
                c,
                &E::ClaimConfirmed {
                    evidence: evidence(11)
                }
            )
            .unwrap_err(),
            TransitionError::PreconditionUnsatisfied
        );
    }

    #[test]
    fn verified_claim_settles_and_requests_consumption() {
        let c = happy_path_to(S::Settling);
        let verified = transition(
            c,
            &E::ClaimEvidenceVerified {
                evidence: evidence(11),
            },
        )
        .unwrap();
        assert_eq!(verified.next.state, S::Settling);
        assert!(verified.next.claim_evidence_verified);
        assert!(verified.effects.contains(&Effect::RequestClaimConsumption {
            evidence: evidence(11)
        }));
        let settled = transition(
            verified.next,
            &E::ClaimConfirmed {
                evidence: evidence(11),
            },
        )
        .unwrap();
        assert_eq!(settled.next.state, S::Settled);
        assert!(settled
            .effects
            .contains(&Effect::RecordTerminalOutcome(S::Settled)));
    }

    #[test]
    fn funding_confirmed_with_mismatched_evidence_fails_closed() {
        let c = happy_path_to(S::Confirming);
        assert_eq!(c.last_observed_height, Some(10));
        assert_eq!(
            transition(
                c,
                &E::FundingConfirmed {
                    evidence: evidence(12)
                }
            )
            .unwrap_err(),
            TransitionError::EvidenceMismatch
        );
    }

    #[test]
    fn refund_confirmed_without_timelock_expired_is_accepted() {
        // D-004: the chain enforces the timelock; the machine records
        // reality. From both Confirming and Settling.
        for target in [S::Confirming, S::Settling] {
            let c = happy_path_to(target);
            let t = transition(
                c,
                &E::RefundConfirmed {
                    evidence: evidence(13),
                },
            )
            .unwrap();
            assert_eq!(t.next.state, S::Refunded);
            assert!(t
                .effects
                .contains(&Effect::RecordTerminalOutcome(S::Refunded)));
        }
    }

    #[test]
    fn timelock_expiry_arms_refund_without_moving_state() {
        for target in [S::Confirming, S::Settling] {
            let c = happy_path_to(target);
            let t = transition(c, &E::TimelockExpired).unwrap();
            assert_eq!(t.next.state, target);
            assert!(t.next.refund_path_armed);
            assert!(t.effects.contains(&Effect::ArmRefundPath));
        }
    }

    #[test]
    fn reorg_regresses_observation_not_outcome_and_clears_verification() {
        let c = happy_path_to(S::Settling);
        let verified = transition(
            c,
            &E::ClaimEvidenceVerified {
                evidence: evidence(11),
            },
        )
        .unwrap()
        .next;
        assert!(verified.claim_evidence_verified);
        let t = transition(
            verified,
            &E::ReorgInvalidated {
                from_height: 10,
                old_anchor: [0xA0; 32],
            },
        )
        .unwrap();
        assert_eq!(t.next.state, S::Confirming);
        assert_eq!(t.next.last_observed_height, None);
        assert!(
            !t.next.claim_evidence_verified,
            "reorg must invalidate the affected proof"
        );
        assert!(t.effects.contains(&Effect::RevalidateFrom { height: 10 }));
        assert!(!t.next.state.is_terminal());
    }

    #[test]
    fn reorg_below_the_observed_height_is_economically_a_no_op() {
        let c = happy_path_to(S::Settling);
        let t = transition(
            c,
            &E::ReorgInvalidated {
                from_height: 50,
                old_anchor: [0xA0; 32],
            },
        )
        .unwrap();
        assert_eq!(projection(t.next), projection(c));
        assert!(t.effects.is_empty(), "no effect for an unaffected reorg");
    }

    #[test]
    fn redelivered_reorg_never_regresses_twice() {
        // I7 (at-least-once): the same reorg event redelivered after the
        // regression is economically inert (the observation is gone).
        let c = happy_path_to(S::Settling);
        let e = E::ReorgInvalidated {
            from_height: 10,
            old_anchor: [0xA0; 32],
        };
        let first = transition(c, &e).unwrap();
        let second = transition(first.next, &e).unwrap();
        assert_eq!(projection(second.next), projection(first.next));
        assert!(second.effects.is_empty());
    }

    #[test]
    fn reobservation_refreshes_height_and_same_height_is_economically_inert() {
        let c = happy_path_to(S::Confirming);
        let again = transition(
            c,
            &E::FundingObserved {
                evidence: evidence(10),
            },
        )
        .unwrap();
        assert_eq!(projection(again.next), projection(c));
        assert!(again.effects.is_empty());
        let refreshed = transition(
            c,
            &E::FundingObserved {
                evidence: evidence(12),
            },
        )
        .unwrap();
        assert_eq!(refreshed.next.last_observed_height, Some(12));
        assert_eq!(refreshed.next.state, S::Confirming);
    }

    #[test]
    fn funding_absent_is_illegal_outside_confirming() {
        for st in [S::Preparing, S::ReadyToFund, S::Settling] {
            assert_eq!(
                transition(
                    ctx(st, Some(10), false),
                    &E::FundingAbsent {
                        revalidation_from: 5
                    }
                )
                .unwrap_err(),
                TransitionError::IllegalEvent,
                "FundingAbsent only exists during Confirming ({st:?})"
            );
        }
    }

    #[test]
    fn funding_absent_after_regression_rearms_early() {
        // Settling --reorg--> Confirming(None) --FundingAbsent-->
        // ReadyToFund, then a fresh observation restarts the cycle without
        // waiting for the timelock. The refund path stays armed (I5 was
        // satisfied once and the pre-signed refund remains valid).
        let c = happy_path_to(S::Settling);
        let after_reorg = transition(
            c,
            &E::ReorgInvalidated {
                from_height: 10,
                old_anchor: [0xA0; 32],
            },
        )
        .unwrap()
        .next;
        assert_eq!(after_reorg.state, S::Confirming);
        assert_eq!(after_reorg.last_observed_height, None);
        let rearmed = transition(
            after_reorg,
            &E::FundingAbsent {
                revalidation_from: 5,
            },
        )
        .unwrap()
        .next;
        assert_eq!(rearmed.state, S::ReadyToFund);
        assert!(rearmed.refund_path_armed);
        let reobserved = transition(
            rearmed,
            &E::FundingObserved {
                evidence: evidence(20),
            },
        )
        .unwrap()
        .next;
        assert_eq!(reobserved.state, S::Confirming);
        assert_eq!(reobserved.last_observed_height, Some(20));
    }

    #[test]
    fn redelivery_of_any_accepted_event_is_economically_idempotent() {
        // At-least-once delivery (I7): if the same event is accepted
        // twice in a row, the second acceptance must not change the
        // economic projection. (Store-level event-id dedupe normally
        // rejects the redelivery before the machine even runs; this is
        // the machine's own defense in depth.)
        for c in all_contexts() {
            for e in all_events() {
                if let Ok(first) = transition(c, &e) {
                    if let Ok(second) = transition(first.next, &e) {
                        assert_eq!(
                            projection(second.next),
                            projection(first.next),
                            "redelivery changed the projection ({c:?}, {e:?})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn no_event_carries_or_stores_secret_bytes() {
        // Compile-time by construction (no secret-bearing variant exists),
        // runtime spot check: every effect of every accepted transition is
        // one of the five public-effect kinds.
        for c in all_contexts() {
            for e in all_events() {
                if let Ok(t) = transition(c, &e) {
                    for eff in &t.effects {
                        assert!(matches!(
                            eff,
                            Effect::AuthorizeFunding
                                | Effect::RequestClaimConsumption { .. }
                                | Effect::ArmRefundPath
                                | Effect::RevalidateFrom { .. }
                                | Effect::RecordTerminalOutcome(_)
                        ));
                    }
                }
            }
        }
    }

    /// The normative table of spec §7.5, row by row, as executable truth.
    #[test]
    fn normative_table_holds() {
        // Preparing | RefundArmed -> ReadyToFund + AuthorizeFunding.
        let t = transition(SettlementContext::new(), &E::RefundArmed).unwrap();
        assert_eq!(t.next.state, S::ReadyToFund);
        assert_eq!(t.effects, vec![Effect::AuthorizeFunding]);

        // ReadyToFund | FundingObserved -> Confirming, no effect.
        let t = transition(
            happy_path_to(S::ReadyToFund),
            &E::FundingObserved {
                evidence: evidence(10),
            },
        )
        .unwrap();
        assert_eq!(t.next.state, S::Confirming);
        assert!(t.effects.is_empty());

        // Confirming | FundingObserved -> Confirming (idempotent refresh).
        let t = transition(
            happy_path_to(S::Confirming),
            &E::FundingObserved {
                evidence: evidence(12),
            },
        )
        .unwrap();
        assert_eq!(t.next.state, S::Confirming);
        assert!(t.effects.is_empty());

        // Confirming | FundingAbsent -> ReadyToFund, no effect.
        let t = transition(
            happy_path_to(S::Confirming),
            &E::FundingAbsent {
                revalidation_from: 5,
            },
        )
        .unwrap();
        assert_eq!(t.next.state, S::ReadyToFund);
        assert!(t.effects.is_empty());

        // Confirming | FundingConfirmed(matching) -> Settling, no effect.
        let t = transition(
            happy_path_to(S::Confirming),
            &E::FundingConfirmed {
                evidence: evidence(10),
            },
        )
        .unwrap();
        assert_eq!(t.next.state, S::Settling);
        assert!(t.effects.is_empty());

        // Settling | ClaimEvidenceVerified -> Settling + consumption.
        // Settling | ClaimConfirmed -> Settled + terminal record.
        // (proved in verified_claim_settles_and_requests_consumption)

        // Confirming/Settling | TimelockExpired -> same state + ArmRefundPath.
        // (proved in timelock_expiry_arms_refund_without_moving_state)

        // Confirming/Settling | RefundConfirmed -> Refunded + terminal.
        // (proved in refund_confirmed_without_timelock_expired_is_accepted)

        // Non-terminal | ReorgInvalidated -> idempotent regression.
        // (proved in the reorg tests)

        // Terminal | any event -> error, terminal never changes.
        // (proved in settled_and_refunded_are_mutually_exclusive_and_terminal)
    }
}

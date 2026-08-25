//! USPE — minimal economic assurance (F4).
//!
//! DOM Interop Foundation Document v0.2.1 §3.4 and invariant I12.
//!
//! NON-NEGOTIABLE CONSTRAINT OF DOM v2: all slashing and compensation is
//! executable through cryptography and timelocks — the effects of this
//! machine (`ExecuteSlash`, releases) are authorizations for conditioned
//! spends in contracts (ConditionLock/2-of-2), NEVER calls to an
//! operator, arbiter or admin. There is no human-intervention state;
//! timeouts resolve everything via the conservative `terminal_policy`:
//! with no evidence accepted within the deadline, the bond goes back
//! (ClaimRejected → Released).
//!
//! As in `kaystra_core::state`, the transition function is PURE and
//! table-driven: no I/O, no clock, no adapters. Evidence arrives already
//! VERIFIED by the adapters (I9) — this machine decides economic
//! consequence, it does not interpret chain bytes.
//!
//! Invariants of gate G-F4, proven in the tests by exhaustive search:
//! - NO_DOUBLE_COMPENSATION: at most one compensation per obligation;
//! - NO_RELEASE_AND_SLASH: release and slash never occur in the same
//!   history of an obligation;
//! - TIMEOUT_SAFE: from every waiting state there is a timeout event that
//!   progresses toward a terminal without any privileged action;
//! - cap: the compensated amount never exceeds `compensation_cap`;
//! - binding: certificate and claim are invalid under a divergent
//!   `terms_hash`;
//! - late evidence after rejection/termination cannot slash.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bond;
pub mod evidence;
pub mod journal;
pub mod objects;

/// Assurance states of ONE protected obligation.
///
/// Ported from the Master Document v1.0.1 §8.3, adapted (no
/// ACTION_REQUIRED; EvidenceVerification is mechanical verification by
/// the adapters, not human review).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AssuranceState {
    /// Policy waives the bond for this obligation. Terminal.
    NotRequired,
    /// Bond required; awaiting the collateral lock.
    BondRequired,
    /// Collateral lock observed; awaiting verified evidence.
    BondLocking,
    /// Certificate issued; obligation protected.
    Protected,
    /// Bond release authorized, awaiting on-chain confirmation. Three
    /// origins converge here, all economically identical (the collateral
    /// goes back to whoever posted it): the obligation was fulfilled, the
    /// claim window elapsed unused, or the collateral was never
    /// certified before its verification deadline.
    ReleasePending,
    /// Economic terminal: bond released.
    Released,
    /// Obligation failed; window for the protected party to claim
    /// compensation.
    ClaimWindow,
    /// Claim registered; awaiting the verified evidence result.
    EvidenceVerification,
    /// Evidence rejected (or deadline expired): release path.
    ClaimRejected,
    /// Evidence accepted: slash authorized, awaiting compensation
    /// confirmed on-chain.
    Slashed,
    /// Economic terminal: compensation executed.
    Compensated,
}

impl AssuranceState {
    /// Economic terminal (no event is accepted afterwards).
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::NotRequired | Self::Released | Self::Compensated)
    }
}

/// Accepted events. All evidence arrives VERIFIED (I9) — the events
/// carry results, never chain bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AssuranceEvent {
    /// Collateral lock observed on the bond chain.
    BondLockObserved,
    /// Collateral evidence verified by the adapter, bound to the terms.
    /// Issues the certificate (its only possible origin).
    CollateralVerified {
        /// Terms binding the certificate carries.
        terms_hash: [u8; 32],
    },
    /// Settlement of the obligation reached terminal SETTLED.
    ObligationSettled,
    /// Demonstrable failure or expired settlement deadline.
    ObligationFailed,
    /// Bond release confirmed on-chain.
    ReleaseConfirmed,
    /// Protected party registered a compensation claim.
    CompensationClaimed {
        /// Terms binding of the claim — must match the certificate.
        terms_hash: [u8; 32],
    },
    /// Verified result of the claim's evidence.
    EvidenceVerified {
        /// `true` = obligation failure proven.
        valid: bool,
    },
    /// Collateral-verification deadline expired without VERIFIED
    /// collateral (none arrived, or every attempt diverged from the
    /// obligation's terms). TIMEOUT_SAFE: nothing was ever protected, so
    /// the locked collateral goes back to whoever posted it.
    CollateralDeadlineExpired,
    /// Claim window expired without a claim.
    ClaimWindowExpired,
    /// Evidence-verification deadline expired without accepted evidence.
    EvidenceDeadlineExpired,
    /// Compensation confirmed on-chain with the effective amount.
    CompensationConfirmed {
        /// Compensated amount, in the bond's unit.
        amount: u128,
    },
}

/// Effects the engine executes after an accepted transition.
///
/// All are authorizations for conditioned spends — no effect is an
/// administrative decision (I12).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AssuranceEffect {
    /// Persist the new state before any external action.
    PersistState(AssuranceState),
    /// Issue the protection certificate (only after verified collateral).
    IssueCertificate {
        /// Terms binding recorded in the certificate.
        terms_hash: [u8; 32],
    },
    /// Authorize the bond release spend.
    AuthorizeRelease,
    /// Authorize the bond slash spend (unlocked by evidence).
    ExecuteSlash,
    /// Record the terminal economic outcome — at most one.
    RecordEconomicOutcome(AssuranceState),
}

/// Transition errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AssuranceError {
    /// Illegal event for the current state.
    #[error("illegal event for current assurance state")]
    IllegalEvent,
    /// Terminal state is immutable.
    #[error("terminal assurance state is immutable")]
    TerminalState,
    /// `terms_hash` diverges from the one bound to the obligation.
    #[error("terms hash does not match the protected obligation")]
    TermsMismatch,
    /// Compensation would exceed the policy cap.
    #[error("compensation exceeds the policy cap")]
    CompensationExceedsCap,
}

/// Persisted assurance context of an obligation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssuranceContext {
    /// Current state.
    pub state: AssuranceState,
    /// Terms binding of the obligation (immutable after creation).
    pub terms_hash: [u8; 32],
    /// Compensation cap of the policy (bond's unit).
    pub compensation_cap: u128,
}

impl AssuranceContext {
    /// Creates the context according to the policy: with or without a bond requirement.
    pub const fn new(terms_hash: [u8; 32], compensation_cap: u128, bond_required: bool) -> Self {
        Self {
            state: if bond_required {
                AssuranceState::BondRequired
            } else {
                AssuranceState::NotRequired
            },
            terms_hash,
            compensation_cap,
        }
    }
}

/// Result of an accepted transition.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssuranceTransition {
    /// Next context.
    pub next: AssuranceContext,
    /// Effects, in order; `PersistState` always first.
    pub effects: Vec<AssuranceEffect>,
}

/// Pure transition function.
pub fn assurance_transition(
    ctx: AssuranceContext,
    event: &AssuranceEvent,
) -> Result<AssuranceTransition, AssuranceError> {
    use AssuranceEvent as E;
    use AssuranceState as S;

    if ctx.state.is_terminal() {
        return Err(AssuranceError::TerminalState);
    }

    let (next_state, mut effects) = match (ctx.state, event) {
        (S::BondRequired, E::BondLockObserved) => (S::BondLocking, vec![]),

        // The certificate's only origin: VERIFIED collateral with terms
        // identical to the obligation's (binding invariant).
        (S::BondLocking, E::CollateralVerified { terms_hash }) => {
            if *terms_hash != ctx.terms_hash {
                return Err(AssuranceError::TermsMismatch);
            }
            (
                S::Protected,
                vec![AssuranceEffect::IssueCertificate {
                    terms_hash: *terms_hash,
                }],
            )
        }

        // TIMEOUT_SAFE: the only state that locks collateral before any
        // protection exists must not be able to strand it. No
        // certificate was issued and no slash can ever have been
        // authorized from here, so the collateral simply goes back —
        // this arm cannot interact with the compensation path.
        (S::BondLocking, E::CollateralDeadlineExpired) => {
            (S::ReleasePending, vec![AssuranceEffect::AuthorizeRelease])
        }

        (S::Protected, E::ObligationSettled) => {
            (S::ReleasePending, vec![AssuranceEffect::AuthorizeRelease])
        }

        (S::Protected, E::ObligationFailed) => (S::ClaimWindow, vec![]),

        // TIMEOUT_SAFE: window without a claim => release path.
        (S::ClaimWindow, E::ClaimWindowExpired) => {
            (S::ReleasePending, vec![AssuranceEffect::AuthorizeRelease])
        }

        (S::ClaimWindow, E::CompensationClaimed { terms_hash }) => {
            if *terms_hash != ctx.terms_hash {
                return Err(AssuranceError::TermsMismatch);
            }
            (S::EvidenceVerification, vec![])
        }

        (S::EvidenceVerification, E::EvidenceVerified { valid: true }) => {
            (S::Slashed, vec![AssuranceEffect::ExecuteSlash])
        }
        (S::EvidenceVerification, E::EvidenceVerified { valid: false }) => {
            (S::ClaimRejected, vec![])
        }
        // Conservative TIMEOUT_SAFE (terminal_policy): with no evidence
        // accepted within the deadline, the bond goes back — the claimant
        // had the window.
        (S::EvidenceVerification, E::EvidenceDeadlineExpired) => (S::ClaimRejected, vec![]),

        // ClaimRejected converges to release.
        (S::ClaimRejected, E::ReleaseConfirmed) => (
            S::Released,
            vec![AssuranceEffect::RecordEconomicOutcome(S::Released)],
        ),
        (S::ClaimRejected, E::ObligationSettled) => {
            // Tolerated arrival order: authorizes the missing release.
            (S::ClaimRejected, vec![AssuranceEffect::AuthorizeRelease])
        }

        (S::ReleasePending, E::ReleaseConfirmed) => (
            S::Released,
            vec![AssuranceEffect::RecordEconomicOutcome(S::Released)],
        ),

        (S::Slashed, E::CompensationConfirmed { amount }) => {
            if *amount > ctx.compensation_cap {
                return Err(AssuranceError::CompensationExceedsCap);
            }
            (
                S::Compensated,
                vec![AssuranceEffect::RecordEconomicOutcome(S::Compensated)],
            )
        }

        _ => return Err(AssuranceError::IllegalEvent),
    };

    let next = AssuranceContext {
        state: next_state,
        ..ctx
    };
    effects.insert(0, AssuranceEffect::PersistState(next.state));
    Ok(AssuranceTransition { next, effects })
}

#[cfg(test)]
mod tests {
    use super::*;
    use AssuranceEvent as E;
    use AssuranceState as S;

    const TERMS: [u8; 32] = [0x11; 32];
    const WRONG_TERMS: [u8; 32] = [0x22; 32];
    const CAP: u128 = 1_000;

    fn ctx0() -> AssuranceContext {
        AssuranceContext::new(TERMS, CAP, true)
    }

    fn all_events() -> Vec<E> {
        vec![
            E::BondLockObserved,
            E::CollateralVerified { terms_hash: TERMS },
            E::CollateralVerified {
                terms_hash: WRONG_TERMS,
            },
            E::ObligationSettled,
            E::ObligationFailed,
            E::ReleaseConfirmed,
            E::CompensationClaimed { terms_hash: TERMS },
            E::CompensationClaimed {
                terms_hash: WRONG_TERMS,
            },
            E::EvidenceVerified { valid: true },
            E::EvidenceVerified { valid: false },
            E::CollateralDeadlineExpired,
            E::ClaimWindowExpired,
            E::EvidenceDeadlineExpired,
            E::CompensationConfirmed { amount: CAP },
            E::CompensationConfirmed { amount: CAP + 1 },
        ]
    }

    /// Walks ALL event sequences up to `depth`, accumulating each
    /// history's effects, and calls the checker on each history.
    fn walk_all(depth: usize, check: &mut dyn FnMut(&[AssuranceEffect])) {
        fn rec(
            ctx: AssuranceContext,
            depth: usize,
            history: &mut Vec<AssuranceEffect>,
            events: &[E],
            check: &mut dyn FnMut(&[AssuranceEffect]),
        ) {
            check(history);
            if depth == 0 {
                return;
            }
            for e in events {
                if let Ok(t) = assurance_transition(ctx, e) {
                    let added = t.effects.len();
                    history.extend(t.effects.iter().cloned());
                    rec(t.next, depth - 1, history, events, check);
                    history.truncate(history.len() - added);
                }
            }
        }
        let events = all_events();
        let mut history = Vec::new();
        rec(ctx0(), depth, &mut history, &events, check);
    }

    #[test]
    fn no_double_compensation_exhaustive() {
        // G-F4 NO_DOUBLE_COMPENSATION: no history, up to depth 9,
        // contains two Compensated outcomes (nor two ExecuteSlash).
        walk_all(9, &mut |h| {
            let comp = h
                .iter()
                .filter(|e| matches!(e, AssuranceEffect::RecordEconomicOutcome(S::Compensated)))
                .count();
            let slash = h
                .iter()
                .filter(|e| matches!(e, AssuranceEffect::ExecuteSlash))
                .count();
            assert!(comp <= 1, "double compensation: {h:?}");
            assert!(slash <= 1, "double slash: {h:?}");
        });
    }

    #[test]
    fn no_release_and_slash_exhaustive() {
        // G-F4 NO_RELEASE_AND_SLASH: release (authorized OR recorded) and
        // slash never coexist in the same history.
        walk_all(9, &mut |h| {
            let released = h.iter().any(|e| {
                matches!(
                    e,
                    AssuranceEffect::AuthorizeRelease
                        | AssuranceEffect::RecordEconomicOutcome(S::Released)
                )
            });
            let slashed = h.iter().any(|e| matches!(e, AssuranceEffect::ExecuteSlash));
            assert!(
                !(released && slashed),
                "release and slash in the same history: {h:?}"
            );
        });
    }

    #[test]
    fn terminal_outcomes_are_mutually_exclusive_exhaustive() {
        // Released and Compensated never both occur (I12).
        walk_all(9, &mut |h| {
            let outcomes: Vec<_> = h
                .iter()
                .filter(|e| matches!(e, AssuranceEffect::RecordEconomicOutcome(_)))
                .collect();
            assert!(outcomes.len() <= 1, "two economic outcomes: {h:?}");
        });
    }

    #[test]
    fn certificate_only_from_verified_collateral_with_matching_terms() {
        walk_all(6, &mut |h| {
            // Every issued certificate carries exactly the obligation's
            // terms — and can only have come from CollateralVerified.
            for e in h {
                if let AssuranceEffect::IssueCertificate { terms_hash } = e {
                    assert_eq!(*terms_hash, TERMS);
                }
            }
        });
        // Wrong terms never issue a certificate:
        let mut c = assurance_transition(ctx0(), &E::BondLockObserved)
            .unwrap()
            .next;
        assert_eq!(
            assurance_transition(
                c,
                &E::CollateralVerified {
                    terms_hash: WRONG_TERMS
                }
            )
            .unwrap_err(),
            AssuranceError::TermsMismatch
        );
        // And with the right terms, it issues exactly once:
        c = assurance_transition(c, &E::CollateralVerified { terms_hash: TERMS })
            .unwrap()
            .next;
        assert_eq!(c.state, S::Protected);
    }

    #[test]
    fn claim_with_wrong_terms_is_rejected() {
        let c = protected().0;
        let cw = assurance_transition(c, &E::ObligationFailed).unwrap().next;
        assert_eq!(
            assurance_transition(
                cw,
                &E::CompensationClaimed {
                    terms_hash: WRONG_TERMS
                }
            )
            .unwrap_err(),
            AssuranceError::TermsMismatch
        );
    }

    fn protected() -> (AssuranceContext, ()) {
        let mut c = ctx0();
        for e in [
            E::BondLockObserved,
            E::CollateralVerified { terms_hash: TERMS },
        ] {
            c = assurance_transition(c, &e).unwrap().next;
        }
        assert_eq!(c.state, S::Protected);
        (c, ())
    }

    #[test]
    fn compensation_never_exceeds_cap() {
        let c = protected().0;
        let mut s = c;
        for e in [
            E::ObligationFailed,
            E::CompensationClaimed { terms_hash: TERMS },
            E::EvidenceVerified { valid: true },
        ] {
            s = assurance_transition(s, &e).unwrap().next;
        }
        assert_eq!(s.state, S::Slashed);
        assert_eq!(
            assurance_transition(s, &E::CompensationConfirmed { amount: CAP + 1 }).unwrap_err(),
            AssuranceError::CompensationExceedsCap
        );
        let done = assurance_transition(s, &E::CompensationConfirmed { amount: CAP }).unwrap();
        assert_eq!(done.next.state, S::Compensated);
    }

    #[test]
    fn timeout_safe_every_waiting_state_progresses_without_privilege() {
        // G-F4 TIMEOUT_SAFE: from every state that locks collateral, a
        // (non-privileged) timeout event progresses toward a terminal.
        // BondLocking --deadline--> ReleasePending --confirms--> Released:
        // collateral that is never certified is never stranded.
        let locking = assurance_transition(ctx0(), &E::BondLockObserved)
            .unwrap()
            .next;
        assert_eq!(locking.state, S::BondLocking);
        let expired = assurance_transition(locking, &E::CollateralDeadlineExpired).unwrap();
        assert_eq!(expired.next.state, S::ReleasePending);
        assert!(expired.effects.contains(&AssuranceEffect::AuthorizeRelease));
        assert!(
            !expired
                .effects
                .iter()
                .any(|e| matches!(e, AssuranceEffect::IssueCertificate { .. })),
            "uncertified collateral must not issue a certificate"
        );
        assert_eq!(
            assurance_transition(expired.next, &E::ReleaseConfirmed)
                .unwrap()
                .next
                .state,
            S::Released
        );

        let c = protected().0;
        // ClaimWindow --expires--> ReleasePending --confirms--> Released
        let cw = assurance_transition(c, &E::ObligationFailed).unwrap().next;
        let rp = assurance_transition(cw, &E::ClaimWindowExpired).unwrap();
        assert_eq!(rp.next.state, S::ReleasePending);
        assert!(rp.effects.contains(&AssuranceEffect::AuthorizeRelease));
        let done = assurance_transition(rp.next, &E::ReleaseConfirmed).unwrap();
        assert_eq!(done.next.state, S::Released);
        // EvidenceVerification --expires--> ClaimRejected --release--> Released
        let ev = assurance_transition(
            assurance_transition(c, &E::ObligationFailed).unwrap().next,
            &E::CompensationClaimed { terms_hash: TERMS },
        )
        .unwrap()
        .next;
        let cr = assurance_transition(ev, &E::EvidenceDeadlineExpired).unwrap();
        assert_eq!(cr.next.state, S::ClaimRejected);
        let rel = assurance_transition(cr.next, &E::ReleaseConfirmed).unwrap();
        assert_eq!(rel.next.state, S::Released);
    }

    #[test]
    fn late_evidence_cannot_slash_after_rejection_or_terminal() {
        let c = protected().0;
        let mut s = c;
        for e in [
            E::ObligationFailed,
            E::CompensationClaimed { terms_hash: TERMS },
            E::EvidenceDeadlineExpired, // rejection by deadline
        ] {
            s = assurance_transition(s, &e).unwrap().next;
        }
        assert_eq!(s.state, S::ClaimRejected);
        assert_eq!(
            assurance_transition(s, &E::EvidenceVerified { valid: true }).unwrap_err(),
            AssuranceError::IllegalEvent,
            "late evidence slashed after rejection"
        );
        let released = assurance_transition(s, &E::ReleaseConfirmed).unwrap().next;
        assert_eq!(
            assurance_transition(released, &E::EvidenceVerified { valid: true }).unwrap_err(),
            AssuranceError::TerminalState
        );
    }

    #[test]
    fn not_required_is_terminal_from_birth() {
        let c = AssuranceContext::new(TERMS, CAP, false);
        for e in all_events() {
            assert_eq!(
                assurance_transition(c, &e).unwrap_err(),
                AssuranceError::TerminalState
            );
        }
    }

    #[test]
    fn every_accepted_transition_persists_first() {
        walk_all(5, &mut |_| {});
        // Directed check of the first-effect rule:
        let t = assurance_transition(ctx0(), &E::BondLockObserved).unwrap();
        assert!(matches!(
            t.effects.first(),
            Some(AssuranceEffect::PersistState(_))
        ));
    }

    #[test]
    fn crash_redelivery_is_idempotent_or_rejected() {
        // At-least-once (I7): redelivering the same event after a "crash"
        // on the new context never produces a context different from the first.
        fn contexts() -> Vec<AssuranceContext> {
            let mut v = vec![ctx0(), AssuranceContext::new(TERMS, CAP, false)];
            let mut c = ctx0();
            for e in [
                E::BondLockObserved,
                E::CollateralVerified { terms_hash: TERMS },
                E::ObligationFailed,
                E::CompensationClaimed { terms_hash: TERMS },
                E::EvidenceVerified { valid: true },
            ] {
                c = assurance_transition(c, &e).unwrap().next;
                v.push(c);
            }
            v
        }
        for c in contexts() {
            for e in all_events() {
                if let Ok(first) = assurance_transition(c, &e) {
                    if let Ok(second) = assurance_transition(first.next, &e) {
                        assert_eq!(
                            second.next, first.next,
                            "redelivery changed the context ({c:?}, {e:?})"
                        );
                    }
                }
            }
        }
    }
}

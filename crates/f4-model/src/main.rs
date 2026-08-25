//! F4 model checker — the economic invariants of gate G-F4.
//!
//! Exhaustively explores the composition of the REAL assurance machine
//! (`uspe::assurance_transition`) with an abstract world and proves the
//! properties the Foundation Document requires of the USPE:
//!
//! ```text
//! NO_DOUBLE_COMPENSATION
//! NO_RELEASE_AND_SLASH
//! TIMEOUT_SAFE
//! AG compensated_total <= compensation_cap
//! AG certificate.terms == obligation.terms
//! AG recorded_outcome in {Released, Compensated}
//! AG accepted_transition -> PersistState(next) first
//! AG terminal -> AX unchanged
//! AG effect in authorized_set                     (I12)
//! ```
//!
//! The machine under check is the production transition function, not a
//! re-modelled copy. Only the WORLD is abstract: the economic facts a
//! history can accumulate are saturating counters, which is what keeps
//! the space finite while preserving every distinction the properties
//! speak about ("zero", "one", "more than one").
//!
//! # Threat model of the exploration
//!
//! Delivery is ADVERSARIAL and UNBOUNDED: every event of the alphabet is
//! offered in every reachable world, any number of times, in any order.
//! The checker therefore assumes **no** deduplication layer — the
//! properties below are proven by the machine's own structure, not by the
//! engine's I7 idempotency. That is deliberately stronger than reality:
//! in production the ratified F2 outbox suppresses redelivery, and its
//! own delivery properties (persist-before-effect, at-most-once
//! completion, atomic commit under crash) are model-checked separately by
//! `f2-model` over the same outbox this machine will ride. This checker
//! does not re-prove those; it proves the ECONOMIC decisions.
//!
//! One consequence of dropping deduplication is visible in the results:
//! `AuthorizeRelease` may be emitted more than once along a history (the
//! tolerated `ClaimRejected + ObligationSettled` arrival order re-emits
//! it). That is sound — every emission authorizes the SAME single
//! conditioned spend, which the lock can execute at most once — so the
//! uniqueness properties below are stated over RECORDED ECONOMIC
//! OUTCOMES and over `ExecuteSlash`, which must never repeat.
//!
//! Exit code 0 = every reachable state satisfies every property.

#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};

use uspe::{
    assurance_transition, AssuranceContext, AssuranceEffect, AssuranceEvent, AssuranceState,
};

/// Terms binding of the modelled obligation.
const TERMS: [u8; 32] = [0x11; 32];
/// A divergent binding — every object carrying it must be refused.
const WRONG_TERMS: [u8; 32] = [0x22; 32];
/// Compensation cap of the modelled policy.
const CAP: u128 = 1_000;
/// Saturation ceiling of the fact counters. The properties only ever
/// distinguish 0, 1 and "more than 1", so counting past 2 would enlarge
/// the space without adding an economic distinction.
const FACT_CEILING: u8 = 2;

/// Every event the world may deliver, including the ill-formed ones
/// (divergent terms, amount above the cap) an adversary would try.
fn alphabet() -> Vec<AssuranceEvent> {
    use AssuranceEvent as E;
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
        E::CompensationConfirmed { amount: 0 },
        E::CompensationConfirmed { amount: CAP },
        E::CompensationConfirmed { amount: CAP + 1 },
    ]
}

/// The NON-PRIVILEGED subset: deadline expiries and the on-chain
/// confirmation of a spend the machine has already authorized. Nothing
/// here requires the cooperation of a counterparty, an operator or an
/// arbiter — anyone, including the harmed party, can drive these (I12).
///
/// `ObligationFailed` belongs here because the Foundation Document
/// defines it as "demonstrable failure OR expired settlement deadline":
/// its timeout half needs no cooperation.
fn timeout_alphabet() -> Vec<AssuranceEvent> {
    use AssuranceEvent as E;
    vec![
        E::ObligationFailed,
        E::CollateralDeadlineExpired,
        E::ClaimWindowExpired,
        E::EvidenceDeadlineExpired,
        E::ReleaseConfirmed,
        E::CompensationConfirmed { amount: CAP },
    ]
}

/// States in which collateral is already locked and no terminal has been
/// reached — the states where TIMEOUT_SAFE has something to protect.
///
/// `BondRequired` is excluded on purpose: no collateral has been locked
/// yet, so there is no capital to strand. `NotRequired` is terminal.
fn bond_at_risk(state: AssuranceState) -> bool {
    !state.is_terminal()
        && !matches!(
            state,
            AssuranceState::NotRequired | AssuranceState::BondRequired
        )
}

/// Abstract world: the machine's state plus the economic facts the
/// history has accumulated so far.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct World {
    state: AssuranceState,
    /// Terms carried by the last issued certificate, if any.
    certificate: Option<[u8; 32]>,
    certificates_issued: u8,
    release_authorized: u8,
    slash_authorized: u8,
    release_recorded: u8,
    compensation_recorded: u8,
    /// Outcomes recorded for a state that is not an economic terminal —
    /// must stay zero.
    ill_formed_outcomes: u8,
    /// Sum of every confirmed compensation, saturating just above the cap
    /// so that "over the cap" is representable without unbounding it.
    compensated_total: u128,
}

impl World {
    fn initial(bond_required: bool) -> Self {
        Self {
            state: AssuranceContext::new(TERMS, CAP, bond_required).state,
            certificate: None,
            certificates_issued: 0,
            release_authorized: 0,
            slash_authorized: 0,
            release_recorded: 0,
            compensation_recorded: 0,
            ill_formed_outcomes: 0,
            compensated_total: 0,
        }
    }

    /// The obligation's terms and cap are immutable, so the context is
    /// fully determined by the modelled state.
    fn context(&self) -> AssuranceContext {
        AssuranceContext {
            state: self.state,
            terms_hash: TERMS,
            compensation_cap: CAP,
        }
    }
}

fn bump(counter: &mut u8) {
    *counter = counter.saturating_add(1).min(FACT_CEILING);
}

/// Exhaustive match over the effect alphabet: every variant is an
/// authorization for a conditioned spend or a bookkeeping record, and
/// none is a call to an operator, an arbiter or an admin (I12). Adding a
/// privileged variant upstream stops this file from compiling.
fn effect_is_authorized(effect: &AssuranceEffect) -> bool {
    match effect {
        AssuranceEffect::PersistState(_)
        | AssuranceEffect::IssueCertificate { .. }
        | AssuranceEffect::AuthorizeRelease
        | AssuranceEffect::ExecuteSlash
        | AssuranceEffect::RecordEconomicOutcome(_) => true,
    }
}

/// A property violation, with the transition that exhibits it.
#[derive(Debug)]
struct Violation {
    property: &'static str,
    detail: String,
}

/// Can a terminal be reached from `from` using ONLY non-privileged
/// events? This is the TIMEOUT_SAFE obligation, checked as reachability
/// over the machine itself.
fn escapes_without_privilege(from: AssuranceState) -> bool {
    let mut seen: HashSet<AssuranceState> = HashSet::new();
    let mut queue: VecDeque<AssuranceState> = VecDeque::new();
    seen.insert(from);
    queue.push_back(from);
    while let Some(state) = queue.pop_front() {
        if state.is_terminal() {
            return true;
        }
        let ctx = AssuranceContext {
            state,
            terms_hash: TERMS,
            compensation_cap: CAP,
        };
        for event in timeout_alphabet() {
            if let Ok(applied) = assurance_transition(ctx, &event) {
                if seen.insert(applied.next.state) {
                    queue.push_back(applied.next.state);
                }
            }
        }
    }
    false
}

/// Successors of one world, plus any violation observed on its edges.
fn successors(world: &World, out: &mut Vec<World>, violations: &mut Vec<Violation>) {
    // TIMEOUT_SAFE is a property of the STATE reached, checked wherever
    // collateral is locked and the history has not terminated.
    if bond_at_risk(world.state) && !escapes_without_privilege(world.state) {
        violations.push(Violation {
            property: "TIMEOUT_SAFE",
            detail: format!(
                "{:?}: no non-privileged event sequence reaches a terminal — collateral is stranded",
                world.state
            ),
        });
    }

    for event in alphabet() {
        let applied = match assurance_transition(world.context(), &event) {
            Ok(applied) => applied,
            Err(_) => continue,
        };

        // AG terminal -> AX unchanged: a terminal state must accept
        // nothing at all, so reaching this line from one is already the
        // violation.
        if world.state.is_terminal() {
            violations.push(Violation {
                property: "AG terminal -> AX unchanged",
                detail: format!("{:?} accepted {event:?}", world.state),
            });
        }

        // AG accepted_transition -> PersistState(next) first: the new
        // state must be durable before any external authorization, and
        // exactly one persist per transition.
        if applied.effects.first() != Some(&AssuranceEffect::PersistState(applied.next.state)) {
            violations.push(Violation {
                property: "AG accepted_transition -> PersistState(next) first",
                detail: format!("{:?} --{event:?}--> {:?}", world.state, applied.effects),
            });
        }
        if applied
            .effects
            .iter()
            .filter(|e| matches!(e, AssuranceEffect::PersistState(_)))
            .count()
            != 1
        {
            violations.push(Violation {
                property: "AG accepted_transition -> PersistState(next) first",
                detail: format!("{:?} --{event:?}--> repeated persist", world.state),
            });
        }

        let mut next = *world;
        next.state = applied.next.state;
        for effect in &applied.effects {
            if !effect_is_authorized(effect) {
                violations.push(Violation {
                    property: "AG effect in authorized_set",
                    detail: format!("{effect:?}"),
                });
            }
            match effect {
                AssuranceEffect::PersistState(_) => {}
                AssuranceEffect::IssueCertificate { terms_hash } => {
                    bump(&mut next.certificates_issued);
                    next.certificate = Some(*terms_hash);
                }
                AssuranceEffect::AuthorizeRelease => bump(&mut next.release_authorized),
                AssuranceEffect::ExecuteSlash => bump(&mut next.slash_authorized),
                AssuranceEffect::RecordEconomicOutcome(AssuranceState::Released) => {
                    bump(&mut next.release_recorded);
                }
                AssuranceEffect::RecordEconomicOutcome(AssuranceState::Compensated) => {
                    bump(&mut next.compensation_recorded);
                    if let AssuranceEvent::CompensationConfirmed { amount } = event {
                        next.compensated_total =
                            next.compensated_total.saturating_add(amount).min(CAP + 1);
                    }
                }
                AssuranceEffect::RecordEconomicOutcome(_) => bump(&mut next.ill_formed_outcomes),
            }
        }

        check_facts(&next, world, &event, violations);
        out.push(next);
    }
}

/// Every property that is a predicate over accumulated facts.
fn check_facts(
    next: &World,
    from: &World,
    event: &AssuranceEvent,
    violations: &mut Vec<Violation>,
) {
    let edge = || format!("{:?} --{event:?}--> {next:?}", from.state);

    if next.compensation_recorded > 1 || next.slash_authorized > 1 {
        violations.push(Violation {
            property: "NO_DOUBLE_COMPENSATION",
            detail: edge(),
        });
    }
    if next.release_recorded + next.compensation_recorded > 1 {
        violations.push(Violation {
            property: "NO_DOUBLE_COMPENSATION",
            detail: format!("two economic outcomes recorded: {}", edge()),
        });
    }
    let released = next.release_authorized > 0 || next.release_recorded > 0;
    if released && next.slash_authorized > 0 {
        violations.push(Violation {
            property: "NO_RELEASE_AND_SLASH",
            detail: edge(),
        });
    }
    if next.compensated_total > CAP {
        violations.push(Violation {
            property: "AG compensated_total <= compensation_cap",
            detail: edge(),
        });
    }
    if next.certificates_issued > 1 || matches!(next.certificate, Some(t) if t != TERMS) {
        violations.push(Violation {
            property: "AG certificate.terms == obligation.terms",
            detail: edge(),
        });
    }
    if next.ill_formed_outcomes > 0 {
        violations.push(Violation {
            property: "AG recorded_outcome in {Released, Compensated}",
            detail: edge(),
        });
    }
}

/// Every property the checker adjudicates, in report order.
const PROPERTIES: [&str; 9] = [
    "coverage: every state of the machine is reachable",
    "NO_DOUBLE_COMPENSATION",
    "NO_RELEASE_AND_SLASH",
    "TIMEOUT_SAFE",
    "AG compensated_total <= compensation_cap",
    "AG certificate.terms == obligation.terms",
    "AG recorded_outcome in {Released, Compensated}",
    "AG accepted_transition -> PersistState(next) first",
    "AG terminal -> AX unchanged",
];

/// Exhaustive breadth-first exploration from both policy shapes (bond
/// required and waived). The world is finite, so this is a fixpoint: it
/// covers histories of EVERY length, not a bounded prefix.
fn explore() -> (HashSet<World>, Vec<Violation>) {
    let mut seen: HashSet<World> = HashSet::new();
    let mut queue: VecDeque<World> = VecDeque::new();
    let mut violations = Vec::new();
    for bond_required in [true, false] {
        let initial = World::initial(bond_required);
        if seen.insert(initial) {
            queue.push_back(initial);
        }
    }

    let mut buffer = Vec::new();
    while let Some(world) = queue.pop_front() {
        buffer.clear();
        successors(&world, &mut buffer, &mut violations);
        for next in buffer.drain(..) {
            if seen.insert(next) {
                queue.push_back(next);
            }
        }
    }
    (seen, violations)
}

/// Dense index of every state. The match is exhaustive on purpose: a
/// state added upstream stops this file from compiling, and the index
/// test below then forces it into `ALL_STATES` — the model can never
/// silently ignore part of the machine.
fn state_index(state: AssuranceState) -> usize {
    match state {
        AssuranceState::NotRequired => 0,
        AssuranceState::BondRequired => 1,
        AssuranceState::BondLocking => 2,
        AssuranceState::Protected => 3,
        AssuranceState::ReleasePending => 4,
        AssuranceState::Released => 5,
        AssuranceState::ClaimWindow => 6,
        AssuranceState::EvidenceVerification => 7,
        AssuranceState::ClaimRejected => 8,
        AssuranceState::Slashed => 9,
        AssuranceState::Compensated => 10,
    }
}

/// Every state of the machine, in `state_index` order.
const ALL_STATES: [AssuranceState; 11] = [
    AssuranceState::NotRequired,
    AssuranceState::BondRequired,
    AssuranceState::BondLocking,
    AssuranceState::Protected,
    AssuranceState::ReleasePending,
    AssuranceState::Released,
    AssuranceState::ClaimWindow,
    AssuranceState::EvidenceVerification,
    AssuranceState::ClaimRejected,
    AssuranceState::Slashed,
    AssuranceState::Compensated,
];

/// States of the machine the exploration never visited, in index order.
/// A non-empty result means the model degenerated and every property
/// below would hold vacuously over the missing part.
fn uncovered_states(seen: &HashSet<World>) -> Vec<AssuranceState> {
    let mut missing: Vec<AssuranceState> = ALL_STATES
        .into_iter()
        .filter(|state| !seen.iter().any(|world| world.state == *state))
        .collect();
    missing.sort_unstable_by_key(|state| state_index(*state));
    missing
}

fn main() {
    let (seen, mut violations) = explore();
    let missing = uncovered_states(&seen);
    if !missing.is_empty() {
        violations.push(Violation {
            property: "coverage: every state of the machine is reachable",
            detail: format!("never visited: {missing:?}"),
        });
    }
    println!("F4 model checker (G-F4 economic invariants)");
    println!("  reachable worlds explored: {}", seen.len());
    println!(
        "  machine states covered: {}/{}",
        ALL_STATES.len() - missing.len(),
        ALL_STATES.len()
    );
    for property in PROPERTIES {
        let failed = violations.iter().filter(|v| v.property == property).count();
        println!(
            "  {} {property}",
            if failed == 0 { "HOLDS  " } else { "VIOLATED" }
        );
    }
    if violations.is_empty() {
        println!("  result: PASS");
    } else {
        println!("  result: FAIL ({} violations)", violations.len());
        let mut reported: Vec<&str> = Vec::new();
        for violation in &violations {
            if reported.contains(&violation.property) {
                continue;
            }
            reported.push(violation.property);
            println!("    {}: {}", violation.property, violation.detail);
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reachable_state_satisfies_every_property() {
        let (_, violations) = explore();
        assert!(
            violations.is_empty(),
            "model checking found {} violation(s): {:?}",
            violations.len(),
            violations.iter().take(3).collect::<Vec<_>>()
        );
    }

    /// Non-degeneracy: the exploration must actually visit the whole
    /// machine. A model that never leaves the first two states would
    /// satisfy every property above vacuously.
    #[test]
    fn the_exploration_covers_every_state_of_the_machine() {
        let (seen, _) = explore();
        for state in ALL_STATES {
            assert!(
                seen.iter().any(|world| world.state == state),
                "{state:?} is never reached — the model degenerated"
            );
        }
    }

    /// Non-vacuity of the uniqueness properties: both economic terminals
    /// and the certificate must genuinely occur, otherwise "at most one"
    /// is proven of something that never happens.
    #[test]
    fn the_model_reaches_both_economic_outcomes() {
        let (seen, _) = explore();
        assert!(
            seen.iter().any(|w| w.release_recorded > 0),
            "the model never records Released"
        );
        assert!(
            seen.iter().any(|w| w.compensation_recorded > 0),
            "the model never records Compensated"
        );
        assert!(
            seen.iter().any(|w| w.certificates_issued > 0),
            "the model never issues a certificate"
        );
        assert!(
            seen.iter().any(|w| w.slash_authorized > 0),
            "the model never authorizes a slash"
        );
    }

    /// The state alphabet the model enumerates matches the machine's,
    /// one for one. Paired with the exhaustive match in `state_index`,
    /// a state added upstream cannot slip past the model.
    #[test]
    fn every_state_of_the_machine_is_enumerated_exactly_once() {
        let mut indices: Vec<usize> = ALL_STATES.iter().copied().map(state_index).collect();
        indices.sort_unstable();
        assert_eq!(indices, (0..ALL_STATES.len()).collect::<Vec<_>>());
    }

    /// Falsifiability control: the checker must FAIL on a machine that
    /// really does violate the property. A model that cannot report a
    /// violation proves nothing.
    #[test]
    fn the_checker_reports_an_injected_violation() {
        let mut violations = Vec::new();
        let mut world = World::initial(true);
        world.release_authorized = 1;
        world.slash_authorized = 1;
        check_facts(
            &world,
            &World::initial(true),
            &AssuranceEvent::ObligationSettled,
            &mut violations,
        );
        assert!(
            violations
                .iter()
                .any(|v| v.property == "NO_RELEASE_AND_SLASH"),
            "the checker stayed silent on a release-and-slash world"
        );

        let mut over_cap = World::initial(true);
        over_cap.compensated_total = CAP + 1;
        let mut violations = Vec::new();
        check_facts(
            &over_cap,
            &World::initial(true),
            &AssuranceEvent::CompensationConfirmed { amount: CAP + 1 },
            &mut violations,
        );
        assert!(
            violations
                .iter()
                .any(|v| v.property == "AG compensated_total <= compensation_cap"),
            "the checker stayed silent on an over-cap world"
        );
    }

    /// TIMEOUT_SAFE is a reachability claim; this pins the witness for
    /// each state where collateral is locked, so a regression names the
    /// state that lost its escape.
    #[test]
    fn every_state_with_locked_collateral_escapes_without_privilege() {
        for state in [
            AssuranceState::BondLocking,
            AssuranceState::Protected,
            AssuranceState::ReleasePending,
            AssuranceState::ClaimWindow,
            AssuranceState::EvidenceVerification,
            AssuranceState::ClaimRejected,
            AssuranceState::Slashed,
        ] {
            assert!(
                escapes_without_privilege(state),
                "{state:?} strands the collateral: no non-privileged path to a terminal"
            );
        }
    }
}

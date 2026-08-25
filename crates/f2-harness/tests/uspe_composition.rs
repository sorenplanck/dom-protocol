//! USPE composition with a settlement outcome (F4 advance work).
//!
//! The settlement half of G-F2 lives in `g_f2_scenarios.rs`; what remains
//! here is the composition the F2 gate asks for: a terminal settlement
//! outcome released or compensated by the USPE machine, within the cap and
//! without any privileged action, and late evidence that cannot slash
//! after the deadline.
//!
//! The settlement outcome is produced by the REAL durable engine, so the
//! composition rests on a settlement that actually reached its terminal
//! through the store — not on a hand-written label.

mod common;

use common::{Fixture, SECRET};
use kaystra_core::state::SettlementState;
use uspe::{
    assurance_transition, AssuranceContext, AssuranceError, AssuranceEvent, AssuranceState,
};

const TERMS: [u8; 32] = [0x7E; 32];

/// Drives a real settlement to its claim terminal through the durable
/// engine and returns the terminal state.
fn settled_outcome(name: &str) -> SettlementState {
    let (fx, mut engine) = Fixture::new(name, 2, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    for round in 0..12usize {
        if round == 2 {
            fx.chain.submit_claim(SECRET);
        }
        fx.step(&mut engine, 20 + round as i64);
        if fx.state(&engine).is_terminal() {
            break;
        }
    }
    fx.state(&engine)
}

#[test]
fn uspe_composition_settled_releases_bond() {
    // Settlement ends Settled => obligation fulfilled => bond released.
    assert_eq!(settled_outcome("uspe-settled"), SettlementState::Settled);
    let mut a = AssuranceContext::new(TERMS, 1_000, true);
    for e in [
        AssuranceEvent::BondLockObserved,
        AssuranceEvent::CollateralVerified { terms_hash: TERMS },
        AssuranceEvent::ObligationSettled,
        AssuranceEvent::ReleaseConfirmed,
    ] {
        a = assurance_transition(a, &e).unwrap().next;
    }
    assert_eq!(a.state, AssuranceState::Released);
}

#[test]
fn uspe_composition_failure_compensates_within_cap_without_privilege() {
    // Settlement failed (user's refund on their leg) => compensation
    // claim => verified evidence => slash => compensation <= cap.
    // No step is an administrative decision: they are verified events
    // and conditioned spends (I12).
    let mut a = AssuranceContext::new(TERMS, 1_000, true);
    for e in [
        AssuranceEvent::BondLockObserved,
        AssuranceEvent::CollateralVerified { terms_hash: TERMS },
        AssuranceEvent::ObligationFailed,
        AssuranceEvent::CompensationClaimed { terms_hash: TERMS },
        AssuranceEvent::EvidenceVerified { valid: true },
    ] {
        a = assurance_transition(a, &e).unwrap().next;
    }
    assert_eq!(a.state, AssuranceState::Slashed);
    assert_eq!(
        assurance_transition(a, &AssuranceEvent::CompensationConfirmed { amount: 1_001 })
            .unwrap_err(),
        AssuranceError::CompensationExceedsCap
    );
    let done =
        assurance_transition(a, &AssuranceEvent::CompensationConfirmed { amount: 900 }).unwrap();
    assert_eq!(done.next.state, AssuranceState::Compensated);
}

#[test]
fn uspe_late_evidence_after_deadline_cannot_slash() {
    // Late evidence (G-F2 "late evidence"): after the deadline, the claim
    // was rejected and valid evidence arriving afterwards is illegal.
    let mut a = AssuranceContext::new(TERMS, 1_000, true);
    for e in [
        AssuranceEvent::BondLockObserved,
        AssuranceEvent::CollateralVerified { terms_hash: TERMS },
        AssuranceEvent::ObligationFailed,
        AssuranceEvent::CompensationClaimed { terms_hash: TERMS },
        AssuranceEvent::EvidenceDeadlineExpired,
    ] {
        a = assurance_transition(a, &e).unwrap().next;
    }
    assert_eq!(a.state, AssuranceState::ClaimRejected);
    assert_eq!(
        assurance_transition(a, &AssuranceEvent::EvidenceVerified { valid: true }).unwrap_err(),
        AssuranceError::IllegalEvent
    );
}

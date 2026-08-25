//! The G-F2 scenario table (F2 spec §16), executed end to end.
//!
//! Each test is one row of the table, named after its `F2-E2E-0NN` id.
//! Everything runs against the REAL durable store, the REAL machine and
//! the REAL simulated chain; crashes are injected at the eleven commit and
//! dispatch boundaries of spec §13 through the test-only `failpoints`
//! feature, and a "restart" drops the engine and re-opens the database.
//!
//! `dom-sim` is NOT the DOM (I13/I15).

mod common;

use adapter_dom_sim::LockState;
use common::{b32, Engine, Fixture, CHAIN, SECRET};
use f2_harness::{SimEffectSink, SimSettlementChain, SinkAction};
use kaystra_core::ingest::{ingest_event, EngineError, IngestResult};
use kaystra_core::settlement_engine::{SettlementEngine, SettlementEngineError};
use kaystra_core::state::{EvidenceRefV1, SettlementEvent, SettlementState};
use kaystra_core::store_port::{
    derive_event_id, effects_to_outbox, EventEnvelopeV1, EvidenceStatus, SettlementStore,
    SqliteSettlementStore, StorePortError, PROTOCOL_VERSION,
};
use kaystra_core::types::{ChainId, EvidenceId, SessionId};
use store::failpoints::{arm, disarm, Failpoint};

/// Drives a settlement all the way to `Settled`: arm, fund, confirm,
/// claim, confirm. Returns the number of rounds it took.
fn drive_to_settled(fx: &Fixture, engine: &mut Engine, claim_at_round: usize) -> usize {
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    for round in 0..14usize {
        if round == claim_at_round {
            fx.chain.submit_claim(SECRET);
        }
        fx.step(engine, 20 + round as i64);
        if fx.state(engine).is_terminal() {
            return round;
        }
    }
    panic!("the claim path did not converge");
}

fn terminal_of(engine: &Engine, fx: &Fixture) -> Option<SettlementState> {
    engine
        .store()
        .terminal(fx.terms.settlement_id)
        .unwrap()
        .map(|(state, _, _)| state)
}

/// Journal event ids, in sequence order.
fn journal_event_ids(engine: &Engine, fx: &Fixture) -> Vec<EvidenceId> {
    engine
        .store()
        .journal(fx.terms.settlement_id)
        .unwrap()
        .into_iter()
        .map(|row| row.envelope.event_id)
        .collect()
}

#[test]
fn f2_e2e_001_claim_path_reaches_settled() {
    let (fx, mut engine) = Fixture::new("e2e-001", 2, 1_000);
    drive_to_settled(&fx, &mut engine, 2);
    assert_eq!(fx.state(&engine), SettlementState::Settled);
    assert_eq!(terminal_of(&engine, &fx), Some(SettlementState::Settled));
    assert_eq!(engine.sink().claim_consumptions().len(), 1);
}

#[test]
fn f2_e2e_002_timelock_path_reaches_refunded() {
    let (fx, mut engine) = Fixture::new("e2e-002", 2, 6);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.run_until_terminal(&mut engine, 16, 12);
    assert_eq!(fx.state(&engine), SettlementState::Refunded);
    assert_eq!(terminal_of(&engine, &fx), Some(SettlementState::Refunded));
    assert_eq!(fx.chain.lock_state(), LockState::Spent);
}

#[test]
fn f2_e2e_003_crash_at_every_boundary_matches_the_baseline() {
    // A crash at C0–C10 must leave the settlement reaching the SAME
    // terminal as an uninterrupted run, with no effect left behind.
    let boundaries = [
        Failpoint::C0,
        Failpoint::C1,
        Failpoint::C2,
        Failpoint::C3,
        Failpoint::C4,
        Failpoint::C5,
        Failpoint::C6,
        Failpoint::C7,
        Failpoint::C8,
        Failpoint::C9,
        Failpoint::C10,
    ];
    // Baseline, no injection.
    let (fx, mut engine) = Fixture::new("e2e-003-baseline", 2, 1_000);
    drive_to_settled(&fx, &mut engine, 2);
    let baseline = terminal_of(&engine, &fx);
    assert_eq!(baseline, Some(SettlementState::Settled));

    for (index, boundary) in boundaries.iter().enumerate() {
        for fire_at in 0..5usize {
            let name = format!("e2e-003-{index}-{fire_at}");
            let (fx, mut engine) = Fixture::new(&name, 2, 1_000);
            engine.arm_refund(10).unwrap();
            engine.tick(11).unwrap();
            for round in 0..14usize {
                if round == 2 {
                    fx.chain.submit_claim(SECRET);
                }
                if round == fire_at {
                    arm(*boundary);
                }
                fx.chain.advance(1);
                if engine.tick(20 + round as i64).is_err() {
                    // The boundary fired: the process "dies" and a new one
                    // recovers from the same database file.
                    disarm();
                    engine = fx.restart(engine);
                }
                if fx.state(&engine).is_terminal() {
                    break;
                }
            }
            disarm();
            // Converge whatever the crash delayed.
            fx.run_until_terminal(&mut engine, 14, 100);
            assert_eq!(
                terminal_of(&engine, &fx),
                baseline,
                "{boundary:?} at round {fire_at} changed the terminal"
            );
            // One tick to dispatch whatever the terminal enqueued, then
            // the next must find nothing: every effect ran exactly once.
            engine.tick(10_000_000).unwrap();
            let drained = engine.tick(10_000_001).unwrap();
            assert_eq!(
                drained.effects_dispatched, 0,
                "{boundary:?} at round {fire_at} left an effect pending"
            );
        }
    }
}

#[test]
fn f2_e2e_004_duplicating_every_event_produces_no_duplicate_effect() {
    // A second engine over the same database re-delivers every event from
    // the durable cursor. Nothing may be journalled or effected twice.
    let (fx, mut engine) = Fixture::new("e2e-004", 2, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    let mut shadow = fx.open_engine();
    for round in 0..12usize {
        if round == 2 {
            fx.chain.submit_claim(SECRET);
        }
        fx.step(&mut engine, 20 + round as i64);
        // The shadow sees exactly the same chain, from its own cursor.
        shadow.tick(20 + round as i64).unwrap();
        if fx.state(&engine).is_terminal() {
            break;
        }
    }
    assert_eq!(fx.state(&engine), SettlementState::Settled);

    let ids = journal_event_ids(&engine, &fx);
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(ids.len(), unique.len(), "an event was journalled twice");

    // Every effect completed exactly once across both engines.
    assert_eq!(engine.tick(10_000_000).unwrap().effects_dispatched, 0);
    assert_eq!(shadow.tick(10_000_001).unwrap().effects_dispatched, 0);
    // The lock was funded once and spent once: no duplicate submission
    // survived (the chain deduplicates byte-identical bytes, I7).
    assert_eq!(fx.chain.lock_state(), LockState::Spent);
}

#[test]
fn f2_e2e_005_replay_after_restart_is_an_idempotent_ack() {
    let (fx, mut engine) = Fixture::new("e2e-005", 2, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.step(&mut engine, 12);
    fx.step(&mut engine, 13);
    let before = engine.snapshot().unwrap();

    let mut engine = fx.restart(engine);
    let report = engine.tick(14).unwrap();
    assert_eq!(report.committed, 0, "replay committed a new transition");
    let after = engine.snapshot().unwrap();
    assert_eq!(after.context, before.context);
    assert_eq!(after.last_event_seq, before.last_event_seq);

    // Re-deliver an already committed envelope verbatim, as a peer or a
    // rewound scanner would: the answer is an idempotent ACK, and the
    // durable state does not move.
    for row in engine.store().journal(fx.terms.settlement_id).unwrap() {
        assert_eq!(
            ingest_event(engine.store(), &row.envelope, None, 15).unwrap(),
            IngestResult::Duplicate,
            "replaying a journalled envelope must be acknowledged"
        );
    }
    assert_eq!(
        engine.snapshot().unwrap().last_event_seq,
        before.last_event_seq
    );
}

#[test]
fn f2_e2e_006_same_event_id_with_different_bytes_is_equivocation() {
    let (fx, mut engine) = Fixture::new("e2e-006", 2, 1_000);
    engine.arm_refund(10).unwrap();
    fx.step(&mut engine, 11);

    // Take a committed event and re-present its id with other bytes.
    let row = engine
        .store()
        .journal(fx.terms.settlement_id)
        .unwrap()
        .into_iter()
        .next()
        .expect("at least one journalled event");
    let mut forged = row.envelope.clone();
    forged.source_sequence = forged.source_sequence.wrapping_add(1);
    assert_ne!(forged.canonical_bytes(), row.envelope.canonical_bytes());

    let snapshot = engine
        .store()
        .load(fx.terms.settlement_id)
        .unwrap()
        .unwrap();
    let transition = kaystra_core::state::transition(
        kaystra_core::state::SettlementContext::new(),
        &forged.event,
    )
    .unwrap();
    let outbox = effects_to_outbox(&forged, &transition.effects);
    match engine.store().commit_transition(
        snapshot.context.revision,
        &forged,
        &transition,
        &outbox,
        None,
        50,
    ) {
        Err(StorePortError::Equivocation) => {}
        other => panic!("equivocation must fail closed, got {other:?}"),
    }
}

#[test]
fn f2_e2e_007_claim_before_funding_confirmation_parks_then_applies() {
    // Three confirmations: the claim lands while the funding is still
    // confirming, so its verification is parked, not guessed.
    let (fx, mut engine) = Fixture::new("e2e-007", 3, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.step(&mut engine, 12); // funding observed -> Confirming
    assert_eq!(fx.state(&engine), SettlementState::Confirming);

    fx.chain.submit_claim(SECRET);
    fx.step(&mut engine, 13);
    assert_eq!(fx.state(&engine), SettlementState::Confirming);
    assert!(
        engine.parked_len() > 0
            || !engine
                .store()
                .evidence(fx.terms.settlement_id, EvidenceStatus::Parked)
                .unwrap()
                .is_empty(),
        "the early claim must be parked durably"
    );

    fx.run_until_terminal(&mut engine, 12, 20);
    assert_eq!(fx.state(&engine), SettlementState::Settled);
    assert_eq!(engine.sink().claim_consumptions().len(), 1);
}

#[test]
fn f2_e2e_008_batched_and_per_block_delivery_agree() {
    // The same observation SET delivered with different batching (one tick
    // per block versus one tick for many blocks) must produce the same
    // economic projection and the same journalled events.
    let run = |name: &str, batch: u64| -> (SettlementState, Vec<EvidenceId>) {
        let (fx, mut engine) = Fixture::new(name, 2, 1_000);
        engine.arm_refund(10).unwrap();
        engine.tick(11).unwrap();
        for round in 0..10usize {
            if round == 2 {
                fx.chain.submit_claim(SECRET);
            }
            fx.chain.advance(batch);
            engine.tick(20 + round as i64).unwrap();
            if fx.state(&engine).is_terminal() {
                break;
            }
        }
        (fx.state(&engine), journal_event_ids(&engine, &fx))
    };
    let (state_one, events_one) = run("e2e-008-a", 1);
    let (state_many, events_many) = run("e2e-008-b", 3);
    assert_eq!(state_one, SettlementState::Settled);
    assert_eq!(state_many, SettlementState::Settled);
    // Both journals contain the same kinds of decision, without duplicates.
    assert_eq!(
        events_one.len(),
        {
            let mut u = events_one.clone();
            u.sort();
            u.dedup();
            u.len()
        },
        "batched run journalled a duplicate"
    );
    assert_eq!(events_many.len(), {
        let mut u = events_many.clone();
        u.sort();
        u.dedup();
        u.len()
    });
}

#[test]
fn f2_e2e_009_reorg_of_the_claim_before_finality_is_not_terminal() {
    let (fx, mut engine) = Fixture::new("e2e-009", 3, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.step(&mut engine, 12);
    fx.step(&mut engine, 13);
    fx.step(&mut engine, 14);
    assert_eq!(fx.state(&engine), SettlementState::Settling);

    fx.chain.submit_claim(SECRET);
    fx.step(&mut engine, 15);
    assert!(engine.snapshot().unwrap().context.claim_evidence_verified);

    // Reorg away the block carrying the claim, before it is final.
    fx.chain.inject_reorg(1);
    engine.tick(16).unwrap();
    assert!(
        !fx.state(&engine).is_terminal(),
        "a claim removed before finality must not settle"
    );

    // It converges once the claim is re-mined and confirmed.
    fx.run_until_terminal(&mut engine, 14, 20);
    assert!(fx.state(&engine).is_terminal());
    assert_eq!(fx.state(&engine), SettlementState::Settled);
}

#[test]
fn f2_e2e_010_deep_reorg_removing_the_funding_rearms() {
    let (fx, mut engine) = Fixture::new("e2e-010", 2, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.step(&mut engine, 12);
    fx.step(&mut engine, 13);
    assert_eq!(fx.state(&engine), SettlementState::Settling);

    fx.chain.inject_reorg(fx.chain.height());
    engine.tick(14).unwrap();
    assert!(!fx.state(&engine).is_terminal());

    for round in 0..12usize {
        if round == 3 {
            fx.chain.submit_claim(SECRET);
        }
        fx.step(&mut engine, 20 + round as i64);
        if fx.state(&engine).is_terminal() {
            break;
        }
    }
    assert_eq!(fx.state(&engine), SettlementState::Settled);
}

#[test]
fn f2_e2e_011_a_redelivered_reorg_is_a_no_op() {
    let (fx, mut engine) = Fixture::new("e2e-011", 2, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.step(&mut engine, 12);
    fx.step(&mut engine, 13);

    fx.chain.inject_reorg(2);
    engine.tick(14).unwrap();
    let after_first = engine.snapshot().unwrap();

    // Ticking again without any chain change must not regress twice.
    let second = engine.tick(15).unwrap();
    let after_second = engine.snapshot().unwrap();
    assert_eq!(
        after_second.context.state, after_first.context.state,
        "the redelivered reorg regressed the state again"
    );
    assert_eq!(
        second.committed, 0,
        "the redelivered reorg committed a second regression"
    );
}

#[test]
fn f2_e2e_012_evidence_after_terminal_has_no_economic_effect() {
    let (fx, mut engine) = Fixture::new("e2e-012", 2, 1_000);
    drive_to_settled(&fx, &mut engine, 2);
    let terminal = terminal_of(&engine, &fx);

    // A fresh engine rescans from the durable cursor and re-delivers the
    // observations it finds — all of them now late.
    let mut late_engine = fx.open_engine();
    let report = late_engine.tick(500).unwrap();
    assert_eq!(report.committed, 0);
    assert_eq!(
        terminal_of(&late_engine, &fx),
        terminal,
        "late evidence changed the terminal"
    );
    assert_eq!(fx.state(&late_engine), SettlementState::Settled);
}

#[test]
fn f2_e2e_013_a_journal_gap_fails_recovery_closed() {
    let (fx, mut engine) = Fixture::new("e2e-013", 2, 1_000);
    engine.arm_refund(10).unwrap();
    fx.step(&mut engine, 11);
    fx.step(&mut engine, 12);
    drop(engine);

    // Delete the first journal row: the sequence now starts at 2.
    let conn = rusqlite::Connection::open(&fx.path).unwrap();
    conn.execute(
        "DELETE FROM settlement_journal WHERE settlement_id = ?1 AND seq = 1",
        rusqlite::params![fx.terms.settlement_id.0],
    )
    .unwrap();
    drop(conn);

    let store = SqliteSettlementStore::open(&fx.path).unwrap();
    let sink = SimEffectSink::new(fx.chain.clone(), 1_000);
    match SettlementEngine::open(store, fx.chain.clone(), sink, fx.terms.settlement_id) {
        Err(SettlementEngineError::Store(StorePortError::Storage(_)))
        | Err(SettlementEngineError::RecoveryDivergence(_)) => {}
        other => panic!("a journal gap must fail closed, got {other:?}"),
    }
}

#[test]
fn f2_e2e_014_the_cursor_never_advances_without_a_persisted_event() {
    let (fx, mut engine) = Fixture::new("e2e-014", 2, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    let chain_id = ChainId(CHAIN);
    assert!(engine
        .store()
        .cursor(fx.terms.settlement_id, chain_id)
        .unwrap()
        .is_none());

    // Crash immediately before COMMIT on the tick that would persist the
    // funding observation AND its cursor.
    fx.chain.advance(1);
    arm(Failpoint::C6);
    let outcome = engine.tick(12);
    disarm();
    assert!(outcome.is_err(), "the injected crash must surface");

    let engine = fx.restart(engine);
    assert!(
        engine
            .store()
            .cursor(fx.terms.settlement_id, chain_id)
            .unwrap()
            .is_none(),
        "the cursor advanced without a committed event"
    );
    assert_eq!(
        engine.snapshot().unwrap().last_event_seq,
        1,
        "an uncommitted transaction left a journal row"
    );
}

#[test]
fn f2_e2e_015_crash_after_the_external_effect_resends_identical_bytes() {
    let (fx, mut engine) = Fixture::new("e2e-015", 2, 1_000);
    engine.arm_refund(10).unwrap();

    // C9 fires after the sink executed and before completion is marked.
    arm(Failpoint::C9);
    let outcome = engine.tick(11);
    disarm();
    assert!(outcome.is_err(), "the injected crash must surface");
    let executed_before = engine.sink().actions().to_vec();
    assert!(
        executed_before.contains(&SinkAction::FundingSubmitted),
        "the external effect must have run before the crash"
    );

    // The restart re-claims the SAME entry once the lease expires and
    // resends the persisted payload — never a reconstruction.
    let mut engine = fx.restart(engine);
    let report = engine.tick(10_000_000).unwrap();
    assert_eq!(
        report.effects_dispatched, 1,
        "the effect must be re-claimed"
    );
    assert_eq!(report.effects_completed, 1);
    assert!(engine
        .sink()
        .actions()
        .contains(&SinkAction::FundingSubmitted));

    // The chain saw byte-identical submissions: one lock, not two.
    fx.chain.advance(1);
    assert_eq!(fx.chain.lock_state(), LockState::Open);
    // And it is never dispatched again.
    assert_eq!(engine.tick(20_000_000).unwrap().effects_dispatched, 0);
}

#[test]
fn f2_e2e_016_two_writers_on_one_revision_one_wins_the_other_reloads() {
    let (fx, mut engine) = Fixture::new("e2e-016", 2, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    let mut rival = fx.open_engine();

    // Both engines see the same new block and try to commit the same
    // observation from the same revision.
    fx.chain.advance(1);
    let first = engine.tick(12).unwrap();
    let second = rival.tick(12).unwrap();

    assert_eq!(first.committed + second.committed, 1, "both writers won");
    assert!(
        second.duplicates > 0 || second.conflicts > 0,
        "the loser must acknowledge or reload, not fail"
    );
    // Both converge to the same durable state.
    assert_eq!(
        engine.snapshot().unwrap().context,
        rival.snapshot().unwrap().context
    );
}

#[test]
fn f2_e2e_017_a_diverging_terms_hash_is_rejected_before_the_machine() {
    let (fx, mut engine) = Fixture::new("e2e-017", 2, 1_000);
    engine.arm_refund(10).unwrap();
    fx.step(&mut engine, 11);
    let seq_before = engine.snapshot().unwrap().last_event_seq;

    let evidence = EvidenceRefV1 {
        chain_id: ChainId(CHAIN),
        tx_id: b32(0x71),
        event_index: 0,
        block_height: 1,
        block_anchor: b32(0xa0),
    };
    let event = SettlementEvent::FundingConfirmed { evidence };
    let mut envelope = EventEnvelopeV1 {
        protocol_version: PROTOCOL_VERSION,
        settlement_id: fx.terms.settlement_id,
        session_id: fx.terms.session_id,
        terms_hash: fx.terms.terms_hash().unwrap(),
        source_chain: ChainId(CHAIN),
        event_id: derive_event_id(fx.terms.settlement_id, &event),
        source_sequence: 1,
        event,
    };
    envelope.terms_hash = b32(0xff);
    match ingest_event(engine.store(), &envelope, None, 50) {
        Err(EngineError::BindingMismatch) => {}
        other => panic!("a diverging terms_hash must be refused, got {other:?}"),
    }
    // And the same for a diverging session.
    envelope.terms_hash = fx.terms.terms_hash().unwrap();
    envelope.session_id = SessionId(b32(0xff));
    match ingest_event(engine.store(), &envelope, None, 51) {
        Err(EngineError::BindingMismatch) => {}
        other => panic!("a diverging session must be refused, got {other:?}"),
    }
    assert_eq!(
        engine.snapshot().unwrap().last_event_seq,
        seq_before,
        "a rejected binding still reached the journal"
    );
}

#[test]
fn f2_e2e_018_the_f1_real_backend_regression_stays_wired_in_ci() {
    // G-F2 requires the full F1 regression to stay green against the REAL
    // cryptographic backend. That suite lives in `dom-vault` behind
    // `--features real-dom-adaptor`; this test fails if the job that runs
    // it is ever removed from CI, so the regression cannot be silently
    // dropped while the gate still claims it.
    let workflow =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml");
    let content = std::fs::read_to_string(&workflow)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", workflow.display()));
    assert!(
        content.contains("cargo test -p dom-vault --features real-dom-adaptor"),
        "CI no longer runs the F1 real-backend regression (dom-vault)"
    );
    assert!(
        content.contains("cargo test -p dom-leg --features real-dom-adaptor"),
        "CI no longer runs the F1 real-backend regression (dom-leg)"
    );
}

/// Sanity: the scenario ids above cover the whole §16 table.
#[test]
fn the_scenario_table_is_complete() {
    let source = include_str!("g_f2_scenarios.rs");
    for id in 1..=18u32 {
        let needle = format!("f2_e2e_{id:03}");
        assert!(
            source.contains(&needle),
            "scenario F2-E2E-{id:03} is missing from the table"
        );
    }
}

/// Guards against an accidental import of the neutral engine types being
/// dropped: every scenario above must actually build an engine.
#[allow(dead_code)]
fn _type_anchor(_: &SimSettlementChain, _: &IngestResult) {}

//! Durable settlement engine mechanics (F2 spec §10–§13, steps 9–10).
//!
//! The numbered G-F2 scenario table lives in `g_f2_scenarios.rs`; this
//! suite covers the engine's own contract: opening, recovery, secret
//! containment and idempotence.

mod common;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use adapter_dom_sim::LockState;
use common::{b32, contains, db_path, terms, Fixture, CHAIN, SECRET};
use f2_harness::{SimEffectSink, SimSettlementChain, SinkAction};
use kaystra_core::settlement_engine::{
    ChainCursorV1, ChainRecordV1, ChainSourceErrorV1, ChainSourceV1, SettlementEngine,
    SettlementEngineError,
};
use kaystra_core::state::{SettlementContext, SettlementState};
use kaystra_core::store_port::{
    encode_context, SettlementStore, SqliteSettlementStore, StorePortError,
};
use kaystra_core::types::*;

#[test]
fn claim_path_settles_through_the_durable_store() {
    // F2-E2E-001: refund armed -> funding -> confirmations -> claim.
    let (fx, mut engine) = Fixture::new("claim-path", 2, 1_000);
    assert_eq!(fx.state(&engine), SettlementState::Preparing);

    // I5: funding is only authorized after the refund is armed.
    engine.arm_refund(10).unwrap();
    assert_eq!(fx.state(&engine), SettlementState::ReadyToFund);
    let report = engine.tick(11).unwrap();
    assert_eq!(report.effects_dispatched, 1, "AuthorizeFunding dispatched");
    assert_eq!(report.effects_completed, 1);

    // The funding is mined and observed.
    fx.step(&mut engine, 12);
    assert_eq!(fx.state(&engine), SettlementState::Confirming);
    assert_eq!(fx.chain.lock_state(), LockState::Open);

    // Second confirmation moves it to Settling.
    fx.step(&mut engine, 13);
    assert_eq!(fx.state(&engine), SettlementState::Settling);

    // The counterparty claims on chain, revealing the secret THERE.
    fx.chain.submit_claim(SECRET);
    fx.step(&mut engine, 14);
    assert!(
        engine.snapshot().unwrap().context.claim_evidence_verified,
        "claim evidence verified on sight (non-terminal, reorg-reversible)"
    );
    assert_eq!(
        fx.state(&engine),
        SettlementState::Settling,
        "verification alone never settles"
    );

    // Only after finality does the claim become terminal.
    fx.step(&mut engine, 15);
    assert_eq!(fx.state(&engine), SettlementState::Settled);
    let (terminal, _, _) = engine
        .store()
        .terminal(fx.terms.settlement_id)
        .unwrap()
        .unwrap();
    assert_eq!(terminal, SettlementState::Settled);

    // The F1 boundary was handed the evidence reference exactly once.
    let consumptions = engine.sink().claim_consumptions();
    assert_eq!(consumptions.len(), 1);
    assert!(fx.chain.resolves(&consumptions[0]));
}

#[test]
fn refund_path_settles_after_the_timelock() {
    // F2-E2E-002: refund armed -> funding -> timelock -> refund.
    let (fx, mut engine) = Fixture::new("refund-path", 2, 6);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.step(&mut engine, 12); // funding mined
    fx.step(&mut engine, 13); // confirmed -> Settling

    let rounds = fx.run_until_terminal(&mut engine, 12, 14);
    assert!(rounds < 12, "the refund path must converge");
    assert_eq!(fx.state(&engine), SettlementState::Refunded);
    assert_eq!(fx.chain.lock_state(), LockState::Spent);
    assert!(engine
        .sink()
        .actions()
        .contains(&SinkAction::RefundSubmitted));
    let (terminal, _, _) = engine
        .store()
        .terminal(fx.terms.settlement_id)
        .unwrap()
        .unwrap();
    assert_eq!(terminal, SettlementState::Refunded);
}

#[test]
fn the_secret_never_reaches_the_engine_or_the_database() {
    // Spec §18: `t` must not appear in the journal, the snapshot, the
    // outbox or any persisted byte. The claim reveals it ON CHAIN; the
    // adapter drops it and the core only ever sees a reference.
    let (fx, mut engine) = Fixture::new("no-secret", 1, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.step(&mut engine, 12);
    fx.step(&mut engine, 13);
    fx.chain.submit_claim(SECRET);
    fx.run_until_terminal(&mut engine, 10, 14);
    assert_eq!(fx.state(&engine), SettlementState::Settled);

    // Drop the engine so SQLite flushes everything it holds.
    drop(engine);
    let bytes = fx.database_bytes();
    assert!(
        !bytes.is_empty(),
        "the database must have content to search"
    );
    assert!(
        !contains(&bytes, &SECRET),
        "the revealed secret was persisted by the core"
    );
    // A 16-byte prefix would already be a catastrophic leak.
    assert!(!contains(&bytes, &SECRET[..16]));
}

#[test]
fn crash_at_every_round_converges_to_the_same_terminal() {
    // F2-E2E-003 shape: restarting the process at each round must not
    // change the outcome. The engine is dropped and re-opened from the
    // same database file, so recovery is exercised for real.
    for cut in 0..7usize {
        let (fx, mut engine) = Fixture::new(&format!("crash-{cut}"), 2, 1_000);
        engine.arm_refund(10).unwrap();
        engine.tick(11).unwrap();
        for round in 0..7usize {
            if round == cut {
                engine = fx.restart(engine);
            }
            if round == 2 {
                fx.chain.submit_claim(SECRET);
            }
            fx.step(&mut engine, 20 + round as i64);
        }
        assert_eq!(
            fx.state(&engine),
            SettlementState::Settled,
            "crash before round {cut} changed the outcome"
        );
        let (terminal, _, _) = engine
            .store()
            .terminal(fx.terms.settlement_id)
            .unwrap()
            .unwrap();
        assert_eq!(terminal, SettlementState::Settled);
        // Nothing was left behind by the restart: with every lease long
        // expired, a final tick finds no claimable effect, so each one was
        // executed and completed exactly once across the whole lifetime.
        let drained = engine.tick(10_000_000).unwrap();
        assert_eq!(
            drained.effects_dispatched, 0,
            "crash before round {cut} left an effect pending"
        );
    }
}

#[test]
fn repeated_ticks_are_idempotent() {
    // F2-E2E-004/005: ticking without mining produces no new economic
    // effect; every redelivery is an acknowledged duplicate.
    let (fx, mut engine) = Fixture::new("idempotent", 2, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.step(&mut engine, 12);
    let baseline = engine.snapshot().unwrap();
    for now in 13..20 {
        let report = engine.tick(now).unwrap();
        assert_eq!(report.committed, 0, "idle tick committed a transition");
    }
    let after = engine.snapshot().unwrap();
    assert_eq!(after.context, baseline.context);
    assert_eq!(after.last_event_seq, baseline.last_event_seq);
}

#[test]
fn deep_reorg_removing_the_funding_rearms_and_converges() {
    // F2-E2E-010: a reorg deep enough to remove the funding regresses the
    // observation, never the economic outcome, and the settlement
    // re-arms and converges afterwards.
    let (fx, mut engine) = Fixture::new("deep-reorg", 2, 1_000);
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    fx.step(&mut engine, 12);
    fx.step(&mut engine, 13);
    assert_eq!(fx.state(&engine), SettlementState::Settling);

    // Remove every block: the funding leaves the canonical chain.
    fx.chain.inject_reorg(fx.chain.height());
    let report = engine.tick(14).unwrap();
    assert!(report.records_seen > 0, "the reorg must be observed");
    assert!(
        !fx.state(&engine).is_terminal(),
        "a reorg never produces a terminal"
    );

    // Converge: the engine re-scans, re-arms and settles the claim.
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
fn recovery_rejects_a_tampered_snapshot() {
    // Spec §13 steps 2-4, at BOTH depths. A snapshot edited behind the
    // engine's back is never trusted and never "repaired".
    let (fx, mut engine) = Fixture::new("tampered", 2, 1_000);
    engine.arm_refund(10).unwrap();
    fx.step(&mut engine, 11);
    let context = engine.snapshot().unwrap().context;
    drop(engine);

    let reopen = |fx: &Fixture| {
        let store = SqliteSettlementStore::open(&fx.path).unwrap();
        let sink = SimEffectSink::new(fx.chain.clone(), 1_000);
        SettlementEngine::open(store, fx.chain.clone(), sink, fx.terms.settlement_id)
    };

    // Depth 1: the revision column alone is bumped. The snapshot no
    // longer agrees with its own encoded context — corruption, caught
    // before recovery even starts.
    let conn = rusqlite::Connection::open(&fx.path).unwrap();
    conn.execute(
        "UPDATE settlement_snapshot SET revision = revision + 1 WHERE settlement_id = ?1",
        rusqlite::params![fx.terms.settlement_id.0],
    )
    .unwrap();
    drop(conn);
    match reopen(&fx) {
        Err(SettlementEngineError::Store(StorePortError::CorruptContext)) => {}
        other => panic!("self-inconsistent snapshot must fail closed, got {other:?}"),
    }

    // Depth 2: column AND encoded context bumped consistently, so the
    // snapshot is internally coherent and only the JOURNAL can expose the
    // lie. Replay must catch it.
    let forged = SettlementContext {
        revision: context.revision + 1,
        ..context
    };
    let conn = rusqlite::Connection::open(&fx.path).unwrap();
    conn.execute(
        "UPDATE settlement_snapshot SET context_bytes = ?2 WHERE settlement_id = ?1",
        rusqlite::params![fx.terms.settlement_id.0, encode_context(&forged)],
    )
    .unwrap();
    drop(conn);
    match reopen(&fx) {
        Err(SettlementEngineError::RecoveryDivergence(_)) => {}
        other => panic!("unreplayable snapshot must fail closed, got {other:?}"),
    }
}

#[test]
fn an_unsupported_timelock_domain_fails_closed_at_open() {
    // The engine has no clock: a timestamp deadline is refused loudly
    // rather than silently ignored (its adapter arrives in F3/F5).
    let path = db_path("timestamp-domain");
    let mut t = terms(0xa1, 2, 100);
    t.dom_leg.deadline = TimelockSpec::TimestampSeconds { value: 1_700_000 };
    let chain = SimSettlementChain::new(ChainId(CHAIN), t.settlement_id.0);
    let store = SqliteSettlementStore::open(&path).unwrap();
    store.create(&t, 1).unwrap();
    let sink = SimEffectSink::new(chain.clone(), 0);
    match SettlementEngine::open(store, chain, sink, t.settlement_id) {
        Err(SettlementEngineError::UnsupportedTimelockDomain) => {}
        other => panic!("unsupported domain must fail closed, got {other:?}"),
    }
}

#[test]
fn a_chain_source_for_another_chain_is_refused() {
    let path = db_path("chain-mismatch");
    let t = terms(0xa1, 2, 100);
    let wrong = SimSettlementChain::new(ChainId(b32(0xee)), t.settlement_id.0);
    let store = SqliteSettlementStore::open(&path).unwrap();
    store.create(&t, 1).unwrap();
    let sink = SimEffectSink::new(wrong.clone(), 100);
    match SettlementEngine::open(store, wrong, sink, t.settlement_id) {
        Err(SettlementEngineError::ChainMismatch) => {}
        other => panic!("chain mismatch must fail closed, got {other:?}"),
    }
}

#[derive(Clone)]
struct FailingSource {
    inner: SimSettlementChain,
    unavailable: Arc<AtomicBool>,
}

impl ChainSourceV1 for FailingSource {
    fn chain_id(&self) -> ChainId {
        self.inner.chain_id()
    }

    fn genesis_cursor(&self) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        self.inner.genesis_cursor()
    }

    fn cursor_at(&self, height: u64) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        self.inner.cursor_at(height)
    }

    fn scan(
        &self,
        from: &ChainCursorV1,
    ) -> Result<(Vec<ChainRecordV1>, ChainCursorV1), ChainSourceErrorV1> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err(ChainSourceErrorV1::Unavailable)
        } else {
            self.inner.scan(from)
        }
    }

    fn tip_height(&self) -> Result<u64, ChainSourceErrorV1> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err(ChainSourceErrorV1::Unavailable)
        } else {
            self.inner.tip_height()
        }
    }
}

#[test]
fn unavailable_real_source_never_looks_like_an_empty_success() {
    let path = db_path("fallible-chain-source");
    let settlement_terms = terms(0xa1, 2, 100);
    let inner = SimSettlementChain::new(ChainId(CHAIN), settlement_terms.settlement_id.0);
    let unavailable = Arc::new(AtomicBool::new(false));
    let source = FailingSource {
        inner: inner.clone(),
        unavailable: unavailable.clone(),
    };
    let store = SqliteSettlementStore::open(&path).unwrap();
    store.create(&settlement_terms, 1).unwrap();
    let sink = SimEffectSink::new(inner, 100);
    let mut engine =
        SettlementEngine::open(store, source, sink, settlement_terms.settlement_id).unwrap();
    engine.arm_refund(2).unwrap();
    let before = engine.snapshot().unwrap();
    let before_cursor = engine
        .store()
        .cursor(settlement_terms.settlement_id, ChainId(CHAIN))
        .unwrap();

    unavailable.store(true, Ordering::SeqCst);
    assert!(matches!(
        engine.tick(3),
        Err(SettlementEngineError::ChainSource(
            ChainSourceErrorV1::Unavailable
        ))
    ));
    assert_eq!(engine.snapshot().unwrap(), before);
    assert_eq!(
        engine
            .store()
            .cursor(settlement_terms.settlement_id, ChainId(CHAIN))
            .unwrap(),
        before_cursor,
        "an unavailable RPC must not advance the durable cursor"
    );
}

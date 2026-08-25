//! Mandatory property tests of F2 spec §14.
//!
//! The pure properties run against the REAL machine; the durability
//! property runs against the REAL SQLite store, crashing at every prefix
//! of the trace and requiring the same economic projection as the
//! uninterrupted run. Nothing here is modelled twice: `transition` and
//! `ingest_event` are the production functions.
//!
//! Case count is controlled by `PROPTEST_CASES` (the closure report
//! records the number actually executed).

use std::path::PathBuf;

use kaystra_core::ingest::{ingest_event, IngestResult};
use kaystra_core::state::{
    transition, Effect, EvidenceRefV1, SettlementContext, SettlementEvent, SettlementState,
};
use kaystra_core::store_port::{
    derive_event_id, EventEnvelopeV1, SettlementStore, SqliteSettlementStore, PROTOCOL_VERSION,
};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::*;
use proptest::prelude::*;

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

const CHAIN: [u8; 32] = [0xc1; 32];

/// Small deterministic event domain: heights collide on purpose, so
/// duplicates, stale confirmations and out-of-range reorgs all occur.
#[derive(Clone, PartialEq, Eq, Debug)]
enum ModelEvent {
    Arm,
    Observe(u8),
    Confirm(u8),
    Absent,
    Verify(u8),
    Claim(u8),
    Timelock,
    Refund(u8),
    Reorg(u8),
}

fn evidence(height: u8) -> EvidenceRefV1 {
    EvidenceRefV1 {
        chain_id: ChainId(CHAIN),
        tx_id: b32(0x70 | height),
        event_index: 0,
        block_height: u64::from(height),
        block_anchor: b32(0xa0),
    }
}

impl ModelEvent {
    fn to_event(&self) -> SettlementEvent {
        match self {
            Self::Arm => SettlementEvent::RefundArmed,
            Self::Observe(h) => SettlementEvent::FundingObserved {
                evidence: evidence(*h),
            },
            Self::Confirm(h) => SettlementEvent::FundingConfirmed {
                evidence: evidence(*h),
            },
            Self::Absent => SettlementEvent::FundingAbsent {
                revalidation_from: 1,
            },
            Self::Verify(h) => SettlementEvent::ClaimEvidenceVerified {
                evidence: evidence(*h),
            },
            Self::Claim(h) => SettlementEvent::ClaimConfirmed {
                evidence: evidence(*h),
            },
            Self::Timelock => SettlementEvent::TimelockExpired,
            Self::Refund(h) => SettlementEvent::RefundConfirmed {
                evidence: evidence(*h),
            },
            Self::Reorg(h) => SettlementEvent::ReorgInvalidated {
                from_height: u64::from(*h),
                old_anchor: b32(0xa0),
            },
        }
    }
}

fn arb_event() -> impl Strategy<Value = ModelEvent> {
    prop_oneof![
        Just(ModelEvent::Arm),
        (1u8..4).prop_map(ModelEvent::Observe),
        (1u8..4).prop_map(ModelEvent::Confirm),
        Just(ModelEvent::Absent),
        (1u8..4).prop_map(ModelEvent::Verify),
        (1u8..4).prop_map(ModelEvent::Claim),
        Just(ModelEvent::Timelock),
        (1u8..4).prop_map(ModelEvent::Refund),
        (1u8..4).prop_map(ModelEvent::Reorg),
    ]
}

fn arb_trace() -> impl Strategy<Value = Vec<ModelEvent>> {
    prop::collection::vec(arb_event(), 0..9)
}

/// What an execution is allowed to be judged on: the economic facts.
/// Revision is excluded on purpose — it counts accepted transitions, not
/// economic outcomes, and two paths to the same outcome may differ in it.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct Projection {
    terminal: Option<SettlementState>,
    terminal_effects: usize,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct Outcome {
    projection: Projection,
    settled_seen: bool,
    refunded_seen: bool,
    funding_effect_before_refund_armed: bool,
}

/// Pure execution of a trace through the real machine.
fn execute(trace: &[ModelEvent]) -> Outcome {
    let mut ctx = SettlementContext::new();
    let mut out = Outcome::default();
    for event in trace {
        let Ok(applied) = transition(ctx, &event.to_event()) else {
            continue;
        };
        for effect in &applied.effects {
            match effect {
                Effect::AuthorizeFunding => {
                    if !ctx.refund_path_armed && !applied.next.refund_path_armed {
                        out.funding_effect_before_refund_armed = true;
                    }
                }
                Effect::RecordTerminalOutcome(state) => {
                    out.projection.terminal_effects += 1;
                    out.projection.terminal = Some(*state);
                    match state {
                        SettlementState::Settled => out.settled_seen = true,
                        SettlementState::Refunded => out.refunded_seen = true,
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        ctx = applied.next;
    }
    out
}

fn terms(settlement: u8) -> SettlementTermsV1 {
    SettlementTermsV1 {
        settlement_id: SettlementId(b32(settlement)),
        session_id: SessionId(b32(settlement.wrapping_add(0x40))),
        intent_hash: IntentHash(b32(0xa3)),
        solver_id: SolverId(b32(0xa4)),
        roster: [ParticipantId(b32(0xb1)), ParticipantId(b32(0xb2))],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId(CHAIN),
            asset_id: AssetId(b32(0xc2)),
            amount: 5,
            beneficiary: ParticipantId(b32(0xb2)),
            refund_to: ParticipantId(b32(0xb1)),
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight { value: 100 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 4,
            },
            adapter_profile_hash: b32(0xc3),
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId(b32(0xd1)),
            asset_id: AssetId(b32(0xd2)),
            amount: 7,
            beneficiary: ParticipantId(b32(0xb1)),
            refund_to: ParticipantId(b32(0xb2)),
            mechanism: LockMechanism::ConditionLock,
            deadline: TimelockSpec::BlockHeight { value: 100 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 4,
            },
            adapter_profile_hash: b32(0xd3),
        },
        adaptor_point_sec1: {
            let mut p = [0xe1u8; 33];
            p[0] = 0x02;
            p
        },
        fee_limit: FeeLimitV1 {
            dom_max: 0,
            counterparty_max: 0,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 4,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: Vec::new(),
    }
}

fn envelope(t: &SettlementTermsV1, event: SettlementEvent) -> EventEnvelopeV1 {
    EventEnvelopeV1 {
        protocol_version: PROTOCOL_VERSION,
        settlement_id: t.settlement_id,
        session_id: t.session_id,
        terms_hash: t.terms_hash().expect("valid terms"),
        source_chain: ChainId(CHAIN),
        event_id: derive_event_id(t.settlement_id, &event),
        source_sequence: 0,
        event,
    }
}

fn db_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kaystra-f2-props-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Durable execution of a trace through the REAL store, optionally
/// "crashing" (dropping and re-opening the database) before index `cut`.
fn execute_durable(trace: &[ModelEvent], cut: Option<usize>, tag: &str) -> Projection {
    let path = db_dir().join(format!("{tag}.sqlite"));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(db_dir().join(format!("{tag}.sqlite{suffix}")));
    }
    let t = terms(0xa1);
    let mut store = SqliteSettlementStore::open(&path).expect("open");
    store.create(&t, 1).expect("create");

    for (index, event) in trace.iter().enumerate() {
        if cut == Some(index) {
            // Crash: everything in memory is lost, the file is all there is.
            drop(store);
            store = SqliteSettlementStore::open(&path).expect("reopen");
        }
        let env = envelope(&t, event.to_event());
        let r = ingest_event(&store, &env, None, 10 + index as i64);
        if std::env::var("F2_DEBUG").is_ok() {
            eprintln!("DEBUG ingest[{index}] {event:?} -> {r:?}");
        }
        match r {
            Ok(IngestResult::Committed { .. } | IngestResult::Duplicate) => {}
            Ok(IngestResult::ParkedForReorder | IngestResult::LateNoEconomicEffect) => {}
            // A hard rejection is a legitimate outcome for an arbitrary
            // trace (illegal event without evidence, evidence mismatch).
            Err(_) => {}
        }
    }
    let terminal = store
        .terminal(t.settlement_id)
        .expect("terminal read")
        .map(|(state, _, _)| state);
    Projection {
        terminal,
        terminal_effects: usize::from(terminal.is_some()),
    }
}

proptest! {
    /// A terminal state never changes, whatever arrives afterwards.
    #[test]
    fn terminal_is_immutable(trace in arb_trace()) {
        let mut ctx = SettlementContext::new();
        for event in &trace {
            let before = ctx.state;
            if let Ok(applied) = transition(ctx, &event.to_event()) {
                ctx = applied.next;
            }
            if before.is_terminal() {
                prop_assert_eq!(ctx.state, before);
            }
        }
    }

    /// Settled and Refunded never coexist, and at most one terminal
    /// economic effect is ever produced.
    #[test]
    fn settled_and_refunded_never_coexist(trace in arb_trace()) {
        let result = execute(&trace);
        prop_assert!(!(result.settled_seen && result.refunded_seen));
        prop_assert!(result.projection.terminal_effects <= 1);
    }

    /// No funding is ever authorized before the refund path is armed (I5).
    #[test]
    fn funding_requires_refund_armed(trace in arb_trace()) {
        prop_assert!(!execute(&trace).funding_effect_before_refund_armed);
    }

    /// Duplicating every event of a trace is observationally equivalent.
    #[test]
    fn duplicate_trace_is_observationally_equivalent(trace in arb_trace()) {
        let once = execute(&trace);
        let duplicated: Vec<ModelEvent> = trace
            .iter()
            .flat_map(|e| [e.clone(), e.clone()])
            .collect();
        prop_assert_eq!(execute(&duplicated).projection, once.projection);
    }

    /// The same trace delivered to the DURABLE store, with a crash before
    /// every prefix, converges to the baseline projection.
    #[test]
    fn crash_prefix_recovery_converges(trace in prop::collection::vec(arb_event(), 0..7)) {
        let baseline = execute_durable(&trace, None, "baseline");
        for cut in 0..=trace.len() {
            let recovered = execute_durable(&trace, Some(cut), &format!("cut-{cut}"));
            prop_assert_eq!(recovered, baseline.clone());
        }
    }

    /// The durable path never contradicts the pure machine about the
    /// terminal outcome.
    #[test]
    fn durable_and_pure_agree_on_the_terminal(trace in prop::collection::vec(arb_event(), 0..7)) {
        let pure = execute(&trace).projection.terminal;
        let durable = execute_durable(&trace, None, "agree").terminal;
        prop_assert_eq!(durable, pure);
    }
}

/// Exhaustive search over short sequences: every state, every event, all
/// orders up to depth 6. Complements the randomized properties with a
/// complete proof for the shallow space (spec §14).
#[test]
fn exhaustive_short_sequences_preserve_the_invariants() {
    let alphabet = [
        ModelEvent::Arm,
        ModelEvent::Observe(1),
        ModelEvent::Observe(2),
        ModelEvent::Confirm(1),
        ModelEvent::Absent,
        ModelEvent::Verify(1),
        ModelEvent::Claim(1),
        ModelEvent::Timelock,
        ModelEvent::Refund(1),
        ModelEvent::Reorg(1),
    ];

    fn walk(
        ctx: SettlementContext,
        terminals: usize,
        depth: usize,
        alphabet: &[ModelEvent],
        worst: &mut usize,
    ) {
        *worst = (*worst).max(terminals);
        assert!(terminals <= 1, "more than one terminal economic effect");
        if depth == 0 {
            return;
        }
        for event in alphabet {
            let Ok(applied) = transition(ctx, &event.to_event()) else {
                continue;
            };
            // I5 on every edge, not just on complete traces.
            if applied.effects.contains(&Effect::AuthorizeFunding) {
                assert!(
                    applied.next.refund_path_armed,
                    "funding authorized without an armed refund path"
                );
            }
            let added = applied
                .effects
                .iter()
                .filter(|e| matches!(e, Effect::RecordTerminalOutcome(_)))
                .count();
            // A terminal state accepts nothing further.
            if ctx.state.is_terminal() {
                panic!("a terminal context accepted an event");
            }
            walk(applied.next, terminals + added, depth - 1, alphabet, worst);
        }
    }

    let mut worst = 0;
    walk(SettlementContext::new(), 0, 6, &alphabet, &mut worst);
    assert_eq!(worst, 1, "no reachable trace produced a terminal");
}

/// Same bytes, same `terms_hash`, in Rust and against the frozen vector
/// (the independent verifier re-derives the same value in Python).
#[test]
fn terms_hash_matches_the_frozen_vector() {
    let hex = include_str!("../fixtures/terms-v1/valid-minimal.hash").trim();
    let expected: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    // Rebuild the exact vector terms and re-hash them.
    let bytes = include_str!("../fixtures/terms-v1/valid-minimal.hex").trim();
    let encoded: Vec<u8> = (0..bytes.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).expect("hex"))
        .collect();
    let decoded = SettlementTermsV1::decode(&encoded).expect("vector decodes");
    assert_eq!(decoded.terms_hash().expect("hash").to_vec(), expected);
    assert_eq!(decoded.canonical_bytes().expect("encode"), encoded);
}

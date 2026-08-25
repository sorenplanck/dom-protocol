//! The composed route DRIVEN BY THE COMPOSER, over two real durable
//! engines (SQLite/WAL stores, `dom-sim` chain semantics) — the level-2
//! composed-routes evidence, now with every gate of `route-composer`
//! enforced on the way:
//!
//! - binding refuses before any engine exists if the composition is bad;
//! - no funding dispatches before BOTH refunds are armed;
//! - the downstream leg (the one whose claim reveals `t`) funds LAST,
//!   only after the upstream funding is confirmed;
//! - the observed scalar passes through `verify_revealed_scalar` before
//!   it may touch the upstream claim, and a bit-flipped scalar is
//!   refused while the route stays alive;
//! - if the downstream leg is never claimed, BOTH legs refund and no
//!   chain ever learns `t`;
//! - `t` appears in NEITHER durable store (spec §18 / I1).

use adapter_evm::binding::adaptor_point_of_scalar;
use f2_harness::{SimEffectSink, SimSettlementChain};
use kaystra_core::settlement_engine::SettlementEngine;
use kaystra_core::state::SettlementState;
use kaystra_core::store_port::{SettlementStore, SqliteSettlementStore};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::*;
use route_composer::{
    authorize_funding, ComposedBindingV1, ComposedLeg, ComposedWindowPolicyV1, ComposerRefusal,
};
use std::path::{Path, PathBuf};

type Engine = SettlementEngine<SqliteSettlementStore, SimSettlementChain, SimEffectSink>;

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

fn route_scalar() -> [u8; 32] {
    let mut t = [0u8; 32];
    for (i, byte) in t.iter_mut().enumerate() {
        *byte = (0x11 + i as u8) | 0x01;
    }
    t[0] = 0x2b;
    t
}

fn db_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("route-composer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.sqlite"));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite{suffix}")));
    }
    path
}

fn terms(settlement: u8, dom_deadline: u64, cp_deadline: u64, t33: [u8; 33]) -> SettlementTermsV1 {
    SettlementTermsV1 {
        settlement_id: SettlementId(b32(settlement)),
        session_id: SessionId(b32(settlement.wrapping_add(1))),
        intent_hash: IntentHash(b32(0xa3)),
        solver_id: SolverId(b32(0xa4)),
        roster: [ParticipantId(b32(0xb1)), ParticipantId(b32(0xb2))],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId(b32(0x33)), // ONE hub chain
            asset_id: AssetId(b32(0xc2)),
            amount: 5,
            beneficiary: ParticipantId(b32(0xb2)),
            refund_to: ParticipantId(b32(0xb1)),
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight {
                value: dom_deadline,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 2,
                max_reorg_depth: 10,
            },
            adapter_profile_hash: b32(0xc3),
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId(b32(settlement.wrapping_add(0x20))),
            // (counterparty chains differ per settlement; deadline in seconds)
            asset_id: AssetId(b32(0xd2)),
            amount: 7,
            beneficiary: ParticipantId(b32(0xb1)),
            refund_to: ParticipantId(b32(0xb2)),
            mechanism: LockMechanism::ConditionLock,
            deadline: TimelockSpec::TimestampSeconds { value: cp_deadline },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 9,
            },
            adapter_profile_hash: b32(0xd3),
        },
        adaptor_point_sec1: t33,
        fee_limit: FeeLimitV1 {
            dom_max: 0,
            counterparty_max: 0,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 10,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: Vec::new(),
    }
}

fn open_engine(path: &Path, terms: &SettlementTermsV1, chain: &SimSettlementChain) -> Engine {
    let store = SqliteSettlementStore::open(path).unwrap();
    let refund_not_before = match terms.dom_leg.deadline {
        TimelockSpec::BlockHeight { value } => value,
        _ => unreachable!("height deadline"),
    };
    let sink = SimEffectSink::new(chain.clone(), refund_not_before);
    SettlementEngine::open(store, chain.clone(), sink, terms.settlement_id).unwrap()
}

fn state(engine: &Engine) -> SettlementState {
    engine.snapshot().unwrap().context.state
}

/// Raw bytes of every file the store wrote, for the secret sweep.
fn database_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{suffix}", path.display()));
        if let Ok(mut content) = std::fs::read(&p) {
            bytes.append(&mut content);
        }
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Tick `engine` (advancing its chain) until `target` or the round budget
/// is exhausted; optionally submit a claim revealing `reveal` at round 2.
fn drive_until(
    chain: &SimSettlementChain,
    engine: &mut Engine,
    target: SettlementState,
    reveal: Option<[u8; 32]>,
    rounds: usize,
) {
    for round in 0..rounds {
        if state(engine) == target || state(engine).is_terminal() {
            break;
        }
        if round == 2 {
            if let Some(t) = reveal {
                chain.submit_claim(t);
            }
        }
        chain.advance(1);
        engine.tick(100 + round as i64).unwrap();
    }
}

/// The composed route end to end, every composer gate enforced.
#[test]
fn the_composer_drives_a_composed_route_to_both_settled() {
    let t = route_scalar();
    let t33 = adaptor_point_of_scalar(&t).expect("canonical scalar");

    // Ladder: downstream deadlines 900/1000, upstream 2000/2100, margin 100.
    let up_terms = terms(0xa0, 2000, 2100, t33);
    let dn_terms = terms(0xd0, 900, 1000, t33);
    let binding = ComposedBindingV1::bind(
        up_terms.clone(),
        dn_terms.clone(),
        ComposedWindowPolicyV1 {
            hub_margin: 100,
            counterparty_margin: 100,
        },
    )
    .expect("a valid composition binds");

    let up_chain = SimSettlementChain::new(up_terms.dom_leg.chain_id, up_terms.settlement_id.0);
    let dn_chain = SimSettlementChain::new(dn_terms.dom_leg.chain_id, dn_terms.settlement_id.0);
    let up_path = db_path("settle-up");
    let dn_path = db_path("settle-dn");
    SqliteSettlementStore::open(&up_path)
        .unwrap()
        .create(&up_terms, 1)
        .unwrap();
    SqliteSettlementStore::open(&dn_path)
        .unwrap()
        .create(&dn_terms, 1)
        .unwrap();
    let mut up = open_engine(&up_path, &up_terms, &up_chain);
    let mut dn = open_engine(&dn_path, &dn_terms, &dn_chain);

    // GATE: with only the upstream refund armed, upstream funding refuses.
    up.arm_refund(10).unwrap();
    assert_eq!(
        authorize_funding(ComposedLeg::Upstream, state(&up), state(&dn)).unwrap_err(),
        ComposerRefusal::FundingOutOfOrder,
        "no funding before BOTH refunds are armed"
    );

    // Both refunds armed -> upstream funding authorized; drive it to
    // Settling (funding confirmed, awaiting claim).
    dn.arm_refund(10).unwrap();
    authorize_funding(ComposedLeg::Upstream, state(&up), state(&dn))
        .expect("both armed: upstream may fund");
    // GATE: the downstream leg must NOT fund yet.
    assert_eq!(
        authorize_funding(ComposedLeg::Downstream, state(&up), state(&dn)).unwrap_err(),
        ComposerRefusal::FundingOutOfOrder,
        "the reveal leg funds last"
    );
    drive_until(&up_chain, &mut up, SettlementState::Settling, None, 24);
    assert_eq!(
        state(&up),
        SettlementState::Settling,
        "upstream funding confirmed"
    );

    // Upstream locked -> downstream funding authorized; claim it,
    // revealing t ON ITS CHAIN.
    authorize_funding(ComposedLeg::Downstream, state(&up), state(&dn))
        .expect("upstream locked: downstream may fund");
    drive_until(&dn_chain, &mut dn, SettlementState::Settled, Some(t), 24);
    assert_eq!(state(&dn), SettlementState::Settled, "downstream settles");

    // The hand-off: observe t from the downstream chain, verify it
    // against the committed T, and only then let it near the upstream leg.
    let observed = dn_chain
        .observe_revealed_secret()
        .expect("the downstream claim revealed a scalar");

    // A corrupted observation refuses by name and the route stays alive.
    let mut flipped = observed;
    flipped[11] ^= 0x08;
    assert_eq!(
        binding.verify_revealed_scalar(&flipped).unwrap_err(),
        ComposerRefusal::WrongSecret
    );
    assert_eq!(
        state(&up),
        SettlementState::Settling,
        "upstream untouched by the refusal"
    );

    // The genuine scalar is released and settles the upstream leg.
    let released = binding
        .verify_revealed_scalar(&observed)
        .expect("t opens T");
    drive_until(
        &up_chain,
        &mut up,
        SettlementState::Settled,
        Some(*released.expose()),
        24,
    );
    assert_eq!(
        state(&up),
        SettlementState::Settled,
        "upstream settles with the same t"
    );

    // I1 / §18: t reached NEITHER durable store.
    drop(up);
    drop(dn);
    assert!(
        !contains(&database_bytes(&up_path), &t),
        "t never in the upstream store"
    );
    assert!(
        !contains(&database_bytes(&dn_path), &t),
        "t never in the downstream store"
    );
}

/// If the downstream leg is never claimed, the whole route dies by
/// refund on both sides and no chain ever learns `t`.
#[test]
fn an_unclaimed_route_refunds_both_legs_and_reveals_nothing() {
    let t = route_scalar();
    let t33 = adaptor_point_of_scalar(&t).expect("canonical scalar");

    // Short ladder so both refunds mature inside the test: downstream
    // 30/40, upstream 200/300, margin 50 (200 >= 40 + 50).
    let up_terms = terms(0xa1, 200, 300, t33);
    let dn_terms = terms(0xd1, 30, 40, t33);
    let binding = ComposedBindingV1::bind(
        up_terms.clone(),
        dn_terms.clone(),
        ComposedWindowPolicyV1 {
            hub_margin: 50,
            counterparty_margin: 50,
        },
    )
    .expect("a valid composition binds");
    let _ = binding;

    let up_chain = SimSettlementChain::new(up_terms.dom_leg.chain_id, up_terms.settlement_id.0);
    let dn_chain = SimSettlementChain::new(dn_terms.dom_leg.chain_id, dn_terms.settlement_id.0);
    let up_path = db_path("refund-up");
    let dn_path = db_path("refund-dn");
    SqliteSettlementStore::open(&up_path)
        .unwrap()
        .create(&up_terms, 1)
        .unwrap();
    SqliteSettlementStore::open(&dn_path)
        .unwrap()
        .create(&dn_terms, 1)
        .unwrap();
    let mut up = open_engine(&up_path, &up_terms, &up_chain);
    let mut dn = open_engine(&dn_path, &dn_terms, &dn_chain);

    // The same authorized order as the settle path...
    up.arm_refund(10).unwrap();
    dn.arm_refund(10).unwrap();
    authorize_funding(ComposedLeg::Upstream, state(&up), state(&dn)).unwrap();
    drive_until(&up_chain, &mut up, SettlementState::Settling, None, 24);
    authorize_funding(ComposedLeg::Downstream, state(&up), state(&dn)).unwrap();

    // ...but nobody ever claims. Both legs must die by refund.
    drive_until(&dn_chain, &mut dn, SettlementState::Refunded, None, 60);
    assert_eq!(
        state(&dn),
        SettlementState::Refunded,
        "downstream refunds first"
    );
    drive_until(&up_chain, &mut up, SettlementState::Refunded, None, 260);
    assert_eq!(
        state(&up),
        SettlementState::Refunded,
        "upstream refunds after"
    );

    // No chain learned the scalar, and neither store holds it.
    assert!(
        dn_chain.observe_revealed_secret().is_none(),
        "no reveal downstream"
    );
    assert!(
        up_chain.observe_revealed_secret().is_none(),
        "no reveal upstream"
    );
    drop(up);
    drop(dn);
    assert!(!contains(&database_bytes(&up_path), &t));
    assert!(!contains(&database_bytes(&dn_path), &t));
}

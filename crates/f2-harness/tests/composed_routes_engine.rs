//! Composed cross-chain route proof — LEVEL 2 (durable settlement engine).
//!
//! NOT RATIFIED. Laboratory evidence requested by the operator to decide,
//! before any normative work, whether the four composed routes
//!   BTC -> DOM -> BTC   EVM -> DOM -> EVM   BTC -> DOM -> EVM   EVM -> DOM -> BTC
//! hold not just at the cryptographic layer (level 1, `dom-leg` composed
//! routes test) but through TWO real durable `SettlementEngine` instances
//! chained together — an upstream settlement and a downstream settlement.
//!
//! The composed route is DOM-in-the-middle (Foundation Document §1.2), so a
//! route is two settlements sharing one adaptor point `T = t*G`: claiming the
//! downstream leg reveals `t` on chain, and the counterparty carries that same
//! `t` to finalize the upstream leg. This test proves exactly that hand-off on
//! the real engine + real SQLite/WAL store + `dom-sim` chain semantics.
//!
//! Two invariants make it a proof and not a demo:
//!   1. The two engines are linked ONLY by the shared `T` in both terms and
//!      the shared `t` at the chain layer — nothing in the engine API couples
//!      them. That is the honest picture of a composed route.
//!   2. `t` never reaches either durable store (spec §18 / I1). The engine
//!      boundary drops the secret; the downstream leg recovers `t` by watching
//!      the origin chain, off to the side, never through the store. Both
//!      databases are swept for `t` and it appears zero times.
//!
//! `dom-sim` is NOT the DOM (I13/I15): it simulates chain semantics only. The
//! live-node execution is level 3.

use adapter_evm::binding::{adaptor_address_of_scalar, adaptor_point_of_scalar};
use f2_harness::{SimEffectSink, SimSettlementChain};
use kaystra_core::settlement_engine::SettlementEngine;
use kaystra_core::state::SettlementState;
use kaystra_core::store_port::{SettlementStore, SqliteSettlementStore};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::*;
use std::path::{Path, PathBuf};

type Engine = SettlementEngine<SqliteSettlementStore, SimSettlementChain, SimEffectSink>;

fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

/// One canonical route scalar in `1..n-1`, chosen by the test (in production
/// this is the F7 derived route scalar). The SAME `t` opens both legs.
fn route_scalar() -> [u8; 32] {
    let mut t = [0u8; 32];
    for (i, byte) in t.iter_mut().enumerate() {
        *byte = (0x11 + i as u8) | 0x01;
    }
    t[0] = 0x2b;
    t
}

fn db_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kaystra-composed-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.sqlite"));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite{suffix}")));
    }
    path
}

/// Terms whose DOM leg lives on `chain_id`, committed to adaptor point `t33`.
/// `settlement` seeds the settlement/lock id; `deadline_height` sets the DOM
/// refund timelock — the ladder between the two legs.
fn terms_with_point(
    settlement: u8,
    chain_id: [u8; 32],
    min_confirmations: u32,
    deadline_height: u64,
    t33: [u8; 33],
) -> SettlementTermsV1 {
    SettlementTermsV1 {
        settlement_id: SettlementId(b32(settlement)),
        session_id: SessionId(b32(settlement.wrapping_add(1))),
        intent_hash: IntentHash(b32(0xa3)),
        solver_id: SolverId(b32(0xa4)),
        roster: [ParticipantId(b32(0xb1)), ParticipantId(b32(0xb2))],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId(chain_id),
            asset_id: AssetId(b32(0xc2)),
            amount: 5,
            beneficiary: ParticipantId(b32(0xb2)),
            refund_to: ParticipantId(b32(0xb1)),
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight {
                value: deadline_height,
            },
            finality: FinalityPolicyV1 {
                min_confirmations,
                max_reorg_depth: min_confirmations + 8,
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
            deadline: TimelockSpec::BlockHeight { value: 500 },
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

/// Opens a fresh durable engine over `path` for `terms`/`chain`.
fn open_engine(path: &Path, terms: &SettlementTermsV1, chain: &SimSettlementChain) -> Engine {
    let store = SqliteSettlementStore::open(path).unwrap();
    let refund_not_before = match terms.dom_leg.deadline {
        TimelockSpec::BlockHeight { value } => value,
        _ => unreachable!("height deadline"),
    };
    let sink = SimEffectSink::new(chain.clone(), refund_not_before);
    SettlementEngine::open(store, chain.clone(), sink, terms.settlement_id).unwrap()
}

fn is_terminal(engine: &Engine) -> bool {
    engine.snapshot().unwrap().context.state.is_terminal()
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

/// One durable settlement, funded then claimed by revealing `reveal` on its
/// chain, driven to a terminal. Returns nothing; caller reads state/observe.
fn fund_and_claim(chain: &SimSettlementChain, engine: &mut Engine, reveal: [u8; 32]) {
    engine.arm_refund(10).unwrap(); // Preparing -> ReadyToFund, enqueue funding
    engine.tick(11).unwrap(); // dispatch funding
    for round in 0..24usize {
        if is_terminal(engine) {
            break;
        }
        if round == 2 {
            // The beneficiary claims the lock, revealing t ON CHAIN.
            chain.submit_claim(reveal);
        }
        chain.advance(1);
        engine.tick(20 + round as i64).unwrap();
    }
}

/// Drive a settlement to its refund terminal: no claim is ever submitted, the
/// DOM timelock matures, and the refund path fires. Nothing reveals `t`.
fn fund_then_refund(chain: &SimSettlementChain, engine: &mut Engine, deadline_height: u64) {
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    for round in 0..((deadline_height + 8) as usize) {
        if is_terminal(engine) {
            break;
        }
        chain.advance(1);
        engine.tick(20 + round as i64).unwrap();
    }
}

/// The heart of the composed route: two engines, one shared T, the scalar
/// revealed by the downstream claim carried to finalize the upstream leg.
#[test]
fn two_engines_share_one_scalar_across_the_route() {
    let t = route_scalar();
    let t33 = adaptor_point_of_scalar(&t).expect("T = t*G is a canonical point");
    // terms.validate requires a SEC1 compressed point (prefix 0x02/0x03).
    assert!(t33[0] == 0x02 || t33[0] == 0x03, "T is SEC1 compressed");

    // Level-1 tie-in: this is the exact real point the DOM/BTC adaptor legs
    // and the EVM commitment all bind. The engine composition is bound to it.
    let _evm_addr = adaptor_address_of_scalar(&t).expect("t commits on the EVM leg");

    // Timelock ladder: the downstream leg (the one claimed first, revealing t)
    // must have a refund deadline strictly before the upstream leg's, so the
    // party who learns t downstream still has time to claim upstream.
    let dn_deadline = 1_000;
    let up_deadline = 2_000;
    assert!(
        dn_deadline < up_deadline,
        "downstream matures before upstream"
    );

    // Downstream settlement: shares T, its own chain/store/id.
    let dn_terms = terms_with_point(0xd0, b32(0xc1), 2, dn_deadline, t33);
    let dn_path = db_path("downstream");
    let dn_chain = SimSettlementChain::new(dn_terms.dom_leg.chain_id, dn_terms.settlement_id.0);
    SqliteSettlementStore::open(&dn_path)
        .unwrap()
        .create(&dn_terms, 1)
        .unwrap();
    let mut dn = open_engine(&dn_path, &dn_terms, &dn_chain);

    // Upstream settlement: SAME T, different chain/store/id.
    let up_terms = terms_with_point(0xa0, b32(0xc7), 2, up_deadline, t33);
    let up_path = db_path("upstream");
    let up_chain = SimSettlementChain::new(up_terms.dom_leg.chain_id, up_terms.settlement_id.0);
    SqliteSettlementStore::open(&up_path)
        .unwrap()
        .create(&up_terms, 1)
        .unwrap();
    let mut up = open_engine(&up_path, &up_terms, &up_chain);

    assert_eq!(
        up_terms.adaptor_point_sec1, dn_terms.adaptor_point_sec1,
        "both legs commit to the same T"
    );

    // 1. Claim the DOWNSTREAM leg by revealing t on its chain; drive to Settled.
    fund_and_claim(&dn_chain, &mut dn, t);
    assert_eq!(state(&dn), SettlementState::Settled, "downstream settles");

    // 2. Recover t by WATCHING the downstream chain — exactly what the upstream
    //    counterparty does. This is the propagation, not a value the test kept.
    let recovered = dn_chain
        .observe_revealed_secret()
        .expect("the downstream claim revealed a scalar on chain");
    assert_eq!(
        recovered, t,
        "the scalar observed on chain is the route scalar"
    );

    // 3. Carry that recovered t to the UPSTREAM leg; drive to Settled.
    fund_and_claim(&up_chain, &mut up, recovered);
    assert_eq!(
        state(&up),
        SettlementState::Settled,
        "upstream settles with the same t"
    );

    // Each leg's claim reached the F1 boundary exactly once.
    assert_eq!(
        dn.sink().claim_consumptions().len(),
        1,
        "one downstream claim"
    );
    assert_eq!(
        up.sink().claim_consumptions().len(),
        1,
        "one upstream claim"
    );

    // 4. I1 / §18: t must appear in NEITHER durable store. The engine boundary
    //    drops the secret; only the off-to-the-side chain observation ever saw
    //    it. This is what makes the composition safe.
    drop(dn);
    drop(up);
    assert!(
        !contains(&database_bytes(&dn_path), &t),
        "the route scalar never reached the downstream store"
    );
    assert!(
        !contains(&database_bytes(&up_path), &t),
        "the route scalar never reached the upstream store"
    );
}

/// A crash between funding and claim on the upstream leg must not lose the
/// route: the engine recovers from its durable state and still settles with t.
#[test]
fn a_crash_mid_route_recovers_and_still_settles() {
    let t = route_scalar();
    let t33 = adaptor_point_of_scalar(&t).unwrap();

    let terms = terms_with_point(0xa0, b32(0xc7), 2, 2_000, t33);
    let path = db_path("crash-mid-route");
    let chain = SimSettlementChain::new(terms.dom_leg.chain_id, terms.settlement_id.0);
    SqliteSettlementStore::open(&path)
        .unwrap()
        .create(&terms, 1)
        .unwrap();
    let mut engine = open_engine(&path, &terms, &chain);

    // Fund and confirm, but do NOT claim yet.
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    for round in 0..6usize {
        chain.advance(1);
        engine.tick(20 + round as i64).unwrap();
    }
    assert!(!is_terminal(&engine), "not settled before the claim");

    // Crash: drop the engine entirely, reopen from the same database file.
    drop(engine);
    let mut resumed = open_engine(&path, &terms, &chain);

    // Now the claim arrives, revealing t; the resumed engine settles.
    for round in 0..24usize {
        if is_terminal(&resumed) {
            break;
        }
        if round == 1 {
            chain.submit_claim(t);
        }
        chain.advance(1);
        resumed.tick(60 + round as i64).unwrap();
    }
    assert_eq!(
        state(&resumed),
        SettlementState::Settled,
        "the resumed engine settled with t after a crash"
    );
    assert_eq!(resumed.sink().claim_consumptions().len(), 1);

    drop(resumed);
    assert!(
        !contains(&database_bytes(&path), &t),
        "t never reached the store, even across the crash"
    );
}

/// If the downstream leg is never claimed, the composed route unwinds by
/// refund on BOTH legs and no `t` is ever revealed anywhere — the safe
/// no-swap outcome (claim XOR refund per leg, §1.3 Exit).
#[test]
fn a_refund_cascade_reveals_no_scalar() {
    let t = route_scalar();
    let t33 = adaptor_point_of_scalar(&t).unwrap();

    let dn_terms = terms_with_point(0xd0, b32(0xc1), 2, 40, t33);
    let dn_path = db_path("refund-downstream");
    let dn_chain = SimSettlementChain::new(dn_terms.dom_leg.chain_id, dn_terms.settlement_id.0);
    SqliteSettlementStore::open(&dn_path)
        .unwrap()
        .create(&dn_terms, 1)
        .unwrap();
    let mut dn = open_engine(&dn_path, &dn_terms, &dn_chain);

    let up_terms = terms_with_point(0xa0, b32(0xc7), 2, 40, t33);
    let up_path = db_path("refund-upstream");
    let up_chain = SimSettlementChain::new(up_terms.dom_leg.chain_id, up_terms.settlement_id.0);
    SqliteSettlementStore::open(&up_path)
        .unwrap()
        .create(&up_terms, 1)
        .unwrap();
    let mut up = open_engine(&up_path, &up_terms, &up_chain);

    fund_then_refund(&dn_chain, &mut dn, 40);
    fund_then_refund(&up_chain, &mut up, 40);

    assert_eq!(state(&dn), SettlementState::Refunded, "downstream refunds");
    assert_eq!(state(&up), SettlementState::Refunded, "upstream refunds");
    assert_eq!(
        dn.sink().claim_consumptions().len(),
        0,
        "no downstream claim"
    );
    assert_eq!(up.sink().claim_consumptions().len(), 0, "no upstream claim");

    // No claim ever revealed t on either chain.
    assert!(dn_chain.observe_revealed_secret().is_none());
    assert!(up_chain.observe_revealed_secret().is_none());
}

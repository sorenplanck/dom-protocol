//! Shared fixture for the G-F2 suites: REAL machine, REAL SQLite store,
//! REAL simulated chain. A crash is a dropped process re-opening the same
//! database file — there is no in-memory journal and no stub anywhere.
//!
//! `dom-sim` is NOT the DOM (I13/I15): it simulates chain semantics only.
#![allow(dead_code)]

use std::path::PathBuf;

use f2_harness::{SimEffectSink, SimSettlementChain};
use kaystra_core::settlement_engine::{SettlementEngine, TickReportV1};
use kaystra_core::state::SettlementState;
use kaystra_core::store_port::{SettlementStore, SqliteSettlementStore};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::*;

/// Secret the counterparty reveals on chain when claiming. It must never
/// appear in the engine, the store or any artifact (spec §18).
pub const SECRET: [u8; 32] = [0x5e; 32];

pub const CHAIN: [u8; 32] = [0xc1; 32];

pub fn b32(x: u8) -> [u8; 32] {
    [x; 32]
}

pub fn db_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kaystra-g-f2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.sqlite"));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite{suffix}")));
    }
    path
}

/// Terms whose DOM leg lives on the simulated chain. The settlement id is
/// also the lock id: one settlement funds one lock.
pub fn terms(settlement: u8, min_confirmations: u32, deadline_height: u64) -> SettlementTermsV1 {
    SettlementTermsV1 {
        settlement_id: SettlementId(b32(settlement)),
        session_id: SessionId(b32(settlement.wrapping_add(1))),
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
            evidence_retention_blocks: 10,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: Vec::new(),
    }
}

pub type Engine = SettlementEngine<SqliteSettlementStore, SimSettlementChain, SimEffectSink>;

pub struct Fixture {
    pub path: PathBuf,
    pub terms: SettlementTermsV1,
    pub chain: SimSettlementChain,
}

impl Fixture {
    pub fn new(name: &str, min_confirmations: u32, deadline_height: u64) -> (Self, Engine) {
        let path = db_path(name);
        let terms = terms(0xa1, min_confirmations, deadline_height);
        let chain = SimSettlementChain::new(ChainId(CHAIN), terms.settlement_id.0);
        let store = SqliteSettlementStore::open(&path).unwrap();
        store.create(&terms, 1).unwrap();
        let engine = Self::engine(&path, &terms, &chain);
        (Self { path, terms, chain }, engine)
    }

    fn engine(
        path: &std::path::Path,
        terms: &SettlementTermsV1,
        chain: &SimSettlementChain,
    ) -> Engine {
        let store = SqliteSettlementStore::open(path).unwrap();
        let sink = SimEffectSink::new(
            chain.clone(),
            match terms.dom_leg.deadline {
                TimelockSpec::BlockHeight { value } => value,
                _ => unreachable!("test terms use height deadlines"),
            },
        );
        SettlementEngine::open(store, chain.clone(), sink, terms.settlement_id).unwrap()
    }

    /// Opens an ADDITIONAL engine over the same database and chain, for
    /// the concurrent-writer and duplicate-delivery scenarios.
    pub fn open_engine(&self) -> Engine {
        Self::engine(&self.path, &self.terms, &self.chain)
    }

    /// Simulates a process crash: the engine is dropped entirely and a new
    /// one recovers from the same database file.
    pub fn restart(&self, engine: Engine) -> Engine {
        drop(engine);
        Self::engine(&self.path, &self.terms, &self.chain)
    }

    pub fn state(&self, engine: &Engine) -> SettlementState {
        engine.snapshot().unwrap().context.state
    }

    /// Mines one block and ticks once.
    pub fn step(&self, engine: &mut Engine, now: i64) -> TickReportV1 {
        self.chain.advance(1);
        engine.tick(now).unwrap()
    }

    /// Mines and ticks until the settlement is terminal or `max` rounds
    /// elapse. Returns the number of rounds actually run.
    pub fn run_until_terminal(&self, engine: &mut Engine, max: usize, base_now: i64) -> usize {
        for round in 0..max {
            if self.state(engine).is_terminal() {
                return round;
            }
            self.step(engine, base_now + round as i64);
        }
        max
    }

    /// Raw bytes of every file the store wrote.
    pub fn database_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{suffix}", self.path.display()));
            if let Ok(mut content) = std::fs::read(&path) {
                bytes.append(&mut content);
            }
        }
        bytes
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

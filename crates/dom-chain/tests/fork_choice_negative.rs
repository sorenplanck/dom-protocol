//! dom-shield KAV-negativo — fork-choice boundaries that must NOT reorg.
//!
//! Attack vectors (Lens A: incorrect-result, malleability):
//!  - Equal-work sibling: a peer mines a competing tip with EXACTLY the same
//!    total_difficulty as our tip. Bitcoin/Nakamoto fork choice is "strictly
//!    more work wins, first-seen holds on ties". If `promote_heavier_known_tip`
//!    (or the connect_block dispatch) reorganized on equal work, an attacker
//!    could flap the canonical tip back and forth with zero extra work — a
//!    cheap chain-instability / double-spend lever. This pins the strict-`>`
//!    fork-choice rule at the reorg entry point.
//!  - Common ancestor AT genesis: when two branches share the real genesis
//!    block (not two *separate* genesis blocks, which reorg_equivalence.rs
//!    already covers), find_common_ancestor must return that genesis hash, not
//!    Hash256::ZERO and not None. A wrong answer here makes reorg depth /
//!    resurrection math start from the wrong height.
//!
//! The reorg-depth boundary (1000 ok / 1001 reject) is already covered by
//! reorg_equivalence.rs::check_reorg_depth_boundary and is deliberately NOT
//! duplicated here.

mod common;

use common::open_test_store;
use dom_chain::reorg::find_common_ancestor;
use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_core::{BlockHeight, DomError, Hash256, Timestamp, PROTOCOL_VERSION};
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::DomStore;
use primitive_types::U256;
use tempfile::TempDir;

fn block_hash(header: &BlockHeader) -> Hash256 {
    dom_crypto::hash::blake2b_256(&header.to_bytes().expect("serialize header"))
}

fn synthetic_header(prev_hash: Hash256, height: u64, nonce_seed: u64, diff: u64) -> BlockHeader {
    BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(height),
        prev_hash,
        timestamp: Timestamp(1_700_000_000 + height),
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(0),
        total_difficulty: U256::from(diff),
        pow: ProofOfWork {
            nonce: nonce_seed,
            randomx_hash: Hash256::ZERO,
        },
    }
}

fn put_header(store: &DomStore, header: &BlockHeader) -> Hash256 {
    let hash = block_hash(header);
    let header_bytes = header.to_bytes().expect("header serialise");
    let body_bytes = vec![0u8; 8];
    store
        .commit_block(
            hash.as_bytes(),
            header.height.0,
            &header_bytes,
            &body_bytes,
            &[],
            &[],
            &[],
        )
        .expect("commit_block (synthetic)");
    hash
}

fn open_chain(dir: &std::path::Path) -> ChainState {
    ChainState::open(
        open_test_store(dir),
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("chain open")
}

#[test]
fn common_ancestor_is_shared_genesis_block() {
    // One real genesis at height 0; two branches both extend it. The common
    // ancestor MUST be that genesis hash (not ZERO, not None).
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());

    let genesis = synthetic_header(Hash256::ZERO, 0, 0, 0);
    let genesis_hash = put_header(&store, &genesis);

    let mut prev_a = genesis_hash;
    let mut tip_a = genesis_hash;
    for h in 1..=4 {
        let header = synthetic_header(prev_a, h, 1000 + h, h);
        tip_a = put_header(&store, &header);
        prev_a = tip_a;
    }
    let mut prev_b = genesis_hash;
    let mut tip_b = genesis_hash;
    for h in 1..=3 {
        let header = synthetic_header(prev_b, h, 9000 + h, h);
        tip_b = put_header(&store, &header);
        prev_b = tip_b;
    }

    let ancestor = find_common_ancestor(&store, tip_a, tip_b).expect("walk");
    assert_eq!(
        ancestor,
        Some(genesis_hash),
        "two branches off one genesis must share that genesis as ancestor"
    );
    assert_ne!(ancestor, Some(Hash256::ZERO));
}

#[test]
fn equal_work_sibling_does_not_reorg() {
    // Canonical chain genesis..tip with total_difficulty == 5. A competing tip
    // with EXACTLY total_difficulty == 5 must be refused by the reorg entry
    // point with PolicyRejected ("not heavier") — strict greater-than only.
    let dir = TempDir::new().expect("tempdir");
    let mut chain = open_chain(dir.path());

    // Build a synthetic canonical chain directly in the store, then point the
    // ChainState tip at it. total_difficulty grows by height: tip diff == 5.
    let genesis = synthetic_header(Hash256::ZERO, 0, 0, 0);
    let genesis_hash = put_header(&chain.store, &genesis);
    let mut prev = genesis_hash;
    let mut canon_tip = genesis_hash;
    for h in 1..=5 {
        let header = synthetic_header(prev, h, 100 + h, h);
        canon_tip = put_header(&chain.store, &header);
        prev = canon_tip;
    }
    chain.tip_hash = canon_tip;
    chain.tip_height = BlockHeight(5);
    chain.tip_difficulty = U256::from(5u64);

    // Sibling branch forking at height 2 (shared ancestor), reaching height 5
    // with EQUAL total_difficulty == 5 (different nonces => distinct hashes).
    // Fork at the canonical height-2 block.
    let canon_h2 = chain.store.get_hash_at_height(2).expect("h2").expect("h2 exists");
    let mut sib_prev = Hash256::from_bytes(canon_h2);
    let mut sib_tip = sib_prev;
    for h in 3..=5 {
        let header = synthetic_header(sib_prev, h, 50_000 + h, h);
        sib_tip = put_header(&chain.store, &header);
        sib_prev = sib_tip;
    }

    let result = chain.promote_heavier_known_tip(sib_tip);
    match result {
        Err(DomError::PolicyRejected(msg)) => {
            assert!(
                msg.contains("not heavier"),
                "equal-work sibling must be rejected as not-heavier, got: {msg}"
            );
        }
        other => panic!("equal-work sibling must NOT reorg, got: {other:?}"),
    }
    // Tip must be unchanged.
    assert_eq!(chain.tip_hash, canon_tip, "tip must not move on equal work");
}

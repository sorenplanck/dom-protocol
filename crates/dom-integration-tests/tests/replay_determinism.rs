//! Roadmap v2 Phase 1.1 — Replay Determinism Proofs.
//!
//! Property: applying the same block sequence to two independent
//! `ChainState` instances must produce byte-identical chain state.
//! "Byte-identical" here means: same `tip_hash`, same `tip_height`,
//! same `tip_difficulty`, and same PMMR roots in the tip header.
//!
//! This is the foundational deterministic-replay test. It does NOT
//! depend on PoW being trivial (the produced blocks already contain a
//! valid RandomX hash); it only depends on `connect_block` being a
//! pure function of `(prior state, block bytes)`.
//!
//! Runs under `Network::Regtest` so two miners + two validators fit
//! comfortably under 1 GB RAM and the suite finishes in seconds.

use dom_chain::ChainState;
use dom_consensus::{
    block::{BlockHeader, ProofOfWork},
    Block, CoinbaseKernel, CoinbaseTransaction, TransactionOutput,
};
use dom_core::{Hash256, Timestamp};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_integration_tests::helpers::*;
use dom_pow::{target_to_difficulty, CompactTarget, REGTEST_TARGET_COMPACT};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_store::DomStore;
use std::path::Path;
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Collect serialised block bytes for heights 1..=count from a freshly
/// mined Regtest chain.
async fn produce_block_sequence(name: &str, port: u16, count: u64) -> Vec<Vec<u8>> {
    let mut config = test_config(name, port, false);
    config.wallet_path = Some(format!("/tmp/dom-replay-{}.dom", name));
    config.wallet_password = Some("replay".into());

    // Cleanup any prior state so the test is self-contained.
    let _ = std::fs::remove_file(config.wallet_path.as_ref().unwrap());
    let _ = std::fs::remove_dir_all(&config.data_dir);

    let node = spawn_node(config.clone()).await;
    // No need to run the full event loop — manual mining suffices.
    mine_blocks(&node, count).await.expect("mining failed");

    // Read each newly-mined block back from the store. Header + body are
    // persisted separately in LMDB; `Block::deserialize` consumes
    // `header || body` (RFC-0007 §X — `DomSerialize` is concatenative),
    // so we reconstruct the wire bytes by concatenating the two records.
    let chain = node.chain.lock().await;
    let mut out = Vec::with_capacity(count as usize);
    for h in 1..=count {
        let hash = chain
            .store
            .get_hash_at_height(h)
            .expect("get_hash_at_height")
            .expect("hash present");
        let bytes = chain
            .store
            .get_block_body(&hash)
            .expect("get_block_body")
            .expect("body present");
        out.push(bytes);
    }
    out
}

async fn produce_single_block(name: &str, port: u16) -> (Vec<u8>, Hash256) {
    let mut config = test_config(name, port, false);
    config.wallet_path = Some(format!("/tmp/dom-replay-{}.dom", name));
    config.wallet_password = Some("replay".into());

    let _ = std::fs::remove_file(config.wallet_path.as_ref().unwrap());
    let _ = std::fs::remove_dir_all(&config.data_dir);

    let node = spawn_node(config).await;
    mine_blocks(&node, 1).await.expect("mining failed");
    let chain = node.chain.lock().await;
    let hash = chain.tip_hash;
    let bytes = chain
        .store
        .get_block_body(hash.as_bytes())
        .expect("get block body")
        .expect("body present");
    (bytes, hash)
}

/// Open an empty `ChainState` rooted at `data_dir` (cleaned first).
fn fresh_chain(data_dir: &str, network_magic: u32) -> ChainState {
    let _ = std::fs::remove_dir_all(data_dir);
    std::fs::create_dir_all(data_dir).expect("mkdir data_dir");
    let store = DomStore::open(Path::new(data_dir)).expect("store open");
    let genesis_hash = Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST);
    ChainState::open(store, genesis_hash, network_magic).expect("chain open")
}

fn replay_commitment(seed: u8, value: u64) -> Commitment {
    let mut blind = [0u8; 32];
    blind[31] = seed.max(1);
    Commitment::commit(
        value,
        &BlindingFactor::from_bytes(blind).expect("deterministic blinding"),
    )
}

fn replay_block_hash(header: &BlockHeader) -> Hash256 {
    Hash256::from_bytes(
        *dom_crypto::hash::blake2b_256(&header.to_bytes().expect("header serialize")).as_bytes(),
    )
}

fn synthetic_replay_block(
    prev_hash: Hash256,
    height: u64,
    timestamp: u64,
    total_difficulty: u64,
    nonce_seed: u64,
) -> Block {
    let coinbase_commitment = replay_commitment((height as u8).wrapping_add(1), height + 1);
    Block {
        header: BlockHeader {
            version: dom_core::PROTOCOL_VERSION,
            height: dom_core::BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(timestamp),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(REGTEST_TARGET_COMPACT),
            total_difficulty: total_difficulty.into(),
            pow: ProofOfWork {
                nonce: nonce_seed,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase: CoinbaseTransaction {
            output: TransactionOutput {
                commitment: coinbase_commitment,
                proof: vec![height as u8; 8],
            },
            kernel: CoinbaseKernel {
                features: dom_core::KERNEL_FEAT_COINBASE,
                explicit_value: 1,
                excess: replay_commitment((height as u8).wrapping_add(100), 0),
                excess_signature: [height as u8; 65],
            },
            offset: [0u8; 32],
        },
        transactions: Vec::new(),
    }
}

fn write_replay_fixture_chain(
    data_dir: &str,
) -> (
    Hash256,
    dom_core::BlockHeight,
    primitive_types::U256,
    u32,
    Vec<u8>,
) {
    let _ = std::fs::remove_dir_all(data_dir);
    std::fs::create_dir_all(data_dir).expect("mkdir replay fixture dir");
    let store = DomStore::open(Path::new(data_dir)).expect("fixture store open");

    let compact = CompactTarget(REGTEST_TARGET_COMPACT);
    let target = compact.to_target().expect("regtest target");
    let diff = target_to_difficulty(&target) as u64;
    let genesis = synthetic_replay_block(
        Hash256::ZERO,
        0,
        dom_core::GENESIS_TIMESTAMP_PLACEHOLDER,
        diff,
        1,
    );
    let genesis_hash = replay_block_hash(&genesis.header);
    store
        .commit_block(
            genesis_hash.as_bytes(),
            0,
            &genesis.header.to_bytes().expect("genesis header"),
            &genesis.to_bytes().expect("genesis block"),
            &[],
            &[],
            &[],
        )
        .expect("commit genesis fixture");

    let block_1 = synthetic_replay_block(
        genesis_hash,
        1,
        genesis.header.timestamp.0 + 1,
        diff.saturating_mul(2),
        2,
    );
    let block_1_hash = replay_block_hash(&block_1.header);
    let header_bytes = block_1.header.to_bytes().expect("tip header");
    store
        .commit_block(
            block_1_hash.as_bytes(),
            1,
            &header_bytes,
            &block_1.to_bytes().expect("tip block"),
            &[],
            &[],
            &[],
        )
        .expect("commit tip fixture");

    let reopened = ChainState::open(
        store,
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("open fixture chain");
    (
        reopened.tip_hash,
        reopened.tip_height,
        reopened.tip_difficulty,
        reopened.network_magic,
        header_bytes,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_two_independent_chains_converge() {
    init_tracing();

    // 1. Produce a canonical block sequence (3 blocks under Regtest).
    let blocks = produce_block_sequence("replay-source", 43400, 3).await;
    assert_eq!(blocks.len(), 3, "must collect three blocks");

    // 2. Open two independent fresh chains (separate LMDB directories).
    let mut chain_a = fresh_chain("/tmp/dom-replay-a", dom_core::NETWORK_MAGIC_REGTEST);
    let mut chain_b = fresh_chain("/tmp/dom-replay-b", dom_core::NETWORK_MAGIC_REGTEST);

    // 3. Apply the same sequence to both chains.
    for (i, bytes) in blocks.iter().enumerate() {
        let block = Block::from_bytes(bytes).expect("decode block");
        chain_a
            .connect_block(&block, Timestamp(now_secs()))
            .unwrap_or_else(|e| panic!("A connect_block({}) failed: {e}", i + 1));
        chain_b
            .connect_block(&block, Timestamp(now_secs()))
            .unwrap_or_else(|e| panic!("B connect_block({}) failed: {e}", i + 1));
    }

    // 4. Equivalence: tips agree on hash, height, difficulty.
    assert_eq!(
        chain_a.tip_height, chain_b.tip_height,
        "tip heights diverged"
    );
    assert_eq!(chain_a.tip_hash, chain_b.tip_hash, "tip hashes diverged");
    assert_eq!(
        chain_a.tip_difficulty, chain_b.tip_difficulty,
        "total difficulty diverged"
    );

    // 5. PMMR roots in the tip header must match byte-for-byte.
    let header_a_bytes = chain_a
        .store
        .get_block_header(chain_a.tip_hash.as_bytes())
        .expect("header A")
        .expect("present");
    let header_b_bytes = chain_b
        .store
        .get_block_header(chain_b.tip_hash.as_bytes())
        .expect("header B")
        .expect("present");
    assert_eq!(
        header_a_bytes, header_b_bytes,
        "tip header bytes diverge between chains — PMMR root drift would surface here"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_same_chain_reopens_to_identical_tip() {
    init_tracing();

    let data_dir = "/tmp/dom-replay-reopen".to_string();
    let (tip_hash, tip_height, tip_diff, network_magic, header_bytes) =
        write_replay_fixture_chain(&data_dir);

    let store = DomStore::open(Path::new(&data_dir)).expect("reopen store");
    let chain_reopen = ChainState::open(
        store,
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("reopen chain");

    assert_eq!(chain_reopen.network_magic, network_magic);
    assert_eq!(chain_reopen.tip_hash, tip_hash);
    assert_eq!(chain_reopen.tip_height, tip_height);
    assert_eq!(chain_reopen.tip_difficulty, tip_diff);
    let reopen_header = chain_reopen
        .store
        .get_block_header(chain_reopen.tip_hash.as_bytes())
        .expect("header")
        .expect("present");
    let reopen_decoded = BlockHeader::from_bytes(&reopen_header).expect("decode reopen header");
    assert_eq!(reopen_header, header_bytes);
    assert_eq!(reopen_decoded.target.0, REGTEST_TARGET_COMPACT);
    let next_target = chain_reopen
        .next_block_target()
        .expect("next target after reopen");
    assert_eq!(
        next_target.next_target,
        dom_core::REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION
    );
    assert_eq!(
        next_target,
        ChainState::open(
            DomStore::open(Path::new(&data_dir)).expect("second reopen store"),
            Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
            dom_core::NETWORK_MAGIC_REGTEST,
        )
        .expect("second reopen chain")
        .next_block_target()
        .expect("second reopen next target")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow RandomX-backed side-chain restart proof; covered by deterministic chain/store tests in dom-chain and dom-store"]
async fn side_chain_block_does_not_rewrite_canonical_tip_after_restart() {
    init_tracing();

    let data_dir = "/tmp/dom-sidechain-canonical-restart".to_string();
    let _ = std::fs::remove_dir_all(&data_dir);

    let mut config = test_config("sidechain-canonical-restart", 43402, false);
    config.wallet_path = Some("/tmp/dom-sidechain-canonical-restart.dom".into());
    config.wallet_password = Some("replay".into());
    config.data_dir = data_dir.clone();
    let _ = std::fs::remove_file(config.wallet_path.as_ref().unwrap());

    let node = spawn_node(config.clone()).await;
    mine_blocks(&node, 1).await.expect("canonical mining");

    let (canonical_tip, canonical_height, canonical_diff) = {
        let chain = node.chain.lock().await;
        (chain.tip_hash, chain.tip_height, chain.tip_difficulty)
    };

    let (side_bytes, side_hash) = produce_single_block("sidechain-source", 43403).await;
    assert_ne!(
        side_hash, canonical_tip,
        "test requires two distinct height-1 blocks"
    );
    let side_block = Block::from_bytes(&side_bytes).expect("decode side block");

    {
        let mut chain = node.chain.lock().await;
        let result = chain
            .connect_block(&side_block, Timestamp(now_secs()))
            .expect("side block should validate as known side chain");
        assert_eq!(result, dom_chain::ConnectResult::SideChain);
        assert_eq!(chain.tip_hash, canonical_tip);
        assert_eq!(chain.tip_height, canonical_height);
        assert_eq!(chain.tip_difficulty, canonical_diff);
        assert_eq!(
            chain.store.get_chain_tip().unwrap().unwrap(),
            *canonical_tip.as_bytes(),
            "side-chain connect must not rewrite persisted chain_tip"
        );
        assert_eq!(
            chain
                .store
                .get_hash_at_height(canonical_height.0)
                .unwrap()
                .unwrap(),
            *canonical_tip.as_bytes(),
            "side-chain connect must not rewrite canonical height index"
        );
        assert!(
            chain
                .store
                .get_block_header(side_hash.as_bytes())
                .unwrap()
                .is_some(),
            "side-chain header should be retained for duplicate suppression"
        );
        assert!(
            chain
                .store
                .get_block_body(side_hash.as_bytes())
                .unwrap()
                .is_some(),
            "side-chain body should be retained for duplicate suppression"
        );
    }

    drop(node);

    let store = DomStore::open(Path::new(&data_dir)).expect("reopen store");
    let reopened = ChainState::open(
        store,
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("reopen chain");

    assert_eq!(reopened.tip_hash, canonical_tip);
    assert_eq!(reopened.tip_height, canonical_height);
    assert_eq!(reopened.tip_difficulty, canonical_diff);
    assert_eq!(
        reopened
            .store
            .get_hash_at_height(canonical_height.0)
            .unwrap()
            .unwrap(),
        *canonical_tip.as_bytes()
    );
}

//! Regression test: a sync-only (non-mining) node must converge with an
//! ACTIVELY MINING peer in regtest.
//!
//! This guards two bugs that NO prior test caught, because both only reproduce
//! with the REAL mining loop running on the source node — the deterministic
//! `mine_blocks()` helper used by the other integration tests bypasses both:
//!
//!   1. GENESIS BOOTSTRAP. Genesis was created only inside `mining_loop`
//!      (gated on `config.mine`), so a non-mining node never committed its own
//!      genesis. Its epoch-0 PoW seed then fell back to `[0u8; 32]` during IBD
//!      validation, while the miner sealed those blocks against the real genesis
//!      hash (`get_hash_at_height(0)`). The two seeds disagree, so every block
//!      failed PoW with "proof-of-work invalid: hash mismatch" and a sync-only
//!      node could never sync. Fixed by creating the (deterministic) genesis on
//!      EVERY node at startup, before IBD.
//!
//!   2. RELAY DURING IBD. The mining peer relays freshly-mined blocks on the
//!      SAME connection while the joiner is still fetching IBD bodies. The
//!      joiner treated those unsolicited relay blocks as responses to its
//!      GetBlockData request → "IBD block response hash mismatch" and the sync
//!      aborted against an actively-mining peer. Fixed by matching IBD responses
//!      by hash and skipping relay blocks.
//!
//! IMPORTANT: this test does NOT use `spawn_node()` (which pre-creates genesis
//! via the helper and would mask bug 1) nor `mine_blocks()` (which mines
//! deterministically and would mask bug 2). It drives the real `node.run()`
//! lifecycle with `config.mine = true` on the source node, exactly like the
//! desktop wallet's embedded node.
//!
//! Without either fix this test fails (B never reaches A's height); with both,
//! the sync-only node B catches up to a continuously-mining node A.

use dom_config::NodeConfig;
use dom_integration_tests::helpers::*;
use dom_node::node::DomNode;
use std::sync::Arc;
use std::time::Duration;

/// A regtest node config from the REAL `NodeConfig::regtest()` defaults, with
/// only the data dir, listen port and mining flag customised for the test.
fn regtest_config(name: &str, port: u16, mine: bool) -> NodeConfig {
    let unique = format!(
        "dom-live-miner-{}-{}-{}-{}",
        name,
        std::process::id(),
        port,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let data_dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&data_dir).expect("create live-miner test data dir");

    let mut config = NodeConfig::regtest();
    config.data_dir = data_dir.to_string_lossy().into_owned();
    config.p2p_listen_addr = format!("127.0.0.1:{port}");
    config.mine = mine;
    config.log_level = "info".into();
    config
}

// NOT #[ignore]: this guards two real bugs (genesis bootstrap + relay-during-IBD)
// that no other test caught, and it runs in ~2s using the cache-only RandomX-fast
// regtest path. If a CPU-starved CI proves flaky here, prefer raising the
// `wait_for_*` timeouts below over silencing the test with #[ignore].
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_only_node_converges_with_actively_mining_peer() {
    init_tracing();

    let port_a = free_local_port();
    let port_b = free_local_port();

    // Node A: a real, continuously-mining regtest node (mine = true).
    let config_a = regtest_config("miner", port_a, true);
    // Node B: sync-only (mine = false), points at A.
    let mut config_b = regtest_config("syncer", port_b, false);
    config_b.seed_peers = vec![format!("127.0.0.1:{port_a}")];

    // Build the nodes directly (NOT via spawn_node) so neither pre-creates its
    // genesis: the genesis bootstrap inside `run()` is exactly what bug 1 fixes.
    let node_a = Arc::new(DomNode::init(config_a).expect("node A init"));
    let node_b = Arc::new(DomNode::init(config_b).expect("node B init"));

    // Start A; its `run()` must bootstrap genesis and begin mining.
    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port_a}"), 10)
        .await
        .expect("node A P2P listener should come up");

    // Let A mine a handful of blocks first, so B must perform real IBD against a
    // pre-existing chain (not merely receive a relayed block or two).
    wait_for_height(&node_a, 5, Duration::from_secs(60))
        .await
        .expect("mining node A should produce blocks");

    // Start B. A is STILL mining (and relaying new blocks) throughout B's IBD —
    // this is what exercises bug 2.
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("node B should connect to mining node A");

    // The sync-only node must catch up to a meaningful height despite A mining
    // the whole time. Before the fixes this never advances past 0 (PoW hash
    // mismatch / IBD response mismatch).
    let target = 5;
    wait_for_height(&node_b, target, Duration::from_secs(90))
        .await
        .expect("sync-only node B should catch up to the actively-mining node A");

    // Both nodes must agree on early, now-immutable history (same chain).
    let a_hash = node_a
        .chain
        .lock()
        .await
        .store
        .get_hash_at_height(3)
        .expect("read A hash@3");
    let b_hash = node_b
        .chain
        .lock()
        .await
        .store
        .get_hash_at_height(3)
        .expect("read B hash@3");
    assert!(a_hash.is_some(), "A must have a block at height 3");
    assert_eq!(
        a_hash, b_hash,
        "B must be on the SAME chain as A (hash at height 3 must match)"
    );
}

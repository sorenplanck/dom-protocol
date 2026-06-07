//! Regression test for the "two local regtest nodes never connect (peers = 0)"
//! bug.
//!
//! ROOT CAUSE: `NodeConfig::regtest()` once shipped `min_outbound = 0`. The peer
//! connector only dials while `PeerManager::needs_outbound()` is true, and that
//! is `outbound + pending < min(min_outbound, max_in_flight)`. With
//! `min_outbound = 0` the target is 0, `needs_outbound()` is always false, and
//! the connector NEVER dials — even with seed peers configured. Two local nodes
//! therefore stayed at peers = 0 forever.
//!
//! This test builds both nodes straight from `NodeConfig::regtest()` (NOT the
//! `test_config` helper, which hard-codes `min_outbound = 1` and would mask the
//! regression) and asserts that:
//!   1. node B dials node A and establishes at least one peer connection, and
//!   2. a block mined on A propagates to B (they exchange at least one block).
//!
//! If `regtest().min_outbound` is reverted to 0, step 1 times out and this test
//! FAILS, which is exactly the guard we want. It also exercises the real
//! loopback path through the /16 eclipse protection, proving two `127.0.0.1`
//! nodes are NOT rejected as same-subnet.

use dom_config::NodeConfig;
use dom_integration_tests::helpers::*;
use std::time::Duration;

/// A regtest node config derived from the REAL `NodeConfig::regtest()` defaults
/// (so `min_outbound` is whatever the protocol ships), with only the data dir
/// and listen port made unique for the test.
fn regtest_config(name: &str, port: u16) -> NodeConfig {
    let unique = format!(
        "dom-p2p-test-{}-{}-{}-{}",
        name,
        std::process::id(),
        port,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let data_dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&data_dir).expect("create p2p test data dir");

    let mut config = NodeConfig::regtest();
    config.data_dir = data_dir.to_string_lossy().into_owned();
    config.p2p_listen_addr = format!("127.0.0.1:{port}");
    // Keep the log volume sane for CI; the connector path logs at info.
    config.log_level = "info".into();
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_regtest_nodes_connect_and_exchange_a_block() {
    init_tracing();

    let port_a = free_local_port();
    let port_b = free_local_port();

    let config_a = regtest_config("connect-a", port_a);
    let mut config_b = regtest_config("connect-b", port_b);
    // Node B dials node A's P2P port — the exact desktop-wallet scenario.
    config_b.seed_peers = vec![format!("127.0.0.1:{port_a}")];

    // Guard against the regression at the config layer too, so a failure here is
    // unambiguous about the cause rather than surfacing only as a timeout.
    assert!(
        config_a.min_outbound >= 1,
        "regtest min_outbound must be >= 1 or the connector never dials (got {})",
        config_a.min_outbound
    );

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port_a}"), 10)
        .await
        .expect("node A P2P listener should come up");
    tokio::spawn(node_b.clone().run());

    // (1) Connection: node B must dial A and register at least one peer.
    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("node B should establish at least one peer with node A");

    // (2) Block exchange: a block mined on A must propagate to B.
    let start_height = node_a.chain.lock().await.tip_height.0;
    mine_blocks(&node_a, 1).await.expect("node A mining failed");
    let target = start_height + 1;
    wait_for_height(&node_b, target, Duration::from_secs(40))
        .await
        .expect("block mined on A should propagate to B");

    // Both nodes must agree on the tip after propagation.
    let chain_a = node_a.chain.lock().await;
    let chain_b = node_b.chain.lock().await;
    assert!(chain_b.tip_height.0 >= target, "B did not reach A's height");
    assert_eq!(
        chain_a.tip_hash, chain_b.tip_hash,
        "tip hashes diverge after propagation"
    );
}

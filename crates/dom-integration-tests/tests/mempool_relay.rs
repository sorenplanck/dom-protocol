//! Test: Mempool relay between connected nodes.
//!
//! Tests transaction propagation in the mempool. Currently a setup
//! placeholder until full tx-building API is exposed for testing.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
#[ignore]
async fn test_mempool_setup() {
    let config_a = test_config("mempool-a", 43384, true);
    let mut config_b = test_config("mempool-b", 43385, false);
    config_b.seed_peers = vec!["127.0.0.1:43384".into()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(10))
        .await
        .expect("nodes should connect");

    // Need blocks for UTXOs
    mine_blocks(&node_a, 2).await.expect("mining failed");
    wait_for_height(&node_b, 2, Duration::from_secs(10))
        .await
        .expect("B should sync");

    // TODO: Build transaction on A via SpendBuilder when wallet API exposes
    // owned outputs as InputSource. Then submit and verify B sees it.

    println!("Mempool setup OK at height 2");
    println!("TODO: complete with tx building and relay verification");
}

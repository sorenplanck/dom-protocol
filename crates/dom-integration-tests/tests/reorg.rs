//! Test: Reorg handling between two nodes.
//!
//! Sets up two nodes, mines competing chains, and verifies the longest
//! chain wins. Currently placeholder until disconnect_peer API exists.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
#[ignore] // Run with --ignored flag
async fn test_reorg_longest_chain_wins() {
    let config_a = test_config("reorg-a", 43380, true);
    let mut config_b = test_config("reorg-b", 43381, true);
    config_b.seed_peers = vec!["127.0.0.1:43380".into()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    tokio::spawn(node_b.clone().run());

    // Initial sync
    wait_for_peer_count(&node_b, 1, Duration::from_secs(10))
        .await
        .expect("nodes should connect");

    // Both at height 0, both mining
    mine_blocks(&node_a, 3).await.expect("node A mining failed");
    wait_for_height(&node_b, 3, Duration::from_secs(10))
        .await
        .expect("node B should sync to height 3");

    // TODO: Once disconnect_peer API is available, disconnect nodes,
    // mine competing chains, reconnect, and verify longest wins.

    println!("Reorg test: initial sync OK at height 3");
    println!("TODO: complete with disconnect/reconnect scenario");
}

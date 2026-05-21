//! Test: Initial Block Download (IBD) from scratch.
//!
//! Node A mines blocks, then node B comes online and syncs from scratch.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
#[ignore]
async fn test_ibd_full_sync() {
    // Node A: producer
    let config_a = test_config("ibd-a", 43382, true);
    let node_a = spawn_node(config_a).await;
    tokio::spawn(node_a.clone().run());

    // Mine 5 blocks on A before B exists
    mine_blocks(&node_a, 5).await.expect("node A mining failed");

    // Node B: starts fresh, must IBD
    let mut config_b = test_config("ibd-b", 43383, false);
    config_b.seed_peers = vec!["127.0.0.1:43382".into()];
    let node_b = spawn_node(config_b).await;
    tokio::spawn(node_b.clone().run());

    // B should connect and sync to height 5
    wait_for_peer_count(&node_b, 1, Duration::from_secs(10))
        .await
        .expect("B should connect to A");

    wait_for_height(&node_b, 5, Duration::from_secs(30))
        .await
        .expect("B should sync to height 5 via IBD");

    println!("IBD test: node B synced to height 5");
}

//! Test: Reorg handling — sync convergence after competing mining.
//!
//! Tests that two nodes mining independently converge to the same tip
//! once connected. Doesn't test deep reorgs (needs disconnect_peer API).

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
async fn test_sync_convergence() {
    let config_a = test_config("reorg-a", 43380, true);
    let mut config_b = test_config("reorg-b", 43381, true);
    config_b.seed_peers = vec!["127.0.0.1:43380".into()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready("127.0.0.1:43380", 10).await.expect("A listener");
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("nodes should connect");

    // Mine 3 blocks on A
    mine_blocks(&node_a, 3).await.expect("A mining failed");
    wait_for_height(&node_b, 3, Duration::from_secs(45))
        .await
        .expect("B should sync to height 3");

    // Verify identical tip
    let (h_a, hash_a) = {
        let c = node_a.chain.lock().await;
        (c.tip_height.0, c.tip_hash)
    };
    let (h_b, hash_b) = {
        let c = node_b.chain.lock().await;
        (c.tip_height.0, c.tip_hash)
    };
    assert_eq!(h_a, h_b, "heights diverge");
    assert_eq!(hash_a, hash_b, "tips diverge");

    println!("[OK] sync_convergence: both nodes at height {} hash {}", h_a, hash_a);
}

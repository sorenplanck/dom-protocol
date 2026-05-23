//! Test: Initial Block Download (IBD) from scratch.
//!
//! Node A mines blocks, then node B comes online and syncs from scratch.
//! Verifies tip_hash matches after sync (proves UTXO set is identical).

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
async fn test_ibd_full_sync() {
    let config_a = test_config("ibd-a", 43382, true);
    let node_a = spawn_node(config_a).await;
    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready("127.0.0.1:43382", 10)
        .await
        .expect("A listener");

    // Mine 5 blocks on A before B exists
    mine_blocks(&node_a, 5).await.expect("A mining failed");

    let (height_a, hash_a) = {
        let c = node_a.chain.lock().await;
        (c.tip_height.0, c.tip_hash)
    };
    assert_eq!(height_a, 5, "A should be at height 5");

    // Node B: starts fresh, must IBD
    let mut config_b = test_config("ibd-b", 43383, false);
    config_b.seed_peers = vec!["127.0.0.1:43382".into()];
    let node_b = spawn_node(config_b).await;
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("B should connect to A");

    wait_for_height(&node_b, 5, Duration::from_secs(60))
        .await
        .expect("B should sync to height 5 via IBD");

    // Critical: verify B reached IDENTICAL tip (not just height — hash too)
    let (height_b, hash_b) = {
        let c = node_b.chain.lock().await;
        (c.tip_height.0, c.tip_hash)
    };
    assert_eq!(height_a, height_b, "heights diverge after IBD");
    assert_eq!(
        hash_a, hash_b,
        "tip hashes diverge — UTXO sets are different!"
    );

    println!("[OK] ibd: B synced to height {} hash {}", height_b, hash_b);
}

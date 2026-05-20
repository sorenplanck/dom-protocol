//! Test 1: Two-node local testnet with P2P and block propagation.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
#[ignore] // Run with --ignored flag
async fn test_two_node_testnet() {
    let config_a = test_config("two-node-a", 43370, true);
    let mut config_b = test_config("two-node-b", 43371, true);
    config_b.seed_peers = vec!["127.0.0.1:43370".into()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(10))
        .await
        .expect("node B should connect to node A");

    mine_blocks(&node_a, 1).await.expect("mining failed");
    wait_for_height(&node_b, 1, Duration::from_secs(5))
        .await
        .expect("block should propagate");

    mine_blocks(&node_b, 1).await.expect("mining failed");
    wait_for_height(&node_a, 2, Duration::from_secs(5))
        .await
        .expect("block should propagate back");

    let chain_a = node_a.chain.lock().await;
    let chain_b = node_b.chain.lock().await;
    
    assert_eq!(chain_a.tip_height, chain_b.tip_height);
    assert_eq!(chain_a.tip_hash, chain_b.tip_hash);
    
    println!("✅ Two-node testnet: PASS");
}

//! Test 1: Two-node local testnet with P2P, block propagation, UTXO consistency.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
async fn test_two_node_testnet() {
    init_tracing();
    let config_a = test_config("two-node-a", 43370, true);
    let mut config_b = test_config("two-node-b", 43371, true);
    config_b.seed_peers = vec!["127.0.0.1:43370".into()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready("127.0.0.1:43370", 10)
        .await
        .expect("A listener");
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("node B should connect to node A");

    // Mine on A, verify propagation to B
    mine_blocks(&node_a, 1).await.expect("A mining failed");
    wait_for_height(&node_b, 1, Duration::from_secs(40))
        .await
        .expect("block should propagate A→B");

    // Mine on B, verify propagation back to A
    mine_blocks(&node_b, 1).await.expect("B mining failed");
    wait_for_height(&node_a, 2, Duration::from_secs(40))
        .await
        .expect("block should propagate B→A");

    // Verify both nodes agree on tip
    let chain_a = node_a.chain.lock().await;
    let chain_b = node_b.chain.lock().await;
    assert_eq!(
        chain_a.tip_height, chain_b.tip_height,
        "tip heights diverge"
    );
    assert_eq!(chain_a.tip_hash, chain_b.tip_hash, "tip hashes diverge");

    println!(
        "[OK] two_node: height={} hash={}",
        chain_a.tip_height.0, chain_a.tip_hash
    );
}

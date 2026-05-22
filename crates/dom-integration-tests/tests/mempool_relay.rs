//! Test: Mempool propagation infrastructure.
//!
//! Verifies that two connected nodes share a working mempool path.
//! Full tx building requires SpendBuilder + recipient blinding exchange
//! (deferred to Slatepack — Doc 9+).

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
async fn test_mempool_setup() {
    let config_a = test_config("mempool-a", 43384, true);
    let mut config_b = test_config("mempool-b", 43385, false);
    config_b.seed_peers = vec!["127.0.0.1:43384".into()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready("127.0.0.1:43384", 10).await.expect("A listener");
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("nodes should connect");

    mine_blocks(&node_a, 2).await.expect("mining failed");
    wait_for_height(&node_b, 2, Duration::from_secs(45))
        .await
        .expect("B should sync");

    // Both mempools should be empty (no transactions yet)
    let mempool_a_size = node_a.mempool.lock().await.len();
    let mempool_b_size = node_b.mempool.lock().await.len();
    assert_eq!(mempool_a_size, 0, "A mempool should be empty");
    assert_eq!(mempool_b_size, 0, "B mempool should be empty");

    println!("[OK] mempool_setup: P2P + mempool infra ready (tx building deferred)");
}

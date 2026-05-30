//! Test: Three-node network convergence.
//!
//! Three nodes connected in a chain (A→B→C). Block mined on A must
//! propagate to C through B. Verifies multi-hop block relay.
//
// ENV-BLOCKED-WSL-2026-05-24: multi-node + RandomX cache-only mining
// exceeds WSL2's CPU/RAM budget within test deadlines. See spend_e2e.rs
// header for the full classification context.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
#[ignore = "env-blocked-wsl — needs VPS or dedicated 8GB+ machine"]
async fn test_three_node_propagation() {
    let config_a = test_config("3n-a", 43390, true);
    let mut config_b = test_config("3n-b", 43391, false);
    config_b.seed_peers = vec!["127.0.0.1:43390".into()];
    let mut config_c = test_config("3n-c", 43392, false);
    config_c.seed_peers = vec!["127.0.0.1:43391".into()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;
    let node_c = spawn_node(config_c).await;

    let _node_a_runtime = spawn_node_runtime(node_a.clone());
    wait_for_listener_ready("127.0.0.1:43390", 10)
        .await
        .expect("A listener");
    let _node_b_runtime = spawn_node_runtime(node_b.clone());
    wait_for_listener_ready("127.0.0.1:43391", 10)
        .await
        .expect("B listener");
    let _node_c_runtime = spawn_node_runtime(node_c.clone());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("B should connect to A");
    wait_for_peer_count(&node_c, 1, Duration::from_secs(35))
        .await
        .expect("C should connect to B");

    // Mine on A
    mine_blocks(&node_a, 1).await.expect("A mining failed");

    // Block must reach C through B (2 hops)
    wait_for_height(&node_c, 1, Duration::from_secs(30))
        .await
        .expect("block should propagate A→B→C");

    let (h_a, h_b, h_c) = {
        let a = node_a.chain.lock().await.tip_height.0;
        let b = node_b.chain.lock().await.tip_height.0;
        let c = node_c.chain.lock().await.tip_height.0;
        (a, b, c)
    };

    assert_eq!(h_a, 1);
    assert_eq!(h_b, 1);
    assert_eq!(h_c, 1);
    println!("[OK] three_node: A={} B={} C={}", h_a, h_b, h_c);
}

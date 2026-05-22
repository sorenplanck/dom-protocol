//! Test: Late-joining node performs IBD from running network.
//!
//! Two nodes run and mine 5 blocks. A third node joins late and must
//! IBD all 5 blocks from one of them.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
async fn test_late_join_ibd() {
    let config_a = test_config("late-a", 43393, true);
    let mut config_b = test_config("late-b", 43394, false);
    config_b.seed_peers = vec!["127.0.0.1:43393".into()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;
    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready("127.0.0.1:43393", 10).await.expect("A listener");
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("B should connect to A");

    // Mine 5 blocks while only A and B are online
    mine_blocks(&node_a, 5).await.expect("A mining failed");
    wait_for_height(&node_b, 5, Duration::from_secs(30))
        .await
        .expect("B should sync");

    // Now C joins late
    let mut config_c = test_config("late-c", 43395, false);
    config_c.seed_peers = vec!["127.0.0.1:43394".into()]; // connects to B
    wait_for_listener_ready("127.0.0.1:43394", 10).await.expect("B listener");
    let node_c = spawn_node(config_c).await;
    tokio::spawn(node_c.clone().run());

    wait_for_peer_count(&node_c, 1, Duration::from_secs(35))
        .await
        .expect("C should connect");

    wait_for_height(&node_c, 5, Duration::from_secs(60))
        .await
        .expect("C should IBD to height 5");

    // All three should agree
    let (h_a, hash_a) = {
        let c = node_a.chain.lock().await;
        (c.tip_height.0, c.tip_hash)
    };
    let (h_c, hash_c) = {
        let c = node_c.chain.lock().await;
        (c.tip_height.0, c.tip_hash)
    };
    assert_eq!(h_a, h_c);
    assert_eq!(hash_a, hash_c);

    println!("[OK] late_join_ibd: C synced to height {}", h_c);
}

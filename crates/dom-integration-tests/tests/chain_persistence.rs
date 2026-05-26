//! Test: Chain state persists across node restart.
//!
//! Bootstraps canonical state, shuts down, restarts, verifies chain state preserved.

use dom_integration_tests::helpers::*;
use std::time::Duration;
use std::time::Instant;

#[tokio::test]
async fn test_chain_persists_across_restart() {
    let data_dir = "/tmp/dom-test-chain-persist".to_string();
    let _ = std::fs::remove_dir_all(&data_dir);

    // First run
    let (height_first, hash_first) = {
        let mut config = test_config("chain-persist", free_local_port(), true);
        config.data_dir = data_dir.clone();

        let node = tokio::time::timeout(Duration::from_secs(20), spawn_node(config))
            .await
            .expect("initial spawn timed out");

        tokio::time::sleep(Duration::from_millis(500)).await;

        let chain = node.chain.lock().await;
        let snapshot = (chain.tip_height.0, chain.tip_hash);
        drop(chain);
        drop(node);
        snapshot
    };

    assert_eq!(
        height_first, 0,
        "genesis height should persist as canonical base"
    );

    // Drop everything, wait
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Second run: same data_dir, no mining
    let (height_second, hash_second) = {
        let mut config = test_config("chain-persist-2", free_local_port(), false);
        config.data_dir = data_dir.clone();

        let node = tokio::time::timeout(Duration::from_secs(20), spawn_node(config))
            .await
            .expect("restart spawn timed out");
        // Don't even need to run() for this — init reads from disk
        let chain = node.chain.lock().await;
        let snapshot = (chain.tip_height.0, chain.tip_hash);
        drop(chain);
        drop(node);
        snapshot
    };

    assert_eq!(height_first, height_second, "height should persist");
    assert_eq!(hash_first, hash_second, "tip hash should persist");

    println!(
        "[OK] chain_persists: height={} hash={}",
        height_second, hash_second
    );
}

#[tokio::test]
async fn deferred_block_queue_is_runtime_only_across_restart() {
    let data_dir = "/tmp/dom-test-deferred-queue-runtime-only".to_string();
    let _ = std::fs::remove_dir_all(&data_dir);

    let (height_first, hash_first) = {
        let mut config = test_config("deferred-queue-runtime-only", free_local_port(), true);
        config.data_dir = data_dir.clone();

        let node = tokio::time::timeout(Duration::from_secs(20), spawn_node(config))
            .await
            .expect("initial spawn timed out");

        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(
            node.future_block_queue
                .defer(dom_node::future_block_queue::DeferredBlock {
                    block_hash: [0x42; 32],
                    timestamp: u64::MAX,
                    queued_at: Instant::now(),
                    block_bytes: vec![0xde, 0xad, 0xbe, 0xef],
                })
                .await
        );
        assert_eq!(node.future_block_queue.size().await, 1);

        let chain = node.chain.lock().await;
        let snapshot = (chain.tip_height.0, chain.tip_hash);
        drop(chain);
        drop(node);
        snapshot
    };

    tokio::time::sleep(Duration::from_secs(2)).await;

    let (height_second, hash_second, queue_size_second) = {
        let mut config = test_config("deferred-queue-runtime-only-2", free_local_port(), false);
        config.data_dir = data_dir.clone();

        let node = tokio::time::timeout(Duration::from_secs(20), spawn_node(config))
            .await
            .expect("restart spawn timed out");
        let queue_size = node.future_block_queue.size().await;
        let chain = node.chain.lock().await;
        let snapshot = (chain.tip_height.0, chain.tip_hash, queue_size);
        drop(chain);
        drop(node);
        snapshot
    };

    assert_eq!(height_first, height_second, "height should persist");
    assert_eq!(hash_first, hash_second, "tip hash should persist");
    assert_eq!(
        queue_size_second, 0,
        "deferred block queue must remain runtime-only across restart"
    );
}

#[tokio::test]
async fn deferred_block_queue_stays_runtime_only_across_restart_loop() {
    let data_dir = "/tmp/dom-test-deferred-queue-restart-loop".to_string();
    let _ = std::fs::remove_dir_all(&data_dir);

    let (expected_height, expected_hash) = {
        let mut config = test_config(
            "deferred-queue-restart-loop-initial",
            free_local_port(),
            true,
        );
        config.data_dir = data_dir.clone();

        let node = tokio::time::timeout(Duration::from_secs(20), spawn_node(config))
            .await
            .expect("initial spawn timed out");

        let chain = node.chain.lock().await;
        let snapshot = (chain.tip_height.0, chain.tip_hash);
        drop(chain);
        drop(node);
        snapshot
    };

    for round in 0..16u8 {
        let mut config = test_config(
            &format!("deferred-queue-restart-loop-{round}"),
            free_local_port(),
            false,
        );
        config.data_dir = data_dir.clone();

        let node = tokio::time::timeout(Duration::from_secs(20), spawn_node(config))
            .await
            .expect("restart spawn timed out");

        let queue_size = node.future_block_queue.size().await;
        let chain = node.chain.lock().await;
        assert_eq!(
            chain.tip_height.0, expected_height,
            "restart round {round} must preserve canonical height"
        );
        assert_eq!(
            chain.tip_hash, expected_hash,
            "restart round {round} must preserve canonical tip hash"
        );
        drop(chain);

        assert_eq!(
            queue_size, 0,
            "restart round {round} must not resurrect deferred queue state"
        );
        assert_eq!(
            node.metrics
                .peer_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "restart round {round} must not reopen with connected peers"
        );
        assert_eq!(
            node.metrics
                .inbound_peers
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "restart round {round} must not reopen with inbound peer metrics"
        );
        assert_eq!(
            node.metrics
                .outbound_peers
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "restart round {round} must not reopen with outbound peer metrics"
        );

        assert!(
            node.future_block_queue
                .defer(dom_node::future_block_queue::DeferredBlock {
                    block_hash: [round; 32],
                    timestamp: u64::MAX - round as u64,
                    queued_at: Instant::now(),
                    block_bytes: vec![round, 0xde, 0xad, 0xbe, 0xef],
                })
                .await,
            "restart round {round} must admit a runtime-only deferred block"
        );
        assert_eq!(
            node.future_block_queue.size().await,
            1,
            "restart round {round} should hold exactly one runtime-only deferred block before drop"
        );

        drop(node);
    }
}

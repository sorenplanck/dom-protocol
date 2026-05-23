//! Test helpers for integration tests.

use dom_config::NodeConfig;
use std::sync::Once;

static TRACING_INIT: Once = Once::new();

/// Initialize tracing once per test process. Safe to call from multiple tests.
pub fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let filter = std::env::var("RUST_LOG")
            .unwrap_or_else(|_| "info,dom_node=debug,dom_wire=debug".into());
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init();
    });
}
use dom_node::node::DomNode;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// Spawn a test node with custom config.
///
/// Genesis block is created automatically if the chain is empty. This
/// mirrors production behavior: since `genesis_anchor()` uses
/// `GENESIS_TIMESTAMP_PLACEHOLDER` (a compile-time constant), every node
/// produces the same genesis_hash deterministically. In production, every
/// fresh node bootstraps genesis locally on first start — no P2P sync
/// needed for height=0. The test harness reflects that.
pub async fn spawn_node(config: NodeConfig) -> Arc<DomNode> {
    let node = Arc::new(DomNode::init(config).expect("node init failed"));
    {
        let chain = node.chain.lock().await;
        let needs_genesis = chain.tip_height.0 == 0 && chain.tip_hash == dom_core::Hash256::ZERO;
        drop(chain);
        if needs_genesis {
            dom_node::miner::create_genesis_block(node.clone())
                .await
                .expect("genesis creation failed");
        }
    }
    node
}

/// Wait for a node's P2P listener to be ready (port accepting connections).
pub async fn wait_for_listener_ready(addr: &str, timeout_secs: u64) -> Result<(), String> {
    use tokio::net::TcpStream;
    let start = std::time::Instant::now();
    let deadline = std::time::Duration::from_secs(timeout_secs);
    while start.elapsed() < deadline {
        if TcpStream::connect(addr).await.is_ok() {
            // Give the listener a moment to fully set up
            sleep(Duration::from_millis(200)).await;
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "listener at {} did not become ready in {}s",
        addr, timeout_secs
    ))
}

/// Wait for node to reach a specific height (with timeout).
pub async fn wait_for_height(
    node: &Arc<DomNode>,
    target_height: u64,
    timeout_duration: Duration,
) -> Result<(), String> {
    timeout(timeout_duration, async {
        loop {
            let chain = node.chain.lock().await;
            let current_height = chain.tip_height.0;
            drop(chain);

            if current_height >= target_height {
                return Ok(());
            }

            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| format!("timeout waiting for height {}", target_height))?
}

/// Wait for node to have at least N peers connected.
pub async fn wait_for_peer_count(
    node: &Arc<DomNode>,
    min_peers: usize,
    timeout_duration: Duration,
) -> Result<(), String> {
    timeout(timeout_duration, async {
        loop {
            let peers = node.peers.lock().await;
            let count = peers.connected_peers().len();
            drop(peers);

            if count >= min_peers {
                return Ok(());
            }

            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| format!("timeout waiting for {} peers", min_peers))?
}

/// Mine N blocks on a node (blocks until done).
///
/// If the chain is empty (no genesis), creates the genesis block first.
/// This mirrors what `mining_loop` does automatically when `mine: true`,
/// but lets integration tests control mining deterministically.
pub async fn mine_blocks(node: &Arc<DomNode>, count: u64) -> Result<(), String> {
    // Bootstrap genesis if chain is empty.
    {
        let chain = node.chain.lock().await;
        let needs_genesis = chain.tip_height.0 == 0 && chain.tip_hash == dom_core::Hash256::ZERO;
        drop(chain);
        if needs_genesis {
            dom_node::miner::create_genesis_block(node.clone())
                .await
                .map_err(|e| format!("genesis failed: {:?}", e))?;
        }
    }
    for _ in 0..count {
        dom_node::miner::mine_one_block(node.clone())
            .await
            .map_err(|e| format!("mining failed: {:?}", e))?;
    }
    Ok(())
}

/// Create a test NodeConfig with unique data directory.
///
/// IMPORTANT: the `mine` parameter is accepted for backwards-compat with existing
/// tests but is FORCED to `false` internally. Auto-mining in `node.run()` spawns
/// a tight loop that holds `chain.lock()` continuously, which deadlocks against
/// the manual `mine_blocks()` helper. Integration tests must use deterministic
/// manual mining via `mine_blocks()` instead — the helper now bootstraps genesis
/// automatically on first call.
pub fn test_config(name: &str, port: u16, _mine: bool) -> NodeConfig {
    let data_dir = format!("/tmp/dom-test-{}", name);
    NodeConfig {
        network: dom_config::Network::Testnet,
        data_dir,
        p2p_listen_addr: format!("127.0.0.1:{}", port),
        max_inbound: 10,
        min_outbound: 1,
        dns_seeds: vec![],
        seed_peers: vec![],
        mine: false,
        miner_address: None,
        wallet_path: None,
        wallet_password: None,
        log_level: "debug".into(),
        rpc_listen_addr: None,
    }
}

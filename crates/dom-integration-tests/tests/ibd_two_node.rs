//! Adversarial two-node IBD/reorg/eclipse integration suite.
//!
//! Every test in this file is tied to a production regression that escaped unit
//! coverage:
//!
//! - B1: Noise headers payloads above one frame failed without fragmentation.
//! - B2: RandomX seed lookup used only committed store during header-first IBD.
//! - B3: sync-only nodes did not commit genesis before IBD.
//! - B4: relayed blocks during IBD were confused with GetBlockData responses.
//! - B5: epoch-boundary seed drift split miner/validator at height 2048.

use dom_config::{Network, NodeConfig};
use dom_consensus::block::ProofOfWork;
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, BlockHeader, CoinbaseKernel,
    CoinbaseTransaction, TransactionOutput,
};
use dom_core::{BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, PROTOCOL_VERSION};
use dom_integration_tests::helpers::*;
use dom_node::node::DomNode;
use dom_pow::{
    compute_expected_target, fast_pow_hash, randomx_seed_height, target_to_compact,
    target_to_difficulty, CompactTarget, RANDOMX_SEED_INTERVAL,
};
use dom_serialization::DomDeserialize;
use dom_wire::codec::NoiseCodec;
use dom_wire::handshake::{generate_static_keypair, perform_handshake_initiator};
use dom_wire::message::{Command, HeadersPayload, HelloPayload, WireMessage};
use primitive_types::U256;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const IBD_TIMEOUT: Duration = Duration::from_secs(120);
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(30);
const TEST_LMDB_MAP_SIZE: usize = 64 << 20;
const T1_RANDOMX_BOUNDARY_HEIGHT: u64 = RANDOMX_SEED_INTERVAL + 12;
const T1_IBD_TIMEOUT: Duration = Duration::from_secs(300);

fn enable_fast_regtest_mining() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "error");
    }
}

struct TestLog {
    path: PathBuf,
    file: File,
}

impl TestLog {
    fn new(name: &str) -> Self {
        let root = std::env::var_os("DOM_INTEGRATION_LOG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("dom-ibd-two-node-logs"));
        fs::create_dir_all(&root).expect("create integration log dir");
        let path = root.join(format!("{name}.log"));
        let file = File::create(&path).expect("create integration log file");
        Self { path, file }
    }

    fn line(&mut self, msg: impl AsRef<str>) {
        writeln!(self.file, "{}", msg.as_ref()).expect("write integration log");
        self.file.flush().expect("flush integration log");
    }
}

impl Drop for TestLog {
    fn drop(&mut self) {
        let _ = self.file.flush();
        eprintln!("DOM integration log: {}", self.path.display());
    }
}

async fn start_node(node: Arc<DomNode>) -> tokio::task::JoinHandle<Result<(), dom_core::DomError>> {
    let addr = node.config.p2p_listen_addr.clone();
    let handle = tokio::spawn(node.clone().run());
    wait_for_listener_ready(&addr, 10)
        .await
        .unwrap_or_else(|e| panic!("{addr} listener should start: {e}"));
    handle
}

async fn stop_node(
    node: &Arc<DomNode>,
    handle: tokio::task::JoinHandle<Result<(), dom_core::DomError>>,
) {
    node.request_shutdown().await;
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("node shutdown should not hang")
        .expect("node task should join")
        .expect("node shutdown should be clean");
}

async fn spawn_node(config: NodeConfig) -> Arc<DomNode> {
    let node = Arc::new(
        DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE).expect("node init failed"),
    );
    {
        let chain = node.chain.lock().await;
        let needs_genesis = chain.tip_height.0 == 0 && chain.tip_hash == Hash256::ZERO;
        drop(chain);
        if needs_genesis {
            dom_node::miner::create_genesis_block(node.clone())
                .await
                .expect("genesis creation failed");
        }
    }
    node
}

async fn tip(node: &Arc<DomNode>) -> (u64, Hash256) {
    let chain = node.chain.lock().await;
    (chain.tip_height.0, chain.tip_hash)
}

async fn peer_count(node: &Arc<DomNode>) -> usize {
    node.peers.lock().await.connected_peers().len()
}

async fn wait_for_tip_hash(node: &Arc<DomNode>, expected: Hash256, timeout_duration: Duration) {
    let started = Instant::now();
    loop {
        {
            let chain = node.chain.lock().await;
            if chain.tip_hash == expected {
                break;
            }
        }

        assert!(
            started.elapsed() < timeout_duration,
            "timeout waiting for matching tip hash"
        );

        tokio::select! {
            _ = node.state_events.notified() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

async fn mine_blocks_resilient(node: &Arc<DomNode>, count: u64) -> Result<(), String> {
    let mut mined = 0;
    while mined < count {
        match mine_blocks(node, 1).await {
            Ok(()) => mined += 1,
            Err(err) if err.contains("too far in future") => {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_test_coinbase(
    height: BlockHeight,
    chain_id: &[u8; 32],
) -> Result<CoinbaseTransaction, dom_core::DomError> {
    use dom_crypto::bulletproof;
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::keys::SecretKey;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use dom_crypto::schnorr_sign;

    let explicit_value = dom_core::block_reward(height).noms();
    let blinding = BlindingFactor::random();
    let output_commitment = Commitment::commit(explicit_value, &blinding);
    let (range_proof, _) = bulletproof::prove(explicit_value, &blinding)
        .map_err(|e| dom_core::DomError::Internal(format!("coinbase proof: {e}")))?;
    let excess = Commitment::commit(0, &blinding);
    let kernel_message = {
        let mut data = Vec::with_capacity(9);
        data.push(KERNEL_FEAT_COINBASE);
        data.extend_from_slice(&explicit_value.to_le_bytes());
        blake2b_256_tagged(dom_core::TAG_KERNEL_MSG_COINBASE, &data)
    };
    let sk = SecretKey::from_bytes(blinding.as_bytes())
        .map_err(|e| dom_core::DomError::Internal(format!("coinbase secret: {e}")))?;
    let signature = schnorr_sign(&sk, kernel_message.as_bytes(), chain_id)
        .map_err(|e| dom_core::DomError::Internal(format!("coinbase sign: {e}")))?;

    Ok(CoinbaseTransaction {
        output: TransactionOutput {
            commitment: output_commitment,
            proof: range_proof.bytes,
        },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value,
            excess,
            excess_signature: signature.to_bytes(),
        },
        offset: [0u8; 32],
    })
}

async fn prepopulate_coinbase_chain(node: &Arc<DomNode>, target_height: u64) -> Result<(), String> {
    enable_fast_regtest_mining();
    let chain_id = chain_id_for(node.config.network);
    loop {
        let (tip_hash, tip_height, tip_difficulty, parent_ts, seed_hash) = {
            let chain = node.chain.lock().await;
            if chain.tip_height.0 >= target_height {
                return Ok(());
            }
            let current_tip = chain.tip_hash;
            let parent_ts = chain
                .store
                .get_block_header(current_tip.as_bytes())
                .map_err(|e| e.to_string())?
                .and_then(|bytes| BlockHeader::from_bytes(&bytes).ok())
                .map(|header| header.timestamp.0)
                .unwrap_or(0);
            let new_height = chain.tip_height.0 + 1;
            let seed_h = randomx_seed_height(new_height);
            let seed_hash = chain
                .store
                .get_hash_at_height(seed_h)
                .map_err(|e| e.to_string())?
                .unwrap_or([0u8; 32]);
            (
                current_tip,
                chain.tip_height.0,
                chain.tip_difficulty,
                parent_ts,
                seed_hash,
            )
        };

        let new_height = tip_height + 1;
        let timestamp = Timestamp((parent_ts + 1).min(now_secs()));
        let target = compute_expected_target(
            node.config.network.magic(),
            timestamp,
            BlockHeight(new_height),
        )
        .map_err(|e| e.to_string())?;
        let block_diff = target_to_difficulty(&target);
        let new_total_diff = tip_difficulty + U256::from(block_diff);
        let coinbase =
            build_test_coinbase(BlockHeight(new_height), &chain_id).map_err(|e| e.to_string())?;
        let (output_root, kernel_root, rangeproof_root) =
            compute_block_pmmr_roots(&coinbase, &[]).map_err(|e| e.to_string())?;
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_hash: tip_hash,
            height: BlockHeight(new_height),
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(target_to_compact(&target)),
            total_difficulty: new_total_diff,
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        };
        let pow_hash = fast_pow_hash(&seed_hash, &header.pow_preimage());
        header.pow.randomx_hash = Hash256::from_bytes(pow_hash);
        let block = Block {
            header,
            coinbase,
            transactions: vec![],
        };
        {
            let mut chain = node.chain.lock().await;
            chain
                .connect_block(&block, Timestamp(now_secs()))
                .map_err(|e| e.to_string())?;
        }
        node.state_events.notify_waiters();
    }
}

async fn assert_no_bans(node: &Arc<DomNode>) {
    let peers = node.peers.lock().await;
    let reputation = peers.peer_reputation_state();
    assert!(
        reputation.entries.is_empty(),
        "expected no peer bans/penalties, got {:?}",
        reputation.entries
    );
}

fn clear_test_peer_rotation_backoff(data_dir: &str) {
    const PEER_ROTATION_METADATA_KEY: &[u8] = b"dom/peer_rotation_state/v2";
    const LEGACY_PEER_ROTATION_METADATA_KEY: &[u8] = b"dom/peer_rotation_state/v1";

    let store =
        dom_store::DomStore::open_with_map_size(std::path::Path::new(data_dir), TEST_LMDB_MAP_SIZE)
            .expect("open store to clear test peer rotation backoff");
    store
        .delete_metadata(PEER_ROTATION_METADATA_KEY)
        .expect("clear test peer rotation metadata");
    store
        .delete_metadata(LEGACY_PEER_ROTATION_METADATA_KEY)
        .expect("clear legacy test peer rotation metadata");
}

fn chain_id_for(network: Network) -> [u8; 32] {
    let genesis_hash = match network {
        Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
    };
    *derive_chain_id(network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes()
}

async fn connect_noise_peer_with_height(
    node: &Arc<DomNode>,
    best_height: u64,
    user_agent: &str,
) -> (tokio::net::TcpStream, NoiseCodec) {
    let config = node.config.clone();
    let mut stream = tokio::net::TcpStream::connect(&config.p2p_listen_addr)
        .await
        .expect("connect adversarial peer");
    let (privkey, _) = generate_static_keypair();
    let chain_id = chain_id_for(config.network);
    let transport =
        perform_handshake_initiator(&mut stream, &privkey, config.network.magic(), &chain_id)
            .await
            .expect("perform Noise handshake");
    let mut codec = NoiseCodec::new(transport, config.network.magic());
    let hello = HelloPayload {
        version: PROTOCOL_VERSION,
        network_magic: config.network.magic(),
        chain_id,
        best_height,
        best_hash: [0u8; 32],
        user_agent: user_agent.into(),
        local_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let wire = WireMessage {
        magic: config.network.magic(),
        command: Command::Hello,
        payload: hello.to_bytes().expect("serialize hello"),
    };
    codec.send(&mut stream, &wire).await.expect("send hello");
    let response = codec.recv(&mut stream).await.expect("receive hello");
    assert_eq!(response.command, Command::Hello);
    (stream, codec)
}

async fn wait_for_any_peer_penalty(node: &Arc<DomNode>, timeout_duration: Duration) {
    tokio::time::timeout(timeout_duration, async {
        loop {
            let reputation = node.peers.lock().await.peer_reputation_state();
            if !reputation.entries.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("timeout waiting for peer penalty");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn t1_ibd_through_randomx_epoch_boundary_via_three_real_nodes() {
    enable_fast_regtest_mining();
    init_tracing();
    let mut log = TestLog::new("t1_epoch_boundary");
    log.line("T1 covers B2+B3+B5: IBD through RandomX epoch boundary");

    let port_a = free_local_port();
    let port_b = free_local_port();
    let port_c = free_local_port();

    let mut config_b = test_config("t1-b-miner", port_b, false);
    config_b.min_outbound = 0;
    let node_b = spawn_node(config_b).await;

    let target_seed_height = randomx_seed_height(T1_RANDOMX_BOUNDARY_HEIGHT);
    assert!(
        target_seed_height > 0,
        "T1 target must cross the first RandomX seed boundary"
    );
    log.line(format!(
        "T1 target height={T1_RANDOMX_BOUNDARY_HEIGHT}, seed_height={target_seed_height}"
    ));
    let started = Instant::now();
    prepopulate_coinbase_chain(&node_b, T1_RANDOMX_BOUNDARY_HEIGHT)
        .await
        .expect("B should mine past the first RandomX seed boundary");
    log.line(format!(
        "B mined {T1_RANDOMX_BOUNDARY_HEIGHT} blocks in {:?}",
        started.elapsed()
    ));
    let _task_b = start_node(node_b.clone()).await;

    let mut config_a = test_config("t1-a-sync", port_a, false);
    config_a.seed_peers = vec![format!("127.0.0.1:{port_b}")];
    let node_a = spawn_node(config_a).await;
    let _task_a = start_node(node_a.clone()).await;
    wait_for_peer_count(&node_a, 1, Duration::from_secs(45))
        .await
        .expect("A should complete outbound handshake with B before boundary IBD");
    wait_for_peer_count(&node_b, 1, Duration::from_secs(45))
        .await
        .expect("B should register A before serving boundary IBD");

    let a_sync_started = Instant::now();
    if let Err(err) = wait_for_height(&node_a, T1_RANDOMX_BOUNDARY_HEIGHT, T1_IBD_TIMEOUT).await {
        let (height_a, hash_a) = tip(&node_a).await;
        let (height_b, hash_b) = tip(&node_b).await;
        let peers_a = peer_count(&node_a).await;
        let peers_b = peer_count(&node_b).await;
        log.line(format!(
            "A IBD timeout after {:?}: A height={height_a}, A tip={}, B height={height_b}, B tip={}, A peers={peers_a}, B peers={peers_b}",
            a_sync_started.elapsed(),
            hex::encode(hash_a.as_bytes()),
            hex::encode(hash_b.as_bytes())
        ));
        panic!("A IBD should complete within {:?}: {err}", T1_IBD_TIMEOUT);
    }
    let a_elapsed = a_sync_started.elapsed();
    log.line(format!("A synced in {:?}", a_elapsed));
    assert!(
        a_elapsed < T1_IBD_TIMEOUT,
        "A IBD exceeded T1 guard timeout: {:?}",
        a_elapsed
    );

    let mut config_c = test_config("t1-c-sync", port_c, false);
    config_c.seed_peers = vec![format!("127.0.0.1:{port_a}")];
    let node_c = spawn_node(config_c).await;
    let _task_c = start_node(node_c.clone()).await;
    wait_for_peer_count(&node_c, 1, Duration::from_secs(45))
        .await
        .expect("C should complete outbound handshake with A before indirect IBD");
    wait_for_peer_count(&node_a, 2, Duration::from_secs(45))
        .await
        .expect("A should register C while still connected to B");

    if let Err(err) = wait_for_height(&node_c, T1_RANDOMX_BOUNDARY_HEIGHT, T1_IBD_TIMEOUT).await {
        let (height_a, hash_a) = tip(&node_a).await;
        let (height_b, hash_b) = tip(&node_b).await;
        let (height_c, hash_c) = tip(&node_c).await;
        let peers_a = peer_count(&node_a).await;
        let peers_b = peer_count(&node_b).await;
        let peers_c = peer_count(&node_c).await;
        log.line(format!(
            "C IBD timeout: A height={height_a}, A tip={}, B height={height_b}, B tip={}, C height={height_c}, C tip={}, A peers={peers_a}, B peers={peers_b}, C peers={peers_c}",
            hex::encode(hash_a.as_bytes()),
            hex::encode(hash_b.as_bytes()),
            hex::encode(hash_c.as_bytes())
        ));
        panic!("C should sync indirectly through A: {err}");
    }

    let (h_a, hash_a) = tip(&node_a).await;
    let (h_b, hash_b) = tip(&node_b).await;
    let (h_c, hash_c) = tip(&node_c).await;
    assert!(
        h_a >= T1_RANDOMX_BOUNDARY_HEIGHT
            && h_b >= T1_RANDOMX_BOUNDARY_HEIGHT
            && h_c >= T1_RANDOMX_BOUNDARY_HEIGHT
    );
    assert_eq!(hash_a, hash_b, "A and B tips diverged");
    assert_eq!(hash_a, hash_c, "A and C tips diverged");
    assert_no_bans(&node_a).await;
    assert_no_bans(&node_b).await;
    assert_no_bans(&node_c).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn t2_ibd_with_active_miner_relay_during_sync() {
    enable_fast_regtest_mining();
    init_tracing();
    let mut log = TestLog::new("t2_active_miner_relay");
    log.line("T2 covers B4: relayed blocks during IBD are not GetBlockData replies");

    let port_a = free_local_port();
    let port_b = free_local_port();
    let node_a = spawn_node(test_config("t2-a-miner", port_a, false)).await;
    let _task_a = start_node(node_a.clone()).await;
    mine_blocks_resilient(&node_a, 50)
        .await
        .expect("A should pre-mine 50 blocks");

    let mut config_b = test_config("t2-b-sync", port_b, false);
    config_b.seed_peers = vec![format!("127.0.0.1:{port_a}")];
    let node_b = spawn_node(config_b).await;
    let _task_b = start_node(node_b.clone()).await;
    wait_for_peer_count(&node_b, 1, Duration::from_secs(45))
        .await
        .expect("B should complete outbound handshake with A before active mining");
    wait_for_peer_count(&node_a, 1, Duration::from_secs(45))
        .await
        .expect("A should register B before relaying active mining blocks");

    let miner = {
        let node = node_a.clone();
        tokio::spawn(async move {
            for _ in 0..2 {
                let _ = mine_blocks_resilient(&node, 1).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
    };

    wait_for_height(&node_b, 50, IBD_TIMEOUT)
        .await
        .expect("B should complete IBD while A is still mining");
    miner.await.expect("miner task should finish");
    let (h_a, hash_a) = tip(&node_a).await;
    wait_for_height(&node_b, h_a, IBD_TIMEOUT)
        .await
        .expect("B should catch blocks mined while IBD was active");
    wait_for_tip_hash(&node_b, hash_a, Duration::from_secs(30)).await;

    mine_blocks_resilient(&node_a, 1)
        .await
        .expect("A mine post-IBD live relay block");
    let (live_height, live_hash) = tip(&node_a).await;
    wait_for_height(&node_b, live_height, Duration::from_secs(60))
        .await
        .expect("B should keep receiving live mined blocks after IBD");
    wait_for_tip_hash(&node_b, live_hash, Duration::from_secs(30)).await;
    assert_no_bans(&node_b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn t3_ibd_noise_fragmentation_headers_above_one_frame() {
    enable_fast_regtest_mining();
    init_tracing();
    let mut log = TestLog::new("t3_noise_fragmentation");
    log.line("T3 covers B1: headers payload above one Noise frame");

    let headers = vec![vec![0u8; 260]; 300];
    let payload_len = HeadersPayload { headers }
        .to_bytes()
        .expect("serialize synthetic 300-header payload")
        .len();
    assert!(
        payload_len > 65_519,
        "300 headers must exceed one Noise frame; got {payload_len}"
    );
    log.line(format!("synthetic Headers payload length = {payload_len}"));

    let port_a = free_local_port();
    let port_b = free_local_port();
    let node_a = spawn_node(test_config("t3-a-source", port_a, false)).await;
    let _task_a = start_node(node_a.clone()).await;
    prepopulate_coinbase_chain(&node_a, 300)
        .await
        .expect("A should pre-populate 300 blocks");

    let mut config_b = test_config("t3-b-sync", port_b, false);
    config_b.seed_peers = vec![format!("127.0.0.1:{port_a}")];
    let node_b = spawn_node(config_b).await;
    let _task_b = start_node(node_b.clone()).await;
    wait_for_height(&node_b, 300, IBD_TIMEOUT)
        .await
        .expect("B should sync 300 blocks over fragmented Noise messages");

    let (h_a, hash_a) = tip(&node_a).await;
    let (h_b, hash_b) = tip(&node_b).await;
    assert_eq!(h_a, h_b);
    assert_eq!(hash_a, hash_b);
    assert_no_bans(&node_b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn t4_reorg_convergence_between_divergent_nodes() {
    enable_fast_regtest_mining();
    init_tracing();
    let mut log = TestLog::new("t4_reorg_convergence");
    log.line("T4 covers divergent private chains converging via reorg");

    let port_a = free_local_port();
    let port_b = free_local_port();
    let node_a = spawn_node(test_config("t4-a-private", port_a, false)).await;
    let node_b = spawn_node(test_config("t4-b-private", port_b, false)).await;
    mine_blocks_resilient(&node_a, 10).await.expect("A mine 10");
    mine_blocks_resilient(&node_b, 8).await.expect("B mine 8");
    let (_, b_old_hash) = tip(&node_b).await;

    let _task_a = start_node(node_a.clone()).await;
    let data_dir_b = node_b.config.data_dir.clone();
    drop(node_b);

    let mut config_b = test_config("t4-b-reopen", port_b, false);
    config_b.data_dir = data_dir_b;
    config_b.seed_peers = vec![format!("127.0.0.1:{port_a}")];
    let node_b = spawn_node(config_b).await;
    let _task_b = start_node(node_b.clone()).await;

    wait_for_height(&node_b, 10, CONVERGENCE_TIMEOUT)
        .await
        .expect("B should reorg to A's taller chain");
    let (h_a, hash_a) = tip(&node_a).await;
    wait_for_tip_hash(&node_b, hash_a, CONVERGENCE_TIMEOUT).await;
    let (h_b, hash_b) = tip(&node_b).await;
    assert_eq!(h_a, h_b);
    assert_eq!(hash_a, hash_b);
    assert_ne!(hash_b, b_old_hash, "B did not change tip during reorg");

    let utxos_a = node_a
        .chain
        .lock()
        .await
        .store
        .read_all_utxos_raw()
        .expect("A utxo set");
    let utxos_b = node_b
        .chain
        .lock()
        .await
        .store
        .read_all_utxos_raw()
        .expect("B utxo set");
    assert_eq!(utxos_a, utxos_b, "UTXO sets diverged after reorg");
    assert_no_bans(&node_a).await;
    assert_no_bans(&node_b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn t5_peer_ban_does_not_isolate_node_from_honest_peer() {
    enable_fast_regtest_mining();
    init_tracing();
    let mut log = TestLog::new("t5_peer_ban_no_isolation");
    log.line("T5 covers malicious peer ban without isolating honest sync");

    let port_a = free_local_port();
    let port_b = free_local_port();
    let node_a = spawn_node(test_config("t5-a-honest", port_a, false)).await;
    let _task_a = start_node(node_a.clone()).await;
    mine_blocks_resilient(&node_a, 20).await.expect("A mine 20");

    let mut config_b = test_config("t5-b-target", port_b, false);
    config_b.seed_peers = vec![format!("127.0.0.1:{port_a}")];
    let node_b = spawn_node(config_b).await;
    let _task_b = start_node(node_b.clone()).await;
    wait_for_peer_count(&node_b, 1, Duration::from_secs(35))
        .await
        .expect("B should keep honest A peer");

    let (mut stream, mut codec) =
        connect_noise_peer_with_height(&node_b, 0, "dom-malicious-c").await;
    let invalid = WireMessage {
        magic: node_b.config.network.magic(),
        command: Command::Block,
        payload: vec![0xde, 0xad],
    };
    for _ in 0..6 {
        let _ = codec.send(&mut stream, &invalid).await;
    }
    wait_for_any_peer_penalty(&node_b, Duration::from_secs(10)).await;
    assert!(
        !node_b.peers.lock().await.connected_peers().is_empty(),
        "B should retain the honest A connection after penalizing C"
    );

    mine_blocks_resilient(&node_a, 2)
        .await
        .expect("A mine post-ban");
    let (h_a, _) = tip(&node_a).await;
    wait_for_height(&node_b, h_a, Duration::from_secs(60))
        .await
        .expect("B should continue syncing from A after C is banned");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn t6_partial_eclipse_invalid_header_peer_is_penalized() {
    enable_fast_regtest_mining();
    init_tracing();
    let mut log = TestLog::new("t6_partial_eclipse");
    log.line("T6 covers partial eclipse: invalid-header peer is penalized");

    let port_a = free_local_port();
    let honest_ports = [free_local_port(), free_local_port(), free_local_port()];
    let mut target_config = test_config("t6-a-target", port_a, false);
    target_config.min_outbound = 4;
    target_config.seed_peers = honest_ports
        .iter()
        .map(|port| format!("127.0.0.1:{port}"))
        .collect();

    let mut honest_nodes = Vec::new();
    for (idx, port) in honest_ports.iter().copied().enumerate() {
        let node = spawn_node(test_config(&format!("t6-honest-{idx}"), port, false)).await;
        mine_blocks_resilient(&node, 4)
            .await
            .expect("honest peer mine");
        let _task = start_node(node.clone()).await;
        honest_nodes.push(node);
    }

    let node_a = spawn_node(target_config).await;
    let _task_a = start_node(node_a.clone()).await;
    wait_for_peer_count(&node_a, 2, Duration::from_secs(45))
        .await
        .expect("target should keep at least two honest peers");

    let (mut stream, mut codec) =
        connect_noise_peer_with_height(&node_a, 10, "dom-invalid-header-peer").await;
    let invalid_headers = HeadersPayload {
        headers: vec![vec![0u8; 128]; 4],
    }
    .to_bytes()
    .expect("serialize invalid headers");
    let wire = WireMessage {
        magic: node_a.config.network.magic(),
        command: Command::Headers,
        payload: invalid_headers,
    };
    for _ in 0..6 {
        let _ = codec.send(&mut stream, &wire).await;
    }

    wait_for_any_peer_penalty(&node_a, Duration::from_secs(10)).await;
    assert!(
        node_a.peers.lock().await.connected_peers().len() >= 2,
        "target should retain at least two honest peers"
    );
    let (height, _) = tip(&node_a).await;
    assert!(
        height <= 4,
        "target accepted invalid adversarial headers unexpectedly; height={height}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn t7_ibd_restart_resume_after_interruption() {
    enable_fast_regtest_mining();
    init_tracing();
    let mut log = TestLog::new("t7_ibd_restart_resume");
    log.line("T7 covers IBD interruption/restart resume");

    let port_a = free_local_port();
    let port_b1 = free_local_port();
    let port_b2 = free_local_port();
    let config_a = test_config("t7-a-source", port_a, false);
    let data_dir_a = config_a.data_dir.clone();
    let node_a = spawn_node(config_a).await;
    let task_a = start_node(node_a.clone()).await;
    prepopulate_coinbase_chain(&node_a, 200)
        .await
        .expect("A mine 200");

    let data_dir = {
        let mut config_b = test_config("t7-b-resume", port_b1, false);
        config_b.seed_peers = vec![format!("127.0.0.1:{port_a}")];
        let data_dir = config_b.data_dir.clone();
        let node_b = spawn_node(config_b).await;
        let task_b = start_node(node_b.clone()).await;
        wait_for_height(&node_b, 100, IBD_TIMEOUT)
            .await
            .expect("B should reach at least 50% before interruption");
        let interrupted_height = tip(&node_b).await.0;
        log.line(format!("B interrupted at height {interrupted_height}"));
        stop_node(&node_a, task_a).await;
        drop(node_a);
        log.line("A stopped to drop B's IBD connection before restart");
        stop_node(&node_b, task_b).await;
        drop(node_b);
        clear_test_peer_rotation_backoff(&data_dir);
        log.line("B peer-rotation backoff cleared for deterministic test reconnect");
        tokio::time::sleep(Duration::from_millis(500)).await;
        data_dir
    };

    let mut resumed_source = test_config("t7-a-source-resumed", port_a, false);
    resumed_source.data_dir = data_dir_a;
    let node_a = spawn_node(resumed_source).await;
    let _task_a = start_node(node_a.clone()).await;

    let mut resumed = test_config("t7-b-resumed", port_b2, false);
    resumed.data_dir = data_dir;
    resumed.seed_peers = vec![format!("127.0.0.1:{port_a}")];
    log.line(format!(
        "B resume config: listen={}, seed_peers={:?}; A listen={}",
        resumed.p2p_listen_addr, resumed.seed_peers, node_a.config.p2p_listen_addr
    ));
    let node_b = spawn_node(resumed).await;
    let pre_resume_height = tip(&node_b).await.0;
    log.line(format!("B reopened at height {pre_resume_height}"));
    assert!(
        (100..200).contains(&pre_resume_height),
        "B did not persist partial IBD progress; height={pre_resume_height}"
    );
    let _task_b = start_node(node_b.clone()).await;
    if let Err(err) = wait_for_peer_count(&node_b, 1, Duration::from_secs(45)).await {
        let (height_a, hash_a) = tip(&node_a).await;
        let (height_b, hash_b) = tip(&node_b).await;
        let peers_a = peer_count(&node_a).await;
        let peers_b = peer_count(&node_b).await;
        log.line(format!(
            "B resume handshake timeout: err={err}, A listen={}, B listen={}, A height={height_a}, A tip={}, B height={height_b}, B tip={}, A peers={peers_a}, B peers={peers_b}",
            node_a.config.p2p_listen_addr,
            node_b.config.p2p_listen_addr,
            hex::encode(hash_a.as_bytes()),
            hex::encode(hash_b.as_bytes())
        ));
        panic!("resumed B should complete outbound handshake with A: {err}");
    }
    if let Err(err) = wait_for_peer_count(&node_a, 1, Duration::from_secs(45)).await {
        let (height_a, hash_a) = tip(&node_a).await;
        let (height_b, hash_b) = tip(&node_b).await;
        let peers_a = peer_count(&node_a).await;
        let peers_b = peer_count(&node_b).await;
        log.line(format!(
            "A resume registration timeout: err={err}, A listen={}, B listen={}, A height={height_a}, A tip={}, B height={height_b}, B tip={}, A peers={peers_a}, B peers={peers_b}",
            node_a.config.p2p_listen_addr,
            node_b.config.p2p_listen_addr,
            hex::encode(hash_a.as_bytes()),
            hex::encode(hash_b.as_bytes())
        ));
        panic!("resumed A should register B before IBD resume: {err}");
    }
    if let Err(err) = wait_for_height(&node_b, 200, IBD_TIMEOUT).await {
        let (height, hash) = tip(&node_b).await;
        let a_height = tip(&node_a).await.0;
        let peers_a = peer_count(&node_a).await;
        let peers_b = peer_count(&node_b).await;
        log.line(format!(
            "B resume timeout: A height={a_height}, B height={height}, B tip={}, A peers={peers_a}, B peers={peers_b}",
            hex::encode(hash.as_bytes())
        ));
        panic!("B should resume and finish IBD: {err}");
    }
    let (_, hash_a) = tip(&node_a).await;
    wait_for_tip_hash(&node_b, hash_a, Duration::from_secs(30)).await;
}

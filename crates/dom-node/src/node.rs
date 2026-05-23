//! Full node orchestration.

use crate::miner::mining_loop;
use dom_chain::ChainState;
use dom_config::NodeConfig;
use dom_consensus::derive_chain_id;
use dom_core::DomError;
use dom_core::Hash256;
use dom_core::Timestamp;
use dom_mempool::Mempool;
use dom_store::DomStore;
use dom_wire::dandelion::DandelionRouter;
use dom_wire::manager::PeerManager;
use dom_wallet::Wallet;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};
use crate::time_health::{check_clock_health, DriftStatus};
use crate::metrics::Metrics;

/// The full DOM node.
pub struct DomNode {
    /// Node configuration.
    pub config: NodeConfig,
    /// Chain state.
    pub chain: Arc<Mutex<ChainState>>,
    /// Transaction mempool.
    pub mempool: Arc<Mutex<Mempool>>,
    /// Peer manager.
    pub peers: Arc<Mutex<PeerManager>>,
    /// Dandelion++ router.
    pub dandelion: Arc<Mutex<DandelionRouter>>,
    /// Node's Noise static keypair private key.
    pub noise_privkey: [u8; 32],
    /// Broadcast channel for relaying newly-mined or received blocks to all peers.
    /// Senders: miner after connect_block; message_loop after accepting a relayed Block.
    /// Receivers: one per connected peer task.
    pub block_relay_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    /// Broadcast channel for Dandelion++ Fluff-phase transactions.
    /// Every connected peer task forwards every Fluff envelope to its peer.
    /// Senders: submit_tx (local origination) and Command::Tx handler when
    /// process_stem_tx returns Fluff. Also the periodic stem-timeout task.
    pub tx_fluff_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    /// Broadcast channel for Dandelion++ Stem-phase transactions.
    /// Every peer task receives the envelope but only the one whose peer_addr
    /// matches StemEnvelope.target_peer actually forwards to its peer.
    /// Senders: submit_tx and Command::Tx handler when route decides Stem.
    pub tx_stem_tx: tokio::sync::broadcast::Sender<dom_wire::dandelion::StemEnvelope>,
    /// Optional wallet for mining rewards.
    /// If Some, miner uses wallet.build_coinbase() for deterministic blinding.
    /// If None, miner falls back to random blinding (DOM-SEC-004 unresolved).
    pub wallet: Option<Arc<Mutex<Wallet>>>,
    /// Node metrics for Prometheus export.
    pub metrics: Arc<Metrics>,
    /// Future block queue for soft buffer (Doc 4.5 mitigation 1).
    pub future_block_queue: Arc<crate::future_block_queue::FutureBlockQueue>,
}

/// Per-connection I/O context passed into message_loop.
struct PeerConn<'a> {
    stream: &'a mut tokio::net::TcpStream,
    codec: &'a mut dom_wire::codec::NoiseCodec,
}

/// Shared node services passed into per-connection tasks.
/// Groups mempool, dandelion router, peer manager, and wallet to stay under
/// clippy's function-argument limit (max 7).
#[derive(Clone)]
struct NodeServices {
    mempool: Arc<Mutex<dom_mempool::Mempool>>,
    dandelion: Arc<Mutex<dom_wire::dandelion::DandelionRouter>>,
    peers: Arc<Mutex<dom_wire::manager::PeerManager>>,
    wallet: Option<Arc<Mutex<dom_wallet::Wallet>>>,
}

/// Broadcast channels shared across connection tasks.
///
/// Consolidates the three broadcast senders that were previously passed
/// individually to connect_outbound / handle_inbound / message_loop,
/// keeping each function under the clippy::too_many_arguments threshold.
#[derive(Clone)]
struct BroadcastChannels {
    block_relay_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    tx_fluff_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    tx_stem_tx: tokio::sync::broadcast::Sender<dom_wire::dandelion::StemEnvelope>,
}

impl DomNode {
    /// Initialize the node from configuration.
    pub fn init(config: NodeConfig) -> Result<Self, DomError> {
        info!("Initializing DOM node ({:?} network)", config.network);
        info!("Data directory: {}", config.data_dir);

        // Open storage
        let data_path = Path::new(&config.data_dir);
        let store = DomStore::open(data_path)?;

        // Canonical genesis hash for this network.
        let genesis_hash = Hash256::from_bytes(match config.network {
            dom_config::Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
            dom_config::Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        });

        // Initialize chain state
        let chain = ChainState::open(store, genesis_hash, config.network.magic())?;
        info!("Chain tip: height={}", chain.tip_height);

        // Generate or load Noise keypair
        let (noise_privkey, noise_pubkey) = dom_wire::handshake::generate_static_keypair();
        info!("Node identity: {}", hex::encode(noise_pubkey));

        let (block_relay_tx, _) = tokio::sync::broadcast::channel(64);
        let (tx_fluff_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);
        let (tx_stem_tx, _) = tokio::sync::broadcast::channel::<dom_wire::dandelion::StemEnvelope>(256);

        // Load or create wallet if configured
        let wallet = if let (Some(wallet_path), Some(wallet_password)) = 
            (&config.wallet_path, &config.wallet_password)
        {
            use crate::wallet_helpers::wallet_network_from_config;
            let wallet_net = wallet_network_from_config(config.network);
            let path = Path::new(wallet_path);
            
            match Wallet::open(path, wallet_password) {
                Ok(w) => {
                    info!("Wallet loaded from {:?}", path);
                    Some(Arc::new(Mutex::new(w)))
                }
                Err(_) => {
                    // Create new wallet if doesn't exist
                    match Wallet::create(path, wallet_password, wallet_net, &genesis_hash) {
                        Ok(w) => {
                            info!("New wallet created at {:?}", path);
                            Some(Arc::new(Mutex::new(w)))
                        }
                        Err(e) => {
                            warn!("Failed to create wallet: {:?}. Mining without wallet (DOM-SEC-004 unresolved).", e);
                            None
                        }
                    }
                }
            }
        } else {
            None
        };

        // NTP health check (Doc 4.5 mitigation 2)
        let metrics = Arc::new(Metrics::new());
        match check_clock_health() {
            Ok(DriftStatus::Critical { drift_secs }) => {
                warn!(
                    "CLOCK DRIFT CRITICAL: {}s — mining disabled until clock is synchronized",
                    drift_secs
                );
                // Disable mining if drift is critical
                // config.mine = false; // config is not mut here — logged as warning
            }
            Ok(DriftStatus::Warning { drift_secs }) => {
                warn!("Clock drift warning: {}s — consider synchronizing NTP", drift_secs);
            }
            Ok(DriftStatus::Healthy { drift_secs }) => {
                info!("Clock health OK: drift={}s", drift_secs);
            }
            Ok(DriftStatus::Unknown) => {
                warn!("Clock health unknown — NTP servers unreachable");
            }
            Err(e) => {
                warn!("Clock health check failed: {}", e);
            }
        }

        Ok(Self {
            noise_privkey,
            block_relay_tx,
            tx_fluff_tx,
            tx_stem_tx,
            config: config.clone(),
            chain: Arc::new(Mutex::new(chain)),
            mempool: Arc::new(Mutex::new(Mempool::new())),
            peers: Arc::new(Mutex::new(PeerManager::new(
                config.max_inbound,
                config.min_outbound,
            ))),
            dandelion: Arc::new(Mutex::new(DandelionRouter::new())),
            wallet,
            metrics,
            future_block_queue: Arc::new(crate::future_block_queue::FutureBlockQueue::new()),
        })
    }

    /// Start all node services.
    pub async fn run(self: Arc<Self>) -> Result<(), DomError> {
        info!("Starting DOM node services");

        // Start P2P listener
        let p2p_addr = self.config.p2p_listen_addr.clone();
        let node_listener = self.clone();
        let listener_task = tokio::spawn(async move {
            if let Err(e) = node_listener.run_p2p_listener(&p2p_addr).await {
                warn!("P2P listener error: {e}");
            }
        });

        // Start outbound peer connector
        let node_connector = self.clone();
        let connector_task = tokio::spawn(async move {
            node_connector.run_peer_connector().await;
        });

        // Start miner if enabled
        if self.config.mine {
            let node_miner = self.clone();
            tokio::spawn(async move {
                mining_loop(node_miner).await;
            });
        }

        // Start RPC server if configured
        if let Some(rpc_addr) = self.config.rpc_listen_addr.clone() {
            use crate::node_handle::NodeHandleImpl;
            let handle: Arc<dyn dom_rpc::NodeHandle> = Arc::new(NodeHandleImpl(self.clone()));
            tokio::spawn(async move {
                let addr: std::net::SocketAddr = match rpc_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("Invalid RPC listen addr {rpc_addr}: {e}");
                        return;
                    }
                };
                info!("RPC server listening on {addr}");
                if let Err(e) = dom_rpc::serve(handle, addr).await {
                    warn!("RPC server error: {e}");
                }
            });
        }

        // future_block_queue drain loop — re-evaluate deferred blocks every 30s
        {
            let queue = self.future_block_queue.clone();
            let chain = self.chain.clone();
            let relay_tx = self.block_relay_tx.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(
                    tokio::time::Duration::from_secs(30)
                );
                loop {
                    interval.tick().await;
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let now = dom_core::Timestamp(now_secs);
                    let ready = queue.drain_ready(now_secs, dom_core::FUTURE_BLOCK_SOFT_BUFFER_SECS).await;
                    for deferred in ready {
                        tracing::debug!(
                            "Re-evaluating deferred block ts={}",
                            deferred.timestamp
                        );
                        use dom_serialization::DomDeserialize;
                        match dom_consensus::Block::from_bytes(&deferred.block_bytes) {
                            Ok(block) => {
                                let result = {
                                    let mut c = chain.lock().await;
                                    c.connect_block(&block, now)
                                };
                                match result {
                                    Ok(dom_chain::ConnectResult::BestChain) => {
                                        tracing::info!(
                                            "Accepted deferred block ts={} (new tip)",
                                            deferred.timestamp
                                        );
                                        let _ = relay_tx.send(deferred.block_bytes);
                                    }
                                    Ok(dom_chain::ConnectResult::SideChain) => {
                                        tracing::debug!(
                                            "Accepted deferred block ts={} (side chain — no rebroadcast)",
                                            deferred.timestamp
                                        );
                                    }
                                    Ok(dom_chain::ConnectResult::AlreadyHave) => {
                                        tracing::trace!(
                                            "Deferred block ts={} already known — no-op",
                                            deferred.timestamp
                                        );
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "Deferred block still rejected: {e}"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Deferred block decode error: {e}");
                            }
                        }
                    }
                }
            });
        }
        // Dandelion++ Stem-timeout promoter.
        //
        // Every STEM_CHECK_INTERVAL, walk the router and pull out any tx whose
        // stem timer expired. For each, re-look up the tx_bytes in the local
        // mempool, re-serialize them, and broadcast over the Fluff channel so
        // every peer receives the tx and the propagation completes.
        //
        // Without this task, a tx that entered Stem phase but whose target
        // peer disconnected would stay forever in the local stem map and
        // never reach the rest of the network — a privacy guarantee turned
        // into a liveness bug.
        {
            let dandelion = self.dandelion.clone();
            let mempool = self.mempool.clone();
            let tx_fluff_tx = self.tx_fluff_tx.clone();
            tokio::spawn(async move {
                const STEM_CHECK_INTERVAL_SECS: u64 = 5;
                let mut interval = tokio::time::interval(
                    tokio::time::Duration::from_secs(STEM_CHECK_INTERVAL_SECS)
                );
                interval.tick().await; // skip first immediate tick
                loop {
                    interval.tick().await;
                    let timed_out: Vec<[u8; 32]> = {
                        let mut d = dandelion.lock().await;
                        d.collect_timed_out()
                    };
                    if timed_out.is_empty() {
                        continue;
                    }
                    tracing::debug!(
                        "Dandelion: promoting {} stem-timed-out tx(s) to fluff",
                        timed_out.len()
                    );
                    use dom_serialization::DomSerialize;
                    for tx_hash in timed_out {
                        let tx_bytes_opt = {
                            let m = mempool.lock().await;
                            m.get_tx(&tx_hash).and_then(|e| e.tx.to_bytes().ok())
                        };
                        if let Some(tx_bytes) = tx_bytes_opt {
                            let _ = tx_fluff_tx.send(tx_bytes);
                        } else {
                            tracing::debug!(
                                "Stem-timed-out tx {} not in mempool; dropping",
                                hex::encode(tx_hash)
                            );
                        }
                    }
                }
            });
        }

        // Wait for tasks
        tokio::select! {
            _ = listener_task => warn!("P2P listener exited"),
            _ = connector_task => warn!("Peer connector exited"),
        }

        Ok(())
    }

    /// Listen for incoming P2P connections.
    async fn run_p2p_listener(&self, addr: &str) -> Result<(), DomError> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| DomError::Internal(format!("bind {addr}: {e}")))?;
        info!("P2P listening on {addr}");

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    info!("Inbound connection from {peer_addr}");
                    let can_accept = {
                        let mgr = self.peers.lock().await;
                        mgr.can_accept_inbound(peer_addr.ip())
                    };
                    if !can_accept {
                        warn!("Rejecting connection from {peer_addr}: peer limit or subnet limit");
                        continue;
                    }
                    // Spawn connection handler
                    let config = self.config.clone();
                    let privkey = self.noise_privkey;
                    let chain = self.chain.clone();
                    let channels = BroadcastChannels {
                        block_relay_tx: self.block_relay_tx.clone(),
                        tx_fluff_tx: self.tx_fluff_tx.clone(),
                        tx_stem_tx: self.tx_stem_tx.clone(),
                    };
                    let svc = NodeServices { mempool: self.mempool.clone(), dandelion: self.dandelion.clone(), peers: self.peers.clone(), wallet: self.wallet.clone() };
                    tokio::spawn(async move {
                        handle_inbound(stream, peer_addr, config, privkey, chain, channels, svc)
                            .await;
                    });
                }
                Err(e) => {
                    warn!("Accept error: {e}");
                }
            }
        }
    }

    /// Connect to peers (DNS seeds + configured peers).
    async fn run_peer_connector(&self) {
        let svc = NodeServices { mempool: self.mempool.clone(), dandelion: self.dandelion.clone(), peers: self.peers.clone(), wallet: self.wallet.clone() };
        loop {
            let needs_more = {
                let mgr = self.peers.lock().await;
                mgr.needs_outbound()
            };

            if needs_more {
                let is_mainnet = self.config.network == dom_config::Network::Mainnet;
                let port = self.config.network.default_port();
                let mut addrs =
                    dom_wire::dns_seed::resolve_seeds(is_mainnet, port, &self.config.dns_seeds)
                        .await;

                // Also try configured seed peers
                addrs.extend(self.config.seed_peers.iter().cloned());

                for addr in addrs {
                    let already_connected = {
                        let mgr = self.peers.lock().await;
                        mgr.peers.contains_key(&addr)
                    };
                    if already_connected {
                        continue;
                    }

                    let config = self.config.clone();
                    let privkey = self.noise_privkey;
                    let chain = self.chain.clone();
                    let channels = BroadcastChannels {
                        block_relay_tx: self.block_relay_tx.clone(),
                        tx_fluff_tx: self.tx_fluff_tx.clone(),
                        tx_stem_tx: self.tx_stem_tx.clone(),
                    };
                    info!("Connecting to peer {addr}");
                    let svc_c = svc.clone();
                    tokio::spawn(async move {
                        connect_outbound(&addr, config, privkey, chain, channels, svc_c).await;
                    });
                }
            }

            // Check every 30 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    }
}

impl dom_rpc::NodeHandle for DomNode {
    fn chain_height(&self) -> u64 {
        self.chain.try_lock().map(|c| c.tip_height.0).unwrap_or(0)
    }

    fn mempool_size(&self) -> usize {
        self.mempool.try_lock().map(|m| m.len()).unwrap_or(0)
    }

    fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
        self.mempool
            .try_lock()
            .map(|m| m.all_hashes())
            .unwrap_or_default()
    }

    fn get_mempool_tx(&self, hash: &[u8; 32]) -> Option<dom_rpc::MempoolTxInfo> {
        let pool = self.mempool.try_lock().ok()?;
        let entry = pool.get_tx(hash)?;
        let fee = entry.tx.total_fee().ok()?;
        let weight = entry.tx.weight();
        Some(dom_rpc::MempoolTxInfo {
            tx_hash: *hash,
            fee,
            fee_rate: if weight > 0 { fee / weight as u64 } else { 0 },
            weight,
        })
    }

    fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<[u8; 32], dom_rpc::RpcError> {
        use dom_serialization::DomDeserialize;
        let tx = dom_consensus::Transaction::from_bytes(&tx_bytes)
            .map_err(|e| dom_rpc::RpcError::InvalidHex(format!("invalid tx: {e}")))?;
        let hash = {
            let data = tx_bytes.clone();
            *dom_crypto::hash::blake2b_256(&data).as_bytes()
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut pool = self
            .mempool
            .try_lock()
            .map_err(|_| dom_rpc::RpcError::Internal("mempool locked".into()))?;
        pool.accept_tx(tx, hash, now)
            .map_err(|e| dom_rpc::RpcError::Rejected(e.to_string()))?;
        Ok(hash)
    }

    fn get_block_header(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let chain = self.chain.try_lock().ok()?;
        chain.store.get_block_header(hash).ok()?
    }

    fn get_block_hash_at_height(&self, height: u64) -> Option<[u8; 32]> {
        let chain = self.chain.try_lock().ok()?;
        chain.store.get_hash_at_height(height).ok()?
    }

    fn get_utxo(&self, commitment: &[u8; 33]) -> Option<dom_rpc::UtxoInfo> {
        let chain = self.chain.try_lock().ok()?;
        let tip_height = chain.tip_height.0;
        let entry = chain.store.get_utxo(commitment).ok()??;
        Some(dom_rpc::UtxoInfo {
            commitment: hex::encode(commitment),
            block_height: entry.block_height,
            is_coinbase: entry.is_coinbase,
            is_mature: entry.is_mature(tip_height),
        })
    }

    fn get_peers(&self) -> Vec<dom_rpc::PeerInfo> {
        let Ok(peers) = self.peers.try_lock() else {
            return Vec::new();
        };
        peers
            .connected_peers()
            .into_iter()
            .map(|addr| dom_rpc::PeerInfo {
                addr,
                direction: "inbound".into(),
                connected_since: 0,
            })
            .collect()
    }
}

async fn handle_inbound(
    mut stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    config: NodeConfig,
    privkey: [u8; 32],
    chain: Arc<Mutex<ChainState>>,
    channels: BroadcastChannels,
    svc: NodeServices,
) {
    let BroadcastChannels { block_relay_tx, tx_fluff_tx, tx_stem_tx } = channels.clone();
    // Derive chain_id from network magic + canonical genesis hash.
    let genesis_hash = match config.network {
        dom_config::Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        dom_config::Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
    };
    let chain_id =
        *derive_chain_id(config.network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes();
    let transport = match dom_wire::handshake::perform_handshake_responder(
        &mut stream,
        &privkey,
        config.network.magic(),
        &chain_id,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            warn!("Handshake failed with {addr}: {e}");
            return;
        }
    };
    info!("Noise handshake complete with {addr}");

    let mut codec = dom_wire::codec::NoiseCodec::new(transport, config.network.magic());
    match hello_exchange(&mut stream, &mut codec, &config, &chain_id, &chain).await {
        Ok(peer_hello) => {
            info!(
                "Hello from {addr}: height={} ua={:?}",
                peer_hello.best_height, peer_hello.user_agent
            );
            // Register peer in manager so connected_peers() sees it
            {
                use dom_wire::peer::PeerInfo;
                let mut peer_info = PeerInfo::new(addr, false);
                peer_info.state = dom_wire::peer::PeerState::Connected;
                peer_info.best_height = peer_hello.best_height;
                peer_info.best_hash = peer_hello.best_hash;
                peer_info.user_agent = peer_hello.user_agent.clone();
                let result = svc.peers.lock().await.register_peer(peer_info);
                info!("register_peer inbound {addr} → {result:?}");
                if let Err(e) = result {
                    warn!("Failed to register inbound peer {addr}: {e}");
                }
            }
            // IBD loop: if the inbound peer claims a higher chain, sync from it.
            // Mirrors connect_outbound logic so inbound-only nodes (behind NAT
            // who can only accept connections) still converge to the network's
            // tip instead of remaining stuck at a stale height.
            let our_height = chain.lock().await.tip_height.0;
            if peer_hello.best_height > our_height {
                info!(
                    "Starting IBD from {addr}: our={our_height} peer={}",
                    peer_hello.best_height
                );
                loop {
                    match ibd_sync_round(&mut stream, &mut codec, &config, &chain, addr, svc.wallet.clone()).await
                    {
                        Ok(true) => continue,
                        Ok(false) => {
                            info!("IBD with {addr} caught up");
                            break;
                        }
                        Err(e) => {
                            warn!("IBD with {addr} failed: {e}");
                            return;
                        }
                    }
                }
            }
            if let Err(e) = message_loop(
                PeerConn { stream: &mut stream, codec: &mut codec },
                &config,
                addr,
                chain.clone(),
                BroadcastChannels {
                    block_relay_tx: block_relay_tx.clone(),
                    tx_fluff_tx: tx_fluff_tx.clone(),
                    tx_stem_tx: tx_stem_tx.clone(),
                },
                svc.clone(),
            )
            .await
            {
                info!("Connection to {addr} closed: {e}");
            }
        }
        Err(e) => warn!("Hello exchange with {addr} failed: {e}"),
    }
}

async fn connect_outbound(
    addr: &str,
    config: NodeConfig,
    privkey: [u8; 32],
    chain: Arc<Mutex<ChainState>>,
    channels: BroadcastChannels,
    svc: NodeServices,
) {
    let BroadcastChannels { block_relay_tx, tx_fluff_tx, tx_stem_tx } = channels.clone();
    let mut stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Connection to {addr} failed: {e}");
            return;
        }
    };
    let genesis_hash = match config.network {
        dom_config::Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        dom_config::Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
    };
    let chain_id =
        *derive_chain_id(config.network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes();
    let transport = match dom_wire::handshake::perform_handshake_initiator(
        &mut stream,
        &privkey,
        config.network.magic(),
        &chain_id,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            warn!("Handshake failed with {addr}: {e}");
            return;
        }
    };
    info!("Connected to {addr}");

    let mut codec = dom_wire::codec::NoiseCodec::new(transport, config.network.magic());
    match hello_exchange(&mut stream, &mut codec, &config, &chain_id, &chain).await {
        Ok(peer_hello) => {
            info!(
                "Hello from {addr}: height={} ua={:?}",
                peer_hello.best_height, peer_hello.user_agent
            );
            // Register peer in manager so connected_peers() sees it
            {
                use dom_wire::peer::PeerInfo;
                let sock_addr: std::net::SocketAddr = match addr.parse() {
                    Ok(a) => a,
                    Err(_) => match stream.peer_addr() {
                        Ok(a) => a,
                        Err(e) => {
                            warn!("Cannot determine addr for register_peer: {e}");
                            return;
                        }
                    },
                };
                let mut peer_info = PeerInfo::new(sock_addr, true);
                peer_info.state = dom_wire::peer::PeerState::Connected;
                peer_info.best_height = peer_hello.best_height;
                peer_info.best_hash = peer_hello.best_hash;
                peer_info.user_agent = peer_hello.user_agent.clone();
                let result = svc.peers.lock().await.register_peer(peer_info);
                info!("register_peer outbound {addr} → {result:?}");
                if let Err(e) = result {
                    warn!("Failed to register outbound peer {addr}: {e}");
                }
            }
            let peer_addr = match stream.peer_addr() {
                Ok(a) => a,
                Err(_) => {
                    warn!("Could not resolve peer_addr for {addr}");
                    return;
                }
            };

            // IBD loop: keep syncing while peer claims to be ahead.
            // Each ibd_sync_round returns false when the peer has nothing new.
            let our_height = chain.lock().await.tip_height.0;
            if peer_hello.best_height > our_height {
                info!(
                    "Starting IBD from {addr}: our={our_height} peer={}",
                    peer_hello.best_height
                );
                loop {
                    match ibd_sync_round(&mut stream, &mut codec, &config, &chain, peer_addr, svc.wallet.clone()).await
                    {
                        Ok(true) => continue,
                        Ok(false) => {
                            info!("IBD with {addr} caught up");
                            break;
                        }
                        Err(e) => {
                            warn!("IBD with {addr} failed: {e}");
                            return;
                        }
                    }
                }
            }

            if let Err(e) = message_loop(
                PeerConn { stream: &mut stream, codec: &mut codec },
                &config,
                peer_addr,
                chain.clone(),
                BroadcastChannels {
                    block_relay_tx: block_relay_tx.clone(),
                    tx_fluff_tx: tx_fluff_tx.clone(),
                    tx_stem_tx: tx_stem_tx.clone(),
                },
                svc.clone(),
            )
            .await
            {
                info!("Connection to {addr} closed: {e}");
            }
        }
        Err(e) => warn!("Hello exchange with {addr} failed: {e}"),
    }
}

/// Perform the Hello message exchange after the Noise handshake completes.
///
/// Sends our Hello with our current tip, receives theirs, and validates:
/// - protocol version matches
/// - network_magic matches
/// - chain_id matches (same network, same genesis)
///
/// Returns the peer's HelloPayload on success.
async fn hello_exchange(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    config: &NodeConfig,
    chain_id: &[u8; 32],
    chain: &Arc<Mutex<ChainState>>,
) -> Result<dom_wire::message::HelloPayload, DomError> {
    use dom_wire::message::{Command, HelloPayload, WireMessage};

    // Snapshot our tip under the lock.
    let (best_height, best_hash) = {
        let c = chain.lock().await;
        (c.tip_height.0, *c.tip_hash.as_bytes())
    };

    let our_hello = HelloPayload {
        version: dom_core::PROTOCOL_VERSION,
        network_magic: config.network.magic(),
        chain_id: *chain_id,
        best_height,
        best_hash,
        user_agent: format!("dom-node/{}", env!("CARGO_PKG_VERSION")),
        local_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let msg = WireMessage {
        magic: config.network.magic(),
        command: Command::Hello,
        payload: our_hello.to_bytes()?,
    };
    codec.send(stream, &msg).await?;

    let peer_msg = codec.recv(stream).await?;
    if peer_msg.command != Command::Hello {
        return Err(DomError::Invalid(format!(
            "expected Hello, got {:?}",
            peer_msg.command
        )));
    }
    let peer_hello = HelloPayload::from_bytes(&peer_msg.payload)?;

    if peer_hello.version != dom_core::PROTOCOL_VERSION {
        return Err(DomError::Invalid(format!(
            "protocol version mismatch: ours={} theirs={}",
            dom_core::PROTOCOL_VERSION,
            peer_hello.version
        )));
    }
    if peer_hello.network_magic != config.network.magic() {
        return Err(DomError::Invalid(format!(
            "network_magic mismatch: ours=0x{:08x} theirs=0x{:08x}",
            config.network.magic(),
            peer_hello.network_magic
        )));
    }
    if peer_hello.chain_id != *chain_id {
        return Err(DomError::Invalid("chain_id mismatch".into()));
    }

    // Peer time discipline evaluation (Doc 4.5 mitigation 3)
    let our_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Note: scorer not available here — log drift for now
    // Full integration requires passing scorer or metrics into hello_exchange
    let drift = (our_ts as i64 - peer_hello.local_timestamp as i64).abs();
    if drift > dom_core::PEER_DRIFT_DISCONNECT_SECS {
        return Err(DomError::Invalid(format!(
            "peer clock drift too large: {}s (limit {}s)",
            drift, dom_core::PEER_DRIFT_DISCONNECT_SECS
        )));
    }
    if drift > dom_core::PEER_DRIFT_WARN_SECS {
        warn!("Peer clock drift warning: {}s for peer at exchange", drift);
    }

    Ok(peer_hello)
}

/// Persistent message loop after Hello exchange.
///
/// Reads framed messages from the peer in a loop and dispatches by command:
/// - Ping: reply with Pong echoing the payload
/// - Pong: ignored (could update last-seen for liveness tracking)
/// - Other commands: logged and ignored (IBD/relay handled in Phase 3)
///
/// Sends a Ping every `PING_INTERVAL_SECS` to detect dead peers.
/// Exits on any I/O error or idle timeout (NoiseCodec::recv enforces it).
/// Build a sparse block locator (newest tip first, exponentially-spaced).
///
/// Format: [tip, tip-1, tip-2, tip-4, tip-8, tip-16, ..., genesis].
/// This lets the peer find the common ancestor in O(log n) headers.
async fn build_locator(chain: &Arc<Mutex<ChainState>>) -> Result<Vec<[u8; 32]>, DomError> {
    let c = chain.lock().await;
    let tip_height = c.tip_height.0;
    let mut out: Vec<[u8; 32]> = Vec::new();
    let mut step: u64 = 1;
    let mut h: i64 = tip_height as i64;
    while h >= 0 && out.len() < dom_core::MAX_LOCATOR_HASHES {
        if let Some(hash) = c.store.get_hash_at_height(h as u64)? {
            out.push(hash);
        }
        if out.len() >= 10 {
            step = step.saturating_mul(2);
        }
        h -= step as i64;
    }
    Ok(out)
}

/// Run a single IBD sync round against one peer.
///
/// Sends GetHeaders, receives headers, requests bodies in batches, and connects
/// each block via ChainState::connect_block. Returns Ok(true) if any progress
/// was made (at least one block accepted), Ok(false) if peer had nothing new.
async fn ibd_sync_round(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    config: &NodeConfig,
    chain: &Arc<Mutex<ChainState>>,
    peer_addr: std::net::SocketAddr,
    wallet: Option<Arc<Mutex<dom_wallet::Wallet>>>,
) -> Result<bool, DomError> {
    use dom_consensus::Block;
    use dom_serialization::DomDeserialize;
    use dom_wire::message::{
        BlockPayload, Command, GetBlockDataPayload, GetHeadersPayload, HeadersPayload, WireMessage,
    };

    // 1. Request headers from peer using our locator.
    let locator = build_locator(chain).await?;
    let req = GetHeadersPayload {
        locator_hashes: locator,
        stop_hash: [0u8; 32],
    };
    let wire = WireMessage {
        magic: config.network.magic(),
        command: Command::GetHeaders,
        payload: req.to_bytes()?,
    };
    codec.send(stream, &wire).await?;

    // 2. Receive Headers (skip non-Headers messages).
    let headers_msg = loop {
        let msg = codec.recv(stream).await?;
        match msg.command {
            Command::Headers => break msg,
            Command::Ping => {
                let pong = WireMessage {
                    magic: config.network.magic(),
                    command: Command::Pong,
                    payload: msg.payload,
                };
                codec.send(stream, &pong).await?;
            }
            Command::Pong => {}
            other => {
                tracing::debug!("IBD: ignoring {other:?} while waiting for Headers");
            }
        }
    };
    let headers_payload = HeadersPayload::from_bytes(&headers_msg.payload)?;
    if headers_payload.headers.is_empty() {
        return Ok(false); // peer has nothing new for us
    }

    // 3. Compute block hashes from headers, then filter out blocks we already
    // have. Without this filter, a peer that resends the same headers (either
    // maliciously or due to a relay loop) would cause us to re-download bodies
    // for blocks already in our store — wasting bandwidth and IBD time.
    //
    // DOM-IBD-DUP-001 fix (2026-05-23): pre-filter before batched body request.
    // The chain_state::connect_block early-return (ab82f89) still catches any
    // duplicates that slip through, but filtering here avoids the network
    // round-trip entirely.
    let mut block_hashes: Vec<[u8; 32]> = Vec::with_capacity(headers_payload.headers.len());
    {
        let c = chain.lock().await;
        for h_bytes in &headers_payload.headers {
            let hash = *dom_crypto::hash::blake2b_256(h_bytes).as_bytes();
            // Skip blocks already in our store — peer may have sent them
            // redundantly (relay loop, malicious replay, or honest overlap).
            match c.store.get_block_header(&hash) {
                Ok(Some(_)) => {
                    tracing::trace!(
                        "IBD: skipping already-known block hash {}",
                        hex::encode(&hash[..4])
                    );
                    continue;
                }
                Ok(None) => block_hashes.push(hash),
                Err(e) => {
                    tracing::warn!("IBD: store lookup error for header hash: {e}");
                    // Be defensive — include the hash, connect_block will catch
                    // any real duplicates via its own early-return.
                    block_hashes.push(hash);
                }
            }
        }
    }

    if block_hashes.is_empty() {
        tracing::debug!(
            "IBD: peer sent {} headers but all are already in our store — no bodies to fetch",
            headers_payload.headers.len()
        );
        return Ok(false);
    }

    let mut connected_any = false;
    let now = Timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );

    for batch in block_hashes.chunks(dom_core::MAX_GETBLOCKDATA_HASHES) {
        let req = GetBlockDataPayload {
            hashes: batch.to_vec(),
        };
        let wire = WireMessage {
            magic: config.network.magic(),
            command: Command::GetBlockData,
            payload: req.to_bytes()?,
        };
        codec.send(stream, &wire).await?;

        // Receive one Block per requested hash, in order.
        for _ in 0..batch.len() {
            let msg = loop {
                let m = codec.recv(stream).await?;
                match m.command {
                    Command::Block => break m,
                    Command::Ping => {
                        let pong = WireMessage {
                            magic: config.network.magic(),
                            command: Command::Pong,
                            payload: m.payload,
                        };
                        codec.send(stream, &pong).await?;
                    }
                    Command::Pong => {}
                    other => {
                        tracing::debug!("IBD: ignoring {other:?} while waiting for Block");
                    }
                }
            };
            let payload = BlockPayload::from_bytes(&msg.payload)?;
            let block = Block::from_bytes(&payload.block_bytes)?;
            let height = block.header.height.0;
            let txs_for_scan = block.transactions.clone();
            {
                let mut c = chain.lock().await;
                match c.connect_block(&block, now) {
                    Ok(dom_chain::ConnectResult::BestChain)
                    | Ok(dom_chain::ConnectResult::SideChain) => {
                        connected_any = true;
                    }
                    Ok(dom_chain::ConnectResult::AlreadyHave) => {
                        // Peer sent us a block we already have. Unusual during
                        // IBD but not an error — count as progress to avoid
                        // stalling the download loop.
                        tracing::debug!(
                            "IBD from {peer_addr}: block already known at height {}",
                            height
                        );
                        connected_any = true;
                    }
                    Err(e) => {
                        return Err(DomError::Invalid(format!(
                            "IBD from {peer_addr}: connect_block rejected: {e}"
                        )));
                    }
                }
            }
            // Scan block for wallet outputs (IBD path).
            if let Some(ref wallet_arc) = wallet {
                let mut w = wallet_arc.lock().await;
                w.scan_block(&txs_for_scan, height);
            }
        }
    }

    Ok(connected_any)
}

/// Build a Headers response for a GetHeaders request.
///
/// Finds the most recent locator hash on our main chain, then returns up to
/// MAX_HEADERS_PER_MSG headers forward from there, stopping at stop_hash or tip.
async fn build_headers_response(
    chain: &Arc<Mutex<ChainState>>,
    req: &dom_wire::message::GetHeadersPayload,
) -> Result<Vec<Vec<u8>>, DomError> {
    use dom_serialization::DomDeserialize;
    let c = chain.lock().await;
    let tip_height = c.tip_height.0;

    let mut start_height: u64 = 0;
    for h in &req.locator_hashes {
        if let Some(header_bytes) = c.store.get_block_header(h)? {
            let header = dom_consensus::block::BlockHeader::from_bytes(&header_bytes)?;
            if c.store.get_hash_at_height(header.height.0)? == Some(*h) {
                start_height = header.height.0 + 1;
                break;
            }
        }
    }

    let max = dom_core::MAX_HEADERS_PER_MSG;
    let stop_is_zero = req.stop_hash == [0u8; 32];
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(max);
    let mut h = start_height;
    while h <= tip_height && out.len() < max {
        let hash = match c.store.get_hash_at_height(h)? {
            Some(x) => x,
            None => break,
        };
        let bytes = match c.store.get_block_header(&hash)? {
            Some(b) => b,
            None => break,
        };
        out.push(bytes);
        if !stop_is_zero && hash == req.stop_hash {
            break;
        }
        h += 1;
    }
    Ok(out)
}

async fn message_loop(
    conn: PeerConn<'_>,
    config: &NodeConfig,
    peer_addr: std::net::SocketAddr,
    chain: Arc<Mutex<ChainState>>,
    channels: BroadcastChannels,
    svc: NodeServices,
) -> Result<(), DomError> {
    // Subscribe to all broadcast channels for this peer connection.
    let mut block_relay_rx = channels.block_relay_tx.subscribe();
    let block_relay_tx = channels.block_relay_tx.clone();
    let mut tx_fluff_rx = channels.tx_fluff_tx.subscribe();
    let tx_fluff_tx = channels.tx_fluff_tx.clone();
    let mut tx_stem_rx = channels.tx_stem_tx.subscribe();
    let tx_stem_tx = channels.tx_stem_tx.clone();
    let PeerConn { stream, codec } = conn;
    use dom_wire::message::{
        BlockPayload, Command, GetBlockDataPayload, GetHeadersPayload, HeadersPayload, WireMessage,
    };

    const PING_INTERVAL_SECS: u64 = 30;
    let mut ping_timer =
        tokio::time::interval(tokio::time::Duration::from_secs(PING_INTERVAL_SECS));
    // Skip the immediate first tick.
    ping_timer.tick().await;

    loop {
        tokio::select! {
            // Relay broadcast: someone (miner or another peer task) wants to send a Block
            relay = block_relay_rx.recv() => {
                match relay {
                    Ok(block_bytes) => {
                        let payload = BlockPayload { block_bytes };
                        let msg = WireMessage {
                            magic: config.network.magic(),
                            command: Command::Block,
                            payload: payload.to_bytes()?,
                        };
                        if let Err(e) = codec.send(stream, &msg).await {
                            return Err(DomError::Internal(format!("relay send to {peer_addr}: {e}")));
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("relay lagged by {n} for {peer_addr}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(DomError::Internal("relay channel closed".into()));
                    }
                }
            }
            // Dandelion++ Fluff: a transaction we want to broadcast to every peer.
            // Each connected peer task receives every Fluff envelope and forwards it.
            fluff = tx_fluff_rx.recv() => {
                match fluff {
                    Ok(tx_bytes) => {
                        let msg = WireMessage {
                            magic: config.network.magic(),
                            command: Command::Tx,
                            payload: tx_bytes,
                        };
                        if let Err(e) = codec.send(stream, &msg).await {
                            return Err(DomError::Internal(format!("fluff send to {peer_addr}: {e}")));
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("tx_fluff lagged by {n} for {peer_addr}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(DomError::Internal("tx_fluff channel closed".into()));
                    }
                }
            }
            // Dandelion++ Stem: a transaction to be forwarded to ONE specific peer.
            // Every peer task receives the envelope, but only the task whose
            // peer_addr matches StemEnvelope.target_peer actually sends. This
            // preserves source-anonymity per the Dandelion++ paper.
            stem = tx_stem_rx.recv() => {
                match stem {
                    Ok(env) => {
                        if env.target_peer == peer_addr {
                            let msg = WireMessage {
                                magic: config.network.magic(),
                                command: Command::Tx,
                                payload: env.tx_bytes,
                            };
                            if let Err(e) = codec.send(stream, &msg).await {
                                return Err(DomError::Internal(format!("stem send to {peer_addr}: {e}")));
                            }
                        }
                        // else: this envelope is targeted at a different peer; ignore
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("tx_stem lagged by {n} for {peer_addr}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(DomError::Internal("tx_stem channel closed".into()));
                    }
                }
            }
            // Periodic ping
            _ = ping_timer.tick() => {
                let nonce: [u8; 8] = rand::random();
                let ping = WireMessage {
                    magic: config.network.magic(),
                    command: Command::Ping,
                    payload: nonce.to_vec(),
                };
                if let Err(e) = codec.send(stream, &ping).await {
                    return Err(DomError::Internal(format!("ping send to {peer_addr}: {e}")));
                }
            }
            // Inbound message
            recv = codec.recv(stream) => {
                let msg = recv?;
                match msg.command {
                    Command::Ping => {
                        // Echo payload as Pong
                        let pong = WireMessage {
                            magic: config.network.magic(),
                            command: Command::Pong,
                            payload: msg.payload,
                        };
                        codec.send(stream, &pong).await?;
                    }
                    Command::Pong => {
                        // Liveness confirmed; nothing else to do until peer tracking added
                    }
                    Command::Hello => {
                        // Second Hello after handshake is a protocol violation
                        return Err(DomError::Invalid(
                            "unexpected Hello in message loop [ban+20]".into(),
                        ));
                    }
                    Command::GetHeaders => {
                        let req = GetHeadersPayload::from_bytes(&msg.payload)?;
                        let headers = build_headers_response(&chain, &req).await?;
                        let resp = HeadersPayload { headers };
                        let wire = WireMessage {
                            magic: config.network.magic(),
                            command: Command::Headers,
                            payload: resp.to_bytes()?,
                        };
                        codec.send(stream, &wire).await?;
                    }
                    Command::Block => {
                        // Peer relayed a block to us. Validate and accept.
                        use dom_serialization::DomDeserialize;
                        let payload = BlockPayload::from_bytes(&msg.payload)?;
                        let block = dom_consensus::Block::from_bytes(&payload.block_bytes)?;
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let now = dom_core::Timestamp(now_secs);

                        // Doc 4.5 mitigation 1: soft buffer for future blocks
                        use dom_consensus::block::{validate_future_timestamp_with_buffer, TimestampDecision};
                        match validate_future_timestamp_with_buffer(&block.header, now) {
                            Ok(TimestampDecision::Accept) => {
                                // Normal path: validate and connect
                                let height = block.header.height.0;
                                let txs_for_scan = block.transactions.clone();
                                let result = {
                                    let mut c = chain.lock().await;
                                    c.connect_block(&block, now)
                                };
                                match result {
                                    Ok(dom_chain::ConnectResult::BestChain) => {
                                        tracing::info!("Accepted relayed block from {peer_addr} (new tip)");
                                        // Scan block for wallet outputs (relay path).
                                        if let Some(ref wallet_arc) = svc.wallet {
                                            let mut w = wallet_arc.lock().await;
                                            w.scan_block(&txs_for_scan, height);
                                        }
                                        // DOM-SEC-RELAY-LOOP: only rebroadcast when we
                                        // actually extended the best chain. SideChain
                                        // and AlreadyHave MUST NOT rebroadcast — that
                                        // creates infinite relay loops between peers.
                                        let _ = block_relay_tx.send(payload.block_bytes);
                                    }
                                    Ok(dom_chain::ConnectResult::SideChain) => {
                                        tracing::debug!(
                                            "Accepted relayed block from {peer_addr} (side chain — no rebroadcast)"
                                        );
                                        // Scan side chain for wallet outputs in case the
                                        // side chain becomes best chain via later reorg.
                                        //
                                        // WARNING (audit 2026-05-23, ACHADO 3): wallet.scan_block
                                        // is currently a no-op placeholder. When real scan logic
                                        // is implemented, this branch MUST be revisited:
                                        //   - Naive scan would count side-chain UTXOs as if they
                                        //     were canonical, inflating balance and risking
                                        //     double-counting on reorg.
                                        //   - Proper handling: either (a) defer scan until the
                                        //     side chain wins via reorg, or (b) tag scanned
                                        //     outputs with their block hash and only count
                                        //     those whose ancestor is the canonical tip.
                                        // Also a DoS vector: peer can flood valid side blocks
                                        // to force repeated scans (DOM-SCAN-001 — rate-limit
                                        // planned in follow-up commit).
                                        if let Some(ref wallet_arc) = svc.wallet {
                                            let mut w = wallet_arc.lock().await;
                                            w.scan_block(&txs_for_scan, height);
                                        }
                                    }
                                    Ok(dom_chain::ConnectResult::AlreadyHave) => {
                                        tracing::trace!(
                                            "Block from {peer_addr} already known — no-op"
                                        );
                                    }
                                    Err(dom_core::DomError::Invalid(e)) => {
                                        tracing::warn!("Rejected block from {peer_addr}: {e}");
                                    }
                                    Err(e) => {
                                        tracing::debug!("Block from {peer_addr} not accepted: {e}");
                                    }
                                }
                            }
                            Ok(TimestampDecision::Defer) => {
                                // Soft buffer: hold for re-evaluation
                                tracing::debug!("Block from {peer_addr} deferred (future timestamp soft buffer)");
                                let deferred = crate::future_block_queue::DeferredBlock {
                                    block_hash: { let mut h = [0u8;32]; h[..8].copy_from_slice(&block.header.height.0.to_le_bytes()); h[8..16].copy_from_slice(&block.header.timestamp.0.to_le_bytes()); h },
                                    timestamp: block.header.timestamp.0,
                                    queued_at: std::time::Instant::now(),
                                    block_bytes: payload.block_bytes,
                                };
                                // future_block_queue not in scope here — log and skip
                                // Full integration requires passing queue into message_loop
                                tracing::debug!(
                                    "Deferred block ts={} now={} (queue not yet wired)",
                                    deferred.timestamp, now_secs
                                );
                            }
                            Err(e) => {
                                tracing::warn!("Block from {peer_addr} rejected by timestamp: {e}");
                            }
                        }
                    }
                    Command::Tx => {
                        // Relayed transaction from peer — payload IS the raw tx bytes
                        use dom_serialization::DomDeserialize;
                        use dom_consensus::Transaction;
                        let tx_bytes = msg.payload.clone();
                        match Transaction::from_bytes(&tx_bytes) {
                            Ok(tx) => {
                                let tx_hash = *dom_crypto::blake2b_256(&tx_bytes).as_bytes();
                                let now_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                let accepted = {
                                    let mut m = svc.mempool.lock().await;
                                    m.accept_tx(tx, tx_hash, now_secs).is_ok()
                                };
                                if accepted {
                                    tracing::debug!(
                                        "Accepted relayed tx {} from {peer_addr}",
                                        hex::encode(tx_hash)
                                    );
                                    // Dandelion++ re-route: decide Stem vs Fluff,
                                    // then dispatch the tx over the correct channel.
                                    let peer_list: Vec<std::net::SocketAddr> = if let Ok(p) = svc.peers.try_lock() {
                                        p.connected_peers()
                                            .into_iter()
                                            .filter_map(|s| s.parse().ok())
                                            .collect()
                                    } else {
                                        Vec::new()
                                    };
                                    let phase = {
                                        let mut d = svc.dandelion.lock().await;
                                        d.process_stem_tx(tx_hash, &peer_list, peer_addr)
                                    };
                                    use dom_wire::dandelion::{DandelionPhase, StemEnvelope};
                                    match phase {
                                        DandelionPhase::Fluff => {
                                            let _ = tx_fluff_tx.send(tx_bytes.clone());
                                        }
                                        DandelionPhase::Stem => {
                                            if let Some(target) = svc.dandelion.lock().await.get_stem_peer(&tx_hash) {
                                                let _ = tx_stem_tx.send(StemEnvelope {
                                                    target_peer: target,
                                                    tx_bytes: tx_bytes.clone(),
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::debug!("Invalid tx from {peer_addr}: {e}");
                            }
                        }
                    }
                    Command::GetBlockData => {
                        let req = GetBlockDataPayload::from_bytes(&msg.payload)?;
                        for hash in &req.hashes {
                            let body = {
                                let c = chain.lock().await;
                                c.store.get_block_body(hash)?
                            };
                            if let Some(bytes) = body {
                                let resp = BlockPayload { block_bytes: bytes };
                                let wire = WireMessage {
                                    magic: config.network.magic(),
                                    command: Command::Block,
                                    payload: resp.to_bytes()?,
                                };
                                codec.send(stream, &wire).await?;
                            }
                        }
                    }
                    other => {
                        tracing::debug!("ignoring {other:?} from {peer_addr}");
                    }
                }
            }
        }
    }
}

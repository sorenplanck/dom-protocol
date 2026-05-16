//! Full node orchestration.

use crate::miner::mining_loop;
use dom_chain::ChainState;
use dom_config::NodeConfig;
use dom_core::DomError;
use dom_core::Hash256;
use dom_mempool::Mempool;
use dom_store::DomStore;
use dom_wire::dandelion::DandelionRouter;
use dom_wire::manager::PeerManager;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

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
}

impl DomNode {
    /// Initialize the node from configuration.
    pub fn init(config: NodeConfig) -> Result<Self, DomError> {
        info!("Initializing DOM node ({:?} network)", config.network);
        info!("Data directory: {}", config.data_dir);

        // Open storage
        let data_path = Path::new(&config.data_dir);
        let store = DomStore::open(data_path)?;

        // Genesis hash — placeholder until RFC-0006 finalizes
        let genesis_hash = Hash256::ZERO;

        // Initialize chain state
        let chain = ChainState::open(store, genesis_hash)?;
        info!("Chain tip: height={}", chain.tip_height);

        // Generate or load Noise keypair
        let (noise_privkey, noise_pubkey) = dom_wire::handshake::generate_static_keypair();
        info!("Node identity: {}", hex::encode(noise_pubkey));

        Ok(Self {
            noise_privkey,
            config: config.clone(),
            chain: Arc::new(Mutex::new(chain)),
            mempool: Arc::new(Mutex::new(Mempool::new())),
            peers: Arc::new(Mutex::new(PeerManager::new(
                config.max_inbound,
                config.min_outbound,
            ))),
            dandelion: Arc::new(Mutex::new(DandelionRouter::new())),
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
                    tokio::spawn(async move {
                        handle_inbound(stream, peer_addr, config, privkey).await;
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
                    info!("Connecting to peer {addr}");
                    tokio::spawn(async move {
                        connect_outbound(&addr, config, privkey).await;
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
        self.mempool.try_lock().map(|m| m.all_hashes()).unwrap_or_default()
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
            let mut data = tx_bytes.clone();
            *dom_crypto::hash::blake2b_256(&data).as_bytes()
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut pool = self.mempool.try_lock()
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
        let Ok(peers) = self.peers.try_lock() else { return Vec::new() };
        peers.connected_peers().into_iter().map(|addr| dom_rpc::PeerInfo {
            addr,
            direction: "inbound".into(),
            connected_since: 0,
        }).collect()
    }
}


async fn handle_inbound(
    mut stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    config: NodeConfig,
    privkey: [u8; 32],
) {
    let chain_id = [0u8; 32]; // TODO: use real chain_id from RFC-0009
    match dom_wire::handshake::perform_handshake_responder(
        &mut stream,
        &privkey,
        config.network.magic(),
        &chain_id,
    )
    .await
    {
        Ok(_transport) => {
            info!("Noise handshake complete with {addr}");
            // TODO: Hello exchange, then message loop
        }
        Err(e) => {
            warn!("Handshake failed with {addr}: {e}");
        }
    }
}

async fn connect_outbound(addr: &str, config: NodeConfig, privkey: [u8; 32]) {
    match tokio::net::TcpStream::connect(addr).await {
        Ok(mut stream) => {
            let chain_id = [0u8; 32]; // TODO: real chain_id
            match dom_wire::handshake::perform_handshake_initiator(
                &mut stream,
                &privkey,
                config.network.magic(),
                &chain_id,
            )
            .await
            {
                Ok(_transport) => {
                    info!("Connected to {addr}");
                    // TODO: Hello exchange, message loop, IBD
                }
                Err(e) => warn!("Handshake failed with {addr}: {e}"),
            }
        }
        Err(e) => warn!("Connection to {addr} failed: {e}"),
    }
}

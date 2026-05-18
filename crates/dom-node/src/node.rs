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
                    let chain = self.chain.clone();
                    tokio::spawn(async move {
                        handle_inbound(stream, peer_addr, config, privkey, chain).await;
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
                    let chain = self.chain.clone();
                    info!("Connecting to peer {addr}");
                    tokio::spawn(async move {
                        connect_outbound(&addr, config, privkey, chain).await;
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
) {
    // chain_id derived from network magic + genesis hash (currently ZERO until
    // genesis hash is finalized — same as in validate_kernel_signatures context).
    let chain_id = [0u8; 32];
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
            if let Err(e) =
                message_loop(&mut stream, &mut codec, &config, addr, chain.clone()).await
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
) {
    let mut stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Connection to {addr} failed: {e}");
            return;
        }
    };
    let chain_id = [0u8; 32];
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
            // TODO Phase 3: IBD if peer.best_height > our height
            let peer_addr = match stream.peer_addr() {
                Ok(a) => a,
                Err(_) => {
                    warn!("Could not resolve peer_addr for {addr}");
                    return;
                }
            };
            if let Err(e) =
                message_loop(&mut stream, &mut codec, &config, peer_addr, chain.clone()).await
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
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    config: &NodeConfig,
    peer_addr: std::net::SocketAddr,
    chain: Arc<Mutex<ChainState>>,
) -> Result<(), DomError> {
    use dom_wire::message::{
        BlockPayload, Command, GetBlockDataPayload, GetHeadersPayload, HeadersPayload, WireMessage,
    };

    const PING_INTERVAL_SECS: u64 = 60;
    let mut ping_timer =
        tokio::time::interval(tokio::time::Duration::from_secs(PING_INTERVAL_SECS));
    // Skip the immediate first tick.
    ping_timer.tick().await;

    loop {
        tokio::select! {
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

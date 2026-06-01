//! Full node orchestration.

use crate::metrics::Metrics;
use crate::miner::mining_loop;
use crate::missing_block_tracker::MissingBlockTracker;
use crate::orphan_pool::{
    OrphanBlock, RuntimeOrphanPool, DEFAULT_MAX_ORPHANS_PER_PARENT, DEFAULT_MAX_ORPHAN_BLOCKS,
};
use crate::task_supervisor::{NodeTaskSupervisor, ShutdownToken, TaskKind};
use crate::time_health::{check_clock_health, DriftStatus};
use dom_chain::ChainState;
use dom_config::NodeConfig;
use dom_consensus::derive_chain_id;
use dom_consensus::Transaction;
use dom_core::DomError;
use dom_core::Hash256;
use dom_core::Timestamp;
use dom_mempool::Mempool;
use dom_store::utxo::UtxoEntry;
use dom_store::DomStore;
use dom_wallet::Wallet;
use dom_wire::dandelion::DandelionRouter;
use dom_wire::manager::PeerManager;
use std::collections::HashMap;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};
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
    /// Runtime-only orphan/missing-parent tracker for deterministic re-requests.
    pub missing_blocks: Arc<Mutex<MissingBlockTracker>>,
    /// Bounded runtime orphan bytes retained for parent-arrival reprocessing.
    pub orphan_pool: Arc<Mutex<RuntimeOrphanPool>>,
    /// Live runtime task supervisor and shutdown coordinator.
    pub task_supervisor: NodeTaskSupervisor,
    /// Test/runtime observers wait here for chain, mempool, or peer-state changes.
    pub state_events: Arc<Notify>,
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
    metrics: Arc<Metrics>,
    future_block_queue: Arc<crate::future_block_queue::FutureBlockQueue>,
    missing_blocks: Arc<Mutex<MissingBlockTracker>>,
    orphan_pool: Arc<Mutex<RuntimeOrphanPool>>,
    wallet: Option<Arc<Mutex<dom_wallet::Wallet>>>,
    state_events: Arc<Notify>,
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

struct TracedMutexGuard<'a, T> {
    lock_name: &'static str,
    acquired_at: Instant,
    guard: tokio::sync::MutexGuard<'a, T>,
}

impl<T> Deref for TracedMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for TracedMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for TracedMutexGuard<'_, T> {
    fn drop(&mut self) {
        tracing::debug!(
            event = "lock_held_ms",
            lock_name = self.lock_name,
            held_ms = self.acquired_at.elapsed().as_millis() as u64,
            "lock released"
        );
    }
}

async fn trace_lock<'a, T>(
    lock_name: &'static str,
    mutex: &'a Arc<Mutex<T>>,
) -> TracedMutexGuard<'a, T> {
    let started = Instant::now();
    let guard = mutex.lock().await;
    tracing::debug!(
        event = "lock_wait_ms",
        lock_name,
        wait_ms = started.elapsed().as_millis() as u64,
        "lock acquired"
    );
    TracedMutexGuard {
        lock_name,
        acquired_at: Instant::now(),
        guard,
    }
}

async fn trace_task_result<F>(task_name: &'static str, future: F) -> Result<(), String>
where
    F: Future<Output = Result<(), String>>,
{
    tracing::info!(event = "task_started", task_name, "task started");
    let result = future.await;
    match &result {
        Ok(()) => tracing::info!(event = "task_stopped", task_name, "task stopped"),
        Err(e) => tracing::error!(
            event = "task_failed",
            task_name,
            error = %e,
            failure_class = "runtime",
            "task failed"
        ),
    }
    result
}

const FUTURE_BLOCK_QUEUE_DRAIN_INTERVAL_SECS: u64 = 30;
const FUTURE_BLOCK_QUEUE_MAX_AGE_SECS: u64 = dom_core::MAX_FUTURE_BLOCK_TIME
    + dom_core::FUTURE_BLOCK_SOFT_BUFFER_SECS
    + FUTURE_BLOCK_QUEUE_DRAIN_INTERVAL_SECS * 2;
const HELLO_EXCHANGE_TIMEOUT_SECS: u64 = dom_wire::handshake::HANDSHAKE_TIMEOUT_SECS;
const PEER_ROTATION_METADATA_KEY: &[u8] = b"dom/peer_rotation_state/v2";
const LEGACY_PEER_ROTATION_METADATA_KEY: &[u8] = b"dom/peer_rotation_state/v1";
const PEER_REPUTATION_METADATA_KEY: &[u8] = b"dom/peer_reputation_state/v1";
const MEMPOOL_METADATA_KEY: &[u8] = b"dom/mempool_state/v1";
const NOISE_STATIC_KEY_METADATA_KEY: &[u8] = b"dom/noise_static_key/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundAttemptOutcome {
    RetryableFailure,
    Registered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferredReplayAction {
    RelayBestChain,
    Requeue,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayBlockAction {
    RelayBestChain,
    Suppress,
    PenalizePeer,
    Drop,
}

#[derive(Debug, Clone)]
pub(crate) struct TxChainView {
    pub(crate) current_height: u64,
    pub(crate) chain_id: [u8; 32],
    pub(crate) coinbase_maturity: u64,
    pub(crate) utxos: HashMap<[u8; 33], Option<UtxoEntry>>,
}

#[derive(Debug, Clone)]
struct ReinjectableTx {
    tx: Transaction,
    tx_hash: [u8; 32],
    now_secs: u64,
    chain_view: TxChainView,
}

pub(crate) fn snapshot_tx_chain_view(
    chain: &ChainState,
    tx: &Transaction,
) -> Result<TxChainView, DomError> {
    let mut utxos = HashMap::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let commitment = *input.commitment.as_bytes();
        utxos
            .entry(commitment)
            .or_insert(chain.store.get_utxo(&commitment)?);
    }
    Ok(TxChainView {
        current_height: chain.tip_height.0,
        chain_id: *derive_chain_id(chain.network_magic, &chain.genesis_hash).as_bytes(),
        coinbase_maturity: chain.coinbase_maturity,
        utxos,
    })
}

async fn purge_mempool_confirmed_inputs(
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
    transactions: &[Transaction],
) -> Result<(), DomError> {
    let mut spent_inputs: Vec<[u8; 33]> =
        Vec::with_capacity(transactions.iter().map(|tx| tx.inputs.len()).sum());
    for tx in transactions {
        for input in &tx.inputs {
            spent_inputs.push(*input.commitment.as_bytes());
        }
    }
    if spent_inputs.is_empty() {
        return Ok(());
    }

    {
        let mut mempool = mempool.lock().await;
        mempool.remove_confirmed(&spent_inputs);
    }
    persist_mempool_state(chain, mempool).await
}

impl DomNode {
    /// Initialize the node from configuration.
    pub fn init(config: NodeConfig) -> Result<Self, DomError> {
        Self::init_inner(config, None)
    }

    /// Initialize the node with an explicit LMDB map size override.
    ///
    /// Production callers should keep using [`Self::init`], which preserves the
    /// 16 GiB default. This override exists for tiny test fixtures so Windows
    /// CI does not reserve a full production-sized LMDB map for each temporary
    /// node/store instance.
    pub fn init_with_map_size(config: NodeConfig, map_size: usize) -> Result<Self, DomError> {
        Self::init_inner(config, Some(map_size))
    }

    fn init_inner(config: NodeConfig, map_size_override: Option<usize>) -> Result<Self, DomError> {
        info!("Initializing DOM node ({:?} network)", config.network);
        info!("Data directory: {}", config.data_dir);

        // Fail closed before touching the data directory if this build still
        // carries placeholder genesis constants for the requested network.
        let genesis_hash =
            dom_core::startup_genesis_hash_for_network_magic(config.network.magic())?;

        // Open storage
        let data_path = Path::new(&config.data_dir);
        let store = match map_size_override {
            Some(map_size) => DomStore::open_with_map_size(data_path, map_size)?,
            None => DomStore::open(data_path)?,
        };

        // Generate or load Noise keypair.
        let noise_privkey = load_or_create_noise_static_key(&store)?;
        let noise_pubkey = dom_wire::handshake::derive_static_pubkey(&noise_privkey);
        info!("Node identity: {}", hex::encode(noise_pubkey));

        // Initialize chain state
        let chain = ChainState::open(store, genesis_hash, config.network.magic())?;
        info!("Chain tip: height={}", chain.tip_height);

        let mut peers = PeerManager::new(config.max_inbound, config.min_outbound);
        restore_peer_rotation_state(&chain.store, &mut peers)?;
        restore_peer_reputation_state(&chain.store, &mut peers)?;
        // Volatile mempool policy (RFC-0012 §1): start empty and clear any legacy
        // on-disk mempool bytes from older builds. The mempool is never loaded
        // from disk; a restarted node re-acquires pending txs from peers.
        clear_persisted_mempool_snapshot(&chain.store)?;
        let mempool = Mempool::new();

        let (block_relay_tx, _) = tokio::sync::broadcast::channel(64);
        let (tx_fluff_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);
        let (tx_stem_tx, _) =
            tokio::sync::broadcast::channel::<dom_wire::dandelion::StemEnvelope>(256);

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
                warn!(
                    "Clock drift warning: {}s — consider synchronizing NTP",
                    drift_secs
                );
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
            mempool: Arc::new(Mutex::new(mempool)),
            peers: Arc::new(Mutex::new(peers)),
            dandelion: Arc::new(Mutex::new(DandelionRouter::new())),
            wallet,
            metrics,
            future_block_queue: Arc::new(crate::future_block_queue::FutureBlockQueue::new()),
            missing_blocks: Arc::new(Mutex::new(MissingBlockTracker::new(8, 2, 16))),
            orphan_pool: Arc::new(Mutex::new(RuntimeOrphanPool::new(
                DEFAULT_MAX_ORPHAN_BLOCKS,
                DEFAULT_MAX_ORPHANS_PER_PARENT,
            ))),
            task_supervisor: NodeTaskSupervisor::new(),
            state_events: Arc::new(Notify::new()),
        })
    }

    pub fn notify_state_changed(&self) {
        self.state_events.notify_waiters();
    }

    /// Request coordinated shutdown of live node tasks.
    pub async fn request_shutdown(&self) {
        tracing::info!("shutdown_requested");
        self.task_supervisor.request_shutdown().await;
    }

    /// Observe the node's live shutdown signal.
    pub fn shutdown_token(&self) -> ShutdownToken {
        self.task_supervisor.shutdown_token()
    }

    /// Start all node services.
    pub async fn run(self: Arc<Self>) -> Result<(), DomError> {
        info!("Starting DOM node services");

        // ── Synchronous listener binds ──────────────────────────────────
        // Bind P2P and RPC sockets BEFORE spawning their accept loops, so
        // bind errors (EADDRINUSE, permission denied, malformed addr)
        // propagate to the caller via `Result<(), DomError>` instead of
        // being swallowed inside a detached task. Previous code spawned
        // `dom_rpc::serve(handle, addr)` (which binds internally) inside
        // `tokio::spawn`, so a stale-port collision on the RPC port turned
        // into a single `warn!` and the node ran indefinitely with a dead
        // RPC server — making readiness checks lie and external tooling
        // (curl/CLI/scripts) see ConnectionRefused with no explanation.
        let p2p_addr = self.config.p2p_listen_addr.clone();
        let p2p_listener = tokio::net::TcpListener::bind(&p2p_addr)
            .await
            .map_err(|e| DomError::Internal(format!("P2P bind {p2p_addr}: {e}")))?;
        info!("P2P listening on {p2p_addr}");

        let rpc_pair = if let Some(rpc_addr) = self.config.rpc_listen_addr.clone() {
            use crate::node_handle::NodeHandleImpl;
            let parsed: std::net::SocketAddr = rpc_addr.parse().map_err(|e| {
                DomError::Internal(format!("Invalid RPC listen addr {rpc_addr}: {e}"))
            })?;
            let listener = dom_rpc::bind(parsed)
                .await
                .map_err(|e| DomError::Internal(format!("RPC bind {parsed}: {e}")))?;
            let handle: Arc<dyn dom_rpc::NodeHandle> = Arc::new(NodeHandleImpl(self.clone()));
            Some((handle, listener))
        } else {
            None
        };

        // ── Supervised runtime tasks ────────────────────────────────────
        // Binds already succeeded; from here on long-lived services are
        // supervised so failures are observable and shutdown is coordinated.
        let supervisor = self.task_supervisor.clone();
        let shutdown = supervisor.shutdown_token();
        let node_listener = self.clone();
        let listener_supervisor = supervisor.clone();
        let listener_shutdown = shutdown.clone();
        supervisor
            .spawn_critical(TaskKind::Listener, async move {
                trace_task_result("p2p_listener", async move {
                    node_listener
                        .run_p2p_listener_on(p2p_listener, listener_supervisor, listener_shutdown)
                        .await
                })
                .await
            })
            .await;

        // Start outbound peer connector
        let node_connector = self.clone();
        let connector_supervisor = supervisor.clone();
        let connector_shutdown = shutdown.clone();
        supervisor
            .spawn_critical(TaskKind::Connector, async move {
                trace_task_result("peer_connector", async move {
                    node_connector
                        .run_peer_connector(connector_supervisor, connector_shutdown)
                        .await
                })
                .await
            })
            .await;

        // Start miner if enabled
        if self.config.mine {
            let node_miner = self.clone();
            let miner_shutdown = shutdown.clone();
            supervisor
                .spawn_critical(TaskKind::Miner, async move {
                    trace_task_result("miner", async move {
                        mining_loop(node_miner, miner_shutdown)
                            .await
                            .map_err(|e| e.to_string())
                    })
                    .await
                })
                .await;
        }

        if let Some((handle, listener)) = rpc_pair {
            let rpc_shutdown = shutdown.clone();
            supervisor
                .spawn_critical(TaskKind::Rpc, async move {
                    trace_task_result("rpc_server", async move {
                        tokio::select! {
                            _ = rpc_shutdown.wait() => Ok(()),
                            result = dom_rpc::serve(handle, listener) => {
                                result.map_err(|e| format!("RPC server error: {e}"))
                            }
                        }
                    })
                    .await
                })
                .await;
        }

        // future_block_queue drain loop — re-evaluate deferred blocks every 30s
        {
            let queue = self.future_block_queue.clone();
            let chain = self.chain.clone();
            let mempool = self.mempool.clone();
            let relay_tx = self.block_relay_tx.clone();
            let metrics = self.metrics.clone();
            let state_events = self.state_events.clone();
            let future_shutdown = shutdown.clone();
            supervisor
                .spawn_critical(TaskKind::FutureQueue, async move {
                    trace_task_result("future_block_queue_drain", async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                    FUTURE_BLOCK_QUEUE_DRAIN_INTERVAL_SECS,
                ));
                loop {
                    tokio::select! {
                        _ = future_shutdown.wait() => return Ok(()),
                        _ = interval.tick() => {}
                    }
                    let evicted = queue.evict_expired(FUTURE_BLOCK_QUEUE_MAX_AGE_SECS).await;
                    if evicted > 0 {
                        tracing::debug!(
                            "Evicted {evicted} expired deferred block(s) before replay drain"
                        );
                    }
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let now = dom_core::Timestamp(now_secs);
                    let ready = queue
                        .drain_ready(now_secs, dom_core::FUTURE_BLOCK_SOFT_BUFFER_SECS)
                        .await;
                    for deferred in ready {
                        tracing::debug!("Re-evaluating deferred block ts={}", deferred.timestamp);
                        match decode_deferred_block_bytes(&deferred.block_bytes) {
                            Ok(block) => {
                                let result = {
                                    let mut c = trace_lock("chain", &chain).await;
                                    c.connect_block(&block, now)
                                };
                                match deferred_replay_action(&result) {
                                    DeferredReplayAction::RelayBestChain => {
                                        tracing::info!(
                                            event = "orphan_reprocessed",
                                            block_height = block.header.height.0,
                                            block_hash = %hex::encode(deferred.block_hash),
                                            action = "accepted_best_chain",
                                            failure_class = "runtime_deferred_replay",
                                            "deferred block reprocessed"
                                        );
                                        if let Ok(ref connect_result) = result {
                                            if let Err(e) = reconcile_mempool_after_connect(
                                                &chain,
                                                &mempool,
                                                connect_result,
                                                &block.transactions,
                                            )
                                            .await
                                            {
                                                tracing::warn!(
                                                    "Deferred block mempool reconciliation failed: {e}"
                                                );
                                            }
                                        }
                                        tracing::info!(
                                            "Accepted deferred block ts={} (new tip)",
                                            deferred.timestamp
                                        );
                                        if let Err(e) = purge_mempool_confirmed_inputs(
                                            &chain,
                                            &mempool,
                                            &block.transactions,
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                "Deferred block confirmed-input purge failed: {e}"
                                            );
                                        }
                                        let _ = relay_tx.send(deferred.block_bytes);
                                        state_events.notify_waiters();
                                    }
                                    DeferredReplayAction::Drop => {
                                        if matches!(result, Ok(dom_chain::ConnectResult::SideChain))
                                        {
                                            tracing::info!(
                                                event = "orphan_reprocessed",
                                                block_height = block.header.height.0,
                                                block_hash = %hex::encode(deferred.block_hash),
                                                action = "accepted_side_chain_drop",
                                                failure_class = "runtime_deferred_replay",
                                                "deferred block reprocessed"
                                            );
                                            tracing::debug!(
                                                "Accepted deferred block ts={} (side chain — no rebroadcast)",
                                                deferred.timestamp
                                            );
                                        } else if matches!(
                                            result,
                                            Ok(dom_chain::ConnectResult::AlreadyHave)
                                        ) {
                                            tracing::trace!(
                                                "Deferred block ts={} already known — no-op",
                                                deferred.timestamp
                                            );
                                        } else if let Err(ref e) = result {
                                            tracing::debug!("Deferred block still rejected: {e}");
                                        }
                                    }
                                    DeferredReplayAction::Requeue => {
                                        tracing::info!(
                                            event = "orphan_reprocessed",
                                            block_height = block.header.height.0,
                                            block_hash = %hex::encode(deferred.block_hash),
                                            action = "requeue",
                                            failure_class = "runtime_deferred_replay",
                                            "deferred block reprocessed"
                                        );
                                        let requeued = queue
                                            .defer(crate::future_block_queue::DeferredBlock {
                                                block_hash: deferred.block_hash,
                                                block_height: deferred.block_height,
                                                timestamp: deferred.timestamp,
                                                queued_at: std::time::Instant::now(),
                                                block_bytes: deferred.block_bytes.clone(),
                                            })
                                            .await;
                                        if requeued {
                                            tracing::debug!(
                                                "Deferred block ts={} requeued after retryable rejection",
                                                deferred.timestamp
                                            );
                                        } else {
                                            tracing::warn!(
                                                "Deferred block ts={} could not be requeued (queue full)",
                                                deferred.timestamp
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // Deferred queue entries are runtime-only and no longer
                                // attributable to a live peer. Malformed bytes must drop
                                // deterministically without requeueing or scoring anyone.
                                metrics
                                    .malformed_block_relays
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                tracing::warn!("Deferred block decode error: {e}");
                            }
                        }
                    }
                }
                    })
                    .await
            })
                .await;
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
            let dandelion_shutdown = shutdown.clone();
            supervisor
                .spawn_critical(TaskKind::DandelionStem, async move {
                    trace_task_result("dandelion_stem_timeout", async move {
                        const STEM_CHECK_INTERVAL_SECS: u64 = 5;
                        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                            STEM_CHECK_INTERVAL_SECS,
                        ));
                        interval.tick().await; // skip first immediate tick
                        loop {
                            tokio::select! {
                                _ = dandelion_shutdown.wait() => return Ok(()),
                                _ = interval.tick() => {}
                            }
                            let timed_out: Vec<[u8; 32]> = {
                                let mut d = trace_lock("dandelion", &dandelion).await;
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
                                    let m = trace_lock("mempool", &mempool).await;
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
                    })
                    .await
                })
                .await;
        }
        tracing::info!(
            event = "shutdown_completed",
            failure_class = "runtime_shutdown",
            "shutdown completed"
        );

        shutdown.wait().await;
        tracing::info!(
            event = "shutdown_requested",
            reason = "shutdown_token",
            failure_class = "runtime_shutdown",
            "shutdown requested"
        );
        let failure = supervisor.failure().await;
        let report = supervisor
            .shutdown_ordered(Duration::from_secs(5), async {
                tracing::debug!("shutdown_persistence_drain");
            })
            .await;
        tracing::info!(
            event = "shutdown_completed",
            failure_class = "runtime_shutdown",
            aborted_tasks = report.aborted.len(),
            stopped_tasks = report.stopped_order.len(),
            "shutdown_completed"
        );

        if let Some(failure) = failure {
            Err(DomError::Internal(format!(
                "critical task {:?} failed: {}",
                failure.failure_task, failure.failure_reason
            )))
        } else {
            Ok(())
        }
    }

    /// Accept incoming P2P connections on an already-bound listener.
    ///
    /// Called by `run()` after `tokio::net::TcpListener::bind` has
    /// succeeded synchronously, so this loop never observes bind errors —
    /// only per-connection accept errors, which are logged and skipped.
    async fn run_p2p_listener_on(
        &self,
        listener: tokio::net::TcpListener,
        supervisor: NodeTaskSupervisor,
        shutdown: ShutdownToken,
    ) -> Result<(), String> {
        loop {
            let accepted = tokio::select! {
                _ = shutdown.wait() => return Ok(()),
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, peer_addr)) => {
                    info!("Inbound connection from {peer_addr}");
                    let reserved = {
                        let mut mgr = trace_lock("peers", &self.peers).await;
                        mgr.reserve_inbound(peer_addr)
                    };
                    if let Err(e) = reserved {
                        warn!("Rejecting connection from {peer_addr}: {e}");
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
                    let svc = NodeServices {
                        mempool: self.mempool.clone(),
                        dandelion: self.dandelion.clone(),
                        peers: self.peers.clone(),
                        metrics: self.metrics.clone(),
                        future_block_queue: self.future_block_queue.clone(),
                        missing_blocks: self.missing_blocks.clone(),
                        orphan_pool: self.orphan_pool.clone(),
                        wallet: self.wallet.clone(),
                        state_events: self.state_events.clone(),
                    };
                    let peers = svc.peers.clone();
                    let metrics = svc.metrics.clone();
                    let chain_for_persist = chain.clone();
                    let peer_shutdown = shutdown.clone();
                    let task_id = supervisor
                        .spawn_relay(async move {
                            trace_task_result("p2p_inbound_session", async move {
                                handle_inbound(
                                    stream,
                                    peer_addr,
                                    config,
                                    privkey,
                                    chain,
                                    channels,
                                    svc,
                                    peer_shutdown,
                                )
                                .await;
                                let mut mgr = trace_lock("peers", &peers).await;
                                let peer_key = peer_addr.to_string();
                                mgr.remove_peer(&peer_key);
                                mgr.release_inbound_reservation(&peer_addr);
                                drop(mgr);
                                if let Err(e) =
                                    persist_peer_reputation_state(&chain_for_persist, &peers).await
                                {
                                    warn!("Persisting peer reputation state failed: {e}");
                                }
                                refresh_peer_metrics(&peers, &metrics, None).await;
                                Ok(())
                            })
                            .await
                        })
                        .await;
                    tracing::debug!(?task_id, peer = %peer_addr, "inbound_peer_task_registered");
                }
                Err(e) => {
                    warn!("Accept error: {e}");
                }
            }
        }
    }

    /// Connect to peers (DNS seeds + configured peers).
    async fn run_peer_connector(
        &self,
        supervisor: NodeTaskSupervisor,
        shutdown: ShutdownToken,
    ) -> Result<(), String> {
        let svc = NodeServices {
            mempool: self.mempool.clone(),
            dandelion: self.dandelion.clone(),
            peers: self.peers.clone(),
            metrics: self.metrics.clone(),
            future_block_queue: self.future_block_queue.clone(),
            missing_blocks: self.missing_blocks.clone(),
            orphan_pool: self.orphan_pool.clone(),
            wallet: self.wallet.clone(),
            state_events: self.state_events.clone(),
        };
        loop {
            if shutdown.is_shutdown() {
                return Ok(());
            }
            let needs_more = {
                let mgr = trace_lock("peers", &self.peers).await;
                mgr.needs_outbound()
            };

            if needs_more {
                if let Err(e) = advance_peer_rotation_cooldowns(&self.chain, &self.peers).await {
                    warn!("Advancing peer rotation cooldowns failed: {e}");
                }
                let is_mainnet = self.config.network == dom_config::Network::Mainnet;
                let port = self.config.network.default_port();
                let mut addrs =
                    dom_wire::dns_seed::resolve_seeds(is_mainnet, port, &self.config.dns_seeds)
                        .await;

                // Also try configured seed peers
                addrs.extend(self.config.seed_peers.iter().cloned());
                addrs.sort();
                addrs.dedup();
                addrs = {
                    let mgr = trace_lock("peers", &self.peers).await;
                    mgr.outbound_candidates_in_retry_order(addrs)
                };

                for addr in addrs {
                    let (reserved, failure_count, cooldown_rounds) = {
                        let mut mgr = trace_lock("peers", &self.peers).await;
                        if !mgr.needs_outbound() {
                            (
                                false,
                                mgr.outbound_failure_count(&addr),
                                mgr.outbound_cooldown_rounds(&addr),
                            )
                        } else {
                            let failure_count = mgr.outbound_failure_count(&addr);
                            let cooldown_rounds = mgr.outbound_cooldown_rounds(&addr);
                            (
                                mgr.reserve_outbound(&addr).is_ok(),
                                failure_count,
                                cooldown_rounds,
                            )
                        }
                    };
                    if !reserved {
                        continue;
                    }
                    tracing::info!(
                        event = "reconnect_attempt",
                        peer_addr = %addr,
                        failure_count,
                        cooldown_rounds,
                        failure_class = "operational_network",
                        "outbound reconnect attempt scheduled"
                    );

                    let config = self.config.clone();
                    let privkey = self.noise_privkey;
                    let chain = self.chain.clone();
                    let channels = BroadcastChannels {
                        block_relay_tx: self.block_relay_tx.clone(),
                        tx_fluff_tx: self.tx_fluff_tx.clone(),
                        tx_stem_tx: self.tx_stem_tx.clone(),
                    };
                    info!("Connecting to peer {addr}");
                    let cleanup_addr = addr.clone();
                    let log_addr = cleanup_addr.clone();
                    let peers = self.peers.clone();
                    let metrics = self.metrics.clone();
                    let svc_c = svc.clone();
                    let chain_for_persist = self.chain.clone();
                    let peer_shutdown = shutdown.clone();
                    let task_id = supervisor
                        .spawn_relay(async move {
                            trace_task_result("p2p_outbound_session", async move {
                                let outcome = connect_outbound(
                                    &addr,
                                    config,
                                    privkey,
                                    chain,
                                    channels,
                                    svc_c,
                                    peer_shutdown,
                                )
                                .await;
                                let mut mgr = trace_lock("peers", &peers).await;
                                if outcome == OutboundAttemptOutcome::RetryableFailure {
                                    mgr.record_outbound_failure(&cleanup_addr);
                                }
                                mgr.remove_peer(&cleanup_addr);
                                mgr.release_outbound_reservation(&cleanup_addr);
                                drop(mgr);
                                if let Err(e) =
                                    persist_peer_rotation_state(&chain_for_persist, &peers).await
                                {
                                    warn!("Persisting peer rotation state failed: {e}");
                                }
                                if let Err(e) =
                                    persist_peer_reputation_state(&chain_for_persist, &peers).await
                                {
                                    warn!("Persisting peer reputation state failed: {e}");
                                }
                                refresh_peer_metrics(&peers, &metrics, None).await;
                                Ok(())
                            })
                            .await
                        })
                        .await;
                    tracing::debug!(?task_id, peer = %log_addr, "outbound_peer_task_registered");
                }
            }

            tokio::select! {
                _ = shutdown.wait() => return Ok(()),
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(
                    dom_wire::manager::OUTBOUND_RECONNECT_POLICY.initial_delay_secs,
                )) => {}
            }
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
        let chain_view = {
            let chain = self
                .chain
                .try_lock()
                .map_err(|_| dom_rpc::RpcError::Internal("chain locked".into()))?;
            snapshot_tx_chain_view(&chain, &tx)
                .map_err(|e| dom_rpc::RpcError::Rejected(e.to_string()))?
        };
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
        pool.accept_tx_with_chain_view(
            tx,
            hash,
            now,
            chain_view.current_height,
            chain_view.chain_id,
            chain_view.coinbase_maturity,
            |commitment| Ok(chain_view.utxos.get(commitment).cloned().flatten()),
        )
        .map_err(|e| dom_rpc::RpcError::Rejected(e.to_string()))?;
        drop(pool);
        self.notify_state_changed();
        let chain = self
            .chain
            .try_lock()
            .map_err(|_| dom_rpc::RpcError::Internal("chain locked".into()))?;
        clear_persisted_mempool_snapshot(&chain.store)
            .map_err(|e| dom_rpc::RpcError::Internal(format!("persist mempool: {e}")))?;
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

#[allow(clippy::too_many_arguments)]
async fn handle_inbound(
    mut stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    config: NodeConfig,
    privkey: [u8; 32],
    chain: Arc<Mutex<ChainState>>,
    channels: BroadcastChannels,
    svc: NodeServices,
    shutdown: ShutdownToken,
) {
    let BroadcastChannels {
        block_relay_tx,
        tx_fluff_tx,
        tx_stem_tx,
    } = channels.clone();
    // Derive chain_id from network magic + canonical genesis hash.
    let genesis_hash = match config.network {
        dom_config::Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        dom_config::Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        dom_config::Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
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
            let _ = record_pending_peer_violation(&chain, &svc.peers, addr, &e).await;
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
                    return;
                }
            }
            if let Err(e) = persist_peer_rotation_state(&chain, &svc.peers).await {
                warn!("Persisting peer rotation state after inbound registration failed: {e}");
            }
            if let Err(e) = persist_peer_reputation_state(&chain, &svc.peers).await {
                warn!("Persisting peer reputation state after inbound registration failed: {e}");
            }
            refresh_peer_metrics(&svc.peers, &svc.metrics, Some(&svc.state_events)).await;
            // IBD loop: if the inbound peer claims a higher chain, sync from it.
            // Mirrors connect_outbound logic so inbound-only nodes (behind NAT
            // who can only accept connections) still converge to the network's
            // tip instead of remaining stuck at a stale height.
            let our_height = chain.lock().await.tip_height.0;
            if peer_hello.best_height > our_height {
                match run_ibd_session(
                    &mut stream,
                    &mut codec,
                    &config,
                    &chain,
                    &svc.mempool,
                    addr,
                    peer_hello.best_height,
                    svc.wallet.clone(),
                    svc.state_events.clone(),
                )
                .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        let _ = record_peer_violation(&chain, &svc.peers, addr, &e).await;
                        warn!("IBD with {addr} failed: {e}");
                        return;
                    }
                }
            }
            if let Err(e) = message_loop(
                PeerConn {
                    stream: &mut stream,
                    codec: &mut codec,
                },
                &config,
                addr,
                chain.clone(),
                BroadcastChannels {
                    block_relay_tx: block_relay_tx.clone(),
                    tx_fluff_tx: tx_fluff_tx.clone(),
                    tx_stem_tx: tx_stem_tx.clone(),
                },
                svc.clone(),
                shutdown.clone(),
            )
            .await
            {
                tracing::info!(
                    event = "session_closed_reason",
                    peer_addr = %addr,
                    direction = "inbound",
                    reason = %e,
                    failure_class = "operational_network",
                    "peer session closed"
                );
                info!("Connection to {addr} closed: {e}");
            }
        }
        Err(e) => {
            let _ = record_pending_peer_violation(&chain, &svc.peers, addr, &e).await;
            warn!("Hello exchange with {addr} failed: {e}")
        }
    }
}

async fn connect_outbound(
    addr: &str,
    config: NodeConfig,
    privkey: [u8; 32],
    chain: Arc<Mutex<ChainState>>,
    channels: BroadcastChannels,
    svc: NodeServices,
    shutdown: ShutdownToken,
) -> OutboundAttemptOutcome {
    let BroadcastChannels {
        block_relay_tx,
        tx_fluff_tx,
        tx_stem_tx,
    } = channels.clone();
    let mut stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                event = "session_closed_reason",
                peer_addr = %addr,
                direction = "outbound",
                reason = %e,
                failure_class = "operational_network",
                "outbound connection failed"
            );
            warn!("Connection to {addr} failed: {e}");
            return OutboundAttemptOutcome::RetryableFailure;
        }
    };
    let genesis_hash = match config.network {
        dom_config::Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        dom_config::Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        dom_config::Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
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
            if let Ok(peer_addr) = addr.parse() {
                let _ = record_pending_peer_violation(&chain, &svc.peers, peer_addr, &e).await;
            }
            warn!("Handshake failed with {addr}: {e}");
            return OutboundAttemptOutcome::RetryableFailure;
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
                            return OutboundAttemptOutcome::RetryableFailure;
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
                    return OutboundAttemptOutcome::RetryableFailure;
                }
            }
            if let Err(e) = persist_peer_rotation_state(&chain, &svc.peers).await {
                warn!("Persisting peer rotation state after outbound registration failed: {e}");
            }
            if let Err(e) = persist_peer_reputation_state(&chain, &svc.peers).await {
                warn!("Persisting peer reputation state after outbound registration failed: {e}");
            }
            refresh_peer_metrics(&svc.peers, &svc.metrics, Some(&svc.state_events)).await;
            let peer_addr = match stream.peer_addr() {
                Ok(a) => a,
                Err(_) => {
                    warn!("Could not resolve peer_addr for {addr}");
                    return OutboundAttemptOutcome::RetryableFailure;
                }
            };

            // IBD loop: keep syncing while peer claims to be ahead.
            let our_height = chain.lock().await.tip_height.0;
            if peer_hello.best_height > our_height {
                match run_ibd_session(
                    &mut stream,
                    &mut codec,
                    &config,
                    &chain,
                    &svc.mempool,
                    peer_addr,
                    peer_hello.best_height,
                    svc.wallet.clone(),
                    svc.state_events.clone(),
                )
                .await
                {
                    Ok(()) => {}
                    Err(e) => {
                        let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e).await;
                        warn!("IBD with {addr} failed: {e}");
                        return OutboundAttemptOutcome::RetryableFailure;
                    }
                }
            }

            if let Err(e) = message_loop(
                PeerConn {
                    stream: &mut stream,
                    codec: &mut codec,
                },
                &config,
                peer_addr,
                chain.clone(),
                BroadcastChannels {
                    block_relay_tx: block_relay_tx.clone(),
                    tx_fluff_tx: tx_fluff_tx.clone(),
                    tx_stem_tx: tx_stem_tx.clone(),
                },
                svc.clone(),
                shutdown.clone(),
            )
            .await
            {
                tracing::info!(
                    event = "session_closed_reason",
                    peer_addr = %addr,
                    direction = "outbound",
                    reason = %e,
                    failure_class = "operational_network",
                    "peer session closed"
                );
                info!("Connection to {addr} closed: {e}");
            }
            OutboundAttemptOutcome::Registered
        }
        Err(e) => {
            let peer_addr = match stream.peer_addr() {
                Ok(a) => a,
                Err(_) => match addr.parse() {
                    Ok(a) => a,
                    Err(_) => {
                        warn!("Hello exchange with {addr} failed: {e}");
                        return OutboundAttemptOutcome::RetryableFailure;
                    }
                },
            };
            let _ = record_pending_peer_violation(&chain, &svc.peers, peer_addr, &e).await;
            warn!("Hello exchange with {addr} failed: {e}");
            OutboundAttemptOutcome::RetryableFailure
        }
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
    tokio::time::timeout(
        tokio::time::Duration::from_secs(HELLO_EXCHANGE_TIMEOUT_SECS),
        hello_exchange_inner(stream, codec, config, chain_id, chain),
    )
    .await
    .map_err(|_| {
        DomError::PolicyRejected(format!(
            "hello timeout after {HELLO_EXCHANGE_TIMEOUT_SECS}s"
        ))
    })?
}

async fn hello_exchange_inner(
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
            drift,
            dom_core::PEER_DRIFT_DISCONNECT_SECS
        )));
    }
    if drift > dom_core::PEER_DRIFT_WARN_SECS {
        warn!("Peer clock drift warning: {}s for peer at exchange", drift);
    }

    Ok(peer_hello)
}

fn peer_violation_score(error: &DomError) -> Option<u32> {
    use dom_wire::peer::ban_scores;

    match error {
        DomError::Malformed(_) => Some(ban_scores::MALFORMED_MESSAGE),
        DomError::PolicyRejected(msg) if msg.contains("handshake timeout") => {
            Some(ban_scores::PROTOCOL_VIOLATION)
        }
        DomError::Invalid(msg) if msg.contains("chain_id mismatch") => {
            Some(ban_scores::WRONG_CHAIN_ID)
        }
        DomError::Invalid(msg) if msg.contains("network_magic mismatch") => {
            Some(ban_scores::WRONG_CHAIN_ID)
        }
        DomError::Invalid(msg) if msg.contains("unexpected Hello") => {
            Some(ban_scores::PROTOCOL_VIOLATION)
        }
        DomError::Invalid(_) => Some(ban_scores::PROTOCOL_VIOLATION),
        _ => None,
    }
}

fn pending_peer_violation_score(error: &DomError) -> Option<u32> {
    match error {
        DomError::TemporarilyInvalid(_) | DomError::Orphan(_) | DomError::Internal(_) => None,
        DomError::PolicyRejected(msg) if msg.contains("hello timeout") => {
            Some(dom_wire::peer::ban_scores::PROTOCOL_VIOLATION)
        }
        other => peer_violation_score(other),
    }
}

async fn record_peer_violation(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
    peer_addr: std::net::SocketAddr,
    error: &DomError,
) -> bool {
    let Some(score) = peer_violation_score(error) else {
        return false;
    };

    let peer_key = peer_addr.to_string();
    let banned = {
        let mut mgr = trace_lock("peers", peers).await;
        mgr.add_ban_score(&peer_key, score)
    };
    if let Err(e) = persist_peer_reputation_state(chain, peers).await {
        warn!("Persisting peer reputation state failed: {e}");
    }

    if banned {
        warn!("Peer {peer_addr} banned after protocol violation: {error}");
    } else {
        warn!("Peer {peer_addr} protocol violation (+{score}): {error}");
    }

    banned
}

async fn record_pending_peer_violation(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
    peer_addr: std::net::SocketAddr,
    error: &DomError,
) -> bool {
    let Some(score) = pending_peer_violation_score(error) else {
        return false;
    };

    let peer_key = peer_addr.to_string();
    let banned = {
        let mut mgr = trace_lock("peers", peers).await;
        mgr.add_pending_ban_score(&peer_key, score) >= dom_wire::peer::ban_scores::BAN_THRESHOLD
    };
    if let Err(e) = persist_peer_reputation_state(chain, peers).await {
        warn!("Persisting peer reputation state failed: {e}");
    }

    if banned {
        warn!("Pending peer {peer_addr} banned after pre-registration violation: {error}");
    } else {
        warn!("Pending peer {peer_addr} violation (+{score}): {error}");
    }

    banned
}

async fn queue_future_block(
    queue: &Arc<crate::future_block_queue::FutureBlockQueue>,
    block: &dom_consensus::Block,
    block_bytes: Vec<u8>,
) -> bool {
    use dom_serialization::DomSerialize;

    let header_bytes = match block.header.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("Could not serialise deferred block header: {e}");
            return false;
        }
    };
    let hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
    let deferred = crate::future_block_queue::DeferredBlock {
        block_hash: hash,
        block_height: block.header.height.0,
        timestamp: block.header.timestamp.0,
        queued_at: std::time::Instant::now(),
        block_bytes,
    };
    let admitted = queue.defer(deferred).await;
    tracing::info!(
        event = "orphan_admitted",
        block_height = block.header.height.0,
        block_hash = %hex::encode(hash),
        action = if admitted { "queued" } else { "rejected_queue_full" },
        failure_class = "runtime_future_block",
        "future block queue admission decided"
    );
    admitted
}

fn deferred_replay_action(
    result: &Result<dom_chain::ConnectResult, DomError>,
) -> DeferredReplayAction {
    match result {
        Ok(dom_chain::ConnectResult::BestChain) | Ok(dom_chain::ConnectResult::Reorg(_)) => {
            DeferredReplayAction::RelayBestChain
        }
        Ok(dom_chain::ConnectResult::SideChain) | Ok(dom_chain::ConnectResult::AlreadyHave) => {
            DeferredReplayAction::Drop
        }
        Err(DomError::TemporarilyInvalid(_)) | Err(DomError::Orphan(_)) => {
            DeferredReplayAction::Requeue
        }
        Err(_) => DeferredReplayAction::Drop,
    }
}

fn relay_block_action(result: &Result<dom_chain::ConnectResult, DomError>) -> RelayBlockAction {
    match result {
        Ok(dom_chain::ConnectResult::BestChain) | Ok(dom_chain::ConnectResult::Reorg(_)) => {
            RelayBlockAction::RelayBestChain
        }
        Ok(dom_chain::ConnectResult::SideChain)
        | Ok(dom_chain::ConnectResult::AlreadyHave)
        | Err(DomError::TemporarilyInvalid(_))
        | Err(DomError::Orphan(_)) => RelayBlockAction::Suppress,
        Err(DomError::Invalid(_)) | Err(DomError::Malformed(_)) => RelayBlockAction::PenalizePeer,
        Err(_) => RelayBlockAction::Drop,
    }
}

fn tx_hash(tx: &Transaction) -> Result<[u8; 32], DomError> {
    use dom_serialization::DomSerialize;

    let tx_bytes = tx.to_bytes()?;
    Ok(*dom_crypto::hash::blake2b_256(&tx_bytes).as_bytes())
}

fn block_hash(block: &dom_consensus::Block) -> Result<[u8; 32], DomError> {
    use dom_serialization::DomSerialize;

    let header_bytes = block.header.to_bytes()?;
    Ok(*dom_crypto::hash::blake2b_256(&header_bytes).as_bytes())
}

fn collect_spent_commitments(transactions: &[Transaction]) -> Vec<[u8; 33]> {
    let mut spent = Vec::with_capacity(transactions.iter().map(|tx| tx.inputs.len()).sum());
    for tx in transactions {
        for input in &tx.inputs {
            spent.push(*input.commitment.as_bytes());
        }
    }
    spent
}

/// Collect, in canonical order, the transactions from disconnected blocks that
/// remain valid under the **new** canonical chain and may be reinjected into the
/// live mempool (RFC-0012 §3).
///
/// Reinjection affects transaction *availability* only; it never affects block
/// validity (RFC-0012 invariant I-1). A candidate is excluded if it is a
/// coinbase/system transaction (§3.2), spends an input that is no longer a live
/// (and, for coinbase, mature) UTXO, or whose outputs/kernels already exist on the
/// surviving branch. Survivors are sorted by `tx_hash` ascending so the
/// reinjection batch — and therefore the resulting mempool — is independent of the
/// order in which the disconnected transactions were originally delivered.
/// Double-spends among survivors are then resolved deterministically by the
/// mempool's input-reservation check (first in hash order wins).
fn collect_reinjectable_reorg_txs(
    chain: &ChainState,
    delta: &dom_chain::ReorgDelta,
) -> Result<Vec<ReinjectableTx>, DomError> {
    let mut reinject = Vec::new();
    for tx in &delta.disconnected_txs {
        // RFC-0012 §3.2: exclude coinbase/system transactions. The canonical
        // coinbase is already structurally excluded (`disconnected_txs` is built
        // from `block.transactions`, never `block.coinbase`); this guard also
        // drops any regular transaction carrying a coinbase kernel feature, which
        // is a system output that must never re-enter the relay mempool.
        let is_coinbase_or_system = tx
            .kernels
            .iter()
            .any(|kernel| kernel.features & dom_core::KERNEL_FEAT_COINBASE != 0);
        if is_coinbase_or_system {
            continue;
        }

        let inputs_are_live = tx.inputs.iter().all(|input| {
            let commitment = input.commitment.as_bytes();
            match chain.store.get_utxo(commitment) {
                Ok(Some(entry)) => {
                    !entry.is_coinbase
                        || entry.is_mature_for(chain.tip_height.0, chain.coinbase_maturity)
                }
                Ok(None) => false,
                Err(_) => false,
            }
        });
        if !inputs_are_live {
            continue;
        }

        let outputs_are_fresh = tx.outputs.iter().all(|output| {
            chain
                .store
                .get_utxo(output.commitment.as_bytes())
                .map(|entry| entry.is_none())
                .unwrap_or(false)
        });
        if !outputs_are_fresh {
            continue;
        }

        let kernels_are_fresh = tx.kernels.iter().all(|kernel| {
            chain
                .store
                .get_kernel_block(kernel.excess.as_bytes())
                .map(|entry| entry.is_none())
                .unwrap_or(false)
        });
        if !kernels_are_fresh {
            continue;
        }

        reinject.push(ReinjectableTx {
            tx: tx.clone(),
            tx_hash: tx_hash(tx)?,
            now_secs: chain.tip_height.0,
            chain_view: snapshot_tx_chain_view(chain, tx)?,
        });
    }
    reinject.sort_unstable_by_key(|entry| entry.tx_hash);
    Ok(reinject)
}

pub(crate) async fn reconcile_mempool_after_connect(
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
    connect_result: &dom_chain::ConnectResult,
    connected_block_txs: &[Transaction],
) -> Result<(), DomError> {
    let (spent_commitments, reinjectable) = {
        let chain = chain.lock().await;
        match connect_result {
            dom_chain::ConnectResult::BestChain => {
                (collect_spent_commitments(connected_block_txs), Vec::new())
            }
            dom_chain::ConnectResult::Reorg(delta) => (
                collect_spent_commitments(&delta.connected_txs),
                collect_reinjectable_reorg_txs(&chain, delta)?,
            ),
            dom_chain::ConnectResult::SideChain | dom_chain::ConnectResult::AlreadyHave => {
                return Ok(());
            }
        }
    };

    let mut mempool = mempool.lock().await;
    if !spent_commitments.is_empty() {
        mempool.remove_confirmed(&spent_commitments);
    }
    if !reinjectable.is_empty() {
        for tx in reinjectable {
            let chain_view = tx.chain_view;
            let _ = mempool.accept_tx_with_chain_view(
                tx.tx,
                tx.tx_hash,
                tx.now_secs,
                chain_view.current_height,
                chain_view.chain_id,
                chain_view.coinbase_maturity,
                |commitment| Ok(chain_view.utxos.get(commitment).cloned().flatten()),
            );
        }
    }
    drop(mempool);

    let chain = chain.lock().await;
    clear_persisted_mempool_snapshot(&chain.store)
}

fn decode_deferred_block_bytes(block_bytes: &[u8]) -> Result<dom_consensus::Block, DomError> {
    use dom_serialization::DomDeserialize;

    dom_consensus::Block::from_bytes(block_bytes)
}

fn decode_relay_block(msg_payload: &[u8]) -> Result<(Vec<u8>, dom_consensus::Block), DomError> {
    use dom_serialization::DomDeserialize;
    use dom_wire::message::BlockPayload;

    let payload = BlockPayload::from_bytes(msg_payload)?;
    let block = dom_consensus::Block::from_bytes(&payload.block_bytes)?;
    Ok((payload.block_bytes, block))
}

async fn reprocess_orphan_children(
    parent_hash: [u8; 32],
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
    relay_tx: &tokio::sync::broadcast::Sender<Vec<u8>>,
    orphan_pool: &Arc<Mutex<RuntimeOrphanPool>>,
    missing_blocks: &Arc<Mutex<MissingBlockTracker>>,
    metrics: &Arc<Metrics>,
) -> Result<(), DomError> {
    let mut ready_parents = vec![parent_hash];
    while let Some(available_parent) = ready_parents.pop() {
        missing_blocks.lock().await.resolve(&available_parent);
        let children = orphan_pool.lock().await.take_children(&available_parent);
        for orphan in children {
            let child = match decode_deferred_block_bytes(&orphan.block_bytes) {
                Ok(block) => block,
                Err(e) => {
                    metrics
                        .malformed_block_relays
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(
                        child = %hex::encode(orphan.block_hash),
                        "Dropping malformed orphan during parent replay: {e}"
                    );
                    continue;
                }
            };
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let result = {
                let mut c = chain.lock().await;
                c.connect_block(&child, dom_core::Timestamp(now_secs))
            };
            match relay_block_action(&result) {
                RelayBlockAction::RelayBestChain => {
                    if let Ok(ref connect_result) = result {
                        reconcile_mempool_after_connect(
                            chain,
                            mempool,
                            connect_result,
                            &child.transactions,
                        )
                        .await?;
                    }
                    let _ = relay_tx.send(orphan.block_bytes.clone());
                    ready_parents.push(orphan.block_hash);
                }
                RelayBlockAction::Suppress => {
                    if matches!(
                        result,
                        Ok(dom_chain::ConnectResult::SideChain)
                            | Ok(dom_chain::ConnectResult::AlreadyHave)
                    ) {
                        ready_parents.push(orphan.block_hash);
                    } else if matches!(result, Err(DomError::Orphan(_))) {
                        let new_parent = *child.header.prev_hash.as_bytes();
                        missing_blocks.lock().await.note_orphan(
                            orphan.block_hash,
                            new_parent,
                            child.header.height.0.checked_sub(1),
                        );
                        let _ = orphan_pool.lock().await.insert(OrphanBlock {
                            block_hash: orphan.block_hash,
                            parent_hash: new_parent,
                            height: child.header.height.0,
                            block_bytes: orphan.block_bytes,
                        });
                    }
                }
                RelayBlockAction::PenalizePeer | RelayBlockAction::Drop => {
                    if let Err(e) = result {
                        tracing::debug!(
                            child = %hex::encode(orphan.block_hash),
                            "Dropping orphan after parent replay: {e}"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn decode_ibd_block_response(
    msg_payload: &[u8],
    expected_hash: [u8; 32],
) -> Result<(Vec<u8>, dom_consensus::Block), DomError> {
    use dom_serialization::{DomDeserialize, DomSerialize};
    use dom_wire::message::BlockPayload;

    let payload = BlockPayload::from_bytes(msg_payload)?;
    let block = dom_consensus::Block::from_bytes(&payload.block_bytes)?;
    let header_bytes = block.header.to_bytes()?;
    let block_hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
    if block_hash != expected_hash {
        return Err(DomError::Invalid(format!(
            "IBD block response hash mismatch: expected {}, got {}",
            hex::encode(expected_hash),
            hex::encode(block_hash)
        )));
    }
    Ok((payload.block_bytes, block))
}

pub(crate) fn persist_peer_rotation_snapshot(
    store: &DomStore,
    snapshot: &dom_wire::manager::PersistedPeerRotationState,
) -> Result<(), DomError> {
    use dom_serialization::DomSerialize;

    if snapshot.outbound_failures.is_empty() {
        store.delete_metadata(PEER_ROTATION_METADATA_KEY)?;
        return store.delete_metadata(LEGACY_PEER_ROTATION_METADATA_KEY);
    }
    store.put_metadata(PEER_ROTATION_METADATA_KEY, &snapshot.to_bytes()?)?;
    store.delete_metadata(LEGACY_PEER_ROTATION_METADATA_KEY)
}

pub(crate) fn persist_peer_reputation_snapshot(
    store: &DomStore,
    snapshot: &dom_wire::manager::PersistedPeerReputationState,
) -> Result<(), DomError> {
    use dom_serialization::DomSerialize;

    if snapshot.entries.is_empty() {
        return store.delete_metadata(PEER_REPUTATION_METADATA_KEY);
    }
    store.put_metadata(PEER_REPUTATION_METADATA_KEY, &snapshot.to_bytes()?)
}

pub(crate) fn load_peer_rotation_snapshot(
    store: &DomStore,
) -> Result<Option<dom_wire::manager::PersistedPeerRotationState>, DomError> {
    use dom_serialization::DomDeserialize;

    match store.get_metadata(PEER_ROTATION_METADATA_KEY)? {
        Some(bytes) => {
            let snapshot = dom_wire::manager::PersistedPeerRotationState::from_bytes(&bytes)
                .map_err(|e| {
                    DomError::Invalid(format!("peer rotation snapshot decode failed: {e}"))
                })?;
            Ok(Some(snapshot))
        }
        None => match store.get_metadata(LEGACY_PEER_ROTATION_METADATA_KEY)? {
            Some(bytes) => {
                let snapshot =
                    dom_wire::manager::PersistedPeerRotationState::from_legacy_bytes(&bytes)
                        .map_err(|e| {
                            DomError::Invalid(format!(
                                "legacy peer rotation snapshot decode failed: {e}"
                            ))
                        })?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        },
    }
}

pub(crate) fn load_peer_reputation_snapshot(
    store: &DomStore,
) -> Result<Option<dom_wire::manager::PersistedPeerReputationState>, DomError> {
    use dom_serialization::DomDeserialize;

    match store.get_metadata(PEER_REPUTATION_METADATA_KEY)? {
        Some(bytes) => {
            let snapshot = dom_wire::manager::PersistedPeerReputationState::from_bytes(&bytes)
                .map_err(|e| {
                    DomError::Invalid(format!("peer reputation snapshot decode failed: {e}"))
                })?;
            Ok(Some(snapshot))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
pub(crate) fn persist_mempool_snapshot(
    store: &DomStore,
    snapshot: &dom_mempool::PersistedMempoolState,
) -> Result<(), DomError> {
    use dom_serialization::DomSerialize;

    if snapshot.entries.is_empty() {
        return store.delete_metadata(MEMPOOL_METADATA_KEY);
    }
    store.put_metadata(MEMPOOL_METADATA_KEY, &snapshot.to_bytes()?)
}

/// Clear any on-disk mempool bytes (RFC-0012 §1).
///
/// The mempool is volatile: it is never loaded from disk into runtime state.
/// Older builds may have left `MEMPOOL_METADATA_KEY` bytes; this removes them so
/// the on-disk view stays consistent with the empty-on-restart policy. It is
/// called on init, on every block connect, and on tx admission.
pub(crate) fn clear_persisted_mempool_snapshot(store: &DomStore) -> Result<(), DomError> {
    store.delete_metadata(MEMPOOL_METADATA_KEY)
}

// Test-only: under the volatile mempool policy (RFC-0012 §1) no runtime path
// reads on-disk mempool bytes into state. This decoder exists solely so tests can
// assert that legacy/adversarial on-disk mempool metadata has been cleared.
#[cfg(test)]
pub(crate) fn load_mempool_snapshot(
    store: &DomStore,
) -> Result<Option<dom_mempool::PersistedMempoolState>, DomError> {
    use dom_serialization::DomDeserialize;

    match store.get_metadata(MEMPOOL_METADATA_KEY)? {
        Some(bytes) => {
            let snapshot = dom_mempool::PersistedMempoolState::from_bytes(&bytes)
                .map_err(|e| DomError::Invalid(format!("mempool snapshot decode failed: {e}")))?;
            Ok(Some(snapshot))
        }
        None => Ok(None),
    }
}

pub(crate) fn restore_peer_rotation_state(
    store: &DomStore,
    peers: &mut PeerManager,
) -> Result<(), DomError> {
    match load_peer_rotation_snapshot(store)? {
        Some(snapshot) => peers
            .restore_outbound_failure_state(&snapshot)
            .map_err(|e| {
                DomError::Invalid(format!("persisted peer rotation state restore failed: {e}"))
            }),
        None => Ok(()),
    }
}

pub(crate) fn restore_peer_reputation_state(
    store: &DomStore,
    peers: &mut PeerManager,
) -> Result<(), DomError> {
    match load_peer_reputation_snapshot(store)? {
        Some(snapshot) => peers.restore_peer_reputation_state(&snapshot).map_err(|e| {
            DomError::Invalid(format!(
                "persisted peer reputation state restore failed: {e}"
            ))
        }),
        None => Ok(()),
    }
}

async fn persist_peer_rotation_state(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
) -> Result<(), DomError> {
    let snapshot = {
        let peers = peers.lock().await;
        peers.outbound_failure_state()
    };
    let chain = chain.lock().await;
    persist_peer_rotation_snapshot(&chain.store, &snapshot)
}

async fn persist_peer_reputation_state(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
) -> Result<(), DomError> {
    let snapshot = {
        let peers = peers.lock().await;
        peers.peer_reputation_state()
    };
    let chain = chain.lock().await;
    persist_peer_reputation_snapshot(&chain.store, &snapshot)
}

/// Persist mempool lifecycle state.
///
/// Under the volatile mempool policy (RFC-0012 §1) the mempool is **never**
/// written to disk: "persisting" it means ensuring no on-disk mempool bytes
/// remain, so a restart deterministically starts empty. The live `mempool` is
/// intentionally unused here.
async fn persist_mempool_state(
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
) -> Result<(), DomError> {
    let chain = chain.lock().await;
    let _ = mempool;
    clear_persisted_mempool_snapshot(&chain.store)
}

async fn advance_peer_rotation_cooldowns(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
) -> Result<(), DomError> {
    let changed = {
        let mut peers = peers.lock().await;
        peers.advance_outbound_cooldowns()
    };
    if changed {
        persist_peer_rotation_state(chain, peers).await?;
    }
    Ok(())
}

pub(crate) fn load_or_create_noise_static_key(store: &DomStore) -> Result<[u8; 32], DomError> {
    match store.get_metadata(NOISE_STATIC_KEY_METADATA_KEY)? {
        Some(bytes) => parse_persisted_noise_static_key(&bytes),
        None => {
            let (privkey, _) = dom_wire::handshake::generate_static_keypair();
            store.put_metadata(NOISE_STATIC_KEY_METADATA_KEY, &privkey)?;
            Ok(privkey)
        }
    }
}

fn parse_persisted_noise_static_key(bytes: &[u8]) -> Result<[u8; 32], DomError> {
    if bytes.len() != 32 {
        return Err(DomError::Invalid(format!(
            "persisted Noise static key has invalid length: expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(bytes);
    let mut normalized = privkey;
    dom_wire::handshake::clamp_static_privkey(&mut normalized);
    if normalized != privkey {
        return Err(DomError::Invalid(
            "persisted Noise static key is not in canonical clamped form".into(),
        ));
    }
    Ok(privkey)
}

async fn record_duplicate_block_relay(
    peers: &Arc<Mutex<PeerManager>>,
    metrics: &Arc<Metrics>,
    peer_addr: std::net::SocketAddr,
) -> bool {
    let peer_key = peer_addr.to_string();
    metrics
        .suppressed_duplicate_block_relays
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let exceeded = {
        let mut mgr = peers.lock().await;
        mgr.record_duplicate_block_relay(&peer_key)
    };
    if exceeded {
        metrics
            .duplicate_block_relay_quota_exceeded
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    exceeded
}

async fn refresh_peer_metrics(
    peers: &Arc<Mutex<PeerManager>>,
    metrics: &Arc<Metrics>,
    state_events: Option<&Arc<Notify>>,
) {
    let (peer_count, inbound_peers, outbound_peers) = {
        let mgr = trace_lock("peers", peers).await;
        let mut peer_count = 0u64;
        let mut inbound_peers = 0u64;
        let mut outbound_peers = 0u64;
        for peer in mgr.peers.values() {
            if peer.state == dom_wire::peer::PeerState::Connected {
                peer_count += 1;
                if peer.outbound {
                    outbound_peers += 1;
                } else {
                    inbound_peers += 1;
                }
            }
        }
        (peer_count, inbound_peers, outbound_peers)
    };

    metrics
        .peer_count
        .store(peer_count, std::sync::atomic::Ordering::Relaxed);
    metrics
        .inbound_peers
        .store(inbound_peers, std::sync::atomic::Ordering::Relaxed);
    metrics
        .outbound_peers
        .store(outbound_peers, std::sync::atomic::Ordering::Relaxed);
    if let Some(state_events) = state_events {
        state_events.notify_waiters();
    }
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

async fn persist_ibd_state(
    chain: &Arc<Mutex<ChainState>>,
    peer_addr: std::net::SocketAddr,
    ibd: &dom_chain::IbdState,
    round: IbdRoundState,
) -> Result<(), DomError> {
    let chain = chain.lock().await;
    let snapshot = dom_chain::PersistedIbdState {
        phase: ibd.phase,
        peer_addr: peer_addr.to_string(),
        start_height: ibd.start_height,
        best_peer_height: ibd.best_peer_height,
        headers_height: ibd.headers_height,
        blocks_height: ibd.blocks_height,
        last_progress_height: ibd.last_progress_height,
        checkpoint_tip_hash: *chain.tip_hash.as_bytes(),
        retry_attempts: ibd.retry_attempts,
        last_interruption: ibd.last_interruption,
        pending_blocks: round.pending_blocks,
        pending_headers: round.pending_headers,
        block_cursor: round.block_cursor,
        header_cursor: round.header_cursor,
        header_cursor_height: round.header_cursor_height,
    };
    snapshot.save(&chain.store)
}

async fn clear_persisted_ibd_state(chain: &Arc<Mutex<ChainState>>) -> Result<(), DomError> {
    let chain = chain.lock().await;
    dom_chain::PersistedIbdState::clear(&chain.store)
}

struct IbdRuntimeContext<'a> {
    config: &'a NodeConfig,
    peer_addr: std::net::SocketAddr,
    mempool: Arc<Mutex<Mempool>>,
    wallet: Option<Arc<Mutex<dom_wallet::Wallet>>>,
    state_events: Arc<Notify>,
}

#[derive(Clone)]
struct IbdRoundState {
    pending_blocks: Vec<[u8; 32]>,
    pending_headers: Vec<Vec<u8>>,
    block_cursor: u32,
    header_cursor: u32,
    header_cursor_height: u64,
}

async fn initialize_ibd_state(
    chain: &Arc<Mutex<ChainState>>,
    peer_addr: std::net::SocketAddr,
    peer_best_height: u64,
) -> Result<(dom_chain::IbdState, Option<dom_chain::PersistedIbdState>), DomError> {
    let peer_key = peer_addr.to_string();
    let (tip_height, tip_hash, persisted) = {
        let chain = chain.lock().await;
        (
            chain.tip_height.0,
            *chain.tip_hash.as_bytes(),
            dom_chain::PersistedIbdState::load(&chain.store)?,
        )
    };

    let Some(snapshot) = persisted else {
        return Ok((dom_chain::IbdState::new(tip_height, peer_best_height), None));
    };

    let resumable = snapshot.peer_addr == peer_key
        && snapshot.best_peer_height == peer_best_height
        && snapshot.blocks_height == tip_height
        && snapshot.checkpoint_tip_hash == tip_hash
        && !matches!(
            snapshot.phase,
            dom_chain::IbdPhase::Completed | dom_chain::IbdPhase::Failed
        );

    if !resumable {
        clear_persisted_ibd_state(chain).await?;
        return Ok((dom_chain::IbdState::new(tip_height, peer_best_height), None));
    }

    match dom_chain::IbdState::from_persisted(&snapshot) {
        Ok(ibd) => Ok((ibd, Some(snapshot))),
        Err(_) => {
            clear_persisted_ibd_state(chain).await?;
            Ok((dom_chain::IbdState::new(tip_height, peer_best_height), None))
        }
    }
}

async fn resume_ibd_block_sync(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    chain: &Arc<Mutex<ChainState>>,
    runtime: &IbdRuntimeContext<'_>,
    ibd: &mut dom_chain::IbdState,
    round: IbdRoundState,
) -> Result<bool, DomError> {
    use dom_wire::message::{Command, GetBlockDataPayload, WireMessage};

    let start = usize::try_from(round.block_cursor)
        .map_err(|_| DomError::Internal("persisted block cursor conversion failed".into()))?;
    if start >= round.pending_blocks.len() {
        return Ok(false);
    }

    ibd.begin_block_sync();
    let mut connected_any = false;
    let mut processed = round.block_cursor;

    for batch in round.pending_blocks[start..].chunks(dom_core::MAX_GETBLOCKDATA_HASHES) {
        let req = GetBlockDataPayload {
            hashes: batch.to_vec(),
        };
        let wire = WireMessage {
            magic: runtime.config.network.magic(),
            command: Command::GetBlockData,
            payload: req.to_bytes()?,
        };
        codec.send(stream, &wire).await?;

        for expected_hash in batch {
            let msg = loop {
                let m = codec.recv(stream).await?;
                match m.command {
                    Command::Block => break m,
                    Command::Ping => {
                        let pong = WireMessage {
                            magic: runtime.config.network.magic(),
                            command: Command::Pong,
                            payload: m.payload,
                        };
                        codec.send(stream, &pong).await?;
                    }
                    Command::Pong => {}
                    other => {
                        tracing::debug!("IBD resume: ignoring {other:?} while waiting for Block");
                    }
                }
            };
            let (_, block) =
                decode_ibd_block_response(&msg.payload, *expected_hash).map_err(|e| {
                    DomError::Invalid(format!(
                        "IBD from {}: resumed block response for {} rejected: {e}",
                        runtime.peer_addr,
                        hex::encode(expected_hash)
                    ))
                })?;
            let height = block.header.height.0;
            let txs_for_scan = block.transactions.clone();
            // DOM-AUDIT-001: connect the block under the chain guard, capture
            // the owned `ConnectResult` (and `best_chain`), then DROP the guard
            // before any follow-up work. `purge_mempool_confirmed_inputs`
            // re-acquires the chain lock (via `persist_mempool_state`); calling
            // it while the guard is still alive deadlocks the non-reentrant
            // Tokio mutex. Mirrors the correct call-sites (deferred replay /
            // orphan reprocess / peer block): capture-in-scope, act-after-drop.
            let (connect_result, best_chain) = {
                let mut c = chain.lock().await;
                let connect_result = match c.connect_block(
                    &block,
                    Timestamp(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    ),
                ) {
                    Ok(result) => result,
                    Err(e) => {
                        return Err(DomError::Invalid(format!(
                            "IBD resume from {}: connect_block rejected: {e}",
                            runtime.peer_addr,
                        )));
                    }
                };
                let best_chain = match &connect_result {
                    dom_chain::ConnectResult::BestChain => {
                        connected_any = true;
                        true
                    }
                    dom_chain::ConnectResult::Reorg(_) => {
                        connected_any = true;
                        true
                    }
                    dom_chain::ConnectResult::SideChain => {
                        connected_any = true;
                        false
                    }
                    dom_chain::ConnectResult::AlreadyHave => {
                        tracing::debug!(
                            "IBD resume from {}: block already known at height {}",
                            runtime.peer_addr,
                            height
                        );
                        connected_any = true;
                        false
                    }
                };
                (connect_result, best_chain)
            };
            // Chain guard dropped above. The following re-acquire chain/mempool/
            // wallet internally and must run with NO chain guard held.
            if best_chain {
                purge_mempool_confirmed_inputs(chain, &runtime.mempool, &txs_for_scan).await?;
                if let Some(ref wallet_arc) = runtime.wallet {
                    let mut w = wallet_arc.lock().await;
                    match connect_result {
                        dom_chain::ConnectResult::BestChain => {
                            w.apply_canonical_block_with_hash(
                                &txs_for_scan,
                                height,
                                Some(*expected_hash),
                            )
                            .map_err(|e| {
                                DomError::Internal(format!(
                                    "wallet canonical block apply during resumed IBD failed: {e}"
                                ))
                            })?;
                        }
                        dom_chain::ConnectResult::Reorg(delta) => {
                            w.rollback_to(delta.common_ancestor_height).map_err(|e| {
                                DomError::Internal(format!(
                                    "wallet rollback during resumed IBD reorg failed: {e}"
                                ))
                            })?;
                            for block in &delta.connected_blocks {
                                w.apply_canonical_block_with_hash(
                                    &block.transactions,
                                    block.block_height,
                                    Some(block.block_hash),
                                )
                                .map_err(|e| {
                                    DomError::Internal(format!(
                                        "wallet canonical reorg block apply during resumed IBD failed: {e}"
                                    ))
                                })?;
                            }
                        }
                        dom_chain::ConnectResult::SideChain
                        | dom_chain::ConnectResult::AlreadyHave => {}
                    }
                }
            }
            runtime.state_events.notify_waiters();
            processed = processed.saturating_add(1);
            persist_ibd_state(
                chain,
                runtime.peer_addr,
                ibd,
                IbdRoundState {
                    pending_blocks: round.pending_blocks.clone(),
                    pending_headers: Vec::new(),
                    block_cursor: processed,
                    header_cursor: 0,
                    header_cursor_height: round.header_cursor_height,
                },
            )
            .await?;
        }
    }

    Ok(connected_any)
}

fn ibd_now() -> Timestamp {
    Timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

async fn continue_ibd_header_sync(
    chain: &Arc<Mutex<ChainState>>,
    peer_addr: std::net::SocketAddr,
    ibd: &mut dom_chain::IbdState,
    round: IbdRoundState,
    now: Timestamp,
) -> Result<Vec<[u8; 32]>, DomError> {
    let start = usize::try_from(round.header_cursor)
        .map_err(|_| DomError::Internal("persisted header cursor conversion failed".into()))?;
    if start > round.pending_headers.len() {
        return Err(DomError::PolicyRejected(format!(
            "persisted header cursor {} exceeds pending header count {}",
            round.header_cursor,
            round.pending_headers.len()
        )));
    }

    if round.pending_headers.is_empty() {
        return Ok(round.pending_blocks);
    }

    ibd.begin_header_sync();
    let pending_headers = round.pending_headers;
    let mut pending_blocks = round.pending_blocks;

    for cursor in start..pending_headers.len() {
        let (height, updated_pending_blocks) = {
            let c = chain.lock().await;
            c.validate_ibd_header_step(&pending_headers, cursor, &pending_blocks, now)?
        };
        pending_blocks = updated_pending_blocks;
        ibd.headers_height = ibd.headers_height.max(height);
        ibd.last_progress_height = ibd.last_progress_height.max(height);
        persist_ibd_state(
            chain,
            peer_addr,
            ibd,
            IbdRoundState {
                pending_blocks: pending_blocks.clone(),
                pending_headers: pending_headers.clone(),
                block_cursor: 0,
                header_cursor: u32::try_from(cursor + 1)
                    .map_err(|_| DomError::Internal("header cursor overflow".into()))?,
                header_cursor_height: round.header_cursor_height,
            },
        )
        .await?;
    }

    if pending_blocks.is_empty() {
        ibd.phase = dom_chain::IbdPhase::Discovering;
    } else {
        ibd.begin_block_sync();
    }
    persist_ibd_state(
        chain,
        peer_addr,
        ibd,
        IbdRoundState {
            pending_blocks: pending_blocks.clone(),
            pending_headers: Vec::new(),
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: round.header_cursor_height,
        },
    )
    .await?;
    Ok(pending_blocks)
}

#[allow(clippy::too_many_arguments)]
async fn run_ibd_session(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    config: &NodeConfig,
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
    peer_addr: std::net::SocketAddr,
    peer_best_height: u64,
    wallet: Option<Arc<Mutex<dom_wallet::Wallet>>>,
    state_events: Arc<Notify>,
) -> Result<(), DomError> {
    let our_height = chain.lock().await.tip_height.0;
    let (mut ibd, persisted) = initialize_ibd_state(chain, peer_addr, peer_best_height).await?;
    let runtime = IbdRuntimeContext {
        config,
        peer_addr,
        mempool: mempool.clone(),
        wallet: wallet.clone(),
        state_events: state_events.clone(),
    };
    match ibd.begin_session() {
        dom_chain::IbdControl::Complete => {
            clear_persisted_ibd_state(chain).await?;
            info!(
                "IBD with {peer_addr} already complete at height {}",
                our_height
            );
            return Ok(());
        }
        dom_chain::IbdControl::Continue => {}
        dom_chain::IbdControl::Retry | dom_chain::IbdControl::Fail => {
            return Err(DomError::Internal(
                "IBD state machine returned invalid initial control".into(),
            ));
        }
    }
    if let Some(snapshot) = persisted.clone() {
        if !snapshot.pending_headers.is_empty()
            && snapshot.header_cursor < snapshot.pending_headers.len() as u32
        {
            let pending_blocks = continue_ibd_header_sync(
                chain,
                peer_addr,
                &mut ibd,
                IbdRoundState {
                    pending_blocks: snapshot.pending_blocks.clone(),
                    pending_headers: snapshot.pending_headers.clone(),
                    block_cursor: snapshot.block_cursor,
                    header_cursor: snapshot.header_cursor,
                    header_cursor_height: snapshot.header_cursor_height,
                },
                ibd_now(),
            )
            .await?;
            if !pending_blocks.is_empty() {
                match resume_ibd_block_sync(
                    stream,
                    codec,
                    chain,
                    &runtime,
                    &mut ibd,
                    IbdRoundState {
                        pending_blocks,
                        pending_headers: Vec::new(),
                        block_cursor: 0,
                        header_cursor: 0,
                        header_cursor_height: snapshot.header_cursor_height,
                    },
                )
                .await
                {
                    Ok(true) => {
                        let new_height = chain.lock().await.tip_height.0;
                        match ibd.note_round_progress(new_height) {
                            dom_chain::IbdControl::Complete => {
                                clear_persisted_ibd_state(chain).await?;
                                info!(
                                    "IBD with {peer_addr} resumed and caught up at height {new_height}"
                                );
                                return Ok(());
                            }
                            dom_chain::IbdControl::Continue => {
                                persist_ibd_state(
                                    chain,
                                    peer_addr,
                                    &ibd,
                                    IbdRoundState {
                                        pending_blocks: Vec::new(),
                                        pending_headers: Vec::new(),
                                        block_cursor: 0,
                                        header_cursor: 0,
                                        header_cursor_height: ibd.headers_height,
                                    },
                                )
                                .await?;
                            }
                            dom_chain::IbdControl::Retry | dom_chain::IbdControl::Fail => {
                                return Err(DomError::Internal(
                                    "resumed IBD progress transition returned invalid control"
                                        .into(),
                                ));
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(e) => match ibd.note_round_error(&e) {
                        dom_chain::IbdControl::Retry => {
                            warn!(
                                "IBD with {peer_addr} interrupted ({e}); retry {}/{} remaining={}",
                                ibd.retry_attempts,
                                dom_chain::ibd::MAX_IBD_RETRY_ATTEMPTS,
                                ibd.remaining_retries()
                            );
                        }
                        dom_chain::IbdControl::Fail => {
                            clear_persisted_ibd_state(chain).await?;
                            return Err(e);
                        }
                        dom_chain::IbdControl::Complete | dom_chain::IbdControl::Continue => {
                            return Err(DomError::Internal(
                                "resumed IBD error transition returned invalid control".into(),
                            ));
                        }
                    },
                }
            } else {
                persist_ibd_state(
                    chain,
                    peer_addr,
                    &ibd,
                    IbdRoundState {
                        pending_blocks: Vec::new(),
                        pending_headers: Vec::new(),
                        block_cursor: 0,
                        header_cursor: 0,
                        header_cursor_height: ibd.headers_height,
                    },
                )
                .await?;
            }
        } else if !snapshot.pending_blocks.is_empty()
            && snapshot.block_cursor < snapshot.pending_blocks.len() as u32
        {
            match resume_ibd_block_sync(
                stream,
                codec,
                chain,
                &runtime,
                &mut ibd,
                IbdRoundState {
                    pending_blocks: snapshot.pending_blocks.clone(),
                    pending_headers: Vec::new(),
                    block_cursor: snapshot.block_cursor,
                    header_cursor: 0,
                    header_cursor_height: snapshot.header_cursor_height,
                },
            )
            .await
            {
                Ok(true) => {
                    let new_height = chain.lock().await.tip_height.0;
                    match ibd.note_round_progress(new_height) {
                        dom_chain::IbdControl::Complete => {
                            clear_persisted_ibd_state(chain).await?;
                            info!(
                                "IBD with {peer_addr} resumed and caught up at height {new_height}"
                            );
                            return Ok(());
                        }
                        dom_chain::IbdControl::Continue => {
                            persist_ibd_state(
                                chain,
                                peer_addr,
                                &ibd,
                                IbdRoundState {
                                    pending_blocks: Vec::new(),
                                    pending_headers: Vec::new(),
                                    block_cursor: 0,
                                    header_cursor: 0,
                                    header_cursor_height: ibd.headers_height,
                                },
                            )
                            .await?;
                        }
                        dom_chain::IbdControl::Retry | dom_chain::IbdControl::Fail => {
                            return Err(DomError::Internal(
                                "resumed IBD progress transition returned invalid control".into(),
                            ));
                        }
                    }
                }
                Ok(false) => {}
                Err(e) => match ibd.note_round_error(&e) {
                    dom_chain::IbdControl::Retry => {
                        warn!(
                            "IBD with {peer_addr} interrupted ({e}); retry {}/{} remaining={}",
                            ibd.retry_attempts,
                            dom_chain::ibd::MAX_IBD_RETRY_ATTEMPTS,
                            ibd.remaining_retries()
                        );
                    }
                    dom_chain::IbdControl::Fail => {
                        clear_persisted_ibd_state(chain).await?;
                        return Err(e);
                    }
                    dom_chain::IbdControl::Complete | dom_chain::IbdControl::Continue => {
                        return Err(DomError::Internal(
                            "resumed IBD error transition returned invalid control".into(),
                        ));
                    }
                },
            }
        } else {
            persist_ibd_state(
                chain,
                peer_addr,
                &ibd,
                IbdRoundState {
                    pending_blocks: Vec::new(),
                    pending_headers: Vec::new(),
                    block_cursor: 0,
                    header_cursor: 0,
                    header_cursor_height: ibd.headers_height,
                },
            )
            .await?;
        }
    } else {
        persist_ibd_state(
            chain,
            peer_addr,
            &ibd,
            IbdRoundState {
                pending_blocks: Vec::new(),
                pending_headers: Vec::new(),
                block_cursor: 0,
                header_cursor: 0,
                header_cursor_height: ibd.headers_height,
            },
        )
        .await?;
    }

    info!("Starting IBD from {peer_addr}: our={our_height} peer={peer_best_height}");

    loop {
        ibd.begin_header_sync();
        match ibd_sync_round(
            stream,
            codec,
            config,
            chain,
            mempool,
            peer_addr,
            wallet.clone(),
            state_events.clone(),
            &mut ibd,
        )
        .await
        {
            Ok(true) => {
                let new_height = chain.lock().await.tip_height.0;
                match ibd.note_round_progress(new_height) {
                    dom_chain::IbdControl::Complete => {
                        clear_persisted_ibd_state(chain).await?;
                        info!("IBD with {peer_addr} caught up at height {new_height}");
                        return Ok(());
                    }
                    dom_chain::IbdControl::Continue => {
                        persist_ibd_state(
                            chain,
                            peer_addr,
                            &ibd,
                            IbdRoundState {
                                pending_blocks: Vec::new(),
                                pending_headers: Vec::new(),
                                block_cursor: 0,
                                header_cursor: 0,
                                header_cursor_height: ibd.headers_height,
                            },
                        )
                        .await?;
                        continue;
                    }
                    dom_chain::IbdControl::Retry | dom_chain::IbdControl::Fail => {
                        return Err(DomError::Internal(
                            "IBD progress transition returned invalid control".into(),
                        ));
                    }
                }
            }
            Ok(false) => match ibd.note_empty_response() {
                dom_chain::IbdControl::Complete => {
                    clear_persisted_ibd_state(chain).await?;
                    info!(
                        "IBD with {peer_addr} completed after empty response at height {}",
                        ibd.blocks_height
                    );
                    return Ok(());
                }
                dom_chain::IbdControl::Retry => {
                    persist_ibd_state(
                        chain,
                        peer_addr,
                        &ibd,
                        IbdRoundState {
                            pending_blocks: Vec::new(),
                            pending_headers: Vec::new(),
                            block_cursor: 0,
                            header_cursor: 0,
                            header_cursor_height: ibd.headers_height,
                        },
                    )
                    .await?;
                    warn!(
                        "IBD with {peer_addr} made no progress; retry {}/{} remaining={}",
                        ibd.retry_attempts,
                        dom_chain::ibd::MAX_IBD_RETRY_ATTEMPTS,
                        ibd.remaining_retries()
                    );
                    continue;
                }
                dom_chain::IbdControl::Fail => {
                    clear_persisted_ibd_state(chain).await?;
                    return Err(DomError::PolicyRejected(format!(
                        "IBD from {peer_addr}: exhausted retry budget after empty response"
                    )));
                }
                dom_chain::IbdControl::Continue => {
                    return Err(DomError::Internal(
                        "IBD empty-response transition returned invalid control".into(),
                    ));
                }
            },
            Err(e) => match ibd.note_round_error(&e) {
                dom_chain::IbdControl::Retry => {
                    warn!(
                        "IBD with {peer_addr} interrupted ({e}); retry {}/{} remaining={}",
                        ibd.retry_attempts,
                        dom_chain::ibd::MAX_IBD_RETRY_ATTEMPTS,
                        ibd.remaining_retries()
                    );
                    continue;
                }
                dom_chain::IbdControl::Fail => {
                    clear_persisted_ibd_state(chain).await?;
                    return Err(e);
                }
                dom_chain::IbdControl::Complete => {
                    clear_persisted_ibd_state(chain).await?;
                    return Ok(());
                }
                dom_chain::IbdControl::Continue => {
                    return Err(DomError::Internal(
                        "IBD error transition returned invalid control".into(),
                    ));
                }
            },
        }
    }
}

/// Run a single IBD sync round against one peer.
///
/// Sends GetHeaders, receives headers, requests bodies in batches, and connects
/// each block via ChainState::connect_block. Returns Ok(true) if any progress
/// was made (at least one block accepted), Ok(false) if peer had nothing new.
#[allow(clippy::too_many_arguments)]
async fn ibd_sync_round(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    config: &NodeConfig,
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
    peer_addr: std::net::SocketAddr,
    wallet: Option<Arc<Mutex<dom_wallet::Wallet>>>,
    state_events: Arc<Notify>,
    ibd: &mut dom_chain::IbdState,
) -> Result<bool, DomError> {
    use dom_consensus::block::BlockHeader;
    use dom_serialization::DomDeserialize;
    use dom_wire::message::{Command, GetHeadersPayload, HeadersPayload, WireMessage};

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

    let now = ibd_now();
    let header_cursor_height = BlockHeader::from_bytes(
        headers_payload
            .headers
            .last()
            .ok_or_else(|| DomError::Internal("headers payload unexpectedly empty".into()))?,
    )?
    .height
    .0;

    let block_hashes = continue_ibd_header_sync(
        chain,
        peer_addr,
        ibd,
        IbdRoundState {
            pending_blocks: Vec::new(),
            pending_headers: headers_payload.headers.clone(),
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height,
        },
        now,
    )
    .await?;

    if block_hashes.is_empty() {
        tracing::debug!(
            "IBD: peer sent {} headers but all are already in our store — no bodies to fetch",
            headers_payload.headers.len()
        );
        return Ok(false);
    }

    let runtime = IbdRuntimeContext {
        config,
        peer_addr,
        mempool: mempool.clone(),
        wallet,
        state_events,
    };
    resume_ibd_block_sync(
        stream,
        codec,
        chain,
        &runtime,
        ibd,
        IbdRoundState {
            pending_blocks: block_hashes,
            pending_headers: Vec::new(),
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height,
        },
    )
    .await
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
    shutdown: ShutdownToken,
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
            _ = shutdown.wait() => {
                return Ok(());
            }
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
                let msg = match recv {
                    Ok(msg) => msg,
                    Err(e) => {
                        let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e).await;
                        return Err(e);
                    }
                };
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
                        let err = DomError::Invalid(
                            "unexpected Hello in message loop [ban+20]".into(),
                        );
                        let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &err).await;
                        return Err(err);
                    }
                    Command::GetHeaders => {
                        let req = match GetHeadersPayload::from_bytes(&msg.payload) {
                            Ok(req) => req,
                            Err(e) => {
                                let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                    .await;
                                return Err(e);
                            }
                        };
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
                        let (block_bytes, block) = match decode_relay_block(&msg.payload) {
                            Ok(decoded) => decoded,
                            Err(e) => {
                                svc.metrics
                                    .malformed_block_relays
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                    .await;
                                return Err(e);
                            }
                        };
                        let relay_block_hash = {
                            use dom_serialization::DomSerialize;
                            *dom_crypto::hash::blake2b_256(&block.header.to_bytes()?).as_bytes()
                        };
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let now = dom_core::Timestamp(now_secs);
                        let current_block_hash = block_hash(&block)?;

                        // Doc 4.5 mitigation 1: soft buffer for future blocks
                        use dom_consensus::block::{
                            validate_future_timestamp_with_buffer_limits, TimestampDecision,
                        };
                        let (max_future, soft_buffer) =
                            if config.network == dom_config::Network::Testnet {
                                (
                                    dom_core::TESTNET_MAX_FUTURE_BLOCK_TIME,
                                    dom_core::TESTNET_FUTURE_BLOCK_SOFT_BUFFER_SECS,
                                )
                            } else {
                                (
                                    dom_core::MAX_FUTURE_BLOCK_TIME,
                                    dom_core::FUTURE_BLOCK_SOFT_BUFFER_SECS,
                                )
                            };
                        match validate_future_timestamp_with_buffer_limits(
                            &block.header,
                            now,
                            max_future,
                            soft_buffer,
                        ) {
                            Ok(TimestampDecision::Accept) => {
                                // Normal path: validate and connect
                                let height = block.header.height.0;
                                let txs_for_scan = block.transactions.clone();
                                let result = {
                                    let mut c = chain.lock().await;
                                    c.connect_block(&block, now)
                                };
                                match relay_block_action(&result) {
                                    RelayBlockAction::RelayBestChain => {
                                        if let Ok(ref connect_result) = result {
                                            if let Err(e) = reconcile_mempool_after_connect(
                                                &chain,
                                                &svc.mempool,
                                                connect_result,
                                                &block.transactions,
                                            )
                                            .await
                                            {
                                                tracing::warn!(
                                                    "Mempool reconciliation failed after block from {peer_addr}: {e}"
                                                );
                                            }
                                        }
                                        tracing::info!(
                                            "Accepted relayed block from {peer_addr} (new tip)"
                                        );
                                        // Wallet state follows canonical blocks only.
                                        if let Ok(ref connect_result) = result {
                                            match connect_result {
                                                dom_chain::ConnectResult::BestChain => {
                                                    if let Some(ref wallet_arc) = svc.wallet {
                                                        let mut w = wallet_arc.lock().await;
                                                        if let Err(e) =
                                                            w.apply_canonical_block_with_hash(
                                                                &txs_for_scan,
                                                                height,
                                                                Some(relay_block_hash),
                                                            )
                                                        {
                                                            tracing::warn!(
                                                                "wallet canonical block apply failed at height {height}: {e}"
                                                            );
                                                        }
                                                    }
                                                }
                                                dom_chain::ConnectResult::Reorg(delta) => {
                                                    if let Some(ref wallet_arc) = svc.wallet {
                                                        let mut w = wallet_arc.lock().await;
                                                        if let Err(e) = w.rollback_to(
                                                            delta.common_ancestor_height,
                                                        ) {
                                                            tracing::warn!(
                                                                "wallet rollback failed at reorg ancestor height {}: {e}",
                                                                delta.common_ancestor_height
                                                            );
                                                        } else {
                                                            for block in &delta.connected_blocks {
                                                                if let Err(e) = w
                                                                    .apply_canonical_block_with_hash(
                                                                        &block.transactions,
                                                                        block.block_height,
                                                                        Some(block.block_hash),
                                                                    )
                                                                {
                                                                    tracing::warn!(
                                                                        "wallet canonical reorg block apply failed at height {} hash {}: {e}",
                                                                        block.block_height,
                                                                        hex::encode(block.block_hash)
                                                                    );
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                dom_chain::ConnectResult::SideChain
                                                | dom_chain::ConnectResult::AlreadyHave => {}
                                            }
                                        }
                                        // DOM-SEC-RELAY-LOOP: only rebroadcast when we
                                        // actually extended the best chain. SideChain
                                        // and AlreadyHave MUST NOT rebroadcast — that
                                        // creates infinite relay loops between peers.
                                        let _ = block_relay_tx.send(block_bytes);
                                        svc.state_events.notify_waiters();
                                        if let Err(e) = reprocess_orphan_children(
                                            current_block_hash,
                                            &chain,
                                            &svc.mempool,
                                            &block_relay_tx,
                                            &svc.orphan_pool,
                                            &svc.missing_blocks,
                                            &svc.metrics,
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                "Orphan replay after block from {peer_addr} failed: {e}"
                                            );
                                        }
                                    }
                                    RelayBlockAction::Suppress => {
                                        if matches!(result, Ok(dom_chain::ConnectResult::SideChain)) {
                                            tracing::debug!(
                                                "Accepted relayed block from {peer_addr} (side chain — no rebroadcast)"
                                            );
                                            // Wallet state intentionally ignores side-chain blocks.
                                            // Pending-spend reconciliation and output recovery are
                                            // canonical-only until the wallet learns explicit reorg
                                            // rollback semantics.
                                            if let Err(e) = reprocess_orphan_children(
                                                current_block_hash,
                                                &chain,
                                                &svc.mempool,
                                                &block_relay_tx,
                                                &svc.orphan_pool,
                                                &svc.missing_blocks,
                                                &svc.metrics,
                                            )
                                            .await
                                            {
                                                tracing::warn!(
                                                    "Side-chain orphan replay after block from {peer_addr} failed: {e}"
                                                );
                                            }
                                        } else if matches!(result, Ok(dom_chain::ConnectResult::AlreadyHave)) {
                                            if record_duplicate_block_relay(
                                                &svc.peers,
                                                &svc.metrics,
                                                peer_addr,
                                            )
                                            .await
                                            {
                                                return Err(DomError::PolicyRejected(
                                                    "duplicate block relay quota exceeded".into(),
                                                ));
                                            }
                                            tracing::trace!(
                                                "Block from {peer_addr} already known — no-op"
                                            );
                                        } else if matches!(result, Err(DomError::Orphan(_))) {
                                            let parent_hash = *block.header.prev_hash.as_bytes();
                                            let insert_outcome = svc.orphan_pool.lock().await.insert(OrphanBlock {
                                                block_hash: current_block_hash,
                                                parent_hash,
                                                height: block.header.height.0,
                                                block_bytes: block_bytes.clone(),
                                            });
                                            let requests = {
                                                let mut tracker = svc.missing_blocks.lock().await;
                                                tracker.note_orphan(
                                                    current_block_hash,
                                                    parent_hash,
                                                    block.header.height.0.checked_sub(1),
                                                );
                                                tracker.next_request_batch(block.header.height.0)
                                            };
                                            tracing::debug!(
                                                peer = %peer_addr,
                                                child = %hex::encode(current_block_hash),
                                                parent = %hex::encode(parent_hash),
                                                ?insert_outcome,
                                                "Recorded orphan block and scheduled missing-parent request"
                                            );
                                            if !requests.is_empty() {
                                                let req = GetBlockDataPayload { hashes: requests };
                                                let wire = WireMessage {
                                                    magic: config.network.magic(),
                                                    command: Command::GetBlockData,
                                                    payload: req.to_bytes()?,
                                                };
                                                codec.send(stream, &wire).await?;
                                            }
                                        } else if let Err(ref e) = result {
                                            tracing::debug!("Block from {peer_addr} not accepted: {e}");
                                        }
                                    }
                                    RelayBlockAction::PenalizePeer => {
                                        let e = result.expect_err("penalized relay result must be an error");
                                        if matches!(e, DomError::Malformed(_)) {
                                            svc.metrics
                                                .malformed_block_relays
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        }
                                        tracing::warn!(
                                            event = "consensus_rejection",
                                            peer_addr = %peer_addr,
                                            block_height = block.header.height.0,
                                            reason = %e,
                                            failure_class = "consensus_rejection",
                                            "relayed block rejected"
                                        );
                                        let banned =
                                            record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                                .await;
                                        tracing::warn!("Rejected block from {peer_addr}: {e}");
                                        if banned {
                                            return Err(e);
                                        }
                                    }
                                    RelayBlockAction::Drop => {
                                        if let Err(ref e) = result {
                                            tracing::debug!("Block from {peer_addr} not accepted: {e}");
                                        }
                                    }
                                }
                            }
                            Ok(TimestampDecision::Defer) => {
                                // Soft buffer: hold for re-evaluation
                                tracing::info!(
                                    event = "future_block_policy_action",
                                    peer_addr = %peer_addr,
                                    block_height = block.header.height.0,
                                    block_timestamp = block.header.timestamp.0,
                                    action = "defer",
                                    failure_class = "runtime_future_block",
                                    "future block deferred by soft buffer"
                                );
                                tracing::debug!("Block from {peer_addr} deferred (future timestamp soft buffer)");
                                if queue_future_block(&svc.future_block_queue, &block, block_bytes).await {
                                    tracing::debug!(
                                        "Deferred block ts={} queued for replay",
                                        block.header.timestamp.0
                                    );
                                } else {
                                    tracing::warn!(
                                        "Deferred block ts={} dropped because future queue is full",
                                        block.header.timestamp.0
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::info!(
                                    event = "future_block_policy_action",
                                    peer_addr = %peer_addr,
                                    block_height = block.header.height.0,
                                    block_timestamp = block.header.timestamp.0,
                                    action = "reject",
                                    reason = %e,
                                    failure_class = "consensus_rejection",
                                    "future block rejected by timestamp policy"
                                );
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
                                let chain_view = {
                                    let c = chain.lock().await;
                                    snapshot_tx_chain_view(&c, &tx)
                                };
                                let now_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                let accepted = match chain_view {
                                    Ok(view) => {
                                        let mut m = svc.mempool.lock().await;
                                        let result = m.accept_tx_with_chain_view(
                                            tx,
                                            tx_hash,
                                            now_secs,
                                            view.current_height,
                                            view.chain_id,
                                            view.coinbase_maturity,
                                            |commitment| {
                                                Ok(view.utxos.get(commitment).cloned().flatten())
                                            },
                                        );
                                        drop(m);
                                        if result.is_ok() {
                                            let chain = chain.lock().await;
                                            clear_persisted_mempool_snapshot(&chain.store)?;
                                        }
                                        result
                                    }
                                    Err(e) => Err(e),
                                };
                                if accepted.is_ok() {
                                    svc.state_events.notify_waiters();
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
                                } else if let Err(e) = accepted {
                                    tracing::debug!(
                                        event = "consensus_rejection",
                                        peer_addr = %peer_addr,
                                        tx_hash = %hex::encode(tx_hash),
                                        reason = %e,
                                        failure_class = "consensus_rejection",
                                        "relayed transaction rejected"
                                    );
                                    let banned =
                                        record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                            .await;
                                    tracing::debug!(
                                        "Rejected relayed tx {} from {peer_addr}: {e}",
                                        hex::encode(tx_hash)
                                    );
                                    if banned {
                                        return Err(e);
                                    }
                                }
                            }
                            Err(e) => {
                                let banned =
                                    record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                        .await;
                                tracing::debug!("Invalid tx from {peer_addr}: {e}");
                                if banned {
                                    return Err(e);
                                }
                            }
                        }
                    }
                    Command::GetBlockData => {
                        let req = match GetBlockDataPayload::from_bytes(&msg.payload) {
                            Ok(req) => req,
                            Err(e) => {
                                let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                    .await;
                                return Err(e);
                            }
                        };
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

#[cfg(test)]
mod tests {
    use super::{
        clear_persisted_mempool_snapshot, continue_ibd_header_sync, decode_deferred_block_bytes,
        decode_ibd_block_response, decode_relay_block, deferred_replay_action, ibd_now,
        initialize_ibd_state, load_mempool_snapshot, load_or_create_noise_static_key,
        load_peer_reputation_snapshot, load_peer_rotation_snapshot,
        parse_persisted_noise_static_key, peer_violation_score, pending_peer_violation_score,
        persist_mempool_snapshot, persist_peer_reputation_snapshot, purge_mempool_confirmed_inputs,
        reconcile_mempool_after_connect, refresh_peer_metrics, relay_block_action,
        restore_peer_rotation_state, trace_lock, tx_hash, DeferredReplayAction, DomNode,
        IbdRoundState, OutboundAttemptOutcome, RelayBlockAction, LEGACY_PEER_ROTATION_METADATA_KEY,
        MEMPOOL_METADATA_KEY, NOISE_STATIC_KEY_METADATA_KEY, PEER_REPUTATION_METADATA_KEY,
        PEER_ROTATION_METADATA_KEY,
    };
    use crate::future_block_queue::DeferredBlock;
    use crate::metrics::Metrics;
    use crate::orphan_pool::OrphanBlock;
    use crate::replay_snapshot::ReplaySnapshot;
    use crate::task_supervisor::{SupervisorStatus, TaskKind};
    use dom_chain::{
        ChainState, ConnectResult, IbdInterruption, IbdPhase, PersistedIbdState, ReorgDelta,
    };
    use dom_config::NodeConfig;
    use dom_consensus::block::{BlockHeader, ProofOfWork};
    use dom_consensus::{
        Block, CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionInput,
        TransactionKernel, TransactionOutput,
    };
    use dom_core::{
        Amount, BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
        MAX_BLOCK_SERIALIZED_SIZE, MIN_RELAY_FEE_RATE, NETWORK_MAGIC_REGTEST, PROTOCOL_VERSION,
        TAG_KERNEL_MSG, TAG_KERNEL_MSG_COINBASE,
    };
    use dom_crypto::bulletproof;
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::keys::SecretKey;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use dom_crypto::schnorr_sign;
    use dom_mempool::Mempool;
    use dom_pow::{
        compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target,
        target_to_compact, target_to_difficulty, CompactTarget,
    };
    use dom_serialization::DomSerialize;
    use dom_store::utxo::UtxoEntry;
    use dom_store::DomStore;
    use dom_wire::manager::{PeerManager, PersistedPeerReputationState};
    use dom_wire::message::BlockPayload;
    use dom_wire::peer::ban_scores;
    use dom_wire::peer::{PeerInfo, PeerState};
    use primitive_types::U256;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::net::TcpStream;
    use tokio::sync::Mutex;

    const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

    type TestUtxoBytes = ([u8; 33], Vec<u8>);

    #[tokio::test]
    async fn traced_lock_guard_preserves_state_transition() {
        let state = Arc::new(Mutex::new(0u8));
        {
            let mut guard = trace_lock("test_state", &state).await;
            *guard = 1;
        }
        assert_eq!(*state.lock().await, 1);
    }

    fn commitment(seed: u8, value: u64) -> Commitment {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        let blind = BlindingFactor::from_bytes(bytes).expect("deterministic blinding");
        Commitment::commit(value, &blind)
    }

    fn scalar(seed: u8) -> BlindingFactor {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        BlindingFactor::from_bytes(bytes).expect("deterministic blinding")
    }

    fn build_coinbase(
        height: BlockHeight,
        claimed_fees: u64,
        chain_id: &[u8; 32],
    ) -> CoinbaseTransaction {
        let reward = dom_core::block_reward(height).noms();
        let explicit_value = reward + claimed_fees;
        let blinding = scalar(height.0 as u8 + 1);
        let commitment = Commitment::commit(explicit_value, &blinding);
        let (proof, _) = bulletproof::prove(explicit_value, &blinding).expect("coinbase proof");
        let excess = Commitment::commit(0, &blinding);
        let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
        let msg = {
            let mut data = Vec::with_capacity(1 + 8);
            data.push(KERNEL_FEAT_COINBASE);
            data.extend_from_slice(&explicit_value.to_le_bytes());
            blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
        };
        let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id).expect("coinbase sig");
        CoinbaseTransaction {
            output: TransactionOutput {
                commitment,
                proof: proof.bytes,
            },
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value,
                excess,
                excess_signature: sig.to_bytes(),
            },
            offset: [0u8; 32],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mine_fast_header(
        seed_hash: [u8; 32],
        prev_hash: Hash256,
        height: BlockHeight,
        timestamp: Timestamp,
        output_root: Hash256,
        kernel_root: Hash256,
        rangeproof_root: Hash256,
        total_kernel_offset: [u8; 32],
        total_difficulty: U256,
    ) -> BlockHeader {
        let target =
            compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
        let mut nonce = 0u64;
        loop {
            let mut header = BlockHeader {
                version: PROTOCOL_VERSION,
                height,
                prev_hash,
                timestamp,
                output_root,
                kernel_root,
                rangeproof_root,
                total_kernel_offset,
                target: CompactTarget(target_to_compact(&target)),
                total_difficulty,
                pow: ProofOfWork {
                    nonce,
                    randomx_hash: Hash256::ZERO,
                },
            };
            let hash = fast_pow_hash(&seed_hash, &header.pow_preimage());
            if hash_meets_target(&hash, &target) {
                header.pow.randomx_hash = Hash256::from_bytes(hash);
                return header;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    fn build_coinbase_only_block(
        seed_hash: [u8; 32],
        prev_hash: Hash256,
        height: BlockHeight,
        parent_total_difficulty: U256,
        total_kernel_offset: [u8; 32],
        chain_id: &[u8; 32],
    ) -> Block {
        let coinbase = build_coinbase(height, 0, chain_id);
        let (output_root, kernel_root, rangeproof_root) =
            dom_consensus::compute_block_pmmr_roots(&coinbase, &[]).expect("roots");
        let timestamp = genesis_anchor(NETWORK_MAGIC_REGTEST)
            .expect("anchor")
            .timestamp
            .checked_add_secs(height.0 * dom_core::TARGET_SPACING)
            .expect("timestamp");
        let target =
            compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
        let total_difficulty = parent_total_difficulty + U256::from(target_to_difficulty(&target));
        let header = mine_fast_header(
            seed_hash,
            prev_hash,
            height,
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset,
            total_difficulty,
        );
        Block {
            header,
            coinbase,
            transactions: vec![],
        }
    }

    fn safe_now() -> Timestamp {
        Timestamp(2_000_000_000)
    }

    fn synthetic_block(height: u64, nonce: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height: BlockHeight(height),
                prev_hash: Hash256::ZERO,
                timestamp: Timestamp(1_700_000_000 + height),
                output_root: Hash256::ZERO,
                kernel_root: Hash256::ZERO,
                rangeproof_root: Hash256::ZERO,
                total_kernel_offset: [0u8; 32],
                target: CompactTarget(0),
                total_difficulty: U256::from(height),
                pow: ProofOfWork {
                    nonce,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase: CoinbaseTransaction {
                output: dom_consensus::TransactionOutput {
                    commitment: commitment(1, 50),
                    proof: vec![0x42; 8],
                },
                kernel: CoinbaseKernel {
                    features: KERNEL_FEAT_COINBASE,
                    explicit_value: 50,
                    excess: commitment(2, 0),
                    excess_signature: [0x24; 65],
                },
                offset: [0u8; 32],
            },
            transactions: Vec::new(),
        }
    }

    fn synthetic_block_with_transactions(
        prev_hash: Hash256,
        height: u64,
        nonce: u64,
        coinbase_seed: u8,
        transactions: Vec<Transaction>,
    ) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height: BlockHeight(height),
                prev_hash,
                timestamp: Timestamp(1_700_100_000 + height),
                output_root: Hash256::ZERO,
                kernel_root: Hash256::ZERO,
                rangeproof_root: Hash256::ZERO,
                total_kernel_offset: [0u8; 32],
                target: CompactTarget(0),
                total_difficulty: U256::from(height),
                pow: ProofOfWork {
                    nonce,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase: CoinbaseTransaction {
                output: TransactionOutput {
                    commitment: commitment(coinbase_seed, 1_000_000 + height),
                    proof: vec![coinbase_seed; 8],
                },
                kernel: CoinbaseKernel {
                    features: KERNEL_FEAT_COINBASE,
                    explicit_value: 1,
                    excess: commitment(coinbase_seed.wrapping_add(100), 0),
                    excess_signature: [coinbase_seed; 65],
                },
                offset: [0u8; 32],
            },
            transactions,
        }
    }

    fn synthetic_spend_tx(input: Commitment, output_seed: u8, kernel_seed: u8) -> Transaction {
        Transaction {
            inputs: vec![TransactionInput { commitment: input }],
            outputs: vec![TransactionOutput {
                commitment: commitment(output_seed, u64::from(output_seed) + 1),
                proof: vec![output_seed; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(kernel_seed, 0),
                excess_signature: [kernel_seed; 65],
            }],
            offset: [0u8; 32],
        }
    }

    fn signed_spend_tx(
        input_value: u64,
        input_blinding: BlindingFactor,
        fee: u64,
        _output_seed: u8,
        kernel_seed: u8,
        chain_id: &[u8; 32],
    ) -> Transaction {
        let output_value = input_value.checked_sub(fee).expect("fee below input");
        let kernel_blinding = scalar(kernel_seed);
        let output_blinding = input_blinding
            .add(&kernel_blinding)
            .expect("output blinding");
        let input = Commitment::commit(input_value, &input_blinding);
        let output = Commitment::commit(output_value, &output_blinding);
        let (proof, _) = bulletproof::prove(output_value, &output_blinding).expect("tx proof");
        let excess = Commitment::commit(0, &kernel_blinding);
        let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
        let msg = {
            let mut data = Vec::with_capacity(1 + 8 + 8);
            data.push(KERNEL_FEAT_PLAIN);
            data.extend_from_slice(&fee.to_le_bytes());
            data.extend_from_slice(&0u64.to_le_bytes());
            blake2b_256_tagged(TAG_KERNEL_MSG, &data)
        };
        let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id).expect("kernel sig");

        Transaction {
            inputs: vec![TransactionInput { commitment: input }],
            outputs: vec![TransactionOutput {
                commitment: output,
                proof: proof.bytes,
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).expect("fee"),
                lock_height: 0,
                excess,
                excess_signature: sig.to_bytes(),
            }],
            offset: [0u8; 32],
        }
    }

    fn spending_tx(input: Commitment, seed: u8) -> Transaction {
        Transaction {
            inputs: vec![TransactionInput { commitment: input }],
            outputs: vec![TransactionOutput {
                commitment: commitment(seed.wrapping_add(10), 1),
                proof: vec![seed; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 25).unwrap(),
                lock_height: 0,
                excess: commitment(seed.wrapping_add(20), 0),
                excess_signature: [seed; 65],
            }],
            offset: [0u8; 32],
        }
    }

    fn mempool_tx(seed: u8, fee_multiplier: u64) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: commitment(seed, 1),
                proof: vec![seed; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * fee_multiplier).unwrap(),
                lock_height: 0,
                excess: commitment(seed.wrapping_add(50), 0),
                excess_signature: [seed; 65],
            }],
            offset: [0u8; 32],
        }
    }

    fn block_state_changes(block: &Block) -> (Vec<TestUtxoBytes>, Vec<[u8; 33]>) {
        let mut new_utxos = vec![(
            *block.coinbase.output.commitment.as_bytes(),
            UtxoEntry {
                block_height: block.header.height.0,
                is_coinbase: true,
                proof: block.coinbase.output.proof.clone(),
            }
            .to_bytes(),
        )];
        let mut spent_utxos = Vec::new();
        for tx in &block.transactions {
            for input in &tx.inputs {
                spent_utxos.push(*input.commitment.as_bytes());
            }
            for output in &tx.outputs {
                new_utxos.push((
                    *output.commitment.as_bytes(),
                    UtxoEntry {
                        block_height: block.header.height.0,
                        is_coinbase: false,
                        proof: output.proof.clone(),
                    }
                    .to_bytes(),
                ));
            }
        }
        (new_utxos, spent_utxos)
    }

    fn kernel_excesses(block: &Block) -> Vec<([u8; 33], [u8; 32])> {
        let hash = block_hash(block);
        let mut out = vec![(*block.coinbase.kernel.excess.as_bytes(), hash)];
        for tx in &block.transactions {
            for kernel in &tx.kernels {
                out.push((*kernel.excess.as_bytes(), hash));
            }
        }
        out
    }

    async fn commit_chain_block(chain: &Arc<Mutex<ChainState>>, block: &Block) {
        let hash = block_hash(block);
        let header_bytes = block.header.to_bytes().expect("header bytes");
        let body_bytes = block.to_bytes().expect("body bytes");
        let (new_utxos, spent_utxos) = block_state_changes(block);
        let kernels = kernel_excesses(block);
        let mut guard = chain.lock().await;
        guard
            .store
            .commit_block(
                &hash,
                block.header.height.0,
                &header_bytes,
                &body_bytes,
                &new_utxos,
                &spent_utxos,
                &kernels,
            )
            .expect("commit block");
        guard.tip_hash = Hash256::from_bytes(hash);
        guard.tip_height = block.header.height;
        guard.tip_difficulty = block.header.total_difficulty;
    }
    fn ibd_payload(block: &Block) -> Vec<u8> {
        BlockPayload {
            block_bytes: block.to_bytes().expect("serialize block"),
        }
        .to_bytes()
        .expect("serialize block payload")
    }

    fn block_hash(block: &Block) -> [u8; 32] {
        *dom_crypto::hash::blake2b_256(&block.header.to_bytes().expect("serialize header"))
            .as_bytes()
    }

    fn header_hash(header: &BlockHeader) -> [u8; 32] {
        *dom_crypto::hash::blake2b_256(&header.to_bytes().expect("serialize header")).as_bytes()
    }

    fn open_chain(dir: &std::path::Path) -> Arc<Mutex<ChainState>> {
        let store = open_test_store(dir);
        let chain = ChainState::open(
            store,
            Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
            NETWORK_MAGIC_REGTEST,
        )
        .expect("chain open");
        Arc::new(Mutex::new(chain))
    }

    async fn store_known_header(chain: &Arc<Mutex<ChainState>>, header: &BlockHeader) {
        let header_bytes = header.to_bytes().expect("serialize header");
        let hash = header_hash(header);
        let chain = chain.lock().await;
        chain
            .store
            .store_known_block(&hash, &header_bytes, &[0u8; 8])
            .expect("store known header");
    }

    fn synthetic_known_header(
        height: u64,
        prev_hash: Hash256,
        total_difficulty: u64,
    ) -> BlockHeader {
        BlockHeader {
            version: 1,
            height: BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(1_700_000_000 + height),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0),
            total_difficulty: U256::from(total_difficulty),
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        }
    }

    fn fresh_test_dir(label: &str) -> PathBuf {
        let unique = format!(
            "dom-node-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn regtest_node_config(data_dir: &std::path::Path) -> NodeConfig {
        let mut config = NodeConfig::regtest();
        config.data_dir = data_dir.to_string_lossy().into_owned();
        config.wallet_path = None;
        config.wallet_password = None;
        config.mine = false;
        config
    }

    fn init_test_node(config: NodeConfig) -> DomNode {
        DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE).expect("node init")
    }

    fn open_test_store(dir: &std::path::Path) -> DomStore {
        DomStore::open_with_map_size(dir, TEST_LMDB_MAP_SIZE).expect("store open")
    }

    fn free_local_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral localhost port")
            .local_addr()
            .expect("read localhost addr")
            .port()
    }

    async fn wait_for_supervisor(
        node: &Arc<DomNode>,
        predicate: impl Fn(Vec<TaskKind>, usize, SupervisorStatus, bool) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let kinds = node.task_supervisor.active_kinds().await;
                let relay_count = node.task_supervisor.relay_count().await;
                let status = node.task_supervisor.status().await;
                let shutdown = node.task_supervisor.is_shutdown();
                if predicate(kinds, relay_count, status, shutdown) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("runtime status should converge");
    }

    #[tokio::test]
    async fn run_registers_listener_connector_future_queue_and_dandelion_tasks() {
        let dir = fresh_test_dir("runtime-registers-core-tasks");
        let mut config = regtest_node_config(&dir);
        config.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        let node = Arc::new(init_test_node(config));
        let run = tokio::spawn(node.clone().run());

        wait_for_supervisor(&node, |kinds, _, status, _| {
            kinds.contains(&TaskKind::Listener)
                && kinds.contains(&TaskKind::Connector)
                && kinds.contains(&TaskKind::FutureQueue)
                && kinds.contains(&TaskKind::DandelionStem)
                && status == SupervisorStatus::Running
        })
        .await;

        node.request_shutdown().await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run should stop after shutdown")
            .expect("join")
            .expect("graceful shutdown");
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test]
    async fn run_registers_miner_only_when_mining_enabled() {
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let dir_off = fresh_test_dir("runtime-miner-disabled");
        let mut config_off = regtest_node_config(&dir_off);
        config_off.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        let node_off = Arc::new(init_test_node(config_off));
        let run_off = tokio::spawn(node_off.clone().run());
        wait_for_supervisor(&node_off, |kinds, _, _, _| {
            !kinds.contains(&TaskKind::Miner) && kinds.contains(&TaskKind::Listener)
        })
        .await;
        node_off.request_shutdown().await;
        tokio::time::timeout(Duration::from_secs(5), run_off)
            .await
            .expect("run should stop")
            .expect("join")
            .expect("shutdown");
        fs::remove_dir_all(&dir_off).expect("cleanup test dir");

        let dir_on = fresh_test_dir("runtime-miner-enabled");
        let mut config_on = regtest_node_config(&dir_on);
        config_on.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        config_on.mine = true;
        let node_on = Arc::new(init_test_node(config_on));
        let run_on = tokio::spawn(node_on.clone().run());
        wait_for_supervisor(&node_on, |kinds, _, _, _| kinds.contains(&TaskKind::Miner)).await;
        node_on.request_shutdown().await;
        tokio::time::timeout(Duration::from_secs(5), run_on)
            .await
            .expect("run should stop")
            .expect("join")
            .expect("shutdown");
        fs::remove_dir_all(&dir_on).expect("cleanup test dir");
    }

    #[tokio::test]
    async fn run_does_not_immediately_shutdown_after_startup() {
        let dir = fresh_test_dir("runtime-long-lived");
        let mut config = regtest_node_config(&dir);
        config.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        let node = Arc::new(init_test_node(config));
        let run = tokio::spawn(node.clone().run());

        wait_for_supervisor(&node, |_, _, status, shutdown| {
            status == SupervisorStatus::Running && !shutdown
        })
        .await;
        assert!(
            !run.is_finished(),
            "DomNode::run must stay alive until explicit shutdown"
        );

        node.request_shutdown().await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run should stop")
            .expect("join")
            .expect("shutdown");
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test]
    async fn relay_worker_registry_is_cleaned_after_worker_exit() {
        let dir = fresh_test_dir("runtime-relay-cleanup");
        let mut config = regtest_node_config(&dir);
        config.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        let listen_addr = config.p2p_listen_addr.clone();
        let node = Arc::new(init_test_node(config));
        let run = tokio::spawn(node.clone().run());

        wait_for_supervisor(&node, |kinds, _, _, _| kinds.contains(&TaskKind::Listener)).await;

        let stream = TcpStream::connect(&listen_addr)
            .await
            .expect("connect test peer");
        wait_for_supervisor(&node, |_, relay_count, _, _| relay_count > 0).await;
        drop(stream);
        wait_for_supervisor(&node, |_, relay_count, _, _| relay_count == 0).await;

        node.request_shutdown().await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run should stop")
            .expect("join")
            .expect("shutdown");
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn noise_static_key_persists_across_store_reopen() {
        let dir = fresh_test_dir("noise-key-reopen");
        let store = open_test_store(&dir);
        let first = load_or_create_noise_static_key(&store).expect("first load/create");
        drop(store);

        let reopened = open_test_store(&dir);
        let second = load_or_create_noise_static_key(&reopened).expect("second load");

        assert_eq!(first, second, "persisted Noise key must survive reopen");
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn node_identity_survives_restart_init() {
        let dir = fresh_test_dir("noise-node-restart");
        let config = regtest_node_config(&dir);

        let first = init_test_node(config.clone());
        let second = init_test_node(config);

        assert_eq!(
            first.noise_privkey, second.noise_privkey,
            "Noise static key must survive restart"
        );
        assert_eq!(
            dom_wire::handshake::derive_static_pubkey(&first.noise_privkey),
            dom_wire::handshake::derive_static_pubkey(&second.noise_privkey),
            "derived public identity must survive restart"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn malformed_persisted_noise_key_is_rejected_without_replacement() {
        let dir = fresh_test_dir("noise-key-corrupt");
        let store = open_test_store(&dir);
        store
            .put_metadata(NOISE_STATIC_KEY_METADATA_KEY, b"corrupt")
            .expect("write corrupt metadata");

        let err = load_or_create_noise_static_key(&store).expect_err("corrupt key should fail");
        let message = err.to_string();
        assert!(
            message.contains("invalid length"),
            "unexpected error message: {message}"
        );
        assert_eq!(
            store
                .get_metadata(NOISE_STATIC_KEY_METADATA_KEY)
                .expect("reload metadata")
                .expect("metadata present"),
            b"corrupt"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn malformed_persisted_noise_key_aborts_node_init() {
        let dir = fresh_test_dir("noise-node-corrupt");
        let store = open_test_store(&dir);
        store
            .put_metadata(NOISE_STATIC_KEY_METADATA_KEY, b"corrupt")
            .expect("write corrupt metadata");
        drop(store);

        let err = match DomNode::init_with_map_size(regtest_node_config(&dir), TEST_LMDB_MAP_SIZE) {
            Ok(_) => panic!("init should fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("persisted Noise static key"),
            "unexpected error message: {message}"
        );

        let reopened = open_test_store(&dir);
        assert_eq!(
            reopened
                .get_metadata(NOISE_STATIC_KEY_METADATA_KEY)
                .expect("reload metadata")
                .expect("metadata present"),
            b"corrupt"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn mempool_is_empty_by_design_after_restart() {
        let dir = fresh_test_dir("mempool-restart-empty");
        let config = regtest_node_config(&dir);
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: commitment(90, 5),
                proof: vec![0x90; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(91, 0),
                excess_signature: [0x91; 65],
            }],
            offset: [0u8; 32],
        };
        let tx_hash = tx_hash(&tx).expect("tx hash");

        let first = init_test_node(config.clone());
        first
            .mempool
            .try_lock()
            .expect("mempool lock")
            .accept_tx(tx, tx_hash, 1)
            .expect("accept runtime tx");
        assert_eq!(first.mempool.try_lock().expect("mempool lock").len(), 1);
        drop(first);

        let second = init_test_node(config);
        assert_eq!(
            second.mempool.try_lock().expect("mempool lock").len(),
            0,
            "mempool must restart empty instead of reconstructing runtime-only state"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    /// TASK 27 / RFC-0012 §2: under the volatile policy there is no persisted
    /// mempool to revalidate on reopen. This proves the two properties that make
    /// that safe: restart is **deterministic** (always empty) and
    /// **consensus-neutral** (the canonical chain tip after restart is identical
    /// regardless of what the mempool held — runtime txs and even a structurally
    /// valid on-disk legacy snapshot — and identical to a node that never had any
    /// mempool activity at all).
    #[test]
    fn chain_validity_is_unaffected_by_mempool_restart_state() {
        // Node A: accept a runtime tx AND plant a structurally valid legacy
        // on-disk mempool snapshot, then capture the canonical chain tip.
        let dir_a = fresh_test_dir("mempool-neutral-a");
        let tip_a_before = {
            let node = init_test_node(regtest_node_config(&dir_a));
            let tx = mempool_tx(0x31, 100);
            let hash = tx_hash(&tx).expect("hash a");
            node.mempool
                .try_lock()
                .expect("mempool lock")
                .accept_tx(tx.clone(), hash, 1)
                .expect("accept runtime tx");
            let chain = node.chain.try_lock().expect("chain lock");
            let mut planted = Mempool::new();
            planted.accept_tx(tx, hash, 1).expect("plant accept");
            persist_mempool_snapshot(&chain.store, &planted.snapshot())
                .expect("plant legacy snapshot");
            (chain.tip_height.0, *chain.tip_hash.as_bytes())
        };

        // Node B (control): never touches the mempool.
        let dir_b = fresh_test_dir("mempool-neutral-b");
        let node_b = init_test_node(regtest_node_config(&dir_b));
        let tip_b = {
            let chain = node_b.chain.try_lock().expect("chain lock b");
            (chain.tip_height.0, *chain.tip_hash.as_bytes())
        };
        assert!(
            node_b
                .mempool
                .try_lock()
                .expect("mempool lock b")
                .is_empty(),
            "control node starts with an empty mempool"
        );
        drop(node_b);

        // Restart A. The chain tip must be byte-identical to before the restart
        // (mempool state did not perturb consensus) and to the control node
        // (chain validity is independent of mempool history). The mempool must be
        // empty and the legacy on-disk snapshot must be gone.
        let restarted = init_test_node(regtest_node_config(&dir_a));
        let tip_a_after = {
            let chain = restarted.chain.try_lock().expect("chain lock a2");
            (chain.tip_height.0, *chain.tip_hash.as_bytes())
        };
        assert_eq!(
            tip_a_after, tip_a_before,
            "chain tip is unchanged by mempool restart state (consensus-neutral)"
        );
        assert_eq!(
            tip_a_after, tip_b,
            "chain validity is identical regardless of mempool history (deterministic)"
        );
        assert_eq!(
            restarted.mempool.try_lock().expect("mempool lock a2").len(),
            0,
            "restart is deterministic: mempool is always empty"
        );
        let reopened = DomStore::open(&dir_a).expect("store reopen a");
        assert!(
            load_mempool_snapshot(&reopened)
                .expect("load mempool a")
                .is_none(),
            "no persisted mempool is trusted or loaded on reopen"
        );

        fs::remove_dir_all(&dir_a).expect("cleanup a");
        fs::remove_dir_all(&dir_b).expect("cleanup b");
    }

    #[test]
    fn unclamped_persisted_noise_key_is_rejected() {
        let raw = [0xff; 32];
        let err = parse_persisted_noise_static_key(&raw).expect_err("unclamped key should fail");
        let message = err.to_string();
        assert!(
            message.contains("canonical clamped form"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn legacy_peer_rotation_snapshot_loads_for_restart_compatibility() {
        use dom_serialization::Writer;

        let dir = fresh_test_dir("peer-rotation-legacy");
        let store = open_test_store(&dir);
        let mut w = Writer::new();
        w.write_u64(3);
        w.write_u32(1);
        w.write_vec(b"198.51.100.30:33369").expect("addr");
        w.write_u8(3);
        w.write_u64(3);
        store
            .put_metadata(LEGACY_PEER_ROTATION_METADATA_KEY, &w.finish())
            .expect("persist legacy peer rotation");

        let snapshot = load_peer_rotation_snapshot(&store)
            .expect("load peer rotation")
            .expect("snapshot present");
        assert_eq!(snapshot.next_failure_seq, 3);
        assert_eq!(snapshot.outbound_failures.len(), 1);
        assert_eq!(snapshot.outbound_failures[0].cooldown_rounds, 0);

        let mut peers = PeerManager::new(125, 2);
        restore_peer_rotation_state(&store, &mut peers).expect("restore peer rotation");
        assert_eq!(peers.outbound_failure_count("198.51.100.30:33369"), 3);
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn invalid_persisted_peer_rotation_aborts_node_init_without_clearing_state() {
        let dir = fresh_test_dir("peer-rotation-invalid");
        let store = open_test_store(&dir);
        store
            .put_metadata(PEER_ROTATION_METADATA_KEY, b"invalid")
            .expect("persist invalid peer rotation");
        drop(store);

        let err = match DomNode::init_with_map_size(regtest_node_config(&dir), TEST_LMDB_MAP_SIZE) {
            Ok(_) => panic!("invalid peer rotation should fail init"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("peer rotation"),
            "unexpected error message: {message}"
        );

        let reopened = open_test_store(&dir);
        assert_eq!(
            reopened
                .get_metadata(PEER_ROTATION_METADATA_KEY)
                .expect("reload metadata")
                .expect("metadata present"),
            b"invalid"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn missing_persisted_peer_reputation_starts_empty() {
        let dir = fresh_test_dir("peer-reputation-empty");
        let store = open_test_store(&dir);
        assert!(load_peer_reputation_snapshot(&store)
            .expect("load peer reputation")
            .is_none());

        let node = init_test_node(regtest_node_config(&dir));
        let peers = node.peers.try_lock().expect("peer lock");
        assert_eq!(peers.pending_penalty_count(), 0);
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn peer_score_survives_restart_init() {
        let dir = fresh_test_dir("peer-reputation-restart");
        let store = open_test_store(&dir);
        let mut peers = PeerManager::new(125, 8);
        let peer = PeerInfo::new("10.0.0.42:33369".parse().expect("peer addr"), false);
        let addr = peer.addr.to_string();
        peers.register_peer(peer).expect("register peer");
        assert!(!peers.add_ban_score(&addr, 35));
        persist_peer_reputation_snapshot(&store, &peers.peer_reputation_state())
            .expect("persist peer reputation");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        let peers = node.peers.try_lock().expect("peer lock");
        assert_eq!(peers.pending_ban_score(&addr), 35);
        assert_eq!(peers.ban_score(&addr), None);
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn banned_peer_remains_banned_after_restart() {
        let dir = fresh_test_dir("peer-reputation-ban-restart");
        let store = open_test_store(&dir);
        let mut peers = PeerManager::new(125, 8);
        let addr = "10.0.0.43:33369";
        assert_eq!(
            peers.add_pending_ban_score(addr, ban_scores::BAN_THRESHOLD),
            100
        );
        persist_peer_reputation_snapshot(&store, &peers.peer_reputation_state())
            .expect("persist peer reputation");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        let mut peers = node.peers.try_lock().expect("peer lock");
        assert_eq!(peers.pending_ban_score(addr), ban_scores::BAN_THRESHOLD);
        assert!(peers.reserve_outbound(addr).is_err());
        assert!(
            peers
                .reserve_inbound(addr.parse().expect("peer addr"))
                .is_err(),
            "persisted ban should block later inbound retry"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn wrong_network_ban_score_survives_restart() {
        let dir = fresh_test_dir("peer-reputation-wrong-network");
        let store = open_test_store(&dir);
        let snapshot = PersistedPeerReputationState {
            entries: vec![dom_wire::manager::PersistedPeerReputation {
                addr: "10.0.0.44:33369".into(),
                score: ban_scores::WRONG_CHAIN_ID,
            }],
        };
        persist_peer_reputation_snapshot(&store, &snapshot).expect("persist peer reputation");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        let peers = node.peers.try_lock().expect("peer lock");
        assert_eq!(
            peers.pending_ban_score("10.0.0.44:33369"),
            ban_scores::WRONG_CHAIN_ID
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn invalid_persisted_peer_reputation_aborts_node_init_without_clearing_state() {
        let dir = fresh_test_dir("peer-reputation-invalid");
        let store = open_test_store(&dir);
        store
            .put_metadata(PEER_REPUTATION_METADATA_KEY, b"invalid")
            .expect("persist invalid peer reputation");
        drop(store);

        let err = match DomNode::init_with_map_size(regtest_node_config(&dir), TEST_LMDB_MAP_SIZE) {
            Ok(_) => panic!("invalid peer reputation should fail init"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("peer reputation"),
            "unexpected error message: {message}"
        );

        let reopened = open_test_store(&dir);
        assert_eq!(
            reopened
                .get_metadata(PEER_REPUTATION_METADATA_KEY)
                .expect("reload metadata")
                .expect("metadata present"),
            b"invalid"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn peer_reputation_persistence_remains_separate_from_noise_identity() {
        let dir = fresh_test_dir("peer-reputation-separate-identity");
        let store = open_test_store(&dir);
        let noise = load_or_create_noise_static_key(&store).expect("noise key");
        let snapshot = PersistedPeerReputationState {
            entries: vec![dom_wire::manager::PersistedPeerReputation {
                addr: "10.0.0.45:33369".into(),
                score: 20,
            }],
        };
        persist_peer_reputation_snapshot(&store, &snapshot).expect("persist peer reputation");
        drop(store);

        let reopened = open_test_store(&dir);
        assert_eq!(
            reopened
                .get_metadata(NOISE_STATIC_KEY_METADATA_KEY)
                .expect("noise metadata")
                .expect("noise key present"),
            noise.to_vec()
        );
        assert_eq!(
            load_peer_reputation_snapshot(&reopened)
                .expect("load peer reputation")
                .expect("peer reputation present"),
            snapshot
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn persisted_mempool_snapshot_is_cleared_and_not_restored_on_restart_init() {
        let dir = fresh_test_dir("mempool-restart-legacy-snapshot");
        let store = open_test_store(&dir);
        let tx_a = mempool_tx(0x21, 100);
        let tx_b = mempool_tx(0x22, 200);
        let hash_a = tx_hash(&tx_a).expect("hash a");
        let hash_b = tx_hash(&tx_b).expect("hash b");
        let mut mempool = Mempool::new();
        mempool
            .accept_tx(tx_b.clone(), hash_b, 2)
            .expect("accept b");
        mempool
            .accept_tx(tx_a.clone(), hash_a, 1)
            .expect("accept a");
        persist_mempool_snapshot(&store, &mempool.snapshot()).expect("persist mempool");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        assert_eq!(
            node.mempool.blocking_lock().len(),
            0,
            "legacy mempool snapshot must not be restored into runtime state"
        );

        let reopened = open_test_store(&dir);
        assert!(
            load_mempool_snapshot(&reopened)
                .expect("load mempool")
                .is_none(),
            "legacy mempool snapshot metadata must be cleared on restart"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn invalid_persisted_mempool_is_ignored_and_cleared_on_restart_init() {
        let dir = fresh_test_dir("mempool-invalid");
        let store = open_test_store(&dir);
        store
            .put_metadata(MEMPOOL_METADATA_KEY, b"invalid")
            .expect("persist invalid mempool");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        assert_eq!(
            node.mempool.try_lock().expect("mempool lock").len(),
            0,
            "invalid legacy mempool metadata must not reconstruct runtime state"
        );

        let reopened = open_test_store(&dir);
        assert!(
            reopened
                .get_metadata(MEMPOOL_METADATA_KEY)
                .expect("reload metadata")
                .is_none(),
            "invalid legacy mempool metadata should be cleared explicitly"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn clear_persisted_mempool_snapshot_removes_legacy_metadata() {
        let dir = fresh_test_dir("mempool-clear-legacy");
        let store = open_test_store(&dir);
        store
            .put_metadata(MEMPOOL_METADATA_KEY, b"stale")
            .expect("persist legacy mempool metadata");

        clear_persisted_mempool_snapshot(&store).expect("clear mempool metadata");
        assert!(store
            .get_metadata(MEMPOOL_METADATA_KEY)
            .expect("reload metadata")
            .is_none());
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn malformed_message_maps_to_malformed_score() {
        assert_eq!(
            peer_violation_score(&DomError::Malformed("bad frame".into())),
            Some(ban_scores::MALFORMED_MESSAGE)
        );
    }

    #[test]
    fn wrong_network_identity_maps_to_immediate_ban_score() {
        assert_eq!(
            peer_violation_score(&DomError::Invalid("chain_id mismatch".into())),
            Some(ban_scores::WRONG_CHAIN_ID)
        );
        assert_eq!(
            peer_violation_score(&DomError::Invalid("network_magic mismatch".into())),
            Some(ban_scores::WRONG_CHAIN_ID)
        );
    }

    #[test]
    fn temporary_peer_errors_do_not_score() {
        assert_eq!(
            peer_violation_score(&DomError::TemporarilyInvalid("future block".into())),
            None
        );
        assert_eq!(
            peer_violation_score(&DomError::Orphan("missing parent".into())),
            None
        );
    }

    #[test]
    fn pre_registration_handshake_timeout_scores() {
        assert_eq!(
            pending_peer_violation_score(&DomError::PolicyRejected(
                "handshake timeout after 10s".into()
            )),
            Some(ban_scores::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn pre_registration_hello_timeout_scores() {
        assert_eq!(
            pending_peer_violation_score(&DomError::PolicyRejected(
                "hello timeout after 10s".into()
            )),
            Some(ban_scores::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn deferred_best_chain_replays_to_relay() {
        assert_eq!(
            deferred_replay_action(&Ok(ConnectResult::BestChain)),
            DeferredReplayAction::RelayBestChain
        );
        assert_eq!(
            deferred_replay_action(&Ok(ConnectResult::Reorg(ReorgDelta::default()))),
            DeferredReplayAction::RelayBestChain
        );
    }

    #[test]
    fn deferred_retryable_rejections_requeue() {
        assert_eq!(
            deferred_replay_action(&Err(DomError::TemporarilyInvalid("future block".into()))),
            DeferredReplayAction::Requeue
        );
        assert_eq!(
            deferred_replay_action(&Err(DomError::Orphan("missing parent".into()))),
            DeferredReplayAction::Requeue
        );
    }

    #[test]
    fn deferred_non_retryable_outcomes_drop() {
        assert_eq!(
            deferred_replay_action(&Ok(ConnectResult::SideChain)),
            DeferredReplayAction::Drop
        );
        assert_eq!(
            deferred_replay_action(&Ok(ConnectResult::AlreadyHave)),
            DeferredReplayAction::Drop
        );
        assert_eq!(
            deferred_replay_action(&Err(DomError::Malformed("bad deferred bytes".into()))),
            DeferredReplayAction::Drop
        );
        assert_eq!(
            deferred_replay_action(&Err(DomError::Invalid("bad block".into()))),
            DeferredReplayAction::Drop
        );
        assert_eq!(
            deferred_replay_action(&Err(DomError::Internal("store failure".into()))),
            DeferredReplayAction::Drop
        );
    }

    #[test]
    fn relay_best_chain_rebroadcasts() {
        assert_eq!(
            relay_block_action(&Ok(ConnectResult::BestChain)),
            RelayBlockAction::RelayBestChain
        );
        assert_eq!(
            relay_block_action(&Ok(ConnectResult::Reorg(ReorgDelta::default()))),
            RelayBlockAction::RelayBestChain
        );
    }

    #[tokio::test]
    async fn reorg_mempool_reconciliation_reinjects_live_txs_and_evicts_conflicts() {
        let dir = fresh_test_dir("reorg-mempool-reconcile");
        let chain = open_chain(&dir);
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let chain_id = {
            let c = chain.lock().await;
            *dom_consensus::derive_chain_id(c.network_magic, &c.genesis_hash).as_bytes()
        };

        let base_value = 500_000;
        let base_blinding = scalar(40);
        let base_output = Commitment::commit(base_value, &base_blinding);
        let base_tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: base_output.clone(),
                proof: vec![0x40; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(41, 0),
                excess_signature: [0x41; 65],
            }],
            offset: [0u8; 32],
        };
        let base_block =
            synthetic_block_with_transactions(Hash256::ZERO, 1, 11, 42, vec![base_tx.clone()]);
        commit_chain_block(&chain, &base_block).await;

        let disconnected_tx = signed_spend_tx(
            base_value,
            base_blinding,
            MIN_RELAY_FEE_RATE * 100,
            50,
            51,
            &chain_id,
        );
        let conflicting_input = commitment(60, 30);
        let conflicting_live_tx = synthetic_spend_tx(conflicting_input.clone(), 61, 62);
        let conflicting_live_hash = tx_hash(&conflicting_live_tx).expect("hash");
        {
            let mut pool = mempool.lock().await;
            pool.accept_tx(conflicting_live_tx, conflicting_live_hash, 1)
                .expect("accept conflicting tx");
        }
        let connected_tx = synthetic_spend_tx(conflicting_input, 63, 64);
        let reorg = ReorgDelta {
            disconnected_txs: vec![disconnected_tx.clone()],
            connected_txs: vec![connected_tx],
            ..Default::default()
        };

        reconcile_mempool_after_connect(&chain, &mempool, &ConnectResult::Reorg(reorg), &[])
            .await
            .expect("reconcile reorg mempool");

        let disconnected_hash = tx_hash(&disconnected_tx).expect("hash");
        let pool = mempool.lock().await;
        assert!(
            pool.get_tx(&disconnected_hash).is_some(),
            "live disconnected tx must be resurrected deterministically"
        );
        assert!(
            pool.get_tx(&conflicting_live_hash).is_none(),
            "connected-branch input must evict conflicting mempool tx"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test]
    async fn reorg_reinjection_is_canonical_and_chainstate_aware() {
        let dir = fresh_test_dir("reorg-reinject-canonical");
        let chain = open_chain(&dir);
        let mempool_a = Arc::new(Mutex::new(Mempool::new()));
        let mempool_b = Arc::new(Mutex::new(Mempool::new()));
        let chain_id = {
            let c = chain.lock().await;
            *dom_consensus::derive_chain_id(c.network_magic, &c.genesis_hash).as_bytes()
        };

        let live_value = 500_000;
        let live_blinding = scalar(70);
        let live_output = Commitment::commit(live_value, &live_blinding);
        let base_tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: live_output.clone(),
                proof: vec![0x70; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(71, 0),
                excess_signature: [0x71; 65],
            }],
            offset: [0u8; 32],
        };
        let base_block = synthetic_block_with_transactions(Hash256::ZERO, 1, 17, 72, vec![base_tx]);
        commit_chain_block(&chain, &base_block).await;

        let conflict_a = signed_spend_tx(
            live_value,
            live_blinding.clone(),
            MIN_RELAY_FEE_RATE * 100,
            73,
            74,
            &chain_id,
        );
        let conflict_b = signed_spend_tx(
            live_value,
            live_blinding,
            MIN_RELAY_FEE_RATE * 100,
            75,
            76,
            &chain_id,
        );
        let missing_input_tx = signed_spend_tx(
            500_000,
            scalar(77),
            MIN_RELAY_FEE_RATE * 100,
            78,
            79,
            &chain_id,
        );
        let immature_coinbase_tx = signed_spend_tx(
            1_000_001,
            scalar(72),
            MIN_RELAY_FEE_RATE * 100,
            80,
            81,
            &chain_id,
        );

        let delta_a = ReorgDelta {
            disconnected_txs: vec![
                conflict_b.clone(),
                missing_input_tx.clone(),
                immature_coinbase_tx.clone(),
                conflict_a.clone(),
            ],
            connected_txs: vec![],
            ..Default::default()
        };
        let delta_b = ReorgDelta {
            disconnected_txs: vec![
                conflict_a.clone(),
                immature_coinbase_tx,
                missing_input_tx,
                conflict_b.clone(),
            ],
            connected_txs: vec![],
            ..Default::default()
        };

        reconcile_mempool_after_connect(&chain, &mempool_a, &ConnectResult::Reorg(delta_a), &[])
            .await
            .expect("reconcile canonical order A");
        reconcile_mempool_after_connect(&chain, &mempool_b, &ConnectResult::Reorg(delta_b), &[])
            .await
            .expect("reconcile canonical order B");

        let conflict_a_hash = tx_hash(&conflict_a).expect("hash");
        let conflict_b_hash = tx_hash(&conflict_b).expect("hash");
        let winner = conflict_a_hash.min(conflict_b_hash);
        let loser = conflict_a_hash.max(conflict_b_hash);

        let pool_a = mempool_a.lock().await;
        let pool_b = mempool_b.lock().await;
        assert_eq!(pool_a.all_hashes(), vec![winner]);
        assert_eq!(pool_b.all_hashes(), vec![winner]);
        assert!(pool_a.get_tx(&winner).is_some());
        assert!(pool_a.get_tx(&loser).is_none());
        assert!(
            pool_b.all_hashes() == pool_a.all_hashes(),
            "repeated reinjection over the same inputs must converge identically"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    /// RFC-0012 §3.2: a disconnected transaction carrying a coinbase/system kernel
    /// feature must never be reinjected into the relay mempool, even when its
    /// inputs are live under the new canonical chain. A sibling plain transaction
    /// over a different live output is reinjected, proving the exclusion is
    /// specific to the coinbase feature and not a blanket drop.
    #[tokio::test]
    async fn reorg_reinjection_excludes_coinbase_feature_transactions() {
        let dir = fresh_test_dir("reorg-reinject-coinbase-excluded");
        let chain = open_chain(&dir);
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let chain_id = {
            let c = chain.lock().await;
            *dom_consensus::derive_chain_id(c.network_magic, &c.genesis_hash).as_bytes()
        };

        // Two live outputs created by a base block.
        let live_a_value = 500_000;
        let live_b_value = 600_000;
        let live_a_blinding = scalar(110);
        let live_b_blinding = scalar(112);
        let live_a = Commitment::commit(live_a_value, &live_a_blinding);
        let live_b = Commitment::commit(live_b_value, &live_b_blinding);
        let base_tx = Transaction {
            inputs: vec![],
            outputs: vec![
                TransactionOutput {
                    commitment: live_a.clone(),
                    proof: vec![0xA0; 8],
                },
                TransactionOutput {
                    commitment: live_b.clone(),
                    proof: vec![0xB0; 8],
                },
            ],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(114, 0),
                excess_signature: [0xC0; 65],
            }],
            offset: [0u8; 32],
        };
        let base_block =
            synthetic_block_with_transactions(Hash256::ZERO, 1, 23, 120, vec![base_tx]);
        commit_chain_block(&chain, &base_block).await;

        // Plain tx over live_a — eligible. Coinbase-feature tx over live_b —
        // forbidden for relay despite a live input.
        let plain_tx = signed_spend_tx(
            live_a_value,
            live_a_blinding,
            MIN_RELAY_FEE_RATE * 100,
            130,
            131,
            &chain_id,
        );
        let mut coinbase_feature_tx = signed_spend_tx(
            live_b_value,
            live_b_blinding,
            MIN_RELAY_FEE_RATE * 100,
            132,
            133,
            &chain_id,
        );
        coinbase_feature_tx.kernels[0].features = dom_core::KERNEL_FEAT_COINBASE;

        let reorg = ReorgDelta {
            disconnected_txs: vec![coinbase_feature_tx.clone(), plain_tx.clone()],
            connected_txs: vec![],
            ..Default::default()
        };
        reconcile_mempool_after_connect(&chain, &mempool, &ConnectResult::Reorg(reorg), &[])
            .await
            .expect("reconcile reorg mempool");

        let pool = mempool.lock().await;
        assert!(
            pool.get_tx(&tx_hash(&plain_tx).expect("hash")).is_some(),
            "plain tx over a live output must be reinjected"
        );
        assert!(
            pool.get_tx(&tx_hash(&coinbase_feature_tx).expect("hash"))
                .is_none(),
            "coinbase/system-feature tx must be excluded from reinjection"
        );
        assert_eq!(pool.len(), 1, "exactly the eligible plain tx is reinjected");
        drop(pool);
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    /// RFC-0012 §3.4: two nodes that experience the same reorg but originally
    /// received the disconnected transactions in different orders converge to the
    /// same canonical mempool **digest**. This pins the convergence guarantee to
    /// the byte-level digest, not just the hash listing.
    #[tokio::test]
    async fn reorg_reinjection_converges_to_same_digest_across_delivery_order() {
        let dir = fresh_test_dir("reorg-reinject-digest-converge");
        let chain = open_chain(&dir);
        let mempool_a = Arc::new(Mutex::new(Mempool::new()));
        let mempool_b = Arc::new(Mutex::new(Mempool::new()));
        let chain_id = {
            let c = chain.lock().await;
            *dom_consensus::derive_chain_id(c.network_magic, &c.genesis_hash).as_bytes()
        };

        // Three independent live outputs → three non-conflicting eligible txs.
        let live_values = [500_000, 600_000, 700_000];
        let live_blindings = [scalar(140), scalar(142), scalar(144)];
        let live = [
            Commitment::commit(live_values[0], &live_blindings[0]),
            Commitment::commit(live_values[1], &live_blindings[1]),
            Commitment::commit(live_values[2], &live_blindings[2]),
        ];
        let base_tx = Transaction {
            inputs: vec![],
            outputs: live
                .iter()
                .enumerate()
                .map(|(i, c)| TransactionOutput {
                    commitment: c.clone(),
                    proof: vec![0xD0 + i as u8; 8],
                })
                .collect(),
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(146, 0),
                excess_signature: [0xE0; 65],
            }],
            offset: [0u8; 32],
        };
        let base_block =
            synthetic_block_with_transactions(Hash256::ZERO, 1, 29, 150, vec![base_tx]);
        commit_chain_block(&chain, &base_block).await;

        let t0 = signed_spend_tx(
            live_values[0],
            live_blindings[0].clone(),
            MIN_RELAY_FEE_RATE * 100,
            160,
            161,
            &chain_id,
        );
        let t1 = signed_spend_tx(
            live_values[1],
            live_blindings[1].clone(),
            MIN_RELAY_FEE_RATE * 100,
            162,
            163,
            &chain_id,
        );
        let t2 = signed_spend_tx(
            live_values[2],
            live_blindings[2].clone(),
            MIN_RELAY_FEE_RATE * 100,
            164,
            165,
            &chain_id,
        );

        // Different delivery orders into A and B.
        let delta_a = ReorgDelta {
            disconnected_txs: vec![t2.clone(), t0.clone(), t1.clone()],
            connected_txs: vec![],
            ..Default::default()
        };
        let delta_b = ReorgDelta {
            disconnected_txs: vec![t1.clone(), t2.clone(), t0.clone()],
            connected_txs: vec![],
            ..Default::default()
        };
        reconcile_mempool_after_connect(&chain, &mempool_a, &ConnectResult::Reorg(delta_a), &[])
            .await
            .expect("reconcile A");
        reconcile_mempool_after_connect(&chain, &mempool_b, &ConnectResult::Reorg(delta_b), &[])
            .await
            .expect("reconcile B");

        let pool_a = mempool_a.lock().await;
        let pool_b = mempool_b.lock().await;
        assert_eq!(pool_a.len(), 3, "all three eligible txs reinjected");
        assert_eq!(
            pool_a.digest(),
            pool_b.digest(),
            "reorg reinjection converges to the same mempool digest regardless of delivery order"
        );
        drop(pool_a);
        drop(pool_b);
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn relay_duplicates_and_retryable_errors_are_suppressed() {
        assert_eq!(
            relay_block_action(&Ok(ConnectResult::SideChain)),
            RelayBlockAction::Suppress
        );
        assert_eq!(
            relay_block_action(&Ok(ConnectResult::AlreadyHave)),
            RelayBlockAction::Suppress
        );
        assert_eq!(
            relay_block_action(&Err(DomError::TemporarilyInvalid("future block".into()))),
            RelayBlockAction::Suppress
        );
        assert_eq!(
            relay_block_action(&Err(DomError::Orphan("missing parent".into()))),
            RelayBlockAction::Suppress
        );
    }

    #[test]
    fn relay_invalid_or_malformed_errors_penalize_peers() {
        assert_eq!(
            relay_block_action(&Err(DomError::Invalid("bad block".into()))),
            RelayBlockAction::PenalizePeer
        );
        assert_eq!(
            relay_block_action(&Err(DomError::Malformed("bad payload".into()))),
            RelayBlockAction::PenalizePeer
        );
        assert_eq!(
            relay_block_action(&Err(DomError::Internal("store failure".into()))),
            RelayBlockAction::Drop
        );
    }

    #[test]
    fn malformed_relay_payload_is_rejected_before_block_decode() {
        let err = decode_relay_block(&[0xde, 0xad]).expect_err("short payload must fail");
        assert!(matches!(err, DomError::Malformed(_)));
    }

    #[test]
    fn oversized_relay_payload_is_rejected_without_allocating_block_body() {
        let oversized = ((MAX_BLOCK_SERIALIZED_SIZE + 1) as u32).to_le_bytes();
        let err = decode_relay_block(&oversized).expect_err("oversized payload must fail");
        assert!(
            matches!(err, DomError::Malformed(ref msg) if msg.contains("block too large")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn malformed_relay_block_body_is_rejected() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(3u32).to_le_bytes());
        payload.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

        let err = decode_relay_block(&payload).expect_err("malformed block body must fail");
        assert!(matches!(err, DomError::Malformed(_)));
    }

    #[test]
    fn ibd_block_response_rejects_hash_mismatch() {
        let expected = synthetic_block(1, 11);
        let wrong = synthetic_block(1, 22);
        let err = decode_ibd_block_response(&ibd_payload(&wrong), block_hash(&expected))
            .expect_err("mismatched IBD block must reject");
        assert!(
            matches!(err, DomError::Invalid(ref msg) if msg.contains("hash mismatch")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ibd_block_response_accepts_requested_block() {
        let block = synthetic_block(2, 33);
        let decoded = decode_ibd_block_response(&ibd_payload(&block), block_hash(&block))
            .expect("matching IBD block must decode");
        assert_eq!(decoded.1.header.height.0, 2);
        assert_eq!(decoded.1.header.pow.nonce, 33);
    }

    #[tokio::test]
    async fn invariant_ibd_import_rejects_header_and_pmmr_valid_but_economically_unbalanced_block()
    {
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let dir = fresh_test_dir("ibd-invalid-economic-balance");
        let chain = open_chain(&dir);
        let chain_id = {
            use dom_consensus::derive_chain_id;
            *derive_chain_id(
                NETWORK_MAGIC_REGTEST,
                &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
            )
            .as_bytes()
        };

        let genesis = build_coinbase_only_block(
            [0u8; 32],
            Hash256::ZERO,
            BlockHeight::GENESIS,
            U256::zero(),
            [0u8; 32],
            &chain_id,
        );
        {
            let mut guard = chain.lock().await;
            guard
                .connect_block(&genesis, safe_now())
                .expect("connect genesis");
        }

        let mut invalid_offset = [0u8; 32];
        invalid_offset[31] = 1;
        let invalid = build_coinbase_only_block(
            block_hash(&genesis),
            Hash256::from_bytes(block_hash(&genesis)),
            BlockHeight(1),
            genesis.header.total_difficulty,
            invalid_offset,
            &chain_id,
        );
        let payload = ibd_payload(&invalid);
        let (_, decoded) = decode_ibd_block_response(&payload, block_hash(&invalid))
            .expect("IBD payload itself must decode and hash-match");

        let err = {
            let mut guard = chain.lock().await;
            guard
                .connect_block(&decoded, safe_now())
                .expect_err("IBD import must reject economic imbalance")
        };
        let msg = err.to_string();
        assert!(
            msg.contains("aggregate") || msg.contains("balance"),
            "expected economic-balance rejection, got: {msg}"
        );

        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[test]
    fn malformed_deferred_block_bytes_are_dropped_on_decode() {
        let err = decode_deferred_block_bytes(&[0x01, 0x02, 0x03])
            .expect_err("malformed deferred bytes must fail");
        assert!(matches!(err, DomError::Malformed(_)));
    }

    #[test]
    fn outbound_attempt_outcome_marks_retryable_failures_only() {
        assert_eq!(
            OutboundAttemptOutcome::RetryableFailure,
            OutboundAttemptOutcome::RetryableFailure
        );
        assert_ne!(
            OutboundAttemptOutcome::RetryableFailure,
            OutboundAttemptOutcome::Registered
        );
    }

    #[tokio::test]
    async fn refresh_peer_metrics_counts_connected_peer_directions() {
        let peers = Arc::new(Mutex::new(PeerManager::new(125, 8)));
        let metrics = Arc::new(Metrics::new());

        let inbound_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 33369);
        let mut inbound = PeerInfo::new(inbound_addr, false);
        inbound.state = PeerState::Connected;

        let outbound_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 33369);
        let mut outbound = PeerInfo::new(outbound_addr, true);
        outbound.state = PeerState::Connected;

        let banned_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 33369);
        let mut banned = PeerInfo::new(banned_addr, false);
        banned.state = PeerState::Banned;

        {
            let mut mgr = peers.lock().await;
            mgr.register_peer(inbound).expect("register inbound");
            mgr.register_peer(outbound).expect("register outbound");
            mgr.peers.insert(banned_addr.to_string(), banned);
        }

        refresh_peer_metrics(&peers, &metrics, None).await;

        assert_eq!(metrics.peer_count.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.inbound_peers.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.outbound_peers.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn refresh_peer_metrics_ignores_failed_outbound_reservations() {
        let peers = Arc::new(Mutex::new(PeerManager::new(125, 1)));
        let metrics = Arc::new(Metrics::new());

        {
            let mut mgr = peers.lock().await;
            mgr.reserve_outbound("203.0.113.44:33369")
                .expect("reserve outbound");
        }
        refresh_peer_metrics(&peers, &metrics, None).await;

        assert_eq!(metrics.peer_count.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.inbound_peers.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.outbound_peers.load(Ordering::Relaxed), 0);

        {
            let mut mgr = peers.lock().await;
            mgr.release_outbound_reservation("203.0.113.44:33369");
        }
        refresh_peer_metrics(&peers, &metrics, None).await;

        assert_eq!(metrics.peer_count.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.inbound_peers.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.outbound_peers.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn best_chain_cleanup_purges_mempool_conflicts_by_input() {
        let dir = fresh_test_dir("mempool-purge");
        let chain = open_chain(&dir);
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let shared_input = commitment(9, 50);
        let tx = spending_tx(shared_input, 0x21);
        let tx_hash = [0x21; 32];
        {
            let mut pool = mempool.lock().await;
            pool.accept_tx(tx.clone(), tx_hash, 0).expect("accept tx");
            assert_eq!(pool.len(), 1);
        }

        purge_mempool_confirmed_inputs(&chain, &mempool, &[tx])
            .await
            .expect("purge mempool");

        let pool = mempool.lock().await;
        assert_eq!(
            pool.len(),
            0,
            "confirmed inputs must be purged from mempool"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    /// DOM-AUDIT-001 regression. `resume_ibd_block_sync` used to call
    /// `purge_mempool_confirmed_inputs` while the chain guard `c` from
    /// `connect_block` was still alive. `purge` re-acquires the chain lock via
    /// `persist_mempool_state`, and tokio's `Mutex` is NOT reentrant, so the IBD
    /// task deadlocked on its own guard. The fix captures the `ConnectResult`
    /// under the guard, drops it, and only then purges + applies to the wallet.
    ///
    /// This test pins both halves of the invariant on the non-empty purge path
    /// (a non-coinbase tx whose input commitment is live in the mempool, which
    /// forces the re-acquiring `persist_mempool_state` branch):
    ///   1. holding the chain guard across `purge` deadlocks (pre-fix behaviour),
    ///   2. dropping it first lets `purge` complete and empties the mempool.
    /// The deadlock is detected with a short `tokio::time::timeout`: the IBD task
    /// parks forever on the self-held mutex while the runtime's timer driver
    /// still fires the timeout, so the pre-fix branch resolves to `Err(Elapsed)`
    /// rather than hanging the test. The fixed branch completes in microseconds,
    /// well inside its (deliberately generous) timeout.
    #[tokio::test]
    async fn ibd_resume_purge_after_connect_does_not_deadlock_on_chain_relock() {
        let dir = fresh_test_dir("ibd-purge-relock");
        let chain = open_chain(&dir);
        let shared_input = commitment(9, 50);

        // (1) Pre-fix pattern: chain guard held across purge -> must deadlock.
        {
            let mempool = Arc::new(Mutex::new(Mempool::new()));
            let tx = spending_tx(shared_input.clone(), 0x21);
            {
                let mut pool = mempool.lock().await;
                pool.accept_tx(tx.clone(), [0x21; 32], 0)
                    .expect("accept tx");
                assert_eq!(pool.len(), 1);
            }

            let guard = chain.lock().await;
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                purge_mempool_confirmed_inputs(&chain, &mempool, &[tx]),
            )
            .await;
            assert!(
                outcome.is_err(),
                "purge while holding the chain guard must deadlock on the re-acquire (DOM-AUDIT-001)"
            );
            drop(guard);
        }

        // (2) Fixed pattern: guard dropped before purge -> completes + purges.
        {
            let mempool = Arc::new(Mutex::new(Mempool::new()));
            let tx = spending_tx(shared_input, 0x22);
            {
                let mut pool = mempool.lock().await;
                pool.accept_tx(tx.clone(), [0x22; 32], 0)
                    .expect("accept tx");
                assert_eq!(pool.len(), 1);
            }

            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                purge_mempool_confirmed_inputs(&chain, &mempool, &[tx]),
            )
            .await
            .expect("purge must not deadlock once the chain guard is dropped")
            .expect("purge succeeds");

            assert_eq!(
                mempool.lock().await.len(),
                0,
                "confirmed inputs must be purged once the chain guard is released"
            );
        }

        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test]
    async fn persisted_header_resume_completes_with_canonical_snapshot_cleanup() {
        let dir = fresh_test_dir("header-resume-ok");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");
        let checkpoint_tip_hash = { *chain.lock().await.tip_hash.as_bytes() };

        let header1 = synthetic_known_header(0, Hash256::ZERO, 1);
        let header2 = synthetic_known_header(1, Hash256::from_bytes(header_hash(&header1)), 2);
        store_known_header(&chain, &header1).await;
        store_known_header(&chain, &header2).await;

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: peer_addr.to_string(),
            start_height: 0,
            best_peer_height: 1,
            headers_height: 0,
            blocks_height: 0,
            last_progress_height: 0,
            checkpoint_tip_hash,
            retry_attempts: 0,
            last_interruption: None,
            pending_blocks: Vec::new(),
            pending_headers: vec![
                header1.to_bytes().expect("header1 bytes"),
                header2.to_bytes().expect("header2 bytes"),
            ],
            block_cursor: 0,
            header_cursor: 1,
            header_cursor_height: 1,
        };
        {
            let chain = chain.lock().await;
            snapshot.save(&chain.store).expect("save snapshot");
        }

        let (mut ibd, restored) = initialize_ibd_state(&chain, peer_addr, 1)
            .await
            .expect("initialize");
        let restored = restored.expect("restored snapshot");
        let pending_blocks = continue_ibd_header_sync(
            &chain,
            peer_addr,
            &mut ibd,
            IbdRoundState {
                pending_blocks: restored.pending_blocks.clone(),
                pending_headers: restored.pending_headers.clone(),
                block_cursor: restored.block_cursor,
                header_cursor: restored.header_cursor,
                header_cursor_height: restored.header_cursor_height,
            },
            ibd_now(),
        )
        .await
        .expect("resume header sync");

        assert!(pending_blocks.is_empty());
        assert_eq!(ibd.headers_height, 1);
        assert_eq!(ibd.phase, IbdPhase::Discovering);

        let persisted = {
            let chain = chain.lock().await;
            PersistedIbdState::load(&chain.store)
                .expect("load snapshot")
                .expect("snapshot present")
        };
        assert!(persisted.pending_headers.is_empty());
        assert!(persisted.pending_blocks.is_empty());
        assert_eq!(persisted.header_cursor, 0);
        assert_eq!(persisted.headers_height, 1);
        assert_eq!(persisted.phase, IbdPhase::Discovering);
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test]
    async fn persisted_header_resume_rejects_corrupted_continuation() {
        let dir = fresh_test_dir("header-resume-bad");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");
        let checkpoint_tip_hash = { *chain.lock().await.tip_hash.as_bytes() };

        let header1 = synthetic_known_header(0, Hash256::ZERO, 1);
        let mut header2 = synthetic_known_header(1, Hash256::from_bytes(header_hash(&header1)), 2);
        header2.prev_hash = Hash256::from_bytes([0x99; 32]);
        store_known_header(&chain, &header1).await;

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: peer_addr.to_string(),
            start_height: 0,
            best_peer_height: 1,
            headers_height: 0,
            blocks_height: 0,
            last_progress_height: 0,
            checkpoint_tip_hash,
            retry_attempts: 0,
            last_interruption: None,
            pending_blocks: Vec::new(),
            pending_headers: vec![
                header1.to_bytes().expect("header1 bytes"),
                header2.to_bytes().expect("header2 bytes"),
            ],
            block_cursor: 0,
            header_cursor: 1,
            header_cursor_height: 1,
        };
        {
            let chain = chain.lock().await;
            snapshot.save(&chain.store).expect("save snapshot");
        }

        let (mut ibd, restored) = initialize_ibd_state(&chain, peer_addr, 1)
            .await
            .expect("initialize");
        let restored = restored.expect("restored snapshot should remain resumable");
        let err = continue_ibd_header_sync(
            &chain,
            peer_addr,
            &mut ibd,
            IbdRoundState {
                pending_blocks: restored.pending_blocks.clone(),
                pending_headers: restored.pending_headers.clone(),
                block_cursor: restored.block_cursor,
                header_cursor: restored.header_cursor,
                header_cursor_height: restored.header_cursor_height,
            },
            ibd_now(),
        )
        .await
        .expect_err("corrupted continuation must reject");

        assert!(
            matches!(err, DomError::Invalid(ref msg) if msg.contains("prev_hash mismatch")),
            "unexpected error: {err}"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test]
    async fn persisted_header_resume_rejects_malformed_header_bytes() {
        let dir = fresh_test_dir("header-resume-malformed");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");
        let checkpoint_tip_hash = { *chain.lock().await.tip_hash.as_bytes() };

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: peer_addr.to_string(),
            start_height: 0,
            best_peer_height: 1,
            headers_height: 0,
            blocks_height: 0,
            last_progress_height: 0,
            checkpoint_tip_hash,
            retry_attempts: 0,
            last_interruption: None,
            pending_blocks: Vec::new(),
            pending_headers: vec![vec![0xAA, 0xBB, 0xCC]],
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: 1,
        };
        {
            let chain = chain.lock().await;
            snapshot.save(&chain.store).expect("save snapshot");
        }

        let (mut ibd, restored) = initialize_ibd_state(&chain, peer_addr, 1)
            .await
            .expect("initialize");
        let restored = restored.expect("restored snapshot");
        let err = continue_ibd_header_sync(
            &chain,
            peer_addr,
            &mut ibd,
            IbdRoundState {
                pending_blocks: restored.pending_blocks.clone(),
                pending_headers: restored.pending_headers.clone(),
                block_cursor: restored.block_cursor,
                header_cursor: restored.header_cursor,
                header_cursor_height: restored.header_cursor_height,
            },
            ibd_now(),
        )
        .await
        .expect_err("malformed resumed header bytes must reject");

        assert!(
            matches!(err, DomError::Malformed(_)),
            "unexpected error: {err}"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test]
    async fn persisted_ibd_snapshot_is_rejected_when_tip_hash_changed_at_same_height() {
        let dir = fresh_test_dir("header-resume-tip-mismatch");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");

        {
            let mut guard = chain.lock().await;
            guard.tip_height = BlockHeight(5);
            guard.tip_hash = Hash256::from_bytes([0x10; 32]);
        }

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: peer_addr.to_string(),
            start_height: 0,
            best_peer_height: 7,
            headers_height: 5,
            blocks_height: 5,
            last_progress_height: 5,
            checkpoint_tip_hash: [0x20; 32],
            retry_attempts: 1,
            last_interruption: Some(IbdInterruption::Timeout),
            pending_blocks: Vec::new(),
            pending_headers: vec![
                synthetic_known_header(5, Hash256::from_bytes([0x10; 32]), 6)
                    .to_bytes()
                    .expect("header bytes"),
            ],
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: 6,
        };
        {
            let guard = chain.lock().await;
            snapshot.save(&guard.store).expect("save snapshot");
        }

        let (_, restored) = initialize_ibd_state(&chain, peer_addr, 7)
            .await
            .expect("initialize");

        assert!(restored.is_none(), "mismatched tip hash must not resume");

        let persisted = {
            let guard = chain.lock().await;
            PersistedIbdState::load(&guard.store).expect("load snapshot")
        };
        assert!(
            persisted.is_none(),
            "mismatched snapshot must be cleared deterministically"
        );
        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    /// TASK 17 — chain-lock-across-await regression guard.
    ///
    /// The block-connect reconciliation path must acquire the chain lock,
    /// extract what it needs, DROP it, and only then await the mempool lock —
    /// it must never hold the chain guard across the mempool `.await`
    /// (`reconcile_mempool_after_connect`, node.rs: the `{ let chain =
    /// chain.lock().await; ... }` block drops the guard before
    /// `mempool.lock().await`).
    ///
    /// This is proven deterministically — no timing sleeps. On a current-thread
    /// runtime the test holds the mempool lock so `reconcile` is forced to park
    /// on it; once parked, the chain lock MUST be free. `try_lock` succeeding is
    /// only possible if `reconcile` already released the chain guard before the
    /// mempool await. Were the guard held across the await, `try_lock` returns
    /// `Err` and the test fails with a clear message rather than deadlocking.
    #[tokio::test(flavor = "current_thread")]
    async fn task17_reconcile_does_not_hold_chain_lock_across_mempool_await() {
        let dir = fresh_test_dir("task17-reconcile-lock-across-await");
        let chain = open_chain(&dir);
        let mempool = Arc::new(Mutex::new(Mempool::new()));

        // Hold the mempool lock so reconcile is forced to park on it.
        let mempool_guard = mempool.lock().await;

        let chain_task = chain.clone();
        let mempool_task = mempool.clone();
        // `BestChain` reaches the unconditional mempool acquisition after the
        // chain guard is dropped, even with no connected transactions.
        let handle = tokio::spawn(async move {
            reconcile_mempool_after_connect(
                &chain_task,
                &mempool_task,
                &ConnectResult::BestChain,
                &[],
            )
            .await
        });

        // Cooperatively schedule the spawned task until it parks on the held
        // mempool lock. On a current-thread runtime each poll runs it to its
        // next await; it must pass the chain acquire+drop first.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        // Proof: while reconcile is parked on the mempool await, the chain lock
        // must be free. This is the assertion that would fail (deterministically)
        // if the chain guard were held across the mempool await.
        {
            let _chain_guard = chain
                .try_lock()
                .expect("chain lock must be released before reconcile awaits the mempool");
        }

        // Let reconcile finish.
        drop(mempool_guard);
        handle
            .await
            .expect("reconcile task join")
            .expect("reconcile must succeed");

        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_during_orphan_future_processing_restarts_cleanly() {
        let dir = fresh_test_dir("runtime-orphan-future-shutdown");
        let node = init_test_node(regtest_node_config(&dir));
        let before = ReplaySnapshot::capture_runtime(&node.chain, &node.mempool, &node.peers)
            .await
            .expect("capture before");

        let future_hash = [0xA1; 32];
        assert!(
            node.future_block_queue
                .defer(DeferredBlock {
                    block_hash: future_hash,
                    block_height: before.chain_tip_height + 1,
                    timestamp: 1_700_100_000,
                    queued_at: Instant::now(),
                    block_bytes: vec![0xA1; 32],
                })
                .await
        );
        {
            let mut orphans = node.orphan_pool.lock().await;
            assert_eq!(
                orphans.insert(OrphanBlock {
                    block_hash: [0xB2; 32],
                    parent_hash: [0xB1; 32],
                    height: before.chain_tip_height + 2,
                    block_bytes: vec![0xB2; 64],
                }),
                crate::orphan_pool::OrphanInsertOutcome::Inserted
            );
        }
        {
            let mut missing = node.missing_blocks.lock().await;
            missing.note_orphan([0xB2; 32], [0xB1; 32], Some(before.chain_tip_height + 1));
            assert_eq!(missing.missing_len(), 1);
        }
        assert_eq!(node.future_block_queue.size().await, 1);
        assert_eq!(node.orphan_pool.lock().await.len(), 1);

        node.request_shutdown().await;
        assert!(node.task_supervisor.is_empty().await);
        drop(node);

        let reopened_store = open_test_store(&dir);
        drop(reopened_store);
        let restarted = init_test_node(regtest_node_config(&dir));
        let after =
            ReplaySnapshot::capture_runtime(&restarted.chain, &restarted.mempool, &restarted.peers)
                .await
                .expect("capture after");

        before
            .assert_equivalent(&after)
            .expect("deep replay snapshot remains valid after runtime-only interruption");
        assert_eq!(
            restarted.future_block_queue.size().await,
            0,
            "future queue is runtime-only and restarts empty"
        );
        assert!(
            restarted.orphan_pool.lock().await.is_empty(),
            "orphan pool is runtime-only and restarts empty"
        );
        assert_eq!(
            restarted.missing_blocks.lock().await.missing_len(),
            0,
            "missing-parent tracker is runtime-only and restarts empty"
        );

        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn interruption_during_mempool_reconciliation_leaves_store_restartable() {
        let dir = fresh_test_dir("runtime-mempool-reconcile-interrupt");
        let node = init_test_node(regtest_node_config(&dir));
        let before = ReplaySnapshot::capture_runtime(&node.chain, &node.mempool, &node.peers)
            .await
            .expect("capture before");

        let mempool_guard = node.mempool.lock().await;
        let chain_task = node.chain.clone();
        let mempool_task = node.mempool.clone();
        let handle = tokio::spawn(async move {
            reconcile_mempool_after_connect(
                &chain_task,
                &mempool_task,
                &ConnectResult::BestChain,
                &[],
            )
            .await
        });

        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        {
            let _chain_guard = node
                .chain
                .try_lock()
                .expect("chain lock must not be held while reconcile awaits mempool");
        }

        handle.abort();
        let join = handle
            .await
            .expect_err("interrupted reconcile task is cancelled");
        assert!(join.is_cancelled(), "reconcile task cancelled explicitly");
        drop(mempool_guard);

        assert_eq!(
            node.mempool.lock().await.len(),
            0,
            "interrupted reconciliation did not silently mutate mempool"
        );
        let after_interrupt =
            ReplaySnapshot::capture_runtime(&node.chain, &node.mempool, &node.peers)
                .await
                .expect("capture after interrupt");
        before
            .assert_equivalent(&after_interrupt)
            .expect("no partial mutation accepted after interrupted reconciliation");

        node.request_shutdown().await;
        drop(node);

        let reopened_store = open_test_store(&dir);
        drop(reopened_store);
        let restarted = init_test_node(regtest_node_config(&dir));
        let after_restart =
            ReplaySnapshot::capture_runtime(&restarted.chain, &restarted.mempool, &restarted.peers)
                .await
                .expect("capture after restart");
        before
            .assert_equivalent(&after_restart)
            .expect("deep replay snapshot remains valid after restart");

        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }

    #[tokio::test]
    async fn live_node_run_observes_shutdown_and_drains_supervisor() {
        let dir = fresh_test_dir("live-node-shutdown");
        let mut config = regtest_node_config(&dir);
        config.p2p_listen_addr = "127.0.0.1:0".into();
        config.rpc_listen_addr = None;
        config.mine = false;
        let node = Arc::new(init_test_node(config));
        let running = node.clone();
        let handle = tokio::spawn(async move { running.run().await });

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if node.task_supervisor.contains(TaskKind::Listener).await
                    && node.task_supervisor.contains(TaskKind::Connector).await
                    && node.task_supervisor.contains(TaskKind::FutureQueue).await
                    && node.task_supervisor.contains(TaskKind::DandelionStem).await
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("live node tasks registered");

        node.request_shutdown().await;
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("run returns after shutdown")
            .expect("join")
            .expect("clean shutdown");
        assert!(node.task_supervisor.is_empty().await);
        assert!(node.task_supervisor.failure().await.is_none());

        fs::remove_dir_all(&dir).expect("cleanup test dir");
    }
}

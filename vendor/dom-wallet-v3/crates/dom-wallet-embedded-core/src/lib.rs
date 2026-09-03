//! Wallet-owned lifecycle boundary for the embedded DOM node.

#![forbid(unsafe_code)]

use dom_config::{Network, NodeConfig};
use dom_node::{node::DomNode, wallet_core_api::EmbeddedWalletCoreApi};
use dom_wallet_core_api::{
    BlockSelector, BlockSummary, ChainIdentity, CursorValidation, FeeBreakdown, FeeEstimate,
    FeeEstimateRequest, FeePolicySnapshot, FeeValidation, KernelQueryResult, MempoolPolicySnapshot,
    ScanRequest, ScanResult, SubmissionResult, SubmitTransactionRequest, SyncStatus,
    TransactionIdentifier, TransactionShape, TransactionStatus, TransactionWeight, UtxoQueryResult,
    WalletCoreApi, WalletCoreError, WalletScanCursor,
};
use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    path::PathBuf,
    sync::{
        atomic::{AtomicU8, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use thiserror::Error;

mod miner;
pub use miner::{mine_wallet_block, WalletMiner, WalletMiningError, WalletMiningOutcome};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STATE_UNINITIALIZED: u8 = 0;
const STATE_STARTING: u8 = 1;
const STATE_RUNNING: u8 = 2;
const STATE_STOPPING: u8 = 3;
const STATE_STOPPED: u8 = 4;
const STATE_FAILED: u8 = 5;
const SEED_PENDING: u8 = 0;
const SEED_RESOLVING: u8 = 1;
const SEED_RESOLVED: u8 = 2;
const SEED_RETRYING: u8 = 3;

/// Canonical desktop-wallet Mainnet DNS seeds.
pub const MAINNET_DNS_SEEDS: [&str; 3] = [
    "seed1.dom-protocol.org",
    "seed2.dom-protocol.org",
    "seed3.dom-protocol.org",
];
/// Canonical Mainnet P2P port.
pub const MAINNET_P2P_PORT: u16 = 33_369;

/// Outbound peers the embedded Mainnet node keeps connected.
///
/// This was 1, and a single peer is a single point of truth: the wallet
/// bootstrapped against one seed that was ~4400 blocks behind the real tip and
/// had no second opinion to notice, while losing that one peer stalled
/// synchronization outright. Several peers make a stale or lying seed visible
/// immediately and keep the wallet alive when one drops.
///
/// Upstream's own Mainnet default is 8, which is also the connector's
/// `max_in_flight_attempts` ceiling — asking for more would be silently capped.
pub const MAINNET_OUTBOUND_PEER_TARGET: usize = 8;

/// Inbound slots on Mainnet. The wallet is a leaf client that dials out and
/// never advertises itself, so this stays small; it does not limit the outbound
/// connections that carry synchronization.
pub const MAINNET_INBOUND_PEER_LIMIT: usize = 4;

/// LMDB map-exhaustion sentinel emitted by the protocol store layer
/// (`dom-store`). The embedded adapter surfaces this exact code so the
/// desktop shell can restart the node with a doubled map size.
pub const LMDB_MAP_FULL_ERROR_CODE: &str = "LMDB_MAP_FULL";

/// Smallest LMDB map size the Wallet accepts (64 MiB); anything below this
/// cannot even hold the genesis chain state plus store metadata.
pub const MINIMUM_LMDB_MAP_SIZE_BYTES: usize = 64 * 1024 * 1024;

/// Platform-conscious default LMDB map size for the embedded node.
///
/// LMDB reserves the whole map eagerly in the on-disk file allocation on
/// Windows (no sparse punch-through as on unix), so a 16 GiB default there
/// immediately claims 16 GiB of disk. Windows therefore starts at 4 GiB and
/// grows on demand when the shell observes [`LMDB_MAP_FULL_ERROR_CODE`];
/// unix keeps the upstream 16 GiB default.
pub fn default_lmdb_map_size() -> usize {
    if cfg!(windows) {
        4 * 1024 * 1024 * 1024
    } else {
        16 * 1024 * 1024 * 1024
    }
}

/// Network selected for the embedded node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedCoreNetwork {
    /// Production network.
    Mainnet,
    /// Public test network.
    Testnet,
    /// Isolated development network.
    Regtest,
}

impl EmbeddedCoreNetwork {
    fn node_network(self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Testnet => Network::Testnet,
            Self::Regtest => Network::Regtest,
        }
    }
}

/// Validated Wallet-side configuration for the embedded node boundary.
#[derive(Clone)]
pub struct EmbeddedCoreConfiguration {
    network: EmbeddedCoreNetwork,
    data_directory: PathBuf,
    p2p_listen_address: SocketAddr,
    maximum_inbound_peers: usize,
    seed_peers: Vec<SocketAddr>,
    lmdb_map_size: Option<usize>,
}

impl EmbeddedCoreConfiguration {
    /// Create a configuration. Validation occurs before node initialization.
    pub fn new(
        network: EmbeddedCoreNetwork,
        data_directory: impl Into<PathBuf>,
        p2p_listen_address: SocketAddr,
    ) -> Self {
        Self {
            network,
            data_directory: data_directory.into(),
            p2p_listen_address,
            maximum_inbound_peers: 32,
            seed_peers: Vec::new(),
            lmdb_map_size: None,
        }
    }

    /// Build the single production configuration used by the desktop Wallet.
    pub fn mainnet(data_directory: impl Into<PathBuf>, p2p_listen_address: SocketAddr) -> Self {
        Self::new(
            EmbeddedCoreNetwork::Mainnet,
            data_directory,
            p2p_listen_address,
        )
        .with_maximum_inbound_peers(MAINNET_INBOUND_PEER_LIMIT)
    }

    /// Set the maximum inbound peer count.
    pub fn with_maximum_inbound_peers(mut self, maximum: usize) -> Self {
        self.maximum_inbound_peers = maximum;
        self
    }

    /// Set explicit bootstrap peers. DNS discovery remains disabled.
    pub fn with_seed_peers(mut self, peers: Vec<SocketAddr>) -> Self {
        self.seed_peers = deduplicate_socket_addresses(peers);
        self
    }

    /// Override the LMDB map size used by `DomNode::init_with_map_size`.
    ///
    /// Without an override the platform-conscious [`default_lmdb_map_size`]
    /// applies. The shell persists and doubles this value after observing
    /// [`LMDB_MAP_FULL_ERROR_CODE`].
    pub fn with_lmdb_map_size(mut self, map_size: usize) -> Self {
        self.lmdb_map_size = Some(map_size);
        self
    }

    /// Effective LMDB map size: the explicit override or the platform default.
    pub fn lmdb_map_size(&self) -> usize {
        self.lmdb_map_size.unwrap_or_else(default_lmdb_map_size)
    }

    fn validate(&self) -> Result<(), EmbeddedCoreAdapterError> {
        if self.data_directory.as_os_str().is_empty() {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "EMPTY_DATA_DIRECTORY",
            });
        }
        if self.p2p_listen_address.port() == 0 {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "ZERO_P2P_PORT",
            });
        }
        if self.maximum_inbound_peers == 0 {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "ZERO_INBOUND_LIMIT",
            });
        }
        if self.seed_peers.iter().any(|peer| peer.port() == 0) {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "ZERO_SEED_PORT",
            });
        }
        if self
            .lmdb_map_size
            .is_some_and(|map_size| map_size < MINIMUM_LMDB_MAP_SIZE_BYTES)
        {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "LMDB_MAP_SIZE_TOO_SMALL",
            });
        }
        if self.network == EmbeddedCoreNetwork::Mainnet
            && (!self.p2p_listen_address.ip().is_loopback()
                || self.seed_peers.contains(&self.p2p_listen_address)
                || self
                    .seed_peers
                    .iter()
                    .any(|peer| !is_public_routable_peer(*peer)))
        {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "UNSAFE_MAINNET_LISTENER_OR_SELF_PEER",
            });
        }
        Ok(())
    }

    fn node_config(&self) -> NodeConfig {
        let mut config = match self.network.node_network() {
            Network::Mainnet => NodeConfig::mainnet(),
            Network::Testnet => NodeConfig::testnet(),
            Network::Regtest => NodeConfig::regtest(),
        };
        config.data_dir = self.data_directory.to_string_lossy().into_owned();
        config.p2p_listen_addr = self.p2p_listen_address.to_string();
        config.max_inbound = self.maximum_inbound_peers;
        config.min_outbound = if self.network == EmbeddedCoreNetwork::Mainnet {
            MAINNET_OUTBOUND_PEER_TARGET
        } else {
            // An explicit local seed is an instruction to establish the
            // laboratory/testnet session. Leaving the target at zero makes
            // Core's connector correctly decide that no outbound peer is
            // needed, so `with_seed_peers` would only populate an inert list.
            // No-seed isolated regtest retains the prior zero-outbound shape.
            self.seed_peers.len()
        };
        // The Wallet owns DNS discovery so each seed has independent bounded
        // backoff. Core's resolver logs every failed seed on every connector
        // pass and is therefore deliberately disabled here.
        config.dns_seeds.clear();
        config.disable_dns_seeds = true;
        // Mainnet fallbacks are staged by the Wallet after an observed failure.
        // Supplying every endpoint here would let Core's canonical address sort
        // override Wallet priority and could reserve more than one relay endpoint.
        config.seed_peers = if self.network == EmbeddedCoreNetwork::Mainnet {
            self.seed_peers
                .first()
                .map(ToString::to_string)
                .into_iter()
                .collect()
        } else {
            self.seed_peers.iter().map(ToString::to_string).collect()
        };
        config.mine = false;
        config.miner_address = None;
        config.wallet_path = None;
        config.wallet_password = None;
        config.rpc_listen_addr = None;
        config.rpc_bearer_token = None;
        config.metrics_listen_addr = None;
        config
    }
}

/// Privacy-safe live peer counters from the embedded node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedPeerStatus {
    pub connected_inbound: u64,
    pub connected_outbound: u64,
    pub connected_total: u64,
    pub known_peers: u64,
    pub bootstrap_phase: &'static str,
    pub peer_addresses: Vec<String>,
    pub canonical_height: u64,
    pub highest_known_peer_height: u64,
    pub seed_resolution_states: Vec<&'static str>,
}

impl fmt::Debug for EmbeddedCoreConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddedCoreConfiguration")
            .field("network", &self.network)
            .field("data_directory", &"<redacted>")
            .field("p2p_listen_address", &self.p2p_listen_address)
            .field("maximum_inbound_peers", &self.maximum_inbound_peers)
            .field("seed_peer_count", &self.seed_peers.len())
            .finish()
    }
}

/// Observable lifecycle state of the embedded Core owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedCoreLifecycleState {
    /// Configuration exists but Core has not been initialized.
    Uninitialized,
    /// Core is initializing and binding its local services.
    Starting,
    /// Core completed startup and its Wallet API may be used.
    Running,
    /// Shutdown has been requested.
    Stopping,
    /// Core shut down cleanly.
    Stopped,
    /// Initialization, startup, or shutdown failed.
    Failed,
}

impl EmbeddedCoreLifecycleState {
    fn from_raw(raw: u8) -> Self {
        match raw {
            STATE_STARTING => Self::Starting,
            STATE_RUNNING => Self::Running,
            STATE_STOPPING => Self::Stopping,
            STATE_STOPPED => Self::Stopped,
            STATE_FAILED => Self::Failed,
            _ => Self::Uninitialized,
        }
    }
}

/// Stable adapter failures. Diagnostic codes contain no Core error text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EmbeddedCoreAdapterError {
    /// Wallet configuration was rejected before node initialization.
    #[error("invalid embedded Core configuration ({code})")]
    InvalidConfiguration { code: &'static str },
    /// The node could not be initialized.
    #[error("embedded Core initialization failed ({code})")]
    InitializationFailed { code: &'static str },
    /// The node task could not reach the running state.
    #[error("embedded Core startup failed ({code})")]
    StartupFailed { code: &'static str },
    /// The requested operation requires a running node.
    #[error("embedded Core is not running")]
    NotRunning,
    /// Shutdown or task joining failed.
    #[error("embedded Core shutdown failed ({code})")]
    ShutdownFailed { code: &'static str },
    /// An internal adapter invariant failed.
    #[error("embedded Core adapter failure ({code})")]
    Internal { code: &'static str },
}

enum LifecycleCommand {
    Shutdown,
}

struct MainnetDiscoveryConfiguration {
    enabled: bool,
    bootstrap_peers: Vec<SocketAddr>,
    seed_resolution: Arc<[AtomicU8; MAINNET_DNS_SEEDS.len()]>,
}

/// Lifecycle-gated implementation of the frozen Wallet-facing Core contract.
pub struct EmbeddedWalletApiHandle {
    inner: EmbeddedWalletCoreApi,
    lifecycle: Arc<AtomicU8>,
}

impl EmbeddedWalletApiHandle {
    fn ensure_running(&self) -> Result<(), WalletCoreError> {
        if self.lifecycle.load(Ordering::Acquire) == STATE_RUNNING {
            Ok(())
        } else {
            Err(WalletCoreError::NodeNotReady(
                "embedded Core lifecycle is not running".to_owned(),
            ))
        }
    }
}

macro_rules! delegate_wallet_api {
    ($name:ident ( $($argument:ident : $argument_type:ty),* ) -> $result:ty) => {
        fn $name(&self, $($argument: $argument_type),*) -> Result<$result, WalletCoreError> {
            self.ensure_running()?;
            self.inner.$name($($argument),*)
        }
    };
}

impl WalletCoreApi for EmbeddedWalletApiHandle {
    delegate_wallet_api!(chain_identity() -> ChainIdentity);
    delegate_wallet_api!(scan_range(request: ScanRequest) -> ScanResult);
    delegate_wallet_api!(validate_cursor(cursor: WalletScanCursor) -> CursorValidation);
    delegate_wallet_api!(canonical_hash_at_height(height: u64) -> Option<[u8; 32]>);
    delegate_wallet_api!(get_utxo(commitment: &[u8; 33]) -> Option<UtxoQueryResult>);
    delegate_wallet_api!(get_kernel(excess: &[u8; 33]) -> Option<KernelQueryResult>);
    delegate_wallet_api!(get_block_summary(selector: BlockSelector) -> Option<BlockSummary>);
    delegate_wallet_api!(transaction_status(id: TransactionIdentifier) -> TransactionStatus);
    delegate_wallet_api!(submit_transaction(request: SubmitTransactionRequest) -> SubmissionResult);
    delegate_wallet_api!(rebroadcast_transaction(id: TransactionIdentifier) -> SubmissionResult);
    delegate_wallet_api!(query_submission(id: TransactionIdentifier) -> SubmissionResult);
    delegate_wallet_api!(sync_status() -> SyncStatus);
    delegate_wallet_api!(is_ready_for_wallet_operations() -> bool);
    delegate_wallet_api!(mempool_policy_snapshot() -> MempoolPolicySnapshot);
    delegate_wallet_api!(fee_policy_snapshot() -> FeePolicySnapshot);
    delegate_wallet_api!(transaction_weight(shape: TransactionShape) -> TransactionWeight);
    delegate_wallet_api!(minimum_fee(shape: TransactionShape) -> FeeBreakdown);
    delegate_wallet_api!(estimate_fee(request: FeeEstimateRequest) -> FeeEstimate);

    fn validate_fee(
        &self,
        transaction: &dom_consensus::Transaction,
    ) -> Result<FeeValidation, WalletCoreError> {
        self.ensure_running()?;
        self.inner.validate_fee(transaction)
    }
}

/// Exclusive owner of the embedded DOM node runtime and Wallet API adapter.
pub struct EmbeddedCoreLifecycle {
    configuration: EmbeddedCoreConfiguration,
    lifecycle: Arc<AtomicU8>,
    node: Option<Arc<DomNode>>,
    wallet_api: Option<Arc<EmbeddedWalletApiHandle>>,
    command_sender: Option<tokio::sync::mpsc::UnboundedSender<LifecycleCommand>>,
    runtime_thread: Option<JoinHandle<()>>,
    seed_resolution: Arc<[AtomicU8; MAINNET_DNS_SEEDS.len()]>,
}

impl fmt::Debug for EmbeddedCoreLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmbeddedCoreLifecycle")
            .field("configuration", &self.configuration)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl EmbeddedCoreLifecycle {
    /// Create an uninitialized owner. No node process or task starts here.
    pub fn new(configuration: EmbeddedCoreConfiguration) -> Self {
        Self {
            configuration,
            lifecycle: Arc::new(AtomicU8::new(STATE_UNINITIALIZED)),
            node: None,
            wallet_api: None,
            command_sender: None,
            runtime_thread: None,
            seed_resolution: Arc::new(std::array::from_fn(|_| AtomicU8::new(SEED_PENDING))),
        }
    }

    /// Return the current lifecycle state.
    pub fn state(&self) -> EmbeddedCoreLifecycleState {
        EmbeddedCoreLifecycleState::from_raw(self.lifecycle.load(Ordering::Acquire))
    }

    /// Initialize Core and start its services on an owned runtime thread.
    pub fn start(&mut self) -> Result<(), EmbeddedCoreAdapterError> {
        if self.state() != EmbeddedCoreLifecycleState::Uninitialized {
            return Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "LIFECYCLE_ALREADY_STARTED",
            });
        }
        self.configuration.validate()?;
        self.lifecycle.store(STATE_STARTING, Ordering::Release);

        let node = Arc::new(
            DomNode::init_with_map_size(
                self.configuration.node_config(),
                self.configuration.lmdb_map_size(),
            )
            .map_err(|error| {
                self.lifecycle.store(STATE_FAILED, Ordering::Release);
                EmbeddedCoreAdapterError::InitializationFailed {
                    // The store layer tags MDB_MAP_FULL with a stable sentinel;
                    // surface it verbatim so the shell can double the map size
                    // and retry. Every other cause stays a redacted init code.
                    code: if format!("{error:?}").contains(LMDB_MAP_FULL_ERROR_CODE) {
                        LMDB_MAP_FULL_ERROR_CODE
                    } else {
                        "DOM_NODE_INIT"
                    },
                }
            })?,
        );
        let wallet_api = Arc::new(EmbeddedWalletApiHandle {
            inner: EmbeddedWalletCoreApi::new(node.clone()),
            lifecycle: self.lifecycle.clone(),
        });
        let (command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
        let lifecycle = self.lifecycle.clone();
        let listen_address = self.configuration.p2p_listen_address;
        let runtime_node = node.clone();
        let discovery = MainnetDiscoveryConfiguration {
            enabled: self.configuration.network == EmbeddedCoreNetwork::Mainnet,
            bootstrap_peers: self.configuration.seed_peers.clone(),
            seed_resolution: Arc::clone(&self.seed_resolution),
        };

        let runtime_thread = thread::Builder::new()
            .name("dom-wallet-embedded-core".to_owned())
            .spawn(move || {
                run_node_thread(
                    runtime_node,
                    listen_address,
                    lifecycle,
                    command_receiver,
                    startup_sender,
                    discovery,
                );
            })
            .map_err(|_| {
                self.lifecycle.store(STATE_FAILED, Ordering::Release);
                EmbeddedCoreAdapterError::StartupFailed {
                    code: "RUNTIME_THREAD_SPAWN",
                }
            })?;

        match startup_receiver.recv_timeout(STARTUP_TIMEOUT + Duration::from_secs(2)) {
            Ok(Ok(())) => {
                self.node = Some(node);
                self.wallet_api = Some(wallet_api);
                self.command_sender = Some(command_sender);
                self.runtime_thread = Some(runtime_thread);
                Ok(())
            }
            Ok(Err(())) => {
                let _ = runtime_thread.join();
                Err(EmbeddedCoreAdapterError::StartupFailed {
                    code: "DOM_NODE_RUN",
                })
            }
            Err(_) => {
                let _ = command_sender.send(LifecycleCommand::Shutdown);
                let _ = runtime_thread.join();
                self.lifecycle.store(STATE_FAILED, Ordering::Release);
                Err(EmbeddedCoreAdapterError::StartupFailed {
                    code: "STARTUP_TIMEOUT",
                })
            }
        }
    }

    /// Obtain a lifecycle-gated handle to the frozen Wallet Core API.
    pub fn wallet_api(
        &self,
    ) -> Result<Arc<dyn WalletCoreApi + Send + Sync>, EmbeddedCoreAdapterError> {
        if self.state() != EmbeddedCoreLifecycleState::Running {
            return Err(EmbeddedCoreAdapterError::NotRunning);
        }
        self.wallet_api
            .as_ref()
            .map(|api| api.clone() as Arc<dyn WalletCoreApi + Send + Sync>)
            .ok_or(EmbeddedCoreAdapterError::Internal {
                code: "MISSING_WALLET_API",
            })
    }

    /// Query readiness through the frozen Wallet Core API.
    pub fn is_ready_for_wallet_operations(&self) -> Result<bool, EmbeddedCoreAdapterError> {
        self.wallet_api()?
            .is_ready_for_wallet_operations()
            .map_err(|_| EmbeddedCoreAdapterError::Internal {
                code: "READINESS_QUERY",
            })
    }

    /// Query synchronization status through the frozen Wallet Core API.
    pub fn sync_status(&self) -> Result<SyncStatus, EmbeddedCoreAdapterError> {
        self.wallet_api()?
            .sync_status()
            .map_err(|_| EmbeddedCoreAdapterError::Internal {
                code: "SYNC_STATUS_QUERY",
            })
    }

    /// Return safe live peer and bootstrap diagnostics without exposing Noise state.
    pub fn peer_status(&self) -> Result<EmbeddedPeerStatus, EmbeddedCoreAdapterError> {
        if self.state() != EmbeddedCoreLifecycleState::Running {
            return Err(EmbeddedCoreAdapterError::NotRunning);
        }
        let node = self
            .node
            .as_ref()
            .ok_or(EmbeddedCoreAdapterError::Internal {
                code: "MISSING_NODE",
            })?;
        let connected_inbound = node.metrics.inbound_peers.load(Ordering::Relaxed);
        let connected_outbound = node.metrics.outbound_peers.load(Ordering::Relaxed);
        let connected_total = node.metrics.peer_count.load(Ordering::Relaxed);
        let canonical_height = node.metrics.chain_height.load(Ordering::Relaxed);
        let highest_known_peer_height = node.metrics.best_known_peer_height.load(Ordering::Relaxed);
        let known_peers = node
            .pex
            .try_lock()
            .map(|pex| pex.known_count() as u64)
            .unwrap_or(connected_total);
        let peer_addresses = node
            .peers
            .try_lock()
            .map(|peers| {
                peers
                    .connected_peers()
                    .into_iter()
                    .filter_map(|peer| peer.parse::<SocketAddr>().ok())
                    .map(redact_peer_address)
                    .collect()
            })
            .unwrap_or_default();
        Ok(EmbeddedPeerStatus {
            connected_inbound,
            connected_outbound,
            connected_total,
            known_peers,
            bootstrap_phase: bootstrap_phase(connected_total),
            peer_addresses,
            canonical_height,
            highest_known_peer_height,
            seed_resolution_states: self
                .seed_resolution
                .iter()
                .map(|state| match state.load(Ordering::Acquire) {
                    SEED_RESOLVING => "RESOLVING",
                    SEED_RESOLVED => "RESOLVED",
                    SEED_RETRYING => "RETRYING_WITH_BACKOFF",
                    _ => "PENDING",
                })
                .collect(),
        })
    }

    /// Return an in-process node handle for the Wallet-owned miner interface.
    /// No seed, key, password, or private recovery material is attached to it.
    pub fn node_handle(&self) -> Result<Arc<DomNode>, EmbeddedCoreAdapterError> {
        if self.state() != EmbeddedCoreLifecycleState::Running {
            return Err(EmbeddedCoreAdapterError::NotRunning);
        }
        self.node
            .as_ref()
            .cloned()
            .ok_or(EmbeddedCoreAdapterError::Internal {
                code: "MISSING_NODE",
            })
    }

    /// Request shutdown. Repeated requests are safe.
    pub fn request_shutdown(&mut self) -> Result<(), EmbeddedCoreAdapterError> {
        match self.state() {
            EmbeddedCoreLifecycleState::Uninitialized => {
                self.lifecycle.store(STATE_STOPPED, Ordering::Release);
                Ok(())
            }
            EmbeddedCoreLifecycleState::Starting | EmbeddedCoreLifecycleState::Running => {
                self.lifecycle.store(STATE_STOPPING, Ordering::Release);
                if let Some(sender) = &self.command_sender {
                    sender.send(LifecycleCommand::Shutdown).map_err(|_| {
                        EmbeddedCoreAdapterError::ShutdownFailed {
                            code: "SHUTDOWN_CHANNEL_CLOSED",
                        }
                    })?;
                }
                Ok(())
            }
            EmbeddedCoreLifecycleState::Stopping
            | EmbeddedCoreLifecycleState::Stopped
            | EmbeddedCoreLifecycleState::Failed => Ok(()),
        }
    }

    /// Wait for the owned node runtime to stop.
    pub fn wait_for_shutdown(&mut self) -> Result<(), EmbeddedCoreAdapterError> {
        if let Some(runtime_thread) = self.runtime_thread.take() {
            runtime_thread.join().map_err(|_| {
                self.lifecycle.store(STATE_FAILED, Ordering::Release);
                EmbeddedCoreAdapterError::ShutdownFailed {
                    code: "RUNTIME_THREAD_PANIC",
                }
            })?;
        }
        self.command_sender = None;
        self.wallet_api = None;
        self.node = None;
        if self.state() == EmbeddedCoreLifecycleState::Failed {
            Err(EmbeddedCoreAdapterError::ShutdownFailed {
                code: "DOM_NODE_RUN",
            })
        } else {
            self.lifecycle.store(STATE_STOPPED, Ordering::Release);
            Ok(())
        }
    }
}

fn is_public_routable_peer(address: SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match address.ip() {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn deduplicate_socket_addresses(peers: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::with_capacity(peers.len());
    peers
        .into_iter()
        .filter(|peer| seen.insert(*peer))
        .collect()
}

#[derive(Debug)]
struct BootstrapFallbackSequence {
    endpoints: Vec<SocketAddr>,
    active_index: Option<usize>,
    observed_failure_count: u8,
}

impl BootstrapFallbackSequence {
    fn new(endpoints: Vec<SocketAddr>) -> Self {
        let endpoints = deduplicate_socket_addresses(endpoints);
        Self {
            active_index: (!endpoints.is_empty()).then_some(0),
            endpoints,
            observed_failure_count: 0,
        }
    }

    fn active(&self) -> Option<SocketAddr> {
        self.active_index.map(|index| self.endpoints[index])
    }

    fn has_untried_endpoint(&self) -> bool {
        self.active_index
            .is_some_and(|index| index + 1 < self.endpoints.len())
    }

    fn observe_failure(&mut self, endpoint: SocketAddr, failure_count: u8) -> Option<SocketAddr> {
        if self.active() != Some(endpoint) || failure_count <= self.observed_failure_count {
            return None;
        }
        self.observed_failure_count = failure_count;
        let next_index = self.active_index? + 1;
        if next_index >= self.endpoints.len() {
            return None;
        }
        self.active_index = Some(next_index);
        self.observed_failure_count = 0;
        self.active()
    }
}

fn bootstrap_phase(connected_peers: u64) -> &'static str {
    if connected_peers > 0 {
        "CONNECTED"
    } else {
        "DISCOVERING_PEERS"
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    if a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
    {
        return false;
    }
    !(a == 255 && b == 255 && c == 255 && d == 255)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.to_ipv4().is_some()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
    {
        return false;
    }
    let is_discard_only =
        segments[0] == 0x0100 && segments[1..].iter().all(|segment| *segment == 0);
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let is_benchmark = segments[0] == 0x2001 && segments[1] == 0x0002;
    let is_orchid = segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020;
    !(is_discard_only || is_documentation || is_benchmark || is_orchid)
}

fn redact_peer_address(address: SocketAddr) -> String {
    match address.ip() {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            format!("{}.{}.x.x:{}", octets[0], octets[1], address.port())
        }
        std::net::IpAddr::V6(_) => format!("[IPv6]:{}", address.port()),
    }
}

impl Drop for EmbeddedCoreLifecycle {
    fn drop(&mut self) {
        let _ = self.request_shutdown();
        let _ = self.wait_for_shutdown();
    }
}

fn run_node_thread(
    node: Arc<DomNode>,
    listen_address: SocketAddr,
    lifecycle: Arc<AtomicU8>,
    mut command_receiver: tokio::sync::mpsc::UnboundedReceiver<LifecycleCommand>,
    startup_sender: mpsc::SyncSender<Result<(), ()>>,
    discovery: MainnetDiscoveryConfiguration,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            lifecycle.store(STATE_FAILED, Ordering::Release);
            let _ = startup_sender.send(Err(()));
            return;
        }
    };

    runtime.block_on(async move {
        let discovery_task = if discovery.enabled {
            let discovery_shutdown = node.task_supervisor.shutdown_token();
            let discovery_node = Arc::clone(&node);
            Some(tokio::spawn(async move {
                run_wallet_dns_discovery(
                    discovery_node,
                    listen_address,
                    discovery_shutdown,
                    discovery.bootstrap_peers,
                    discovery.seed_resolution,
                )
                .await;
            }))
        } else {
            None
        };
        let mut node_task = tokio::spawn(node.clone().run());
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if node_task.is_finished() || Instant::now() >= deadline {
                node.request_shutdown().await;
                let _ = node_task.await;
                if let Some(task) = &discovery_task {
                    task.abort();
                }
                lifecycle.store(STATE_FAILED, Ordering::Release);
                let _ = startup_sender.send(Err(()));
                return;
            }
            if listener_is_bound(listen_address) {
                break;
            }
            tokio::time::sleep(STARTUP_POLL_INTERVAL).await;
        }

        lifecycle.store(STATE_RUNNING, Ordering::Release);
        if startup_sender.send(Ok(())).is_err() {
            node.request_shutdown().await;
        }

        tokio::select! {
            command = command_receiver.recv() => {
                if matches!(command, Some(LifecycleCommand::Shutdown)) {
                    lifecycle.store(STATE_STOPPING, Ordering::Release);
                }
                node.request_shutdown().await;
                match node_task.await {
                    Ok(Ok(())) => lifecycle.store(STATE_STOPPED, Ordering::Release),
                    _ => lifecycle.store(STATE_FAILED, Ordering::Release),
                }
            }
            _ = &mut node_task => {
                lifecycle.store(STATE_FAILED, Ordering::Release);
            }
        }
        if let Some(task) = discovery_task {
            task.abort();
        }
    });
}

async fn run_wallet_dns_discovery(
    node: Arc<DomNode>,
    local_address: SocketAddr,
    shutdown: dom_node::task_supervisor::ShutdownToken,
    bootstrap_peers: Vec<SocketAddr>,
    seed_resolution: Arc<[AtomicU8; MAINNET_DNS_SEEDS.len()]>,
) {
    const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
    const MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
    const SUCCESS_REFRESH: Duration = Duration::from_secs(30 * 60);
    let mut failures = [0u8; MAINNET_DNS_SEEDS.len()];
    let mut next_attempt = [Instant::now(); MAINNET_DNS_SEEDS.len()];
    let mut bootstrap = BootstrapFallbackSequence::new(bootstrap_peers);
    let mut observed_connected = HashSet::new();
    let mut last_connected_count = usize::MAX;
    if let Some(peer) = bootstrap.active() {
        tracing::info!(
            event = "wallet_bootstrap_peer_attempted",
            peer = %peer,
            fallback = false,
            "attempting prioritized Mainnet bootstrap peer"
        );
    }
    loop {
        if shutdown.is_shutdown() {
            return;
        }
        let (connected, active_failure_count) = {
            let peers = node.peers.lock().await;
            let connected = peers
                .connected_peers()
                .into_iter()
                .filter_map(|peer| peer.parse::<SocketAddr>().ok())
                .collect::<HashSet<_>>();
            let active_failure_count = bootstrap
                .active()
                .map(|peer| peers.outbound_failure_count(&peer.to_string()))
                .unwrap_or(0);
            (connected, active_failure_count)
        };
        for peer in connected.difference(&observed_connected) {
            tracing::info!(
                event = "wallet_bootstrap_connection_accepted",
                peer = %peer,
                connected_peers = connected.len(),
                "Mainnet peer connection accepted"
            );
        }
        if connected.len() != last_connected_count {
            tracing::info!(
                event = "wallet_bootstrap_connected_peers_final",
                connected_peers = connected.len(),
                "Mainnet bootstrap connected peer count updated"
            );
            last_connected_count = connected.len();
        }
        observed_connected = connected;

        if let Some(active) = bootstrap.active() {
            if active_failure_count > bootstrap.observed_failure_count {
                let has_untried_endpoint = bootstrap.has_untried_endpoint();
                tracing::warn!(
                    event = "wallet_bootstrap_connection_refused",
                    peer = %active,
                    failure_count = active_failure_count,
                    has_untried_endpoint,
                    "Mainnet bootstrap peer connection refused"
                );
                if let Some(fallback) = bootstrap.observe_failure(active, active_failure_count) {
                    node.pex
                        .lock()
                        .await
                        .seed_from_config(&[fallback.to_string()]);
                    tracing::info!(
                        event = "wallet_bootstrap_fallback_activated",
                        failed_peer = %active,
                        peer = %fallback,
                        "attempting next Mainnet bootstrap fallback"
                    );
                    tracing::info!(
                        event = "wallet_bootstrap_peer_attempted",
                        peer = %fallback,
                        fallback = true,
                        "attempting Mainnet bootstrap fallback peer"
                    );
                }
            }
        }
        let now = Instant::now();
        for (index, seed) in MAINNET_DNS_SEEDS.iter().enumerate() {
            if now < next_attempt[index] {
                continue;
            }
            seed_resolution[index].store(SEED_RESOLVING, Ordering::Release);
            let resolved = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((*seed, MAINNET_P2P_PORT)),
            )
            .await;
            match resolved {
                Ok(Ok(addresses)) => {
                    let addresses = addresses
                        .filter(|address| *address != local_address)
                        .filter(|address| is_public_routable_peer(*address))
                        .map(|address| address.to_string())
                        .collect::<Vec<_>>();
                    if !addresses.is_empty() {
                        if let Ok(mut pex) = node.pex.try_lock() {
                            pex.seed_from_config(&addresses);
                        }
                        failures[index] = 0;
                        seed_resolution[index].store(SEED_RESOLVED, Ordering::Release);
                        next_attempt[index] = Instant::now() + SUCCESS_REFRESH;
                        continue;
                    }
                    failures[index] = failures[index].saturating_add(1);
                }
                _ => failures[index] = failures[index].saturating_add(1),
            }
            let exponent = failures[index].saturating_sub(1).min(6) as u32;
            seed_resolution[index].store(SEED_RETRYING, Ordering::Release);
            let delay = INITIAL_BACKOFF
                .checked_mul(1u32.checked_shl(exponent).unwrap_or(u32::MAX))
                .unwrap_or(MAX_BACKOFF)
                .min(MAX_BACKOFF);
            next_attempt[index] = Instant::now() + delay;
        }
        tokio::select! {
            _ = shutdown.wait() => return,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

fn listener_is_bound(address: SocketAddr) -> bool {
    match TcpListener::bind(address) {
        Ok(listener) => {
            drop(listener);
            false
        }
        Err(error) => error.kind() == std::io::ErrorKind::AddrInUse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn unused_loopback_address() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral test port");
        let address = listener.local_addr().expect("read ephemeral test port");
        drop(listener);
        address
    }

    /// Configuration for the tests that start a REAL node.
    ///
    /// The listen port must be reserved per test: `cargo test` runs these in
    /// parallel threads inside one process, and a hardcoded port made whichever
    /// node lost the race die with a bare `DOM_NODE_RUN`, so the suite failed
    /// on an arbitrary one of these tests while every one of them passed alone.
    fn regtest_configuration(directory: &Path) -> EmbeddedCoreConfiguration {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral test listener");
        let address = listener.local_addr().expect("ephemeral local address");
        drop(listener);
        EmbeddedCoreConfiguration::new(EmbeddedCoreNetwork::Regtest, directory, address)
            .with_maximum_inbound_peers(2)
    }

    #[test]
    fn mainnet_wallet_configuration_is_fixed_private_and_non_mining() {
        let directory = TempDir::new().expect("temporary directory");
        let address = "127.0.0.1:34341".parse().expect("static test address");
        let configuration = EmbeddedCoreConfiguration::mainnet(directory.path(), address);
        configuration
            .validate()
            .expect("fixed configuration is valid");
        let node = configuration.node_config();
        assert_eq!(node.network, Network::Mainnet);
        assert_eq!(node.p2p_listen_addr, address.to_string());
        // A single outbound peer is a single point of truth: the wallet used to
        // bootstrap against one stale seed with no second opinion, and lost all
        // synchronization when that peer dropped.
        assert_eq!(node.min_outbound, MAINNET_OUTBOUND_PEER_TARGET);
        assert!(
            node.min_outbound >= 5,
            "Mainnet must keep several outbound peers, got {}",
            node.min_outbound
        );
        assert_eq!(node.max_inbound, MAINNET_INBOUND_PEER_LIMIT);
        assert!(node.disable_dns_seeds);
        assert!(node.dns_seeds.is_empty());
        assert!(configuration.seed_peers.is_empty());
        assert!(node.seed_peers.is_empty());
        assert_eq!(
            MAINNET_DNS_SEEDS,
            [
                "seed1.dom-protocol.org",
                "seed2.dom-protocol.org",
                "seed3.dom-protocol.org",
            ]
        );
        assert_eq!(MAINNET_P2P_PORT, 33_369);
        assert!(!node.mine);
        assert!(node.wallet_path.is_none());
        assert!(node.wallet_password.is_none());
        assert!(node.rpc_listen_addr.is_none());
    }

    #[test]
    fn regression_lmdb_map_size_default_is_platform_conscious_and_overridable() {
        let expected_default = if cfg!(windows) {
            4 * 1024 * 1024 * 1024
        } else {
            16 * 1024 * 1024 * 1024
        };
        assert_eq!(default_lmdb_map_size(), expected_default);

        let directory = TempDir::new().expect("temporary directory");
        let address = "127.0.0.1:34341".parse().expect("static test address");
        let configuration = EmbeddedCoreConfiguration::mainnet(directory.path(), address);
        assert_eq!(configuration.lmdb_map_size(), expected_default);
        configuration.validate().expect("default map size is valid");

        let doubled = expected_default * 2;
        let grown = EmbeddedCoreConfiguration::mainnet(directory.path(), address)
            .with_lmdb_map_size(doubled);
        assert_eq!(grown.lmdb_map_size(), doubled);
        grown.validate().expect("doubled map size is valid");

        let too_small = EmbeddedCoreConfiguration::mainnet(directory.path(), address)
            .with_lmdb_map_size(MINIMUM_LMDB_MAP_SIZE_BYTES - 1);
        assert!(matches!(
            too_small.validate(),
            Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "LMDB_MAP_SIZE_TOO_SMALL",
            })
        ));
        assert_eq!(LMDB_MAP_FULL_ERROR_CODE, "LMDB_MAP_FULL");
    }

    #[test]
    fn mainnet_configuration_rejects_public_listener_and_self_bootstrap() {
        let directory = TempDir::new().expect("temporary directory");
        let public = EmbeddedCoreConfiguration::mainnet(
            directory.path(),
            "0.0.0.0:33369".parse().expect("address"),
        );
        assert!(public.validate().is_err());
        let address = "127.0.0.1:34341".parse().expect("static test address");
        let self_peer = EmbeddedCoreConfiguration::mainnet(directory.path(), address)
            .with_seed_peers(vec![address]);
        assert!(self_peer.validate().is_err());
    }

    #[test]
    fn mainnet_rejects_non_routable_seed_addresses() {
        let rejected = [
            "0.0.0.0:33369",
            "127.0.0.1:33369",
            "10.0.0.1:33369",
            "100.64.0.1:33369",
            "169.254.1.1:33369",
            "172.16.0.1:33369",
            "192.168.0.1:33369",
            "192.0.2.1:33369",
            "198.18.0.1:33369",
            "198.51.100.1:33369",
            "203.0.113.1:33369",
            "224.0.0.1:33369",
            "255.255.255.255:33369",
            "[::]:33369",
            "[::1]:33369",
            "[::8.8.8.8]:33369",
            "[::ffff:8.8.8.8]:33369",
            "[fc00::1]:33369",
            "[fe80::1]:33369",
            "[ff02::1]:33369",
            "[2001:db8::1]:33369",
            "[2001:2::1]:33369",
        ];
        let directory = TempDir::new().expect("temporary directory");
        for value in rejected {
            let seed = value.parse().expect("test socket address");
            let configuration = EmbeddedCoreConfiguration::mainnet(
                directory.path(),
                "127.0.0.1:34341".parse().expect("static test address"),
            )
            .with_seed_peers(vec![seed]);
            assert!(
                configuration.validate().is_err(),
                "accepted non-routable seed {value}"
            );
        }
    }

    #[test]
    fn explicit_local_peers_remain_available_for_regtest() {
        let directory = TempDir::new().expect("temporary directory");
        for value in ["127.0.0.1:33369", "10.0.0.2:33369", "[::1]:33369"] {
            let configuration = regtest_configuration(directory.path())
                .with_seed_peers(vec![value.parse().expect("test socket address")]);
            assert!(configuration.validate().is_ok(), "rejected {value}");
            assert_eq!(
                configuration.node_config().min_outbound,
                1,
                "an explicit Regtest seed must activate Core's connector"
            );
        }
        assert_eq!(
            regtest_configuration(directory.path())
                .node_config()
                .min_outbound,
            0,
            "an isolated Regtest node must not dial public peers"
        );
    }

    #[test]
    fn public_peer_policy_accepts_global_ipv4_and_ipv6() {
        assert!(is_public_routable_peer(
            "8.8.8.8:33369".parse().expect("public IPv4")
        ));
        assert!(is_public_routable_peer(
            "[2606:4700:4700::1111]:33369".parse().expect("public IPv6")
        ));
        assert!(!is_public_routable_peer(
            "8.8.8.8:0".parse().expect("zero port")
        ));
    }

    #[test]
    fn bootstrap_failure_advances_to_the_next_untried_endpoint() {
        let first: SocketAddr = "8.8.8.8:33369".parse().expect("first test peer");
        let second: SocketAddr = "1.1.1.1:33369".parse().expect("second test peer");
        let mut bootstrap = BootstrapFallbackSequence::new(vec![first, second]);

        assert_eq!(bootstrap.active(), Some(first));
        assert!(bootstrap.has_untried_endpoint());
        assert_eq!(bootstrap.observe_failure(first, 1), Some(second));
        assert_eq!(bootstrap.active(), Some(second));
    }

    #[test]
    fn bootstrap_endpoints_are_deduplicated_by_socket_address() {
        let first: SocketAddr = "8.8.8.8:33369".parse().expect("first test peer");
        let second: SocketAddr = "1.1.1.1:33369".parse().expect("second test peer");
        let bootstrap = BootstrapFallbackSequence::new(vec![first, first, second, second]);

        assert_eq!(bootstrap.endpoints, vec![first, second]);
    }

    #[test]
    fn connected_peer_reports_connected_bootstrap_phase() {
        assert_eq!(bootstrap_phase(1), "CONNECTED");
        assert_eq!(bootstrap_phase(0), "DISCOVERING_PEERS");
    }

    #[test]
    fn peer_status_reads_live_chain_and_peer_height_metrics() {
        let directory = TempDir::new().expect("temporary directory");
        let mut lifecycle = EmbeddedCoreLifecycle::new(regtest_configuration(directory.path()));
        lifecycle.start().expect("Regtest embedded node starts");
        let node = lifecycle.node_handle().expect("node handle");

        node.metrics.chain_height.store(1_008, Ordering::Release);
        node.metrics
            .best_known_peer_height
            .store(6_622, Ordering::Release);
        let status = lifecycle.peer_status().expect("live peer status");

        assert_eq!(status.canonical_height, 1_008);
        assert_eq!(status.highest_known_peer_height, 6_622);
        lifecycle.request_shutdown().expect("shutdown request");
        lifecycle.wait_for_shutdown().expect("shutdown");
    }

    #[test]
    #[ignore = "live Mainnet acceptance gate"]
    fn live_mainnet_bootnode_connects_without_mining() {
        let directory = TempDir::new().expect("temporary directory");
        let mut lifecycle = EmbeddedCoreLifecycle::new(EmbeddedCoreConfiguration::mainnet(
            directory.path(),
            unused_loopback_address(),
        ));
        lifecycle.start().expect("Mainnet embedded node starts");
        let deadline = Instant::now() + Duration::from_secs(45);
        let mut status = lifecycle.peer_status().expect("peer status");
        while status.connected_total == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
            status = lifecycle.peer_status().expect("peer status");
        }
        assert!(
            status.connected_total >= 1,
            "no live Mainnet peer connected"
        );
        assert_eq!(status.canonical_height, 0);
        let node = lifecycle.node_handle().expect("node handle");
        assert_eq!(node.metrics.mining_active.load(Ordering::Relaxed), 0);
        lifecycle.request_shutdown().expect("shutdown request");
        lifecycle.wait_for_shutdown().expect("shutdown");
    }

    #[test]
    fn configuration_fails_before_node_startup() {
        let directory = TempDir::new().expect("temporary directory");
        let configuration = EmbeddedCoreConfiguration::new(
            EmbeddedCoreNetwork::Regtest,
            directory.path(),
            "127.0.0.1:0".parse().expect("socket address"),
        );
        let mut lifecycle = EmbeddedCoreLifecycle::new(configuration);

        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Uninitialized);
        assert!(matches!(
            lifecycle.wallet_api(),
            Err(EmbeddedCoreAdapterError::NotRunning)
        ));
        assert!(matches!(
            lifecycle.start(),
            Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "ZERO_P2P_PORT"
            })
        ));
        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Uninitialized);
    }

    #[test]
    fn initialization_failure_does_not_publish_an_api() {
        let directory = TempDir::new().expect("temporary directory");
        let invalid_path = directory.path().join("not-a-directory");
        fs::write(&invalid_path, b"file").expect("write invalid data path fixture");
        let mut lifecycle = EmbeddedCoreLifecycle::new(regtest_configuration(&invalid_path));

        assert!(matches!(
            lifecycle.start(),
            Err(EmbeddedCoreAdapterError::InitializationFailed { .. })
        ));
        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Failed);
        assert!(matches!(
            lifecycle.wallet_api(),
            Err(EmbeddedCoreAdapterError::NotRunning)
        ));
    }

    #[test]
    fn lifecycle_gates_wallet_api_and_shutdown_is_idempotent() {
        let directory = TempDir::new().expect("temporary directory");
        let mut lifecycle = EmbeddedCoreLifecycle::new(regtest_configuration(directory.path()));

        lifecycle.start().expect("start embedded Core");
        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Running);
        let api = lifecycle.wallet_api().expect("running Wallet Core API");
        let identity = api.chain_identity().expect("chain identity");
        assert_eq!(identity.network, dom_wallet_core_api::CoreNetwork::Regtest);
        assert_eq!(
            lifecycle
                .peer_status()
                .expect("peer status")
                .seed_resolution_states,
            vec!["PENDING"; MAINNET_DNS_SEEDS.len()]
        );
        assert!(lifecycle.sync_status().is_ok());
        assert!(lifecycle.is_ready_for_wallet_operations().is_ok());
        assert!(matches!(
            lifecycle.start(),
            Err(EmbeddedCoreAdapterError::InvalidConfiguration {
                code: "LIFECYCLE_ALREADY_STARTED"
            })
        ));

        lifecycle.request_shutdown().expect("request shutdown");
        lifecycle.request_shutdown().expect("repeat shutdown");
        assert!(matches!(
            api.chain_identity(),
            Err(WalletCoreError::NodeNotReady(_))
        ));
        lifecycle.wait_for_shutdown().expect("join node runtime");
        assert_eq!(lifecycle.state(), EmbeddedCoreLifecycleState::Stopped);
        lifecycle.request_shutdown().expect("shutdown after stop");
    }

    #[test]
    fn dropping_running_owner_releases_listener() {
        let directory = TempDir::new().expect("temporary directory");
        let address = unused_loopback_address();
        let configuration =
            EmbeddedCoreConfiguration::new(EmbeddedCoreNetwork::Regtest, directory.path(), address);
        let mut lifecycle = EmbeddedCoreLifecycle::new(configuration);
        lifecycle.start().expect("start embedded Core");

        drop(lifecycle);

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match TcpListener::bind(address) {
                Ok(listener) => {
                    drop(listener);
                    break;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("listener was not released: {error}"),
            }
        }
    }

    #[test]
    fn public_source_uses_only_the_frozen_node_boundary() {
        let source = include_str!("lib.rs");
        for forbidden in [
            concat!("req", "west"),
            concat!("http", "://"),
            concat!("https", "://"),
            concat!("rpc", " route"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden API reference: {forbidden}"
            );
        }
    }
}

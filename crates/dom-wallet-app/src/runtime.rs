use crate::storage::{self, AppStorageError, PersistedAppState};
use anyhow::Context;
use dom_core::Address;
use dom_core::Hash256;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_serialization::DomDeserialize;
use dom_wallet::{
    Bip39Seed, Network, NodeRpc, NodeRpcClient, NodeStatus, ReceiveRequestDescriptor,
    ReceiveRequestStatus, RpcClientError, SeedAcceptance, Transaction, TxJournal, TxStatus, Wallet,
    WalletBalance, WalletDir,
};
use dom_wire::message::{Command, WireMessage};
use rand::RngCore;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const INITIAL_RECONNECT_DELAY_SECS: u64 = 1;
const MAX_RECONNECT_DELAY_SECS: u64 = 60;
const HEARTBEAT_TIMEOUT_SECS: u64 = 15;
const PENDING_RESUBMIT_INTERVAL_SECS: u64 = 60;
const DIAGNOSTIC_LOG_MAX_ENTRIES: usize = 512;
const DIAGNOSTIC_LOG_MAX_EXPORT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Splash,
    Welcome,
    Create,
    Restore,
    Unlock,
    Dashboard,
    Receive,
    Send,
    History,
    Diagnostics,
    Settings,
}

#[derive(Debug, Clone)]
pub struct HistoryRow {
    pub timestamp: u64,
    pub tx_hash_hex: String,
    pub status: String,
    pub warning: Option<String>,
    pub can_cancel: bool,
    pub can_rebroadcast: bool,
}

#[derive(Clone)]
pub struct ReceiveRow {
    pub index: u32,
    pub amount: u64,
    pub address: String,
    pub commitment_hex: String,
    pub blinding_hex: String,
    pub request_text: String,
    pub created_at: u64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPaymentRequest {
    pub network: Network,
    pub amount: u64,
    pub address: String,
    pub commitment_hex: String,
    pub blinding_hex: String,
}

pub struct WalletSession {
    pub wallet_dir: WalletDir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildDiagnostics {
    pub app_version: &'static str,
    pub git_hash: &'static str,
}

impl Default for BuildDiagnostics {
    fn default() -> Self {
        Self {
            app_version: env!("CARGO_PKG_VERSION"),
            git_hash: option_env!("GITHUB_SHA")
                .or(option_env!("DOM_GIT_HASH"))
                .or(option_env!("VERGEN_GIT_SHA"))
                .unwrap_or("unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticLog {
    entries: VecDeque<String>,
    max_entries: usize,
    max_export_bytes: usize,
    build: BuildDiagnostics,
}

impl Default for DiagnosticLog {
    fn default() -> Self {
        Self::new(
            DIAGNOSTIC_LOG_MAX_ENTRIES,
            DIAGNOSTIC_LOG_MAX_EXPORT_BYTES,
            BuildDiagnostics::default(),
        )
    }
}

impl DiagnosticLog {
    pub fn new(max_entries: usize, max_export_bytes: usize, build: BuildDiagnostics) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries,
            max_export_bytes,
            build,
        }
    }

    pub fn append(&mut self, timestamp: u64, event: &str, detail: impl AsRef<str>) {
        let line = format!(
            "ts={timestamp} event={} {}",
            redact_secret_text(event),
            redact_secret_text(detail.as_ref())
        );
        self.entries.push_back(line);
        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }

    pub fn append_network_snapshot(
        &mut self,
        timestamp: u64,
        network: Option<Network>,
        backbone_peer: &str,
        status: &NetworkStatus,
    ) {
        self.append(
            timestamp,
            "network_snapshot",
            format!(
                "app_version={} git_hash={} network_mode={} backbone_peers={} state={} connected_peer={} peer_count={} reconnect_delay={}s last_error={}",
                self.build.app_version,
                self.build.git_hash,
                network.map(network_name).unwrap_or("unconfigured"),
                backbone_peer,
                status.state.label(),
                status.connected_peer.as_deref().unwrap_or("none"),
                status.peer_count,
                status.reconnect_delay.as_secs(),
                status.last_error.as_deref().unwrap_or("none")
            ),
        );
    }

    pub fn export_text(&self) -> String {
        let mut out = format!(
            "DOM wallet diagnostics\napp_version={}\ngit_hash={}\n",
            self.build.app_version, self.build.git_hash
        );
        for entry in &self.entries {
            out.push_str(entry);
            out.push('\n');
            if out.len() > self.max_export_bytes {
                out.truncate(self.max_export_bytes);
                out.push_str("\n[truncated]\n");
                break;
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn redact_secret_text(input: &str) -> String {
    let sensitive = [
        "password",
        "wallet_password",
        "seed",
        "seed_phrase",
        "private_key",
        "secret_key",
        "token",
        "bearer",
        "authorization",
    ];
    let mut out = Vec::new();
    let mut redact_next = 0usize;
    for part in input.split_whitespace() {
        if redact_next > 0 {
            out.push("<redacted>".to_string());
            redact_next -= 1;
            continue;
        }
        let lower = part.to_ascii_lowercase();
        if lower == "bearer" {
            out.push("bearer <redacted>".to_string());
            redact_next = 1;
        } else if lower == "authorization" || lower == "authorization:" {
            out.push(format!("{} <redacted>", part.trim_end_matches(':')));
            redact_next = 2;
        } else if sensitive.iter().any(|key| {
            lower.starts_with(&format!("{key}=")) || lower.starts_with(&format!("{key}:"))
        }) {
            let separator = if part.contains('=') { '=' } else { ':' };
            let key = part.split(['=', ':']).next().unwrap_or(part);
            out.push(format!("{key}{separator}<redacted>"));
        } else {
            out.push(part.to_string());
        }
    }
    out.join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkStatusState {
    Disconnected,
    TcpConnecting,
    TcpConnected,
    Handshaking,
    Connected,
    Reconnecting,
    Failed,
}

impl NetworkStatusState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::TcpConnecting => "TCP connecting",
            Self::TcpConnected => "TCP connected",
            Self::Handshaking => "Handshaking",
            Self::Connected => "Connected",
            Self::Reconnecting => "Reconnecting",
            Self::Failed => "Failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkStatus {
    pub state: NetworkStatusState,
    pub last_error: Option<String>,
    pub last_tcp_connect_at: Option<u64>,
    pub last_handshake_at: Option<u64>,
    pub last_pong_at: Option<u64>,
    pub reconnect_delay: Duration,
    pub connected_peer: Option<String>,
    pub peer_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDiagnosticsRows {
    pub state: String,
    pub connected_peer: String,
    pub last_error: String,
    pub last_tcp_connect: String,
    pub last_handshake: String,
    pub last_pong: String,
    pub reconnect_delay: String,
    pub peer_count: String,
}

impl NetworkStatus {
    pub fn diagnostics_rows(&self) -> NetworkDiagnosticsRows {
        NetworkDiagnosticsRows {
            state: self.state.label().to_string(),
            connected_peer: self
                .connected_peer
                .clone()
                .unwrap_or_else(|| "none".to_string()),
            last_error: self
                .last_error
                .clone()
                .unwrap_or_else(|| "none".to_string()),
            last_tcp_connect: format_optional_timestamp(self.last_tcp_connect_at),
            last_handshake: format_optional_timestamp(self.last_handshake_at),
            last_pong: format_optional_timestamp(self.last_pong_at),
            reconnect_delay: format!("{}s", self.reconnect_delay.as_secs()),
            peer_count: self.peer_count.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatError {
    NoPingInFlight,
    MalformedPong { len: usize },
    NonceMismatch { expected: u64, got: u64 },
    Timeout { nonce: u64 },
    UnexpectedCommand(Command),
}

impl std::fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPingInFlight => write!(f, "pong received without ping in flight"),
            Self::MalformedPong { len } => write!(f, "pong payload must be 8 bytes, got {len}"),
            Self::NonceMismatch { expected, got } => {
                write!(f, "pong nonce mismatch: expected {expected}, got {got}")
            }
            Self::Timeout { nonce } => write!(f, "pong timeout for nonce {nonce}"),
            Self::UnexpectedCommand(command) => {
                write!(f, "unexpected heartbeat command: {command:?}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatEvent {
    None,
    PongAccepted,
    ReconnectRequired(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatSession {
    pending_nonce: Option<u64>,
    ping_sent_at: Option<u64>,
    timeout: Duration,
}

impl Default for HeartbeatSession {
    fn default() -> Self {
        Self {
            pending_nonce: None,
            ping_sent_at: None,
            timeout: Duration::from_secs(HEARTBEAT_TIMEOUT_SECS),
        }
    }
}

impl HeartbeatSession {
    pub fn begin_ping_with_nonce(
        &mut self,
        now_secs: u64,
        network_magic: u32,
        nonce: u64,
    ) -> WireMessage {
        self.pending_nonce = Some(nonce);
        self.ping_sent_at = Some(now_secs);
        WireMessage {
            magic: network_magic,
            command: Command::Ping,
            payload: nonce.to_le_bytes().to_vec(),
        }
    }

    pub fn begin_ping(&mut self, now_secs: u64, network_magic: u32) -> WireMessage {
        let nonce = rand::thread_rng().next_u64();
        self.begin_ping_with_nonce(now_secs, network_magic, nonce)
    }

    pub fn observe_message(
        &mut self,
        status: &mut NetworkStatus,
        now_secs: u64,
        message: &WireMessage,
    ) -> Result<HeartbeatEvent, HeartbeatError> {
        if message.command != Command::Pong {
            return Ok(HeartbeatEvent::None);
        }
        let nonce = decode_pong_nonce(&message.payload)?;
        match self.pending_nonce {
            Some(expected) if expected == nonce => {
                self.pending_nonce = None;
                self.ping_sent_at = None;
                status.last_pong_at = Some(now_secs);
                Ok(HeartbeatEvent::PongAccepted)
            }
            Some(expected) => Err(HeartbeatError::NonceMismatch {
                expected,
                got: nonce,
            }),
            None => Err(HeartbeatError::NoPingInFlight),
        }
    }

    pub fn check_timeout(&mut self, status: &mut NetworkStatus, now_secs: u64) -> HeartbeatEvent {
        let Some(sent_at) = self.ping_sent_at else {
            return HeartbeatEvent::None;
        };
        if now_secs.saturating_sub(sent_at) < self.timeout.as_secs() {
            return HeartbeatEvent::None;
        }
        let nonce = self.pending_nonce.take().unwrap_or_default();
        self.ping_sent_at = None;
        let error = HeartbeatError::Timeout { nonce }.to_string();
        status.mark_reconnecting(error.clone());
        HeartbeatEvent::ReconnectRequired(error)
    }

    pub fn clear(&mut self) {
        self.pending_nonce = None;
        self.ping_sent_at = None;
    }
}

fn decode_pong_nonce(payload: &[u8]) -> Result<u64, HeartbeatError> {
    let bytes: [u8; 8] = payload
        .try_into()
        .map_err(|_| HeartbeatError::MalformedPong { len: payload.len() })?;
    Ok(u64::from_le_bytes(bytes))
}

fn format_optional_timestamp(timestamp: Option<u64>) -> String {
    timestamp
        .map(|value| value.to_string())
        .unwrap_or_else(|| "never".to_string())
}

impl Default for NetworkStatus {
    fn default() -> Self {
        Self {
            state: NetworkStatusState::Disconnected,
            last_error: None,
            last_tcp_connect_at: None,
            last_handshake_at: None,
            last_pong_at: None,
            reconnect_delay: Duration::from_secs(INITIAL_RECONNECT_DELAY_SECS),
            connected_peer: None,
            peer_count: 0,
        }
    }
}

impl NetworkStatus {
    pub fn state_label(&self) -> &'static str {
        self.state.label()
    }

    pub fn reconnect_delay_secs(&self) -> u64 {
        self.reconnect_delay.as_secs()
    }

    pub fn observe_peer_registry_count(&mut self, peer_count: usize) {
        self.peer_count = peer_count;
    }

    fn mark_tcp_connecting(&mut self) {
        self.state = NetworkStatusState::TcpConnecting;
    }

    fn mark_tcp_connected(&mut self, now_secs: u64, peer: impl Into<String>) {
        self.state = NetworkStatusState::TcpConnected;
        self.last_tcp_connect_at = Some(now_secs);
        self.connected_peer = Some(peer.into());
    }

    fn mark_handshaking(&mut self) {
        self.state = NetworkStatusState::Handshaking;
    }

    fn mark_connected(&mut self, now_secs: u64, peer: impl Into<String>) {
        let peer = peer.into();
        self.state = NetworkStatusState::Connected;
        self.last_tcp_connect_at = Some(now_secs);
        self.last_handshake_at = Some(now_secs);
        self.connected_peer = Some(peer);
        self.last_error = None;
        self.reconnect_delay = Duration::from_secs(INITIAL_RECONNECT_DELAY_SECS);
    }

    fn mark_reconnecting(&mut self, error: impl Into<String>) {
        self.state = NetworkStatusState::Reconnecting;
        self.last_error = Some(error.into());
        self.connected_peer = None;
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Default)]
pub struct NodeConnectionSession {
    client: Option<NodeRpcClient>,
    pub status: NetworkStatus,
    pub heartbeat: HeartbeatSession,
    next_reconnect_at: Option<u64>,
    consecutive_failures: u32,
}

impl NodeConnectionSession {
    pub fn state_label(&self) -> &'static str {
        self.status.state_label()
    }

    pub fn reconnect_delay_secs(&self) -> u64 {
        self.status.reconnect_delay_secs()
    }

    pub fn next_reconnect_at(&self) -> Option<u64> {
        self.next_reconnect_at
    }

    pub fn is_reconnect_due(&self, now_secs: u64) -> bool {
        match self.status.state {
            NetworkStatusState::Disconnected | NetworkStatusState::Failed => true,
            NetworkStatusState::Connected
            | NetworkStatusState::TcpConnecting
            | NetworkStatusState::TcpConnected
            | NetworkStatusState::Handshaking => false,
            NetworkStatusState::Reconnecting => self
                .next_reconnect_at
                .map(|deadline| now_secs >= deadline)
                .unwrap_or(true),
        }
    }

    fn begin_attempt(
        &mut self,
        node_url: &str,
        now_secs: u64,
    ) -> Result<&NodeRpcClient, RpcClientError> {
        self.status.mark_tcp_connecting();
        if self.client.is_none() {
            self.client = Some(node_client(node_url)?);
        }
        self.status.mark_tcp_connected(now_secs, node_url);
        self.status.mark_handshaking();
        Ok(self.client.as_ref().expect("client just initialized"))
    }

    fn on_success(&mut self, now_secs: u64, peer: &str) {
        self.status.mark_connected(now_secs, peer);
        self.next_reconnect_at = None;
        self.consecutive_failures = 0;
    }

    fn on_session_closed(&mut self, now_secs: u64, error: impl Into<String>) {
        self.client = None;
        self.heartbeat.clear();
        self.status.mark_reconnecting(error);
        self.next_reconnect_at =
            Some(now_secs.saturating_add(self.status.reconnect_delay.as_secs()));
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let next_delay = self
            .status
            .reconnect_delay
            .as_secs()
            .saturating_mul(2)
            .max(1);
        self.status.reconnect_delay = Duration::from_secs(next_delay.min(MAX_RECONNECT_DELAY_SECS));
    }

    fn reset(&mut self) {
        self.client = None;
        self.heartbeat.clear();
        self.status.reset();
        self.next_reconnect_at = None;
        self.consecutive_failures = 0;
    }
}

pub struct AppRuntime {
    pub data_dir: PathBuf,
    pub persisted: PersistedAppState,
    pub screen: Screen,
    pub session: Option<WalletSession>,
    pub node_connection: NodeConnectionSession,
    pub node_status: Option<NodeStatus>,
    pub wallet_balance: Option<WalletBalance>,
    pub history: Vec<HistoryRow>,
    pub receive_requests: Vec<ReceiveRow>,
    pub last_error: Option<String>,
    pub diagnostic_log: DiagnosticLog,
    next_pending_resubmit_at: Option<u64>,
}

impl AppRuntime {
    pub fn load(data_dir: PathBuf) -> Result<Self, AppStorageError> {
        let persisted = storage::load_or_default(&data_dir)?;
        Ok(Self {
            data_dir,
            persisted,
            screen: Screen::Splash,
            session: None,
            node_connection: NodeConnectionSession::default(),
            node_status: None,
            wallet_balance: None,
            history: Vec::new(),
            receive_requests: Vec::new(),
            last_error: None,
            diagnostic_log: DiagnosticLog::default(),
            next_pending_resubmit_at: None,
        })
    }

    pub fn complete_bootstrap(&mut self) {
        self.screen = if self.persisted.wallet_dir.is_some() {
            Screen::Unlock
        } else {
            Screen::Welcome
        };
    }

    pub fn save_persisted(&self) -> Result<(), AppStorageError> {
        storage::save(&self.data_dir, &self.persisted)
    }

    pub fn export_diagnostics(&mut self) -> Result<PathBuf, AppStorageError> {
        std::fs::create_dir_all(&self.data_dir).map_err(|e| AppStorageError::Io(e.to_string()))?;
        self.diagnostic_log.append_network_snapshot(
            unix_now(),
            self.persisted.network,
            &self.persisted.node_url,
            &self.node_connection.status,
        );
        let path = self
            .data_dir
            .join(format!("dom-wallet-diagnostics-{}.log", unix_now()));
        let mut file = File::create(&path).map_err(|e| AppStorageError::Io(e.to_string()))?;
        file.write_all(self.diagnostic_log.export_text().as_bytes())
            .map_err(|e| AppStorageError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| AppStorageError::Io(e.to_string()))?;
        Ok(path)
    }

    pub fn set_error(&mut self, error: impl Into<String>) {
        let error = error.into();
        self.diagnostic_log.append(unix_now(), "error", &error);
        self.last_error = Some(error);
    }

    pub fn clear_error(&mut self) {
        self.last_error = None;
    }

    pub fn create_wallet(
        &mut self,
        wallet_dir: PathBuf,
        password: &str,
        network: Network,
    ) -> anyhow::Result<String> {
        let seed = Bip39Seed::generate_new()?;
        let phrase = seed.phrase().to_string();
        let genesis_hash = genesis_hash_for(network)?;
        let wallet_dir_handle =
            WalletDir::create_from_seed(&wallet_dir, password, network, &genesis_hash, &seed)?;
        drop(wallet_dir_handle);

        self.persisted.wallet_dir = Some(wallet_dir);
        self.persisted.network = Some(network);
        self.save_persisted()?;
        self.screen = Screen::Unlock;
        Ok(phrase)
    }

    pub fn restore_wallet(
        &mut self,
        wallet_dir: PathBuf,
        password: &str,
        network: Network,
        phrase: &str,
    ) -> anyhow::Result<()> {
        let seed = Bip39Seed::from_phrase(phrase, SeedAcceptance::NewWallet)?;
        let genesis_hash = genesis_hash_for(network)?;
        let wallet_dir_handle =
            WalletDir::create_from_seed(&wallet_dir, password, network, &genesis_hash, &seed)?;
        drop(wallet_dir_handle);

        self.persisted.wallet_dir = Some(wallet_dir);
        self.persisted.network = Some(network);
        self.save_persisted()?;
        self.screen = Screen::Unlock;
        Ok(())
    }

    pub fn unlock_wallet(&mut self, password: &str) -> anyhow::Result<()> {
        let wallet_dir_path = self
            .persisted
            .wallet_dir
            .clone()
            .ok_or_else(|| anyhow::anyhow!("wallet directory is not configured"))?;
        let wallet_dir = WalletDir::open(&wallet_dir_path, password)?;
        self.session = Some(WalletSession { wallet_dir });
        self.next_pending_resubmit_at = None;
        self.diagnostic_log.append(
            unix_now(),
            "wallet_unlocked",
            format!(
                "network_mode={} backbone_peers={}",
                self.persisted
                    .network
                    .map(network_name)
                    .unwrap_or("unconfigured"),
                self.persisted.node_url
            ),
        );
        self.refresh_wallet_view();
        let _ = self.refresh_node_status();
        self.screen = Screen::Dashboard;
        Ok(())
    }

    pub fn lock_wallet(&mut self) {
        self.diagnostic_log
            .append(unix_now(), "wallet_locked", "session closed");
        self.session = None;
        self.node_connection.reset();
        self.next_pending_resubmit_at = None;
        self.node_status = None;
        self.wallet_balance = None;
        self.history.clear();
        self.receive_requests.clear();
        self.screen = if self.persisted.wallet_dir.is_some() {
            Screen::Unlock
        } else {
            Screen::Welcome
        };
    }

    pub fn refresh_node_status(&mut self) -> Result<(), RpcClientError> {
        self.refresh_node_status_at(unix_now())
    }

    pub fn poll_node_reconnect(&mut self) {
        if self.session.is_none() || !self.node_connection.is_reconnect_due(unix_now()) {
            return;
        }
        if let Err(e) = self.refresh_node_status() {
            self.last_error = Some(format!("node reconnect: {e}"));
        }
    }

    pub fn poll_pending_resubmit(&mut self) {
        self.poll_pending_resubmit_at(unix_now());
    }

    fn poll_pending_resubmit_at(&mut self, now_secs: u64) {
        if self.session.is_none()
            || self.node_connection.status.state != NetworkStatusState::Connected
        {
            return;
        }
        let Some(client) = self.node_connection.client.clone() else {
            return;
        };
        let _ = self.resubmit_pending_transactions_due_with(&client, now_secs, false);
    }

    pub fn send_heartbeat_ping(&mut self, now_secs: u64) -> Option<WireMessage> {
        if self.node_connection.status.state != NetworkStatusState::Connected {
            return None;
        }
        let network = self.persisted.network?;
        Some(
            self.node_connection
                .heartbeat
                .begin_ping(now_secs, network.magic()),
        )
    }

    pub fn handle_heartbeat_message(
        &mut self,
        now_secs: u64,
        message: &WireMessage,
    ) -> Result<HeartbeatEvent, HeartbeatError> {
        let event = self.node_connection.heartbeat.observe_message(
            &mut self.node_connection.status,
            now_secs,
            message,
        )?;
        if event == HeartbeatEvent::PongAccepted {
            self.diagnostic_log
                .append(now_secs, "heartbeat_pong", "valid matching pong");
        }
        Ok(event)
    }

    pub fn check_heartbeat_timeout(&mut self, now_secs: u64) -> HeartbeatEvent {
        let event = self
            .node_connection
            .heartbeat
            .check_timeout(&mut self.node_connection.status, now_secs);
        if let HeartbeatEvent::ReconnectRequired(error) = &event {
            self.node_connection
                .on_session_closed(now_secs, error.clone());
            self.diagnostic_log
                .append(now_secs, "connection_reconnecting", error);
        }
        event
    }

    fn refresh_node_status_at(&mut self, now_secs: u64) -> Result<(), RpcClientError> {
        let was_connected = self.node_connection.status.state == NetworkStatusState::Connected;
        let status = match self
            .node_connection
            .begin_attempt(&self.persisted.node_url, now_secs)
        {
            Ok(client) => client.status(),
            Err(err) => Err(err),
        };
        let previous_height = self.node_status.as_ref().map(|status| status.chain_height);
        let status = match status {
            Ok(status) => status,
            Err(err) => {
                self.node_status = None;
                self.next_pending_resubmit_at = None;
                self.node_connection
                    .on_session_closed(now_secs, err.to_string());
                self.diagnostic_log
                    .append(now_secs, "connection_error", err.to_string());
                return Err(err);
            }
        };
        if previous_height != Some(status.chain_height) {
            self.diagnostic_log.append(
                now_secs,
                "chain_height_changed",
                format!(
                    "from={} to={}",
                    previous_height
                        .map(|height| height.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    status.chain_height
                ),
            );
        }
        self.node_status = Some(status);
        self.node_connection
            .on_success(now_secs, &self.persisted.node_url);
        let force_pending_resubmit = !was_connected || self.next_pending_resubmit_at.is_none();
        if let Some(client) = self.node_connection.client.clone() {
            let _ = self.resubmit_pending_transactions_due_with(
                &client,
                now_secs,
                force_pending_resubmit,
            );
        }
        self.diagnostic_log.append_network_snapshot(
            now_secs,
            self.persisted.network,
            &self.persisted.node_url,
            &self.node_connection.status,
        );
        self.refresh_wallet_view();
        Ok(())
    }

    fn resubmit_pending_transactions_due_with<R: NodeRpc>(
        &mut self,
        rpc: &R,
        now_secs: u64,
        force: bool,
    ) -> PendingResubmitSummary {
        if !force
            && self
                .next_pending_resubmit_at
                .map(|deadline| now_secs < deadline)
                .unwrap_or(false)
        {
            return PendingResubmitSummary::default();
        }
        self.next_pending_resubmit_at =
            Some(now_secs.saturating_add(PENDING_RESUBMIT_INTERVAL_SECS));
        self.resubmit_pending_transactions_with(rpc, now_secs)
    }

    fn resubmit_pending_transactions_with<R: NodeRpc>(
        &mut self,
        rpc: &R,
        now_secs: u64,
    ) -> PendingResubmitSummary {
        let mut summary = PendingResubmitSummary::default();
        let Some(session) = self.session.as_mut() else {
            return summary;
        };

        let records = match TxJournal::open(session.wallet_dir.path()).and_then(|j| j.replay()) {
            Ok(records) => records,
            Err(err) => {
                self.diagnostic_log.append(
                    now_secs,
                    "pending_resubmit_journal_error",
                    err.to_string(),
                );
                return summary;
            }
        };

        let mut candidates = Vec::new();
        for (tx_hash, record) in records {
            if !matches!(record.status, TxStatus::Building | TxStatus::Submitted) {
                continue;
            }
            let Some(tx_bytes) = session.wallet_dir.wallet().pending_tx_bytes(&tx_hash) else {
                continue;
            };
            let tx = match Transaction::from_bytes(tx_bytes) {
                Ok(tx) => tx,
                Err(err) => {
                    let reason = format!("pending tx bytes decode failed: {err}");
                    if let Err(mark_err) = session
                        .wallet_dir
                        .wallet_mut()
                        .mark_failed(tx_hash, &reason)
                    {
                        self.diagnostic_log.append(
                            now_secs,
                            "pending_resubmit_mark_failed_error",
                            format!(
                                "tx={} reason={} mark_failed={mark_err}",
                                hex::encode(tx_hash),
                                reason
                            ),
                        );
                    }
                    summary.failed += 1;
                    continue;
                }
            };
            candidates.push((tx_hash, record.status, tx));
        }

        for (pending_key, status, tx) in candidates {
            summary.attempted += 1;
            match rpc.submit_tx(&tx) {
                Ok(outcome) => {
                    if let Some(warning) = &outcome.warning {
                        self.diagnostic_log.append(
                            now_secs,
                            "pending_resubmit_warning",
                            format!("tx={} warning={warning}", hex::encode(outcome.tx_hash)),
                        );
                    }
                    if matches!(status, TxStatus::Building) {
                        if let Err(err) =
                            session.wallet_dir.wallet_mut().mark_submitted(pending_key)
                        {
                            self.diagnostic_log.append(
                                now_secs,
                                "pending_resubmit_mark_submitted_error",
                                format!("tx={} error={err}", hex::encode(pending_key)),
                            );
                        }
                    }
                    summary.submitted += 1;
                }
                Err(RpcClientError::NodeRejected { status: 409, .. }) => {
                    if matches!(status, TxStatus::Building) {
                        if let Err(err) =
                            session.wallet_dir.wallet_mut().mark_submitted(pending_key)
                        {
                            self.diagnostic_log.append(
                                now_secs,
                                "pending_resubmit_mark_submitted_error",
                                format!("tx={} error={err}", hex::encode(pending_key)),
                            );
                        }
                    }
                    summary.already_in_mempool += 1;
                }
                Err(err) if pending_resubmit_should_retry(&err) => {
                    self.diagnostic_log.append(
                        now_secs,
                        "pending_resubmit_retry_later",
                        format!("tx={} error={err}", hex::encode(pending_key)),
                    );
                    summary.retry_later += 1;
                }
                Err(err) => {
                    let reason = format!("pending resubmit stopped: {err}");
                    tracing::warn!(
                        "pending tx {} marked failed: {reason}",
                        hex::encode(pending_key)
                    );
                    if let Err(mark_err) = session
                        .wallet_dir
                        .wallet_mut()
                        .mark_failed(pending_key, &reason)
                    {
                        self.diagnostic_log.append(
                            now_secs,
                            "pending_resubmit_mark_failed_error",
                            format!(
                                "tx={} reason={} mark_failed={mark_err}",
                                hex::encode(pending_key),
                                reason
                            ),
                        );
                    }
                    self.diagnostic_log.append(
                        now_secs,
                        "pending_resubmit_failed",
                        format!("tx={} reason={reason}", hex::encode(pending_key)),
                    );
                    summary.failed += 1;
                }
            }
        }

        if summary.attempted > 0 {
            self.diagnostic_log.append(
                now_secs,
                "pending_resubmit_summary",
                format!(
                    "attempted={} submitted={} already_in_mempool={} retry_later={} failed={}",
                    summary.attempted,
                    summary.submitted,
                    summary.already_in_mempool,
                    summary.retry_later,
                    summary.failed
                ),
            );
        }
        self.refresh_wallet_view();
        summary
    }

    pub fn refresh_wallet_view(&mut self) {
        let Some(session) = &self.session else {
            self.wallet_balance = None;
            self.history.clear();
            self.receive_requests.clear();
            return;
        };

        let current_height = self
            .node_status
            .as_ref()
            .map(|s| s.chain_height)
            .unwrap_or(0);
        self.wallet_balance = Some(session.wallet_dir.wallet().balance(current_height));
        let rpc_client = node_client(&self.persisted.node_url).ok();
        self.history = journal_rows(
            session.wallet_dir.path(),
            session.wallet_dir.wallet(),
            rpc_client.as_ref(),
        );
        match session.wallet_dir.wallet().receive_descriptors() {
            Ok(rows) => {
                let network = session.wallet_dir.wallet().network();
                self.receive_requests = rows
                    .into_iter()
                    .map(|row| receive_row(network, row))
                    .collect();
            }
            Err(e) => {
                self.receive_requests.clear();
                self.set_error(format!("receive descriptor validation: {e}"));
            }
        }
    }

    pub fn create_receive_request(&mut self, amount: u64) -> anyhow::Result<()> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
        session
            .wallet_dir
            .wallet_mut()
            .create_receive_request(amount)?;
        self.refresh_wallet_view();
        Ok(())
    }

    pub fn refresh_receive_statuses(&mut self) -> anyhow::Result<()> {
        let Some(session) = self.session.as_mut() else {
            return Err(anyhow::anyhow!("wallet is not unlocked"));
        };

        let client = node_client(&self.persisted.node_url)?;
        let descriptors = session.wallet_dir.wallet().receive_descriptors()?;
        for descriptor in descriptors {
            let commitment = parse_commitment_hex(&descriptor.commitment_hex)?;
            let next_status =
                client
                    .utxo(&commitment)?
                    .map(|utxo| ReceiveRequestStatus::Detected {
                        block_height: utxo.block_height,
                        is_coinbase: utxo.is_coinbase,
                        is_mature: utxo.is_mature,
                    });
            session
                .wallet_dir
                .wallet_mut()
                .update_receive_request_status(&commitment, next_status)?;
        }
        self.refresh_wallet_view();
        Ok(())
    }

    pub fn submit_payment_request(
        &mut self,
        request_text: &str,
        fee: u64,
    ) -> anyhow::Result<[u8; 32]> {
        let request = parse_payment_request(request_text)?;
        let wallet_network = self
            .persisted
            .network
            .ok_or_else(|| anyhow::anyhow!("wallet network is not configured"))?;
        if request.network != wallet_network {
            return Err(anyhow::anyhow!(
                "payment request network {:?} does not match wallet network {:?}",
                request.network,
                wallet_network
            ));
        }

        let client = node_client(&self.persisted.node_url)?;
        let status = client.status()?;
        self.node_status = Some(status.clone());

        let blinding = parse_blinding_hex(&request.blinding_hex)?;
        let commitment = parse_commitment_hex(&request.commitment_hex)?;

        let tx = {
            let session = self
                .session
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
            session.wallet_dir.wallet_mut().build_spend(
                Commitment::from_compressed_bytes(&commitment)
                    .map_err(|e| anyhow::anyhow!("recipient commitment decode: {e}"))?,
                blinding,
                request.amount,
                fee,
                status.chain_height,
            )?
        };

        let tx_hash = Wallet::tracking_tx_hash(&tx)?;
        match client.submit_tx(&tx) {
            Ok(outcome) => {
                if let Some(warning) = &outcome.warning {
                    tracing::warn!(
                        "transaction {} accepted with relay warning: {warning}",
                        tx_hash_hex(outcome.tx_hash)
                    );
                }
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
                session.wallet_dir.wallet_mut().mark_submitted(tx_hash)?;
            }
            Err(RpcClientError::NodeRejected { status: 409, .. }) => {
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
                session.wallet_dir.wallet_mut().mark_submitted(tx_hash)?;
            }
            Err(RpcClientError::NodeRejected { reason, .. }) => {
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
                session
                    .wallet_dir
                    .wallet_mut()
                    .mark_failed(tx_hash, reason.clone())?;
                self.refresh_wallet_view();
                return Err(anyhow::anyhow!(
                    "node rejected transaction {}: {}. reservations remain until you cancel or replace it",
                    tx_hash_hex(tx_hash),
                    reason
                ));
            }
            Err(err) => {
                self.refresh_wallet_view();
                return Err(anyhow::anyhow!(
                    "submission outcome for {} is unknown: {err}. transaction remains journaled as building for restart-safe recovery",
                    tx_hash_hex(tx_hash)
                ));
            }
        }

        self.refresh_wallet_view();
        Ok(tx_hash)
    }

    pub fn cancel_transaction(&mut self, tx_hash_hex: &str) -> anyhow::Result<()> {
        let tx_hash = parse_hash_hex(tx_hash_hex)?;
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
        session.wallet_dir.wallet_mut().cancel_tx(tx_hash)?;
        self.refresh_wallet_view();
        Ok(())
    }

    pub fn rebroadcast_transaction(&mut self, tx_hash_hex_str: &str) -> anyhow::Result<()> {
        let tx_hash = parse_hash_hex(tx_hash_hex_str)?;
        let client = node_client(&self.persisted.node_url)?;
        let tx = {
            let session = self
                .session
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
            let tx_bytes = session
                .wallet_dir
                .wallet()
                .pending_tx_bytes(&tx_hash)
                .ok_or_else(|| anyhow::anyhow!("pending transaction bytes unavailable"))?;
            Transaction::from_bytes(tx_bytes)
                .map_err(|e| anyhow::anyhow!("decode pending transaction bytes: {e}"))?
        };

        match client.submit_tx(&tx) {
            Ok(outcome) => {
                if let Some(warning) = &outcome.warning {
                    tracing::warn!(
                        "rebroadcast {} accepted with relay warning: {warning}",
                        tx_hash_hex(outcome.tx_hash)
                    );
                }
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
                session.wallet_dir.wallet_mut().mark_submitted(tx_hash)?;
            }
            Err(RpcClientError::NodeRejected { status: 409, .. }) => {
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
                session.wallet_dir.wallet_mut().mark_submitted(tx_hash)?;
            }
            Err(RpcClientError::NodeRejected { reason, .. }) => {
                let session = self
                    .session
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("wallet is not unlocked"))?;
                session
                    .wallet_dir
                    .wallet_mut()
                    .mark_failed(tx_hash, reason.clone())?;
                self.refresh_wallet_view();
                return Err(anyhow::anyhow!(
                    "rebroadcast rejected for {}: {}",
                    tx_hash_hex(tx_hash),
                    reason
                ));
            }
            Err(err) => {
                self.refresh_wallet_view();
                return Err(anyhow::anyhow!(
                    "rebroadcast outcome for {} is unknown: {err}",
                    tx_hash_hex(tx_hash)
                ));
            }
        }

        self.refresh_wallet_view();
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PendingResubmitSummary {
    attempted: usize,
    submitted: usize,
    already_in_mempool: usize,
    retry_later: usize,
    failed: usize,
}

fn pending_resubmit_should_retry(err: &RpcClientError) -> bool {
    matches!(
        err,
        RpcClientError::ConnectTimeout { .. }
            | RpcClientError::ReadTimeout { .. }
            | RpcClientError::Transport { .. }
    )
}

fn journal_rows(
    wallet_dir: &Path,
    wallet: &Wallet,
    rpc: Option<&NodeRpcClient>,
) -> Vec<HistoryRow> {
    let Ok(journal) = dom_wallet::TxJournal::open(wallet_dir) else {
        return Vec::new();
    };
    let Ok(records) = journal.replay() else {
        return Vec::new();
    };

    let mut rows: Vec<_> = records
        .into_iter()
        .map(|(tx_hash, record)| history_row(wallet, rpc, tx_hash, record))
        .collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.timestamp));
    rows
}

fn history_row(
    wallet: &Wallet,
    rpc: Option<&NodeRpcClient>,
    tx_hash: [u8; 32],
    record: dom_wallet::TxRecord,
) -> HistoryRow {
    let observed_in_mempool = rpc
        .and_then(|client| client.mempool_tx(&tx_hash).ok().flatten())
        .is_some();
    let can_cancel = wallet.has_pending_tx(&tx_hash)
        && matches!(
            record.status,
            TxStatus::Building | TxStatus::Submitted | TxStatus::Failed { .. }
        );
    let can_rebroadcast = wallet.pending_tx_bytes(&tx_hash).is_some()
        && wallet.has_pending_tx(&tx_hash)
        && matches!(
            record.status,
            TxStatus::Building | TxStatus::Submitted | TxStatus::Failed { .. }
        );

    let (status, warning) = match &record.status {
        TxStatus::Building if observed_in_mempool => (
            "observed".to_string(),
            Some("journal says building, but node currently sees it in mempool".to_string()),
        ),
        TxStatus::Building => (
            "building".to_string(),
            Some("transaction not yet observed in mempool".to_string()),
        ),
        TxStatus::Submitted if observed_in_mempool => ("observed".to_string(), None),
        TxStatus::Submitted => (
            "submitted".to_string(),
            Some("submitted earlier but not currently observed in mempool".to_string()),
        ),
        TxStatus::Confirmed { block_height } => (format!("confirmed @ {block_height}"), None),
        TxStatus::Failed { reason } => (
            "failed".to_string(),
            Some(format!(
                "{}; transaction remains reserved until explicit cancel or rebroadcast",
                reason
            )),
        ),
        TxStatus::Replaced { by_tx_hash } => {
            (format!("replaced by {}", hex::encode(by_tx_hash)), None)
        }
        TxStatus::Canceled => ("canceled".to_string(), None),
    };

    HistoryRow {
        timestamp: record.last_updated_at,
        tx_hash_hex: hex::encode(tx_hash),
        status,
        warning,
        can_cancel,
        can_rebroadcast,
    }
}

fn receive_row(network: Network, descriptor: ReceiveRequestDescriptor) -> ReceiveRow {
    let request = format_payment_request(network, &descriptor);
    ReceiveRow {
        index: descriptor.index,
        amount: descriptor.amount,
        address: descriptor.address,
        commitment_hex: descriptor.commitment_hex,
        blinding_hex: descriptor.blinding_hex,
        request_text: request,
        created_at: descriptor.created_at,
        status: format_receive_status(&descriptor.status),
    }
}

fn format_receive_status(status: &ReceiveRequestStatus) -> String {
    match status {
        ReceiveRequestStatus::Pending => "pending".to_string(),
        ReceiveRequestStatus::Detected {
            block_height,
            is_coinbase,
            is_mature,
        } => format!(
            "detected @ {block_height} (coinbase={}, mature={})",
            is_coinbase, is_mature
        ),
    }
}

fn genesis_hash_for(network: Network) -> Result<Hash256, dom_core::DomError> {
    dom_core::startup_genesis_hash_for_network_magic(network.magic())
}

fn node_client(url: &str) -> Result<NodeRpcClient, RpcClientError> {
    let parsed = Url::parse(url).map_err(|e| RpcClientError::Config {
        reason: format!("invalid node url: {e}"),
    })?;
    NodeRpcClient::builder(parsed).build()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_payment_request(network: Network, descriptor: &ReceiveRequestDescriptor) -> String {
    format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork={}\namount_noms={}\naddress={}\ncommitment={}\nblinding={}",
        network_name(network),
        descriptor.amount,
        descriptor.address,
        descriptor.commitment_hex,
        descriptor.blinding_hex,
    )
}

fn parse_payment_request(request_text: &str) -> anyhow::Result<ParsedPaymentRequest> {
    let mut lines = request_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let Some(header) = lines.next() else {
        return Err(anyhow::anyhow!("payment request is empty"));
    };
    if header != "DOM-PAYMENT-REQUEST-V1" {
        return Err(anyhow::anyhow!(
            "unsupported payment request header: {header}"
        ));
    }

    let mut network = None;
    let mut amount = None;
    let mut address = None;
    let mut commitment_hex = None;
    let mut blinding_hex = None;

    for line in lines {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("invalid payment request line: {line}"))?;
        match key {
            "network" => network = Some(parse_network_name(value)?),
            "amount_noms" => amount = Some(value.parse::<u64>().context("amount_noms")?),
            "address" => address = Some(value.to_string()),
            "commitment" => commitment_hex = Some(value.to_string()),
            "blinding" => blinding_hex = Some(value.to_string()),
            _ => return Err(anyhow::anyhow!("unknown payment request field: {key}")),
        }
    }

    let parsed = ParsedPaymentRequest {
        network: network.ok_or_else(|| anyhow::anyhow!("missing network"))?,
        amount: amount.ok_or_else(|| anyhow::anyhow!("missing amount_noms"))?,
        address: address.ok_or_else(|| anyhow::anyhow!("missing address"))?,
        commitment_hex: commitment_hex.ok_or_else(|| anyhow::anyhow!("missing commitment"))?,
        blinding_hex: blinding_hex.ok_or_else(|| anyhow::anyhow!("missing blinding"))?,
    };
    validate_payment_request(&parsed)?;
    Ok(parsed)
}

fn validate_payment_request(request: &ParsedPaymentRequest) -> anyhow::Result<()> {
    let commitment = parse_commitment_hex(&request.commitment_hex)?;
    let address = Address::decode(&request.address).context("address decode")?;
    if address.payload != commitment {
        return Err(anyhow::anyhow!(
            "address payload does not match commitment field"
        ));
    }

    let expected_mainnet = matches!(request.network, Network::Mainnet);
    if address.is_mainnet != expected_mainnet {
        return Err(anyhow::anyhow!(
            "address network does not match request network"
        ));
    }

    let blinding = parse_blinding_hex(&request.blinding_hex)?;
    let recomputed = Commitment::commit(request.amount, &blinding);
    if *recomputed.as_bytes() != commitment {
        return Err(anyhow::anyhow!(
            "commitment does not match amount + blinding"
        ));
    }
    Ok(())
}

fn parse_commitment_hex(value: &str) -> anyhow::Result<[u8; 33]> {
    let bytes = hex::decode(value)?;
    let arr: [u8; 33] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("commitment must be 33 bytes, got {}", v.len()))?;
    Ok(arr)
}

fn parse_blinding_hex(value: &str) -> anyhow::Result<BlindingFactor> {
    let bytes = hex::decode(value)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("blinding must be 32 bytes, got {}", v.len()))?;
    BlindingFactor::from_bytes(arr).map_err(|e| anyhow::anyhow!("blinding decode: {e}"))
}

fn tx_hash_hex(tx_hash: [u8; 32]) -> String {
    hex::encode(tx_hash)
}

fn parse_hash_hex(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("tx hash must be 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

fn parse_network_name(value: &str) -> anyhow::Result<Network> {
    match value {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(anyhow::anyhow!("unknown network: {value}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::pedersen::Commitment;
    use dom_wallet::{BlockHeaderInfo, OwnedOutput, RpcMempoolTxInfo, TxSubmitOutcome, UtxoInfo};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use tempfile::TempDir;

    fn test_genesis() -> Hash256 {
        Hash256::from_bytes([0x42u8; 32])
    }

    fn make_output(value: u64, height: u64, is_coinbase: bool) -> OwnedOutput {
        let bf = BlindingFactor::random();
        let commitment = Commitment::commit(value, &bf);
        OwnedOutput::new(
            *commitment.as_bytes(),
            value,
            *bf.as_bytes(),
            height,
            is_coinbase,
        )
    }

    fn build_runtime_with_pending(mark_submitted: bool) -> (TempDir, AppRuntime, [u8; 32]) {
        let temp = TempDir::new().unwrap();
        let wallet_dir = temp.path().join("wallet");
        let mut wallet_dir_handle =
            WalletDir::create(&wallet_dir, "pw", Network::Regtest, &test_genesis()).unwrap();
        wallet_dir_handle
            .wallet_mut()
            .add_output(make_output(900, 100, false));

        let recipient_blinding = BlindingFactor::random();
        let recipient_commitment = Commitment::commit(800, &recipient_blinding);
        let tx = wallet_dir_handle
            .wallet_mut()
            .build_spend(recipient_commitment, recipient_blinding, 800, 100, 1000)
            .unwrap();
        let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
        if mark_submitted {
            wallet_dir_handle
                .wallet_mut()
                .mark_submitted(tx_hash)
                .unwrap();
        }

        let mut runtime = AppRuntime::load(temp.path().join("app")).unwrap();
        runtime.persisted.wallet_dir = Some(wallet_dir);
        runtime.persisted.network = Some(Network::Regtest);
        runtime.session = Some(WalletSession {
            wallet_dir: wallet_dir_handle,
        });
        (temp, runtime, tx_hash)
    }

    fn replay_status(runtime: &AppRuntime, tx_hash: &[u8; 32]) -> TxStatus {
        let session = runtime.session.as_ref().unwrap();
        let journal = TxJournal::open(session.wallet_dir.path()).unwrap();
        journal
            .replay()
            .unwrap()
            .get(tx_hash)
            .unwrap()
            .status
            .clone()
    }

    struct FakeRpc {
        outcomes: RefCell<VecDeque<Result<TxSubmitOutcome, RpcClientError>>>,
        calls: Cell<usize>,
    }

    impl FakeRpc {
        fn new(outcomes: Vec<Result<TxSubmitOutcome, RpcClientError>>) -> Self {
            Self {
                outcomes: RefCell::new(outcomes.into()),
                calls: Cell::new(0),
            }
        }

        fn success(tx_hash: [u8; 32]) -> Self {
            Self::new(vec![Ok(TxSubmitOutcome {
                tx_hash,
                relayed: true,
                warning: None,
            })])
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl NodeRpc for FakeRpc {
        fn health(&self) -> Result<(), RpcClientError> {
            Ok(())
        }

        fn status(&self) -> Result<NodeStatus, RpcClientError> {
            Ok(NodeStatus {
                version: 1,
                chain_height: 0,
                tip_hash: None,
                mempool_size: 0,
                network: "regtest".to_string(),
            })
        }

        fn block_at_height(&self, _height: u64) -> Result<Option<BlockHeaderInfo>, RpcClientError> {
            Ok(None)
        }

        fn block_by_hash(
            &self,
            _hash: &[u8; 32],
        ) -> Result<Option<BlockHeaderInfo>, RpcClientError> {
            Ok(None)
        }

        fn submit_tx(&self, _tx: &Transaction) -> Result<TxSubmitOutcome, RpcClientError> {
            self.calls.set(self.calls.get().saturating_add(1));
            self.outcomes
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected submit_tx call {}", self.calls.get()))
        }

        fn mempool_tx(
            &self,
            _tx_hash: &[u8; 32],
        ) -> Result<Option<RpcMempoolTxInfo>, RpcClientError> {
            Ok(None)
        }

        fn utxo(&self, _commitment: &[u8; 33]) -> Result<Option<UtxoInfo>, RpcClientError> {
            Ok(None)
        }
    }

    #[test]
    fn runtime_without_wallet_starts_in_welcome() {
        let temp = TempDir::new().unwrap();
        let runtime = AppRuntime::load(temp.path().to_path_buf()).unwrap();
        assert_eq!(runtime.screen, Screen::Splash);
    }

    #[test]
    fn runtime_with_persisted_wallet_starts_in_unlock() {
        let temp = TempDir::new().unwrap();
        let persisted = PersistedAppState {
            wallet_dir: Some(temp.path().join("wallet")),
            network: Some(Network::Regtest),
            node_url: "http://127.0.0.1:33369".to_string(),
        };
        storage::save(temp.path(), &persisted).unwrap();
        let runtime = AppRuntime::load(temp.path().to_path_buf()).unwrap();
        assert_eq!(runtime.screen, Screen::Splash);
    }

    #[test]
    fn pending_resubmit_on_open_marks_building_tx_submitted() {
        let (_temp, mut runtime, tx_hash) = build_runtime_with_pending(false);
        let rpc = FakeRpc::success(tx_hash);

        let summary = runtime.resubmit_pending_transactions_due_with(&rpc, 10, true);

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.submitted, 1);
        assert_eq!(rpc.calls(), 1);
        assert_eq!(replay_status(&runtime, &tx_hash), TxStatus::Submitted);
    }

    #[test]
    fn pending_resubmit_after_reconnect_forces_retry_before_interval() {
        let (_temp, mut runtime, tx_hash) = build_runtime_with_pending(true);
        runtime.next_pending_resubmit_at = Some(1_000);
        let rpc = FakeRpc::success(tx_hash);

        let skipped = runtime.resubmit_pending_transactions_due_with(&rpc, 20, false);
        assert_eq!(skipped.attempted, 0);
        assert_eq!(rpc.calls(), 0);

        let summary = runtime.resubmit_pending_transactions_due_with(&rpc, 21, true);
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.submitted, 1);
        assert_eq!(rpc.calls(), 1);
        assert_eq!(replay_status(&runtime, &tx_hash), TxStatus::Submitted);
    }

    #[test]
    fn submitted_tx_survives_node_restart_by_wallet_resubmit() {
        let (_temp, mut runtime, tx_hash) = build_runtime_with_pending(true);
        let restarted_node_rpc = FakeRpc::success(tx_hash);

        let summary = runtime.resubmit_pending_transactions_due_with(&restarted_node_rpc, 60, true);

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.submitted, 1);
        assert_eq!(
            restarted_node_rpc.calls(),
            1,
            "wallet must resubmit the pending tx after a node restart lost volatile mempool state"
        );
        assert_eq!(replay_status(&runtime, &tx_hash), TxStatus::Submitted);
    }

    #[test]
    fn pending_resubmit_treats_409_already_in_mempool_as_success() {
        let (_temp, mut runtime, tx_hash) = build_runtime_with_pending(false);
        let rpc = FakeRpc::new(vec![Err(RpcClientError::NodeRejected {
            status: 409,
            reason: "already in mempool".to_string(),
        })]);

        let summary = runtime.resubmit_pending_transactions_due_with(&rpc, 10, true);

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.already_in_mempool, 1);
        assert_eq!(rpc.calls(), 1);
        assert_eq!(replay_status(&runtime, &tx_hash), TxStatus::Submitted);
    }

    #[test]
    fn pending_resubmit_validation_rejection_marks_failed_and_stops_retrying() {
        let (_temp, mut runtime, tx_hash) = build_runtime_with_pending(true);
        let rpc = FakeRpc::new(vec![Err(RpcClientError::NodeRejected {
            status: 400,
            reason: "invalid transaction".to_string(),
        })]);

        let summary = runtime.resubmit_pending_transactions_due_with(&rpc, 10, true);

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(rpc.calls(), 1);
        assert!(matches!(
            replay_status(&runtime, &tx_hash),
            TxStatus::Failed { ref reason }
                if reason.contains("invalid transaction")
        ));

        let retry = FakeRpc::success(tx_hash);
        let second = runtime.resubmit_pending_transactions_due_with(&retry, 11, true);
        assert_eq!(second.attempted, 0);
        assert_eq!(retry.calls(), 0);
    }

    #[test]
    fn pending_resubmit_network_error_retries_next_cycle() {
        let (_temp, mut runtime, tx_hash) = build_runtime_with_pending(true);
        let rpc = FakeRpc::new(vec![Err(RpcClientError::Transport {
            url: "http://127.0.0.1:33369/tx/submit".to_string(),
            reason: "connection reset".to_string(),
        })]);

        let summary = runtime.resubmit_pending_transactions_due_with(&rpc, 10, true);

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.retry_later, 1);
        assert_eq!(rpc.calls(), 1);
        assert_eq!(replay_status(&runtime, &tx_hash), TxStatus::Submitted);

        let retry = FakeRpc::success(tx_hash);
        let second = runtime.resubmit_pending_transactions_due_with(&retry, 70, false);
        assert_eq!(second.attempted, 1);
        assert_eq!(second.submitted, 1);
        assert_eq!(retry.calls(), 1);
    }

    #[test]
    fn payment_request_roundtrips() {
        let blinding = BlindingFactor::from_bytes([7u8; 32]).unwrap();
        let commitment = Commitment::commit(77, &blinding);
        let descriptor = ReceiveRequestDescriptor {
            index: 0,
            amount: 77,
            address: Address::new(*commitment.as_bytes(), false).encode(),
            commitment_hex: hex::encode(commitment.as_bytes()),
            blinding_hex: hex::encode(blinding.as_bytes()),
            created_at: 1,
            status: ReceiveRequestStatus::Pending,
        };

        let text = format_payment_request(Network::Regtest, &descriptor);
        let parsed = parse_payment_request(&text).unwrap();
        assert_eq!(parsed.network, Network::Regtest);
        assert_eq!(parsed.amount, 77);
        assert_eq!(parsed.address, descriptor.address);
        assert_eq!(parsed.commitment_hex, descriptor.commitment_hex);
    }

    #[test]
    fn payment_request_parser_rejects_missing_fields() {
        let err = parse_payment_request("DOM-PAYMENT-REQUEST-V1\nnetwork=regtest")
            .expect_err("missing fields must be rejected");
        assert!(err.to_string().contains("missing amount_noms"));
    }

    #[test]
    fn session_drop_schedules_fresh_reconnect_without_poisoning_peer() {
        let mut session = NodeConnectionSession::default();
        session.on_success(99, "http://127.0.0.1:33369");
        assert_eq!(session.status.state, NetworkStatusState::Connected);

        session.on_session_closed(100, "tcp closed");

        assert_eq!(session.status.state, NetworkStatusState::Reconnecting);
        assert_eq!(session.next_reconnect_at(), Some(101));
        assert_eq!(session.status.last_error.as_deref(), Some("tcp closed"));
        assert_eq!(session.status.connected_peer, None);
        assert!(!session.is_reconnect_due(100));
        assert!(session.is_reconnect_due(101));
        assert_eq!(
            session.reconnect_delay_secs(),
            INITIAL_RECONNECT_DELAY_SECS * 2
        );
    }

    #[test]
    fn repeated_failures_apply_bounded_exponential_backoff_without_duplicate_loops() {
        let mut session = NodeConnectionSession::default();
        session.on_session_closed(10, "first");
        assert_eq!(session.next_reconnect_at(), Some(11));
        assert_eq!(session.reconnect_delay_secs(), 2);

        session.on_session_closed(11, "second");
        assert_eq!(session.next_reconnect_at(), Some(13));
        assert_eq!(session.reconnect_delay_secs(), 4);

        for now in 12..30 {
            if session.is_reconnect_due(now) {
                session.on_session_closed(now, "still down");
            }
        }
        assert!(session.reconnect_delay_secs() <= MAX_RECONNECT_DELAY_SECS);
        assert_eq!(session.status.state, NetworkStatusState::Reconnecting);
    }

    #[test]
    fn stable_connection_resets_backoff() {
        let mut session = NodeConnectionSession::default();
        session.on_session_closed(1, "down");
        session.on_session_closed(2, "still down");
        assert!(session.reconnect_delay_secs() > INITIAL_RECONNECT_DELAY_SECS);

        session.on_success(3, "http://127.0.0.1:33369");

        assert_eq!(session.status.state, NetworkStatusState::Connected);
        assert_eq!(session.reconnect_delay_secs(), INITIAL_RECONNECT_DELAY_SECS);
        assert_eq!(session.next_reconnect_at(), None);
        assert_eq!(session.status.last_error, None);
        assert_eq!(session.status.last_tcp_connect_at, Some(3));
        assert_eq!(session.status.last_handshake_at, Some(3));
    }

    #[test]
    fn reconnect_does_not_require_wallet_close_reopen() {
        let mut session = NodeConnectionSession::default();
        session.on_session_closed(50, "session dropped");
        assert_eq!(session.status.state, NetworkStatusState::Reconnecting);

        assert!(session.is_reconnect_due(51));
        session.on_success(51, "http://127.0.0.1:33369");

        assert_eq!(session.status.state, NetworkStatusState::Connected);
        assert_eq!(session.next_reconnect_at(), None);
    }

    #[test]
    fn last_seen_peer_registry_alone_does_not_imply_connected() {
        let mut status = NetworkStatus::default();
        status.observe_peer_registry_count(3);

        assert_eq!(status.peer_count, 3);
        assert_eq!(status.state, NetworkStatusState::Disconnected);
        assert_eq!(status.connected_peer, None);
        assert_eq!(status.last_handshake_at, None);
    }

    #[test]
    fn tcp_reachability_alone_does_not_imply_connected() {
        let mut status = NetworkStatus::default();
        status.mark_tcp_connected(42, "127.0.0.1:33369");

        assert_eq!(status.state, NetworkStatusState::TcpConnected);
        assert_ne!(status.state, NetworkStatusState::Connected);
        assert_eq!(status.last_tcp_connect_at, Some(42));
        assert_eq!(status.last_handshake_at, None);
    }

    #[test]
    fn handshake_success_updates_network_status() {
        let mut status = NetworkStatus::default();
        status.mark_tcp_connected(42, "127.0.0.1:33369");
        status.mark_handshaking();
        status.mark_connected(43, "127.0.0.1:33369");

        assert_eq!(status.state, NetworkStatusState::Connected);
        assert_eq!(status.connected_peer.as_deref(), Some("127.0.0.1:33369"));
        assert_eq!(status.last_tcp_connect_at, Some(43));
        assert_eq!(status.last_handshake_at, Some(43));
        assert_eq!(status.last_error, None);
    }

    #[test]
    fn valid_pong_keeps_connection_healthy_and_updates_status() {
        let mut heartbeat = HeartbeatSession::default();
        let mut status = NetworkStatus::default();
        status.mark_connected(10, "127.0.0.1:33369");
        let ping = heartbeat.begin_ping_with_nonce(11, Network::Regtest.magic(), 77);
        assert_eq!(ping.command, Command::Ping);
        assert_eq!(ping.payload, 77u64.to_le_bytes());

        let pong = WireMessage {
            magic: Network::Regtest.magic(),
            command: Command::Pong,
            payload: 77u64.to_le_bytes().to_vec(),
        };
        let event = heartbeat
            .observe_message(&mut status, 12, &pong)
            .expect("matching pong");

        assert_eq!(event, HeartbeatEvent::PongAccepted);
        assert_eq!(status.state, NetworkStatusState::Connected);
        assert_eq!(status.last_pong_at, Some(12));
        assert_eq!(
            heartbeat.check_timeout(&mut status, 100),
            HeartbeatEvent::None
        );
    }

    #[test]
    fn missing_pong_causes_reconnect_without_sleep() {
        let mut heartbeat = HeartbeatSession::default();
        let mut status = NetworkStatus::default();
        status.mark_connected(20, "127.0.0.1:33369");
        heartbeat.begin_ping_with_nonce(21, Network::Regtest.magic(), 88);

        assert_eq!(
            heartbeat.check_timeout(&mut status, 35),
            HeartbeatEvent::None
        );
        let event = heartbeat.check_timeout(&mut status, 36);

        assert_eq!(
            event,
            HeartbeatEvent::ReconnectRequired("pong timeout for nonce 88".to_string())
        );
        assert_eq!(status.state, NetworkStatusState::Reconnecting);
        assert_eq!(
            status.last_error.as_deref(),
            Some("pong timeout for nonce 88")
        );
    }

    #[test]
    fn wrong_nonce_does_not_count_as_pong() {
        let mut heartbeat = HeartbeatSession::default();
        let mut status = NetworkStatus::default();
        status.mark_connected(30, "127.0.0.1:33369");
        heartbeat.begin_ping_with_nonce(31, Network::Regtest.magic(), 99);
        let wrong_pong = WireMessage {
            magic: Network::Regtest.magic(),
            command: Command::Pong,
            payload: 100u64.to_le_bytes().to_vec(),
        };

        let err = heartbeat
            .observe_message(&mut status, 32, &wrong_pong)
            .expect_err("wrong nonce must reject");

        assert_eq!(
            err,
            HeartbeatError::NonceMismatch {
                expected: 99,
                got: 100
            }
        );
        assert_eq!(status.last_pong_at, None);
        assert_eq!(
            heartbeat.check_timeout(&mut status, 46),
            HeartbeatEvent::ReconnectRequired("pong timeout for nonce 99".to_string())
        );
    }

    #[test]
    fn malformed_pong_is_rejected() {
        let mut heartbeat = HeartbeatSession::default();
        let mut status = NetworkStatus::default();
        status.mark_connected(40, "127.0.0.1:33369");
        heartbeat.begin_ping_with_nonce(41, Network::Regtest.magic(), 101);
        let malformed_pong = WireMessage {
            magic: Network::Regtest.magic(),
            command: Command::Pong,
            payload: vec![1, 2, 3],
        };

        let err = heartbeat
            .observe_message(&mut status, 42, &malformed_pong)
            .expect_err("malformed pong must reject");

        assert_eq!(err, HeartbeatError::MalformedPong { len: 3 });
        assert_eq!(status.last_pong_at, None);
    }

    #[test]
    fn heartbeat_message_handling_does_not_starve_non_heartbeat_messages() {
        let mut heartbeat = HeartbeatSession::default();
        let mut status = NetworkStatus::default();
        status.mark_connected(50, "127.0.0.1:33369");
        heartbeat.begin_ping_with_nonce(51, Network::Regtest.magic(), 102);
        let block_message = WireMessage {
            magic: Network::Regtest.magic(),
            command: Command::Block,
            payload: vec![9, 9, 9],
        };

        let event = heartbeat
            .observe_message(&mut status, 52, &block_message)
            .expect("non-heartbeat message is left for the normal dispatcher");

        assert_eq!(event, HeartbeatEvent::None);
        assert_eq!(status.state, NetworkStatusState::Connected);
        assert_eq!(status.last_pong_at, None);
    }

    #[test]
    fn network_diagnostics_rows_come_from_network_status() {
        let mut status = NetworkStatus::default();
        status.observe_peer_registry_count(8);
        status.mark_connected(70, "127.0.0.1:33369");
        status.last_pong_at = Some(71);
        status.last_error = Some("redacted transport error".to_string());
        status.reconnect_delay = Duration::from_secs(13);

        let rows = status.diagnostics_rows();

        assert_eq!(rows.state, "Connected");
        assert_eq!(rows.connected_peer, "127.0.0.1:33369");
        assert_eq!(rows.last_error, "redacted transport error");
        assert_eq!(rows.last_tcp_connect, "70");
        assert_eq!(rows.last_handshake, "70");
        assert_eq!(rows.last_pong, "71");
        assert_eq!(rows.reconnect_delay, "13s");
        assert_eq!(rows.peer_count, "8");
    }

    #[test]
    fn network_diagnostics_rows_do_not_infer_connected_from_peer_count() {
        let mut status = NetworkStatus::default();
        status.observe_peer_registry_count(8);

        let rows = status.diagnostics_rows();

        assert_eq!(rows.state, "Disconnected");
        assert_eq!(rows.connected_peer, "none");
        assert_eq!(rows.last_tcp_connect, "never");
        assert_eq!(rows.last_handshake, "never");
        assert_eq!(rows.last_pong, "never");
        assert_eq!(rows.peer_count, "8");
    }

    #[test]
    fn diagnostic_log_redacts_secrets_on_append_and_export() {
        let mut log = DiagnosticLog::new(
            8,
            4096,
            BuildDiagnostics {
                app_version: "test",
                git_hash: "abc123",
            },
        );
        log.append(
            1,
            "secret_test",
            "password=hunter2 seed_phrase=alpha-beta token=rpc-token private_key=deadbeef Authorization: Bearer bearer-secret",
        );

        let exported = log.export_text();

        assert!(exported.contains("password=<redacted>"));
        assert!(exported.contains("seed_phrase=<redacted>"));
        assert!(exported.contains("token=<redacted>"));
        assert!(exported.contains("private_key=<redacted>"));
        assert!(exported.contains("Authorization <redacted>"));
        assert!(!exported.contains("hunter2"));
        assert!(!exported.contains("alpha-beta"));
        assert!(!exported.contains("rpc-token"));
        assert!(!exported.contains("deadbeef"));
        assert!(!exported.contains("bearer-secret"));
    }

    #[test]
    fn diagnostic_log_rotation_bounds_entries() {
        let mut log = DiagnosticLog::new(
            2,
            4096,
            BuildDiagnostics {
                app_version: "test",
                git_hash: "abc123",
            },
        );
        log.append(1, "first", "height=1");
        log.append(2, "second", "height=2");
        log.append(3, "third", "height=3");

        let exported = log.export_text();

        assert_eq!(log.len(), 2);
        assert!(!exported.contains("first"));
        assert!(exported.contains("second"));
        assert!(exported.contains("third"));
    }

    #[test]
    fn diagnostic_export_writes_redacted_file() {
        let temp = TempDir::new().unwrap();
        let mut runtime = AppRuntime::load(temp.path().to_path_buf()).unwrap();
        runtime
            .diagnostic_log
            .append(1, "export", "wallet_password=open-sesame token=rpc-token");

        let path = runtime.export_diagnostics().expect("export diagnostics");
        let exported = std::fs::read_to_string(path).expect("read export");

        assert!(exported.contains("wallet_password=<redacted>"));
        assert!(exported.contains("token=<redacted>"));
        assert!(!exported.contains("open-sesame"));
        assert!(!exported.contains("rpc-token"));
        assert!(exported.contains("app_version="));
        assert!(exported.contains("network_mode=unconfigured"));
    }
}

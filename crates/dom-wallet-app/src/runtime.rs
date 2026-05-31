use crate::storage::{self, AppStorageError, PersistedAppState};
use anyhow::Context;
use dom_core::Address;
use dom_core::Hash256;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_serialization::DomDeserialize;
use dom_wallet::{
    Bip39Seed, Network, NodeRpc, NodeRpcClient, NodeStatus, ReceiveRequestDescriptor,
    ReceiveRequestStatus, RpcClientError, SeedAcceptance, Transaction, TxStatus, Wallet,
    WalletBalance, WalletDir,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const INITIAL_RECONNECT_DELAY_SECS: u64 = 1;
const MAX_RECONNECT_DELAY_SECS: u64 = 60;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletNetworkState {
    Disconnected,
    Connected,
    Reconnecting,
}

impl WalletNetworkState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connected => "Connected",
            Self::Reconnecting => "Reconnecting",
        }
    }
}

pub struct NodeConnectionSession {
    client: Option<NodeRpcClient>,
    pub state: WalletNetworkState,
    pub reconnect_delay: Duration,
    next_reconnect_at: Option<u64>,
    consecutive_failures: u32,
    pub last_error: Option<String>,
}

impl Default for NodeConnectionSession {
    fn default() -> Self {
        Self {
            client: None,
            state: WalletNetworkState::Disconnected,
            reconnect_delay: Duration::from_secs(INITIAL_RECONNECT_DELAY_SECS),
            next_reconnect_at: None,
            consecutive_failures: 0,
            last_error: None,
        }
    }
}

impl NodeConnectionSession {
    pub fn state_label(&self) -> &'static str {
        self.state.label()
    }

    pub fn reconnect_delay_secs(&self) -> u64 {
        self.reconnect_delay.as_secs()
    }

    pub fn next_reconnect_at(&self) -> Option<u64> {
        self.next_reconnect_at
    }

    pub fn is_reconnect_due(&self, now_secs: u64) -> bool {
        match self.state {
            WalletNetworkState::Disconnected => true,
            WalletNetworkState::Connected => false,
            WalletNetworkState::Reconnecting => self
                .next_reconnect_at
                .map(|deadline| now_secs >= deadline)
                .unwrap_or(true),
        }
    }

    fn client(&mut self, node_url: &str) -> Result<&NodeRpcClient, RpcClientError> {
        if self.client.is_none() {
            self.client = Some(node_client(node_url)?);
        }
        Ok(self.client.as_ref().expect("client just initialized"))
    }

    fn on_success(&mut self) {
        self.state = WalletNetworkState::Connected;
        self.next_reconnect_at = None;
        self.consecutive_failures = 0;
        self.reconnect_delay = Duration::from_secs(INITIAL_RECONNECT_DELAY_SECS);
        self.last_error = None;
    }

    fn on_session_closed(&mut self, now_secs: u64, error: impl Into<String>) {
        self.client = None;
        self.state = WalletNetworkState::Reconnecting;
        self.last_error = Some(error.into());
        self.next_reconnect_at = Some(now_secs.saturating_add(self.reconnect_delay.as_secs()));
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let next_delay = self.reconnect_delay.as_secs().saturating_mul(2).max(1);
        self.reconnect_delay = Duration::from_secs(next_delay.min(MAX_RECONNECT_DELAY_SECS));
    }

    fn reset(&mut self) {
        self.client = None;
        self.state = WalletNetworkState::Disconnected;
        self.next_reconnect_at = None;
        self.consecutive_failures = 0;
        self.reconnect_delay = Duration::from_secs(INITIAL_RECONNECT_DELAY_SECS);
        self.last_error = None;
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

    pub fn set_error(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
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
        self.refresh_wallet_view();
        let _ = self.refresh_node_status();
        self.screen = Screen::Dashboard;
        Ok(())
    }

    pub fn lock_wallet(&mut self) {
        self.session = None;
        self.node_connection.reset();
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

    fn refresh_node_status_at(&mut self, now_secs: u64) -> Result<(), RpcClientError> {
        let status = match self.node_connection.client(&self.persisted.node_url) {
            Ok(client) => client.status(),
            Err(err) => Err(err),
        };
        let status = match status {
            Ok(status) => status,
            Err(err) => {
                self.node_status = None;
                self.node_connection
                    .on_session_closed(now_secs, err.to_string());
                return Err(err);
            }
        };
        self.node_status = Some(status);
        self.node_connection.on_success();
        self.refresh_wallet_view();
        Ok(())
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
            Ok(_) => {
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
            Ok(_) | Err(RpcClientError::NodeRejected { status: 409, .. }) => {
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
    use tempfile::TempDir;

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
        session.on_success();
        assert_eq!(session.state, WalletNetworkState::Connected);

        session.on_session_closed(100, "tcp closed");

        assert_eq!(session.state, WalletNetworkState::Reconnecting);
        assert_eq!(session.next_reconnect_at(), Some(101));
        assert_eq!(session.last_error.as_deref(), Some("tcp closed"));
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
        assert_eq!(session.state, WalletNetworkState::Reconnecting);
    }

    #[test]
    fn stable_connection_resets_backoff() {
        let mut session = NodeConnectionSession::default();
        session.on_session_closed(1, "down");
        session.on_session_closed(2, "still down");
        assert!(session.reconnect_delay_secs() > INITIAL_RECONNECT_DELAY_SECS);

        session.on_success();

        assert_eq!(session.state, WalletNetworkState::Connected);
        assert_eq!(session.reconnect_delay_secs(), INITIAL_RECONNECT_DELAY_SECS);
        assert_eq!(session.next_reconnect_at(), None);
        assert_eq!(session.last_error, None);
    }

    #[test]
    fn reconnect_does_not_require_wallet_close_reopen() {
        let mut session = NodeConnectionSession::default();
        session.on_session_closed(50, "session dropped");
        assert_eq!(session.state, WalletNetworkState::Reconnecting);

        assert!(session.is_reconnect_due(51));
        session.on_success();

        assert_eq!(session.state, WalletNetworkState::Connected);
        assert_eq!(session.next_reconnect_at(), None);
    }
}

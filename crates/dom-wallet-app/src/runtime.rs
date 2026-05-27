use crate::storage::{self, AppStorageError, PersistedAppState};
use dom_core::{Hash256, GENESIS_HASH_MAINNET, GENESIS_HASH_REGTEST, GENESIS_HASH_TESTNET};
use dom_wallet::{
    Bip39Seed, Network, NodeRpc, NodeRpcClient, NodeStatus, ReceiveRequestDescriptor,
    ReceiveRequestStatus, RpcClientError, SeedAcceptance, TxStatus, WalletBalance, WalletDir,
};
use std::path::{Path, PathBuf};
use url::Url;

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
}

#[derive(Clone)]
pub struct ReceiveRow {
    pub index: u32,
    pub amount: u64,
    pub address: String,
    pub commitment_hex: String,
    pub blinding_hex: String,
    pub created_at: u64,
    pub status: String,
}

pub struct WalletSession {
    pub wallet_dir: WalletDir,
}

pub struct AppRuntime {
    pub data_dir: PathBuf,
    pub persisted: PersistedAppState,
    pub screen: Screen,
    pub session: Option<WalletSession>,
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
        let genesis_hash = genesis_hash_for(network);
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
        let genesis_hash = genesis_hash_for(network);
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
        let client = node_client(&self.persisted.node_url)?;
        let status = client.status()?;
        self.node_status = Some(status);
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
        self.history = journal_rows(session.wallet_dir.path());
        match session.wallet_dir.wallet().receive_descriptors() {
            Ok(rows) => {
                self.receive_requests = rows.into_iter().map(receive_row).collect();
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
}

fn journal_rows(wallet_dir: &Path) -> Vec<HistoryRow> {
    let Ok(journal) = dom_wallet::TxJournal::open(wallet_dir) else {
        return Vec::new();
    };
    let Ok(records) = journal.replay() else {
        return Vec::new();
    };

    let mut rows: Vec<_> = records
        .into_iter()
        .map(|(tx_hash, record)| HistoryRow {
            timestamp: record.last_updated_at,
            tx_hash_hex: hex::encode(tx_hash),
            status: format_tx_status(&record.status),
        })
        .collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.timestamp));
    rows
}

fn format_tx_status(status: &TxStatus) -> String {
    match status {
        TxStatus::Building => "building".to_string(),
        TxStatus::Submitted => "submitted".to_string(),
        TxStatus::Confirmed { block_height } => format!("confirmed @ {block_height}"),
        TxStatus::Failed { reason } => format!("failed: {reason}"),
        TxStatus::Replaced { by_tx_hash } => format!("replaced by {}", hex::encode(by_tx_hash)),
        TxStatus::Canceled => "canceled".to_string(),
    }
}

fn receive_row(descriptor: ReceiveRequestDescriptor) -> ReceiveRow {
    ReceiveRow {
        index: descriptor.index,
        amount: descriptor.amount,
        address: descriptor.address,
        commitment_hex: descriptor.commitment_hex,
        blinding_hex: descriptor.blinding_hex,
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

fn genesis_hash_for(network: Network) -> Hash256 {
    match network {
        Network::Mainnet => Hash256::from_bytes(GENESIS_HASH_MAINNET),
        Network::Testnet => Hash256::from_bytes(GENESIS_HASH_TESTNET),
        Network::Regtest => Hash256::from_bytes(GENESIS_HASH_REGTEST),
    }
}

fn node_client(url: &str) -> Result<NodeRpcClient, RpcClientError> {
    let parsed = Url::parse(url).map_err(|e| RpcClientError::Config {
        reason: format!("invalid node url: {e}"),
    })?;
    NodeRpcClient::builder(parsed).build()
}

fn parse_commitment_hex(value: &str) -> anyhow::Result<[u8; 33]> {
    let bytes = hex::decode(value)?;
    let arr: [u8; 33] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("commitment must be 33 bytes, got {}", v.len()))?;
    Ok(arr)
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
}

use crate::storage::{self, AppStorageError, PersistedAppState};
use dom_core::{Hash256, GENESIS_HASH_MAINNET, GENESIS_HASH_REGTEST, GENESIS_HASH_TESTNET};
use dom_wallet::{
    Bip39Seed, Network, NodeRpc, NodeRpcClient, NodeStatus, RpcClientError, SeedAcceptance,
    TxStatus, WalletBalance, WalletDir,
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
            return;
        };

        let current_height = self
            .node_status
            .as_ref()
            .map(|s| s.chain_height)
            .unwrap_or(0);
        self.wallet_balance = Some(session.wallet_dir.wallet().balance(current_height));
        self.history = journal_rows(session.wallet_dir.path());
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

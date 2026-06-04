//! User-controllable node settings, and the mapping to `dom_config::NodeConfig`.
//!
//! Each field corresponds to one of the `DOM_*` environment variables the
//! standalone node honours. We both (a) populate the strongly-typed
//! `NodeConfig` and (b) export the matching env vars, so the embedded node
//! behaves identically to the CLI node.

use anyhow::{anyhow, Result};
use dom_config::NodeConfig;
use dom_wallet::Network as WalletNetwork;
use serde::{Deserialize, Serialize};

/// Mirrors the `DOM_NETWORK` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    Mainnet,
    Testnet,
    Regtest,
}

impl NetworkKind {
    pub fn as_env(self) -> &'static str {
        match self {
            NetworkKind::Mainnet => "mainnet",
            NetworkKind::Testnet => "testnet",
            NetworkKind::Regtest => "regtest",
        }
    }
}

/// All knobs the Settings + Node tabs expose. Serializable so the frontend can
/// round-trip it; NEVER contains the wallet password (that lives only in the
/// backend, transiently — see `commands.rs`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSettings {
    pub network: NetworkKind,
    /// CSV becomes Vec on the way in; we store the parsed list.
    pub seed_peers: Vec<String>,
    pub p2p_listen_addr: String,
    pub rpc_listen_addr: String,
    pub data_dir: String,
    /// Optional miner wallet file (.dom) so coinbase rewards are spendable.
    pub miner_wallet_path: Option<String>,
    pub mine: bool,
    pub metrics_listen_addr: Option<String>,
    pub log_level: String,
}

impl Default for NodeSettings {
    fn default() -> Self {
        let data_dir = default_data_dir();
        Self {
            network: NetworkKind::Testnet,
            seed_peers: Vec::new(),
            p2p_listen_addr: "0.0.0.0:33370".to_string(),
            rpc_listen_addr: "127.0.0.1:33372".to_string(),
            data_dir,
            miner_wallet_path: None,
            mine: false,
            metrics_listen_addr: Some("127.0.0.1:33371".to_string()),
            log_level: "info".to_string(),
        }
    }
}

impl NodeSettings {
    /// Export the `DOM_*` env vars. Mirrors `dom-node`'s `main.rs` reads.
    /// NOTE: we deliberately do NOT export the wallet password here; the node
    /// only needs `DOM_WALLET_PATH` for mining, and the password is supplied
    /// out-of-band when the user unlocks. (If a future build wires
    /// wallet-integrated mining that needs the password, set it transiently
    /// and clear it immediately — never persist it.)
    pub fn export_env(&self) {
        std::env::set_var("DOM_NETWORK", self.network.as_env());
        std::env::set_var("DOM_P2P_LISTEN_ADDR", &self.p2p_listen_addr);
        std::env::set_var("DOM_RPC_LISTEN_ADDR", &self.rpc_listen_addr);
        std::env::set_var("DOM_DATA_DIR", &self.data_dir);
        std::env::set_var("DOM_MINE", if self.mine { "true" } else { "false" });
        std::env::set_var("DOM_LOG", &self.log_level);
        if !self.seed_peers.is_empty() {
            std::env::set_var("DOM_SEED_PEERS", self.seed_peers.join(","));
        } else {
            std::env::remove_var("DOM_SEED_PEERS");
        }
        match &self.metrics_listen_addr {
            Some(a) => std::env::set_var("DOM_METRICS_LISTEN_ADDR", a),
            None => std::env::remove_var("DOM_METRICS_LISTEN_ADDR"),
        }
        match &self.miner_wallet_path {
            Some(p) => std::env::set_var("DOM_WALLET_PATH", p),
            None => std::env::remove_var("DOM_WALLET_PATH"),
        }
    }

    /// Build the strongly-typed `NodeConfig`.
    pub fn to_node_config(&self) -> Result<NodeConfig> {
        let mut config = match self.network {
            NetworkKind::Mainnet => NodeConfig::mainnet(),
            NetworkKind::Testnet => NodeConfig::testnet(),
            NetworkKind::Regtest => NodeConfig::regtest(),
        };

        config.p2p_listen_addr = self.p2p_listen_addr.clone();
        config.data_dir = self.data_dir.clone();
        config.mine = self.mine;
        config.log_level = self.log_level.clone();
        config.rpc_listen_addr = Some(self.rpc_listen_addr.clone());
        config.metrics_listen_addr = self.metrics_listen_addr.clone();
        config.wallet_path = self.miner_wallet_path.clone();

        if !self.seed_peers.is_empty() {
            config.seed_peers = self.seed_peers.clone();
        }

        // Basic validation that would otherwise fail deep inside the node.
        if config.rpc_listen_addr.as_deref() == Some("") {
            return Err(anyhow!("RPC listen address must not be empty"));
        }
        Ok(config)
    }

    /// Map our UI network to the wallet `Network` enum used by
    /// `Wallet::create`, `Wallet::create_from_seed`, etc.
    pub fn wallet_network(&self) -> WalletNetwork {
        match self.network {
            NetworkKind::Mainnet => WalletNetwork::Mainnet,
            NetworkKind::Testnet => WalletNetwork::Testnet,
            NetworkKind::Regtest => WalletNetwork::Regtest,
        }
    }
}

/// `~/.dom/data` cross-platform.
fn default_data_dir() -> String {
    dirs_home()
        .map(|h| h.join(".dom").join("data").to_string_lossy().to_string())
        .unwrap_or_else(|| "./dom-data".to_string())
}

fn dirs_home() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(std::path::PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(std::path::PathBuf::from)
    }
}

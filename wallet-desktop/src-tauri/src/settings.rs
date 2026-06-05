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
    ///
    /// MINING WALLET (DOM-SEC-004): to credit block rewards, the node needs a
    /// wallet *path AND password*. We deliberately NEVER pass the user's wallet
    /// password to the node. Instead, when mining is enabled, we use a
    /// DEDICATED miner wallet that the app manages: its path lives under the
    /// data dir and its password is generated once and stored beside it. The
    /// node auto-creates this wallet on first run. The user's own wallet is
    /// never touched and its password never leaves the wallet manager.
    pub fn export_env(&self) {
        std::env::set_var("DOM_NETWORK", self.network.as_env());
        std::env::set_var("DOM_P2P_LISTEN_ADDR", &self.p2p_listen_addr);
        std::env::set_var("DOM_RPC_LISTEN_ADDR", &self.rpc_listen_addr);
        std::env::set_var("DOM_DATA_DIR", &self.data_dir);
        std::env::set_var("DOM_MINE", if self.mine { "true" } else { "false" });
        std::env::set_var("DOM_LOG", &self.log_level);
        // Regtest fast mining (FastDevOnly): blocos quase instantâneos para
        // desenvolvimento/teste local. O nó só aceita esta flag em regtest
        // (guarda fail-closed em mainnet/testnet), então é seguro exportá-la
        // apenas quando a rede selecionada for Regtest.
        match self.network {
            NetworkKind::Regtest => std::env::set_var("DOM_REGTEST_FAST_MINING", "1"),
            _ => std::env::remove_var("DOM_REGTEST_FAST_MINING"),
        }
        if !self.seed_peers.is_empty() {
            std::env::set_var("DOM_SEED_PEERS", self.seed_peers.join(","));
        } else {
            std::env::remove_var("DOM_SEED_PEERS");
        }
        match &self.metrics_listen_addr {
            Some(a) => std::env::set_var("DOM_METRICS_LISTEN_ADDR", a),
            None => std::env::remove_var("DOM_METRICS_LISTEN_ADDR"),
        }

        if self.mine {
            // Dedicated miner wallet (path + generated password). If the user
            // explicitly chose a miner_wallet_path we honour it; otherwise we
            // default to one under the data dir.
            if let Ok((path, password)) = self.miner_wallet_credentials() {
                std::env::set_var("DOM_WALLET_PATH", &path);
                std::env::set_var("DOM_WALLET_PASSWORD", &password);
            } else {
                std::env::remove_var("DOM_WALLET_PATH");
                std::env::remove_var("DOM_WALLET_PASSWORD");
            }
        } else {
            // Not mining → never expose any wallet path/password to the node.
            std::env::remove_var("DOM_WALLET_PATH");
            std::env::remove_var("DOM_WALLET_PASSWORD");
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

        // Mining wallet (dedicated; never the user's). Only set when mining.
        if self.mine {
            if let Ok((path, password)) = self.miner_wallet_credentials() {
                config.wallet_path = Some(path);
                config.wallet_password = Some(password);
            }
        } else {
            config.wallet_path = None;
            config.wallet_password = None;
        }

        if !self.seed_peers.is_empty() {
            config.seed_peers = self.seed_peers.clone();
        }

        // Basic validation that would otherwise fail deep inside the node.
        if config.rpc_listen_addr.as_deref() == Some("") {
            return Err(anyhow!("RPC listen address must not be empty"));
        }
        Ok(config)
    }

    /// Resolve the dedicated miner wallet's path and password.
    ///
    /// Path: the user's explicit `miner_wallet_path` if set, else
    /// `<data_dir>/miner-wallet.dom`. Password: generated once and stored in
    /// `<wallet_path>.key` (restricted perms on Unix). The node auto-creates
    /// the wallet on first run. This wallet is SEPARATE from the user's wallet;
    /// the user's password is never used or exposed here.
    fn miner_wallet_credentials(&self) -> Result<(String, String)> {
        let wallet_path = match &self.miner_wallet_path {
            Some(p) if !p.trim().is_empty() => std::path::PathBuf::from(p),
            _ => std::path::Path::new(&self.data_dir).join("miner-wallet.dom"),
        };

        let key_path = {
            let mut k = wallet_path.clone();
            let name = format!(
                "{}.key",
                k.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "miner-wallet.dom".into())
            );
            k.set_file_name(name);
            k
        };

        // Ensure parent dir exists (data_dir may not be created yet).
        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Read existing password, or generate and persist a new one.
        let password = match std::fs::read_to_string(&key_path) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                let mut bytes = [0u8; 24];
                getrandom::getrandom(&mut bytes)
                    .map_err(|e| anyhow!("OS RNG unavailable for miner wallet key: {e}"))?;
                let pw = hex::encode(bytes);
                std::fs::write(&key_path, &pw)
                    .map_err(|e| anyhow!("could not store miner wallet key: {e}"))?;
                restrict_permissions(&key_path);
                pw
            }
        };

        Ok((wallet_path.to_string_lossy().to_string(), password))
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

/// Restrict a file to owner-only read/write where the OS supports it.
/// On Windows this is a no-op (NTFS ACLs differ); the file lives in the user's
/// own data dir. The miner wallet key is a local test-network secret.
fn restrict_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

//! User-controllable node settings, and the mapping to `dom_config::NodeConfig`.
//!
//! Each field corresponds to one of the `DOM_*` environment variables the
//! standalone node honours. The desktop wallet passes them through the
//! strongly-typed `NodeConfig` instead of exporting process-global env vars.

use std::io::Write as _;
use std::net::SocketAddr;

use anyhow::{anyhow, Context as _, Result};
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
    pub fn validate(&self) -> Result<()> {
        parse_socket_addr("P2P listen address", &self.p2p_listen_addr)?;
        let rpc = parse_socket_addr("RPC listen address", &self.rpc_listen_addr)?;
        if !rpc.ip().is_loopback() {
            return Err(anyhow!("RPC listen address must be loopback"));
        }
        if let Some(addr) = self.metrics_listen_addr.as_deref() {
            if !addr.trim().is_empty() {
                let metrics = parse_socket_addr("metrics listen address", addr)?;
                if !metrics.ip().is_loopback() {
                    return Err(anyhow!("metrics listen address must be loopback"));
                }
            }
        }
        if self.data_dir.trim().is_empty() {
            return Err(anyhow!("data directory must not be empty"));
        }
        if let Some(path) = &self.miner_wallet_path {
            if path.trim().is_empty() {
                return Err(anyhow!("miner wallet path must not be empty when set"));
            }
        }
        Ok(())
    }

    /// Build the strongly-typed `NodeConfig`.
    ///
    /// This is the SINGLE source of truth handed to the embedded node via
    /// `DomNode::init(config)`. We deliberately do NOT export any `DOM_*`
    /// environment variables (H1/M5): `std::env::set_var` is not thread-safe
    /// and would race the node's Tokio threads, and exporting
    /// `DOM_WALLET_PASSWORD` would leak the miner-wallet secret into the
    /// process environment (and any child process / crash dump). Every knob
    /// the standalone node reads from `DOM_*` is set directly on the
    /// `NodeConfig` below, so the embedded node behaves identically without
    /// touching global process state.
    ///
    /// MINING WALLET (DOM-SEC-004): to credit block rewards the node needs a
    /// wallet *path AND password*. We NEVER pass the user's wallet password to
    /// the node. When mining is enabled we use a DEDICATED miner wallet the app
    /// manages (path under the data dir, password generated once and stored in a
    /// permission-restricted `.key` beside it). The node auto-creates it on
    /// first run; the user's own wallet is never touched.
    pub fn to_node_config(&self, rpc_bearer_token: Option<String>) -> Result<NodeConfig> {
        self.validate()?;
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
        config.rpc_bearer_token = rpc_bearer_token;
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
            // Defense-in-depth for the P2P "peers stays 0" bug. The peer
            // connector only dials while `PeerManager::needs_outbound()` is
            // true, and that is `outbound+pending < min(min_outbound,
            // max_in_flight)`. If `min_outbound == 0` (regtest historically
            // shipped 0 — fixed to 1 upstream, but a future regression or a
            // legacy persisted config could bring it back), the connector
            // NEVER dials even with seed peers configured, so two local nodes
            // never connect. When the user explicitly configured seed peers we
            // therefore guarantee at least one outbound slot. Scoped to "seed
            // peers present" so it never widens outbound for the public
            // mainnet/testnet defaults.
            if config.min_outbound == 0 {
                config.min_outbound = self.seed_peers.len().clamp(1, 8);
            }
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
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "could not create miner wallet key directory {}",
                    parent.display()
                )
            })?;
        }

        // Read existing password, or generate and persist a new one.
        if key_path.exists() {
            restrict_permissions(&key_path)?;
        }

        let password = match std::fs::read_to_string(&key_path) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => create_miner_key_file(&key_path)?,
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

    /// Whether an open wallet's network matches this node configuration (M2).
    /// Used to refuse starting the embedded node on a network that doesn't
    /// match the open wallet, which would otherwise yield an inconsistent
    /// balance/genesis view.
    pub fn matches_wallet_network(&self, wallet_network: WalletNetwork) -> bool {
        self.wallet_network() == wallet_network
    }
}

fn parse_socket_addr(label: &str, addr: &str) -> Result<SocketAddr> {
    addr.parse::<SocketAddr>()
        .map_err(|e| anyhow!("{label} is invalid ({addr:?}): {e}"))
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

/// Restrict the miner-wallet key file to the current user only.
///
/// On Unix: `chmod 0600`. On Windows: strip inherited ACEs and grant the
/// current user full control via `icacls` (H1) — NTFS files created in the
/// user's data dir otherwise inherit broad ACLs, leaving the plaintext key
/// readable by other principals. Permission failures are fatal for miner-key
/// creation because the key is stored plaintext.
fn create_miner_key_file(key_path: &std::path::Path) -> Result<String> {
    if let Some(parent) = key_path.parent() {
        restrict_permissions(parent).with_context(|| {
            format!(
                "could not secure miner wallet key directory {}",
                parent.display()
            )
        })?;
    }

    let mut bytes = [0u8; 24];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| anyhow!("OS RNG unavailable for miner wallet key: {e}"))?;
    let pw = hex::encode(bytes);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(key_path)
        .with_context(|| format!("could not create miner wallet key {}", key_path.display()))?;
    file.write_all(pw.as_bytes())
        .with_context(|| format!("could not write miner wallet key {}", key_path.display()))?;
    file.sync_all()
        .with_context(|| format!("could not sync miner wallet key {}", key_path.display()))?;
    drop(file);
    restrict_permissions(key_path)
        .with_context(|| format!("could not secure miner wallet key {}", key_path.display()))?;
    Ok(pw)
}

fn restrict_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mut perms = meta.permissions();
        perms.set_mode(if meta.is_dir() { 0o700 } else { 0o600 });
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        // Avoid flashing a console window from the GUI process.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let p = path.to_string_lossy().to_string();
        // Resolve the current account as DOMAIN\user (or bare user for local
        // accounts) so the /grant ACE targets exactly this principal.
        let user = std::env::var("USERNAME").unwrap_or_default();
        let account = match std::env::var("USERDOMAIN") {
            Ok(dom) if !dom.is_empty() && !user.is_empty() => format!("{dom}\\{user}"),
            _ => user.clone(),
        };

        // /inheritance:r removes inherited permissions (must run first);
        // /grant:r replaces this user's ACE with full control only.
        let status = Command::new("icacls")
            .arg(&p)
            .arg("/inheritance:r")
            .creation_flags(CREATE_NO_WINDOW)
            .status()?;
        if !status.success() {
            return Err(anyhow!("icacls inheritance removal failed for {p}"));
        }
        if account.is_empty() {
            return Err(anyhow!("could not determine current Windows account"));
        }
        let status = Command::new("icacls")
            .arg(&p)
            .arg("/grant:r")
            .arg(format!("{account}:F"))
            .creation_flags(CREATE_NO_WINDOW)
            .status()?;
        if !status.success() {
            return Err(anyhow!("icacls grant failed for {p}"));
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        return Err(anyhow!(
            "permission hardening is unsupported on this platform"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regtest_settings_with_seed(seed: Vec<String>) -> NodeSettings {
        NodeSettings {
            network: NetworkKind::Regtest,
            seed_peers: seed,
            p2p_listen_addr: "127.0.0.1:33370".into(),
            rpc_listen_addr: "127.0.0.1:33372".into(),
            data_dir: std::env::temp_dir()
                .join("dom-settings-test")
                .to_string_lossy()
                .into_owned(),
            miner_wallet_path: None,
            mine: false,
            metrics_listen_addr: Some("127.0.0.1:33371".into()),
            log_level: "debug".into(),
        }
    }

    /// Regression guard for the "peers stays 0" bug: when the user configures
    /// seed peers, `to_node_config` must guarantee at least one outbound slot
    /// so `PeerManager::needs_outbound()` can ever be true and the connector
    /// actually dials. Without the guard a `min_outbound == 0` config silently
    /// disables all outbound dialing.
    #[test]
    fn seed_peers_force_at_least_one_outbound() {
        let settings = regtest_settings_with_seed(vec!["127.0.0.1:33371".into()]);
        let config = settings.to_node_config(None).expect("config");
        assert_eq!(config.seed_peers, vec!["127.0.0.1:33371".to_string()]);
        assert!(
            config.min_outbound >= 1,
            "min_outbound must be >= 1 when seed peers are configured, got {}",
            config.min_outbound
        );
    }

    /// The guard must NOT widen outbound when no seed peers are set: the public
    /// network defaults (mainnet 8 / testnet 4 / regtest 1) stay untouched.
    #[test]
    fn no_seed_peers_leaves_outbound_default() {
        let settings = regtest_settings_with_seed(vec![]);
        let config = settings.to_node_config(None).expect("config");
        assert!(config.seed_peers.is_empty());
        assert_eq!(config.min_outbound, NodeConfig::regtest().min_outbound);
    }
}

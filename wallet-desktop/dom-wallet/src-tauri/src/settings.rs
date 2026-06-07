//! Persistent application settings.
//!
//! Stored as JSON in the app config dir. Holds node/network knobs, the
//! auto-lock timeout, mining preferences, directories, and theme. Secrets are
//! NEVER stored here (no passwords, no seeds, no bearer tokens).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

/// Default listen addresses / ports from the brief.
const DEFAULT_P2P_PORT: u16 = 33370;
const DEFAULT_METRICS_PORT: u16 = 33371;
const DEFAULT_RPC_PORT: u16 = 33372;

/// Theme options for the UI.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    Light,
    Dark,
    Auto,
}

impl Default for Theme {
    fn default() -> Self {
        // Dark is the default per the visual identity.
        Theme::Dark
    }
}

/// All user-facing settings. Serializable for the Settings screen and for disk.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeSettings {
    /// "testnet" | "mainnet" | "regtest".
    pub network: String,
    /// CSV-derived list of host:port seed peers (may be empty).
    pub seed_peers: Vec<String>,
    /// P2P listen address (host:port).
    pub p2p_listen_addr: String,
    /// Local RPC listen address (loopback host:port).
    pub rpc_listen_addr: String,
    /// Prometheus metrics listen address (loopback host:port).
    pub metrics_listen_addr: String,
    /// Chain data directory.
    pub data_dir: String,
    /// Wallet directory (the WalletDir lives here).
    pub wallet_dir: String,
    /// Backup directory for exported wallet copies.
    pub backup_dir: String,
    /// Auto-lock timeout in minutes. `None` = never.
    pub auto_lock_minutes: Option<u32>,
    /// Whether mining is enabled.
    pub mining_enabled: bool,
    /// Number of miner threads (1..=cores).
    pub mining_threads: u32,
    /// Node log verbosity: trace|debug|info|warn|error.
    pub log_level: String,
    /// UI theme.
    pub theme: Theme,

    // ── V2 transaction defaults (additive; default via serde for V1 configs) ──
    /// Default transaction mode: "slatepack" | "simple".
    #[serde(default = "default_tx_mode")]
    pub default_tx_mode: String,
    /// Default slate expiry in hours (Mode A).
    #[serde(default = "default_expiry_hours")]
    pub tx_slate_expiry_hours: Option<u32>,
    /// Default receive-descriptor expiry in hours (Mode B).
    #[serde(default = "default_expiry_hours")]
    pub tx_descriptor_expiry_hours: Option<u32>,
    /// Show advanced fee options in the Send UI.
    #[serde(default)]
    pub tx_show_advanced_fees: bool,
    /// Auto-generate a new Slatepack address per transaction (privacy).
    #[serde(default = "default_true")]
    pub tx_new_address_per_tx: bool,
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn default_tx_mode() -> String {
    "slatepack".into()
}
fn default_expiry_hours() -> Option<u32> {
    Some(24)
}
fn default_true() -> bool {
    true
}

impl Default for NodeSettings {
    fn default() -> Self {
        let base = default_data_root();
        NodeSettings {
            network: "testnet".into(),
            seed_peers: Vec::new(),
            p2p_listen_addr: format!("0.0.0.0:{DEFAULT_P2P_PORT}"),
            rpc_listen_addr: format!("127.0.0.1:{DEFAULT_RPC_PORT}"),
            metrics_listen_addr: format!("127.0.0.1:{DEFAULT_METRICS_PORT}"),
            data_dir: base.join("chain").to_string_lossy().into_owned(),
            wallet_dir: base.join("wallet").to_string_lossy().into_owned(),
            backup_dir: base.join("backups").to_string_lossy().into_owned(),
            auto_lock_minutes: Some(30),
            mining_enabled: true,
            mining_threads: default_threads(),
            log_level: "info".into(),
            theme: Theme::default(),
            default_tx_mode: default_tx_mode(),
            tx_slate_expiry_hours: Some(24),
            tx_descriptor_expiry_hours: Some(24),
            tx_show_advanced_fees: false,
            tx_new_address_per_tx: true,
        }
    }
}

impl NodeSettings {
    /// Map the configured network string to the wallet crate's `Network`.
    pub fn wallet_network(&self) -> dom_wallet::Network {
        match self.network.as_str() {
            "mainnet" => dom_wallet::Network::Mainnet,
            "regtest" => dom_wallet::Network::Regtest,
            _ => dom_wallet::Network::Testnet,
        }
    }

    /// The wallet file/dir path used by the node + wallet manager.
    pub fn wallet_path(&self) -> PathBuf {
        PathBuf::from(&self.wallet_dir)
    }

    /// Validate the parts that, if wrong, would break node startup. Returns a
    /// clean config error rather than letting the node fail opaquely.
    pub fn validate(&self) -> AppResult<()> {
        if !matches!(self.network.as_str(), "testnet" | "mainnet" | "regtest") {
            return Err(AppError::Config(format!(
                "unknown network '{}'",
                self.network
            )));
        }
        check_addr(&self.p2p_listen_addr, "P2P listen address")?;
        check_addr(&self.rpc_listen_addr, "RPC listen address")?;
        check_addr(&self.metrics_listen_addr, "metrics listen address")?;
        if !self.rpc_listen_addr.starts_with("127.0.0.1")
            && !self.rpc_listen_addr.starts_with("localhost")
        {
            return Err(AppError::Config(
                "RPC must bind to loopback (127.0.0.1) — it is a security boundary".into(),
            ));
        }
        if self.mining_threads == 0 {
            return Err(AppError::Config("mining threads must be at least 1".into()));
        }
        // Auto-lock of 0 minutes would re-lock on every watcher tick, making the
        // wallet unusable. The UI never offers it, but the raw settings IPC and
        // a hand-edited file could. Reject it (use None for "never"). (Audit D-01.)
        if self.auto_lock_minutes == Some(0) {
            return Err(AppError::Config(
                "auto-lock minutes must be at least 1 (use \"never\" to disable)".into(),
            ));
        }
        Ok(())
    }

    /// Load settings, or defaults if the file is ABSENT (first run). A file that
    /// exists but fails to parse is a hard error — silently reverting to
    /// defaults would flip network/paths/mining and could point the app at the
    /// wrong wallet or start a node with unintended settings. (Audit HIGH-04.)
    pub fn load(path: &std::path::Path) -> Self {
        match Self::try_load(path) {
            Ok(s) => s,
            Err(_) => NodeSettings::default(),
        }
    }

    /// Fallible load: `Ok(defaults)` if absent, `Ok(settings)` if valid, `Err`
    /// (after quarantining) if a present file is corrupt.
    pub fn try_load(path: &std::path::Path) -> AppResult<Self> {
        if !path.exists() {
            return Ok(NodeSettings::default());
        }
        let text = std::fs::read_to_string(path).map_err(|e| AppError::Config(e.to_string()))?;
        match serde_json::from_str::<NodeSettings>(&text) {
            Ok(s) => Ok(s),
            Err(e) => {
                let q = path.with_extension(format!("corrupt.{}", now_unix_secs()));
                let _ = std::fs::rename(path, &q);
                tracing::error!("settings corrupt ({e}); quarantined to {}", q.display());
                Err(AppError::Config(format!(
                    "settings file is corrupt and was quarantined to {}. \
                     Default settings are in effect; review before mining or sending.",
                    q.display()
                )))
            }
        }
    }

    /// Persist settings durably: temp → flush → fsync → rename → fsync parent.
    pub fn save(&self, path: &std::path::Path) -> AppResult<()> {
        use std::io::Write;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text =
            serde_json::to_string_pretty(self).map_err(|e| AppError::Config(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.flush()?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

fn check_addr(addr: &str, label: &str) -> AppResult<()> {
    let ok = addr
        .rsplit_once(':')
        .map(|(_, port)| port.parse::<u16>().is_ok())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(AppError::Config(format!("{label} is not host:port: {addr}")))
    }
}

/// Best-effort default data root: `$HOME/.dom-wallet` (or CWD fallback).
fn default_data_root() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        PathBuf::from(home).join(".dom-wallet")
    } else {
        PathBuf::from(".dom-wallet")
    }
}

fn default_threads() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        NodeSettings::default().validate().unwrap();
    }

    #[test]
    fn rpc_must_be_loopback() {
        let mut s = NodeSettings::default();
        s.rpc_listen_addr = "0.0.0.0:33372".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn rejects_unknown_network() {
        let mut s = NodeSettings::default();
        s.network = "fakenet".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn roundtrip_save_load() {
        let dir = std::env::temp_dir().join(format!("dom-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let mut s = NodeSettings::default();
        s.mining_threads = 3;
        s.auto_lock_minutes = None;
        s.save(&path).unwrap();
        let loaded = NodeSettings::load(&path);
        assert_eq!(loaded.mining_threads, 3);
        assert_eq!(loaded.auto_lock_minutes, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wallet_network_maps_correctly() {
        let mut s = NodeSettings::default();
        s.network = "mainnet".into();
        assert!(matches!(s.wallet_network(), dom_wallet::Network::Mainnet));
        s.network = "regtest".into();
        assert!(matches!(s.wallet_network(), dom_wallet::Network::Regtest));
    }

    #[test]
    fn rejects_zero_auto_lock() {
        // Audit D-01: 0 would re-lock every tick.
        let mut s = NodeSettings::default();
        s.auto_lock_minutes = Some(0);
        assert!(s.validate().is_err());
        s.auto_lock_minutes = Some(1);
        assert!(s.validate().is_ok());
        s.auto_lock_minutes = None; // "never" is fine
        assert!(s.validate().is_ok());
    }
}

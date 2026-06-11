//! User-controllable node settings, and the mapping to `dom_config::NodeConfig`.
//!
//! Each field corresponds to one of the `DOM_*` environment variables the
//! standalone node honours. The desktop wallet passes them through the
//! strongly-typed `NodeConfig` instead of exporting process-global env vars.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{anyhow, Context as _, Result};
use dom_config::{MinerThrottleConfig, NodeConfig};
use dom_wallet::{Bip39Seed, Network as WalletNetwork, WalletDir};
use serde::{Deserialize, Serialize};

const DEFAULT_BOOTSTRAP_SEED_PEER: &str = "192.153.57.211:8443";
const LEGACY_BOOTSTRAP_SEED_PEER: &str = "192.153.57.211:33370";

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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    /// Operator-facing CPU limit. The embedded miner currently runs one active
    /// nonce-search worker; keep this explicit so saved wallet settings cannot
    /// request unbounded miner workers in future builds.
    #[serde(default = "default_miner_threads")]
    pub miner_threads: usize,
    /// Local sleep applied by the node miner throttle. This is resource control
    /// only and is not consensus data.
    #[serde(default = "default_miner_throttle_ms")]
    pub miner_throttle_ms: u64,
    pub metrics_listen_addr: Option<String>,
    pub log_level: String,
}

impl Default for NodeSettings {
    fn default() -> Self {
        let data_dir = default_data_dir();
        Self {
            network: NetworkKind::Testnet,
            seed_peers: vec![DEFAULT_BOOTSTRAP_SEED_PEER.to_string()],
            p2p_listen_addr: "0.0.0.0:33370".to_string(),
            rpc_listen_addr: "127.0.0.1:33372".to_string(),
            data_dir,
            miner_wallet_path: None,
            mine: false,
            miner_threads: default_miner_threads(),
            miner_throttle_ms: default_miner_throttle_ms(),
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
        for peer in self.normalized_seed_peers() {
            parse_socket_addr("seed peer", &peer)?;
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
        if self.mine {
            // No explicit path means the app-managed default
            // (`<data_dir>/miner-wallet.dom`, auto-created with its own
            // generated key — see `miner_wallet_credentials`). Mining must
            // never require the user to pick a reward wallet manually; an
            // EXPLICIT path is an advanced override and is still validated.
            if let Some(path) = self
                .miner_wallet_path
                .as_deref()
                .map(str::trim)
                .filter(|path| !path.is_empty())
            {
                validate_miner_wallet_path(path)?;
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
        config.miner_throttle = self.miner_throttle_config();
        config.log_level = self.log_level.clone();
        config.rpc_listen_addr = Some(self.rpc_listen_addr.clone());
        config.rpc_bearer_token = rpc_bearer_token;
        config.metrics_listen_addr = self.metrics_listen_addr.clone();

        // Mining wallet (dedicated; never the user's). Only set when mining.
        if self.mine {
            let (path, password) = self.miner_wallet_credentials()?;
            // DOM-SEC-004: the embedded node only OPENS a wallet directory — it
            // never creates one. Resolving the path/password above is not
            // enough; without a real wallet on disk the node fails to open
            // `miner-wallet.dom` and fail-closes mining. Materialize it here,
            // right before `DomNode::init`, so it exists for every path that
            // enables mining (create, restore, open-by-name, or toggling mining
            // on later in Settings).
            self.ensure_miner_wallet_exists(&path, &password)?;
            config.wallet_path = Some(path);
            config.wallet_password = Some(password);
        } else {
            config.wallet_path = None;
            config.wallet_password = None;
        }

        let seed_peers = self.normalized_seed_peers();
        if !seed_peers.is_empty() {
            let seed_peer_count = seed_peers.len();
            config.seed_peers = seed_peers;
            // When the user supplies explicit seed peers we treat them as the
            // authoritative bootstrap set and DISABLE DNS-seed discovery. Note
            // that clearing `config.dns_seeds` alone is NOT enough: an empty
            // list makes `dom_wire::dns_seed::resolve_seeds` fall back to the
            // hardcoded network DNS seeds, and the testnet seed
            // (`testnet-seed1.dom-protocol.org`) resolves to the bootstrap host
            // which would then be dialed on the default P2P port (33370). The
            // explicit flag makes the connector skip DNS resolution entirely,
            // so a custom seed (e.g. a local tunnel `127.0.0.1:18443`) is the
            // only bootstrap source. Scoped to "seed peers present" so the
            // public mainnet/testnet defaults keep DNS discovery.
            config.disable_dns_seeds = true;
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
                config.min_outbound = seed_peer_count.clamp(1, 8);
            }
        }

        // Basic validation that would otherwise fail deep inside the node.
        if config.rpc_listen_addr.as_deref() == Some("") {
            return Err(anyhow!("RPC listen address must not be empty"));
        }
        tracing::info!(
            "wallet node settings: mining_enabled={} miner_threads={} miner_throttle_ms={} effective_seed_peers={}",
            config.mine,
            self.normalized_miner_threads(),
            self.normalized_miner_throttle_ms(),
            if config.seed_peers.is_empty() {
                "(none)".to_string()
            } else {
                config.seed_peers.join(",")
            }
        );
        Ok(config)
    }

    pub fn normalized_miner_threads(&self) -> usize {
        self.miner_threads.clamp(1, available_parallelism())
    }

    pub fn normalized_miner_throttle_ms(&self) -> u64 {
        self.miner_throttle_ms
    }

    fn normalized_seed_peers(&self) -> Vec<String> {
        let mut peers = Vec::new();
        for peer in &self.seed_peers {
            let peer = match peer.trim() {
                "" => continue,
                LEGACY_BOOTSTRAP_SEED_PEER => DEFAULT_BOOTSTRAP_SEED_PEER,
                peer => peer,
            };
            if !peers.iter().any(|existing| existing == peer) {
                peers.push(peer.to_string());
            }
        }
        peers
    }

    fn miner_throttle_config(&self) -> MinerThrottleConfig {
        let ms = self.normalized_miner_throttle_ms();
        if ms == 0 {
            MinerThrottleConfig::default()
        } else {
            MinerThrottleConfig {
                enabled: true,
                yield_every_nonces: 1_000,
                sleep_micros: ms.saturating_mul(1_000),
            }
        }
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

    /// Materialize the dedicated miner wallet at `path` if it does not exist.
    ///
    /// DOM-SEC-004: the embedded node only OPENS a wallet directory — it never
    /// creates one (see `dom_node::node`: a missing/unopenable wallet leaves
    /// mining disabled, fail-closed). `miner_wallet_credentials` resolves the
    /// path and persists the generated password, but without a real wallet on
    /// disk the node cannot open `miner-wallet.dom`. We create a genuine,
    /// reopenable `WalletDir` here — same primitive the user's own wallet uses
    /// (`wallet_manager::create_new`) — so the fail-closed check is SATISFIED,
    /// not bypassed.
    ///
    /// The miner wallet has its OWN fresh seed (never the user's seed or
    /// password): coinbase rewards land here and the periodic auto-sweep
    /// (`lib.rs::do_sweep`) forwards matured rewards to the user's wallet. The
    /// mnemonic is intentionally throwaway — it is discarded immediately and
    /// NEVER logged, the same way the generated key password is never logged.
    ///
    /// Idempotent: when a wallet already exists at `path` we leave it untouched.
    /// Recreating it would discard already-mined rewards and the existing seed.
    /// (`WalletDir::create_from_seed` itself refuses to overwrite a non-empty
    /// directory, but we skip it explicitly so a normal app restart is a clean
    /// no-op rather than a swallowed error.)
    fn ensure_miner_wallet_exists(&self, path: &str, password: &str) -> Result<()> {
        let wallet_dir = Path::new(path);
        if wallet_dir_is_populated(wallet_dir) {
            // Already created on a previous run — reuse it as-is.
            return Ok(());
        }

        let network = self.wallet_network();
        let genesis = dom_core::startup_genesis_hash_for_network_magic(network.magic())
            .map_err(|e| anyhow!("miner wallet genesis hash: {e}"))?;
        let seed = Bip39Seed::generate_new().map_err(|e| anyhow!("miner wallet seed gen: {e}"))?;

        // Create then immediately drop: `create_from_seed` holds the exclusive
        // wallet lockfile, and the embedded node opens this same directory
        // moments later — dropping the handle releases the lock. The mnemonic
        // is never bound to a variable that outlives this call and is never
        // logged.
        let dir = WalletDir::create_from_seed(wallet_dir, password, network, &genesis, &seed)
            .map_err(|e| anyhow!("create miner wallet: {e}"))?;
        drop(dir);

        // Path only — never the seed or password.
        tracing::info!("dedicated miner wallet created at {}", wallet_dir.display());
        Ok(())
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

/// Whether `path` already holds a wallet directory we must not clobber.
///
/// Mirrors `WalletDir::create_from_seed`'s own guard: a non-empty directory is
/// treated as an existing wallet (reuse it), while a missing or empty directory
/// means "create". Used to keep miner-wallet creation idempotent across restarts.
fn wallet_dir_is_populated(path: &Path) -> bool {
    path.is_dir()
        && std::fs::read_dir(path)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false)
}

fn default_miner_threads() -> usize {
    1
}

fn default_miner_throttle_ms() -> u64 {
    10
}

fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn parse_socket_addr(label: &str, addr: &str) -> Result<SocketAddr> {
    addr.parse::<SocketAddr>()
        .map_err(|e| anyhow!("{label} is invalid ({addr:?}): {e}"))
}

fn validate_miner_wallet_path(path: &str) -> Result<()> {
    let path = Path::new(path);
    if path.exists() {
        let meta = std::fs::metadata(path)
            .map_err(|_| anyhow!("Miner reward wallet is invalid or cannot be opened."))?;
        if meta.is_dir() {
            return Err(anyhow!(
                "Miner reward wallet is invalid or cannot be opened."
            ));
        }
        return Ok(());
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("Miner reward wallet is invalid or cannot be opened."))?;
    let meta = std::fs::metadata(parent)
        .map_err(|_| anyhow!("Miner reward wallet is invalid or cannot be opened."))?;
    if !meta.is_dir() {
        return Err(anyhow!(
            "Miner reward wallet is invalid or cannot be opened."
        ));
    }
    Ok(())
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
            miner_threads: 1,
            miner_throttle_ms: 10,
            metrics_listen_addr: Some("127.0.0.1:33371".into()),
            log_level: "debug".into(),
        }
    }

    /// Regression guard for the "peers stays 0" bug: when the user configures
    /// seed peers, `to_node_config` must guarantee at least one outbound slot
    /// so `PeerManager::needs_outbound()` can ever be true and the connector
    /// actually dials. Without the guard a `min_outbound == 0` config silently
    /// disables all outbound dialing.
    fn testnet_settings_with_seed(seed: Vec<String>) -> NodeSettings {
        NodeSettings {
            network: NetworkKind::Testnet,
            seed_peers: seed,
            p2p_listen_addr: "0.0.0.0:33370".into(),
            rpc_listen_addr: "127.0.0.1:33372".into(),
            data_dir: std::env::temp_dir()
                .join("dom-settings-test-testnet")
                .to_string_lossy()
                .into_owned(),
            miner_wallet_path: None,
            mine: false,
            miner_threads: 1,
            miner_throttle_ms: 10,
            metrics_listen_addr: Some("127.0.0.1:33371".into()),
            log_level: "debug".into(),
        }
    }

    /// Etapa 1: a custom seed peer (e.g. the local SSH tunnel `127.0.0.1:18443`)
    /// must be PRESERVED and must DISABLE DNS-seed discovery, so the testnet DNS
    /// seed cannot reintroduce the bootstrap host on the default P2P port
    /// (`192.153.57.211:33370`).
    #[test]
    fn custom_seed_peers_disable_dns_seeds_and_preserve_tunnel() {
        // Sanity: testnet ships a non-empty DNS seed by default, so disabling it
        // is a deliberate, observable change rather than a no-op.
        assert!(!NodeConfig::testnet().dns_seeds.is_empty());

        let settings = testnet_settings_with_seed(vec!["127.0.0.1:18443".into()]);
        let config = settings.to_node_config(None).expect("config");
        assert_eq!(config.seed_peers, vec!["127.0.0.1:18443".to_string()]);
        assert!(
            config.disable_dns_seeds,
            "custom seed peers must disable DNS-seed discovery"
        );
    }

    /// Without a custom seed peer the default behavior is unchanged: DNS-seed
    /// discovery stays enabled and the testnet DNS seed list is preserved.
    #[test]
    fn no_custom_seed_peers_keep_dns_seeds_enabled() {
        let settings = testnet_settings_with_seed(vec![]);
        let config = settings.to_node_config(None).expect("config");
        assert!(config.seed_peers.is_empty());
        assert!(!config.disable_dns_seeds);
        assert_eq!(config.dns_seeds, NodeConfig::testnet().dns_seeds);
    }

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

    #[test]
    fn default_wallet_settings_do_not_mine_and_keep_local_services() {
        let settings = NodeSettings::default();
        assert!(!settings.mine);
        assert_eq!(settings.miner_threads, 1);
        assert_eq!(settings.miner_throttle_ms, 10);
        assert_eq!(settings.seed_peers, vec!["192.153.57.211:8443"]);
        let config = settings.to_node_config(None).expect("default config");
        assert!(!config.mine);
        assert_eq!(config.rpc_listen_addr.as_deref(), Some("127.0.0.1:33372"));
        assert_eq!(
            config.metrics_listen_addr.as_deref(),
            Some("127.0.0.1:33371")
        );
    }

    /// Mining without an explicit reward wallet must auto-provision the
    /// app-managed one under the node data dir — the user never picks a path.
    #[test]
    fn mining_without_explicit_reward_wallet_uses_managed_default() {
        let mut settings = regtest_settings_with_seed(vec![]);
        settings.data_dir = tempfile::tempdir()
            .expect("tempdir")
            .keep()
            .to_string_lossy()
            .into_owned();
        settings.mine = true;
        settings.miner_wallet_path = None;
        let config = settings
            .to_node_config(None)
            .expect("mining must not require a manual reward wallet");
        assert!(config.mine);
        let wallet_path = config.wallet_path.expect("auto miner wallet path");
        assert!(
            wallet_path.ends_with("miner-wallet.dom"),
            "auto reward wallet must live under the data dir, got {wallet_path}"
        );
        assert!(
            wallet_path.starts_with(&settings.data_dir),
            "auto reward wallet must live under the data dir"
        );
        let password = config.wallet_password.expect("auto miner wallet password");
        assert!(!password.is_empty());
        let _ = std::fs::remove_dir_all(&settings.data_dir);
    }

    #[test]
    fn mining_off_accepts_missing_empty_or_invalid_miner_wallet() {
        let mut settings = regtest_settings_with_seed(vec![]);

        settings.mine = false;
        settings.miner_wallet_path = None;
        let config = settings.to_node_config(None).expect("none accepted");
        assert!(!config.mine);
        assert_eq!(config.wallet_path, None);
        assert_eq!(config.wallet_password, None);

        settings.miner_wallet_path = Some("".into());
        let config = settings.to_node_config(None).expect("empty accepted");
        assert!(!config.mine);
        assert_eq!(config.wallet_path, None);
        assert_eq!(config.wallet_password, None);

        settings.miner_wallet_path = Some(
            std::env::temp_dir()
                .join("dom-missing-miner-parent")
                .join("node.dom")
                .to_string_lossy()
                .into_owned(),
        );
        let config = settings
            .to_node_config(None)
            .expect("invalid ignored while off");
        assert!(!config.mine);
        assert_eq!(config.wallet_path, None);
        assert_eq!(config.wallet_password, None);
    }

    /// An EXPLICIT miner wallet override is still validated: a path whose
    /// parent does not exist must be rejected, while an empty string now falls
    /// back to the app-managed default instead of failing.
    #[test]
    fn mining_on_rejects_invalid_explicit_miner_wallet() {
        let mut settings = regtest_settings_with_seed(vec![]);
        settings.mine = true;

        settings.miner_wallet_path = Some(
            std::env::temp_dir()
                .join("dom-missing-miner-parent")
                .join("node.dom")
                .to_string_lossy()
                .into_owned(),
        );
        let err = settings
            .to_node_config(None)
            .expect_err("invalid miner wallet must fail");
        assert_eq!(
            err.to_string(),
            "Miner reward wallet is invalid or cannot be opened."
        );
    }

    #[test]
    fn miner_thread_limit_is_normalized_safely() {
        let mut settings = regtest_settings_with_seed(vec![]);
        settings.miner_threads = 0;
        assert_eq!(settings.normalized_miner_threads(), 1);

        settings.miner_threads = usize::MAX;
        assert_eq!(settings.normalized_miner_threads(), available_parallelism());
    }

    #[test]
    fn miner_throttle_maps_to_local_node_throttle_only() {
        let mut settings = regtest_settings_with_seed(vec![]);
        settings.miner_throttle_ms = 25;
        let config = settings.to_node_config(None).expect("config");
        assert!(!config.mine);
        assert!(config.miner_throttle.enabled);
        assert_eq!(config.miner_throttle.yield_every_nonces, 1_000);
        assert_eq!(config.miner_throttle.sleep_micros, 25_000);
    }

    #[test]
    fn bootstrap_seed_peer_is_valid_socket() {
        let settings = regtest_settings_with_seed(vec!["192.153.57.211:8443".into()]);
        let config = settings
            .to_node_config(None)
            .expect("bootstrap peer accepted");
        assert_eq!(config.seed_peers, vec!["192.153.57.211:8443"]);
    }

    #[test]
    fn legacy_bootstrap_seed_peer_is_migrated_and_deduplicated() {
        let settings = regtest_settings_with_seed(vec![
            "192.153.57.211:33370".into(),
            "192.153.57.211:8443".into(),
            " 192.153.57.211:33370 ".into(),
        ]);
        let config = settings
            .to_node_config(None)
            .expect("legacy bootstrap peer migrated");
        assert_eq!(config.seed_peers, vec!["192.153.57.211:8443"]);
    }

    #[test]
    fn invalid_seed_peer_is_rejected() {
        let settings = regtest_settings_with_seed(vec!["not-a-socket".into()]);
        let err = settings
            .to_node_config(None)
            .expect_err("invalid seed peer must fail");
        assert!(err.to_string().contains("seed peer is invalid"));
    }

    /// A `mine=true` config in a fresh data dir whose miner wallet does not yet
    /// exist on disk.
    fn mining_settings_in_fresh_dir() -> NodeSettings {
        let mut settings = regtest_settings_with_seed(vec![]);
        settings.data_dir = tempfile::tempdir()
            .expect("tempdir")
            .keep()
            .to_string_lossy()
            .into_owned();
        settings.mine = true;
        settings.miner_wallet_path = None;
        settings
    }

    fn miner_wallet_paths(settings: &NodeSettings) -> (std::path::PathBuf, std::path::PathBuf) {
        let wallet = std::path::Path::new(&settings.data_dir).join("miner-wallet.dom");
        let key = std::path::Path::new(&settings.data_dir).join("miner-wallet.dom.key");
        (wallet, key)
    }

    /// DOM-SEC-004 root cause: when mining is enabled and the miner wallet does
    /// not exist yet, `to_node_config` must CREATE a real, reopenable wallet —
    /// not just resolve a path/password. Proven by reopening the created wallet
    /// with the persisted key password, exactly as the embedded node does.
    #[test]
    fn mining_creates_a_reopenable_miner_wallet() {
        let settings = mining_settings_in_fresh_dir();
        let (wallet_path, key_path) = miner_wallet_paths(&settings);

        assert!(
            !wallet_path.exists(),
            "precondition: miner wallet must not exist yet"
        );

        let config = settings.to_node_config(None).expect("mining config");
        assert!(config.mine);
        assert_eq!(config.wallet_path.as_deref(), wallet_path.to_str());

        // The wallet directory now exists and can be OPENED with the generated
        // key password — i.e. the node's `WalletDir::open` will succeed and
        // mining will NOT fall into the DOM-SEC-004 fail-closed branch.
        assert!(wallet_dir_is_populated(&wallet_path));
        let password = std::fs::read_to_string(&key_path).expect("key file");
        WalletDir::open(&wallet_path, password.trim()).expect("miner wallet must reopen");

        let _ = std::fs::remove_dir_all(&settings.data_dir);
    }

    /// Idempotence: a second `to_node_config` (e.g. an app restart, or toggling
    /// settings) must REUSE the existing miner wallet, never recreate or
    /// overwrite it — recreating would discard already-mined rewards and the
    /// original seed.
    #[test]
    fn miner_wallet_creation_is_idempotent() {
        let settings = mining_settings_in_fresh_dir();
        let (wallet_path, _key_path) = miner_wallet_paths(&settings);

        settings.to_node_config(None).expect("first config");
        let dat_path = wallet_path.join("wallet.dat");
        let first = std::fs::read(&dat_path).expect("wallet.dat after first run");

        // Second call must succeed (no "refusing to overwrite" error) AND leave
        // the encrypted vault byte-for-byte identical (same seed/state).
        settings.to_node_config(None).expect("second config");
        let second = std::fs::read(&dat_path).expect("wallet.dat after second run");
        assert_eq!(
            first, second,
            "miner wallet must be reused, not recreated/overwritten"
        );

        let _ = std::fs::remove_dir_all(&settings.data_dir);
    }

    /// Mining OFF must never create the miner wallet (no path/password set, and
    /// nothing is written to disk).
    #[test]
    fn mining_off_does_not_create_miner_wallet() {
        let mut settings = mining_settings_in_fresh_dir();
        settings.mine = false;
        let (wallet_path, key_path) = miner_wallet_paths(&settings);

        let config = settings.to_node_config(None).expect("config");
        assert!(!config.mine);
        assert_eq!(config.wallet_path, None);
        assert_eq!(config.wallet_password, None);
        assert!(
            !wallet_path.exists(),
            "mining off must not create the miner wallet"
        );
        assert!(
            !key_path.exists(),
            "mining off must not even generate the key file"
        );

        let _ = std::fs::remove_dir_all(&settings.data_dir);
    }

    /// The miner wallet password (and, by construction, its seed) must NEVER
    /// reach any log. We capture all tracing output produced while creating the
    /// wallet and assert the generated key password does not appear in it.
    #[test]
    fn miner_wallet_secret_is_never_logged() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let settings = mining_settings_in_fresh_dir();
        let (_wallet_path, key_path) = miner_wallet_paths(&settings);

        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let make = {
            let buf = buf.clone();
            move || SharedBuf(buf.clone())
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(make)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            settings.to_node_config(None).expect("mining config");
        });

        let logs = String::from_utf8(buf.lock().unwrap().clone()).expect("utf8 logs");
        let password = std::fs::read_to_string(&key_path).expect("key file");
        let password = password.trim();
        assert!(!password.is_empty());
        assert!(
            !logs.contains(password),
            "miner wallet password must never be logged"
        );

        let _ = std::fs::remove_dir_all(&settings.data_dir);
    }
}

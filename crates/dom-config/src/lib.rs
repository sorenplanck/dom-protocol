//! DOM node configuration.
#![deny(unsafe_code)]
#![deny(missing_docs)]

use dom_core::{
    P2P_PORT_MAINNET, P2P_PORT_REGTEST, P2P_PORT_TESTNET, RPC_PORT_MAINNET, RPC_PORT_REGTEST,
    RPC_PORT_TESTNET,
};
use serde::{Deserialize, Serialize};

/// Network selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    /// Mainnet.
    Mainnet,
    /// Testnet.
    Testnet,
    /// Regtest — DEV-ONLY local network. Distinct magic byte
    /// (`NETWORK_MAGIC_REGTEST`) prevents peering with Mainnet/Testnet.
    /// Consensus logic is identical to the real networks; only the PoW
    /// target, coinbase maturity, and RandomX VM flags differ — see
    /// `REGTEST_COINBASE_MATURITY` in `dom-core` and
    /// `REGTEST_TARGET_COMPACT` in `dom-pow`.
    Regtest,
}

impl Network {
    /// Default P2P port.
    pub fn default_port(&self) -> u16 {
        match self {
            Network::Mainnet => P2P_PORT_MAINNET,
            Network::Testnet => P2P_PORT_TESTNET,
            Network::Regtest => P2P_PORT_REGTEST,
        }
    }

    /// Default loopback RPC port.
    pub fn default_rpc_port(&self) -> u16 {
        match self {
            Network::Mainnet => RPC_PORT_MAINNET,
            Network::Testnet => RPC_PORT_TESTNET,
            Network::Regtest => RPC_PORT_REGTEST,
        }
    }

    /// Default loopback RPC listen address.
    ///
    /// RPC remains disabled until an operator explicitly enables it. This
    /// helper supplies the authoritative private binding when no custom address
    /// is requested.
    pub fn default_rpc_listen_addr(&self) -> String {
        format!("127.0.0.1:{}", self.default_rpc_port())
    }
    /// Network magic bytes.
    pub fn magic(&self) -> u32 {
        match self {
            Network::Mainnet => dom_core::NETWORK_MAGIC_MAINNET,
            Network::Testnet => dom_core::NETWORK_MAGIC_TESTNET,
            Network::Regtest => dom_core::NETWORK_MAGIC_REGTEST,
        }
    }

    /// Coinbase maturity (blocks) required before a coinbase output is
    /// spendable on this network.
    ///
    /// Mainnet / Testnet: `dom_core::COINBASE_MATURITY` (1000).
    /// Regtest: `dom_core::REGTEST_COINBASE_MATURITY` (1).
    pub fn coinbase_maturity(&self) -> u64 {
        match self {
            Network::Mainnet | Network::Testnet => dom_core::COINBASE_MATURITY,
            Network::Regtest => dom_core::REGTEST_COINBASE_MATURITY,
        }
    }

    /// Lowercase network name as reported over RPC (`/status`) and in log
    /// banners: `"mainnet"`, `"testnet"`, or `"regtest"`. Informational only;
    /// network isolation is enforced by [`magic`](Self::magic), not this string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        }
    }

    /// `true` if this network exists for local development only and must
    /// never reach a real-network peer. Magic-byte isolation is the
    /// primary guarantee; this helper is informational (e.g. for log
    /// banners).
    pub fn is_dev_only(&self) -> bool {
        matches!(self, Network::Regtest)
    }
}

/// Parse the optional `DOM_NETWORK` value using the canonical startup policy.
///
/// The variable must be present and exactly match one lowercase network name.
/// Empty, mixed-case, padded, unknown, or missing values fail closed instead of
/// selecting a network that could create listeners or contact peers.
pub fn parse_dom_network(value: Option<&str>) -> Result<Network, dom_core::DomError> {
    match value {
        None => Err(dom_core::DomError::Invalid(
            "DOM_NETWORK is required; expected mainnet, testnet, or regtest".into(),
        )),
        Some("mainnet") => Ok(Network::Mainnet),
        Some("testnet") => Ok(Network::Testnet),
        Some("regtest") => Ok(Network::Regtest),
        Some(other) => Err(dom_core::DomError::Invalid(format!(
            "invalid DOM_NETWORK value {other:?}; expected mainnet, testnet, or regtest"
        ))),
    }
}

/// Full node configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Network.
    pub network: Network,
    /// Data directory for LMDB files.
    pub data_dir: String,
    /// P2P listen address.
    pub p2p_listen_addr: String,
    /// Max inbound connections.
    pub max_inbound: usize,
    /// Min outbound connections.
    pub min_outbound: usize,
    /// DNS seeds.
    pub dns_seeds: Vec<String>,
    /// When `true`, the outbound connector skips DNS-seed resolution entirely,
    /// including the hardcoded fallback seeds in `dom_wire::dns_seed`. The
    /// desktop wallet sets this whenever the user supplies explicit
    /// `seed_peers`, so a custom seed (e.g. a local SSH tunnel) is the ONLY
    /// bootstrap source and the network's default DNS seeds cannot reintroduce
    /// unwanted peers (e.g. a testnet DNS seed resolving to the bootstrap host
    /// on the default P2P port). Default `false` leaves standalone-node
    /// behavior unchanged. `#[serde(default)]` keeps legacy configs loadable.
    #[serde(default)]
    pub disable_dns_seeds: bool,
    /// Hardcoded seed peers (IP:port).
    pub seed_peers: Vec<String>,
    /// Enable mining.
    pub mine: bool,
    /// Local miner CPU throttling. This only affects the node process' CPU
    /// usage and is not serialized into blocks, headers, PoW preimages, or
    /// network messages.
    #[serde(default)]
    pub miner_throttle: MinerThrottleConfig,
    /// Number of concurrent nonce-search workers the local miner spawns.
    /// Resource control only — never consensus data. Values are clamped to
    /// at least 1 by the miner; `#[serde(default)]` keeps legacy configs
    /// loadable (defaulting to the historical single worker).
    #[serde(default = "default_miner_threads")]
    pub miner_threads: usize,
    /// Miner reward address.
    pub miner_address: Option<String>,
    /// Path to the wallet file (.dom). Required if mining and using wallet-integrated mining.
    /// If None, miner falls back to throwaway random blindings (DOM-SEC-004 unresolved).
    #[serde(default)]
    pub wallet_path: Option<String>,
    /// Password for the wallet file.
    /// In production, this should come from a separate secret store, not the config TOML.
    #[serde(default, skip_serializing)]
    pub wallet_password: Option<String>,
    /// Log level.
    pub log_level: String,
    /// RPC listen address. `None` keeps RPC disabled. Use
    /// [`Network::default_rpc_listen_addr`] for the authoritative loopback
    /// address when enabling RPC without a custom binding.
    #[serde(default)]
    pub rpc_listen_addr: Option<String>,
    /// Explicit RPC bearer token for embedded callers.
    ///
    /// If unset, `dom-rpc` falls back to its standalone-node behavior: read
    /// `DOM_RPC_TOKEN`, then `~/.dom/rpc_token`, then generate a token file.
    #[serde(default, skip_serializing)]
    pub rpc_bearer_token: Option<String>,
    /// Prometheus metrics listen address (for example `127.0.0.1:3371`).
    /// None = metrics endpoint disabled. Prefer loopback/internal bindings;
    /// metrics expose node health and topology signals.
    #[serde(default)]
    pub metrics_listen_addr: Option<String>,
}

/// Historical default: one nonce-search worker.
fn default_miner_threads() -> usize {
    1
}

/// Local miner CPU throttle configuration.
///
/// This is an operator resource-control setting only. It is not consensus
/// data and must never affect target calculation, block validity, or emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MinerThrottleConfig {
    /// Enable local throttling.
    pub enabled: bool,
    /// Apply a local yield/sleep after this many nonce attempts.
    pub yield_every_nonces: u64,
    /// Sleep duration in microseconds when throttling. Zero means yield only.
    pub sleep_micros: u64,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("network", &self.network)
            .field("data_dir", &self.data_dir)
            .field("p2p_listen_addr", &self.p2p_listen_addr)
            .field("max_inbound", &self.max_inbound)
            .field("min_outbound", &self.min_outbound)
            .field("dns_seeds", &self.dns_seeds)
            .field("disable_dns_seeds", &self.disable_dns_seeds)
            .field("seed_peers", &self.seed_peers)
            .field("mine", &self.mine)
            .field("miner_throttle", &self.miner_throttle)
            .field("miner_threads", &self.miner_threads)
            .field("miner_address", &self.miner_address)
            .field("wallet_path", &self.wallet_path)
            .field(
                "wallet_password",
                &self
                    .wallet_password
                    .as_ref()
                    .map(|_| "<redacted>")
                    .unwrap_or("<none>"),
            )
            .field("log_level", &self.log_level)
            .field("rpc_listen_addr", &self.rpc_listen_addr)
            .field(
                "rpc_bearer_token",
                &self
                    .rpc_bearer_token
                    .as_ref()
                    .map(|_| "<redacted>")
                    .unwrap_or("<none>"),
            )
            .field("metrics_listen_addr", &self.metrics_listen_addr)
            .finish()
    }
}

impl NodeConfig {
    /// Default mainnet config.
    pub fn mainnet() -> Self {
        Self {
            network: Network::Mainnet,
            data_dir: "./dom-data".into(),
            p2p_listen_addr: format!("0.0.0.0:{P2P_PORT_MAINNET}"),
            max_inbound: 125,
            min_outbound: 8,
            dns_seeds: vec![
                "seed1.dom-protocol.org".into(),
                "seed2.dom-protocol.org".into(),
            ],
            disable_dns_seeds: false,
            seed_peers: vec![],
            mine: false,
            miner_throttle: MinerThrottleConfig::default(),
            miner_threads: 1,
            miner_address: None,
            wallet_path: None,
            wallet_password: None,
            log_level: "info".into(),
            rpc_listen_addr: None,
            rpc_bearer_token: None,
            metrics_listen_addr: None,
        }
    }
    /// Default testnet config.
    pub fn testnet() -> Self {
        Self {
            network: Network::Testnet,
            data_dir: "./dom-testnet-data".into(),
            p2p_listen_addr: format!("0.0.0.0:{P2P_PORT_TESTNET}"),
            max_inbound: 50,
            min_outbound: 4,
            dns_seeds: vec!["testnet-seed1.dom-protocol.org".into()],
            disable_dns_seeds: false,
            seed_peers: vec![],
            mine: true,
            miner_throttle: MinerThrottleConfig::default(),
            miner_threads: 1,
            miner_address: None,
            wallet_path: None,
            wallet_password: None,
            log_level: "debug".into(),
            rpc_listen_addr: None,
            rpc_bearer_token: None,
            metrics_listen_addr: None,
        }
    }

    /// Default Regtest config — DEV-ONLY. Listens on `127.0.0.1` only,
    /// no DNS seeds, no remote peering. Suitable for local CI and
    /// integration tests; never for a production deployment.
    pub fn regtest() -> Self {
        Self {
            network: Network::Regtest,
            data_dir: "./dom-regtest-data".into(),
            p2p_listen_addr: format!("127.0.0.1:{P2P_PORT_REGTEST}"),
            max_inbound: 8,
            min_outbound: 1,
            dns_seeds: vec![],
            disable_dns_seeds: false,
            seed_peers: vec![],
            mine: false,
            miner_throttle: MinerThrottleConfig::default(),
            miner_threads: 1,
            miner_address: None,
            wallet_path: None,
            wallet_password: None,
            log_level: "debug".into(),
            rpc_listen_addr: None,
            rpc_bearer_token: None,
            metrics_listen_addr: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Network, NodeConfig};

    #[test]
    fn network_as_str_matches_variant() {
        assert_eq!(Network::Mainnet.as_str(), "mainnet");
        assert_eq!(Network::Testnet.as_str(), "testnet");
        assert_eq!(Network::Regtest.as_str(), "regtest");
    }

    #[test]
    fn metrics_listen_addr_defaults_to_disabled() {
        assert!(NodeConfig::mainnet().metrics_listen_addr.is_none());
        assert!(NodeConfig::testnet().metrics_listen_addr.is_none());
        assert!(NodeConfig::regtest().metrics_listen_addr.is_none());
    }

    #[test]
    fn metrics_listen_addr_is_serde_defaulted_for_legacy_configs() {
        let json = r#"{
            "network":"Regtest",
            "data_dir":"./tmp",
            "p2p_listen_addr":"127.0.0.1:0",
            "max_inbound":8,
            "min_outbound":0,
            "dns_seeds":[],
            "seed_peers":[],
            "mine":false,
            "miner_address":null,
            "log_level":"debug",
            "rpc_listen_addr":null
        }"#;
        let config: NodeConfig = serde_json::from_str(json).expect("legacy config");
        assert!(config.metrics_listen_addr.is_none());
        assert_eq!(
            config.miner_threads, 1,
            "legacy configs without miner_threads must keep the historical single worker"
        );
    }

    #[test]
    fn miner_threads_defaults_to_one_worker() {
        assert_eq!(NodeConfig::mainnet().miner_threads, 1);
        assert_eq!(NodeConfig::testnet().miner_threads, 1);
        assert_eq!(NodeConfig::regtest().miner_threads, 1);
    }

    #[test]
    fn debug_redacts_secret_fields() {
        let mut config = NodeConfig::regtest();
        config.wallet_password = Some("secret-password".into());
        config.rpc_bearer_token = Some("rpc-secret".into());

        let rendered = format!("{config:?}");

        assert!(rendered.contains("wallet_password: \"<redacted>\""));
        assert!(rendered.contains("rpc_bearer_token: \"<redacted>\""));
        assert!(!rendered.contains("secret-password"));
        assert!(!rendered.contains("rpc-secret"));
    }

    #[test]
    fn serialization_omits_secret_fields() {
        let mut config = NodeConfig::regtest();
        config.wallet_password = Some("secret-password".into());
        config.rpc_bearer_token = Some("rpc-secret".into());

        let json = serde_json::to_string(&config).expect("serialize config");

        assert!(!json.contains("wallet_password"));
        assert!(!json.contains("rpc_bearer_token"));
        assert!(!json.contains("secret-password"));
        assert!(!json.contains("rpc-secret"));
    }
}

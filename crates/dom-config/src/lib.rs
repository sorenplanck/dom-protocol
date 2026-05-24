//! DOM node configuration.
#![deny(unsafe_code)]
#![deny(missing_docs)]

use dom_core::{P2P_PORT_MAINNET, P2P_PORT_REGTEST, P2P_PORT_TESTNET};
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
    /// `REGTEST_COINBASE_MATURITY` and
    /// `REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION` in `dom-core`.
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

    /// `true` if this network exists for local development only and must
    /// never reach a real-network peer. Magic-byte isolation is the
    /// primary guarantee; this helper is informational (e.g. for log
    /// banners).
    pub fn is_dev_only(&self) -> bool {
        matches!(self, Network::Regtest)
    }
}

/// Full node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Hardcoded seed peers (IP:port).
    pub seed_peers: Vec<String>,
    /// Enable mining.
    pub mine: bool,
    /// Miner reward address.
    pub miner_address: Option<String>,
    /// Path to the wallet file (.dom). Required if mining and using wallet-integrated mining.
    /// If None, miner falls back to throwaway random blindings (DOM-SEC-004 unresolved).
    #[serde(default)]
    pub wallet_path: Option<String>,
    /// Password for the wallet file.
    /// In production, this should come from a separate secret store, not the config TOML.
    #[serde(default)]
    pub wallet_password: Option<String>,
    /// Log level.
    pub log_level: String,
    /// RPC listen address (e.g. "127.0.0.1:3370"). None = RPC disabled.
    #[serde(default)]
    pub rpc_listen_addr: Option<String>,
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
            seed_peers: vec![],
            mine: false,
            miner_address: None,
            wallet_path: None,
            wallet_password: None,
            log_level: "info".into(),
            rpc_listen_addr: None,
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
            seed_peers: vec![],
            mine: true,
            miner_address: None,
            wallet_path: None,
            wallet_password: None,
            log_level: "debug".into(),
            rpc_listen_addr: None,
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
            min_outbound: 0,
            dns_seeds: vec![],
            seed_peers: vec![],
            mine: false,
            miner_address: None,
            wallet_path: None,
            wallet_password: None,
            log_level: "debug".into(),
            rpc_listen_addr: None,
        }
    }
}

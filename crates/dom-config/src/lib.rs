//! DOM node configuration.
#![deny(unsafe_code)]
#![deny(missing_docs)]

use dom_core::{P2P_PORT_MAINNET, P2P_PORT_TESTNET};
use serde::{Deserialize, Serialize};

/// Network selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network { 
    /// Mainnet.
    Mainnet, 
    /// Testnet.
    Testnet 
}

impl Network {
    /// Default P2P port.
    pub fn default_port(&self) -> u16 {
        match self { Network::Mainnet => P2P_PORT_MAINNET, Network::Testnet => P2P_PORT_TESTNET }
    }
    /// Network magic bytes.
    pub fn magic(&self) -> u32 {
        match self { Network::Mainnet => dom_core::NETWORK_MAGIC_MAINNET, Network::Testnet => dom_core::NETWORK_MAGIC_TESTNET }
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
    /// Log level.
    pub log_level: String,
}

impl NodeConfig {
    /// Default mainnet config.
    pub fn mainnet() -> Self {
        Self {
            network: Network::Mainnet,
            data_dir: "./dom-data".into(),
            p2p_listen_addr: format!("0.0.0.0:{P2P_PORT_MAINNET}"),
            max_inbound: 125, min_outbound: 8,
            dns_seeds: vec!["seed1.dom-protocol.org".into(), "seed2.dom-protocol.org".into()],
            seed_peers: vec![], mine: false, miner_address: None,
            log_level: "info".into(),
        }
    }
    /// Default testnet config.
    pub fn testnet() -> Self {
        Self {
            network: Network::Testnet,
            data_dir: "./dom-testnet-data".into(),
            p2p_listen_addr: format!("0.0.0.0:{P2P_PORT_TESTNET}"),
            max_inbound: 50, min_outbound: 4,
            dns_seeds: vec!["testnet-seed1.dom-protocol.org".into()],
            seed_peers: vec![], mine: true, miner_address: None,
            log_level: "debug".into(),
        }
    }
}

//! DOM node entry point.

use dom_config::NodeConfig;
use dom_node::node::DomNode;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("DOM_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    info!("DOM Node v{}", env!("CARGO_PKG_VERSION"));
    info!("Author: Soren Planck");
    info!("License: MIT");

    // Select network via DOM_NETWORK (regtest|testnet|mainnet). Defaults to testnet.
    // Regtest is a LOCAL dev network with a trivial PoW target — fast blocks, no real mining power
    // needed. NEVER use regtest for anything public.
    let mut config = match std::env::var("DOM_NETWORK").as_deref() {
        Ok("regtest") => {
            info!("Network: REGTEST (local dev, trivial PoW)");
            NodeConfig::regtest()
        }
        Ok("mainnet") => {
            info!("Network: MAINNET");
            NodeConfig::mainnet()
        }
        Ok("testnet") | Err(_) => {
            info!("Network: testnet");
            NodeConfig::testnet()
        }
        Ok(other) => {
            info!("Unknown DOM_NETWORK={other}, defaulting to testnet");
            NodeConfig::testnet()
        }
    };

    // Allow override of seed peers via DOM_SEED_PEERS env var (CSV of host:port).
    // Useful for testnet privado where DNS seeds don't exist.
    if let Ok(seeds_csv) = std::env::var("DOM_SEED_PEERS") {
        let seeds: Vec<String> = seeds_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !seeds.is_empty() {
            info!("Using seed peers from DOM_SEED_PEERS: {seeds:?}");
            config.seed_peers = seeds;
        }
    }

    // Allow override of P2P listen address via DOM_P2P_LISTEN_ADDR.
    // Useful when running multiple nodes on the same host.
    if let Ok(addr) = std::env::var("DOM_P2P_LISTEN_ADDR") {
        info!("Overriding P2P listen address: {addr}");
        config.p2p_listen_addr = addr;
    }

    // Allow internal Prometheus metrics endpoint via DOM_METRICS_LISTEN_ADDR.
    // Prefer loopback bindings such as 127.0.0.1:3371; metrics expose node
    // health and topology signals and should not be public by default.
    if let Ok(addr) = std::env::var("DOM_METRICS_LISTEN_ADDR") {
        info!("Enabling metrics listen address: {addr}");
        config.metrics_listen_addr = Some(addr);
    }

    // Allow enabling the RPC server via DOM_RPC_LISTEN_ADDR.
    // The RPC exposes /status, /block, /wallet/spend (bearer-auth) etc. Prefer an internal
    // binding (127.0.0.1) or a firewalled interface; /wallet/spend is sensitive.
    if let Ok(addr) = std::env::var("DOM_RPC_LISTEN_ADDR") {
        info!("Enabling RPC listen address: {addr}");
        config.rpc_listen_addr = Some(addr);
    }

    // Allow disabling mining via DOM_MINE=false (validator/relay-only node).
    // Accepts "false"/"0"/"no" (case-insensitive) to disable; anything else leaves the default.
    if let Ok(v) = std::env::var("DOM_MINE") {
        let on = !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "no" | "off"
        );
        info!("Mining set via DOM_MINE={v} -> mine={on}");
        config.mine = on;
    }

    // Allow override of data dir via DOM_DATA_DIR.
    if let Ok(dir) = std::env::var("DOM_DATA_DIR") {
        info!("Overriding data dir: {dir}");
        config.data_dir = dir;
    }

    // Allow override of wallet path via DOM_WALLET_PATH.
    if let Ok(path) = std::env::var("DOM_WALLET_PATH") {
        info!("Overriding wallet path: {path}");
        config.wallet_path = Some(path);
    }

    // Allow override of wallet password via DOM_WALLET_PASSWORD.
    if let Ok(password) = std::env::var("DOM_WALLET_PASSWORD") {
        info!("Overriding wallet password: [REDACTED]");
        config.wallet_password = Some(password);
    }

    // Initialize node
    let node = Arc::new(DomNode::init(config)?);

    // Verify H generator on startup — FAIL FAST if placeholder
    // A placeholder H may have known discrete log → Pedersen commitment backdoor.
    // Nodes with placeholder H MUST NOT process any transactions.
    let _h_bytes = dom_crypto::h_compressed()
        .map_err(|e| anyhow::anyhow!(
            "H generator not finalized — node refuses to start.\n             Run: cargo test -p dom-crypto print_h_generator -- --nocapture\n             Then update H_COMPRESSED_FINAL in crates/dom-crypto/src/h_generator.rs\n             Error: {e}"
        ))?;
    info!("H generator verified OK: {}", hex::encode(_h_bytes));

    // Run node
    node.run().await?;
    Ok(())
}

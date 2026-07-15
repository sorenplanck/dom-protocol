//! DOM node entry point.

use dom_config::{parse_dom_network, Network, NodeConfig};
use dom_node::node::DomNode;
use std::sync::Arc;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupAction {
    Run,
    Version,
    Help,
}

fn parse_startup_action<I>(args: I) -> anyhow::Result<StartupAction>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let Some(argument) = args.next() else {
        return Ok(StartupAction::Run);
    };
    if args.next().is_some() {
        anyhow::bail!("only --help or --version are accepted as command-line arguments");
    }
    match argument.as_str() {
        "--version" | "-V" => Ok(StartupAction::Version),
        "--help" | "-h" => Ok(StartupAction::Help),
        _ => anyhow::bail!("unknown argument {argument:?}; use --help"),
    }
}

fn print_help() {
    println!(
        "DOM node {}\n\nUsage:\n  DOM_NETWORK=<mainnet|testnet|regtest> dom-node\n\nThe network must be selected explicitly before the node initializes storage, listeners, mining, or peer discovery.\n\nOptions:\n  -h, --help       Print help\n  -V, --version    Print version",
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_startup_action(std::env::args())? {
        StartupAction::Run => {}
        StartupAction::Version => {
            println!("dom-node {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        StartupAction::Help => {
            print_help();
            return Ok(());
        }
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("DOM_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    info!("DOM Node v{}", env!("CARGO_PKG_VERSION"));
    info!("Author: Soren Planck");
    info!("License: MIT");

    // Select the network before any storage, listener, RPC, metrics, mining, or
    // peer task is initialized. The value must exactly match a canonical
    // lowercase network name; a missing value fails closed.
    let network_value = std::env::var("DOM_NETWORK").ok();
    let network = parse_dom_network(network_value.as_deref())?;
    let mut config = match network {
        Network::Regtest => {
            info!("Network: REGTEST (local dev, trivial PoW)");
            NodeConfig::regtest()
        }
        Network::Mainnet => {
            info!("Network: MAINNET");
            NodeConfig::mainnet()
        }
        Network::Testnet => {
            info!("Network: TESTNET");
            NodeConfig::testnet()
        }
    };

    // Allow override of seed peers via DOM_SEED_PEERS env var (CSV of host:port).
    // Useful for private Testnet deployments where DNS seeds do not exist.
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
    // Metrics remain disabled unless explicitly enabled. The value `default`
    // selects the authoritative loopback-only service port.
    if let Ok(requested) = std::env::var("DOM_METRICS_LISTEN_ADDR") {
        let addr = if requested == "default" {
            format!("127.0.0.1:{}", dom_core::METRICS_PORT)
        } else {
            requested
        };
        info!("Enabling metrics listen address: {addr}");
        config.metrics_listen_addr = Some(addr);
    }

    // Allow enabling the RPC server via DOM_RPC_LISTEN_ADDR.
    // The RPC exposes /status, /block, /wallet/spend (bearer-auth) etc. Prefer an internal
    // binding (127.0.0.1) or a firewalled interface; /wallet/spend is sensitive.
    if let Ok(requested) = std::env::var("DOM_RPC_LISTEN_ADDR") {
        let addr = if requested == "default" {
            config.network.default_rpc_listen_addr()
        } else {
            requested
        };
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

    // Allow override of miner worker count via DOM_MINER_THREADS (resource
    // control only, never consensus data). Clamped to 1..=256; invalid values
    // keep the default.
    if let Ok(v) = std::env::var("DOM_MINER_THREADS") {
        match v.trim().parse::<usize>() {
            Ok(n) if n >= 1 => {
                let n = n.min(256);
                info!("Miner threads set via DOM_MINER_THREADS={v} -> {n}");
                config.miner_threads = n;
            }
            _ => {
                info!(
                    "Invalid DOM_MINER_THREADS={v}, keeping {}",
                    config.miner_threads
                );
            }
        }
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

#[cfg(test)]
mod tests {
    use super::{parse_startup_action, StartupAction};

    #[test]
    fn inspection_arguments_exit_before_node_startup() {
        assert_eq!(
            parse_startup_action(["dom-node".into(), "--version".into()]).unwrap(),
            StartupAction::Version
        );
        assert_eq!(
            parse_startup_action(["dom-node".into(), "--help".into()]).unwrap(),
            StartupAction::Help
        );
    }

    #[test]
    fn unknown_startup_argument_fails_closed() {
        assert!(parse_startup_action(["dom-node".into(), "--unknown".into()]).is_err());
    }
}

//! DOM node entry point.

use dom_config::{parse_dom_network, Network, NodeConfig};
use dom_consensus::derive_chain_id;
use dom_node::node::DomNode;
use dom_sidecar::{Artifact, SidecarManifest};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Notify;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupAction {
    Run,
    Probe,
    SidecarManifest(Network),
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
    match argument.as_str() {
        "--version" | "-V" if args.next().is_none() => Ok(StartupAction::Version),
        "--probe" if args.next().is_none() => Ok(StartupAction::Probe),
        "--help" | "-h" if args.next().is_none() => Ok(StartupAction::Help),
        "--sidecar-manifest" => {
            let network = args.next().ok_or_else(|| {
                anyhow::anyhow!("--sidecar-manifest requires mainnet, testnet, or regtest")
            })?;
            if args.next().is_some() {
                anyhow::bail!("--sidecar-manifest accepts exactly one network");
            }
            Ok(StartupAction::SidecarManifest(parse_dom_network(Some(
                &network,
            ))?))
        }
        _ => anyhow::bail!("unknown argument {argument:?}; use --help"),
    }
}

fn print_help() {
    println!(
        "DOM node {}\n\nUsage:\n  DOM_NETWORK=<mainnet|testnet|regtest> dom-node\n  dom-node --probe\n  dom-node --sidecar-manifest <network>\n\nThe network must be selected explicitly before the node initializes storage, listeners, mining, or peer discovery. Probe mode never opens the configured data directory, starts P2P, or mines; it exposes authenticated build metadata on an ephemeral loopback RPC listener for at most 30 seconds. --sidecar-manifest computes the executable SHA-256 and emits all compiled identity; release tooling supplies only distribution metadata, then signs the completed document.\n\nOptions:\n  -h, --help       Print help\n  -V, --version    Print version\n      --probe      Isolated sidecar capability probe\n      --sidecar-manifest <network>  Generate a signed-input release manifest",
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_startup_action(std::env::args())? {
        StartupAction::Run => {}
        StartupAction::Probe => return run_probe().await,
        StartupAction::SidecarManifest(network) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&build_sidecar_manifest(network)?)?
            );
            return Ok(());
        }
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

/// Generate the identity-bearing portion of a release manifest from this
/// binary's compiled constants. Release tooling may only add artifact URLs and
/// digests, then signs the resulting document; it must not hand-copy identity.
fn build_sidecar_manifest(network: Network) -> anyhow::Result<SidecarManifest> {
    let platform = required_release_env("DOM_SIDECAR_ARTIFACT_PLATFORM")?;
    let url = required_release_env("DOM_SIDECAR_ARTIFACT_URL")?;
    let min_wallet_version = required_release_env("DOM_MIN_WALLET_VERSION")?;
    let published_at = required_release_env("DOM_SIDECAR_PUBLISHED_AT")?;
    let executable = std::env::current_exe()?;
    let binary = std::fs::read(executable)?;
    Ok(build_sidecar_manifest_from_values(
        network,
        Artifact {
            platform,
            sha256: hex::encode(Sha256::digest(&binary)),
            url,
        },
        min_wallet_version,
        published_at,
    ))
}

fn required_release_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("{name} is required to generate a release manifest"))
}

fn build_sidecar_manifest_from_values(
    network: Network,
    artifact: Artifact,
    min_wallet_version: String,
    published_at: String,
) -> SidecarManifest {
    let genesis_hash = dom_core::configured_genesis_hash_for_network_magic(network.magic())
        .expect("Network constants are valid");
    SidecarManifest {
        schema: 1,
        version: env!("CARGO_PKG_VERSION").into(),
        revision: env!("DOM_NODE_BUILD_COMMIT").into(),
        network: network.as_str().into(),
        chain_id: hex::encode(derive_chain_id(network.magic(), &genesis_hash).as_bytes()),
        genesis_hash: hex::encode(genesis_hash.as_bytes()),
        rpc_protocol_version: dom_rpc::RPC_PROTOCOL_VERSION,
        p2p_protocol_version: dom_core::PROTOCOL_VERSION,
        storage_schema_version_supported: dom_store::STORAGE_SCHEMA_VERSION_SUPPORTED,
        min_wallet_version,
        published_at,
        artifacts: vec![artifact],
    }
}

struct ProbeNode {
    stop: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl dom_rpc::NodeHandle for ProbeNode {
    fn request_shutdown(&self) -> dom_rpc::ShutdownFuture {
        let stop = self.stop.clone();
        let notify = self.notify.clone();
        Box::pin(async move {
            stop.store(true, Ordering::SeqCst);
            notify.notify_waiters();
        })
    }
    fn chain_height(&self) -> u64 {
        0
    }
    fn mempool_size(&self) -> usize {
        0
    }
    fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }
    fn get_mempool_tx(&self, _: &[u8; 32]) -> Option<dom_rpc::MempoolTxInfo> {
        None
    }
    fn submit_tx(&self, _: Vec<u8>) -> Result<dom_rpc::TxAdmission, dom_rpc::RpcError> {
        Err(dom_rpc::RpcError::Internal(
            "probe mode does not accept transactions".into(),
        ))
    }
    fn network(&self) -> &'static str {
        "probe"
    }
    fn get_block_header(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
    fn get_block_hash_at_height(&self, _: u64) -> Option<[u8; 32]> {
        None
    }
    fn get_utxo(&self, _: &[u8; 33]) -> Option<dom_rpc::UtxoInfo> {
        None
    }
}

async fn run_probe() -> anyhow::Result<()> {
    use rand::RngCore;

    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    let listener = dom_rpc::bind("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .map_err(|e| anyhow::anyhow!("probe RPC bind: {e}"))?;
    let address = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let notify = Arc::new(Notify::new());
    let node = Arc::new(ProbeNode {
        stop: stop.clone(),
        notify: notify.clone(),
    });

    // This is consumed by the wallet process that launched the candidate.
    // It is deliberately the only stdout line before the listener starts.
    println!(
        "{}",
        serde_json::json!({"rpc_addr": address, "token": token})
    );

    dom_rpc::serve_with_token_until_shutdown(node, listener, Some(token), async move {
        if !stop.load(Ordering::SeqCst) {
            let notified = notify.notified();
            if !stop.load(Ordering::SeqCst) {
                tokio::select! {
                    _ = notified => {}
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                }
            }
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("probe RPC server: {e}"))
}

#[cfg(test)]
mod tests {
    use super::{
        build_sidecar_manifest_from_values, parse_startup_action, Artifact, Network, StartupAction,
    };

    #[test]
    fn inspection_arguments_exit_before_node_startup() {
        assert_eq!(
            parse_startup_action(["dom-node".into(), "--version".into()]).unwrap(),
            StartupAction::Version
        );
        assert_eq!(
            parse_startup_action(["dom-node".into(), "--probe".into()]).unwrap(),
            StartupAction::Probe
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

    #[test]
    fn sidecar_manifest_identity_is_derived_from_compiled_constants() {
        let manifest = build_sidecar_manifest_from_values(
            Network::Testnet,
            Artifact {
                platform: "linux-x86_64".into(),
                sha256: "hash".into(),
                url: "https://example.test/node".into(),
            },
            "0.3.1".into(),
            "2026-07-23T00:00:00Z".into(),
        );
        assert_eq!(manifest.p2p_protocol_version, dom_core::PROTOCOL_VERSION);
        assert_eq!(manifest.p2p_protocol_version, 2);
        assert_eq!(manifest.rpc_protocol_version, dom_rpc::RPC_PROTOCOL_VERSION);
        assert_eq!(
            manifest.storage_schema_version_supported,
            dom_store::STORAGE_SCHEMA_VERSION_SUPPORTED
        );
        assert!(!manifest.revision.is_empty());
        assert!(!manifest.chain_id.is_empty());
        assert!(!manifest.genesis_hash.is_empty());
        assert_eq!(manifest.artifacts.len(), 1);
    }
}

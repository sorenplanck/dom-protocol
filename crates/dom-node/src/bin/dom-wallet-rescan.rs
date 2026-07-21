//! Maintenance tool: rescan the mining wallet against this node's canonical
//! chain, draining phantom outputs (e.g. provisional coinbases credited by
//! aborted mining attempts before the abort-cleanup fix).
//!
//! MUST run with `dom-node.service` STOPPED: it opens the node's chain store
//! and takes the wallet directory's exclusive lock. The embedded node is
//! initialized WITHOUT a wallet and never `run()` — no listeners, no mining —
//! so `rescan_wallet_dir`'s "different wallet dir than the node opened"
//! contract holds (the node opened none).
//!
//! Usage (reads the same env as the service, e.g. `.dom/miner.env`):
//!   DOM_NETWORK=mainnet DOM_DATA_DIR=… DOM_WALLET_PATH=… DOM_WALLET_PASSWORD=… \
//!     dom-wallet-rescan            # dry-run: CompareOnly, nothing persisted
//!   DOM_RESCAN_APPLY=1 …           # Repair: persist the deterministic rebuild
//!
//! Prints balance before/after in noms and DOM so operators can diff.

use dom_config::{parse_dom_network, Network, NodeConfig};
use dom_node::node::DomNode;
use dom_wallet::{WalletDir, WalletRescanMode};
use std::path::Path;
use std::sync::Arc;

fn dom(noms: u64) -> f64 {
    noms as f64 / 1e8
}

fn print_balance(label: &str, wallet_dir: &WalletDir, tip: u64) {
    let b = wallet_dir.wallet().balance(tip);
    println!(
        "{label} @tip={tip}: confirmed={} ({:.3} DOM) immature={} ({:.3} DOM) reserved={} total={} ({:.3} DOM)",
        b.confirmed,
        dom(b.confirmed),
        b.immature,
        dom(b.immature),
        b.reserved,
        b.confirmed + b.immature + b.reserved,
        dom(b.confirmed + b.immature + b.reserved),
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("DOM_LOG").unwrap_or_else(|_| "warn".into()))
        .init();

    let network = parse_dom_network(std::env::var("DOM_NETWORK").ok().as_deref())?;
    let mut config = match network {
        Network::Regtest => NodeConfig::regtest(),
        Network::Testnet => NodeConfig::testnet(),
        Network::Mainnet => NodeConfig::mainnet(),
    };
    if let Ok(data_dir) = std::env::var("DOM_DATA_DIR") {
        config.data_dir = data_dir;
    }
    let wallet_path = std::env::var("DOM_WALLET_PATH")
        .map_err(|_| anyhow::anyhow!("DOM_WALLET_PATH is required"))?;
    let wallet_password = std::env::var("DOM_WALLET_PASSWORD")
        .map_err(|_| anyhow::anyhow!("DOM_WALLET_PASSWORD is required"))?;
    let apply = std::env::var("DOM_RESCAN_APPLY").map(|v| v == "1").unwrap_or(false);

    // No wallet, no mining, no listeners: chain store read + wallet repair only.
    config.wallet_path = None;
    config.wallet_password = None;
    config.mine = false;

    let node = Arc::new(DomNode::init(config)?);
    let tip = node.chain.lock().await.tip_height.0;
    println!("chain store aberto: tip={tip} network={network:?} apply={apply}");

    let mut wallet_dir = WalletDir::open(Path::new(&wallet_path), &wallet_password)
        .map_err(|e| anyhow::anyhow!("open wallet: {e}"))?;
    print_balance("ANTES ", &wallet_dir, tip);

    if apply {
        let summary = node.rescan_wallet_dir(&mut wallet_dir).await?;
        println!("summary: {summary:?}");
        print_balance("DEPOIS", &wallet_dir, tip);
    } else {
        // Dry-run through the same scan the Repair path uses.
        let scan = {
            let chain = node.chain.lock().await;
            dom_node::wallet_scan::collect_chain_scan(&chain.store, tip)?
        };
        let summary = wallet_dir
            .wallet_mut()
            .rescan_canonical_chain(&scan, WalletRescanMode::CompareOnly)
            .map_err(|e| anyhow::anyhow!("compare-only rescan: {e}"))?;
        println!("summary (CompareOnly, nada persistido): {summary:?}");
        print_balance("DEPOIS (inalterado)", &wallet_dir, tip);
    }
    Ok(())
}

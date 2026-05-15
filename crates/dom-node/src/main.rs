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

    // Load config — default to testnet for now
    let config = NodeConfig::testnet();

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

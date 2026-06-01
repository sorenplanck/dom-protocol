use dom_faucet::{FaucetServer, NodeBackend};
use std::{env, error::Error, sync::Arc};
use tracing::info;
use url::Url;

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let listen_addr =
        env::var("DOM_FAUCET_LISTEN_ADDR").unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
    let node_url = required_env("DOM_FAUCET_NODE_URL")?;
    let bearer_token = required_env("DOM_FAUCET_BEARER_TOKEN")?;
    let amount_noms = parse_required_u64("DOM_FAUCET_AMOUNT_NOMS")?;
    let fee_noms = parse_required_u64("DOM_FAUCET_FEE_NOMS")?;

    let backend = Arc::new(NodeBackend::new(
        Url::parse(&node_url).map_err(|e| format!("invalid DOM_FAUCET_NODE_URL: {e}"))?,
        bearer_token,
    )?);

    info!(
        listen_addr,
        node_url, amount_noms, fee_noms, "starting DOM testnet faucet"
    );

    FaucetServer::new(listen_addr, backend, amount_noms, fee_noms)
        .start()
        .await
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
}

fn parse_required_u64(name: &str) -> Result<u64, String> {
    required_env(name)?
        .parse::<u64>()
        .map_err(|e| format!("{name} must be an unsigned integer: {e}"))
}

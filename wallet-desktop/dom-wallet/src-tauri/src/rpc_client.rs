//! Local RPC + metrics client.
//!
//! The embedded node exposes a blocking HTTP RPC (`dom_wallet::NodeRpcClient`)
//! on loopback with a Bearer token, plus a Prometheus `/metrics` endpoint. V1
//! uses only the read-only subset: `/status`, `/health`, plus the metrics gauges
//! for peers / hashrate / mining state (which `/status` does not carry).
//!
//! Transport note (audit D-05): the RPC is plain HTTP over `127.0.0.1` with a
//! per-launch 32-byte CSPRNG bearer token (held in `Zeroizing`, never persisted,
//! never logged). The bind is hard-restricted to loopback in `settings`
//! validation, so the token is not exposed to the network. The residual — that
//! on a shared host a root/admin user could observe loopback traffic — is
//! inherent to a local embedded node and accepted for the wallet's scope;
//! mitigating it would require an OS-local transport (e.g. a unix-domain socket)
//! that the embedded `dom-node` does not currently offer. Documented here so the
//! tradeoff is explicit rather than assumed.
//!
//! Both the RPC client and the metrics fetch are blocking (`reqwest::blocking`),
//! so every call here is wrapped in `tokio::task::spawn_blocking` to avoid
//! stalling the async runtime. The wallet only ever READS from the node
//! (Principle 2 — observe, never command).

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use dom_wallet::{NodeRpc, NodeRpcClient};
use serde::Serialize;
use url::Url;

use crate::node_host::NodeEndpoints;

/// Combined node status for the UI (merges `/status` with metrics gauges).
#[derive(Clone, Debug, Default, Serialize)]
pub struct NodeStatusView {
    pub version: u32,
    pub chain_height: u64,
    pub mempool_size: u64,
    pub network: String,
    pub peer_count: u64,
    pub mining_active: bool,
    pub hashrate: f64,
    pub blocks_mined: u64,
}

/// Build a blocking RPC client for the given endpoints.
fn build_client(ep: &NodeEndpoints) -> Result<NodeRpcClient> {
    let url = Url::parse(&ep.rpc_base_url).map_err(|e| anyhow!("bad RPC url: {e}"))?;
    NodeRpcClient::builder(url)
        .bearer_token(ep.rpc_token.to_string())
        .user_agent("dom-wallet/0.1")
        .build()
        .map_err(|e| anyhow!("rpc client build: {e}"))
}

/// `GET /health` — Ok(()) if the node answers.
pub async fn health(ep: &NodeEndpoints) -> Result<()> {
    let ep = ep.clone();
    tokio::task::spawn_blocking(move || {
        let client = build_client(&ep)?;
        client.health().map_err(|e| anyhow!("health: {e}"))
    })
    .await
    .map_err(|e| anyhow!("join: {e}"))?
}

/// V2: broadcast a finalized transaction to the node's mempool
/// (`POST /tx/submit`). Returns the chain txid hex on success.
pub async fn submit_tx(
    ep: &NodeEndpoints,
    tx: dom_consensus::transaction::Transaction,
) -> Result<String> {
    use dom_wallet::NodeRpc;
    let ep = ep.clone();
    tokio::task::spawn_blocking(move || {
        let client = build_client(&ep)?;
        let outcome = client.submit_tx(&tx).map_err(|e| anyhow!("submit tx: {e}"))?;
        Ok(hex::encode(outcome.tx_hash))
    })
    .await
    .map_err(|e| anyhow!("join: {e}"))?
}

/// Fetch combined status: `/status` (chain height, mempool, network, version)
/// merged with Prometheus gauges (peers, hashrate, mining, blocks mined).
pub async fn status_view(ep: &NodeEndpoints) -> Result<NodeStatusView> {
    let ep = ep.clone();
    tokio::task::spawn_blocking(move || {
        let client = build_client(&ep)?;
        let status = client.status().map_err(|e| anyhow!("status: {e}"))?;

        let mut view = NodeStatusView {
            version: status.version,
            chain_height: status.chain_height,
            mempool_size: status.mempool_size,
            network: status.network,
            ..Default::default()
        };

        // Metrics are best-effort: if scraping fails, return the /status part
        // and leave gauges at zero rather than erroring the whole call.
        match scrape_metrics(&ep.metrics_url) {
            Ok(m) => {
                view.peer_count = m.get("dom_peer_count").copied().unwrap_or(0.0) as u64;
                view.hashrate = m.get("dom_hashrate").copied().unwrap_or(0.0);
                view.mining_active = m.get("dom_mining_active").copied().unwrap_or(0.0) > 0.5;
                view.blocks_mined = m.get("dom_blocks_mined").copied().unwrap_or(0.0) as u64;
                // Prefer the metrics mempool gauge if present, else /status value.
                if let Some(mp) = m.get("dom_mempool_size") {
                    view.mempool_size = *mp as u64;
                }
                if let Some(h) = m.get("dom_chain_height") {
                    // /status is authoritative; only use the gauge if /status was 0.
                    if view.chain_height == 0 {
                        view.chain_height = *h as u64;
                    }
                }
            }
            Err(e) => tracing::debug!("metrics scrape failed (non-fatal): {e}"),
        }
        Ok(view)
    })
    .await
    .map_err(|e| anyhow!("join: {e}"))?
}

/// Minimal Prometheus text-exposition parser: returns `metric_name -> value`
/// for simple gauges (ignores labels by taking the first sample per name).
fn scrape_metrics(metrics_url: &str) -> Result<HashMap<String, f64>> {
    let body = reqwest::blocking::Client::new()
        .get(metrics_url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .map_err(|e| anyhow!("metrics request: {e}"))?
        .text()
        .map_err(|e| anyhow!("metrics body: {e}"))?;
    Ok(parse_prometheus(&body))
}

/// Parse Prometheus text format into name→value, skipping comments and keeping
/// the first value seen for each base metric name (labels stripped).
fn parse_prometheus(body: &str) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `name{labels} value` or `name value`
        let (name_part, value_part) = match line.rsplit_once(char::is_whitespace) {
            Some(parts) => parts,
            None => continue,
        };
        let name = name_part.split('{').next().unwrap_or(name_part).trim();
        if let Ok(v) = value_part.trim().parse::<f64>() {
            out.entry(name.to_string()).or_insert(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_gauges() {
        let body = "\
# HELP dom_chain_height Current chain height
# TYPE dom_chain_height gauge
dom_chain_height 18234
dom_peer_count 8
dom_mining_active 1
dom_hashrate 612.5
dom_blocks_mined 47
";
        let m = parse_prometheus(body);
        assert_eq!(m["dom_chain_height"], 18234.0);
        assert_eq!(m["dom_peer_count"], 8.0);
        assert_eq!(m["dom_mining_active"], 1.0);
        assert_eq!(m["dom_hashrate"], 612.5);
        assert_eq!(m["dom_blocks_mined"], 47.0);
    }

    #[test]
    fn ignores_labels_and_comments() {
        let body = "\
# a comment
dom_peer_count{state=\"outbound\"} 3
dom_peer_count{state=\"inbound\"} 5
";
        let m = parse_prometheus(body);
        // First sample wins.
        assert_eq!(m["dom_peer_count"], 3.0);
    }
}

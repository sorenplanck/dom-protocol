//! Reads the node's Prometheus metrics endpoint for live UI stats.
//!
//! The node exposes (per the protocol spec) at `DOM_METRICS_LISTEN_ADDR`:
//!   dom_chain_height, dom_peer_count, dom_blocks_mined,
//!   dom_mining_active, dom_mempool_size
//!
//! We scrape the plaintext exposition format with a tiny parser — no extra
//! Prometheus client dependency needed for a handful of gauges.

use anyhow::Result;

#[derive(Clone, Copy, Default, serde::Serialize)]
pub struct NodeMetrics {
    pub chain_height: u64,
    pub peer_count: u64,
    pub blocks_mined: u64,
    pub mining_active: bool,
    pub mempool_size: u64,
}

/// Fetch + parse the metrics text. `base` is e.g. "127.0.0.1:33371".
pub fn fetch_metrics(base: &str) -> Result<NodeMetrics> {
    let url = format!("http://{base}/metrics");
    // Blocking minreq-free fetch via std + ureq-like manual TCP would be
    // heavier; reuse reqwest's blocking client which is already in the tree
    // through dom-wallet's rpc_client.
    let body = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?
        .get(url)
        .send()?
        .text()?;
    Ok(parse_metrics(&body))
}

fn parse_metrics(text: &str) -> NodeMetrics {
    let mut m = NodeMetrics::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: `name value` or `name{labels} value`.
        let (name, value) = match line.rsplit_once(char::is_whitespace) {
            Some((n, v)) => (n.split('{').next().unwrap_or(n).trim(), v.trim()),
            None => continue,
        };
        let v: f64 = match value.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        match name {
            "dom_chain_height" => m.chain_height = v as u64,
            "dom_peer_count" => m.peer_count = v as u64,
            "dom_blocks_mined" => m.blocks_mined = v as u64,
            "dom_mining_active" => m.mining_active = v != 0.0,
            "dom_mempool_size" => m.mempool_size = v as u64,
            _ => {}
        }
    }
    m
}

/// Balance of the node's (miner) wallet, read from `GET /wallet/balance`.
/// Fields default to 0 if absent. Used by the auto-sweep to know how much
/// matured (confirmed) balance can be moved to the user's wallet.
#[derive(Clone, Copy, Default, serde::Deserialize)]
pub struct NodeWalletBalance {
    #[serde(default)]
    pub confirmed_noms: u64,
    #[serde(default)]
    pub immature_noms: u64,
    #[serde(default)]
    pub reserved_noms: u64,
}

/// Fetch the node (miner) wallet balance. `rpc_base` is e.g. "127.0.0.1:33372",
/// `token` is the RPC bearer token. The endpoint is bearer-protected.
pub fn fetch_node_wallet_balance(rpc_base: &str, token: &str) -> Result<NodeWalletBalance> {
    let url = format!("http://{rpc_base}/wallet/balance");
    let resp = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?
        .get(url)
        .bearer_auth(token)
        .send()?;
    if !resp.status().is_success() {
        anyhow::bail!("node wallet balance unavailable (status {})", resp.status());
    }
    Ok(resp.json::<NodeWalletBalance>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_exposition() {
        let txt = "# HELP dom_chain_height ...\n\
                   dom_chain_height 156\n\
                   dom_peer_count 4\n\
                   dom_mining_active 1\n\
                   dom_mempool_size 2\n\
                   dom_blocks_mined 156\n";
        let m = parse_metrics(txt);
        assert_eq!(m.chain_height, 156);
        assert_eq!(m.peer_count, 4);
        assert!(m.mining_active);
        assert_eq!(m.mempool_size, 2);
        assert_eq!(m.blocks_mined, 156);
    }
}

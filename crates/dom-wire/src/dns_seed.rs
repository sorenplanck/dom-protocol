//! DNS seed peer discovery.

/// Hardcoded DNS seeds — must be controlled by independent operators.
const MAINNET_DNS_SEEDS: &[&str] = &[
    "seed1.dom-protocol.org",
    "seed2.dom-protocol.org",
    "seed3.dom-protocol.org",
    "seed4.dom-protocol.org",
    "seed5.dom-protocol.org",
];

const TESTNET_DNS_SEEDS: &[&str] = &[
    "testnet-seed1.dom-protocol.org",
    "testnet-seed2.dom-protocol.org",
];

/// Hardcoded fallback IPs (in case DNS is unavailable).
/// These are long-running foundation nodes.
const MAINNET_SEED_IPS: &[&str] = &[
    // To be filled after genesis
];

/// Resolve DNS seeds to IP:port pairs.
///
/// Uses the system resolver. On failure, falls back to hardcoded IPs.
pub async fn resolve_seeds(mainnet: bool, port: u16, custom_seeds: &[String]) -> Vec<String> {
    use tokio::net::lookup_host;

    let seeds: Vec<&str> = if !custom_seeds.is_empty() {
        custom_seeds.iter().map(|s| s.as_str()).collect()
    } else if mainnet {
        MAINNET_DNS_SEEDS.to_vec()
    } else {
        TESTNET_DNS_SEEDS.to_vec()
    };

    let mut addrs = Vec::new();

    for seed in &seeds {
        let host = format!("{seed}:{port}");
        match lookup_host(host).await {
            Ok(resolved) => {
                for addr in resolved {
                    addrs.push(addr.to_string());
                }
            }
            Err(e) => {
                tracing::warn!("DNS seed {seed} resolution failed: {e}");
            }
        }
    }

    // Fallback to hardcoded IPs if DNS resolution produced nothing
    if addrs.is_empty() && mainnet {
        for ip in MAINNET_SEED_IPS {
            addrs.push(ip.to_string());
        }
    }

    addrs
}

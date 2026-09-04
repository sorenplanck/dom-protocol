//! DNS seed peer discovery.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Hardcoded DNS seeds — must be controlled by independent operators.
const MAINNET_DNS_SEEDS: &[&str] = &[
    "seed1.dom-protocol.org",
    "seed2.dom-protocol.org",
    "seed3.dom-protocol.org",
];

const TESTNET_DNS_SEEDS: &[&str] = &[
    "testnet-seed1.dom-protocol.org",
    "testnet-seed2.dom-protocol.org",
];

/// Hardcoded fallback IPs (in case DNS is unavailable).
/// These are long-running foundation nodes.
///
/// DNS is otherwise a single point of failure for onboarding: an expired
/// domain, an outage at the DNS provider, or a resolver that is blocked or
/// hijacked — routine on corporate and some residential networks — leaves a
/// FRESH install with no way into the network at all. Nodes that are already
/// running survive on their PEX pool; new ones do not. A literal address also
/// removes DNS resolution latency from the boot path.
///
/// This list is NOT a replacement for DNS. It is only consulted when DNS
/// returned nothing (see the fallback at the end of `resolve_seeds`), because
/// baked-in addresses are a censorship point and they go stale: a rebuilt VPS
/// changes IP and the literal becomes dead weight inside everyone's binary.
/// Treat it as part of the release checklist — review it every version.
///
/// IPv6 literals (`[2001:db8::1]:33369`) belong here too, but only once the
/// hubs actually have global IPv6; today they do not.
const MAINNET_SEED_IPS: &[&str] = &["66.42.127.141:33369", "64.177.121.62:33369"];

const DNS_SUCCESS_TTL: Duration = Duration::from_secs(10 * 60);
const DNS_TEMPORARY_BACKOFF_INITIAL: Duration = Duration::from_secs(30);
const DNS_TEMPORARY_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);
const DNS_NOT_FOUND_BACKOFF: Duration = Duration::from_secs(6 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsFailureClass {
    NotFound,
    Temporary,
}

#[derive(Debug, Clone)]
enum DnsCacheEntry {
    Resolved {
        addrs: Vec<String>,
        expires_at: Instant,
    },
    Failed {
        class: DnsFailureClass,
        failures: u8,
        retry_at: Instant,
    },
}

fn dns_cache() -> &'static Mutex<HashMap<String, DnsCacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, DnsCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn classify_dns_error(error: &std::io::Error) -> DnsFailureClass {
    // `lookup_host` maps EAI_NONAME to `Uncategorized` on some libc targets,
    // so ErrorKind alone cannot distinguish NXDOMAIN/no-record from a
    // temporary resolver outage.
    let message = error.to_string().to_ascii_lowercase();
    if error.kind() == std::io::ErrorKind::NotFound
        || message.contains("name or service not known")
        || message.contains("nodename nor servname")
        || message.contains("no address associated")
        || message.contains("nxdomain")
    {
        DnsFailureClass::NotFound
    } else {
        DnsFailureClass::Temporary
    }
}

fn retry_delay(class: DnsFailureClass, failures: u8) -> Duration {
    match class {
        DnsFailureClass::NotFound => DNS_NOT_FOUND_BACKOFF,
        DnsFailureClass::Temporary => {
            let exponent = failures.saturating_sub(1).min(15) as u32;
            DNS_TEMPORARY_BACKOFF_INITIAL
                .saturating_mul(1u32.checked_shl(exponent).unwrap_or(u32::MAX))
                .min(DNS_TEMPORARY_BACKOFF_MAX)
        }
    }
}

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
        let now = Instant::now();
        let cached = {
            let cache = dns_cache().lock().unwrap_or_else(|e| e.into_inner());
            cache.get(&host).cloned()
        };
        match cached {
            Some(DnsCacheEntry::Resolved {
                addrs: cached_addrs,
                expires_at,
            }) if expires_at > now => {
                addrs.extend(cached_addrs);
                continue;
            }
            Some(DnsCacheEntry::Failed {
                class,
                failures,
                retry_at,
            }) if retry_at > now => {
                tracing::debug!(
                    event = "dns_seed_backoff",
                    dns_seed = %seed,
                    failure_class = ?class,
                    failures,
                    retry_in_secs = retry_at.saturating_duration_since(now).as_secs(),
                    "DNS seed resolution suppressed by backoff"
                );
                continue;
            }
            _ => {}
        }

        let previous_failures = match cached {
            Some(DnsCacheEntry::Failed { failures, .. }) => failures,
            _ => 0,
        };
        match lookup_host(&host).await {
            Ok(resolved) => {
                let mut resolved_addrs: Vec<String> =
                    resolved.map(|addr| addr.to_string()).collect();
                resolved_addrs.sort();
                resolved_addrs.dedup();
                let mut cache = dns_cache().lock().unwrap_or_else(|e| e.into_inner());
                cache.insert(
                    host.clone(),
                    DnsCacheEntry::Resolved {
                        addrs: resolved_addrs.clone(),
                        expires_at: now + DNS_SUCCESS_TTL,
                    },
                );
                addrs.extend(resolved_addrs);
            }
            Err(e) => {
                let class = classify_dns_error(&e);
                let failures = previous_failures.saturating_add(1);
                let delay = retry_delay(class, failures);
                let mut cache = dns_cache().lock().unwrap_or_else(|e| e.into_inner());
                cache.insert(
                    host.clone(),
                    DnsCacheEntry::Failed {
                        class,
                        failures,
                        retry_at: now + delay,
                    },
                );
                drop(cache);
                match class {
                    DnsFailureClass::NotFound => tracing::warn!(
                        event = "dns_seed_resolution_failed",
                        dns_seed = %seed,
                        failure_class = "not_found",
                        failures,
                        retry_in_secs = delay.as_secs(),
                        error = %e,
                        "DNS seed does not currently exist"
                    ),
                    DnsFailureClass::Temporary => tracing::warn!(
                        event = "dns_seed_resolution_failed",
                        dns_seed = %seed,
                        failure_class = "temporary",
                        failures,
                        retry_in_secs = delay.as_secs(),
                        error = %e,
                        "temporary DNS seed resolution failure"
                    ),
                }
            }
        };
    }

    // Fallback to hardcoded IPs if DNS resolution produced nothing
    if addrs.is_empty() && mainnet {
        for ip in MAINNET_SEED_IPS {
            addrs.push(ip.to_string());
        }
    }

    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_fallback_uses_the_three_canonical_dns_seeds() {
        assert_eq!(
            MAINNET_DNS_SEEDS,
            [
                "seed1.dom-protocol.org",
                "seed2.dom-protocol.org",
                "seed3.dom-protocol.org",
            ]
        );
    }

    /// A9: the fallback exists so that a fresh install can still enter the
    /// network when DNS returns nothing. An empty list makes the whole fallback
    /// branch inert, which is what shipped before.
    #[test]
    fn mainnet_seed_ip_fallback_is_populated() {
        assert!(
            !MAINNET_SEED_IPS.is_empty(),
            "the DNS-unavailable fallback must not be empty, or DNS is a single \
             point of failure for onboarding"
        );
    }

    /// Each fallback entry is dialed directly, so it must already carry a port
    /// and parse as a socket address — a bare IP would be dialed as-is and fail.
    #[test]
    fn mainnet_seed_ips_are_dialable_socket_addrs() {
        use std::net::SocketAddr;
        for entry in MAINNET_SEED_IPS {
            let addr: SocketAddr = entry
                .parse()
                .unwrap_or_else(|e| panic!("fallback seed {entry} is not a socket address: {e}"));
            assert_ne!(addr.port(), 0, "fallback seed {entry} has no port");
        }
    }

    /// The fallback must span more than one host, for the same reason the
    /// wallet's factory bootstrap must: one address is one point of failure.
    #[test]
    fn mainnet_seed_ips_span_multiple_hosts() {
        use std::collections::BTreeSet;
        use std::net::SocketAddr;
        let hosts: BTreeSet<_> = MAINNET_SEED_IPS
            .iter()
            .map(|e| e.parse::<SocketAddr>().expect("socket addr").ip())
            .collect();
        assert!(
            hosts.len() >= 2,
            "fallback must cover >=2 distinct hosts, got {hosts:?}"
        );
    }

    #[test]
    fn temporary_dns_backoff_is_exponential_and_capped() {
        assert_eq!(
            retry_delay(DnsFailureClass::Temporary, 1),
            Duration::from_secs(30)
        );
        assert_eq!(
            retry_delay(DnsFailureClass::Temporary, 2),
            Duration::from_secs(60)
        );
        assert_eq!(
            retry_delay(DnsFailureClass::Temporary, 20),
            DNS_TEMPORARY_BACKOFF_MAX
        );
    }

    #[test]
    fn nonexistent_seed_uses_long_backoff_class() {
        let error = std::io::Error::new(std::io::ErrorKind::NotFound, "NXDOMAIN");
        assert_eq!(classify_dns_error(&error), DnsFailureClass::NotFound);
        assert_eq!(
            retry_delay(DnsFailureClass::NotFound, 1),
            DNS_NOT_FOUND_BACKOFF
        );
        let libc_style = std::io::Error::other("Name or service not known");
        assert_eq!(classify_dns_error(&libc_style), DnsFailureClass::NotFound);
    }
}

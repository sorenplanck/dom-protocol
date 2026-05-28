//! Safe test environment configuration.
//!
//! This module enforces the **strict** rule that fast mining can ONLY be
//! enabled when the network is regtest/devtest (or under `cfg(test)`).
//!
//! The runner sets these env vars before invoking cargo. The DOM node/miner
//! code is expected to honor the same rule on its side — this runner alone
//! cannot bypass mainnet/testnet PoW; it only signals intent.

use std::collections::BTreeMap;

/// Networks where fast mining is allowed.
pub const SAFE_NETWORKS: &[&str] = &["regtest", "devtest", "test"];

/// Result of validating a requested fast-mining configuration.
#[derive(Debug, PartialEq, Eq)]
pub enum FastMiningCheck {
    /// Allowed: network is one of regtest/devtest/test.
    Allowed { network: String },
    /// Forbidden: caller asked for fast mining on mainnet/testnet.
    /// Fails closed.
    Forbidden { network: String, reason: String },
}

/// Validate whether fast mining may be enabled for the requested `network`.
///
/// Rules:
/// - regtest / devtest / test → ALLOWED.
/// - anything else (e.g. mainnet, testnet, prod) → FORBIDDEN.
///
/// This function never panics and never has side effects.
pub fn check_fast_mining(network: &str) -> FastMiningCheck {
    let net = network.trim().to_ascii_lowercase();
    if SAFE_NETWORKS.iter().any(|s| *s == net) {
        FastMiningCheck::Allowed { network: net }
    } else {
        FastMiningCheck::Forbidden {
            network: net.clone(),
            reason: format!(
                "DOM_REGTEST_FAST_MINING is only honored on regtest/devtest/test, \
                 refusing to enable on '{net}'. \
                 This guard protects mainnet/testnet PoW from accidental weakening."
            ),
        }
    }
}

/// Build the environment variable set that `dom-test-runner` injects
/// into every cargo invocation it spawns.
///
/// Always uses `regtest` as the network — fast mining can only ever be
/// requested here. Mainnet/testnet builds are unaffected.
pub fn safe_test_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("DOM_NETWORK".to_string(), "regtest".to_string());
    env.insert("DOM_REGTEST_FAST_MINING".to_string(), "1".to_string());
    env.insert("RUST_BACKTRACE".to_string(), "1".to_string());
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_mining_allowed_on_regtest() {
        assert!(matches!(
            check_fast_mining("regtest"),
            FastMiningCheck::Allowed { .. }
        ));
    }

    #[test]
    fn fast_mining_allowed_on_devtest() {
        assert!(matches!(
            check_fast_mining("devtest"),
            FastMiningCheck::Allowed { .. }
        ));
    }

    #[test]
    fn fast_mining_allowed_on_test_cfg() {
        assert!(matches!(
            check_fast_mining("test"),
            FastMiningCheck::Allowed { .. }
        ));
    }

    #[test]
    fn fast_mining_forbidden_on_mainnet() {
        match check_fast_mining("mainnet") {
            FastMiningCheck::Forbidden { network, reason } => {
                assert_eq!(network, "mainnet");
                assert!(reason.contains("regtest/devtest/test"));
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn fast_mining_forbidden_on_testnet() {
        // Public testnet must NOT receive fast mining — only the local
        // `regtest`/`devtest` networks may.
        match check_fast_mining("testnet") {
            FastMiningCheck::Forbidden { network, .. } => {
                assert_eq!(network, "testnet");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn fast_mining_case_insensitive_and_trims() {
        assert!(matches!(
            check_fast_mining("  REGTEST  "),
            FastMiningCheck::Allowed { .. }
        ));
        assert!(matches!(
            check_fast_mining("MAINNET"),
            FastMiningCheck::Forbidden { .. }
        ));
    }

    #[test]
    fn safe_env_uses_regtest_only() {
        let env = safe_test_env();
        assert_eq!(env.get("DOM_NETWORK").map(String::as_str), Some("regtest"));
        assert_eq!(
            env.get("DOM_REGTEST_FAST_MINING").map(String::as_str),
            Some("1")
        );
        // Sanity: this runner never asks for mainnet or testnet.
        for v in env.values() {
            assert!(v != "mainnet");
            assert!(v != "testnet");
        }
    }
}

//! Changed-file → profile selection.
//!
//! Implements the rules documented under `affected` and `explain affected`.
//! All path matching is pure-function and unit-tested — the runner only
//! supplies the list of changed paths.

use std::collections::BTreeMap;

/// A reason why a profile was selected, paired with the offending path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Selection {
    pub profile: &'static str,
    pub reason: String,
}

/// Compute which profiles to run given a list of changed files
/// (paths relative to repo root, forward-slashes).
///
/// Returns a sorted, de-duplicated list of `Selection`s.
pub fn select_profiles(changed: &[String]) -> Vec<Selection> {
    let mut out: BTreeMap<&'static str, Selection> = BTreeMap::new();

    if changed.is_empty() {
        return Vec::new();
    }

    // Quick check: if only docs/** changed, fast-check is enough.
    let only_docs = changed.iter().all(|p| p.starts_with("docs/"));
    if only_docs {
        out.insert(
            "fast-check",
            Selection {
                profile: "fast-check",
                reason: "only docs/** changed".to_string(),
            },
        );
        return out.into_values().collect();
    }

    for path in changed {
        for sel in selections_for_path(path) {
            out.entry(sel.profile).or_insert(sel);
        }
    }

    out.into_values().collect()
}

/// All selections triggered by a single changed file.
fn selections_for_path(path: &str) -> Vec<Selection> {
    let mut sels = Vec::new();

    if path.starts_with("crates/dom-mempool/") {
        sels.push(Selection {
            profile: "mempool",
            reason: format!("dom-mempool changed ({path})"),
        });
        sels.push(Selection {
            profile: "integration-mempool",
            reason: "mempool integrates with node relay/reorg cleanup".to_string(),
        });
    }

    if path.starts_with("crates/dom-node/") {
        sels.push(Selection {
            profile: "node",
            reason: format!("dom-node changed ({path})"),
        });
        sels.push(Selection {
            profile: "integration",
            reason: "node touches all integration paths".to_string(),
        });
    }

    if path.starts_with("crates/dom-wire/") {
        sels.push(Selection {
            profile: "wire",
            reason: format!("dom-wire changed ({path})"),
        });
        sels.push(Selection {
            profile: "integration-network",
            reason: "wire-level changes can affect multi-node networking".to_string(),
        });
    }

    if path.starts_with("crates/dom-pow/") {
        sels.push(Selection {
            profile: "pow",
            reason: format!("dom-pow changed ({path})"),
        });
        sels.push(Selection {
            profile: "two-node",
            reason: "PoW changes can desync nodes in two-node tests".to_string(),
        });
        sels.push(Selection {
            profile: "reorg",
            reason: "PoW changes affect reorg behavior".to_string(),
        });
    }

    if path.starts_with("crates/dom-chain/") {
        sels.push(Selection {
            profile: "chain",
            reason: format!("dom-chain changed ({path})"),
        });
        sels.push(Selection {
            profile: "ibd",
            reason: "chain changes affect IBD".to_string(),
        });
        sels.push(Selection {
            profile: "reorg",
            reason: "chain changes affect reorg correctness".to_string(),
        });
    }

    if path.starts_with("crates/dom-store/") {
        sels.push(Selection {
            profile: "store",
            reason: format!("dom-store changed ({path})"),
        });
        sels.push(Selection {
            profile: "chain",
            reason: "store changes can affect chain restart/reopen".to_string(),
        });
    }

    if path.starts_with("crates/dom-wallet/") {
        sels.push(Selection {
            profile: "wallet",
            reason: format!("dom-wallet changed ({path})"),
        });
    }

    if path.starts_with("crates/dom-wallet-app/") {
        sels.push(Selection {
            profile: "wallet-app",
            reason: format!("dom-wallet-app changed ({path})"),
        });
        // Note: we deliberately do NOT pull in heavy network tests for
        // wallet-app-only changes; those only fire if node/chain/mempool
        // also changed in the same diff.
    }

    if path.starts_with("crates/dom-integration-tests/") {
        sels.push(Selection {
            profile: "integration",
            reason: format!("dom-integration-tests changed ({path})"),
        });
    }

    if path.starts_with("crates/dom-test-runner/") {
        sels.push(Selection {
            profile: "fast-check",
            reason: format!("dom-test-runner changed ({path})"),
        });
        // Real `cargo test -p dom-test-runner` is added at the runner
        // layer because it's the binary running.
    }

    if path.starts_with("crates/dom-agent-runner/") {
        sels.push(Selection {
            profile: "fast-check",
            reason: format!("dom-agent-runner changed ({path})"),
        });
    }

    if path.starts_with(".github/workflows/") {
        sels.push(Selection {
            profile: "fast-check",
            reason: format!("CI workflow changed ({path})"),
        });
    }

    sels
}

/// Profiles to always run for `pre-push` once `select_profiles` has
/// produced its set. `pre-push` is `affected` plus a baseline.
pub fn pre_push_baseline() -> Vec<Selection> {
    vec![Selection {
        profile: "fast-check",
        reason: "pre-push baseline".to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(sels: &[Selection]) -> Vec<&'static str> {
        sels.iter().map(|s| s.profile).collect()
    }

    #[test]
    fn empty_diff_selects_nothing() {
        assert!(select_profiles(&[]).is_empty());
    }

    #[test]
    fn docs_only_runs_fast_check() {
        let sels = select_profiles(&["docs/README.md".to_string()]);
        assert_eq!(names(&sels), vec!["fast-check"]);
    }

    #[test]
    fn mempool_change_selects_mempool_and_integration_mempool() {
        let sels = select_profiles(&["crates/dom-mempool/src/lib.rs".to_string()]);
        let n = names(&sels);
        assert!(n.contains(&"mempool"));
        assert!(n.contains(&"integration-mempool"));
    }

    #[test]
    fn pow_change_selects_pow_two_node_reorg() {
        let sels = select_profiles(&["crates/dom-pow/src/randomx.rs".to_string()]);
        let n = names(&sels);
        assert!(n.contains(&"pow"));
        assert!(n.contains(&"two-node"));
        assert!(n.contains(&"reorg"));
    }

    #[test]
    fn chain_change_selects_chain_ibd_reorg() {
        let sels = select_profiles(&["crates/dom-chain/src/state.rs".to_string()]);
        let n = names(&sels);
        assert!(n.contains(&"chain"));
        assert!(n.contains(&"ibd"));
        assert!(n.contains(&"reorg"));
    }

    #[test]
    fn store_change_pulls_in_chain() {
        let sels = select_profiles(&["crates/dom-store/src/lmdb.rs".to_string()]);
        let n = names(&sels);
        assert!(n.contains(&"store"));
        assert!(n.contains(&"chain"));
    }

    #[test]
    fn wallet_app_alone_does_not_run_network_tests() {
        let sels = select_profiles(&["crates/dom-wallet-app/src/main.rs".to_string()]);
        let n = names(&sels);
        assert!(n.contains(&"wallet-app"));
        assert!(!n.contains(&"two-node"));
        assert!(!n.contains(&"integration-network"));
        assert!(!n.contains(&"integration"));
    }

    #[test]
    fn wallet_app_plus_node_does_run_integration() {
        let sels = select_profiles(&[
            "crates/dom-wallet-app/src/main.rs".to_string(),
            "crates/dom-node/src/lib.rs".to_string(),
        ]);
        let n = names(&sels);
        assert!(n.contains(&"wallet-app"));
        assert!(n.contains(&"integration"));
    }

    #[test]
    fn workflow_change_runs_fast_check() {
        let sels = select_profiles(&[".github/workflows/ci.yml".to_string()]);
        assert!(names(&sels).contains(&"fast-check"));
    }

    #[test]
    fn selections_are_deduplicated() {
        let sels = select_profiles(&[
            "crates/dom-mempool/src/a.rs".to_string(),
            "crates/dom-mempool/src/b.rs".to_string(),
        ]);
        let n = names(&sels);
        let count = n.iter().filter(|x| **x == "mempool").count();
        assert_eq!(count, 1, "duplicate selections must be merged");
    }

    #[test]
    fn unrelated_path_selects_nothing() {
        // Random unrelated file should produce no selection. The runner
        // layer then decides to fall back to fast-check.
        assert!(select_profiles(&["random/path/file.txt".to_string()]).is_empty());
    }
}

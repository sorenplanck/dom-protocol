use dom_wallet_core::PRODUCTION_REACHABILITY;
use dom_wallet_core_recovery::{CANONICAL_TRANSACTION_OUTPUT_SIZE, PRODUCTION_OUTPUT_PATHS};
use dom_wallet_production_backend::PRODUCTION_BACKEND_KIND;
use std::{fs, path::Path};

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
}

#[test]
fn production_core_backend_cutover_e2e() {
    assert_eq!(PRODUCTION_BACKEND_KIND, "EMBEDDED_WALLET_CORE_API_ONLY");
    let entries = PRODUCTION_REACHABILITY
        .iter()
        .copied()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(entries.get("scanner"), Some(&"CoreChainAdapter"));
    assert_eq!(entries.get("submission"), Some(&"CoreSubmissionService"));
    assert_eq!(entries.get("fees"), Some(&"CoreFeePolicyService"));
    assert_eq!(entries.get("slate"), Some(&"RecoverySlateV4"));
    assert_eq!(entries.get("restore"), Some(&"SeedRestoreService"));
}

#[test]
fn no_legacy_production_reachability() {
    let core = fs::read_to_string(workspace_root().join("crates/dom-wallet-core/src/lib.rs"))
        .expect("read production core");
    let tauri = fs::read_to_string(workspace_root().join("src-tauri/Cargo.toml"))
        .expect("read Tauri manifest");
    for forbidden in [
        "DomHttpChainSource",
        "ChainSource",
        "build_send(",
        "respond_receive(",
        "/tx/submit",
        "/chain/scan",
        "expected_weight(",
    ] {
        assert!(
            !core.contains(forbidden),
            "forbidden production symbol: {forbidden}"
        );
    }
    assert!(!tauri.contains("dom-wallet-chain"));
    assert!(!tauri.contains("dom-wallet-protocol"));
}

#[test]
fn no_mixed_output_regime() {
    assert_eq!(CANONICAL_TRANSACTION_OUTPUT_SIZE, 872);
    assert_eq!(PRODUCTION_OUTPUT_PATHS.len(), 5);
    assert!(PRODUCTION_OUTPUT_PATHS
        .iter()
        .all(|path| path.recovery_required));
}

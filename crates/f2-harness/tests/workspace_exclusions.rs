//! The workspace's exclusion list is pinned here.
//!
//! A crate outside the workspace is a crate no gate covers: `cargo build`,
//! `cargo clippy -D warnings` and `cargo test --workspace` all skip it. One
//! such crate exists and its reason is written in `Cargo.toml`. The danger is
//! not that entry — it is the next one, added quietly to make a build pass.
//!
//! This test fails whenever the list changes. Growing it is then a deliberate
//! act with a diff a reviewer sees, not a side effect.

use std::path::Path;

/// Every path the workspace is allowed to exclude, and why.
const ALLOWED_EXCLUSIONS: &[(&str, &str)] = &[
    (
        "wallet-desktop",
        "the node's own Tauri desktop wallet: needs a frontend dist/ that would \
         break `cargo build --workspace`; built from wallet-desktop/ instead",
    ),
    (
        "crates/f7-runner",
        "the F7 laboratory runtime: its Wallet V3 pin expects scanner surfaces \
         the mainnet release line does not publish, and neither growing the node \
         nor stubbing the wallet is permitted",
    ),
];

fn declared_exclusions(manifest: &str) -> Vec<String> {
    let start = manifest
        .find("\nexclude = [")
        .expect("the workspace manifest declares no `exclude` list");
    let body = &manifest[start..];
    let end = body.find("\n]").expect("unterminated `exclude` list");
    let mut found = Vec::new();
    let mut rest = &body[..end];
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let close = after.find('"').expect("unterminated string in `exclude`");
        found.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    found
}

#[test]
fn the_workspace_excludes_exactly_the_crates_it_is_allowed_to() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", manifest_path.display()));

    let declared = declared_exclusions(&manifest);
    let allowed: Vec<&str> = ALLOWED_EXCLUSIONS.iter().map(|(path, _)| *path).collect();

    for path in &declared {
        assert!(
            allowed.contains(&path.as_str()),
            "the workspace now excludes `{path}`, which this guard does not know.\n\
             A crate outside the workspace is covered by no gate — not the build, \
             not clippy, not the test suite.\n\
             If the exclusion is genuinely necessary, add it to ALLOWED_EXCLUSIONS \
             with the reason, so the next reader sees what is uncovered and why."
        );
    }

    for (path, reason) in ALLOWED_EXCLUSIONS {
        assert!(
            declared.contains(&(*path).to_string()),
            "`{path}` is no longer excluded, but this guard still records it as \
             uncovered ({reason}).\n\
             If it now builds inside the workspace, remove its entry from \
             ALLOWED_EXCLUSIONS."
        );
    }

    assert_eq!(
        declared.len(),
        ALLOWED_EXCLUSIONS.len(),
        "the exclusion list changed size: declared {declared:?}, allowed {allowed:?}"
    );
}

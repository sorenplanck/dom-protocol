//! `deny.toml` is policy that only CI executes, so nothing local catches it
//! when it stops parsing.
//!
//! It did stop parsing once: merging the layer's licence policy into the
//! node's file duplicated `[bans]` and `[sources]`. TOML forbids redefining a
//! table, so `cargo deny check` aborted at the parse — taking the advisories
//! check down with it — and every local gate stayed green, because cargo-deny
//! is not part of them.
//!
//! This test needs no TOML parser and no network. It checks the one thing that
//! broke.

use std::collections::BTreeMap;
use std::path::Path;

/// Table headers in declaration order. `[[array]]` entries are excluded:
/// repeating those is how an array of tables is written, and the licence
/// exceptions rely on it.
fn table_headers(policy: &str) -> Vec<(usize, String)> {
    policy
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            let header = line.strip_prefix('[')?.strip_suffix(']')?;
            if header.starts_with('[') {
                return None;
            }
            Some((index + 1, header.to_string()))
        })
        .collect()
}

#[test]
fn the_supply_chain_policy_declares_no_table_twice() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deny.toml");
    let policy = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    let mut first_seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut duplicates = Vec::new();
    for (line, header) in table_headers(&policy) {
        match first_seen.get(&header) {
            Some(earlier) => {
                duplicates.push(format!("[{header}] at line {line}, already at {earlier}"))
            }
            None => {
                first_seen.insert(header, line);
            }
        }
    }

    assert!(
        duplicates.is_empty(),
        "deny.toml declares a table more than once, which is invalid TOML:\n  {}\n\
         `cargo deny check` fails at the parse, so the advisories check does not \
         run at all.\n\
         Merge the duplicate into the section that already exists rather than \
         appending a second one.",
        duplicates.join("\n  ")
    );
}

#[test]
fn the_supply_chain_policy_still_denies_what_it_must() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deny.toml");
    let policy = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    // The three F1 vectors the node's own policy header names. Carrying the
    // layer's licence block must not relax any of them.
    for required in [
        "yanked = \"deny\"",
        "unknown-registry = \"deny\"",
        "unknown-git = \"deny\"",
        "required-git-spec = \"rev\"",
    ] {
        assert!(
            policy.contains(required),
            "deny.toml no longer carries `{required}` — the layer's policy may \
             only ADD to the node's supply-chain detector, never loosen it"
        );
    }
}

/// Source-level layer: the barriers must EXIST, checkable without a build.
///
/// The build guards (`check-release-surface.sh`,
/// `check-relay-fault-surface.sh`) prove the barriers FIRE. This proves they
/// are still written, and catches someone deleting one without needing a
/// release build to notice — the same two-layer shape the Contracts lineage
/// used for the Store.
#[test]
fn the_release_barriers_are_present_in_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (krate, feature) in [
        ("dom-scriptless-store", "evidence-only"),
        ("relay", "relay-fault-injection"),
    ] {
        let lib = root.join("crates").join(krate).join("src/lib.rs");
        let source = std::fs::read_to_string(&lib)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", lib.display()));
        let gate = format!("feature = \"{feature}\", not(debug_assertions)");
        assert!(
            source.contains(&gate),
            "{krate} no longer carries the release barrier for `{feature}`.\n\
             A laboratory surface that can be compiled into a release build is \
             one build-configuration mistake away from shipping."
        );
        assert!(
            source.contains("compile_error!"),
            "{krate} carries the cfg gate but no compile_error! behind it"
        );
    }
}

//! Roadmap v2 Phase 7.1 — RFC ↔ constants bidirectional audit.
//!
//! Every consensus constant lives in two places: `dom-core::constants`
//! (the source of truth at compile time) and the RFC / launch
//! documents under `docs/` (the source of truth for external
//! implementers and the audit trail). Drift between them is a
//! latent fork: a node compiled from this repo and a second
//! implementation written against the RFCs would disagree on the
//! protocol parameters.
//!
//! This test pins a curated table of (constant_name, value,
//! documented_form) triples. For each entry the test asserts:
//!
//!   * The compile-time constant in `dom-core` matches the expected
//!     numeric value.
//!   * The documented form (the exact substring readers will look
//!     for) appears in at least one `docs/*.md` file. This catches
//!     a regression where the code changes but the RFC isn't
//!     updated, or vice versa.
//!
//! The audit is hermetic — it reads files from the repository tree
//! via `CARGO_MANIFEST_DIR` rather than over the network, so it
//! runs on every leg of the Phase 1.4 cross-platform CI matrix.
//!
//! When a constant must legitimately change (post-genesis fork,
//! emergency parameter update), the procedure is:
//!   1. Update the dom-core constant.
//!   2. Update every `docs/*.md` reference to the new documented
//!      form.
//!   3. Add an RFC entry describing the change rationale.
//!   4. Update this table to point at the new value + form.
//!   5. Verify the test still passes.

use dom_core::{
    ASERT_HALF_LIFE, ASERT_RADIX_BITS, COIN_UNIT, COINBASE_MATURITY, HALVING_EPOCHS,
    HALVING_INTERVAL, INITIAL_BLOCK_REWARD, MAX_BLOCK_WEIGHT, MAX_FUTURE_BLOCK_TIME,
    MAX_SUPPLY_NOMS, NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_TESTNET, P2P_PORT_MAINNET,
    PROTOCOL_VERSION, TARGET_SPACING,
};
use std::path::PathBuf;

/// One (constant_name, runtime_value, documented_substring) audit
/// row. `documented_substring` is the exact text future readers
/// search for — keep it as it appears in MAINNET_LAUNCH.md / RFCs.
struct AuditRow {
    name: &'static str,
    runtime: u128,
    documented_form: &'static str,
}

fn rows() -> Vec<AuditRow> {
    vec![
        AuditRow {
            name: "INITIAL_BLOCK_REWARD",
            runtime: INITIAL_BLOCK_REWARD as u128,
            // 33 DOM * COIN_UNIT.
            documented_form: "INITIAL_BLOCK_REWARD = 33 DOM",
        },
        AuditRow {
            name: "HALVING_INTERVAL",
            runtime: HALVING_INTERVAL as u128,
            documented_form: "HALVING_INTERVAL = 330,000 blocks",
        },
        AuditRow {
            name: "TARGET_SPACING",
            runtime: TARGET_SPACING as u128,
            documented_form: "TARGET_SPACING = 120 seconds",
        },
        AuditRow {
            name: "MAX_SUPPLY_NOMS",
            runtime: MAX_SUPPLY_NOMS as u128,
            documented_form: "MAX_SUPPLY_NOMS = 3,299,999,976,900,000",
        },
        AuditRow {
            name: "COINBASE_MATURITY",
            runtime: COINBASE_MATURITY as u128,
            documented_form: "COINBASE_MATURITY = 1,000",
        },
        AuditRow {
            name: "MAX_FUTURE_BLOCK_TIME",
            runtime: MAX_FUTURE_BLOCK_TIME as u128,
            documented_form: "MAX_FUTURE_BLOCK_TIME = 120s",
        },
        AuditRow {
            name: "NETWORK_MAGIC_MAINNET",
            runtime: NETWORK_MAGIC_MAINNET as u128,
            documented_form: "NETWORK_MAGIC_MAINNET = 0x444F4D31",
        },
        AuditRow {
            name: "P2P_PORT_MAINNET",
            runtime: P2P_PORT_MAINNET as u128,
            documented_form: "P2P_PORT_MAINNET = 33,369",
        },
        AuditRow {
            name: "PROTOCOL_VERSION",
            runtime: PROTOCOL_VERSION as u128,
            documented_form: "PROTOCOL_VERSION = 2",
        },
        AuditRow {
            name: "ASERT_HALF_LIFE",
            runtime: ASERT_HALF_LIFE as u128,
            documented_form: "ASERT_HALF_LIFE = 172,800 seconds",
        },
        AuditRow {
            name: "ASERT_RADIX_BITS",
            runtime: ASERT_RADIX_BITS as u128,
            documented_form: "ASERT_RADIX_BITS = 16",
        },
    ]
}

/// Concatenate every `docs/*.md` file into one big haystack the
/// audit can grep over. Reads from `$CARGO_MANIFEST_DIR/../../docs`.
fn doc_corpus() -> String {
    let docs_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root")
        .join("docs");
    let mut buf = String::new();
    for entry in std::fs::read_dir(&docs_dir).expect("docs dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        buf.push_str(&content);
        buf.push_str("\n\n");
    }
    buf
}

/// Sanity baselines for the constants the runtime exports — pinned
/// against the values published in the whitepaper / RFC bundle. A
/// drift between dom-core::constants and these literals is a
/// consensus-class regression.
#[test]
fn audit_runtime_constants_match_published_literals() {
    assert_eq!(
        INITIAL_BLOCK_REWARD,
        33u64 * COIN_UNIT,
        "INITIAL_BLOCK_REWARD drift"
    );
    assert_eq!(HALVING_INTERVAL, 330_000, "HALVING_INTERVAL drift");
    assert_eq!(TARGET_SPACING, 120, "TARGET_SPACING drift");
    assert_eq!(
        MAX_SUPPLY_NOMS, 3_299_999_976_900_000,
        "MAX_SUPPLY_NOMS drift"
    );
    assert_eq!(COINBASE_MATURITY, 1_000, "COINBASE_MATURITY drift");
    assert_eq!(MAX_FUTURE_BLOCK_TIME, 120, "MAX_FUTURE_BLOCK_TIME drift");
    assert_eq!(NETWORK_MAGIC_MAINNET, 0x444F_4D31, "MAINNET magic drift");
    assert_eq!(NETWORK_MAGIC_TESTNET, 0x444F_4D54, "TESTNET magic drift");
    assert_eq!(P2P_PORT_MAINNET, 33_369, "P2P_PORT_MAINNET drift");
    assert_eq!(PROTOCOL_VERSION, 2, "PROTOCOL_VERSION drift");
    assert_eq!(ASERT_HALF_LIFE, 172_800, "ASERT_HALF_LIFE drift");
    assert_eq!(ASERT_RADIX_BITS, 16, "ASERT_RADIX_BITS drift");
    assert_eq!(HALVING_EPOCHS, 55, "HALVING_EPOCHS drift");
    assert_eq!(MAX_BLOCK_WEIGHT, 40_000, "MAX_BLOCK_WEIGHT drift");
}

/// Every audited constant MUST be mentioned in the documentation
/// corpus with its published form. Catches the case where a constant
/// is bumped in code but the docs still cite the previous value.
#[test]
fn audit_each_documented_form_appears_in_docs() {
    let corpus = doc_corpus();
    let mut missing: Vec<&str> = Vec::new();
    for row in rows() {
        if !corpus.contains(row.documented_form) {
            missing.push(row.documented_form);
        }
    }
    assert!(
        missing.is_empty(),
        "audit failure — these documented forms were not found in docs/*.md:\n  {}\n\
         (either the code changed without updating the docs, or the audit \
         table's documented_form text drifted from the doc text)",
        missing.join("\n  ")
    );
}

/// The MAINNET_LAUNCH.md immutable-parameters checklist MUST cite
/// every audited constant by name. A regression here means a new
/// audited parameter was added to the constants module but never
/// registered in the launch checklist.
#[test]
fn audit_mainnet_launch_checklist_references_each_constant() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("docs/MAINNET_LAUNCH.md");
    let content = std::fs::read_to_string(&path).expect("read MAINNET_LAUNCH.md");
    let mut missing: Vec<&str> = Vec::new();
    for row in rows() {
        if !content.contains(row.name) {
            missing.push(row.name);
        }
    }
    assert!(
        missing.is_empty(),
        "MAINNET_LAUNCH.md missing references to: {}",
        missing.join(", ")
    );
}

/// Cross-spec sanity: the per-row numeric value MUST be derivable
/// from the documented form (i.e., parsing the trailing literal in
/// `"NAME = LITERAL ..."` and stripping commas / underscores yields
/// the same u128 we read from the runtime). This catches a drift
/// where someone updates the constants module but accidentally
/// edits the comma in MAINNET_LAUNCH.md to say "330,001" instead of
/// "330,000".
#[test]
fn audit_documented_form_literals_parse_back_to_runtime_values() {
    for row in rows() {
        // INITIAL_BLOCK_REWARD is documented in human DOM units
        // ("33 DOM") while the runtime carries the noms-denominated
        // value (33 * COIN_UNIT). The other audit entries already
        // pin the noms value directly; here we apply the unit
        // conversion before comparing.
        let unit_scale: u128 = if row.name == "INITIAL_BLOCK_REWARD" {
            COIN_UNIT as u128
        } else {
            1
        };

        let after_eq = row
            .documented_form
            .split_once('=')
            .expect("documented_form has '='")
            .1
            .trim();
        let literal_token = after_eq
            .split_whitespace()
            .next()
            .expect("non-empty after =");
        let parsed_value = if let Some(hex_str) = literal_token.strip_prefix("0x") {
            u128::from_str_radix(hex_str, 16)
                .unwrap_or_else(|e| panic!("hex parse {literal_token}: {e}"))
        } else {
            let cleaned: String = literal_token
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '_')
                .filter(|c| *c != '_')
                .collect();
            cleaned
                .parse::<u128>()
                .unwrap_or_else(|e| panic!("decimal parse {literal_token}: {e}"))
        };
        assert_eq!(
            parsed_value * unit_scale,
            row.runtime,
            "documented_form for {} parses to {} ×{} = {} but runtime says {}",
            row.name,
            parsed_value,
            unit_scale,
            parsed_value * unit_scale,
            row.runtime
        );
    }
}

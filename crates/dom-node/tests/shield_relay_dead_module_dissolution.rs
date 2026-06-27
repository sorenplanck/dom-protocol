//! dom-shield — FIX-011 dissolution: the `dom_node::relay` module is DEAD.
//!
//! FIX-011 flagged two liabilities in `crates/dom-node/src/relay/`:
//!   * `dandelion.rs`: a hardcoded-seed PRNG (`rng_state: 0xDEADBEEFCAFEBABE`)
//!     making `should_stem()` fully predictable across restarts.
//!   * `tx_relay.rs`: `mark_seen` does `seen.clear()` on overflow (clear-on-full),
//!     wiping the entire dedup set instead of evicting one entry.
//!
//! CONFIRMED DISSOLUTION: the LIVE node path uses `dom_wire::dandelion::DandelionRouter`
//! (see `node.rs`: `use dom_wire::dandelion::DandelionRouter;` and
//! `dandelion: Arc::new(Mutex::new(DandelionRouter::new()))`). The local
//! `dom_node::relay::{DandelionRouter, TxRelay}` types are exported via
//! `pub mod relay` in lib.rs but are referenced by NOTHING in the runtime path —
//! only by their own in-module `#[cfg(test)]` blocks. They are therefore
//! NOT-CURRENTLY-ATTACKABLE (no live caller can be reached by a peer).
//!
//! These tests (a) prove the predictability/clear-on-full liabilities are real
//! in the local module (so the dissolution rationale is "dead", not "fixed"),
//! and (b) provide a grep-probe asserting no live reference exists. Outcome:
//! MARK `crates/dom-node/src/relay/` FOR DELETION (human decision — touches a
//! pub module surface).

use dom_node::relay::{DandelionRouter, RelayDecision, TxRelay};
use std::path::PathBuf;

/// Liability #1 (dead): the local DandelionRouter is fully deterministic from a
/// hardcoded seed — two fresh instances emit the identical should_stem() stream.
/// Predictable stem/fluff would let an observer de-anonymise tx origin IF this
/// were wired in. It is not (see grep-probe below).
#[test]
fn local_dandelion_prng_is_predictable_from_hardcoded_seed() {
    let mut a = DandelionRouter::new(0.5, 300);
    let mut b = DandelionRouter::new(0.5, 300);
    let seq_a: Vec<bool> = (0..256).map(|_| a.should_stem()).collect();
    let seq_b: Vec<bool> = (0..256).map(|_| b.should_stem()).collect();
    assert_eq!(
        seq_a, seq_b,
        "hardcoded-seed PRNG => identical stream across instances (predictable)"
    );
}

/// Liability #2 (dead): clear-on-full wipes the WHOLE dedup set. After the cap
/// is hit, a previously-seen tx is forgotten — re-broadcast amplification IF
/// this were wired in. It is not.
#[tokio::test]
async fn local_tx_relay_clears_entire_set_on_overflow() {
    let relay = TxRelay::new(4);
    for i in 0..4u8 {
        relay.mark_seen([i; 32]).await;
    }
    assert_eq!(relay.seen_count().await, 4);
    // One more insert triggers clear() then insert -> count collapses to 1.
    relay.mark_seen([99u8; 32]).await;
    assert_eq!(
        relay.seen_count().await,
        1,
        "clear-on-full forgets all prior tx hashes (re-broadcast window)"
    );
    // A tx seen before the overflow is now treated as brand-new (Accept).
    assert_eq!(
        relay.process_incoming([0u8; 32]).await,
        RelayDecision::Accept,
        "previously-seen tx is forgotten after clear-on-full"
    );
}

/// Grep-probe: NO file under crates/dom-node/src/ references the local relay
/// types OUTSIDE the relay module itself and OUTSIDE #[cfg(test)]. The live
/// path uses dom_wire::dandelion instead. This is the dissolution evidence.
#[test]
fn relay_module_has_no_live_caller() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    visit(&src, &mut |path, contents| {
        // Skip the relay module's own files.
        if path.components().any(|c| c.as_os_str() == "relay") {
            return;
        }
        for (lineno, line) in contents.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            // Live use would look like `crate::relay::` or `use ...relay::Dandelion`.
            // The dom_wire one is `dom_wire::dandelion::` — explicitly allowed.
            let mentions_local_relay = (line.contains("crate::relay")
                || line.contains("use crate::relay")
                || line.contains("super::relay"))
                && !line.contains("dom_wire");
            if mentions_local_relay {
                offenders.push(format!("{}:{}: {}", path.display(), lineno + 1, t));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "FIX-011 dissolution broken — found live reference(s) to dom_node::relay:\n{}",
        offenders.join("\n")
    );
}

fn visit(dir: &std::path::Path, f: &mut impl FnMut(&std::path::Path, &str)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit(&path, f);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                f(&path, &contents);
            }
        }
    }
}

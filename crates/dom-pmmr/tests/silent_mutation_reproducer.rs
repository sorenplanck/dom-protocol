//! Phase A empirical reproducers for the PMMR silent-leaf-mutation bug.
//!
//! These tests target two observable, consensus-critical symptoms of the
//! pre-Phase-B `Pmmr` implementation:
//!
//! 1. `Pmmr::push` returns the wrong leaf position because `leaf_pos`
//!    is computed as the post-insert node count, which equates a fresh
//!    leaf with the parent that should have been merged above it.
//! 2. `node_height` reads `pos.trailing_ones()` directly. The MMR
//!    postorder height formula is *not* `trailing_ones(pos)` — it is
//!    derived from the most-significant set bit after left-jumping
//!    until all bits are ones (see Grin's `bintree_postorder_height`).
//!    Heights at positions 1, 3, 5, 7, … come out one too high, which
//!    suppresses every peak merge inside `merge_peaks`.
//!
//! Combined, these two bugs collapse `root()` for a multi-leaf MMR to
//! `leaf_hash(last_pos, last_payload)` — the root depends on the last
//! leaf only and silently ignores every earlier leaf. That is a
//! straightforward chainstate forgery primitive: any block producer can
//! mutate the historical UTXO/kernel set without disturbing the
//! committed MMR root.
//!
//! Every assertion below MUST fail before the Phase B fix and MUST pass
//! after. If any of these starts passing on broken code, the bug
//! reproducer has lost its grip and needs to be re-examined.
//!
//! Reference for the expected algorithm: Grin's `core/src/core/pmmr/pmmr.rs`
//! (BSD-3) — DOM's wire-level hashes diverge (DOM uses tagged Blake2b-256
//! with the position prefixed inside the tag domain) but the index
//! arithmetic and peak/bagging order match.

use dom_pmmr::{bag_peaks, leaf_hash, node_hash, Pmmr};

/// Helper: build a PMMR by pushing `payloads` in order and return the root.
fn root_of(payloads: &[&[u8]]) -> dom_core::Hash256 {
    let mut pmmr = Pmmr::new();
    for p in payloads {
        pmmr.push(p).expect("push must succeed");
    }
    pmmr.root()
}

// ── (1) Silent-mutation symptom ──────────────────────────────────────────────

/// For every `n` in {2,3,4,5,7,8,9,15,16}, mutating *any* leaf MUST
/// change the root. The broken implementation only ever hashes the
/// final leaf into the root, so this fails for every `mutate_idx`
/// except the last.
#[test]
fn root_changes_when_any_leaf_changes() {
    for &n in &[2usize, 3, 4, 5, 7, 8, 9, 15, 16] {
        // Baseline payloads: [0, 1, 2, …]
        let baseline: Vec<[u8; 8]> = (0..n as u64).map(|i| i.to_le_bytes()).collect();
        let baseline_refs: Vec<&[u8]> = baseline.iter().map(|b| b.as_slice()).collect();
        let baseline_root = root_of(&baseline_refs);

        for mutate_idx in 0..n {
            let mut mutated = baseline.clone();
            // Flip every bit of the chosen leaf so the payload is
            // guaranteed to differ from any other leaf.
            for byte in mutated[mutate_idx].iter_mut() {
                *byte ^= 0xFF;
            }
            let mutated_refs: Vec<&[u8]> = mutated.iter().map(|b| b.as_slice()).collect();
            let mutated_root = root_of(&mutated_refs);
            assert_ne!(
                baseline_root, mutated_root,
                "n={n} mutate_idx={mutate_idx}: root unchanged after flipping leaf payload \
                 — every leaf MUST influence the MMR root"
            );
        }
    }
}

/// Swapping two leaves MUST change the root (leaf order is consensus).
#[test]
fn root_depends_on_leaf_order() {
    let r_ab = root_of(&[b"a", b"b"]);
    let r_ba = root_of(&[b"b", b"a"]);
    assert_ne!(
        r_ab, r_ba,
        "PMMR root must depend on insertion order — leaf positions differ"
    );

    let r_abcd = root_of(&[b"a", b"b", b"c", b"d"]);
    let r_dcba = root_of(&[b"d", b"c", b"b", b"a"]);
    assert_ne!(
        r_abcd, r_dcba,
        "4-leaf PMMR root must depend on insertion order"
    );
}

// ── (2) Hand-computed reference roots ────────────────────────────────────────

/// 2-leaf MMR has a single peak at postorder position 3 that is the
/// parent of leaves at positions 1 and 2.
///
/// Expected root = `node_hash(3, leaf_hash(1, a), leaf_hash(2, b))`.
///
/// The broken implementation places leaf "b" at position 3 (the parent
/// slot), never runs the merge, and returns `leaf_hash(3, b)`.
#[test]
fn two_leaf_root_matches_hand_computation() {
    let a = b"alpha";
    let b = b"beta";

    let expected = {
        let lh1 = leaf_hash(1, a);
        let lh2 = leaf_hash(2, b);
        node_hash(3, &lh1, &lh2)
    };

    let actual = root_of(&[a, b]);

    assert_eq!(
        actual, expected,
        "2-leaf root must equal node_hash(3, lh(1,a), lh(2,b)) per the MMR postorder layout"
    );
}

/// 4-leaf MMR collapses to a single peak at position 7. The peak is
/// `node(7, node(3, lh(1,a), lh(2,b)), node(6, lh(4,c), lh(5,d)))`.
/// `bag_peaks` of a single-peak MMR returns that peak unchanged.
#[test]
fn four_leaf_root_matches_hand_computation() {
    let payloads: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];

    let lh1 = leaf_hash(1, payloads[0]);
    let lh2 = leaf_hash(2, payloads[1]);
    let lh4 = leaf_hash(4, payloads[2]);
    let lh5 = leaf_hash(5, payloads[3]);
    let n3 = node_hash(3, &lh1, &lh2);
    let n6 = node_hash(6, &lh4, &lh5);
    let expected_peak = node_hash(7, &n3, &n6);
    // Single peak: bag_peaks is the identity.
    let expected = bag_peaks(&[expected_peak]);

    let actual = root_of(&payloads);

    assert_eq!(
        actual, expected,
        "4-leaf root must equal node(7, node(3, lh1, lh2), node(6, lh4, lh5))"
    );
}

/// 3-leaf MMR has two peaks: the merged subtree at position 3
/// and the unmerged leaf at position 4. Root = bag([peak3, peak4]).
#[test]
fn three_leaf_root_matches_hand_computation() {
    let payloads: [&[u8]; 3] = [b"a", b"b", b"c"];

    let lh1 = leaf_hash(1, payloads[0]);
    let lh2 = leaf_hash(2, payloads[1]);
    let lh4 = leaf_hash(4, payloads[2]);
    let n3 = node_hash(3, &lh1, &lh2);
    let expected = bag_peaks(&[n3, lh4]);

    let actual = root_of(&payloads);

    assert_eq!(
        actual, expected,
        "3-leaf root must equal bag([node(3, lh1, lh2), lh(4, c)])"
    );
}

// ── (3) Leaf-position contract ───────────────────────────────────────────────

/// `Pmmr::push` MUST return the canonical MMR postorder position for
/// each leaf: 1, 2, 4, 5, 8, 9, 11, 12, … (powers of two are *parent*
/// positions, never leaves).
///
/// The broken implementation returns `new_node_count`, which gives the
/// sequence 1, 3, 4, 7, 8, 10, 11, 15, … — coinciding with the
/// reference only at the first leaf, before any merges happen.
#[test]
fn pushed_leaves_have_canonical_mmr_postorder_positions() {
    // Reference taken from Grin's leaf_index_to_position table for the
    // first 16 leaves. Equivalently: i-th leaf position is
    //     2*i - popcount(i-1)            (1-indexed i)
    // which matches the MMR postorder traversal.
    let expected_positions: [u64; 16] = [1, 2, 4, 5, 8, 9, 11, 12, 16, 17, 19, 20, 23, 24, 26, 27];

    let mut pmmr = Pmmr::new();
    for (i, &expected) in expected_positions.iter().enumerate() {
        let actual = pmmr
            .push(&(i as u64).to_le_bytes())
            .expect("push must succeed");
        assert_eq!(
            actual, expected,
            "leaf #{i} reported position {actual}, expected {expected} \
             (MMR postorder — leaves never sit on power-of-two positions \
              once any merge has happened)"
        );
    }
}

// ── (4) Empty-tree invariant (sanity baseline) ───────────────────────────────

/// The empty-PMMR root must be the deterministic `TAG_PMMR_EMPTY`
/// digest and MUST differ from any single-leaf root. This is a
/// regression baseline — already true on the broken code, kept here so
/// the Phase B fix is forced to preserve it.
#[test]
fn empty_root_differs_from_any_single_leaf_root() {
    let empty = root_of(&[]);
    let single = root_of(&[b"x"]);
    assert_ne!(
        empty, single,
        "empty PMMR root must differ from any populated root"
    );
}

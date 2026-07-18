#![allow(missing_docs)]
//! # dom-pmmr
//!
//! Pruned Merkle Mountain Range accumulator.
//!
//! Source of truth: DOM_RFC_0004_PMMR_Hardening.md
//!
//! ## Consensus Rules
//!
//! - Leaf hash: Blake2b-256(tag || position || payload)
//! - Node hash: Blake2b-256(tag || position || left || right)
//! - Peaks MUST be ordered left-to-right by PMMR position
//! - Bagging MUST use right-to-left fold ONLY
//! - Empty PMMR root: Blake2b-256(tag="DOM:pmmr-empty:v1", payload="")
//! - Any alternate peak order or bagging direction is consensus-invalid

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::arithmetic_side_effects)] // MMR math: indices audited

use dom_core::{DomError, Hash256, TAG_PMMR_BAG, TAG_PMMR_EMPTY, TAG_PMMR_LEAF, TAG_PMMR_NODE};
use dom_crypto::hash::blake2b_256_tagged;

#[cfg(kani)]
mod kani_invariants;

// ── Position arithmetic ───────────────────────────────────────────────────────
//
// Convention (RFC-0004, matching Grin's `core/src/core/pmmr/pmmr.rs`):
//
//   * 1-indexed MMR postorder positions: leaves and internal nodes share
//     the same monotone numbering. The empty MMR has no position 0.
//   * Height 0 = leaf. A node at height h is the root of a perfect
//     binary subtree containing 2^h leaves and 2^(h+1) - 1 nodes.
//   * Leaf positions are NOT given by `trailing_ones`; postorder height
//     must be computed by left-jumping until the position becomes
//     "all-ones" (2^k - 1) and reading the most-significant bit index.
//
// The pre-Phase-B implementation used `pos.trailing_ones()` directly
// (DOM-PMMR-001), inflating heights at positions 1, 3, 5, 7, … by one
// and suppressing every merge inside `merge_peaks`.

/// True iff `n` is of the form `2^k - 1` (binary representation is all
/// ones below the most-significant bit). Used by the postorder height
/// loop as the termination predicate.
#[inline]
fn is_all_ones(n: u64) -> bool {
    // n = 2^k - 1  ⇔  n+1 is a non-zero power of two.
    n != 0 && n.checked_add(1).map(u64::is_power_of_two).unwrap_or(false)
}

/// 1-indexed position of the most-significant set bit (msb_pos(1) = 1,
/// msb_pos(0) = 0). Equivalent to `64 - n.leading_zeros()` for `n > 0`.
#[inline]
fn most_significant_pos(n: u64) -> u32 {
    if n == 0 {
        0
    } else {
        64 - n.leading_zeros()
    }
}

/// Move `pos` to the leftmost sibling at the same height by subtracting
/// the size of the subtree rooted at the most-significant level minus
/// one. Mirrors Grin's `bintree_jump_left`.
#[inline]
fn jump_left(pos: u64) -> u64 {
    let msb = most_significant_pos(pos);
    // msb is at least 1 here because the caller only invokes jump_left
    // when `pos > 0` and `!is_all_ones(pos)` — i.e. pos has at least
    // one zero bit below the msb, which forces msb >= 2.
    let shift = msb.saturating_sub(1);
    pos - ((1u64 << shift) - 1)
}

/// Returns the postorder height of the node at MMR position `pos`.
///
/// Height 0 = leaf. The Grin-derived algorithm: keep jumping left until
/// the position is `2^k - 1` (a perfect-subtree root), then height =
/// `msb_pos - 1`.
///
/// Examples (1-indexed): heights at 1..15 =
///   [0, 0, 1, 0, 0, 1, 2, 0, 0, 1, 0, 0, 1, 2, 3].
fn node_height(pos: u64) -> u32 {
    if pos == 0 {
        return 0;
    }
    let mut h = pos;
    while !is_all_ones(h) {
        h = jump_left(h);
    }
    most_significant_pos(h) - 1
}

/// Given a leaf count `n`, return the list of peak positions (1-indexed).
///
/// Peaks are ordered left-to-right by MMR position, which is the
/// consensus-mandated order per RFC-0004.
#[derive(Clone, Copy)]
struct PeakPositions {
    positions: [u64; 64],
    len: usize,
}

impl PeakPositions {
    fn as_slice(&self) -> &[u64] {
        &self.positions[..self.len]
    }
}

fn peak_positions_fixed(leaf_count: u64) -> Option<PeakPositions> {
    let mut peaks = PeakPositions {
        positions: [0; 64],
        len: 0,
    };
    if leaf_count == 0 {
        return Some(peaks);
    }

    let mut remaining = leaf_count;
    let mut pos_offset: u64 = 0;

    // Decompose leaf_count into sum of powers of 2 (binary representation)
    // Each set bit corresponds to a perfect sub-tree (peak)
    let mut bit = 63u32;
    loop {
        let subtree_leaves = 1u64 << bit;
        if subtree_leaves <= remaining {
            // This peak has subtree_leaves leaves
            // Peak position in the MMR = pos_offset + (2 * subtree_leaves - 1)
            // Compute 2*n-1 without overflowing the intermediate 2*n. This
            // keeps the single 2^63-leaf peak representable at u64::MAX.
            let subtree_size = subtree_leaves.checked_sub(1)?.checked_add(subtree_leaves)?;
            let peak_pos = pos_offset.checked_add(subtree_size)?;
            peaks.positions[peaks.len] = peak_pos;
            peaks.len += 1;
            pos_offset = peak_pos;
            remaining = remaining.checked_sub(subtree_leaves)?;
        }
        if bit == 0 {
            break;
        }
        bit -= 1;
    }

    Some(peaks)
}

fn peak_positions(leaf_count: u64) -> Vec<u64> {
    peak_positions_fixed(leaf_count)
        .expect("PMMR peak positions exceed the u64 position domain")
        .as_slice()
        .to_vec()
}

// ── Hashing ───────────────────────────────────────────────────────────────────

/// Compute the leaf hash for a PMMR leaf.
///
/// leaf_hash = Blake2b-256(u16_le(len(tag)) || tag || pos_le8 || payload)
pub fn leaf_hash(position: u64, payload: &[u8]) -> Hash256 {
    let mut data = Vec::with_capacity(8 + payload.len());
    data.extend_from_slice(&position.to_le_bytes());
    data.extend_from_slice(payload);
    blake2b_256_tagged(TAG_PMMR_LEAF, &data)
}

/// Compute the internal node hash.
///
/// node_hash = Blake2b-256(u16_le(len(tag)) || tag || pos_le8 || left || right)
pub fn node_hash(position: u64, left: &Hash256, right: &Hash256) -> Hash256 {
    let mut data = Vec::with_capacity(8 + 32 + 32);
    data.extend_from_slice(&position.to_le_bytes());
    data.extend_from_slice(left.as_bytes());
    data.extend_from_slice(right.as_bytes());
    blake2b_256_tagged(TAG_PMMR_NODE, &data)
}

/// Compute the PMMR root by bagging the peaks.
///
/// Rules (RFC-0004, consensus-critical):
/// - Empty PMMR: root = Blake2b-256(tag="DOM:pmmr-empty:v1", payload="")
/// - One peak: root = peak_hash
/// - Multiple peaks: right-to-left fold
///
/// Bagging (multiple peaks, right-to-left):
/// ```text
/// acc = last_peak
/// for peak in reverse(peaks_without_last):
///     acc = Blake2b-256(u16_le(len(bag_tag)) || bag_tag || peak || acc)
/// root = acc
/// ```
pub fn bag_peaks(peaks: &[Hash256]) -> Hash256 {
    match peaks.len() {
        0 => {
            // Empty PMMR
            blake2b_256_tagged(TAG_PMMR_EMPTY, &[])
        }
        1 => peaks[0],
        _ => {
            // Right-to-left fold: start from the rightmost peak
            let mut acc = *peaks.last().expect("peaks is non-empty");
            // Iterate remaining peaks in reverse (right to left, excluding last)
            for peak in peaks[..peaks.len() - 1].iter().rev() {
                let mut data = Vec::with_capacity(32 + 32);
                data.extend_from_slice(peak.as_bytes());
                data.extend_from_slice(acc.as_bytes());
                acc = blake2b_256_tagged(TAG_PMMR_BAG, &data);
            }
            acc
        }
    }
}

// ── PMMR State ────────────────────────────────────────────────────────────────

/// An append-only Pruned Merkle Mountain Range.
///
/// Stores all node hashes for the current state. In a pruned node,
/// spent leaf hashes may be removed while the internal node hashes
/// are retained for proof generation.
#[derive(Debug, Clone)]
pub struct Pmmr {
    /// All node hashes indexed by MMR position (1-indexed, 0 unused).
    nodes: Vec<Option<Hash256>>,
    /// Number of leaves appended.
    leaf_count: u64,
}

impl Pmmr {
    /// Create a new empty PMMR.
    pub fn new() -> Self {
        Self {
            nodes: vec![None], // position 0 unused; 1-indexed
            leaf_count: 0,
        }
    }

    /// Number of leaves in this PMMR.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Total number of nodes (leaves + internal).
    pub fn node_count(&self) -> u64 {
        // A PMMR with n leaves has 2n - popcount(n) nodes
        let n = self.leaf_count;
        let popcount = n.count_ones() as u64;
        n.checked_mul(2)
            .and_then(|x| x.checked_sub(popcount))
            .expect("node count overflow")
    }

    /// Append a new leaf with the given payload.
    ///
    /// Returns the MMR postorder position of the appended leaf. With
    /// `n - 1` leaves already in the MMR, the new leaf is placed
    /// immediately after the last existing node:
    ///
    /// ```text
    ///   leaf_pos(n) = nodes_before(n) + 1
    ///              = (2*(n-1) - popcount(n-1)) + 1
    ///              = 2*n - 1 - popcount(n-1)
    /// ```
    ///
    /// Pre-Phase-B (DOM-PMMR-001) this used the *post*-insert node
    /// count, which placed each fresh leaf into the parent slot it
    /// would have been merged into, suppressing every subsequent merge
    /// and collapsing `root()` to `leaf_hash(last_pos, last_payload)`.
    pub fn push(&mut self, payload: &[u8]) -> Result<u64, DomError> {
        let new_leaf_count = self
            .leaf_count
            .checked_add(1)
            .ok_or_else(|| DomError::Internal("PMMR leaf count overflow".into()))?;

        // Position of the new leaf = (nodes already present) + 1.
        let nodes_before = {
            let n = self.leaf_count;
            let pc = n.count_ones() as u64;
            n.checked_mul(2)
                .and_then(|x| x.checked_sub(pc))
                .ok_or_else(|| DomError::Internal("node count overflow".into()))?
        };
        let leaf_pos = nodes_before
            .checked_add(1)
            .ok_or_else(|| DomError::Internal("leaf_pos overflow".into()))?;

        // Compute leaf hash and place it.
        let lh = leaf_hash(leaf_pos, payload);
        self.set_node(leaf_pos, lh)?;

        // Merge peaks: any two adjacent peaks of equal height merge
        // into a parent at the position immediately to the right.
        self.merge_peaks(leaf_pos)?;

        self.leaf_count = new_leaf_count;
        Ok(leaf_pos)
    }

    /// Merge newly created peaks bottom-up.
    ///
    /// In an MMR, a node at height `h` covers a perfect subtree of size
    /// `2^(h+1) - 1`. Its left sibling (if any) is exactly that many
    /// positions to the left.
    fn merge_peaks(&mut self, mut pos: u64) -> Result<(), DomError> {
        loop {
            let h = node_height(pos);
            // Size of a complete subtree at height h: 2^(h+1) - 1
            let subtree_size = (1u64 << (h + 1))
                .checked_sub(1)
                .ok_or_else(|| DomError::Internal("subtree_size underflow".into()))?;

            if pos <= subtree_size {
                break; // no room for a left sibling
            }

            let left_pos = pos
                .checked_sub(subtree_size)
                .ok_or_else(|| DomError::Internal("left_pos underflow".into()))?;

            // Left sibling must exist and have the same height
            if node_height(left_pos) != h {
                break;
            }

            // Parent is immediately to the right of pos
            let parent_pos = pos
                .checked_add(1)
                .ok_or_else(|| DomError::Internal("parent_pos overflow".into()))?;

            let left_hash = self
                .get_node(left_pos)
                .ok_or_else(|| DomError::Internal(format!("missing node at {left_pos}")))?;
            let right_hash = self
                .get_node(pos)
                .ok_or_else(|| DomError::Internal(format!("missing node at {pos}")))?;

            let ph = node_hash(parent_pos, &left_hash, &right_hash);
            self.set_node(parent_pos, ph)?;
            pos = parent_pos;
        }
        Ok(())
    }

    /// Compute the current PMMR root by bagging all peaks.
    pub fn root(&self) -> Result<Hash256, DomError> {
        let positions = peak_positions(self.leaf_count);
        let mut peak_hashes = Vec::with_capacity(positions.len());
        for &p in &positions {
            // FIX-021: a peak position implied by `leaf_count` MUST be present.
            // The previous `filter_map` silently dropped a missing (e.g. pruned)
            // peak and bagged the survivors, yielding a well-formed root over an
            // INCOMPLETE peak set — a hidden-history / forged-shape root. Refuse
            // to compute a root over a hole, mirroring the `set_node` guard.
            let h = self.get_node(p).ok_or_else(|| {
                DomError::Internal(format!(
                    "PMMR invariant violated: missing peak at position {p} \
                     (leaf_count={}); refusing to compute root over an incomplete \
                     peak set",
                    self.leaf_count
                ))
            })?;
            peak_hashes.push(h);
        }
        Ok(bag_peaks(&peak_hashes))
    }

    /// Place a node hash at `pos`. The MMR is append-only; overwriting
    /// an existing entry is a consensus-class bug (it would silently
    /// rewrite committed history without changing the leaf count), so
    /// this guard rejects any attempt at re-assignment.
    fn set_node(&mut self, pos: u64, hash: Hash256) -> Result<(), DomError> {
        let idx = pos as usize;
        if idx >= self.nodes.len() {
            let needed = idx
                .checked_add(1)
                .ok_or_else(|| DomError::Internal("node index overflow".into()))?;
            self.nodes.resize(needed, None);
        }
        if self.nodes[idx].is_some() {
            return Err(DomError::Internal(format!(
                "PMMR invariant violated: attempt to overwrite node at position {pos}"
            )));
        }
        self.nodes[idx] = Some(hash);
        Ok(())
    }

    fn get_node(&self, pos: u64) -> Option<Hash256> {
        self.nodes.get(pos as usize).copied().flatten()
    }
}

impl Default for Pmmr {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty PMMR root must be deterministic.
    #[test]
    fn empty_pmmr_root_is_deterministic() {
        let pmmr = Pmmr::new();
        let r1 = pmmr.root().unwrap();
        let r2 = pmmr.root().unwrap();
        assert_eq!(r1, r2);
        // Must not be all-zero
        assert_ne!(r1, Hash256::ZERO);
    }

    /// Single leaf PMMR root = leaf hash (no bagging).
    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let mut pmmr = Pmmr::new();
        let pos = pmmr.push(b"leaf0").unwrap();
        let expected = leaf_hash(pos, b"leaf0");
        assert_eq!(pmmr.root().unwrap(), expected);
    }

    /// Root changes when leaf is added.
    #[test]
    fn root_changes_on_append() {
        let mut pmmr = Pmmr::new();
        let r0 = pmmr.root().unwrap();
        pmmr.push(b"leaf0").unwrap();
        let r1 = pmmr.root().unwrap();
        assert_ne!(r0, r1);
        pmmr.push(b"leaf1").unwrap();
        let r2 = pmmr.root().unwrap();
        assert_ne!(r1, r2);
    }

    /// PMMR with same leaves produces same root (determinism).
    #[test]
    fn pmmr_is_deterministic() {
        let leaves = [b"a".as_ref(), b"b", b"c", b"d"];
        let root1 = {
            let mut p = Pmmr::new();
            for l in &leaves {
                p.push(l).unwrap();
            }
            p.root().unwrap()
        };
        let root2 = {
            let mut p = Pmmr::new();
            for l in &leaves {
                p.push(l).unwrap();
            }
            p.root().unwrap()
        };
        assert_eq!(root1, root2);
    }

    /// Test required vectors from RFC-0004: 0,1,2,3,4,7,8,15,16 leaves.
    #[test]
    fn required_vectors_are_stable() {
        let leaf_counts = [0usize, 1, 2, 3, 4, 7, 8, 15, 16];
        let mut roots = Vec::new();

        for &count in &leaf_counts {
            let mut pmmr = Pmmr::new();
            for i in 0..count {
                pmmr.push(&i.to_le_bytes()).unwrap();
            }
            roots.push(pmmr.root().unwrap());
        }

        // All roots must be distinct
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(
                    roots[i], roots[j],
                    "roots[{i}] == roots[{j}] — should be distinct"
                );
            }
        }

        // None should be all-zero
        for r in &roots[1..] {
            // skip empty (index 0)
            assert_ne!(*r, Hash256::ZERO);
        }
    }

    /// Postorder heights at positions 1..=15 — pinned against the
    /// canonical reference table. Catches any regression in the
    /// Grin-derived `node_height` derivation.
    #[test]
    fn node_height_matches_postorder_table() {
        let expected: [u32; 15] = [0, 0, 1, 0, 0, 1, 2, 0, 0, 1, 0, 0, 1, 2, 3];
        for (i, &h) in expected.iter().enumerate() {
            let pos = (i as u64) + 1;
            assert_eq!(
                node_height(pos),
                h,
                "node_height({pos}) expected {h}, got {}",
                node_height(pos)
            );
        }
    }

    #[test]
    fn peak_positions_single_leaf() {
        let peaks = peak_positions(1);
        assert_eq!(peaks.len(), 1);
    }

    #[test]
    fn peak_positions_two_leaves() {
        let peaks = peak_positions(2);
        assert_eq!(peaks.len(), 1); // two leaves merge into one peak
    }

    #[test]
    fn peak_positions_three_leaves() {
        let peaks = peak_positions(3);
        assert_eq!(peaks.len(), 2); // one 2-tree peak + one leaf peak
    }

    #[test]
    fn peak_position_domain_boundary_is_explicit() {
        let largest_single_peak = peak_positions_fixed(1u64 << 63).expect("single peak fits");
        assert_eq!(largest_single_peak.as_slice(), &[u64::MAX]);
        assert!(
            peak_positions_fixed((1u64 << 63) + 1).is_none(),
            "a second peak after u64::MAX must fail instead of wrapping"
        );
    }

    #[test]
    fn bagging_is_not_commutative() {
        let h1 = Hash256::from_bytes([0x11u8; 32]);
        let h2 = Hash256::from_bytes([0x22u8; 32]);
        let forward = bag_peaks(&[h1, h2]);
        let reverse = bag_peaks(&[h2, h1]);
        assert_ne!(forward, reverse);
    }

    #[test]
    fn leaf_count_increments() {
        let mut pmmr = Pmmr::new();
        assert_eq!(pmmr.leaf_count(), 0);
        pmmr.push(b"x").unwrap();
        assert_eq!(pmmr.leaf_count(), 1);
        pmmr.push(b"y").unwrap();
        assert_eq!(pmmr.leaf_count(), 2);
    }

    /// `set_node` MUST reject any attempt to overwrite an already-set
    /// position. The MMR is append-only; silent overwrite is a
    /// consensus-class corruption primitive (it would rewrite committed
    /// history without changing the leaf count), so the internal guard
    /// is exercised here directly via the privileged crate-local view.
    #[test]
    fn set_node_overwrite_is_rejected() {
        let mut pmmr = Pmmr::new();
        pmmr.push(b"a").unwrap();
        // Position 1 is now occupied by the first leaf hash.
        let attempt = pmmr.set_node(1, Hash256::ZERO);
        assert!(
            attempt.is_err(),
            "set_node must refuse to overwrite an already-populated MMR position"
        );

        // Push a second leaf — that runs merge_peaks which writes
        // position 3 (the parent). Re-attempting overwrite at 3 must
        // also be rejected.
        pmmr.push(b"b").unwrap();
        let attempt2 = pmmr.set_node(3, Hash256::ZERO);
        assert!(
            attempt2.is_err(),
            "set_node must refuse to overwrite an internal node either"
        );
    }
}

// ── dom-shield internal probes ───────────────────────────────────────────────
//
// These tests exercise PRIVATE arithmetic (`node_height`, `peak_positions`)
// and a PRIVATE-field corruption (`nodes`) that is not reachable through the
// public push/root surface. They live in-crate because the targeted surfaces
// are crate-private by design. No production logic is modified.
#[cfg(test)]
mod shield_internal_probes {
    use super::*;

    // ── Clean-room references (independent of the production algorithm) ───────

    /// Reference postorder height by repeated binary "peel": subtract the
    /// size of the most-significant complete level (2^(msb-1) - 1) until
    /// the position is all-ones, then height = msb - 1. Distinct in form
    /// from `node_height`'s `jump_left` loop, so a shared bug is unlikely.
    fn ref_height(mut pos: u64) -> u32 {
        assert!(pos > 0);
        let msb = |n: u64| -> u32 {
            if n == 0 {
                0
            } else {
                64 - n.leading_zeros()
            }
        };
        let all_ones = |n: u64| -> bool { n != 0 && (n + 1).is_power_of_two() };
        while !all_ones(pos) {
            let m = msb(pos);
            pos -= (1u64 << (m - 1)) - 1;
        }
        msb(pos) - 1
    }

    /// Reference peak positions from `leaf_count`'s binary popcount
    /// decomposition: for each set bit (MSB→LSB) accumulate the subtree
    /// node size (2*2^bit - 1) and record the running offset as the peak
    /// position. Independent of `peak_positions`'s loop structure.
    fn ref_peak_positions(n: u64) -> Vec<u64> {
        if n == 0 {
            return vec![];
        }
        let mut v = Vec::new();
        let mut off = 0u64;
        for bit in (0..64).rev() {
            if (n >> bit) & 1 == 1 {
                off += 2 * (1u64 << bit) - 1;
                v.push(off);
            }
        }
        v
    }

    // ── proptest-invariante: node_height vs reference (DOM-PMMR-001 class) ────

    /// `node_height(pos)` must match the independent postorder reference
    /// for every position in 1..=4096. DOM-PMMR-001 was an inflated
    /// height at odd positions; this pins the whole table, not just 1..15.
    #[test]
    fn node_height_matches_reference_to_4096() {
        for pos in 1u64..=4096 {
            assert_eq!(
                node_height(pos),
                ref_height(pos),
                "node_height({pos}) diverged from postorder reference"
            );
        }
    }

    /// Spot-check large positions far from the small table, including the
    /// all-ones perfect-tree roots (2^k - 1) where height == k - 1.
    #[test]
    fn node_height_perfect_tree_roots() {
        for k in 1u32..=40 {
            let pos = (1u64 << k) - 1; // all-ones => perfect-tree root
            assert_eq!(node_height(pos), k - 1, "all-ones pos={pos} height");
            assert_eq!(node_height(pos), ref_height(pos));
        }
    }

    // ── proptest-invariante: peak_positions vs binary popcount ───────────────

    /// `peak_positions(n)` must equal the binary-popcount reference for
    /// every n in 0..=4096. Also checks the count equals popcount(n) and
    /// the positions are strictly increasing (left-to-right order).
    #[test]
    fn peak_positions_matches_popcount_reference_to_4096() {
        for n in 0u64..=4096 {
            let got = peak_positions(n);
            let want = ref_peak_positions(n);
            assert_eq!(got, want, "peak_positions({n}) diverged from reference");
            assert_eq!(
                got.len() as u32,
                n.count_ones(),
                "peak count must equal popcount({n})"
            );
            for w in got.windows(2) {
                assert!(w[0] < w[1], "peak positions must be strictly increasing");
            }
        }
    }

    // ── directed-corruption / GUARD FIX-021 (RESOLVED) ───────────────────────
    //
    // `root()` previously collected peak hashes with
    // `filter_map(|p| self.get_node(p))`, which SILENTLY DROPPED any peak whose
    // node was missing instead of erroring. A fresh `Pmmr` built via `push`
    // always has every peak present, so this was unreachable through the public
    // API; it would have become reachable the moment pruning (which removes
    // nodes) was added — producing a root indistinguishable from a smaller,
    // legitimately-shaped PMMR (forged-inclusion / hidden-history primitive).
    //
    // FIX-021 fix: `root()` now returns `Result` and refuses (Err) to compute
    // over an incomplete peak set, mirroring the `set_node` overwrite guard.
    // Consensus-neutral: every reachable PMMR (built fresh per block) has all
    // peaks present, so production roots are unchanged. The guard below
    // constructs the would-be-pruned state directly via the crate-private
    // `nodes` field and asserts the fail-closed behavior.

    /// FIX-021 guard (RESOLVED). `root()` must REFUSE to compute over an
    /// incomplete peak set instead of silently dropping a missing (e.g.
    /// pruned) peak and returning a forged-shape root. This was a RED
    /// `#[ignore]` reproducer; it is now an active green guard because
    /// `root()` returns `Err` on a missing peak.
    #[test]
    fn fix021_root_refuses_incomplete_peak_set() {
        // Build a 3-leaf PMMR: peaks at positions [3, 4] (a merged
        // subtree at 3 and a lone leaf at 4).
        let mut pmmr = Pmmr::new();
        pmmr.push(b"a").unwrap();
        pmmr.push(b"b").unwrap();
        pmmr.push(b"c").unwrap();

        let positions = peak_positions(pmmr.leaf_count());
        assert_eq!(
            positions,
            vec![3, 4],
            "precondition: 3-leaf peaks are [3,4]"
        );

        // A complete PMMR computes a root fine.
        assert!(pmmr.root().is_ok(), "complete 3-leaf PMMR must have a root");

        // Simulate a pruned node: drop the LONE leaf peak at position 4.
        // (Direct private-field manipulation — exactly the state a future
        //  pruning pass would create; no public API can reach it today.)
        let mut pruned = pmmr.clone();
        pruned.nodes[4] = None;
        assert!(pruned.get_node(4).is_none(), "peak 4 is now missing");

        // FIX-021 fix: a PMMR that has lost a peak it still claims
        // (leaf_count unchanged => peak_positions still yields position 4)
        // MUST NOT silently produce a well-formed root. `root()` now returns
        // Err rather than bagging the surviving peaks into a forged-shape root.
        assert!(
            pruned.root().is_err(),
            "FIX-021: root() must refuse to compute over an incomplete peak \
             set (missing peak 4), not silently drop it into a forged-shape root"
        );
    }
}

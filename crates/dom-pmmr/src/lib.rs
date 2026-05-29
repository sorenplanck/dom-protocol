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
fn peak_positions(leaf_count: u64) -> Vec<u64> {
    if leaf_count == 0 {
        return vec![];
    }

    let mut peaks = Vec::new();
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
            let subtree_size = subtree_leaves
                .checked_mul(2)
                .and_then(|x| x.checked_sub(1))
                .expect("subtree size overflow");
            let peak_pos = pos_offset
                .checked_add(subtree_size)
                .expect("peak position overflow");
            peaks.push(peak_pos);
            pos_offset = pos_offset
                .checked_add(subtree_size)
                .expect("pos_offset overflow");
            remaining = remaining
                .checked_sub(subtree_leaves)
                .expect("remaining underflow");
        }
        if bit == 0 {
            break;
        }
        bit -= 1;
    }

    peaks
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
    pub fn root(&self) -> Hash256 {
        let positions = peak_positions(self.leaf_count);
        let peak_hashes: Vec<Hash256> =
            positions.iter().filter_map(|&p| self.get_node(p)).collect();
        bag_peaks(&peak_hashes)
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
        let r1 = pmmr.root();
        let r2 = pmmr.root();
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
        assert_eq!(pmmr.root(), expected);
    }

    /// Root changes when leaf is added.
    #[test]
    fn root_changes_on_append() {
        let mut pmmr = Pmmr::new();
        let r0 = pmmr.root();
        pmmr.push(b"leaf0").unwrap();
        let r1 = pmmr.root();
        assert_ne!(r0, r1);
        pmmr.push(b"leaf1").unwrap();
        let r2 = pmmr.root();
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
            p.root()
        };
        let root2 = {
            let mut p = Pmmr::new();
            for l in &leaves {
                p.push(l).unwrap();
            }
            p.root()
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
            roots.push(pmmr.root());
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

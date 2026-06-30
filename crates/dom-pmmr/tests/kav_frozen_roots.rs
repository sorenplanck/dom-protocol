//! KAV-drift-congelado / KAV-conformância + XDIFF for dom-pmmr (RFC-0004).
//!
//! Subfamily: frozen known-answer vectors for `Pmmr::root()` over the
//! consensus-mandated leaf counts {0,1,2,3,4,7,8,15,16}.
//!
//! The expected roots are NOT captured from this crate's own output.
//! They were derived by an INDEPENDENT clean-room reference implementing
//! the Grin MMR postorder algorithm (bag-of-mountains stack simulation)
//! plus the RFC-0004 wire format:
//!
//!   tagged(tag, data) = Blake2b256( u16_le(tag.len()) || tag || data )
//!   leaf_hash(pos, payload) = tagged("DOM:pmmr-leaf:v1", u64_le(pos) || payload)
//!   node_hash(pos, l, r)    = tagged("DOM:pmmr-node:v1", u64_le(pos) || l || r)
//!   bag (>=2 peaks, right-to-left): acc = last_peak;
//!       for p in rev(peaks[..last]): acc = tagged("DOM:pmmr-bag:v1", p || acc)
//!   empty root = tagged("DOM:pmmr-empty:v1", "")
//!
//! Because the reference is a separate implementation, these vectors
//! double as a cross-implementation differential (XDIFF) against a
//! Grin-derived spec. Any future drift in tag bytes, position encoding
//! (LE), peak ordering, or bagging fold direction will flip a vector.
//!
//! Payload convention for the frozen set: leaf i (0-based) carries
//! `(i as u64).to_le_bytes()` — byte-identical to the in-source
//! `required_vectors_are_stable` payloads (`i.to_le_bytes()`, i: usize,
//! 8 bytes on a 64-bit target), but here pinned to EXACT root bytes
//! rather than mere pairwise-distinctness.

use dom_pmmr::{bag_peaks, leaf_hash, node_hash, Pmmr};

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn pmmr_root(n: u64) -> [u8; 32] {
    let mut pmmr = Pmmr::new();
    for i in 0..n {
        pmmr.push(&i.to_le_bytes()).expect("push");
    }
    *pmmr.root().unwrap().as_bytes()
}

/// Frozen roots derived from the clean-room Grin-postorder reference.
const FROZEN: &[(u64, &str)] = &[
    (
        0,
        "4af723a9c80c18bbb3f064a0268049dffb15a1e7c4c7fa5e8062ebbb61f532f0",
    ),
    (
        1,
        "d7834b348a8e70f74fe0f71c3314f21252d92569bc2d501c78ee958bfe42df1e",
    ),
    (
        2,
        "34ed1c907c3daea3e72dec770a6b1fcfe9b5fc22975a047872f0791acd898576",
    ),
    (
        3,
        "d73d551a0b06ed3e01816503029245061cf0297b12d6703407f73474cdebb2fe",
    ),
    (
        4,
        "d65c11f3f96bc9b9014444698709e55a5925f97608505b6302a464994b7def58",
    ),
    (
        7,
        "4bd0ca87a4b3c45086d0978fba30e44f3fbd2768ba0d909d1ff262c5d5698191",
    ),
    (
        8,
        "d86f63309c5f2cebe71f230af0737aee38d7059114aeb49339cb302ea4e33282",
    ),
    (
        15,
        "265c0a884d2f22a3ebd89e6e3e959571648f96cc9324248efc8012f7d6e1ddcd",
    ),
    (
        16,
        "70660b13b900c86b443a72b7d5f29519de53350b7bd02484ee85bebaab414094",
    ),
];

/// KAV: every frozen vector must match `Pmmr::root()` byte-for-byte.
#[test]
fn frozen_roots_match_clean_room_reference() {
    for &(n, expected) in FROZEN {
        let got = hex(&pmmr_root(n));
        assert_eq!(
            got, expected,
            "n={n}: Pmmr::root() drifted from the Grin-derived clean-room \
             reference root. If this is an intentional consensus change, the \
             frozen vector and RFC-0004 MUST be updated together (HUMAN DECISION)."
        );
    }
}

/// XDIFF: the empty-PMMR root must equal the clean-room
/// `tagged("DOM:pmmr-empty:v1", "")` digest exactly.
#[test]
fn empty_root_matches_reference_byte_for_byte() {
    let empty = hex(&pmmr_root(0));
    assert_eq!(
        empty, "4af723a9c80c18bbb3f064a0268049dffb15a1e7c4c7fa5e8062ebbb61f532f0",
        "empty root diverged from tagged(DOM:pmmr-empty:v1, \"\")"
    );
}

/// XDIFF: the full preimage chain for n=3 (two peaks: node(3) + leaf(4),
/// then a right-to-left bag). Pins the exact intermediate byte
/// encodings — leaf/node tag-length prefix, position LE, and the bag
/// fold order — against the reference. A subtle endianness flip or a
/// left-to-right fold would change `root3` while leaving the
/// distinctness-only tests green.
#[test]
fn n3_preimage_chain_matches_reference() {
    let l1 = leaf_hash(1, &0u64.to_le_bytes());
    let l2 = leaf_hash(2, &1u64.to_le_bytes());
    let n3 = node_hash(3, &l1, &l2);
    let l4 = leaf_hash(4, &2u64.to_le_bytes());

    assert_eq!(
        hex(l1.as_bytes()),
        "d7834b348a8e70f74fe0f71c3314f21252d92569bc2d501c78ee958bfe42df1e",
        "leaf1"
    );
    assert_eq!(
        hex(l2.as_bytes()),
        "d0ff96eae57a3d23efce7f321691ac4b43eaf6562db7c2fbcd416d7d49457af6",
        "leaf2"
    );
    assert_eq!(
        hex(n3.as_bytes()),
        "34ed1c907c3daea3e72dec770a6b1fcfe9b5fc22975a047872f0791acd898576",
        "node3"
    );
    assert_eq!(
        hex(l4.as_bytes()),
        "f6467b126a77c09afe61f92b5a3d1f6aa8e00bdac071cdae443a02801db159c4",
        "leaf4"
    );

    // Right-to-left bag of [node3, leaf4].
    let root3 = bag_peaks(&[n3, l4]);
    assert_eq!(
        hex(root3.as_bytes()),
        "d73d551a0b06ed3e01816503029245061cf0297b12d6703407f73474cdebb2fe",
        "n=3 bagged root diverged from reference (fold direction / tag bytes)"
    );

    // And the full Pmmr must reach the same root.
    assert_eq!(
        hex(&pmmr_root(3)),
        hex(root3.as_bytes()),
        "Pmmr n=3 != reconstructed n=3"
    );
}

/// XDIFF: bag fold direction is right-to-left ONLY. Re-deriving the
/// n=3 root with a LEFT-to-right fold MUST produce a DIFFERENT value,
/// proving the production path is not silently order-agnostic.
#[test]
fn bag_fold_is_right_to_left_only() {
    let n3_root = bag_peaks(&[
        leaf_hash(99, b"x"), // arbitrary distinct hashes
        leaf_hash(100, b"y"),
        leaf_hash(101, b"z"),
    ]);
    // Left-to-right manual fold of the same three peaks.
    let p = [
        leaf_hash(99, b"x"),
        leaf_hash(100, b"y"),
        leaf_hash(101, b"z"),
    ];
    let mut acc = p[0];
    for next in &p[1..] {
        let mut d = Vec::new();
        d.extend_from_slice(acc.as_bytes());
        d.extend_from_slice(next.as_bytes());
        acc = dom_crypto::hash::blake2b_256_tagged(dom_core::TAG_PMMR_BAG, &d);
    }
    assert_ne!(
        hex(n3_root.as_bytes()),
        hex(acc.as_bytes()),
        "left-to-right fold collided with bag_peaks — fold direction is not enforced"
    );
}

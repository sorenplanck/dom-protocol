# DOM RFC-0004 — Pruned Merkle Mountain Range (PMMR) Hardening

Status: **Normative**
Supersedes: the prior informal PMMR notes referenced from RFC-0007 / RFC-0011 §1
Depends on: RFC-0000, RFC-0007, RFC-0011

---

## Motivation

DOM commits to three PMMR roots in every block header (`output_root`,
`kernel_root`, `rangeproof_root`). A PMMR layout bug is consensus-class: two
implementations that disagree on leaf positions, peak ordering, or bagging
direction will fork on the very first non-trivial block.

This RFC pins the complete layout the protocol actually runs after the
DOM-PMMR-001 fix (commit `bcd59ad`). It is the source-of-truth that the
reference implementation (`dom-pmmr`) and any independent re-implementation
must agree on byte-for-byte.

It also documents the DOM-PMMR-001 bug class so future audits have a record of
what was wrong and why the chosen fix is correct.

---

## 1. Position Arithmetic

The PMMR uses 1-indexed postorder positions. Leaves and internal nodes share a
single monotonically increasing numbering — there is no separate leaf index.

### 1.1 Leaf Positions

For the n-th leaf appended to the MMR (1-indexed), its postorder position is:

```
leaf_pos(n) = 2*n - 1 - popcount(n - 1)
```

Equivalently, given `nodes_before(n) = 2*(n-1) - popcount(n-1)` total nodes already
present before the n-th `push`, the new leaf is placed at:

```
leaf_pos(n) = nodes_before(n) + 1
```

Reference table for the first 16 leaves:

```
i  : 1  2  4  5  8  9 11 12 16 17 19 20 23 24 26 27
```

Powers of two are **parent** positions and MUST NEVER appear as leaf positions
once at least one merge has occurred.

### 1.2 Postorder Height

The height of the node at position `pos` is the depth of the perfect binary
subtree it roots, with leaves at height 0. The canonical Grin algorithm:

```
function node_height(pos):
    if pos == 0:
        return 0
    h = pos
    while !is_all_ones(h):              # h is of the form 2^k - 1
        h = jump_left(h)                # subtract (2^(msb - 1) - 1)
    return msb_pos(h) - 1
```

where `is_all_ones(n)` is true iff `n != 0` and `n + 1` is a non-zero power of
two, and `jump_left(pos) = pos - (2^(msb_pos(pos) - 1) - 1)`.

Reference table for positions 1..=15:

```
pos    : 1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
height : 0  0  1  0  0  1  2  0  0  1  0  0  1  2  3
```

**Non-normative implementation note.** `pos.trailing_ones()` is **not** a valid
substitute for `node_height(pos)` — that shortcut is what produced the
DOM-PMMR-001 silent-mutation bug; see §6.

### 1.3 Peak Positions

For a PMMR with `n` leaves, the peak positions are derived from the binary
expansion of `n` from the most significant bit down. Each set bit at position
`k` contributes one peak rooted at the postorder position immediately after
the cumulative subtree size:

```
function peak_positions(n):
    if n == 0: return []
    peaks = []
    offset = 0
    for bit in (63, 62, ..., 0):
        subtree_leaves = 1 << bit
        if subtree_leaves <= remaining(n, peaks):
            subtree_size = 2*subtree_leaves - 1
            peak_pos = offset + subtree_size
            peaks.append(peak_pos)
            offset += subtree_size
    return peaks
```

`peak_positions(n).len() == popcount(n)`. Peaks are listed left-to-right (older
peaks first).

---

## 2. Hashing

All PMMR hashing uses `Blake2b-256` with a length-prefixed tag domain. The
length prefix is `u16_le(len(tag))`.

### 2.1 Domain Tags

```
TAG_PMMR_LEAF  = "DOM:pmmr-leaf:v1"
TAG_PMMR_NODE  = "DOM:pmmr-node:v1"
TAG_PMMR_BAG   = "DOM:pmmr-bag:v1"
TAG_PMMR_EMPTY = "DOM:pmmr-empty:v1"
```

### 2.2 Leaf Hash

```
leaf_hash(pos, payload) =
    Blake2b-256( u16_le(len(TAG_PMMR_LEAF))   ||
                 TAG_PMMR_LEAF                  ||
                 pos_le8                        ||
                 payload )
```

`pos_le8` is the 8-byte little-endian encoding of the leaf's postorder position
(NOT a leaf index).

### 2.3 Internal Node Hash

```
node_hash(pos, left, right) =
    Blake2b-256( u16_le(len(TAG_PMMR_NODE))   ||
                 TAG_PMMR_NODE                  ||
                 pos_le8                        ||
                 left[32]                       ||
                 right[32] )
```

### 2.4 Bagging (Right-to-Left Fold)

For peaks listed left-to-right `[p_0, p_1, ..., p_{k-1}]`:

```
if k == 0:
    root = Blake2b-256( u16_le(len(TAG_PMMR_EMPTY)) || TAG_PMMR_EMPTY || ε )
elif k == 1:
    root = p_0
else:
    acc = p_{k-1}
    for j in (k-2, k-3, ..., 0):
        acc = Blake2b-256( u16_le(len(TAG_PMMR_BAG)) || TAG_PMMR_BAG ||
                           p_j[32] || acc[32] )
    root = acc
```

The fold is **right-to-left**. The left peak is the older peak; the right
accumulator is the newer side. Any reversal is consensus-invalid.

---

## 3. Append Algorithm

```
function push(pmmr, payload):
    n = pmmr.leaf_count + 1
    nodes_before = 2*(n-1) - popcount(n-1)
    pos = nodes_before + 1
    pmmr[pos] = leaf_hash(pos, payload)
    merge_peaks(pmmr, pos)
    pmmr.leaf_count = n
```

`merge_peaks` walks upwards, merging two adjacent same-height peaks into a
parent at the position immediately to the right:

```
function merge_peaks(pmmr, pos):
    loop:
        h = node_height(pos)
        subtree_size = 2^(h+1) - 1
        if pos <= subtree_size: break             # no left sibling
        left_pos = pos - subtree_size
        if node_height(left_pos) != h: break      # heights don't match
        parent_pos = pos + 1
        pmmr[parent_pos] = node_hash(parent_pos, pmmr[left_pos], pmmr[pos])
        pos = parent_pos
```

The MMR is append-only. Writing to a position that already holds a hash is
consensus-class corruption and MUST be rejected. The reference implementation
returns `DomError::Internal("PMMR invariant violated: attempt to overwrite
node at position N")` for this case.

---

## 4. Block-Level PMMR Layout

Each block commits three PMMRs:

* **Output MMR** — one leaf per output (coinbase output first, then per-tx
  outputs in `Block.transactions` order). Payload = the 33-byte SEC1
  commitment.
* **Kernel MMR** — one leaf per kernel (coinbase kernel first, then per-tx
  kernels in `Block.transactions` order). Payload = the 33-byte SEC1 excess
  commitment.
* **Rangeproof MMR** — one leaf per output (same order as the Output MMR).
  Payload = the variable-length Bulletproofs proof bytes.

The single source of truth for this iteration order is
`dom_consensus::compute_block_pmmr_roots(coinbase, &transactions)`. Both
`validate_pmmr_roots` and the miner call that helper; any drift between them
is structurally impossible.

---

## 5. Test Vectors (Canonical)

For leaf counts 0, 1, 2, 3, 4, 7, 8, 15, 16 with payload `i.to_le_bytes()`
for the i-th leaf (0-indexed):

```
leaves= 0: 4af723a9c80c18bbb3f064a0268049dffb15a1e7c4c7fa5e8062ebbb61f532f0
leaves= 1: d7834b348a8e70f74fe0f71c3314f21252d92569bc2d501c78ee958bfe42df1e
leaves= 2: 34ed1c907c3daea3e72dec770a6b1fcfe9b5fc22975a047872f0791acd898576
leaves= 3: d73d551a0b06ed3e01816503029245061cf0297b12d6703407f73474cdebb2fe
leaves= 4: d65c11f3f96bc9b9014444698709e55a5925f97608505b6302a464994b7def58
leaves= 7: 4bd0ca87a4b3c45086d0978fba30e44f3fbd2768ba0d909d1ff262c5d5698191
leaves= 8: d86f63309c5f2cebe71f230af0737aee38d7059114aeb49339cb302ea4e33282
leaves=15: 265c0a884d2f22a3ebd89e6e3e959571648f96cc9324248efc8012f7d6e1ddcd
leaves=16: 70660b13b900c86b443a72b7d5f29519de53350b7bd02484ee85bebaab414094
```

These hex roots are enforced by
`dom-test-vectors::pmmr_vectors::tests::vectors_match_pinned_hex`. Any
deliberate change to PMMR layout requires regenerating the vectors AND a
fork-class protocol bump.

---

## 6. Bug History — DOM-PMMR-001 (Silent Leaf Mutation)

### 6.1 Symptom

The pre-fix implementation reduced `root()` for any multi-leaf MMR to a single
peak hash that depended only on the latest leaf payload. Concretely, for a
PMMR with `n ≥ 2` leaves the root was effectively
`leaf_hash(broken_last_pos, last_payload)` (n = 2) or a single peak that
ignored most of the inner leaves (n ≥ 3). Mutating any non-last leaf left the
root unchanged. This is a direct chainstate-forgery primitive: any block
producer could rewrite the committed UTXO / kernel set without disturbing the
header roots.

### 6.2 Root Causes

Two collaborating defects:

1. **`node_height` used `pos.trailing_ones()` directly.** Postorder height is
   not trailing-ones; it is the most-significant-bit position after the
   `jump_left` loop (§1.2). Heights at positions 1, 3, 5, 7, … came out one
   too high, so the equal-height check inside `merge_peaks` always failed and
   every merge was suppressed.

2. **`push` placed each fresh leaf at the *post*-insert node count.** The new
   leaf was hashed at the position the parent should have lived at, and the
   merge that should have run on top of it was suppressed by defect (1).

The two defects compounded into a clean reproducer:
`crates/dom-pmmr/tests/silent_mutation_reproducer.rs`.

### 6.3 Fix Approach

The fix follows Grin's reference postorder layout (the same arithmetic the
broader MMR literature uses):

* `node_height(pos)` walks `jump_left` until `is_all_ones(h)` then returns
  `msb_pos(h) - 1`.
* `push` computes `leaf_pos = nodes_before(n) + 1` from the *pre*-insert leaf
  count.
* `set_node` rejects any attempt to overwrite an already-populated MMR
  position with an explicit invariant-violation error.

### 6.4 Validation Evidence

* `dom-pmmr/tests/silent_mutation_reproducer.rs` — Phase A deterministic
  reproducer (commit `596ba5c`) covering every-leaf mutation, hand-computed
  2-/3-/4-leaf roots, canonical postorder positions, empty-vs-populated
  distinctness.
* `dom-pmmr/tests/adversarial_suite.rs` — Phase D independent recursive
  oracle, peak-boundary sweeps to n=2^10, 32× reconstruction determinism,
  proptest-driven mutation / ordering / cross-impl checks (commit `91f78ed`).
* `dom-pmmr/src/lib.rs::tests` — `node_height_matches_postorder_table` pins
  the canonical postorder table; `set_node_overwrite_is_rejected` exercises
  the corruption guard (commit `bcd59ad`).
* `dom-consensus/src/lib.rs::tests` — `validate_pmmr_roots_*` and
  `compute_block_pmmr_roots_*` pin the miner / validator contract
  (commit `151acbe`).
* `dom-test-vectors/src/pmmr_vectors.rs::tests::vectors_match_pinned_hex` —
  pinned RFC-0004 root hex (commit `2994048`).

---

## 7. Deferred Gaps

The following PMMR-class validation items are not yet executable on the
current single-VPS environment and are tracked in `docs/RELEASE_BLOCKERS.md`:

* **Cross-platform deterministic roots** — Linux x86_64 vs Windows vs macOS
  vs ARM64 reproduction. Requires Phase 1.4 GitHub Actions matrix.
* **Interrupted-flush / partial-persistence equivalence (PMMR-specific)** —
  the Phase 3.2 observable contract covers store-level partial persistence;
  a dedicated PMMR-level harness (kill mid-`commit_block` and reopen) is not
  yet wired.
* **Replay-after-restart and replay-after-reorg equivalence on the new
  algorithm** — `replay_determinism` was authored before Phase B; rerunning
  against the fixed implementation requires a dedicated long-mining host
  (RandomX FULL_MEM dataset init ≈ 150 s per block on the current VPS).

These gaps are uncertainty-tracked deferrals, not closed items.

---

## 8. References

* Grin's reference implementation: `core/src/core/pmmr/pmmr.rs` (BSD-3). The
  index arithmetic above mirrors Grin's; only the wire-level hashing diverges
  (DOM uses length-prefixed tag domains over Blake2b-256, Grin uses BLAKE2b
  with a different domain encoding).
* RFC-0007 §10 — PMMR update during block validation.
* RFC-0011 §1 — peak bagging algorithm (this RFC supersedes the brief
  reference there with the complete normative spec).

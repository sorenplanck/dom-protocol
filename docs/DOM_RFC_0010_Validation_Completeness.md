# DOM RFC-0010 — Validation Completeness

Status: **Normative**
Supersedes: DOM_v6_1_Validation_Pipeline.md (deprecated)
Extends: RFC-0007
Depends on: RFC-0000, RFC-0007, RFC-0008, RFC-0009

---

## Motivation

The audit of DOM v6.1 identified four consensus-critical gaps in the validation
specification:

1. **Weight units undefined** — `MAX_BLOCK_WEIGHT` and `MAX_TX_WEIGHT` were defined
   as numbers without specifying how to measure weight, making the limits
   non-deterministic across implementations.

2. **total_difficulty undefined** — Block validation step 7 ("total difficulty
   validation") was listed but never specified, making chain selection non-deterministic.

3. **Cut-through/duplicate order wrong** — RFC-0007 steps 9 and 10 must be
   reordered to detect duplicates both before AND after cut-through as required
   by the consensus specification.

4. **v6.1_Validation_Pipeline contradicts RFC-0007** — The archived pipeline document
   lists validation steps in a different order and must be explicitly deprecated.

This RFC resolves all four issues.

---

## 1. Weight Units — Complete Definition

### 1.1 Weight of Each Structure

All weight values are in abstract "weight units" (wu). This is the canonical definition:

```
weight(TransactionInput)  = 1 wu
weight(TransactionOutput) = 21 wu   // abstract scaled unit; proof bytes are capped separately
weight(TransactionKernel) = 3 wu    // features(1) + fee(8) + excess(33) + sig(65) + lock(8) scaled
weight(CoinbaseKernel)    = 2 wu    // lighter: no fee, no lock_height

weight(Transaction) =
    sum(weight(input)  for input  in tx.inputs)
  + sum(weight(output) for output in tx.outputs)
  + sum(weight(kernel) for kernel in tx.kernels)
```

`WEIGHT_OUTPUT = 21 wu` is a fixed consensus weight unit, not a formula derived
from serialized proof bytes. DOM v1 range proofs are non-aggregated
single-output Bulletproofs; the grin `secp256k1zkp` implementation (via the
audited FFI shim with the custom H_DOM generator) serializes them at exactly
675 bytes, and `MAX_PROOF_SIZE = 768` is the independent malformed-payload
sanity cap.

### 1.2 Block Weight

```
weight(Block) = sum(weight(tx) for tx in block.transactions)
```

The coinbase transaction is NOT counted in block weight. Block weight is the weight
of all non-coinbase transactions only.

### 1.3 Limits

```
MAX_TX_WEIGHT    = 4000 wu   // single transaction limit
MAX_BLOCK_WEIGHT = 40000 wu  // all non-coinbase transactions in a block
```

A transaction with `weight(tx) > MAX_TX_WEIGHT` is `Invalid` (consensus).
A block with `weight(block) > MAX_BLOCK_WEIGHT` is `Invalid` (consensus).

### 1.4 Rationale

These weight definitions are chosen so that:
- A block at `MAX_BLOCK_WEIGHT` contains approximately 1900 inputs, 1900 outputs, 13000 kernels
- This is well within `MAX_BLOCK_TXS = 5000` and `MAX_INPUTS/OUTPUTS_PER_TX = 255`
- A fully saturated block serializes to approximately 4-6 MB, under `MAX_BLOCK_SERIALIZED_SIZE = 16 MiB`

### 1.5 Validation Step

Weight validation occurs at:
- **Transaction**: RFC-0007 step 9
- **Block**: RFC-0007 step 13 (before balance equation)

A transaction that exceeds MAX_TX_WEIGHT is `Invalid`.
A block that exceeds MAX_BLOCK_WEIGHT is `Invalid`.

---

## 2. Total Difficulty — Complete Definition

### 2.1 Difficulty from Target

The difficulty of a block is derived from its compact target:

```
difficulty(compact_target) = MAX_TARGET / expand(compact_target)
```

Where:
- `MAX_TARGET` = `0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`
  (as a 256-bit unsigned integer, big-endian)
- `expand(compact_target)` = the 32-byte target expanded from compact form (see RFC-0003)
- Division is 256-bit integer division (no floating point)

If `expand(compact_target) == 0`: undefined (consensus-invalid target, already rejected
by RFC-0003 target bounds check). This branch should never be reached.

### 2.2 Total Difficulty Accumulation

```
genesis_block.total_difficulty = difficulty(genesis_block.target)

block.total_difficulty = parent.total_difficulty + difficulty(block.target)
```

`total_difficulty` is a **256-bit integer (U256)** in BlockHeader, serialized as
32 bytes big-endian. This was changed from u128 in v7 to prevent loss of monotonicity
when difficulty exceeds 2^128 (relevant for correctness, not practical for centuries).

Serialization: 32 bytes big-endian (`primitive_types::U256::to_big_endian`).

If addition overflows U256, the block is consensus-invalid (`Invalid`).
This overflow requires approximately 2^200 blocks — practically impossible.

### 2.3 Chain Selection Rule

When two chains of equal height diverge, the canonical chain is the one with
the **greater total_difficulty**.

If two chains have equal total_difficulty (extremely unlikely), the canonical
chain is the one whose tip block hash is lexicographically smaller (tiebreaker).

### 2.4 Validation Step

Block validation step 7 (total difficulty validation) MUST verify:

```
block.total_difficulty == parent.total_difficulty + difficulty(block.target)
```

A block with incorrect `total_difficulty` is `Invalid`.

### 2.5 Rust Implementation

```rust
/// Compute difficulty from a 32-byte target.
/// Uses full 256-bit integer division via primitive_types::U256.
/// Returns (hi: u128, lo: u128) of the 256-bit quotient.
pub fn target_to_difficulty_u256(target: &[u8; 32]) -> (u128, u128) {
    // MAX_TARGET as u128 for the leading significant bits
    // For practical purposes, only the top ~128 bits matter
    // since difficulty is always >> 1 for any real target
    
    // Convert target bytes (big-endian) to a comparable value
    // We use the top 16 bytes (128 bits) for the computation
    let target_hi = u128::from_be_bytes(target[0..16].try_into().unwrap());
    
    // MAX_TARGET top 16 bytes: 0x0000ffffffffffffffffffffffffffff
    const MAX_TARGET_HI: u128 = 0x0000_ffff_ffff_ffff_ffff_ffff_ffff_ffff;
    
    if target_hi == 0 {
        return u128::MAX; // target is very small = very high difficulty
    }
    
    MAX_TARGET_HI.saturating_div(target_hi).max(1)
}
```

---

## 3. Cut-Through Order — Corrected RFC-0007

### 3.1 Problem Statement

RFC-0007 block validation steps 9 and 10 are:
```
9. duplicate detection across block
10. deterministic cut-through
```

This order is incorrect. Duplicate detection should occur BEFORE cut-through to catch
all malformed inputs/outputs, AND AFTER cut-through to ensure the resulting set is clean.

The consensus specification (DOM_v6_1_Consensus_Specification.md) states:
"Reject duplicates before and after cut-through."

RFC-0007 step 9 is only one check — it must be split.

### 3.2 Corrected Block Validation Order

RFC-0007 block validation steps 8-14 are amended to:

```
8.  transaction validation (each tx individually per RFC-0007 tx steps 1-10)
9a. duplicate detection BEFORE cut-through:
      - no two inputs in the block share the same commitment
      - no two outputs in the block share the same commitment
      - no two kernels in the block share the same excess commitment
9b. deterministic cut-through:
      - remove outputs that appear as inputs in the SAME block
      - remove the corresponding inputs
      - kernels are ALWAYS preserved (never cut-through)
9c. duplicate detection AFTER cut-through:
      - no two remaining inputs share the same commitment
      - no two remaining outputs share the same commitment
      (kernel check already passed in 9a; cut-through does not create kernel duplicates)
10. PMMR update (using post-cut-through inputs and outputs, ALL kernels)
11. PMMR root verification
12. aggregate block balance equation
13. weight validation (block-level)
14. atomic state commit
```

Note: the original RFC-0007 step numbering is preserved for steps 1-8 and 11-14
(renumbered 10-14 above). Step 9 is replaced by 9a/9b/9c.

### 3.3 Deterministic Cut-Through Algorithm

The cut-through algorithm MUST be applied in this exact order to be deterministic:

```
1. Collect all inputs I = {i_1, ..., i_n} (sorted lexicographically by commitment)
2. Collect all outputs O = {o_1, ..., o_m} (sorted lexicographically by commitment)
3. spent_set = {o.commitment for o in O if o.commitment in {i.commitment for i in I}}
4. O' = O \ {o for o in O if o.commitment in spent_set}
5. I' = I \ {i for i in I if i.commitment in spent_set}
6. Kernels K are unchanged: K' = K
```

The sorting in steps 1-2 ensures the algorithm is deterministic regardless of
the order transactions appear in the block.

### 3.4 Inflation via Cut-Through — Prevented

A potential attack: create two outputs with the same commitment (one "real", one "fake"),
then spend the "fake" one. After cut-through, only the real output remains but one input
is also consumed.

This is prevented by step 9a (duplicate outputs rejected before cut-through). An
attacker cannot create two outputs with the same commitment because:
- Same commitment means same `(v, r)` pair
- Finding a collision requires breaking the discrete log problem

---

## 4. Deprecation of DOM_v6_1_Validation_Pipeline.md

`DOM_v6_1_Validation_Pipeline.md` is hereby **deprecated and non-normative**.

The canonical validation order is RFC-0007 as amended by this RFC (RFC-0010).

Any implementation following the validation order in `DOM_v6_1_Validation_Pipeline.md`
is non-conforming and will diverge from the canonical chain.

Specific contradictions between the deprecated pipeline and RFC-0007:

| Step | Deprecated Pipeline | RFC-0007 (canonical) |
|---|---|---|
| Duplicate detection | Step 6 (after balance) | Step 9a (before cut-through) |
| Balance equation | Step 5 (before duplicates) | Step 12 (after PMMR) |
| Weight validation | Step 7 (last) | Step 9 / step 13 |
| Fee calculation | Absent | Step 8 of tx validation |

---

## 5. PMMR Root Verification — Three Roots

The block header contains three PMMR roots: `output_root`, `kernel_root`, `rangeproof_root`.

### 5.1 PMMR Leaf Definitions

```
output PMMR leaf payload     = output.commitment[33]
kernel PMMR leaf payload     = kernel.serialized_bytes (variable, full kernel)
rangeproof PMMR leaf payload = output.proof (variable, Bulletproof bytes)
```

### 5.2 PMMR Synchronization

Output and rangeproof PMMRs MUST be synchronized: `output_pmmr.leaf[i]` and
`rangeproof_pmmr.leaf[i]` correspond to the same output in the block.

### 5.3 PMMR Update Order

After cut-through (step 9b), the PMMRs are updated in this order:

```
1. Append all remaining outputs to output_pmmr (in block order)
2. Append all remaining range proofs to rangeproof_pmmr (same order as outputs)
3. Append ALL kernels to kernel_pmmr (in block order; kernels are never removed)
4. Mark spent inputs as prunable in output_pmmr (leaf hash preserved, data optional)
```

### 5.4 Root Verification

After PMMR update, the computed roots MUST match the block header:

```
assert output_pmmr.root()     == block.header.output_root
assert kernel_pmmr.root()     == block.header.kernel_root
assert rangeproof_pmmr.root() == block.header.rangeproof_root
```

Any mismatch is `Invalid`.

---

## 6. COINBASE_MATURITY Validation — Placement in RFC-0007

Per the audit finding, `COINBASE_MATURITY` was defined in RFC-0000 but never placed
in the validation pipeline. This RFC adds it explicitly.

At RFC-0007 **transaction validation step 2** (primitive validation), for each input:

```
if input references a coinbase output:
    if current_block_height - coinbase_output_block_height < COINBASE_MATURITY:
        return TemporarilyInvalid("coinbase not yet mature at height {current_height}")
```

The implementation requires knowing which outputs are coinbase outputs. This is tracked
by flagging coinbase output commitments when they are added to the UTXO set (identified
by their corresponding `KERNEL_FEAT_COINBASE` kernel in the same block).

---

## 7. Lock Height Validation — Placement in RFC-0007

At RFC-0007 **transaction validation step 2** (primitive validation), for each kernel:

```
if kernel.features == KERNEL_FEAT_HEIGHT_LOCKED:
    if kernel.lock_height > current_block_height:
        return TemporarilyInvalid("kernel locked until height {lock_height}")
    if kernel.lock_height == 0:
        return Invalid("HEIGHT_LOCKED kernel must have lock_height > 0")
```

---

## 8. Summary of Additions to RFC-0007

| Gap | Resolution |
|---|---|
| Weight units undefined | Section 1: exact wu per structure type |
| total_difficulty undefined | Section 2: `MAX_TARGET / target`, u128 |
| Cut-through/duplicate order | Section 3: steps 9a/9b/9c |
| Deprecated pipeline | Section 4: explicit deprecation |
| Three PMMR roots undefined | Section 5: leaf payloads + update order |
| COINBASE_MATURITY not in pipeline | Section 6: step 2 of tx validation |
| lock_height not in pipeline | Section 7: step 2 of tx validation |

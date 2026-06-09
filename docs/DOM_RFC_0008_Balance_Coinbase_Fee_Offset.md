# DOM RFC-0008 — Balance Equation, Coinbase, Fee & Offset

Status: **Normative**
Supersedes: None
Depends on: RFC-0000, RFC-0001, RFC-0007

---

## Motivation

The audit of DOM v6.1 identified that the central Mimblewimble balance equation
was never fully specified. Three components were missing:

1. **Transaction fee** — how the declared fee in the kernel is enforced mathematically
2. **Kernel offset** — how the blinding-factor offset is accumulated and verified
3. **Coinbase** — how block rewards are committed without enabling silent inflation

Without these three components, the balance equation is incomplete and an
implementation would be vulnerable to silent inflation attacks.

This RFC is **consensus-critical**. Any deviation from the equations defined here
constitutes an invalid block.

---

## 1. The Complete Mimblewimble Balance Equation

### 1.1 Transaction Balance

For a valid transaction, the following equation MUST hold over secp256k1:

```
sum(output_commitments) - sum(input_commitments) + total_fee * H
  = sum(kernel_excesses) + tx_offset * G
```

Equivalently (moving fee to RHS with negative sign):
```
sum(output_commitments) - sum(input_commitments)
  = sum(kernel_excesses) + tx_offset * G - total_fee * H
```

**Canonical verification form (NORMATIVE):**

```
LHS = sum(output_commitments) - sum(input_commitments) + total_fee * H
RHS = sum(kernel_excesses) + tx_offset * G
VALID IFF: LHS == RHS  (comparison in secp256k1 group element space)
```

The alternative form `sum(outputs) - sum(inputs) = sum(excesses) + offset*G - fee*H`
is mathematically equivalent and shown in §1.2 for derivation clarity, but
**the LHS form above is the normative canonical form for implementation**.
Implementations MUST use this exact form to ensure cross-implementation compatibility.

See CHANGELOG for correction history (fee sign was inverted in v4–v6).

Where:
- `output_commitments`: all Pedersen commitments `C = v*H + r*G` in the output set
- `input_commitments`: all Pedersen commitments being spent
- `kernel_excesses`: the excess blinding factor commitment in each kernel (`r_excess * G`)
  **Note:** kernel excess is `r_excess * G` only — NOT a full Pedersen commitment.
  It is the public key corresponding to the blinding factor difference, with NO value component.
- `tx_offset`: the transaction offset scalar (32 bytes, in range [0, n-1])
- `total_fee`: the sum of fees from all kernels in this transaction (u64, in noms)
- `G`: secp256k1 generator point
- `H`: DOM generator point (derived via RFC9380, defined in RFC-0001)

**Why fee is on the LHS:** Value conservation requires `Σv_out + fee = Σv_in`,
so `Σv_out - Σv_in = -fee`. Moving `-fee * H` from RHS to `+fee * H` on LHS
cancels the value deficit: `(Σv_out - Σv_in)*H + fee*H = 0*H`. The equation
then reduces to the blinding factor equality: `Σr_excess * G`. This is consistent
with Grin (`grin/doc/intro.md`) and eprint 2020/1064 §2.1.

**Fee binding**: The fee declared in `kernel.fee` MUST satisfy the balance equation.
A transaction where the declared fee does not balance the equation MUST be rejected
as `Invalid`.

**Offset constraint**: If `tx_offset == 0`, the transaction is still valid. Zero offset
provides no graph privacy protection but is not a consensus error. Wallets SHOULD
generate a non-zero random offset for every transaction.

### 1.2 Block Balance Equation

For a valid block, the following equation MUST hold:

```
sum(all_output_commitments_in_block)
  - sum(all_input_commitments_in_block)
  - coinbase_output_commitment
  + block_total_tx_fee * H
  = sum(all_kernel_excesses_in_block)
    + block_total_offset * G
```

Note: `block_total_tx_fee * H` is on the LEFT side (same sign correction as §1.1).

Where:
- `coinbase_output_commitment`: the single output commitment of the coinbase transaction
- `block_total_offset`: `sum(tx.offset for all non-coinbase tx in block) mod n`
  accumulated as a scalar, serialized as the `total_kernel_offset` field in BlockHeader
- `block_total_tx_fee`: `sum(kernel.fee for all non-coinbase kernels in block)`

**Verification order**: This equation is verified at RFC-0007 block validation step 13
(aggregate block balance equation).

**Clarification on coinbase "exclusion":** RFC-0008 §3.6 states that the coinbase output
is "excluded from the general block balance equation." This means the coinbase commitment
is **subtracted explicitly** in the block equation (§1.2), not omitted. The coinbase creates
value ex nihilo — subtracting it from the LHS isolates the conservation constraint on
non-coinbase transactions. Implementations MUST include `- coinbase_output_commitment`
in the block balance equation. Omitting it entirely would make the equation satisfiable
with any coinbase value — enabling silent inflation.

---

## 2. Kernel Fee Specification

### 2.1 Fee Field

`TransactionKernel.fee` is a `u64` value in noms (not DOM).

Minimum fee: 0 (zero-fee transactions are relay-policy rejected but consensus-valid).

Maximum fee per kernel: `u64::MAX` noms (consensus limit; policy minimum applies).

### 2.2 Fee Verification

The balance equation enforces fee implicitly. No separate fee check is required
beyond verifying the balance equation holds.

However, validators MUST verify:

```
sum(kernel.fee for all kernels in tx) == total_fee used in balance equation
```

This prevents a kernel declaring fee=X while the equation uses fee=Y.

### 2.3 Coinbase Kernel Fee

The coinbase kernel MUST have `fee == 0`. A coinbase kernel with non-zero fee
is consensus-invalid.

The coinbase kernel MAY include fees collected from other transactions in the
same block via the `explicit_value` field (see Section 3.3).

---

## 3. Coinbase Specification

### 3.1 Coinbase Kernel Features

A coinbase transaction is identified by its kernel `features` field.

```
KERNEL_FEAT_PLAIN         = 0x00   // standard transaction kernel
KERNEL_FEAT_COINBASE      = 0x01   // coinbase kernel
KERNEL_FEAT_HEIGHT_LOCKED = 0x02   // kernel with lock_height > 0
```

A block MUST contain exactly one coinbase kernel with `features == KERNEL_FEAT_COINBASE`.
A block with zero or more than one coinbase kernels is consensus-invalid.

Non-coinbase kernels MUST NOT have `features == KERNEL_FEAT_COINBASE`.

### 3.2 Coinbase Value

The coinbase kernel MUST include an `explicit_value` field (u64) representing
the total coinbase value in noms:

```
coinbase_kernel.explicit_value = block_reward(block_height) + sum(tx_fees_in_block)
```

Where:
- `block_reward(h)` = deterministic lookup in `BLOCK_REWARD_TABLE`, using
  `epoch = h / HALVING_INTERVAL`
- `sum(tx_fees_in_block)` = sum of all `kernel.fee` from non-coinbase kernels in this block

The reward schedule is defined by the implementation-authoritative constants in
`crates/dom-core/src/constants.rs` and the lookup function in
`crates/dom-core/src/types.rs`.

Normative reward rule:

```
epoch = height / HALVING_INTERVAL
if epoch >= HALVING_EPOCHS:
    block_reward(height) = 0
else:
    block_reward(height) = BLOCK_REWARD_TABLE[epoch]
```

`BLOCK_REWARD_TABLE` is the normative current reward schedule. The table is
derived deterministically with integer arithmetic:

```
reward(0) = INITIAL_BLOCK_REWARD
reward(n) = (reward(n - 1) * 67) / 100
```

No floating-point arithmetic is used. Implementations MUST NOT use an alternate
reward formula when that formula diverges from `BLOCK_REWARD_TABLE`.
The table lookup performed by `dom_core::block_reward(height)` is the canonical
rule for coinbase validation.

**Validators MUST verify**:
```
coinbase_kernel.explicit_value == block_reward(block_height) + sum(non_coinbase_fees)
```

A coinbase with incorrect explicit_value is consensus-invalid (`Invalid` error).

### 3.3 Coinbase Output Commitment

The coinbase output commitment is a standard Pedersen commitment:
```
coinbase_output_commitment = v * H + r * G
```

Where `v == coinbase_kernel.explicit_value` and `r` is the miner's chosen blinding factor.

The miner proves ownership by holding `r` privately.

The coinbase output commitment MUST be included in the output PMMR.

### 3.4 Coinbase Kernel Serialization

**Note on `excess` field:** The `excess` commitment in ALL kernels (coinbase and plain)
is `r * G` — the public key of the blinding factor. It is NOT a full Pedersen
commitment `v * H + r * G`. The value component of kernel excess is always zero.
This is consistent with Grin and the Mimblewimble paper.

The coinbase kernel has a modified serialization compared to plain kernels:

```
CoinbaseKernel {
  features:       u8   = 0x01
  explicit_value: u64  (little-endian) — the total coinbase value in noms
  excess:         [u8; 33]  — SEC1 compressed Pedersen commitment
  signature:      [u8; 65]  — Schnorr signature (R_compressed || s)
}
```

Note: coinbase kernels do NOT have a `fee` field (it is always zero and omitted
from serialization to prevent ambiguity).

Note: coinbase kernels do NOT have a `lock_height` field. Coinbase maturity is
enforced via `COINBASE_MATURITY` blocks, not lock_height.

### 3.5 Coinbase Maturity Enforcement

A transaction input that spends a coinbase output MUST be rejected as
`TemporarilyInvalid` if:

```
current_block_height - coinbase_block_height < COINBASE_MATURITY
```

This check MUST occur at RFC-0007 transaction validation step 2 (primitive validation).

The `TemporarilyInvalid` error class is correct here: the output WILL become spendable
after `COINBASE_MATURITY` blocks. Do not return `Invalid`.

### 3.6 Coinbase in the Balance Equation

The coinbase output is excluded from the general block balance equation (Section 1.2).
This is because the coinbase creates value ex nihilo — it is the only place in the
protocol where new coins are created.

The coinbase validity is verified separately:
```
coinbase_kernel.explicit_value == block_reward(height) + sum(tx_fees)
coinbase_output_commitment encodes exactly explicit_value  (verified via Bulletproof)
```

---

## 4. Kernel Offset Specification

### 4.1 Transaction Offset

Every non-coinbase transaction includes an `offset` field: a 32-byte scalar in [0, n-1].

The offset is generated by the **sender** as a uniformly random scalar before
constructing the transaction.

If `offset == 0`, the transaction is valid but provides no offset privacy.
Wallets SHOULD generate non-zero offsets.

### 4.2 Block Kernel Offset Accumulation

The `BlockHeader.total_kernel_offset` field accumulates all transaction offsets:

```
total_kernel_offset = sum(tx.offset for all non-coinbase tx in block) mod n
```

The coinbase transaction MUST have `offset = [0u8; 32]` (zero scalar).

`total_kernel_offset` is serialized as 32 bytes, little-endian scalar.

### 4.3 Offset in the Balance Equation

See Section 1.2. The `total_kernel_offset` appears as:
```
+ block_total_offset * G
```
on the right-hand side of the block balance equation.

### 4.4 Offset Validation

Validators MUST verify that `total_kernel_offset` is a canonical little-endian scalar
in [0, n-1]. A non-canonical offset is `Malformed`.

---

## 5. Kernel Features Table (Complete)

All kernel feature values:

| Value | Name | Description |
|---|---|---|
| 0x00 | `KERNEL_FEAT_PLAIN` | Standard transaction kernel |
| 0x01 | `KERNEL_FEAT_COINBASE` | Block reward kernel |
| 0x02 | `KERNEL_FEAT_HEIGHT_LOCKED` | Absolute timelock kernel |

All other values are consensus-invalid (`Invalid` error).

A `KERNEL_FEAT_HEIGHT_LOCKED` kernel MUST have `lock_height > 0`.
A `KERNEL_FEAT_HEIGHT_LOCKED` kernel with `lock_height == 0` is consensus-invalid.

A kernel with `lock_height > current_block_height` causes the entire transaction
to be `TemporarilyInvalid` (not `Invalid`).

---

## 6. Complete Validation Rules Added to RFC-0007

This RFC adds the following rules to the RFC-0007 validation pipeline.

### 6.1 Transaction Validation Additions (after existing step 10)

At step 2 (primitive validation), additionally verify:

- For each input: if input references a coinbase output, verify coinbase maturity (Section 3.5)
- All kernel `features` values are in the defined table (Section 5)
- `KERNEL_FEAT_HEIGHT_LOCKED` kernels have `lock_height > 0`

At step 8 (fee calculation), verify:

- `sum(kernel.fee) == total_fee` (no kernel fee discrepancy)
- No kernel has `features == KERNEL_FEAT_COINBASE` in a non-coinbase transaction

At step 10 (transaction balance equation), use the complete equation from Section 1.1.

### 6.2 Block Validation Additions

At step 8 (transaction validation), additionally verify per block:

- Exactly one kernel with `features == KERNEL_FEAT_COINBASE` exists
- `coinbase_kernel.explicit_value == block_reward(height) + sum(non_coinbase_fees)`
- Coinbase `offset == [0u8; 32]`

At step 13 (aggregate block balance equation), use the complete equation from Section 1.2.

---

## 7. Security Properties

### 7.1 Inflation Prevention

Silent inflation is prevented by:

1. The Bulletproof range proof on the coinbase output ensures `v >= 0`
2. The explicit_value field enforces `v == block_reward + fees` exactly
3. The balance equation ties all outputs cryptographically to inputs + coinbase

An attacker attempting to create extra coins would need to:
- Either break the discrete logarithm problem (infeasible)
- Or find a collision in Blake2b-256 (infeasible)

### 7.2 Fee Theft Prevention

A miner cannot steal transaction fees beyond what is declared in kernels:
the balance equation forces `total_fee * H` to balance exactly with the
difference between outputs and inputs. Undeclared fees would break the equation.

### 7.3 Offset Privacy

The offset mechanism ensures that even with full blockchain visibility, it is
impossible to determine which inputs and outputs in a block belong to the same
transaction (assuming non-zero offsets). The total_kernel_offset proves the
sum is correct without revealing individual offsets.

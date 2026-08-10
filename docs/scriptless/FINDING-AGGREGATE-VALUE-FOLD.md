# Finding — Aggregate Check Folds the Value Instead of the Spec's `vH + Σ R_i`

Date: 2026-08-10
Severity: **spec-divergence, not an output-correctness bug**
Location: pre-existing code (`crates/dom-adaptor/src/bulletproof_mpc.rs`)

## What the spec says

Master specification `DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0`:

- **§4.3 "Commitment agregado"**: *"R_total = Σ R_i; C = vH + R_total"*, where each
  published share is the **pure point** `R_i = r_i·G` (§4.2). So the aggregate
  is `C = v·H + Σ R_i`.
- **§5.2**: `BpStatementV1` carries both `commitment_shares: Vec<[u8;33]>` and
  `aggregate_commitment: [u8;33]`, plus `value_noms` and `value_generator`.

The spec's natural model is therefore: `commitment_shares[i] = R_i` (the exact
point party *i* proves in its §4.2 PoK), and `aggregate_commitment = v·H + Σ R_i`.
The check is `aggregate == value_noms · value_generator + Σ commitment_shares`.

## What the code does

`validate_aggregate` checks `Σ shares == aggregate` with no value term:

```rust
fn validate_aggregate(shares: &[PublicKey], aggregate: &PublicKey) -> Result<()> {
    if scriptless_add_public_points(shares)? != *aggregate {
        return Err(AdaptorError::InvalidContext(
            "Bulletproof aggregate commitment differs from ordered share sum",
        ));
    }
    Ok(())
}
```

For `Σ shares == aggregate` to hold when `aggregate = C = vH + Σ r_i·G`, the
shares must fold `vH` in. The `collaborative_proof` test does exactly that:
`commitment_shares[0] = commit(v, r_0) = vH + r_0·G`, and `commitment_shares[i>0]
= commit(0, r_i) = r_i·G`.

## Consequence

- **The output stays valid.** `aggregate_commitment` is still `C`, the proof is
  still built over `value_noms = v` with each party's blind, and consensus
  verifies the proof against `C`. Nothing about the on-chain output is wrong.
- **But `commitment_shares[0]` is not `R_0`.** It is `vH + r_0·G`, so the
  statement's first share is not the pure point the §4.2 PoK proves. The clean
  identity "statement.commitment_shares[i] == the R_i proven by party i" does not
  hold in the value-carrying slot.
- This representation gap is what made an earlier session module
  (`partial_commitment_pop.rs`) look necessary: the shares in the statement were
  not the pure `R_i`, so a proof over the statement share and a proof over `R_i`
  looked like different objects. Per §4.2/§4.3 they should be the same object.

## Spec-faithful fix (bounded, testable)

1. `validate_aggregate` takes the value and checks
   `aggregate == v·H + Σ shares`, where `v·H` is
   `Commitment::commit(v, b).sub(Commitment::commit(0, b))` for a fixed nonzero
   `b` (no zero blinding), matching `collaborative_output.rs`'s §4.3 computation.
2. `BpStatementV1::new` is built with `commitment_shares = the pure R_i` (the
   session-layer shares from `collaborative_output.rs`), unifying the two layers
   so the §4.2 PoK proves exactly the statement's shares.
3. The `collaborative_proof` test builds the statement with pure `R_i` shares;
   the proof stays 739 bytes and verifies via the consensus-shaped
   `range_proof_verify_with_extra_commit`.

This changes the frozen statement construction (the `statement_hash` and the
common-nonce derivation shift because the shares change from folded to pure), so
it is a deliberate, reviewed change to the collaborative-proof evidence, not a
silent one.

## Relationship to the extra_commit fix

This is the second spec-divergence found in `bulletproof_mpc` while building the
driver. The first, the 32-byte `extra_commit`, was an **output-correctness bug**
(the shared output would fail consensus) and is fixed. This one is a
**representation divergence** that does not break the output but blocks the
clean, spec-faithful driver construction and explains the earlier PoK confusion.

```text
AGGREGATE_CHECK = FOLDS_VALUE_INTO_SHARE_0_NOT_SPEC_4_3
OUTPUT_VALIDITY = UNAFFECTED
DRIVER_CLEAN_CONSTRUCTION = REQUIRES_PURE_R_I_SHARES
FIX = VALIDATE_AGGREGATE_ADD_VALUE_TERM_AND_USE_PURE_R_I
FIX_TOUCHES = FROZEN_STATEMENT_BYTES_DELIBERATE_CHANGE
```

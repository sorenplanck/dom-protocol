# DOM RFC-0015 - Monetary Integrity Layer

Status: Draft
Phase: 1
Type: Public auditability layer
Change class: Documentation-only in this phase
Depends on: RFC-0008, RFC-0009, RFC-0010, RFC-0011, Monetary Constitution,
`docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`,
`docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md`

## 1. Purpose

This RFC defines the public, verifiable monetary integrity layer for DOM as a
future read-only audit surface. It is intended to make issuance, supply, fees,
coinbase value, and supply checkpoints independently auditable from canonical
history.

This RFC does not change consensus. It does not change validation. It does not
change RandomX. It does not change difficulty. It does not change the block
format. It does not change node behavior. It does not change wallet behavior.
It does not add RPC. It does not add executable tests in Phase 1.

## 2. Non-Goals

RFC-0015 does not:

- introduce a new monetary rule
- reinterpret the reward schedule
- alter `MAX_SUPPLY_NOMS`
- alter `BLOCK_REWARD_TABLE`
- alter coinbase maturity
- alter fee validity
- alter block acceptance
- alter transaction acceptance
- alter PMMR roots
- alter kernel offset rules
- alter RandomX or difficulty
- create a governance mint
- create treasury issuance
- create wallet-visible balance rules
- require a live node API

## 3. Current Authoritative Monetary Sources

The implementation-authoritative monetary sources are:

- `crates/dom-core/src/constants.rs`
  - `COIN_UNIT`
  - `INITIAL_BLOCK_REWARD`
  - `HALVING_INTERVAL`
  - `HALVING_EPOCHS`
  - `BLOCK_REWARD_TABLE`
  - `MAX_SUPPLY_NOMS`
  - `COINBASE_MATURITY`
  - `REGTEST_COINBASE_MATURITY`
- `crates/dom-core/src/types.rs`
  - `BlockHeight::halving_epoch`
  - `Amount::from_noms`
  - `block_reward`
- `crates/dom-consensus/src/transaction.rs`
  - `CoinbaseKernel`
  - `CoinbaseKernel::validate_explicit_value`
  - `CoinbaseTransaction`
  - `CoinbaseTransaction::validate`
- `crates/dom-consensus/src/lib.rs`
  - `validate_transaction`
  - `validate_block_transactions`
- `crates/dom-consensus/src/block_full.rs`
  - `Block::total_fees`
  - `validate_block`
- `crates/dom-chain/src/chain_state.rs`
  - `ChainState::connect_block`
  - `validate_direct_extension_inputs`
  - `build_utxo_changeset`
  - `apply_connect`
- `crates/dom-store/src/utxo.rs`
  - `UtxoEntry`
  - `UtxoEntry::is_mature_for`
  - `UtxoSet::validate_input_with_maturity`
- `crates/dom-node/src/miner.rs`
  - `build_coinbase_with_blinding`
  - `build_real_coinbase`
  - `build_genesis_coinbase`

## 4. Monetary Invariants

The monetary integrity layer MUST preserve and publicly reflect these existing
invariants:

1. The only authorized issuance source is the block coinbase.
2. A block coinbase value is valid only when:

```text
coinbase.explicit_value == block_reward(block_height) + sum(non_coinbase_fees)
```

3. `block_reward(height)` is implementation-authoritative and is currently
   table based, via `BLOCK_REWARD_TABLE`.
4. Transaction fees are public kernel values denominated in noms.
5. Fee sums MUST be checked for overflow.
6. Coinbase value addition MUST be checked for overflow.
7. Coinbase output commitments MUST have valid range proofs.
8. Coinbase kernel signatures MUST validate against the chain ID.
9. Coinbase offset MUST be zero.
10. The aggregate block balance equation MUST validate.
11. Coinbase outputs MUST be tagged as coinbase UTXOs.
12. Coinbase spends MUST respect network-specific maturity.
13. The maximum scheduled subsidy is `MAX_SUPPLY_NOMS`.
14. Monetary audit tooling MUST be observational and fail closed on ambiguity.

## 5. Reward Schedule Rule

The monetary integrity layer MUST use the same reward function as consensus:

```text
epoch = height / HALVING_INTERVAL
if epoch >= HALVING_EPOCHS:
    reward = 0
else:
    reward = BLOCK_REWARD_TABLE[epoch]
```

The reward table is the authoritative schedule for audit output. Auditors MUST
NOT recompute rewards with floating point arithmetic. Auditors MUST NOT use any
alternate reward formula if it differs from `BLOCK_REWARD_TABLE`.

## 6. Supply Accounting Model

For each canonical block, the monetary integrity layer SHOULD derive:

```text
height
block_hash
base_reward_noms
non_coinbase_fee_sum_noms
coinbase_explicit_value_noms
expected_coinbase_value_noms
coinbase_value_valid
cumulative_scheduled_subsidy_noms
cumulative_claimed_coinbase_noms
cumulative_non_coinbase_fees_noms
max_supply_noms
remaining_scheduled_subsidy_noms
```

Definitions:

- `base_reward_noms` is `block_reward(height).noms()`.
- `non_coinbase_fee_sum_noms` is the checked sum of all non-coinbase kernel
  fees in the block.
- `expected_coinbase_value_noms` is `base_reward_noms +
  non_coinbase_fee_sum_noms`, checked for overflow.
- `coinbase_explicit_value_noms` is the public `CoinbaseKernel.explicit_value`.
- `cumulative_scheduled_subsidy_noms` is the checked sum of base rewards over
  canonical heights.
- `cumulative_claimed_coinbase_noms` is the checked sum of explicit coinbase
  values over canonical heights.
- `cumulative_non_coinbase_fees_noms` is the checked sum of all non-coinbase
  fees over canonical heights.
- `remaining_scheduled_subsidy_noms` is `MAX_SUPPLY_NOMS -
  cumulative_scheduled_subsidy_noms`, checked for underflow.

Fees are included in coinbase outputs but are not new supply. Therefore, public
audit output MUST distinguish scheduled subsidy from claimed coinbase value.

## 7. Public Checkpoint Model

Future Phase 2 tooling SHOULD be able to emit deterministic checkpoints. A
checkpoint SHOULD contain:

```text
network_magic
genesis_hash
tip_height
tip_hash
max_supply_noms
cumulative_scheduled_subsidy_noms
cumulative_claimed_coinbase_noms
cumulative_non_coinbase_fees_noms
remaining_scheduled_subsidy_noms
coinbase_outputs_seen
regular_outputs_seen
inputs_seen
live_utxo_count
live_coinbase_utxo_count
monetary_audit_digest
```

The `monetary_audit_digest` SHOULD be deterministic over the checkpoint fields
and canonical per-block monetary rows. The digest format is deferred to Phase 2
and MUST be specified before implementation.

The public transcript schema is specified in
`docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`. RFC-0015 uses that document as
the single transcript source for public monetary integrity output.

## 8. Verification Procedure

A future monetary integrity verifier SHOULD:

1. Read canonical blocks in strict height order.
2. Reject missing heights, duplicate heights, or non-canonical branch ambiguity.
3. Decode blocks using canonical serialization.
4. Recompute non-coinbase fee sums with checked arithmetic.
5. Recompute `block_reward(height)` via `BLOCK_REWARD_TABLE`.
6. Recompute expected coinbase value with checked arithmetic.
7. Compare expected coinbase value to `CoinbaseKernel.explicit_value`.
8. Track cumulative scheduled subsidy separately from transaction fees.
9. Track coinbase UTXO creation and coinbase spend maturity.
10. Emit deterministic checkpoints.
11. Fail closed if any block, value, field, or state transition is ambiguous.

The verifier MUST NOT accept data merely because it is present in a wallet. The
source of monetary truth is canonical chain history and consensus-valid block
data, not wallet-local balance state.

The formal replay procedure is specified in
`docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md`. RFC-0015 uses that document as the
single procedure for deriving transcript fields from canonical history.

## 9. Phase Boundaries

### Phase 0 - Audit

Phase 0 is complete when the current monetary implementation is mapped and
documented with findings, risks, and Phase 2 recommendations.

Output:

- `docs/MONETARY_INTEGRITY_AUDIT.md`

### Phase 1 - RFC

Phase 1 is complete when this RFC defines the public monetary integrity layer
boundary without adding executable code.

Output:

- `docs/DOM_RFC_0015_Monetary_Integrity_Layer.md`
- `docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`
- `docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md`
- `audit/00_MASTER_INDEX.md` compatibility path

### Phase 2 - Proposed Implementation Scope

Phase 2 SHOULD be limited to:

- read-only offline audit tooling
- implementation of the transcript schema already specified in
  `docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`
- implementation of the replay procedure already specified in
  `docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md`
- non-consensus golden vectors
- non-consensus regression tests for audit tooling

Phase 2 MUST NOT:

- alter consensus rules
- alter validation
- alter RandomX
- alter difficulty
- alter block format
- alter node behavior
- alter wallet behavior
- add RPC without a separate explicit RFC and authorization

## 10. Security Requirements

Any future implementation of this RFC MUST:

- use checked arithmetic for all sums and differences
- use implementation-authoritative reward constants
- fail closed on overflow, underflow, missing data, duplicate data, or decode
  ambiguity
- distinguish scheduled subsidy from transaction fees
- distinguish canonical history from side-chain data
- avoid floating point arithmetic
- avoid wall-clock dependent output
- avoid map-order dependent output
- avoid wallet-derived monetary authority
- avoid network-derived trust assumptions

## 11. Public Audit Output Requirements

Public monetary audit output SHOULD be:

- deterministic
- machine-readable
- stable across platforms
- independent of wallet state
- independent of live peer state
- reproducible from persisted canonical history
- explicit about network identity
- explicit about genesis hash
- explicit about tip hash and height

The output MUST include enough information for an external auditor to verify
that scheduled subsidy does not exceed `MAX_SUPPLY_NOMS` and that every
coinbase value equals base reward plus the block's non-coinbase fees.

## 12. Closure Status

The Phase 0/1 gaps identified by `docs/MONETARY_INTEGRITY_AUDIT.md` are closed
at the documentation/specification level as follows:

- DOM-MIL-001: resolved by updating RFC-0008 to define `BLOCK_REWARD_TABLE` as
  the normative current reward schedule.
- DOM-MIL-002: resolved by `docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`.
- DOM-MIL-003: resolved by `docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md`.
- DOM-MIL-004: resolved by creating `audit/00_MASTER_INDEX.md` as a
  compatibility path while preserving `audit/00_MASTER_INDEX`.

These closures are documentation/specification closures. They do not implement
node behavior, wallet behavior, RPC, metrics, explorer behavior, or consensus
changes.

## 13. Compatibility

This RFC is compatible with the current implementation because it describes an
observational layer over existing monetary rules. It does not require a hard
fork, soft fork, migration, block format change, RPC change, wallet change, or
node behavior change.

## 14. Acceptance Criteria for Phase 2

Before Phase 2 implementation is accepted, it SHOULD demonstrate:

- no consensus files changed unless separately authorized
- no validation behavior changed
- no RandomX or difficulty files changed
- no block format changed
- no wallet behavior changed
- no RPC added
- deterministic audit output on repeated runs
- deterministic audit output across restart/reopen
- negative tests for malformed audit inputs
- explicit validation evidence

## 15. Final Statement

The DOM Monetary Integrity Layer is a public verification layer, not a new
monetary policy layer. Its purpose is to make the existing emission and supply
rules independently auditable while preserving the current consensus boundary.

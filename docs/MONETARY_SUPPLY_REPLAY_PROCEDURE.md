# DOM Monetary Supply Replay Procedure

Status: Phase 1 procedure
Change class: Documentation-only
Scope: Deterministic monetary replay from canonical chain history

## 1. Purpose

This document defines the formal replay procedure for recomputing DOM scheduled
subsidy, claimed coinbase value, fees, and transcript fields from canonical
chain history.

This procedure does not alter consensus, validation, RandomX, difficulty, block
format, serialization, node behavior, wallet behavior, RPC, explorer behavior,
or metrics.

## 2. Source of Truth

The only monetary source of truth for replay is canonical chain history and the
implementation-authoritative monetary constants and functions:

- `BLOCK_REWARD_TABLE`
- `HALVING_INTERVAL`
- `HALVING_EPOCHS`
- `MAX_SUPPLY_NOMS`
- `block_reward(height)`
- canonical block bodies
- canonical block headers
- `CoinbaseKernel.explicit_value`
- non-coinbase transaction kernel fees

Never use wallet state as a monetary source of truth.

## 3. Replay Inputs

A replay implementation requires:

- network identity
- genesis hash
- canonical block headers
- canonical block bodies
- canonical chain tip
- implementation-authoritative monetary constants

Side-chain blocks, orphan blocks, wallet records, peer advertisements, mempool
contents, RPC summaries, and explorer data MUST NOT be treated as authoritative
monetary inputs.

## 4. Formal Procedure

1. Initialize replay state with zeroed counters:
   - `cumulative_scheduled_subsidy_noms`
   - `cumulative_claimed_coinbase_noms`
   - `cumulative_non_coinbase_fees_noms`
   - `coinbase_outputs_seen`
   - `regular_outputs_seen`
   - `inputs_seen`
   - live UTXO set
   - live coinbase UTXO set
2. Read canonical blocks in strict ascending height order.
3. Validate height continuity. Genesis MUST be height 0. Every later block MUST
   have height `previous_height + 1`.
4. Validate hash continuity. Every non-genesis block MUST reference the previous
   canonical block hash as `prev_hash`.
5. Decode headers and bodies using canonical serialization.
6. For each block, calculate:

```text
reward = block_reward(height).noms()
```

7. Compute non-coinbase fees by summing every non-coinbase transaction kernel
   fee with checked arithmetic.
8. Compute expected coinbase value:

```text
expected_coinbase = checked_add(reward, non_coinbase_fee_sum)
```

9. Compare `expected_coinbase` with `CoinbaseKernel.explicit_value`. Mismatch is
   a fail-closed condition.
10. Accumulate scheduled subsidy separately from fees:

```text
cumulative_scheduled_subsidy_noms += reward
```

11. Accumulate claimed coinbase separately:

```text
cumulative_claimed_coinbase_noms += CoinbaseKernel.explicit_value
```

12. Accumulate non-coinbase fees separately:

```text
cumulative_non_coinbase_fees_noms += non_coinbase_fee_sum
```

13. Track coinbase output creation:
   - increment `coinbase_outputs_seen`
   - insert the coinbase commitment into the live UTXO set
   - mark that UTXO as coinbase
   - record creation height
14. Track regular transaction inputs:
   - increment `inputs_seen`
   - require the input to exist in the live UTXO set
   - if the input spends a coinbase UTXO, enforce network-specific maturity
   - remove the spent input from the live UTXO set
15. Track regular transaction outputs:
   - increment `regular_outputs_seen`
   - require no duplicate live output commitment
   - insert the output into the live UTXO set as non-coinbase
16. Reject ambiguity:
   - missing block
   - duplicate block
   - duplicate output
   - missing input
   - height discontinuity
   - parent hash discontinuity
   - overflow
   - underflow
   - non-canonical decode
   - ambiguous canonical tip
17. After the final canonical block, compute:

```text
remaining_scheduled_subsidy_noms =
    checked_sub(MAX_SUPPLY_NOMS, cumulative_scheduled_subsidy_noms)
```

18. Derive:
   - `live_utxo_count`
   - `live_coinbase_utxo_count`
19. Produce the deterministic transcript defined in
   `docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`.
20. Produce `transcript_hash` over the canonical transcript payload.

## 5. Required Arithmetic Discipline

Replay implementations MUST:

- use checked addition
- use checked subtraction
- never use floating point
- never silently wrap
- never saturate monetary counters unless the procedure explicitly says so
- fail closed on overflow or underflow

## 6. Determinism Requirements

Replay implementations MUST NOT depend on:

- wallet state
- wall-clock time
- peer state
- mempool state
- map iteration order
- platform-specific formatting
- locale-specific formatting
- floating-point behavior

Any unordered collection used during replay MUST be explicitly sorted before it
affects transcript output or transcript hashing.

## 7. Coinbase Maturity Tracking

Coinbase UTXOs MUST be tracked with:

- output commitment
- creation height
- coinbase flag

When an input spends a coinbase UTXO, replay MUST verify:

```text
current_height - coinbase_creation_height >= network_coinbase_maturity
```

The maturity threshold is `COINBASE_MATURITY` for mainnet and testnet, and
`REGTEST_COINBASE_MATURITY` for regtest.

## 8. Replay Equivalence

Replay-equivalence means that two independent executions over the same
canonical history and monetary constants produce identical transcript fields and
the same `transcript_hash`.

To preserve replay-equivalence, implementations MUST use the same canonical
JSON rules and hashing rules defined in
`docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`.

## 9. Restart Equivalence

Restart-equivalence means that replay from persisted canonical history after
process restart produces the same transcript as replay before restart.

Replay implementations MUST NOT cache monetary counters in a way that can
survive as authoritative state without being reproducible from canonical
history.

## 10. Reorg Safety

Reorg-safety means transcript output is produced from the final selected
canonical chain, not from stale side-chain state.

Replay implementations MUST:

- identify one canonical tip
- traverse only the canonical path from genesis to tip
- exclude orphan and side-chain blocks
- fail closed if canonical selection is ambiguous
- recompute transcript output after any canonical chain change

## 11. Transcript Output

After successful replay, implementations SHOULD emit exactly the transcript
defined by `docs/MONETARY_INTEGRITY_TRANSCRIPT_SPEC.md`.

If replay fails, the implementation MUST NOT emit a transcript with
`monetary_integrity_status` set to `valid`.

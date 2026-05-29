# DAA Post-Migration Verification

Date: 2026-05-29

## Canonical DAA

The canonical expected-target function is now:

```text
crates/dom-pow/src/lib.rs:663 compute_expected_target(network_magic, block_timestamp, block_height)
```

For mainnet and testnet, `compute_expected_target`:

1. Resolves network parameters with `pow_params_for_network`.
2. Resolves the genesis ASERT anchor with `genesis_anchor`.
3. Computes ASERT with `asert_next_target_with_params`.
4. Canonicalizes the result through DOM compact target encoding so the returned
   bytes exactly match what a header can serialize and a validator can expand.

For regtest, `compute_expected_target` returns the fixed compact-stable easy
target from regtest PoW params. This keeps the development network isolated
from public consensus.

`expected_target_for_network` remains as a backwards-compatible wrapper around
`compute_expected_target`; it no longer contains independent DAA logic.

## Miner Path

Production mining now calls the canonical helper directly:

```text
crates/dom-node/src/miner.rs:374 compute_expected_target(...)
crates/dom-node/src/miner.rs:579 header.target = CompactTarget(target_to_compact(&target))
```

The miner target used for hashing is the same compact-canonical target the
header carries.

## Validator Path

Block validation now calls the same canonical helper:

```text
crates/dom-chain/src/chain_state.rs:246 validate_future_timestamp_with_limit
crates/dom-chain/src/chain_state.rs:249 validate_pow_for_network
crates/dom-chain/src/chain_state.rs:251 validate_expected_target
crates/dom-chain/src/chain_state.rs:730 validate_expected_target
crates/dom-chain/src/chain_state.rs:754 expected_target_for_child
crates/dom-chain/src/chain_state.rs:765 compute_expected_target(...)
```

The final comparison remains strict:

```text
actual_target != expected.next_target -> reject
```

There is no fallback target path in validator consensus.

## Window Retarget Status

Search terms:

```text
window_next_target
difficulty_adjustment_window
NextTargetAdjustment
retarget
```

Results in production DAA paths:

- `window_next_target`: no matches in `dom-chain`, `dom-node`, or production
  `dom-pow`.
- `difficulty_adjustment_window_blocks`: no matches.
- `NextTargetAdjustment`: no matches.
- `legacy_window_retarget_for_tests_only`: present only inside
  `crates/dom-pow/src/lib.rs` under `#[cfg(test)]`.

Mainnet and testnet cannot reach the legacy window retarget code because it is
not compiled into normal builds and is not imported by chain or node code.

## Network Modes

- Mainnet: ASERT through `compute_expected_target`.
- Testnet: ASERT through `compute_expected_target`, with testnet PoW params.
- Regtest: fixed compact-stable easy target through `compute_expected_target`.

Tests added or updated:

- Public network target preview equals `compute_expected_target`.
- Mainnet and testnet targets differ from regtest target.
- First public block after genesis uses the ASERT anchor target on schedule.
- Wrong public-network target is rejected by validator target checking.
- Regtest keeps fixed easy target.
- Miner-selected target matches `compute_expected_target`.
- ASERT large positive delta, large negative delta, and clamp behavior.
- Compact target conversion round-trips consensus compact targets.

## Timestamp Safety

Timestamp validation remains before target comparison:

- Parent timestamp progression: `validate_parent_timestamp_progression`.
- Median-time-past: `validate_median_time_past`.
- Future timestamp bound: `validate_future_timestamp_with_limit`.

ASERT uses:

- Anchor timestamp from `genesis_anchor(network_magic)`.
- Candidate block timestamp from `header.timestamp`.
- Candidate block height from `header.height`.

It does not use local wall clock internally. Local time is only passed into the
existing future-timestamp validity check.

## Total Difficulty Safety

Total difficulty accumulation is unchanged:

```text
block_diff = target_to_difficulty(header.target.to_target())
expected_total = parent.total_difficulty + block_diff
```

The chain-selection rule remains unchanged: direct extensions and reorg
promotion still compare cumulative `total_difficulty`.

`target_to_difficulty` still delegates to `target_to_difficulty_u256` for
deterministic integer division. No floating point arithmetic was introduced.

## Validation Results

Commands run:

- `cargo fmt --all`: passed. The command also formatted unrelated pre-existing
  files; that formatting churn was reverted so the commit only carries scoped
  changes.
- `cargo check --workspace`: passed.
- `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- `cargo test -p dom-pow`: passed.
- `cargo test -p dom-chain`: passed.
- `cargo test -p dom-node`: passed.
- `timeout 600s cargo test --workspace`: blocked inside the default sandbox
  because socket-binding integration tests could not bind `127.0.0.1:0`
  (`Operation not permitted`).
- `timeout 600s cargo test --workspace` outside the sandbox: reached
  `replay_two_independent_chains_converge` and exceeded the artificial 600s
  limit under full RandomX mining in this CPU-contended environment.
- `DOM_REGTEST_FAST_MINING=1 timeout 1200s cargo test --workspace` outside the
  sandbox: passed.

Validation hardening performed while running the full suite:

- `dom-integration-tests/replay_determinism` now bootstraps replay stores with
  the exact genesis block produced by the source node before applying child
  blocks. This makes the replay test deterministic under both normal regtest
  and explicit fast-regtest mining.
- `dom-test-runner` now deduplicates affected-profile selections by profile
  name instead of by the full `(profile, reason)` tuple.
- `dom-wallet/tests/rpc_client.rs` now sends shutdown to its mock server before
  joining the server thread, removing a test harness hang.

No production consensus fallback was added for any validation issue above.

## Final Answers

- Public consensus is ASERT-only for mainnet and testnet.
- Mainnet and testnet cannot reach window retarget.
- Miner and validator are byte-for-byte aligned on
  `compute_expected_target(network_magic, block_timestamp, block_height)`.
- The repository is ready for ASERT half-life tuning as a separate consensus
  change.

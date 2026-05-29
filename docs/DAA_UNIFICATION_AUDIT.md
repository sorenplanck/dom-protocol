# DAA Unification Audit

Date: 2026-05-29

This document records the executable difficulty adjustment paths found before
the ASERT unification change. It intentionally ignores comments, roadmap text,
and whitepaper claims except where they point to code that actually executes.

## Current Miner DAA Path

Production mining enters `dom_node::miner::mine_one_block`:

```text
crates/dom-node/src/miner.rs:366 mine_one_block
crates/dom-node/src/miner.rs:373 block_timestamp = Timestamp(now_secs())
crates/dom-node/src/miner.rs:374 expected_target_for_network(network_magic, block_timestamp, new_height)
crates/dom-pow/src/lib.rs:677 expected_target_for_network
crates/dom-pow/src/lib.rs:687 asert_next_target_with_params
crates/dom-node/src/miner.rs:579 header.target = CompactTarget(target_to_compact(&target))
```

The miner therefore uses the network-aware ASERT implementation through
`expected_target_for_network`.

## Current Validator DAA Path

Block validation enters `dom_chain::ChainState::connect_block`:

```text
crates/dom-chain/src/chain_state.rs:159 connect_block
crates/dom-chain/src/chain_state.rs:233 validate_pow_for_network
crates/dom-chain/src/chain_state.rs:236 validate_expected_target
crates/dom-chain/src/chain_state.rs:715 next_target_after_parent_from_prior
crates/dom-chain/src/chain_state.rs:745 regtest fixed target branch
crates/dom-chain/src/chain_state.rs:756 parent-genesis previous-target branch
crates/dom-chain/src/chain_state.rs:767 difficulty_adjustment_window_blocks
crates/dom-chain/src/chain_state.rs:779 window_next_target
```

IBD header validation also reaches `validate_expected_target` at:

- `crates/dom-chain/src/chain_state.rs:412`
- `crates/dom-chain/src/chain_state.rs:582`

Header-only validation reaches it at:

- `crates/dom-chain/src/chain_state.rs:658`

The validator currently does not call `expected_target_for_network`.

## Exact Divergence Point

The divergence is at target calculation:

- Miner: `expected_target_for_network(network_magic, candidate_timestamp, child_height)`
- Validator: `next_target_after_parent_from_prior(parent, prior_headers)`

For public non-regtest networks, validator target calculation reaches
`window_next_target(previous_target, parent_elapsed, window_blocks)` instead of
ASERT. The validator uses parent/window timestamps and never passes the child
candidate timestamp to ASERT.

## Active Network Modes Before Migration

`Network::magic()` maps node configuration to consensus network magic:

- Mainnet -> `NETWORK_MAGIC_MAINNET`
- Testnet -> `NETWORK_MAGIC_TESTNET`
- Regtest -> `NETWORK_MAGIC_REGTEST`

Before migration:

- Mainnet miner: ASERT via `expected_target_for_network`.
- Testnet miner: ASERT via `expected_target_for_network`, with testnet params.
- Regtest miner: ASERT via `expected_target_for_network`.
- Mainnet validator: window retarget after the first post-genesis block.
- Testnet validator: window retarget after the first post-genesis block.
- Regtest validator: fixed `REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION`.

## Reachable Target-Generation Paths Before Migration

### Public Consensus Reachable

- `ChainState::validate_expected_target`
- `ChainState::next_target_after_parent_from_prior`
- `window_next_target`

### Miner Reachable

- `expected_target_for_network`
- `asert_next_target_with_params`
- `target_to_compact`

### Regtest Validator Reachable

- `uses_dev_fixed_target`
- `REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION`

### Test-Only Or Legacy Reachable

- Direct calls to `asert_next_target` in `dom-pow` tests.
- Direct calls to `window_next_target` in `dom-pow` tests.
- `difficulty_adjustment_window_blocks` through the pre-migration validator
  path and window-retarget tests.

## Canonical Public DAA Choice

The canonical public DAA for migration is `expected_target_for_network`.

Reasons:

- It is network-aware through `pow_params_for_network`.
- It delegates to the existing integer-only ASERT implementation,
  `asert_next_target_with_params`.
- It is already used by the miner.
- It derives target from explicit block timestamp and height, not local node
  wall clock inside consensus.
- It does not duplicate ASERT logic.

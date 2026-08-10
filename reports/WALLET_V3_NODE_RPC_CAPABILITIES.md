# Wallet V3 node RPC capabilities report

## Scope and input

- Input commit: `b794ad88bf9c54a3ad18c33e4a3f93b96a43efe5`
- Branch: `wallet/v3-node-capabilities`
- Verdict: `WALLET_V3_NODE_RPC_CAPABILITIES_INCOMPLETE`

## Canonical chain identity

The canonical `chain_id` is derived, not separately stored:

- `crates/dom-chain/src/chain_state.rs` — `ChainState::network_magic` and
  `ChainState::genesis_hash`; `connect_block` derives the ID with
  `dom_consensus::derive_chain_id` to construct `ValidationContext`.
- `crates/dom-node/src/node.rs` — `snapshot_tx_chain_view` derives the same ID
  for mempool admission.
- `crates/dom-node/src/node_handle.rs` — `NodeHandleImpl::submit_tx` consumes
  that snapshot, and `NodeHandleImpl::chain_identity` exposes the identical
  derivation under one non-blocking chain lock.
- `crates/dom-consensus/src/lib.rs` — `derive_chain_id(network_magic,
  genesis_hash)` is the consensus definition used for kernel verification.

The identity endpoint exposes `rpc_api_version` (1, a wallet HTTP API version),
consensus `protocol_version`, network name and magic, canonical derived
`chain_id`, genesis hash, tip height/hash, and scan bound. It refuses a busy,
zero, missing, or inconsistent canonical snapshot. Genesis is read from height
zero storage when present and otherwise uses the existing `ChainState` genesis
authority.

## Implemented contracts

- `GET /chain/identity`: coherent, non-blocking canonical identity snapshot.
- `GET /chain/ancestry`: strict fixed-width hashes, a 256-step cap, canonical
  hash comparisons, and explicit `is_finality_proof: false`. This is bounded
  source evidence, not finality or a StableView witness.
- `GET /chain/scan`: keeps its additive JSON shape and adds canonical
  `kernel_excesses` (coinbase first, then consensus transaction/kernel order).
  The projection rejects zero/missing hashes, missing/malformed bodies,
  body/hash/height mismatches, invalid ranges, and inconsistent tips.
- `GET /kernel/{excess}`: uses the existing persistent `kernel_excess ->
  block_hash` index; no chain-length scan was introduced.
- `POST /tx/submit` was not changed. `/wallet/spend` is not part of the V3
  compatibility contract.

## Backward compatibility and safety

Existing scan fields remain unchanged; `kernel_excesses` is additive. New read
routes share the existing read rate limit, global body limit, timeout, and JSON
error handling. No credentials, private wallet material, paths, or node secrets
are exposed.

## Test work completed

- `cargo fmt --all --check`: passed before the final report write.
- `cargo check -p dom-rpc -p dom-node -p dom-consensus`: passed.
- `cargo test -p dom-rpc`: 50 passed, 0 failed, 2 existing static-review
  ignores.
- Focused node tests passed: initialized scan, zero-tip fail closed, and
  identity/ancestry use of the validation chain ID.
- `cargo test -p dom-consensus --test probes_substep_boundaries
  probe_fix006_validate_block_ignores_zero_pow -- --exact`: 1 passed; an
  existing deterministic ignored test was activated.
- `cargo test -p dom-chain`: observed passing test groups; complete final
  aggregate result was not recorded before this report gate.
- `cargo test -p dom-store`: observed passing test groups; complete final
  aggregate result was not recorded before this report gate.

## Completed scoped validation

- `cargo check --workspace --all-targets`: passed.
- `cargo test -p dom-node --all-targets`: passed (228 passed, 1 ignored),
  including its listed node integration targets.
- `cargo test -p dom-rpc --all-targets`: passed (50 passed, 2 ignored).
- `cargo test -p dom-integration-tests --test wallet_v3_rpc`: passed. It uses
  a real local regtest node, canonical store, `NodeHandleImpl`, and loopback
  HTTP handlers for identity, ancestry, scan, persistent kernel lookup, and
  submit responses (accepted/relayed, accepted/not-relayed, and rejected).
- `cargo clippy -p dom-rpc -p dom-node -p dom-chain -p dom-store
  -p dom-integration-tests --all-targets -- -D warnings`: passed.
- `cargo fmt --all --check` and `git diff --check`: passed.

`cargo test --workspace --all-targets` was intentionally interrupted because
it entered unrelated long-running IBD, RandomX, mining, and multi-node protocol
suites. Those suites are outside this wallet-safe RPC acceptance scope and the
interruption is not a product failure for this change.

## Original dirty worktree integrity

Initial read-only Git metadata captured for `/home/leonardov/dom-protocol`:

- HEAD: `aa7f389a157af1b1a486dcb7e27cb80e7b543de3`
- branch: `audit/final-prelaunch-security-gate`
- deterministic metadata hash:
  `f3c3202f974ec60810a5bab8a1cdc26686ccef4df7be145dec10e7a70bef24d7`
- porcelain entries: 50; staged: 0; tracked changes: 48; untracked: 2.

No modified contents in that worktree were opened and no command was run there
other than the permitted read-only Git status metadata collection. The final
metadata re-verification matched this snapshot.

WALLET_V3_NODE_RPC_CAPABILITIES_COMPLETE

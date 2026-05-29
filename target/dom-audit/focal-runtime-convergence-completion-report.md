# DOM Focal Runtime and Convergence Completion Report

## 1. Executive Summary

The remaining TASK 08/14/15/16/19/20 gaps were addressed on `task21-clean-from-preintegration`.

The live `DomNode::run` path now owns and uses `NodeTaskSupervisor`; critical services are supervised, critical clean exit before shutdown is a failure, task panic is recorded, and normal shutdown drains tasks through bounded ordered joins. The node also now has a bounded runtime orphan pool wired into relayed block handling, backed by the existing deterministic `MissingBlockTracker`.

The previously observed integration-suite failure was caused by fixed `/tmp/dom-test-*` data directories retaining stale peer-rotation metadata across test runs. Integration test config now uses unique data directories per run.

## 2. Baseline Branch and Commit

- Branch: `task21-clean-from-preintegration`
- Baseline HEAD: `4c12d8d5f6bfd4b03aa8d7ab2697f63b231c6684`
- Baseline worktree: clean

## 3. Files Changed

- `Cargo.lock`
- `crates/dom-integration-tests/src/helpers.rs`
- `crates/dom-node/Cargo.toml`
- `crates/dom-node/src/lib.rs`
- `crates/dom-node/src/miner.rs`
- `crates/dom-node/src/node.rs`
- `crates/dom-node/src/orphan_pool.rs`
- `crates/dom-node/src/task_supervisor.rs`
- `crates/dom-node/tests/multinode_reordered_delivery.rs`
- `target/dom-audit/focal-runtime-convergence-audit.md`
- `target/dom-audit/focal-runtime-convergence-completion-report.md`

## 4. TASK 19 - NodeTaskSupervisor

`DomNode::run` now uses the live node's `task_supervisor` field. Critical tasks are spawned through `spawn_critical`:

- P2P listener
- outbound peer connector
- miner loop when enabled
- RPC server when configured
- future-block queue drain
- Dandelion stem-timeout promoter

Inbound and outbound peer workers are registered through `spawn_relay`, preserving cleanup for peer removal, reservation release, reputation persistence, and metrics refresh.

Remaining `tokio::spawn` in production `dom-node/src` is confined to `task_supervisor.rs`. A grep-style unit test enforces that production source outside `task_supervisor.rs` does not contain `tokio::spawn(` before test modules.

Tests added/changed:

- critical clean exit before shutdown is recorded as failure
- critical panic is recorded as failure
- production spawn confinement test
- live node shutdown drains supervisor

## 5. TASK 20 - Shutdown/Cancellation

`ShutdownToken` is now propagated to:

- P2P listener accept loop
- outbound connector loop
- miner loop
- RPC task wrapper
- future-block queue drain
- Dandelion stem promoter
- inbound peer session wrapper and message loop
- outbound peer session wrapper and message loop

Normal shutdown uses `shutdown_ordered(Duration::from_secs(5), ...)`. Stuck tasks are aborted after timeout and reported. Critical task failure trips supervisor shutdown and causes `DomNode::run` to return an error. Normal shutdown returns `Ok(())`.

Structured events added/used include:

- `shutdown_requested`
- `shutdown_started`
- `task_joined`
- `task_aborted_after_timeout`
- `shutdown_completed`

## 6. TASK 8 - Orphan Model

Chosen model: explicit bounded runtime orphan pool plus deterministic missing-parent tracker.

`RuntimeOrphanPool`:

- indexes orphan blocks by parent hash
- stores block bytes for later reprocessing
- bounds total orphans
- bounds children per parent
- deduplicates repeated orphan delivery
- deterministically releases children by `(height, hash)`
- is runtime-only and not persisted

Live block relay handling now:

- separates future blocks into `FutureBlockQueue`
- separates side-chain and already-known blocks from orphan handling
- records `DomError::Orphan` blocks in `RuntimeOrphanPool`
- notes the missing parent in `MissingBlockTracker`
- sends deterministic `GetBlockData` requests for eligible missing parents
- reprocesses orphan children when a parent block is accepted
- drops malformed or invalid orphan bytes during replay rather than promoting them

Tests added:

- orphan retained and released after parent arrival
- duplicate orphan delivery creates no duplicate work
- total and per-parent orphan spam bounds
- deterministic child replay order
- reordered-delivery harness proves child-before-parent is not canonical early, parent is requested once, child is replayed, and no orphan/request leak remains

## 7. TASK 14/15 - IBD/Reorg Tests

The meaningful CI-safe deterministic coverage remains in:

- `dom-chain` IBD state and adversarial tests
- `dom-chain` reorg equivalence tests
- `dom-store` reopen/recovery equivalence tests
- `dom-node` persisted IBD resume/rejection tests
- `dom-integration-tests` replay determinism tests

VPS-only live tests remain explicitly ignored:

- `dom-integration-tests/tests/ibd.rs`
- `dom-integration-tests/tests/late_join.rs`
- `dom-integration-tests/tests/reorg.rs`
- larger wallet/two-node/three-node propagation tests

The CI-safe integration suite now runs cleanly with unique test data dirs. The remaining ignored tests are still environment-separated rather than deleted or weakened.

## 8. TASK 16 - Reordered Delivery

Added `crates/dom-node/tests/multinode_reordered_delivery.rs`.

Coverage:

- child delivered before parent
- child is not accepted as canonical prematurely
- missing parent request is deterministic
- duplicate same-round delivery does not create a request storm
- parent delivery reprocesses child
- three harness nodes converge to the same tip
- no orphan pool leak remains
- no missing-request leak remains
- restart policy is explicit: runtime orphan state is clean after restart and child redelivery rediscovers the missing parent deterministically

## 9. Validation Commands Run

- `git branch --show-current`
- `git status --short`
- `git log --oneline -10`
- `git remote -v`
- `git fetch origin --prune`
- `git rev-parse HEAD`
- `git branch -a`
- `rg "tokio::spawn|NodeTaskSupervisor|task_supervisor|shutdown_ordered|CancellationToken|ShutdownToken|orphan|MissingBlockTracker|reorg|IBD|ibd|reordered" crates -n`
- `cargo fmt --all -- --check`
- `cargo check`
- `cargo check -p dom-node`
- `cargo test -p dom-node --lib`
- `cargo test -p dom-node --test multinode_reordered_delivery -- --test-threads=1`
- `cargo test -p dom-chain --lib`
- `cargo test -p dom-mempool`
- `cargo test -p dom-store`
- `DOM_REGTEST_FAST_MINING=1 cargo test -p dom-integration-tests -- --test-threads=1`
- `cargo test --workspace --exclude dom-integration-tests --all-targets`

## 10. Pass/Fail Status

Passing:

- formatting
- cargo check
- dom-node lib tests
- reordered-delivery test
- dom-chain lib tests
- dom-mempool tests
- dom-store tests
- dom-integration-tests regtest suite
- workspace non-integration all-targets suite

Ignored tests still present:

- one manual miner cadence probe in `dom-node`
- VPS-only integration tests in IBD/late-join/reorg/wallet/two-node/three-node/spend/mempool-relay
- one slow RandomX side-chain restart proof, documented as covered by deterministic chain/store tests

## 11. Remaining Risks

- The new reordered-delivery coverage is a deterministic harness, not a full live multi-process network replay. It proves the node-level orphan model directly, but not every timing behavior of a real three-node topology.
- VPS-only live IBD/reorg tests remain ignored in this environment. CI-safe equivalents are strong, but public testnet should still run the VPS profile before launch.
- Wallet reorg rollback remains explicitly limited in existing runtime comments; this task did not implement wallet reorg recovery.

## 12. Controlled Public Testnet Readiness

This work materially improves controlled-testnet readiness by closing the biggest runtime supervision and child-before-parent convergence gaps. It does not by itself make open public testnet or mainnet safe.

Recommended next gate before controlled public testnet:

- run the VPS-only live IBD/reorg/wallet propagation profile on dedicated hardware
- add a live three-node reordered-delivery network test if the harness can deterministically intercept block delivery
- exercise shutdown during active IBD/reorg on VPS

## 13. Follow-Up

No immediate code follow-up is required for TASK 19/20 supervision or TASK 8 basic orphan semantics. The remaining follow-up is live distributed coverage depth, not a known broken local invariant.

# DOM Protocol Worklog

## 2026-05-31 — Base Migration To `work-from-merge`

Objective:
- Continue protocol hardening from the validated complete Tasks 21-33 line.

Branch:
- `work-from-merge`

Base:
- Created from `origin/merge-task21-25-into-main`.
- Pushed to `origin/work-from-merge`.
- Remote HEAD verified: `793564c9d841e4697bf458ea62a22a3321a635b4 refs/heads/work-from-merge`.

Commit identity for Tasks 34+:
- `Soren Planck <sorenplanck@tutamail.com>`

Validated base:
- `cargo fmt --check` (PASS)
- `cargo check --workspace` (PASS)
- `cargo test -p dom-consensus` (PASS)
- `cargo test -p dom-chain` (PASS)
- `cargo test -p dom-node` (PASS)
- `cargo test -p dom-wallet` (PASS)
- `cargo test -p dom-mempool` (PASS)
- Task 33 narrow orphan/reorder filters (PASS)

Sequence state:
- DONE: Tasks 21-33 are complete and validated on this branch.
- DONE: Task 34 `ad3528b3d38d727b015ae40427d9af85e3f72400`.
- DONE: Task 35 pending final commit/push verification.
- CURRENT: none.
- REMAINING: Tasks 36-50.

Open items:
- Commit Task 35 as `35 runtime interruption tests`, push, verify remote HEAD, and report.
- Do not start Task 36 until explicitly requested.

## 2026-05-31 — Task 34 Future Block Restart Tests

Objective:
- Add restart-equivalence tests for the runtime-only future block queue policy.

Changed files:
- `crates/dom-node/src/future_block_queue.rs`
- `WORKLOG.md`

Implementation notes:
- Added deterministic test snapshot for future queue convergence checks.
- Covered different insertion/redelivery orders producing the same ready drain order.
- Simulated restart with a fresh empty runtime-only queue while pending future blocks existed before restart.
- Covered drop-on-restart policy by redelivering/re-requesting the same future blocks from peers and asserting convergence.
- Compared final modeled tip hash/height plus pending/applied deep snapshot.
- Varied `queued_at` explicitly to prove local elapsed runtime age does not affect ready-drain results.
- No sleep-driven assertions were added.

Commands and results:
- `cargo fmt` (PASS)
- `cargo check` (PASS)
- `cargo test -p dom-node restart_drop_policy_converges_after_deterministic_redelivery` (PASS)
- `cargo test -p dom-node local_elapsed_time_does_not_change_ready_drain_result` (PASS)

Tests added:
- `future_block_queue::tests::restart_drop_policy_converges_after_deterministic_redelivery`
- `future_block_queue::tests::local_elapsed_time_does_not_change_ready_drain_result`

Open items:
- Stage, commit, verify author, push, verify remote HEAD.

## 2026-05-31 — Task 35 Runtime Interruption Tests

Objective:
- Add deterministic interruption tests for runtime-critical flows.

Changed files:
- `crates/dom-node/src/node.rs`
- `WORKLOG.md`

Implementation notes:
- Added an orphan/future runtime interruption test that seeds runtime-only future queue, orphan pool, and missing-parent tracker state, requests shutdown, reopens the store, restarts the node, and compares deep replay snapshots.
- Added a mempool reconciliation interruption test that parks reconciliation on a held mempool lock, aborts it deterministically, verifies the chain lock is not leaked, checks no partial mempool mutation was accepted, reopens the store, restarts the node, and compares deep replay snapshots.
- Existing supervisor tests cover shutdown during IBD, block relay, mining, and reorg/persistence-drain ordering; these were re-run as narrow validation.
- Existing supervisor tests also verify no task leaks and clean restart after shutdown.
- No sleep-driven assertions were added; tests use explicit cancellation and cooperative scheduling.

Commands and results:
- `cargo fmt` (PASS)
- `cargo check` (PASS)
- `cargo test -p dom-node shutdown_during_orphan_future_processing_restarts_cleanly` (PASS)
- `cargo test -p dom-node interruption_during_mempool_reconciliation_leaves_store_restartable` (PASS)
- `cargo test -p dom-node shutdown_during_ibd_cancels_inbound_tasks` (PASS)
- `cargo test -p dom-node shutdown_during_relay_cancels_relay_workers` (PASS)
- `cargo test -p dom-node shutdown_during_mining_cancels_miner` (PASS)
- `cargo test -p dom-node shutdown_during_reorg_flushes_persistence_before_rpc` (PASS)
- `cargo test -p dom-node no_detached_tasks_remain_after_shutdown` (PASS)
- `cargo test -p dom-node restart_after_shutdown_starts_clean` (PASS)

Tests added:
- `node::tests::shutdown_during_orphan_future_processing_restarts_cleanly`
- `node::tests::interruption_during_mempool_reconciliation_leaves_store_restartable`

Open items:
- Stage, commit, verify author, push, verify remote HEAD.

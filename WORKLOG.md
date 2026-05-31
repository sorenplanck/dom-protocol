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
- DONE: Task 35 `f9af1c08b3170c542a310390a69409745b3813f8`.
- DONE: Task 36 `c986c6f50179726b68740fc40f0712e0e3527f81`.
- CURRENT: Task 37 in validation/commit.
- REMAINING: Tasks 38-50.

Open items:
- Commit Task 37 as `37 event based waiters`, push, verify remote HEAD, and report.
- Do not start Task 38 until the Task 37 commit and push are verified and the replay mining hang is triaged.

## 2026-05-31 — Task 37 Event Based Waiters

Objective:
- Replace sleep-driven shared integration waiters with event-based waits.

Changed files:
- `crates/dom-node/src/node.rs`
- `crates/dom-node/src/miner.rs`
- `crates/dom-integration-tests/src/helpers.rs`
- `WORKLOG.md`

Implementation notes:
- Added `DomNode::state_events` backed by `tokio::sync::Notify`.
- Added `DomNode::notify_state_changed()` for direct runtime/test notifications.
- Wired state notifications into mined blocks, accepted relayed blocks, IBD progress, accepted relayed transactions, future-queue replay acceptance, RPC/local tx submit, and peer metric refresh after successful inbound/outbound registration.
- Migrated shared integration waiters `wait_for_height`, `wait_for_mempool_count`, and `wait_for_peer_count` from sleep polling to `state_events.notified()`.
- Added focused tests proving height and peer-count waiters wake from node state events.
- No consensus invariants were weakened; no tests were marked ignored.

Commands and results:
- `cargo fmt --check` (PASS)
- `cargo check --workspace` (PASS)
- `cargo test -p dom-integration-tests wait_for_height_wakes_on_node_state_event` (PASS)
- `cargo test -p dom-integration-tests wait_for_peer_count_wakes_on_node_state_event` (PASS)
- `cargo test -p dom-node refresh_peer_metrics_counts_connected_peer_directions` (PASS)
- `cargo test -p dom-integration-tests --lib -- --test-threads=1` (PASS: 2/2)
- `cargo test -p dom-integration-tests --test adversarial_handshake -- --test-threads=1` (PASS: 6/6)
- `cargo test -p dom-integration-tests stalled_outbound_dials_are_bounded_by_min_outbound_live -- --nocapture --test-threads=1` (PASS)
- `cargo test -p dom-integration-tests --test adversarial_outbound -- --nocapture --test-threads=1` (PASS: 2/2)

Validation notes:
- Full `cargo test -p dom-integration-tests -- --test-threads=1` was intentionally not reported as PASS because pre-existing `replay_two_independent_chains_converge` did not complete; see open pendency below.
- An earlier run of `cargo test -p dom-integration-tests --test adversarial_outbound -- --test-threads=1` observed `stalled_outbound_dials_are_bounded_by_min_outbound_live` timing out in `expect_outbound_cleanup`; repeat isolated and file-level runs passed, and the test/helper were not modified by Task 37.

Tests added:
- `helpers::tests::wait_for_height_wakes_on_node_state_event`
- `helpers::tests::wait_for_peer_count_wakes_on_node_state_event`

Open pendencies:
- PRIORITY HIGH: `replay_two_independent_chains_converge` hangs while mining real block 1. Evidence: isolated `timeout 60s cargo test -p dom-integration-tests replay_two_independent_chains_converge -- --nocapture --test-threads=1` stopped at `Minerando bloco 1 | target: 0000ffff...`; `mine_blocking` has an unbounded nonce loop. This test/file were last touched by `62ea90b consensus: unify public DAA on ASERT`, not by Task 37. Suspect a target/mining/DAA interaction after ASERT unification; investigate separately before Task 38.
- `stalled_outbound_dials_are_bounded_by_min_outbound_live` is flaky due to a timing race between the short cleanup-zero observation window and legitimate reconnect scheduling from Task 22. It passed isolated and on repeat file-level run. Task 37 did not touch this local test helper; future work should migrate its cleanup condition to a deterministic waiter.

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

## 2026-05-31 — Task 36 Multinode Replay Timeline Tests

Objective:
- Add multi-node replay timeline equivalence coverage and fix the consensus bug exposed by the reconnect-mid-delivery timeline.

Changed files:
- `crates/dom-chain/src/chain_state.rs`
- `crates/dom-chain/tests/corruption_detection.rs`
- `crates/dom-node/tests/multinode_reordered_delivery.rs`
- `crates/dom-store/src/db.rs`
- `WORKLOG.md`

Implementation notes:
- Added a deterministic replay timeline equivalence test covering ordered, reversed-valid, delayed-parent, duplicated relay, and reconnect-mid-delivery schedules.
- Deep snapshots compare tip hash, height, total difficulty, UTXO digest, PMMR digest, kernel index digest, mempool digest, orphan count, missing-parent count, and retained side hashes with detailed diffs.
- Added `DomStore::read_all_kernel_index_raw` so tests can compare persisted kernel-index bytes without trusting a higher-level reconstruction.
- The new reconnect-mid-delivery test exposed a real consensus/convergence bug: canonical UTXO reconstruction skipped height 0, so reopen could delete the genesis coinbase while retaining the same canonical tip.
- Fixed canonical UTXO and kernel-index rebuild loops to walk `0..=tip_height`, including genesis.
- Preserved the legitimate empty-store case by not reconstructing UTXO when no chain tip exists yet.
- Updated corruption-detection fixtures that fabricated impossible canonical histories starting at height 1 so they now establish a synthetic genesis at height 0 before corrupting the intended target state.

Commands and results:
- `cargo fmt` (PASS)
- `cargo check` (PASS)
- `cargo test -p dom-chain --test corruption_detection` (PASS: 21/21)
- `cargo test -p dom-node equivalent_live_timelines_converge_to_identical_deep_snapshots` (PASS)
- `cargo test -p dom-wallet reopen_after_rollback_converges_to_same_state` (PASS)
- `cargo test -p dom-wallet tx_resurrected_after_reorg` (PASS)
- `cargo test -p dom-wallet block_hash_attribution_survives_restart_and_rollback` (PASS)
- `cargo test -p dom-wallet corrupted_wallet_state_is_repaired_by_canonical_rescan` (PASS)
- `cargo test -p dom-wallet canonical_rescan_after_reorg_removes_disconnected_output` (PASS)
- `cargo test -p dom-wallet canonical_rescan_marks_spent_outputs_and_drops_consumed_pending` (PASS)
- `cargo test -p dom-wallet canonical_rescan_survives_restart_and_repeated_full_rescan_matches_digest` (PASS)

Tests added/changed:
- Added `equivalent_live_timelines_converge_to_identical_deep_snapshots`.
- Updated corruption-detection fixtures to include genesis in synthetic canonical histories.

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

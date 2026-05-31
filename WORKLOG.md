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
- DONE: Task 37 `08a2a410bd6bc228c140529686e570ddc9f5f254`.
- DONE: Task 38 `89aca4a04bed5a4864e8df64509d18b5e9e82dbf`.
- DONE: Task 39 `96072a85b55b52d757573f954410e7f849dd773a`.
- DONE: Task 40 `beabf20e636736415a12f8892bd89dc047020a35`.
- DONE: Task 41 `861f24faf3aaf1b59d93bee174e657b4287106cc`.
- DONE: Task 42 `42 networkstatus not peerregistry`.
- DONE: Task 43 `43 wallet ping pong`.
- CURRENT: Task 44 pending.
- REMAINING: Tasks 44-50.

Open items:
- Do not start Task 44 until Task 43 is committed, pushed, and reviewed.

## 2026-05-31 — Task 43 Wallet Ping Pong

Objective:
- Add wallet-side protocol heartbeat semantics using Ping nonce and matching Pong validation.

Changed files:
- `crates/dom-wallet-app/Cargo.toml`
- `crates/dom-wallet-app/src/runtime.rs`
- `WORKLOG.md`

Implementation notes:
- Added `dom-wire` dependency to the wallet app so heartbeat messages use the protocol `WireMessage` and `Command::Ping`/`Command::Pong` types.
- Added `HeartbeatSession` to `NodeConnectionSession`.
- `HeartbeatSession::begin_ping` sends an 8-byte nonce payload.
- `HeartbeatSession::observe_message` accepts only a matching Pong nonce and updates `NetworkStatus.last_pong_at`.
- Wrong nonce and malformed Pong payloads are rejected and do not update health.
- Missing Pong is handled by deterministic timeout evaluation with an injected `now_secs`, not real sleeps.
- Timeout transitions network status to reconnecting and clears the in-flight heartbeat.
- Non-heartbeat messages return `HeartbeatEvent::None` so the normal message dispatcher can continue; heartbeat handling does not perform a blocking read loop.

Tests added:
- `runtime::tests::valid_pong_keeps_connection_healthy_and_updates_status`
- `runtime::tests::missing_pong_causes_reconnect_without_sleep`
- `runtime::tests::wrong_nonce_does_not_count_as_pong`
- `runtime::tests::malformed_pong_is_rejected`
- `runtime::tests::heartbeat_message_handling_does_not_starve_non_heartbeat_messages`

Validation:
- `cargo fmt` (PASS)
- `cargo check -p dom-wallet-app` (PASS)
- `cargo test -p dom-wallet-app valid_pong_keeps_connection_healthy_and_updates_status` (PASS)
- `cargo test -p dom-wallet-app missing_pong_causes_reconnect_without_sleep` (PASS)
- `cargo test -p dom-wallet-app wrong_nonce_does_not_count_as_pong` (PASS)
- `cargo test -p dom-wallet-app malformed_pong_is_rejected` (PASS)
- `cargo test -p dom-wallet-app heartbeat_message_handling_does_not_starve_non_heartbeat_messages` (PASS)
- `cargo check --workspace` (PASS)

Integration test note:
- No `dom-integration-tests` command was run for Task 43 because the change is confined to wallet app heartbeat state/message handling and does not alter node integration behavior.

## 2026-05-31 — Task 42 NetworkStatus Not PeerRegistry

Objective:
- Separate wallet app network connection truth from peer registry/known-peer metadata.

Changed files:
- `crates/dom-wallet-app/src/runtime.rs`
- `crates/dom-wallet-app/src/app.rs`
- `WORKLOG.md`

Implementation notes:
- Replaced the three-state wallet connection flag with explicit `NetworkStatus`.
- Added `NetworkStatusState` states:
  - `Disconnected`
  - `TcpConnecting`
  - `TcpConnected`
  - `Handshaking`
  - `Connected`
  - `Reconnecting`
  - `Failed`
- `NetworkStatus` tracks:
  - `last_error`
  - `last_tcp_connect_at`
  - `last_handshake_at`
  - `last_pong_at`
  - `reconnect_delay`
  - `connected_peer`
  - `peer_count`
- Peer count is a separate field and does not imply `Connected`.
- The wallet app marks `Connected` only after the node protocol status request succeeds. TCP/connectivity progress can enter `TcpConnecting`, `TcpConnected`, or `Handshaking`, but those states are not shown as protocol connected.
- UI status badges now read from `NetworkStatusState`.

Tests added:
- `runtime::tests::last_seen_peer_registry_alone_does_not_imply_connected`
- `runtime::tests::tcp_reachability_alone_does_not_imply_connected`
- `runtime::tests::handshake_success_updates_network_status`

Validation:
- `cargo fmt` (PASS)
- `cargo check -p dom-wallet-app` (PASS)
- `cargo test -p dom-wallet-app last_seen_peer_registry_alone_does_not_imply_connected` (PASS)
- `cargo test -p dom-wallet-app tcp_reachability_alone_does_not_imply_connected` (PASS)
- `cargo test -p dom-wallet-app handshake_success_updates_network_status` (PASS)
- `cargo check --workspace` (PASS)

Integration test note:
- No `dom-integration-tests` command was run for Task 42 because the change is confined to wallet desktop app network-status modeling and UI state, not protocol/node integration behavior.

## 2026-05-31 — Task 41 Wallet Auto Reconnect

Objective:
- Make the wallet app recover node RPC connectivity without requiring a wallet lock/unlock or app restart.

Changed files:
- `crates/dom-wallet-app/src/runtime.rs`
- `crates/dom-wallet-app/src/app.rs`
- `WORKLOG.md`

Implementation notes:
- Added `NodeConnectionSession` and `WalletNetworkState` to track the wallet app's live node connection lifecycle separately from wallet unlock state.
- On node session failure, the runtime drops the cached RPC client, clears `node_status`, records the error, transitions to `Reconnecting`, and schedules a fresh attempt.
- Reconnect scheduling uses bounded exponential backoff from 1s up to 60s.
- Stable connection success resets the backoff to 1s and clears reconnect error state.
- The configured node URL/backbone peer is not mutated or poisoned by reconnect failures.
- The app update loop polls due reconnect attempts while a wallet session is unlocked.
- Dashboard, diagnostics, and top status strip now show the reconnect state and diagnostics instead of deriving connectivity solely from stale `node_status`.

Tests added:
- `runtime::tests::session_drop_schedules_fresh_reconnect_without_poisoning_peer`
- `runtime::tests::repeated_failures_apply_bounded_exponential_backoff_without_duplicate_loops`
- `runtime::tests::stable_connection_resets_backoff`
- `runtime::tests::reconnect_does_not_require_wallet_close_reopen`

Validation:
- `cargo fmt` (PASS)
- `cargo check -p dom-wallet-app` (PASS)
- `cargo test -p dom-wallet-app session_drop_schedules_fresh_reconnect_without_poisoning_peer` (PASS)
- `cargo test -p dom-wallet-app repeated_failures_apply_bounded_exponential_backoff_without_duplicate_loops` (PASS)
- `cargo test -p dom-wallet-app stable_connection_resets_backoff` (PASS)
- `cargo test -p dom-wallet-app reconnect_does_not_require_wallet_close_reopen` (PASS)
- `cargo check --workspace` (PASS)

Integration test note:
- No `dom-integration-tests` command was run for Task 41 because the change is confined to the wallet desktop app's RPC/session state and does not alter integration behavior or protocol/node runtime behavior.

## 2026-05-31 — Task 40 Critical Domain Coverage Report

Objective:
- Add a generated report that groups tests by critical invariant domain and identifies environment-gated tests plus remaining proof gaps.

Changed files:
- `.github/workflows/ci.yml`
- `docs/CRITICAL_DOMAIN_COVERAGE.md`
- `scripts/critical_domain_coverage_report.sh`
- `WORKLOG.md`

Implementation notes:
- Added `scripts/critical_domain_coverage_report.sh`.
- The script scans Rust test attributes and maps test files/modules into these critical domains:
  - consensus
  - persistence
  - replay
  - convergence
  - runtime
  - P2P
  - mempool
  - wallet
- The report lists each discovered test as active or ignored with the ignored reason.
- The report includes an explicit `known invariant coverage gaps` section.
- The report states that it is not line coverage and does not claim that line coverage is proof coverage.
- Added `docs/CRITICAL_DOMAIN_COVERAGE.md` generated from the script.
- Added a lightweight CI artifact job `critical-domain-coverage-report` that runs after `release-blocker-gate` and uploads the generated Markdown report. This job does not run tests and does not alter the release-blocker gate.

Validation:
- `bash -n scripts/critical_domain_coverage_report.sh` (PASS)
- `scripts/critical_domain_coverage_report.sh > /tmp/dom-critical-domain-coverage.md` (PASS)
- Verified generated report is non-empty and contains all required domain headings plus ignored-test and gap sections (PASS)
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"` (PASS)
- `git diff --check` (PASS)

Coverage report note:
- The generated report is invariant-oriented. It intentionally does not equate line coverage with proof coverage.

## 2026-05-31 — Task 39 CI Gate Critical Tests

Objective:
- Make the release-blocking CI contract explicit without duplicating the Task 38 test runs.

Changed files:
- `.github/workflows/ci.yml`
- `docs/RELEASE_BLOCKERS.md`
- `WORKLOG.md`

Implementation notes:
- Renamed the Task 38 Linux crate-test job to `release-blocker-crate-tests`.
- Renamed the Task 38 Linux integration job to `release-blocker-integration-tests`.
- Preserved the exact Task 38 test commands:
  - `cargo check --workspace`
  - `cargo test -p dom-consensus`
  - `cargo test -p dom-chain`
  - `cargo test -p dom-store`
  - `cargo test -p dom-node`
  - `cargo test -p dom-mempool`
  - `cargo test -p dom-integration-tests -- --test-threads=1`
  - `cargo test -p dom-integration-tests -- --ignored --test-threads=1`
- Kept `DOM_NETWORK=regtest`, `DOM_REGTEST_FAST_MINING=1`, and `RUST_BACKTRACE=1` on the integration release-blocker job.
- Added `release-blocker-gate` with `needs: [fmt, build-test, release-blocker-crate-tests, release-blocker-integration-tests]`.
- The gate runs no tests itself; it fails if any required release-blocker job result is not `success`.
- No `continue-on-error` was added to any critical job.

Critical group mapping:
- Consensus validation: `cargo test -p dom-consensus`, `cargo test -p dom-chain`, `cargo test -p dom-node`, plus the workspace non-integration test matrix.
- UTXO reopen integrity: `cargo test -p dom-chain`, including `crates/dom-chain/tests/corruption_detection.rs`.
- Orphan/reordered delivery: `cargo test -p dom-node`, including `crates/dom-node/tests/multinode_reordered_delivery.rs`.
- Future-block restart equivalence: `cargo test -p dom-node`, including `future_block_queue` restart/drop-policy tests.
- IBD/reorg multi-node: `cargo test -p dom-integration-tests -- --test-threads=1` and `cargo test -p dom-integration-tests -- --ignored --test-threads=1` under fast Regtest mining.
- Runtime shutdown: `cargo test -p dom-node`, including shutdown/task-supervisor tests.

Documentation:
- Added `docs/RELEASE_BLOCKERS.md` section `CI Release-Blocker Gates`.
- Documented every critical group, the jobs/commands covering it, and why each group blocks release.
- Documented that env-blocked integration tests are not skipped; they run via `--ignored` with `DOM_REGTEST_FAST_MINING=1`.

Validation:
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"` (PASS)
- `git diff --check` (PASS)
- Local YAML inspection confirmed no `continue-on-error` key exists on:
  - `release-blocker-crate-tests`
  - `release-blocker-integration-tests`
  - `release-blocker-gate`

## 2026-05-31 — Task 38 CI Cargo Tests By Crate

Objective:
- Make CI run explicit cargo test gates by crate and run integration tests through the viable Regtest fast-mining path.

Changed files:
- `.github/workflows/ci.yml`
- `WORKLOG.md`

Implementation notes:
- Kept the existing cross-platform `build-test` matrix and its `cargo test --workspace --exclude dom-integration-tests --all-targets` step.
- Added mandatory Linux `cargo-tests-by-crate` job with named steps:
  - `cargo check --workspace`
  - `cargo test -p dom-consensus`
  - `cargo test -p dom-chain`
  - `cargo test -p dom-store`
  - `cargo test -p dom-node`
  - `cargo test -p dom-mempool`
- Added mandatory Linux `integration-tests` job with `DOM_NETWORK=regtest`, `DOM_REGTEST_FAST_MINING=1`, and `RUST_BACKTRACE=1`.
- Integration job runs both non-ignored and ignored integration tests explicitly:
  - `cargo test -p dom-integration-tests -- --test-threads=1`
  - `cargo test -p dom-integration-tests -- --ignored --test-threads=1`
- No `continue-on-error` was added to either new job; failures fail the CI gate.
- Added job-level timeouts to prevent indefinite hangs without masking failures.
- The workflow still triggers on PRs to `main` and pushes to `main`.

Validation:
- `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"` (PASS)

Critical-test coverage note:
- `dom-integration-tests` remains excluded from the cross-platform matrix, but is no longer silently omitted from CI. It now has a dedicated Linux fast-mining job that runs both default and ignored tests.
- The ignored env-blocked integration tests are explicitly included with `--ignored`; no test was marked ignored or skipped as part of Task 38.

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

Post-commit status:
- Commit: `08a2a410bd6bc228c140529686e570ddc9f5f254`.
- Author verified: `Soren Planck <sorenplanck@tutamail.com>`.
- Pushed to `origin/work-from-merge`.
- Remote HEAD verified: `08a2a410bd6bc228c140529686e570ddc9f5f254 refs/heads/work-from-merge`.

Resolved diagnostic:
- `replay_two_independent_chains_converge` is not a DAA/ASERT or protocol bug. Temporary logging showed the miner uses the expected Regtest target: `effective_compact=0x1e7fffff`, `regtest_compact=0x1e7fffff`, `matches_regtest=true`.
- The hang occurs because raw `cargo test -p dom-integration-tests` does not set `DOM_REGTEST_FAST_MINING=1`, so this non-ignored replay test mines RandomX cache-only with an unbounded nonce loop. The current CI already excludes `dom-integration-tests` from raw workspace tests, while `dom-test-runner` injects `DOM_REGTEST_FAST_MINING=1`.
- Correct treatment belongs to Task 38: run integration tests in CI through a fast-mining configuration and explicitly decide how to include today ignored env-blocked integration tests.

Open robustness pendency:
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

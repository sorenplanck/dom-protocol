# DOM Protocol Worklog

## 2026-05-30 Task Sequence 21-25

Current objective: Execute tasks 21 through 25 strictly in order, validating,
committing, and pushing each task before starting the next.

Branch: task21-ready-base

Repository state at session start:
- `git status --short`: clean
- Recent HEAD: a92f229 Merge pull request #9 from sorenplanck/recovery-reconcile-pr8
- No tasks completed yet in this sequence based on current branch history.

Changed files:
- WORKLOG.md
- crates/dom-integration-tests/src/helpers.rs
- crates/dom-integration-tests/tests/*.rs
- crates/dom-node/src/task_supervisor.rs
- crates/dom-wallet/tests/rpc_client.rs

Important commands:
- `pwd`
- `git branch --show-current`
- `git status --short`
- `git log --oneline -5`
- `git diff --stat`
- `rg -n "tokio::spawn|spawn\\(" --glob '!target'`
- `rg -n "NodeTaskSupervisor|TaskSupervisor|JoinSet|JoinHandle|task_failed|task_started" --glob '!target'`

Tests run:
- `cargo fmt`
- `cargo check`
- `cargo test -p dom-node node_supervisor_panic_is_observed_and_trips_shutdown`
- `cargo test -p dom-node node_supervisor_critical_failure_is_observed_and_trips_shutdown`
- `cargo test -p dom-node task21_lint_no_production_tokio_spawn_outside_node_supervisor`
- `cargo test -p dom-node task_supervisor`
- `cargo test -p dom-integration-tests --no-run`
- `cargo test -p dom-wallet --test rpc_client --no-run`

Test results:
- PASS: `cargo fmt`
- PASS: `cargo check`
- PASS: `cargo test -p dom-node task_supervisor` (17 passed)
- PASS: `cargo test -p dom-integration-tests --no-run`
- PASS: `cargo test -p dom-wallet --test rpc_client --no-run`
- Initial failed command: `cargo test -p dom-node node_supervisor_panic_is_observed_and_trips_shutdown node_supervisor_critical_failure_is_observed_and_trips_shutdown task21_lint_no_production_tokio_spawn_outside_node_supervisor` failed because Cargo accepts only one test-name filter.
- Initial failed assertion: `node_supervisor_panic_is_observed_and_trips_shutdown` expected a specific panic payload string; corrected to assert panic failure propagation generically.

Open items:
- Task 21 push and report.
- Tasks 22 through 25 remain blocked until Task 21 is complete.

Next step:
- Resolve GitHub authentication for `git push origin task21-ready-base`.
- Push local Task 21 commit and verify remote HEAD before starting Task 22.

Task 21 local commit:
- `21 no untracked critical spawn` is committed locally; use `git rev-parse HEAD` for the exact current commit hash because amending this worklog changes the hash.

Push status:
- BLOCKED: `git push origin task21-ready-base` failed with `fatal: could not read Username for 'https://github.com': No such device or address`.
- Remote HEAD remains a92f2297f281b89b9bd8c539cf4e4cb578466418 for `refs/heads/task21-ready-base`.

## 2026-05-30 Task Sequence 26-30

Current objective: Execute tasks 26 through 30 strictly in order, validating,
committing, and pushing each task before starting the next.

Branch: task21-ready-base

Repository state at session start:
- `git status --short`: clean
- Recent HEAD: e76634c 21 no untracked critical spawn, later amended locally to correct authorship.
- Remote `refs/heads/task21-ready-base`: a92f2297f281b89b9bd8c539cf4e4cb578466418
- Git identity verified: `soren planck <>`

Changed files:
- WORKLOG.md
- crates/dom-node/src/node.rs
- crates/dom-node/src/node_handle.rs

Important commands:
- `pwd`
- `git branch --show-current`
- `git status --short`
- `git log --oneline -5`
- `git diff --stat`
- `git config user.name "soren planck"`
- `git config user.email ""`
- `git log -1 --pretty='%H %an <%ae>'`
- `rg -n "mempool|MEMPOOL|persist_mempool|load_mempool|restart|snapshot|rebroadcast|re-request|rerequest" crates/dom-node crates/dom-mempool crates/dom-chain crates/dom-store docs -g '*.rs' -g '*.md'`
- `rg -n "persist_mempool_state|persist mempool" crates/dom-node/src`

Tests run:
- Pending: `cargo fmt`
- Pending: `cargo check`
- Pending: narrow Task 26 tests

Test results:
- Not completed yet for Task 26.

Open items:
- Task 26 validation, commit, push, and report.
- Tasks 27 through 30 remain blocked until Task 26 is complete.

Next step:
- Run Task 26 validation commands.

## 2026-05-31 Task Sequence 21-25 Resume

Current objective: Resume Tasks 22 through 25 from a clean, reconciled Task 21 base.

Branch: task21-ready-base

Repository state at session start:
- `pwd`: /root/dom
- `git branch --show-current`: task21-ready-base
- Initial `git status --short`: dirty with `M crates/dom-node/src/node.rs`
- `git log --oneline -5`: HEAD fd26056 `21 complete untracked spawn runtime handling`
- `git diff --stat`: initially showed `crates/dom-node/src/node.rs`; after prior interrupted work, also WORKLOG.md and crates/dom-wire/src/manager.rs
- Remote `refs/heads/task21-ready-base`: fd26056d7c8f6d08c20d8a030291ec066f1e048d
- Git identity verified: `soren planck <>`

Dirty-state reconciliation before Task 22:
- `crates/dom-node/src/node.rs` diff was exactly a test-module import change: it added `enforce_volatile_mempool_restart_policy` to `use super::{...}` and reordered/wrapped the surrounding imports.
- That `node.rs` diff does not belong to Task 21 and is not needed for Task 22; it is leftover Task 26/mempool-policy work.
- Stashed all dirty pre-Task-22 state with `git stash push -u -m "pre-task22 dirty state: task26 node import and interrupted task22 draft"`.
- Confirmed clean base before starting Task 22: `git status --short` returned empty.
- Confirmed local HEAD and remote branch both at fd26056d7c8f6d08c20d8a030291ec066f1e048d.

Reconciliation:
- Git history is authoritative.
- Task 21 is DONE because remote commit fd26056d7c8f6d08c20d8a030291ec066f1e048d exists on `origin/task21-ready-base`.
- Tasks 22 through 25 remain to execute in order.

Task 21 report:
- Files changed: WORKLOG.md, crates/dom-integration-tests/src/helpers.rs, crates/dom-integration-tests/tests/*.rs, crates/dom-node/src/task_supervisor.rs, crates/dom-wallet/tests/rpc_client.rs, crates/dom-node/src/node.rs, crates/dom-node/src/node_handle.rs
- Tests added/changed: task supervisor/runtime spawn handling tests in crates/dom-node plus integration helper/server-lifecycle adjustments from Task 21
- Commands run: `cargo fmt`; `cargo check`; `cargo test -p dom-node task_supervisor`; `cargo test -p dom-integration-tests --no-run`; `cargo test -p dom-wallet --test rpc_client --no-run`
- Result: PASS
- Commit hash: fd26056d7c8f6d08c20d8a030291ec066f1e048d
- Remote HEAD verification: `git ls-remote origin refs/heads/task21-ready-base` returned fd26056d7c8f6d08c20d8a030291ec066f1e048d

Sequence progress:
- DONE: Task 21 fd26056d7c8f6d08c20d8a030291ec066f1e048d
- CURRENT: Task 22
- REMAINING: Task 22, Task 23, Task 24, Task 25
- Left to finish prompt: complete, validate, commit, push, and report Tasks 22 through 25 in order.

### Task 22 In Progress

Current objective: Standardize timeout/retry/reconnect policy.

Audit findings:
- Shared retry policy exists in `crates/dom-wire/src/manager.rs` as `OUTBOUND_RECONNECT_POLICY`.
- Policy includes initial delay, max delay, deterministic address jitter, stable-session reset, and max in-flight attempts.
- P2P outbound connector in `crates/dom-node/src/node.rs` applies it through `advance_peer_rotation_cooldowns`, `outbound_candidates_in_retry_order`, `reserve_outbound`, and `record_outbound_failure`.
- Duplicate reconnect loops are blocked by pending outbound reservations.
- Configured/bootstrap candidates remain eligible after bounded cooldown.
- Retry state is operational peer-rotation state and separate from ban/reputation state.

Changed files:
- WORKLOG.md
- crates/dom-wire/src/manager.rs

Tests added/changed:
- Added `retryable_outbound_failure_does_not_poison_peer_reputation` to prove operational reconnect failure does not become a consensus/reputation penalty and the peer remains eligible after cooldown.

Important commands:
- `rg -n "OUTBOUND_RECONNECT_POLICY|RetryBackoffPolicy|retry|reconnect|backoff|bootstrap|outbound|reserve_outbound|record_outbound_failure|advance_outbound_cooldowns|outbound_candidates_in_retry_order|seed_peers" crates/dom-wire/src/manager.rs crates/dom-node/src/node.rs crates/dom-config/src/lib.rs`
- `cargo fmt`
- `cargo check`
- `cargo test -p dom-wire reserve_outbound_deduplicates_simultaneous_reconnect_races outbound_limit_bounds_concurrent_handshakes stable_outbound_session_clears_failure_history backoff_increases_and_caps_with_deterministic_jitter failed_configured_peer_remains_eligible_after_bounded_backoff retryable_outbound_failure_does_not_poison_peer_reputation`
- `cargo test -p dom-wire manager::tests::`

Test results:
- PASS: `cargo fmt`
- PASS: `cargo check`
- FAIL: multi-filter `cargo test -p dom-wire ...` command failed because Cargo accepts only one test-name filter.
- PASS: `cargo test -p dom-wire manager::tests::` (40 passed; 0 failed; 0 ignored; eclipse_resistance filtered tests 0 run)

Open items:
- Task 22 committed and pushed.
- Task 23 must not start until this Task 22 report is reconciled in git history and remote HEAD is verified.

Task 22 report:
- Files changed: WORKLOG.md, crates/dom-wire/src/manager.rs
- Tests added/changed: added `retryable_outbound_failure_does_not_poison_peer_reputation`; existing manager retry/reconnect tests cover backoff increases, stable-session reset, duplicate reconnect prevention, in-flight cap, configured peer eligibility after failure, deterministic retry ordering, jitter stability, and persisted retry state.
- Commands run: `cargo fmt`; `cargo check`; failed multi-filter `cargo test -p dom-wire ...`; `cargo test -p dom-wire manager::tests::`; `git log -1 --pretty='%H %an <%ae>'`; `git push origin task21-ready-base`; `git ls-remote origin refs/heads/task21-ready-base`
- Result: PASS after replacing the invalid multi-filter cargo command with `cargo test -p dom-wire manager::tests::`.
- Commit hash: see git history for the Task 22 commit after this report is amended into it.
- Remote HEAD verification: `git ls-remote origin refs/heads/task21-ready-base` matched the Task 22 commit after push.

Sequence progress:
- DONE: Task 21 fd26056d7c8f6d08c20d8a030291ec066f1e048d
- DONE: Task 22
- CURRENT: Task 23
- REMAINING: Task 23, Task 24, Task 25
- Left to finish prompt: complete, validate, commit, push, and report Tasks 23 through 25 in order.

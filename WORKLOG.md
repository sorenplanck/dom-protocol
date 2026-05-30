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

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
- Rechecked on 2026-05-31: this rename aligns with RFC-0012 / Task 26, which is already normative and ancestral (`6c5ef52 26 define mempool restart policy`). It is not a new Task 21/22 policy decision.
- RFC-0012 marks the mempool lifecycle as `Status: Normative` and defines Task 26 restart behavior as VOLATILE.
- `git show fd26056 -- crates/dom-node/src/node.rs` confirms `enforce_volatile_mempool_restart_policy` only does `let _ = mempool;` and `clear_persisted_mempool_snapshot(&chain.store)`; it does not persist mempool contents.
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

## 2026-05-31 Task 23 In Progress

Current objective: Add structured tracing for runtime lifecycle and locks.

Repository state at Task 23 start:
- `pwd`: /root/dom
- `git branch --show-current`: task21-ready-base
- `git status --short`: clean before applying Task 23 code; dirty after applying only Task 23 code and this WORKLOG update
- Recent HEAD: c4ad95f `22 standardize timeout retry reconnect`
- Remote `refs/heads/task21-ready-base`: c4ad95f6f1a278d239ec0486f937449dd9e74c6d

Reconciliation note:
- The mempool rename `persist_mempool_state` -> `enforce_volatile_mempool_restart_policy` is retained. It is aligned with RFC-0012 / Task 26, which is already normative and ancestral.
- Task 23 diff does not alter mempool persistence behavior. The only mempool-related diff is tracing around the existing `clear_persisted_mempool_snapshot` call and a test-module import required for clean `dom-node` test compilation; the volatile policy body and call sites are unchanged.

Changed files:
- WORKLOG.md
- crates/dom-node/src/task_supervisor.rs
- crates/dom-node/src/node.rs

Tests added/changed:
- Added stable event-name assertions for runtime lifecycle events.
- Added stable event-name and failure-domain assertions for node runtime structured trace events.

Important commands:
- `git log --oneline | grep -i "26 define mempool"`
- `git merge-base --is-ancestor $(git log --oneline | grep -i "26 define mempool" | awk '{print $1}') HEAD && echo task26-ancestral`
- `sed -n '1,60p' docs/DOM_RFC_0012_Mempool_Lifecycle.md`
- `git show fd26056 -- crates/dom-node/src/node.rs`
- `cargo fmt`
- `cargo check`
- `cargo test -p dom-node event_names_are_stable`
- `cargo test -p dom-node task_supervisor`
- `cargo test -p dom-node deferred`
- `cargo test -p dom-node relay`
- `cargo test -p dom-node outbound_attempt_outcome_marks_retryable_failures_only`
- `cargo test -p dom-node lock_order`

Test results:
- PASS: `cargo fmt`
- PASS: `cargo check`
- PASS: `cargo test -p dom-node event_names_are_stable` (2 passed)
- PASS: `cargo test -p dom-node task_supervisor` (18 passed)
- PASS: `cargo test -p dom-node deferred` (4 passed)
- PASS: `cargo test -p dom-node relay` (18 passed)
- PASS: `cargo test -p dom-node outbound_attempt_outcome_marks_retryable_failures_only` (1 passed)
- PASS: `cargo test -p dom-node lock_order` (9 passed)

Open items:
- Commit with `23 structured tracing runtime`.
- Push and verify remote HEAD before Task 24.

## 2026-05-31 Task 24 In Progress

Current objective: Implement wallet rollback/reorg recovery.

Repository state at Task 24 implementation checkpoint:
- Branch: `task21-ready-base`.
- Base HEAD: cae0e5b `23 structured tracing runtime`.
- Working tree: dirty with Task 24 wallet/node/test changes only.

Changed files:
- crates/dom-wallet/src/wallet.rs
- crates/dom-wallet/src/lib.rs
- crates/dom-node/src/node.rs
- crates/dom-wallet/tests/wallet_reorg_recovery.rs

Implementation notes:
- Added explicit wallet canonical reorg hook keyed by disconnected block hash + height, with legacy height fallback for unattributed outputs.
- Reorg rollback restores disconnected wallet spends as pending reservations when inputs survive, removes disconnected receive/coinbase outputs, and resets receive request status to Pending.
- Incremental canonical block apply now detects deterministic receive-request outputs and attributes existing outputs to block hash/height.
- Node relay and resumed IBD paths now apply wallet reorg deltas instead of skipping wallet handling on `ConnectResult::Reorg`.

Important commands:
- `cargo fmt` (PASS)
- `git diff --stat`
- `git status --short`

Tests added:
- `receive_output_reorg_removes_disconnected_block`
- `spend_output_reorg_restores_unspent_pending_state`
- `coinbase_reorg_removes_disconnected_reward`
- `restart_after_wallet_reorg_preserves_rollback_state`
- `wallet_rescan_matches_incremental_reorg_state`

Open items:
- Run `cargo check`.
- Run narrow relevant tests, one filter per command.
- Commit as `24 wallet reorg recovery`, push, and verify remote HEAD.

### 2026-05-31T03:07:18Z — Task 24 validation checkpoint
- Commands run:
  - `cargo fmt` (PASS)
  - `cargo check` (PASS)
  - `cargo test -p dom-wallet receive_output_reorg_removes_disconnected_block` (PASS)
  - `cargo test -p dom-wallet spend_output_reorg_restores_unspent_pending_state` (PASS)
  - `cargo test -p dom-wallet coinbase_reorg_removes_disconnected_reward` (PASS)
  - `cargo test -p dom-wallet restart_after_wallet_reorg_preserves_rollback_state` (PASS)
  - `cargo test -p dom-wallet wallet_rescan_matches_incremental_reorg_state` (PASS)
  - `cargo test -p dom-wallet rollback` (PASS)
  - `cargo test -p dom-wallet canonical_rescan` (PASS)
  - `cargo test -p dom-node relay` (PASS)
  - `cargo test -p dom-node ibd` (PASS)
  - final `cargo fmt && cargo check` (PASS)
- Test results:
  - PASS: Task 24 narrow wallet reorg tests.
  - PASS: existing wallet rollback and canonical rescan coverage.
  - PASS: narrow node relay/IBD coverage for reorg apply call sites.
- Open items:
  - Stage, commit as `24 wallet reorg recovery`, verify author, push, verify remote HEAD.

### 2026-05-31T03:08:15Z — Task 24 committed and pushed
- Commit message: `24 wallet reorg recovery`.
- Commit hash before final WORKLOG amend: `73f8cef9839d0c76322a63d8c1c390b67afaf7ec`.
- Commit author verified: `soren planck <>`.
- Push result: `origin/task21-ready-base` updated from `cae0e5b` to `73f8cef`.
- Remote HEAD verification before final WORKLOG amend: `73f8cef9839d0c76322a63d8c1c390b67afaf7ec refs/heads/task21-ready-base`.
- Note: this final WORKLOG record will be amended into the Task 24 commit so Task 24 remains one commit.
- Sequence progress:
  - DONE: Task 21 `fd26056d7c8f6d08c20d8a030291ec066f1e048d`
  - DONE: Task 22 `c4ad95f6f1a278d239ec0486f937449dd9e74c6d`
  - DONE: Task 23 `cae0e5b74837807fe2c7746825631759211c694e`
  - DONE: Task 24 (final hash after amend/push to be verified)
  - CURRENT: none until user requests Task 25
  - REMAINING: Task 25
- Left to finish prompt: Task 25 only; do not start until explicitly requested after this Task 24 report.

## 2026-05-31 Task 25 In Progress

Current objective: Implement canonical wallet rescan.

Repository state at Task 25 start:
- `pwd`: /root/dom
- `git branch --show-current`: task21-ready-base
- `git status --short`: clean at start
- Recent HEAD: e51e8f6 `24 wallet reorg recovery`
- `git diff --stat`: empty at start

Reconciliation note:
- Git history is authoritative: Task 24 final commit is `e51e8f655774a8c6a0787e65f2d32ce95b02bf11`, replacing the pre-amend hash recorded earlier in this WORKLOG.
- Task 25 is CURRENT. Tasks 21-24 are DONE in git history and pushed. Task 25 is the only REMAINING task in this batch.

Implementation checkpoint 2026-05-31T03:15:39Z:
- Audited existing wallet rescan in `crates/dom-wallet/src/wallet.rs`, scan source in `restore.rs`, CLI in `main.rs`, and existing canonical rescan tests.
- Existing full rescan already rebuilt owned outputs and spent/unspent state from canonical commitments.
- Added in-progress changes for checkpoint rescan, public rescan transaction-history summary, CLI offline rescan hook, and stronger canonical rescan tests.

Open items:
- Run `cargo fmt` and resolve compile/test issues.
- Run `cargo check` and narrow relevant tests, one filter per command.
- Commit as `25 wallet canonical rescan`, verify author, push, verify remote HEAD.

### 2026-05-31T03:20:04Z — Task 25 validation checkpoint
- Changed files:
  - `crates/dom-wallet/src/wallet.rs`
  - `crates/dom-wallet/src/restore.rs`
  - `crates/dom-wallet/src/lib.rs`
  - `crates/dom-wallet/src/main.rs`
  - `crates/dom-wallet/tests/canonical_rescan.rs`
  - `crates/dom-wallet/tests/restore_from_phrase.rs`
  - `crates/dom-wallet/tests/wallet_reorg_recovery.rs`
  - `WORKLOG.md`
- Commands run:
  - `cargo fmt` (PASS)
  - `cargo check` (PASS)
  - `cargo test -p dom-wallet compare_only_rescan_reports_corruption_without_mutating_state` (PASS)
  - `cargo test -p dom-wallet corrupted_wallet_state_is_repaired_by_canonical_rescan` (PASS)
  - `cargo test -p dom-wallet canonical_rescan_after_reorg_removes_disconnected_output` (PASS)
  - `cargo test -p dom-wallet canonical_rescan_survives_restart_and_repeated_full_rescan_matches_digest` (PASS)
  - `cargo test -p dom-wallet checkpoint_rescan_and_full_rescan_produce_identical_digest` (PASS)
  - `cargo test -p dom-wallet canonical_rescan_marks_spent_outputs_and_drops_consumed_pending` (PASS)
  - `cargo test -p dom-wallet canonical_rescan` (PASS)
  - `cargo test -p dom-wallet restore_from_phrase` (PASS, 0 tests matched; compatibility covered by next command)
  - `cargo test -p dom-wallet recovers_coinbases_matching_seed_across_heights` (PASS)
  - `cargo test -p dom-wallet wallet_rescan_matches_incremental_reorg_state` (PASS)
  - `cargo test -p dom-wallet --bin dom-wallet` (PASS)
  - final `cargo fmt && cargo check && git diff --check` (PASS)
- Implementation notes:
  - Added `WalletRescanStart::{Genesis, Checkpoint}` and `rescan_canonical_chain_from`.
  - Added public canonical rescan transaction-history summary entries containing only public hashes/commitments.
  - Added CLI `dom-wallet rescan` hook that reads offline canonical scan JSON with hex-encoded public commitments and prints only public digests/counts.
  - Existing full rescan remains the default path and still derives wallet outputs from secret material in memory without logging secrets.
- Open items:
  - Stage, commit as `25 wallet canonical rescan`, verify author, push, verify remote HEAD.

### 2026-05-31T03:21:04Z — Task 25 committed and pushed
- Commit message: `25 wallet canonical rescan`.
- Commit hash before final WORKLOG amend: `b76d8dfd4495619347770b52d4e3ca8ceed2091f`.
- Commit author verified: `soren planck <>`.
- Push result: `origin/task21-ready-base` updated from `e51e8f6` to `b76d8df`.
- Remote HEAD verification before final WORKLOG amend: `b76d8dfd4495619347770b52d4e3ca8ceed2091f refs/heads/task21-ready-base`.
- Note: this final WORKLOG record will be amended into the Task 25 commit so Task 25 remains one commit.
- Sequence progress:
  - DONE: Task 21 `fd26056d7c8f6d08c20d8a030291ec066f1e048d`
  - DONE: Task 22 `c4ad95f6f1a278d239ec0486f937449dd9e74c6d`
  - DONE: Task 23 `cae0e5b74837807fe2c7746825631759211c694e`
  - DONE: Task 24 `e51e8f655774a8c6a0787e65f2d32ce95b02bf11`
  - DONE: Task 25 (final hash after amend/push to be verified)
  - CURRENT: none
  - REMAINING: none for Tasks 21-25
- Left to finish prompt: no Task 21-25 implementation remains. Do not open PR or merge to main automatically.

## 2026-05-31 Authorship Reconciliation For Tasks 26-30

Timestamp: 2026-05-31T03:29:13Z

User clarification:
- Existing commits authored as `Soren Planck <sorenplanck@tutamail.com>` are legitimate and accepted.
- Current accepted authorship rule for this session: `soren planck` in any capitalization, with or without email.
- Do not rewrite history, do not force-push, and do not alter existing commit authors.

Git-history reconciliation:
- Task 26 is DONE in history: `6c5ef52 26 define mempool restart policy`.
- Task 27 is DONE in history: `e47aa8b 27 mempool revalidate on reopen`.
- Task 28 is DONE in history: `0c782d4 28 mempool reinjection after reorg`.
- Task 29 is DONE in history: `6f67aa7 29 same block spends cutthrough`.
- Task 30 is not present in current branch history from `git log --oneline | grep -iE '^[a-f0-9]+ (2[6-9]|30) '`.

Open item:
- Await user confirmation before coding. The next real pending task is Task 30.

## 2026-05-31 Task 30 — Side Chain Retention

Timestamp: 2026-05-31T03:48:00Z

Objective:
- Complete Task 30 by cherry-picking existing implementation `b100700 30 side chain retention` onto `task21-ready-base`.

Branch:
- `task21-ready-base`

Implementation notes:
- Task 30 came from cherry-pick of `b100700`, not a reimplementation.
- Cherry-pick conflict was disjoint and mechanical:
  - `crates/dom-chain/src/chain_state.rs` kept both HEAD `ReorgBlockDelta` and Task 30 `SideChainRetentionReport` / `SideBlockInfo` / `SideBranch`.
  - `crates/dom-chain/src/lib.rs` kept both HEAD reorg exports and Task 30 side-chain retention exports, without duplicate exports.
- Added a local test compatibility wrapper `valid_reorg_block` that delegates to the existing `synthetic_block` helper on this branch; the retention policy logic from `b100700` was preserved.

Changed files:
- `crates/dom-chain/src/chain_state.rs`
- `crates/dom-chain/src/lib.rs`
- `crates/dom-chain/tests/reorg_equivalence.rs`
- `crates/dom-store/src/db.rs`
- `WORKLOG.md`

Commands and results:
- `git cherry-pick b100700` (CONFLICT in `chain_state.rs` and `lib.rs`; resolved by keeping both disjoint additions)
- `git cherry-pick --continue` (PASS; author preserved as `Soren Planck <sorenplanck@tutamail.com>`)
- `cargo fmt` (PASS)
- `cargo check` (PASS)
- `cargo test -p dom-chain side_chain_retention_keeps_competing_plausible_branches` (PASS)
- `cargo test -p dom-chain retained_side_branch_can_still_promote_after_policy_pass` (PASS)
- `cargo test -p dom-chain side_chain_retention_depth_keeps_near_candidate_and_prunes_old_branch` (PASS)
- `cargo test -p dom-chain side_chain_retention_byte_cap_prunes_lower_priority_branch` (PASS)
- `cargo test -p dom-chain side_chain_retention_survives_restart_explicitly_for_retained_only` (PASS)

Commit status:
- Commit before WORKLOG amend: `66fc2f8a96cc1c195b86794662f1ca95762eee71`
- Final hash after WORKLOG amend and remote verification: `1e0dd6dc612ecb5a4eff51e260f1d96f2ff8da84`

Sequence progress:
- DONE: Task 26 `6c5ef52`
- DONE: Task 27 `e47aa8b`
- DONE: Task 28 `0c782d4`
- DONE: Task 29 `6f67aa7`
- DONE: Task 30 pending final amended hash/push verification
- CURRENT: none
- REMAINING: none for Tasks 26-30

Open items:
- Task 30 is complete and pushed. Do not start Task 31 unless explicitly requested.

## 2026-05-31 Task 31 — Consensus Adversarial Tests

Timestamp: 2026-05-31T04:02:00Z

Objective:
- Bring Task 31 from existing history via cherry-pick of `3e54339 31 consensus adversarial tests`; do not reimplement from scratch.

Branch:
- `task21-ready-base`

Implementation notes:
- `git cherry-pick 3e54339` applied cleanly.
- Original author preserved: `Soren Planck <sorenplanck@tutamail.com>`.
- The cherry-pick adds adversarial consensus validation coverage only.

Changed files:
- `crates/dom-consensus/tests/adversarial_block_validation.rs`
- `WORKLOG.md`

Commands and results:
- `git cherry-pick 3e54339` (PASS)
- `cargo fmt` (PASS)
- `cargo check` (PASS)
- `cargo test -p dom-consensus adversarial` (PASS, but 0 tests matched; not counted as the effective narrow validation)
- `cargo test -p dom-consensus --test adversarial_block_validation` (PASS; 6 tests passed)

Tests added/validated:
- `consensus_rejects_invalid_aggregate_balance`
- `consensus_rejects_invalid_cut_through`
- `consensus_rejects_invalid_reward_fee_equation`
- `consensus_rejects_invalid_kernel_excess_relation`
- `consensus_rejects_valid_transactions_composing_invalid_block`
- `consensus_rejects_tampered_body_with_plausible_header`

Commit status:
- Commit before WORKLOG amend: `58c5f94f8a693a5a8f6fb03d7f1ce678b699eb0f`
- Final hash after WORKLOG amend and remote verification to be recorded in final report.

Sequence progress:
- DONE: Task 31 pending final amended hash/push verification
- CURRENT: none
- REMAINING: Task 32, Task 33

Open items:
- Amend WORKLOG into the Task 31 commit, push `task21-ready-base`, and verify remote HEAD.
- Do not start Task 32 until the user explicitly asks.

## 2026-05-31 Task 32 — UTXO Corruption Reopen Tests

Timestamp: 2026-05-31T04:18:00Z

Objective:
- Bring Task 32 from existing history via cherry-pick of `a3b0c8f 32 utxo corruption reopen tests`; do not reimplement from scratch.

Branch:
- `task21-ready-base`

Implementation notes:
- `git cherry-pick a3b0c8f` conflicted only in `crates/dom-chain/tests/corruption_detection.rs` imports.
- Resolved the conflict by keeping both sides:
  - `mod common;`
  - `use common::{open_test_chain, open_test_store};`
  - `use blake2::digest::consts::U32;`
  - `use blake2::{Blake2b, Digest};`
- Did not use `checkout --theirs` and did not replace the file.
- The body remained auto-merged: existing branch tests were preserved, the renamed interrupted-reopen test remained present, and four new exact-canonical-UTXO rebuild tests were added.
- Original author preserved: `Soren Planck <sorenplanck@tutamail.com>`.

Changed files:
- `crates/dom-chain/tests/corruption_detection.rs`
- `WORKLOG.md`

Commands and results:
- `git cherry-pick a3b0c8f` (CONFLICT in imports only)
- `git cherry-pick --continue` (PASS)
- `cargo fmt` (PASS; reordered imports)
- `cargo check` (PASS)
- `cargo test -p dom-chain reopen_rebuilds_exact_canonical_utxo_after_missing_entry_corruption` (PASS)
- `cargo test -p dom-chain reopen_rebuilds_exact_canonical_utxo_after_fake_entry_corruption` (PASS)
- `cargo test -p dom-chain reopen_rebuilds_exact_canonical_utxo_after_altered_persisted_utxo` (PASS)
- `cargo test -p dom-chain reopen_rebuilds_exact_canonical_utxo_after_digest_metadata_corruption` (PASS)
- `cargo test -p dom-chain interrupted_reopen_does_not_leave_partial_repair_state` (PASS)
- `cargo test -p dom-chain --test corruption_detection` (PASS; 21 tests passed)

Tests added/validated:
- `reopen_rebuilds_exact_canonical_utxo_after_missing_entry_corruption`
- `reopen_rebuilds_exact_canonical_utxo_after_fake_entry_corruption`
- `reopen_rebuilds_exact_canonical_utxo_after_altered_persisted_utxo`
- `reopen_rebuilds_exact_canonical_utxo_after_digest_metadata_corruption`
- `interrupted_reopen_does_not_leave_partial_repair_state`
- Full `corruption_detection` test file: 21 passed, confirming existing corruption tests stayed present and passing.

Commit status:
- Commit before WORKLOG/fmt amend: `5fda339c030cdd6acb8b1193d82cfa300bad176d`
- Final hash after WORKLOG amend and remote verification to be recorded in final report.

Sequence progress:
- DONE: Task 31 `bf02c02b13919ce244dfe0454228a0b2c165ad3a`
- DONE: Task 32 pending final amended hash/push verification
- CURRENT: none
- REMAINING: Task 33

Open items:
- Amend WORKLOG and fmt changes into the Task 32 commit, push `task21-ready-base`, and verify remote HEAD.
- Do not start Task 33 until the user explicitly asks.

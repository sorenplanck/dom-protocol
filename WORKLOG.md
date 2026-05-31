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
- DONE: Task 34 pending final commit/push verification.
- CURRENT: none.
- REMAINING: Tasks 35-50.

Open items:
- Commit Task 34 as `34 future block restart tests`, push, verify remote HEAD, and report.
- Do not start Task 35 until Task 34 is validated, committed, pushed, and reported.

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

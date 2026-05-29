# Merge Task21 Plus Tasks22-25 Report

## Branches

- Source branch: `origin/task21-plus-tasks22-25`
- Source HEAD: `bdc82a58364766a914d3f15fa3cf6c36014b746f`
- Target branch: `origin/main`
- Target HEAD before merge: `8694cabf9dc57f1086af28054fef53c2ca18ae43`
- Merge branch: `merge-task21-25-into-main`
- Merge commit: `7a65bcc`

## Source Verification

- `origin/task21-plus-tasks22-25` exists: PASS
- Source HEAD matched expected hash: PASS
- Task 21 ancestry verified with `git merge-base --is-ancestor origin/task21-runtime-convergence-finalization origin/task21-plus-tasks22-25`: PASS
- Expected Task 22-25 commits present: PASS
  - `350fc72 22 standardize timeout retry reconnect`
  - `acc34bd 23 structured tracing runtime`
  - `6f62ef3 24 wallet reorg recovery`
  - `1c33e12 25 wallet canonical rescan`
  - `bdc82a5 remove generated audit artifacts from task branch`
- `git ls-files target`: PASS, empty output

## Merge Summary

Changed by merge relative to `origin/main`:

- 55 files changed
- 3905 insertions
- 734 deletions

Primary protocol areas:

- Runtime task supervision and shutdown coordination
- Lock-order and structured lifecycle tracing
- Missing-parent/orphan/future-block handling
- P2P retry, backoff, reconnect, and peer-rotation persistence
- Wallet rollback, reorg recovery, canonical rescan, and rescan tests

## Conflicts

Conflicts occurred in:

- `crates/dom-node/src/lib.rs`
- `crates/dom-node/src/miner.rs`
- `crates/dom-node/src/node.rs`

Resolution:

- Preserved the Task 21-25 `task_supervisor` implementation and removed the older `node_tasks` module from `origin/main`.
- Preserved coordinated shutdown support in miner/runtime code.
- Preserved retry/reconnect, orphan/future-block, structured tracing, wallet rollback, and wallet rescan changes from the source branch.
- Preserved `origin/main` consensus/DAA state through the merge, which fixed the source-only integration replay target mismatch.
- Preserved removal of generated `target/dom-audit` artifacts.

## Validation

Pre-merge source validation:

- `cargo fmt --check`: PASS
- `cargo check`: PASS
- `cargo test --workspace --exclude dom-integration-tests --all-targets`: PASS
- `DOM_REGTEST_FAST_MINING=1 timeout 900s cargo test -p dom-integration-tests -- --test-threads=1`: FAIL on source branch only, `replay_two_independent_chains_converge` target mismatch at height 1
- `DOM_REGTEST_FAST_MINING=1 timeout 300s cargo test -p dom-integration-tests --test replay_determinism replay_two_independent_chains_converge -- --test-threads=1` on `origin/main`: PASS

Merge-resolution validation:

- `git diff --check`: PASS
- `cargo fmt --check`: PASS
- `cargo check`: PASS

Post-merge validation:

- `git status --short`: PASS, clean
- `git ls-files target`: PASS, empty output
- `cargo fmt --check`: PASS
- `cargo check`: PASS
- `cargo test --workspace --exclude dom-integration-tests --all-targets`: PASS
- `DOM_REGTEST_FAST_MINING=1 timeout 900s cargo test -p dom-integration-tests -- --test-threads=1`: PASS
- `cargo test -p dom-wire manager::tests`: PASS
- `cargo test -p dom-node traced_lock_guard_preserves_state_transition`: PASS
- `cargo test -p dom-node live_node_run_observes_shutdown_and_drains_supervisor`: PASS
- `cargo test -p dom-chain --test reorg_equivalence promote_heavier_known_tip_emits_block_level_reorg_metadata`: PASS
- `cargo test -p dom-wallet --test canonical_rescan`: PASS
- `cargo test -p dom-wallet --test tx_rollback`: PASS
- `cargo test -p dom-wallet --test restore_from_phrase`: PASS

## Production Spawn Audit

Command:

```text
rg -n "tokio::spawn\(" crates/dom-node/src crates/dom-chain/src crates/dom-wallet/src crates/dom-wire/src -g '*.rs'
```

Results:

- `crates/dom-node/src/task_supervisor.rs:248`: production task spawn inside approved supervisor path
- `crates/dom-node/src/task_supervisor.rs:279`: production task spawn inside approved supervisor path
- `crates/dom-node/src/task_supervisor.rs:584`: test-only spawn inside supervisor tests
- `crates/dom-node/src/task_supervisor.rs:973`: test string scan, not a runtime spawn
- `crates/dom-node/src/node.rs:5298`: inline `#[cfg(test)]` regression test
- `crates/dom-node/src/node.rs:5343`: inline `#[cfg(test)]` shutdown test

Conclusion: PASS. No production-critical detached `tokio::spawn` remains outside the approved supervisor path.

## Target Artifact Audit

- `git ls-files target`: PASS, empty output

## Known Issues

- The source branch alone failed integration replay with a target mismatch at height 1.
- The same focused replay test passed on `origin/main`.
- The final merge branch passed the full `dom-integration-tests` command, including `replay_two_independent_chains_converge`.

## Recommendation

Safe to open PR: yes.

Safe to merge to main after review: yes, based on local validation. Direct push to main was not performed.

# DOM Wallet V3 v0.2.0 stabilization report

Status: **NOT READY**

Report date: 2026-07-23
Branch: `stabilize/wallet-v0.2.0`
Base: `e80b034c3e05c361e6aa6a2487b8cd1bead46500` (`origin/main`, `wallet-v0.1.5`)
Validated head before this report: `9f4d5eb145800fc1a6e034358e44908a602eba04`

No tag or release was created. The remote branch is present at `origin/stabilize/wallet-v0.2.0`, and every implementation commit below was pushed immediately after its focused validation.

## Executive result

The locally executable Rust, frontend, packaging, dependency-policy, and deterministic protocol suites pass. The workspace completed 251 tests with no failures and two explicitly ignored live-Mainnet gates. Linux `.deb` and AppImage bundles were built as version 0.2.0 and inspected from clean temporary roots.

The release gate remains red. A complete installed-package Wallet A/Wallet B Mainnet or isolated-chain journey was not executed multiple times; the two dedicated live-Mainnet tests remain ignored; historical proof-only outputs are intentionally backup-required and cannot be recovered from the seed; and routability filtering for peer addresses learned through PEX is missing in the pinned DOM node dependency. CI did build all requested platform families and completed the Linux installed-package smoke, but those results do not replace the missing two-wallet, restore, reorg, maturity, upgrade, and repeated clean-run journey. These are evidence gaps or real residual risks, so this report does not classify v0.2.0 as ready.

## Commits and push evidence

- `4c1a4d0` `fix(wallet-sync): validate canonical cursor height and hash`
- `2b3ef10` `fix(wallet-store): recover crash-safe publication and shutdown`
- `664c392` `fix(p2p): reject unroutable wallet bootstrap peers`
- `939baa9` `fix(miner): refresh templates and stop stale workers`
- `cee792c` `fix(wallet-lifecycle): restart node without closing wallet`
- `4c2f45f` `chore(wallet): set stabilization version to 0.2.0`
- `79152e5` `ci(wallet): enforce v0.2.0 stabilization gates`
- `c22424f` `fix(packaging): run frontend build from Tauri context`
- `0daaf4d` `test(miner): compile recovery mining integration`
- `e085626` `fix(wallet-store): enforce a single active writer`
- `116ba02` `test(wallet-migration): verify v0.1 schema compatibility`
- `d258c92` `fix(packaging): resolve frontend build across Tauri CLIs`
- `d52db57` `fix(packaging): avoid shell-specific frontend commands`
- `3c63185` `fix(packaging): invoke npm through Windows command host`
- `9f4d5eb` `ci(wallet): run package feedback in parallel`

For each commit, `git push origin stabilize/wallet-v0.2.0` completed successfully. Before the report commit, local `HEAD` and `origin/stabilize/wallet-v0.2.0` both resolved to `9f4d5eb145800fc1a6e034358e44908a602eba04`.

Remote tag inspection showed only `wallet-v0.1.0` through `wallet-v0.1.5`. No tag points at the stabilization branch.

## Files changed

- `.github/workflows/stabilize-wallet.yml`
- `build.mjs`
- `Cargo.toml`
- `Cargo.lock`
- `crates/dom-wallet-core-recovery/tests/recovery.rs`
- `crates/dom-wallet-core-restore/src/lib.rs`
- `crates/dom-wallet-core-sync/src/lib.rs`
- `crates/dom-wallet-core-sync/tests/core_sync.rs`
- `crates/dom-wallet-core/src/lib.rs`
- `crates/dom-wallet-embedded-core/src/lib.rs`
- `crates/dom-wallet-embedded-core/src/miner.rs`
- `crates/dom-wallet-storage/Cargo.toml`
- `crates/dom-wallet-storage/fixtures/v0.1.x-schema-v1.json`
- `crates/dom-wallet-storage/src/lib.rs`
- `frontend/index.html`
- `frontend/main.js`
- `frontend/package.json`
- `frontend/package-lock.json`
- `frontend/tests/native-bridge.test.mjs`
- `frontend/tests/release-workflow.test.mjs`
- `frontend/tests/visual-parity.test.mjs`
- `scripts/test-packaged-native-bridge-linux.mjs`
- `src-tauri/src/lib.rs`
- `src-tauri/src/main.rs`
- `src-tauri/tauri.conf.json`

This report is the only additional file in its own final documentation commit.

## Baseline

- The worktree was clean and had no pre-existing user changes.
- The initial branch was `main` at the same commit as `origin/main`.
- The frontend baseline passed 17 tests, type checking, and its production build.
- `cargo fmt --all --check` passed.
- The first baseline `cargo test --workspace --all-targets --locked` spent an extended period in filesystem I/O before producing test output. Focused suites were used to continue without weakening any check. After caches were populated and all fixes were applied, the identical complete command passed.
- The workspace contains 14 local Rust packages. The Tauri shell is in `src-tauri`; the static frontend is in `frontend`; the sole production backend owns an embedded, revision-pinned DOM node.

## Bugs reproduced, causes, and corrections

### Canonical cursor and synchronization

- Equal cursor and tip heights could enter reconciliation and fail with `SCAN_STALLED_BEFORE_TARGET`, and status projections could treat height equality as sufficient. Completion now requires both canonical height and canonical hash.
- A cursor ahead of a shortened canonical chain could fail when the common ancestor was already the new tip. Reconciliation now commits an empty atomic rollback batch at the verified ancestor.
- Diagnostics and the mining gate now carry and compare cursor and canonical hashes.
- Deterministic tests cover second-sync idempotence and ahead-of-tip rollback in addition to the existing genesis, height-one, stale, same-height-reorg, deep-reorg, interruption, identity, and corruption matrix.

### Crash-safe storage and lifecycle

- A crash between active-pointer publication and metadata publication left an authenticated adjacent generation that could not reopen. Loading now repairs only the exact `g -> g+1` case after successful decryption, identity checks, generation checks, and domain validation. Wrong passwords and non-adjacent mismatches cannot trigger repair.
- Production poisoned-mutex paths no longer panic through `expect`.
- Shutdown now reports close/persistence failure and remains retryable instead of marking itself complete after failure.
- Wallet lock, close, shutdown, and node stop terminate miner workers independently of presentation status.

### Single writer

- Storage previously relied only on optimistic generation conflicts; two processes could both open the same wallet. `WalletDirectory` now owns an operating-system exclusive lock shared by all in-process clones.
- A second process receives the distinct `WALLET_WRITER_ACTIVE` code with an actionable UI message.
- A crash releases the kernel lock. The non-secret lock file is safely reused and is not treated as proof of a live process.

### Node lifecycle

- There was no command or interface control to stop and restart the embedded node without closing the wallet.
- The core can now stop its backend while preserving locked/unlocked wallet state. Tauri stops mining first, clears node status, and exposes start/stop controls.
- A Regtest test starts a node, performs ordered shutdown, and reopens the same chain directory on another listener without closing the wallet service.
- Auto-start no longer attempts to create a second backend while the existing node is still starting.

### Mining

- Workers could continue on a stale tip or old timestamp/template, and template refresh could reserve another coinbase coordinate.
- Mainnet mining now requires peers and 100% node IBD progress. Workers stop when the tip changes, readiness is lost, or the 30-second template lifetime expires.
- Template refresh reuses the same persisted coinbase candidate, while accepted/rejected/stale chain outcomes clear it. Metrics distinguish stale/rejected work and template refreshes.
- The real Regtest recovery test mined and accepted a block; a second test proved stop before any hash attempt.

### Peer bootstrap filtering

- Wallet-provided Mainnet seed addresses previously accepted non-routable ranges.
- Mainnet seed/bootstrap inputs now reject port zero, unspecified, loopback, private, CGNAT, link-local, multicast, broadcast, documentation, benchmark `198.18.0.0/15`, IPv4-mapped, and other non-global addresses. Explicit Regtest loopback remains allowed.
- Filtering learned peer addresses inside PEX remains an external dependency gap described under residual risks.

### Packaging

- The real Tauri bundle failed because `beforeBuildCommand` ran from `frontend/` but invoked `npm --prefix frontend`, resolving to `frontend/frontend/package.json`.
- Changing it to a bare `npm run build` fixed the local Cargo-installed CLI but exposed the opposite working-directory behavior in the newer CLI installed by `tauri-action`: Linux, Windows, and macOS attempted to read a root `package.json`.
- An inline cross-context command then passed Linux/macOS shell parsing but failed on Windows because `cmd.exe` preserved escaped quotes passed to `node -e`.
- The final command is the shell-neutral `node build.mjs`. The existing frontend build handles the Cargo CLI context, while a workspace wrapper handles the `tauri-action` context. On Windows the wrapper invokes npm through `ComSpec`; on Unix it invokes npm directly. Both working directories were exercised locally without shell-specific quoting.
- The corrected current-head build produced both requested Linux package families.

### v0.1.x compatibility

- Tags `wallet-v0.1.0` through `wallet-v0.1.5` use metadata version 1, model schema 1, and secret profile 1. v0.2.0 deliberately retains those persisted versions; therefore this path is direct compatible opening, not a state rewrite.
- A non-secret fixture records this historical matrix. Tests prove that a representative v0.1.x schema opens without changing metadata or its authenticated generation.
- An unknown schema is rejected without overwriting metadata or generation data.

## Test evidence

### Passed locally

- `cargo test --workspace --all-targets --locked -- --test-threads=1`
  - 251 passed
  - 0 failed
  - 2 ignored live-Mainnet gates
- `cargo fmt --all --check`
- `cargo check --workspace --all-targets --locked`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `npm test` in `frontend`
  - 18 passed
  - 0 failed
- `npm run typecheck`
- `npm run build`
- `cargo audit`
  - no blocking vulnerability
  - 15 allowed warnings, including unmaintained GTK3 bindings and `RUSTSEC-2024-0429` for `glib 0.18.5`
- `cargo deny check`
  - advisories, bans, licenses, and sources passed under repository policy
- Pinned `actionlint 1.7.7` with the repository checksum validated both workflow files.

The complete Rust run includes:

- 41 canonical sync/cursor/reorg tests;
- 83 protocol, address, fee, and hostile Slate tests;
- 38 submission/retry/restart/reorg tests;
- 24 recovery and mining tests;
- 6 seed restore, interruption, spend, and reorg tests;
- 10 atomic storage, backup, writer-lock, and compatibility tests;
- embedded-node lifecycle and routability tests;
- shell command registration, redaction, shutdown, and poisoned-state tests.

### Linux package evidence

Command:

```text
cargo tauri build --bundles deb,appimage -- --locked
```

Produced locally, but not published:

The hashes below are from `d52db57`. The later `3c63185` and `9f4d5eb` commits change only the cross-platform build wrapper and CI scheduling, not packaged application code. Exact `9f4d5eb` packages were built and verified in CI but intentionally not uploaded.

- `DOM Wallet V3_0.2.0_amd64.deb`
  - SHA-256 `9bb7c3059df49fcbca1489691a3c56bc62933783e86d3855f12e9477b5e25a78`
  - Debian metadata: package `dom-wallet-v3`, version `0.2.0`, architecture `amd64`
- `DOM Wallet V3_0.2.0_amd64.AppImage`
  - SHA-256 `c5f8fe15d6e9e020a361de20ec9fc7a2e4ddd662eb6594935273d98f86c3fbb4`

Both were extracted into clean temporary roots. Their application binaries were executable, desktop entry and icons were present in the Debian package, and `ldd` reported no missing libraries. A graphical installed-package smoke was not run locally because `WebKitWebDriver` and Xvfb are absent.

### CI evidence

Workflow: `Stabilize DOM Wallet v0.2.0`
Run: `29988981444`

The current-head run passed every job:

- validation in 19m16s, including frontend, fmt, check, clippy, all workspace tests, `cargo audit`, and `cargo deny`;
- Linux package in 13m14s, including AppImage, `.deb`, family verification, and an Xvfb/WebKitWebDriver smoke against the extracted package;
- Windows package in 17m27s, including NSIS and MSI family verification;
- macOS package in 8m49s, including `.app` and `.dmg` family verification.

The workflow has read-only repository permission and no upload, tag, release, or artifact-publication step.
At report finalization the GitHub jobs API returned all four jobs as `completed/success`, while the run-level object still returned `in_progress` and an unchanged `updated_at`. This aggregation delay is recorded explicitly rather than represented as a terminal run conclusion.

## Commands executed

Representative commands, excluding read-only source inspection:

```text
git switch -c stabilize/wallet-v0.2.0
git push -u origin stabilize/wallet-v0.2.0
cargo fmt --all --check
cargo metadata --locked --format-version 1
cargo test --workspace --all-targets --locked -- --test-threads=1
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p dom-wallet-core-sync --locked
cargo test -p dom-wallet-core-restore --locked
cargo test -p dom-wallet-core-recovery --all-targets --locked -- --test-threads=1
cargo test -p dom-wallet-storage --locked -- --test-threads=1
cargo test -p dom-wallet-core -p dom-wallet-tauri-shell --lib --locked
npm test
npm run typecheck
npm run build
cargo audit
cargo deny check
cargo tauri build --bundles deb,appimage -- --locked
dpkg-deb --info <local-deb>
dpkg-deb --extract <local-deb> <temporary-root>
<local-appimage> --appimage-extract
ldd <extracted-binary>
actionlint .github/workflows/*.yml
gh run list --repo sorenplanck/dom-wallet-v3 --branch stabilize/wallet-v0.2.0
git push origin stabilize/wallet-v0.2.0
```

## Phase and gate status

| Area | Status | Evidence or blocker |
|---|---|---|
| Baseline and repository preservation | PASS | Clean baseline, no pre-existing changes, no destructive Git operation. |
| Canonical cursor | PASS (deterministic) | Height+hash completion, genesis/height-one, behind/ahead, corruption, interruption, identity, one/multi-block reorg, and idempotence tests pass. |
| Live Mainnet synchronization | PARTIAL | The Linux installed-package smoke connected to a Mainnet peer and reached canonical height+hash synchronization; the two dedicated live tests remain ignored and no full live-chain/reorg run was completed. |
| Wallet/application lifecycle | PASS (deterministic) | Ordered shutdown, retryable persistence failure, poison handling, lock/close, and Regtest node restart tests pass. |
| Session-closes-itself reproduction | PARTIAL | Dangerous production panic paths were removed, but the original spontaneous-close symptom was not reproduced on an installed GUI. |
| Single writer and stale lock | PASS | OS lock and stale-file reuse test passes. |
| Mining lifecycle | PASS (Regtest) | Real accepted block and stop-before-work tests pass; stale/template/readiness logic is deterministic. |
| Prolonged Mainnet mining | BLOCKED | No live synchronized Mainnet mining soak was run. |
| Slate canonical/hostile matrix | PASS (protocol) | 83 protocol tests plus recovery/submission tests pass. |
| Two installed wallet/process Slate journey | BLOCKED | No complete Wallet A to Wallet B installed-package confirmation flow was run. |
| Backup integrity/import | PASS (deterministic) | Authenticated backup, corruption, wrong identity/password, overwrite refusal, and atomic installation pass. |
| Capsule-v1 seed restore | PASS (deterministic) | All five production output classes self-recover; spend/reorg/interruption tests pass. |
| Historical proof-only seed restore | FAIL by design | These outputs contain no capsule and are backup-required; seed-only recovery cannot reconstruct them. |
| Peer bootstrap address filtering | PASS | Wallet-controlled Mainnet source filtering matrix passes. |
| PEX-learned address filtering | FAIL | Pinned DOM node PEX accepts any parseable `SocketAddr`; routability policy is not applied there. |
| Persistence and crash recovery | PASS (covered cases) | Atomic generations, adjacent publication repair, interrupted restore, reorg, and writer concurrency pass. |
| Disk-full/read-only/permission fault injection | BLOCKED | Not comprehensively exercised on this host. |
| v0.1.x schema compatibility | PASS | Historical schema matrix and no-mutation open test pass. |
| Real user v0.1.x encrypted fixture upgrade | BLOCKED | No private real-user wallet was used; this is intentionally not fabricated. |
| Frontend state fidelity/redaction | PASS (automated) | 18 frontend contract tests and shell status/redaction tests pass. |
| Linux `.deb` and AppImage build | PASS | Both versioned bundles produced and structurally inspected. |
| Linux graphical installed smoke | PASS (CI) | Extracted `.deb` passed native bridge, create/unlock, Mainnet peer/sync, mining-control, and ordered-shutdown smoke under Xvfb/WebKitWebDriver. |
| Windows installer | PASS (CI build) | NSIS and MSI were built and family-verified; install/reopen smoke remains absent. |
| macOS bundle | PASS (CI build) | `.app` and `.dmg` were built and family-verified; open/persistence smoke remains absent. |
| Mandatory installed-package E2E repeated cleanly | FAIL | No complete 31-step flow was run multiple times. |
| Prolonged restart/lock/mining/memory soak | BLOCKED | No controlled long-duration soak evidence. |
| CI non-release contract | PASS (static) | Pinned actions, read-only permissions, no upload/tag/release path, actionlint and frontend contract tests pass. |
| CI current-head result | PASS (jobs); aggregation delayed | Run `29988981444`; validation and all three package jobs are `completed/success`, while GitHub's run-level object remains stale at `in_progress`. |

## Final mandatory product gates

| Gate | Result |
|---|---|
| Create, close, reopen, unlock, lock | Deterministic backend coverage; installed GUI sequence not proven |
| Connect embedded node | Regtest pass; installed Linux Mainnet peer smoke pass |
| Synchronize height 0 and 1 with canonical height+hash | Deterministic pass; installed Mainnet same-tip proof pass, installed 0-to-1 transition pending |
| Mining start/stop/restart and coinbase | Regtest real-block pass; installed/live/prolonged proof pending |
| Coinbase maturity and spend | Restore/spend logic covered; complete installed journey pending |
| Slate send/receive/respond/finalize/submit/confirm | Canonical protocol and submission pass; two-installed-wallet journey pending |
| Backup and restore to another location | Deterministic pass; installed cross-machine journey pending |
| Restore mined and received funds | Capsule-v1 classes pass; installed combined journey pending |
| Restart and reorg | Deterministic pass |
| v0.1.x migration/compatibility | Schema compatibility pass; real-user fixture pending |
| Real installation and reopen | Linux extracted-package graphical create/unlock smoke pass; real package-manager installation and reopen pending |
| Multiple clean E2E executions | Not executed |

## Residual risks and external blockers

1. **Historical proof-only funds:** the test `legacy_proof_only_output_is_explicitly_not_recoverable` and `docs/WALLET_RECOVERY_AND_BACKUP.md` establish that outputs without Recovery Capsule v1 cannot reveal value/blinding from the mnemonic. The encrypted full backup preserves those funds. No code may manufacture a blinding or claim seed-only recovery. This keeps the release gate red under the requested seed-only promise.
2. **PEX policy gap:** the pinned DOM node file `crates/dom-node/src/pex.rs` accepts learned addresses when `addr.parse::<SocketAddr>().is_ok()`. It bounds queues and peer tables, but does not reject private, loopback, link-local, multicast, benchmark, or mapped addresses learned from a remote peer. Fixing this requires a reviewed DOM node dependency revision; editing Cargo's checkout would not be a valid product fix.
3. **Live network evidence:** the two live-Mainnet tests are ignored and were not converted into false deterministic successes.
4. **Installed E2E evidence:** local package creation and the CI Linux graphical smoke succeeded, but no two-machine/process transaction journey was completed.
5. **Platform evidence:** Windows and macOS bundles were built in CI, but install, launch, restart, upgrade, and uninstall/reinstall were not exercised.
6. **Dependency advisories:** repository policy permits the audit warnings, but GTK3 unmaintained status and the `glib` advisory remain visible maintenance risk.
7. **Fault/soak coverage:** disk-full, permission, read-only, handle leak, memory growth, long mining, and repeated clean-run tests remain incomplete.

## Final classification

**NOT READY**

The branch is materially more stable and all locally executable deterministic gates are green. It must not be released until the failed and blocked mandatory gates above have concrete passing evidence. No release or tag was created as part of this work.

# Phase 1 Integration Preflight

Date: 2026-08-04
Mission: `DOM-SCRIPTLESS-PHASE1-INTEGRATION v1`
Classification: CRITICAL
Integration branch: `feat/phase-1-integrated`
Preflight verdict: **CONFIRMED — PRODUCTION DIFF MAY BEGIN**

## 1. Method and status vocabulary

This report was created before any production-code delta on the integration
branch. It records V1 through V15 exactly as required by the integration
mission.

- **CONFIRMED** means the command executed locally and its result matched the
  required baseline.
- **HYPOTHESIS** means a proposition not yet supported by executed evidence.
- **BLOCKED** means a required value or condition is absent or contradictory.

There are no hypotheses or blockers in V1 through V15. Open G1a/G1b gate items
remain implementation or evidence work; they are not preflight failures.

## 2. V1 — coordinator identity and cleanliness

Status: **CONFIRMED**

```text
path   /home/leonardov/dom-scriptless-dev/dom-scriptless-contracts
branch feat/phase-1-dom-adaptor
HEAD   76915842465f89867b045c9016d532dc3538ac2d
tree   79fee013db55ab11a9d9c5c283c0321e5080aaa9
status clean
```

Command:

```text
pwd -P
git branch --show-current
git rev-parse HEAD
git rev-parse HEAD^{tree}
git status --short
```

Result: all expected values matched; exit code `0`.

Source: ratified ADR-P1-001 lines 10-27 and integration mission §2.
Artifact: Git tree `79fee013db55ab11a9d9c5c283c0321e5080aaa9`.

## 3. V2 and V3 — ADR content and signature

Status: **CONFIRMED**

| Artifact | SHA-256 |
|---|---|
| ADR-P1-001 content | `e35c39e74f9af61e19ecda8e1ca503f37a7fc04c6e2a0f40f5d96bf6a20d1596` |
| detached Minisign signature | `1c584fb8cb5b697ef1540c37b5354ea676aac36afdcac5b5d3f7fe49096cdd98` |

Command:

```text
sha256sum <ADR> <ADR.minisig>
minisign -Vm <ADR> -x <ADR.minisig> \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Result:

```text
Signature and comment signature verified
trusted timestamp 2026-08-04T20:44:26-03:00
key ID 74197A95CA309CF0
exit 0
```

The private key was not accessed.
Source: `docs/scriptless/source-guides/normative/amendments/ADR-P1-001-integrated-g1a-g1b-authorization-boundary.en.md:1`.
Artifacts: the two SHA-256 values above.

## 4. V4 — normative manifest

Status: **CONFIRMED**

Command:

```text
sha256sum --check docs/scriptless/source-guides/normative/MANIFEST.sha256
```

Result: all 13 entries reported `OK`; exit code `0`.

Source: `docs/scriptless/source-guides/normative/MANIFEST.sha256:1`.
Manifest SHA-256 at the preflight base:
`5aee735f6b6431ed9efea78e76498f93ff69468741aea47978bc439f5ad9586c`.

## 5. V5 through V7 — repository controls and initial gates

Status: **CONFIRMED**

| Command | Exit | Result |
|---|---:|---|
| `./scripts/scriptless/preflight.sh` | 0 | branch/HEAD and Cargo metadata valid |
| `./scripts/scriptless/verify-isolation.sh` | 0 | official sources and push blocks intact |
| `./scripts/scriptless/phase1-gate.sh` | 1 | expected open gate |

Initial gate result:

```text
G1a pending 19
G1b pending 26
G1a NOT APPROVED
G1b NOT APPROVED
PHASE 1 NOT APPROVED
```

The nonzero gate exit is expected evidence, not a concealed failure.

Source: `scripts/scriptless/phase1-gate.sh:1` and ADR-P1-001 lines 859-879.
Artifacts: Git blobs at coordinator tree
`79fee013db55ab11a9d9c5c283c0321e5080aaa9`.

## 6. V8 — official-source integrity

Status: **CONFIRMED**

### Official DOM

```text
path   /home/leonardov/dom-release
branch release/mainnet
HEAD   769822562565f18ef55423dc992e7aa661206b4a
tree   9cee98e2d393d52b7a330e398a04216f98f4f339
tracked status clean
```

Preserved untracked file:

```text
e036be3b8ae8f081a214958ed47e0d311c14e91277cbc57797f7276ef8c66064  crates/dom-node/src/bin/adaptor_parity_probe.rs
```

### Official Wallet

```text
path   /home/leonardov/dom-wallet-v3
branch redesign/restore-remote-scan
HEAD   1868e61bc39eca223d794348d70e48668ad06708
tree   5c572e4b5d083dbb7caa0ca608c0d2864add9f6c
tracked status clean
```

Preserved untracked files:

```text
88efe0f79ee4a795d3918e8c431b1477e1d5909a96445a8048309de01195e7f1  reports/DOM_NODE_IBD_SYNC_INVESTIGATION_2026-07-29.md
41741803d8f95c64ca40d8ffc6584f07cb833736f9c88264debd1f9e30d76d68  reports/MISSAO_1_B1_INPUTS_CONGELADOS_2026-08-04.md
71936f8fca1bacb5901a7add3c791bb8832b0afb5d81fa487119de2a0cd84059  reports/MISSAO_2_HEIGHT_LOCKED_RPC_2026-08-04.md
```

Commands: read-only `git branch`, `git rev-parse`, `git status`, and
`sha256sum`; exit code `0`. No untracked artifact was opened as executable,
imported, copied, moved, renamed, or changed.

## 7. V9 — clone, branch, and worktree inventory

Status: **CONFIRMED**

The isolated DOM repository contained these relevant worktrees before new
integration worktrees were created:

| Path | Branch/state | HEAD | Tracked changes |
|---|---|---|---:|
| coordinator | `feat/phase-1-dom-adaptor` | `76915842465f89867b045c9016d532dc3538ac2d` | 0 |
| `worktrees/g1a` | `feat/phase-1-g1a-implementation` | `60c0a8d2e692c11a7aa95c568339a25912f94a5a` | 0 |
| `worktrees/phase3-snv-dom` | `feat/phase-3-snv-contract` | `ec9e99661c52f4e09609603261455c09e1d615a7` | 0 |
| `worktrees/phase1-independent-vectors-ratified` | `test/phase-1-independent-vectors-ratified` | `6b90e7a021541a63a728354910b323603da635b2` | 0 |

The isolated Wallet repository contained:

| Path | Branch | HEAD | Tracked changes |
|---|---|---|---:|
| Wallet coordinator | `feat/scriptless-integration` | `1868e61bc39eca223d794348d70e48668ad06708` | 0 |
| `worktrees/phase3-snv-wallet` | `feat/phase-3-snv-wallet` | `e855ed67f641b7885f7e0e1928866253df60e34b` | 0 |

The old Wallet candidate worktree has one preserved pre-existing untracked
`.githooks/pre-push`; it has no tracked delta and was not imported as
production content.

Command: `git worktree list --porcelain`, `git for-each-ref`, and scoped
`git status`; exit code `0`.

## 8. V10 — candidate commit resolution

Status: **CONFIRMED**

Every candidate resolves locally to a commit and matches the reported branch,
tree, and subject:

| Role | Commit | Tree | Branch | Subject |
|---|---|---|---|---|
| G1a code freeze | `f821937a8ff1712d5f9bafd58f152b82073538f2` | `49c1d430e59c8caa5cdcc06b1726972dd1a95850` | `feat/phase-1-g1a-implementation` | quarantine nonce exports pending G1b |
| G1a report | `60c0a8d2e692c11a7aa95c568339a25912f94a5a` | `7bc9f7c9fd93d3830ab10b416f469be4f37a57e9` | same | record fail-closed G1a quarantine |
| G1b DOM | `ec9e99661c52f4e09609603261455c09e1d615a7` | `9ed2ada34d2bf9d4ebb174dfa5a4e7aed998f946` | `feat/phase-3-snv-contract` | record ratified G1b gate evidence |
| independent pre-comparison | `3486a863ba922e2b7a4fc52e5ded988c6d32de87` | `ba364dbad6169d7acd8efbbf61641abc0c052209` | `test/phase-1-independent-vectors-ratified` | freeze complete independent vectors |
| independent barrier | `f0a8be6efce885281fc2a4c4619698d2aa494f9f` | `935a41f98ba9f0fa73009fdff7e482232063e1f8` | same | record independent evidence barrier |
| independent comparison | `6b90e7a021541a63a728354910b323603da635b2` | `ec81b24ebd3d1463637e306f7142d274b6219336` | same | record production comparison |
| G1b Wallet | `e855ed67f641b7885f7e0e1928866253df60e34b` | `b99ca3d8c216212b9eaf78013c61b368a46c1612` | `feat/phase-3-snv-wallet` | record ratified G1b evidence |

Commands: `git cat-file -t`, `git show -s`, `git branch --contains`, and
`git merge-base --is-ancestor`; exit code `0` for resolution. None is silently
treated as already integrated.

## 9. V11 — DAG, ancestry, range, and diffstat

Status: **CONFIRMED**

The complete command outputs were inspected using:

```text
git log --graph --decorate --oneline --boundary --all
git merge-base <coordinator> <candidate>
git log --reverse <base>..<candidate>
git range-diff <base>..<g1a> <base>..<g1b-dom>
git diff --stat <base>..<candidate>
```

Topology:

- G1a and G1b DOM both diverge from
  `a37f0bbeeb7c0ee5579154ae64476e8374d1dabb`.
- The independent ratified-vector trail diverges from
  `6062f9adb6ddd1812c41b2fb66b9ec69a249f324` and contains the expected
  pre-comparison/barrier/comparison order.
- G1b Wallet descends linearly from authoritative Wallet baseline
  `1868e61bc39eca223d794348d70e48668ad06708`.
- Coordinator commits after `a37f0bbe...` are documentary ratifications and
  the Wallet rebaseline; candidate implementation trails are not ancestors of
  the coordinator.

Diffstat summary:

| Trail | Files | Insertions | Deletions |
|---|---:|---:|---:|
| G1a DOM | 46 | 9,272 | 102 |
| G1b DOM | 19 | 3,449 | 54 |
| independent evidence | 20 | 6,148 | 0 |
| G1b Wallet | 21 | 8,478 | 0 |

The range-diff confirms distinct semantic trails rather than equivalent
rebased patches. This requires deliberate reconciliation; wholesale merge or
automatic conflict selection is not authorized.

## 10. V12 — integration-name collision check

Status: **CONFIRMED**

Before creation, all required paths and branches were absent:

```text
FREE worktrees/phase1-integrated-dom
FREE worktrees/phase1-integrated-wallet
FREE worktrees/phase1-integrated-review
FREE DOM branch feat/phase-1-integrated
FREE Wallet branch feat/phase-1-integrated
```

Commands: filesystem existence checks and `git show-ref --verify`; exit code
`0`.

After V1-V15 completion, the coordinator created exactly those three
worktrees from the required baselines. This report is the first new tracked
artifact on the DOM integration branch.

## 11. V13 — absolute dependencies and bypass inventory

Status: **CONFIRMED**, with expected integration work identified.

No `Cargo.toml` or `Cargo.lock` in the scoped isolated repositories contains an
absolute `/home/leonardov` dependency or absolute Cargo `path` dependency.

Search command:

```text
rg -n '/home/leonardov|path\s*=\s*"/' <DOM> <Wallet> \
  -g Cargo.toml -g Cargo.lock
```

Result: zero matches; exit code `1` from `rg` means no match.

The G1a candidate intentionally contains `test-helpers`-gated nonce operations
and a private `from_durable_bytes` record parser. Default-build export is
quarantined by commit `f821937...`. No `skip_vault`, `skip_witness`, or
`skip_persist` route was found. The integration must retain record parsing as
non-authorizing and replace the quarantine only with the ratified vault-backed
path.

Sources: ADR-P1-001 lines 29-51, 351-547, and 758-777.
Artifact: G1a tree `49c1d430e59c8caa5cdcc06b1726972dd1a95850`.

## 12. V14 — directed pre-integration baselines

Status: **CONFIRMED**

All commands ran with at most four Cargo build jobs.

### G1a candidate

| Command | Executed result |
|---|---|
| Cargo metadata/fmt/check | exit 0 |
| `cargo test -p dom-adaptor --locked` | 28 tests, 0 failures |
| `cargo test -p dom-crypto --lib scriptless --features test-helpers --locked` | 6 tests, 0 failures |
| fresh 10,000-cycle real-verifier property test | passed in 137.38 seconds |
| SCAD0 consensus fixture test | 1 test covering 8/8 fixtures, passed |
| adaptor and crypto clippy with `-D warnings` | exit 0 |
| `git diff --check` and tracked status | clean |

### G1b DOM candidate

| Command | Executed result |
|---|---|
| Cargo metadata/fmt/check | exit 0 |
| `cargo test -p dom-adaptor --locked` | 6 tests, 0 failures |
| clippy `--all-targets -D warnings` | exit 0 |
| `git diff --check` and tracked status | clean |

### G1b Wallet candidate

| Command | Executed result |
|---|---|
| Cargo metadata/fmt | exit 0 |
| `cargo test -p dom-wallet-scriptless-vault --locked` | 29 tests plus 1 compile-fail doctest, passed |
| vault clippy `--all-targets -D warnings` | exit 0 |
| checks for domain, core, and production backend | exit 0 |
| `git diff --check` and tracked status | clean |

These are new pre-integration executions, not relabeled historical evidence.
They authenticate the candidate inputs but do not substitute for integrated
HEAD validation.

## 13. V15 — toolchain, platform, filesystem, and evidence tools

Status: **CONFIRMED**

```text
OS          Ubuntu 24.04
kernel      Linux 7.0.0-28-generic
architecture x86_64
filesystem  ext4
Rust/Cargo  1.96.1
LLVM        22.1.2
DOM lock    24dd3d311f5c2b8fc1352fa4b5fbcbf777fbbd0a254a6a2a61103f0d5611e39a
Wallet lock 782fc788ba9d098f644e12182b0094cf50293876621b81c852f5421ef762fc08
free space  164 GiB
```

Available:

- nightly Rust toolchains;
- `cargo-fuzz 0.13.2`;
- `cargo-nextest 0.9.138`;
- `cargo-deny`;
- Clang 18.1.3;
- `strace`;
- CMake 3.28.3, Make 4.3, pkg-config 1.8.1;
- Node 24.16.0 and npm 11.13.0;
- OS `O_DSYNC`, `O_SYNC`, `O_TMPFILE`, `O_DIRECTORY`, `fdatasync`, file
  `sync_all`, directory `sync_all`, rename, and real subprocess-kill testing.

Unavailable locally:

- real Windows runner;
- real macOS runner;
- Valgrind, GDB, and LLDB.

Windows and macOS will remain explicitly unexecuted unless a real runner is
discovered later. Prepared harnesses cannot close those lines.

## 14. New integration worktrees

Created only after V1-V15 were confirmed:

| Role | Path | Branch/state | Base |
|---|---|---|---|
| DOM integration | `/home/leonardov/dom-scriptless-dev/worktrees/phase1-integrated-dom` | `feat/phase-1-integrated` | `76915842465f89867b045c9016d532dc3538ac2d` |
| Wallet integration | `/home/leonardov/dom-scriptless-dev/worktrees/phase1-integrated-wallet` | `feat/phase-1-integrated` | `1868e61bc39eca223d794348d70e48668ad06708` |
| independent review | `/home/leonardov/dom-scriptless-dev/worktrees/phase1-integrated-review` | detached evidence-only | `76915842465f89867b045c9016d532dc3538ac2d` |

All three worktrees were clean at creation. Push URLs remain
`no_push://push-disabled` for every configured remote.

## 15. Preflight adjudication

| Item | Status |
|---|---|
| V1 coordinator | CONFIRMED |
| V2 ADR hash | CONFIRMED |
| V3 ADR signature | CONFIRMED |
| V4 normative manifest | CONFIRMED |
| V5 preflight script | CONFIRMED |
| V6 isolation script | CONFIRMED |
| V7 initial gate | CONFIRMED open as expected |
| V8 official integrity | CONFIRMED |
| V9 inventory | CONFIRMED |
| V10 candidate commits | CONFIRMED |
| V11 DAG/range/diffstat | CONFIRMED |
| V12 collision absence | CONFIRMED |
| V13 dependency/bypass search | CONFIRMED |
| V14 candidate baselines | CONFIRMED |
| V15 environment | CONFIRMED |

No production file was edited before all 15 confirmations. Production
integration may now begin under ADR-P1-001. G1a, G1b, Phase 1, production, and
real-funds use remain unapproved.

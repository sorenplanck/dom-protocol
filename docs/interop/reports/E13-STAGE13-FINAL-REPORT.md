# Stage 13 — final report: guards, CI, release readiness and controlled publication

- Date: 2026-09-02 / 2026-09-03. Branch `feat/interop-stage9`.
- Snapshot audited: HEAD `161c0650a7855db083c1cdfffa2aa85539bd4073`, 20 commits ahead
  of `origin/mainnetswap` (`187b13e2…`), 0 behind, after absorbing upstream #104 and #105.
- Every number below was measured in this pass on this snapshot; nothing is carried over
  from an earlier report unless it says so. Local logs live under `~/.dom-interop-logs/`
  and are cited by SHA-256 prefix so a reader can match them.
- This report does not assert a gate verdict for item 6 (publication): that is the
  operator's order, and it had not been given at the time of writing.

## 1. Verdict per roadmap item

| # | roadmap item | state |
| --- | --- | --- |
| 1 | Close `guards.sh`, `ci_local.sh` and every layer check; the guard may not be taught to ignore a finding | **CLOSED.** 25 → 0 layer-guard violations, 14 → 0 boundary violations, every `ci_local` gate green except the publication boundary, which waits for the push (§3). No rule relaxed, no file excluded, no allowlist widened — the two allowlists that changed shrank. |
| 2 | Restore/validate the three workflows; sync `dependencies.lock.json`; validate scripts/manifests and the production build with exact features | **CLOSED.** Workflows and the real Sepolia driver chain restored from history (§4). Production build with exact features green (§3). |
| 3 | Proportional Rust/Foundry/fuzz/E2E suites; Sepolia only on operator credentials; never Signet | **CLOSED for what this machine can execute.** 242 suites / 2 487 tests / 0 failures across the 115-package layer set; three live gates green; fuzz evidence stands from Stage 11. Sepolia not executed (no credentials, no order). Signet not executed (cancelled). |
| 4 | Requirement-by-requirement audit; resolve every gap, convert none into a follow-up | **CLOSED.** Runbook written (§6); the four open risks of the 2026-08-27 adversarial audit are all closed, two by code in this pass (§5). |
| 5 | Final report with hashes, commands, counts, justified ignores, real environmental limits, evidence matrix; compare with `mainnetswap` | **This document.** |
| 6 | Only on explicit operator order: identity, atomic commits, metadata check, publish | **READY, NOT EXECUTED.** 20 outgoing commits, all authored and committed by Soren Planck, zero co-author trailers (`check-authorship.sh` PASS against `origin/mainnetswap`). The push is the operator's order. |

## 2. What was red at the start, and how each red was closed

### 2.1 Layer guard — 25 violations, red since the stage-7 composition root

`guards.sh` was PASS at `b77695b` (Stage 6) and red for 27 commits. The pass output
after closure is byte-identical to the Stage 6 baseline (log `d369938b…`).

| class | count | resolution |
| --- | --- | --- |
| I14 `expect` in production | 2 | code: decoder loses its panic path; two writers become infallible `push_str`; one allowlist entry **removed** |
| I6 `eprintln` | 3 | inventory with dated review: all in `main.rs`, terminal branches returning `ExitCode::FAILURE` |
| F1 Sponsor lines | 7 | inventory: every new line **refuses** Sponsor |
| F1 whole-file freezes | 8 | every diff read against the 2026-08-31 freeze; the only protocol change is `RefundAdaptor = 0x05` (NAR-DC-P1-009); Sponsor byte-identical in all; re-frozen with the diff named in the registry |
| `evidence-only` under a neutral feature name | 2 | code: feature renamed `f7-wallet-compositor-evidence-only` — the restored compositor *is* the laboratory surface |
| dynamic process dispatch in Python | 2 | code: literal argv (`cwd=`, `bash -n` via stdin) |
| literal secp context | 1 | allowance **removed** — the literal is test-only now; production builds every context from `fresh_entropy()` |

The guard's own unit test that had *required* the old `|| true` neutralisation of the
production gates now refuses it (54/54 guard unit tests).

Restoring the automation surface exposed three more (a `source "$VAR"` in the stub
scripts): closed by restoring the original scripts, which are self-contained.

### 2.2 Workspace boundaries — 14 violations

13 files with machine-local paths (redacted to `~/`; frozen debt list untouched) and the
six `dom-wallet-*` git dependencies. Those, and the wallet vendor's fifteen rev-`6f8a947`
git references, became direct paths; **both `[patch]` sections are gone**, no `dom-*`
crate is a git dependency anywhere, and `Cargo.lock` was byte-identical before and after
the conversion.

### 2.3 CI script gates — 5 failures

Shared-output BP guard (the `[patch]` override), ratification-signature pin (14 → 15: the
vendored sidecar fixture signature, verified against the operator key like every other),
publication boundary (§3), and the two that were the guard/boundary failures in flight.

### 2.4 CI cargo gates — measured individually, then re-run whole

The neutralised CI had never exercised these gates on the merged tree. Measured
one by one (log `e8e90be4…`, 12/13 PASS, the 13th fixed and re-measured):

- `cargo fmt --all --check`: drift in six files, one of them F1-frozen (re-ratified: five
  whitespace-only insertions, zero token changes).
- layer clippy `-D warnings`: the `expect(dead_code)` tripwires of the daemon's frozen
  surfaces conflicted with `--all-targets`; the expectations now match measured reality
  and still fail the production build the moment each surface is first wired.
- layer tests: one latent failure — the workspace-exclusion pin did not know the two
  stage-12 exclusions; both recorded with their reasons and their own gates.
- production daemon tests: four `production_f6_lifecycle` fixtures failed against the
  first O-03 cut (§5) and pass against the final one — 386/0 (+1 bin).

**Round 5 — the whole layer-test gate re-run after every fix, raw counts:**
**242 suites, 2 487 tests passed, 0 failed** (`9b3ab733…`). Doc tests, the real DOM
adaptor backend, the real EVM HTTP backend, production daemon check/clippy/tests, both
release-surface refusals and the `Cargo.lock` digest check all PASS.

### 2.5 Live gates (`--live-local`)

| gate | result | evidence |
| --- | --- | --- |
| EVM contract release | PASS | `dependencies.lock.json` forge-std 1.9.6 / OZ 5.1.0 |
| local Anvil E2E | PASS — 12 + 6 scenarios on chain id 31337 | `f1dd9458…` |
| local Bitcoin Core regtest E2E (V2, genesis-rooted) | PASS — claim and refund crossed the independently pinned authority `6f45496e…` | `a47e3996…` |

### 2.6 XMR v7 static validator (the `xmr-v7.yml` gate)

Run as CI runs it, on a clean checkout: one real error — two packages named
`dom-wallet-crypto` (node 0.2.0, vendored wallet 0.3.2). The vendored package is renamed
`dom-wallet-v3-crypto` with its library name kept, so no `use` path changes; validator
**PASS** (28 active components, 40 files, 0 errors; `feec5580…`).

## 3. The one gate that stays red, and why it is the operator's

`mainnetswap publication boundary` requires the 29 node crates to be byte-identical to
`origin/mainnetswap`. Three ratified local commits touch them: the wallet directory
`0700` pin (`1a35bab`), the slate-secret redaction in `Debug` (`3240c6e`) and the
node-side part of the F7 restoration (`b77fab2`). Reverting them would loosen ratified
hardening; publishing them is the push. The gate turns green with item 6 and with
nothing else.

## 4. Automation surface restored

`f3-sepolia.yml`, `f4-sepolia.yml`, `f5-e2e.yml` and the real Sepolia drivers
(`sepolia.sh` 45.9 KB, `sepolia_deploy.sh`, `sepolia_e2e.sh`, `f4_sepolia_slash.sh`)
return from the `Dom-interop` history — the local 42-line stubs would have let the F3
gate pass while exercising nothing. Contracts verified: `F3_ANVIL_*` → `e2e_anvil`,
the F4 slash names the test that exists (`e2e_sepolia.rs:373`). The regtest-only F5
installer and runner stay (stronger, Signet-cancelled); `infra/signet` is not restored.
The sidecar build script builds the DOM deliverable only (`--package dom-xmr-sidecar` +
a workspace `cargo check` for graft integrity), not the host wallet's GUI.

## 5. Requirement-by-requirement audit — what changed

**Open risks of the 2026-08-27 adversarial audit:** O-01 closed by the tree (production
composition root exists; `chain-profile` has six production consumers; the four crates
ratified on 2026-09-02). O-02 closed by the tree (`AssetRepresentationV1::EvmErc20
{ token, token_code_hash }` committed through `asset_binding_digest`). **O-03 closed by
code:** the relay pipeline adjudicates `policy_version` against the session's pinned
value carried in `RecipientContextV1` — the audit's own recommendation — refusing a
mismatch and zero at step 4; the daemon's F6 lifecycle and the route-transport bridge
already pinned it at their layers. **O-04 closed by code:** admissibility refuses
`QuoteDeadlineElapsed` when `now` passes the RFQ's own quoting window, using the `now`
selection already receives. Both are pure tightenings with tests.

**Operations:** `docs/interop/runbooks/DOM-INTEROPD-OPERATIONS.md` — startup contract,
the V3 stdin secret stream, printed known limits, state directory as the unit of
backup/restore with the executed crash matrix, epoch-based rotation and the registry
rollback floor, the no-wildcard config-family posture, closed DoS bounds, and the
deliberate absence of a metrics port (observability is stderr/journald, exit code and the
durable journals).

**Ratifications signed today (local, never published):** E13-G (guard pass) and the
block ratification of eleven executed decisions (v2), 236/0 measured for the latter,
including the composed-route level-3 proof executed live in this session (anvil +
Bitcoin Core regtest, both directions, 99.65 s).

## 6. Known limits and what stays off — by design, printed at startup

The five `PRODUCTION_KNOWN_LIMITS_V1` entries all stand: Bitcoin claim materialization,
EVM re-extraction source, Solana and Monero route shapes, extended chain-services faces.
Mainnet Bitcoin and Monero do not exist in their enums (D-027); EVM chain id 1 is
refused; `MAINNET = DISABLED` and `REAL_FUNDS = PROHIBITED` are frozen module text. The
swap surface therefore ships **off** in this publication, as ordered, and nothing in the
20 outgoing commits opens a path — every change refuses more, never less.

Work already delivered by the operator's parallel agents toward Block A (EVM
re-extraction source; the authenticated Bitcoin claim round) is **not** in this snapshot
and is integrated after the push, with the refusals dropped last.

## 7. Environmental limits, stated plainly

- 8-core machine shared with the sidecar build and, later, the operator's agents; the
  cargo gates run at `CARGO_BUILD_JOBS=2` for fidelity with `ci_local.sh`.
- A host reboot at 11:05 killed the sidecar build9 and wiped `/tmp` logs; all durable
  logs moved to `~/.dom-interop-logs/`. Build10 produced the authenticated
  `dom-xmr-sidecar` binary (refuses to start without `DOM_XMR_SIDECAR_AUTH_HEX`); its
  host-GUI fat-LTO targets were cut deliberately (nothing in the DOM tree consumes them).
- Sepolia not executed (operator credentials + order). Signet cancelled. No network
  action beyond `git fetch`.
- Two measurement artefacts of this pass were operator-visible mistakes, both corrected:
  a stale gate run surviving a kill and writing into a fresh log (re-run clean), and a
  `pgrep` self-match reporting the validator as still running for hours after it had
  passed.

## 8. Commands (all offline, `--locked`)

```text
bash scripts/guards.sh                              LAYER_GUARDS = PASS   (d369938b…)
bash scripts/check-boundaries.sh                    BOUNDARIES = PASS
bash scripts/ci_local.sh                            16/17 script gates PASS (publication boundary: §3)
cargo test --locked --offline <115 layer pkgs> --all-targets
                                                    242 suites, 2 487 passed, 0 failed (9b3ab733…)
cargo test -p dom-interopd --no-default-features --features production --lib --bins
                                                    386 passed, 0 failed, 3 ignored (+1 bin)
bash contracts/scripts/check_release.sh             PASS
bash scripts/e2e_anvil.sh                           PASS 12+6 scenarios (f1dd9458…)
bash scripts/f5-regtest-e2e.sh                      PASS V2 (a47e3996…)
python3 scripts/xmr-v7-static-validate.py .         PASS 28/40/0 (feec5580…)
DOM_AUTHORSHIP_BASELINE=origin/mainnetswap scripts/check-authorship.sh HEAD
                                                    AUTHORSHIP = PASS (20 commits)
Cargo.lock                                          86490303…
```

The three `ignored` in the daemon suite are scenarios that require an external
environment, documented in the crate; there are no other ignores in the measured set.

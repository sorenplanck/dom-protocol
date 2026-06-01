# DOM Protocol — Incremental Security Audit Report

**Date:** 2026-06-01
**Auditor:** Claude (Opus 4.8), AI security auditor
**Repository:** `/root/dom`
**Branch / HEAD:** `feat/metrics-instrumentation` @ `d926d21` (0 commits ahead of `main`)
**Working tree:** an **active, in-progress metrics-instrumentation feature** by the maintainer — uncommitted edits across 10 files (`Cargo.lock`, `dom-config/src/lib.rs`, `dom-faucet/{Cargo.toml,src/lib.rs,src/main.rs}`, `dom-integration-tests/src/helpers.rs`, `dom-node/{main.rs,node.rs,node_handle.rs,task_supervisor.rs}`, `dom-wallet/src/rpc_client.rs`; +557/−62). This work grew during the audit session (it was a single +58 `node.rs` diff at the start). It adds a Prometheus metrics endpoint + counters and is observability-only; see §3, §5 (AUDIT-2026-06-01-006), §11.
**Methodology baseline:** the audit knowledge base under `audit/` (`00_MASTER_INDEX` … `10_REPORT_TEMPLATE.md`)

---

## 1. Executive Summary

This is an **incremental** audit. DOM already carries substantial prior audit work: three reports under `audit/` (`DOM_AUDIT_REPORT.md`, `FULL_PROTOCOL_AUDIT_REPORT.md`, `BOOTSTRAP_READING_REPORT.md`) and ~23 `fix/` branches.

The central finding of this pass is methodological: **the prior reports are stale snapshots.** Cross-referencing every report finding against git, **22 of 23 `fix/`/`audit/` branches are merged into `main`**, and nearly every issue the reports list as "Open" already has a merged fix. Re-reporting those as open would be wrong.

The audit therefore pivoted to two higher-value tasks:

1. **Independent verification** that the merged fixes genuinely close their findings *without weakening consensus invariants* (several were marked "fixed by inspection only", which Doc 02 forbids relying on).
2. **A fresh static sweep** for new bugs not covered by any prior report, including regressions introduced by recent fixes.

**Outcome:**
- All independently-verified Critical/High fixes are **CLOSED / SOUND** (genesis state-drift, mempool full-validation, coinbase range-proof, side-chain quarantine, IBD self-deadlock, and the crypto core: H-generator unification, Schnorr challenge binding, balance-equation fee sign).
- The fresh sweep found **no new High/Critical** issues. The consensus/parsing surface is well-guarded (bounded allocations, `checked_*` arithmetic, deterministic iteration). Only **Low/Informational** observations are recorded here.
- **Validation is fully green:** `cargo fmt --check` ✅, `cargo clippy --workspace --all-targets -- -D warnings` ✅, `cargo test --workspace` → **1109 passed, 0 failed, 12 ignored** (1 slow test deliberately excluded — see §3 and §11). Note these ran against the working tree **including** the maintainer's in-progress metrics feature.
- What genuinely remains for mainnet are **process/feature blockers** in `docs/RELEASE_BLOCKERS.md` (DNS seeds, wallet slate protocol, IBD RFC, ≥90-day testnet + ≥10k CPU-hr fuzz gates), **not latent code bugs**.

**Overall risk for the reviewed scope: LOW.** The code is disciplined and the security-relevant fixes hold up under independent scrutiny. Mainnet readiness remains gated by process items and dynamic validation that this static audit does not and cannot grant.

---

## 2. Scope Reviewed

**Crates (24 total in workspace):** primary focus on consensus-critical and external-input-facing crates —
`dom-consensus`, `dom-chain`, `dom-core`, `dom-crypto`, `dom-tx`, `dom-pmmr`, `dom-pow`, `dom-mempool`, `dom-store`, `dom-serialization`, `dom-wire`, `dom-node`, `dom-rpc`, `dom-wallet`.

**Specific artifacts:**
- The in-progress metrics-instrumentation working-tree changes (observability; reviewed at AUDIT-2026-06-01-006).
- Merged fix commits `4df98ac`, `cf96c4c`, `57c7589`, `95d297f`, `1a3ac1a`, `e866922`, `841e82b`, `e7a4d46`, `8d5ec87`, `0fc52a6`, `f2adf9e`, `19ce8e1`, `0da49b6`, and the `fix/mempool-full-validation` / `fix/coinbase-range-proof-verify` / `fix/side-chain-quarantine-rationale` merges.
- `docs/RELEASE_BLOCKERS.md`, `docs/DOM_RFC_0004/0008/0009/0010/0011/0012`, `KNOWN_ISSUES.md`.

**Out of scope / not exercised:** live multi-node convergence, fuzz campaigns, `cargo audit` / `cargo deny`, cross-platform PMMR determinism, and the one slow RandomX replay test (§11).

---

## 3. Methodology

- **Static source review** of the merged fixes and current code, traced from external input → validation → state mutation → persistence.
- **Independent verification via parallel sub-audits** — six focused verification passes (mempool validation, coinbase range proof, side-chain persistence, RandomX + IBD deadlock, crypto core, fresh bug sweep), each required to cite `file:line` and be adversarially skeptical (default to "not closed" unless proven). These targeted the merged-to-`main` fix logic; the maintainer's in-progress metrics edits are observability-only and do not touch the consensus/IBD/crypto paths verified.
- **Dynamic test execution** — full workspace `fmt` / `clippy` / `test` (§11).
- **Diff review** of the working-tree changes.
- **Git forensics** — branch/worktree state, merge status of every fix branch, ID-collision reconciliation between the two prior reports.

**Limitations (explicit):**
- This is a **read-only static + unit/integration** audit. It does **not** include live adversarial networking, multi-node convergence under partition, or a fuzz campaign. Those are required for mainnet and are out of this pass.
- **The working tree was a moving target:** the maintainer was actively developing the metrics feature during the session (1 → 10 files). The validation run (§11) reflects the tree at run time, which includes that in-progress work. Re-run `fmt`/`clippy`/`test` after the feature is committed for a stable baseline.
- One integration test (`replay_two_independent_chains_converge`) does **real RandomX mining** and did not complete in the audit environment (>56 min; maintainers' own VPS timed it out at 900 s). It was **excluded by name** from the validation run so the rest of the suite could complete, and is recorded as a coverage gap to be **run in isolation on dedicated hardware** (§11, §14).
- Crate-path assumptions in the KB (`dom-p2p`, `dom-miner`) do not exist; networking is `dom-wire` + `dom-node/src/net`, mining is `dom-pow` + `dom-node`.

---

## 4. Findings Summary

### 4a. Verification of prior fixes (independently confirmed)

| Prior ID | Severity | Area | Title | Verdict |
|----------|----------|------|-------|---------|
| FULL-001 / `DOM-AUDIT-001` (genesis) | Critical | Consensus/Storage | Genesis persisted without UTXO/kernel changeset → create≠reopen chain-split | **CLOSED** — create routes through same `genesis_canonical_changeset` as reopen; equivalence test added |
| FULL-002 | High | Mempool | Mempool admitted txs without full crypto/economic validation | **CLOSED** — admission runs `validate_transaction` (range proofs + Schnorr + balance); 3 regression tests |
| FULL-003 | Medium | Consensus/Crypto | Coinbase range proof unverified (only `is_empty`) | **CLOSED** — real `bp_verify`; value bound separately by balance eq + explicit-value check |
| FULL-004 | High | Storage/P2P | Side-chain persisted before contextual validation (DoS) | **MITIGATED-BY-DESIGN** — PoW-at-real-difficulty gates persistence; 8-tip/1000-block prune cap bounds disk |
| NEW `DOM-AUDIT-001` | High | Node/Runtime | IBD held `chain` lock across `.await` → self-deadlock | **CLOSED** — guard scoped/dropped before async purge + wallet apply; deadlock regression test |
| RB-RANDOMX | Critical | PoW | RandomX validation (was Blake2b bypass) | **CLOSED** — real RandomX; mining path == validation path; fast-path fenced to regtest (see AUDIT-...-003) |
| RB-H-GENERATOR / KI-FORMAT | Critical | Crypto | Pedersen vs Bulletproof H-generator/format mismatch | **SOUND** — same H point (byte-exact test); SEC1↔zkp bridge on consensus path |
| RB-SCHNORR-* | Critical | Crypto | R encoding + chain_id binding (cross-chain replay) | **SOUND** — challenge binds R‖PK‖chain_id‖msg; cross-chain replay test fails as expected |
| RB-FEE-SIGN | Critical | Crypto | Balance-equation fee sign (inflation) | **SOUND** — `Σout − Σin + fee·H == Σexcess + offset·G`; identity-safe; no inflation vector |

### 4b. New observations from this pass (all Low / Informational)

| ID | Severity | Area | Title | Status |
|----|----------|------|-------|--------|
| AUDIT-2026-06-01-001 | Low | Mempool | Legacy `Mempool::accept_tx` / `reinject_batch` (structure-only) remain `pub` with no production caller — latent footgun that could reopen FULL-002 | Open (hardening) |
| AUDIT-2026-06-01-002 | Low | Chain | `prune_retained_side_chains` does an O(total-headers) scan on every block connect | Open (perf) |
| AUDIT-2026-06-01-003 | Low | PoW/Test | Consensus PoW path uses Blake2b `FastDevOnly` under `cfg!(test)`, so real RandomX consensus wiring is never exercised by `cargo test` | Open (test coverage) |
| AUDIT-2026-06-01-004 | Info | Hygiene | Two binaries committed at repo root (`dom-agent-runner.exe`, `dom-dev-terminal-local.exe`) | Open (hygiene) |
| AUDIT-2026-06-01-005 | Info | Docs | Stale audit KB / report discrepancies (ID collisions, crate-name drift, `RB-HANDSHAKE-TIMEOUT` listed both OPEN and RESOLVED, `KNOWN_ISSUES.md` stale header) | Open (docs) |
| AUDIT-2026-06-01-006 | Info | Observability | In-progress metrics-instrumentation feature (working tree) is clean (no consensus impact, correct lock discipline, has tests) but should be committed on its own branch | Advisory |

---

## 5. Detailed Findings (new observations)

### AUDIT-2026-06-01-001 — Legacy structure-only mempool admission still `pub`
**Severity:** Low · **Area:** Mempool · **Status:** Open (hardening)
**Affected:** `crates/dom-mempool/src/lib.rs:193` (`accept_tx`), `:416` (`reinject_batch`)
**Description:** The FULL-002 fix moved all production admission/reinjection to the `*_with_chain_view` variants that run full `validate_transaction`. The old structure-only `accept_tx`/`reinject_batch` remain `pub` and documented "legacy/test-only". Verified: every non-test caller uses the `_with_chain_view` variant; current callers of the legacy fns are only `#[cfg(test)]` modules and one test harness (`crates/dom-node/tests/multinode_reordered_delivery.rs`).
**Impact:** No current bug. A future production caller wired to `accept_tx` would silently reopen FULL-002 (mempool accepting cryptographically-invalid txs).
**Exploitability:** None today (no production path).
**Recommended fix:** `#[cfg(test)]`-gate or `#[doc(hidden)]` + `debug_assert!` the legacy functions, or fold them into the validated path.
**Validation:** `cargo test -p dom-mempool` (the three `accept_tx_with_chain_view_rejects_*` tests already cover the validated path).

### AUDIT-2026-06-01-002 — O(total-headers) scan per block connect
**Severity:** Low · **Area:** Chain (performance) · **Status:** Open
**Affected:** `crates/dom-chain/src/chain_state.rs` (`prune_retained_side_chains` → `read_all_block_headers_raw`, `db.rs:351`)
**Description:** `prune_retained_side_chains` runs on every connect and reads all block headers + computes `find_common_ancestor` per candidate. Cost grows with chain height. It is bounded work driven by the validated chain (not unauthenticated-input amplification), so it is a scaling/performance concern, not a security DoS.
**Impact:** Increasing per-block CPU as the chain grows.
**Recommended fix:** Cache side-branch tip metadata / index headers by height to avoid the full scan.
**Validation:** benchmark connect latency at increasing heights.

### AUDIT-2026-06-01-003 — RandomX consensus path not exercised under `cargo test`
**Severity:** Low · **Area:** PoW / test coverage · **Status:** Open
**Affected:** `crates/dom-pow/src/lib.rs` (`pow_validation_mode_for_network` returns `FastDevOnly` when `cfg!(test)`), consumed via `crates/dom-chain/src/chain_state.rs` (`validate_pow_for_network`)
**Description:** The production consensus PoW path is real RandomX, and the `DOM_REGTEST_FAST_MINING` override is correctly hard-rejected on mainnet/testnet. However, because `cfg!(test)` selects `FastDevOnly` (Blake2b), the standard test suite validates blocks under Blake2b — the real RandomX consensus wiring is **never** exercised by `cargo test`. A regression breaking RandomX consensus wiring would not be caught by the suite. (This is also *why* the one real-RandomX integration test in §11 is so slow and had to be excluded.)
**Impact:** Test blind spot on a Critical consensus primitive.
**Recommended fix:** Add a non-`cfg(test)` integration test (or one that calls `validate_pow_randomx` directly on a real mined header) that runs in CI on dedicated hardware.

### AUDIT-2026-06-01-004 — Binaries committed to the repository
**Severity:** Informational · **Area:** Hygiene · **Status:** Open
**Affected:** `dom-agent-runner.exe` (350 KB), `dom-dev-terminal-local.exe` (7.8 MB) at repo root (tracked).
**Impact:** Supply-chain/provenance and repo-bloat concern; opaque binaries in a consensus-critical repo.
**Recommended fix:** Remove from version control, add to `.gitignore`, distribute via releases.

### AUDIT-2026-06-01-005 — Stale audit documentation
**Severity:** Informational · **Area:** Docs · **Status:** Open
**Description:** (a) `DOM-AUDIT-00x` IDs collide between the two prior reports (git binds them to the newer report). (b) KB references non-existent `dom-p2p`/`dom-miner`. (c) `RELEASE_BLOCKERS.md` lists `RB-HANDSHAKE-TIMEOUT` as both OPEN and "RESOLVED in v8", and `RB-BAN-POLICY` as "never called" though `add_ban_score` now has production call sites (`node.rs:1724`, `manager.rs:731,854`). (d) `KNOWN_ISSUES.md` keeps a "blocks production" header above a "✅ RESOLVED" body.
**Recommended fix:** Reconcile the docs; treat git/code as source of truth.

### AUDIT-2026-06-01-006 — In-progress metrics-instrumentation feature (advisory)
**Severity:** Informational · **Area:** Observability · **Status:** Advisory
**Affected:** working-tree edits across 10 files (see header); core is `crates/dom-node/src/node.rs` + `crates/dom-config/src/lib.rs` (`metrics_listen_addr`) + a Prometheus endpoint.
**Description:** Adds `refresh_runtime_metrics` and `txs_received`/`txs_relayed`/`mempool_size`/`future_block_queue_size` counters plus a metrics listen address. Reviewed (node.rs core): locks `chain`→drop, `mempool`→drop, `future_block_queue` sequentially (no guard held across `.await`; passes the lock-across-await invariant), `AtomicU64`/`Relaxed` is correct for metrics, only counts successful sends, and includes unit tests. No consensus impact. The full 10-file feature was still in flux during the audit and was not line-by-line reviewed in its latest state.
**Recommended action:** Commit the feature on its own branch with its tests; **re-run `fmt`/`clippy`/`test` on the committed state** for a stable baseline, and have the metrics endpoint's network binding/exposure reviewed (it leaks node health/topology — prefer loopback, as the config comment already notes).

---

## 6. Consensus Impact Assessment

No reviewed change weakens a consensus rule. The genesis fix (FULL-001) makes `create == reopen` hold **by construction** (shared `genesis_canonical_changeset`) and explicitly preserves the `chain_id`/`GENESIS_HASH` invariant. Mempool admission now uses **identical** per-tx validity rules to block inclusion (Doc 02 invariant), with only stricter relay policy layered on top. Block-weight, fee, supply, and difficulty arithmetic use `checked_*`; `total_difficulty` saturation is on infeasible `U256` work. Iteration feeding hashing/roots is deterministic (slice order; `BTree*` where ordering matters). The in-progress metrics feature is observability-only and does not touch consensus.

## 7. Cryptography Impact Assessment

The crypto core is **SOUND**. Pedersen and Bulletproof now share one H generator (byte-exact equality test, consensus-frozen as a tripwire), with a bijective SEC1↔zkp bridge wired into the live range-proof verification path. Schnorr challenges bind `R(33-byte SEC1)‖PK‖chain_id‖message`; cross-chain replay fails. The balance equation has the correct fee sign (no inflation), and point-sum identity is handled without panic. Range proofs and kernel signatures are verified at both mempool admission and block connection. **Residual:** independent cross-implementation reproduction of the RandomX/Bulletproof/H frozen vectors is still a mainnet checklist item (not done here).

## 8. Mempool / Reorg / Double-Spend Assessment

Mempool admission runs full `validate_transaction` and chain-aware UTXO/maturity checks; conflicting spends are reserved/rejected deterministically; weight-cap eviction loops until the incoming tx fits (DOM-AUDIT-003). Reorg reinjection uses the validated `*_with_chain_view` path; the IBD self-deadlock (chain lock across `.await`) is fixed with a regression test. Side-chain blocks are PoW-gated at real difficulty before persistence and pruned to a bounded set, so the storage-pollution DoS is not viable. **Residual:** AUDIT-2026-06-01-001 (legacy structure-only fns) as a latent footgun.

## 9. Wallet Safety Assessment

Verified merged fixes cover: spend reserved only under the lock that admits to mempool (DOM-AUDIT-005), canonical wallet apply on miner-triggered reorg (DOM-AUDIT-006b), coinbase-with-fees recovery in scan (DOM-AUDIT-006a), journal fail-closed on WAL append failure, and the `build_spend` Built→save crash gap (DOM-FINAL-007). No new wallet issue found in this pass. Wallet key/seed handling and slate protocol were not deeply re-audited here (slate spec is an open mainnet item, RB-WALLET-SLATE).

## 10. P2P / DoS Assessment

Wire decoders bound every length/count against a `MAX_*` constant before allocating (`MAX_MESSAGE_PAYLOAD` 16 MiB cap; ≤5000 tx structs); PEX/addr parsers reject malformed/trailing bytes (DOM-AUDIT-007); ban scoring now has production call sites. **Open mainnet items (not code bugs in scope):** DNS seeds / bootstrap discovery (RB-DNS-SEEDS), peer eviction policy and PEX subnet diversity, and the handshake-timeout entry needs doc reconciliation. Eclipse/sybil resistance requires live testing not performed here.

---

## 11. Validation Evidence

Commands run from repository root:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast -- --skip replay_two_independent_chains_converge
```

Results:

```text
cargo fmt --check                         → PASS (exit 0)
cargo clippy --workspace --all-targets    → PASS (exit 0, no warnings under -D warnings)
cargo test --workspace                     → PASS
    115 test binaries
    1109 passed; 0 failed; 12 ignored; 1 filtered out
    no FAILED / panicked / error in the full log
```

These ran against the working tree **including** the maintainer's in-progress metrics feature (so the green result also implies that WIP does not break the suite). Re-run on the committed feature state for a stable baseline.

**Excluded test (must be run in isolation on dedicated hardware):**
`replay_two_independent_chains_converge` in `crates/dom-integration-tests/tests/replay_determinism.rs`.
This test performs **real RandomX mining of two independent chains** to prove replay determinism. It does not honor any fast-mining shortcut. In the audit environment it ran **>56 minutes without completing**; the maintainers' own VPS previously timed it out at 900 s. It was excluded **by name** (not silently skipped) so the remaining 1109 tests could complete with a clean result. **Action required:** run this single test in isolation on a host capable of ≥1 block/60 s before relying on it as a release gate. The sibling `replay_same_chain_reopens_to_identical_tip` (single-chain) **passed**.

`cargo audit` / `cargo deny` were not run (not in scope / not invoked).

---

## 12. Files Changed

- **`AUDIT_REPORT.md`** (this file) — new audit report, committed on its own (only this file is staged). No source/consensus/crypto/persistence files were modified by the auditor.
- **Reviewed but not modified by the auditor:** the in-progress metrics-instrumentation working-tree changes across 10 files (pre-existing, authored by the maintainer; see AUDIT-2026-06-01-006). These remain uncommitted and were intentionally **not** included in the report commit.

## 13. Forbidden File Compliance

**No forbidden files were modified.** This audit is read-only; the only file written is this report (a new top-level document, not in any protected category per `audit/07_FORBIDDEN_FILES.md`). The maintainer's in-progress source edits were left untouched. All remediation for the Low/Info observations above is left as **proposals** for maintainer review — none were applied.

## 14. Remaining Risks

1. **Mainnet process/feature blockers** (not latent bugs, from `RELEASE_BLOCKERS.md`): DNS seeds (RB-DNS-SEEDS), wallet slate protocol (RB-WALLET-SLATE), IBD RFC (RB-IBD partial), peer eviction / PEX subnet diversity, and the ≥90-day public testnet + ≥10k CPU-hr fuzz gates.
2. **Dynamic validation not performed:** live multi-node convergence, partition/adversarial networking, fuzz campaigns, cross-platform PMMR determinism.
3. **The excluded RandomX replay test** (§11) must be run in isolation on dedicated hardware.
4. **Independent cross-implementation reproduction** of RandomX / Bulletproof / H frozen vectors (mainnet checklist).
5. **Human cryptography/consensus sign-off** — required before mainnet; an AI static audit does not substitute for it.
6. The Low/Info observations AUDIT-2026-06-01-001..006, and re-validation once the metrics feature is committed.

## 15. Final Recommendation

**Ready for the next audit/test phase (testnet-class) — NOT ready for mainnet.**

For the **reviewed static scope**, the protocol is in good shape: the Critical/High security fixes hold up under independent, skeptical verification; the fresh sweep surfaced no new High/Critical issues; and the full test suite (minus one environment-limited test) is green. Mainnet readiness remains correctly gated by the open process/feature blockers, the dynamic validation campaigns, the isolated RandomX replay test, and **human cryptography/consensus review** — none of which this static audit provides.

---

*Generated by an AI auditor. Treat consensus- and cryptography-critical conclusions as requiring confirmation by a human expert and by the dynamic test campaigns noted above.*

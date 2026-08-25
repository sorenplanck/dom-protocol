# F2 CLOSURE REPORT — Kaystra Core

```text
Phase:               F2 — Kaystra Core
Gate:                G-F2
Specification:       docs/normative/DOM-Interop-F2-Engineering-Specification-v1.0.md
Foundation Document: docs/normative/DOM-Interop-Foundation-Document-v0.4.md
Prior gate:          G-F1 = PASS (docs/reports/F1-CLOSURE.md §12)
Date:                2026-08-10
Authority:           operator ratification of the F2 specification, 2026-08-09
```

This report is the record required by specification §22. Every claim below
is backed by a command in this repository; anything not demonstrated is
stated as residual, not implied as done.

---

## 1. Initial and final commit

| | Commit |
|---|---|
| Base (F1 closure, start of F2) | `5370168` — *F1: close the gate — funding->claim and funding->refund through the vault (G-F1 = PASS)* |
| Final (this report) | `5e6b0c2` — *Merge feat/f2-closure: F2 §24 steps 14-15 — F1 real-backend regression and the F2 closure report (G-F2 = PASS)* |

Seven merges compose F2, each validated and merged into `main` on its own:

| Merge | Build-order steps | Subject |
|---|---|---|
| `9e97b10` | spec registration + 1–2 | English normative spec; frozen types; `SettlementTermsV1` + A3 vectors |
| `03e7c2c` | 3 | consolidated machine v2; prototype quarantined |
| `9e84e6e` | 4 | SQLite WAL settlement schema (store version 2) |
| `348ee28` | 5–7 | durable `SettlementStore`: CAS commit, atomic cursor, leased outbox |
| `6fbc0e6` | 8 | §10 ingest algorithm + deterministic reorder parking |
| `0ab2373` | 9–10 | durable `SettlementEngine`; dom-sim envelope adapter |
| `370f662` | 11+13 | failpoints C0–C10; the 18 G-F2 scenarios; prototype retired |
| `2d2fed6` | 12 | property tests; exhaustive model checker |

## 2. Files created and modified

Created:

```text
docs/normative/DOM-Interop-F2-Engineering-Specification-v1.0.md
crates/kaystra-core/src/types.rs
crates/kaystra-core/src/terms.rs
crates/kaystra-core/src/store_port.rs
crates/kaystra-core/src/ingest.rs
crates/kaystra-core/src/settlement_engine.rs
crates/kaystra-core/fixtures/terms-v1/{12 vectors, MANIFEST.md}
crates/kaystra-core/tests/{terms_vectors,settlement_store,ingest_reorder,
                           state_properties,decoder_smoke}.rs
crates/store/migrations/0001_f2_core.sql
crates/store/src/settlement.rs
crates/store/tests/f2_schema.rs
crates/f2-harness/src/settlement.rs
crates/f2-harness/tests/{common/mod.rs,g_f2_engine.rs,g_f2_scenarios.rs}
crates/f2-model/{Cargo.toml,src/main.rs}
scripts/verify_terms_vectors.py
```

Rewritten: `crates/kaystra-core/src/state.rs` (consolidated machine §7),
`crates/adapters/dom-sim/src/lib.rs` (detailed scan), `scripts/guards.sh`
(seventh guard), `.github/workflows/ci.yml` (F2 adjudication job),
`README.md`.

Deleted (spec §20 reconciliation): `crates/kaystra-core/src/engine.rs`,
`crates/kaystra-core/src/legacy.rs`,
`crates/kaystra-core/tests/engine_hardening.rs`, the prototype half of
`crates/f2-harness/tests/g_f1.rs`, and `g_f2.rs` (its USPE composition
survives as `uspe_composition.rs`, now driven by a REAL terminal outcome).
**No `InMemoryJournal` remains in the repository.**

## 3. Final A3 implementation and vector hashes

`SettlementTermsV1` is frozen in `crates/kaystra-core/src/terms.rs`:
magic `DOMITRM1`, version 1, fixed field order, all integers big-endian,
`terms_hash = BLAKE2b-256("DOM-INTEROP/SETTLEMENT-TERMS/V1\0" || bytes)`.
The decoder is strict: wrong magic, unknown version, unknown enum or flag
tag, truncation, metadata beyond 4096 (checked before allocating) and any
trailing byte all fail closed, and every decoded value is revalidated.

```text
valid-minimal (675 bytes)  fddae40bbd402b1c1ebf3a76293b0e1654e9a70d12963b1175a86f51fd159c73
valid-full    (749 bytes)  2a14e662f2008f98d365243589e7c7a92cab3a92f6dc0198a8ca247fff8d518a
```

Eight invalid vectors (roster equal, roster unsorted, bad version, unknown
enum tag, trailing byte, zero amount, bad point prefix, oversize metadata)
each fail closed with their frozen error. `scripts/verify_terms_vectors.py`
recomputes both hashes with Python's `hashlib` only — it does not import
`kaystra-core`, so the encoder cannot vouch for itself.

## 4. State / event / effect / persistence matrix

Implemented verbatim from spec §7.4–§7.5 in `crates/kaystra-core/src/state.rs`
and asserted row by row by `normative_table_holds`:

| State | Accepted event | Next | Persistence | Effect after commit |
|---|---|---|---|---|
| `Preparing` | `RefundArmed` | `ReadyToFund` | context + event | `AuthorizeFunding` |
| `ReadyToFund` | `FundingObserved` | `Confirming` | evidence ref + height | none |
| `Confirming` | `FundingObserved` | `Confirming` | idempotent refresh | none |
| `Confirming` | `FundingAbsent` | `ReadyToFund` | revalidation decision | none |
| `Confirming` | `FundingConfirmed` (matching) | `Settling` | confirmed evidence | none |
| `Settling` | `ClaimEvidenceVerified` | `Settling` | `EvidenceRefV1` only | consume evidence at the leg |
| `Settling` | `ClaimConfirmed` | `Settled` | terminal by CAS | record terminal |
| `Confirming`/`Settling` | `TimelockExpired` | same | refund armed | submit refund |
| `Confirming`/`Settling` | `RefundConfirmed` | `Refunded` | terminal by CAS | record terminal |
| non-terminal | `ReorgInvalidated` | idempotent regression | anchor + cursor + context | revalidate |
| terminal | any event | error / no economic effect | auditable late evidence | none |

Fail-closed rejections: `ClaimConfirmed` without verified evidence
(`PreconditionUnsatisfied`), `FundingConfirmed` against a different
observation (`EvidenceMismatch`), revision overflow (`RevisionOverflow`).

## 5. Schema and migrations

`crates/store/migrations/0001_f2_core.sql` applies the eight tables of
spec §8.1 verbatim as store schema version 2: `settlement_terms`,
`settlement_snapshot`, `settlement_journal`, `chain_cursor`,
`observed_evidence`, `durable_outbox`, `terminal_outcome`,
`late_evidence`. All `STRICT`, `foreign_keys=ON`, `journal_mode=WAL`,
`synchronous=FULL`. A version-1 database upgrades in place keeping its
data; a higher version fails closed. `crates/store/tests/f2_schema.rs`
(9 tests) proves the identifier length CHECKs, STRICT typing, foreign
keys, the unique `session_id`, the **unique terminal row** and the
duplicate-`event_id` refusal at the database level.

## 6. Boundaries C0–C10 and the result of each failpoint

Hooks compiled only under the test-only `failpoints` feature, at the
eleven boundaries of spec §13. `F2-E2E-003` fires each of them at five
different rounds — **55 crash-and-recover runs** — and requires the same
terminal as the uninterrupted baseline plus no effect left pending.

| Boundary | Injected at | Result |
|---|---|---|
| C0 | before `BEGIN IMMEDIATE` | PASS — nothing written, retry converges |
| C1 | after dedupe, before snapshot read | PASS |
| C2 | after the journal append | PASS — rollback, no partial row |
| C3 | after the snapshot CAS | PASS |
| C4 | after evidence / cursor | PASS |
| C5 | after the outbox insert | PASS |
| C6 | immediately before `COMMIT` | PASS — proves `F2-E2E-014` |
| C7 | immediately after `COMMIT` | PASS — effect dispatched after restart |
| C8 | after the outbox claim | PASS — lease expiry re-claims it |
| C9 | after the external effect | PASS — byte-identical resend |
| C10 | after marking completed | PASS — never dispatched again |

The seventh guard in `scripts/guards.sh` fails the build if the feature
ever becomes a default or is enabled outside `[dev-dependencies]`.

## 7. Requirement → test → result

| Requirement (spec) | Test | Result |
|---|---|---|
| §6 A3 canonical wire + hash | `terms_vectors.rs`, `verify_terms_vectors.py` | PASS |
| §6.1 strict decoder | `decoder_smoke.rs` (9) | PASS |
| §7 consolidated machine | `state.rs` unit tests (19) | PASS |
| §8.1 schema | `f2_schema.rs` (9) | PASS |
| §8.2 commit contract | `settlement_store.rs` (12) | PASS |
| §9 envelope, dedupe, equivocation | `settlement_store.rs`, `g_f2_scenarios.rs` | PASS |
| §10 ingest + reorder | `ingest_reorder.rs` (7) | PASS |
| §11 reorg | `F2-E2E-009/010/011` | PASS |
| §12 late evidence | `F2-E2E-012` | PASS |
| §13 recovery + failpoints | `F2-E2E-003/013/014/015`, `g_f2_engine.rs` | PASS |
| §14 property tests | `state_properties.rs` (8) | PASS |
| §16 scenario table | `g_f2_scenarios.rs` (19) | PASS |
| §17 model checking | `f2-model` | PASS |
| §18 no secret persisted | `g_f2_engine.rs` DB byte scan | PASS |

## 8. Counts, commands, exit codes and duration

```bash
cargo test --workspace --locked                    # 157 tests, 33 suites, exit 0
cargo test -p store --features failpoints --locked # exit 0
cargo clippy --workspace --all-targets -- -D warnings   # exit 0
cargo fmt --all -- --check                         # exit 0
./scripts/guards.sh                                # 7/7 PASS, exit 0
python3 scripts/verify_terms_vectors.py            # 10 vectors verified, exit 0
cargo run -p f2-model                              # 171,547 states, exit 0
PROPTEST_CASES=2000 cargo test -p kaystra-core --test state_properties  # 84.28 s, exit 0
cargo test -p dom-leg   --features real-dom-adaptor --locked  # 25 tests, exit 0
cargo test -p dom-vault --features real-dom-adaptor --locked  # 42 tests, exit 0
```

## 9. Property tests, fuzzing and model checking

**Property tests (§14).** Eight properties, executed at 2000 cases:
terminal immutability; `Settled`/`Refunded` never coexist with at most one
terminal effect; no funding before the refund is armed; duplicating every
event is observationally equivalent; **the same trace committed to the REAL
store with a crash before every prefix converges to the baseline**; the
durable path never contradicts the pure machine; an exhaustive depth-6
search checking the invariants on every edge; and the Rust `terms_hash`
tied to the frozen vector.

**Model checking (§17).** `crates/f2-model` explores the REAL transition
function composed with an abstract world — atomic commit or full rollback,
byte-identical redelivery, late evidence, two concurrent dispatchers that
may die between executing and completing — over **171,547 reachable
states**, with all five properties holding:

```text
AG !(Settled && Refunded)              HOLDS
AG terminal -> AX terminal_same        HOLDS
AG AuthorizeFunding -> refund_armed    HOLDS
AG external_effect -> journal_committed HOLDS
AG effect_completed_count <= 1         HOLDS
```

A second test proves the model actually reaches BOTH terminals, so none of
the properties holds vacuously.

**Fuzzing — declared limit.** The five `cargo-fuzz` targets named in §17
are **NOT** executed: they require a nightly toolchain with libFuzzer,
which this environment does not provide. What IS executed, in every CI
run, is `decoder_smoke.rs`: arbitrary bytes and single-byte mutations
through all three strict decoders, asserting no panic, bound checks before
allocation, no ignored trailing byte, unknown tags failing closed, and —
the strongest of them — `encode(decode(bytes)) == bytes`, so no decoder
silently normalizes two byte strings into one value (which would make two
encodings share one `terms_hash`). The coverage-guided targets remain
open as residual hardening in §12.

## 10. Proof that no `t` was persisted

`the_secret_never_reaches_the_engine_or_the_database` drives a full claim
to `Settled`, drops the engine so SQLite flushes, then reads the raw
`.sqlite`, `-wal` and `-shm` bytes and searches for the revealed secret —
full value and 16-byte prefix. Both absent.

This is structural, not incidental: `dom-sim`'s `scan_detailed` does not
carry the revealed secret at all, the adapter maps a claim to an evidence
REFERENCE, and no F2 type has a field able to hold secret material.
Cryptographic consumption happens at the F1 boundary through the
`RequestClaimConsumption` effect, which returns only success or failure.

## 11. Proof of claim XOR refund

Four independent layers: the machine refuses any event in a terminal state
(exhaustive depth-6 and depth-7 searches); the property suite asserts
`settled_seen && refunded_seen` is unreachable; the model checker proves
`AG !(Settled && Refunded)` over 171,547 states; and `terminal_outcome` has
`PRIMARY KEY(settlement_id)`, so the database itself refuses a second
terminal row under any application bug above it (`f2_schema.rs`).

## 12. Proof of CAS and logical exactly-once outbox

`commit_transition` runs one `BEGIN IMMEDIATE` transaction whose `UPDATE`
re-checks the revision in its `WHERE` clause; a stale writer loses and
`stale_revision_loses_the_cas_and_leaves_no_trace` proves nothing leaks —
no journal row, no cursor, snapshot untouched. `F2-E2E-016` runs two
engines over one database: exactly one commits, the other reloads without
error. Effects carry a deterministic `effect_id`; the payload returned by a
re-claim is byte-identical to the first persistence (`F2-E2E-015`), a wrong
payload hash refuses completion, and completion is idempotent.

## 13. Full F1 regression with the real backend

```text
cargo test -p dom-vault --features real-dom-adaptor   42 tests, PASS
cargo test -p dom-leg   --features real-dom-adaptor   25 tests, PASS
```

Both drive the pinned crate `a1825639154dcc9d89be098079112e9cb975940e`,
including the SCAD0 differential ending in `validate_kernel_signatures`.
`F2-E2E-018` asserts the CI jobs that run them still exist, so the gate
cannot keep claiming a suite that was removed.

## 14. Declaration: `dom-sim` is not the real DOM

`dom-sim` simulates chain semantics only — inclusion, confirmations,
timelock, spend exclusivity, reorg. It validates NO cryptography (I13/I15)
and confers no network compatibility. Every G-F2 result is a result about
the ENGINE against a simulated chain. Substitution for the real DOM node
is F7, under its own eligibility gate.

## 15. Declaration: F3 and later were not started

No work was done on ConditionLockV2/Foundry (F3), real EVM/BTC finality
(F3/F5), bonds, slash or USPE compensation (F4), BIP340/Taproot/Keystone
(F5), RFQ, solver economics or production Relay (F6), a real DOM node (F7),
consensus changes or DOM v2 integration (F8). The `uspe` crate keeps only
the pre-existing F4 advance work; F2 added no capability to it.

## 16. Published branch and remote HEAD

`main` carries every commit above; each step was developed on its own
`feat/` branch, merged with `--no-ff` and pushed. Verified at publication:

```text
local  HEAD = 5e6b0c2c6e602f0e56496308fc671e1ef7671c62
remote HEAD = 5e6b0c2c6e602f0e56496308fc671e1ef7671c62   (origin/main)
```

## 17. Clean worktree

`git status --short` is empty at the moment of publication (0 files).

---

## G-F2 adjudication (specification §23)

| Criterion | Verdict | Evidence |
|---|---|---|
| `SettlementTermsV1` and `terms_hash` frozen, vectorized, used in every binding | MET | §3; the envelope carries `terms_hash`, the engine derives every policy from the terms, the store binds them at creation |
| Complete machine table implemented | MET | §4 |
| `Settled` and `Refunded` mutually exclusive by proof AND constraint | MET | §11 |
| Every state / event / cursor / outbox durable | MET | §5, §12 |
| Crash at each transition and boundary converges to the baseline | MET | §6 (55 runs), §9 (crash before every prefix) |
| Duplication and replay idempotent | MET | `F2-E2E-004/005`, property suite |
| Equivocation fails closed | MET | `F2-E2E-006` |
| Reorder converges without applying a premature event | MET | `F2-E2E-007/008`, 24-permutation test |
| Reorg invalidates and revalidates observations correctly | MET | `F2-E2E-009/010/011` |
| Late evidence does not change the terminal | MET | `F2-E2E-012` |
| No secret persisted | MET | §10 |
| Real F1 regression green | MET | §13 |
| Suite, lint, property tests, **fuzz smoke** and model checking green | MET with a declared limit | §8, §9 — the property-based decoder smoke runs; the coverage-guided `cargo-fuzz` targets do not, and are listed as residual |
| Report, commits, push and remote verification exist | MET | this document, §1, §16 |

```text
G-F2 = PASS (2026-08-10)
```

The gate is adjudicated PASS on the criteria as written, with one
explicitly declared limit: the coverage-guided fuzz targets of §17 were
not executed in this environment. Per §23 the forbidden shortcuts are
absent — there is no `InMemoryJournal`, the F1 cryptography is on, the
store is real, the terms are not a placeholder, the vectors exist, and the
evidence is far more than unit tests of `transition()`.

## Residual hardening (tracked, not gate-blocking)

1. **Coverage-guided fuzzing.** The five `cargo-fuzz` targets of §17
   (`fuzz_terms_v1_decoder`, `fuzz_event_envelope_v1_decoder`,
   `fuzz_cursor_decoder`, `fuzz_journal_recovery`,
   `fuzz_reorder_convergence`) need a nightly toolchain with libFuzzer.
2. **External adversarial audit.** Inherited from F1 and still open.
3. **Multi-settlement engine.** F2 drives one settlement per engine
   instance; the store schema is already keyed by `settlement_id`.
4. **Non-height timelock domains.** `TimestampSeconds` and `BtcTime512s`
   fail closed at `open()`; their adapters arrive with F3/F5.
5. **G-F0 remains under WAIVER** (A1 name, A2 definitive license/IP, A12).
   It must be closed before any F3 work begins.

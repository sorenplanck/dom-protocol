# F6 CLOSURE REPORT — G-F6 ADJUDICATION PACKAGE

```text
Phase:      F6 — RFQ, solver and Relay
Gate:       G-F6 (Foundation Document v0.12 §7): "complete settlement
            with a solver; total loss of the Relay and its database
            does not prevent local claim or refund;
            ACK/dedup/byte-identical retransmission approved."
Authority:  DOM-Interop F6 Engineering Specification v1.0.3
            (adopted by the operator 2026-08-10; A5/A10 ratified by
            D-018; AD-1 §9; D-019, D-020, D-021, D-022 recorded in
            Foundation Document v0.12 §12.1)
Date:       2026-08-10
Executor:   this report PREPARES the adjudication. G-F6 = PASS exists
            only when the operator says so, in writing. Nothing here is
            self-ratification.
```

---

## 1. The gate's three clauses, and where each is proven

**Clause 1 — complete settlement with a solver.**
`crates/f6-engine/tests/g_f6_e2e.rs`: the full market step — RFQ to two
solvers, quotes back, ratified A5 selection, atomic §4.2 binding on
both sides, acceptance to the winner — over the REAL Relay and the REAL
§5.4/D-019 pipelines with real BIP340 signatures; the accepted
`terms_hash` carried into `SettlementTermsV1` (§4.2) and the real F2
engine driven to `Settled` and to `Refunded` under it on the dom-sim
seam; the real F4 assurance bound to the same `terms_hash` driven to
`Compensated`. The carry is committed by the A3 hash (asserted by
mutation), the F6→F4 binding is enforced by the machine's own named
`TermsMismatch` refusal, and the selection is observer-recomputable
(I12). Report: `F6-STEP8-E2E.md`.

**Clause 2 — total loss of the Relay and its database.**
`crates/f6-engine/tests/g_f6_relay_loss.rs`: the Relay killed — process
AND database, nothing copied out — at each of seven protocol stages, on
the claim path and on the refund path. Every lossy run is compared
field by field against a no-loss control: settlement terminal,
assurance terminal and revision, both parties' bindings,
`binding_complete`, winning quote — all identical. Participants restart
from their own SQLite files, and the restart PROVES it recovered
(revision + ledger asserted; mutation-checked live: deleting the
journal file fails both gate tests). The honest complement is asserted
too: an undelivered message IS lost, and only the sender's local copy
re-sends it. Report: `F6-STEP7-RELAY-LOSS.md`.

**Clause 3 — ACK/dedup/byte-identical retransmission.**
`crates/relay/tests/relay_transport.rs` + the D-020 proofs in
`d019_message_type_policy.rs`: same key + same bytes ⇒ the WHOLE ACK
byte-identical, resend replays the persisted bytes recomputing nothing
(I7); at-least-once delivery becomes exactly-once effects at the
recipient (named `Duplicate`, watermark unmoved); same key + different
bytes ⇒ `Equivocation` failing closed, with a proof a third party
verifies from the sender's own two signatures — and a fabricated proof
fails that verification in three distinct ways. Report:
`F6-STEP6-D019-MATRIX.md`.

## 2. The build order, step by step

| step | deliverable | evidence | state |
|------|-------------|----------|-------|
| 1 | objects + canonical codecs + frozen vectors | `crates/rfq`, `crates/relay` (RFQ id `e4345d8e…`, quote id `7d9cde80…`, terms `cdd7dff5…`, selection `fb797713…`, envelope digest `5ea98453…`) | done |
| 2 | f6-model exhaustive checker | `crates/f6-model`: 2658 books; arrival-order independence, 18 non-vacuous refusals, optimality, unique resolution + AD-1.4 exactly on the self-tie, bounds, DOM centrality | done |
| 3 | bond reservation + atomic §4.2 binding | `crates/f6-engine` kind `0xF601`, crash-at-every-transition on real SQLite | done |
| 4 | journaled selection; binding requires it | `select_and_record` over the REAL `rfq::selection`; `BindWithoutSelection`/`SelectionQuoteMismatch` | done |
| 5 | A10 authentication + §5.4 order | `crates/relay/src/auth.rs`; 17 adversarial tests, each refusal by name at its ratified step | done |
| 6 | Relay reference + D-019 registry | byte-identical ACKs, provable equivocation, closed message-kind registry, canonical policy structurally exclusive (guards.sh) | done |
| 7 | Relay-loss suite | 4 tests, differential against control, mutation-checked | done |
| 8 | end-to-end composition | 5 tests over the dom-sim seam | done |
| 9 | closure + adjudication package | this report | done |

## 3. Decisions in force

| id | content | state |
|----|---------|-------|
| D-018 | A5 (admissible/binding/winner; best-net-outcome; tie chain; arrival-order independence) + A10 (full-envelope BIP340 digest; roster snapshot; §5.4 order) | RATIFIED |
| AD-1.1..1.4 | DOM centrality; fee-cap composition; mode exactness; self-tie refusal | RATIFIED (AD-1.2/1.4 registered as D-021/D-022) |
| D-019 | closed message-kind registry; role→kind mapping; canonical policy exclusivity; consumer payload check | RATIFIED |
| D-020 | sequence domain = addressed flow; idempotency key distinguishes recipient | RATIFIED |

## 4. Test inventory (the F6 surface)

```text
crates/rfq          unit + selection + vectors        (workspace suite)
crates/f6-model     exhaustive checker                 2658 books, P1-P6
crates/relay        7 unit + 17 adversarial
                    + 18 D-019/D-020 + 8 transport  =  50
crates/f6-engine    9 unit + 7 consumer
                    + 4 Relay-loss + 5 E2E          =  25
```

Full local CI green end to end: fmt, clippy `-D warnings`, workspace
tests, store failpoints, f3-harness rpc-http, doc tests, f2/f4/f6
model checkers, 2000-case property suite, independent terms-vector
verifier, ten executable guards, forge suite in CI.

## 5. Open items — declared, not hidden

1. **The §4.2 carry field — RESOLVED by D-023** (operator decision,
   2026-08-10): option 1 ratified. The carry is the domain-tagged
   record in `metadata`, exactly once, commitment-only; the composition
   root (`crates/f6-engine/src/composition.rs`) is journal-sourced and
   a divergent restore fails closed by name (`TermsCarryMismatch`,
   `AssuranceBindingMismatch`). The eleven mandatory checks are green
   (`d023_terms_carry.rs` + the preserved E2E checks + the independent
   A3 vector verifier). Option 2 stays reserved for a future
   `SettlementTermsV2`; option 3 was rejected.
2. **F7 boundary.** The dom-sim seam carries the DOM leg by design;
   F7 swaps the real DOM. Nothing in F6 pre-claims F7.
3. **Real-chain legs.** F3 (Anvil/Sepolia) and F5 (regtest/signet) keep
   their own gates; G-F3's Sepolia rerun is pending dispatch and is not
   part of G-F6's clauses.

## 6. Gate state (operator decision, 2026-08-10)

The operator recognised F6 steps 1-9 as COMPLETE (commits `d831543`,
`a37b49b`), the executor side as COMPLETE, the evidence package as
ACCEPTED and the G-F6 evidence criteria as SATISFIED — and DEFERRED the
formal adjudication:

```text
G-F6 = EVIDENCE COMPLETE — FORMAL ADJUDICATION DEFERRED
```

Reason, per Foundation Document §8: no phase begins without the prior
gate PASS or a written ratified waiver, and at the time of this record
G-F3 and G-F4 are pending adjudication and G-F5 awaits its
public-signet leg. No prior written waiver of that ordering exists, and
none is presumed or created retroactively.

This state does not invalidate, demote or require repeating any F6
work. When G-F3, G-F4 and G-F5 are formally PASS, G-F6 may be
adjudicated WITHOUT re-running the tests, provided: the evidence
commits remain identifiable; the relevant code is unchanged; the pins
and interfaces F6 consumes are unchanged; and any later change has its
full regression green.

The adjudication itself is the operator's word alone. The executor
prepared this package and does not adjudicate it.

### Later note (2026-08-11) — two of the three blocking gates have closed

Appended after the fact; the record above is unchanged. On 2026-08-11 the
operator adjudicated **G-F3 = PASS** (decision D-025, closure
`docs/reports/F3-CLOSURE.md`) and, later the same day, **G-F4 = PASS**
(decision D-026, closure `docs/reports/F4-CLOSURE.md`, on Sepolia workflow
run 31521948686 executed at `main@593364b`). Both are recorded in Foundation
Document v0.16 §12.1.

Of the three gates this section names as blocking G-F6's adjudication, G-F3
and G-F4 are now closed; **G-F5 remains open** — Annex M v3.2 M.15.2 still
lacks its public-signet leg. `G-F6 = EVIDENCE COMPLETE — FORMAL
ADJUDICATION DEFERRED` therefore still stands, unchanged and for the same
reason. Nothing about F6 is promoted by D-025 or D-026.

---

## 7. Adjudication (operator decision, 2026-08-12)

The deferral recorded in §6 is lifted. Its stated cause — G-F3 and G-F4
pending and G-F5 awaiting its network leg — no longer exists: G-F3 closed by
D-025, G-F4 by D-026 and G-F5 by D-027, all recorded in the Foundation
Document's registry. The §8 ordering no longer withholds anything.

```text
G-F6 = PASS — OPERATOR ADJUDICATED
F6   = COMPLETED
```

Adjudicated by Soren Planck on 2026-08-12, recorded as decision **D-028** in
`docs/normative/DOM-Interop-Foundation-Document-v0.18.md` §12.1.

### The four conditions of §6, verified before this adjudication

§6 permits adjudication WITHOUT re-running the tests under four conditions.
Each was verified against `origin/main` at
`56a0d067bb668be2d21afbc1dbc2607532367ce2`, not inferred from the earlier
record:

| condition | verification | result |
|---|---|---|
| evidence commits remain identifiable | all eleven — `6e6ea40`, `04ec3fd`, `0bc92f4`, `5c62151`, `d65be31`, `bae94a4`, `7f8703c`, `e791496`, `d831543`, `a37b49b`, `27f7a37` — exist and are ancestors of `origin/main` | **SATISFIED** |
| relevant code unchanged | `git diff 27f7a37..origin/main` over `crates/f6-engine`, `crates/relay`, `crates/rfq`, `crates/f6-model` is **empty**; likewise over `kaystra-core`, `store`, `uspe`, `btc-crypto`, `dom-sim`, `counterparty-api`, `f2-harness` | **SATISFIED** |
| pins and consumed interfaces unchanged | `DOM_ADAPTOR_REV = eb6aa1ca59226bc316e3aace5ee0e279e5a154c2` identical; every `dom-*` source line in `Cargo.lock` identical by direct diff | **SATISFIED** |
| any later change has its full regression green | `./scripts/ci_local.sh` at `56a0d06`: exit 0, 336 s, `CI-LOCAL VERDICT: PASS` | **SATISFIED** |

### The two changes on the consumed surface, and why neither contaminates

The diff since the F6 baseline is not empty, and the two entries were
examined rather than waved past:

- `crates/f4-harness/tests/e2e_anvil.rs` (+226 lines) — the f4-harness
  **test binary**. `crates/f4-harness/src` and its manifest are untouched,
  and `f6-engine` links the library, never another crate's test targets.
  It cannot reach F6.
- `Cargo.lock` (+10 lines) — `f5-e2e` acquiring dependencies, among them
  `f6-engine`, `rfq`, `uspe` and `adapter-dom-sim`. This is a **new consumer
  of F6**, not a change to it: `f6-engine`, `relay` and `rfq` keep exactly
  the dependency sets they had.

### The three gate clauses, re-executed green at the adjudicated head

Although §6 does not require it, the suites were run again so that the
adjudication rests on a measurement of the current tree rather than on a
report:

| clause | suite | result |
|---|---|---|
| complete settlement with a solver | `g_f6_e2e.rs` | 5 passed / 0 failed |
| total loss of the Relay and its database | `g_f6_relay_loss.rs` | 4 passed / 0 failed |
| ACK / dedup / byte-identical retransmission | `relay_transport.rs` 8/0; `d019_message_type_policy.rs` 18/0 | green |
| F6→F2 carry (D-023) | `d023_terms_carry.rs` | 7 passed / 0 failed |
| recipient payload check (D-019) | `d019_consumer_payload.rs` | 7 passed / 0 failed |
| Relay library; RFQ | 7/0; 19/0 | green |
| selection invariants over the REAL `rfq::selection` | `f6-model` | PASS — fifteen named refusals, each fired at least once, none vacuous |

`f6-model` is worth naming precisely: it does not re-model the selection, it
drives the production one, and it proves every named refusal
(`FeeAboveLimit`, `RouteExcludesDom`, `BondNotReserved`,
`ExposureNotCovered`, `TieUnresolved`, and the rest) is reachable. A refusal
that never fires is a vacuous assertion; none here is vacuous.

### Scope of this adjudication

This closes G-F6 and phase F6. It promotes nothing else. **G-F7 remains
BLOCKED BY EXTERNAL DEPENDENCY** — the DOM-side Scriptless Phases 2–6 — and
G-F8 remains NOT STARTED. No F6 code, contract, script, workflow, vector or
manifest was modified by this adjudication, and nothing was executed on any
chain for it.

### Recorded debt, not converted into PASS

No independent external audit has covered F6. Annex M M.18's six-role
independent audit applies to F5 and was not met there either (its record
declares five review passes and "no claim of an external third party"). F6
never had one at all. External composition audit is F8's deliverable; this
is recorded so the absence stays visible rather than dissolving with time.

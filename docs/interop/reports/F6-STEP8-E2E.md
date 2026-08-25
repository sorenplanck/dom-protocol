# F6 BUILD-ORDER STEP 8 — END-TO-END COMPOSITION

```text
Phase:      F6 (RFQ / quotes / selection / binding)
Step:       8 — end to end: RFQ → quotes → selection → binding →
            F2 settlement → F4 assurance, over the dom-sim seam
Authority:  DOM-Interop F6 Engineering Specification v1.0.3 §4.2, §7
Date:       2026-08-10
Executor:   this report states results only; the GATE verdict is the
            operator's and is not claimed here.
Suite:      crates/f6-engine/tests/g_f6_e2e.rs
```

---

## 1. What this step adds over step 7

Step 7 proved the Relay is not load-bearing, and explicitly did NOT
claim the connection between the negotiated terms and the settlement.
Step 8 makes that connection and proves it:

> §4.2: "The accepted `terms_hash` is carried into the settlement's
> `SettlementTermsV1` so the F2 engine adjudicates under it."

The whole market step runs over the real Relay and the real §5.4/D-019
pipelines; a `SettlementTermsV1` is then DERIVED from the negotiation —
not written down independently — and the real F2 engine settles under
it; the real F4 assurance machine is bound to the SAME negotiated
`terms_hash` and compensates under it.

## 2. Results

| test | what it proves | result |
|------|----------------|--------|
| `the_negotiated_terms_settle_end_to_end` | full pipeline to `Settled`: negotiation over the Relay, terms derived from it (session, winner, fee bound, carried `terms_hash`), F2 settles on the sim chain, F4 reaches `Compensated` bound to the same negotiated `terms_hash`, both parties still hold the identical binding | PASS |
| `the_negotiated_terms_refund_on_the_timelock` | the same negotiation refunds on the chain's clock under the same derived terms | PASS |
| `the_settlement_terms_commit_the_negotiated_terms_hash` | the A3 hash COMMITS the carry: changing the carried F6 `terms_hash`, the winner, the session or the fee bound each changes the settlement's A3 `terms_hash` — the settlement cannot silently adjudicate a different negotiation | PASS |
| `the_assurance_refuses_any_other_terms_hash_by_name` | the F6→F4 binding is enforced by the machine: collateral verified against ANY other `terms_hash` refuses with the named `TermsMismatch`, and the negotiated one is then accepted (the refusal was the divergence, not a broken machine) | PASS |
| `an_observer_recomputes_the_journaled_selection` | I12 at the composition's root: an observer holding the candidate book recomputes the same winner and the same candidate-set digest the initiator journaled | PASS |

Also asserted inside the settle test: the journaled `terms_hash` is
recomputable from the objects (`TermsBindingV1::from_parts → terms_hash`
equals what the atomic binding journaled), so the value the settlement
carries is derivable by either party, not a private artifact.

## 3. The seam, stated honestly

"Driven with the dom-sim seam" is the build order's own phrase. The
chains here are `SimSettlementChain` — chain semantics only: funding,
claim, timelock, finality; no cryptography (I13/I15) — exactly as the
ratified G-F2 scenarios drive the same engine. The real-chain legs have
their own gate suites (F3 on Anvil/Sepolia, F5 on regtest/signet), and
F7 swaps the real DOM into this seam. This suite proves the
COMPOSITION; it does not re-prove the legs, and does not claim to.

## 4. Field mapping — what is derived, from where

| `SettlementTermsV1` field | source | rule |
|---------------------------|--------|------|
| `session_id` | `rfq.session_id` | same session, both layers name it |
| `intent_hash` | `rfq.rfq_id` | the RFQ IS the user intent this settlement executes; its id is content-derived |
| `solver_id` | `winner.solver` | the ratified selection's winner, no other |
| `fee_limit` | `rfq.fee_limit` | the ratified F2 bound, verbatim (AD-1.2 was already enforced at admissibility) |
| `metadata` | `CARRY_DOMAIN ‖ acceptance.terms_hash` | the §4.2 carry — INTERIM, NOT RATIFIED, see §5 |
| legs, adaptor point, recovery | sim-seam fixtures | the seam's, as in every ratified G-F2 scenario |

## 5. Reported to the operator — the carry field (NOT RATIFIED)

§4.2 mandates that the accepted `terms_hash` be carried into
`SettlementTermsV1`, but **no ratified document names the field**. The
existing candidates carry their own ratified labels:

- `intent_hash` — "hash of the user intent this settlement executes";
  the accepted terms are not the intent, so reusing it would repurpose
  a ratified meaning;
- `metadata` — "opaque, bounded and economically non-authoritative:
  nothing in it may ever influence a transition or an effect";
- a dedicated field — a wire change to the A3 canonical encoding,
  which under D-018-style discipline needs a new version and express
  ratification.

The interim implemented here, marked NOT RATIFIED in the code: a
domain-tagged record in `metadata`
(`DOM-INTEROP/F6-TERMS-CARRY/V1\0 ‖ terms_hash`). It respects
metadata's ratified label because the copy is a COMMITMENT, not an
input: the A3 terms hash commits it (asserted), while every machine
that ACTS on the F6 `terms_hash` — the F4 assurance — receives it as a
direct, explicit constructor input. Nothing reads it back out of
metadata to decide anything, and the suite asserts the commitment, not
a readback.

Options for the operator's word:

1. **Ratify the metadata carry** (this interim) as the V1 rule — no
   wire change, commitment-only semantics as implemented;
2. **A dedicated `f6_terms_hash` field** in a `SettlementTermsV2` — the
   cleanest long-term shape, at the cost of a new canonical encoding,
   new frozen vectors and a ratified migration;
3. **Repurpose `intent_hash`** — no wire change, but it overwrites a
   ratified meaning and loses the RFQ-id binding this suite uses.

The executor's recommendation is (1) now, with (2) noted as the natural
shape if a V2 of the terms wire ever opens for other reasons. Until the
operator decides, the code says NOT RATIFIED.

## 6. Totals

```text
crates/f6-engine   9 unit + 7 D-019 consumer + 4 Relay-loss + 5 E2E = 25
crates/relay       7 unit + 17 adversarial + 18 D-019/D-020
                   + 8 transport                                    = 50
                                                             total    75
```

Full local CI (`scripts/ci_local.sh`): **PASS**.

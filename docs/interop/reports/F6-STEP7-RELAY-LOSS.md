# F6 BUILD-ORDER STEP 7 — RELAY-LOSS SURVIVABILITY

```text
Phase:      F6 (RFQ / quotes / selection / binding)
Step:       7 — the Relay-loss adversarial suite
Clause:     the SECOND CLAUSE of the G-F6 gate
Authority:  DOM-Interop F6 Engineering Specification v1.0.3 §6.3
            (ported from Foundation Document §4.6)
Date:       2026-08-10
Executor:   this report states results only; the GATE verdict is the
            operator's and is not claimed here.
Suite:      crates/f6-engine/tests/g_f6_relay_loss.rs
```

---

## 1. The ratified rule

> **Relay-loss survivability (the gate's second clause).** Claim, refund
> and compensation read only local durable state and the chains. The
> G-F6 suite must kill the Relay (process AND database) at every
> protocol stage and prove the session still reaches its terminal state
> through local artifacts plus chain observation.

## 2. What "kill" means in this suite

Nothing is softened. The `RelayV1` value is **dropped** — the process
dies — and replaced by a fresh empty one — the database is gone. Every
stored envelope, every mailbox and every ACK it produced ceases to
exist, and nothing is copied out first. Three assertions run at the
moment of the kill:

- the new Relay is empty (`is_empty()`, `len() == 0`);
- every participant's mailbox is empty;
- a key the old Relay acknowledged seconds earlier can no longer be
  answered for (`stored_bytes(&key)` is `None`).

In the same breath each **participant** restarts too: its
`DurableBinding` is dropped and recovered from its own SQLite file, and
the settlement engine is dropped and recovered from its own. What
continues the session is a genuinely new process reading a genuinely
durable local artifact — not a value that survived in memory.

The recipients' `TranscriptStateV1` is deliberately **not** reset. Replay,
gap and equivocation state is the recipient's own durable state; §6.3's
whole point is that the recipient keeps what it needs while the Relay
keeps nothing.

## 3. The stages

The rule says "at every protocol stage", so the list is the stages of an
F6 session rather than a sample of them. Each is exercised twice — once
on the claim path, once on the refund path.

| stage | what has happened |
|-------|-------------------|
| `BeforeRfq` | nothing sent yet |
| `RfqDelivered` | the RFQ reached both solvers |
| `OneQuoteDelivered` | one quote reached the initiator; the other had not been submitted |
| `QuotesDelivered` | both quotes reached the initiator |
| `SelectionRecorded` | the ratified A5 selection is journaled |
| `BindingRecorded` | the atomic §4.2 binding is journaled on both sides |
| `AcceptanceDelivered` | the acceptance reached the winning solver |

## 4. Results

| test | what it proves | result |
|------|----------------|--------|
| `relay_loss_at_every_stage_still_reaches_the_claim_terminal` | 7 stages killed; every run reaches `Settled` with the same binding, the same winner and the same F4 `Compensated`, identical to a no-loss control | PASS |
| `relay_loss_at_every_stage_still_reaches_the_refund_terminal` | the same 7 stages on the timelock path; every run reaches `Refunded`, identical to its control | PASS |
| `a_killed_relay_keeps_nothing_and_can_answer_for_nothing` | the kill is real: a Relay that carried a whole negotiation holds nothing, delivers nothing, and cannot answer for a key it just acknowledged | PASS |
| `relay_loss_costs_the_session_its_transport_and_only_that` | the honest complement: an **undelivered** message IS lost for good, and only the sender's own local copy gets it moving again — into a new Relay, byte-identical (I7), accepted exactly once | PASS |

All three ratified outcomes are covered, because §6.3 names all three:

- **claim** → `SettlementState::Settled`, real F2 engine, real SQLite, simulated chain;
- **refund** → `SettlementState::Refunded`, on the chain's clock;
- **compensation** → `AssuranceState::Compensated`, the real F4 assurance
  journal, recovered from its file between every single transition.

Not one event in the compensation history is a Relay message: they are
chain observations and local evidence checks. That is *why* compensation
survives the Relay's death, and the suite drives it that way rather than
asserting it.

## 5. Why this suite is not vacuous

If the second half of a session never touched the Relay, killing the
Relay would prove nothing. Four things prevent that reading:

1. **The negotiation really travels the Relay.** Every message is a
   signed `RelayEnvelopeV1` submitted to the real Relay, delivered from
   a real mailbox, validated by the real §5.4 pipeline and checked by
   the real D-019 consumer. A refusal anywhere fails the test.
2. **The comparison is differential, not existential.** "Reaches a
   terminal" would be weak. Each lossy run is compared field by field
   against a control run with no loss: settlement terminal, assurance
   terminal, assurance revision, both parties' bindings,
   `binding_complete`, and the winning quote.
3. **The restart is proven to recover.** `Party::restart` captures the
   revision and the ledger before dropping, and asserts both after
   recovery. A restart that silently began from an empty journal would
   otherwise look exactly like a successful one.
4. **The kill is proven to destroy.** Asserted separately, so the suite
   cannot pass with a `kill` that quietly did nothing.

**Mutation check performed.** Point 3's assertion was verified live: with
the journal file deleted before recovery, both gate tests FAIL at the
revision assertion (`g_f6_relay_loss.rs:373`). Restored, all four pass.
An assertion that cannot fail is not an assertion.

## 6. Scope — what this step does NOT claim

Step 7 proves the Relay is not load-bearing. It does **not** wire the
negotiated `terms_hash` into the settlement's terms: the F6 binding and
the F2 settlement are driven as the separate machines they are today.
Connecting them end to end is build-order step 8's job, and claiming it
here would be claiming more than this suite measures.

## 7. Totals

```text
crates/f6-engine   9 unit + 7 D-019 consumer + 4 Relay-loss = 20
crates/relay       7 unit + 17 adversarial + 18 D-019/D-020
                   + 8 transport                            = 50
                                                     total    70
```

Full local CI (`scripts/ci_local.sh`): **PASS**.

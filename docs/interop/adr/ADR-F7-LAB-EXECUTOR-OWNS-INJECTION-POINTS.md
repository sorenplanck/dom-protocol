# ADR-F7-LAB-EXECUTOR-OWNS-INJECTION-POINTS — What blocks the remaining fault rows

Status: LAB DESIGN NOTE — **PARTLY IMPLEMENTED AND PARTLY RETRACTED**, see the
resolution section at the end. Originally recorded the change that would unblock
four fault families at once and why it was specified rather than attempted.
Proposes no change to Foundation v0.18, Annex M v3.3, or any ratified decision,
and claims no gate result.

## The observation

Every fault family still unexecuted is blocked by the same thing, and it is not
cryptographic and not a missing durable structure. It is a boundary of
responsibility: **the executor delegates a phase to a lower call, so it cannot
inject a fault inside that phase.**

| Family | Delegated to | Consequence |
| --- | --- | --- |
| Restart cut at `BothAnchorsConfirmed` and `AnchorsValidated` | `validate_real_anchors_and_authorize_claims` | The stages are committed inside the call. The executor's observation loop never sees them, so a cut placed at either can never fire. |
| `ReorderedDelivery`, `Equivocation` | the compositor's DSC1 signing rounds | **This row was wrong — see the correction below.** |
| `RelayProcessLoss`, `RelayDatabaseLoss` | nothing — the relay carries no route traffic | The executor authenticates the relay and calls `len()`. Injecting loss into a transport the route never uses proves nothing. |
| `LateChainEvidence` | — | The runner database has a `late_evidence` table, but nothing in the F7 path writes to it. `record_late_evidence` exists only on the `kaystra-core` store port and in that crate's tests. |

## Correction: the DSC1 seam already existed

The row above said there was no seam inside the DSC1 rounds at which to
reorder or duplicate a message. That is false, and reading `dom-leg` rather
than the laboratory's own wrapper is what showed it.

`F7DomDsc1FaultControllerV1` (`crates/dom-leg/src/f7_wallet.rs:237`) is called
after every durable prefix, and `F7DomDsc1FaultDirectiveV1`
(`crates/dom-leg/src/f7_wallet.rs:216`) already carries `RejectNextReordered`,
`ReplayLastExact` and `PersistLastEquivocation`. All three are enacted by the
compositor itself against the retained production identity and the real
Contracts store — the reorder probe at `f7_wallet.rs:1728`, the duplicate at
`:1799`, the equivocation at `:1810`, which drives the session to
`FailedClosed` and verifies `EquivocationPersisted` before returning.

The laboratory had an adapter for it — `F7LiveDomDsc1FaultAdapterV1` — which
was exported, documented, and **never constructed anywhere**. The reason it
could not be constructed is one line of visibility: the compositor entry that
accepts a controller was `pub(crate)` inside `dom-leg`, so the only public
route-level entry, `sign_or_resume_claim`, always passed a no-op.

The consequence is larger than the two protocol rows. Every
`AfterDsc1Prefix` restart cut — 7 prefixes across 3 purposes — was equally
unreachable, and a scenario carrying one would have run as though it carried
no fault at all. The restart guard added earlier catches that as a refusal
rather than a pass, which is how it stays honest, but the cuts themselves
needed the seam.

What was missing was therefore plumbing, not design, and it is now in place
for the Claim purpose. The Funding and Refund rounds reach the same
compositor helper through different entries and need the same one-line
visibility change to be driveable from the laboratory.

## Why this was found by executing, not by reading

Two of these were silent. A reorg scenario could reach a terminal **without
performing its reorg**, and a restart scenario could reach a terminal **without
its restart firing**. Both looked exactly like a pass: revision 10, one terminal,
clean outbox, `quick_check` ok.

Both are now guarded — the route refuses to verify a terminal unless the
chain-control receipt carries reorg evidence, and unless the fault boundary
recorded a fired restart. The guards are the durable part of this work; the
individual rows are not.

## The change that would unblock the anchor cuts

`validate_real_anchors_and_authorize_claims` is already **re-entrant**: it
accepts `BothAnchorsConfirmed` and `AnchorsValidated` as entry states and treats
the corresponding transitions as no-ops when the durable digests already match.
That property is what makes the change tractable.

Give the method an observation seam:

```rust
fn validate_real_anchors_and_authorize_claims(
    …,
    observe: &mut dyn FnMut(F7RouteStageV1) -> Result<ObserveOutcome, F7RunnerError>,
)
```

invoked immediately after each durable stage commit. `ObserveOutcome::Continue`
proceeds; `ObserveOutcome::Stop` returns without advancing further. The executor
passes a closure wrapping `observe_route_stage`, so a cut at either stage fires
with the durable state exactly at that stage — and because the method is
re-entrant, the resumed generation re-enters it and the already-committed
transitions no-op.

This must not become a general "stop anywhere" hook. The seam exists so that a
stage the executor is accountable for observing is observable; it is not a
mechanism for interrupting the runner at arbitrary points.

## Why it was not attempted

The change touches the path that all four settled claim routes traverse. It
would need at least one full route executed end to end to show it had not broken
them.

At the time of writing the host cannot deliver that: a few hundred MiB of RAM
free against 9.4 GiB of swap, 572 error or `RPC server stopped` lines in the DOM
node log for the session, and route attempts failing at chain observation steps
that the settled routes pass through unchanged when the machine has room.

Making a structural change to a working path, on a machine that cannot verify
whether it still works, trades a known-good state for an unverifiable one. The
change is specified here instead, so that it can be made where it can be
checked.

## Ordering, if taken up

1. The anchor observation seam, verified by executing scenarios 5 and 6 and
   requiring the restart marker to be present rather than the route to settle.
2. The relay carrying live route transport, which is the prerequisite for both
   relay-loss rows and is the largest of the four.
3. The DSC1 message seam for reordering and equivocation.
4. The runner-side late-evidence path.

Step 1 is the smallest and closes two rows. Step 2 unblocks two more but is a
transport design change, not a fault-injection change.

## Resolution — 2026-08-16

Three of the four rows are closed and one stands. Recorded here so the note is
not read as a live work item.

**1. The anchor observation seam: implemented and proven.** The seam was built
as specified. Scenario 5 fired its cut at `BothAnchorsConfirmed` with the stage
durable, the worker exited with the reserved status, generation 1 resumed and
the route settled at revision 10 with one terminal. Scenario 6 did the same for
`AnchorsValidated`. Both had previously reached a terminal with no restart at
all and were refused by the guard rather than counted.

The concern recorded in "Why it was not attempted" — that the change touches the
path all four settled claim routes traverse — was addressed by executing, not by
argument. Two full routes settled through the modified path.

An intermediate error is recorded with it: the first version observed only
`BothAnchorsConfirmed`. `AnchorsValidated` is committed later in the same call
and was still invisible, so scenario 6 settled with no restart. The guard caught
that, which is what a guard is for.

**2. Reorder and equivocation: the row was wrong, see the correction above.**
The seam already existed in `dom-leg`; the laboratory could not reach it because
the compositor entries that accept a controller were `pub(crate)`. Both probes
are now reachable for the Claim and Funding purposes.

**3. The relay rows: the row was right and they stand.** Every relay entry point
needs a real `RelayEnvelopeV1`, and the route's DSC1 messages go straight to the
Contracts store. Manufacturing envelopes so the relay would have something to
lose was considered and refused: that is evidence built for the test.

**4. Late chain evidence: implemented.** The runner-side path did not exist and
now does, asserted at every terminal against the route's own terminal event id.

What replaced this note as the open list is `F7_FINAL_STATE.md` sections 6 and
7, plus `B-F7-NORM-001` in `F7_BLOCKERS.md` for the one genuinely normative
question this work raised.

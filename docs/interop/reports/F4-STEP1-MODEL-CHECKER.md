# F4 step 1 — exhaustive model checker for the G-F4 economic invariants

Status: **EXECUTED** (evidence below). It closes no gate on its own; G-F4
remains open until the remaining F4 items are executed and the operator
ratifies the phase.

Artefact: `crates/f4-model` (adjudication CLI, nothing links it).
Machine under check: `uspe::assurance_transition` — the production
function, not a re-modelled copy.

## 1. What it proves

Nine properties, each reported `HOLDS`/`VIOLATED`, exit code 1 on any
violation:

| Property | Origin |
| --- | --- |
| `coverage: every state of the machine is reachable` | non-degeneracy |
| `NO_DOUBLE_COMPENSATION` | Foundation Document, gate G-F4 |
| `NO_RELEASE_AND_SLASH` | Foundation Document, gate G-F4 |
| `TIMEOUT_SAFE` | Foundation Document, gate G-F4 |
| `AG compensated_total <= compensation_cap` | policy cap |
| `AG certificate.terms == obligation.terms` | binding |
| `AG recorded_outcome in {Released, Compensated}` | economic terminals |
| `AG accepted_transition -> PersistState(next) first` | persist-before-effect |
| `AG terminal -> AX unchanged` | terminal immutability |

## 2. Why it is stronger than the existing unit tests

`crates/uspe` already walks every event sequence up to depth 9. That is a
bounded prefix. This checker explores a **finite abstract world to a
fixpoint**, so it covers histories of *every* length.

It also drops the deduplication layer entirely: every event is offered in
every reachable world, any number of times, in any order. The properties
are therefore proven by the machine's own structure, not by the engine's
I7 idempotency. The delivery layer's own properties (persist-before-effect
under crash, at-most-once completion, atomic commit) are not re-proven
here — they belong to the ratified F2 outbox and are model-checked by
`f2-model` over that same outbox.

One visible consequence: `AuthorizeRelease` may be emitted more than once
along a history (the tolerated `ClaimRejected + ObligationSettled` arrival
order re-emits it). That is sound — every emission authorizes the SAME
single conditioned spend — so the uniqueness properties are stated over
recorded economic outcomes and over `ExecuteSlash`, which never repeats.

## 3. Finding: `BondLocking` stranded the collateral

On its first run the checker reported:

```
  VIOLATED TIMEOUT_SAFE
    TIMEOUT_SAFE: BondLocking: no non-privileged event sequence reaches a
    terminal — collateral is stranded
```

`BondLocking` is entered when the collateral lock is observed on chain.
The only event it accepted was `CollateralVerified`, and that event is
refused when the terms binding diverges (`TermsMismatch`). So collateral
that was locked but never certified — because verification never arrived,
or because every attempt carried the wrong `terms_hash` — had **no exit
at all**. The capital stayed locked with no timeout, no release and no
privileged rescue. This is the one shape the gate's TIMEOUT_SAFE
invariant exists to forbid, and it was real.

### Correction applied

Additive, in `crates/uspe`:

- new event `AssuranceEvent::CollateralDeadlineExpired`;
- new arm `(BondLocking, CollateralDeadlineExpired) => (ReleasePending, [AuthorizeRelease])`.

No state was added and no existing arm was changed. The collateral goes
back to whoever posted it, through the same release path the other
timeouts already use. The arm cannot interact with the compensation path:
from `BondLocking` no certificate has been issued and no slash can ever
have been authorized, and `ReleasePending` accepts only
`ReleaseConfirmed`. `NO_RELEASE_AND_SLASH` and `NO_DOUBLE_COMPENSATION`
are unaffected, which the checker then confirmed over the whole space.

Nothing was loosened to obtain the green result: the property was left as
the document states it and the machine was corrected to satisfy it.

## 4. Falsifiability

Three controls, all in `crates/f4-model`:

- `the_checker_reports_an_injected_violation` — feeds the checker a world
  that really does hold both a release and a slash fact, and one over the
  cap, and asserts it reports both. A checker that cannot report proves
  nothing.
- `the_exploration_covers_every_state_of_the_machine` — all 11 states are
  visited, so no property holds vacuously over an unexplored region.
- `the_model_reaches_both_economic_outcomes` — `Released`, `Compensated`,
  the certificate and `ExecuteSlash` all genuinely occur.

`state_index` matches exhaustively on `AssuranceState`: a state added
upstream stops `f4-model` from compiling, and `effect_is_authorized` does
the same for the effect alphabet (I12 tripwire).

## 5. Measured evidence

```
$ cargo run -p f4-model --release --locked
F4 model checker (G-F4 economic invariants)
  reachable worlds explored: 18
  machine states covered: 11/11
  HOLDS   coverage: every state of the machine is reachable
  HOLDS   NO_DOUBLE_COMPENSATION
  HOLDS   NO_RELEASE_AND_SLASH
  HOLDS   TIMEOUT_SAFE
  HOLDS   AG compensated_total <= compensation_cap
  HOLDS   AG certificate.terms == obligation.terms
  HOLDS   AG recorded_outcome in {Released, Compensated}
  HOLDS   AG accepted_transition -> PersistState(next) first
  HOLDS   AG terminal -> AX unchanged
  result: PASS
```

Eighteen worlds is the honest size of this space: the assurance machine
has 11 states and the economic facts are saturating counters, with no
outbox modelled here. The `coverage` property is what guards against
degeneration — a magic state-count threshold would not.

- `cargo test -p f4-model` — 6/6 pass.
- `cargo test -p uspe` — 11/11 pass (including the extended
  `timeout_safe_every_waiting_state_progresses_without_privilege`, which
  now pins the `BondLocking` escape).
- `cargo test --workspace --locked` — full suite green.
- `cargo clippy --workspace --all-targets` — clean.
- `scripts/guards.sh` — all guards PASS.

## 6. Integration

- workspace member `crates/f4-model`, lockfile committed;
- CI job `f2-adjudication` gained the step
  `cargo run -p f4-model --release --locked`;
- `scripts/guards.sh` I6 exclusion extended to `crates/f4-model/*` on the
  same rationale as `f2-model` (adjudication CLI whose entire purpose is
  printing its verdict; nothing links it).

## 7. What this does NOT close

F4 items 2–4 (`AssurancePolicyV1`, `AssuranceCertificateV1`,
`BondAdapter` over ConditionLock, `EvidenceVerifier`) are still marked
**[PROPOSAL]** in §3.4 of the Foundation Document, and the route decision
between (a) a ratified normative execution spec first and (b) coding
directly on §3.4 is still with the operator. This step was chosen
precisely because it does not depend on that decision.

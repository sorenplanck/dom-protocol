# G1 Adjudication Record

Date: 2026-08-10
Coordinator: Soren Planck

## Decision

The coordinator reviewed the consolidated Phase 1 gate — G1A (cryptography,
DOM Protocol), G1B (Store/Nonce Vault, this repository), and G1C (their
commit-bound composition) — and adjudicated it **approved**. The adjudication
act was the coordinator's merge of pull request #2, integrating the
`phase1-evidence` branch into `main` (merge commit `00339be8`, authored by the
coordinator). This record documents that decision so it exists as repository
state rather than only as an action in the hosting platform's history.

Adjudication authority belongs to the coordinator alone. Repository tests,
green checks, and agent-produced summaries are inputs to this decision, never
substitutes for it.

## Bound state

| Input | Binding |
| --- | --- |
| `dom-contracts` evidence tip at adjudication | `3cf5b950d7ed551a88b4ca2cf15b77228c313214` |
| DOM Protocol revision consumed (immutable pin) | `6f2b230ebbec390040dbf0bff110efaf4bb0f101` |
| G1A supplementary test evidence branch | `feat/dom-protocol-phase1-closure` at `f93f1b2e141fc6dfea87ac0fe57ddb35ed8c3eeb` |
| Adjudication merge on `main` | `00339be8e8c100ea59fec65ac817c4649bd8af07` |

The supplementary G1A evidence (the 10,000-case closed-cycle property test and
the closed-request-type fuzz harness) lives at a descendant of the pinned
revision and changes no production code; the pin itself is unchanged.

Per the rule in `PHASE1-CONTRACTS-CLOSURE.md`, no workflow run identity is
recorded in this file. Run capture is the coordinator's NAR-DC-P1-006 §7.2
obligation and lives outside the tree it attests.

## Open items carried past adjudication

Adjudicating G1 is the coordinator's call and does not erase recorded
obligations. The following remained open at adjudication time and stay
recorded; they gate later milestones, not this one:

- coordinator capture of the required workflow-run identities (§7.2);
- executed fuzz campaigns bound to the final candidate commits in both
  repositories, including the new `closed_request_types` target;
- the independent 311-field comparison, the zeroization and constant-time
  review, the selected-history secret scan, the wallet isolation proof, and a
  clean cache-independent reproducibility execution on the current pin;
- independent external security review.

## Effect

```text
G1_CONSOLIDATED = ADJUDICATED_APPROVED_BY_COORDINATOR
PHASE1_CODE = CLOSED
NEXT_PHASE_DEVELOPMENT = PHASE2_SHARED_OUTPUT_MAY_BEGIN
PRODUCTION = NOT_AUTHORIZED
MAINNET = DISABLED
REAL_FUNDS = PROHIBITED
```

A detached Minisign signature by the established operator key
`74197A95CA309CF0` may be attached as `G1-ADJUDICATION.md.minisig` to bind
this record cryptographically. Until then, the record is evidenced by the
coordinator's authenticated merge action on the hosting platform.

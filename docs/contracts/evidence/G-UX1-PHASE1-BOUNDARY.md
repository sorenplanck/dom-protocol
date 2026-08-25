# G-UX1 Phase 1 Boundary

Status: **PHASE 1 CONTRIBUTION SATISFIED; FULL G-UX1 PENDING**

Date: 2026-08-09  
Scope: DOM Contracts Phase 1 adaptor, nonce, and release-surface boundary

## Decision

The G-UX1 addendum assigns two requirements to Phase 1:

1. the supported public application API must not expose nonce control or
   partial-signing coordination; and
2. production builds must reject laboratory bypass surfaces.

The candidate satisfies that Phase 1 assignment. This finding does not approve
the complete G-UX1 gate. The persistent executor, recovery behavior, public
state and error model, refund-before-funding flow, claim/refund end-to-end
tests, and integrator study remain assigned to Phases 3 through 7.

## Supported surface

The only current application binary is a fail-closed validation shell. It
offers no contract, funding, signing, nonce, networking, storage, mainnet, or
real-funds operation. No production SDK is published from this repository.

Workspace crates contain internal storage codecs and opaque adaptor
composition types. They are not declared to be the supported application SDK.
The Store's production composition uses the pinned `NonceVaultV1` boundary;
test constructors require the `evidence-only` feature.

## Reproducible controls

| Control | Evidence | Result |
| --- | --- | --- |
| No application nonce or partial-signing method | The `dom-contracts` binary has a validation-only command surface. | Pass for the Phase 1 candidate |
| Linear opaque signer capabilities | Compile-fail doctests reject cloning, manufacturing, raw extraction, and reuse of permits and exported signer states. | Pass |
| Laboratory surface excluded from release | `scripts/check-release-surface.sh` first compiles the supported release Store and then requires the `evidence-only` release build to fail with the policy diagnostic. | Enforced in CI |
| Production bypass cannot be hidden by a generic compiler failure | The release-surface gate verifies the exact expected diagnostic. | Enforced in CI |
| Non-Linux production runtime remains absent | The durable Store runtime is compiled only on Linux; portable evidence compiles and tests codecs without adding a fallback runtime. | Pass |

## Gate status

```text
G_UX1_PHASE1_API_BOUNDARY = SATISFIED
G_UX1_PHASE1_RELEASE_BYPASS_TEST = ENFORCED
G_UX1_FULL_GATE = PENDING_PHASES_3_TO_7
PRODUCTION = NOT_AUTHORIZED
MAINNET = DISABLED
REAL_FUNDS = PROHIBITED
```

This record is evidence, not release authority. Full G-UX1 remains a
stop-ship gate until every acceptance criterion has commit-bound code, test,
environment, and independent approval evidence.

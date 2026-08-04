# Phase 3-SNV DOM contract result

Status: **PARTIAL** — the storage-independent contract is implemented and
validated; G1b is not approved and no Wallet integration is present on this
branch.

## Baseline and scope

- Branch: `feat/phase-3-snv-contract`
- Starting commit: `a37f0bbeeb7c0ee5579154ae64476e8374d1dabb`
- Implementation commit: `3f91b4a8e594db47c1d600ae6057958cb2e92a07`
- Worktree: `/home/leonardov/dom-scriptless-dev/worktrees/phase3-snv-dom`

The change is confined to `dom-adaptor` and Phase 3-SNV documentation. It does
not implement Phase 3-SM, adaptor cryptography, persistent Wallet storage, or a
remote witness protocol.

## Implemented contract

- `NonceVault` lifecycle: reserve, commit public material, authorize exposure,
  exact retry, consume, and abort;
- opaque and redacted key, session, counterparty, reservation, and idempotency
  identifiers without a serialized wire representation;
- closed Funding V1, Claim V1, and Refund V1 purposes;
- monotonic reservation and restore capability states;
- typed errors for budget exhaustion, conflict, invalid transitions, witness
  failure, rollback, divergence, quarantine, corruption, and storage failure;
- receipt as an associated semantic type, leaving production bytes and
  authentication unfrozen;
- no dependency from `dom-adaptor` to Wallet V3.

## Validation

| Command | Result |
|---|---|
| `cargo test -p dom-adaptor --locked` | passed: 6 tests, including 3 new contract tests and 3 existing freeze probes |
| `cargo clippy -p dom-adaptor --all-targets --locked -- -D warnings` | passed |
| `cargo fmt --all --check` | passed after formatting |
| `git diff --check` | passed before the implementation commit |

## Gate status and blockers

G1b remains **NOT APPROVED**. Only the checklist item requiring the trait in
`dom-adaptor` is closed. The following remain open:

- integration against a Wallet revision that pins the future authoritative DOM
  commit containing `dom-adaptor`;
- measured and frozen budget values;
- production witness encoding, authentication, signed receipt format, and
  self-hosted implementation;
- production nonce sealer/generator integration;
- cross-platform Windows and macOS persistence tests;
- complete crash, rollback, fork, restore, and ordinary-transaction isolation
  evidence.

## Expected integration seam

The Wallet branch intentionally has no nonportable path dependency on this
worktree. It currently mirrors the semantic purpose and lifecycle types locally.
Integration must update the Wallet's authoritative DOM revision and implement
`dom_adaptor::NonceVault` with explicit conversions. The concurrent G1a branch
may also define canonical public-exposure types, so this conversion boundary is
the primary anticipated API conflict.

No official repository was modified. No DL2P material was imported. No push,
merge, release, publication, consensus change, or remote mutation occurred.

## G1b completion mission update — 2026-08-04

Status remains **PARTIAL / G1b NOT APPROVED**.

The contract now enforces consume-before-export at its type boundary:

- `authorize_exposure` persists a verified receipt but returns no bytes;
- `consume` must durably remove nonce material and write a terminal tombstone
  before returning `ConsumedExposure`;
- `retry_public_material` is post-consumption only and returns the exact
  previously committed bytes;
- abort semantics distinguish `AbortedBeforePublicMaterial`,
  `ConsumedOnAbort`, and conservative `Burned`;
- the purpose projection names Refund, ClaimAdaptor, Funding, and Sponsor while
  deliberately defining no second wire codec; Sponsor fails strict V1 policy.

ADR-3SNV-0002 accepts this ordering. ADR-3SNV-0003 blocks production witness
wire/client/service work because the authentication and byte-layout inputs are
not frozen and Wallet has no approved service signing/key-lifecycle boundary.
No provisional protocol or local-file fallback was added.

Focused Linux validation after the correction:

```text
cargo test -p dom-adaptor --locked
  PASS: 6 tests total
cargo clippy -p dom-adaptor --all-targets --locked -- -D warnings
  PASS
cargo fmt --all --check
  PASS
git diff --check
  PASS
```

Windows, macOS, sanitizers, production witness interoperability, and complete
fault injection were not executed. No production functionality outside the
new unpublished contract changed.

## Ratified contract update — 2026-08-04

Status remains **PARTIAL / G1b NOT APPROVED**. This section supersedes the
earlier witness-input blocker description: signed operator-ratified NAR-001,
NAR-002, ADR-SNV-001, and ADR-SNV-002 inputs were imported and used to define
the exact current boundary.

### DOM contract commits

- `5cae068` imports the ratified assignment and signature evidence;
- `2b91614` defines the ratified lifecycle, exact IDs, closed purpose and
  exposure registries, typed terminal states, and canonical permit binding;
- `18a4880` makes the permit an implementation-owned associated type so an
  application cannot fabricate or parse a production authorization; and
- `04b113467df9470fd880af9ce5f47b4e77f728b1` requires nonzero lifetime-unique
  session IDs across abort, consume, epoch rotation, restart, restore, and
  compaction.

The canonical contract requires three distinct durable authorizations for
nonce commitment, nonce reveal, and participant partial signature. The Wallet
owns the opaque permit implementation. `dom-adaptor` exposes only the immutable
binding required for conformance and does not provide a public permit parser or
constructor. The Wallet production branch implements exact spent-permit resend
without recomputation and preserves lifetime ID tombstones and budgets across
successor epochs.

### Current validation

```text
cargo test -p dom-adaptor --locked --offline
  PASS: 3 contract unit tests, 3 preimplementation probes, and doc tests
cargo fmt --all --check
  PASS
git diff --check
  PASS before the contract commit
```

The coordinator-path control scripts intentionally reject this independent
worktree: `preflight.sh` exited 4 because the path is not the coordinator clone,
and `verify-isolation.sh` and `phase1-gate.sh` each exited 1. Those exits are
recorded, not treated as gate success; the coordinator must execute the scripts
from its own branch after any conditional integration review.

The isolated Wallet branch independently reports 29 passing unit tests, one
compile-fail doctest, all-target/all-feature compilation and clippy, the exact
TLS witness endpoints, ratified lifecycle completion, and focused Linux crash
cuts. Those results do not constitute a published cross-repository conformance
integration and do not close the remaining gate items.

### Remaining gate blockers

- complete process-death and storage-fault injection at every durable cut
  point, rather than the executed focused Linux corruption cuts;
- Windows and macOS execution;
- measured and accepted numeric production budgets, retry limits, timeouts,
  and retention policy;
- residual witness timing and sequence privacy measurement;
- conformance against one published DOM revision without an absolute or local
  production path dependency;
- complete ordinary-Wallet runtime and frontend isolation evidence; and
- final combined G1a/G1b integration review, which is outside this branch.

No Phase 3-SM code, adaptor cryptography, consensus change, existing wire
change, persisted-block change, official-repository modification, DL2P import,
push, merge, release, publication, or production activation occurred.

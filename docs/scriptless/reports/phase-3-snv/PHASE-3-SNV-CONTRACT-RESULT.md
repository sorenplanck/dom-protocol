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

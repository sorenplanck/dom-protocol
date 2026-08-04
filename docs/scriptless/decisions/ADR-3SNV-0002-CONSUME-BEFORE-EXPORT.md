# ADR-3SNV-0002 — Consume before export

Status: **ACCEPTED** for the storage-independent G1b contract. G1b remains
**NOT APPROVED**.

## Context

The original contract allowed a caller to retrieve committed public bytes in
`ExposureAuthorized` and write the irreversible nonce tombstone afterward. A
process failure between those operations could leave externally visible
material backed by a locally live nonce.

## Evidence

- **MISSION DECISION:** nonce ciphertext and its irreversible tombstone must be
  durable before any outbound material is returned.
- **NORMATIVE DOCUMENT:** Master Specification sections 5.5, 6.6, 8, 10, 18,
  and Appendix F require consume-before-export, exact retry, and conservative
  burn on uncertainty.
- **CODE EVIDENCE:** `crates/dom-adaptor/src/nonce_vault.rs`.

## Decision

`authorize_exposure` only records a verified, durable witness receipt and moves
the reservation to `ExportAuthorized`. It does not return public material.

`consume` must atomically remove secret nonce material, write the irreversible
`Consumed` tombstone, retain the exact committed outbound bytes for retry, and
only then return a `ConsumedExposure`. `retry_public_material` is valid only
for the `Consumed` state. An error from either operation returns no exportable
bytes.

Abort before a public commitment produces `AbortedBeforePublicMaterial`. Abort
after a public commitment produces `ConsumedOnAbort`. Ambiguous restore can
produce `Burned`. None of these states permits export or refunds budget.

## Alternatives considered

- Export after authorization and consume later: rejected because a crash can
  create an exposed-but-live nonce.
- Delete public bytes at consumption: rejected because a network retry must
  resend byte-identical output without recomputation.
- Return nonce ciphertext with the permit: rejected because reusable secret
  material must not cross the application boundary.

## Consequences

Wallet implementations must persist both the terminal tombstone and exact
outbound bytes before returning. The API is intentionally incompatible with
the prior unsafe ordering and must be reconciled deliberately during Phase 1
integration.

## Compatibility

This changes only the new, unpublished `dom-adaptor` contract. It changes no
DOM consensus, existing wire encoding, transaction encoding, or persisted
block.

## Risks

The storage implementation still requires crash-cut evidence at every durable
boundary and a production signed witness before G1b can close.

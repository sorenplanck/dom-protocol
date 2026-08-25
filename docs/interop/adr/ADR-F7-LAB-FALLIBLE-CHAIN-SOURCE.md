# ADR-F7-LAB: Fallible Real-Chain Observation Boundary

- Status: **LAB CANDIDATE**
- Date: 2026-08-13
- Scope: DOM Interop F7

## Problem

`ChainSourceV1` originally returned an infallible `(records, cursor)` tuple.
That was adequate for the in-process `dom-sim`, but it cannot represent an
unavailable RPC service, an identity mismatch, malformed canonical evidence or
a response-size violation. Mapping any of those conditions to an empty scan
would be fail-open and could let policy advance against a false chain view.

## Context

F7 replaces `dom-sim` with an authenticated real DOM scanner. Network and disk
failures are normal operational states, while invalid evidence is a security
failure. The settlement engine already commits a cursor only with the durable
consequence of an accepted observation; the API also needs to ensure that a
failed observation returns no cursor at all.

## Decision

All `ChainSourceV1` operations that consult or derive chain position return
`Result<_, ChainSourceErrorV1>`. The closed error taxonomy distinguishes
unavailability, invalid evidence, a stale cursor, exceeded bounds and frozen
identity mismatch. `SettlementEngineError` preserves that error, and `open`,
recovery, scanning, finality policy and revalidation propagate it before any
cursor or economic transition is committed.

The simulated source returns `Ok` with its existing deterministic values. It
does not gain a mock error mode and remains explicitly ineligible for F7.

## Alternatives considered

- Return an empty page on transport errors. Rejected as fail-open.
- Cache a last successful tip and hide failures. Rejected because finality and
  timelock policy require a current authenticated view.
- Store an error inside the adapter and expose it through another method.
  Rejected because callers could forget to check it before using a cursor.
- Panic on malformed evidence. Rejected because adversarial RPC input is an
  expected error path, not a process invariant.

## Invariants

- Failure returns no new cursor and commits no economic transition.
- Identity mismatch and invalid evidence are never retried as empty success.
- A stale cursor is handled only through the explicit reorg/revalidation path.
- `t`, nonce material and signing shares never enter the chain-source error.
- The core still never decodes chain-specific evidence.

## Compatibility and security impact

This is a source-compatible change only after implementers update their return
types; the repository had exactly one implementation (`SimSettlementChain`) at
the time of the decision. The change is intentionally made before adding the
real DOM implementation so no production caller can accidentally inherit the
old infallible contract.

## Proof tests

- Existing F2/F6 scenario suites exercise the simulator through the fallible
  interface without changing economic behavior.
- The F7 real adapter suite injects unavailable RPC, malformed evidence,
  identity substitution, stale anchors and oversized responses and asserts that
  the durable cursor and settlement revision remain unchanged.

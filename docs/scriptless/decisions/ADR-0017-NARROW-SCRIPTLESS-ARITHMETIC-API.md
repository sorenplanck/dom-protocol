# ADR-0017 — Narrow authoritative Scriptless arithmetic API

Status: **ACCEPTED** for the implemented arithmetic boundary; this does not
approve G1a.

## Context

ADR-0009 forbids a production `k256` dependency in `dom-adaptor`, while adaptor
verification, adaptation, extraction, and two-nonce public binding require
operations that were private to `dom-crypto`.

## Evidence

- **AUTHORITATIVE DOM CODE:** `dom-crypto/src/schnorr.rs` owns point parsing,
  scalar parsing, DOM challenge construction, and Schnorr verification.
- **NORMATIVE DOCUMENT:** Master Specification sections 3 and 6 define the
  adaptor and two-nonce equations without authorizing a second backend.
- **FROZEN FIXTURE OR TEST:** the eight SCAD0 records fix the DOM adaptor sign
  convention and final kernel bytes.
- **ENGINEERING ADR:** ADR-0009 requires a narrow reviewed extension in
  `dom-crypto`; ADR-0014 requires the real DOM verifier.

## Decision

`dom-crypto::scriptless` owns a protocol-specific arithmetic boundary. It
exports only:

- an opaque canonical secret scalar with zeroization and no `Clone`, `Debug`,
  or generic serialization;
- adaptor pre-signature verification;
- adaptation and validated extraction;
- public two-nonce binding;
- bound-partial verification; and
- delegation to the unchanged DOM final verifier.

Generic scalar and point arithmetic remains private. `dom-adaptor` depends on
`dom-crypto` and has no direct production dependency on `k256`. No nonce
derivation function is exposed until the secret two-nonce KDF is frozen.

## Alternatives considered

- Direct `k256` use in `dom-adaptor`: rejected as a parallel production
  backend.
- Public generic curve arithmetic: rejected as broader than the required
  protocol boundary.
- Reusing `schnorr_aggregate_sigs` for all adaptor operations: rejected because
  it cannot verify the adaptor equation or validate extracted `t*G == T`.
- Accepting caller-provided nonce pairs in a production signing API: rejected
  until the KDF and vault lifecycle are frozen.

## Consequences

Adaptor operations reuse one parser, challenge, and verifier implementation.
The public-binding transcript can advance independently, but complete signing
remains blocked on nonce derivation and G1b lifecycle guarantees.

## Compatibility

The change is additive inside `dom-crypto`. It does not change consensus,
kernel wire bytes, existing Schnorr signatures, persisted blocks, or existing
serialization.

## Risks

The new boundary handles irreversible secret material and requires audit beyond
passing tests. Independent two-nonce and adaptor vectors remain mandatory. The
API must not be expanded into a generic arithmetic escape hatch.

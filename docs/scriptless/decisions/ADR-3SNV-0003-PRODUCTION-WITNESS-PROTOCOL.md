# ADR-3SNV-0003 — Production monotonic witness protocol

Status: **BLOCKED**. No production wire, client, or service is authorized.

## Context

G1b requires a portable remote monotonic witness, authenticated requests,
signed receipts, idempotent recovery, self-hosted deployment, and no local-file
fallback. A byte-exact protocol must be accepted before network code exists.

## Evidence

- **MISSION DECISION:** the protocol must freeze magic, version, message kinds,
  field order, limits, authentication inputs, receipt inputs, replay behavior,
  rotation, recovery, privacy fields, timeouts, and retention.
- **CODE INSPECTION:** Wallet V3 contains `minisign_verify` for update artifact
  verification, but no approved service-side signing/key-lifecycle boundary
  suitable for witness request authentication and receipt issuance.
- **CURRENT CONTRACT:** `WitnessClient` is semantic and the deterministic
  witness is compiled under `cfg(test)` only.

## Blocked inputs

The authoritative documents and accepted ADRs do not freeze all of:

- protocol magic, version, and request/receipt message kind bytes;
- authentication and receipt-signature byte preimages and domain tags;
- approved client and witness signing-key lifecycle;
- maximum message size and parser allocation limits;
- connection, response, and retry timeouts;
- receipt and equivocation-evidence retention;
- transport profile and key-rotation ceremony.

## Decision

No production witness bytes, authentication, client, server, or fallback are
implemented. The existing semantic interface remains the only production
boundary. The deterministic witness remains test-only and must never be wired
into a release feature.

## Alternatives considered

- Reuse updater Minisign verification: rejected because it does not provide an
  approved service signing/key-management boundary or the required mutual
  request/receipt protocol.
- Use DOM Schnorr with locally invented tags: rejected because that would
  invent protocol bytes and key policy.
- Use a local monotonic file: rejected because it is not independent of backup
  rollback and silent fallback is prohibited.

## Consequences

Production witness, signed receipts, self-hosted service, network fault tests,
and end-to-end authorization remain code blockers. G1b is not eligible for
integration.

## Compatibility

No production protocol exists, so this ADR changes no existing wire or remote
behavior.

## Risks

The local journal cannot detect a complete valid-prefix rollback without an
independent witness. Adaptor export must remain disabled in production until
the blocked protocol is accepted and implemented.

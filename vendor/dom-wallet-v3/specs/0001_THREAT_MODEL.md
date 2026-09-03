# DOM Wallet V3 Threat Model

**Status:** REVIEW
**Owner:** Soren Planck

## Purpose and scope

This specification defines the security properties that every DOM Wallet V3 component MUST preserve. It covers a wallet from secret creation through local persistence, chain observation, transaction intent, recovery, backup, and migration. It defines threats and required outcomes; it does not define a transaction lifecycle, key format, backup format, or network API. DOM consensus, cryptography, chain identity, wire formats, fee and weight rules, coinbase rules, maturity rules, transaction semantics, privacy model, and backup guarantees remain sovereign.

## Authoritative sources

The authoritative inputs are `specs/0000_DESIGN_PRINCIPLES.md`, `docs/REFERENCE_BASELINE.md`, `docs/ENGINEERING_SOURCES.md`, `docs/EPIC_DOM_ADOPTION_MATRIX.md`, `docs/CONFIRMED_DESIGN_INPUTS.md`, and `docs/SPECIFICATION_GATE.md`. DOM Wallet V1 and V2 are evidence for DOM-specific properties. The comparative-study reports named in the repository baseline provide protected-property and test-category evidence only. A non-DOM reference MUST NOT determine DOM protocol behavior.

## Terminology and assets

* **Wallet identity** is the versioned, chain-bound identity defined by Specification 0002.
* **Secret** includes seed material, password-derived key material, private transaction context, signing material, blinding factors, nonces, authenticated backup plaintext, and credentials with wallet authority.
* **Integrity-critical state** includes identity, chain ID, canonical cursor, derivation allocation evidence, outputs, reservations, transaction records, private contexts, recovery events, audit events, generations, and encrypted envelope metadata.
* **Availability-critical state** includes a recoverable durable generation, recovery plan, backup generation, indexes rebuildable from canonical records, and source progress.
* **Privacy assets** include ownership of outputs, account structure, balances, transaction links, derivation positions, addresses or receiving material, source queries, and audit metadata.
* **Canonical cursor** means exactly the chain-bound pair `(height, block_hash)` plus a declared verification status; height alone is not a cursor.
* **Local intent** is a durable, user-authorized action record. It is distinct from a chain observation and from an external delivery attempt.

## Trust boundaries and attacker classes

The trusted computing base is the approved DOM consensus and cryptographic implementation, the wallet domain logic, the authenticated storage backend, and the platform primitives on which they execute. Boundaries exist at unlock input, UI or caller authority, storage, backup media, chain source, transaction transport, operating-system services, dependency/build supply chain, and external time or randomness.

The design MUST resist: a remote unauthenticated caller; a caller with a narrower wallet capability; a malicious, stale, inconsistent, or unavailable chain source; a replaying transaction peer; a concurrent local process; a storage reader, corrupter, truncator, or rollback attacker; a thief of backup media; and a resource-exhaustion attacker. A local attacker with active process-memory access, a compromised approved dependency, or a compromised operating system can defeat some confidentiality properties; the wallet MUST still minimize exposure, fail closed where possible, and make the boundary explicit.

## Assumptions and out of scope

The wallet assumes DOM consensus validation and cryptographic primitives are correct for the selected chain ID; secure randomness and authenticated-encryption primitives are available; users protect unlock and backup passwords; and the platform can eventually provide durable storage. A chain source may be authenticated without being truthful, so source authentication is not evidence of canonical validity.

Physical coercion, a fully compromised endpoint while secrets are unlocked, undisclosed consensus defects, and availability against an attacker able to permanently deny all storage and network service are out of scope. They MUST NOT be described as solved by encryption, backups, or source authentication.

## Mandatory protected properties

1. Secrets MUST remain confidential in storage, backups, diagnostics, logs, redacted audit events, and external requests unless disclosure is explicitly required by a DOM transaction format.
2. The wallet MUST authenticate and validate all persisted secret-bearing envelopes before use. Malformed fields, including fixed-size encodings of wrong length, MUST return an error and MUST NOT panic.
3. Every durable state generation MUST be bound to the selected DOM chain ID. Cross-chain substitution MUST be rejected before records are merged, selected, signed, or displayed as spendable.
4. A derivation position, transaction nonce, blinding factor, reservation identity, or idempotency key MUST NOT be reused for a distinct logical purpose. Durable non-reuse evidence MUST survive restart, restore, and migration.
5. A spendable output MUST have one local control state and at most one active reservation. Concurrent selection MUST use the generation and reservation rules of Specification 0002 and the atomicity rules of Specification 0004.
6. A node response MUST NOT directly authorize spending, finalization, or cursor advancement. It can only contribute validated chain observation through Specification 0005.
7. Replay of a caller request, received transaction material, submit attempt, restore, or recovery plan MUST be idempotent or rejected without creating a second reservation, receive, context, or external side effect.
8. Corruption, truncation, stale indexes, and interrupted operations MUST cause validation and deterministic recovery before normal operation resumes. The wallet MUST NOT silently discard canonical-history evidence.
9. A backup theft MUST be treated as an offline password-guessing threat. DOM-approved password hardening, authenticated encryption, chain binding, and version checks MUST be retained or strengthened only through approved specifications.
10. Least privilege MUST separate unlock, spending, receiving, backup, administration, and observation capabilities. A component MUST receive only the records and secret material necessary for its operation.

## Threat treatment

| Threat | Required treatment |
|---|---|
| Malicious or stale node | Validate bounded responses; bind scans to a stable view; compare height and hash; reconcile or fail closed on missing, changed, or unverifiable hashes. |
| Storage rollback | Detect inconsistent generations where evidence exists; never reuse allocation evidence. Anti-rollback against a capable storage replayer is unresolved and MUST be surfaced at open. |
| Corruption or truncation | Authenticate envelope, validate framing and lengths before indexing, rebuild derived indexes, and retain the last valid generation or enter recovery. |
| Concurrent reservation | Atomically compare expected generation and install exactly one active reservation per output. |
| Replay | Require a durable idempotency key for all externally retriable intents and deduplicate against canonical record identity. |
| Migration | Validate source chain binding, version, semantic conversion, and allocation evidence in one transactional migration; reject ambiguous conversion. |
| Backup theft or substitution | Use authenticated, chain-bound, versioned encryption; do not merge a foreign-chain or unauthenticated snapshot. |
| Resource exhaustion | Cap response sizes, page counts, ancestor search, retries, context count, input count, and recovery work; preserve a resumable error state. |
| Supply-chain compromise | Pin and review approved dependencies, preserve reproducible validation, minimize secret-bearing dependencies, and require later assurance review. |
| Secret leakage | Redact audit events, errors, telemetry, and diagnostics; zeroize transient secret buffers where supported; prohibit secrets in examples and configuration defaults. |

## Valid and invalid behavior

Valid behavior authenticates authority, validates inputs before allocation or indexing, persists intent before an external effect, and returns a durable operation reference that can be retried safely. A source switch is valid only after it satisfies the same canonical-view rules as the prior source.

It is invalid to select an output from an unverified or foreign chain; advance a cursor separately from the state it summarizes; write a plaintext private context; accept an unsigned or malformed fixed-size field by slicing; expose secrets in an audit event; accept a replay as a new payment; or continue normal operation after unrecoverable generation validation failure. Invalid requests MUST leave no new reservation, derivation allocation, or external intent.

## Persistence, crash, and reorganization behavior

The only authoritative durable state is the canonical encrypted generation defined by Specification 0004. A crash means termination before a durable acknowledgement; restart means reopen, authenticate, validate, rebuild indexes, and resume or compensate a durable operation idempotently. A durable operation is either absent or complete from the perspective of the reopened generation; observable external effects are reconciled through their durable intent.

A reorganization is a chain-observation change, never a reason to erase local intent or non-reuse evidence. Removed chain facts MUST be reclassified with recovery evidence. A same-height hash change, lower observed height, missing hash, changed hash, or unverifiable hash MUST enter reconciliation rather than a freshness shortcut.

## Security considerations

No specification here authorizes weaker DOM cryptography, foreign transaction encodings, foreign economics, or foreign transports. Error messages SHOULD distinguish caller-correctable from recovery-required errors without revealing secret values or detailed ownership. Availability limits MUST fail closed into a resumable recovery state, not fabricate ancestry or declare a speculative balance final.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Capability denial, chain mismatch, malformed length rejection, redaction, reservation conflict, and invalid transition non-mutation. |
| Property tests | No duplicate active reservation; no allocation reuse across arbitrary retries and reopen; valid-state serialization round trip; derived balances never include non-spendable output. |
| Integration tests | Authenticated and unauthenticated sources, source switching, backup import, restore, restart, and caller capability separation. |
| Fault-injection tests | Crash before and after every durable acknowledgement, storage truncation, stale index, failed external submission, and rollbacked storage generation. |
| Fuzz targets | Encrypted-envelope framing, backup framing, persisted records, source pages, transaction-context input, and audit-event decoding; no panic or secret disclosure. |

## Acceptance criteria for REVIEW

This document may move to REVIEW when Specifications 0002, 0004, 0005, and 0006 trace each mandatory property to an invariant and test class; the unresolved items below have owners and gates; and an assurance review confirms no requirement substitutes a non-DOM protocol rule.

## Dependencies and unresolved decisions

This specification depends on 0000 and contracts from 0002 through 0006. Specification 0003 will own final transaction lifecycle states, while it MUST preserve this specification's idempotency, non-reuse, and durable-intent properties. Specifications 0007 through 0012 will own final secret, backup, economics, interface, migration, and assurance details.

* **Anti-rollback mechanism:** affects detection of a valid but older authenticated generation. Evidence required: platform threat analysis and a DOM-compatible durable monotonicity design. Gate: 0012 assurance acceptance.
* **Capability credential form and revocation:** affects least privilege at UI and transport boundaries. Evidence required: API threat analysis and DOM wire constraints. Gate: 0010 acceptance.
* **Secret zeroization guarantees by platform:** affects residual-memory exposure. Evidence required: supported-platform audit. Gate: 0007 acceptance.

## Review Blockers

* DEC-ROLLBACK-PROTECTION
* DEC-API-DEPLOYMENT

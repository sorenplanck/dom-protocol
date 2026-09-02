# DOM Wallet V3 Transaction Lifecycle

**Status:** DRAFT
**Owner:** Soren Planck

## Purpose and scope

This specification defines the DOM-native lifecycle of a logical payment. It governs intent, reservation, participant exchange, finalization, submission, observation, cancellation, expiry, failure, restart, and reorganization classification. DOM consensus and the authoritative DOM transaction and slate formats govern transaction validity and wire content; this document does not replace them.

## Authoritative sources and terminology

Authoritative inputs are Specifications 0000 through 0006, DOM Wallet V1/V2 behavior, DOM consensus, DOM transaction validation, and the DOM slate implementation. Specification 0002 owns canonical records and spendability; 0004 owns durable units of work; 0005 owns ChainSource evidence; 0006 owns ReorgPlan execution; 0007 owns secret handling; and 0009 owns economic policy.

**TransactionId** is the stable identifier of one TransactionRecord. **TransactionIntentId** is the stable identifier of one user-authorized LocalIntent and MUST NOT be reused for another purpose. **ReservationId** identifies one Reservation. **ParticipantId** identifies an opaque participant binding permitted by the DOM format. **ReplayId** is a phase-scoped opaque idempotency identifier. **DurableIntent** records an acknowledged external-effect request. **ExposureRecord** records that participant material or transaction bytes may have left the wallet. **UncertaintyState** records whether an external effect is absent, known, or requires reconciliation.

WalletId is an alias for the immutable WalletIdentity identifier of 0002 and MUST NOT identify a separate object. AccountId, Generation, ChainId, BlockHeight, BlockHash, CanonicalCursor, StableView, OutputRecord, PrivateTransactionContext, RecoveryEvent, and AuditEvent have the meanings in 0002 through 0006.

## Protected properties, boundaries, and assumptions

The lifecycle service may request transitions; the domain validates them; storage commits one durable unit of work; ChainSource supplies observations without changing local control; the secret service releases only operation-scoped private material; and a transport adapter delivers opaque DOM-native messages without interpreting confirmation. A caller, participant, node, storage backend, and ChainSource are separate trust boundaries.

The wallet assumes the selected DOM format can be validated by authoritative DOM code and that a transport can report delivery uncertainty. It MUST NOT assume delivery, a node acknowledgement, or mempool presence proves canonical inclusion.

## State and data model

Each TransactionRecord links exactly one TransactionId, TransactionIntentId, chain-bound LocalIntent, optional DOM transaction reference, participant bindings, ReservationIds, context identifier, exposure records, DurableIntent, observations, recovery events, and redacted audit events. PrivateTransactionContext is encrypted canonical state owned by the transaction; it MUST NOT be a plaintext or external sidecar.

The lifecycle projection is: Created, Prepared, ParticipantExchange, Finalized, SubmissionIntended, SubmissionUncertain, MempoolObserved, CanonicallyConfirmed, Cancelled, Expired, Failed, or RecoveryRequired. This projection is distinct from OutputRecord chain observation, maturity, and local control. A reorganization may reclassify chain-derived projection evidence but MUST NOT delete LocalIntent, allocation, exposure, context-disposal, or non-reuse evidence.

## Invariants

1. One TransactionIntentId creates at most one TransactionRecord; a retry returns that record or its recorded outcome.
2. Preparation atomically records LocalIntent, idempotency key, reservations, allocations, permitted change OutputRecords, TransactionRecord, encrypted context, recovery event, and audit event.
3. Each active output has one Reservation, and selection uses the complete 0002 spendable predicate and 0009 policy.
4. Participant exposure follows a durable preparation record. Node submission follows a durable submission intent containing immutable exact canonical transaction bytes.
5. Finalized bytes and their content hash are immutable. Every retry and repost uses exactly those bytes.
6. A ReplayId maps to one canonical request fingerprint and result. The same identifier with different authenticated content is rejected without mutation.
7. Canonical confirmation is created only by the synchronization unit of work that commits matching observations and CanonicalCursor.

## Valid behavior and transition contract

| Action | Preconditions | Durable postconditions |
|---|---|---|
| Send or self-transfer preparation | Spending authority, active ChainId, expected Generation, unique TransactionIntentId, spendable inputs, and valid 0009 policy | Prepared record and all preparation records in one durable unit |
| Receive | Receiving authority, active ChainId, valid DOM-native input, unused ReplayId or identical replay | Replay-stable receive result, context and any local output evidence in one durable unit |
| Participant exchange | Prepared record and durable ExposureRecord before external delivery | Exchange transcript reference or typed recovery state |
| Finalization | Valid context, authorized participant material, current Generation, and renewed 0009 validation | Finalized immutable bytes, content hash, context disposition, input local control set to locally_finalized_spend(TransactionId), and audit record |
| Submission | Finalized bytes, node-adapter authority, and no incompatible DurableIntent | SubmissionIntended DurableIntent before adapter invocation |
| Mempool observation | Bounded node evidence associated with exact bytes or DOM reference | Non-canonical observation only |
| Confirmation | Valid 0005 evidence and cursor in a synchronization unit | Canonical observations and CanonicallyConfirmed projection |
| Repost | Existing immutable bytes and unresolved durable submission | Same DurableIntent identity and exact-byte adapter call |
| Cancellation or expiry | Expected Generation and a state that has not reached canonical confirmation | Terminal projection, retained evidence, and only permitted reservation release |

Preparation MUST validate expected Generation, capability, ChainId, intent fingerprint, input uniqueness, spendability, input and change cardinality, and all 0009 selection results before allocating or reserving. Receive MUST bind the request to ChainId and WalletIdentity before accepting participant material. A self-transfer MUST run both send and receive contracts without creating a second logical intent.

Finalization MUST revalidate context integrity, participant material, reservation ownership, Generation, and economics. In the finalization DUW, every selected input MUST retain its reservation evidence and change local control to locally_finalized_spend(TransactionId); this is not chain-spent evidence. Submission MUST call the adapter with the exact durable bytes; a duplicate node submission is an admissible uncertain external effect, not a second transaction. Node outcomes are Accepted, DuplicateOrAlreadyKnown, Rejected, TemporarilyUnavailable, TimeoutOrUnknown, or MalformedResponse. A later MempoolObserved or canonical observation is admissible only through validated ChainSource evidence matching immutable bytes or the DOM reference, regardless of an earlier adapter result; none of these outcomes alone proves confirmation.

## Invalid behavior

The wallet MUST reject without mutation: an expired or foreign-chain request; a changed request using an existing idempotency key or ReplayId; an unavailable, immature, reserved, provisional, or non-spendable output; a zero or otherwise disallowed change cardinality; finalization without a valid context; changed bytes under an existing DurableIntent; a transition with an unexpected Generation; and use of a nonce, blinding, allocation, reservation, participant binding, or replay identifier for a distinct purpose.

It MUST NOT expose participant material before preparation is durable, infer confirmation from transport or mempool evidence, release evidence after exposure, cancel a canonically confirmed record, or erase a transaction because a reorganization removed its chain observation.

## Persistence and atomicity

Every transition uses the 0004 durable unit of work with expected Generation and one resulting Generation. Durable acknowledgement is the only authority that a local transition occurred. Preparation, receive, finalization, submission intent, node-result recording, confirmation, cancellation, expiry, failure, and reclassification MUST include their affected canonical records, RecoveryEvent, and redacted AuditEvent in that unit.

Cancellation before exposure MAY release its reservations atomically. Cancellation after exposure, finalization, or submission MUST retain allocations, exact bytes, context disposition, exposure records, and non-reuse evidence; it MAY enter RecoveryRequired instead of releasing inputs. Retention duration and secure deletion eligibility are policy records and MUST preserve evidence until the associated recovery and replay obligations have ended.

## Crash and restart behavior

A crash before durable acknowledgement leaves the old generation authoritative. A crash after durable preparation and before exposure permits retry with the original identifiers. A crash after external exposure and before its result is recorded enters SubmissionUncertain or RecoveryRequired on restart. A crash after DurableIntent acknowledgement and before node response is resolved by query, synchronization, or exact-byte retry using the same DurableIntent.

On restart the wallet validates references, chain binding, context authentication, reservation uniqueness, content hashes, and non-reuse evidence. It MUST then resume the recorded recovery action or fail closed; it MUST NOT generate replacement transaction bytes or replacement secret material.

## Reorganization behavior

When 0006 applies a ReorgPlan, lifecycle reclassification uses the plan's expected Generation and retained TransactionId. A removed confirmation becomes an unresolved chain observation and may return to MempoolObserved, SubmissionUncertain, or RecoveryRequired only with recorded evidence. A re-mined transaction returns to CanonicallyConfirmed through synchronization. Rollback plus replay MUST equal FreshReconciliation for the same StableView and LocalIntent.

DOM-W2-SYNC-001 applies before confirmation and before selection or repost after a chain check: a missing, changed, unverifiable, same-height divergent, or lower BlockHeight cursor requires reconciliation. A height alone MUST NOT permit a freshness shortcut.

## Concurrency, replay, and idempotency

One writer with the matching expected Generation advances a transaction. A losing concurrent caller receives a conflict and MUST re-read state; it MUST NOT allocate another position or reservation. Caller idempotency keys are scoped to WalletIdentity, capability, operation class, TransactionIntentId, and authenticated request fingerprint. Receive responses are replay-stable: an identical replay returns the recorded response; a mismatched replay fails closed.

Reordered, duplicated, delayed, or absent transport messages are handled as evidence of uncertainty. The transport adapter MUST NOT mutate lifecycle state directly.

## Security, compatibility, and migration impact

Private contexts, participant material, exact bytes where sensitive, and identifiers that reveal linkability MUST be encrypted or redacted according to 0001 and 0007. Diagnostics MUST expose only correlation-safe references. DOM Wallet V2 data is admitted only by 0011 staging. No Epic lifecycle labels, slates, transaction bytes, repost policy, routes, or transports are compatible inputs.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Every legal and forbidden transition, expected-generation conflict, result taxonomy, cancellation restriction, exact-byte equality, and replay mismatch |
| Property tests | Reservation and non-reuse uniqueness, no partial preparation, idempotent receive, and retry identity preservation |
| Executable-model tests | Generated commands for send, receive, self-transfer, exposure, finalize, submit, cancel, expire, crash, and reorg |
| Integration tests | DOM-native participant exchange, duplicate submission, mempool observation, confirmation, and repost through a transport harness |
| Restart tests | Every acknowledgement and external-exposure boundary, including uncertain submission resolution |
| Reorganization tests | Same-height, lower-height, removed/re-mined spend, cursor divergence, reservation retention, and rollback-plus-replay equivalence |
| Concurrency tests | Competing preparation, finalization, cancellation, and receive replay |
| Fault-injection tests | Storage, context, adapter, acknowledgement, timeout, and node-result failures before and after durable intent |
| Fuzz targets | Participant messages, identifiers, contexts, result envelopes, and malformed DOM-format boundary inputs without panic or leakage |

## Acceptance criteria for promotion from DRAFT to REVIEW

Promotion requires a reviewed DOM participant-wire and expiry contract, a transition-to-durable-unit map, exact-byte and replay test oracles, complete 0009 policy inputs, and traceability from every invariant to executable evidence. A compilation result, a test count, or a successful happy path is insufficient.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0004, 0005, 0006, 0007, 0009, and 0012.

The authoritative DOM participant-wire version, expiry semantics, post-exposure cancellation policy, payment-proof or invoice semantics, and durable retention periods are unresolved. Each requires DOM format, consensus, or approved product-policy evidence before implementation; no foreign behavior selects an answer.

## Review Blockers

* DEC-LIFECYCLE-PARTICIPANT-WIRE
* DEC-RESERVATION-LIFETIME

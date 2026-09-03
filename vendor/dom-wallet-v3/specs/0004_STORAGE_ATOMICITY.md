# DOM Wallet V3 Storage and Atomicity

**Status:** REVIEW
**Owner:** Soren Planck

## Purpose and scope

This specification defines backend-independent atomic persistence for canonical wallet state. It protects one logical wallet action from partial durability, concurrent writers, corruption, and restart. It defines no database product, file layout, transaction wire format, migration implementation, or external API. DOM-approved encrypted-envelope and chain-binding properties MUST be preserved.

## Authoritative sources and terminology

Sources are 0000 through 0002, the repository design evidence, and DOM Wallet V1/V2 validated encrypted storage and backup behavior. The comparative study establishes the protected property that reservations, transaction records, private context, and canonical transaction bytes cannot be split between a database commit and a non-atomic external file.

A **durable unit of work (DUW)** is one all-or-nothing change from generation `g` to `g + 1`. An **expected generation** is the generation the caller observed. A **durability acknowledgement** is returned only after the new authenticated generation and recovery metadata meet the backend's declared durable-write contract. A **durable intent** is a committed idempotent record describing an external side effect before it is attempted. A **crash point** is any point before or after a durable acknowledgement, including process termination, power loss, backend error, or completion uncertainty.

## Protected properties and boundaries

The storage adapter owns bytes, atomic replacement or equivalent commit, durability acknowledgement, and reopen validation. The wallet domain owns transition validation and contents of a DUW. No adapter, UI, transport, or chain source may independently mutate canonical records. Secret-bearing canonical state, private contexts, and backup plaintext MUST cross only the encrypted boundary defined by 0007 and 0008.

Every DUW MUST:

1. require an expected generation and fail with a conflict if it differs from the current generation;
2. validate the full resulting state and canonical serialization before publication;
3. authenticate magic, model version, wallet identity, and DOM chain ID before records are used; the V3 authenticated-context encoding is controlled by DEC-CRYPTO-ENVELOPE-BINDING and MUST NOT be inferred from the current V2 envelope;
4. include all canonical records, indexes needed for recovery, recovery events, and audit event for the logical action;
5. write authenticated bytes through one atomic publication protocol and acknowledge only after its required synchronization point;
6. leave either the old valid generation or the complete new valid generation after a crash; and
7. never create plaintext or non-atomic transaction sidecars, private-context files, or external transaction references whose required bytes are not in the DUW.

## Required units of work

| Operation | Atomic contents |
|---|---|
| Send preparation | Validated local intent, idempotency key, input reservations, derivation allocations, change/output records, transaction record, encrypted private context, recovery event, and audit event. |
| Receive | Replay check, received record/output observation, allocation evidence, transaction linkage, encrypted context if required, and audit event. |
| Finalize | Finalized DOM-native canonical transaction bytes or reference inside canonical state, context transition, allocations, retained reservation evidence, selected-input local-control transition to locally_finalized_spend(TransactionId), recovery event, and audit event. |
| Submit intent | Durable intent, idempotency key, canonical transaction reference, attempt state, and audit event before transport invocation. |
| Confirmation | Validated chain observation, output and transaction reclassification, maturity input, cursor, recovery completion, and audit event. |
| Cancellation | Authorized lifecycle update, reservation release or retention evidence, context disposition, recovery event, and audit event. |
| Synchronization | Stable-view evidence, all observation changes, maturity recalculation, cursor, recovery event, and audit event. |
| Reorg rollback | Durable plan phase, rewound observations, reclassified records, cursor, replay checkpoint, recovery event, and audit event. |
| Backup | Read one validated generation and write a chain-bound encrypted snapshot identified by that exact generation; backup metadata is committed only as defined by 0008. |
| Restore | Validated source identity/version/chain, merge plan, all merged records and allocation evidence, recovery event, and audit event. |
| Migration | Source validation, converted complete state, migration marker, old-to-new mapping, recovery event, and audit event in one publish-or-recover protocol. |

## Canonical serialization and concurrency

Canonical serialization MUST have a deterministic schema version, field ordering, integer representation, identifier representation, and exact-length rules. It MUST reject duplicate map keys, unsupported critical fields, non-canonical encodings, trailing ambiguity, and invalid references before state use. Content hashes MAY assist integrity checks but MUST NOT replace authenticated encryption or chain binding.

Only one writer may commit a generation. Implementations MAY use a process lock, backend transaction, compare-and-swap, or equivalent mechanism, but correctness MUST depend on expected-generation detection, not a best-effort lock alone. A conflict MUST return the current generation or a safe retry signal without performing the requested allocation, reservation, or intent. Readers MUST observe either a validated old generation or validated new generation.

## Durable intent and external effects

Network delivery, submission, notification, file export, and any external side effect have uncertain completion after a crash. The wallet MUST first commit a DUW containing a stable idempotency key, required canonical bytes, intended destination class, and recovery action. It MAY then attempt the effect. The result is committed in a later DUW. On restart, the wallet MUST retry, query, reconcile, or present a controlled recovery action using that same intent; it MUST NOT create a second logical transaction merely because completion is unknown.

## Crash and restart matrix

| Crash point | Required reopened behavior |
|---|---|
| Before validation or expected-generation check | No state change. |
| After validation, before authenticated bytes are durable | Old generation remains authoritative; no external effect may have been attempted. |
| After bytes staged, before atomic publication | Choose last complete authenticated generation; remove or ignore incomplete staging. |
| After publication, before durability acknowledgement | Reopen validates either complete generation; caller treats result as unknown and reconciles idempotently. |
| After acknowledgement, before external effect | New durable intent exists; restart resumes the intent. |
| During or after external effect, before result commit | Intent is authoritative; retry/query/reconcile without duplicating it. |
| During backup, restore, or migration | Source and destination generation markers select complete state or resumable recovery; no partial state becomes normal operation. |
| During sync or rollback | Recovery event and cursor/plan phase identify a deterministic replay point; normal selection remains blocked until completion. |

## Reopen validation, corruption, and recovery

Open MUST authenticate envelope data before parsing secret-bearing fields, check fixed lengths before indexing, validate generation and all 0002 invariants, verify chain ID, and detect truncation or framing errors. It MUST rebuild stale derived indexes exclusively from canonical records. A corrupted newest generation MAY fall back only to a separately validated prior generation if the backend has an authenticated recovery protocol; otherwise the wallet MUST enter a recovery-required state. It MUST NOT silently initialize an empty wallet over existing invalid state.

Storage rollback by an attacker who can replay an older valid authenticated generation is not proven prevented by this specification. The implementation MUST expose detection capability and generation evidence. A final anti-rollback mechanism is unresolved; until accepted, restore, migration, and normal open MUST preserve allocation non-reuse evidence and warn or fail according to the later approved policy.

## Valid, invalid, and reorganization behavior

Valid behavior combines every affected canonical record into one DUW and returns only after the durability contract. It is invalid to split a send's reservation and private context, advance a cursor without its output changes, publish transaction bytes outside canonical storage, acknowledge before required synchronization, accept an old expected generation, or write plaintext secrets.

Reorganization work uses the same DUW protocol: a plan phase and its resulting reclassification/cursor checkpoint commit together. Restart uses the durable plan and is idempotent. The backend MUST NOT choose ancestry, interpret consensus rules, or drop local intent.

## Security considerations

Authenticated encryption is not a substitute for atomicity, and atomicity is not a substitute for backup. Backup snapshots MUST represent exactly one validated generation. Resource limits MUST cap staging, recovery journals, migration input, index rebuild work, and retained failed intents. Errors and audit records MUST be redacted.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Expected-generation conflicts, DUW validation, canonical encoding rejection, idempotency lookup, and no sidecar creation. |
| Property tests | Arbitrary valid DUWs preserve 0002 invariants; reopen yields old-or-new state only; repeated recovery converges; indexes rebuild identically. |
| Integration tests | Two writers, encrypted reopen, send/receive/finalize/submit/confirm/cancel, backup/restore/migration, sync, and reorg across supported adapters. |
| Fault-injection tests | Every crash matrix row, failed sync/rename/commit, torn and truncated writes, post-submit uncertainty, corruption, stale index, and migration interruption. |
| Fuzz targets | Envelope framing, canonical serialization, migration/backup headers, recovery-event records, and truncated staged generations; no panic. |

## Acceptance criteria for REVIEW

Move to REVIEW only when a backend-neutral DUW test harness can demonstrate every matrix row; 0002 transition mapping is complete; 0005/0006 cursor and reorg changes use one DUW; and 0007/0008 approve encryption and backup boundaries.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0005, and 0006; 0003 supplies lifecycle transition contracts. Later 0007, 0008, 0011, and 0012 supply final secret, backup, migration, and assurance decisions.

* **Anti-rollback primitive:** affects valid authenticated old-generation replay. Evidence required: supported-storage and platform design review. Gate: 0012 acceptance.
* **Backend durability profile:** affects the precise synchronization primitive behind acknowledgement. Evidence required: adapter design and fault model. Gate: implementation-design review after this specification.
* **Migration retention period for source bytes:** affects recoverability and privacy. Evidence required: 0011 migration plan. Gate: 0011 review.

## Review Blockers

* DEC-CRYPTO-ENVELOPE-BINDING
* DEC-ROLLBACK-PROTECTION

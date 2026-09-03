# DOM Wallet V3 Canonical Wallet State Model

**Status:** REVIEW
**Owner:** Soren Planck

## Purpose and scope

This specification defines the one canonical, versioned wallet state model and its state ownership. It prevents contradictory loose flags by separating chain observation, maturity, and local control. It does not decide final transaction lifecycle names owned by Specification 0003, secret derivation owned by 0007, backup format owned by 0008, or DOM economics owned by 0009.

## Authoritative sources

The sources are 0000, 0001, the repository design inputs and gate, and DOM Wallet V1/V2 behavior. DOM consensus is authoritative for transaction, coinbase, maturity, fee, weight, proof, and chain rules. Comparative-study material supplies only protected properties and test categories.

## Canonical model and terminology

The canonical state is an encrypted, canonical serialization containing a `model_version`, `generation`, and `wallet_identity` bound to one DOM `chain_id`. It contains these records:

| Record | Required contents and identity |
|---|---|
| Wallet identity | immutable wallet UUID, chain ID, creation generation, model version, and declared recovery capability; identity never changes in place. |
| Account | account UUID, stable account label or opaque reference, account policy reference, and creation/tombstone metadata. |
| Derivation position | `(account_id, derivation_domain, position)` with allocation status, allocation generation, purpose reference, and non-reuse evidence. |
| Output | output UUID, commitment or DOM-native output reference, account ID, value, origin, derivation reference where applicable, immutable discovery evidence, chain observation, maturity observation, local control, and retention metadata. |
| Reservation | reservation UUID, output UUID, transaction reference, intent key, expected generation, creation generation, expiry policy reference, and active or released terminal evidence. |
| Transaction record | transaction UUID, DOM transaction reference when available, local intent reference, participant or counterparty references only as permitted, chain observation, lifecycle contract reference, and recovery linkage. |
| Private transaction context | context UUID, transaction UUID, encrypted opaque DOM-native private bytes, version, purpose, allocation references, checksum, and disposal evidence. |
| Canonical cursor | verified `(height, block_hash)`, stable-view binding, source-independent validation evidence, and generation. |
| Recovery event | event UUID, operation reference, phase, deterministic idempotency key, observed failure class, required next action, and completion evidence. |
| Redacted audit event | event UUID, generation, actor capability class, operation reference, outcome, and redacted metadata only. |

`generation` is a strictly increasing durable state generation, not a chain height. A record reference is stable across reclassification; it MUST NOT be replaced merely because an observation changes.

### Orthogonal output dimensions

An output has exactly one value in each dimension:

* **Chain observation:** `unobserved_local`, `observed_unconfirmed`, `canonical_unspent`, `canonical_spent`, or `removed_from_canonical`.
* **Maturity observation:** `not_applicable`, `immature(required_height)`, or `mature`. The required height MUST be computed only from DOM consensus rules and observed canonical origin.
* **Local control:** `uncontrolled`, `available`, `reserved(reservation_id)`, `locally_finalized_spend(transaction_id)`, or `retired`.

These dimensions are facts of different kinds. A local reservation does not make an output chain-spent. A mature output does not imply local ownership or availability. A removed receive remains retained evidence and is not silently deleted.

## Protected properties and boundaries

State ownership belongs to the wallet domain. Storage may atomically persist and reopen records but MUST NOT infer a transition. Chain source may provide observations but MUST NOT change local control. A lifecycle component may request a transition under Specification 0003 but MUST pass expected generation and authority. A secret component may access private context only through its capability boundary.

Global invariants are:

1. `wallet_identity.chain_id` equals the chain ID in every chain-bound record and envelope.
2. One generation serializes one internally consistent state; generation increases exactly once per committed unit of work.
3. Every active reservation references one existing output and transaction record, and no output has more than one active reservation.
4. Every allocated derivation position has one durable purpose or explicit burned/tombstone reason; allocation is never reused.
5. Every private context references exactly one transaction record and is either present with authenticated bytes or has durable disposal evidence; it is never represented by a plaintext sidecar.
6. A cursor is absent only before first successful reconciliation. When present it includes height and block hash and represents the same committed chain observations.
7. Canonical outputs, spends, removed observations, transaction references, allocation evidence, and recovery events are retained. Tombstones preserve identity, reason, and generation; they do not erase non-reuse evidence.
8. Derived indexes and balances are not authoritative and MUST be reproducible from canonical records.

## Derived predicates and behavior

An output is **spendable** iff it is bound to the active chain ID, has chain observation `canonical_unspent`, has maturity `mature`, local control `available`, no active reservation, and satisfies all DOM selection and economic predicates. The predicate MUST NOT be replaced by a single mutable status flag.

Available, reserved, pending, immature, confirmed, spent, removed, and total balance views are derived projections with explicit inclusion predicates. A UI MAY show a provisional view during reconciliation, but MUST label it provisional and MUST NOT authorize selection from it. A balance MUST NOT double count a received and removed observation, or treat a locally finalized spend as chain-spent without observation.

A valid transition is authorized by its owner, validated against the expected generation, and committed with all affected records. Invalid behavior includes allocating before input validation, overwriting a context, attaching an output to a different chain ID, releasing another transaction's reservation, changing an immutable identity, or mutating a derived index as if it were canonical. Invalid transitions MUST not advance generation.

## Persistence, crash, restart, and reorganization

Canonical records use a deterministic schema and canonical field ordering. IDs are explicitly typed; byte fields and fixed-size fields have exact-length validation; unknown critical schema elements and unsupported versions MUST be rejected. Canonical secret-bearing state is encrypted under the boundaries of 0004 and 0007. A generation becomes visible only on the durable acknowledgement defined by 0004.

On restart, the wallet MUST validate identity, chain binding, generation, references, reservation uniqueness, allocation evidence, private-context integrity, and cursor consistency before exposing spendability. It MUST rebuild stale derived indexes and resume recovery events idempotently. Failure to validate MUST enter recovery rather than discard records.

On reorganization, chain observation and maturity are recalculated from the durable reorg plan of 0006 while local intent, reservations, allocation evidence, contexts, transaction references, and audit evidence remain retained. A reservation whose intended transaction loses a canonical observation remains a local-control fact until 0003's lifecycle contract releases, expires, or reuses it through a new authorized operation. Reconciliation is correct only if rollback plus replay produces the same canonical records and derived balances as deterministic fresh reconciliation of the same canonical chain and same local intent.

## Security considerations

The model prohibits state ambiguity that could lead to local double selection, accidental reuse, cross-chain display, or loss of recovery evidence. Redacted audit events MUST exclude secret bytes, password data, full private contexts, and unnecessary counterparty data. Retention MAY increase local metadata exposure; therefore retained records remain encrypted and redaction is mandatory.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Each legal and illegal dimension transition, chain mismatch, maturity recalculation, reservation uniqueness, tombstone retention, and no mutation on rejected transition. |
| Property tests | Generated transition sequences preserve all global invariants; no allocation or reservation reuse; serialize-deserialize equivalence; balance projections equal their predicates. |
| Integration tests | Concurrent operations with expected-generation conflicts, restart from committed generations, source reconciliation, restore merge, and transaction-context recovery. |
| Fault-injection tests | Termination before or after each affected record is acknowledged, index loss, context corruption, and reorg interruption. |
| Fuzz targets | State decoder, version dispatcher, record references, fixed-size fields, and invalid transition requests; no panic and no acceptance of contradictory dimensions. |

## Acceptance criteria for REVIEW

Move to REVIEW only when 0003 defines lifecycle states compatible with the record contract; 0004 proves each transition has one durable unit; 0005 and 0006 prove cursor and rollback semantics; and tests trace every invariant to at least one unit or property test and one relevant integration or fault test.

## Dependencies and unresolved decisions

Dependencies are 0000, 0001, 0004, 0005, and 0006. This document provides the required state contract to 0003 and later specifications.

* **Account policy fields and deletion policy:** affect retention and authorization. Evidence required: approved account and API requirements. Gate: 0010 review.
* **Reservation expiry semantics:** affect liveness and user-visible recovery. Evidence required: lifecycle and DOM transaction-expiry analysis. Gate: 0003 review.
* **Exact canonical serialization encoding:** affects interoperability and corruption handling. Evidence required: storage and migration design with DOM cryptographic review. Gate: 0004 review.

## Review Blockers

* DEC-CANONICAL-SERIALIZATION
* DEC-RESERVATION-LIFETIME

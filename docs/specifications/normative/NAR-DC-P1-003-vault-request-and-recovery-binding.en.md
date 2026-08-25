# NAR-DC-P1-003 — Nonce Vault Request, Export, and Recovery Binding

Status: **PROPOSED / UNSIGNED / NOT NORMATIVE**  
Project: **DOM Contracts**  
Date: **2026-08-05**  
Scope: **Phase 1B minimum Nonce Vault and its public DOM adaptor boundary**

> This document has no normative effect until the operator reviews and signs
> these exact bytes with the established Minisign identity. Implementations
> must remain fail-closed wherever this record supplies a missing decision.

## 1. Purpose

NAR-DC-P1-001 and NAR-DC-P1-002 freeze storage encryption, canonical lifecycle
records, journal ordering, restore projection, and capability-rooted I/O. The
published `dom-adaptor` revision also freezes `NonceVaultV1`. A source-level
cross-repository review found six bindings that are required to implement that
trait without inventing semantics:

1. derivation of `NonceIdentityV1.bound_digest` from a reservation request;
2. durable retention of reservation, key-budget, counterparty, and idempotency
   identifiers that do not fit any existing canonical record;
3. separation of the adaptor outbound digest from the Contracts exposure
   digest;
4. use of a live export capability without fabricating a witness receipt;
5. stable lookup for byte-identical resend; and
6. high-level abort, restore-state, and resend access through the vault-backed
   signer.

This record assigns only those missing bindings. It does not authorize a
witness, watchtower, transport, Phase 2, real funds, mainnet, production,
consensus changes, existing DOM wire changes, publication of `dom-contracts`,
or a numerical budget policy.

## 2. Authority

After ratification, the order for this scope is:

1. P1-ARCH-002;
2. this record;
3. NAR-DC-P1-002;
4. NAR-DC-P1-001;
5. the published `dom-adaptor` API;
6. the Master Specification where not superseded.

All integers are fixed-width little-endian. All hashes use only the pinned
`dom_crypto::blake2b_256_tagged` implementation:

```text
H_tag(tag, data) =
  DOM_BLAKE2b_256(u16_le(len(ASCII(tag))) || ASCII(tag) || data)
```

## 3. ReservationAuthorityV1

### 3.1 Registered tags

The following exact case-sensitive ASCII tags are registered:

```text
DOM:contracts-vault-reservation-binding:v1
DOM:contracts-vault-reservation-authority:v1
DOM:contracts-vault-export-permit-id:v1
```

No alias, fallback, alternate version, generic BLAKE2 construction, SHA-256
tag construction, or caller-selected tag is permitted.

### 3.2 Canonical record

`ReservationAuthorityV1` is exactly 347 bytes:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `DOMNVRA1` |
| 8 | 2 | version | `1` |
| 10 | 32 | reservation_id | exact `ReservationNonceId`, nonzero |
| 42 | 32 | key_id | exact `VaultKeyId`, nonzero |
| 74 | 32 | session_id | exact `SessionId`, nonzero and lifetime-unique |
| 106 | 32 | counterparty_bucket | exact `CounterpartyBucket`, nonzero |
| 138 | 1 | purpose | exact canonical `PurposeV1` byte |
| 139 | 32 | participant_id | exact `ParticipantId`, nonzero |
| 171 | 32 | template_hash | exact `TemplateHash`, nonzero |
| 203 | 32 | request_id | exact `IdempotencyKey`, nonzero |
| 235 | 8 | nonce_epoch | nonzero |
| 243 | 32 | budget_policy_digest | nonzero digest of the externally ratified policy |
| 275 | 32 | bound_digest | definition below |
| 307 | 8 | authority_revision | exactly `1` in V1 |
| 315 | 32 | authority_digest | definition below |

`bound_digest` is exactly:

```text
H_tag(
  "DOM:contracts-vault-reservation-binding:v1",
  reservation_authority_bytes[10..275]
)
```

`authority_digest` is exactly:

```text
H_tag(
  "DOM:contracts-vault-reservation-authority:v1",
  reservation_authority_bytes[0..315]
)
```

The `NonceIdentityV1.bound_digest` field must equal this exact
`ReservationAuthorityV1.bound_digest`. It is not the template hash and must
never be populated by copying or renaming another digest.

### 3.3 Durability and idempotency

The reservation authority is created with create-no-clobber under the same
retained root and exclusive lock as the session claim. The authority record,
session claim, initial journal entry, and charged budget projection form one
logical reservation transaction. A process failure may leave a lifetime claim
and authority record that recovery burns, but it may never delete or reuse the
session or refund a charged budget.

An existing `request_id` with byte-identical bytes returns the already-created
reservation handle. The same `request_id` with any different byte is a
permanent idempotency conflict and quarantines adaptor operations. A duplicate
session ID or reservation ID with different authority bytes is also a
permanent conflict.

`budget_policy_digest` binds a separately ratified canonical policy. This
record assigns no budget number, window, timeout, retry count, or retention
value. Without a nonzero digest for a trusted, ratified policy, the adaptor
subsystem does not start. Evidence-only tests may use an explicitly labelled
public policy fixture; it is never a production default.

## 4. Canonical mappings

The following mappings are exhaustive:

| `NonceVaultV1` value | Persistent authority |
|---|---|
| `ReservationNonceId` | `ReservationAuthorityV1.reservation_id` |
| `VaultKeyId` | `ReservationAuthorityV1.key_id` |
| `SessionId` | both `ReservationAuthorityV1.session_id` and `NonceIdentityV1.session_id` |
| `CounterpartyBucket` | `ReservationAuthorityV1.counterparty_bucket` |
| `PurposeV1` | both records; bytes must match |
| `ParticipantId` | both records; bytes must match |
| `TemplateHash` | `ReservationAuthorityV1.template_hash` |
| `IdempotencyKey` | `ReservationAuthorityV1.request_id` |
| nonce epoch | both records; values must match |
| `bound_digest` | definition in §3.2; both records must match |

`SigningPhaseV1` maps to artifact kind exactly as frozen by NAR-DC-P1-002.
Sponsor is codec-recognized but cannot create a reservation, attempt, permit,
or export in strict Phase 1.

## 5. Two distinct outbound digests

The adaptor authorization digest remains:

```text
adaptor_outbound_digest = H_tag(
  "DOM:scriptless-vault-outbound:v1",
  artifact_kind_u8 || outbound_length_u32_le || exact_outbound_bytes
)
```

The Contracts persistence digest remains:

```text
contracts_outbound_digest = H_tag(
  "DOM:contracts-vault-exposure:v1",
  artifact_kind_u8 || outbound_length_u32_le || exact_outbound_bytes
)
```

Both values are stored or recomputed under their own authority and compared to
the same exact bytes. They are never treated as interchangeable despite equal
preimage framing.

## 6. Minimum Phase 1B export capability

### 6.1 No fabricated witness authority

Witness and watchtower implementation remain outside DOM-CONTRACTS-P1-001.
The 252-byte `ExposurePermitBindingV1` field named `receipt_chain_hash` belongs
to the later witness-enabled profile. The minimum Phase 1B store must not
construct that record with a local journal digest, zero bytes, random bytes,
or a fake receipt.

The associated `NonceVaultV1::ExposurePermit` for this mission is instead the
nonserializable live `ExposureExportCapabilityV1<'authority>` frozen by
NAR-DC-P1-002 §5.6. Its authority is the retained root and lock handles, active
generation, verified `Spent` exposure version, and exact journal entry that
made it spent. It is private, one-shot, and cannot be reconstructed from any
caller-supplied bytes.

This local minimum is not rollback-resistant against replacement of the whole
authentic store before open. That limitation remains explicit until a later
witness/monotonic-anchor mission.

### 6.2 Deterministic public lookup identifier

For an exact spent exposure, the non-authoritative lookup identifier is:

```text
permit_id_32 = H_tag(
  "DOM:contracts-vault-export-permit-id:v1",
  exposure_version_id_155 || spent_journal_entry_digest_32
)
```

A zero result is terminal and fail-closed. The lookup identifier is public and
may be reconstructed after restart. It is not an export capability. Supplying
it authorizes nothing: the store must reopen and validate the complete spent
exposure, retained authority, and journal head before creating one new
one-shot resend capability.

## 7. Required DOM adaptor recovery surface

The next reviewed DOM adaptor revision must expose high-level, vault-backed
operations without exposing raw nonce, secret plaintext, receipt Boolean,
persistence Boolean, or capability bytes:

1. terminal abort methods that consume each live signer state and call
   `NonceVaultV1::abort` with the closed reason;
2. read-only `restore_state` delegation;
3. a resend lookup route that accepts a public `PermitIdV1` plus expected
   artifact kind/digest from trusted protocol state, calls
   `NonceVaultV1::resend_exported`, and returns only the exact typed artifact;
4. access to the public lookup ID on the concrete exported artifact or typed
   signer result, without exposing the live capability; and
5. no `into_inner`, mutable vault accessor, trait-object plugin, or raw export
   escape hatch.

Until that revision is reviewed, publicly committed, and pinned, normal
reserve/commit/reveal/partial integration may be tested, but complete abort and
retry conformance remains open.

## 8. Required tests

Ratification alone closes no implementation or evidence item. Required tests
include:

- every byte and every truncation of `ReservationAuthorityV1`;
- unknown purpose and Sponsor execution rejection;
- mismatched request/identity fields;
- template-hash substitution proving `bound_digest` changes;
- request-ID exact replay and conflicting replay;
- session-ID and reservation-ID collision;
- absent, zero, or changed budget-policy digest;
- both outbound digests checked against independent expected bytes;
- proof that a 252-byte witness-profile record creates no local capability;
- proof that a permit lookup ID creates no capability without full retained
  authority validation;
- process death before and after reservation authority, session claim, budget
  charge, exposure persistence, journal append, permit spend, and export;
- exact resend after restart with no nonce open, KDF, derivation, or signing;
- compile-fail proof that caller code cannot construct, clone, serialize, or
  reuse a live capability; and
- static and runtime proof that the ordinary DOM Wallet has no dependency or
  call path to these records.

## 9. Rejected alternatives

- `bound_digest = template_hash`: rejected because it omits reservation,
  participant, purpose, epoch, idempotency, and policy bindings.
- Storing missing fields in JSON, Serde, bincode, filenames, logs, or ambient
  application state: rejected.
- Reusing the adaptor outbound digest as the Contracts record digest: rejected.
- Filling `receipt_chain_hash` with a local journal hash: rejected.
- Treating a parsed 252-byte record or permit lookup ID as authority: rejected.
- Numeric test budgets as production defaults: rejected.
- Reopening pathnames instead of retaining directory and lock capabilities:
  rejected.
- Adding raw vault access to `VaultBackedSignerV1`: rejected.

## 10. Ratification effect

After a valid signature is verified, implementations may create and validate
`ReservationAuthorityV1`, use its bound digest in `NonceIdentityV1`, implement
the minimum local live capability, and implement the recovery surface in §7.
Witness, whole-root rollback resistance, numerical production budgets,
publication of another DOM revision, Phase 2, mainnet, and production remain
separately blocked.

## 11. Operator ratification block

```text
DOCUMENT_ID = NAR-DC-P1-003
DECISION = RATIFY_EXACT_FILE_BYTES
PROJECT = DOM Contracts
PHASE = Phase 1B minimum Nonce Vault
PRODUCTION = NOT AUTHORIZED
MAINNET = DISABLED
PHASE2 = NOT AUTHORIZED
```


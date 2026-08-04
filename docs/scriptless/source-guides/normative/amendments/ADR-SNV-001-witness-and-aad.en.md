# ADR-SNV-001 — Monotonic Witness Protocol and Vault AAD

Status: **FINAL CANDIDATE — EFFECTIVE ONLY AFTER VALID DETACHED RATIFICATION**  
Date: 2026-08-04  
Scope: Phase 3-SNV / G1b  
Ratification authority: DOM release signing key, Minisign key ID `74197A95CA309CF0`  
Verification public key: `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`

## 1. Decision summary

After ratification, this ADR freezes the portable production baseline for the remote monotonic witness and the canonical associated-data context passed to the existing Wallet V3 sealer.

The baseline is mandatory for adaptor sessions:

- no export of nonce-derived public material occurs before a verified witness receipt and the corresponding local durable state;
- no silent local-file witness fallback exists;
- a self-hosted witness service is a product requirement;
- TPM, Secure Enclave, and equivalent hardware anchors are optional backends, not replacements for the portable baseline unless separately approved;
- ordinary Wallet creation, restore, scan, sync, plain send, submit, rebroadcast, and cancellation never initialize or contact the vault or witness;
- witness unavailability blocks adaptor-session exposure only;
- restore on another device begins in `RESTORE_QUARANTINED`.

This ADR does not select numeric production defaults for budgets, windows, timeouts, retries, retention, or compaction. Those values remain caller-supplied and fail closed until measurement ADRs are accepted.

## 2. Approved primitive reuse

No new cryptographic primitive is introduced.

### 2.1 Hashing

All witness hashes use the authoritative DOM function:

```text
crates/dom-crypto/src/hash.rs::blake2b_256_tagged
```

At official DOM baseline `769822562565f18ef55423dc992e7aa661206b4a`, it computes native 32-byte BLAKE2b over:

```text
u16_le(tag_ascii_length) || tag_ascii || data
```

It has no key, salt, or personalization parameter.

### 2.2 Authentication signatures

Client authentication and witness receipts use the authoritative DOM Schnorr implementation, without a variant:

- type: `crates/dom-crypto/src/schnorr.rs::SchnorrSignature`;
- parser: `SchnorrSignature::from_bytes`;
- serializer: `SchnorrSignature::to_bytes`;
- verifier: the authoritative `dom-crypto` Schnorr verifier;
- bytes: `r_compressed[33] || s_be32[32]`, exactly 65 bytes.

The witness protocol does not replace the DOM consensus verifier and does not change consensus or existing transaction encoding.

### 2.3 Vault sealing

Production vault records reuse the Wallet V3 boundary at official Wallet baseline `1868e61bc39eca223d794348d70e48668ad06708`:

```text
crates/dom-wallet-crypto/src/lib.rs::seal
crates/dom-wallet-crypto/src/lib.rs::open
crates/dom-wallet-crypto/src/lib.rs::KdfParameters::DOM_CONTINUITY
crates/dom-wallet-crypto/src/lib.rs::SecretBytes
```

That boundary owns:

- Argon2id password hardening;
- HKDF-SHA256 expansion with the existing Wallet label;
- ChaCha20-Poly1305;
- fresh 32-byte salt and 12-byte AEAD nonce from `OsRng`;
- bounded envelope validation;
- zeroizing key/plaintext containers;
- authenticated `canonical_context` input.

G1b must call this boundary; it must not reproduce its KDF or AEAD internally. Existing Wallet envelope versioning and encoding remain Wallet-owned and are not redefined here.

## 3. Privacy model

The witness observes a pseudonymous chain of updates, request timing, traffic volume, network metadata, and the configured witness endpoint. This residual metadata must be disclosed.

The witness must not receive, directly or in a reversible field:

- civil or Wallet user identity;
- Wallet identifier;
- contract identifier;
- session identifier;
- counterparty identifier;
- amount or fee;
- address;
- PurposeV1 value;
- transaction hash;
- template hash;
- transcript plaintext;
- signing share, nonce share, partial signature, final signature, or adaptor secret.

The witness receives only epoch-scoped pseudonyms, opaque commitments, sequence data, idempotency nonces, pseudonymous authentication keys, and signatures.

## 4. Closed domain-tag registry

Exactly these ASCII tags are assigned:

| Tag | Use |
|---|---|
| `DOM:scriptless-witness-client-auth:v1` | client request authentication digest |
| `DOM:scriptless-witness-receipt:v1` | witness receipt signature digest |
| `DOM:scriptless-witness-receipt-chain:v1` | hash of a complete applied receipt for chaining |
| `DOM:scriptless-witness-transition:v1` | client-side commitment to a vault transition |
| `DOM:scriptless-witness-keyid:v1` | witness public-key identifier |
| `DOM:scriptless-witness-client-keyid:v1` | epoch client public-key identifier |
| `DOM:scriptless-witness-epoch-link:v1` | commitment linking a closed epoch to its successor |
| `DOM:scriptless-witness-key-succession:v1` | witness key-succession signature digest |

No runtime tag concatenation or V1 alias is permitted.

## 5. Protocol envelope

### 5.1 Common header

Every protocol message begins with:

| Order | Field | Size | Encoding |
|---:|---|---:|---|
| 1 | `magic` | 8 | ASCII `DOMSNV01` |
| 2 | `version` | 2 | `u16` LE, exactly `0x0001` |
| 3 | `message_kind` | 1 | closed registry below |
| 4 | `body_length` | 4 | `u32` LE; exact bytes after header |

The header is 15 bytes. Total messages larger than 4096 bytes are rejected before allocation. Trailing bytes, compression, alternate encodings, and unknown kinds are rejected.

### 5.2 Message-kind registry

| Byte | Name | Direction |
|---:|---|---|
| `0x01` | `RegisterEpochRequest` | client to witness |
| `0x02` | `AdvanceRequest` | client to witness |
| `0x03` | `QueryHeadRequest` | client to witness |
| `0x04` | `CloseEpochRequest` | client to witness |
| `0x81` | `RegisteredReceipt` | witness to client |
| `0x82` | `AdvancedReceipt` | witness to client |
| `0x83` | `HeadReceipt` | witness to client |
| `0x84` | `ClosedReceipt` | witness to client |
| `0xe1` | `ConflictReceipt` | witness to client |
| `0xe2` | `StaleReceipt` | witness to client |
| `0xe3` | `UnknownEpochReceipt` | witness to client |
| `0xf0` | `WitnessKeySuccession` | witness configuration object |

Every other byte is rejected. An unauthenticated malformed request may be closed without a response; it never changes witness state.

## 6. RequestV1 framing

Kinds `0x01..0x04` use the same fixed 282-byte body:

| Order | Field | Size | Encoding and rule |
|---:|---|---:|---|
| 1 | `epoch_pseudonym` | 32 | nonzero opaque CSPRNG value, unique to this vault epoch |
| 2 | `chain_id` | 32 | exact trusted DOM chain ID |
| 3 | `epoch` | 8 | `u64` LE, nonzero |
| 4 | `sequence` | 8 | `u64` LE |
| 5 | `previous_receipt_hash` | 32 | §8; all-zero only at first registration |
| 6 | `transition_commitment` | 32 | nonzero for register/advance/close; all-zero for query |
| 7 | `request_nonce` | 32 | nonzero CSPRNG idempotency key, unique within the epoch |
| 8 | `client_key_id` | 8 | first 8 bytes of the client key-ID hash below |
| 9 | `client_public_key` | 33 | canonical compressed SEC1, nonidentity |
| 10 | `client_signature` | 65 | DOM Schnorr over the digest below |

Total request size is 297 bytes including the common header. `body_length` is exactly 282.

```text
client_key_id = first_8_bytes(
    H_tag(
        "DOM:scriptless-witness-client-keyid:v1",
        client_public_key_33
    )
)

client_auth_digest = H_tag(
    "DOM:scriptless-witness-client-auth:v1",
    common_header_15 || request_body_without_client_signature_217
)
```

The client signature covers the header, including kind and length, and every preceding request field. DOM Schnorr receives the request's exact `chain_id` as its chain-ID argument and `client_auth_digest` as its message. The 33-byte client key is an epoch-scoped pseudonymous authentication key, not a Wallet identity key. It is generated and sealed by the Wallet for this subsystem only.

### 6.1 Kind-specific request rules

`RegisterEpochRequest`:

- `sequence=0`;
- `previous_receipt_hash=0^32` for the first vault epoch;
- for a successor epoch, `previous_receipt_hash` is the prior `ClosedReceipt` chain hash;
- `transition_commitment` is either the initial vault-state commitment or the epoch-link commitment from §11;
- the epoch pseudonym and client key have never appeared in another epoch.

`AdvanceRequest`:

- `sequence` is exactly the last applied sequence plus one;
- `previous_receipt_hash` equals the last applied receipt chain hash;
- `transition_commitment` commits to the exact local durable transition without revealing its fields.

`QueryHeadRequest`:

- `sequence=0`;
- `previous_receipt_hash=0^32`;
- `transition_commitment=0^32`;
- it is read-only and never advances state;
- its fresh request nonce correlates only the response to this query.

`CloseEpochRequest`:

- follows the same predecessor and sequence rules as `AdvanceRequest`;
- its transition commitment domain-separately commits to the terminal epoch state;
- no later advance is accepted for the closed epoch.

## 7. Transition commitments

The client computes the opaque transition commitment locally:

```text
transition_commitment = H_tag(
    "DOM:scriptless-witness-transition:v1",
    chain_id_32
 || schema_version_u16_le
 || epoch_u64_le
 || sequence_u64_le
 || previous_receipt_hash_32
 || record_kind_u8
 || record_revision_u64_le
 || nonce_id_32
 || local_journal_entry_digest_32
)
```

The witness receives only the resulting 32 bytes. `record_kind`, `record_revision`, `nonce_id`, and `local_journal_entry_digest` never appear on the witness wire. The local journal stores the complete preimage needed for audit and recovery.

## 8. ReceiptV1 framing

Kinds `0x81..0xe3` use the same fixed 258-byte body:

| Order | Field | Size | Encoding and rule |
|---:|---|---:|---|
| 1 | `request_kind` | 1 | one of `0x01..0x04` |
| 2 | `epoch_pseudonym` | 32 | copied from the authenticated request |
| 3 | `chain_id` | 32 | copied from the authenticated request |
| 4 | `epoch` | 8 | copied from the authenticated request |
| 5 | `sequence` | 8 | applied/head/conflicting sequence |
| 6 | `previous_receipt_hash` | 32 | predecessor asserted by the receipt |
| 7 | `transition_commitment` | 32 | applied/head/conflicting commitment |
| 8 | `request_nonce` | 32 | copied from the authenticated request |
| 9 | `client_key_id` | 8 | copied from the authenticated request |
| 10 | `witness_key_id` | 8 | identifier of the signing witness key |
| 11 | `witness_signature` | 65 | DOM Schnorr over the digest below |

Total receipt size is 273 bytes including the common header. `body_length` is exactly 258.

```text
witness_key_id = first_8_bytes(
    H_tag(
        "DOM:scriptless-witness-keyid:v1",
        witness_public_key_33
    )
)

receipt_digest = H_tag(
    "DOM:scriptless-witness-receipt:v1",
    common_header_15 || receipt_body_without_witness_signature_193
)

receipt_chain_hash = H_tag(
    "DOM:scriptless-witness-receipt-chain:v1",
    complete_wire_receipt_273
)
```

DOM Schnorr receives the receipt's exact `chain_id` as its chain-ID argument and `receipt_digest` as its message.

Only `RegisteredReceipt`, `AdvancedReceipt`, and `ClosedReceipt` advance the receipt chain. `HeadReceipt` and error receipts are signed evidence but never become a predecessor.

The witness public key is selected from the Wallet's closed pinned set by `witness_key_id`. Unknown, revoked, noncanonical, or ambiguous keys fail closed.

## 9. Idempotency, conflicts, and recovery

- The idempotency key is `(epoch_pseudonym, request_nonce)`.
- The witness durably stores the complete accepted request bytes and complete signed receipt bytes before responding.
- A byte-identical resend returns the byte-identical persisted receipt and does not sign a new receipt.
- Reuse of a request nonce with different bytes returns a signed `ConflictReceipt` and changes no state.
- A predecessor or sequence behind the witness head returns a signed `StaleReceipt` containing the current head fields.
- An unknown epoch returns a signed `UnknownEpochReceipt` and changes no state.
- A valid next sequence with a wrong predecessor or conflicting commitment returns `ConflictReceipt` and changes no state.
- A lost response is recovered first by byte-identical resend. `QueryHeadRequest` is used only for reconciliation, never to recreate outbound bytes.
- A remote-ahead state is accepted locally only if every missing signed receipt and predecessor hash verifies and matches a locally persisted request/transition. Otherwise the vault enters `RESTORE_QUARANTINED`.
- Local-ahead without matching witness receipts cannot export and must retry the persisted exact request.
- Divergent valid signed receipts at the same epoch/sequence are witness-equivocation evidence. The epoch and vault enter quarantine permanently pending operator resolution.
- An invalid or unavailable witness never causes a local-file fallback.

## 10. Consume-before-export and crash safety

Before an exposure API returns bytes, the Wallet transaction must durably contain:

1. exact outbound bytes;
2. irreversible nonce-consumed tombstone;
3. consumed global and counterparty budget entries;
4. append-only chained journal record;
5. verified witness receipt;
6. receipt chain hash and predecessor;
7. export authorization tied to `nonce_id`, `session_id`, participant, purpose, template hash, and outbound digest.

File/data sync and required parent-directory sync occur before export. A crash or ambiguous I/O result burns the nonce and preserves the budget debit. Recovery returns either the identical persisted bytes or permanent burn/quarantine; it never regenerates secret/public material.

Restore from backup starts in `RESTORE_QUARANTINED`. Union/max merge rules preserve every tombstone, consumed budget, epoch, sequence, and receipt observed by either side. Backward wall-clock movement never resets a rolling budget and causes quarantine when ordering cannot be proved.

## 11. Epoch rotation

Each epoch has a fresh random pseudonym and fresh pseudonymous client authentication key. Closing the old epoch is mandatory before registering a successor.

```text
epoch_link_commitment = H_tag(
    "DOM:scriptless-witness-epoch-link:v1",
    old_closed_receipt_chain_hash_32
 || new_epoch_u64_le
 || new_epoch_pseudonym_32
 || new_client_key_id_8
)
```

The successor `RegisterEpochRequest.transition_commitment` is this value. Rotation never resets global or counterparty budgets; the local store carries them forward independently of the witness-visible commitment.

## 12. Witness key succession

Witness signing keys are generated outside the service. The private key never resides on a shared build system. Rotation uses a separately distributed `WitnessKeySuccession` object.

Body layout for message kind `0xf0`:

| Order | Field | Size | Encoding |
|---:|---|---:|---|
| 1 | `chain_id` | 32 | exact trusted DOM chain ID |
| 2 | `old_witness_key_id` | 8 | current pinned key ID |
| 3 | `new_witness_key_id` | 8 | derived from the new public key |
| 4 | `new_witness_public_key` | 33 | canonical compressed SEC1 |
| 5 | `activation_epoch` | 8 | `u64` LE |
| 6 | `activation_sequence` | 8 | `u64` LE |
| 7 | `revoke_old` | 1 | `0x00` retain for earlier receipts; `0x01` reject after activation boundary |
| 8 | `old_key_signature` | 65 | signature by old key |
| 9 | `new_key_signature` | 65 | proof of possession by new key |

The body is exactly 228 bytes and the complete message is 243 bytes. Both signatures cover:

```text
H_tag(
    "DOM:scriptless-witness-key-succession:v1",
    common_header_15 || succession_body_without_signatures_98
)
```

Both DOM Schnorr signatures receive the object's exact `chain_id` as their chain-ID argument and the succession digest as their message.

The old signature authorizes succession; the new signature proves possession. `revoke_old=0x01` invalidates old-key receipts only after the exact activation boundary. Earlier receipts remain verifiable. Loss of the old key without a valid succession object is fail-closed and requires explicit out-of-band re-pinning; it is never silently recovered.

## 13. Canonical Vault AAD V1

Every SNV record passed to Wallet `seal`/`open` uses this exact `canonical_context`:

```text
vault_aad_v1 =
    "DOMSNVAD"
 || schema_version_u16_le
 || wallet_identity_32
 || vault_id_32
 || epoch_u64_le
 || record_kind_u8
 || record_revision_u64_le
 || nonce_id_32
```

| Order | Field | Size | Validation |
|---:|---|---:|---|
| 1 | AAD magic | 8 | ASCII `DOMSNVAD` |
| 2 | `schema_version` | 2 | `u16` LE, exactly `0x0001` |
| 3 | `wallet_identity` | 32 | nonzero stable local Wallet identity; never sent to witness |
| 4 | `vault_id` | 32 | nonzero local vault identifier; never sent to witness |
| 5 | `epoch` | 8 | nonzero `u64` LE |
| 6 | `record_kind` | 1 | closed local vault record registry |
| 7 | `record_revision` | 8 | monotonic `u64` LE |
| 8 | `nonce_id` | 32 | nonzero for nonce records; a separately defined domain-specific nonzero record ID for non-nonce records |

Total `vault_aad_v1` length is exactly 123 bytes. Unknown versions, record kinds, zero identifiers, wrong length, overflow, or reordered fields fail before decryption.

The Wallet passes all 123 bytes unchanged as `canonical_context` to `dom_wallet_crypto::seal` and `open` with `KdfParameters::DOM_CONTINUITY`. The Wallet boundary additionally authenticates its existing envelope header, salt, and profile. This ADR does not use JSON, Serde, bincode, CBOR, or native struct layout to define the 123 normative context bytes.

## 14. Budget parameters

The following are mandatory caller-supplied, versioned policy parameters with no production default until measurement:

- global session budget per key and epoch-independent history;
- secondary budget per counterparty bucket;
- concurrent reservation limit;
- rolling-window creation limit;
- window duration and monotonic clock source;
- network connect/read/write timeout;
- retry schedule and maximum attempts;
- receipt/journal retention;
- compaction threshold.

Aborts consume budget. Epoch rotation, process restart, backup restore, wall-clock rollback, or witness replacement never refunds or resets budget.

A later measurement ADR must record hardware, operating system, exact revision, workload, sample count, p50/p95/p99/maximum, failure behavior, safety margin, threat rationale, units, clock source, and reset/non-reset rules.

## 15. Transport and self-hosting

- Production transport is HTTPS with TLS 1.3 or a mutually authenticated local transport with equivalent confidentiality and peer integrity.
- Application-layer Schnorr authentication and receipt verification remain mandatory even with TLS.
- Binary messages use media type `application/vnd.dom.snv.v1` and endpoint `POST /v1/witness`.
- HTTP/content compression is disabled for protocol bodies.
- A response body is exactly one bounded protocol message.
- Connect, read, and write timeouts are mandatory caller-supplied positive values; absence is a configuration error.
- Automatic redirects are forbidden.
- Health `/healthz` and readiness `/readyz` disclose only service health and never pseudonyms, counters, keys, or vault state.
- The self-hosted service implements exactly the same protocol, persistence, parser, receipt, and conformance suite as any hosted deployment.
- Retention is caller-configured and must preserve all open epochs, all closed-epoch chain evidence required by configured restore policy, all conflict/equivocation evidence, and all key-succession objects. Absence of a compliant policy is a configuration error.

## 16. Ordinary Wallet isolation

The witness, vault, budgets, anchor, and witness keys are reachable only through an explicit Scriptless/adaptor feature and explicit adaptor-session APIs.

Ordinary Wallet build, create, open, restore, scan, sync, plain send, submit, rebroadcast, and cancellation:

- do not construct a `NonceVault`;
- do not resolve a witness endpoint;
- do not load witness keys or receipts;
- do not read or debit adaptor budgets;
- do not advance a witness anchor;
- succeed while the witness is unavailable.

This isolation requires dependency-graph, feature-graph, call-graph, compile-time, runtime-offline, and source-search evidence. Documentation alone does not approve G1b.

## 17. Required tests and gate effect

Ratification freezes the protocol; it does not approve G1b. The gate still requires:

- bounded parser tests and fuzzing for every request, receipt, and succession object;
- valid, mutation, replay, duplicate, conflict, stale, remote-ahead, divergent, and equivocation cases;
- receipt verification before exposure authorization;
- crash injection before and after every append, sync, rename, receipt persist, acknowledgement, authorization, outbound persist, and tombstone;
- truncation at every journal-record byte boundary;
- rollback to every valid prior prefix;
- backup/restore and concurrent-reservation restore tests;
- proof that no crash revives a nonce or refunds budget;
- proof that secrets and prohibited metadata never enter logs, panic text, requests, or receipts;
- Linux execution evidence and separately recorded Windows/macOS evidence;
- self-hosted service interoperability;
- ordinary Wallet isolation evidence.

Unexecuted platform workflows remain `READY FOR PLATFORM VALIDATION — NOT FULLY APPROVED` and cannot be reported as passed.

## 18. Ratification

Expected detached signature file:

```text
ADR-SNV-001-witness-and-aad.en.md.minisig
```

The signature must verify over the exact bytes of this file with the public key printed in the header. No inline signature text modifies these bytes after signing.

# ADR-SNV-002 — Vault Sealed-Record Registry and AAD Identifier

Status: **FINAL CANDIDATE — EFFECTIVE ONLY AFTER VALID DETACHED RATIFICATION**
Date: 2026-08-04
Supplements: `ADR-SNV-001 — Monotonic Witness Protocol and Vault AAD`
Scope: Phase 3-SNV / G1b records passed to the Wallet production sealer
Ratification authority: DOM release signing key, Minisign key ID `74197A95CA309CF0`
Verification public key: `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`

## 1. Context

Ratified ADR-SNV-001 freezes the 123-byte `vault_aad_v1` layout and requires `record_kind_u8` to use a closed local vault record registry. It also requires the final 32-byte field to be a nonce identifier for nonce records or a separately defined nonzero identifier for non-nonce records.

ADR-SNV-001 does not assign those record-kind bytes or the non-nonce identifier. Production AAD construction is therefore fail-closed until this supplement is ratified.

Inspection of the actual G1b boundary shows exactly two secret-bearing record classes that are passed to Wallet `dom_wallet_crypto::seal` and `open`:

1. one-shot reservation nonce secret material;
2. the epoch-scoped pseudonymous client authentication private key required by ADR-SNV-001 §§6 and 11.

Journal snapshots, witness receipts, outbound public bytes, budgets, anchors, and tombstones are authenticated by their own storage/journal rules but are not additional sealed-record kinds under this registry. Adding any of them later requires a new versioned registry and AAD schema.

Evidence:

- Wallet isolated implementation `crates/dom-wallet-scriptless-vault/src/storage.rs::EncryptedNonceMaterial` and `ReservationRecord::encrypted_nonce`;
- ADR-SNV-001 §6 requires the epoch client key to be generated and sealed by the Wallet;
- ADR-SNV-001 §11 requires a fresh client authentication key for every epoch.

The two classes must not share a byte. Nonce material is reservation-bound, one-shot, and irreversibly tombstoned. The client authentication key is epoch-bound and authorizes multiple witness requests until epoch closure.

## 2. Decision

After valid detached ratification, this document assigns the complete V1 sealed-record registry and the exact identifier rule for each kind. It does not change the 123-byte AAD layout signed in ADR-SNV-001.

## 3. Closed VaultSealedRecordKindV1 registry

| Byte | Exact name | Meaning | Final AAD identifier |
|---:|---|---|---|
| `0x01` | `NonceSecretMaterial` | opaque one-shot two-nonce secret material owned by one reservation | `reservation_nonce_id_32` |
| `0x02` | `EpochClientAuthenticationKey` | pseudonymous DOM Schnorr client private key owned by one witness epoch | full client-key-ID digest |

Rules:

- `VaultSealedRecordKindV1` is a closed `repr(u8)` registry.
- `0x00` and `0x03..0xff` are invalid and fail closed.
- There is no unknown, default, fallback, `non_exhaustive`, or implicit enum-order encoding.
- Parsing uses exhaustive `TryFrom<u8>` behavior and rejects every unassigned byte.
- Serialization uses an explicit exhaustive mapping from each semantic variant to the assigned byte.
- A future sealed-record class requires `VaultSealedRecordKindV2`, a new AAD schema version, a new test-vector set, and separate ratification. V1 is never extended.
- The journal action enum is not this registry and must never be converted to these bytes by declaration order.

## 4. Record revision

`record_revision_u64_le` in `vault_aad_v1` is the monotonic revision of the individual sealed record identified by the final 32-byte AAD field.

Rules:

- the first sealed version uses revision zero;
- any authorized re-seal uses the previous revision plus one with checked arithmetic;
- revision overflow is terminal and fail-closed;
- revision is never derived from wall-clock time;
- retry of an already durable identical operation returns the existing envelope and does not allocate a revision;
- restore, epoch rotation, compaction, and process restart never decrement or reuse a revision;
- a deleted/tombstoned record identifier is never reused with revision zero.

Nonce secret material normally has only revision zero and is then destroyed/tombstoned. Re-sealing it is permitted only for an atomic storage migration that preserves the same identifier, increments the revision, and exposes no public material during migration.

## 5. NonceSecretMaterial identifier

For `record_kind_u8 = 0x01`:

```text
nonce_id_32 = reservation_nonce_id_32
```

`reservation_nonce_id_32` is allocated once before the first durable reservation record.

Requirements:

- exactly 32 bytes and nonzero;
- fresh operating-system CSPRNG output;
- CSPRNG failure is terminal and fail-closed;
- local only and never sent to the witness;
- not a session ID, witness request nonce, Wallet ID, transaction hash, template hash, or hash of secret nonce material;
- stable through reserve, public commitment, witness advance, authorization, consume, abort, crash recovery, and restore;
- never reused after consume, abort, burn, crash ambiguity, restore, epoch rotation, or compaction;
- retained in the irreversible tombstone needed to prove non-reuse.

Variable-length identifiers, truncated hashes, padded UUIDs, UUID text, and serialization hashes are not canonical substitutes.

## 6. EpochClientAuthenticationKey identifier

ADR-SNV-001 already assigns:

```text
client_key_id = first_8_bytes(
    H_tag(
        "DOM:scriptless-witness-client-keyid:v1",
        client_public_key_33
    )
)
```

For `record_kind_u8 = 0x02`, the final 32-byte AAD field is the complete digest from the same operation:

```text
nonce_id_32 = H_tag(
    "DOM:scriptless-witness-client-keyid:v1",
    client_public_key_33
)
```

No new hash tag is introduced.

Requirements:

- `client_public_key_33` is the canonical compressed nonidentity secp256k1 public key corresponding to the sealed private key;
- `H_tag` is exactly the authoritative DOM `blake2b_256_tagged` framing ratified by NAR-001 and ADR-SNV-001;
- the full digest must be nonzero; an all-zero digest is a terminal key-generation error and the key is destroyed before any registration request;
- the witness-visible `client_key_id` remains exactly the first eight bytes of this full digest;
- the full 32-byte digest is local and is never sent as an additional witness field;
- the key and identifier are unique to one epoch and one vault;
- the private key is destroyed after durable epoch closure and is never reused in a successor epoch;
- retry uses the same sealed key and same identifier; it never generates a replacement key inside an open epoch after any authenticated request may have existed.

## 7. Complete AAD binding

The ADR-SNV-001 layout remains byte-for-byte unchanged:

```text
vault_aad_v1 =
    "DOMSNVAD"[8]
 || schema_version_u16_le[2]
 || wallet_identity_32[32]
 || vault_id_32[32]
 || epoch_u64_le[8]
 || record_kind_u8[1]
 || record_revision_u64_le[8]
 || nonce_id_32[32]
```

Total length remains exactly 123 bytes.

Construction order:

1. validate schema version, fixed lengths, nonzero Wallet/vault identities, nonzero epoch, record kind, and revision;
2. select the identifier rule exclusively from `record_kind_u8`;
3. validate or derive the exact nonzero 32-byte final field;
4. encode all 123 bytes without Serde, JSON, bincode, CBOR, native layout, or architecture-dependent lengths;
5. pass the exact 123 bytes unchanged as `canonical_context` to Wallet `dom_wallet_crypto::seal` or `open` with `KdfParameters::DOM_CONTINUITY`.

There is no alternate V1 AAD, zero sentinel, unsealed production fallback, or compatibility default.

## 8. Lifecycle constraints

### 8.1 Nonce secret material

- It is sealed before any derived public value leaves the cryptographic boundary.
- Partial signing consumes the one-shot secret material by value.
- Consume or any ambiguity destroys the secret and persists an irreversible tombstone before exposure.
- Abort after public material may have existed burns the secret and budget.
- Backup/restore cannot recreate the sealed record after its tombstone exists.

### 8.2 Epoch client authentication key

- It is generated and sealed before `RegisterEpochRequest` is signed.
- It signs only witness protocol requests for its exact epoch, chain, and pseudonym.
- It is never a Wallet spending key, release key, witness server key, or user identity key.
- It survives ordinary request retry within the epoch.
- Epoch closure and rotation never reset nonce/session budgets.
- Loss, rollback, or ambiguity places adaptor operations in `RESTORE_QUARANTINED`; no silent replacement key is generated for the same open epoch.

## 9. Required conformance tests

Ratification freezes this registry but does not approve G1b. The implementation must prove:

- roundtrip for `0x01` and `0x02`;
- rejection of `0x00` and every byte in `0x03..0xff`;
- exact 123-byte AAD length and field order for both kinds;
- independent expected AAD bytes for both kinds;
- nonce identifier persistence across the entire reservation lifecycle;
- client private/public key correspondence and full/short key-ID correspondence;
- mutation of any AAD field causes Wallet envelope authentication failure;
- moving ciphertext across Wallet, vault, epoch, kind, revision, or identifier fails authentication;
- idempotent retry does not allocate a new revision, nonce identifier, or epoch key;
- consume, abort, restore, epoch close, and rotation never revive or reuse secret material;
- all unknown kinds, zero identifiers, wrong lengths, and revision overflow fail closed;
- no secret, Wallet identity, session identity, purpose, value, address, template hash, or transaction hash reaches witness messages or logs.

Self-generated vectors are not independent.

## 10. Compatibility and non-goals

This registry is local encrypted-vault metadata. It does not modify:

- DOM consensus;
- transaction, kernel, block, or persisted-block serialization;
- genesis, network magic, PoW, or chain selection;
- the witness wire protocol signed in ADR-SNV-001;
- PurposeV1, DirectionV1, SigningPhaseV1, or the G1a KDF;
- ordinary Wallet operation paths.

No DL2P type, framing, operation, receipt, nullifier, or storage model is imported.

## 11. Ratification

Expected detached signature file:

```text
ADR-SNV-002-vault-record-kind-registry.en.md.minisig
```

The signature must verify over the exact bytes of this file with the public key printed in the header. No inline signature text modifies these bytes after signing.

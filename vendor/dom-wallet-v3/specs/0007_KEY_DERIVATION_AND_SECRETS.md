# DOM Wallet V3 Key Derivation and Secrets

**Status:** DRAFT
**Owner:** Soren Planck

## Purpose and scope

This specification defines root-secret handling, derivation provenance, secret lifetimes, envelope protection, and non-reuse preservation. It preserves authoritative DOM cryptography and records where DOM authority has not yet selected a V3 construction. It does not create a cryptographic primitive or import a foreign derivation scheme.

## Authoritative sources and terminology

Authoritative sources are Specifications 0000, 0001, 0002, and 0004; DOM wallet-keys, wallet-crypto, Wallet V1/V2 code and tests; and DOM consensus cryptography. DOM evidence includes BIP-39 seed handling, BIP-32/BIP-44 derivation, separate DOM coinbase and spend-blinding derivation, versioned Argon2id and HKDF-SHA256 password hardening, ChaCha20Poly1305 envelopes, fresh salt and nonce generation, and atomic envelope publication.

**RootSecret** is root seed material. **SecretWrapper** is an opaque non-Debug, non-Clone, non-serializable holder. **NonReuseEvidence** binds an allocated derivation position, nonce, blinding, or envelope nonce to its purpose and Generation. **ExposureRecord** records irreversible use. A derivation record contains WalletIdentity, ChainId, AccountId, semantic domain, position, version, purpose reference, Generation, and exposure/non-reuse evidence.

## Protected properties, boundaries, and assumptions

The secret service alone unwraps RootSecret and derives secret material. Lifecycle receives operation-scoped material; storage receives authenticated encrypted state; APIs, logs, audit events, support bundles, and transports receive no secret unless an authoritative DOM format requires a specific field. Platform isolation, secure randomness, and approved DOM primitives are assumptions. Zeroization reduces memory lifetime but MUST NOT be represented as proof that every copy in process memory or hardware has been erased.

Secrets include seeds, derived keys, chain codes, scalar material, blindings, nonces, contexts, unlock credentials, envelope keys, and backup plaintext. They MUST be chain-, purpose-, and version-bound and MUST NOT appear in formatting, cloning, ordinary serialization, errors, or diagnostics.

## State and data model

Semantic domains are Root, Account, Coinbase, Receive, Change, PrivateTransactionContext, BackupEnvelope, and Authentication. Existing DOM BIP-39/BIP-32/BIP-44 compatibility behavior, deterministic coinbase-by-height material, and deterministic receive-request material are authoritative for supported V1/V2 recovery and migration when their DOM validation inputs are present. Change and receive-slate blindings remain random, non-derivable material. New V3 private-context, backup-envelope, and authentication subkeys are controlled by DEC-V3-SECRET-DOMAINS and are not invented here.

An unlock session carries WalletIdentity, ChainId, capability scope, issuance and expiry evidence, work or inactivity bound, and explicit lock state. It never contains a serializable RootSecret. A secret provenance record records the approved construction version, purpose, allocation, exposure, disposal, and recovery linkage.

## Invariants

1. Chain mismatch rejects unlock, derivation, restore, migration, backup open, and secret-bearing message use before secret release.
2. Positions are allocated in one durable unit before fresh derivation; per-domain non-reuse floors only advance.
3. Restore and migration use the maximum valid local, imported, and observed floor and MUST NOT decrease it.
4. A nonce or blinding used for an exposed or finalized purpose is never recreated after crash, loss, restore, migration, cancellation, or reorganization.
5. Mnemonic, path, scalar, point, nonce, salt, and fixed-length encodings validate their complete canonical form before indexing or cryptographic use and reject malformed input without panic.
6. Secret wrappers are non-copying where the language permits; debug, display, ordinary clone, and ordinary serialization are prohibited.

## Valid behavior

New root material MUST use an approved CSPRNG and the authoritative DOM mnemonic acceptance model. The wallet MUST use the approved DOM derivation implementation for any implemented DOM protocol domain. Account, coinbase, receive, change, and private-context material MUST record their domain and position before use. Fresh random transaction material MUST be generated through an approved CSPRNG, recorded with its purpose, and exposed only after the associated durable unit is acknowledged.

The current DOM envelope construction is versioned and uses Argon2id followed by HKDF-SHA256 with the established DOM wallet-key context, fresh salt and nonce, and ChaCha20Poly1305. V3 envelope use MUST bind WalletIdentity, ChainId, purpose, and format version as authenticated context or as authenticated canonical plaintext validated before use. A changed profile requires a new version, compatibility decision, vectors, migration, bounded work policy, and cryptographic review.

Unlock authority MUST be scoped to capability and identity, expire or lock explicitly, and release only the required material. Credential rotation MUST re-encrypt through one durable unit without changing secret provenance. Backup and restore follow 0008; migration follows 0011.

## Invalid behavior

It is invalid to use a foreign ChainId, unallocated position, malformed encoding, unbounded KDF profile, reused nonce or blinding, plaintext private context, unlocked secret in a log, password embedded in an example, or a password as a portable derivation path. A password, session, or backup key MUST NOT silently substitute for a DOM protocol key. Rejected operations MUST NOT allocate a position, advance Generation, or expose material.

## Persistence and atomicity

Allocation, derivation floor movement, context creation or disposal, ExposureRecord, RecoveryEvent, and audit record MUST share the relevant 0004 durable unit. At-rest secret-bearing records use authenticated encryption. Envelope publication uses temporary output, required synchronization, and atomic replacement under the selected storage durability profile. The persisted form records a version and bounded profile identifier; it never relies on a caller-selected unbounded cost.

## Crash and restart behavior

A crash before acknowledgement leaves no allocation. A crash after acknowledgement retains allocation and records either recoverable encrypted material or RecoveryRequired; the wallet MUST NOT derive a replacement nonce or blinding. Restart validates envelope framing, version, lengths, identity, chain binding, provenance, floors, and context authentication before unlock or derivation. Credential rotation restarts from its durable recovery event.

## Reorganization, concurrency, replay, and idempotency

Reorganization changes chain observations but MUST NOT remove provenance, floors, or ExposureRecords. Concurrent allocation has one expected-Generation winner. Replay reuses the recorded purpose and material only where that material is safe to reuse; it otherwise resumes typed recovery without manufacturing a replacement. Restore and migration preserve the greatest valid floor even when later ChainSource evidence changes.

## Security, compatibility, and migration impact

Secret values are redacted from logs, errors, audit events, support bundles, metrics, and test failure artifacts. DOM V2 secrets are recognized only in read-only 0011 staging and only after source validation. Epic KDFs, paths, parameters, nonce behavior, commitments, proofs, and slate material are rejected.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Chain and purpose binding, canonical encoding rejection, wrapper redaction, session authority, expiry, and rotation failure |
| Property tests | Monotonic floors, uniqueness across retry and reopen, and non-reuse across restore and migration |
| Executable-model tests | Generated allocation, exposure, crash, restore, rotation, and reorganization sequences |
| Integration tests | DOM envelope opening and saving, scoped unlock, backup/restore, migration, and DOM key vectors |
| Restart tests | Allocation, exposure, rotation, and envelope publication boundaries |
| Reorganization and concurrency tests | Provenance retention and competing allocation behavior |
| Fault-injection tests | CSPRNG, envelope, storage, context, and rotation failures without plaintext persistence |
| Fuzz targets | Mnemonics, paths, scalars, points, envelope headers, ciphertexts, contexts, and fixed-length fields without panic or leakage |

## Acceptance criteria for promotion from DRAFT to REVIEW

Promotion requires reviewed vectors for every implemented DOM domain, a reviewed envelope profile and associated-data contract, cross-chain rejection evidence, lifecycle traceability for non-reuse, and a platform zeroization assessment. A cryptographic claim without vectors and review is insufficient.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0003, 0004, 0008, 0011, and 0012.

The V3 literal domain-label registry, private-context and authentication subkey construction, authenticated-context encoding, KDF upgrade and bound policy, canonical point and scalar representation policy, and platform-specific zeroization guarantees remain unresolved. They require direct DOM cryptographic authority, vectors, and review before implementation.

## Review Blockers

* DEC-CRYPTO-ENVELOPE-BINDING
* DEC-V3-SECRET-DOMAINS

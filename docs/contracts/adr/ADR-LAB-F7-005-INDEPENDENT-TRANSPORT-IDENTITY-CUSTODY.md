# ADR-LAB-F7-005: Independent Contracts Transport-Identity Custody

Status: LAB CANDIDATE — implemented for F7 evaluation; not a production
ratification record

Date: 2026-08-13

## Problem

The authenticated `DSC1` envelope and Noise XX transport require two
long-lived private keys across process restarts: a DOM Schnorr transport
identity and an X25519 Noise static key. The transport crate previously
defined only in-memory key objects and said that Noise private bytes belonged
in a wallet keystore. That statement conflicts with P1-ARCH-002 and
NAR-DC-P1-001, which prohibit DOM Wallet and DOM Contracts from sharing any
seed, key, keystore, or database. Without an independent retained custody
boundary, a restarted F7 peer could neither authenticate the same roster entry
nor complete Noise against the public key frozen before funding.

## Context

NAR-DC-P1-005 requires the transport identity to be independently generated
and distinct from wallet keys, contract spending keys, G1A signing shares,
nonce secrets, storage keys, witness keys, and backup keys. The application
session database needs stable public references, but it must never become a
private-key store. The DOM Interop Foundation also prohibits persistence of
the route secret `t`; that secret is outside this custody design and is never
accepted by its API or record format.

`dom-scriptless-store` cannot own `NoiseStaticKeyV1` directly because the
transport crate already depends on the session store. Reversing that edge
would introduce a crate cycle.

## Decision

1. Add the independent `dom-scriptless-identity-store` composition crate. It
   depends on the transport and session-store crates and owns a separate
   retained application-keystore directory. It does not use the DOM Wallet
   repository, Wallet database, Wallet seed, or Wallet keystore.
2. Draw the 32-byte X25519 secret and 32-byte canonical nonzero DOM Schnorr
   secret independently from the operating-system CSPRNG. Reject equality of
   the two raw draws and retry an invalid secp256k1 scalar.
3. Encrypt both secrets in one versioned immutable envelope with Argon2id
   (`64 MiB`, three iterations, one lane) and ChaCha20-Poly1305. Bind the
   version, fixed KDF parameters, random salt/nonce, opaque key reference, and
   both derived public keys as AEAD associated data. Build and authenticate the
   complete `0600` envelope inside a random owner-only `0700` staging
   directory, fsync the envelope and directory, then publish it under the
   requested root name with one `renameat2(RENAME_NOREPLACE)` and fsync the
   parent. The final root name is therefore either absent or contains a
   complete authenticated store; it is never published before key derivation
   or envelope persistence. A failed concurrent creator cannot replace an
   existing root. An ungraceful crash may leave a non-authoritative hidden
   staging directory, but it cannot block retrying the requested name or be
   opened as that production identity.
4. Retain an exclusive `flock` for the lifetime of an open store. Reopen
   authenticates exact length, format, digest, AEAD tag, KDF parameters,
   filesystem owner/type/mode/link-count policy, both authoritative private
   key parsers, both public-key recomputations, and key separation.
   Live use also reopens the named root, lock, and envelope without following
   links; compares their retained device/inode/mode/owner identities; and
   compares a retained BLAKE2b-256 digest of every exact authenticated
   envelope byte before signing or starting a Noise handshake.
5. Expose no raw secret, general signing callback, codec, `Clone`, or `Debug`
   implementation. The rehydrated authority may only establish Noise from the
   exact local and remote public records loaded from the session database, and
   may sign only a structurally canonical `UnsignedMessageV1` whose sender ID
   equals that local record, through DOM's authoritative Schnorr
   implementation.
6. Add a separate immutable public-only session record binding, for each of
   the two roster participants, the participant ID, opaque keystore reference,
   X25519 public key, and DOM Schnorr public key. It is accepted only when the
   participant order and Schnorr keys exactly equal the previously frozen
   transport roster. Startup audits authenticate and cross-check this record.
7. Keep the route secret `t` entirely outside the identity store. A restarted
   success path must receive it again from its owner and validate `tG = T`;
   otherwise the safe path is refund.

## Alternatives considered

### Store the keys in DOM Wallet V3

Rejected. This directly violates P1-ARCH-002 and NAR-DC-P1-001 and would make
Contracts transport authority depend on wallet custody.

### Derive either key from a wallet seed, session ID, or the other key

Rejected. It violates key separation, correlates independent authority
domains, and makes a public session value part of private-key generation.

### Persist private keys in `SessionRecordV1`

Rejected. Session records are application state and evidence, not an encrypted
private-key boundary. They are intentionally limited to public keys and opaque
references.

### Add raw export/import methods to the transport key objects

Rejected. A general raw-secret surface would let adapters, logs, codecs, and
unrelated stores bypass the retained custody policy. The composition crate
performs generation, sealing, authenticated rehydration, and purpose-specific
use internally.

### Keep fresh in-memory identities after every restart

Rejected. The new public keys would not match the frozen roster or Noise
terms, so restart recovery would be non-interoperable and fail authentication.

## Invariants

- DOM Wallet and DOM Contracts never share key material or storage.
- Noise and DSC1 identity secrets are independent OS-CSPRNG draws and are not
  equal.
- No operational key authority is returned before envelope and directory
  durability has been verified after fsync.
- The caller-selected root name is published atomically with no replacement;
  it never denotes a partially initialized directory.
- The encrypted envelope is immutable, exact-length, versioned, authenticated,
  owner-only, single-linked, and exclusively retained while open.
- Rehydrated public keys exactly equal the public session references.
- DSC1 signing accepts only `UnsignedMessageV1`; arbitrary digests cannot be
  signed through this boundary.
- Session storage contains public data only.
- A missing, replaced, malformed, wrong-key, wrong-passphrase, or tampered
  record fails closed without revealing which private field failed.
- Same-inode mutation of an already authenticated envelope revokes the live
  authority before it can sign or touch the network stream.
- `t`, wallet seeds, spending shares, collaborative proof material, and secret
  nonces are not accepted or persisted.

## Compatibility and security impact

The decision is additive. It does not change `DSC1`, the Noise handshake,
DOM cryptography, consensus, transaction encoding, or existing roster bytes.
The public identity-reference record is a separate V1 object, so frozen
transport-roster encoding remains unchanged. Legacy laboratory callers may
still exercise the roster parser without the record, but the F7 real-transport
composition must load and match it before opening a network connection.

The new boundary makes restart authentication reproducible while reducing the
private-key surface to two purpose-specific operations. Passphrase security
remains an operator responsibility; the fixed Argon2id policy raises the cost
of offline guesses but cannot compensate for a weak passphrase or a fully
compromised running process.

## Verification

The identity-store and session-store tests cover:

- create, fsync, drop, reopen, and exact public-reference equality;
- canonical DSC1 signing before and after restart with the same roster key;
- two independently generated participants completing a real Noise XX
  handshake over TCP after both keystores are reopened;
- authenticated DSC1 delivery inside that restarted encrypted channel;
- wrong passphrase, ciphertext tamper, malformed permissions, and concurrent
  retained-open refusal;
- same-inode ciphertext mutation while the store is open, including proof that
  neither another DSC1 signature nor another Noise I/O attempt occurs;
- process-abort cuts after staging fsync, after envelope fsync, and after the
  atomic rename, proving that early cuts leave the final name absent and
  retryable while the post-rename cut reopens one complete identity and cannot
  be overwritten;
- public session-reference persistence and cross-check against the immutable
  roster after store restart; and
- startup quarantine after a public reference record is modified.

Reproducible commands after the coordinated F7 build lock is released:

```text
CARGO_BUILD_JOBS=2 cargo test -p dom-scriptless-identity-store
CARGO_BUILD_JOBS=2 cargo test -p dom-scriptless-store contracts_identity_public_references
CARGO_BUILD_JOBS=2 cargo clippy -p dom-scriptless-identity-store --all-targets -- -D warnings
```

# ADR-F7-LAB: Crash-atomic Bitcoin claim nonce ownership

- Status: Lab candidate
- Scope: F7 Bitcoin claim signing only
- Normative authority: DOM Interop Annex M v3.3, M.6 and M.8

## Problem

The F5 Bitcoin signer intentionally lost its secret nonce on process exit and
therefore treated every crash after public-nonce exposure as a refund case. F7
must instead survive an ordinary process restart without ever regenerating a
nonce, changing its public nonce, or exposing a partial signature while the
secret owner remains reusable.

## Context

M.6 requires persist-before-exposure, one-shot nonces, byte-identical retry,
and fail-closed recovery. M.8 additionally requires the claim signing nonce to
be bound to validated real DOM and Bitcoin anchors. The pinned Bitcoin signing
backend can deterministically reconstruct its in-memory nonce owner from a
32-byte `session_secrand`, but that secret must not be placed in the public
route record, supplied through an argument or environment variable, or logged.

## Decision

F7 uses a dedicated owner-only key store and the SQLite nonce vault together:

1. The key store creates two participant-specific keys from operating-system
   entropy. Its directory is owned by the effective user with exact mode
   `0700`; its immutable key records and retained lock are regular, single-link
   files with exact mode `0600`. Relative opens remain beneath a retained
   directory descriptor and reject symbolic or magic links.
2. Each key record is bound to the route, participant, immutable claim
   continuation, and canonical vault path. A restart must reopen the same key
   record and owner binding. Existing objects with altered type, owner, mode,
   link count, length, binding, identifier, or authentication tag fail closed;
   they are never silently repaired.
3. Before a public nonce is returned, one `BEGIN IMMEDIATE` SQLite transaction
   stores the authenticated encrypted `session_secrand`, its full continuation
   binding, and the exact public nonce, then advances the nonce state. The
   database uses the existing `synchronous=FULL` durability authority.
4. A normal restart decrypts the same owner, reconstructs the pinned backend
   state, and requires a byte-identical public nonce before continuing.
5. The transaction that persists the local partial signature first clears the
   encrypted owner and writes a durable tombstone. Only after that commit may
   the partial leave the vault. Subsequent restarts can retransmit only the
   exact durable public nonce and partial; no secret nonce is reopened.

Crash-interrupted key staging is either authenticated and atomically renamed or
removed. The containing directory is synchronized after create, rename, and
unlink operations. A crash is therefore a restart condition; only authenticated
corruption, an unavailable key, or an impossible durable state selects refund.

## Alternatives considered

1. Preserve the F5 crash-to-refund rule. Rejected because ordinary restart is a
   required F7 path and would unnecessarily discard a valid funded route.
2. Generate a new nonce after restart. Rejected because a changed nonce breaks
   the committed transcript and nonce reuse can expose the signing key.
3. Put the sealing key in the nonce database, command line, environment, or
   route manifest. Rejected because compromise of one public/runtime channel
   would also disclose every persisted nonce owner.
4. Return the partial before clearing the owner. Rejected because a crash after
   exposure would leave a reusable signing nonce.

## Invariants

- Claim nonce ownership is unavailable before real anchors and M.8 validate.
- No public nonce exists without a complete, authenticated durable owner.
- A reservation has exactly one continuation binding and one public nonce.
- An existing key-store object is validated, never permission-repaired.
- Wrong key, changed binding, storage tamper, or backend drift fails closed.
- The encrypted nonce owner is tombstoned in the same durable transaction that
  stores the partial signature and before the partial is returned.
- After tombstone, retry is byte-identical and cannot recover secret material.
- Key bytes, `session_secrand`, partial scalars, adaptor secrets, seeds, and
  credentials never enter logs or public evidence.

## Compatibility and security impact

This is an additive F7 owner boundary. It does not change Bitcoin transaction,
Taproot, MuSig2, sighash, timelock, consensus, or wire encodings. Legacy F5
retains its documented memory-only behavior. F7 gains normal restart recovery
without weakening one-shot nonce custody; authenticated corruption remains a
fail-closed refund condition.

## Required tests

- Key records reopen with identical public identifiers after process restart.
- A different owner binding, wrong key, modified record, wrong mode, symlink,
  hard link, or truncated record is rejected without repair.
- Every prefix before and after staged-key fsync and atomic rename recovers to
  one valid key or safely creates a fresh key before nonce use.
- Every SQLite crash prefix before public-nonce exposure reveals no bytes; a
  committed owner reconstructs the exact pinned-backend public nonce.
- Every crash prefix around partial persistence either retains the unopened
  owner or retains a tombstoned owner plus the exact durable partial, never
  both an exposed partial and a decryptable owner.
- Restart with the durable key store and vault retransmits public nonce and
  partial byte-identically; wrong-key and row tamper fail closed.
- Secret scanning finds no key, nonce, signing share, adaptor scalar, seed, or
  credential in logs, manifests, or evidence.

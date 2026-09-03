# DOM Wallet V3 schema migrations

Date: 2026-07-28

## Transaction broadcast exposure

`transaction_exposure_version` is persisted on `WalletState`; current version
is `1`. `LocalTransactionIntent.exposure` defaults only at deserialization and
is immediately repaired by `migrate_transaction_exposure` before state is
returned to production code. The migration is idempotent and conservative:
legacy submitted/ambiguous/mempool/reorg/failed/confirmed states become at least
`POSSIBLY_RELAYED`, never `NEVER_BROADCAST`. Validation also rejects impossible
current-version lifecycle/exposure pairs, and authenticated load repairs them
conservatively before any reservation can be released.

The migration is performed for normal wallet loads and encrypted backup loads.
It is committed on the next normal atomic generation publication. Existing
envelopes, generation pointers, and metadata versions remain readable. A
legacy serialized record with both the version and per-transaction exposure
fields absent is regression-tested. A crash after writing the next encrypted
generation but before activating its pointer leaves the old generation active;
a complete unpublished generation is authenticated and removed before retry,
while a pointer-only activation is repaired on the next authenticated open.
All temporary generation and metadata filenames are unique, so stale files
from an earlier crash cannot block a later atomic write.

## Transaction expiry

`expires_at_height` is persisted per local intent with a backward-compatible
default. Every newly created/imported/finalized/submitted/retried slate is
validated against the real canonical tip and the explicit 1,440-block maximum
lifetime using checked arithmetic.

## Password authenticator

New wallets store `authentication.envelope`, an authenticated known-plaintext
record bound to wallet metadata. This separates invalid passwords from
authenticated payload corruption without weakening encryption. Legacy wallets
without the record follow the legacy decrypt path once; after successful
authentication the record is written atomically. Malformed authentication data
fails closed and is never treated as a password error.

## Creation and restore staging

Wallet creation uses `.<name>.create-staging`; seed restore uses the existing
`.<name>.seed-restore` checkpoint. Staging directories are mode `0700` on Unix.
Activation uses same-parent atomic rename followed by parent directory fsync.
Interrupted stages are excluded from the catalog. Resume and abort require the
original password and structural validation. Abort removes only the exact
authenticated stage. A restore checkpoint that reached `Complete` before an
activation crash is resumed by publishing that complete stage; it is not
restarted or exposed as a wallet. Writer locks are released before same-parent
directory rename and reacquired on the published wallet, preserving atomic
activation on platforms that prohibit renaming an open directory. No wallet
schema or DOM Core revision changed.

## Updater preference

`automatic-update-preference.json` has `schema_version: 1` and an `enabled`
boolean. It is written to a uniquely named private temporary file, fsynced,
atomically renamed, and followed by parent fsync. Unknown or corrupt versions
use the conservative default without activating an update.

## Compatibility invariants

- Mainnet chain ID, genesis, network magic, consensus, serialization, PoW, and
  monetary constants are unchanged.
- Every DOM Protocol git revision remains pinned to its original exact commit.
- No unsafe Rust or floating dependency revision was introduced.

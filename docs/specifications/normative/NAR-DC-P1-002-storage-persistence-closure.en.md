# NAR-DC-P1-002 — Storage Persistence Closure Record

Status: **PROPOSED / UNSIGNED / NOT YET NORMATIVE**
Project: **DOM Contracts**
Date: **2026-08-05**
Scope: **Phase 1B storage cryptography, persistence codecs, recovery, and local durability only**

> This document has no normative effect until the operator reviews and signs
> these exact bytes with the established Minisign identity and the detached
> signature is verified. Implementations must remain fail-closed for every
> decision introduced here until ratification.

Revision note: the earlier unsigned draft with SHA-256
`1b5af71e4c24f3dbccf96e01e14c1240476f10da34c52a10c3dd1b51408bb539`
is rejected review evidence. It must not be signed, implemented, or cited as a
normative input. Only the final bytes of this revised document are eligible for
operator review and signature.

## 1. Purpose and authority

This erratum closes eight ambiguities left by the signed
`NAR-DC-P1-001 — Omnibus Phase 1 Gap Assignment and Closure Record`:

1. the canonical payload of every `JournalEntryV1` kind;
2. immutable exposure state, version, path, and predecessor identity;
3. the exact `SigningPhaseV1` to artifact-kind mapping;
4. restore record families and the cross-type canonical sort key;
5. root identity, lock binding, and capability-rooted I/O;
6. activation of the authoritative DOM `H_tag` dependency;
7. global `BackupManifestV1` object-envelope semantics; and
8. restore-time vault/master-key lifecycle and atomic activation order.

After ratification, the authority order is:

1. P1-ARCH-002;
2. this signed erratum for the decisions expressly assigned here;
3. signed NAR-DC-P1-001 where it is not refined by this erratum;
4. earlier signed Phase 1 ADRs, NARs, registries, and manifests where they do
   not conflict with the authorities above;
5. the DOM Scriptless Contracts Master Specification v1.0; and
6. implementation and tests.

This document defines local DOM Contracts storage bytes only. It does not
change DOM consensus, an existing DOM transaction or kernel encoding, L1 wire,
P2P, persisted blocks, genesis, chain ID, network magic, PoW, rewards, or fork
choice. It does not authorize budgets, a witness protocol, DOM Wallet
integration, Phase 2, real funds, mainnet, publication, release, or activation.

## 2. Binding architectural invariants

The following P1-ARCH-002 invariants remain non-negotiable:

- DOM Contracts and the ordinary DOM Wallet are independent applications.
- They do not share a seed, key, keystore, database, nonce inventory, signing
  share, permit, controlled output, storage envelope, KDF domain, or root.
- No DOM Contracts crate depends on `dom-wallet-v3`.
- The algorithm families reviewed in Wallet V3 may inform dependency choice,
  but no Wallet source, type, profile name, tag, identifier, or persisted byte
  is imported.
- `dom-adaptor` remains the semantic authority for Scriptless cryptography.
- Mainnet contract funding remains impossible and production remains
  unauthorized.

## 3. Canonical primitives and notation

### 3.1 Integer and byte notation

- `u16_le`, `u32_le`, and `u64_le` are unsigned little-endian integers of
  exactly 2, 4, and 8 bytes.
- `zero_N` is exactly `N` zero bytes.
- `hex_lower(bytes)` is lowercase ASCII hexadecimal with exactly two
  characters per input byte and no prefix.
- A fixed byte array described as nonzero is rejected when every byte is zero.
- Checked increments fail terminally on overflow.
- No native structure layout, Serde, bincode, JSON, CBOR, or architecture-
  dependent length defines canonical bytes.

### 3.2 Authoritative tagged hash

Every `H_tag` operation in this document is exactly:

```text
H_tag(tag, data) =
    DOM_BLAKE2b_256(
        u16_le(len(ASCII(tag))) || ASCII(tag) || data
    )
```

`len(ASCII(tag))` counts bytes and must fit `u16`. Tags are case-sensitive.
There is no key, salt, personalization, BLAKE2b-512 truncation, BLAKE2s,
SHA-256 substitution, or BIP340 doubled-tag construction.

### 3.3 Existing canonical records retained

This erratum retains without byte changes the following NAR-DC-P1-001 records:

- `NonceIdentityV1`: exactly 105 bytes;
- `SessionClaimV1`: exactly 155 bytes;
- `AttemptRecordV1`: exactly 193 bytes;
- `ExposureRecordV1`: exactly `233 + outbound_length` bytes;
- the `JournalEntryV1` outer envelope: exactly `88 + payload_length` bytes;
- `RestoreManifestV1`: exactly 262 bytes; and
- `RestoreCompleteV1`: exactly 98 bytes.

Where this erratum assigns more precise semantics to an existing field, these
semantics replace the ambiguous wording but do not silently change the field's
offset or size.

### 3.4 Complete VaultObjectEnvelopeV1 digest

The registered tag is:

```text
DOM:contracts-vault-object-envelope:v1
```

For plaintext length `p`, the complete envelope is exactly `240 + p` bytes:
the 224-byte authenticated header followed by exactly `p` ciphertext bytes and
the 16-byte ChaCha20-Poly1305 tag. The full envelope digest is exactly:

```text
VaultObjectEnvelopeV1_digest = H_tag(
  "DOM:contracts-vault-object-envelope:v1",
  u32_le(240 + p) || complete_envelope_bytes[0..240+p]
)
```

The `u32_le` length must equal the actual complete-envelope length and must be
checked without overflow before allocation. No path, filename, outer file
length, decoded plaintext, or omitted AEAD tag enters this preimage. This
digest is the only meaning of a `VaultObjectEnvelopeV1` digest in tombstones,
backup indexes, pending indexes, journals, and reports.

The V1 complete lengths are therefore exact:

```text
NonceSecretRecordV1 envelope = 627..=1122 bytes for plaintext 387..=882
TombstoneV1 envelope         = 495 bytes for plaintext 255
BackupManifestV1 envelope    = 470 bytes for plaintext 230
```

## 4. Closed registries and compatibility rules

### 4.1 ArtifactKindV1

```text
0x01 Commitment
0x02 Reveal
0x03 PartialSignature
```

Every other byte is rejected.

### 4.2 SigningPhaseV1 to ArtifactKindV1 mapping

The only valid attempt mappings are:

| SigningPhaseV1 u16 LE | Name | ArtifactKindV1 |
|---:|---|---:|
| `0x0100` | `SigNonceCommit` | `0x01 Commitment` |
| `0x0101` | `SigNonceReveal` | `0x02 Reveal` |
| `0x0103` | `SigPartial` | `0x03 PartialSignature` |

`SigBinding (0x0102)`, `SigAdapt (0x0104)`, and `SigExtract (0x0105)` never open
a Nonce Vault secret record and therefore never appear in `AttemptRecordV1`.
All other phase/artifact pairs fail closed before any secret is opened.

### 4.3 ExposureStateV1

```text
0x01 Persisted
0x02 Authorized
0x03 Spent
```

The only valid transitions are `Persisted -> Authorized -> Spent`. No state is
skipped, overwritten, reversed, or reused.

### 4.4 Exposure sequence registry

For each `NonceIdentityV1`, exactly these exposure sequences exist:

```text
sequence 1 = Commitment
sequence 2 = Reveal
sequence 3 = PartialSignature
```

No fourth V1 sequence exists. An identity may reach a later sequence only after
the preceding sequence has a durable `Spent` version. Strict Phase 1 policy
continues to reject Sponsor execution.

### 4.5 JournalEntryKindV1

The existing registry remains closed:

```text
0x01 Reserve
0x02 ComputationAttempt
0x03 CommitmentPersisted
0x04 ExposureAuthorized
0x05 RevealPersisted
0x06 PartialConsumed
0x07 AbortConsumed
0x08 Burned
0x09 RestoreBegin
0x0a RestoreRecord
0x0b RestoreComplete
0x0c EpochAdvance
```

Every other byte is rejected.

## 5. Immutable exposure identity and predecessor binding

### 5.1 ExposureVersionIdV1

`ExposureVersionIdV1` is exactly 155 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 105 | complete `NonceIdentityV1` |
| 105 | 8 | exposure sequence, `1..=3`, little-endian |
| 113 | 1 | `ExposureStateV1` |
| 114 | 1 | `ArtifactKindV1` |
| 115 | 8 | lifecycle revision, nonzero |
| 123 | 32 | complete `ExposureRecordV1` digest |

The artifact kind must equal the kind assigned to the exposure sequence. The
digest is the 32-byte `exposure_record_digest` already stored at the end of the
referenced `ExposureRecordV1`.

### 5.2 Immutable version construction

For Commitment and Reveal exposure sequences:

1. the `Persisted` version is created after one matching durable attempt;
2. the `Authorized` version repeats every field and every outbound byte of the
   `Persisted` version except `state`, `lifecycle_revision`, and the resulting
   record digest;
3. the `Spent` version repeats every field and every outbound byte of the
   `Authorized` version except `state`, `lifecycle_revision`, and the resulting
   record digest; and
4. each successor lifecycle revision is the checked predecessor revision plus
   one.

The first `Persisted` lifecycle revision is the checked
`AttemptRecordV1.expected_lifecycle_revision + 1`. Creating `Authorized` and
`Spent` therefore consumes two additional revisions. Attempt records do not
themselves consume a lifecycle revision.

PartialSignature has one additional irreversible transition. Let `r` be the
`AttemptRecordV1.expected_lifecycle_revision` of its matching durable attempt.
Its assignments are exact:

```text
PartialSignature Persisted exposure revision = checked(r + 1)
Consumed TombstoneV1 terminal revision       = checked(r + 2)
PartialSignature Authorized exposure revision = checked(r + 3)
PartialSignature Spent exposure revision      = checked(r + 4)
```

The `Consumed` tombstone binds the digest of the `Persisted` partial exposure.
The partial `Persisted -> Authorized` transition therefore advances by two and
is valid only when the exact intervening `Consumed` tombstone at `r + 2` is
durable. The partial `Authorized -> Spent` transition advances by one. No two
`ExposureRecordV1`/`TombstoneV1` state-transition records for an identity may use
the same lifecycle revision. An AttemptRecordV1 only names the expected current
revision and does not consume it.

Only a durable `Spent` exposure may produce an export capability. The `Spent`
record and its journal entry must be durable before capability creation. A
capability is one-shot, opaque, non-cloneable, non-serializable, and cannot be
recreated from caller-supplied bytes. The trusted transport may request a
byte-identical resend by a persisted exposure identifier; it cannot submit
replacement outbound bytes or invoke the signer.

### 5.3 Exposure predecessor identity

An `ExposureAuthorized` journal entry binds one predecessor
`ExposureVersionIdV1` and the complete canonical successor
`ExposureRecordV1`. Validation requires:

- identical nonce identity, exposure sequence, artifact kind,
  operation-input digest, outbound digest, outbound length, and outbound bytes;
- successor state exactly predecessor state plus one;
- successor lifecycle revision exactly predecessor revision plus one, except
  that PartialSignature `Persisted -> Authorized` is exactly predecessor
  revision plus two and requires the intervening tombstone defined in §5.2;
  and
- predecessor record present at its canonical path with the exact digest.

### 5.4 Canonical exposure path

Let:

```text
identity_key = hex_lower(NonceIdentityV1_105)
sequence_name = exposure_sequence as exactly 20 zero-padded decimal digits
state_name = ExposureStateV1 as exactly two lowercase hexadecimal digits
digest_name = hex_lower(exposure_record_digest_32)
```

The only canonical path relative to the retained exposure-directory capability
is:

```text
<identity_key>/<sequence_name>/<state_name>-<digest_name>.exposure
```

All three directories are created relative to retained capabilities. Files use
create-no-clobber semantics. A second file for the same identity, sequence, and
state, even with another digest, is a permanent conflict and quarantines the
vault. A missing predecessor, duplicate version, changed bytes, symlink,
unexpected file type, or noncanonical name quarantines the vault.

### 5.5 Canonical attempt path

The only canonical attempt path relative to the retained attempt-directory
capability is:

```text
<identity_key>/<expected_revision_20_decimal>-<artifact_kind_2_hex>.attempt
```

There is exactly one attempt for an identity and expected lifecycle revision.
It is create-no-clobber and retained permanently. If an attempt is durable and
its matching `Persisted` exposure is absent or incomplete after recovery, the
identity is irreversibly burned. The attempt is never deleted to permit retry.

### 5.6 Live export-capability binding

`ExposureExportCapabilityV1<'authority>` is an in-process, one-shot authority;
it has no canonical byte encoding. Its private state is bound to all of:

- one live `StoreAuthorityV1` value that owns the retained root-directory and
  lock-file handles;
- the verified `StoreRootIdentityV1` digest;
- the verified `StoreLockIdentityV1` digest and the same live exclusive lock
  acquisition, not a later open of the lock pathname;
- the exact active vault ID, nonce epoch, generation, and
  `ActiveVaultGenerationV1` digest;
- the complete 155-byte `ExposureVersionIdV1` of one `Spent` exposure; and
- the exact journal sequence and journal-entry digest that made that exposure
  durably `Spent`.

The capability has a lifetime tied to the live authority, has private fields
and no public constructor, and is not `Clone`, `Copy`, `Debug`, `Display`,
`Serialize`, `Deserialize`, or convertible to or from bytes. Creation occurs
only while the retained exclusive lock is held, after verification of the
exact canonical exposure file and journal projection. Consumption by value
revalidates the same retained handles, root/lock identities, active-generation
digest, exposure-version ID, and journal head while that same lock remains
held. It then reads and sends only the outbound bytes in that exact persisted
exposure. It cannot accept substitute bytes, another exposure ID, another
vault, another root handle, or another lock acquisition.

The capability is never persisted and dies with the process. After restart,
the trusted store may create a new one only by reopening and fully validating
the canonical `Spent` exposure under a newly established live authority. A
caller-provided identifier is only a lookup request and never authorization.
The store, not the caller, selects the exact verified exposure version. No
capability can authorize more than one send attempt; byte-identical resend
requires a separately constructed capability after the same complete durable
validation.

## 6. Canonical journal payloads

### 6.1 Outer envelope

`JournalEntryV1` remains:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `DOMNVJR1` |
| 8 | 2 | version `1` little-endian |
| 10 | 8 | global sequence, starting at 1 |
| 18 | 32 | predecessor journal digest; zero only at sequence 1 |
| 50 | 1 | `JournalEntryKindV1` |
| 51 | 1 | flags, exactly zero |
| 52 | 4 | payload length little-endian, `0..=16384` |
| 56 | variable | payload assigned below |
| `56+len` | 32 | journal entry digest |

The entry digest is:

```text
H_tag(
  "DOM:contracts-vault-journal-entry:v1",
  all_entry_bytes_before_entry_digest
)
```

### 6.2 Reserve payload — kind `0x01`

Payload length is exactly 155 bytes and the payload is the complete canonical
`SessionClaimV1`. The claim revision is exactly 1. The first journal entry for
that identity must be `Reserve`.

### 6.3 ComputationAttempt payload — kind `0x02`

Payload length is exactly 193 bytes and the payload is the complete canonical
`AttemptRecordV1`. Its phase/artifact pair must satisfy §4.2. It must reference
the current lifecycle revision and must be the first attempt at that revision.

### 6.4 CommitmentPersisted payload — kind `0x03`

Payload length is exactly `233 + outbound_length`. The payload is one complete
canonical `ExposureRecordV1` with:

```text
state = Persisted
artifact kind = Commitment
exposure sequence = 1
outbound_length = 1..=4096
```

It must match the immediately preceding unconsumed Commitment attempt for the
same identity and expected revision.

### 6.5 ExposureAuthorized payload — kind `0x04`

Payload length is exactly `159 + successor_record_length`, where
`successor_record_length = 233 + outbound_length`:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 155 | predecessor `ExposureVersionIdV1` |
| 155 | 4 | successor record length, little-endian |
| 159 | variable | complete canonical successor `ExposureRecordV1` |

The transition must be either `Persisted -> Authorized` or
`Authorized -> Spent` and must satisfy §5.3. This entry kind is used for all
three artifact kinds. No export capability exists until the `Spent` successor
and this journal entry are durable.

### 6.6 RevealPersisted payload — kind `0x05`

Payload length is exactly `233 + outbound_length`. The payload is one complete
canonical `ExposureRecordV1` with:

```text
state = Persisted
artifact kind = Reveal
exposure sequence = 2
outbound_length = 1..=4096
```

The Commitment exposure for the same identity must already be `Spent`. The
record must match the immediately preceding unconsumed Reveal attempt.

### 6.7 TombstoneV1

`TombstoneV1` is exactly 255 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `DOMNVTS1` |
| 8 | 2 | version `1` little-endian |
| 10 | 105 | complete `NonceIdentityV1` |
| 115 | 1 | terminal reason: `1 Consumed`, `2 AbortConsumed`, `3 Burned` |
| 116 | 3 | reserved, all zero |
| 119 | 8 | terminal lifecycle revision, nonzero |
| 127 | 32 | triggering attempt digest, or zero when no attempt existed |
| 159 | 32 | related exposure-record digest, or zero when none existed |
| 191 | 32 | deleted secret-object complete envelope digest per §3.4, or allowed zero |
| 223 | 32 | tombstone digest |

The registered tag is:

```text
DOM:contracts-vault-tombstone:v1
```

The tombstone digest is:

```text
H_tag("DOM:contracts-vault-tombstone:v1", bytes[0..223])
```

`Consumed` requires nonzero attempt, exposure, and deleted-secret digests. For
PartialSignature it has the exact revision and exposure binding assigned in
§5.2. `AbortConsumed` and ordinary non-restore `Burned` use only the exact
current-stage selections and zero rules in §6.7.1; they do not summarize every
historical object. Stale lower-revision attempts and exposures remain committed
as journal/record-set evidence and are not copied into the singular attempt or
exposure digest field of the tombstone. A restore `Burned` tombstone uses §7.4.
Recovery derives every field from verified durable inventory; a caller never
supplies these claims.

#### 6.7.1 AbortConsumed and ordinary Burned evidence selection

This subsection applies to `AbortConsumed` and to `Burned` created outside a
restore. It does not alter the collision-free PartialSignature `Consumed`
assignments in §5.2 or restore `Burn` in §7.4.

Under the same retained root/lock authority, define:

```text
current_state_revision = max(
  SessionClaimV1.claim_revision,
  every ExposureRecordV1.lifecycle_revision,
  active NonceSecretRecordV1 object-header revision
)

terminal_revision = checked(current_state_revision + 1)
```

An AttemptRecordV1 names an expected revision and does not itself advance the
state. Attempts with expected revision greater than `current_state_revision`
are invalid and quarantine. The triggering attempt digest is the digest of the
attempt whose expected revision equals `current_state_revision`. It is zero
only when no such attempt exists. If more than one candidate exists, all
complete canonical bytes and digests must be identical; otherwise the identity
quarantines. Identical duplicates are still a storage-layout violation and
quarantine after their one common digest has been selected for evidence.

The related exposure digest is the digest of the exposure with the greatest
lifecycle revision. It is zero only when no exposure exists. Ties require
byte-identical complete canonical records and one common digest; any differing
tie quarantines.

The deleted secret-object envelope digest is the §3.4 digest of the one exact
active nonce-secret envelope that is scheduled for durable deletion. It is
zero only when no active secret-object path exists. A missing file claimed by
metadata, more than one candidate, a wrong identity/header, failed AEAD,
noncanonical length, or digest disagreement quarantines. Stale lower-revision
attempts/exposures remain evidence but are never substituted for the exact
current-stage selections above.

`AbortConsumed` is used for an authenticated operator/protocol abort. Ordinary
`Burned` is used for crash ambiguity, invalid incomplete state, or recovery
where continuation is prohibited. Both use the same exact evidence-selection
algorithm and terminal revision. The reason byte is their only semantic
difference. If no claim, exposure, or active secret exists, there is no valid
identity to terminate and tombstone construction is rejected.

When encrypted, a tombstone uses key role `0x02`, schema version `0x0001`,
record kind `0x02`, its exact nonzero identity fields, purpose, nonce epoch and
revision, and its tombstone digest as `bound_digest`. Its plaintext length is
exactly 255 and its complete `VaultObjectEnvelopeV1` length is exactly 495.

There is exactly one authoritative terminal `TombstoneV1` per
`NonceIdentityV1` in an active generation and in its canonical record set,
regardless of terminal reason. Its only canonical path relative to that
generation's retained tombstone-directory capability is:

```text
<identity_key>.tombstone
```

The file uses create-no-clobber and is never replaced, renamed, deleted, or
supplemented by a second tombstone. A second tombstone for the identity,
including a byte-identical one at another path, quarantines the vault. Once a
tombstone exists, no Abort, Burn, restore, or migration may create another one.
In an active generation this file contains the one complete 495-byte encrypted
`VaultObjectEnvelopeV1`, whose authenticated plaintext is the canonical
255-byte tombstone above. Journal and restore payloads carry the canonical
tombstone bytes/digest, not the encrypted envelope bytes.
An immutable predecessor-generation snapshot retained as restore evidence is
never active and does not create a second authoritative tombstone.

### 6.8 PartialConsumed payload — kind `0x06`

Payload length is exactly `492 + partial_outbound_length`:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | persisted partial exposure length, little-endian; exactly `233 + partial_outbound_length` |
| 4 | variable | complete PartialSignature `ExposureRecordV1` in `Persisted` state, sequence 3 |
| `4+record_len` | 255 | complete `TombstoneV1` with terminal reason `Consumed` |

The Reveal exposure must already be `Spent`. Let `r` be the expected lifecycle
revision in the immediately preceding unconsumed PartialSignature attempt. The
partial record is `Persisted` at `r + 1`; the included `Consumed` tombstone is
at `r + 2` and binds that partial record digest; the triggering-attempt and
deleted-secret-envelope digests are exact and nonzero. The encrypted nonce
secret object is irreversibly removed, the tombstone is durable, and this
journal entry is durable before the partial exposure may advance to
`Authorized` at `r + 3`. The partial reaches `Spent` at `r + 4` through a
second `ExposureAuthorized` entry before export.

### 6.9 AbortConsumed payload — kind `0x07`

Payload length is exactly 255 bytes and is one canonical `TombstoneV1` with
terminal reason `AbortConsumed`. Abort never removes a session claim, attempt,
exposure, journal entry, or consumed budget, and never restores an earlier
state. It is forbidden when any tombstone already exists for the identity.

### 6.10 Burned payload — kind `0x08`

Payload length is exactly 255 bytes and is one canonical `TombstoneV1` with
terminal reason `Burned`. Orphan-claim recovery uses terminal lifecycle
revision 2. Other ordinary burns use the exact revision and evidence selection
in §6.7.1. Burn is forbidden when any tombstone already exists for the
identity.

### 6.10.1 Durable secret-deletion transaction

Partial consumption, abort, and ordinary burn use one non-bypassable order.
The retained exclusive lock is held throughout. The tombstone staging name is:

```text
.<identity_key>-<hex_lower(tombstone_digest_32)>.tombstone.staging
```

The exact order is:

1. Select the operation branch. PartialConsumed requires exactly one valid
   active nonce-secret envelope; absence or ambiguity quarantines. Verify it
   through its retained handle, authenticate it, retain its complete bytes in
   an owned zeroizing buffer, and compute the §3.4 digest. Abort/Burn instead
   execute §6.7.1. When that selection has one active secret, perform the same
   verification/retention; when it validly has none (including an orphan
   claim), set the deleted-secret digest to zero and create no secret handle or
   buffer. No unlink, export, or capability exists yet.
2. For PartialSignature, verify the durable attempt and persist the exact
   `Persisted` partial exposure at `r + 1` with create-no-clobber, synchronize
   the file and exposure directory, reopen it, and verify every byte/digest.
   The signer is never invoked again for this attempt. Abort/Burn skip this
   step and use §6.7.1 evidence.
3. Construct the exact canonical tombstone, including the retained complete
   secret-envelope digest or the exact allowed zero from step 1. Encrypt it
   under the current vault key with fresh internal instance ID/nonce.
   Create-no-clobber the staging file, synchronize
   it, reopen and verify it, atomically rename-no-replace it to the one canonical
   tombstone path, and synchronize the tombstone directory. In the
   secret-present branch the secret file and retained handle still exist; in
   the no-secret branch neither exists.
4. Append exactly one journal entry: `PartialConsumed` containing the already
   persisted partial and `Consumed` tombstone, `AbortConsumed`, or `Burned`.
   Synchronize the journal file and journal directory; reopen and verify the
   complete chain through the new head.
5. Only after the canonical tombstone and journal projection are durable, the
   secret-present branch unlinks the nonce-secret path through its retained
   parent-directory capability, synchronizes that directory, and proves
   absence. The valid no-secret branch skips unlink and its directory sync
   because no such path/handle exists. Close and zeroize every retained buffer.
6. Reopen and verify the tombstone, journal, required absence of any secret
   path, and unchanged budget/session claim. Only then may a partial proceed to
   `Authorized`; abort/burn returns terminal success without any capability.

From the instant the canonical tombstone appears in step 3, every signing/open
route rejects the identity even while the old secret inode still exists. The
tombstone is therefore the durable deny authority; unlink is irreversible
physical cleanup, not the security transition.

Crash recovery is exact:

- before the partial exposure is durable, recovery burns without invoking the
  signer;
- after the partial exposure but before a canonical tombstone, recovery uses
  the byte-identical persisted partial and retained secret-envelope digest to
  finish the same `Consumed` transaction without recomputation;
- after a canonical tombstone but before its journal entry, recovery verifies
  that exact tombstone and appends only the uniquely determined journal entry;
- after the journal entry but before a durably synchronized unlink, recovery
  only repeats unlink/synchronization for the secret-present branch if the
  exact old path remains; the valid no-secret branch performs no unlink; and
- after durable unlink, recovery verifies absence and never recreates a secret
  file, tombstone, journal entry, budget, session ID, partial, or capability.

At any prefix, missing retained bytes, changed digests, duplicate paths,
ambiguous journal projection, or non-identical persisted partial causes
quarantine rather than reconstruction. Staging without the canonical rename is
not a tombstone and is never trusted; it remains fail-closed evidence for
operator recovery.

### 6.11 RestoreBegin payload — kind `0x09`

Payload length is exactly 262 bytes and is the complete canonical
`RestoreManifestV1`.

### 6.12 RestoreRecord payload — kind `0x0a`

`RestoreRecordPayloadV1` is exactly 220 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 105 | complete `NonceIdentityV1` |
| 105 | 1 | current-target terminal family: `0` absent or `0x04 TombstoneV1` |
| 106 | 4 | current-target tombstone length: `0` or exactly `255` |
| 110 | 32 | current-target tombstone digest, zero iff absent |
| 142 | 1 | source-backup terminal family: `0` absent or `0x04 TombstoneV1` |
| 143 | 4 | source-backup tombstone length: `0` or exactly `255` |
| 147 | 32 | source-backup tombstone digest, zero iff absent |
| 179 | 1 | result family, exactly `0x04 TombstoneV1` |
| 180 | 4 | result canonical length, exactly `255` |
| 184 | 32 | exact result tombstone digest, nonzero |
| 216 | 1 | action: `1 PreserveTerminal`, `2 Burn` |
| 217 | 3 | reserved, all zero |

The record-family registry is in §7.1. Each digest is the complete canonical
tombstone digest. Exactly one `RestoreRecord` exists for each identity in the
union of the verified current and source record sets, sorted by complete
`NonceIdentityV1` bytes. `PreserveTerminal` has the exact semantics in §7.4 and
its result is the allowed terminal tombstone byte for byte. `Burn` always
creates the exact new `Burned` tombstone assigned by §7.4. A RestoreRecord never
returns a SessionClaim, Attempt, Exposure, or active nonce secret.

### 6.13 RestoreComplete payload — kind `0x0b`

The field called `successor_journal_head_digest` in NAR-DC-P1-001 is clarified
as the **pre-complete journal head digest**. It is the digest of the immediately
preceding `EpochAdvance` journal entry. The `EpochAdvance` payload commits only
the already-computable `VaultGenerationCoreV1` digest, never an active record
or final journal head.

The complete payload is exactly 130 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 98 | complete canonical `RestoreCompleteV1` |
| 98 | 32 | full completion digest |

The full completion digest is:

```text
H_tag(
  "DOM:contracts-vault-restore-complete:v1",
  RestoreCompleteV1.bytes[0..90]
)
```

`RestoreCompleteV1.bytes[90..98]` is exactly the first eight bytes of that full
digest. The `RestoreComplete` journal entry digest containing this payload is
then computed and becomes the final successor journal head. Only after that
digest exists is `ActiveVaultGenerationV1` constructed. No earlier object
contains its digest.

### 6.14 EpochAdvance payload — kind `0x0c`

`EpochAdvancePayloadV1` is exactly 176 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 32 | contract wallet ID |
| 32 | 32 | predecessor vault ID |
| 64 | 32 | successor vault ID |
| 96 | 8 | predecessor nonce epoch |
| 104 | 8 | successor nonce epoch |
| 112 | 8 | predecessor vault generation |
| 120 | 8 | successor vault generation |
| 128 | 16 | restore transaction ID |
| 144 | 32 | successor `VaultGenerationCoreV1` digest |

Vault IDs are distinct and nonzero. Successor epoch and generation are exact
checked increments above the maximum verified local/source values assigned by
the restore policy. This payload is emitted after all `RestoreRecord` entries
and before `RestoreComplete`. Its core digest is computed before any successor
journal entry and cannot depend on a journal sequence, journal head,
`RestoreComplete`, active-generation record, or active-generation digest.

### 6.15 Journal order and completeness

For a normal artifact, journal order is:

```text
ComputationAttempt
artifact Persisted entry
ExposureAuthorized (Persisted -> Authorized)
ExposureAuthorized (Authorized -> Spent)
```

For a partial signature, the artifact Persisted entry is `PartialConsumed` and
already commits the irreversible tombstone and secret deletion.

Restore order is exactly:

```text
RestoreBegin
RestoreRecord (one per identity in the canonical union, in identity order)
EpochAdvance
RestoreComplete
```

Every sequence from 1 through the active head exists once. Missing, duplicate,
reordered, extended, unknown, conflicting, or wrong-predecessor entries
quarantine the vault. V1 has no compaction, deletion, or renumbering.

## 7. Restore record families and canonical set

### 7.1 RestoreRecordFamilyV1

```text
0x01 SessionClaimV1
0x02 AttemptRecordV1
0x03 ExposureRecordV1
0x04 TombstoneV1
```

Lifecycle summaries are caches and are not restore authority. Journal entries,
root/lock identities, active-generation records, master-key envelopes,
`BackupManifestV1`, and restore transaction records are verified separately and
are not items in the nonce record set. Nonce secret ciphertext is never a
restore record.

### 7.2 Canonical RestoreRecordKeyV1

The cross-type sort key is exactly 155 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 105 | complete `NonceIdentityV1` |
| 105 | 1 | `RestoreRecordFamilyV1` |
| 106 | 8 | subtype sequence |
| 114 | 1 | subtype version/state |
| 115 | 8 | lifecycle or claim revision |
| 123 | 32 | full canonical record digest |

Family-specific assignments are:

| Family | subtype sequence | subtype version/state | revision | digest |
|---|---:|---:|---:|---|
| SessionClaim | 0 | 0 | claim revision, exactly 1 | claim digest |
| Attempt | expected lifecycle revision | artifact kind | expected lifecycle revision | attempt digest |
| Exposure | exposure sequence | exposure state | lifecycle revision | exposure-record digest |
| Tombstone | 0 | terminal reason | terminal lifecycle revision | tombstone digest |

Sort complete keys as unsigned byte strings in ascending lexicographic order.
Duplicate keys, duplicate family/state versions, two records for one exposure
state, or two session claims for one session ID quarantine the snapshot.

### 7.3 Canonical record set bytes

For each sorted item encode:

```text
RestoreRecordKeyV1_155 ||
record_length_u32_le ||
complete_canonical_record_bytes
```

The record-set digest is:

```text
H_tag(
  "DOM:contracts-vault-record-set:v1",
  record_count_u32_le || concatenated_sorted_items
)
```

`record_count` counts items, not identities. The count is bounded by the
validated backup policy before allocation. No unrecognized file or trailing
object is ignored.

### 7.4 Exact restore terminal projection

Reconciliation groups the current and source canonical record sets by complete
`NonceIdentityV1`. There is exactly one output tombstone and one
`RestoreRecordPayloadV1` for every identity in the union.

`PreserveTerminal` is permitted only under one of these exhaustive cases:

1. exactly one side has one verified terminal tombstone and the other side has
   no tombstone; or
2. both sides have one byte-identical verified terminal tombstone.

Any nonterminal records on the other side are dominated by the terminal state.
The result family is `0x04`, length is 255, and result bytes and digest are
exactly the selected existing tombstone. Two differing tombstones, more than
one tombstone on either side, an invalid tombstone, or a terminal-reason
conflict quarantines the restore; it is never converted to `Burn`.

The successor generation encrypts the selected canonical tombstone under the
fresh successor master key with a fresh object instance ID and AEAD nonce.
`PreserveTerminal` requires byte identity of the 255-byte canonical tombstone
and its digest; it does not copy a predecessor encrypted envelope across vault
IDs or master keys.

`Burn` is required when neither side has a tombstone. It creates exactly one
new `TombstoneV1` with terminal reason `3 Burned` and:

```text
terminal revision = checked(max_verified_revision_for_identity + 1)
triggering attempt digest = unique highest-revision attempt digest, else zero
related exposure digest = unique highest-revision exposure digest, else zero
deleted secret-object envelope digest = verified active-target secret envelope
                                        digest if one was durably deleted,
                                        else zero
```

`max_verified_revision_for_identity` is the greatest claim revision, expected
attempt revision, exposure lifecycle revision, or active-target secret-record
revision found in either fully authenticated record set. A tie at the greatest
attempt or exposure revision is unique only when all tied canonical bytes and
digests are identical; otherwise the corresponding evidence digest is zero.
V1 source backups contain no nonce secret ciphertext. Any such extra object is
an invalid backup and quarantines restore before reconciliation. It is never
treated as a deleted active-target secret. The current and source
manifest/record-set digests commit the complete ambiguous lifecycle input.
Overflow quarantines the restore.

The successor generation likewise encrypts the newly constructed Burned
tombstone under the fresh successor master key with a fresh object instance ID
and AEAD nonce.

The new Burned tombstone is written at the single canonical tombstone path in
§6.7. No source or current SessionClaim, Attempt, Exposure, or secret object is
copied into the successor active record namespace. Lifetime session-claim
identities remain in the append-only journal evidence, while the successor
canonical active record set contains exactly one terminal tombstone for each
reconciled identity.

## 8. Root identity, lock binding, and capability-rooted I/O

### 8.1 Registered tags

```text
DOM:contracts-store-root-identity:v1
DOM:contracts-store-lock-identity:v1
DOM:contracts-vault-generation-core:v1
DOM:contracts-vault-active-generation:v1
DOM:contracts-vault-master-envelope:v1
```

### 8.2 StoreRootIdentityV1

At independent DOM Contracts store creation, the OS CSPRNG generates a nonzero
32-byte `store_root_id` and a nonzero 16-byte `lock_instance_id`. They are
independent of every DOM Wallet value, seed, key, contract key, vault ID, and
session ID.

`StoreRootIdentityV1` is exactly 122 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `DOMNVRI1` |
| 8 | 2 | version `1` little-endian |
| 10 | 32 | contract wallet ID |
| 42 | 32 | store root ID |
| 74 | 16 | lock instance ID |
| 90 | 32 | root identity digest |

The digest is:

```text
H_tag("DOM:contracts-store-root-identity:v1", bytes[0..90])
```

This record is created once and never rewritten by password change, vault
restore, or vault generation change.

### 8.3 StoreLockIdentityV1

The lock file contains exactly 122 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `DOMNVLK1` |
| 8 | 2 | version `1` little-endian |
| 10 | 32 | contract wallet ID |
| 42 | 32 | store root ID |
| 74 | 16 | lock instance ID |
| 90 | 32 | lock identity digest |

The digest is:

```text
H_tag("DOM:contracts-store-lock-identity:v1", bytes[0..90])
```

All three identifiers must match `StoreRootIdentityV1` exactly.

### 8.4 VaultGenerationCoreV1

`VaultGenerationCoreV1` contains every successor-generation field that can be
known before the successor journal is built. It is exactly 186 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `DOMNVGC1` |
| 8 | 2 | version `1` little-endian |
| 10 | 32 | contract wallet ID |
| 42 | 32 | store root ID |
| 74 | 32 | successor vault ID |
| 106 | 8 | successor nonce epoch |
| 114 | 8 | successor vault generation |
| 122 | 32 | successor master-key envelope digest |
| 154 | 32 | generation-core digest |

The generation-core digest is:

```text
H_tag("DOM:contracts-vault-generation-core:v1", bytes[0..154])
```

The core contains no journal sequence, journal head, completion digest,
active-generation digest, or pointer path. It is immutable once the first
successor journal entry is encoded.

### 8.5 ActiveVaultGenerationV1

`ActiveVaultGenerationV1` is exactly 226 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `DOMNVAG1` |
| 8 | 2 | version `1` little-endian |
| 10 | 32 | contract wallet ID |
| 42 | 32 | store root ID |
| 74 | 32 | active vault ID |
| 106 | 8 | active nonce epoch |
| 114 | 8 | active vault generation, starting at 1 |
| 122 | 32 | master-key envelope digest |
| 154 | 8 | active journal sequence |
| 162 | 32 | active journal head digest |
| 194 | 32 | active-generation digest |

The master-key envelope digest is:

```text
H_tag(
  "DOM:contracts-vault-master-envelope:v1",
  complete_VaultMasterKeyEnvelopeV1_182
)
```

The active-generation digest is:

```text
H_tag("DOM:contracts-vault-active-generation:v1", bytes[0..194])
```

Validation reconstructs `VaultGenerationCoreV1.bytes[10..154]` from
`ActiveVaultGenerationV1.bytes[10..154]`, prepends the core magic/version, and
recomputes the core digest. It must equal the digest in the unique
`EpochAdvance` payload. The active journal sequence and head must identify the
following `RestoreComplete` entry. The active-generation digest is therefore
the final value in this strictly sequential construction:

```text
generation core digest
  -> EpochAdvance journal-entry digest (pre-complete head)
  -> RestoreComplete digest and journal-entry digest (final head)
  -> ActiveVaultGenerationV1 digest
```

No arrow points backward and no digest preimage contains itself, directly or
transitively.

### 8.6 Capability and lock rules

1. Store creation uses create-no-clobber for the root, root identity, and lock.
2. Store open obtains a retained directory capability. Every child open,
   create, rename, link, unlink, metadata read, and directory synchronization is
   relative to a retained root or child-directory capability.
3. Normal open never uses `create` for the lock. It opens the existing lock
   without following symlinks, verifies a regular file of exactly 122 bytes,
   acquires the exclusive lock on that retained file handle, and verifies its
   content against the retained root identity.
4. The same retained lock handle, protected by an in-process mutex, serializes
   every state transition. Opening the lock pathname again per operation is
   forbidden.
5. After locking, the implementation revalidates opened-handle metadata and all
   identity bytes. Path metadata obtained before open is never trusted as the
   authority for the opened object.
6. Symlinks, hard-link aliases outside the root policy, devices, sockets,
   FIFOs, and unexpected file types are rejected.
7. On Unix, root/subdirectories are owner-only and regular sensitive files are
   mode `0600`; on non-Unix systems the implementation applies the closest
   owner-only ACL supported by the reviewed capability library. Platform tests
   must prove the actual behavior.
8. Application code adds no unsafe block. The capability library and its exact
   feature graph require dependency and license review.

These rules prevent a live pathname replacement from redirecting an already
opened store. They cannot detect replacement of the complete authentic root by
an older authentic copy before process start. That guarantee still requires a
separately authorized monotonic external anchor and is not claimed here.

## 9. Authoritative H_tag dependency activation

### 9.1 Production dependency rule

Production storage digest verification activates only when DOM Contracts is
pinned to a full immutable public DOM revision that contains both:

- the reviewed `dom-adaptor` API required by Phase 1; and
- the authoritative `dom_crypto::blake2b_256_tagged` implementation with the
  framing in §3.2.

Both dependencies must resolve to the same full DOM Git revision. The only
production wrapper is a narrow DOM Contracts function that delegates every
`H_tag` call to that authoritative backend without reimplementation,
normalization, fallback, feature-selected alternative, or generic BLAKE2
instantiation in the Store.

Before the public pin exists:

- production creation/open/signing/export remains unavailable;
- experimental old formats remain quarantined;
- pure structural parsers may reject malformed fixed fields but cannot mark a
  digest-bearing record authenticated or production-valid; and
- a deterministic independent reference implementation may exist only in a
  non-publishable test/evidence graph and is never selected by a production
  feature.

Cargo features are not an access-control boundary. No offline mode, cached-only
revision, path dependency, sibling worktree, `[patch]`, or Wallet hash helper
activates production.

### 9.2 Complete tag additions assigned by this erratum

```text
DOM:contracts-vault-tombstone:v1
DOM:contracts-vault-object-envelope:v1
DOM:contracts-vault-backup-manifest:v1
DOM:contracts-vault-backup-bundle:v1
DOM:contracts-store-root-identity:v1
DOM:contracts-store-lock-identity:v1
DOM:contracts-vault-generation-core:v1
DOM:contracts-vault-active-generation:v1
DOM:contracts-vault-master-envelope:v1
DOM:contracts-vault-tombstone-envelope-set:v1
DOM:contracts-vault-restore-pending-index:v1
DOM:contracts-vault-restore-only-root:v1
```

All other storage tags referenced here retain their exact NAR-DC-P1-001 bytes.

## 10. Global BackupManifestV1 envelope semantics

### 10.1 BackupManifestV1 plaintext

`BackupManifestV1` is exactly 230 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `DOMNVBM1` |
| 8 | 2 | version `1` little-endian |
| 10 | 32 | contract wallet ID |
| 42 | 32 | source vault ID |
| 74 | 32 | fresh nonzero backup ID, distinct from all wallet/vault/backup IDs |
| 106 | 8 | source nonce epoch |
| 114 | 8 | source journal sequence |
| 122 | 32 | source journal head digest |
| 154 | 4 | canonical nonce-record count |
| 158 | 32 | canonical nonce record-set digest |
| 190 | 8 | backup generation, nonzero checked monotonic counter |
| 198 | 32 | backup manifest digest |

The digest is:

```text
H_tag("DOM:contracts-vault-backup-manifest:v1", bytes[0..198])
```

The backup contains the complete verified journal through the declared head,
the complete canonical nonce record set, the authenticated master-key envelope
needed to open this backup, and no plaintext secret. V1 excludes every nonce
secret ciphertext rather than retaining it as backup evidence; an encountered
secret ciphertext is an unauthorized extra entry and rejects the backup.

### 10.2 VaultObjectEnvelopeV1 global-field exception

For `record_kind = 0x03 BackupManifestV1`, the 224-byte
`VaultObjectEnvelopeV1` header has these exact semantics:

| Header field | Required value |
|---|---|
| key role | `0x03 backup` |
| schema version | `0x0001` |
| contract wallet ID | exact manifest contract wallet ID |
| vault ID | exact manifest source vault ID |
| nonce epoch | exact manifest source nonce epoch, nonzero |
| session ID | exactly `zero_32` |
| participant ID | exactly `zero_32` |
| purpose | exactly `0x00` storage-global sentinel |
| record kind | exactly `0x03` |
| revision | exact backup generation, nonzero |
| bound digest | exact 32-byte backup manifest digest |
| plaintext length | exactly 230 |

The all-zero session, participant, and purpose values are valid only for this
exact combination of key role, schema version, and record kind. They are not a
`PurposeV1` value, never enter Scriptless context, and remain rejected for nonce
secret records and tombstones. Conversely, a `BackupManifestV1` envelope with a
nonzero session, participant, or purpose field is rejected.

Object-key derivation still uses the backup role label and header bytes
`[0..208]`; AEAD AAD still covers the complete 224-byte header. No fabricated
participant, fake contract purpose, Wallet identity, address, or transaction
hash is used.

The complete encrypted manifest object is exactly 470 bytes: 224 header bytes,
230 ciphertext bytes, and one 16-byte AEAD tag. Its digest is the complete
`VaultObjectEnvelopeV1` digest from §3.4.

### 10.3 BackupBundleDigestV1 and canonical paths

The 32-byte backup bundle digest is:

```text
H_tag(
  "DOM:contracts-vault-backup-bundle:v1",
  backup_id_32 ||
  backup_generation_u64_le ||
  backup_master_envelope_digest_32 ||
  backup_manifest_object_envelope_digest_32 ||
  source_journal_sequence_u64_le ||
  source_journal_head_digest_32 ||
  source_record_count_u32_le ||
  source_record_set_digest_32
)
```

The preimage is exactly 180 bytes in the displayed order. The master-envelope
digest uses the tag and full 182-byte preimage in §8.5. The object-envelope
digest uses §3.4.

The immutable completed backup directory is exactly:

```text
backup-<backup_generation_20_decimal>-<hex_lower(backup_id_32)>/
  backup-master-key.envelope
  backup-manifest.object
  backup-bundle.digest
  journal/
    <sequence_20_decimal>-<hex_lower(entry_digest_32)>.journal
  records/
    <hex_lower(RestoreRecordKeyV1_155)>.record
```

`backup-master-key.envelope` is exactly 182 bytes,
`backup-manifest.object` is exactly 470 bytes, and `backup-bundle.digest` is
exactly 32 bytes. Journal files contain complete canonical `JournalEntryV1`
bytes for every sequence from 1 through the manifest head. Record files
contain the complete canonical record named by the key. No other path, file,
symlink, hard-link alias, trailing entry, nonce secret ciphertext, plaintext,
authorization capability, or staging artifact is permitted in a V1 completed
backup.

### 10.4 Exact backup creation and passphrase rewrap

Backup creation never copies the active master-key envelope. Under the same
live retained root/lock authority used by normal Store transitions, it executes
this exact order:

1. Verify the active root/lock identities, active generation, complete journal,
   canonical record set, and active master-key envelope; open the active vault
   master key in a non-cloneable zeroizing value.
2. Receive a separate owned, non-cloneable, zeroizing backup passphrase. It is
   never aliased with the active unlock-passphrase buffer and is never stored.
3. Generate with the OS CSPRNG a fresh nonzero 32-byte backup ID that is
   distinct from the contract wallet ID, source vault ID, and every retained
   backup ID; generate a fresh
   32-byte Argon2 salt, a fresh 12-byte master-envelope AEAD nonce, a fresh
   16-byte manifest `encryption_instance_id`, and a fresh 12-byte manifest AEAD
   nonce. RNG failure is terminal. No caller supplies any of these bytes.
4. Derive a new KEK from the backup passphrase using the exact NAR-DC-P1-001
   Argon2id v0x13 profile and HKDF info with the unchanged contract wallet ID
   and source vault ID. Wrap the same active vault master key into a new
   182-byte `VaultMasterKeyEnvelopeV1` using the fresh salt and nonce. This
   backup envelope never replaces or mutates the active envelope.
5. Assign the checked next completed backup generation, construct the exact
   `BackupManifestV1`, and compute its manifest digest.
6. Encrypt that manifest using the source vault master key, backup role, exact
   global header in §10.2, fresh instance ID/nonce, and complete AEAD AAD.
7. Compute the master-envelope digest, complete manifest-object envelope
   digest, and `BackupBundleDigestV1` in that order.
8. Create with no-clobber the staging directory:

   ```text
   .backup-<backup_generation_20_decimal>-<hex_lower(backup_id_32)>.staging
   ```

   Populate only the exact paths and bytes in §10.3 by copying from verified
   opened handles, never by reopening caller paths.
9. Synchronize each file, each `journal` and `records` directory, and the
   staging directory. Reopen and verify every byte, count, digest, filename,
   and absence of extra entries through retained capabilities.
10. Atomically rename the staging directory to the immutable completed name in
    §10.3 and synchronize its parent directory.
11. Zeroize the backup passphrase, Argon output, KEK, plaintext master-key copy,
    plaintext manifest, and all secret temporaries on every success and error
    path.

An orphan staging directory is never opened as a backup, silently resumed,
overwritten, or deleted. It quarantines that backup ID for operator recovery.
A completed-directory collision is terminal. Restore accepts only a fully
verified completed directory and independently rechecks the backup passphrase
against its contained fresh master-key envelope before decrypting the manifest.

## 11. Restore vault and master-key lifecycle

### 11.1 Stable and rotated identifiers

- `contract_wallet_id` remains stable across restore of the same independent
  DOM Contracts wallet.
- `store_root_id` and `lock_instance_id` remain stable when restoring into an
  existing Contracts store root. A new device creates a new root and therefore
  new values before import.
- Every restore creates a fresh nonzero `vault_id` and a fresh nonzero 32-byte
  `vault_master_key`. The successor nonce epoch is never random: it is exactly
  `checked(max(target_current_epoch, source_backup_epoch) + 1)`, treating the
  absent new-device target epoch as zero. The successor vault generation is
  exactly checked predecessor generation plus one, or exactly 1 for a
  new-device restore-only root.
- The predecessor master key is never reused as the successor master key.
- General master-key rotation outside this restore transaction remains
  unauthorized in Phase 1.

The source backup passphrase and target passphrase are independent owned,
zeroizing inputs. They may contain equal bytes, but one buffer is never aliased
as the other. The source passphrase opens only the authenticated backup. The
target passphrase wraps only the newly generated successor master key.

The exhaustive V1 random-value list is:

- normal Store creation: contract wallet ID (32), initial vault ID (32), vault
  master key (32), store root ID (32), lock instance ID (16), master-envelope
  Argon2 salt (32), and master-envelope AEAD nonce (12);
- every encrypted object creation/reencryption: encryption instance ID (16)
  and object AEAD nonce (12);
- backup creation: backup ID (32), backup master-envelope salt (32), backup
  master-envelope nonce (12), manifest instance ID (16), and manifest nonce
  (12), as a subset of the object rule above stated explicitly;
- every restore: restore transaction ID (16), successor vault ID (32),
  successor vault master key (32), successor master-envelope salt (32), and
  successor master-envelope nonce (12); each successor tombstone also receives
  the object instance ID/nonce above; and
- new-device initialization only: store root ID (32), lock instance ID (16),
  and restore initialization ID (16).

Every listed value is generated internally by the OS CSPRNG; an all-zero value
where its field requires nonzero is rejected before persistence. No other V1
field is random. In particular contract wallet ID on restore is authenticated
from the backup; nonce epoch, vault generation, backup generation, lifecycle
revision, journal sequence, exposure sequence, and every length/discriminant
are deterministic checked values; every digest is deterministically computed.

### 11.2 Preconditions

Restore selects exactly one of two exhaustive, mutually exclusive branches.

**Existing-device branch.** Under a retained target root/lock capability it
must verify:

1. target root and lock identities, one active generation, its master envelope,
   complete journal, and current canonical record set;
2. absence of `restore-only-root.bin`;
3. source backup master envelope, encrypted `BackupManifestV1`, bundle digest,
   journal, record set, every declared digest/count, and source-passphrase
   authentication before manifest decryption;
4. equal nonzero contract wallet IDs; successor vault ID distinct from source
   and active predecessor IDs (source and predecessor may equal); and
5. successor epoch exactly checked max(target, source) plus one and successor
   generation exactly checked active predecessor generation plus one.

**New-device branch.** It must verify only:

1. the exact retained root/lock identities and `RestoreOnlyRootV1` created by
   §11.2.1, with matching contract wallet/root/lock/source-bundle fields;
2. absence of active-generation, generation, journal, record, nonce-secret,
   tombstone, capability, and ordinary-wallet state;
3. the exact authenticated source backup already bound by the restore-only
   record, including source-passphrase authentication and every declared
   byte/count/digest;
4. the exact zero target sentinels in §11.2.1 and a successor vault ID distinct
   from the source vault ID; and
5. successor epoch exactly checked source epoch plus one and successor
   generation exactly 1.

Presence of both active state and a restore-only record, or absence of both,
matches neither branch and quarantines. No check from the existing-device
branch is applied by fabricating target state for a new device. Any failure
leaves the existing target unchanged or the new root restore-only/quarantined.
A source nonce secret ciphertext is an invalid extra entry and is never opened.

### 11.2.1 New-device restore-only root initialization

New-device restore never opens or repurposes an existing directory. Before
creating the destination, the implementation opens the immutable completed
source backup through retained read-only capabilities, verifies its exact
layout and bundle digest, authenticates the operator-provided owned source
backup passphrase against the contained fresh backup master envelope, decrypts
and authenticates the manifest object, and proves that all three contract
wallet IDs agree. That authenticated nonzero value is the stable
`contract_wallet_id`; a value supplied separately by the operator is not
accepted.

`RestoreOnlyRootV1` is exactly 170 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `DOMNVRO1` |
| 8 | 2 | version `1` little-endian |
| 10 | 32 | authenticated stable contract wallet ID |
| 42 | 32 | fresh nonzero store root ID |
| 74 | 16 | fresh nonzero lock instance ID |
| 90 | 32 | verified source `BackupBundleDigestV1` |
| 122 | 16 | fresh nonzero restore initialization ID |
| 138 | 32 | restore-only-root digest |

The digest is:

```text
H_tag("DOM:contracts-vault-restore-only-root:v1", bytes[0..138])
```

Initialization then executes exactly:

1. Prove the destination path does not exist. Any file, directory, symlink,
   mount alias, race-created entry, or previously failed root at that path is a
   collision and stops without modification.
2. Generate independently with the OS CSPRNG a fresh nonzero 32-byte
   `store_root_id`, fresh nonzero 16-byte `lock_instance_id`, and fresh nonzero
   16-byte restore initialization ID.
3. Create the destination directory with create-no-clobber and owner-only
   permissions, retain its directory handle, and create/synchronize exact
   `StoreRootIdentityV1`, `StoreLockIdentityV1`, and
   `restore-only-root.bin`. Synchronize the root's parent directory and root
   directory, then reopen and verify all three records through retained
   handles.
4. Acquire the exclusive lock on the retained lock handle. Prove there is no
   `active-vault-generation`, generation directory, journal, record namespace,
   nonce secret, tombstone, capability, or ordinary-wallet state. The root can
   execute only `resume_restore`/restore initialization.

For this exact state only, `RestoreManifestV1` uses the new-device target
sentinel:

```text
target vault ID = zero_32
target current epoch = 0
target journal sequence = 0
target journal head digest = zero_32
```

`EpochAdvancePayloadV1` likewise uses zero predecessor vault ID, epoch, and
generation. Its successor epoch is exactly
`checked(source_backup_epoch + 1)` and successor generation is exactly 1. The
successor journal begins at sequence 1 with `RestoreBegin` and a zero
predecessor digest; it does not copy a nonexistent target journal. These zero
sentinels are valid only when the exact authenticated restore-only record is
present and no active state exists.

The restore-only record remains in place through the complete pending/activation
transaction. During §11.4 step 15 it is atomically renamed under the
same retained root capability to:

```text
restore-initialized-<hex_lower(restore_initialization_id_16)>.bin
```

The root directory is synchronized and absence of `restore-only-root.bin` is
verified before ordinary open is enabled. A crash or failure leaves the root
restore-only/quarantined and resumable only from its in-root committed state.
It is never deleted, recreated, adopted by another backup, or silently reset.
If `restore-pending` has already been renamed before such a crash, resume
accepts only the one exact `restore-complete-<transaction-id>` directory whose
index matches the live active-generation digest and restore-only record; it may
perform only final revalidation and the marker transition. Any second completed
candidate or mismatch quarantines permanently.

### 11.3 RestorePendingIndexV1 and exact pending tree

`RestorePendingIndexV1` is exactly 530 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `DOMNVPI1` |
| 8 | 2 | version `1` little-endian |
| 10 | 16 | restore transaction ID, nonzero |
| 26 | 32 | contract wallet ID |
| 58 | 32 | `RestoreManifestV1` digest |
| 90 | 32 | source `BackupBundleDigestV1` |
| 122 | 32 | source backup master-envelope digest |
| 154 | 32 | source backup manifest-object envelope digest |
| 186 | 8 | source journal sequence |
| 194 | 32 | source journal head digest |
| 226 | 4 | source record count |
| 230 | 32 | source record-set digest |
| 262 | 32 | successor generation-core digest |
| 294 | 32 | successor master-envelope digest |
| 326 | 8 | successor final journal sequence |
| 334 | 32 | successor final journal head digest |
| 366 | 4 | successor record count |
| 370 | 32 | successor record-set digest |
| 402 | 32 | successor tombstone-envelope-set digest |
| 434 | 32 | successor active-generation digest |
| 466 | 32 | restore-only-root digest for new device, else zero |
| 498 | 32 | pending-index digest |

The pending-index digest is:

```text
H_tag("DOM:contracts-vault-restore-pending-index:v1", bytes[0..498])
```

The restore-only-root field is the exact §11.2.1 digest when the target uses
the new-device sentinel and is all zero for an existing-device restore. Every
other combination is rejected.

Sort successor tombstone envelopes by complete `NonceIdentityV1`. For each,
encode exactly:

```text
NonceIdentityV1_105 || u32_le(495) ||
complete_VaultObjectEnvelopeV1_digest_32
```

The tombstone-envelope-set digest is:

```text
H_tag(
  "DOM:contracts-vault-tombstone-envelope-set:v1",
  tombstone_count_u32_le || concatenated_sorted_entries
)
```

The count must equal successor record count. The identity and authenticated
plaintext digest of each 495-byte envelope must equal the corresponding
canonical tombstone in the successor record set. This additional digest
byte-commits every randomized successor tombstone envelope, including its
instance ID, AEAD nonce, ciphertext, and tag.

Before activation, the exact pending tree is:

```text
restore-pending/
  restore-pending.index
  restore-manifest.bin
  source-backup/
    backup-master-key.envelope
    backup-manifest.object
    backup-bundle.digest
    journal/
      <sequence_20_decimal>-<hex_lower(entry_digest_32)>.journal
    records/
      <hex_lower(RestoreRecordKeyV1_155)>.record
  successor-generation/
    generation-core.bin
    master-key.envelope
    journal/
      <sequence_20_decimal>-<hex_lower(entry_digest_32)>.journal
    tombstones/
      <hex_lower(NonceIdentityV1_105)>.tombstone
  activation/
    active-generation.bin
```

The index, manifest, source-backup bundle, successor core, successor complete
journal, successor terminal record set, successor master envelope, and staged
active record are all written before the staging tree becomes
`restore-pending`. `restore-pending.index` is exactly 530 bytes,
`generation-core.bin` is exactly 186 bytes, `master-key.envelope` is exactly
182 bytes, and `active-generation.bin` is exactly 226 bytes. Every summary in
the index must equal the bytes at these
paths. Each successor tombstone file is the exact 495-byte object envelope in
§6.7; decrypting the sorted envelopes yields exactly the successor canonical
record set committed by the index. Exact source-backup journal/record paths
follow §10.3. No extra path is allowed.

After activation begins, `successor-generation` may exist in exactly one of two
locations: nested under `restore-pending`, or at its immutable final root path.
Likewise `active-generation.bin` may exist in exactly one of two locations:
under `restore-pending/activation`, or as the exact live
`active-vault-generation` root file. The pending index byte-commits both moved
objects, so resume verifies the identical digest at the permitted location.
Missing, duplicate, mixed, or digest-divergent copies quarantine the Store.

### 11.4 Atomic restore order

The exact order is:

1. Acquire and retain the target root lock.
2. Select and verify exactly one exhaustive §11.2 branch without mutating the
   source, active existing target, or restore-only new target.
3. Generate only the random restore values enumerated in §11.1. Compute the
   successor epoch as exact checked maximum-plus-one and the successor
   generation as exact checked predecessor-plus-one (or 1 for restore-only),
   never from randomness. RNG failure is terminal; a random all-zero required
   value is rejected before any persistence.
4. Construct the successor master envelope, `VaultGenerationCoreV1`, exact
   `RestoreManifestV1`, and one terminal result tombstone per union identity.
5. For the existing-device branch, copy the complete verified target journal
   and append `RestoreBegin` after its verified head. For the new-device
   restore-only branch, copy no target journal and encode `RestoreBegin` as
   sequence 1 with the all-zero predecessor digest. In either branch, then
   append one `RestoreRecord` per sorted identity, `EpochAdvance` containing
   the core digest, and `RestoreComplete` containing the resulting pre-complete
   head. Compute the final journal head only after encoding `RestoreComplete`.
6. Construct `ActiveVaultGenerationV1` from the same core fields and that final
   journal sequence/head. Compute its digest last, then construct
   `RestorePendingIndexV1`.
7. Create with no-clobber the staging directory named in §11.5 and populate the
   complete tree in §11.3. Source-backup files are copied only from verified
   opened handles. The successor contains exactly one terminal tombstone per
   union identity and no active or imported nonce secret ciphertext.
8. Synchronize every file, each records/tombstones/journal/activation/source/successor
   directory from leaves upward, and the top-level staging directory. Reopen
   through retained capabilities and verify every byte, path, count, digest,
   and absence of extra entries.
9. Atomically rename the complete staging directory to the single reserved
   `restore-pending` name and synchronize the target root. Its presence
   quarantines ordinary and Scriptless operations. There is no separate
   pending marker or external resume input.
10. Reopen and verify the complete pending tree and index. Atomically rename
    its `successor-generation` directory to the immutable final generation name
    and synchronize the target root.
11. Reopen and verify the final generation against the pending index. Atomically
    rename `restore-pending/activation/active-generation.bin` over the canonical
    root `active-vault-generation` file and synchronize the target root. No
    secret, capability, or export is available yet.
12. Reopen and verify the new live active record, core, master envelope, full
    journal, terminal record set, completion record, and all index commitments.
13. Atomically rename `restore-pending` to the exact retained completed name in
    §11.5 and synchronize the target root.
14. Reopen and revalidate the root/lock identities and complete active
    generation through retained handles. An existing-device restore may end
    quarantine only now.
15. For a new-device root, perform the restore-only marker transition in
    §11.2.1, synchronize and revalidate the root again. Only then may its
    quarantine end.

If death occurs before step 9, the orphan staging tree is never active and
requires fail-closed operator recovery; it is never silently overwritten. If
death occurs from step 9 onward, normal open remains quarantined and
`resume_restore(target_root)` uses only the exact in-root pending index and its
committed objects at the two allowed locations in §11.3. It never accepts a
caller-supplied source backup path, key, source backup passphrase, manifest,
digest, success Boolean, or replacement bytes. It may receive only the owned,
zeroizing target unlock passphrase through the normal Store unlock boundary,
solely to authenticate the exact indexed successor master envelope and
tombstone envelopes; it cannot select or alter any resume byte.

If the active pointer already references the exact indexed successor while
`restore-pending` exists, resume may perform only steps 12–15 after proving all
byte identities. If it references the exact predecessor, resume may continue
from the first incomplete verified step. Any other pointer, location, or state
remains quarantined.

### 11.5 Generation and transaction names

The immutable successor generation directory name is:

```text
generation-<generation_20_decimal>-<hex_lower(vault_id_32)>
```

The complete prepared restore staging name is:

```text
.restore-<hex_lower(restore_transaction_id_16)>.staging
```

The retained completed restore name is:

```text
restore-complete-<hex_lower(restore_transaction_id_16)>
```

Names are exact ASCII, relative to retained directory capabilities, and use
create-no-clobber semantics. Symlinks and unexpected entries quarantine.

### 11.6 Whole-root rollback limitation

The successor journal and active-generation record detect incomplete, mixed,
or locally divergent restore state. They do not prove that an adversary did not
replace the complete authentic root with an older authentic copy before open.
Only a separately authorized monotonic external anchor can provide that
guarantee. This erratum does not define or simulate such an anchor.

## 12. Crash recovery rules

At each persistence boundary, the only valid recovery outcomes are:

1. no public artifact is exported and the ambiguous identity is permanently
   burned; or
2. one exact already persisted `Spent` exposure is available to the trusted
   transport for byte-identical resend.

Specific rules:

- a valid orphan `SessionClaimV1` materializes a `Burned` tombstone at checked
  revision 2 and the claim remains forever;
- an orphan or incomplete attempt burns the identity;
- an exposure without its exact predecessor or journal entry quarantines;
- a record or marker without a complete journal projection quarantines;
- no recovery path accepts replacement output bytes;
- no recovery path invokes nonce derivation, KDF-based nonce generation, or
  partial signing for the affected attempt;
- abort and burn never refund a budget or free a session ID; and
- restore never imports an authorization capability or active secret record.

## 13. Migration and version policy

The following unpublished experimental magics remain development-only and are
not production formats:

```text
DOMNVLR1
DOMNVTM1
DOMNVRS1
DOMNVRE1
DOMNVSC1
DOMNVE01
DOMNVRP1
```

Production open does not silently interpret, extend, or migrate them. In
particular, adding an experimental `PartialAttempted` discriminant to an old
lifecycle file does not implement `AttemptRecordV1`.

The V1 records in NAR-DC-P1-001 plus this erratum are the first production
candidate formats. Any file produced from the ambiguous pre-erratum exposure,
journal payload, restore-set, root, backup, or lifecycle interpretation is also
development-only even if its outer magic matches. It remains quarantined until
a separately reviewed offline migration tool is authorized. Such a tool must
burn every ambiguous slot and can never recreate a capability or nonce secret.

Future incompatible changes require new magics, versions, tags, and explicit
migration authority. Unknown versions, tags, enum values, payload kinds,
lengths, files, or trailing bytes fail closed.

## 14. Required tests and evidence

Ratification freezes inputs but does not approve implementation. At minimum,
the final implementation requires:

### 14.1 Byte and codec evidence

- independent KATs for every fixed offset, length, magic, version, enum, tag,
  digest preimage, HKDF info, AEAD AAD, and path name;
- complete-object envelope-digest KATs covering the exact u32 length prefix,
  224-byte header, ciphertext, and AEAD tag, with mutation of every byte;
- minimum/maximum `ExposureRecordV1` and object-envelope lengths;
- encode/decode byte identity and independent cross-implementation vectors;
- mutation of every field, reserved byte, length byte, digest, predecessor,
  state, role, purpose, nonce, salt, KDF parameter, and AAD byte;
- truncation at every byte boundary and trailing-byte rejection;
- wrong passphrase, wrong IDs, wrong role/schema, and KDF downgrade rejection;
  and
- no allocation based on an unvalidated external length.

### 14.2 State and recovery evidence

- every allowed and forbidden phase/artifact mapping;
- the exact collision-free PartialSignature revision sequence `r+1` through
  `r+4`, including rejection of a missing/wrong tombstone or reused revision;
- every AbortConsumed/ordinary Burned evidence-selection case in §6.7.1,
  including absent/current/stale attempts, exposure ties, secret presence,
  exact zero rules, revision overflow, and every conflict quarantine;
- all exposure state transitions, duplicate versions, missing predecessors,
  wrong paths, and exact resend without signer invocation;
- complete journal sequence, every payload kind, missing/duplicate/reordered
  entries, wrong predecessor, and all valid prefixes;
- restore sets with every record family, cross-type ordering, duplicate keys,
  omitted/injected records, conflicting sessions, changed count, and changed
  digest;
- every `PreserveTerminal` and `Burn` case in §7.4, including proof of exactly
  one terminal tombstone per union identity and quarantine on differing
  terminal tombstones;
- independent digest-DAG tests proving the one-way order core, EpochAdvance,
  RestoreComplete final head, and active-generation digest, with a mutation at
  every edge and no fixed-point or placeholder digest;
- backup creation KATs with independent backup passphrase, fresh ID/salt/two
  nonces/instance ID, exact rewrap, exact 470-byte manifest object, bundle
  digest, atomic rename, wrong-passphrase rejection, and backup staging crash;
- pending-index/path tests covering every field and exact path, moving the
  successor generation and active record through each permitted location, and
  rejecting missing, duplicate, extra, or divergent bytes;
- capability compile-fail and runtime tests proving non-construction,
  non-cloning, one-shot use, exact exposure-version binding, and rejection
  under a different root handle, lock handle/acquisition, vault, generation,
  journal head, or active-record digest;
- new-device tests for authenticated stable identity extraction, absent-path
  create-no-clobber, restore-only record bytes, zero target sentinel, journal
  sequence 1, source-epoch-plus-one, generation 1, path races/collisions,
  every crash prefix, marker finalization, and no normal open before completion;
- deterministic checks proving nonce epoch/generation/revisions/sequences are
  never RNG-derived, plus RNG-failure tests for every random request,
  all-zero rejection for every field designated nonzero, and instrumentation
  proving no other RNG call;
- orphan claim, attempt, exposure, tombstone, journal, staging generation, and
  restore-pending recovery; and
- old development formats quarantined without implicit migration.

### 14.3 Real process-death matrix

Execute real subprocess death immediately before and after:

- create-no-clobber claim, attempt, exposure, tombstone, and journal creation;
- staging create, each write, file synchronization, directory synchronization,
  rename, active-pointer replacement, and root synchronization;
- secret-object open, exact output persistence, secret deletion, tombstone,
  exposure authorization, spent transition, capability creation, and simulated
  export;
- every boundary in §6.10.1: partial persistence, tombstone staging write/fsync,
  rename/directory fsync, journal append/file+directory fsync, secret unlink and
  directory fsync, with exact prefix recovery and zero signer re-entry; and
- every backup step in §10.4 and every restore step in §11.4.

For each cut, record journal head, active generation, session claims, attempts,
exposure versions, secret inventory, tombstones, exact outbound digest, and
post-reopen result. The test must instrument the signer/KDF entry and prove a
zero call count during recovery/resend.

### 14.4 Security and platform evidence

- zeroization, secret-copy, panic/unwind, logging, and constant-time review;
- dependency feature graph, license inventory, and unsafe-code boundary review;
- persistent fuzz targets for all codecs and state projections;
- ASan/libFuzzer evidence with preserved corpus and crash artifacts; and
- real Linux, Windows, and macOS execution for claimed filesystem durability.

A prepared workflow is not platform execution. A local hash chain is not a
remote monotonic anchor. Passing tests is not production authorization.

## 15. Rejected alternatives

- Reusing the DOM Wallet sealer, password type, keystore, database, identity,
  or key domains: rejected by P1-ARCH-002.
- Inventing journal payloads in Rust structs: rejected because persisted bytes
  require one canonical format.
- Overwriting one exposure record as state advances: rejected because it loses
  immutable predecessor evidence and exact resend history.
- Reusing one lifecycle revision for the partial tombstone and partial exposure:
  rejected because it makes the irreversible predecessor order ambiguous.
- Selecting whichever attempt/exposure digest is encountered first for abort or
  burn: rejected because filesystem enumeration cannot define terminal bytes.
- Unlinking a secret before a canonical tombstone and journal durably bind its
  complete envelope digest: rejected because a crash loses reproducible
  deletion evidence; unlinking only after export is rejected as nonce reuse.
- Using enum declaration order, a default variant, `Unknown`, or
  `#[non_exhaustive]`: rejected.
- Treating `SigBinding`, `SigAdapt`, or `SigExtract` as secret-record attempts:
  rejected.
- Fake participant IDs or a fake Scriptless purpose for a global backup:
  rejected; the storage-global zero sentinel is exact and context-limited.
- Retaining the predecessor vault master key after restore: rejected to avoid
  cross-generation secret-object authority.
- Copying the active master-key envelope into a backup: rejected because the
  backup passphrase would not independently authenticate a fresh rewrap.
- Hashing only a VaultObjectEnvelope header or ciphertext: rejected; the one
  complete digest includes length, header, ciphertext, and AEAD tag.
- Making EpochAdvance commit an active-generation digest: rejected because the
  active record commits the final journal head and creates a transitive digest
  cycle.
- Leaving successor-generation resume inputs only in an external source path:
  rejected because post-crash recovery would depend on mutable caller state.
- Adopting an existing directory as a new-device restore root: rejected because
  preexisting authority/state can be confused with authenticated restore
  initialization.
- Generating a random successor nonce epoch: rejected; the only V1 assignment
  is checked maximum authenticated epoch plus one.
- Binding export authority to path strings or serialized permit bytes:
  rejected because it does not prove the same live retained root/lock/vault
  authority.
- Producing a non-tombstone result for Restore `Burn`, modifying an existing
  terminal tombstone under `PreserveTerminal`, or retaining two tombstones for
  one identity: rejected because terminal state must be unique and monotonic.
- Resuming from a caller-selected backup path: rejected because the source can
  change after validation.
- Reopening a lock pathname for every operation: rejected because inode
  substitution splits the lock domain.
- Reimplementing BLAKE2b in Store or selecting a test hash via Cargo features:
  rejected.
- Claiming a root ID or local journal detects a complete authentic rollback:
  rejected; a monotonic external anchor is required.
- Silently migrating experimental files or deleting orphan claims/staging:
  rejected.

## 16. Security consequences and remaining gates

If implemented exactly, this erratum provides deterministic local bytes,
immutable artifact history, attempt-before-open recovery, capability-rooted
active I/O bound to one live authority, collision-free partial-consumption
revisions, complete encrypted-object digests, independently rewrapped atomic
backups, a non-circular restore digest DAG, a self-contained/byte-committed
pending transaction, unique terminal tombstones, independent Contracts storage
keys, deterministic abort/burn evidence, tombstone-before-unlink secret
retirement, create-no-clobber new-device restore initialization, deterministic
successor epochs, and fail-closed restore activation. It deliberately does not
provide:

- protection against complete authentic whole-root rollback before open;
- a witness, watchtower, remote receipt, or monotonic remote sequence;
- numerical budgets, time windows, retry counts, timeouts, or retention
  defaults;
- an OS keystore backend;
- publication of the authoritative DOM dependency;
- an independent external audit;
- Phase 2, production, mainnet, or real-funds authorization.

Those gates remain open after ratification and after implementation.

## 17. Ratification effect

If the operator signs these exact bytes and verification succeeds, the eight
storage-persistence ambiguities listed in §1 are frozen for DOM Contracts Phase
1B. An implementation that cannot follow them byte for byte must stop and
request a signed erratum. Signature alone creates no implementation evidence,
gate approval, publication authority, production authority, or mainnet
authority.

## 18. Operator ratification block

```text
Document: NAR-DC-P1-002-storage-persistence-closure.en.md
Decision: RATIFIED AS WRITTEN
Scope: DOM Contracts Phase 1B storage persistence inputs only
Consensus or existing DOM wire change: NO
Budget or witness assignment: NO
DOM Wallet integration authorization: NO
Phase 2 authorization: NO
Production authorization: NO
Mainnet authorization: NO
Publication authorization: NO
Signature scheme: Minisign
Signature file: NAR-DC-P1-002-storage-persistence-closure.en.md.minisig
```

The private signing key must never be provided to, opened by, hashed by, or used
by an implementation agent. Verification uses only the established public key.

# NAR-DC-P1-004 — Live Store Layout and Runtime Closure

Status: **PROPOSED / UNSIGNED / NOT NORMATIVE**

Project: **DOM Contracts**

Date: **2026-08-05**

Scope: **Phase 1B minimum local Nonce Vault runtime**

> This document has no normative effect until the operator reviews and signs
> these exact bytes with the established Minisign identity. Implementations
> must remain fail-closed wherever this record supplies a missing decision.

## 1. Purpose

NAR-DC-P1-001, NAR-DC-P1-002, and NAR-DC-P1-003 freeze the cryptographic
storage envelope, lifecycle records, append-only journal, restore projection,
reservation binding, public lookup identifier, and live export authority.
Implementation of a concrete retained-handle store identified the remaining
decisions required to turn those records into one deterministic local runtime
without inventing path authority, budget bytes, recovery behavior, or caller
trust.

This record closes all of the following gaps as one atomic decision:

1. exact normal-store root and generation layout;
2. fresh generation-one initialization and its zero-head sentinel;
3. reservation-authority, session-claim, and budget-charge paths;
4. a canonical budget-policy format without numerical defaults;
5. a canonical append-only budget-charge format and journal-first reservation;
6. collision and idempotency lookup without unauthenticated indexes;
7. exact computation-attempt input binding;
8. the nonce-secret object revision and path;
9. abort-reason to terminal-record mapping;
10. local-profile `RestoreState` semantics;
11. a non-fabricable live capability compatible with the existing non-GAT
    `NonceVaultV1` associated type;
12. permit lookup, current-generation resend, and lifetime permit retirement;
13. filesystem capability, locking, synchronization, and no-follow rules;
14. a narrow tombstone sealing boundary;
15. concrete restore API ownership and passphrase rules;
16. exact root and generation entry whitelists;
17. lifetime collision checks across retained generations and arbitrary-depth
    restore chains;
18. deterministic prefix recovery for interrupted reservations;
19. active-generation pointer advancement and recovery;
20. non-caller-selectable key and counterparty budget identities;
21. a strict two-participant operational Phase 1B profile;
22. immutable V1 budget-policy selection and exact rolling-window boundaries;
23. an exact persisted derivation-base context and complete protocol-roster
    binding for reservation replay;
24. distinct fresh-create and retry/resume commands with fail-closed miss
    behavior;
25. a seal-before-public `NonceVaultV1` lifecycle that can be implemented
    without reusing a computation permit;
26. durable public authority for the signer-owned effective retry counter;
27. stage-current transcript and complete commitment/reveal-set binding;
28. one-shot post-open persistence authority before exposure authorization;
    and
29. the implementation and evidence gates that remain open after ratification.

This record does not authorize witness, watchtower, transport, Phase 2, real
funds, mainnet, production, consensus changes, existing DOM wire changes,
publication of `dom-contracts`, a second DOM Core publication, or any numerical
production budget.

## 2. Authority and notation

After ratification, the order for this scope is:

1. P1-ARCH-002;
2. this record;
3. NAR-DC-P1-003;
4. NAR-DC-P1-002;
5. NAR-DC-P1-001;
6. signed NAR-002 for its expressly incorporated and unsuperseded assignments;
7. the published `dom-adaptor` API; and
8. the Master Specification where not superseded.

The following signed records are incorporated by exact identity. Their
detached signatures were verified under the established DOM release Minisign
public key before this proposal was prepared:

| Incorporated signed authority | SHA-256 |
|---|---|
| `NAR-DC-P1-001-omnibus-gap-closure.en.md` | `88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655` |
| `NAR-DC-P1-002-storage-persistence-closure.en.md` | `719a121c11f4b7f8ea016668bfaa05a3e4d03d3a510df31e3495fb9698560e84` |
| `NAR-DC-P1-003-vault-request-and-recovery-binding.en.md` | `082c855782c71a0f61e85828eaac75440a434d5c05d8357e569592a816db05ef` |
| `NAR-002-phase-1-omnibus-normative-closure.en.md` | `b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5` |
| `ADR-P1-001-integrated-g1a-g1b-authorization-boundary.en.md` | `e35c39e74f9af61e19ecda8e1ca503f37a7fc04c6e2a0f40f5d96bf6a20d1596` |
| `ADR-SNV-001-witness-and-aad.en.md` | `3939df85814e8c2b1fad8ea6484492887000b38917c3b23e47d5d505311270c2` |
| `ADR-SNV-002-vault-record-kind-registry.en.md` | `29266c4468d97cb7a1e185561f2e140f08fb914d43d0ad5deef1aa7b07c209c5` |

The published DOM adaptor implementation inspected for API provenance is
exactly commit
`67fe11c441c2b7801b6f70809ab58caa4804c22a`, tree
`4fd42e057d20dd55853f7829778b9fb3f89921d6`. This identity is evidence of
the interface being corrected, not authority over a conflicting signed byte
assignment. The replacement API assigned by this record requires a separately
reviewed DOM revision and a separately authorized publication and pin.

This record expressly supersedes only the following assignments for the
independent DOM Contracts Phase 1B local profile:

1. NAR-DC-P1-002 §6.2, by the variable-length `Reserve` payload in §7.2;
2. NAR-DC-P1-002 §6.10.1, only for the tombstone staging basename, by
   §4.2;
3. NAR-DC-P1-002 §10.3 and §11.3, only for the completed-backup and
   pending-source-backup restore-record paths, by §4.4;
4. NAR-DC-P1-001 §8.8 and NAR-DC-P1-002 §§4.5, 6.15, and 11.4, only
   to extend `JournalEntryKindV1` by `0x0d BudgetCarryForward` and `0x0e
   PermitRetirementCarryForward` and to insert their canonically sorted entries
   after all `RestoreRecord` entries and before `EpochAdvance`, as assigned by
   §§7.3 and 15.1. The journal outer envelope, predecessor rules,
   completeness rules, `EpochAdvance`-before-`RestoreComplete` rule, and
   `RestoreComplete`-last rule remain unchanged;
5. NAR-DC-P1-002 §8.5, only for the fresh, restored, and descendant active
   head validation refinement in §11;
6. signed NAR-002 §§18.3 and 27 and ADR-SNV-001 §14, only for the
   witness-era 51-byte policy body, mutable budget-state body, Wallet/witness
   storage profile, and caller-supplied production-policy selection. In the
   independent Contracts local profile, §6 replaces them with one exact
   144-byte policy selected only by the trusted composition root from
   separately ratified/authenticated bytes and an append-only charge
   projection. Per-operation callers, environment variables, command-line
   values, and untrusted configuration cannot create policy authority. The
   requirements for nonzero limits, no production defaults,
   measurement-backed ratification, checked clocks, and no budget refund
   remain unchanged;
7. NAR-DC-P1-001 §§4.3 and 8.3, only for the private zero-scalar retry
   resolution in §8.3: after durable reservation and before any nonce-secret
   object, public material, or derivation-attempt record exists, the signer may
   resolve one final nonzero nonce pair and its final effective retry context
   in memory. The exact derivation attempt for that final context remains
   mandatory before secret sealing/opening or any public computation,
   persistence, or exposure. Failure or process death burns the already
   charged reservation, and recovery never reruns the KDF;
8. NAR-DC-P1-002 §11.1, only to extend its exhaustive internal V1 random-value
   list by the nonzero 32-byte reservation ID, nonzero 32-byte
   request/idempotency ID, and nonzero process-only 32-byte `open_instance_id`
   assigned in §§5, 7.1, and 12. Each is internally generated by the
   operating-system CSPRNG, never caller supplied, and fails terminally on RNG
   failure or an all-zero result. Every other random/deterministic assignment
   in §11.1 remains unchanged;
9. NAR-DC-P1-001 §7.8, only for availability of in-place active-store
   password/passphrase change and active master-key-envelope rewrap in the
   Phase 1B minimum, by §16.2. Such an operation remains unavailable until a
   separately ratified transaction format and crash-recovery order exist; and
10. NAR-DC-P1-003 §§3.2, 3.3, and 4, only for the former 347-byte
    `ReservationAuthorityV1`, its incomplete `bound_digest`, and the mappings
    affected by them. Sections 7.1–7.2 replace them with one embedded complete
    `ReservationContextBindingV1`, a variable-length authority, and the
    resulting variable-length budget charge and `Reserve` payload. All other
    NAR-DC-P1-003 assignments remain unchanged;
11. ADR-P1-001 §8.4 and §10.1 and the published DOM adaptor's
    `NonceVaultV1::{claim_reservation,begin_computation,
    store_reserved_secret,open_secret,authorize_exposure}` lifecycle, only to
    replace the ambiguous fresh/resume claim, impossible commitment-before-
    seal ordering, reusable associated permit role, and artifact-taking
    authorization call with the exact fresh/resume, seal-before-public, and
    persist-before-authorize lifecycle in §7.1.3 and §8.1. The one
    orchestrated path, private capability rules, attempt-before-open rule,
    exact-byte persistence, and every later-stage consume-before-export rule
    remain unchanged;
12. ADR-P1-001 §7.3 item 6, only to replace byte equality of the stored
    derivation context's phase/transcript with the exact compatibility and
    signed NAR-002 §8.2 transcript-evolution rules in §8.3. Every immutable
    context field and every other semantic validation in ADR-P1-001 §7.3
    remains unchanged;
13. NAR-DC-P1-002 §3.3, §6.3, and §§7.1–7.3, only for the complete
    stored and restored bytes of a `NonceDerivation` computation attempt.
    Section 8.3 wraps the unchanged 193-byte `AttemptRecordV1` in the exact
    201-byte `NonceDerivationAttemptV1 = AttemptRecordV1 ||
    effective_retry_counter_u64_le` payload so later stages can authenticate
    the final retry without decrypting a secret. Reveal and PartialSignature
    attempt payloads and their corresponding canonical restore-record bytes
    remain exactly 193 bytes.
    The attempt path, restore family and key, predecessor, lifecycle, and burn
    semantics remain unchanged except for the explicitly assigned 201-byte
    derivation record body and resulting 289-byte journal entry; and
14. the published DOM adaptor's general attempt-before-private-computation
    wording, only for the zero-scalar retry ordering in §8.3.

Signed NAR-002 §§3, 5, 8.2, and 13.2 domain names, participant-ID
derivation, one-to-one participant/signing-key mapping, and accepted-message
transcript evolution are not superseded. Sections 7.1 and 8.2–8.3 make those
assignments complete persisted inputs to reservation and stage computation.
Network
timeout, retry, and retention assignments outside the local budget codec are
also unchanged. In particular, there is exactly one V1 budget identifier
registry. Every unlisted signed assignment remains unchanged. No development
spelling or superseded path is an alias, migration input, or alternate V1
decoder.

All integers are fixed-width little-endian unless a filename rule explicitly
uses zero-padded decimal or lowercase hexadecimal. Every `H_tag` operation is
exactly:

```text
H_tag(tag, data) =
  DOM_BLAKE2b_256(u16_le(len(ASCII(tag))) || ASCII(tag) || data)
```

There is no key, salt, personalization, BLAKE2b-512 truncation, BLAKE2s,
SHA-256 substitution, BIP340 doubled-tag construction, or caller-selected
domain.

The terms `retained capability`, `retained handle`, and `live authority` mean
an already-open operating-system object handle obtained without following a
symlink, held for the complete operation, and revalidated after the exclusive
lock is acquired. A pathname string is never authority.

## 3. Registered domains

The following exact case-sensitive ASCII tags are newly registered:

```text
DOM:contracts-vault-budget-policy:v1
DOM:contracts-vault-budget-charge:v1
DOM:contracts-vault-permit-retirement:v1
DOM:contracts-vault-reservation-context:v1
DOM:scriptless-vault-computation-input:v1
```

The following already signed NAR-002 §3 and §13.2 assignments are reused
without renaming or changing their preimages:

```text
DOM:scriptless-vault-budget-key:v1
DOM:scriptless-vault-counterparty:v1
```

The existing tags from signed NAR-002 and NAR-DC-P1-001 through
NAR-DC-P1-003 remain unchanged except for the explicitly scoped local-policy
format supersession in §2. No alias or alternate V1 spelling is permitted.

## 4. Exact normal-store layout

### 4.1 Root entries

The normal V1 store root recognizes only the following entries:

```text
store-root-identity.bin
store-lock-identity.bin
active-vault-generation
.active-vault-generation.staging
restore-only-root.bin
restore-initialized-<restore_initialization_id_16_hex>.bin
restore-pending/
.restore-<restore_transaction_id_16_hex>.staging/
restore-complete-<restore_transaction_id_16_hex>/
generation-<generation_20_decimal>-<vault_id_32_hex>/
.generation-<generation_20_decimal>-<vault_id_32_hex>.staging/
backup-<backup_generation_20_decimal>-<backup_id_32_hex>/
.backup-<backup_generation_20_decimal>-<backup_id_32_hex>.staging/
```

Angle-bracket components use the exact NAR-DC-P1-002 encodings. Hexadecimal is
lowercase with no prefix. A suffix not having its exact length and grammar is
not a member of the registry.

`store-root-identity.bin` contains exactly one 122-byte
`StoreRootIdentityV1`. `store-lock-identity.bin` is the one retained lock file
and contains exactly one 122-byte `StoreLockIdentityV1`.
`active-vault-generation` contains exactly one 226-byte
`ActiveVaultGenerationV1`.

The staging and restore entries are permitted only in the exact transaction
states assigned by NAR-DC-P1-002 and this record. They are not generally
ignorable. An entry that is impossible for the verified transaction prefix,
an unknown entry, a duplicate semantic entry, a symlink, an unexpected file
type, or a noncanonical name places adaptor operations in
`RestoreQuarantined`.

The store root never contains ordinary DOM Wallet state, application logs,
reports, sockets, temporary editor files, databases belonging to another
subsystem, or a plaintext secret.

### 4.2 Active generation entries

A normal active generation recognizes only:

```text
generation-core.bin
master-key.envelope
journal/
reservation-authorities/
session-claims/
budget-charges/
attempts/
exposures/
nonce-secrets/
tombstones/
```

`generation-core.bin` is exactly 186 bytes. `master-key.envelope` is exactly
182 bytes. The `journal` and `tombstones` directories are mandatory. The other
six namespace directories may be absent immediately after an exact restore
activation and are then created, with create-no-clobber and directory sync,
before their first object is created. If present they must be directories
opened through the retained generation capability. No other entry is allowed.

The exact object paths relative to those retained namespace capabilities are:

```text
reservation-authorities/<reservation_id_32_hex>.authority
session-claims/<session_id_32_hex>.claim
budget-charges/<reserve_journal_sequence_20_decimal>-<reservation_id_32_hex>.charge
attempts/<identity_key>/<expected_revision_20_decimal>-<artifact_kind_2_hex>.attempt
exposures/<identity_key>/<sequence_20_decimal>/<state_2_hex>-<digest_32_hex>.exposure
nonce-secrets/<identity_key>.secret
tombstones/<identity_key>.tombstone
tombstones/.<identity_key>.tombstone.staging
journal/<sequence_20_decimal>-<entry_digest_32_hex>.journal
```

`identity_key` is the lowercase hexadecimal encoding of the complete 105-byte
`NonceIdentityV1`. The attempts, exposures, tombstones, and journal paths are
the unchanged NAR-DC-P1-002 paths with their namespace prefix made explicit.
The `Commitment (01)` attempt projection contains the exact 201-byte
`NonceDerivationAttemptV1` assigned in §8.3; `Reveal (02)` and
`PartialSignature (03)` attempt projections contain the unchanged exact
193-byte `AttemptRecordV1`. Filename grammar does not select any alternate
body length.

This record expressly supersedes only the NAR-DC-P1-002 §6.10.1 tombstone
staging basename. The canonical component is exactly:

```text
.<identity_key>.tombstone.staging
```

It is exactly `1 + 210 + 18 = 229` bytes. The complete authenticated 495-byte
`VaultObjectEnvelopeV1` staging contents, not the filename, supply the
canonical tombstone digest. The
identity encoded in the filename must equal the identity in the authenticated
`TombstoneV1` plaintext and envelope metadata, and the implementation
recomputes the complete envelope and plaintext digests before rename.

The staging path is permitted only at the one uniquely verified
NAR-DC-P1-002 §6.10.1 terminal transaction prefix for that identity. Exactly
one such staging file may exist for that prefix. A second staging file, a
malformed name, an authenticated-content or identity mismatch, or a staging
file unrelated to that verified transaction prefix quarantines adaptor
operations. The former 294-byte development spelling
`.<identity_key>-<tombstone_digest_32_hex>.tombstone.staging` is rejected and
is never migrated silently. The staging file is never a tombstone and never
grants authority before the assigned synchronized same-directory
rename-no-replace completes. The existing one-prefix, one-staging-file,
create-no-clobber, quarantine, file synchronization, directory
synchronization, retained-handle, and rename-no-replace rules remain
unchanged.

An immutable predecessor generation is retained as evidence and is never
mutated into an active generation. A generation not selected by the exact
active record may be read only while proving a predecessor or restore chain.

### 4.3 No persisted secondary index

V1 defines no mutable session, request, reservation, permit, or budget index.
Exact collision lookup streams and authenticates the canonical authority,
claim, charge, exposure, tombstone, and journal records under the retained
lock. An in-memory cache may accelerate a lookup only after being rebuilt from
those authenticated records; it is disposable, non-authoritative, and may
never be persisted as a V1 store record.

This rule prevents an unspecified index codec from becoming hidden authority.
Implementations must use bounded streaming and checked counters rather than
allocating from an untrusted directory entry count.

### 4.4 Restore-record path supersession

This section expressly supersedes only the flat restore-record path in
NAR-DC-P1-002 §10.3 and §11.3 for both immutable completed backups and
`restore-pending/source-backup`. The canonical nested path is:

```text
records/<hex_lower(RestoreRecordKeyV1[0..105])>/
        <hex_lower(RestoreRecordKeyV1[105..155])>.record
```

The first variable component is exactly 210 lowercase hexadecimal bytes. The
second variable component is exactly 100 lowercase hexadecimal bytes followed
by the seven-byte suffix `.record`, for a total of 107 bytes. Decoding and
concatenating the directory component and filename stem reconstructs exactly
one complete 155-byte `RestoreRecordKeyV1`. The complete canonical record
bytes must independently derive that identical key.

The `records` directory contains only exact 210-byte identity subdirectories.
Each identity subdirectory contains only exact matching 107-byte tail files;
an empty directory, wrong prefix, wrong tail, wrong case, non-hex byte,
duplicate reconstructed key, symlink, hard-link alias, unexpected type, or
extra entry rejects the backup or quarantines the pending restore. Record-set
ordering, record-set bytes, record-set digest, manifest fields, bundle digest,
and canonical record bytes remain unchanged and continue to use the complete
155-byte key, never a pathname encoding.

Backup creation synchronizes each record file, then each identity
subdirectory, then `records`, before synchronizing and publishing the backup
staging directory. Restore staging copies and verifies files through retained
capabilities and synchronizes each
`restore-pending/source-backup/records/<identity>` directory, then its
`records` parent, then the enclosing source-backup and restore staging
directories. Recovery reconstructs the complete key from both components
before accepting any record and repeats the same bottom-up synchronization.
The former flat 317-byte development path is rejected without migration.

## 5. Fresh store and generation-one initialization

Fresh creation accepts a destination parent capability and one absent final
component. It never adopts or cleans an existing path. It accepts an owned,
non-cloneable, zeroizing unlock passphrase and obtains every random value from
the operating-system CSPRNG.

The exact order is:

1. Prove the final component is absent and create the owner-only root with
   create-no-clobber. Retain its directory handle and synchronize its parent.
2. Generate independent nonzero `contract_wallet_id`, `store_root_id`,
   `lock_instance_id`, and `vault_id`; set `nonce_epoch` and
   `vault_generation` to exactly `1`.
3. Create, synchronize, reopen, and byte-verify `store-root-identity.bin` and
   `store-lock-identity.bin`; acquire the exclusive lock on the already
   retained lock handle and revalidate both identities.
4. Generate the vault master key and the exact NAR-DC-P1-001 master-envelope
   random values. Seal the master key through the approved production sealer.
5. Construct `VaultGenerationCoreV1` for generation `1` and create the exact
   `.generation-00000000000000000001-<vault_id>.staging` directory. Populate
   only `generation-core.bin`, `master-key.envelope`, an empty `journal/`, an
   empty `tombstones/`, and the six optional empty namespace directories from
   §4.2.
6. Synchronize and reopen every file and directory from leaves to the staging
   directory. Atomically rename-no-replace the staging directory to its final
   generation name and synchronize the root.
7. Construct the generation-one active record with journal sequence exactly
   `0` and journal head exactly `zero_32`. Write it to
   `.active-vault-generation.staging`, synchronize and verify it, atomically
   rename-no-replace it to `active-vault-generation`, synchronize the root,
   and revalidate the complete store.
8. Zeroize the unlock passphrase, Argon output, KEK, plaintext master key, and
   every secret temporary on every success and error path.

The sequence-zero/head-zero pair is valid only for a fresh authenticated
generation `1` with an empty journal and no lifecycle, budget, secret, or
terminal object. It is invalid for every restored generation and becomes
invalid permanently after journal sequence `1` exists.

This record extends the exhaustive NAR-DC-P1-002 §11.1 random-value list only
with these later-assigned internal values: a nonzero 32-byte reservation ID, a
nonzero 32-byte request/idempotency ID, and a nonzero process-only 32-byte
`open_instance_id`. Each is generated internally from the operating-system
CSPRNG, is never caller supplied, and treats RNG failure or an all-zero result
as terminal before persistence. Initial nonce epoch is deterministic and is
not part of this extension. No other V1 field becomes random through this
record.

A crash-created fresh root is never deleted or silently restarted. Recovery
may complete only one byte-identical verified prefix of the transaction above.
Any missing random value that was not already committed to a canonical record,
any conflicting file, or more than one possible continuation quarantines the
root and requires a new absent destination selected by the operator.

## 6. Canonical budget policy and charges

### 6.1 BudgetPolicyV1

`BudgetPolicyV1` is exactly 144 bytes:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `DOMNVBP1` |
| 8 | 2 | version | exactly `1` |
| 10 | 1 | profile | `0x01 ProductionRatified`, `0x02 EvidenceOnly` |
| 11 | 1 | clock source | exactly `0x01 SystemUtcUnixSeconds` |
| 12 | 4 | reserved | all zero |
| 16 | 32 | policy ID | nonzero |
| 48 | 8 | global lifetime limit | nonzero |
| 56 | 8 | per-counterparty lifetime limit | nonzero |
| 64 | 4 | concurrent-active limit | nonzero |
| 68 | 4 | reserved | all zero |
| 72 | 8 | rolling-window limit | nonzero |
| 80 | 8 | rolling-window seconds | nonzero |
| 88 | 8 | maximum forward step seconds | nonzero |
| 96 | 8 | policy revision | nonzero |
| 104 | 8 | effective-from UTC Unix seconds | nonzero |
| 112 | 32 | policy digest | definition below |

The digest is:

```text
H_tag("DOM:contracts-vault-budget-policy:v1", bytes[0..112])
```

This record assigns a codec, not numerical production values. A production
composition root accepts only exact `ProductionRatified` bytes whose digest is
compiled into or otherwise authenticated by a separately reviewed release.
No environment variable, command-line value, per-operation caller value, or
untrusted config can create production authority. Until such policy bytes are
separately ratified, the adaptor subsystem does not start.

`EvidenceOnly` is available only through the non-production testkit feature,
must carry public test values, and must be absent from release feature
resolution. It cannot be converted into a production policy by changing one
byte because profile and all values are covered by the digest.

Every profile byte other than `0x01` or `0x02`, and every clock-source byte
other than `0x01`, is rejected. There is no unknown, other, default, fallback,
or non-exhaustive V1 value.

The first accepted `Reserve` for one `contract_wallet_id` fixes exactly one
`BudgetPolicyV1.policy_digest` for that contract wallet's complete V1
lifetime. Before that first charge, the trusted composition root may select
one separately authenticated policy. Every later `Reserve`,
`BudgetCarryForward`, backup, and restore charge must carry the identical
digest. V1 defines no policy update, downgrade, merge, reset, or replacement.
A different digest after the first charge quarantines adaptor operations. A
future policy transition requires a separately ratified versioned transition
record and is outside this record.

For avoidance of a competing V1 policy, this 144-byte object expressly
supersedes signed NAR-002 §18.3's witness-era 51-byte `budget_policy_v1` and
mutable `budget_state_v1` only in the independent, witness-free DOM Contracts
local profile. It preserves the signed requirement that
`maximum_forward_step_seconds` is nonzero and authenticated. The signed
`DOM:scriptless-vault-budget-policy:v1` domain remains reserved for that
witness-era format; this object uses only
`DOM:contracts-vault-budget-policy:v1`. The two formats are not aliases and no
decoder accepts one as the other.

### 6.2 Trusted operational budget identities

The minimum vault-backed Phase 1B route requires exactly two participants.
This restriction does not narrow the pure G1A cryptographic API, which may
retain its separately assigned participant range. A V1 operational request
with any count other than `2` is rejected before budget admission or secret
work. Supporting more than two participants requires a new versioned
reservation authority containing a canonical set of per-counterparty buckets;
the two-party variable-length `ReservationAuthorityV1` assigned in §7.1 is
not used for it.

Application callers cannot provide, override, alias, or select `VaultKeyId`,
`CounterpartyBucket`, or raw `ParticipantId`. The vault-backed signer derives
them only after it has validated the complete `SessionContextV1`, the
canonical two-entry protocol roster, the local signing share/public-key
equality, the local participant index, the exact trusted chain ID, and the
signed NAR-002 §5 one-to-one mapping among participant ID, transport identity
key, signing key, protocol-roster position, and G1A participant index. The
derivations reuse signed NAR-002 §13.2 exactly:

```text
key_id = H_tag(
  "DOM:scriptless-vault-budget-key:v1",
  trusted_chain_id_32 || local_signing_public_key_compressed_33
)

counterparty_bucket = H_tag(
  "DOM:scriptless-vault-counterparty:v1",
  trusted_chain_id_32 || remote_participant_id_32
)
```

Semantically, the local signing public key is the context signing key at the
validated local G1A participant index and equals the public key derived from
the actual local signing share. Exactly one protocol-roster mapping carries
that key at that index. The remote participant ID and signing key are those of
the only other entry in the validated one-to-one mapping, and that remote
signing key equals the only other context signing key. Both identity and
signing points are canonical nonidentity compressed SEC1 points, and both
participant IDs are recomputed with the signed
`DOM:scriptless-participant:v1` formula. Duplicate, missing, reordered, or
changed mappings fail before admission. This paragraph assigns semantics, not
names of Rust methods or types that do not yet exist.

The local `ParticipantId` stored in the reservation authority is the local
participant ID from that same opaque validated mapping. The remote participant
ID is used only for the counterparty derivation above. A raw participant ID is
not an argument to the safe reservation-intent constructor. Neither an
unvalidated roster nor application-selected identity bytes can mint
reservation authority.

The counterparty bucket identifies the stable remote participant identity,
not an address, free-form label, signing key alone, or a Sybil-proof human or
organization. An authorized remote signing-key rotation that preserves the
ratified participant identity therefore preserves the same bucket. The global
lifetime and rolling limits for the derived local key ID are the
non-Sybil-dependent safety bounds.

The next reviewed DOM adaptor revision removes `VaultKeyId`,
`CounterpartyBucket`, and raw `ParticipantId` from the safe public
`ReservationIntentV1` constructor. Only an internal constructor receiving the
opaque validated protocol state may populate those fields. No public struct
literal, alternate constructor, feature, or conversion may restore caller
authority over them.

### 6.3 BudgetChargeV1

Let `A = 605 + L` be the exact complete revised
`ReservationAuthorityV1` length assigned by §7.1.2. `BudgetChargeV1` is
exactly `66 + A = 671 + L` bytes, therefore exactly `916` bytes without an
adaptor point and `949` bytes with one:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `DOMNVBC1` |
| 8 | 2 | version | exactly `1` |
| 10 | `A` | reservation authority | complete revised `ReservationAuthorityV1` |
| `10+A` | 8 | charged-at UTC Unix seconds | nonzero and not before policy effective time |
| `18+A` | 8 | reserve journal sequence | nonzero, exact planned `Reserve` sequence |
| `26+A` | 8 | charge revision | exactly `1` |
| `34+A` | 32 | charge digest | definition below |

The digest is:

```text
H_tag("DOM:contracts-vault-budget-charge:v1", bytes[0..34+A])
```

The embedded authority, including the complete embedded reservation-context
binding, is the complete canonical source for recovery. Its
`budget_policy_digest` must equal the immutable V1 policy digest. Its key ID,
counterparty bucket, and participant ID must equal the exact trusted
derivations in §6.2. The path sequence must equal the encoded reserve sequence
and the path reservation ID must equal the embedded reservation ID.

Every accepted reservation creates one charge. The four exact scopes are:

```text
global lifetime:
  every unique authenticated charge matching candidate key_id

counterparty lifetime:
  every unique authenticated charge matching candidate key_id and
  candidate counterparty_bucket

rolling window:
  every unique authenticated charge matching candidate key_id and
  lower < charged_at <= now

concurrent active:
  every unique authenticated charge for this contract_wallet_id, across all
  key IDs and counterparties, that lacks one completely authenticated terminal
  tombstone for its exact NonceIdentityV1 and the exact terminal journal
  projection
```

Global and counterparty counts are lifetime counts and are never decremented
by abort, burn, restore, epoch advance, reorg, cancellation, or time-window
expiry. `Reserve` and carry-forward occurrences of the same byte-identical
charge count once. At admission time `now`, the exact rolling interval is:

```text
lower = now.saturating_sub(rolling_window_seconds)
count every authenticated charge satisfying:
  lower < charged_at && charged_at <= now
```

Expiry does not erase or refund a charge. A charge later than `now`, or an
observed `now` earlier than the greatest authenticated charge timestamp,
quarantines adaptor operations. Concurrent occupancy is store-wide for the
complete `contract_wallet_id`; it cannot be bypassed by local-key,
counterparty, epoch, or generation rotation. A corrupt, ambiguous, missing, or
unverified terminal object never removes occupancy and independently
quarantines normal validation. Occupancy ends only after the exact terminal
tombstone and terminal journal projection are both durable and authenticated;
that end is never a budget refund.

The store persists the greatest observed UTC second as part of its verified
in-memory projection reconstructed from charges. A runtime observation earlier
than the greatest authenticated charge timestamp quarantines adaptor
operations. Before any rolling-window expiry or admission, when a greatest
authenticated charge timestamp exists, the store performs these checked tests
in this order:

```text
now >= greatest_authenticated_charge_timestamp
now - greatest_authenticated_charge_timestamp
    <= policy.maximum_forward_step_seconds
```

Failure of the first test is backward-clock quarantine. Checked-subtraction
failure or a forward step exceeding the nonzero authenticated maximum is
forward-clock quarantine. Neither branch expires a charge, creates a charge,
allocates a reservation, or mutates the high-water projection. Only after both
tests pass may the exact `(now.saturating_sub(window_seconds), now]` rolling
count be evaluated. If there is no prior authenticated charge, `now` must still
be nonzero and not precede the policy effective time. Wall-clock time is not a
whole-root rollback anchor and no such claim is made.

All arithmetic is checked. Counter overflow, timestamp overflow, policy
digest mismatch, a duplicate charge, a missing sequence, a changed charge, or
two different charges for one reservation/request/session quarantines adaptor
operations.

## 7. Reservation transaction and deterministic prefix recovery

### 7.1 Replay precedes all fresh assignments

#### 7.1.1 Complete reservation context and roster binding

The safe signer and Store persist one complete `ReservationContextBindingV1`
inside every `ReservationAuthorityV1`. It is not a hash-only promise. It
contains the exact derivation-base `SessionContextV1` and the complete
one-to-one protocol roster needed to validate every field that can change
nonce derivation, commitment, transcript evolution, or participant authority.

Let `L` be the exact canonical derivation-base context length. The operational
Phase 1B profile has exactly two participants, so `L` is exactly `245` for
Refund or Funding and exactly `278` for ClaimAdaptor. Sponsor and every other
participant count are rejected before reservation. The complete
`ReservationContextBindingV1` length is `254 + L`, therefore exactly `499` or
`532` bytes:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `DOMNVCT1` |
| 8 | 2 | version | exactly `1` |
| 10 | 2 | contract kind | exactly `0x0001 WitnessOrTimeout` |
| 12 | 4 | derivation-base context length | exactly `L`, little-endian |
| 16 | `L` | derivation-base context | complete canonical `SessionContextV1` assigned below |
| `16+L` | 2 | protocol participant count | exactly `2` |
| `18+L` | 202 | protocol roster | exactly two 101-byte entries below, strictly ascending by participant ID |
| `220+L` | 2 | local protocol-roster index | `0` or `1`, little-endian |
| `222+L` | 32 | context-binding digest | definition below |

Each 101-byte protocol-roster entry is exactly:

```text
participant_id_32
|| identity_public_key_compressed_33
|| signing_public_key_compressed_33
|| direction_u8
|| g1a_participant_index_u16_le
```

The two entries are strictly ascending by `participant_id_32`. Participant
IDs are recomputed with signed NAR-002 §5, identity and signing points are
canonical compressed nonidentity SEC1 values, directions use the closed
`DirectionV1` registry, G1A indices are distinct and are exactly the set
`{0,1}`, and every entry is the signed one-to-one mapping among participant
ID, identity key, signing key, protocol position, and G1A signing position.
The entry at `local_protocol_roster_index` has the authority record's local
participant ID, its direction equals the derivation-base context direction,
and its G1A index equals the derivation-base context participant index. Its
signing key is the context key at that index and equals the public key derived
from the actual local signing share. The other entry is the only remote
participant and supplies the counterparty identity used by §6.2. The two
entry signing keys, indexed by their G1A indices, reproduce the complete
strictly ascending two-key signing roster in the context byte for byte.

The derivation-base context is constructed only by the safe vault-backed
signer from trusted validated session state. Its fields are exact as follows:

- version is `1`, chain ID is the trusted local chain ID, and session ID is
  the already lifetime-unique session ID for the exact contract kind above;
- purpose, template hash, kernel-message digest, signing roster, local signing
  index, direction, and optional adaptor point are the complete accepted
  values and satisfy every NAR-001 validation and purpose rule;
- signing phase is exactly `SigNonceCommit (0x0100)`;
- retry counter is exactly zero; and
- transcript hash is the accepted NAR-002 §8.2 transcript head immediately
  before the first `SigNonceCommit` message of this signing round is applied.

That transcript head may include earlier accepted contract messages. It is not
silently replaced by the initial transcript hash. The trusted session adapter
must prove its ancestry from the signed NAR-002 initial transcript and exact
accepted messages; an application-provided arbitrary hash is not authority.

The context-binding digest is exactly:

```text
context_binding_digest = H_tag(
  "DOM:contracts-vault-reservation-context:v1",
  reservation_context_binding_bytes[0..222+L]
)
```

Wrong length, unknown contract kind, wrong phase, nonzero initial retry,
unknown direction or purpose, Sponsor, wrong local index, duplicate or
reordered participant, inconsistent roster mapping, malformed point, wrong
adaptor presence, trailing byte, zero digest, or digest mismatch fails before
budget admission or secret work.

#### 7.1.2 Revised ReservationAuthorityV1

This record replaces the former fixed 347-byte authority. Let `B = 254 + L`
be the complete embedded `ReservationContextBindingV1` length.
`ReservationAuthorityV1` is exactly `351 + B = 605 + L` bytes, therefore
exactly `850` bytes without an adaptor point and `883` bytes with one:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `DOMNVRA1` |
| 8 | 2 | version | exactly `1` |
| 10 | 32 | reservation ID | exact nonzero internal `ReservationNonceId` |
| 42 | 32 | key ID | exact trusted §6.2 derivation, nonzero |
| 74 | 32 | session ID | exact binding/context session, nonzero and lifetime-unique |
| 106 | 32 | counterparty bucket | exact trusted §6.2 derivation, nonzero |
| 138 | 1 | purpose | exact strict context `PurposeV1` |
| 139 | 32 | local participant ID | exact local roster entry, nonzero |
| 171 | 32 | template hash | exact context template hash, nonzero |
| 203 | 32 | request/idempotency ID | exact nonzero internally generated ID |
| 235 | 8 | nonce epoch | exact active epoch, nonzero |
| 243 | 32 | budget-policy digest | exact immutable §6.1 digest, nonzero |
| 275 | 4 | context-binding length | exactly `B`, little-endian |
| 279 | `B` | reservation context binding | complete canonical object above |
| `279+B` | 32 | bound digest | definition below |
| `311+B` | 8 | authority revision | exactly `1` |
| `319+B` | 32 | authority digest | definition below |

```text
bound_digest = H_tag(
  "DOM:contracts-vault-reservation-binding:v1",
  reservation_authority_bytes[10..279+B]
)

authority_digest = H_tag(
  "DOM:contracts-vault-reservation-authority:v1",
  reservation_authority_bytes[0..319+B]
)
```

`NonceIdentityV1.bound_digest` equals this revised `bound_digest`. The
authority's session, purpose, local participant, and template fields must equal
their embedded binding fields. Its key ID and counterparty bucket must equal
the exact derivations from the embedded local and remote roster entries. The
length is derived from the embedded context and adaptor-presence byte; range
membership alone is insufficient. The former 347-byte authority is rejected
as an unsupported unpublished development format and is never an alias.

#### 7.1.3 Replay ordering

Fresh creation and retry/resume are different private commands with no
conversion or fallback between them:

```text
FreshReservationRequestV1
ReservationResumeRequestV1
```

The safe vault-backed signer internally generates the nonzero request/
idempotency ID with the operating-system CSPRNG and binds it, the complete
validated `ReservationContextBindingV1`, and every trusted authority input
into one opaque `FreshReservationRequestV1`. That value is consumed exactly
once by the Store's `claim_fresh_reservation` entry point. Application code receives
only the public non-authoritative request lookup value. On retry it may return
that lookup value to the safe signer, which combines it with the same trusted
validated session state to construct one opaque
`ReservationResumeRequestV1` consumed by `resume_claimed_reservation`;
application code cannot choose or replace any bound field. Neither request
type has a public constructor, byte parser, clone, copy, serialization, or
conversion into the other.

Under the retained exclusive lock, both entry points first stream and
authenticate every request, reservation, session, journal, projection, and
terminal occurrence before sampling time, allocating a journal sequence,
generating a reservation ID, or requesting any other randomness. No CSPRNG
call occurs inside either transaction before this scan. Minting the fresh
opaque request ID is a separate prior vault-backed signer transition; retry
uses the same public lookup ID and trusted binding and never mints another ID.

The fresh entry point's pre-randomness scan succeeds only when it proves
complete lifetime absence of the request ID, session ID, proposed complete
context binding, and every partial or orphan occurrence for those available
identifiers. A reservation ID and completed authority do not exist during
this scan. After admission generates the reservation ID, the separate
post-generation collision scan below proves lifetime absence of that ID before
it constructs the authority. Any matching, conflicting, partial, carried,
restored, terminal, or otherwise pre-existing occurrence on the fresh entry
point is a closed conflict or quarantine result; it is never silently treated
as resume.

The resume entry point succeeds only when the scan finds exactly one coherent
authenticated occurrence chain for the request ID. It compares every
protocol-bound field, every byte of the embedded
`ReservationContextBindingV1`, and both complete digests against the
persisted `ReservationAuthorityV1`. It never recomputes or replaces the
persisted time, reserve sequence, charge, authority, claim, budget identifiers,
or policy digest. Exact equality resumes or reports the existing authenticated
live or terminal result. A changed bound field is a permanent idempotency
conflict. A partial or orphan prefix enters its already assigned deterministic
recovery branch and returns only that resulting terminal/quarantined state. A
restored, carried, retired, burned, or otherwise terminal occurrence returns
only its closed terminal result.

Zero authenticated occurrences on the resume entry point returns the closed
typed `RetryNotFound` result. It performs no fresh admission, no clock read,
no budget evaluation, no randomness request, no sequence allocation, no
journal or projection write, and no state mutation. In particular, a missing
retry can never fall through to fresh creation. Multiple occurrences that are
not one byte-identical coherent chain quarantine adaptor operations.

Only lifetime absence proved on the fresh entry point proceeds. The store
next captures the validated UTC second, verifies the immutable policy,
performs the exact backward- and maximum-forward-step checks in §6.3, and
evaluates all four budget projections.
These checks occur before admission, reservation-ID generation, or journal-
sequence allocation. A clock failure quarantines and creates no charge. If a
limit would be exceeded, no reservation ID, journal sequence, journal entry,
charge, authority, or claim is created and the closed budget error is
returned. Only an admitted request causes the store to generate the internal
nonzero reservation ID, prove its lifetime absence, and allocate the next
checked journal sequence before constructing the canonical records with the
already validated timestamp.

### 7.2 Journal-first reservation authority

For an admitted fresh request, let `L`, `B`, and `A` have their exact meanings
from §7.1. The store constructs the complete 155-byte `SessionClaimV1`,
complete `A = 605 + L` byte `ReservationAuthorityV1`, and complete
`66 + A = 671 + L` byte `BudgetChargeV1` before persistence. This record
explicitly supersedes NAR-DC-P1-002 §6.2 for every store created under
NAR-DC-P1-004. The `Reserve` payload is exactly `221 + A = 826 + L` bytes,
therefore `1071` bytes without an adaptor point or `1104` bytes with one:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 155 | complete canonical `SessionClaimV1` |
| 155 | `66+A` | complete canonical `BudgetChargeV1` |

Validation proves that the charge's embedded authority derives the exact
`NonceIdentityV1` in the claim; that the claim revision and authority revision
are exactly `1`; that the charge reserve sequence equals the enclosing journal
sequence; and that request ID, reservation ID, session ID, purpose, direction,
signing phase, kernel-message digest, base-transcript hash, signing roster,
local signing index, adaptor presence/point, complete protocol roster and
mapping, participant ID, nonce epoch, bound digest, template hash, key ID,
counterparty bucket, and immutable policy digest agree everywhere assigned.
The complete `JournalEntryV1` is exactly `309 + A = 914 + L` bytes, therefore
`1159` or `1192` bytes. There is no
digest cycle: the planned sequence is known before encoding, and the charge
does not contain the enclosing journal-entry digest.

The exact durable order is:

1. Append create-no-clobber the exact `Reserve(SessionClaimV1 ||
   BudgetChargeV1)` journal entry; synchronize its file and journal directory;
   reopen it; and verify the complete predecessor chain.
2. Create-no-clobber the byte-identical embedded
   `ReservationAuthorityV1` projection; synchronize its file and directory;
   reopen and verify it against the journal payload.
3. Create-no-clobber the byte-identical `SessionClaimV1` projection;
   synchronize and verify it against the journal payload.
4. Create-no-clobber the byte-identical `BudgetChargeV1` projection;
   synchronize and verify it against the journal payload.
5. Advance `active-vault-generation` by §11 and revalidate the complete
   transaction before returning any reservation handle.

The synchronized journal entry is the first durable authority. The other
three files are mandatory byte-identical projections, never independent
authority. A crash prefix after the journal append is completed only from the
exact authenticated journal payload, including its original timestamp and
system assignments. Recovery creates any missing byte-identical projections,
advances the pointer if uniquely determined, and immediately creates one
`Burned` tombstone using the exact orphan-claim rule. It never derives a nonce,
opens a secret, returns a reservation handle, refunds a charge, releases an ID,
or changes the original bytes.

A projection without the exact authoritative journal payload, or any changed,
partial, or conflicting projection, quarantines adaptor operations. The former
155-byte `Reserve` payload is an unpublished development format for this
runtime. It is rejected and is not silently migrated or interpreted as a
NAR-DC-P1-004 reservation.

### 7.3 Extended closed journal registry

NAR-DC-P1-002 §4.5 is extended by exactly these two values:

```text
0x0d BudgetCarryForward
0x0e PermitRetirementCarryForward
```

Values `0x01` through `0x0c` retain their assigned meanings except for the
explicitly superseded `0x01 Reserve` payload in §7.2. Every other byte is
rejected; there is no unknown, other, default, fallback, or non-exhaustive V1
kind.

Kind `0x02 ComputationAttempt` also retains its meaning. Its
`NonceDerivation` body is the exact 201-byte stage-specific wrapper assigned
in §8.3, while its Reveal and PartialSignature bodies remain the exact
193-byte record. This body refinement introduces no additional journal kind.

`BudgetCarryForward` has exactly the complete `(66 + A)`-byte
`BudgetChargeV1` as its payload, so its complete journal entry is exactly
`154 + A = 759 + L` bytes, therefore `1004` or `1037` bytes. It
preserves an already charged source reservation and creates no new budget
charge, reservation handle, claim projection, secret, or export authority.
The embedded original reserve sequence remains unchanged and is not required
to equal the carry-forward entry sequence.

### 7.4 PermitRetirementV1

`PermitRetirementV1` is exactly 229 bytes:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `DOMNVPR1` |
| 8 | 2 | version | exactly `1` |
| 10 | 155 | exposure version | complete `ExposureVersionIdV1`, state exactly `Spent` |
| 165 | 32 | spent journal-entry digest | exact entry that made the exposure `Spent` |
| 197 | 32 | retirement digest | definition below |

```text
retirement_digest = H_tag(
  "DOM:contracts-vault-permit-retirement:v1",
  bytes[0..197]
)
```

The permit ID is recomputed exactly as NAR-DC-P1-003 §6.2 assigns:

```text
permit_id = H_tag(
  "DOM:contracts-vault-export-permit-id:v1",
  exposure_version_id_155 || spent_journal_entry_digest_32
)
```

The exposure version and entry digest must be nonzero, canonical, mutually
consistent, and the permit ID must be nonzero. Exactly two exhaustive
provenance branches may introduce the record into successor history:

1. **Initial derivation.** The source contains the complete canonical `Spent`
   exposure and the exact contiguous authenticated source journal entry that
   made that exposure `Spent`. Validation recomputes the exposure version,
   authorizing entry digest, retirement digest, permit ID, every cross-field
   equality, and the entry's ancestry to the current verified source head.
2. **Transitive carry.** The source contains the complete 229-byte record as
   the payload of an authenticated contiguous `0x0e
   PermitRetirementCarryForward` entry whose entry is an ancestor of the
   current verified source head. Validation recomputes the retirement digest
   and permit ID and verifies every byte and cross-field equality. The
   original `Spent` exposure and original authorizing entry need not coexist
   in this later journal. The identical 229 payload bytes are re-carried.

A raw standalone retirement file, unjournaled record, filename, index entry,
or application-supplied payload is never accepted in either branch. A zero
permit ID, malformed or non-`Spent` exposure version, changed origin, invalid
ancestry, or differing bytes for one permit ID fails closed.
`PermitRetirementCarryForward` has the complete 229-byte record as its
payload, so its complete journal entry is exactly `88 + 229 = 317` bytes.
Both provenance branches provide collision evidence only. A retirement
carries no outbound bytes and can never create a resend or export capability,
including after any number of restore hops.

## 8. Computation input binding

### 8.1 DOM adaptor API correction

The next reviewed DOM adaptor revision replaces the published shared
`ComputationPermit` and commitment-requiring `store_reserved_secret` methods.
That published combination is not implementable in the required order:
`store_reserved_secret` consumes the derivation permit but demands a
precomputed commitment, while `open_secret` demands another computation
permit. Computing the commitment before the secret is durably sealed violates
ADR-SNV-002 §8.1; reusing or fabricating a second derivation permit violates
one-shot attempt authority.

The revised `NonceVaultV1` has these distinct private associated authority
types:

```text
type DerivationAttemptPermit;
type InitialSecretOpenPermit;
type StageComputationPermit;
type ArtifactPersistencePermit;
type PersistedExposureHandle;
type ExposurePermit;
```

None has a public constructor, byte representation, parser, clone, copy,
debug, display, serialization, equality, ordering, or conversion from another
permit type. They are not interchangeable.

The request and resume types are also distinct:

```text
FreshReservationRequestV1
ReservationResumeRequestV1
NonceDerivationRequestV1
StageComputationRequestV1
```

Each has private fields, no public constructor or parser, and is constructed
only by the safe vault-backed signer from trusted state and §7.1/§8.2
canonical bytes. Fresh and resume requests have no conversion in either
direction. `NonceDerivationRequestV1` and `StageComputationRequestV1` have no
conversion in either direction. A request is not a capability.

Both computation requests expose one read-only borrowed
`ValidatedVaultComputationViewV1` obtained only by calling an immutable method
on the unforgeable request itself. The Store never accepts such a view or its
fields as caller parameters. The view contains exactly:

```text
closed stage
reservation_context_binding_digest_32
borrowed validated SessionContextV1 and its exact canonical bytes
borrowed complete canonical §8.2 tagged-data bytes
operation_input_digest_32
effective_retry_counter_u64
```

The canonical tagged-data bytes are the complete data argument beginning at
`version_u16_le` and ending at the final field byte, before the outer `H_tag`
framing. Their length is one of the exact §8.2 sizes. The safe dom-adaptor
signer performs the complete protocol-roster, context, accepted-DSC1-message,
commitment/reveal-set, transcript replay, binding-factor, aggregate-point,
aggregate-key, kernel-message, and purpose validation before its private
constructor can create either request. It also proves that the digest is the
§8.2 `H_tag` result for those exact bytes.

The concrete Store calls only that read-only request method and independently
recomputes the authoritative `H_tag` over the returned canonical bytes. For a
`NonceDerivationRequestV1`, no 201-byte derivation record exists yet: the Store
compares the binding digest to the complete persisted authority, requires the
view context to equal the embedded derivation-base context in every byte
except its signer-owned effective retry counter, requires phase
`SigNonceCommit`, and requires equality among that counter, the context bytes,
the tagged-data bytes, and the operation-input digest. Only after those checks
does `begin_nonce_derivation` create, synchronize, reopen, and verify the
unique 201-byte record containing that counter. Requiring a pre-existing
derivation record on this path is forbidden.

For a `StageComputationRequestV1`, the Store instead requires one already
authenticated unique 201-byte derivation record, obtains the effective retry
counter only from it, and compares the request context to the persisted base
authority under the exact §8.3 compatibility relation: immutable fields and
the final retry remain equal while phase and transcript equal the assigned
stage-current values. It then cross-checks the stage, binding digest, context,
counter, tagged-data bytes, and operation-input digest before it may create a
later-stage attempt. The Store does not parse or interpret DSC1 protocol
messages and does not need hidden protocol bytes; the safe signer has already
validated those messages before constructing the request. No
application-visible setter, builder, mutable field, raw-byte constructor,
generic stage request, or caller-created view exists. The Store may inspect
and hash the immutable view but cannot substitute it.

The closed resume output is:

```rust
enum ReservationResumeResultV1<H> {
    Live(H),
    Terminal(TerminalReservationV1),
    RetryNotFound,
}
```

It has no unknown, other, fallback, or default variant. `RetryNotFound` grants
no handle or authority. A fresh-on-existing request returns the existing
closed `IdempotencyConflict`, `SessionIdReused`, or `RestoreQuarantined`
failure as applicable; it never returns `Live`. A resume binding mismatch
returns `IdempotencyConflict`; corrupt, partial, or divergent authority returns
`RestoreQuarantined`.

The replacement semantic interface and method partition are normative. A
conforming Rust revision uses these ownership edges and does not collapse two
authority types or expose an additional safe route:

```rust
fn claim_fresh_reservation(
  &mut self,
  request: FreshReservationRequestV1,       // consumed
) -> Result<Self::ReservationHandle, Self::Error>;

fn resume_claimed_reservation(
  &mut self,
  request: ReservationResumeRequestV1,      // consumed
) -> Result<
       ReservationResumeResultV1<Self::ReservationHandle>,
       Self::Error,
     >;

fn begin_nonce_derivation(
  &mut self,
  reservation: &mut Self::ReservationHandle,
  request: NonceDerivationRequestV1,
) -> Result<Self::DerivationAttemptPermit, Self::Error>;

fn seal_derived_secret(
  &mut self,
  reservation: &mut Self::ReservationHandle,
  attempt: Self::DerivationAttemptPermit,   // consumed
  secret: NonceSecretTransferV1,            // consumed by value
  seal_capability: VaultSecretSealCapabilityV1,
) -> Result<Self::InitialSecretOpenPermit, Self::Error>;

fn open_sealed_secret_for_commitment(
  &mut self,
  reservation: &mut Self::ReservationHandle,
  permit: Self::InitialSecretOpenPermit,    // consumed
  import_capability: VaultSecretImportCapabilityV1,
) -> Result<
       (NonceSecretTransferV1, Self::ArtifactPersistencePermit),
       Self::Error,
     >;

fn begin_stage_computation(
  &mut self,
  reservation: &mut Self::ReservationHandle,
  request: StageComputationRequestV1,       // NonceReveal or PartialAttempt
) -> Result<Self::StageComputationPermit, Self::Error>;

fn open_secret_for_stage(
  &mut self,
  reservation: &mut Self::ReservationHandle,
  permit: Self::StageComputationPermit,     // consumed
  import_capability: VaultSecretImportCapabilityV1,
) -> Result<
       (NonceSecretTransferV1, Self::ArtifactPersistencePermit),
       Self::Error,
     >;

fn persist_computed_artifact(
  &mut self,
  reservation: &mut Self::ReservationHandle,
  permit: Self::ArtifactPersistencePermit,  // consumed
  artifact: PreparedExposureV1,             // consumed by value
) -> Result<Self::PersistedExposureHandle, Self::Error>;

fn authorize_persisted_exposure(
  &mut self,
  reservation: &mut Self::ReservationHandle,
  persisted: Self::PersistedExposureHandle, // consumed
) -> Result<Self::ExposurePermit, Self::Error>;
```

The published single `claim_reservation` method is absent from the revised V1
trait. It has no compatibility wrapper or default implementation. Only
`claim_fresh_reservation` can create; only `resume_claimed_reservation` can
resume, report a terminal result, or return `RetryNotFound`.

`seal_derived_secret` returns `InitialSecretOpenPermit` only after the complete
secret envelope is durably created, its file and parent directory are
synchronized, and the object is reopened, authenticated, byte-verified, and
matched to the exact derivation attempt, authority, and effective context. It
does not accept or compute a commitment. The initial open permit authorizes
exactly one open for commitment computation in that process and reservation;
it is never reconstructed after restart. A crash after the derivation attempt
and before a matching persisted commitment burns the slot. The sealed object
remains the durable source for later reveal and partial stages, but neither
later stage may use the initial permit.

`begin_stage_computation` rejects `NonceDerivation`; its permit records exactly
one reveal or partial attempt and is consumed by the matching stage open.
`open_secret_for_stage` rejects the initial-open permit and every wrong stage.
The Store never returns plaintext without consuming the corresponding opaque
permit and crate-private import capability.

Each successful open returns exactly one new
`ArtifactPersistencePermit` beside the one secret transfer. That permit is
bound to the live Store authority, open instance, reservation, nonce identity,
attempt digest, operation-input digest, phase, artifact kind, exposure
sequence, expected lifecycle revision, and exact stage context. It is
process-only and one-shot. The safe signer alone consumes the secret transfer
to construct a non-cloneable `PreparedExposureV1` carrying the same private
computation binding; application code can construct neither value.

`persist_computed_artifact` accepts only the matching pair, strictly parses
and canonical-reencodes the prepared public artifact, performs every available
public equation and context/binding verification, and never recomputes a nonce,
reveal, secret-derived partial scalar, or other secret-derived artifact. Its
durable action is stage-specific:

- for Commitment, it persists the exact already computed outbound bytes as
  the `Persisted` exposure projection and the one canonical
  `CommitmentPersisted (0x03)` journal entry, synchronizes, reopens, and
  byte-verifies both;
- for Reveal, it performs the same operation with the one canonical
  `RevealPersisted (0x05)` journal entry; and
- for PartialSignature, it executes the complete unchanged
  NAR-DC-P1-002 §6.10.1 transaction before returning: verify and retain the
  active secret-envelope digest; create-no-clobber, synchronize, reopen, and
  verify the exact `Persisted` partial exposure at `r+1`; create and durably
  rename the canonical `Consumed` tombstone at `r+2`; append exactly one
  `PartialConsumed (0x06)` journal entry containing that partial and tombstone;
  unlink and synchronize the secret path; and reverify the complete prefix.
  There is no standalone PartialSignature-persisted journal kind or journal
  entry.

Only after the applicable complete transaction succeeds does the method
return one `PersistedExposureHandle`. It returns no outbound bytes. A dropped,
wrong, reused, cross-stage, cross-attempt, or cross-Store persistence permit
cannot persist or authorize anything. An error after secret open follows the
exact stage crash-prefix rules and never permits recomputation.

`PersistedExposureHandle` is itself a private process-only, one-shot authority,
not a durable record and not a public lookup token. It binds all of:

- private pointer identity to the same live `StoreAuthorityInner`, nonzero
  process `open_instance_id`, retained root/generation/lock capabilities, held
  lock acquisition, root and lock identity digests, active vault ID, nonce
  epoch, generation, and issuance-time verified journal-head snapshot;
- the exact reservation ID, complete `NonceIdentityV1`, attempt digest,
  operation-input digest, phase, artifact kind, exposure sequence, expected
  revision, and persisted lifecycle revision;
- the complete `Persisted` `ExposureVersionIdV1`, complete exposure-record
  digest, exact outbound digest and length, and either the exact
  Commitment/Reveal persisted-entry digest or the exact PartialConsumed entry
  digest plus complete `Consumed` tombstone and deleted-secret-envelope
  digests, according to the closed artifact kind; and
- proof that the persisted entry is on the unique contiguous current journal
  ancestry and that its projection is byte-identical.

It has no public constructor, parser, byte conversion, clone, copy,
serialization, equality, ordering, downcast, or cross-process reconstruction.
`authorize_persisted_exposure` revalidates every binding, private pointer
identity, live lock, projection, and ancestry against the current head. A
cross-Store, reopened-Store, cross-reservation, cross-stage, wrong-artifact,
wrong-revision, changed-head-branch, or reused handle fails closed.

Dropping the handle or process death after `Persisted` is durable but before
the first matching `Authorized` transition creates no reconstruction right
and no export or resend capability. Durable safety never depends on `Drop`.
For Commitment or Reveal, the next recovery preserves the exact persisted
bytes as immutable evidence and resolves `CrashAmbiguity` to `Burned` without
refund under the assigned single-tombstone transaction. For PartialSignature,
death at any point inside `persist_computed_artifact` follows unchanged
NAR-DC-P1-002 §6.10.1: before the partial is durable it burns; after the
partial is durable it completes the byte-identical `PartialConsumed`/
`Consumed` transaction without recomputation. If the returned handle is then
lost before authorization, the already canonical `Consumed` tombstone remains
the only terminal tombstone; recovery verifies that complete prefix and
quarantines further adaptor action for the unexported partial. It never writes
a conflicting `Burned` tombstone and never reconstructs an authorization
handle. Once `authorize_persisted_exposure` has consumed a live handle and a
matching `Authorized` transition is durable, the unchanged deterministic
prefix rules either complete the exact transaction to `Spent` or quarantine;
they never return to the pre-authorization branch or recompute bytes.

`authorize_persisted_exposure` accepts no `PreparedExposureV1`, replacement
bytes, caller receipt, Boolean, digest-only authority, or storage-success
claim. It rereads only the exact persisted artifact named by its private
handle and performs the retained local-profile `Persisted -> Authorized ->
Spent` transaction. For a partial signature it first verifies that
`persist_computed_artifact` already completed the exact PartialConsumed entry,
irreversible secret deletion, and synchronized `Consumed` tombstone at the
assigned intermediate revision; it never creates a second tombstone or a
standalone persisted journal entry. Only after every required journal entry,
projection, file sync, directory sync, reopen, and byte check succeeds does it
return the existing one-shot `ExposurePermit`; `export` consumes that permit
and returns only the persisted bytes. Commitment and reveal keep the verified
sealed secret for the next stage. No method combines an open with direct
export.

All other `NonceVaultV1` associated types and consuming methods—reservation,
export, resend, abort, and restore-state delegation—retain their signed
semantics as refined above. Private I/O helpers may split mechanical work, but
no alternate public route may seal, open, derive, persist, authorize, or
export nonce material.

The only exception to the general attempt-before-secret-computation wording is
the private zero-scalar retry resolution for `NonceDerivation` in §8.3. It
creates no persisted secret and no public material. Every secret open, seal,
public computation, reveal operation, and partial operation remains forbidden
until its exact durable attempt is verified.

### 8.2 Canonical digest framing

The operation-input digest is:

```text
H_tag(
  "DOM:scriptless-vault-computation-input:v1",
  version_u16_le ||
  stage_u8 ||
  reservation_context_binding_digest_32 ||
  context_length_u32_le || stage_context_v1 ||
  field_count_u8 ||
  repeated(field_kind_u8 || field_length_u32_le || exact_field_bytes)
)
```

`version` is exactly `1`. The 32-byte binding digest is the exact digest at the
end of the embedded `ReservationContextBindingV1`; it is nonzero and must
match the complete authority loaded under the same retained lock. Fields occur
in the displayed order for each stage, with no absent placeholder, padding,
trailing byte, Serde, bincode, or native layout.

The closed field-kind registry is:

```text
0x01 ProtocolCommitmentSetV1
0x02 ProtocolRevealSetV1
0x03 BindingFactor32
0x04 AggregateNonceHat33
0x05 AggregateSigningKey33
0x06 KernelMessageDigest32
```

`ProtocolCommitmentSetV1` is exactly 214 bytes in this two-party profile:

```text
ASCII "DOMNVCM1" [8]
|| version_u16_le = 1 [2]
|| participant_count_u16_le = 2 [2]
|| two ordered commitment entries [202]
```

Each 101-byte commitment entry is:

```text
participant_id_32
|| g1a_participant_index_u16_le
|| accepted_session_message_digest_32
|| canonical_NonceCommitmentV1_35
```

Both entries occur in the exact protocol-roster participant-ID order from
§7.1. The G1A index, purpose, participant index inside the commitment, and
message sender all match that roster entry. The 32-byte message digest is
recomputed from the complete immutable accepted DSC1 commitment message bytes
under signed NAR-002 §8.2. Both commitments must have been accepted before a
reveal-stage request can exist.

`ProtocolRevealSetV1` is exactly `12 + 135*m` bytes:

```text
ASCII "DOMNVRL1" [8]
|| version_u16_le = 1 [2]
|| present_count_u16_le = m [2]
|| m ordered reveal entries
```

Each 135-byte reveal entry is:

```text
participant_id_32
|| g1a_participant_index_u16_le
|| accepted_session_message_digest_32
|| canonical_NonceRevealV1_69
```

Entries are a strict prefix of the exact protocol roster and are ordered by
participant ID. Every reveal matches that participant's already bound
commitment byte for byte, and each message digest is recomputed from the
complete immutable accepted DSC1 reveal message. For the local
`NonceReveal` attempt, `m` is exactly the local protocol-roster index (`0` or
`1`), so the set contains exactly the reveal messages that NAR-002 §8.2
requires to precede the local reveal and never contains the not-yet-produced
local reveal. For `PartialAttempt`, `m` is exactly `2`; both reveals are
present, verified, and accepted. No other count or subset is canonical.

The exact stage assignments are:

| Stage | Stage byte | Signing phase | Ordered fields |
|---|---:|---|---|
| NonceDerivation | `0x01` | `SigNonceCommit` | none; field count `0` |
| NonceReveal | `0x02` | `SigNonceReveal` | complete `ProtocolCommitmentSetV1`, current `ProtocolRevealSetV1`; field count `2` |
| PartialAttempt | `0x03` | `SigPartial` | complete `ProtocolCommitmentSetV1`, complete `ProtocolRevealSetV1`, `BindingFactor32`, `AggregateNonceHat33`, `AggregateSigningKey33`, `KernelMessageDigest32`; field count `6` |

Every other stage byte and every other field-kind byte is rejected. No
unknown, other, default, fallback, or non-exhaustive V1 discriminant exists.

The stage context is an exact validated `SessionContextV1` constructed only by
the safe signer under §8.3. It is not created by mutating caller-owned public
fields. The binding factor is a 32-byte canonical big-endian nonzero scalar,
points are canonical compressed nonidentity SEC1 values of exactly 33 bytes,
and the kernel-message digest is exactly 32 bytes and equals the context field.
Every length is checked before allocation.

For stage-context length `L`, the complete tagged data before the outer
`H_tag` framing is exactly:

```text
NonceDerivation: 40 + L bytes
NonceReveal:     276 + L + 135*m bytes, m = local protocol-roster index
PartialAttempt:  696 + L bytes
```

The 40-byte common prefix is `2 + 1 + 32 + 4 + 1` bytes. The reveal arithmetic
adds field encodings of `5 + 214` and `5 + 12 + 135*m`. The partial arithmetic
adds `219 + 287 + 37 + 38 + 38 + 37 = 656` bytes. In the operational profile,
the resulting exact input sizes are:

| Stage | Refund/Funding (`L=245`) | ClaimAdaptor (`L=278`) |
|---|---:|---:|
| NonceDerivation | 285 | 318 |
| NonceReveal, local protocol index 0 | 521 | 554 |
| NonceReveal, local protocol index 1 | 656 | 689 |
| PartialAttempt | 941 | 974 |

`AttemptRecordV1.operation_input_digest` is this exact digest. A stage/phase,
binding digest, context, participant/message mapping, commitment set, reveal
set, binding factor, aggregate point, aggregate key, or message mismatch
rejects the operation before secret open. The vault-backed signer obtains the
sets from immutable accepted protocol state and retains its own exact
commitment/reveal artifacts; application code cannot reconstruct, reorder, or
replace them.

### 8.3 Effective-context and attempt ordering

The `retry_counter` is part of canonical `SessionContextV1`. Its V1 initial
value and ownership are now closed: the safe vault-backed signer constructs
the derivation-base context with `SigningPhaseV1::SigNonceCommit` and
`retry_counter = 0`. If a public input already carries any other phase or a
nonzero retry counter, the signer rejects it before reservation or budget
admission; it never treats those bytes as a caller-selected starting point.
Neither an application, peer, restore record, Store implementation, nor
operation request can supply, increment, decrement, or reset the counter. Only
the signer owns the checked local counter during the private KDF loop.

The final effective retry counter is durable non-secret authority and is never
recovered by opening or decrypting a nonce-secret object. The complete
`NonceDerivationAttemptV1` is exactly 201 bytes:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 193 | derivation attempt | complete unchanged canonical `AttemptRecordV1`; phase `SigNonceCommit`, artifact `Commitment` |
| 193 | 8 | effective retry counter | exact final signer-owned `u64` value, little-endian |

The inner attempt's `operation_input_digest` is recomputed from the exact
`NonceDerivation` input in §8.2, including the effective context containing
that same counter. Its nonce identity, expected revision, phase, artifact, and
digest must match the authority and stage exactly. Thus the inner attempt
digest transitively binds the appended counter through the operation-input
digest, and the enclosing journal-entry digest directly binds all 201 bytes.
A changed counter with an unchanged attempt, a changed attempt with an
unchanged counter, a counter different from the effective context, wrong
phase/kind, or trailing byte fails closed.

For `JournalEntryKindV1::ComputationAttempt (0x02)`, the derivation payload is
the complete 201-byte `NonceDerivationAttemptV1`, so the complete journal
entry is exactly `88 + 201 = 289` bytes. Its canonical attempt projection at
`attempts/<identity_key>/<expected_revision_20_decimal>-01.attempt` is the
same byte-identical 201-byte object. The retained journal-first attempt
transaction appends, synchronizes, reopens, and verifies the 289-byte entry;
then create-no-clobber persists, synchronizes, reopens, and byte-verifies the
201-byte projection; then advances and verifies the active-generation pointer
under the unchanged transaction rules. A crash prefix is completed only from
the exact authenticated journal bytes and then burns the identity; it never
regenerates the pair.

Reveal and partial attempts remain complete 193-byte `AttemptRecordV1`
payloads, 193-byte projections, and `88 + 193 = 281` byte journal entries.
For `RestoreRecordFamilyV1::Attempt (0x02)`, a Commitment subtype has the
complete 201-byte `NonceDerivationAttemptV1` as its canonical record bytes;
Reveal and PartialSignature subtypes have the unchanged complete 193-byte
`AttemptRecordV1`. The 155-byte restore key retains the inner attempt digest,
artifact subtype, and expected revision. The record length distinguishes the
assigned body, and duplicate keys or wrappers with different appended retry
counters conflict and quarantine. Backup, restore, collision scanning, and
record-set hashing preserve all 201 derivation bytes.

Every later-stage constructor obtains the final counter exclusively by
loading and authenticating that unique derivation journal/projection record
and its authority ancestry. A missing record, journal/projection mismatch,
multiple nonidentical candidates, missing restored wrapper, or secret object
without its matching 201-byte attempt burns or quarantines as already
assigned. There is no fallback to counter zero, caller state, a fresh KDF, or
secret decryption merely to discover the counter.

Because the signed nonce KDF increments that counter whenever either
wide-reduced scalar is zero, the final effective context cannot be committed
before that private loop finishes. This section expressly refines only the
initial KDF ordering named in §2. The complete derivation-base context with
counter zero remains durably bound in `ReservationContextBindingV1`; the
effective context differs from it only in the signer-owned retry counter.

After the reservation transaction is fully durable and before any nonce
secret file, public nonce, commitment, attempt, or public material exists, the
vault-backed signer performs exactly this order:

1. Load and byte-verify the complete reservation authority and derivation-base
   context, including phase `SigNonceCommit`, retry zero, base transcript,
   protocol roster, local mapping, and context-binding digest.
2. Obtain one owned fresh `aux_rand_32` from the operating-system CSPRNG and
   run the complete checked two-nonce KDF retry loop privately in memory,
   starting from the signer-owned counter zero. The same owned auxiliary bytes
   remain bound across zero-scalar retries as signed NAR-001 requires.
3. If either scalar reduces to zero, zeroize the complete rejected pair and
   every temporary, increment the signer-owned counter with checked
   arithmetic, re-encode an otherwise byte-identical context, and retry.
   Overflow or RNG failure is terminal.
4. Retain the first nonzero pair in one owned, non-cloneable, zeroizing value
   and retain the one final effective derivation context containing the exact
   final counter. The pair is never derived again for this reservation.
5. Construct one opaque `NonceDerivationRequestV1` from that effective context
   and the authority's exact context-binding digest, then call
   `begin_nonce_derivation`. The Store obtains the request's immutable
   validated vault view, recomputes its `H_tag`, requires equality among its
   effective retry value, context, digest, and authority, and encodes that
   value at wrapper offset 193. It durably appends,
   synchronizes, reopens, and verifies the exact 201-byte
   `NonceDerivationAttemptV1` and its 289-byte journal entry before proceeding.
6. Consume the derivation permit and retained pair through
   `seal_derived_secret`. The canonical `NonceSecretRecordV1` stores the final
   effective derivation context and both nonces. The Store seals it, durably
   creates and synchronizes the secret-object file and parent directory, then
   reopens, authenticates, byte-verifies, and cross-checks the complete
   envelope, metadata, context, authority, and plaintext.
7. Only after step 6 succeeds may the Store return one private
   `InitialSecretOpenPermit`. The signer consumes it through
   `open_sealed_secret_for_commitment`, validates the opened transfer against
   the same effective context and authority, and receives the paired one-shot
   `ArtifactPersistencePermit`. It derives the public nonce pair and canonical
   commitment, zeroizes the opened secret owner, and submits the resulting
   privately bound prepared commitment and persistence permit to
   `persist_computed_artifact`. Only its returned
   `PersistedExposureHandle` may enter `authorize_persisted_exposure`; only
   that method's returned `ExposurePermit` may enter `export`. No derived
   public value leaves the cryptographic/storage boundary before the verified
   sealed object and exact public artifact are durable and the exposure is
   irreversibly spent.

An error or process death before or during attempt persistence zeroizes the
in-memory pair when memory remains available; durable safety never depends on
that destructor. The already charged reservation is resolved by the exact
orphan recovery branch as `Burned`, is never restarted, and is never refunded.
Recovery does not rerun the KDF.

Process death after the attempt but before a verified secret object or matching
persisted commitment burns the identity and never reruns the KDF.

`NonceReveal` and `PartialAttempt` perform no KDF and no retry. They construct
private validated **stage-current contexts** from the effective derivation
context. The following fields are immutable and must remain byte-identical to
the stored secret and authority: version, chain ID, session ID, purpose,
direction, template hash, kernel-message digest, final retry counter, complete
G1A signing roster, local G1A index, and adaptor presence/point. The phase and
transcript fields evolve only by the exact rules below; no other difference is
permitted.

Let `H_base` be the transcript hash in the derivation-base and effective
contexts. Let the commitment and reveal sets be the exact canonical sets in
§8.2. Using only signed NAR-002 §8.2
`advance_transcript_hash_v1`, compute:

```text
H_commit = fold H_base over both commitment-entry message digests
           in strict protocol-roster participant-ID order,
           using each roster entry's direction and SigNonceCommit

H_reveal_prefix(local) = fold H_commit over exactly the reveal entries whose
                         protocol-roster index is less than the local index,
                         using each entry's direction and SigNonceReveal

H_reveal_all = fold H_commit over both reveal-entry message digests
               in strict protocol-roster participant-ID order,
               using each entry's direction and SigNonceReveal
```

These snapshots use exact round barriers, not arrival order. An incoming
`SigNonceCommit` is received into a bounded unauthoritative buffer and is not
accepted into the transcript until the local derivation attempt, sealed
secret, and persisted local commitment are complete. Both commitment messages
are then validated and applied in strict participant-ID order to reach
`H_commit`. During the reveal round, the local participant at roster index
`i` may begin only after the exact prefix of reveal messages at indices below
`i` has been accepted; later or out-of-order reveals remain buffered. This is
the exact source of `H_reveal_prefix(local)`.

After both reveals are accepted and `H_reveal_all` is reached, every
participant begins and durably persists its local partial attempt/artifact
against that same phase-boundary transcript before any `PartialSignature`
message for the round is accepted. An early partial is buffered and cannot
change the local operation input. Only after the local partial is durably
persisted may the two partial messages be validated and applied in signed
NAR-002 strict participant-ID order for the later protocol transcript. This
barrier does not discard or reorder an accepted message; it defines the exact
pre-acceptance snapshot used by the local cryptographic operation and prevents
participant-dependent partial-signing contexts.

The `NonceReveal` stage context has phase `SigNonceReveal` and transcript hash
exactly `H_reveal_prefix(local)`. Its operation input binds the complete
commitment set and that exact reveal prefix. The `PartialAttempt` stage
context has phase `SigPartial` and transcript hash exactly `H_reveal_all`; its
operation input binds the complete commitment and reveal sets. A stage context
with the immutable base transcript, a future transcript, a missing message, a
message applied in arrival order, a changed sender direction, a duplicate, or
an out-of-order set is rejected.

Before either later secret open, the safe dom-adaptor signer exclusively
compares the stage context to the effective derivation context under this
explicit compatibility relation, verifies every message digest from immutable
accepted DSC1 bytes, replays the transcript from `H_base`, verifies each reveal
against its commitment, verifies the complete authority binding, and privately
constructs `StageComputationRequestV1`. The Store does not duplicate protocol
validation or require hidden DSC1 bytes. It obtains the request's exact
§8.1 read-only validated view, recomputes its `H_tag`, and cross-checks the
typed stage, immutable persisted authority/context fields under the explicit
§8.3 compatibility relation, binding digest, operation-input digest, and
effective retry counter against the unique 201-byte derivation record. The
exact stage attempt is then made durable
through `begin_stage_computation` before
`open_secret_for_stage` consumes its permit and returns the secret transfer
paired with a new stage-bound `ArtifactPersistencePermit`. The safe signer
computes at most one prepared artifact, and the same
`persist_computed_artifact -> authorize_persisted_exposure -> export` chain is
mandatory. A mismatch is a permanent authorization failure, never a reason to
rederive or retry a nonce.

## 9. Nonce-secret object assignment

The active nonce secret exists only at:

```text
nonce-secrets/<identity_key>.secret
```

It is one complete 627..=1122-byte `VaultObjectEnvelopeV1` with plaintext
`NonceSecretRecordV1`. Its object-header revision is exactly:

```text
checked(derivation_attempt.expected_lifecycle_revision + 1)
```

For a fresh reservation this is revision `2`, equal to the future persisted
commitment revision. The secret object is not a lifecycle projection and this
equality does not create a second lifecycle record. Its header identity,
purpose, epoch, revision, and bound digest must match the reservation,
`NonceIdentityV1`, derivation attempt, and secret plaintext exactly.

The plaintext context is exactly the effective derivation context from §8.3:
phase `SigNonceCommit`, the final signer-owned retry counter, and the exact
base transcript hash. It is not rewritten as transcript messages are accepted.
An initial commitment open requires complete byte equality with that context.
A reveal or partial open uses only the explicit §8.3 compatibility relation:
all immutable fields and final retry counter remain byte-identical, while the
phase and transcript equal the one canonically replayed stage-current view.
Neither a Store implementation nor application caller may weaken that check
to selected fields, a digest supplied by the caller, or phase-only mutation.

The file uses create-no-clobber. A second candidate, changed envelope,
identity mismatch, invalid AEAD, wrong plaintext length, wrong revision,
symlink, or noncanonical path quarantines the identity. No recovery path
regenerates it.

## 10. Abort and terminal mapping

The mapping is exhaustive:

| `AbortReasonV1` | Tombstone reason | Public state |
|---|---|---|
| `BeforePublicMaterial` | `AbortConsumed` | `AbortedBeforePublicMaterial` |
| `PublicMaterialMayHaveExisted` | `AbortConsumed` | `ConsumedOnAbort` |
| `CrashAmbiguity` | `Burned` | `Burned` |
| `RestoreAmbiguity` | `Burned` | `Burned` |

Every branch uses NAR-DC-P1-002 §6.7.1 and §6.10.1 under live retained
authority. `BeforePublicMaterial` is valid only when no exposure exists. A
caller claim about secret presence, public exposure, or durable state is never
accepted. An existing exact tombstone is returned idempotently only after its
complete envelope, plaintext, journal ancestry, and terminal projection are
verified. A conflicting tombstone quarantines.

No terminal transition refunds a lifetime, counterparty, or rolling charge,
releases a session ID, deletes an attempt/exposure/journal record, or enables a
new nonce. Concurrent occupancy ending after a durable terminal record is not
a budget refund.

## 11. Active-generation pointer advancement

Every normal operational journal append outside a staged restore is followed
by one active-pointer transaction while the same lock remains held. A restore
constructs its complete successor journal and activation pointer inside the
NAR-DC-P1-002 pending transaction and follows §15.1 instead.

1. Construct the exact successor `ActiveVaultGenerationV1` with unchanged
   identity, vault, epoch, generation, and master-envelope digest; sequence and
   head equal the newly verified journal head.
2. Create-no-clobber `.active-vault-generation.staging`, synchronize and
   reopen it, and verify every byte.
3. Atomically rename it over `active-vault-generation`, synchronize the root,
   reopen the active file, and verify it against the complete journal.

Only this fixed staging name is permitted for a normal pointer advance. If a
crash leaves the old active pointer and a verified journal suffix, recovery
may advance to the unique greatest contiguous authenticated journal head. If a
staging record exists, it must equal that unique next projection byte for byte.
If the active pointer is ahead, references another chain, has more than one
possible suffix, or conflicts with staging, adaptor operations remain
quarantined. Recovery never removes or rewrites journal entries.

For creation, the rename is no-replace because no prior pointer exists. For a
normal advance, replacement must be an atomic same-directory operation. The
old and new bytes are never simultaneously accepted as two authorities.

This record refines NAR-DC-P1-002 §8.5 active-generation validation as follows:

1. A fresh generation-one store has vault generation `1`, nonce epoch `1`,
   sequence/head `0/zero_32`, an empty journal, and no restore pair. Its
   `generation-core.bin` fields and active-record core fields are byte-equal
   and its core digest is recomputed directly. After normal entries exist, its
   current active sequence/head is the unique greatest contiguous verified
   journal head. It still has no `EpochAdvance`/`RestoreComplete` anchor for
   generation `1`.
2. A restored generation has exactly one **matching** `EpochAdvance` followed
   immediately by `RestoreComplete` whose successor vault ID, nonce epoch,
   generation, generation-core digest, and restore transaction ID identify
   that active generation. Older restore pairs may occur only as verified
   ancestors in copied history; they do not match the current generation.
3. The current active sequence/head may equal that matching
   `RestoreComplete` head or any unique contiguous verified descendant created
   by normal operations. An active pointer ahead of the verified journal, on a
   different branch, or lacking the matching generation anchor quarantines.
4. `RestorePendingIndexV1.successor_active_generation_digest` commits the
   exact activation-time active-record snapshot at the matching
   `RestoreComplete` head. After normal descendants advance the live pointer,
   that digest must verify as the unique activation ancestor snapshot; it is
   not compared for equality with the mutable current active-record digest.

In NAR-DC-P1-002 language, “unique” for a restored active generation means the
one matching anchor pair described above, not the only restore pair in the
entire copied journal.

## 12. Live capability compatible with `NonceVaultV1`

The existing trait uses a non-generic associated `ExposurePermit`, so a Rust
borrowed lifetime cannot appear in that associated type. V1 ratifies the
following semantically equivalent rooted design instead of weakening the live
authority requirement.

`ExposureExportCapabilityV1` is a private, non-cloneable, non-copyable,
non-debuggable, non-serializable, one-shot value. It owns a private strong
reference to the exact `StoreAuthorityInner` that owns:

- the retained root and active-generation directory capabilities;
- the retained lock-file handle and still-live exclusive lock acquisition;
- an OS-CSPRNG-generated, nonzero, process-only `open_instance_id` that is
  never persisted or exposed;
- verified root and lock identity digests;
- the currently validated store identity and stable active-generation handles;
  and
- the active vault, epoch, generation, and current active-record identity.

Each capability separately owns immutable capability-local bindings for one
exact spent exposure version, the exact authorizing journal entry, artifact
kind, trusted outbound digest, permit ID, and verified current journal-head
snapshot under which that capability was issued. Multiple sequential
capabilities do not mutate or replace bindings inside the shared inner value.

The concrete store owns another reference to the same inner value. `export`
consumes the capability and verifies private pointer identity with
`Arc::ptr_eq` or a semantically equivalent unforgeable pointer-identity check;
the process-only open ID; retained-handle metadata; held lock; stable inner
fields; and every capability-local binding. The authorizing entry must be an
ancestor of the still-current verified head and the bound snapshot must match
the issuance state. Any mismatch fails closed. The capability cannot be used
with a reopened store, another process, another lock acquisition, another
root, another vault, another exposure, or another journal snapshot.

Dropping the Store while a capability exists keeps the lock and handles alive
but does not permit export because no Store instance with the same private
authority remains to consume it. The capability has no `into_inner`, byte
codec, public constructor, downcast, trait-object plugin route, or caller-owned
receipt Boolean.

No pointer value, process ID, `open_instance_id`, lock token, strong-reference
address, or capability-local binding object is persisted or exposed.

This design is the accepted V1 interpretation of NAR-DC-P1-002 §5.6 for the
published non-GAT trait. A future GAT redesign requires a new reviewed API; it
cannot silently coexist as another V1 authority.

## 13. Permit lookup and exact resend

The 32-byte `permit_id` remains the public non-authoritative lookup value from
NAR-DC-P1-003. Resend lookup streams only canonical `Spent` exposures that
belong to the current active vault ID, current nonce epoch, and current vault
generation, plus their authorizing journal entries. Exactly one current match
is required. Zero matches returns a closed not-found-or-retired result; more
than one match, an ID collision, changed bytes, wrong artifact kind, wrong
trusted adaptor outbound digest, or wrong journal ancestry quarantines.

A predecessor-generation, source-backup, carry-forward, restored, or otherwise
historical permit is retired. Its `PermitRetirementV1` or original verified
history participates only in lifetime collision detection and can never create
resend authority. Trusted protocol state must additionally permit resend for
that exact current session and artifact; storage state alone is insufficient.

The journal may have valid descendants after the entry that made the exposure
Spent. Resend therefore requires that entry to be one exact ancestor of the
current verified contiguous head; equality with the current head is not
required. A newly created resend capability binds both the original spent
entry and the current head snapshot under the live authority from §12.

The trusted protocol state supplies the expected closed artifact kind and the
adaptor-domain outbound digest. It never supplies replacement bytes. The store
reads only the exact persisted exposure bytes, recomputes both adaptor and
Contracts digests, creates one new live capability after complete validation,
spends it, and returns one closed typed artifact. No nonce KDF, secret open,
signing, reveal computation, or caller-provided permit record is invoked.

## 14. Filesystem and platform engineering profile

### 14.1 Required semantics

The Linux Phase 1B implementation must use a reviewed safe-Rust
capability-oriented filesystem dependency plus a reviewed safe wrapper for an
exclusive advisory file lock. The exact dependency versions and feature graph
are pinned in `Cargo.lock` and recorded in an accepted engineering ADR before
the runtime commit. Application code contains no `unsafe` block.

The selected boundary must prove all of:

- open/create relative to retained directory handles;
- no symlink following for every authoritative file and directory;
- regular-file/directory type checks after open;
- create-no-clobber;
- atomic same-directory rename-no-replace where required;
- atomic same-directory replacement only for the active pointer;
- file data synchronization;
- parent-directory synchronization;
- retained-handle unlink;
- one retained exclusive lock acquisition; and
- owner-only mode `0700` for directories and `0600` for sensitive files.

If any required operation is unavailable through the reviewed safe boundary,
the Linux runtime is blocked; application code does not add raw-syscall unsafe
or fall back to ambient paths.

Windows and macOS backends remain unsupported for approval until separate
reviewed implementations prove equivalent no-follow, ACL, locking, replacement,
and synchronization semantics on real runners. They fail closed for adaptor
store creation/open; prepared CI is not executed evidence.

### 14.2 Retained locking

Normal open never creates the lock file and never reopens its pathname per
operation. It opens the existing exact file without following symlinks,
verifies it, acquires an exclusive lock on that handle, then revalidates root
and lock identities. An in-process mutex serializes access to the retained
authority. A second process that cannot acquire the lock performs no read that
could become authorization and returns a closed busy/storage error.

### 14.3 Frozen component-length audit

Capability-relative traversal does not waive filesystem component limits. The
complete V1 component registry has the following maximum encoded lengths:

| Component template | Bytes |
|---|---:|
| `store-root-identity.bin` | 23 |
| `store-lock-identity.bin` | 23 |
| `active-vault-generation` | 23 |
| `.active-vault-generation.staging` | 32 |
| `restore-only-root.bin` | 21 |
| `restore-initialized-<id16hex>.bin` | 56 |
| `restore-pending` | 15 |
| `.restore-<tx16hex>.staging` | 49 |
| `restore-complete-<tx16hex>` | 49 |
| `generation-<u64_20>-<vault32hex>` | 96 |
| `.generation-<u64_20>-<vault32hex>.staging` | 105 |
| `backup-<u64_20>-<id32hex>` | 92 |
| `.backup-<u64_20>-<id32hex>.staging` | 101 |
| `generation-core.bin` | 19 |
| `master-key.envelope` | 19 |
| `journal` | 7 |
| `reservation-authorities` | 23 |
| `session-claims` | 14 |
| `budget-charges` | 14 |
| `attempts` | 8 |
| `exposures` | 9 |
| `nonce-secrets` | 13 |
| `tombstones` | 10 |
| `<reservation32hex>.authority` | 74 |
| `<session32hex>.claim` | 70 |
| `<seq20>-<reservation32hex>.charge` | 92 |
| `<identity105hex>` | 210 |
| `<revision20>-<kind2hex>.attempt` | 31 |
| `<sequence20>` | 20 |
| `<state2>-<digest32hex>.exposure` | 76 |
| `<identity105hex>.secret` | 217 |
| `<identity105hex>.tombstone` | 220 |
| `.<identity105hex>.tombstone.staging` | 229 |
| `<seq20>-<digest32hex>.journal` | 93 |
| `backup-master-key.envelope` | 26 |
| `backup-manifest.object` | 22 |
| `backup-bundle.digest` | 20 |
| `records` | 7 |
| `<RestoreRecordKey[0..105]hex>` | 210 |
| `<RestoreRecordKey[105..155]hex>.record` | 107 |
| `restore-pending.index` | 21 |
| `restore-manifest.bin` | 20 |
| `source-backup` | 13 |
| `successor-generation` | 20 |
| `activation` | 10 |
| `active-generation.bin` | 21 |

The maximum frozen component is therefore exactly 229 bytes. Before creating
or opening a V1 store, backup, or restore transaction, the reviewed
capability-oriented filesystem boundary obtains the effective component limit
for every retained destination filesystem. A limit below 229 fails closed
before mutation. The former 294-byte tombstone staging and 317-byte flat
restore-record components are invalid V1 names even on a filesystem that
could represent them. Full ambient path length is not authority; every
component is parsed and opened relative to its retained parent capability.

## 15. Lifetime uniqueness across history

Session ID, reservation ID, request ID, nonce identity, permit ID, and budget
charge uniqueness are lifetime properties. Their durable transitive authority
is the active generation's complete verified journal. Normal `Reserve` entries
carry the complete claim and charge. Restore carries forward any source charge
or permit retirement not already proven in copied target journal history. A
later backup copies that active journal, so the evidence survives arbitrary
backup/restore depth without depending on an older completed-restore directory.

Only history cryptographically and structurally connected to the active
authority participates. An unrelated directory is an unexpected entry, not
another authority. The same identifier with byte-identical canonical evidence
is one occurrence only where the assigning NAR explicitly permits it. The same
request, reservation, session, nonce identity, or permit ID with different
bytes or independent origins quarantines.

### 15.1 Exact restore carry-forward order

For an existing-device restore, copy and authenticate the complete target
journal exactly as NAR-DC-P1-002 assigns. For a new-device restore, begin an
empty successor journal. After `RestoreBegin`, the exact appended order is:

```text
RestoreRecord entries in canonical NonceIdentityV1 byte order
BudgetCarryForward entries in canonical reservation_id byte order
PermitRetirementCarryForward entries in canonical computed permit_id byte order
EpochAdvance
RestoreComplete
```

`RestoreComplete` remains the final activation entry. The complete successor
journal, including both carry-forward classes, is committed by the unchanged
NAR-DC-P1-002 pending-index journal sequence/head fields before activation.
The pending-index bytes, backup-record-family bytes, and terminal-record-set
bytes remain unchanged because the journal, not those record sets, carries
this lifetime evidence. Their completed-backup and pending-source-backup
record paths use the exact §4.4 nested supersession; the flat path is never
accepted.

The source charge set is the canonical union of every authenticated
variable-length `Reserve` charge and every authenticated variable-length
`BudgetCarryForward` charge in the source journal. Each charge length must be
derived from its embedded canonical context and must be exactly `916` or `949`
bytes. A new-device restore carries every source charge. An
existing-device restore carries every source charge not already proven as
byte-identical in copied target journal history. Sort by the embedded
reservation ID. Deduplicate only a byte-identical occurrence proven to be
common copied history. Equal request, reservation, or session IDs with
different complete charge bytes, a changed policy digest, or two independent
origins quarantines. Projection files may be reconstructed later only as exact
journal projections; they are not required inside the pending successor tree.

The source retirement set is the canonical union of the two exhaustive §7.4
provenance branches:

1. one newly derived `PermitRetirementV1` for every authenticated source
   `Spent` exposure whose exact authorizing entry is present in that source
   journal; and
2. every complete 229-byte `PermitRetirementV1` payload already carried by an
   authenticated contiguous `0x0e PermitRetirementCarryForward` source-journal
   entry, whether or not the original `Spent` entry remains in that later
   journal.

For an existing-device restore, a retirement already proven byte-identical in
copied target history is not appended again. For a new-device restore, every
source retirement is carried. Sort by recomputed permit ID and deduplicate only
proven byte-identical evidence. When initial derivation and an authenticated
prior `0x0e` entry produce the same complete 229 bytes, the set contains one
retirement. A repeated permit ID with different retirement bytes, origin
exposure, or spent entry quarantines. Target spent
entries already present in the copied target journal remain collision evidence
and become historical under the successor generation; they do not require a
duplicate retirement entry.

A standalone retirement record outside an authenticated `0x0e` entry is never
source authority; its presence at any closed-whitelist location quarantines.
Every successor backup copies its active journal, including the complete
`0x0e` entries. A later restore therefore validates the carried entry itself
and re-carries identical payload bytes without needing an older completed
backup or the original `Spent` entry. This rule is transitive for arbitrary
restore depth. Initial derivation and transitive carry remain collision-only
evidence and never become resend authority.

Carry-forward entries never create a reservation, live handle, secret,
capability, resend route, or budget refund. Restore imports no nonce secret,
live capability, computation permit, export permit, active reservation handle,
or mutable secondary index. The successor contains only the terminal identity
projection assigned by NAR-DC-P1-002 plus its lifetime journal evidence.

## 16. Local restore state and concrete APIs

### 16.1 Local-profile meaning

For the witness-free Phase 1B minimum, `RestoreState::Operational` means only:

- the retained root/lock identities are exact and authenticated;
- one active generation and pointer are exact;
- the complete local journal and object projection verify;
- all deterministic crash prefixes have been resolved;
- there is no unknown, conflicting, staging, pending, orphaned, or ambiguous
  entry; and
- every lifetime collision and budget projection check passes.

It does not claim detection of replacement of the complete authentic root with
an older authentic copy before open. That limitation is explicit and remains
blocked on the later remote monotonic witness scope.

The next reviewed DOM adaptor revision must update every public API comment and
type contract in this profile to use this witness-free local meaning. It must
not describe `Operational` as remote-anchor agreement, describe
`RestoreQuarantined` as awaiting witness reconciliation, claim that
`authorize_persisted_exposure` obtains a receipt, or construct the 252-byte
witness-profile permit record. The local profile does not weaken or emulate the
later witness profile; it is a separately explicit closed contract.

Any failed predicate above, an incomplete restore, backward authenticated
clock observation, source/target ambiguity, or unsupported platform produces
`RestoreState::RestoreQuarantined`. Ordinary non-Scriptless application
operations are outside this store and remain unaffected.

### 16.2 Restore API ownership

Restore is a concrete store API, not a method that accepts canonical bytes from
an application caller. It accepts:

- a retained source-backup parent capability and exact selected completed
  backup child;
- an owned, non-cloneable, zeroizing source backup passphrase;
- a retained existing-target Store authority or one absent new-device target
  component under a retained parent capability; and
- an owned, non-cloneable, zeroizing target unlock passphrase.

It validates and copies only from opened authenticated handles. It never
accepts a manifest, record set, master key, tombstone, journal head, vault ID,
receipt, success Boolean, or destination bytes from the caller.

`resume_restore` accepts only the retained target root capability and an owned
zeroizing target unlock passphrase. It obtains every source byte and identifier
from the exact in-root `restore-pending` or completed transaction assigned by
NAR-DC-P1-002. It does not accept or reopen a caller-selected source path,
source passphrase, manifest, key, or transaction ID.

In-place active-store unlock-passphrase/password change and in-place rewrap of
the active master-key envelope are unavailable in the Phase 1B minimum. This
prohibition does not alter the independent fresh backup master-key envelope
assigned by NAR-DC-P1-002 §10.4 or the fresh successor master-key envelope
assigned by its restore transaction. No production API, staging path,
recovery branch, or implicit in-place rewrite exists for active-store rewrap;
it requires a separately ratified transaction format and crash-recovery order.

## 17. Narrow tombstone cryptographic boundary

`dom-scriptless-crypto` may add only opaque production functions equivalent to:

```text
seal_tombstone_v1(canonical_tombstone, metadata, master_key)
open_tombstone_v1(envelope, expected_metadata, master_key)
```

They reuse the already approved `VaultObjectEnvelopeV1`,
ChaCha20-Poly1305, master-key hierarchy, record key role `0x02`, record kind
`0x02`, OS-CSPRNG instance ID/nonce, complete header AAD, and zeroization
policy. They accept and return the closed canonical `TombstoneV1` type, not
arbitrary plaintext, raw keys, Serde values, or caller-selected envelope
fields. Sponsor is rejected. The opened plaintext and every derived key are
zeroized on every path.

No new AEAD, KDF, nonce policy, key role, envelope version, or generic storage
encryption API is authorized.

## 18. Recovery outcomes

For every crash prefix, exactly one of these outcomes is valid:

1. no public artifact was exported and the identity is permanently burned;
2. one exact previously persisted `Spent` artifact is available for
   byte-identical resend under a new live one-shot capability; or
3. adaptor operations remain quarantined because unique safe recovery cannot
   be proved.

Recovery never:

- derives or regenerates a nonce;
- reopens a secret to recompute an existing output;
- accepts replacement outbound bytes;
- refunds a budget charge;
- removes a lifetime claim;
- rewinds a revision, epoch, generation, journal sequence, or terminal state;
- fabricates a receipt or witness result;
- trusts file modification time, filename alone, or application memory;
- deletes an unexpected artifact to make the root appear valid; or
- leaves quarantine without complete retained-handle revalidation.

Process-death tests must cut before and after every file write, file sync,
directory sync, staging rename, journal append, active-pointer replacement,
secret deletion, tombstone transition, capability creation, and simulated
export. A destructor is never required for durable safety.

## 19. DOM adaptor publication boundary

The computation request in §8 and the recovery surface assigned by
NAR-DC-P1-003 require a new reviewed DOM adaptor revision. Local implementation
and conformance tests are authorized by the parent mission. Publication and a
new public `dom-contracts` pin require a separate explicit remote-operation
authorization; the completed authorization for the previously published
revision does not automatically extend to this revision.

Until the new revision is published and pinned, the currently published
dependency remains valid for completed cryptographic and sealer evidence, but
full runtime conformance stays open. No absolute path, sibling worktree path,
`[patch]`, fictitious Git revision, or local override may enter tracked
production manifests.

## 20. Required implementation and evidence

Ratification alone closes no implementation or gate item. Required evidence
includes:

- byte, truncation, reserved-byte, unknown-discriminant, and trailing-byte
  tests for `BudgetPolicyV1`, `ReservationContextBindingV1`, revised
  `ReservationAuthorityV1`, `BudgetChargeV1`, `PermitRetirementV1`, both
  1071/1104-byte Reserve payloads, both 1159/1192-byte Reserve journal
  entries, both 1004/1037-byte budget carry entries, the 317-byte
  permit-retirement carry entry, the 201-byte derivation-attempt wrapper and
  289-byte journal entry, the unchanged 193/281-byte later-stage attempts,
  both protocol-set codecs, and every new digest preimage;
- exhaustive mutation tests for all 144 policy bytes, every byte of both
  499/532-byte context bindings, both 850/883-byte authorities, both
  916/949-byte budget charges, and all 229 permit-retirement bytes;
- exact root/generation whitelist tests, including wrong case, length,
  padding, symlink, hard link, device, socket, FIFO, duplicate, extra entry,
  the exact 229-byte valid tombstone staging name, the rejected 294-byte old
  name, authenticated-content-derived digest, and every invalid staging
  variant;
- completed-backup and pending-source-backup tests for the exact 210/107-byte
  nested restore-record components, full-key reconstruction, unchanged
  record-set bytes/digest, bottom-up synchronization, rejection of the old
  flat name, and fail-closed behavior when the filesystem component limit is
  below 229;
- creation and every deterministic fresh-store crash prefix, proving initial
  nonce epoch `1`, generation `1`, and correct zero-head/direct-core validation;
- reservation death after journal, authority projection, claim projection,
  charge projection, and pointer boundaries, proving permanent charge and burn;
- exact replay and conflicting replay for request, reservation, and session
  IDs; distinct fresh and resume request types; fresh-on-existing conflict;
  resume-on-missing `RetryNotFound`; and proof that neither route falls
  through to the other;
- instrumented proof that replay lookup precedes time, randomness, sequence,
  and all fresh system assignments, that resume reuses exact persisted
  assignments, and that a missing resume performs zero mutation and zero
  fresh work;
- proof that the safe caller cannot select key ID, counterparty bucket, or raw
  participant ID; exact KATs for the signed
  `DOM:scriptless-vault-budget-key:v1` and
  `DOM:scriptless-vault-counterparty:v1` preimages; validated one-to-one
  participant/signing mapping; two-participant acceptance; and operational
  rejection of every other participant count;
- streaming collision checks across active, predecessor, and restored source
  histories;
- global, counterparty, rolling, and concurrent enforcement under an explicit
  public evidence policy, with the exact per-key, per-key-and-counterparty,
  per-key rolling, and store-wide concurrent scopes; no production defaults;
  exact open-lower/closed-upper rolling boundary; immutable lifetime policy
  digest; equality to the maximum forward step accepted; maximum-plus-one,
  backward, future-charge, and overflow clock quarantine before admission;
- operation-input vectors for all three stages and mutation of every field,
  including both 214-byte commitment sets, reveal-set counts `0`, `1`, and
  `2` only where assigned, every accepted DSC1 message digest, every roster
  mapping, the context-binding digest, every stage-current transcript, and
  commitment/reveal/partial round barriers with early messages buffered but
  not accepted;
- read-only request-view tests proving the safe signer alone validates complete
  protocol/DSC1 state, the Store recomputes the canonical `H_tag` and
  cross-binds authority/context/retry without a protocol parser, and no caller
  can construct or substitute a request or view;
- an evidence-only forced zero-reduction retry proving final effective-context
  selection before the derivation attempt, no secret/public persistence before
  that attempt, signer-owned initial counter zero, one retained pair, exact
  201-byte durable final-counter authority and 289-byte journal entry,
  later-stage reconstruction without secret open, backup/restore preservation,
  crash-to-burn, no KDF on reveal/partial, immutable derivation fields, and
  exact NAR-002 transcript evolution between stage-current contexts;
- proof that application callers cannot construct a fresh, resume,
  derivation, or later-stage request, derivation-attempt permit,
  initial-secret-open permit, stage-computation permit,
  `ArtifactPersistencePermit`, or `PersistedExposureHandle`; cannot convert
  among those types; cannot open before durable sealing or open twice with one
  permit; cannot persist without the permit returned by that exact open; and
  cannot authorize before exact persisted bytes exist;
- exact stage-split persistence tests: only `0x03` and `0x05` persist
  Commitment and Reveal; PartialSignature completes one canonical
  `PartialConsumed (0x06)` transaction with the `Consumed` tombstone and no
  standalone persisted journal kind; handle loss before authorization burns
  Commitment/Reveal but preserves the single PartialSignature `Consumed`
  tombstone, enters quarantine, and produces no capability;
- compile-fail and runtime proof that `PersistedExposureHandle` cannot be
  constructed, cloned, serialized, moved across a Store/open instance,
  reservation, stage, or revision, or reconstructed after drop/restart;
- exact secret revision/path, duplicate, corruption, and wrong-header tests;
- all four abort reasons and every secret-present/no-secret prefix;
- compile-fail proof that live export capability cannot be constructed,
  cloned, copied, serialized, decoded, logged, reused, or applied to another
  Store;
- permit-ID collision, wrong kind, wrong digest, non-ancestor, and descendant
  head tests, plus historical/current-generation separation;
- exact resend proving zero nonce derivation, zero secret open, and zero signer
  invocation;
- real two-process exclusive-lock and CAS tests;
- Linux process-death tests around file and directory synchronization;
- tombstone seal/open KATs, all envelope-byte mutations, wrong role/kind/key,
  and zeroization review;
- old-backup restore, terminal union, new epoch, matching restore anchor,
  descendant active-head validation, activation-snapshot ancestry, and
  lifetime-ID collision tests;
- existing-device and new-device restore tests for exact sorted
  `BudgetCarryForward` and `PermitRetirementCarryForward` order, common-history
  deduplication, conflicting-origin quarantine, initial retirement derivation,
  transitive `0x0e` authority without the original Spent entry, rejection of a
  standalone retirement, retired-permit non-authority, and budget/permit
  preservation over at least three backup/restore hops;
- compile-time and runtime proof that password/passphrase rewrap has no Phase
  1B API or staging path, and public API documentation tests for the explicit
  witness-free local restore semantics; and
- static and runtime proof that ordinary `dom-wallet-v3` has zero dependency,
  import, initialization, connection, or state sharing with this Store.

Fuzz targets must persist for policy, charge, permit retirement, both extended
journal kinds, the derivation-attempt wrapper, path grammar, journal recovery,
secret envelope, tombstone envelope, all four closed request types, and permit
lookup.
Executed Linux ASan/libFuzzer evidence must record revision, command, seed,
duration, executions, corpus, crashes, and exit code. Windows and macOS remain
open until real execution.

### 20.1 Exact-byte next-review routing

This table is a self-audit of assignment coverage, not independent review or
gate evidence. A new exact-byte reviewer must re-evaluate every row from the
beginning after a signature candidate hash is produced.

| Required review item | Assigned location | Candidate invariant |
|---|---|---|
| initial versus transitive permit provenance | §§7.4 and 15.1 | only canonical Spent+entry derives initially; only authenticated contiguous `0x0e` carries transitively; neither grants resend |
| tombstone staging basename | §4.2 | exact 229-byte component; digest comes from authenticated 495-byte contents; old 294-byte name rejected |
| split restore-record path | §4.4 | exact 210/107-byte components reconstruct one 155-byte key; completed and pending source backups share the rule |
| all frozen component lengths | §14.3 | complete table audited; maximum 229; smaller platform limit fails before mutation |
| signed budget-ID domains | §§3 and 6.2 | exact signed tags/preimages reused; conflicting draft spellings rejected |
| participant/roster authority | §6.2 | signed semantic one-to-one mapping, exactly two participants, no claimed nonexistent symbol, no caller-selected ID |
| complete reservation binding | §7.1 | 499/532-byte context+roster object is embedded in the 850/883-byte authority and transitively in every charge/Reserve record |
| forward-clock policy | §§6.1 and 6.3 | 144 bytes, nonzero maximum step, digest over `bytes[0..112]`, checked admission order |
| four budget scopes | §6.3 | per-key global, per-key+bucket counterparty, per-key rolling, store-wide concurrent |
| fresh versus resume authority | §7.1.3 | distinct opaque requests; fresh requires lifetime absence; resume requires one exact chain; zero-match resume is mutation-free `RetryNotFound` and never creates |
| effective retry and transcript contexts | §§8.2–8.3 | signer owns base phase/retry; exact 201/289-byte durable final-counter authority precedes seal; later contexts change only phase plus exact accepted-message folds under explicit round barriers |
| signer/Store request boundary | §§8.1–8.3 | signer validates full protocol and creates an unforgeable request; Store hashes the immutable complete view and cross-binds persisted authority/retry without interpreting DSC1 |
| seal-before-public API | §8.1 | distinct derivation, initial-open, stage, persistence, and fully bound persisted-handle authorities make durable seal precede commitment computation and exact stage-specific persistence precede authorization/export; Partial uses the sole `0x06` transaction |
| fixed-width arithmetic and registries | §§6.1, 6.3, 7.1–7.4, 8.2–8.3, and 14.3 | 144; 499/532; 850/883; 916/949; 1071/1104; 1159/1192; 1004/1037; 229; 317; 201/289 derivation attempt; 193/281 later attempts; and exact `40+L`, `276+L+135*m`, `696+L` inputs; only `0x0d` and `0x0e` extend the closed journal registry |
| arbitrary-depth preservation | §15.1 and §20 | charge and permit evidence must survive and be tested through at least three restore hops |
| alias, cycle, and recovery exclusion | §§2, 3, 4, 6–8, 11, 15, 18, and 21 | no competing V1 registry/path, no caller authority, no digest self-reference, no unsafe recovery or resend branch |

The path table in §14.3 enumerates every frozen variable and fixed component
used by the root, generation, backup, and pending-restore layouts. The two path
supersessions change no canonical record-set byte, manifest field, bundle
digest, tombstone plaintext, journal payload, or journal digest preimage.
`BudgetPolicyV1` hashes only its preceding 112 bytes.
`ReservationContextBindingV1` hashes only its bytes before its digest;
`ReservationAuthorityV1` includes that completed binding, hashes its bound
prefix, and then hashes its complete pre-authority-digest prefix.
`BudgetChargeV1` embeds the completed authority and policy digest, then hashes
its own prefix. `Reserve` embeds the completed charge; the charge contains the
planned sequence rather than its enclosing journal digest.
`PermitRetirementV1` hashes only its preceding 197 bytes and is then embedded
by `0x0e`. The effective context is finalized before its inner attempt digest;
that digest binds the operation-input digest containing the same final counter,
and the outer 289-byte journal entry binds the complete 201-byte wrapper.
These directions introduce no direct or transitive self-digest dependency,
but an independent exact-byte review remains mandatory.

## 21. Rejected alternatives

- Ambient absolute or relative path strings as authority: rejected.
- Reopening the lock pathname per operation: rejected.
- JSON, Serde, bincode, SQLite, native struct layout, or filenames as hidden
  canonical authority: rejected.
- A mutable persisted secondary index in V1: rejected.
- Creating a budget charge after records that cannot reconstruct its timestamp:
  rejected.
- Treating a projection file as reservation authority before the exact
  1071/1104-byte journal payload is durable: rejected.
- Preserving only the former 155-byte Reserve payload: rejected because it
  omits authenticated budget history.
- Dropping budget charges or historical permit IDs across restore: rejected;
  sorted journal carry-forward is required.
- Requiring the original `Spent` entry to coexist with an authenticated
  transitive `0x0e` retirement entry: rejected because it breaks arbitrary-
  depth restore; the carried entry itself is the later collision authority.
- Treating a standalone retirement record as authority or as resend evidence:
  rejected.
- Refunding a charge after abort, crash, restore, or expiry: rejected.
- Treating concurrent occupancy release as deletion of a historical charge:
  rejected.
- Scoping concurrent occupancy per key or counterparty: rejected because key
  or counterparty rotation would bypass the store-wide bound.
- Expiring rolling charges after a forward step greater than the authenticated
  maximum: rejected; the store quarantines before admission.
- Supplying production budget numbers through an application call, environment
  variable, or unsigned config: rejected.
- Allowing application code to choose key ID, counterparty bucket, or raw
  participant ID: rejected.
- Registering `DOM:scriptless-vault-key-id:v1` or
  `DOM:scriptless-vault-counterparty-bucket:v1`: rejected as a conflicting
  unsigned alias of the signed NAR-002 V1 registry.
- Using one counterparty bucket for a mutable multi-party coalition: rejected;
  operational V1 is exactly two-party.
- Replacing a V1 budget policy after the first charge: rejected.
- Deriving an operation-input digest from stage alone: rejected.
- Persisting the derivation attempt before the zero-scalar retry loop resolves
  the final effective context: rejected. Persisting a secret or public value
  before that exact attempt is also rejected.
- Letting the application construct a computation request: rejected.
- Persisting a capability, `Arc` pointer value, process open ID, or lock token:
  rejected.
- Treating a public permit ID as authority: rejected.
- Requiring the spent journal entry to remain the current head forever:
  rejected; verified descendant ancestry is required instead.
- Creating resend authority from a predecessor, source backup, carried
  retirement, or any non-current generation: rejected.
- Implementing password/passphrase rewrap without an exact separately ratified
  staging and recovery transaction: rejected.
- The 294-byte tombstone staging basename and 317-byte flat restore-record
  basename: rejected as noncanonical development spellings that exceed the
  current Linux component limit.
- Generic plaintext seal/open functions: rejected.
- Copying the ordinary DOM Wallet keystore, database, seed, keys, or storage
  implementation: rejected.
- A silent local-file witness substitute or whole-root rollback claim: rejected.
- Deleting staging, orphan, or unexpected evidence to recover automatically:
  rejected.
- Choosing a Rust dependency version without lockfile and license review:
  rejected as engineering evidence, not made into a byte-level protocol rule.

## 22. Ratification effect

After a valid signature is verified, implementations may create the exact
normal-store layout, nested backup path, 229-byte staging path, 144-byte policy,
916/949-byte charge, complete reservation binding/authority, deterministic
fresh-versus-resume transaction, checked clock admission, 201-byte derivation
attempt, stage-current computation-input binding, signer-owned
effective-context ordering, seal/open/persist/authorize capability chain,
secret path/revision, local restore profile, rooted non-GAT export capability,
current-generation permit lookup, transitive lifetime budget and permit
carry-forward, pointer update, and narrow tombstone sealer assigned here. The
express supersessions in §2 take effect only for their stated independent
Contracts local-profile scope; no silent competing V1 registry or path becomes
valid.

Ratification does not approve G1B, G1, production, mainnet, Phase 2, numerical
production budgets, whole-root rollback resistance, witness, Windows/macOS
support, publication, or real-funds use. Those gates remain separately
evidence-bound and fail closed.

## 23. Operator ratification block

```text
DOCUMENT_ID = NAR-DC-P1-004
DECISION = RATIFY_EXACT_FILE_BYTES
PROJECT = DOM Contracts
PHASE = Phase 1B minimum local Nonce Vault runtime
NUMERICAL_PRODUCTION_BUDGETS = NOT ASSIGNED
WITNESS = NOT AUTHORIZED
PRODUCTION = NOT AUTHORIZED
MAINNET = DISABLED
PHASE2 = NOT AUTHORIZED
```

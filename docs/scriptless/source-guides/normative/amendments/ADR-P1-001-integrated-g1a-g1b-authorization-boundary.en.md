# ADR-P1-001 — Integrated G1a/G1b Nonce Authority and One-Shot Exposure Boundary

Status: **FINAL CANDIDATE — EFFECTIVE ONLY AFTER VALID DETACHED RATIFICATION**  
Date: 2026-08-04  
Scope: Phase 1/G1a integration with Phase 3-SNV/G1b  
Supplements: ratified NAR-001, ADR-SNV-001, ADR-SNV-002, and NAR-002  
Ratification authority: DOM release signing key, Minisign key ID `74197A95CA309CF0`  
Verification public key: `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`

## 1. Authority and effect

This ADR closes the integration boundary between the ratified G1a
cryptographic construction and the ratified G1b durable nonce authority. It
does not replace any byte assignment in NAR-001, ADR-SNV-001, ADR-SNV-002, or
NAR-002. Where this ADR restates an existing assignment, the earlier ratified
source remains authoritative. This ADR assigns only the previously unspecified
local secret-record plaintext and the production composition, ownership, and
call-order rules required to make those assignments non-bypassable.

This ADR is not effective while unsigned. A valid detached Minisign signature
over the exact bytes of this file makes the decisions below normative for DOM
Scriptless Contracts V1.

Ratification of this ADR freezes an architecture and local encrypted-record
format. It does not approve G1a, G1b, Phase 1, production activation, or use of
real funds. Approval still requires every applicable gate item and executed
evidence.

## 2. Security finding being closed

The reviewed G1a implementation correctly quarantined raw nonce derivation,
public-nonce export, and partial signing from the default production API. The
reviewed G1b implementation separately provides durable one-shot permits,
consume-before-export, witness receipts, persistent budgets, and tombstones.
The two branches are not integrated.

Enabling either isolated API directly would leave one of these unsafe states:

1. G1a can derive or use a nonce without proving that G1b reserved, charged,
   witnessed, and durably retired it.
2. G1b can authorize opaque bytes without proving that they are the canonical
   G1a artifact for the bound context.
3. A raw 252-byte permit record can be parsed as if parsing were authorization.
4. A caller can retain secret nonce material while exporting a commitment,
   reveal, or partial signature through an unrelated path.
5. A crash between cryptographic computation and durable authorization can
   cause recomputation, reuse, or ambiguous recovery.

The integrated production design therefore requires one orchestrated path in
which cryptographic ownership and durable authority advance together and in
which no lower-level production escape hatch exists.

## 3. Authoritative evidence

### 3.1 Ratified normative sources

- NAR-001 freezes `SessionContextV1`, the secret two-nonce KDF, closed
  `PurposeV1`, `DirectionV1`, and `SigningPhaseV1` registries, canonical point
  and scalar rules, and one-shot secret ownership.
- ADR-SNV-001 freezes the Wallet production sealer reuse boundary, 123-byte
  vault AAD, signed monotonic witness baseline, privacy exclusions, and
  no-fallback requirement.
- ADR-SNV-002 freezes `VaultSealedRecordKindV1`, assigning `0x01` to
  `NonceSecretMaterial`, and binds its final AAD identifier to
  `reservation_nonce_id_32`.
- NAR-002 freezes the stable vault chain, local identifiers, revised witness
  messages, transition and exposure registries, lifecycle order, journal,
  receipt record, outbound digest, 252-byte `ExposurePermitV1`, budget ledger,
  crash ambiguity, restore, and ordinary Wallet isolation.

### 3.2 Reviewed implementation evidence

- G1a reviewed code freeze:
  `f821937a8ff1712d5f9bafd58f152b82073538f2`.
- G1a branch report commit:
  `60c0a8d2e692c11a7aa95c568339a25912f94a5a`.
- G1b DOM contract commit:
  `ec9e99661c52f4e09609603261455c09e1d615a7`.
- G1b Wallet implementation commit:
  `e855ed67f641b7885f7e0e1928866253df60e34b`.
- Independent pre-comparison evidence commit:
  `3486a863ba922e2b7a4fc52e5ded988c6d32de87`.
- Independent review branch commit:
  `6b90e7a021541a63a728354910b323603da635b2`.

The independent comparison matched 311 intermediate values after the G1a
transcript correction. That evidence validates the cryptographic construction;
it does not validate this integration boundary until the integration tests in
this ADR execute.

## 4. Scope and non-goals

This ADR decides:

- the single production authority for nonce reservation and public exposure;
- the dependency and trusted-composition boundary;
- one canonical type authority for shared registries and artifacts;
- the exact encrypted nonce-secret plaintext format;
- the ownership transfer into and out of the Wallet sealer;
- the state-machine ordering for commitment, reveal, partial signing, export,
  retry, abort, crash recovery, and restore;
- the distinction between a persisted permit record and an unforgeable
  in-process one-shot capability;
- the minimum production API and test evidence needed to remove the G1a
  quarantine.

This ADR does not assign:

- budget values, rolling-window lengths, timeouts, retry counts, retention, or
  compaction limits;
- a replacement cryptographic primitive;
- a new witness message, receipt, tag, signature algorithm, or transport;
- a new consensus, transaction, kernel, block, or persisted-block encoding;
- a new Wallet backup format for ordinary Wallet state;
- Sponsor execution policy;
- Phase 3-SM session orchestration beyond the typed boundary defined here.

Unassigned operational values remain mandatory caller inputs or blocked inputs
under NAR-002 §27. No default may be introduced to make a test pass.

## 5. Threat model and trusted computing base

### 5.1 Protected failures

The integrated boundary must fail closed against:

- accidental or adversarial application-level nonce reuse;
- repeated calls, duplicate messages, reordered messages, and conflicting
  idempotency keys;
- process death and I/O failure at every local durable boundary;
- lost witness responses, remote-ahead state, divergent receipts, and witness
  equivocation;
- backup rollback, restore to another device, backward wall clock, and epoch
  rotation;
- malformed, noncanonical, wrong-context, wrong-purpose, wrong-participant,
  wrong-template, wrong-stage, or replayed artifacts;
- release-feature activation of test-only nonce constructors or deterministic
  randomness;
- an ordinary Wallet flow accidentally initializing or contacting this
  subsystem.

### 5.2 Trusted components

The production trusted computing base for this boundary is exactly:

1. the reviewed `dom-crypto` arithmetic, hash, parser, challenge, and verifier;
2. the integrated `dom-adaptor` state machine and canonical codecs;
3. the reviewed Wallet V3 `dom-wallet-crypto::{seal, open, encode, decode}`
   boundary with `KdfParameters::DOM_CONTINUITY`;
4. the reviewed concrete Wallet `NonceVaultV1` implementation selected by the
   Wallet production composition root;
5. the authenticated chain adapter, Wallet secret-key boundary, and pinned
   witness-key set;
6. the ratified witness protocol and a conforming witness service.

`NonceVaultV1` is necessarily implemented outside `dom-adaptor`, because the
Wallet owns persistence and `dom-adaptor` must not depend on the Wallet. Rust's
trait system cannot attest filesystem durability. Therefore the trait
implementation is an explicit trusted component, not an untrusted plugin
interface. Production composition must select one reviewed concrete Wallet
implementation statically. UI, RPC, plugin, FFI, configuration, or peer input
must not supply or replace it at runtime.

Test vaults and deterministic witnesses are allowed only under `cfg(test)` or a
test-only feature that is absent from every release feature resolution. They
are not production implementations even if they satisfy the Rust trait.

Compromise of the operating system, process memory, Wallet unlock secret,
witness signing key, or production composition root is outside the protection
that a Rust type boundary alone can provide. This limitation does not relax
zeroization, encryption, least-authority, or fail-closed requirements.

## 6. Single semantic authority and dependency direction

The integrated `dom-adaptor` crate is the only V1 authority for:

- `PurposeV1`;
- `DirectionV1`;
- `SigningPhaseV1`;
- `ExposureKindV1`;
- canonical G1a public artifacts;
- `ExposurePermitBindingV1`;
- `NonceVaultV1` lifecycle requests, states, and errors;
- the integrated one-shot cryptographic state machine.

The exact registries remain:

| Registry | Value | Exact name |
|---|---:|---|
| `PurposeV1` | `0x01` | `Refund` |
| `PurposeV1` | `0x02` | `ClaimAdaptor` |
| `PurposeV1` | `0x03` | `Funding` |
| `PurposeV1` | `0x04` | `Sponsor` |
| `ExposureKindV1` | `0x01` | `NonceCommitment` |
| `ExposureKindV1` | `0x02` | `NonceReveal` |
| `ExposureKindV1` | `0x03` | `PartialSignature` |

`Sponsor` remains codec-recognized and policy-rejected for strict Phase 1.
Wallet-local mirror enums must be removed when the Wallet pins the integrated
DOM revision. Before that pin, an external conformance harness may use total,
exhaustive conversions for review only. Such conversions must reject every
unknown byte and must not become a second semantic authority.

Dependency direction is fixed:

```text
dom-crypto  <-  dom-adaptor  <-  Wallet Scriptless integration
                                      |
                                      +-- Wallet production sealer
                                      +-- durable Nonce Vault
                                      +-- witness client
```

`dom-adaptor` must not depend on any Wallet crate. Ordinary Wallet crates must
not depend on or enable the Scriptless vault unless they are inside the
explicit adaptor-session composition root. No absolute path, sibling-worktree
path, or unpublished local path is permitted in a production `Cargo.toml` or
`Cargo.lock`.

## 7. Exact NonceSecretRecordV1 plaintext

### 7.1 Purpose

The approved Wallet sealer needs an exact plaintext to persist a nonce pair
across commitment, reveal, crash recovery, and partial signing. Existing
ratified sources assign the sealed-record kind and AAD but do not assign this
plaintext. This section freezes the missing local encrypted-record format.

The plaintext is local encrypted vault state. It is not witness wire, session
wire, transaction wire, consensus data, a public API serialization, or a
generic serialization of a Rust secret type.

### 7.2 Byte layout

`NonceSecretRecordV1` is exactly `142 + context_length` bytes:

```text
nonce_secret_record_v1 =
    "DOMSNSEC"[8]
 || schema_version_u16_le[2]
 || reservation_nonce_id_32[32]
 || participant_id_32[32]
 || context_length_u32_le[4]
 || canonical_context_v1[context_length]
 || k1_scalar_be32[32]
 || k2_scalar_be32[32]
```

| Offset | Field | Size | Validation |
|---:|---|---:|---|
| 0 | magic | 8 | exact ASCII `DOMSNSEC` |
| 8 | schema version | 2 | little-endian, exactly `0x0001` |
| 10 | reservation nonce ID | 32 | nonzero; exact ADR-SNV-002 AAD identifier |
| 42 | participant ID | 32 | nonzero; exact NAR-002 participant bound to the permit |
| 74 | context length | 4 | `u32` little-endian; exact remaining context length |
| 78 | canonical context | `L` | exact NAR-001 `canonical_context_v1` |
| `78 + L` | `k1` | 32 | canonical nonzero scalar, big-endian, strictly less than group order |
| `110 + L` | `k2` | 32 | canonical nonzero scalar, big-endian, strictly less than group order |

For participant count `n` and adaptor-presence byte `p`, the only valid
context length is:

```text
L = 179 + 33*n + 33*p
n in 2..=16
p in {0, 1}
```

The resulting plaintext length is 387 through 882 bytes, but range membership
alone is insufficient. The canonical context parser must recompute the exact
length from its closed fields, reject trailing bytes, and enforce all NAR-001
purpose/adaptor compatibility rules.

No checksum or new hash tag is added inside this plaintext. Integrity and
context separation are provided by the approved Wallet AEAD with the exact
ADR-SNV-001 123-byte `vault_aad_v1`, using:

- `record_kind_u8 = 0x01` (`NonceSecretMaterial`);
- `record_revision_u64_le = 0` for the initial record;
- final AAD identifier equal to `reservation_nonce_id_32`.

The complete Wallet envelope is committed by the existing NAR-002
`DOM:scriptless-vault-sealed-envelope:v1` digest. No new domain tag is created
by this ADR.

### 7.3 Semantic validation after decryption

Before reconstructing an in-memory secret pair, the integrated boundary must:

1. authenticate and decode the Wallet envelope with the exact expected AAD;
2. reject any wrong magic, version, length, truncation, extension, or trailing
   byte;
3. compare the record reservation ID with the AAD identifier, journal entry,
   reservation index, tombstone set, and requested operation;
4. compare the participant ID with the reservation, protocol roster mapping,
   and requested operation;
5. parse and fully validate `canonical_context_v1` against the trusted local
   chain adapter;
6. compare session ID, participant, purpose, template hash, participant index,
   phase, direction, message digest, transcript hash, and adaptor point with
   the current accepted session state;
7. parse both scalars through the authoritative DOM exact-scalar parser;
8. derive `R_i1 = k1*G` and `R_i2 = k2*G` through `dom-crypto`;
9. recompute the canonical commitment and compare it with the immutable
   persisted 35-byte commitment;
10. when a reveal is already authorized, compare the recomputed public pair
    byte-for-byte with the immutable persisted 69-byte reveal;
11. reject if any permit is already spent for an incompatible stage or if the
    reservation is terminal;
12. move the parsed scalars into one opaque in-memory owner and zeroize the
    plaintext buffer immediately.

This ADR does not add an equality rejection for `k1 == k2`; NAR-001 defines
zero rejection but does not define pair-equality rejection. Implementations
must not silently change the KDF acceptance rule.

### 7.4 Material deliberately absent

The secret record must not contain:

- the signing share;
- `aux_rand_32`, mask, masked signing share, KDF seed, digest halves, or wide
  reduction buffers;
- Wallet unlock material, mnemonic entropy, witness authentication private
  key, adaptor secret, final signature, or extracted secret;
- JSON, CBOR, bincode, Serde, native struct layout, pointer-sized length, or
  architecture-dependent padding.

`aux_rand_32` is destroyed after nonce derivation as required by NAR-001. The
canonical `k1` and `k2` values, not auxiliary randomness or a signing share,
are the persisted one-shot secret material.

### 7.5 Ownership transfer and zeroization

The plaintext codec is private to the integrated cryptographic/storage bridge.
It must not implement or expose `Serialize`, `Deserialize`, `Clone`, `Copy`,
`Debug`, `Display`, `Eq`, `Ord`, `AsRef<[u8]>`, or an application-readable raw
byte accessor.

Creation transfers a single zeroizing plaintext buffer by value into the
trusted Wallet sealer. Opening transfers one zeroizing decrypted buffer by
value from the trusted Wallet sealer directly into the strict `dom-adaptor`
decoder. UI, RPC, transport, plugin, log, telemetry, crash report, and general
Wallet state APIs must never observe that buffer.

The bridge must use RAII zeroizing guards. Success, parse failure, validation
failure, I/O error, witness error, authorization mismatch, and unwind must all
zeroize plaintext and in-memory scalars. A compiler-visible zeroization audit
remains mandatory.

## 8. Production type-state and API closure

### 8.1 One orchestrated path

The default production build exposes one high-level vault-backed signer. Its
semantic states are:

```text
ValidatedSessionV1
  -> ReservedNonceV1
  -> CommitmentExportedV1
  -> RevealExportedV1
  -> PreparedPartialV1
  -> PartialExportedTerminalV1
```

Abort and failure states terminate ownership:

```text
ValidatedSessionV1       -> no nonce allocated
ReservedNonceV1          -> AbortedBeforePublicMaterial
CommitmentExportedV1     -> ConsumedOnAbort
RevealExportedV1         -> ConsumedOnAbort
PreparedPartialV1        -> ConsumedOnAbort or Burned
ambiguous recovery       -> Burned / RestoreQuarantined
```

State transitions consume the prior state by value unless a state must remain
mutable while producing one separately consumed outbound capability. No state
containing live nonce secrets implements `Clone`, `Copy`, `Debug`, `Display`,
generic serialization, equality, or ordering.

### 8.2 Quarantined lower-level operations

In a default release feature resolution, no public API may independently:

- choose or supply `aux_rand_32`;
- derive `SecretNoncePairV1`;
- obtain local public nonces from a live secret pair;
- construct a commitment, reveal, or partial from local secret material;
- parse 252 permit bytes into authorization authority;
- construct a permit or mark a permit spent;
- invoke partial signing without the vault-backed state machine;
- regenerate an artifact for network retry.

Low-level deterministic constructors and probes may exist only in unit tests,
fuzz targets, or an explicit test-only feature absent from release metadata.
The integrated crate must include compile-fail evidence that these operations
cannot be imported from a default downstream build.

Pure public aggregation, public verification, adaptation, extraction, final
DOM verification, strict canonical parsing, and public-vector utilities may
remain public when they cannot create, expose, duplicate, or reuse a local
secret nonce.

### 8.3 Persisted record versus in-process capability

The 252-byte `ExposurePermitV1` is a canonical persisted binding record. It is
not, by itself, an authorization capability. Strict parsing may validate a
record for audit, but must not enable export or signing.

The in-process permit is an opaque Wallet-owned value with a private
constructor. It is created only after the concrete trusted vault has completed
the required journal, receipt, witness, tombstone, and synchronization steps.
It owns the exact 252-byte binding and is consumed by value exactly once.

The production orchestrator accepts the permit only as the associated permit
type of the concrete `NonceVaultV1` instance that owns the reservation. It does
not accept:

- raw permit bytes;
- a digest alone;
- a trait object supplied by application input;
- a permit from another vault instance, epoch, reservation, or process;
- a caller-selected parser result;
- an authorization Boolean.

The concrete production vault is responsible for durable spent-permit state.
Rust move semantics prevent accidental in-process reuse; the spent-permit
record prevents reuse across process death, retry, backup, and restore.

### 8.4 Reference semantic interface

Exact Rust names may change during mechanical integration, but the ownership
and authority represented by this reference interface are normative:

```rust
pub trait NonceVaultV1 {
    type Error;
    type ReservationHandle;
    type ExposurePermit;

    fn reserve(
        &mut self,
        request: ReservationRequestV1,
        secret: NonceSecretTransferV1,
        commitment: NonceCommitmentV1,
    ) -> Result<Self::ReservationHandle, Self::Error>;

    fn authorize_exposure(
        &mut self,
        reservation: &mut Self::ReservationHandle,
        artifact: PreparedExposureV1,
    ) -> Result<Self::ExposurePermit, Self::Error>;

    fn export(
        &mut self,
        permit: Self::ExposurePermit,
    ) -> Result<AuthorizedExposureV1, Self::Error>;

    fn resend_exported(
        &self,
        permit_id: PermitIdV1,
    ) -> Result<AuthorizedExposureV1, Self::Error>;

    fn abort(
        &mut self,
        reservation: Self::ReservationHandle,
        reason: AbortReasonV1,
    ) -> Result<TerminalReservationV1, Self::Error>;

    fn restore_state(&self) -> RestoreStateV1;
}
```

`NonceSecretTransferV1` is an opaque, by-value, zeroizing transfer into the
trusted sealer. `PreparedExposureV1` is a non-cloneable pre-export value whose
canonical bytes are visible only to the integrated orchestrator and trusted
vault. `AuthorizedExposureV1` contains public bytes, but can be constructed
only by the orchestrator after `export` has durably spent its permit.

The production Wallet adapter owns the witness client, receipt verifier,
durable store, sealer, budget ledger, and pinned witness keys. Consequently,
the production `reserve`, `authorize_exposure`, and `abort` operations perform
their own witness exchange and receipt verification. Their application-facing
forms must not accept any of the following from a caller:

- an allegedly verified receipt;
- a witness-acceptance Boolean;
- raw request or receipt bytes selected by the caller;
- raw permit bytes or a permit digest;
- an arbitrary witness public key;
- a storage-success or synchronization-success Boolean.

A lower-level receipt-consuming storage function may exist privately inside
the Wallet crate for separation of concerns. It is not the production
application interface, and only the Wallet-owned witness verifier may call it.
Unit tests may reach it only under test configuration.

The high-level G1a signer owns the reservation handle and drives the only legal
stage order. Application code receives only the authorized outbound artifact
after the corresponding `export` returns. It never receives the secret
transfer, prepared artifact, live permit, sealed nonce record, decrypted nonce
record, or mutable reservation handle.

## 9. Canonical binding checks

The exact NAR-002 permit remains 252 bytes with these offsets:

| Offset | Field | Size |
|---:|---|---:|
| 0 | magic `DOMEXPV1` | 8 |
| 8 | version `0x0001` LE | 2 |
| 10 | exposure kind | 1 |
| 11 | permit ID / witness request nonce | 32 |
| 43 | reservation nonce ID | 32 |
| 75 | session ID | 32 |
| 107 | participant ID | 32 |
| 139 | purpose | 1 |
| 140 | template hash | 32 |
| 172 | outbound digest | 32 |
| 204 | epoch | 8, `u64` LE |
| 212 | semantic revision | 8, `u64` LE |
| 220 | receipt-chain hash | 32 |

Before an artifact can cross the production boundary, the orchestrator and
vault must jointly establish all of the following:

- exact magic, version, length, and closed exposure kind;
- nonzero permit ID, reservation ID, session ID, participant ID, epoch, and
  receipt-chain hash;
- strict Phase 1 purpose policy;
- permit reservation ID equals the opened reservation and secret record;
- permit session ID, participant ID, purpose, and template hash equal the
  validated session and reservation;
- permit exposure kind equals the only next legal state;
- `outbound_digest_32` recomputed from the exact canonical artifact using
  `DOM:scriptless-vault-outbound:v1` equals the permit field;
- epoch, semantic revision, receipt chain, witness transition, journal entry,
  receipt record, and request nonce form one verified durable chain;
- permit ID is not already spent except for the exact persisted resend path;
- no conflicting artifact or digest exists under the reservation or permit ID.

Every comparison is over exact fixed-length canonical bytes. Secret scalar and
secret-key comparisons use constant-time authoritative primitives. Public
identifier comparisons must not introduce secret-dependent control flow or
logging.

## 10. Required operation ordering

### 10.1 Reservation

The integrated reservation operation performs these logical steps:

1. validate the complete session context and trusted chain inputs;
2. reject Sponsor and every unknown purpose for strict Phase 1 execution;
3. require an operational, non-closed, non-quarantined vault epoch;
4. allocate fresh nonzero reservation and request identifiers from the OS
   CSPRNG and reject lifetime reuse;
5. validate all caller-supplied budgets before secret generation;
6. derive the G1a nonce pair from fresh internal OS randomness;
7. compute the exact canonical 35-byte commitment without exporting it;
8. encode `NonceSecretRecordV1`, seal it with the approved Wallet boundary and
   exact AAD, and zeroize the plaintext;
9. durably charge global, counterparty, concurrent, and rolling-window budget;
10. durably persist the sealed envelope and exact commitment;
11. append the canonical `NonceReservation` journal entry;
12. obtain and verify the applied witness receipt;
13. durably persist the exact request, receipt, receipt-chain hash, journal
    head, budget state, and reservation projection;
14. return only an opaque `ReservedNonceV1` handle.

The commitment bytes are not returned by reservation. A failure after budget
charge never refunds budget. An ambiguous witness result leaves a recoverable
pending exact request or enters quarantine; it never allocates another nonce.

### 10.2 Commitment exposure

1. read the already persisted 35-byte commitment;
2. recompute and validate its stage-bound outbound digest;
3. submit exactly one witnessed
   `ExposureAuthorization(NonceCommitment)` transition;
4. verify and durably persist the applied receipt and permit binding;
5. durably mark the permit ID spent before returning bytes;
6. return exactly the persisted commitment bytes in an authorized outbound
   value;
7. retain the sealed nonce record for reveal and partial signing.

No code may recompute the commitment for retry. Retry reads the spent permit
record and the immutable persisted artifact and returns the same bytes.

### 10.3 Nonce reveal

1. require every expected participant commitment and verify the accepted
   roster and transcript state;
2. decrypt and validate `NonceSecretRecordV1` through §7.3;
3. derive the exact public nonce points from the stored scalars;
4. encode the exact canonical 69-byte reveal and zeroize all reopened secret
   material;
5. durably persist the reveal before witness authorization;
6. submit exactly one witnessed `ExposureAuthorization(NonceReveal)`;
7. verify and durably persist the applied receipt and permit binding;
8. durably mark the permit ID spent before returning bytes;
9. return exactly the persisted reveal bytes;
10. retain the sealed nonce record for the one partial-sign attempt.

Retry reads the exact persisted reveal and never decrypts or recomputes it.

### 10.4 Partial signing and terminal exposure

Before decrypting the secret record for partial signing, the Wallet must
durably mark the reservation as having entered the one-shot partial-attempt
boundary. This is a local pending-storage fact, not a new witness transition or
wire registry value. On recovery, its presence without a completed canonical
partial artifact causes burn or quarantine; it never permits recomputation.

The operation then:

1. validates every accepted participant reveal against its commitment;
2. validates the canonical binding factor, aggregate nonce, adaptor point,
   aggregate signing key, challenge inputs, session context, and local signing
   public key;
3. decrypts and validates `NonceSecretRecordV1` through §7.3;
4. moves both nonce scalars into one opaque `SecretNoncePairV1` owner;
5. consumes that owner by value to compute exactly one prepared 67-byte
   partial signature;
6. verifies the local partial equation before any storage or exposure;
7. zeroizes the nonce owner and every secret temporary on success or failure;
8. durably persists the exact prepared partial and its outbound digest;
9. submits exactly one witnessed `NonceConsumption(PartialSignature)`
   transition;
10. verifies and durably persists the applied receipt and receipt record;
11. irreversibly removes the sealed nonce record;
12. durably writes the nonce tombstone, consumed budget state, terminal
    reservation state, and canonical permit binding;
13. completes required file/data and parent-directory synchronization;
14. durably marks the permit ID spent;
15. only then returns the exact persisted 67-byte partial signature.

If partial computation, local verification, persistence, witness recovery, or
tombstoning fails, no partial bytes are returned. The in-memory nonce is
retired. The durable reservation proceeds to witnessed abort/burn or remains
quarantined until that terminal transition is proved. The same secret record
must not be reopened for another partial-sign computation.

### 10.5 Aggregate artifacts

Aggregate pre-signature, adapted final signature, and extracted adaptor secret
are not participant nonce exposures under `ExposureKindV1`. Their operations
remain governed by G1a canonical validation and the real DOM verifier. They
must not be mislabeled as commitment, reveal, or partial permits.

No final signature is accepted unless the unchanged real DOM verifier accepts
its exact 65 bytes. Extraction additionally requires `t*G == T`.

## 11. Idempotency, retry, abort, and terminal behavior

### 11.1 Exact retry

An idempotent resend is authorized only by an existing durable spent-permit
record. It returns the immutable artifact whose kind, length, bytes, outbound
digest, reservation, permit ID, and receipt chain all revalidate. It performs
no nonce decryption, KDF, scalar arithmetic, signature computation, witness
advance, budget charge, or new permit creation.

A reused request or permit ID with different bytes is a permanent conflict.
There is no last-write-wins behavior.

### 11.2 Abort and burn

- Before commitment authorization, a controlled abort becomes
  `AbortedBeforePublicMaterial`.
- After commitment authorization, a controlled abort becomes
  `ConsumedOnAbort` with `public_material_may_have_existed = 0x01`.
- Corruption, unresolved I/O ambiguity, conflicting durable state, invalid
  receipt chain, or uncertain partial attempt becomes `NonceBurn` and/or
  `RestoreQuarantined` as required by NAR-002.
- Every terminal path destroys the sealed nonce record, writes an irreversible
  tombstone, retains lifetime session and reservation IDs, and retains every
  budget charge.
- A witness outage cannot convert an adaptor failure into a local-only abort.
  The exact pending request is retried or the vault remains quarantined.

No abort, burn, restore, epoch rotation, compaction, or clock change refunds or
resets a charged budget.

### 11.3 Panic and unwind

Drop may zeroize memory but must not be treated as a durable transaction. Any
operation that opens the nonce secret records a durable attempt boundary before
the secret can influence a partial. Recovery treats an incomplete attempt
conservatively. A panic handler, log hook, or error formatter must not print
secret-bearing state.

## 12. Crash and restore adjudication

The minimum safe result at each cut is:

| Cut | Recovery result | Export permitted |
|---|---|---|
| before durable reservation | no reservation; fresh operation may start | no |
| after budget charge, before complete reservation receipt | exact pending recovery or quarantine; budget remains charged | no |
| after reservation receipt, before commitment authorization | reserved record remains exact | no |
| after witness accepts commitment/reveal, before local receipt persistence | byte-identical request recovery; remote-ahead proof required | no |
| after receipt persistence, before spent-permit persistence | complete spent record from exact durable evidence or quarantine | no |
| after spent-permit persistence, before first send | exact persisted artifact may be sent | yes, exact bytes only |
| after first send | exact persisted resend only | yes, exact bytes only |
| after partial-attempt marker, before durable partial | burn or quarantine | no |
| after durable partial, before witness acceptance | retry exact request and artifact; never recompute | no |
| after witness accepts partial, before tombstone | recover receipt, destroy secret, write tombstone, then spend permit; otherwise quarantine | no |
| after tombstone, before spent permit | complete spent record from exact evidence or quarantine | no |
| after partial spent permit | exact persisted partial may be sent | yes, exact bytes only |
| restored backup with any nonterminal reservation | reconcile, conservatively burn ambiguous reservation, retain charges | no until operational |
| divergent valid witness evidence | permanent quarantine and equivocation evidence | no |

Restore starts in `RESTORE_QUARANTINED`. It computes the union of all known
tombstones, spent permit IDs, lifetime session IDs, reservations, budget
charges, epochs, journal entries, and verified receipt chains, and the maximum
monotonic state justified by signed evidence. Absence in an older backup never
proves non-use. A nonterminal reservation that cannot be proven safe is burned.

No local file, fresh epoch, new pseudonym, new client key, new Wallet UUID,
clock reset, or witness-unavailable mode bypasses reconciliation.

## 13. Error and observability contract

The integrated API uses typed errors with at least these stable semantic
classes:

- invalid or noncanonical input;
- context or authorization mismatch;
- invalid lifecycle transition;
- idempotency conflict;
- budget exhausted with nonsecret scope;
- witness unavailable;
- invalid witness receipt;
- rollback detected;
- divergence or equivocation detected;
- restore quarantined;
- corrupt durable state;
- storage unavailable or durability ambiguous;
- randomness failure;
- checked counter overflow;
- unsupported version, purpose, or exposure kind;
- terminal nonce retirement.

Errors must not reveal secret bytes, signing shares, nonce scalars, plaintext
records, Wallet unlock material, witness private keys, prepared partials before
authorization, or transcript plaintext. `Debug`, `Display`, tracing, metrics,
panic output, and health/readiness endpoints must redact identifiers when their
correlation is not operationally required.

Witness-visible data remains limited by ADR-SNV-001 and NAR-002. This ADR does
not authorize sending purpose, participant ID, session ID, template hash,
transaction hash, value, address, Wallet identity, vault ID, nonce ID, journal
plaintext, outbound bytes, or permit bytes to the witness.

## 14. Production composition and release features

The Wallet production composition root must:

1. pin a reviewed published DOM revision containing this integrated boundary;
2. construct the concrete Wallet vault from authenticated Wallet and chain
   state;
3. construct the witness client from a closed pinned witness-key set;
4. provide mandatory caller-supplied operational policy with no silent
   defaults;
5. inject the concrete vault only into the explicit adaptor-session service;
6. keep ordinary Wallet creation, restore, scan, sync, plain send, submit,
   rebroadcast, cancellation, and frontend paths independent;
7. exclude deterministic RNG, test vault, deterministic witness, raw nonce
   constructors, and secret-record probes from release resolution.

Until a published revision exists, local validation may use an external
test-only conformance harness with relative local paths. No such path may be
committed to a production Wallet manifest or lockfile, and harness success is
not publication/pinning evidence.

## 15. Required conformance evidence

Ratification does not mark these tests complete. The integrated implementation
must add and execute evidence for all items below.

### 15.1 Codec and binding

- exact `NonceSecretRecordV1` vectors at `n=2` and `n=16`, with and without an
  adaptor point where policy allows;
- exact length, offsets, endian rules, magic, and schema;
- rejection of every truncation and extension;
- rejection of wrong record/AAD reservation ID, participant ID, chain,
  session, purpose, template, phase, direction, transcript, message, index,
  signing key, point, scalar, and adaptor field;
- rejection of zero and group-order-or-greater scalars;
- no unbounded allocation from `context_length`;
- AEAD authentication failure after mutation of every AAD and plaintext field;
- recomputed public nonce and commitment equality after open;
- exact permit and outbound digest cross-branch vectors.

### 15.2 Type and API safety

- compile-fail proof that default downstream code cannot construct, clone,
  debug, serialize, or obtain a raw secret nonce pair;
- compile-fail proof that raw permit bytes cannot authorize an artifact;
- compile-fail proof that partial signing cannot be called twice on one pair;
- release metadata proof that test helpers and deterministic randomness are
  absent;
- source and dependency proof that `dom-adaptor` has no direct `k256`
  dependency and no Wallet dependency;
- source proof that the Wallet selects one concrete reviewed vault and exposes
  no runtime replacement surface.

### 15.3 Lifecycle

- positive commitment, reveal, and partial flows for Refund, ClaimAdaptor, and
  Funding;
- Sponsor codec acceptance and strict policy rejection;
- exact resend after lost response and after process restart;
- conflicting retry rejection;
- wrong-vault, wrong-epoch, wrong-stage, wrong-reservation, wrong-session,
  wrong-participant, wrong-purpose, wrong-template, wrong-digest, wrong-receipt,
  and already-spent permit rejection;
- no export before durable spent-permit state;
- no partial export before secret destruction and tombstone durability;
- abort and burn never refund budget;
- lifetime session, nonce, request, and permit IDs never revive;
- ordinary Wallet operations succeed while the witness is unavailable and
  never initialize this subsystem.

### 15.4 Fault injection and platforms

Inject failure before and after every relevant write, flush, file/data sync,
parent-directory sync, rename, journal append, receipt persistence, witness
acknowledgement, attempt marker, artifact persistence, secret deletion,
tombstone, permit spend, and outbound return. Exercise every valid journal
prefix, byte truncation, record reorder, duplicate, predecessor gap, digest
mutation, rollback prefix, remote-ahead state, divergence, restore, and epoch
rotation.

Linux, Windows, and macOS must each execute their applicable durability matrix.
A prepared workflow is not executed evidence. If Linux is complete while
Windows or macOS remains unexecuted, the maximum status is:

```text
PHASE 1 LOCALLY COMPLETE — PLATFORM VALIDATION PENDING
```

### 15.5 Cryptographic regression

- all eight frozen SCAD0 vectors through the unchanged real DOM verifier;
- the independent two-nonce vectors with every intermediate byte matching;
- at least 10,000 deterministic closed-cycle cases;
- persistent fuzz targets for every canonical G1a, permit, secret-record,
  witness, receipt, and journal parser;
- sanitizer-compatible execution with actual recorded evidence;
- compiler-visible zeroization and constant-time review;
- final 65-byte signature acceptance by the unchanged DOM verifier;
- extraction proof `t*G == T`.

## 16. Gate consequences

After ratification and successful implementation of this ADR:

- G1a may remove its default-build quarantine only when the integrated
  vault-backed signer is present and all prior raw secret paths remain absent;
- G1b may claim DOM conformance only against the same integrated revision and
  canonical types;
- local integration review may proceed when both code gates are complete;
- Phase 1 remains not approved while any mandatory independent, fuzz,
  sanitizer, crash, ordinary-Wallet isolation, or platform evidence is open;
- production activation additionally requires an authoritative published pin,
  operational policy ratification from measurements, release review, and the
  separately authorized activation process.

## 17. Alternatives considered

### 17.1 Leave raw G1a APIs public and document correct usage

Rejected. Documentation cannot prevent nonce generation or partial signing
outside durable G1b authority.

### 17.2 Treat canonical permit bytes as a bearer capability

Rejected. Persisted bytes can be copied and replayed. Parsing proves syntax,
not live ownership, witness state, or durable one-shot consumption.

### 17.3 Put the vault implementation inside `dom-adaptor`

Rejected. It would couple cryptography to one Wallet, storage backend,
transport, and platform, and invert the accepted dependency direction.

### 17.4 Make `dom-adaptor` depend on Wallet crypto

Rejected. The lower-level protocol crate must not depend on Wallet. The trusted
Wallet sealer is reached through the reviewed external implementation boundary.

### 17.5 Persist `aux_rand_32` and rederive nonces after restart

Rejected. It extends the lifetime of KDF auxiliary secret material, requires
the signing share again for recovery, and creates an avoidable regeneration
path. Persisting the already-derived canonical one-shot scalars is narrower.

### 17.6 Persist the signing share with nonce material

Rejected. The signing share belongs to the Wallet signing-key boundary and is
not required to restore a nonce pair.

### 17.7 Store a native Rust struct, Serde object, or generic secret encoding

Rejected. It would create architecture- or dependency-dependent bytes and
would violate the restriction on generic secret serialization.

### 17.8 Export after witness authorization but before tombstone or permit spend

Rejected. Process death could leave externally visible material while local
state still permits reuse.

### 17.9 Recompute artifacts for retry

Rejected. Exact persisted resend is required; recomputation expands nonce-use
and crash ambiguity.

### 17.10 Use a local-file witness fallback

Rejected. It is not independent from backup rollback and violates the ratified
portable witness baseline.

## 18. Compatibility and migration

This ADR applies only to unpublished Scriptless V1 development state. It
requires deliberate reconciliation of the G1a and G1b branches rather than a
wholesale merge. The integration must preserve the reviewed evidence commits.

Known reconciliation surfaces include:

- `crates/dom-adaptor/src/lib.rs` and crate documentation;
- duplicate `PurposeV1` and `ExposureKindV1` definitions;
- G1a private permit parsing versus G1b Wallet-owned permit capability;
- G1b opaque exposure bytes versus typed G1a artifacts;
- secret-record sealing and reopen ownership;
- error types and lifecycle state names;
- release feature resolution and compile-fail tests.

The change is additive with respect to existing DOM. It does not modify
consensus, existing transaction or kernel serialization, block encoding,
persisted blocks, genesis, network magic, PoW, chain selection, or the real DOM
signature verifier. It imports no DL2P type, framing, operation, receipt,
nullifier, storage model, state machine, or vector.

No migration from a prior production Scriptless vault exists because no prior
version is production-authorized. Any experimental pre-V1 vault is rejected,
not silently upgraded. Existing ordinary Wallet data remains unchanged.

## 19. Risks and residual blockers

Even after ratification, these risks remain evidence or activation blockers:

- the integrated API and secret-record codec do not yet exist;
- the exhaustive crash matrix has not executed;
- Windows and macOS durability evidence has not executed;
- production budget, timeout, retry, and retention values remain intentionally
  unfrozen pending measurement;
- full ordinary Wallet runtime and frontend isolation evidence remains open;
- a permanent published DOM revision is not pinned by Wallet;
- production witness privacy leakage and operational deployment require final
  measurement and review;
- publication, release, activation, and real-funds use remain prohibited.

These blockers must remain visible. They cannot be converted into approval by
this signature.

## 20. Ratification procedure

Expected detached signature file:

```text
ADR-P1-001-integrated-g1a-g1b-authorization-boundary.en.md.minisig
```

The detached signature must verify over the exact bytes of this file with the
public key printed in the header. The document must not be edited after
signing. Verification must record:

- absolute source path;
- complete SHA-256 of this file;
- complete SHA-256 of the detached signature;
- Minisign key ID;
- trusted and untrusted signature comments;
- verification command and exit code;
- verification timestamp.

After successful verification, the exact document and detached signature may
be imported byte-for-byte into the isolated coordinator repository under:

```text
docs/scriptless/source-guides/normative/amendments/
```

Import requires `cmp --silent`, SHA-256 manifest updates, link checks, and an
auditable local commit. Ratification authorizes implementation and validation
of this boundary only; it does not authorize merge, push, publication, release,
production activation, or real-funds execution.

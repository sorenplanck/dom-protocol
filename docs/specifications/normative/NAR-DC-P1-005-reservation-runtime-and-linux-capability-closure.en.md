# NAR-DC-P1-005 — Reservation Runtime and Linux Capability Closure

Status: **PROPOSED / UNSIGNED / NOT NORMATIVE**

Date: 2026-08-05

Project: DOM Contracts / DOM Scriptless Contracts Phase 1

Scope: the minimum additional assignments required to implement the signed
NAR-DC-P1-004 reservation/runtime interface without caller authority, to bind
accepted signing-round messages to immutable authenticated bytes, and to
select the reviewed safe-Rust Linux filesystem/locking boundary required by
NAR-DC-P1-004 §14. This record does not approve G1A, G1B, G1, Phase 2,
publication, production, mainnet, or real-funds use.

## 1. Authority and effect

This record supplements, and does not replace, the following signed records:

| Record | SHA-256 |
|---|---|
| `NAR-002-phase-1-omnibus-normative-closure.en.md` | `b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5` |
| `ADR-P1-001-integrated-g1a-g1b-authorization-boundary.en.md` | `e35c39e74f9af61e19ecda8e1ca503f37a7fc04c6e2a0f40f5d96bf6a20d1596` |
| `ADR-SNV-001-witness-and-aad.en.md` | `3939df85814e8c2b1fad8ea6484492887000b38917c3b23e47d5d505311270c2` |
| `ADR-SNV-002-vault-record-kind-registry.en.md` | `29266c4468d97cb7a1e185561f2e140f08fb914d43d0ad5deef1aa7b07c209c5` |
| `NAR-DC-P1-001-omnibus-gap-closure.en.md` | `88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655` |
| `NAR-DC-P1-002-storage-persistence-closure.en.md` | `719a121c11f4b7f8ea016668bfaa05a3e4d03d3a510df31e3495fb9698560e84` |
| `NAR-DC-P1-003-vault-request-and-recovery-binding.en.md` | `082c855782c71a0f61e85828eaac75440a434d5c05d8357e569592a816db05ef` |
| `NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md` | `2f9eadb08080844ade7dacfa117a71948ee8a365841fff860d69fe734c42b510` |

If this record conflicts with a byte layout, digest, state transition,
durability order, secret-lifetime rule, or fail-closed rule in those records,
the earlier signed assignment remains authoritative unless this record names
the exact superseded sentence. This record assigns only the missing
information flow and engineering boundary described below.

The unsigned bytes of this document grant no authority. A detached Minisign
signature made with the established project operator public identity is
required before implementation may rely on these assignments.

This record expressly supersedes only these earlier API-level interpretations:

- a permit-ID-only safe `resend_exported` call is replaced by the consumed
  `ResendRequestV1` in §4.5;
- a caller-selected `AbortReasonV1` argument is removed from the safe abort
  route by §4.7, while the signed terminal-state mapping remains unchanged;
- a reservation handle exposing only lifecycle state is replaced by the exact
  read-only authenticated live projection in §3.1; and
- a raw-byte-only `PreparedExposureV1` is replaced by the bound closed variants
  and mandatory public verification evidence in §4.6.

No canonical persisted byte layout, digest formula, terminal mapping, exposure
transaction, journal registry, or durability order from the earlier records is
superseded.

## 2. Closed gap inventory

The implementation audit found eight related gaps after NAR-DC-P1-004 was
signed:

1. `claim_fresh_reservation` generates the nonzero reservation ID inside the
   Store after admission, but the safe signer must bind that ID into the exact
   `NonceSecretRecordV1` plaintext before calling `seal_derived_secret`.
   NAR-DC-P1-004 did not assign a non-authoritative read-only route from the
   opaque reservation handle to that identifier.
2. `resume_claimed_reservation` returns `Live(H)`, but the safe signer needs a
   closed authenticated lifecycle projection to reconstruct exactly one legal
   continuation without guessing, trying methods in sequence, or falling back
   to fresh creation.
3. NAR-DC-P1-004 requires complete immutable accepted DSC1 commitment/reveal
   bytes and a reviewed safe-Rust Linux filesystem/locking profile, but neither
   the exact transport-identity signature verification boundary nor the exact
   dependency/version/feature selection was assigned.
4. Exact resend still accepted only a public permit ID even though signed
   NAR-DC-P1-004 requires current trusted protocol-state authority, the expected
   closed artifact kind, and the expected adaptor outbound digest before a
   resend capability can exist.
5. The public request lookup was not a distinct type and its custody order was
   not explicit, leaving lost-response recovery and permit lookup vulnerable to
   accidental aliasing.
6. A signature-valid DSC1 message did not by itself establish accepted sequence,
   transcript ancestry, round-barrier, duplicate, or equivocation state; the
   owning unforgeable signing-round state boundary was unnamed.
7. `PreparedExposureV1` did not expose the public verification evidence and
   exact private computation binding required for the Store to compare it with
   the paired `ArtifactPersistencePermit` before persistence.
8. The safe abort method still accepted a caller-selected `AbortReasonV1` even
   though secret/public/durable-state classification belongs exclusively to the
   authenticated Store projection.

This record closes all eight. No budget number, timeout, retention period,
retry count, witness protocol field, Windows backend, or macOS backend is
assigned here.

## 3. Read-only reservation-handle identity

### 3.1 Exact semantic interface

The revised `NonceVaultV1` associated reservation handle is bounded by one
read-only trait:

```rust
pub trait VaultReservationHandleV1 {
    type SpentArtifactView<'a>: VaultSpentArtifactViewV1
    where
        Self: 'a;

    fn reservation_nonce_id(&self) -> &ReservationNonceId;
    fn request_lookup(&self) -> &ReservationRequestLookupV1;
    fn reservation_context_binding_digest(&self) -> &[u8; 32];
    fn live_stage(&self) -> ReservationLiveStageV1;
    fn final_retry_counter(&self) -> Option<u64>;
    fn spent_commitment(&self) -> Option<Self::SpentArtifactView<'_>>;
    fn spent_reveal(&self) -> Option<Self::SpentArtifactView<'_>>;
}

pub trait VaultSpentArtifactViewV1 {
    fn permit_id(&self) -> &PermitIdV1;
    fn kind(&self) -> ExposureKindV1;
    fn adaptor_outbound_digest(&self) -> &[u8; 32];
}

pub trait NonceVaultV1: Sized {
    type ReservationHandle: VaultReservationHandleV1;
    // All other NAR-DC-P1-004 associated types and methods remain exact.
}
```

No other identifier, secret, key, permit, receipt, journal bytes, storage
result, filesystem handle, pointer identity, or mutable field is exposed by
this trait.

### 3.2 Security properties

The concrete `ReservationHandle`:

- has a private Store constructor;
- is held only inside the safe vault-backed signer typestate;
- implements neither `Clone`, `Copy`, `Debug`, `Display`, generic
  serialization, equality, ordering, a byte codec, nor a public downcast;
- cannot be constructed from a reservation ID, state byte, request lookup ID,
  permit record, restored record, or caller-provided bytes;
- remains bound to the same retained `StoreAuthorityInner`, nonzero process
  open-instance ID, root, generation, lock acquisition, reservation authority,
  nonce epoch, journal ancestry, and active projection assigned by
  NAR-DC-P1-004; and
- becomes unusable when consumed by a terminal transition.

`reservation_nonce_id()` returns only the non-secret nonzero 32-byte identifier
already stored in the authenticated `ReservationAuthorityV1`. It grants no
read, write, open, seal, persist, authorize, export, resend, restore, or budget
authority. The safe signer copies it exactly once into bytes 10..42 of the
canonical `NonceSecretRecordV1`. `seal_derived_secret` independently parses
the plaintext and requires exact equality with the retained handle's
authenticated authority. Mismatch burns or quarantines according to the
existing attempt-prefix rules and never causes ID substitution.

`request_lookup()` returns only the exact distinct public lookup stored in the
authenticated authority. It is never a permit ID. The context-binding accessor
returns the exact nonzero digest recomputed from the complete embedded binding.

The remaining accessors project one closed live stage proven by the current
authenticated journal/projection prefix under the retained lock:

```rust
pub enum ReservationLiveStageV1 {
    PreDerivation,
    AfterCommitment,
    AfterReveal,
}
```

The exact presence table is:

| Live stage | Final retry | Commitment view | Reveal view |
|---|---|---|---|
| `PreDerivation` | `None` | `None` | `None` |
| `AfterCommitment` | `Some(exact persisted counter)` | `Some(kind = Commitment)` | `None` |
| `AfterReveal` | `Some(exact persisted counter)` | `Some(kind = Commitment)` | `Some(kind = Reveal)` |

The Store-owned associated spent-artifact view has a private constructor and
immutable accessors only. It is not an export or resend capability. The safe
signer can inspect it only while owning the unforgeable handle. Each view must
identify the complete current-generation canonical `Spent` exposure and its
verified contiguous journal ancestry. A wrong kind, zero digest, missing or
duplicate occurrence, predecessor-generation occurrence, presence-table
mismatch, or mismatch with the current projection quarantines before a handle
is returned.

A concrete handle cannot return a terminal or ambiguous state through a live
projection. Terminal authority is returned only through
`ReservationResumeResultV1::Terminal`; corrupt, partial, divergent, or
unclassifiable authority returns `RestoreQuarantined`. The projection is a
snapshot under the same retained lock and open-instance authority as the
handle. Every consuming Store method must revalidate the current head and all
handle bindings; an accessor result never freezes later authorization and
cannot substitute for that revalidation.

The accessors do not weaken the one-shot permit types. In particular, a
caller that learns a reservation ID or state cannot construct a request,
secret transfer, computation permit, persistence permit, persisted handle,
exposure permit, or exported artifact.

### 3.3 Fresh reservation and retry ownership

The Store remains the only generator of `ReservationNonceId`. Generation
occurs only after the complete pre-randomness absence scan, clock checks, and
budget admission assigned by NAR-DC-P1-004 §7.1. It uses the operating-system
CSPRNG, rejects zero, performs the post-generation lifetime collision scan,
and creates no public or secret material before that scan succeeds.

`FreshReservationRequestV1` and `ReservationResumeRequestV1` remain distinct,
non-cloneable, non-serializable, privately constructed types. Application code
cannot provide `VaultKeyId`, `CounterpartyBucket`, raw `ParticipantId`, request
ID, reservation ID, nonce epoch, or budget-policy digest.

The safe signer derives:

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

It obtains the local participant ID, purpose, template hash, session ID, and
complete reservation-context binding only from the validated two-entry roster
and immutable derivation-base context. This repeats NAR-DC-P1-004 §6.2 to make
the Rust ownership edge unambiguous; it does not create new tags.

The safe public `ReservationIntentV1` constructor that accepted caller-chosen
key, counterparty, or participant identifiers is removed. There is no
compatibility constructor, default, builder, struct literal, feature, or
conversion restoring those parameters.

The internally generated request lookup ID may be copied into a separate
public non-authoritative lookup value before the one-shot fresh request is
consumed. That lookup value can request only `resume_claimed_reservation`.
Zero occurrences return `RetryNotFound` without mutation. It cannot call fresh
creation, authorize exposure, or reconstruct a handle.

### 3.4 Exact resume-prefix dispatch

After exact resume validation, recovery dispatches every authenticated prefix
before returning any handle:

| Authenticated prefix | Result |
|---|---|
| Same retained open instance, exact freshly claimed reservation, no derivation permit issued, no KDF attempt known to have started, and no attempt, secret, exposure, or terminal object | `Live` with `PreDerivation` |
| Reopened process or Store with only a reserved authority/charge/claim and no derivation attempt | `Terminal(Burned)` because memory cannot prove that a KDF pair was never created |
| Derivation permit issued, derivation attempt absent/partial, derivation attempt present without the exact verified sealed secret and matching spent commitment, or sealed secret without that spent commitment | `Terminal(Burned)` after deterministic prefix completion; never rerun KDF |
| Exact current-generation spent commitment, complete derivation attempt and sealed secret, no reveal attempt/prefix, and unique valid ancestry | `Live` with `AfterCommitment` and the exact final retry plus commitment descriptor |
| Any reveal attempt/persisted prefix that is not the exact complete spent reveal successor | deterministic Burned completion or `RestoreQuarantined` as assigned by the existing prefix rules; never `Live` and never recompute reveal |
| Exact current-generation spent commitment and spent reveal, verified secret, no partial attempt/prefix, and unique valid ancestry | `Live` with `AfterReveal`, exact final retry, and both descriptors |
| Any partial attempt/persisted/consumed prefix that is not the exact complete spent partial successor | complete the byte-identical existing prefix or quarantine as assigned; never `Live`, never recompute partial, and never create authorization from storage alone |
| Exact spent partial successor / `ConsumedPartialAuthorized` | `Terminal`; nonce computation is over and only a separately authorized exact resend request may proceed |
| `AbortedBeforePublicMaterial`, `ConsumedOnAbort`, or `Burned` | corresponding `Terminal`, never `Live` |
| Missing, duplicate, reordered, corrupt, divergent, predecessor-only, or otherwise unclassifiable evidence | `RestoreQuarantined` error; no handle |

The safe signer maps `PreDerivation`, `AfterCommitment`, and `AfterReveal`
exhaustively to distinct private typestates. It cross-checks the projection
against the opaque validated signing-round state before creating an operation
request. No default arm, unknown state, sequential trial of stage methods,
fresh-on-resume fallback, counter-zero fallback, secret decryption to discover
the counter, or KDF replay exists.

### 3.5 Distinct request lookup and custody order

`ReservationRequestLookupV1` and `PermitIdV1` are distinct 32-byte nonzero
newtypes. Neither aliases, converts to, parses as, compares across, nor shares
a generic identifier type with the other. A request lookup grants only exact
resume lookup with the same trusted validated reservation binding. A permit ID
grants only non-authoritative current-exposure lookup and requires the separate
resend authority in §4.5.

The canonical public lookup representation is exactly the raw 32 request-ID
bytes already embedded at offset 203 of `ReservationAuthorityV1`. Its dedicated
parser accepts exactly 32 bytes and rejects all-zero; its encoder is
byte-identical and infallible after parsing. It has no textual, UUID, integer,
Serde, bincode, or native-layout normative representation. The distinct permit
ID parser and type remain unchanged.

The safe signer creates one private `PreparedFreshReservationV1` containing
the one-shot `FreshReservationRequestV1` and its public non-authoritative
`ReservationRequestLookupV1`. Before the fresh request is consumed, the signer
must expose that lookup to the trusted session-state persistence boundary and
must receive confirmation that the exact lookup and context-binding digest are
durable in that state. This is an idempotent recovery-custody operation, not
Store authorization; failure stops before `claim_fresh_reservation`.

Only after that durable custody step does the signer consume
`PreparedFreshReservationV1` and pass its contained fresh request to the Store.
On a lost response, trusted session state supplies the same lookup and the same
validated binding to construct one private `ReservationResumeRequestV1`.
Application code may store or retransmit the public lookup, but cannot combine
it with arbitrary binding fields or call fresh creation. No Boolean supplied
by an application is treated as persistence evidence, and no lookup is minted
inside retry/resume.

The persistence boundary is an application-independent, statically selected
`ReservationLookupCustodyV1` implementation owned by the specialized DOM
Contracts session store. It returns an opaque, one-shot
`DurableReservationLookupV1` only after the exact lookup and context-binding
digest are durably committed and reread. The capability has no public
constructor, bytes, clone, copy, debug, serialization, equality, or caller
Boolean conversion. The safe signer itself invokes this custody boundary and
consumes the resulting capability together with the matching
`PreparedFreshReservationV1`; a cross-lookup, cross-binding, cross-session,
reopened-custody, or reused capability fails before Store admission. This
custody capability authorizes only consumption of the already prepared fresh
request. It cannot create a reservation, budget charge, nonce, permit, or
export by itself.

The custody-before-claim crash prefix is closed fail-safe. If the process dies
after durable lookup custody but before `claim_fresh_reservation` creates any
authenticated Store occurrence, the subsequent exact resume returns
`RetryNotFound`. Trusted session state must then durably mark that lookup and
session as `AbandonedBeforeVaultClaim`. The prepared request and process-only
custody capability are never reconstructed. Fresh creation with that lookup or
session is permanently forbidden, and there is no retry-to-fresh fallback.
Continuation requires a new lifetime-unique session ID, request lookup, and
prepared reservation. Because Store admission never occurred, this prefix has
no vault budget charge or nonce to refund or burn; the trusted session-state
abandonment record is still irreversible and prevents protocol replay.

## 4. Authenticated accepted DSC1 signing messages

### 4.1 Closed envelope parser

The accepted-message boundary used by NAR-DC-P1-004 operation inputs parses
the Master Specification §8.1 envelope exactly:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII `DSC1` |
| 4 | 2 | version `1`, little-endian |
| 6 | 1 | closed message type |
| 7 | 1 | flags, exactly zero |
| 8 | 32 | trusted chain ID |
| 40 | 32 | nonzero session ID |
| 72 | 32 | registered sender participant ID |
| 104 | 8 | sender sequence, little-endian |
| 112 | 32 | previous accepted transcript hash |
| 144 | 4 | payload length, little-endian |
| 148 | `N` | exact canonical payload |
| `148+N` | 65 | transport-identity signature |

The complete length is exactly `213 + N`; trailing or missing bytes fail.
Length and the per-kind cap are checked with checked arithmetic before payload
allocation. For the signing-round evidence used by NAR-DC-P1-004, the only
accepted kinds are:

```text
0x0c SigNonceCommit   cap 4 KiB   payload exactly 35 bytes
0x0d SigNonceReveal   cap 8 KiB   payload exactly 69 bytes
0x0e PartialSignature cap 8 KiB   payload exactly 67 bytes
```

The payload is parsed by the existing canonical `dom-adaptor` type for that
kind and re-encoded byte for byte. Unknown kinds, wrong fixed payload lengths,
wrong purpose, Sponsor, wrong participant index, malformed point/scalar, or
noncanonical re-encoding fail closed.

### 4.2 Message digest and transport-identity signature

The message digest remains exactly:

```text
session_message_digest_32 = H_tag(
  "DOM:scriptless-message:v1",
  message_bytes[0 .. 148+payload_len]
)
```

The 65-byte signature is excluded from that digest. The transport identity
signature reuses the unchanged authoritative DOM Schnorr implementation and
no new signature primitive:

```text
sender_signature_65 = dom_crypto::schnorr_sign(
  sender_transport_identity_secret_key,
  session_message_digest_32,
  trusted_chain_id_32
).to_bytes()

valid = dom_crypto::schnorr_verify(
  SchnorrSignature::from_bytes(sender_signature_65),
  sender_transport_identity_public_key,
  trusted_chain_id_32,
  session_message_digest_32
)
```

The exact source functions are `dom_crypto::schnorr_sign`,
`dom_crypto::schnorr_verify`, and `dom_crypto::SchnorrSignature::{from_bytes,
to_bytes}`. The signature is the canonical 33-byte compressed `R` followed by
the canonical nonzero 32-byte big-endian `s`, total 65 bytes. Verification uses
the unchanged DOM Schnorr challenge and parser. No adaptor challenge,
BIP340/x-only normalization, alternative tag, Ed25519, ECDSA, generic signing
framework, or signature alias is introduced.

The transport identity key is independently generated and remains distinct
from DOM Wallet keys, contract spending keys, G1A signing shares, nonce
secrets, storage keys, witness keys, and backup keys. Key separation and the
already tagged DSC1 digest prevent a transport-signature request from becoming
authority over a DOM kernel key.

### 4.3 Validated accepted-message type

Successful exact parsing, roster lookup, participant-ID recomputation,
canonical payload parsing, and signature verification create one immutable
`ValidatedAcceptedSessionMessageV1`. Its constructor and fields are private.
It exposes immutable accessors only for:

- closed kind;
- trusted chain ID;
- session ID;
- sender participant ID;
- sender sequence;
- previous transcript hash;
- exact unsigned envelope bytes from offset 0 through the payload;
- exact canonical payload bytes; and
- recomputed `session_message_digest_32`.

The type contains no secret and may be moved into the trusted session state,
but application-provided digest-only evidence is never equivalent. The safe
vault-backed signer accepts only these validated objects when constructing
`ProtocolCommitmentSetV1` and `ProtocolRevealSetV1`.

Before constructing an operation request, the signer independently requires:

- exact chain and session equality with the reservation binding;
- exact sender participant and G1A-index mapping;
- exact message kind and payload kind;
- exact purpose and participant index;
- strict protocol-roster order;
- no duplicate logical key `(session_id, sender_id, sequence)`;
- exact previous-transcript ancestry and round barrier;
- reveal equality with the already accepted commitment;
- exact transcript replay through `advance_transcript_hash_v1`; and
- equality between each set entry's recorded message digest and the validated
  object's recomputed digest.

A parser success alone does not make a message accepted. Sequence, transcript,
round, equivocation, and duplicate decisions remain owned by the trusted
session state. An early or out-of-order validly signed message is buffered and
cannot enter an operation input until its assigned barrier is satisfied.

### 4.4 Opaque accepted signing-round state

`dom-adaptor` owns one opaque `ValidatedSigningRoundStateV1`. Its fields and
constructors are private. It implements neither `Clone`, `Copy`, `Debug`,
`Display`, generic serialization, equality, ordering, nor a raw state codec.
Production constructs it only from the trusted chain adapter, the complete
validated two-entry protocol/G1A roster mapping, the accepted contract terms,
the local signing share/public-key equality proof, the initial transcript
ancestry, and the closed Phase 1 purpose policy. Sponsor is rejected.

Its only peer-input method accepts complete DSC1 bytes. Internally it invokes
§4.1–§4.3 parsing and signature verification, recomputes participant identity,
and then enforces, before state advancement:

- exact chain, session, purpose, role/direction, roster, participant index,
  signing key, and transport identity key;
- strict per-sender sequence with duplicate byte-identity and equivocation
  detection;
- exact previous-transcript ancestry and
  `advance_transcript_hash_v1` replay;
- commitment-before-reveal and reveal-before-partial barriers;
- exact one-message-per-participant membership for each closed set;
- reveal equality with the already accepted commitment; and
- no field, digest, set, binding factor, aggregate, or transcript supplied by
  application code.

A valid early message may be buffered as immutable complete bytes, but it
cannot alter the accepted transcript or produce an operation token until its
barrier is satisfied. A duplicate with identical bytes is idempotent; the same
logical `(session_id, sender_id, sequence)` with different bytes is permanent
equivocation and closes the session.

The state can issue only these opaque, one-shot, private stage authorities:

| Authority | Exact prerequisite | Permitted signer output |
|---|---|---|
| `ValidatedDerivationBaseV1` | accepted pre-commit transcript, complete mapping and strict Phase 1 policy | derivation-base context, prepared fresh/resume binding, and one `NonceDerivationRequestV1` |
| `ValidatedCommitmentRoundV1` | both exact commitment DSC1 messages accepted in protocol-roster order | canonical `ProtocolCommitmentSetV1`, commitment-folded transcript, and one reveal-stage request |
| `ValidatedRevealRoundV1` | both exact reveal DSC1 messages accepted, each matching its commitment | canonical commitment/reveal sets, reveal-folded transcript, binding factor, effective/aggregate/adaptor nonce inputs, aggregate key, kernel message, and one partial-stage request |
| `ValidatedResendAuthorizationV1` | current trusted protocol state explicitly permits resend of one already recorded local artifact | one `ResendRequestV1` bound as §4.5 |

Each authority is consumed by the matching safe signer transition. There is no
generic stage token, public constructor, byte decoder, downcast, default arm,
or conversion among stages. Reservation, reveal, partial, and resend requests
accept only the corresponding opaque authority. The operation-input tagged
bytes and digests are recomputed from these owned values; caller-supplied
digests, commitment/reveal sets, binding factors, aggregates, or stage enums
are never authority.

### 4.5 Exact resend authority

The revised safe trait route is exactly:

```rust
fn resend_exported(
    &mut self,
    request: ResendRequestV1, // consumed
) -> Result<Self::ExportedArtifact, Self::Error>;
```

There is no permit-ID-only overload, compatibility wrapper, default method,
raw-byte route, or application-supplied expected digest. `ResendRequestV1` has
private fields and is created only by consuming one
`ValidatedResendAuthorizationV1`. Its immutable Store view binds all of:

- request lookup, reservation ID, nonce identity, participant ID, session ID,
  purpose, and complete reservation-context binding digest;
- exact nonzero `PermitIdV1`;
- expected closed `ExposureKindV1`;
- exact nonzero adaptor-domain outbound digest of the artifact recorded by
  trusted protocol state; and
- the closed current protocol-stage authorization that permits resend of that
  exact local artifact without authorizing a new computation.

The Store streams current-generation `Spent` exposures and requires exactly
one complete match. It verifies vault, epoch, generation, reservation,
identity, context, participant, session, purpose, kind, permit ID, adaptor and
Contracts outbound digests, exact bytes, authorizing entry, and contiguous
ancestry. It then creates and spends one live capability and returns the same
closed typed artifact bytes. Zero matches returns the closed
not-found-or-retired result. Multiple, predecessor-only, carried-only,
changed, or divergent matches quarantine. No KDF, secret open, commitment,
reveal, partial, replacement bytes, caller receipt, or Boolean is involved.
The request carries no Store-private pointer, open-instance ID, lock token, or
filesystem authority. The `&mut self` Store receiver supplies and revalidates
all current live Store authority. The returned `Self::ExportedArtifact` is the
Store-owned type implementing `VaultExportedArtifactV1`; the safe
`dom-adaptor` signer validates its closed kind and bytes and wraps it into the
appropriate application-facing authorized artifact. An external Store never
constructs a private-field concrete signer result.

### 4.6 Bound prepared artifacts and persistence permits

The `NonceVaultV1::ArtifactPersistencePermit` associated type is bounded by a
read-only `VaultArtifactPersistencePermitV1` interface. The permit remains the
private, one-shot Store authority assigned by NAR-DC-P1-004. Its view exposes
to the safe signer and Store only one process-local nonzero computation-binding
ID and the immutable non-secret fields needed for comparison:

```text
reservation ID
complete NonceIdentityV1
reservation-context binding digest
derivation-attempt digest
operation-input digest
effective final retry counter
phase and exposure kind
exposure sequence
expected lifecycle revision
stage-context digest
process-local computation-binding ID [32 bytes]
```

`ProcessComputationBindingIdV1` is exactly one nonzero owned 32-byte value
generated from the operating-system CSPRNG by the Store when the permit is
issued. Its only production constructor takes no byte argument, obtains all 32
bytes internally from the operating-system CSPRNG, retries zero before permit
issuance, and fails closed on RNG failure. It has no caller-bytes constructor,
parser, serializer, textual form, default, deterministic production
constructor, or authority when separated from the private permit. It is never
persisted or logged. It exists only to prove that the prepared artifact was
produced while the safe signer owned the matching one-shot permit. A copied ID
cannot open, persist, authorize, export, or resend.

`PreparedExposureV1` has no raw-bytes constructor. The safe signer alone builds
one of three closed private variants while it owns the matching permit view:

| Variant | Required canonical public evidence |
|---|---|
| Commitment | exact typed outbound bytes, `PublicNoncePairV1`, canonical nonce commitment, local participant/index, context and operation-input evidence |
| Reveal | exact typed outbound bytes, revealed public nonce pair, exact prior spent commitment descriptor and commitment equality evidence, local participant/index, context and operation-input evidence |
| PartialSignature | exact typed outbound bytes, canonical partial scalar, participant public signing key, effective participant nonce, binding factor, aggregate/adaptor nonce, aggregate key, kernel-message/challenge inputs, context and operation-input evidence sufficient for the authoritative partial-verification equation |

Every variant carries an immutable copy of all non-secret computation-binding
fields above. Its constructor and fields are private; it implements no generic
serialization or caller-provided byte conversion. Secret nonce material,
signing share, opened secret transfer, raw capability, or Store pointer is
never stored in it.

The external Store does not inspect private fields directly. `dom-adaptor`
exposes exactly one authoritative read-only validation function:

```rust
pub fn validate_prepared_exposure_v1<'a, P>(
    permit: &'a P,
    artifact: &'a PreparedExposureV1,
) -> Result<ValidatedPreparedExposureViewV1<'a>, PreparedExposureValidationError>
where
    P: VaultArtifactPersistencePermitV1;
```

`ValidatedPreparedExposureViewV1` has a private constructor and immutable
accessors for the closed exposure kind, exact canonical outbound bytes,
outbound digests, process computation-binding ID, and the public verification
evidence applicable to that kind. It carries no secret and grants no
persistence or export authority. The function compares every permit/artifact
binding field and performs the authoritative public checks below. A caller
cannot construct a successful view from raw bytes, and the Store accepts no
alternate validation callback or Boolean.

`persist_computed_artifact` first invokes that function with the exact permit
and artifact it received. The function requires field-for-field equality,
including the process-local ID, strictly parses and canonical-reencodes the
exact outbound bytes, and executes every available public verification through
authoritative `dom-adaptor`/DOM crypto functions:

- commitment recomputation from the submitted public nonce pair;
- reveal-to-prior-commitment equality and current accepted-set membership; and
- participant-bound partial equation, context, binding-factor, aggregate,
  adaptor point, kernel-message, and real DOM challenge verification.

Only after those checks may the unchanged stage-specific persistence
transaction run. A mismatch consumes no alternate route, cannot be corrected
with replacement bytes, and follows the controlling attempt crash-prefix rule.
No Store implementation recomputes a secret-derived artifact.

### 4.7 Caller-free cancellation and internal abort classification

The safe trait route is:

```rust
fn cancel_reservation(
    &mut self,
    reservation: Self::ReservationHandle, // consumed
) -> Result<TerminalReservationV1, Self::Error>;
```

Application code may request cancellation through the high-level signer, but
cannot provide `AbortReasonV1`, secret-presence state, exposure state, durable
state, tombstone reason, or recovery classification. There is no safe
`abort(reservation, reason)` compatibility route.

Under the retained lock, the Store authenticates and classifies the complete
authority, attempt, secret, exposure, journal, and terminal projection. It
then applies the unchanged signed mapping internally:

- proven no-public-material prefix -> `BeforePublicMaterial` ->
  `AbortedBeforePublicMaterial`;
- any proven or possible public-material prefix ->
  `PublicMaterialMayHaveExisted` -> `ConsumedOnAbort`; and
- crash/restore ambiguity -> `CrashAmbiguity`/`RestoreAmbiguity` -> `Burned`
  or quarantine according to the existing deterministic prefix rules.

Cancellation consumes the handle, never refunds any budget, never releases a
session/request/reservation/nonce identity, and never creates a resend or
export capability. Recovery-only reason variants remain internal and cannot be
named by a production caller.

## 5. Linux retained filesystem and lock boundary

### 5.1 Dependency selection

The Linux V1 runtime uses exactly:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
cap-std = { version = "=4.0.2", default-features = false }
cap-fs-ext = { version = "=4.0.2", default-features = false, features = ["std"] }
rustix = { version = "=1.1.4", default-features = false, features = ["std", "fs", "process"] }
nix = { version = "=0.31.3", default-features = false, features = ["fs", "feature"] }
```

Crate metadata:

| Crate | Version | Enabled features | Repository | License | Downloaded `.crate` SHA-256 |
|---|---:|---|---|---|---|
| `cap-std` | `4.0.2` | none | `https://github.com/bytecodealliance/cap-std` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `7281235d6e96d3544ca18bba9049be92f4190f8d923e3caef1b5f66cfa752608` |
| `cap-fs-ext` | `4.0.2` | `std` | `https://github.com/bytecodealliance/cap-std` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `d78e5a3368ae89b7cb68186411452b4b9fac8b41be9c19bf3f47c2d2c8e36e6b` |
| `rustix` | `1.1.4` | `std`, `fs`, `process` | `https://github.com/bytecodealliance/rustix` | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | `b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190` |
| `nix` | `0.31.3` | `fs`, `feature` | `https://github.com/nix-rust/nix` | `MIT` | `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d` |

`Cargo.lock` must pin the registry checksum and its complete resolved
dependency graph. No wildcard feature, `all-apis`, `use-libc`, Git dependency,
path override, absolute path, or untracked patch is permitted.

`cap-std::fs::Dir` is the retained capability object used by application
architecture. `cap-fs-ext` supplies its reviewed no-follow extensions.
`rustix` supplies the exact Linux operations and flags that the higher-level
capability API does not expose with sufficient precision, including
`openat2`, `renameat2(RENAME_NOREPLACE)`, `unlinkat`, `flock`, `fstat`,
`fchmod`, `geteuid`, and descriptor `fsync`. `nix` is used only for
`fpathconf(fd, PathconfVar::NAME_MAX)`. Application code converts only borrowed
or owned safe descriptor types and contains no `unsafe`. Dependency-internal
unsafe remains third-party dependency code subject to the pinned lockfile,
advisory/provenance review, and source review; it is not copied into the
application.

Neither layer is sufficient alone: the `cap-std`/`cap-fs-ext` layer defines
and retains capability ownership, while the `rustix` layer enforces the exact
Linux syscall semantics at every authoritative mutation edge. Application
code must not emulate an unavailable operation with a weaker API.

### 5.2 Required calls and flags

The runtime uses retained `OwnedFd` directory and file descriptors and the
following safe APIs:

| Requirement | Required `rustix::fs` boundary |
|---|---|
| Open existing descendant | `openat2` with `ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS` plus `OFlags::NOFOLLOW | OFlags::CLOEXEC` and the exact file/directory access flags |
| Create exact file | `openat2` with the same resolve flags plus `OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC` |
| Create exact directory | `mkdirat`, followed immediately by retained `openat2`, `fstat`, exact-mode enforcement, and parent `fsync`; `EEXIST` is not treated as successful fresh creation |
| Type and identity verification | `fstat` on the retained descriptor; require the exact assigned type, `st_nlink == 1` for authoritative regular files, `st_uid == rustix::process::geteuid()`, and exact mode; `statat(..., AtFlags::SYMLINK_NOFOLLOW)` is additional evidence and never replaces post-open `fstat` |
| No-replace rename | `renameat_with(..., RenameFlags::NOREPLACE)` in one retained parent directory |
| Active-pointer replacement | `renameat` in one retained parent directory, only for the exact active pointer assigned by NAR-DC-P1-004 |
| Unlink | `unlinkat` relative to the retained parent, followed by parent `fsync` |
| File synchronization | `fsync` on the retained file descriptor |
| Directory synchronization | `fsync` on the retained directory descriptor |
| Exclusive lock | `flock(retained_lock_fd, FlockOperation::NonBlockingLockExclusive)` exactly once during open |
| Owner-only mode | New objects use `fchmod` on the retained descriptor to enforce exact `0700` for directories and `0600` for sensitive files after creation, then verify; existing objects with a wrong mode are rejected and never silently repaired |
| Effective component limit | `nix::unistd::fpathconf(retained_fd, PathconfVar::NAME_MAX)` on every retained destination filesystem; require `Some(limit)` with valid nonzero `limit >= 229` before mutation |
| Directory enumeration | Retain the parent capability and validated child component, reopen that component through the same authoritative `openat2` boundary to obtain an independent directory descriptor, then use `RawDir`; `.` and plain `dup` are forbidden because `.` is not an accepted component and `dup` shares the open-file-description cursor |

Every path argument after the initial operator-selected parent is one validated
single component from the frozen NAR-DC-P1-004 registry. Empty strings, `.`,
`..`, slash, NUL, platform separator aliases, overlong components, and unknown
names fail before a syscall.

Before creating or opening a Store, backup, restore transaction, or new
generation on any destination filesystem, the runtime calls
`nix::unistd::fpathconf` with `PathconfVar::NAME_MAX` on that retained
destination descriptor. `Err`, `None`, an invalid conversion, zero, or a value
below 229 fails closed before any mutation. The check is repeated for every
distinct retained destination filesystem; a successful check on one device is
not evidence for another device.

All authoritative opens use this one `rustix::fs::openat2` route. Ordinary
`cap-std` open methods are not an alternate semantic path. If `openat2`, any
assigned resolve flag, `renameat2(RENAME_NOREPLACE)`, advisory exclusive
locking, file `fsync`, or directory `fsync` returns `ENOSYS`, unsupported
`EINVAL`, `EXDEV`, or equivalent unavailable behavior, Store creation/open
fails closed for adaptor operations. There is no fallback to ambient
`std::fs` paths, `canonicalize`-then-open, pre-open metadata checks, `/proc`
reopening, plain `openat`, replacing rename for a no-replace transaction, or
application-owned raw syscall code.

### 5.3 Retention and synchronization rules

One `StoreAuthorityInner` owns the retained root, lock-file, active-generation,
journal, projection-directory, exposure-directory, attempt-directory,
tombstone-directory, and secret-directory capabilities required by the active
operation. Child capabilities are opened only from an already retained parent.

The lock pathname is never reopened per operation. The lock acquisition lives
for the complete `StoreAuthorityInner` lifetime in a private non-cloneable RAII
owner containing that same `OwnedFd`. It exposes neither the descriptor nor an
unlock method and implements no unlocking `Drop`; closing the final descriptor
releases the kernel lock. A second process receiving a busy lock result returns
a closed Store-busy error before reading any state that could become
authorization. An in-process mutex serializes operations on the same inner
authority.

Immediately after successful exclusive lock acquisition, and before any read
that could become authorization, the runtime revalidates the retained root and
lock identities, types, link counts, owners, modes, and exact lock/root binding
required by NAR-DC-P1-004. Any mismatch creates no application authority and
fails closed.

Create/write durability is:

1. create-no-clobber staging or final object under a retained parent;
2. write all exact bytes with checked completion;
3. `fsync` the file;
4. close or retain according to the assigned transaction;
5. perform the exact no-replace or replacement rename when assigned;
6. `fsync` the parent directory;
7. reopen through `openat2` under the retained parent;
8. `fstat`, read exact length, authenticate, and compare byte for byte; and
9. only then advance the next assigned state.

Unlink durability is retained-parent `unlinkat` followed by parent `fsync` and
an exact no-follow absence check. In this Linux profile, the signed term
`retained-handle unlink` means all of the following, not a nonexistent Linux
operation that unlinks a directory entry directly by file descriptor:

1. retain the already authenticated target file descriptor and its `fstat`
   identity while retaining the authenticated parent-directory capability and
   the Store-wide exclusive lock;
2. immediately before deletion, call
   `statat(parent_fd, component, AtFlags::SYMLINK_NOFOLLOW)` on the exact
   validated single-component name;
3. require the name to identify a regular file with `st_nlink == 1` and require
   its device, inode, type, link count, owner, mode, and assigned immutable
   metadata to match the retained target's `fstat` identity;
4. call `unlinkat` using the retained parent descriptor and the exact validated
   component;
5. `fsync` the retained parent directory; and
6. perform an exact no-follow absence check under the same retained authority.

Any mismatch, replacement, symlink, race evidence, or incomplete
synchronization fails closed and leaves the reservation Burned or the Store
quarantined according to the controlling recovery prefix. It creates no
capability and exports no bytes. The application never claims that Linux can
unlink an inode by passing only its open file descriptor. This profile also
does not claim protection against a malicious same-UID process that already
has write authority to the private Store directories and deliberately ignores
the advisory lock; requiring that threat model is an implementation STOP and
requires a separately ratified process-isolation boundary. A destructor,
process exit, memory zeroization, or dropped file handle is never durability
evidence.

### 5.4 Rejected alternatives

- Ambient `std::fs` path operations are rejected because they do not provide
  the required retained descriptor-relative no-symlink authority.
- `canonicalize` followed by open is rejected because it is a TOCTOU check.
- `fs2`/`fs4` alone are rejected because locking does not supply the required
  complete descriptor-relative filesystem transaction boundary.
- `cap-std` or `cap-fs-ext` alone is rejected because this profile requires
  explicit Linux `openat2` resolve flags,
  `renameat2(RENAME_NOREPLACE)`, `fpathconf(NAME_MAX)`, `flock`, and descriptor-sync
  evidence at authoritative edges.
- `rustix` alone is rejected as the application architecture because the
  retained ownership model must remain explicit in capability types rather
  than becoming an ad hoc collection of file descriptors.
- Direct `libc`, copied syscall constants, application `unsafe`, shell commands,
  and helper subprocesses are rejected.
- Falling back when the kernel lacks an assigned primitive is rejected.

Windows and macOS remain fail-closed and unsupported for G1B approval until
separate signed backend profiles and real-runner evidence exist. This record
does not claim portability from Rust type-checking alone.

## 6. Required implementation order

After ratification, implementation proceeds in this order:

1. Import this exact document and detached signature byte for byte and verify
   both with the established public key.
2. Add `VaultReservationHandleV1`, bind the associated handle, remove the
   caller-authoritative reservation intent fields, add distinct request lookup
   custody, and implement the exact fresh and resume-prefix flows.
3. Add the exact DSC1 accepted-message parser, transport-identity signature
   verification, and opaque accepted signing-round state with positive,
   negative, mutation, ordering, equivocation, and replay tests.
4. Complete the revised NAR-DC-P1-004 computation requests, bound prepared
   artifact variants, distinct permits, persist-before-authorize path,
   request-authorized exact resend, caller-free cancellation, and safe signer
   typestates.
5. Pin `cap-std = 4.0.2`, `cap-fs-ext = 4.0.2` with only `std`,
   `rustix = 1.1.4` with only `std`, `fs`, and `process`, and `nix = 0.31.3`
   with only `fs` and `feature`; inspect the resolved graph and implement the
   retained Linux boundary before any runtime transaction commit.
6. Implement the canonical Store runtime, crash recovery, restore, budgets,
   and exact-byte resend only through that retained boundary.
7. Run compile-fail, unit, mutation, process-death, concurrency, symlink-race,
   fault-injection, fuzz, sanitizer, dependency, and secret-leak checks.

No step authorizes a public Git revision, dependency-pin update, push, merge,
release, production configuration, Phase 2, mainnet, or real funds.

## 7. Mandatory tests

At minimum, evidence must prove:

- callers cannot construct or clone a reservation handle;
- a copied reservation ID cannot reconstruct a handle or permit;
- request lookups and permit IDs cannot alias or convert, the lookup is durable
  before claim, and a lost fresh response resumes only with the exact lookup
  plus validated binding;
- real process death after durable lookup custody but before Store claim yields
  `RetryNotFound`, durably abandons that session/lookup, and cannot recreate the
  prepared request or fresh-fallback with the same session;
- the secret record's reservation ID is byte-identical to the authenticated
  handle and mismatch fails before sealing;
- every live resume state maps exhaustively to one continuation and every
  terminal state is never returned as live;
- every reserved crash prefix follows the §3.4 table, including real process
  death before/after KDF attempt persistence, with no KDF replay;
- `RetryNotFound` performs no time, randomness, budget, journal, projection,
  or filesystem mutation;
- every DSC1 header and payload field mutation fails as assigned;
- unknown message types, flags, trailing bytes, wrong caps, wrong chain,
  session, sender, sequence ancestry, transcript, purpose, participant index,
  payload, public key, and signature fail closed;
- the transport signature verifies only with the exact registered identity key,
  chain ID, and recomputed session-message digest;
- valid early messages remain buffered and cannot alter operation inputs;
- commitment/reveal sets contain only digests recomputed from complete
  validated immutable envelopes;
- no production feature can construct the validated accepted-message type
  without successful signature verification;
- no production route can construct or skip an accepted signing-round stage,
  inject a commitment/reveal set, binding factor, aggregate, transcript, or
  operation-input digest, or advance across an unsatisfied barrier;
- duplicate byte-identical messages are idempotent while same-key differing
  messages close as equivocation;
- a prepared commitment, reveal, or partial with any mismatched private binding
  or public verification field fails before persistence;
- an external Store can validate prepared artifacts only through
  `validate_prepared_exposure_v1`; the validated view cannot be caller-built,
  and the process binding ID alone grants no authority;
- commitment recomputation, reveal-to-commitment equality, and participant
  partial verification execute against the authoritative DOM boundary;
- permit-ID-only resend does not compile, wrong trusted kind/digest fails, and
  exact authorized resend returns only byte-identical current spent bytes;
- callers cannot select `AbortReasonV1`; cancellation derives the terminal
  reason from authenticated state and never refunds budget;
- symlink substitution at every component fails;
- hard-linked authoritative regular files, wrong owner, wrong type, wrong
  mode, and wrong link count fail closed;
- a second process cannot obtain live Store authority;
- create-no-clobber and rename-no-replace never overwrite an existing object;
- active-pointer replacement is the only replacing rename;
- every required file and directory sync failpoint recovers to the assigned
  exact prefix, Burned state, or quarantine without nonce/budget reuse;
- loss of `openat2`, `renameat2`, lock, or directory sync support fails closed;
- an effective component limit below 229 or an unavailable/indeterminate
  `NAME_MAX` fails before mutation;
- repeated complete directory scans use independent `openat2` descriptors and
  do not inherit a shared `dup` cursor;
- no application `unsafe`, ambient authoritative path, absolute local path, or
  untracked dependency override enters production; and
- ordinary DOM Wallet code and data remain absent from the dependency and call
  graphs.

## 8. Explicit non-decisions and remaining gates

This record deliberately does not assign:

- production global, counterparty, concurrent, or rolling budget values;
- clock-forward bounds, timeout, retry, or retention values;
- witness or watchtower production behavior;
- Windows or macOS filesystem semantics;
- a new AEAD, KDF, hash, signature, scalar, point, challenge, or consensus
  rule;
- Phase 2 protocol behavior;
- a published DOM revision or a new `dom-contracts` dependency pin; or
- production/mainnet activation.

Evidence-only budget policies remain explicit test inputs and cannot enter a
production default. A future DOM revision containing the revised API requires
separate publication authorization and a new immutable public dependency pin.

Until all implementation and evidence gates pass:

```text
G1A = NOT CHANGED BY THIS RECORD
G1B = NOT APPROVED
G1 = NOT ADJUDICATED
PHASE2 = NOT AUTHORIZED
MAINNET = DISABLED
PRODUCTION = NOT AUTHORIZED
```

## 9. Ratification

Ratification means only that the exact signed bytes of this record become the
controlling assignment for the missing reservation-handle information flow,
accepted DSC1 transport-identity verification boundary, and Linux retained
filesystem/locking implementation profile. Ratification does not attest that
code or tests exist and does not approve any gate.

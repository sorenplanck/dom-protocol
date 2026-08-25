# ADR-LAB-F7-003: Operational Retained-Capability Session Store

- Status: F7 laboratory candidate; not a normative record
- Date: 2026-08-13
- Scope: `dom-scriptless-store` on Linux only
- Governing references: Master Specification §§7.2, 7.3, 10.1, 10.3, 10.5,
  11.1; NAR-DC-P1-004; NAR-DC-P1-005; the recorded findings in
  NAR-DC-P1-007

## Problem

`SessionRecordV1` defines authenticated authority bytes and its `advance`
operation defines revision CAS and irreversible-state monotonicity, but the
repository had no runtime that durably created, loaded, or compare-and-swapped
those bytes. The existing `ContractsNonceVaultV1` is a complete retained
nonce-safety authority whose signed filesystem inventory does not contain a
session-record namespace. Funding authorization consequently had no durable,
one-shot implementation: a process-local model could not prove that a refund
was persisted before funding, prevent reissuance after restart, or retire the
broadcast authority before returning network bytes.

## Context

The retained Linux boundary already provides the required primitives:
single-component validation, retained `cap_std::fs::Dir` authorities,
`openat2` with `BENEATH | NO_SYMLINKS | NO_MAGICLINKS`, exact ownership and
mode checks, nonblocking `flock`, create-no-clobber, `renameat2(NOREPLACE)`,
file `fsync`, and parent-directory `fsync`.

Changing the nonce-vault generation tree would change the inventory covered by
NAR-DC-P1-004, its backup/restore transaction, and its evidence corpus. It would
also risk creating a second nonce authority, which is forbidden. This ADR does
not assign new consensus, wire, transaction, signature, Bulletproof, adaptor,
or nonce behavior.

NAR-DC-P1-007 records that caller-provided readiness Booleans and merely linear
in-memory tokens are model-only. Its production-status statements remain in
force. This laboratory implementation is evidence for a future normative and
release review; this ADR does not itself authorize production or real funds.

## Decision

### Additive sibling authority

Add `ContractsSessionStoreV1` as a sibling retained root selected by the trusted
composition root. Continue to use `ContractsNonceVaultV1` as the sole nonce
vault. Both production constructors require an explicit authenticated
`BudgetPolicyV1` whose profile is exactly `ProductionRatified`; neither crate
selects numeric defaults. Existing evidence-only constructors remain feature
gated and accept only `EvidenceOnly`.

The session root contains exactly:

```text
session-store-root.bin
session-store-lock.bin
session-store-policy.bin
session-records/
session-artifacts/
session-consumptions/
session-rosters/
session-messages/
```

The root and lock identities bind a random nonzero store identifier and the
exact policy digest. The lock remains retained for the complete open lifetime.
Unknown, misplaced, linked, replaced, incorrectly owned, or incorrectly mode-set
objects quarantine the store.

### Immutable revision CAS

Each session revision is an immutable file named:

```text
<lowercase-session-id>-<20-digit-revision>.session
```

Publication writes an equally registered hidden staging file, syncs its bytes
and parent, renames it with `NOREPLACE`, syncs the parent, reopens it, and checks
the exact bytes. Startup removes only unpublished staging objects while holding
the exclusive lock. Final revision files are commit authority. Load requires a
contiguous history beginning at revision zero and reconstructs every successor
with `SessionRecordV1::advance`; a byte mismatch quarantines the store.

Funding-sensitive transitions cannot enter through the general protocol CAS.
The scanner/reorg API constructs the successor itself and changes only
`SessionChainProjectionV1`; phase, transcript, irreversible state, terms,
session identifier, and encrypted payload remain exact.

### Real DOM artifact verification and exact bytes

`verify_funding_artifacts_v1` is the only public constructor path for
`VerifiedFundingArtifactsV1`. It uses the repository-pinned real DOM canonical
decoder, exact re-encoding check, and complete consensus transaction verifier.
Every refund kernel must use the real height-locked feature at the declared
unlock height. The refund is verified at that height so a correctly pre-signed
future refund is validated without claiming it is spendable at the current
funding height. Funding is verified with an explicit caller-selected chain ID,
height, and timestamp; the Store supplies no network defaults.

The immutable artifact object stores the exact canonical refund and funding
bytes, their lengths, session ID, terms hash, target authorization revision,
refund unlock height, and domain-separated digests. `FundingBroadcastV1`
returns the funding byte slice copied from that authenticated object without
decode/re-encode mutation.

The candidate artifact/root domains use the pinned DOM
`blake2b_256_tagged` implementation with these tags:

```text
DOM:contracts-session-store-root:v1
DOM:contracts-session-store-lock:v1
DOM:contracts-session-refund-bytes:v1
DOM:contracts-session-funding-bytes:v1
DOM:contracts-session-funding-artifacts:v1
DOM:contracts-session-funding-consumption:v1
DOM:contracts-session-transport-roster:v1
DOM:contracts-session-transport-message-record:v1
```

They are deliberately not inserted into the closed ratified
`StorageHashDomainV1` registry. A future normative record must ratify or replace
these candidate formats before a release labels them production authority.

### One-shot funding authority

Issuance proceeds under the in-process operation mutex and retained process
lock:

1. authenticate the current `ClaimPrepared` revision;
2. verify that the supplied `FundingAuthorized` record is the exact
   `SessionRecordV1::advance` successor and sets, rather than clears,
   `funding_authorized`;
3. publish and sync the exact verified artifact object;
4. publish and sync the immutable session successor with CAS; and
5. issue an opaque process-bound `FundingAuthorizationV1`.

The capability has no public fields, constructor, codec, equality, ordering,
`Clone`, `Copy`, or `Debug`. A crash after step 3 permits only an exact retry. A
crash after step 4 cannot reissue authority because durable phase/revision state
has advanced. Restart changes the random open-instance binding and rejects an
old capability.

Consumption proceeds:

1. reauthenticate the capability, session revision, and artifact digest;
2. validate the exact `FundingBroadcast` successor through
   `SessionRecordV1::advance`;
3. publish and sync one immutable consumption record binding the artifact and
   the complete exact `FundingBroadcast` successor bytes;
4. publish and sync the session successor; and
5. return the linear exact-byte broadcast object.

A crash after step 3 but before step 4 is deliberately recoverable without
reconstructing authority or guessing whether bytes reached a network. Restart
authenticates the durable consumption record, its artifact, and the embedded
successor, then publishes that exact successor. The original authorization is
permanently retired. `resend_funding_broadcast` subsequently returns only the
byte-identical persisted funding transaction and only when the consumed record
and historical `FundingBroadcast` revision agree. It is retransmission of a
public transaction, not a second first-broadcast capability.

`load_refund_broadcast` releases only the exact persisted pre-signed refund. It
requires a durable refund-path phase, an explicit current real-DOM validation
context at or above the stored unlock height, exact canonical re-encoding,
full consensus transaction validation, and height-locked kernels bound to the
stored height. A completed `Refunded` session may reload the same bytes after a
lost acknowledgement; it cannot create different refund bytes.

### Store-owned M.8 funding-gate reference

The additive M.8 funding profile deliberately excludes a ClaimAdaptor
pre-signature before funding. Its immutable gate authenticates the refund,
shared-output/Bulletproof statement, claim template and adaptor point, exact
terms, ratified M.8 policy digest, and bilateral durable-share backup receipt.
Issuance additionally binds the then-current authenticated session transcript.
The backup receipt hash is Store-internal evidence; exposing it as a
caller-shaped argument would let a composition root accidentally pair an
otherwise valid DOM authorization request with evidence from another gate.

`prepare_operational_m8_funding_gate_authority` therefore consumes verified
gate evidence and returns a linear, non-cloneable
`PreparedOperationalM8FundingGateV1`. The handle has no public constructor,
fields, getters, codec, debug output, equality, or ordering. It binds only the
session and exact authenticated gate digest internally. The purpose-specific
issue path accepts that handle plus the authoritative unsigned DOM template
and `BpStatementV1`; it reloads the gate and supplies the private backup
receipt hash directly to the pinned DOM M.8 authorization implementation.

After restart,
`resume_operational_m8_funding_gate_authority(session_id)` may rehydrate only
the same exact gate reference in `RefundSigned` or `FundingAuthorized`.
Issuance and issuance-resume remain distinct: an already durable issuance can
only be imported through the existing resume path, with the same binding,
template bytes, statement, digest, and revision. A legacy funding gate, a
different profile, a substituted template/statement, or a changed session
projection cannot satisfy this boundary. The earlier digest-returning API is
retained for source compatibility and evidence, but F7 production composition
selects only the opaque prepared-gate path.

### Durable authenticated transport journal

The Store persists one immutable two-participant roster before accepting a
message. The roster binds the nonzero chain ID, participant IDs, pinned DOM
Schnorr identity keys, and the closed initiator/responder directions. It stores
public authentication material only.

Every accepted DSC1 message is parsed with the closed V1 type registry,
per-message payload ceiling, one-MiB global ceiling, canonical framing, and
pinned DOM identity-signature verifier. The journal is bounded at 256 accepted
messages per session. Its immutable key is
`(session_id, sender_id, sequence)` and its authenticated record contains the
exact signed bytes plus the complete exact `SessionRecordV1::advance`
successor. The Store verifies sender-local contiguous sequence, transcript
ancestry, the closed phase/message mapping, and the exact transcript update.
It syncs the message before syncing the successor; only then may the caller
emit an ACK.

Restart authenticates every roster, identity signature, filename binding,
direction, chain ID, record digest, sequence history, and successor. A message
record durable before its session revision is replayed internally to publish
only its embedded exact successor. An exact duplicate returns the original
durable receipt. Different validly signed bytes at the same immutable key
persist a separate equivocation record and a projection-preserving
`FailedClosed` successor before returning; no ACK is authorized. Signed
messages and transaction bytes are public protocol artifacts. Neither journal
contains signing nonces, Bulletproof nonce material, seeds, shares, or keys.

## Alternatives considered

### Add namespaces to the nonce-vault generation

Rejected. It requires a material refactor of the signed inventory,
backup/restore manifests, restore recovery, evidence fixtures, and authority
hashes. It couples session projection persistence to nonce-secret generations
and increases the risk of accidentally creating a second nonce lifecycle.

### SQLite WAL with `synchronous=FULL`

Not selected. SQLite could provide transactional CAS, but the existing retained
filesystem already supplies all required primitives. A database would add a
new dependency and a second path-containment/ownership/durability boundary
without resolving the signed nonce-vault-layout issue.

### Replace one mutable `current.session` file

Rejected. An immutable, contiguous revision history provides direct crash
prefix evidence, makes stale CAS conflict visible with `NOREPLACE`, and allows
restart to re-run `SessionRecordV1::advance` over every committed edge.

### Caller Boolean or serializable authorization

Rejected by the NAR-DC-P1-007 findings. Neither demonstrates verifier custody,
durability, uniqueness across restart, nor retirement before broadcast.

## Invariants

1. `ContractsNonceVaultV1` remains the sole nonce authority; the session store
   contains no nonce, nonce share, nonce derivation, or nonce export API.
2. Every final session revision is authenticated canonical
   `SessionRecordV1` bytes and every adjacent revision is exactly reproducible
   by `SessionRecordV1::advance`.
3. Revision publication is create-no-clobber and durable before success.
4. A reorg/scanner update changes only the reversible chain projection.
5. Funding authorization is unreachable through initial import or general CAS.
6. Refund and funding bytes are verified with real pinned DOM code and stored
   before authorization.
7. At most one authorization can be issued for a session across threads,
   processes, crashes, and restarts.
8. Authorization retirement is durable before funding bytes are returned.
9. Outbound funding bytes are byte-identical to the authenticated persisted
   artifact.
10. Funding and mature-refund retransmission reload only authenticated exact
    public transaction bytes; retransmission never reissues authority.
11. A transport ACK is reachable only after exact signed bytes and their exact
    session successor are durable; restart preserves duplicate, sequence,
    transcript, replay, and equivocation history.
12. Any ambiguous, noncontiguous, replaced, malformed, or digest-invalid
    authority state fails closed.
13. Production constructors accept only an explicitly supplied
    `ProductionRatified` policy; evidence policy cannot cross that boundary.
14. F7 M.8 funding authorization consumes an opaque Store-owned prepared-gate
    reference; the bilateral backup receipt hash never becomes a
    caller-selected production argument.

## Compatibility and security impact

No DOM consensus, genesis, network, wire, encoding, mempool, transaction, or
cryptographic primitive is changed. Existing canonical session bytes and
nonce-vault APIs remain source compatible. The normal store build now links the
already pinned DOM consensus/core/crypto/serialization crates because the
refund verifier is a real runtime boundary rather than a test fixture.

The additive root is intentionally not included in the existing nonce-vault
backup/restore format. Operators must back up the session root through a future
separately reviewed session-store procedure; treating nonce-vault backup as a
session backup would be unsafe. Loss after funding authorization remains
economically recoverable only through the already persisted refund, and the
Store prefers loss of liveness over reissuing funding authority.

## Tests proving the decision

The `session_store` unit suite covers:

- exact create/load, stale CAS rejection, projection-only reorg, and restart;
- explicit production/evidence policy separation and exact policy binding;
- real pinned DOM canonical transaction and consensus verification;
- malformed DOM artifact rejection;
- byte-identical funding return;
- byte-identical funding retransmission before and after restart;
- real-DOM timelock verification and byte-identical mature refund loading;
- durable authorization issuance and consumption;
- opaque M.8 gate preparation/resume, legacy-profile separation, exact
  template/statement substitution rejection, and no raw backup-receipt
  accessor;
- authenticated transport restart, exact duplicate, reorder, sequence-gap,
  transcript, and equivocation handling;
- eight-thread one-winner issuance;
- second-process exclusive-lock rejection;
- old-open-instance capability rejection after restart;
- authenticated artifact-tamper quarantine;
- child-process death after artifact persistence, authorization-session
  persistence, consumption retirement, broadcast-session persistence,
  transport-message persistence, and transport-session persistence; and
- compile-time assertions that verifier, authorization, and broadcast
  capabilities are not cloneable, copyable, comparable, or debuggable.

Reproducible commands:

```bash
CARGO_BUILD_JOBS=2 cargo test -p dom-scriptless-store --lib session_store
CARGO_BUILD_JOBS=2 cargo test -p dom-scriptless-store --features evidence-only
CARGO_BUILD_JOBS=2 cargo clippy -p dom-scriptless-store --lib -- -D warnings -A dead-code
cargo fmt --all -- --check
```

## Status consequence

This closes the F7 laboratory implementation gap for operational session
persistence and one-shot funding authority. It does not, by itself, change any
ratified gate or the production/mainnet status recorded by NAR-DC-P1-007. That
status requires independent review, ratification of the candidate store
formats/domains and policy bytes, integration by the trusted composition root,
and external failure-injection/filesystem evidence on the release target.

# NAR-DC-P1-006 — Final Runtime Authority, Platform, and Evidence Publication Closure

Status: **PROPOSED / UNSIGNED / NOT NORMATIVE**

Date: 2026-08-05

Project: DOM Contracts / DOM Scriptless Contracts Phase 1

Scope: the final in-process authority assignments required for an accepted
signing session, one coherent live-vault snapshot, and exact resend recovery;
the Linux-only Phase 1 runtime profile; and the narrowly controlled remote
operations required to publish the reviewed DOM API, pin it immutably in DOM
Contracts, and execute the read-only GitHub-hosted Windows/macOS evidence
matrix.

This record does not approve G1A, G1B, consolidated G1, Phase 2, production,
mainnet, real funds, a release, a package publication, or an external security
audit.

## 1. Authority and ratification effect

This record supplements the following signed records:

| Record | SHA-256 |
|---|---|
| `NAR-002-phase-1-omnibus-normative-closure.en.md` | `b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5` |
| `ADR-P1-001-integrated-g1a-g1b-authorization-boundary.en.md` | `e35c39e74f9af61e19ecda8e1ca503f37a7fc04c6e2a0f40f5d96bf6a20d1596` |
| `NAR-DC-P1-001-omnibus-gap-closure.en.md` | `88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655` |
| `NAR-DC-P1-002-storage-persistence-closure.en.md` | `719a121c11f4b7f8ea016668bfaa05a3e4d03d3a510df31e3495fb9698560e84` |
| `NAR-DC-P1-003-vault-request-and-recovery-binding.en.md` | `082c855782c71a0f61e85828eaac75440a434d5c05d8357e569592a816db05ef` |
| `NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md` | `2f9eadb08080844ade7dacfa117a71948ee8a365841fff860d69fe734c42b510` |
| `NAR-DC-P1-005-reservation-runtime-and-linux-capability-closure.en.md` | `4f5582a17426ed5b03d6aa37d6c2fc9cfe564985ec3614d0d4a30fed8ae2d635` |

The detached signature must verify with the established project operator
Minisign public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
key ID 74197A95CA309CF0
```

Unsigned bytes grant no authority. After valid detached signature and exact
byte-for-byte import, this record supersedes only:

1. NAR-DC-P1-005 §3.1's separate reservation-handle projection accessors,
   replacing them with the atomic snapshot interface in §3;
2. NAR-DC-P1-005 §4.4's incomplete production construction edge, replacing it
   with the accepted-session authority in §2;
3. NAR-DC-P1-005 §4.5 only to add the Store-owned recovery lookup and binding
   route in §4; the exact resend and byte-identity rules remain unchanged;
4. the requirement in ADR-P1-001 §15.4 and NAR-DC-P1-005 §5.4 that a Windows
   or macOS durability backend must execute before Phase 1 approval, but only
   because §5 makes Linux the sole Phase 1 runtime platform and keeps adaptor
   runtime unavailable on Windows/macOS; and
5. prior remote-operation prohibitions only to the exact, conditional,
   auditable operations in §§6–7.

No canonical persisted record, cryptographic primitive, hash domain, KDF,
Purpose registry, Direction registry, SigningPhase registry, consensus rule,
existing DOM wire byte, transaction encoding, kernel verifier, genesis value,
network magic, PoW rule, budget number, timeout, retry limit, or retention
period is changed by this record.

## 2. Accepted signing-session authority

### 2.1 Problem closed

A nonzero caller-provided `session_id`, self-consistent roster, transaction,
kernel index, purpose, or adaptor point is not proof that a session was
accepted. Production must not construct a signing round from such a request.
Explicit session IDs and synthetic terms remain permitted only in signed test
fixtures and `cfg(test)`/`cfg(fuzzing)` evidence code.

### 2.2 Static source boundary

`VaultBackedSignerV1` is extended with one statically selected DOM Contracts
session-authority implementation. The semantic interface is:

```rust
pub trait SigningSessionAuthorityV1: Sized {
    type Error: core::error::Error + Send + Sync + 'static;
    type AcceptedSession: AcceptedSigningSessionV1;
}

pub trait AcceptedSigningSessionV1 {
    fn trusted_chain_id(&self) -> &TrustedChainIdV1;
    fn session_id(&self) -> &[u8; 32];
    fn contract_kind(&self) -> ContractKindV1;
    fn purpose(&self) -> PurposeV1;
    fn roster(&self) -> &ParticipantRosterV1;
    fn transaction_template(&self) -> &dom_consensus::Transaction;
    fn kernel_index(&self) -> usize;
    fn adaptor_point(&self) -> Option<&dom_crypto::PublicKey>;
    fn initial_transcript_hash(&self) -> &[u8; 32];
    fn accepted_signing_messages(&self) -> impl Iterator<Item = &[u8]>;
}
```

Equivalent Rust associated-iterator syntax is permitted when required by the
workspace MSRV. The semantic fields and ownership rules are exact.

The production signing entry consumes exactly
`Sessions::AcceptedSession` by value. It does not accept a generic implementer,
raw session request, session ID, roster, terms, transcript hash, sequence,
digest, persistence Boolean, or caller capability. The concrete DOM Contracts
`AcceptedSession` constructor is private to the statically selected trusted
session store. It implements neither `Clone`, `Copy`, `Debug`, `Display`,
Serde, a byte codec, equality, ordering, nor a public downcast.

No runtime plugin, configuration-selected implementation, dynamic library, or
`Box<dyn SigningSessionAuthorityV1>` is permitted in the production
composition root. Test fakes remain test-only and cannot resolve in the
release feature graph.

### 2.3 Conditions for issuing the handle

The DOM Contracts session store may issue one accepted-session handle only
after all of the following are durably proven and reread:

- the trusted local chain ID is exact;
- the initiator session ID was constructed exactly as NAR-002 §6 from fresh
  nonzero OS-CSPRNG `initiator_nonce_32`, or the responder received that exact
  session ID through the already authenticated session-acceptance boundary;
- the session ID is nonzero and absent from the complete lifetime session set,
  including active state, terminal tombstones, backups, restore evidence, and
  predecessor generations;
- the session ID is irreversibly claimed before the handle is returned and is
  never reusable after abort, crash, completion, restore, or compaction;
- `ContractKindV1`, `PurposeV1`, the two-party Phase 1 roster, transport
  identity keys, signing keys, role-stable directions, participant mapping,
  accepted terms, transaction template, kernel index, and adaptor-point policy
  are canonical and immutable;
- the local signing key occurs exactly once and belongs to the retained local
  signing share;
- the transaction kernel excess equals the authoritative aggregate signing
  key, and the exact kernel message is obtained through the unchanged DOM
  boundary;
- the initial transcript is recomputed exactly from NAR-002 §8.1 and equals
  the accepted session-store value; and
- every replayed signing message is a complete immutable DSC1 envelope from
  the durable accepted-message log.

For a fresh signing round, `accepted_signing_messages()` is empty. For a
restart, it contains only the unique canonical accepted prefix, in canonical
transcript application order, with at most the closed two participants times
the three Phase 1 signing message kinds. `dom-adaptor` reparses, verifies, and
replays every envelope; the session store cannot inject a digest, binding
factor, aggregate, partial, or state transition directly.

Duplicate, missing, conflicting, reordered, noncanonical, unauthenticated, or
divergent session evidence fails closed before a signing-round authority
exists. A process-lost handle is not reconstructed from raw fields. The
session store may issue a fresh one-shot restart handle only after replay and
lifetime-authority validation under its retained lock.

### 2.4 Phase 1 availability rule

Until the concrete DOM Contracts accepted-session implementation conforms to
this section, the default production API has no public signing-round
constructor. Failing closed by omitting that entry point is conforming and is
not a reason to expose a caller-shaped compatibility route.

Phase 1 may be adjudicated with this production entry point intentionally
unavailable, because contract/session establishment is integrated in a later
authorized phase. Test and fuzz construction may exercise the complete
cryptographic and vault boundary, but it does not authorize a production
session, Phase 2, mainnet, or funds.

## 3. Atomic retained reservation snapshot

### 3.1 Exact semantic interface

The separate NAR-DC-P1-005 reservation-handle getters are removed from the
production trait. The handle becomes fully opaque. `NonceVaultV1` adds:

```rust
pub trait VaultReservationSnapshotV1 {
    type SpentArtifact: VaultSpentArtifactSnapshotV1;

    fn request_lookup(&self) -> &ReservationRequestLookupV1;
    fn reservation_nonce_id(&self) -> &ReservationNonceId;
    fn reservation_context_binding_digest(&self) -> &[u8; 32];
    fn live_stage(&self) -> ReservationLiveStageV1;
    fn final_retry_counter(&self) -> Option<u64>;
    fn spent_commitment(&self) -> Option<&Self::SpentArtifact>;
    fn spent_reveal(&self) -> Option<&Self::SpentArtifact>;
}

pub trait VaultSpentArtifactSnapshotV1 {
    fn nonce_identity(&self) -> &NonceIdentityV1;
    fn permit_id(&self) -> &PermitIdV1;
    fn kind(&self) -> ExposureKindV1;
    fn adaptor_outbound_digest(&self) -> &[u8; 32];
}

pub trait NonceVaultV1: Sized {
    type ReservationHandle;
    type ReservationSnapshot: VaultReservationSnapshotV1;

    fn snapshot_reservation(
        &mut self,
        reservation: &Self::ReservationHandle,
    ) -> Result<Self::ReservationSnapshot, Self::Error>;
}
```

All other signed associated types and methods remain unless this record names
them explicitly.

### 3.2 Atomicity and authority

The Store creates one owned snapshot while holding the same retained exclusive
lock and open-instance authority as the handle. Before reading any projected
field it revalidates, as one operation:

- the retained root identity and current root pathname binding;
- active generation and active-pointer bytes;
- current lock descriptor and current lock pathname identity;
- vault, epoch, generation, process open-instance, and reservation authority;
- complete contiguous authenticated journal head and every projected record
  used by the snapshot; and
- absence of conflicting, duplicate, predecessor-only, unknown, staging, or
  ambiguous inventory.

The returned value owns copies only of the exact non-secret semantic fields
above. It exposes no descriptor, root, key, receipt, journal bytes, storage
success Boolean, secret record, nonce scalar, share, capability, or mutable
reference. It implements neither `Clone`, `Copy`, `Debug`, `Display`, Serde,
an external byte codec, equality, ordering, nor public construction.

The snapshot is coherent but non-authoritative. Every later consuming Store
method independently revalidates the live handle, named objects, current head,
and exact expected snapshot fields. A stale snapshot creates no permission and
fails closed. The signer consumes the snapshot for one dispatch decision and
never performs a sequence of independent handle getter reads.

The NAR-DC-P1-005 stage/presence table remains exact. Each spent snapshot also
binds the complete current-generation `NonceIdentityV1`, including the
Store-owned nonce epoch. Wrong stage, retry, kind, zero digest, missing or
duplicate descriptor, or identity/context mismatch burns or quarantines under
the existing signed prefix rules.

## 4. Exact resend recovery after restart

### 4.1 Trusted protocol authorization

`ValidatedResendAuthorizationV1` remains opaque and one-shot. After this
record, the trusted session state that creates it binds:

- exact `ReservationRequestLookupV1`;
- exact reservation-context binding digest;
- exact session ID and strict Phase 1 purpose;
- exact closed protocol stage and exposure kind; and
- exact nonzero adaptor-domain outbound digest of the already accepted local
  artifact.

It does not contain a caller receipt, storage Boolean, raw permit, nonce epoch,
secret, outbound replacement bytes, or filesystem authority.

### 4.2 Store-owned recovery lookup

`NonceVaultV1` adds one non-exporting lookup:

```rust
pub trait NonceVaultV1: Sized {
    type RecoveredSpentArtifact: VaultSpentArtifactSnapshotV1;

    fn recover_spent_artifact(
        &mut self,
        authorization: &ValidatedResendAuthorizationV1,
    ) -> Result<Self::RecoveredSpentArtifact, Self::Error>;
}
```

Under the retained lock, the Store streams the current generation and requires
exactly one match for the authorization's lookup, binding, session, purpose,
kind, and adaptor outbound digest. It revalidates vault, epoch, generation,
reservation, complete `NonceIdentityV1`, participant, permit, Contracts
outbound digest, exact persisted bytes, authorizing journal entry, retirement,
and contiguous current ancestry.

Zero matches returns the closed not-found/retired result. Multiple,
predecessor-only, carried-only, changed, partial, or divergent matches
quarantine. The method never runs a KDF, opens a secret, recomputes an artifact,
returns outbound bytes, or creates export authority.

`dom-adaptor` consumes both the original
`ValidatedResendAuthorizationV1` and the returned Store-owned snapshot to
construct the private `ResendRequestV1`. Every overlapping field must match.
The existing `resend_exported(request)` method then revalidates the Store a
second time, creates and spends one live capability, and returns only the exact
byte-identical persisted artifact.

This two-step lookup is deliberately non-authoritative between calls. A crash,
state change, restore, generation change, or head advance cannot turn the
snapshot into permission. Exact current-state revalidation at
`resend_exported` is mandatory.

The same snapshot descriptor supplies complete identity for live commitment
and reveal continuation. Terminal partial resend uses
`recover_spent_artifact`; terminal status alone never reconstructs identity.

## 5. Phase 1 platform scope

### 5.1 Linux-only runtime

The Phase 1 production runtime profile is Linux only and uses the exact signed
NAR-DC-P1-005 retained-capability boundary. All Linux durability,
process-death, locking, filesystem, crash-prefix, restore, fuzz, sanitizer,
and fault-injection evidence required by the applicable gates must execute on
the final reviewed Linux commit.

No Windows or macOS Nonce Vault filesystem backend exists in Phase 1. On those
targets, the adaptor runtime, vault runtime, secret store, export permit path,
and contract-funding path are absent or return a closed unsupported-platform
error before initialization, mutation, randomness, budget charge, or network
activity. There is no local-file fallback and no emulation of Linux
durability.

Adding a Windows or macOS runtime later requires a separate signed backend
profile and the complete applicable durability matrix on a real runner. Rust
type-checking never proves filesystem durability.

### 5.2 Portable GitHub evidence

For Phase 1 only, the Windows/macOS platform evidence requirement is satisfied
when GitHub Actions executes the final pinned DOM Contracts commit on all of:

```text
windows-latest       / windows-x86_64
macos-latest         / macOS arm64
macos-15-intel       / macOS x86_64
```

Each real hosted job must record runner OS/architecture, `rustc -vV`, and
`cargo -vV`, and pass on the exact same commit:

```text
cargo metadata --locked --format-version 1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo check --workspace --all-targets --all-features --locked
cargo test --workspace --all-features --locked --no-run
cargo test --workspace --all-features --locked
```

The workflow must use immutable action revisions, read-only repository
permissions, no secrets, no persisted checkout credential, no artifact upload,
no cache write, no package, no release, no deployment, and no remote mutation.

A prepared workflow, local cross-compilation, skipped job, canceled job, or
successful Linux run is not Windows/macOS execution. A green job proves only
portable code and the intentional absence/fail-closed behavior of the runtime
on that target; it does not claim a Windows/macOS durability backend.

When all Linux G1A/G1B implementation and evidence gates are already green,
all independent-review CRITICAL/HIGH findings are closed, the public DOM pin is
verified, and the three hosted jobs above pass on the final commit, the
remaining Phase 1 platform gap is closed. The coordinator may then adjudicate
Phase 1. GitHub compilation alone does not waive any non-platform gate.

Regardless of adjudication:

```text
PHASE2 = NOT AUTHORIZED
MAINNET = DISABLED
REAL_FUNDS = NOT AUTHORIZED
PRODUCTION = NOT AUTHORIZED
```

## 6. Controlled DOM publication and immutable pin

### 6.1 Pre-push gate

After this exact record and detached signature are imported and independently
verified, the coordinator may publish only the reviewed fast-forward successor
of:

```text
repository: https://github.com/sorenplanck/dom-protocol
remote branch: refs/heads/feat/scriptless-phase1-dom-adaptor-v1
current public commit: 67fe11c441c2b7801b6f70809ab58caa4804c22a
reviewed local checkpoint before this record: 8ee20622142c55bcf3d8a9174d47321f7fb4310a
```

The final candidate may add only this signed record, its public detached
signature and ratification evidence, the three interfaces assigned here,
their fail-closed implementation/tests/fuzz/evidence, and directly necessary
`dom-adaptor`/`dom-crypto` support. It must remain a descendant of the current
public commit. The exact diff, commit list, tree, status, test results, and
selected-history secret scan must be recorded before push.

Push is forbidden if the remote branch has moved to an unknown or non-ancestor
commit, the update is not fast-forward, a force option would be needed, a
fixture changes, any CRITICAL/HIGH remains, or any selected commit changes
consensus, existing wire, persisted blocks, genesis, network parameters, PoW,
DOM Wallet, DL2P, or unrelated code.

Only this command shape is authorized, with the actual audited local ref:

```text
git push https://github.com/sorenplanck/dom-protocol \
  <audited-local-ref>:refs/heads/feat/scriptless-phase1-dom-adaptor-v1
```

No force, tag, other branch, deletion, PR, merge, release, package, binary,
Actions setting, secret, or branch-protection change is authorized.

After success, `git ls-remote` must return the exact published full commit.
DOM Contracts then pins both `dom-adaptor` and any directly consumed matching
DOM package, including `dom-crypto` when present, to that one full immutable
Git revision and the official public URL. `Cargo.lock` must resolve the same
revision. No path dependency, absolute path, `[patch]`, sibling override,
unpublished revision, or cached unpublished object may be required.

A clean temporary checkout with empty task-specific Cargo Git/target caches
must pass locked metadata, formatting, check, Clippy, debug tests, and release
tests. Publication/pin is not complete until that reproducibility test passes.

## 7. Controlled DOM Contracts evidence branch and Actions run

### 7.1 First push authorization

At the time this record was prepared, `git ls-remote
https://github.com/sorenplanck/dom-contracts` returned no refs. After the public
DOM pin, complete local validation, selected-history secret scan, and
independent review pass, the coordinator may create only:

```text
repository: https://github.com/sorenplanck/dom-contracts
remote branch: refs/heads/phase1-evidence
```

The push contains the repository's own audited history only. It must contain
no DOM or Wallet `.git` history, absolute operator path, local override,
secret, real seed, private key, RPC token, database, dump, fuzz crash containing
secret data, build output, binary, release artifact, or unrelated code.

Only a new-branch or later fast-forward update is permitted. Follow-up
fast-forward updates are authorized solely to correct concrete failures from
the same read-only platform matrix, after the same local diff/test/secret
preflight. A failure requiring a normative decision, scope expansion, runtime
backend, force push, history rewrite, release, or Phase 2 stops this authority.

No PR, merge, tag, release, package publication, default-branch rewrite,
branch deletion, Actions-secret change, protection change, deployment, or
artifact upload is authorized.

### 7.2 Evidence capture and end of authority

The coordinator records for every required job:

- repository, branch, workflow path, workflow-file SHA-256, run ID, URL,
  triggering commit, runner label, OS, architecture, and toolchain;
- exact command, exit code, duration, pass/fail/skip/cancel state;
- sanitized logs or cryptographic hashes sufficient to reproduce the result;
  and
- proof that no secret or release artifact was produced.

The coordinator independently verifies the remote commit and all job results.
An agent or GitHub summary alone is insufficient.

This remote authorization ends immediately when the public DOM revision is
pinned reproducibly and the first complete required platform matrix is
recorded, whether green or blocked. Further remote work requires new explicit
authorization.

## 8. Mandatory tests after ratification

At minimum, executed evidence must prove:

- a production caller cannot import or construct the test/fuzz session
  request, bootstrap, accepted-session handle, snapshot, recovered spent
  descriptor, resend request, or any one-shot permit;
- explicit session IDs remain test/fuzz-only;
- the initiator session-ID formula and lifetime collision scan are exact;
- responder authority requires authenticated accepted-session evidence;
- a session handle cannot start two signing rounds;
- fresh accepted-message log is empty; restart replay is bounded, canonical,
  authenticated, and deterministic;
- mutation of chain, session, kind, purpose, roster, role, key, terms,
  template, kernel, adaptor point, initial transcript, replayed message, or
  sequence fails before signing authority;
- `snapshot_reservation` performs one coherent Store operation and callers
  cannot observe mixed-stage fields;
- root, lock pathname, active generation, open instance, journal head, retry,
  kind, identity, and descriptor mutations fail closed;
- process death at every snapshot/recovery boundary creates no authority;
- restart after spent commitment, reveal, or partial can recover only the
  exact complete non-secret identity through the Store lookup;
- zero, multiple, predecessor-only, carried-only, stale, or divergent resend
  matches quarantine or return the closed terminal result;
- lookup followed by state change cannot authorize resend;
- exact resend returns byte-identical persisted bytes and never reruns KDF,
  secret open, reveal, or partial computation;
- direct-final create remains permitted under NAR-DC-P1-005 §5.3, while every
  partial-write/incomplete-sync prefix quarantines before authorization;
- the bounded streaming multi-reservation runtime, complete inventory-before-
  mutation, lifetime collision, budgets without defaults, sealed secret
  runtime, tombstones, restore, and crash matrix pass on Linux;
- default and release dependency graphs contain no test/fuzz authority, direct
  `dom-adaptor -> k256`, DOM Wallet dependency, DL2P dependency, absolute path,
  or unpublished revision; and
- official DOM and DOM Wallet repositories retain their exact initial HEAD,
  tree, tracked status, and preserved untracked hashes.

Self-generated vectors remain non-independent. Existing independent vectors,
all eight SCAD0 fixtures, the 311-field comparison, the fresh 10,000-cycle
property run, real DOM verifier checks, constant-time/zeroization review, fuzz,
sanitizer, secret scan, and full applicable gates remain mandatory and must be
bound to the final commits.

## 9. Stop conditions

Stop without improvisation if:

- this document or signature does not verify byte for byte;
- a caller-shaped production session route reappears;
- a snapshot is assembled from separate handle reads;
- identity is reconstructed from storage without the Store-owned recovery
  lookup and current-head revalidation;
- resend recomputes or changes bytes;
- a process crash can revive authority, nonce, session ID, permit, or budget;
- an implementation needs an unassigned byte, tag, enum, path, numerical
  default, timeout, retry count, or retention value;
- a Windows/macOS runtime or local fallback is added;
- any required GitHub job is skipped, canceled, or not bound to the final
  commit;
- publication is non-fast-forward, the remote moved unexpectedly, a secret is
  found, or force push would be needed;
- DOM Contracts publication would include an absolute/local dependency;
- official DOM or Wallet state changes; or
- any change reaches consensus, existing wire, persisted blocks, genesis,
  network parameters, PoW, DL2P, Phase 2, mainnet, or real funds.

Preserve all valid local commits and evidence. Do not reset, clean, rebase,
amend, delete, or weaken a gate to produce a completion label.

## 10. Ratification and status

Ratification means only that the exact signed bytes become the controlling
assignment for the three missing runtime interfaces, the Linux-only Phase 1
platform profile, and the narrow remote evidence operations above.

Ratification does not attest that implementation or tests exist. Gate status
may change only after commit-bound execution and independent review.

```text
DOCUMENT_ID = NAR-DC-P1-006
ACCEPTED_SESSION_AUTHORITY = ASSIGNED_AFTER_VALID_SIGNATURE
ATOMIC_RESERVATION_SNAPSHOT = ASSIGNED_AFTER_VALID_SIGNATURE
RESTART_RESEND_IDENTITY = ASSIGNED_AFTER_VALID_SIGNATURE
PHASE1_RUNTIME_PLATFORM = LINUX_ONLY
WINDOWS_MACOS_RUNTIME = UNAVAILABLE_FAIL_CLOSED
WINDOWS_MACOS_PORTABLE_EVIDENCE = REAL_GITHUB_RUN_REQUIRED
DOM_PROTOCOL_FAST_FORWARD_PUBLICATION = CONDITIONALLY_AUTHORIZED
DOM_CONTRACTS_PHASE1_EVIDENCE_BRANCH = CONDITIONALLY_AUTHORIZED
FORCE_PUSH = PROHIBITED
RELEASE = PROHIBITED
MERGE = PROHIBITED
PHASE2 = NOT_AUTHORIZED
MAINNET = DISABLED
REAL_FUNDS = NOT_AUTHORIZED
PRODUCTION = NOT_AUTHORIZED
G1A = NOT_CHANGED_BY_SIGNATURE_ALONE
G1B = NOT_CHANGED_BY_SIGNATURE_ALONE
G1_CONSOLIDATED = NOT_ADJUDICATED
```

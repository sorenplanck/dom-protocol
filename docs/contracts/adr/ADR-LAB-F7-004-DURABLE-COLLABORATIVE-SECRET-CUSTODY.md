# ADR-LAB-F7-004: Durable Collaborative-Secret Custody

- Status: F7 laboratory candidate; not a normative record
- Date: 2026-08-13
- Scope: Linux `dom-scriptless-store`, `dom-scriptless-crypto`, and the pinned
  DOM adaptor custody seam
- Governing references: Master Specification §§4.2, 5.4, 5.5, and 7.3;
  NAR-DC-P1-001 §§6.4-6.9, 7, and 8.3; NAR-DC-P1-002; NAR-DC-P1-004

## Problem

The collaborative-output implementation retained three local secrets only in
process memory:

1. the long-lived shared-output blinding/signing share `r_i`;
2. the common-nonce contribution `q_i`; and
3. the independent Bulletproof private nonce `private_nonce_i`.

A process crash therefore made the shared output unspendable, or forced a
caller to generate different Bulletproof material for the same public session.
The latter is forbidden after a public commitment. A process-local
`ShareBackupAckV1` also could not prove that `r_i` had reached authenticated
durable storage before funding.

## Context

NAR-DC-P1-001 §6.4 requires `q_i` and `private_nonce_i` to be independent,
fresh OS-CSPRNG values. Neither value may be derived from a seed, the common
nonce, the statement, or any public transcript. `q_i` must be encrypted and
durable before its commitment can leave the process. Section 6.8 requires all
local Bulletproof secrets to remain non-cloneable, non-debuggable,
non-serializable, and zeroizing.

The ratified `VaultObjectEnvelopeV1` registry is closed to three record kinds.
Treating collaborative material as `NonceSecretRecordV1`, or adding an
unratified fourth kind to that V1 registry, would contradict the storage
specification. The existing `ContractsNonceVaultV1` nevertheless already owns
the correct retained root, exclusive process lock, independently derived
master key, authenticated generation, and Linux durability boundary. A second
nonce vault or a second master-key owner is unnecessary.

The final `BpStatementV1` contains every public `R_i`, so it does not exist
until after local `r_i` has been generated. This creates a real ordering
constraint: the secret must be durable before `R_i` is published, while the
final statement binding can only be added afterwards. Mutating the original
secret envelope would weaken crash evidence.

## Decision

### One existing vault, one additive session-secret namespace

Extend the laboratory generation inventory of `ContractsNonceVaultV1` with
one retained `collaborative-secrets/` namespace. It is not a second
`NonceVaultV1`, does not implement signing-nonce reservation, and does not
share any signing-nonce record kind. The existing vault master key and retained
exclusive lock remain the only local encryption and writer authorities.

The namespace holds only immutable, create-no-clobber objects:

```text
<custody-id>.collaborative-secret
<custody-id>-<revision>.collaborative-stage
<custody-id>.statement-anchor
```

Hidden staging names are permitted only during publication. Every file is
mode `0600`, every directory is mode `0700`, and each publication performs
file `fsync`, no-replace rename, parent-directory `fsync`, retained reopen,
and exact-byte comparison. Unknown objects quarantine the vault.

Live collaborative-secret envelopes are intentionally absent from ordinary
nonce-reservation backup/restore manifests. An active session may not be
silently restored onto another device with duplicated one-shot Bulletproof
material. A future cross-device recovery profile must define an explicit
single-live-copy transfer and retirement protocol before it can carry these
records.

Because every envelope authenticates its creation nonce epoch, the laboratory
also prohibits backup/restore publication (and therefore generation/epoch
advance) while any collaborative state remains in the active generation.
Silently opening an old envelope under the successor epoch would make a valid
`r_i` unavailable; copying it to the successor generation would duplicate
one-shot state and violate the closed restore registry. The supported recovery
path is to reopen the current generation with its original passphrase and
epoch, complete or safely abort each owning session, durably publish its
terminal evidence, and retire its collaborative records. Only an empty
`collaborative-secrets/` inventory is eligible for epoch-advancing backup or
restore publication. A later normative migration protocol may replace this
prohibition only if it proves atomic single-live-copy transfer and predecessor
retirement.

### Separate encrypted candidate envelope

Use a separately versioned candidate envelope rather than changing the closed
ratified object registry. The complete header authenticates:

- Contracts wallet ID, vault ID, and nonce epoch;
- record kind (`SharedOutputBlinding` or `CollaborativeBpNonces`);
- nonzero session ID and participant ID;
- participant index;
- the exact context or `BpStatementV1` hash;
- the expected public `R_i` for a blinding record;
- a fresh envelope instance ID and ChaCha20-Poly1305 nonce; and
- the exact plaintext length.

The object key is independently derived from the existing vault master key by
HKDF-SHA256 under a new kind-specific F7 candidate label. Encryption uses the
existing reviewed ChaCha20-Poly1305 implementation and authenticated complete
header. The envelope digest uses pinned DOM `blake2b_256_tagged` under a
candidate domain. These candidate labels are not inserted into the closed
`StorageHashDomainV1` registry.

The sealer and opener exchange plaintext only through DOM-owned one-shot
capabilities and opaque zeroizing transfers. There is no byte accessor,
generic plaintext function, codec trait, `Clone`, `Copy`, `Debug`, `Display`,
equality, ordering, Serde implementation, or raw scalar constructor in the
Store API.

### Durable shared-output blinding

DOM creates `r_i` with its authoritative OS-CSPRNG scalar boundary and gives
the Store only an opaque transfer plus a one-shot seal capability. Before
returning `R_i` or a share proof, the Store:

1. seals and durably publishes the `SharedOutputBlinding` envelope;
2. reopens and authenticates that exact envelope;
3. imports it through the DOM one-shot capability;
4. requires the imported `SigningShareV1.public_key()` to equal the public key
   authenticated by the envelope; and
5. durably publishes the initial stage record.

The provisional context binds chain ID, session ID, the complete canonical
roster, participant ID and index, direction, terms hash, and `R_i`. It cannot
bind a recovery-capsule hash because the bilateral capsule does not yet exist.
After the capsule exchange, the production restartable transition creates one
immutable bound record containing three independently authenticated
envelopes: the primary share, the backup share, and the exact canonical
96-byte recovery capsule. All three use the complete capsule-bound AAD and the
same storage epoch. This bound record is durable and reread byte-for-byte
before a `SharedPendingRetired` tombstone is published and the provisional
record is deleted. The bound record is the promotion commit intent; neither
secret envelope is mutated in place.

Restart accepts only the stable public context that existed before the crash.
The caller cannot provide `R_i`, a binding digest, capsule bytes, a capsule
hash, a filename, or a record selector. The retained vault authenticates the
complete namespace and requires exactly one matching live stage. It returns
only a stage-typed opaque share capability: provisional when only the pending
record exists, or bound together with the authenticated exact public capsule.
A two-envelope legacy bound record remains readable through the compatibility
API but is deliberately ineligible for F7 restart because it retained only a
hash and cannot reproduce the capsule bytes.

The only accepted promotion prefixes are:

```text
Pending
Pending + Bound
Pending + Bound + PendingRetired
Bound + PendingRetired
```

For each prefix containing `Bound`, restart verifies that the bound binding
embeds the exact pending binding and that the capsule rehashes to the bound
capsule hash. It then publishes or verifies the pending tombstone and deletes
the pending record before returning bound authority. A duplicate or divergent
match, a tombstone without its live bound successor, any bound-retired record,
or a bound record without authenticated predecessor evidence fails closed.

Once all contributions exist, a separate immutable statement anchor binds the
custody ID and `R_i` to the exact final `BpStatementV1` hash. This remains an
additive later binding, not mutation of either share record. Any different
chain, session, roster, participant, index, direction, terms, public key,
capsule, or statement fails closed.

Restart may rehydrate only an opaque `SigningShareV1` after complete inventory,
AEAD, context, stage-chain, anchor, and public-key authentication. It may be
used for the same participant's collaborative proof, funding, claim, and
refund composition; it cannot be exported as bytes or combined across
participants by the Store.

A `ShareBackupAckV1` is issuable only through a DOM one-shot acknowledgement
capability consumed by this authenticated durable-open path. A public
point-only acknowledgement constructor is not a production authority. The
bilateral gate therefore proves that every acknowledged public point came from
an authenticated durable local share record, not merely from caller input.

### Durable collaborative Bulletproof nonces

DOM generates `q_i[32]` and an independent canonical nonzero
`private_nonce_i` using separate OS-CSPRNG calls. The two values cross the
storage boundary only in one opaque, zeroizing, one-shot transfer. The Store
seals the exact 64-byte material under a `CollaborativeBpNonces` envelope bound
to the already frozen `BpStatementV1` hash before a common commitment can be
returned.

The immutable stage chain is monotonic:

```text
Persisted -> CommonCommit -> CommonReveal -> Round1 -> Round2 -> Consumed
                                                    \-> Burned
```

`CommonCommit`, `CommonReveal`, `Round1`, and `Round2` each require a durable
attempt record before opening secret material or entering the backend. An exact
outbound artifact and its stage successor are durable before bytes leave the
process. Restart returns only the byte-identical persisted artifact. A
different artifact, statement, session, participant, input vector, aggregate,
or extra-commit fails closed.

Clean restart after Round 1 may reconstruct the backend's private round state
only by importing the same authenticated opaque material, recomputing under the
same exact public inputs, and comparing the result to the already persisted
Round-1 artifact before it can proceed. This reconstruction does not authorize
a second outbound share. An ambiguous crash after an attempt became durable
but before its matching artifact became durable burns the record; it never
retries a potentially exposed nonce computation.

Round 2 durably records its exact outbound share and `Consumed` successor
before deleting the encrypted secret. Recovery completes a deletion that was
interrupted after the successor became durable. Finalization failure and abort
also publish `Burned` before deletion. Neither terminal state can be reopened.

### Authenticated operational BP continuation

The encrypted collaborative-secret vault remains the only authority that can
reopen local nonce material. The session Store separately reconstructs the
public protocol continuation from its authenticated DSC1 journal. It accepts a
typed trusted chain, session ID, expected cross-chain terms hash, canonical
`BpStatementV1`, and typed `RecoveryCapsule`; it never accepts capsule bytes, a
caller-computed capsule digest, a filename, or a retained-record selector.

The Store reauthenticates the exact two-party roster and independent identity
references, every retained message signature, every immutable session
successor, and the complete predecessor transcript. It then admits only the
closed ordered grammar:

```text
0x05 BpCommonCommit  = 32-byte c_i
0x06 BpCommonReveal  = 32-byte zeroizing q_i
0x07 BpRoundCommit   = 32-byte BpRound1ShareV1 reveal commitment
0x08 BpRound1        = exact 138-byte BpRound1ShareV1
0x09 BpRound2        = exact 104-byte zeroizing BpRound2ShareV1
0x0a BpFinal         = exact 739-byte RangeProof739
```

Messages `0x05` through `0x09` occur in canonical participant order for both
roster members, with exact revisions, sender-local sequences, directions,
phase successors, and transcript hashes. Commitments must open against the
typed reveals/shares. Both typed aggregates are reconstructed inside the Store
from the authenticated ordered transcript and validated by the pinned DOM
implementation. The supplied capsule must hash exactly to the statement's
recovery binding, and the final proof must pass the unchanged real verifier.

Exactly one `0x0a` is canonical. Either authenticated participant may be the
finalizer, at that sender's exact next sequence, after both `0x09` shares. A
same-sender byte-identical retry is the existing Store duplicate and creates no
revision. A second durable finalization under the other sender key is a
competing transcript and continuation fails closed, even when its proof bytes
are identical.

The result is an opaque, Store-constructed, non-cloneable, non-debuggable,
non-serializable continuation. Its stage mask identifies only accepted roster
slots for the current stage. Common commitments, reveals, and round-one values
have candidate-only comparators; no reveal getter exists. Instead, the handle
finishes each independently reopened `PendingCommonNonce` with the Store's
private authenticated common transcript. During partial round 2, no retained
`BpRound2ShareV1` or byte vector crosses the boundary: a caller-owned durable
transport is consumed, its DOM binding is checked, and only those same
caller-owned zeroizing bytes are returned. Once both round-two shares are
durable, consuming the continuation yields Store-built non-cloneable round-one
and round-two aggregates. A completed final proof is available only through a
second opaque consuming handle with a public finalizer index and proof digest.

The cross-chain terms hash is an explicit mandatory input because the BP
statement binds chain, session, value, participants, and capsule, but not the
F7 economic terms. This prevents a valid retained BP session from being reused
under different terms.

### Restart-safe ReadyToFund vote projection

`PreparedOperationalM8FundingGateV1` exposes one borrowed projection:
`ready_to_fund_vote_payload()`, the exact public gate digest already committed
by both `0x11` ReadyToFund votes. The handle has no constructor, clone, debug,
or codec surface and never exposes the retained bilateral
`backup_receipt_hash`. Fresh preparation and restart return the same public
digest only after authenticating the immutable M.8 gate. Issuing or resuming
funding still consumes the handle and independently reauthenticates the exact
gate, BP statement, templates, session phase, terms, votes, and private backup
receipt binding.

### Crash and concurrency authority

All operations run while the retained process lock and one in-process operation
mutex are held. Process-bound capabilities include the random open-instance ID
and exact authenticated predecessor digests. They are invalid after restart.
Immutable no-replace publication gives one winner under thread, process, or
crash races.

## Alternatives considered

### Deterministic derivation from a persisted seed

Rejected. It directly contradicts NAR-DC-P1-001 §6.4, which requires an
independent fresh `private_nonce_i` and forbids deriving it from public session
material or the common nonce. A seed/KDF design also changes the approved
secret model rather than merely making it durable.

### Reuse `NonceSecretRecordV1`

Rejected. That record encodes a two-nonce Schnorr reservation and belongs to a
closed registry and lifecycle. Collaborative Bulletproof nonces and `r_i` have
different semantics, lifetimes, bindings, and retirement rules.

### Store raw scalar bytes in the session journal

Rejected. Session and transport journals are public protocol evidence and
explicitly exclude nonces, shares, seeds, and keys. Filesystem permissions are
not a substitute for authenticated encryption and opaque ownership.

### Mutate the blinding envelope after the capsule or final statement exists

Rejected. In-place mutation destroys crash-prefix evidence and makes the
pre-publication durability claim unverifiable. The immutable statement anchor
solves the causal ordering without rewriting secret authority.

## Invariants

1. The existing `ContractsNonceVaultV1` remains the only nonce-vault authority.
2. `r_i`, `q_i`, and `private_nonce_i` are created only by authoritative DOM
   OS-CSPRNG boundaries and are never deterministically derived.
3. No public commitment, share proof, reveal, or proof-round share precedes
   durable encrypted custody and its exact stage predecessor.
4. Secret plaintext never crosses a generic byte API and is zeroized on all
   success and failure paths.
5. Every open reauthenticates storage IDs, epoch, session, participant, index,
   context/statement, kind, stage chain, and expected public key where present.
6. The exact recovery capsule is encrypted in the immutable bound promotion
   record; a final statement is bound by a later immutable anchor. Neither
   transition mutates the pre-publication blinding envelope.
7. Exact duplicate outbound requests return only already persisted bytes.
8. A divergent duplicate, wrong key, changed context, reordered round, or
   ambiguous post-attempt crash fails closed and burns one-shot BP material.
9. Consumed or burned BP material is irrecoverable and cannot be restored from
   an ordinary nonce-vault backup.
10. Bilateral backup acknowledgement is impossible from an unauthenticated
    caller-supplied public point.
11. A generation/nonce-epoch transition is rejected while any collaborative
    record remains; an envelope is never made undecryptable by silent epoch
    drift and never copied by the ordinary backup/restore profile.
12. Restart discovery accepts only stable session context and never a
    caller-selected `R_i`, capsule, digest, filename, or retained record.
13. A bound promotion is released only after the exact legal prefix converges
    to `Bound + PendingRetired`; duplicate, divergent, orphaned, legacy-bound,
    or terminal state cannot resurrect a share.
14. Operational BP restart accepts only the canonical authenticated prefix of
    the closed `0x05..0x0a` grammar, exact typed capsule and statement, exact
    terms, and the retained two-party identity/roster order.
15. Partial round-two continuation never returns retained `0x09` bytes; only a
    caller-owned durable transport may be consumed and returned after binding
    and, when applicable, exact-byte comparison.
16. Either roster participant may finalize once. A second durable finalizer
    under the competing sender key is noncanonical and fails closed.
17. ReadyToFund vote composition sees only the authenticated public M.8 gate
    digest; `backup_receipt_hash` remains Store-private and is rechecked at
    funding issue/resume.

## Compatibility and security impact

This design changes no DOM consensus, transaction, wire, point/scalar codec,
Bulletproof arithmetic, challenge, transcript, Schnorr, or adaptor rule. The
final proof remains the canonical 739-byte DOM proof verified by the unchanged
real verifier. The changes are confined to local encrypted custody and the
narrow opaque handoff required to feed the existing pinned DOM implementation.

The additive generation namespace and candidate envelope are deliberately F7
laboratory formats. They require normative ratification and migration policy
before production or mainnet use. Existing generation inventories without the
optional namespace remain readable; creating a collaborative secret upgrades
that one retained generation by an authenticated, create-no-clobber namespace
publication.

## Required evidence

- opaque-type compile assertions and compile-fail examples;
- ciphertext does not contain the 32-byte or 64-byte secret plaintext;
- wrong passphrase/master key, header mutation, ciphertext mutation, and tag
  mutation fail authentication without secret-bearing errors;
- wrong session, participant, index, context, statement, kind, epoch, or
  public key fails closed;
- wrong chain, roster, role, terms, or contextual restart substitution fails
  before a share capability is returned;
- restart reproduces the same `R_i`, common commitment, reveal, and round
  outputs from authenticated opaque custody;
- restart from both sides of pending publication and from bound publication
  before the pending tombstone returns the exact original stage without
  reminting `r_i`;
- the normal `Bound + PendingRetired` state and both legal torn promotion
  prefixes converge byte-identically before bound authority is released;
- duplicate matching records, legacy two-envelope bound records, orphan
  pending tombstones, and bound-retired records fail closed;
- crash cuts before and after secret publication, each stage attempt, artifact
  publication, successor publication, terminal record, and secret deletion;
- an ambiguous attempt without an artifact burns on reopen;
- exact artifact resend after a lost acknowledgement;
- thread/process races have one durable winner;
- statement-anchor mismatch and stage reorder/duplication/equivocation fail;
- every operational BP prefix from zero through eleven accepted messages
  reopens to the exact stage, participant mask, revision, and transcript;
- gap, record tamper, participant reorder, typed-profile confusion, signed
  equivocation, terms substitution, and capsule substitution fail closed;
- responder finalization succeeds, same-sender exact final replay is
  idempotent, and a competing second finalizer is quarantined;
- fresh and restarted prepared M.8 handles return the same public ReadyToFund
  vote payload without exposing the bilateral backup receipt hash;
- consumed/burned material cannot reopen;
- bilateral backup ACK cannot be minted before durable `r_i` custody; and
- real DOM final verification succeeds for the recovered two-participant path.

# Minimal Persistent Vault Engine Review Result

Status: **HISTORICAL — SUPERSEDED BY THE CANONICAL VAULT RUNTIME**

This report records the withdrawal of an experimental single-reservation
engine. It is retained as the audit trail for that withdrawal and for the
blockers it enumerated. It is not a statement about the current tree.

The canonical runtime that replaced it lives in
`crates/dom-scriptless-store/src/runtime/linux/`, is adjudicated by
`PHASE1-CONTRACTS-CLOSURE.md`, and consumes the published DOM Protocol
revision `6f2b230ebbec390040dbf0bff110efaf4bb0f101`. The two normative
amendment gaps this report left open — restart-resend trusted identity and one
atomic retained snapshot interface — were assigned by NAR-DC-P1-006 §§3–4 and
ratified in `NAR-DC-P1-006-RATIFICATION.md`.

Every review finding and blocker below is preserved verbatim as written at the
time of withdrawal. A closing section states which of its conditions have since
been addressed and where. Nothing here relabels the withdrawn experiment as
evidence for the current runtime; that evidence is bound to its own commits.

This report supersedes the earlier milestone claim recorded by commit
`f9812a9e576e6f31753d2ea67939c7afc888622d`. Independent review found that the
single-reservation experimental engine did not satisfy the complete ratified
NAR-DC-P1-004 and NAR-DC-P1-005 authority model. The implementation remains
available in Git history for audit, but its source is removed from the current
tree and no module references it.

No G1B, Phase 1, production, publication, mainnet, or real-funds claim may use
the withdrawn experiment as evidence.

## Review findings

The withdrawn experiment had the following blocking defects:

1. It accepted a raw `NonceDerivationAttemptV1`, arbitrary outbound bytes, and
   a revision number instead of the required private one-shot reservation,
   computation, persistence, and persisted-exposure authorities.
2. Recovery after a durable Commitment `Persisted` prefix reconstructed
   authorization. NAR-DC-P1-004 requires process loss before the matching
   `Authorized` transition to burn Commitment or Reveal and never reconstruct
   an authorization handle.
3. Resend accepted a caller-supplied digest instead of one consumed
   `ValidatedResendAuthorizationV1` and complete trusted protocol state.
4. The retained lock descriptor was not tied back to the current lock pathname
   during lifetime revalidation.
5. Direct final-name creation did not have explicit fault evidence proving that
   every partial write or incomplete sync is preserved and classified before
   recovery. NAR-DC-P1-005 permits create-no-clobber at either a staging or
   final object; no additional staging basename is required or implied.
6. Inventory validation occurred after deterministic recovery had already
   mutated state, which could erase the distinction between an unambiguous
   prefix and conflicting forensic evidence.
7. Replay materialized complete directory and journal contents in unbounded
   collections and represented only one lifetime reservation. NAR-DC-P1-004
   requires bounded streaming over multiple lifetime reservations without an
   invented count or budget.
8. A journal-only Reserve crash could be repaired into a live reservation.
   NAR-DC-P1-005 requires a reopened reserved-only prefix to become terminal
   `Burned`, because memory cannot prove that nonce derivation never began.
9. Consuming transitions did not revalidate every named root, generation,
   lock, process-instance, and current-head binding before using authority.

These are authority and crash-safety defects, not cosmetic issues. The
experiment was therefore removed rather than patched into a superficially
passing but nonconforming runtime.

## Retained implementation scope

The current crate retains only:

- fail-closed canonical structural and authenticated record codecs;
- the separately validated safe-Rust Linux retained-capability filesystem
  prerequisite;
- exact no-follow, ownership, mode, link-count, create-no-clobber,
  rename-no-replace, synchronization, retained-unlink, and directory-scan
  helpers; and
- a retained lock that now binds its descriptor identity to the current
  authenticated pathname on every explicit revalidation.

The retained filesystem scan is streaming and uses checked `u64` accounting.
It does not allocate from an untrusted directory-entry count. A registry-valid
512-entry flood test exercises the callback path with scalar caller state.

## Lock replacement boundary

The retained lock owner now keeps:

- the exact opened lock descriptor;
- its authenticated device/inode/type/link/owner/mode identity;
- the retained parent directory capability; and
- the validated lock component.

`revalidate` checks both the descriptor and the no-follow directory entry and
requires identical identity. A rename/recreate test proves that the original
authority becomes invalid even when another lock can be acquired on the new
inode.

NAR-DC-P1-005 explicitly excludes a malicious same-UID process that can mutate
private Store directories while ignoring the advisory lock. Preventing that
threat requires a separately ratified process-isolation boundary. The current
code makes no stronger claim.

## Precise implementation blockers

The complete runtime remains blocked on the following implementation and
publication work. These are not additional unassigned wire bytes:

1. The revised one-shot `NonceVaultV1` lifecycle and private accepted signing
   authorities are reviewed, published, and pinned from the official DOM
   repository.
2. A bounded streaming multi-reservation replay/admission design is
   implemented, including lifetime collision and budget projection, without
   numerical defaults or count limits invented by implementation code.
3. A Contracts-owned secret-record runtime is implemented through the already
   assigned cryptographic boundary. Secret plaintext persistence remains
   prohibited.
4. Recovery performs a complete non-mutating streaming inventory and prefix
   classification before any deterministic mutation.
5. The complete one-shot reservation, computation, persistence,
   persisted-exposure, export, and resend authority graph is available, with
   root/generation/lock/open-instance/current-head revalidation at every
   consuming transition.

## Remaining normative amendment gaps

Exactly two authority gaps still require ratified assignments before a future
engine can close its production interface:

1. restart-resend trusted identity; and
2. one atomic retained snapshot interface that binds the named root, active
   generation, retained lock/open instance, and current journal head for every
   consuming transition.

Storage state, a caller-provided digest, sequential reads, or detached
descriptors cannot substitute for either authority.

Direct final-name creation is not a normative gap. NAR-DC-P1-005 §5.3 permits
create-no-clobber of a staging or final object. A future implementation using a
final name must preserve and classify every partial-write and incomplete-sync
prefix before any recovery mutation and may never authorize from such a
prefix.

## Corrective commit and executed validation

The corrective code commit is
`46ced52afe7a20169c69caf5b0c8d71bfcc14e85`, tree
`cb9758baf0a77183127de95e85d4dfd87449cd80`.

The following commands ran against that exact code tree:

| Command | Result | Exit code |
|---|---|---:|
| `cargo fmt --all -- --check` | PASS | 0 |
| `cargo check -p dom-scriptless-store --locked` | PASS | 0 |
| `cargo test -p dom-scriptless-store --locked` | PASS: 105 parent tests, one parent-ignored subprocess helper executed by its owning test, and 2 compile-fail documentation tests | 0 |
| `cargo clippy -p dom-scriptless-store --all-targets --locked -- -D warnings` | PASS | 0 |
| `git diff --check` | PASS | 0 |

The retained Linux subset reported 15 passing parent tests, one intentionally
ignored helper, and no failures. It includes the lock rename/recreate test and
the 512-entry registry-valid streaming scan.

At the time of withdrawal, and until those conditions were met, there was no
concrete production vault engine, no export path, and no resend path in
`dom-scriptless-store`.

The status recorded at withdrawal was:

```text
WITHDRAWN_SINGLE_RESERVATION_ENGINE = NOT_IN_MODULE_GRAPH
PERSISTENT_VAULT_ENGINE = BLOCKED
REVISED_NONCE_VAULT_TRAIT_CONFORMANCE = BLOCKED_BY_UNPUBLISHED_DOM_API
MULTI_RESERVATION_STREAMING_REPLAY = NOT_IMPLEMENTED
RESTART_RESEND_IDENTITY = BLOCKED_BY_AMENDMENT
ATOMIC_RETAINED_SNAPSHOT_INTERFACE = BLOCKED_BY_AMENDMENT
SECRET_STORAGE_CRYPTO = IMPLEMENTED_AND_LOCALLY_VALIDATED_NOT_RUNTIME_INTEGRATED
G1B = NOT_APPROVED
PHASE1 = NOT APPROVED
PRODUCTION = NOT AUTHORIZED
PUSH = NOT PERFORMED
MERGE = NOT PERFORMED
RELEASE = NOT PERFORMED
```

## Current disposition of the recorded blockers

This section states only which conditions above have since been addressed and
where. It creates no approval of its own; the adjudication of the current
runtime lives in `PHASE1-CONTRACTS-CLOSURE.md`, together with the evidence
obligations that remain open.

```text
WITHDRAWN_SINGLE_RESERVATION_ENGINE = STILL_NOT_IN_MODULE_GRAPH
PERSISTENT_VAULT_ENGINE = REPLACED_BY_CANONICAL_RUNTIME
REVISED_NONCE_VAULT_TRAIT_CONFORMANCE = DOM_API_PUBLISHED_AND_PINNED
MULTI_RESERVATION_STREAMING_REPLAY = IMPLEMENTED
RESTART_RESEND_IDENTITY = ASSIGNED_BY_NAR_DC_P1_006_SECTION_4
ATOMIC_RETAINED_SNAPSHOT_INTERFACE = ASSIGNED_BY_NAR_DC_P1_006_SECTION_3
SECRET_STORAGE_CRYPTO = RUNTIME_INTEGRATED
G1B = CLOSED_AS_PHASE1_CANDIDATE_SEE_PHASE1_CONTRACTS_CLOSURE
PHASE1 = NOT ADJUDICATED
PRODUCTION = NOT AUTHORIZED
MAINNET = DISABLED
REAL_FUNDS = PROHIBITED
```

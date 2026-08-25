# ADR-F7-LAB — Durable production Relay queue and authenticated reconstruction

- **Status:** laboratory implementation decision
- **Date:** 2026-08-14
- **Scope:** `crates/relay` only
- **Gate effect:** none by itself; the real F7 route and fault matrix must still run

## Context

The ratified Relay V1 implementation is intentionally an in-memory protocol
reference. It proves the store-and-forward rules but cannot prove the F7 rows
for process loss, database loss, or an acknowledgement lost after durable
storage. The full F7 route requires all three without making the Relay an
authority over a settlement.

The Relay remains untrusted transport. It may retain canonical signed envelope
bytes and public digests, but it must never interpret payloads, hold private
keys/nonces/shares/route secrets, decide Claim versus Refund, or become the only
source from which a participant can recover.

## Decision

Add a separate `ProductionRelayV1` beside the existing in-memory `RelayV1`.
The production queue uses the workspace-pinned bundled SQLite backend in WAL
mode and an owner-only retained root:

- the root is canonical, local, mode `0700`, owned by the effective user and
  never reached through a symlink;
- identity, lock, database, WAL, SHM and fault markers are regular owner-only
  files with mode `0600` and one link;
- one retained nonblocking exclusive lock prevents two Relay writers;
- SQLite version/source ID, WAL, `synchronous=FULL`, defensive settings,
  foreign keys, trusted schema, read-uncommitted, secure-delete and finite busy
  timeout are configured and read back;
- there is no `ATTACH`, migration, implicit creation on open, or salvage;
- `quick_check`, the closed schema/table set, metadata, ordinal continuity,
  canonical envelope decode, idempotency key, envelope digest, source binding
  and row digest are checked before use.

The closed schema check compares the exact persisted `CREATE TABLE` SQL and
rejects any non-automatic index, view or trigger. Merely retaining the three
expected table names is insufficient.

`create` is exclusively a first-install operation and refuses any existing
root. `open` is exclusively a restart operation and refuses a missing database.
This distinction prevents database loss from silently becoming an empty,
apparently healthy Relay.

## Durable submission and ACK loss

The queue key remains the D-020 tuple
`(session_scope, sender_id, recipient_id, sequence)`.

For a new key, one `BEGIN IMMEDIATE` transaction stores the exact canonical
envelope, envelope digest, routing identity and row digest. The transaction
commits before an ACK is returned. For an existing key:

- exact same bytes return the ACK derived from the persisted row;
- different bytes are stored in the bounded conflict journal and return the
  named fail-closed equivocation error.

`AckV1` has a fixed canonical codec. A first ACK, a retry after lost ACK and a
retry after process restart are therefore byte-identical. Delivery reads the
persisted bytes and remains at-least-once; it does not maintain an authoritative
recipient watermark.

## Database loss and reconstruction

The retained database identity survives loss of the SQLite database/WAL/SHM.
After loss, `open` returns `DatabaseMissing`. The only operation that can make
the root usable again is explicit `reconstruct`, and it consumes an opaque
`AuthenticatedRecoveryBatchV1`.

Candidates are accepted only with one of two closed availability labels:

1. exact bytes retained by a participant Store/outbox; or
2. exact bytes retained in authenticated public-chain evidence.

The label and non-null source-record digest are provenance, not trust. Before a
batch exists, the Relay recovery boundary independently performs canonical
decode, an exact caller-authorized network/session/route/recipient scope match,
roster membership and role checks, BIP340 verification under the named roster
snapshot, expiry-domain comparison, sequence/gap/replay/equivocation checks and
transcript continuity. It uses the existing recipient authentication pipeline.
Thus lying about a source label cannot authenticate modified or foreign bytes.

Exact duplicates from Store/outbox and public chain collapse into one row with
both provenance bindings committed. Same-key/different-byte candidates, gaps,
substitution, unknown scopes and bad signatures reject the entire batch. The
empty candidate set also fails because it authenticates no availability
source. The new database is marked incomplete until every authenticated row
and the batch digest commit in one transaction. An interrupted reconstruction
cannot open.

Public-chain adapters remain responsible for validating chain inclusion and
finality before presenting a candidate. The Relay then validates the signed
envelope contained in that evidence. This separation avoids importing either
DOM or Bitcoin semantics into the payload-opaque Relay.

## Fault controls

Real process/database loss controls exist only under crate tests or the
default-off `relay-fault-injection` feature.

- The process-loss capability binds one database identity, one exact
  idempotency key and the exact envelope digest. It commits that envelope,
  fsync-publishes a fired marker with the same bindings, and aborts before
  returning the ACK. An exact retry of an already committed row returns
  normally, preventing an abort loop.
- The database-loss capability consumes the open Relay, closes SQLite,
  fsync-publishes a database-loss marker, rejects unknown similarly named
  objects, removes only the exact database/WAL/SHM files, and fsyncs the
  retained root. Identity and lock are not deleted.

Normal builds expose neither destructive operation. Markers contain only
public database/key commitments and checksums; no envelope payload is logged.

## Alternatives rejected

- **Continue using `RelayV1` and recreate it after failure:** cannot distinguish
  restart from database loss and cannot prove ACK-after-commit behavior.
- **Let `open` create missing storage:** turns destructive loss into silent
  message omission and violates fail-closed recovery.
- **Copy arbitrary files or salvage SQLite pages:** bypasses canonical envelope
  and source authentication and can manufacture a partial queue.
- **Trust a source enum or caller-supplied digest:** provenance is not
  authentication; every envelope must pass the recipient cryptographic and
  transcript pipeline.
- **Teach Relay payload or chain semantics:** makes an untrusted transport an
  outcome authority and duplicates the Store/DOM/Bitcoin adapters.
- **Compile fault deletion into normal production:** materially enlarges the
  destructive surface and permits accidental operational activation.

## Invariants and proof obligations

The focused Relay workflow must prove:

1. fixed ACK codec round-trip, bad-domain/length refusal and identical bytes on
   first submit, retry and restart;
2. exact persisted delivery and one row under repeated submission;
3. durable same-key/different-byte conflict across restart;
4. owner/mode/symlink/hardlink and second-writer refusal without repair;
5. exact database schema/row/digest tamper and incomplete reconstruction refusal;
6. missing database never opens or auto-creates;
7. Store/outbox plus public-chain exact duplicates collapse, while an empty
   source set, null source binding, substitution, foreign scope, replay/gap and
   bad signature fail;
8. a subprocess dies only at the bound post-commit/pre-ACK cut, the marker is
   exact, and restart returns the persisted ACK;
9. the bounded database-loss hook removes only database/WAL/SHM and only an
   authenticated batch restores service;
10. no payload, secret or filesystem path appears in errors or Debug output.

These component tests do not close F7. The final supervisor must kill the real
Relay process/database inside the real route, replay exact participant outbox
bytes, consult public chains for terminal reconciliation, and independently
prove the same safe economic terminal.

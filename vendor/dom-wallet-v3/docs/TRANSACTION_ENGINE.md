# DOM Wallet V3 transaction engine

Phase 1B-A adds a protocol-pinned, manual two-party DOM transaction engine.
The engine is experimental and intentionally does not provide automatic peer
transport, live-node end-to-end evidence, backup/restore, or migration.

## Protocol boundary

`dom-wallet-protocol` is the sole wallet adapter for DOM transaction and slate
cryptography. It depends on `dom-core`, `dom-crypto`, `dom-consensus`,
`dom-serialization`, `dom-tx`, and `dom-slate` at revision
`f10667d86196daf4599eff6074a7abf73b6ed55a`. It uses
`dom_slate::build_send`, `respond_receive`, and `finalize`; canonical slate and
transaction bytes are produced and decoded through `DomSerialize` and
`DomDeserialize`, including trailing-byte rejection. Fee estimates derive from
the protocol weight constants and `MIN_RELAY_FEE_RATE`.

The adapter owns no files, wallet state, HTTP client, or transport policy.
`dom-wallet-core` owns selection, reservation, encrypted state, lifecycle, and
submission. Tauri and the frontend only invoke redacted core projections.

## Durable lifecycle

The canonical local transaction record advances through explicit states:

`DRAFT → INPUTS_RESERVED → REQUEST_EXPORTED → RESPONSE_IMPORTED → FINALIZED →
SUBMITTING → SUBMITTED`, with recipient states `REQUEST_IMPORTED →
RESPONSE_PREPARED → RESPONSE_EXPORTED`. `ACCEPTED_NOT_RELAYED`, `IN_MEMPOOL`,
`CONFIRMED`, `REORGED`, `RETRANSMIT_REQUIRED`, `CANCELLED`, `FAILED`, and
`RECONCILIATION_REQUIRED` retain their durable evidence. Unknown or backward
transitions fail closed. Canonical scan kernel evidence remains authoritative
for confirmation and reorganization reconciliation.

Before request export, the sender persists selected-input reservations, public
request bytes, sender excess blinding, and single-use sender nonce together in
the encrypted generation. Before recipient response export, the recipient
persists its allocated output descriptor, non-reuse floor advance, output
blinding, response bytes, and local transaction intent together. The exported
slate contains public protocol material only. Sender finalization consumes the
stored sender nonce, persists the immutable canonical transaction bytes and
kernel excess, and is idempotent for the same response.

## Selection, fees, cancellation, and retry

Selection uses only exact local confirmed descriptors that have an encrypted
local output blinding and no existing reservation. Candidates are deterministically
ordered by value, commitment, and output identifier. The protocol-derived
minimum relay fee is checked after each bounded selection step; overflow,
insufficient funds, missing spending evidence, and reservation conflicts fail
closed. Outputs learned by Phase 1A scanning without local spend evidence are
not spendable by this phase.

Cancellation can release reservations only from `INPUTS_RESERVED` or an
explicitly confirmed `REQUEST_EXPORTED` state. It never erases the transaction
record or decreases allocation/non-reuse floors. Submission first persists
`SUBMITTING`, then calls only the existing wallet-safe `POST /tx/submit`
adapter. A transport failure leaves an uncertain durable state; retry uses the
same finalized bytes and never regenerates nonces or inputs. An accepted but
unrelayed result is retained as `ACCEPTED_NOT_RELAYED` for explicit retry.

## Limits

This phase has no automatic transport, Slatepack relay, live VPS two-wallet
test, mining confirmation, backup/restore, migration, or payment
recovery for scan-only outputs. Mempool admission with a real chain view is a
live-E2E boundary; the wallet test instead validates the completed transaction
through the pinned consensus, serialization, range-proof, balance, and
signature path.

Manual QR exchange is another representation of the exact same versioned text
envelope, including bounded multipart reassembly. It is local copy/scan
transport only and is not authenticated network transport.

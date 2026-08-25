# ADR-F7-LAB: Durable exact-byte DOM outbox

- Status: Lab candidate
- Scope: F7 laboratory composition only
- Normative authority: DOM Interop Foundation v0.18; NAR-DC-P1-007

## Problem

The first real-DOM adapter draft retained signed funding and refund transactions
as ordinary `Vec<u8>` values. Although those vectors were decoded and hashed,
their public constructor allowed a composition root to bypass the Contracts
Store's one-time funding authorization, durable consumption, refund timelock
gate, and byte-identical restart path. Such a path cannot be accepted by G-F7.

## Context

The settlement engine persists semantic outbox effects, not secret transaction
material. The Contracts Store is the authority that durably persists the exact
signed artifacts and proves that funding authorization was consumed before any
broadcast attempt. The real DOM HTTP adapter is the authority for node
submission and admission acknowledgement.

## Decision

The F7 real-DOM effect sink accepts no funding or refund byte vector.

The first funding attempt is supplied as a non-cloneable
`FundingBroadcastV1` issued only by the operational funding sink after the
artifact, authorization consumption, and `FundingBroadcast` successor are
durable. Every later attempt reacquires a fresh
`FundingRetransmissionV1` from the Store. Both capabilities are consumed by
`dispatch_with` and lend the exact bytes only to
`ExactDomFundingBroadcasterV1` for the duration of the authenticated RPC call.

Refund broadcast similarly reacquires `RefundBroadcastV1` from the Store. The
Store releases it only in an eligible refund phase and after validating the
persisted height-locked transaction against a fresh real-DOM tip context. Its
bytes are lent only to `ExactDomRefundBroadcasterV1`.

`RealDomExactBroadcasterV1` is the only Interop implementation of those two
boundaries. It forwards the borrowed canonical bytes unchanged to
`DomHttpChainAdapterV1::submit_canonical_transaction`.

## Alternatives considered

1. Keep signed bytes in the Interop outbox payload. Rejected because it creates
   a second artifact authority and bypasses one-time Store issuance.
2. Rebuild transactions on every retry. Rejected because retransmission must be
   byte-identical and rebuilding can change signatures, offsets, ordering, or
   proofs.
3. Expose Store bytes through a read API and let the caller submit them.
   Rejected because copied bytes outlive the linear attempt capability.

## Invariants

- No production constructor accepts raw signed funding or refund bytes.
- Funding is durably consumed before the first byte can reach the broadcaster.
- A retry or process restart loads the authenticated original artifact; it
  never reconstructs or re-signs it.
- Each in-process attempt is linear and consumed by dispatch.
- Refund bytes are unavailable before the real DOM height lock is mature.
- A claimed outbox effect must match the sink's frozen settlement identifier.
- Node rejection is fail-closed; temporary unavailability remains retryable.
- A `new` or `mempool` acknowledgement without relay remains pending, while a
  relayed or confirmed acknowledgement completes the effect.

## Compatibility and security impact

This changes only the laboratory composition API. It does not modify DOM
consensus, transaction serialization, mempool policy, wire formats, or the
settlement engine's canonical effect encoding. It removes an authority bypass
and makes crash recovery depend on authenticated durable state instead of
process memory.

## Required tests

- First funding dispatch uses the Store-issued linear capability.
- Lost ACK and process restart retransmit byte-identical funding.
- Different bytes under the same transaction identifier are rejected by the
  real node adapter.
- Refund dispatch before maturity is rejected and succeeds after maturity.
- Store crash cuts after intent, artifact, consumption, and successor writes
  recover without exposing an unauthorized byte.
- An effect belonging to a different settlement is rejected.
- Secret scanning confirms that no signing share, nonce, seed, or adaptor
  scalar appears in logs or persisted public evidence.

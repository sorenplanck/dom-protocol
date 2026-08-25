# ADR-F7-LAB: Real DOM Source, Cursor and Claim-Evidence Consumption

- Status: **LAB CANDIDATE**
- Date: 2026-08-13
- Scope: DOM Interop F7

## Problem

F2/F6 use `dom-sim` to model chain semantics. F7 requires an implementation
that observes canonical transactions from a real DOM node, detects reorgs after
restart, identifies one settlement without heuristic matching, and extracts
the claim adaptor scalar from the final on-chain kernel signature. The core
must still receive no secret bytes and must never interpret DOM evidence.

## Context

The full-fidelity DOM scanner returns canonical transaction bytes, hashes,
locations and kernel signatures under an authenticated network identity and
anchored pagination. The settlement engine consumes only neutral funding,
claim, refund and reorg records. `dom-leg` is the pinned authority for adaptor
pre-signature verification and `t` extraction.

## Decision

Add `adapter-dom-real` as a separate workspace crate and explicit F7 path. Its
configuration freezes:

- the Interop chain registry id;
- the shared confidential output commitment;
- the signed funding transaction id;
- the signature-omitting claim template hash;
- the signed refund transaction id; and
- the exact claim kernel index.

The source accepts only canonical scanner evidence. Funding must have the exact
id and create the shared commitment. A refund must have the exact pre-authorized
id and spend it. A claim must spend it, match the frozen signature-omitting
template, and pass `DomLegSession::extract_revealed_secret`; any other spend is
invalid evidence, never an ignored transaction.

The engine receives only `EvidenceRefV1`. The now-public scalar is re-extracted
by `RealDomClaimConsumerV1` from that reference when the durable outbox asks for
claim consumption. The consumer always rescans the canonical block, even when
it has a cached copy, so an effect created before a reorg cannot consume stale
branch evidence.

## Cursor decision

The opaque cursor is a versioned binary record containing `next_height` and a
bounded contiguous suffix of `(height, block_hash)` anchors, followed by a
domain-separated BLAKE2b-256 integrity digest. The public cursor fields are
checked projections of those bytes. A stale page removes exactly one abandoned
anchor and emits a reorg record; repeated ticks converge to the common ancestor.
If the retained suffix is exhausted, the source reconstructs the preceding
cursor from the authenticated genesis path instead of guessing an anchor.

## Alternatives considered

- Adapt `dom-sim` to speak RPC. Rejected because its transaction identity and
  verifier are intentionally non-authoritative.
- Match claims by kernel signature or commitment alone. Rejected because that
  does not bind the frozen template and settlement.
- Persist `t` in the settlement core. Rejected because the core must never
  receive secret material and canonical evidence can deterministically
  reconstruct it.
- Trust an in-memory transaction cache after restart/reorg. Rejected because it
  may describe an abandoned branch.
- Store only the latest anchor. Rejected because one-step reorg convergence
  would lose the prior canonical position after process restart.

## Invariants

- No `dom-sim` type is linked into `adapter-dom-real`.
- No consensus, wire, genesis, encoding or mempool rule is modified.
- Scanner identity, canonical bytes and DOM adaptor verification are required;
  there is no compatibility fallback.
- A failed RPC/evidence check advances no cursor or economic state.
- Claim and refund are mutually exclusive because both spend the same real
  confidential output, and an unknown spend fails closed.
- `t` is returned only after final-signature, pre-signature, transcript,
  template and `tG == T` validation by `dom-leg`.
- Scalar bytes, bearer tokens, seeds and nonces are never formatted or logged.

## Compatibility and security impact

The crate is additive and does not change F5/F6 default runners. F7 composition
must opt into it and the real DOM feature. The cross-repository dependency is a
laboratory path until the unified DOM and Contracts commits are externally
published and ratified; the evidence manifest pins their exact local commits.

## Proof tests

- Cursor round-trip, integrity mutation, bounded suffix and exact one-block
  rewind tests.
- Public field versus authority-byte divergence test.
- Real-node tests for identity substitution, restart scan, shallow/deep reorg,
  transaction mutation and evidence refetch.
- Claim-cycle test proving the on-chain final signature extracts the same
  scalar and public point while the settlement core/database contain no scalar.

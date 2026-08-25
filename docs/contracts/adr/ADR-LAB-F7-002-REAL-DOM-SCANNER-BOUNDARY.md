# ADR-LAB-F7-002: Authenticated Full-Fidelity Real DOM Scanner Boundary

- Status: **LAB CANDIDATE — implemented and testable, not externally ratified**
- Scope: F7 laboratory only
- Date: 2026-08-13

## Problem

The legacy DOM wallet scan projection exposes commitments and limited kernel
metadata but discards canonical transaction boundaries and final kernel
signatures. A Scriptless claim observer cannot extract and validate the
revealed adaptor scalar from that projection. The mempool transaction endpoint
also cannot reconstruct a claim after confirmation or restart.

## Context

F7 requires the Interop to use the real DOM builder, RPC, mempool, verifier and
scanner. The scanner must support restart, canonical reorg detection,
byte-identical evidence reconstruction and claim-signature observation without
changing consensus, wire encoding or mempool policy.

DOM Protocol now provides the laboratory endpoint
`GET /chain/scan/scriptless/v1`. It returns an authenticated, bounded page of
canonical blocks and complete non-coinbase transactions. The existing
`POST /tx/submit` endpoint remains the only admission boundary.

## Decision

`dom-scriptless-chain-adapter` implements a strict blocking HTTP client for the
version-1 endpoint. The composition root freezes network name, network magic,
chain id, genesis id, protocol version and range-proof serialization version.
Every request includes the network magic and chain id and every response is
checked against the complete frozen identity.

The client:

1. accepts HTTPS endpoints, or plaintext HTTP only on loopback;
2. prohibits credentials in URLs and follows no redirects;
3. authenticates each request with a zeroizing, redacted bearer token;
4. enforces response, page and transaction bounds before decoding;
5. requires a canonical block anchor for every non-genesis page;
6. validates contiguous heights, previous-hash linkage, canonical header bytes,
   header identifiers, versions and snapshot continuation;
7. decodes every transaction with the pinned DOM canonical decoder, re-encodes
   it byte-for-byte, recomputes its BLAKE2b-256 id and compares every projected
   input, output, kernel, signature, offset and location;
8. submits only locally canonical transactions and verifies the node's returned
   transaction id; and
9. maps anchor conflict to a distinct reorg result so callers can rewind from a
   previously persisted canonical cursor.

The cursor returned by a page is not itself a durability claim. A wallet must
persist the cursor only in the same durable transaction that applies all
observations from the page.

## Alternatives considered

- Extend the legacy flat scanner. Rejected because transaction grouping and
  final signatures cannot be reconstructed without ambiguity.
- Read the DOM database directly. Rejected because it bypasses the node's chain
  lock and creates a second storage authority.
- Treat mempool data as confirmed evidence. Rejected because mempool entries are
  volatile and disappear after confirmation or restart.
- Reimplement DOM parsing in the adapter. Rejected because the pinned DOM
  canonical decoder and hash implementation are the authority.

## Invariants

- No consensus, genesis, wire, encoding or mempool rule is changed.
- A response from another chain, network or version fails closed.
- A non-genesis request without an anchor is never issued.
- A changed anchor is a reorg, never silently accepted as a continuation.
- Canonical transaction bytes are the evidence authority; JSON fields are
  checked projections, not independent truth.
- Secret scalars, wallet seeds, nonces and bearer tokens are never logged.
- Mainnet is outside F7 and is rejected by the laboratory client.
- Transaction admission remains the real node's consensus and policy decision.

## Compatibility and security impact

The endpoint is additive. Existing wallet and RPC endpoints are unchanged. A
node without version 1 fails with `CapabilityUnavailable`; there is no fallback
to an incomplete scanner. The endpoint's bearer middleware and range limits are
the same node-owned security boundary used by existing authenticated wallet
RPCs. The client additionally protects against redirects, unbounded bodies,
schema extension ambiguity, network substitution and replayed stale pages.

The schema and this adapter are laboratory candidates until their combined DOM
pin and bytes are externally ratified. That status does not weaken validation
inside the F7 laboratory.

## Proof tests

- endpoint policy rejects remote plaintext and credentials embedded in URLs;
- token formatting is always redacted;
- malformed cursors, hex, lengths and unknown schema fields fail closed;
- DOM Protocol endpoint tests cover identity mismatch, missing/wrong anchors,
  page bounds, canonical gaps, transaction grouping and kernel signatures;
- the F7 real-node harness covers restart continuation, shallow/deep reorg,
  byte-identical retransmission and claim-secret reconstruction.

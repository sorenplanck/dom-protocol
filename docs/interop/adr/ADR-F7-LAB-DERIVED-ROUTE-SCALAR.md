# ADR-F7-LAB-DERIVED-ROUTE-SCALAR — The route scalar is derived, never stored

Status: LAB DECISION — NON-NORMATIVE — records how this laboratory satisfies
invariant I1 while producing a non-degenerate acceptance instance. It proposes
no change to Foundation v0.18, Annex M v3.3, or any ratified decision, and it
claims no gate result.

## Context

The settled scenario-0 route ran on a degenerate cryptographic instance. The
laboratory pinned the route scalar to `t = 1` and the committed point to
`T = G`, the secp256k1 generator, and its acceptance gate rejected any
bootstrap whose adaptor point was not exactly that generator. No route in this
laboratory could execute with any other scalar.

Annex M v3.3 line 141 defines `t` as a "canonical scalar 1..n-1". The value `1`
lies inside that range, so the fixed instance was legal. It was nonetheless a
weak test:

- `s = ŝ + t` with `t = 1` barely exercises the adaptation arithmetic;
- a defect returning a constant, the identity, or `G` from either the extractor
  or the verifier would have passed unnoticed;
- full-width 32-byte scalar serialisation was never exercised;
- acceptance clause RTE5, "both legs bind the same `T`", is satisfied trivially
  by any code that hardcodes `G`.

Correcting this collides with a ratified rule. Foundation v0.18 section 5
invariant I1 states "Self-custody: no component stores a seed, private key,
share or t", and decision 7 of the same document states "Absolute self-custody;
no component takes custody of seeds, keys, nonce shares or secrets."

## Forces

Three requirements must hold simultaneously:

1. **Unpredictability.** `t` must be unknown to the counterparty, or the swap
   is not atomic. A compiled-in constant fails this.
2. **Restart safety.** `t` must survive a crash between route preparation and
   the first confirmed claim, or a restarted route cannot complete its claim.
   After that claim confirms, `t` is public on chain and recoverable by
   `verify_and_extract`, so the requirement applies to exactly that interval.
3. **No new secret at rest.** I1 forbids storing `t`.

Drawing a fresh scalar and persisting it satisfies 1 and 2 and fails 3.
Holding a fresh scalar only in memory satisfies 1 and 3 and fails 2; it would
reclassify every restart cut before the first claim from `Claims` to `Refunds`,
which is correct protocol behaviour but silently amends the canonical scenario
matrix.

## Decision

**Derive `t` instead of drawing or storing it.**

    t = BLAKE2b-256(
          "DOM-INTEROP/F7/ROUTE-SCALAR-DERIVATION/V1\0"
          || len(seed) || seed
          || binding_digest
          || counter
        )

    binding_digest = BLAKE2b-256(
          "DOM-INTEROP/F7/ROUTE-SCALAR-BINDING/V1\0"
          || scenario_index || session_id || dom_chain_id || bitcoin_chain_id
        )

    T = t·G

`seed` is the claiming wallet's own recovery phrase, which is already under
that wallet's self-custody and already survives restarts. The counter advances
only in the negligible case where the digest falls outside `1..n-1`, keeping
the derivation total rather than emitting a non-canonical scalar.

This satisfies all three forces. Nothing new is written down, so I1 holds in
substance and not merely in letter. The scalar is unpredictable to anyone
without the wallet seed. It recomputes byte-identically after any restart,
preserving restart safety and byte-identical retransmission (I7). Domain
separation and session binding give one wallet an independent scalar per route
(I6).

## Consequences

- `live_fresh.rs` no longer contains any adaptor scalar or point. `T` is
  computed from the derived scalar and threaded into the settlement terms.
- Before the scalar finalises any claim, `T = t·G` is reasserted against the
  point the manifest already committed to; a substituted point fails closed.
- The seed file is authenticated as an owner-only, single-link, bounded regular
  file beneath an owner-only `0700` parent before it is read, and the bytes are
  zeroized as soon as the scalar is derived.
- All 240 canonical scenario rows remain reachable; the matrix needs no
  amendment.

## Laboratory scope and the production boundary

This laboratory necessarily drives both participants from one process, so the
orchestrator opens the claiming wallet's seed directly. That is the one aspect
of this decision that must not be copied into production.

A production implementation must perform the identical derivation **inside the
wallet**, exposing only `T` and an opaque finalisation capability, so the
orchestrator never observes seed material at all. The derivation, its domains,
and its bindings are unchanged; only the execution boundary moves. Until that
boundary exists, no acceptance evidence produced here may be presented as
production evidence.

## Alternatives rejected

- **Store a freshly drawn scalar.** Implemented first, then withdrawn: it
  contradicts I1 as written, and no reading of decision 7 accommodates a
  component taking custody of `t`.
- **Keep the scalar in memory only.** Normatively clean, but it makes every
  pre-claim restart cut end in refund, which silently amends the canonical
  matrix and removes the restart coverage the gate is meant to prove.
- **Custody `t` in the official Wallet as a new stored object.** Rejected for
  the same reason as the first alternative: decision 6 names the wallet as part
  of the product, so the wallet is a component and I1 binds it.

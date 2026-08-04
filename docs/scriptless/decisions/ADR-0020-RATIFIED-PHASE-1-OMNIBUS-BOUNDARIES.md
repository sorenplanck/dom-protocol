# ADR-0020 — Ratified Phase 1 omnibus boundaries

Status: **ACCEPTED**

Date: 2026-08-04

## Context

NAR-002 closes the remaining Phase 1 assignments for authoritative chain and
transaction adapters, participant and session identifiers, transcript naming,
degenerate-point policy, exact G1a/G1b exposure bytes, and the distinction
between cryptographic and session-bound adaptor pre-signatures.

The exact NAR-002 bytes have SHA-256
`b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5`.
The adjacent detached signature verifies under DOM release Minisign public key
`RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3` with trusted
timestamp `1785878139`.

## Evidence

- **NORMATIVE DOCUMENT:** `docs/scriptless/source-guides/normative/amendments/NAR-002-phase-1-omnibus-normative-closure.en.md`
- **DETACHED RATIFICATION:** the adjacent `.minisig` verified before code changes.
- **AUTHORITATIVE DOM CODE:** `dom_consensus::derive_chain_id`,
  `dom_consensus::scriptless_transaction_template_bytes_v1`,
  `dom_consensus::scriptless_kernel_message_digest_v1`, and the unchanged
  `dom_crypto::schnorr_challenge`/verifier boundary.

## Decision

NAR-002 is the byte authority for the following G1a boundaries:

- production chain IDs are obtained from authenticated genesis data through
  `dom_consensus::derive_chain_id`; synthetic chain IDs exist only under test
  or fuzz feature resolution;
- participant identifiers, session identifiers, contract kind, protocol
  roster ordering, signing-roster mapping, and transcript domains use the
  exact NAR-002 tags and framing;
- complete transaction-template bytes are projected by `dom-consensus` while
  omitting only existing signature bytes; no existing DOM serialization is
  changed;
- nonce commitments, binding factors, and DOM challenges continue through the
  authoritative tagged hash and challenge functions with direct nonzero scalar
  parsing and no retry or parity normalization;
- ClaimAdaptor uses `R_hat = R + T`; Funding and Refund use `R_hat = R` and do
  not encode an absent adaptor point as an identity or sentinel;
- the cryptographic adaptor pre-signature core is exactly 65 bytes, while the
  session-bound transport object is exactly 162 bytes;
- durable exposure permits are exactly 252 bytes and separately identify
  commitment, reveal, and partial-signature exposures; each permit binds the
  exact outbound digest; and
- degenerate scalars and identity aggregate points fail closed before public
  exposure.

## Alternatives considered

- Accepting arbitrary chain IDs in the production context constructor was
  rejected because it bypasses authenticated local chain state.
- Reusing ordinary transaction serialization as the template projection was
  rejected because it includes mutable signature bytes.
- Treating the 65-byte core and 162-byte session object as interchangeable was
  rejected because it removes required session binding.
- Keeping the earlier six-field in-memory signing permit was rejected because
  it was not the ratified 252-byte G1b contract.

## Consequences

The G1a code now has exact types and adapters for all independently implementable
NAR-002 boundaries. Durable issuance of three exposure permits, witness
receipts, nonce tombstones, and consume-before-export remain G1b responsibilities
and must be proven at integration. Independent intermediate vector comparison
also remains outside this branch.

## Compatibility

No consensus rule, transaction wire encoding, persisted block, genesis value,
network magic, PoW rule, or existing verifier changed. `dom-adaptor` depends on
`dom-consensus` only to call the ratified authoritative adapter functions and
still has no direct `k256` dependency.

## Risks

- Incorrect G1b permit issuance could still violate lifecycle safety even when
  the 252-byte permit parses correctly.
- Self-generated tests do not satisfy the independent-vector gate.
- Platform and extended sanitizer evidence remain separately required.

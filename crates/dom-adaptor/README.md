# dom-adaptor

`dom-adaptor` is the integrated Phase 1 G1a/G1b semantic boundary for DOM Scriptless
Contracts. Its production code depends on `dom-crypto` for every cryptographic
primitive, does not depend directly on `k256`, and does not depend on Wallet,
storage, witness, transport, or application crates.

The current implementation provides:

- ratified closed `PurposeV1`, `DirectionV1`, and `SigningPhaseV1` registries;
- validated immutable `SessionContextV1` with exact canonical encoding;
- the ratified secret two-nonce KDF through DOM's authoritative hash and scalar boundaries;
- opaque pre-authorization and authorized one-shot nonce-pair ownership;
- participant-bound partial signing, verification, and aggregation;
- closed, versioned Funding, Claim Adaptor, and Refund purposes;
- canonical fixed-width commitment, reveal, partial-signature, and adaptor
  pre-signature payloads;
- frozen tagged commitment and collective binding transcripts;
- pre-signature verification, adaptation, and extraction through a narrow
  arithmetic API owned by `dom-crypto`;
- final verification through DOM's unchanged Schnorr verifier.

The signed input fixture is a production-conformance input set, not independent
output evidence. Independent two-nonce/aggregation vectors and review remain a
separate G1a gate requirement. The G1b durable nonce lifecycle remains outside
this crate. The implementation is not production-authorized until both G1a and
G1b pass their gates.

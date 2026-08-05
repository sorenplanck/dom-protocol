# dom-adaptor

`dom-adaptor` is the Phase 1/G1a integration boundary for DOM Scriptless
Contracts. Its production code depends on `dom-crypto` for every cryptographic
primitive and does not depend directly on `k256`.

The current implementation provides:

- closed, versioned Funding, Claim Adaptor, and Refund purposes;
- canonical fixed-width commitment, reveal, partial-signature, and adaptor
  pre-signature payloads;
- frozen tagged commitment and collective binding transcripts;
- pre-signature verification, adaptation, and extraction through a narrow
  arithmetic API owned by `dom-crypto`;
- final verification through DOM's unchanged Schnorr verifier.

The crate intentionally does not derive secret nonce pairs. The secret
two-nonce KDF, independent two-nonce/aggregation vectors, cumulative session
transcript discriminants, and G1b durable nonce lifecycle remain blocked or
pending. The implementation is not production-authorized until both G1a and
G1b pass their gates.

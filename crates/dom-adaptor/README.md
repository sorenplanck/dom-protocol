# dom-adaptor

`dom-adaptor` is the planned Phase 1 integration boundary for DOM Scriptless Contracts.

This bootstrap intentionally exposes no adaptor-signature, two-nonce, or Nonce Vault API. Curve arithmetic, point parsing, challenges, Schnorr signatures, canonical serialization, hashing and final verification must be imported from the authoritative DOM crates after the normative inputs and Gate G1 fixtures are frozen. No parallel cryptographic implementation is permitted.

Production use is blocked until both G1a (pure cryptography) and G1b (vault, budgets, journal, remote witness and rollback resistance) pass.

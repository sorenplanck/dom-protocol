# dom-adaptor

`dom-adaptor` is the Phase 1 integration boundary for DOM Scriptless Contracts.

The crate owns the storage-independent Nonce Vault lifecycle contract. Its
production implementation belongs to Wallet V3; this crate never opens wallet
storage or implements a witness transport. The contract deliberately leaves the
byte-exact receipt protocol and all measured budget values to later accepted
specifications.

Curve arithmetic, point parsing, challenges, Schnorr signatures, canonical
serialization, hashing, and final verification remain owned by authoritative
DOM crates. No parallel cryptographic implementation is permitted.

Production use is blocked until both G1a (pure cryptography) and G1b (vault, budgets, journal, remote witness and rollback resistance) pass.

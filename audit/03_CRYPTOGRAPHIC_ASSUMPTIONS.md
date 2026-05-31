# DOM Protocol Cryptographic Assumptions

## Purpose

This file defines cryptographic assumptions the auditor must preserve. Any uncertainty in these areas must be treated as security-critical.

## Expected Primitives

Update with exact implementation details after repository inspection.

- Pedersen commitments.
- Range proofs.
- Schnorr or equivalent signatures for kernels.
- Secure hashing for block headers, transactions, kernels, and identifiers.
- Deterministic serialization for consensus objects.
- Cryptographically secure randomness for key generation and nonce generation.

## Assumptions to Verify

### Commitments

- Commitment arithmetic must correctly enforce value conservation.
- Blinding factors must not leak.
- Commitment collisions must be computationally infeasible.
- Aggregation must not allow value inflation.

### Range Proofs

- Every confidential output must have a valid range proof unless explicitly exempted by consensus.
- Range proof verification failure must reject the transaction or block.
- Proof parameters must be fixed and deterministic where consensus-critical.

### Kernel Signatures

- Kernel signatures must bind to the correct transaction/kernel message.
- Signature verification failure must reject the transaction or block.
- Excess commitments must be validated.
- Replay across incompatible contexts must not be possible.

### Hashing and Serialization

- Consensus hashes must use canonical serialization.
- Non-canonical encodings must not produce divergent state across nodes.
- Hash inputs must include all consensus-critical fields.
- No debug-only, platform-dependent, map-order-dependent, or locale-dependent serialization may affect consensus.

### Randomness and Keys

- Wallet key generation must use secure randomness.
- Nonces must not be reused where that compromises signatures.
- Secrets must not be logged.
- Test keys and development secrets must not be used in production paths.

## Cryptographic Red Flags

- Replacing cryptographic validation with structural checks.
- Ignoring signature or proof errors.
- Allowing unverifiable commitments for convenience.
- Using non-cryptographic RNG for secret material.
- Logging private keys, seeds, blinding factors, or raw secret material.
- Changing serialization without migration and consensus review.


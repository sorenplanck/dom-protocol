# DOM Protocol Forbidden Files

## Purpose

This file lists files or categories that Codex/AI must not modify without explicit authorization from the user.

## Absolute Rule

Do not edit, delete, rename, regenerate, or reformat any file listed here unless the user explicitly authorizes the exact file and exact change.

## Categories Treated as Forbidden by Default

Until exact repository paths are confirmed, treat these categories as protected:

### Genesis and Network Identity

- Genesis block definitions.
- Mainnet chain parameters.
- Network identifiers.
- Checkpoints.
- Hardcoded seeds for production networks.

### Consensus Rules

- Block validation logic.
- Transaction validation logic.
- Difficulty adjustment.
- Emission schedule.
- Coinbase maturity.
- Chain selection.
- Reorg state transition.
- UTXO state mutation.

### Cryptography

- Commitment verification.
- Range proof verification.
- Kernel signature verification.
- Hashing and serialization of consensus objects.
- Key derivation and seed handling.

### Persistence

- Chain database schema.
- State migration logic.
- UTXO database layout.
- Wallet database schema.

### Release and Deployment

- Mainnet release scripts.
- CI gates for security validation.
- Docker or deployment files used for production.
- Build scripts that define production binaries.

## Exact File List To Fill After Recon

After inspecting the repo, populate this section with exact paths.

```text
# Example format:
# crates/dom-chain/src/consensus.rs
# crates/dom-chain/src/genesis.rs
# crates/dom-chain/src/difficulty.rs
# crates/dom-crypto/src/commitment.rs
# crates/dom-wallet/src/seed.rs
```

## Change Authorization Template

A user authorization must be explicit, for example:

```text
I authorize changes to crates/dom-chain/src/consensus.rs only to add missing validation for duplicate inputs. Do not alter genesis, difficulty, emission, or serialization.
```


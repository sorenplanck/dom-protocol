# DOM Wallet V0 Foundation Invariants

## Scope

This document covers the wallet foundation shipped in `crates/dom-wallet` for the conservative protocol-validation phase.

## Guaranteed

- `wallet.dat` is always encrypted at rest with Argon2id-derived ChaCha20Poly1305 keys.
- The BIP-39 mnemonic phrase is never persisted in plaintext.
- Deterministic wallets persist only the 64-byte BIP-39 seed bytes, and only inside the encrypted payload.
- New deterministic wallets use 24-word BIP-39 phrases only.
- `WalletDir` remains self-contained: encrypted state, config, lockfile, journal, and CLI access state all live under one directory.
- Transaction lifecycle state is journal-first for `Built`, `Confirmed`, `Canceled`, and `Reorged` events.
- Restore from the same phrase plus the same scan source yields the same recovered owned-output set.
- V1 wallets remain readable; V2 wallets are explicitly version-tagged and reopenable.

## Non-Goals In This Phase

- Full address-based receive flow is not finalized yet.
- CLI restore does not scan a live node yet; it recreates the encrypted deterministic wallet offline.
- Interactive receive recovery and non-coinbase output recovery are deferred.
- Background wallet daemons and persistent unlocked sessions are intentionally not introduced.

## Risks Still Open

- The current spend flow still operates on output blindings rather than a finalized address protocol.
- In-memory owned outputs already contain secret blindings, so `lock` is an execution-state control, not a full memory scrubbing boundary.
- Full node-backed sync and balance recomputation after external reorgs remain dependent on later sync/RPC phases.

# Initial Threat Model

## Protected assets

- independent DOM Contracts seed and private keys;
- one-shot signing and proof nonces;
- signing and blinding shares;
- exact authorized outbound bytes;
- irreversible nonce tombstones and monotonic revisions;
- contract database integrity and restore state.

## Adversaries and failures

- a malicious counterparty that reorders, mutates, duplicates, or replays messages;
- concurrent local processes racing the same nonce reservation;
- process death at every persistence boundary;
- old, truncated, reordered, or divergent backups;
- malformed points, scalars, canonical records, and oversized inputs;
- application callers attempting to forge or reuse export authority;
- accidental coupling to the ordinary DOM Wallet or an unapproved DOM revision;
- diagnostic, panic, crash, or fuzz output that leaks secret material.

## Required controls

- closed canonical codecs and fail-closed parsing;
- one-shot secret ownership and export capabilities;
- consume-before-export with exact-byte persistence and irreversible tombstones;
- compare-and-swap revisions and exclusive writer locking;
- restore union where the most irreversible state wins;
- no plaintext secret persistence before a ratified storage-cryptography boundary;
- no mainnet funding path;
- reproducible tests, fault injection, fuzzing, and independent review.

## Residual risk

No external audit has completed. Storage encryption, the public DOM adapter pin,
numeric operational policy, and cross-platform durability evidence remain open.
Passing local tests cannot authorize production or real funds.

# Node integration

Status: `IMPLEMENTED_AND_DETERMINISTICALLY_VALIDATED`; live execution is opt-in and has not been performed by this repository.

`dom-wallet-chain::DomHttpChainSource` is the only production node source used by `WalletService`. It binds reads to the DOM Protocol wallet-safe HTTP contract at revision `f10667d86196daf4599eff6074a7abf73b6ed55a`:

* `GET /health` and `GET /chain/identity` establish the node identity.
* `GET /block/{height_or_hash}`, `GET /chain/ancestry`, and bounded `GET /chain/scan` establish canonical scan evidence.
* `POST /tx/submit` receives only the already persisted canonical transaction bytes.
* `GET /tx/{hash}` is advisory mempool evidence only. An absent entry is never interpreted as rejection.
* `GET /kernel/{excess}` is targeted public evidence only; confirmation is still applied from the canonical scan block that contains the exact excess.

The adapter uses blocking bounded-timeout requests, an 8 MiB response limit, strict JSON DTO decoding, lower-case fixed-size hex decoding, exact chain ID/genesis/network validation, and typed redacted errors. Protocol names are `regtest`, `testnet`, and `mainnet`; the wallet maps its private-testnet profile to `regtest` and public-testnet profile to `testnet`.

## Submission and reconciliation

Finalization validates and persists canonical transaction bytes, the local transaction hash, kernel excess, reservations, and change descriptor before submission. Submission durably enters `SUBMITTING` before `POST /tx/submit`. A successful node response must include the exact persisted local hash; a mismatch leaves the uncertainty-safe state in place. Accepted/relayed becomes `SUBMITTED`; accepted/not-relayed becomes `ACCEPTED_NOT_RELAYED`; a transport, timeout, malformed response, or hash mismatch remains `SUBMITTING` for exact-byte retry.

`GET /tx/{hash}` changes state only on positive mempool evidence (`IN_MEMPOOL`). Missing evidence is a no-op. Canonical scan applies public input commitments to already known local descriptors, applies public output commitments only to already persisted output descriptors, and maps exact kernel excesses to sender transactions. It never creates an owned output from an arbitrary public commitment. Recipient output evidence confirms the persisted recipient descriptor and receiver transaction exactly once.

The wallet re-reads its cursor block when already at the tip, so close/reopen synchronization revalidates canonical evidence instead of producing an empty scan. Reorg handling remains the existing ScanTarget and kernel-reconciliation path; no live reorg is forced.

## Limitation

This repository has no approved seed/output-recovery construction for scan-only outputs. A live Wallet A must therefore already hold an encrypted local output descriptor and blinding created by the wallet's existing transaction flow. The runner refuses to fabricate one.

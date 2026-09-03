# Build and Run

Status: PHASE_1B_A_TRANSACTION_ENGINE

The Phase 1A foundation and Phase 1B-A manual transaction engine are
experimental and unaudited. They support local wallet lifecycle, strict node
identity, deterministic mock synchronization, and canonical manual DOM slate
request/response/finalization. The engine is not automatic transport or live
VPS confirmation evidence. Backup export, restore, migration, and mining
confirmation are not implemented.

## Rust checks

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

For the focused Phase 1B-A boundary, use:

```bash
cargo test -p dom-wallet-protocol -p dom-wallet-core
CARGO_TARGET_DIR=/tmp/dom-wallet-v3-phase1b-a-target cargo test --manifest-path src-tauri/Cargo.toml --all-targets
```

## Frontend checks

The frontend has no third-party runtime dependency in Phase 1A.

```bash
cd frontend
npm run typecheck
npm test
npm run build
```

## Desktop shell

```bash
cargo run -p dom-wallet-tauri-shell
```

The shell has a native Tauri v2 entry point, invoke handler, and production frontend integration. The UI source is bundled from `frontend/`; do not place passwords, root material, nonce material, contexts, or credentials in browser storage or frontend diagnostics.

The `Manual exchange` panel uses the versioned `dom-slate-v1` text envelope.
It persists sender and recipient contexts in encrypted wallet state before an
external slate is exposed. Only a finalized immutable transaction may be sent
through `POST /tx/submit`; the wallet never calls `/wallet/spend`. See
[Transaction engine](TRANSACTION_ENGINE.md) and
[Manual slate exchange](MANUAL_SLATE_EXCHANGE.md).

The validated release executable was generated as ephemeral local evidence at `/tmp/dom-wallet-v3-tauri-final.7byijG/release/dom-wallet-tauri-shell`. The current Tauri configuration does not generate an installer bundle; packaging remains follow-up work.

## Wallet and node behavior

Tests create disposable wallet directories and use synthetic network identities. Real configuration must provide exact authoritative network, chain ID, and genesis ID. The configured endpoint placeholder is intentionally invalid. A non-mutating node probe requires a negotiated DOM adapter; the current adapter returns a typed capability error rather than inventing a response format.

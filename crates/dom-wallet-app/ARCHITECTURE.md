# DOM Wallet App Architecture

## Batch 1 Scope

This crate introduces the desktop application foundation only.

Implemented in this batch:

- window lifecycle
- splash/bootstrap
- deterministic wallet create
- deterministic wallet restore
- explicit unlock/lock
- node status refresh
- balance dashboard
- journal-backed history view
- local application-state persistence

Deferred to later batches:

- finalized receive workflow
- send transaction flow
- sync orchestration beyond manual status refresh
- reorg-driven UI warnings
- richer history classification

## Layering

- `app.rs`: egui UI only
- `runtime.rs`: wallet session, node RPC, screen transitions, derived view state
- `storage.rs`: crash-safe local app config persistence

## Safety Rules

- no protocol logic in widgets
- no background wallet mutation
- no hidden retries
- no plaintext wallet secrets in app storage
- wallet lock is represented by dropping the in-memory `WalletDir` session

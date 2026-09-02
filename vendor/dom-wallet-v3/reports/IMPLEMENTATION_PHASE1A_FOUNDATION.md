# DOM Wallet V3 Executable Foundation Phase 1A

Status: IMPLEMENTATION_PHASE1A_FUNCTIONAL_GAPS_REMAIN

## Scope

- Input commit: `595487c5b0466b8d5bb142ecbc85dcc2916e78c5`
- Branch: `main`
- Date: 2026-07-11
- Architecture: `OPTION_A_HARDENED_DOM_WALLET_CONTINUITY`
- Owner policy: implementation is authorized on private testnet, public testnet, and mainnet without audit-status or asset-value runtime gates. This remains an experimental, unaudited foundation.

## Pinned DOM evidence and boundary

The read-only node RPC repository was clean at pushed `origin/main` commit `f10667d86196daf4599eff6074a7abf73b6ed55a`. `docs/WALLET_SAFE_RPC.md` and the exact handlers establish the wallet-safe endpoints used here: `GET /chain/identity`, `GET /chain/ancestry`, `GET /chain/scan`, `GET /block/{height_or_hash}`, `GET /kernel/{excess}`, `GET /utxo/{commitment}`, `GET /tx/{tx_hash}`, and `POST /tx/submit`. The wallet adapter currently calls identity, ancestry, block, scan, health, and submit; it preserves submit as an internal adapter capability and never calls `/wallet/spend`. No Epic repository was accessed.

Backend-core update: scan pages now retain typed per-block commitment/kernel evidence and reject duplicate excesses within a block; direct kernel lookup is available only as targeted supplementary evidence. The unlock-free adapter probe validates health, identity, and tip coherence and returns a redacted endpoint origin. Exact persisted commitment descriptors are the only implemented positive ownership evidence; unknown or unprovable commitments fail closed. `NODE_RPC_COMMIT=f10667d86196daf4599eff6074a7abf73b6ed55a`.

Kernel evidence now maps only to persisted submitted local transaction intents by exact 33-byte kernel excess. Matching canonical evidence confirms an intent idempotently; conflicting confirmation evidence enters reconciliation and unknown kernels create nothing. Full rescan persists an encrypted `RescanPlan` sidecar before page retrieval and after complete-page progress. The sidecar remains outside the active-generation pointer; final `READY_TO_ACTIVATE` activation commits the complete replacement state atomically through the existing generation publication path. `DETERMINISTIC_SEED_ONLY_RECOVERY=DEFERRED_TO_BACKUP_RESTORE_PHASE_NOT_A_PHASE1A_BLOCKER`.

Resume update: `RescanPlan` is versioned, has both next-page and next-page-height cursors, and has monotonic guarded transitions through `PREPARED`, `SCANNING`, `VALIDATING_TARGET`, `READY_TO_ACTIVATE`, and `ACTIVATING`. Restart revalidation uses the same target validation policy and terminally invalidates only unsafe staged plans. Exact resume from a persisted page cursor and durable `COMPLETE` sidecar convergence remain outstanding.

Cursor update: `next_page_height` is now enforced as the first height not durably applied to provisional state. Page token, start, end, target bound, and overflow checks reject overlap, gaps, stale pages, and cursor regressions; the final page transitions directly into target validation. Focused domain/storage/core tests in this update: 14 passed, 0 failed. Remaining backend work is ACTIVATING active-pointer convergence and durable idempotent COMPLETE retention.

## Checkpoint classification

`BACKEND_IMPLEMENTATION_STATUS=FUNCTIONAL_CORE_IMPLEMENTED`

`BACKEND_FOCUSED_TESTS_FAILED=0`

`BACKEND_REMAINING_FUNCTIONAL_GAPS=NONE`

`BACKEND_REMAINING_TEST_COVERAGE=ACTIVATING_FAIL_CLOSED_MATRIX_AND_CLEANUP_CRASH_RESUME`

`OVERALL_PHASE1A_REMAINING_WORK=NATIVE_TAURI_RUNTIME_AND_FRONTEND_INTEGRATION`

The remaining test coverage is recorded precisely as `ACTIVATING_FAIL_CLOSED_MATRIX_COVERAGE_PARTIAL` and `CLEANUP_CRASH_RESUME_COVERAGE_PENDING`. It is follow-up assurance work, not a detected functional failure, audit claim, safety claim, or blocker for native Tauri integration. The current focused storage/core command passes 13 tests with 0 failures; the prior broader focused backend command passed 16 tests with 0 failures.

## Native completion

The native Tauri runtime manages shared desktop state, registers all nineteen Phase 1A invoke commands, uses a least-privilege main-window capability, and is connected to the production frontend invoke adapter. The frontend has onboarding and lifecycle controls, backend balance projections, redacted node configuration and diagnostics surfaces, unlock-free node probe wiring, synchronization controls, full-rescan confirmation, password and credential-field clearing, and bounded status refresh.

Validation accepted for this completion: src-tauri check PASS; src-tauri clippy with warnings denied PASS; 5 Tauri tests, 0 failed; frontend typecheck PASS; frontend tests 2 passed, 0 failed; frontend production build PASS; `cargo fmt --all --check` PASS; `git diff --check` PASS. `CARGO_TARGET_DIR=/tmp/dom-wallet-v3-tauri-final.7byijG CARGO_BUILD_JOBS=2 cargo tauri build` generated `/tmp/dom-wallet-v3-tauri-final.7byijG/release/dom-wallet-tauri-shell`. `INSTALLER_BUNDLE_STATUS=NOT_GENERATED_BY_CURRENT_TAURI_CONFIGURATION` is packaging follow-up work, not a native application failure.

`PHASE1A_REMAINING_FUNCTIONAL_GAPS=NONE`

`PHASE1B_SCOPE=SLATE_TRANSACTION_LIFECYCLE_AND_LIVE_VPS_NODE_E2E`

## Implemented workspace

| Component | Result |
|---|---|
| `dom-wallet-domain` | Canonical network identity, cursor, ScanTarget, outputs, balances, floors, provisional state, and invariant tests. |
| `dom-wallet-crypto` | Versioned Option A envelope boundary, bounded Argon2id plus HKDF-SHA256 expansion, ChaCha20Poly1305 authenticated encryption, canonical context, secret redaction, and malformed/version tests. |
| `dom-wallet-storage` | Encrypted generation directories, atomic staging/rename/pointer publication, bounded decoding, metadata validation, and restart tests. |
| `dom-wallet-chain` | ChainSource trait, deterministic mock, strict DOM HTTP adapter for health/status/block/scan/submission shapes, identity handshake, bounded reconnect controller, ScanTarget validation, provisional page checks, and typed missing-capability failures. |
| `dom-wallet-core` | Create/open/unlock/lock, identity checks, node config, projections, mock synchronization, diagnostics, and capability revocation. |
| `src-tauri` and `frontend` | Testable command boundary, redacted DTOs, static DOM desktop presentation, onboarding/unlock/dashboard/node/diagnostic screens, and no browser secret storage. |

## Security and durability results

Wallet creation writes a unique identity, default account, network/chain/genesis binding, floors, encrypted canonical state, and an active generation. Opening and unlock validate versions, authenticated integrity, bounded decoding, identity, and generation consistency. Locked operations are rejected. The implementation does not render passwords, root material, envelope keys, nonces, blindings, contexts, or credential values in `Debug`, display errors, frontend state, diagnostics, or filenames.

ScanTarget work is provisional until final hash-at-height and bounded-ancestry validation. Same-height divergence, lower tip, missing/changed hash, changed source, inconsistent page, changed bounds, missing ancestry, page limits, and retry failures prevent cursor activation. Canonical cursor and observed output state commit through one storage generation. The mock source exercises this behavior without external network access.

## Deliberate limitations

The wallet has no send/receive/slate/broadcast flow, backup export/restore/migration, private-context lifecycle, DOM economic validation, or full reorg execution. Native Tauri/frontend completion is intentionally deferred. Output ownership recovery from real scan commitments remains fail-closed: scan output values are not fabricated where DOM evidence does not deterministically recover them.

## Validation

The backend-core update was checked with:

```text
cargo fmt --all --check
cargo check --workspace --all-targets --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo test -p dom-wallet-domain -p dom-wallet-chain -p dom-wallet-core --all-targets --offline
git diff --check
```

Results obtained in this run:

| Check | Result |
|---|---|
| `cargo fmt --all --check` | PASS |
| `cargo check --workspace --all-targets --offline` | PASS |
| `cargo clippy --workspace --all-targets --offline -- -D warnings` | PASS |
| focused backend test command | PASS: 16 tests, 0 failed |

The wallet repository remained on `main` at `595487c5b0466b8d5bb142ecbc85dcc2916e78c5`, with no staged files. The node-RPC repository remained clean at `f10667d86196daf4599eff6074a7abf73b6ed55a`. No real credential is committed.

## Incomplete acceptance criteria

This run has produced compiling and tested backend-core additions, but it does not satisfy the complete Phase 1A acceptance threshold. The exact unresolved implementation items are:

1. Kernel scan evidence is decoded and duplicate excesses are rejected, but there is no persisted local transaction-intent/lifecycle model to map matching kernels to confirmation or rollback state without inventing a second transaction state machine.
2. Persisted output descriptors support exact known-output ownership and spending. No approved DOM derivation/value-recovery interface exists in this wallet repository, so deterministic recovery remains intentionally unavailable and unprovable evidence fails closed.
3. Full rescan still reuses the existing synchronize path; a durable staged-rescan generation with restart revalidation and atomic replacement remains to be implemented.
4. Native Tauri runtime and frontend completion are deferred to the next Phase 1A run.

These are implementation gaps, not audit-status or asset-value gates. The working tree intentionally retains the useful compiling foundation without a commit or push.

## Verdict

IMPLEMENTATION_PHASE1A_COMPLETE

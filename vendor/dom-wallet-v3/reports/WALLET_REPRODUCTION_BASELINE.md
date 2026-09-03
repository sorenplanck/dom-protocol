# DOM Wallet V3 Finding Reproduction Baseline

Captured before production edits on 2026-07-27 (America/Sao_Paulo).

## Repository identity

- Branch: `audit/close-all-wallet-findings-20260727T235128Z`
- HEAD: `bd85ad0e5b52d10ef5c0fb700932231034bc9987`
- `git describe --always --dirty --tags`: `wallet-v0.2.6`
- `Cargo.lock` SHA-256:
  `ed06fcf579bdf03b2bfff464f45e52462bcac47e56c372660bd5813c653fab60`
- Workspace version: `0.2.6` (`Cargo.toml`)
- Frontend version: `0.2.6` (`frontend/package.json`)
- Tauri version: `0.2.6` (`src-tauri/tauri.conf.json`)

Exact upstream revisions (no pin was changed while capturing this baseline):

- `dom-core`, `dom-crypto`, `dom-consensus`, `dom-serialization`, `dom-tx`,
  `dom-slate`, `dom-config`, `dom-chain`, `dom-node`, `dom-pow`,
  `dom-wallet-core-api`, and `dom-wallet-recovery`:
  `28ba3cefc9fbc913f126336482662528c68a7d8c`
- Experimental `dom-sidecar`:
  `ab45a2944f22fe00f9b12984354f0d5d7cdd229a`

## CI, package scripts, and pre-edit test inventory

Workflows:

- `.github/workflows/stabilize-wallet.yml`: locked metadata, fmt, workspace
  check, workspace clippy with warnings denied, workspace all-target tests,
  `cargo audit`, `cargo deny check`, frontend install/test/typecheck/build, and
  packaged native-bridge smoke tests.
- `.github/workflows/release-wallet.yml`: frontend install/test/build, locked
  metadata/tree, fmt, targeted clippy and Rust tests, audit/deny, release
  workflow contract test, package build, and native-bridge smoke tests.

Frontend scripts:

- `npm run typecheck --prefix frontend` -> `node --check main.js`
- `npm test --prefix frontend` -> `node --test tests/*.test.mjs`
- `npm run build --prefix frontend` -> syntax checks plus `node build.mjs`

Pre-edit inventory:

- 297 Rust `#[test]` declarations across workspace source and targets.
- 29 frontend `test(...)` declarations in four test files.
- `npm test --prefix frontend`: 4/4 file suites passed, 0 failures.
- A pre-edit `cargo test --workspace --all-targets --locked -- --list` attempt
  was interrupted after producing no output; the declaration inventory above
  is therefore the frozen Rust count. The full executable suite is a mandatory
  closure gate.

## Finding reproductions

### C1 — present

- Path/symbol: `src-tauri/src/lib.rs::DesktopApplication::mining_start`;
  `crates/dom-wallet-embedded-core/src/miner.rs::network_ready`.
- Command/test: `rg -n 'ibd_progress_percent' src-tauri crates`.
- Observed: the production mining gate requires the pinned node's
  `ibd_progress_percent >= 100`, while wallet production code only reads that
  metric. No real embedded-node `mining_start` regression test exists.
- Expected: mining uses authoritative, production-updated readiness; zero
  peers and peer-ahead states fail, while explicitly permitted connected
  canonical genesis can pass.
- Root cause: a test-only/non-authoritative metric was treated as the
  production readiness oracle.

### C2 — present

- Path/symbol: `crates/dom-wallet-core/src/lib.rs::transaction_cancel`,
  `submit_transaction`, and `apply_submission_outcome`.
- Command/test: `sed -n '1320,1410p' crates/dom-wallet-core/src/lib.rs`.
- Observed: cancellation denies only five lifecycle variants and releases
  reservations for `RetransmitRequired`, `ReconciliationRequired`, `Reorged`,
  and `Failed`; no persisted exposure field exists.
- Expected: exposure is durably persisted before network I/O and a centralized
  exhaustive decision never releases possibly broadcast reservations.
- Root cause: cancellation infers network exposure from an incomplete
  lifecycle denylist.

### C3 — present

- Path/symbol:
  `crates/dom-wallet-core/src/lib.rs::transaction_send_create_with_identities`;
  `crates/dom-wallet-core-protocol/src/lib.rs::CanonicalSlate::new_recoverable`.
- Command/test:
  `rg -n 'expires_at_height' crates/dom-wallet-core{,-protocol}/src/lib.rs`.
- Observed: creation validates `amount` but not expiry against the canonical
  tip; protocol construction passes expiry as its own current-height
  validation argument and there is no maximum lifetime.
- Expected: validate before reservation, require `expiry > canonical_tip`, use
  checked arithmetic and a bounded lifetime, and revalidate every later
  transaction boundary.
- Root cause: expiry validation is delegated with the wrong height and is
  absent at the reservation boundary.

### C4 — present

- Path/symbol: `WalletService::slate_request_export`,
  `slate_response_export`, and `slate_response_import`.
- Command/test:
  `rg -n 'lifecycle = TransactionLifecycle::(Request|Response)' crates/dom-wallet-core/src/lib.rs`.
- Observed: export/import assigns lifecycle variants unconditionally; QR
  encoding calls those mutating exports.
- Expected: one exhaustive transition API; export/encoding is read-only and
  idempotent; submitted-or-later states never regress.
- Root cause: lifecycle writes are distributed and exports mix serialization
  with mutation.

### C5 — present

- Path/symbol: `src-tauri/src/lib.rs::node_synchronization_status`;
  `frontend/status.js::nodePresentation`.
- Command/test:
  `sed -n '1740,1805p' src-tauri/src/lib.rs; sed -n '1,80p' frontend/status.js`.
- Observed: `ready == true` can produce `READY` with zero peers; peer height is
  suppressed/filled ad hoc rather than represented as an authoritative state.
- Expected: pure table-derived `Stopped`, `Starting`, `WaitingForPeers`,
  `UnknownPeerHeight`, `ConnectedAtGenesis`, `Synchronizing`, `Ready`, `Stale`,
  and `Failed`, with no frontend fallback to local height.
- Root cause: process/mutex readiness and synchronization readiness are
  conflated.

### A1 — present

- Path/symbol: `WalletService::unlock`, `StorageError`, and
  `impl From<CoreError> for CommandError`.
- Command/test:
  `rg -n 'StorageError::Crypto|InvalidPassword|WALLET_STORAGE_FAILED' crates src-tauri`.
- Observed: an authenticated-decryption failure from a wrong password is
  collapsed into the generic storage error mapping; metadata corruption,
  payload corruption, writer lock, and absence are not separate command
  domains.
- Expected: stable redacted authentication and storage-corruption codes proven
  with real encrypted fixtures.
- Root cause: storage crypto and structural errors lose context at the core and
  command boundaries.

### A2 — present

- Path/symbol: `WalletService::ensure_closed`; frontend locked gate controls.
- Command/test:
  `rg -n 'ensure_closed|wallet-close|wallet-lock' crates/dom-wallet-core/src/lib.rs frontend`.
- Observed: locked/incomplete states reject opening another wallet and the gate
  offers no close/switch recovery path.
- Expected: A -> lock -> close -> B works without restart, and interrupted
  create/restore offers authenticated resume or abort.
- Root cause: the lifecycle gate has no managed switching transition exposed
  at onboarding.

### A3 — present

- Path/symbol: `DesktopApplication::mining_start` and
  `stop_mining_worker`.
- Command/test:
  `sed -n '1230,1410p' src-tauri/src/lib.rs`.
- Observed: worker errors leave `MINING_ERROR`; stop sets `MINING_STOPPING` and
  relies on a departed worker to reset state. Join panic maps to a generic
  unavailable error.
- Expected: explicit restartable states, finalizer cleanup, typed panic
  conversion, reaped handles, idempotent stop, and deterministic restart.
- Root cause: cleanup is owned only by the happy worker tail.

### A4 — present

- Path/symbol: `DesktopApplication::synchronization_start_live`.
- Command/test:
  `sed -n '1450,1490p' src-tauri/src/lib.rs`.
- Observed: the command calls `synchronize_live` synchronously while holding
  the global service mutex; pause is only a flag checked before entry.
- Expected: prompt worker start, responsive commands, durable-cursor
  pause/resume, bounded atomic commits, and safe shutdown.
- Root cause: synchronization has no background worker state machine.

### A5 — present

- Path/symbol: `WalletService::last_error`, `unlock`, `diagnostics`, and
  `require_mining_cursor_gate`.
- Command/test:
  `rg -n 'last_error' crates/dom-wallet-core/src/lib.rs src-tauri/src/lib.rs`.
- Observed: unlock failure writes the shared error slot used by sync, node
  presentation, and mining readiness; a successful sync is the unrelated
  clearing operation.
- Expected: independent authentication, storage, lifecycle, node, peer, sync,
  mining, submission, and updater error domains.
- Root cause: one mutable string is used as cross-domain health state.

### A6 — present

- Path/symbol: `DesktopApplication::embedded_node_start_mainnet`,
  `embedded_node_status`; frontend node polling.
- Command/test:
  `rg -n 'node_started|last.*status|embedded_node_status' src-tauri/src/lib.rs frontend/main.js`.
- Observed: `node_started` is not cleared when the backend dies and successful
  status freshness is not recorded; UI can retain a stale success view.
- Expected: stale state, last-success timestamp, dead-node reconstruction, and
  repeatable restart without a stale READY badge.
- Root cause: a start-attempt boolean substitutes for supervised process
  health.

### A7 — present

- Path/symbol: `src-tauri/src/main.rs::wallet_open`;
  `DesktopApplication::wallet_open`.
- Command/test:
  `sed -n '370,405p' src-tauri/src/main.rs`.
- Observed: public IPC accepts an arbitrary raw path without managed-root
  containment, canonicalization, symlink, staging, or structural checks.
- Expected: public commands resolve only a validated catalog entry; raw-path
  opening is internal.
- Root cause: the public command exposes a low-level storage path API.

### A8 — present

- Path/symbol: `SeedRestoreService::begin`, `SeedRestoreSession::publish`.
- Command/test:
  `rg -n 'seed-restore|remove_dir_all|abort' crates/dom-wallet-core-restore/src/lib.rs`.
- Observed: staging is mode 0700 and resumable, but there is no abort API,
  startup discovery, or safe cleanup for abandoned/error stages.
- Expected: authenticated resume/abort, discovery, crash restart, and cleanup
  where safe while sensitive buffers remain zeroized.
- Root cause: restore implements resume/publish but not lifecycle management
  for abandoned sessions.

### M1 — present

- Path/symbol: `src-tauri/src/lib.rs::COMMAND_NAMES`, Tauri
  `generate_handler!`, and frontend `ALLOWED_COMMANDS`.
- Command/test:
  `rg -n 'COMMAND_NAMES|wallet_open_named|wallet_list|len\\(\\), 67' src-tauri frontend/main.js`.
- Observed: Rust declares 67 names and omits `wallet_open_named`/`wallet_list`;
  Tauri/frontend expose 69 and a test hardcodes the stale length.
- Expected: one source of truth with exact-set and duplicate tests.
- Root cause: three manually maintained registries drifted.

### M2 — present

- Path/symbol: updater node/peer endpoint constants, validation helpers,
  `DesktopApplication::check_node_now`, and updater UI.
- Command/test:
  `rg -n 'NODE_UPDATE_ENDPOINT|PEER_UPDATE_ENDPOINT|validate_peer_manifest|check_node_now' crates src-tauri frontend`.
- Observed: node and peer feed capability has no complete production call
  chain; UI exposes constant/misleading status while the signed wallet updater
  is a distinct working subsystem.
- Expected: preserve wallet updater and either fully wire signed local-tested
  node/peer feeds or remove the dead capability end-to-end.
- Root cause: placeholder capability escaped into product status/contracts.

### M3 — present

- Path/symbol: every `DesktopApplication::service.lock()` boundary and
  `WalletService::reconcile_once`.
- Command/test:
  `rg -n 'service\\.lock\\(\\)|\\.take\\(\\)' src-tauri/src/lib.rs crates/dom-wallet-core/src/lib.rs`.
- Observed: poison maps forever to retryable `Unavailable`; operations that
  temporarily `take()` state can lose it across panic; no fatal/recovery state
  or reconstruction boundary exists.
- Expected: panic containment, explicit `RecoveryRequired`, no blind poison
  continuation, disk reconstruction, and typed non-retryable failure.
- Root cause: mutex poison is treated as a transient lock error and temporary
  ownership has no unwind guard.

### M4 — present

- Path/symbol: `DesktopApplication::update_safe_point_available` and
  `perform_update_cycle`.
- Command/test:
  `sed -n '720,750p' src-tauri/src/lib.rs; sed -n '230,270p' src-tauri/src/main.rs`.
- Observed: locked/closed wallets are called safe; the check is separate from
  shutdown/apply and ignores active mining, sync, backup, restore, and critical
  transaction activity.
- Expected: one atomic `ActivityCoordinator` lease blocks both directions of
  the update race.
- Root cause: safe point is a non-atomic lifecycle snapshot.

### M5 — present

- Path/symbol: `src-tauri/src/main.rs::check_updates_now` and
  `perform_update_cycle`; `UpdateControl::automatic_updates`.
- Command/test:
  `sed -n '120,290p' src-tauri/src/main.rs`.
- Observed: manual “check” passes install=true and can download, close, install,
  and restart; automatic update is hardcoded true and has no persisted setter.
- Expected: distinct check/download/verify/apply phases, explicit apply consent,
  and persisted preference.
- Root cause: update discovery and activation are one operation.

### M6 — present

- Path/symbol: updater download path in `src-tauri/src/main.rs` and
  `crates/dom-wallet-updater`.
- Command/test:
  `rg -n 'timeout|bytes\\(\\)|Content-Length|validate_download' src-tauri/src/main.rs crates/dom-wallet-updater/src/lib.rs`.
- Observed: one request timeout covers download, response buffering is
  unbounded relative to the signed size before allocation, and transport/size/
  hash/signature errors are not kept as distinct user-visible domains.
- Expected: separate timeouts, bounded secure streaming file, checked count,
  fsync, and distinct fail-closed verification errors.
- Root cause: artifact transfer is implemented as a buffered request preceding
  validation.

### M7 — present

- Path/symbol: `RecoveryMetadata::phrase_confirmed`,
  `WalletService::recovery_phrase_confirmed`, spend/mine/export/submit paths,
  and frontend secret state.
- Command/test:
  `rg -n 'phrase_confirmed|clearPhrase|recovery_phrase' crates src-tauri frontend`.
- Observed: confirmation is written but never enforced; unconfirmed wallets can
  continue sensitive operations and frontend phrase state can outlive the
  ceremony.
- Expected: a durable policy gate for spend/mine/export/submit plus
  authenticated resume/abort and deterministic frontend clearing.
- Root cause: ceremony persistence is informational rather than authorization.

### M8 — present

- Path/symbol: `DesktopApplication::slate_qr_encode`,
  `slate_qr_decode_frame`; `dom-wallet-protocol::qr_encode_transport`.
- Command/test:
  `rg -n 'DOMQR4|qr_encode_transport|QrReassembler' src-tauri crates/dom-wallet-protocol`.
- Observed: the protocol crate contains an unused bounded multipart helper, but
  the public desktop contract bypasses it, emits one potentially huge
  `DOMQR4` frame, stores one mutable string, and QR export mutates lifecycle.
- Expected: public bounded versioned multipart with message identity,
  part/count/total/hash validation and role/replay tests; encoding is read-only.
- Root cause: the production boundary reimplemented and weakened the existing
  transport adapter.

### M9 — present

- Path/symbol: `src-tauri/src/lib.rs::list_wallet_names`,
  `WalletDirectory::create`.
- Command/test:
  `sed -n '2190,2220p' src-tauri/src/lib.rs; sed -n '80,130p' crates/dom-wallet-storage/src/lib.rs`.
- Observed: any non-hidden validly named directory is listed without checking
  metadata, generations, pointer, corruption, symlink escape, or incomplete
  creation; direct create can leave a name-consuming partial directory.
- Expected: only structurally valid managed wallets are selectable, invalid
  entries are separately diagnosable, and create activates atomically from
  0700 staging.
- Root cause: the catalog validates names and directory type, not wallet
  structure or publication state.


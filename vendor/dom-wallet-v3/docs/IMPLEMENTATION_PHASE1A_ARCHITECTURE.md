# Implementation Phase 1A Architecture

Status: IMPLEMENTED_FOUNDATION

Phase 1A implements an executable, experimental DOM Wallet V3 foundation under `OPTION_A_HARDENED_DOM_WALLET_CONTINUITY`. It preserves the DOM desktop direction: the `src-tauri` shell owns presentation commands only, while the canonical wallet model remains below the command boundary. It does not implement send, receive, slate finalization, submission, backup export, restore, migration, or a negotiated production DOM-node scan adapter.

## Workspace boundaries

| Component | Actual responsibility |
|---|---|
| `dom-wallet-domain` | Network identity, canonical cursor, ScanTarget, accounts, outputs, balances, state invariants, floors, and provisional-to-canonical transition. |
| `dom-wallet-crypto` | `HARDENED_DOM_WALLET_CONTINUITY_V1`, bounded Argon2id then HKDF-SHA256 expansion boundary, ChaCha20Poly1305 envelope boundary, versioned canonical context, and non-Debug secret wrapper. |
| `dom-wallet-storage` | Wallet metadata, encrypted generations, active-generation pointer, bounded decoding, atomic staging/rename/publication, and reopen validation. |
| `dom-wallet-chain` | ChainSource trait, deterministic mock, strict DOM HTTP client for the pinned REST DTO shapes, connection/reconnect state, ScanTarget acquisition/validation, provisional bounded pages, and typed capability errors. |
| `dom-wallet-core` | Create/open/unlock/lock lifecycle, backend projections, node configuration, handshake, mock synchronization, diagnostics, and capability revocation. |
| `src-tauri` | Redacted command-facing DTOs and a testable desktop-shell boundary. It contains no consensus, storage, or cryptographic logic. |
| `frontend` | Static DOM dark-bronze-paper presentation for onboarding, unlock, dashboard, node status, synchronization, settings direction, and diagnostics. It does not store secrets in browser storage. |

## Wallet lifecycle and state

`WalletService` uses `CLOSED`, `LOCKED`, `UNLOCKING`, `UNLOCKED`, `SYNCHRONIZING`, `DEGRADED`, and `ERROR` lifecycle states. Create generates root material with the operating-system CSPRNG, writes a first encrypted generation atomically, and exposes only a locked summary. Open validates metadata before unlock. Unlock authenticates the bounded envelope and validates identity, schema, profile, generation, and state invariants. Lock drops unlocked state and password wrapper and revokes protected operations.

The state binds one `NetworkIdentity`: `PRIVATE_TESTNET`, `PUBLIC_TESTNET`, or `MAINNET`, each with exact chain and genesis identifiers supplied by the caller/configuration. There is no audit-status or asset-value runtime gate. Network, chain, and genesis mismatches fail closed.

## Storage and secret profile

The versioned state context includes the wallet identity, chain ID, genesis identity, generation, and `DOM-WALLET-V3-STATE-V1` construction marker. The Option A envelope derives bounded password material with Argon2id and expands it with HKDF-SHA256 before ChaCha20Poly1305 use. `dom-wallet-crypto` enforces the profile version and bounded KDF parameters before decryption. State is encrypted and authenticated before it is decoded. The profile is an implementation foundation, not an audit claim; future compatible profile changes require an explicit migration.

Generations are written into a staging directory, synced where supported, renamed into a complete generation, then published through a bounded active-generation pointer and metadata. Reopen validates that pointer, metadata, envelope context, state generation, wallet identity, and network identity agree. Incomplete or mixed generations are rejected; a crash can leave only the prior complete generation or the new complete generation active.

## ChainSource and synchronization

`ScanTarget` is the authoritative wallet-domain record: target height, target block hash, source identity, finite scan bounds, and evidence version. Acquisition requires matching node-proven identity and target height-and-hash. Pages are collected only as provisional data. Final validation reacquires identity and hash-at-height; a higher tip additionally requires bounded (maximum 256-step) ancestry evidence, never finality. A lower tip, source change, changed/missing target hash, missing ancestry, inconsistent page, changed bounds, page limit, or transport failure prevents activation. Only the final state commit writes the cursor and scan-derived outputs together.

The deterministic `MockChainSource` is the local test adapter. The DOM HTTP client strictly decodes `/health`, `/chain/identity`, `/chain/ancestry`, `/block/{height-or-hash}`, `/chain/scan`, `/kernel/{excess}`, and `/tx/submit`, including fixed-width scan commitments and per-block duplicate kernel-excess rejection. Identity requires the exact pushed RPC API/protocol version, network, magic, chain ID, genesis, and coherent nonzero tip. `live_probe` is node-only and returns a credential-free endpoint origin plus identity/capability evidence without opening a wallet.

Output ownership currently has one authoritative fail-closed classifier: an exact scanned commitment match against a persisted local output descriptor is `KnownLocalOutput`; all other commitments are `NotOwnedOrUnprovable`. The foundation contains no approved DOM derivation/value-recovery interface, so it deliberately cannot fabricate a deterministically recoverable output. Descriptor matches can be marked spent through the canonical output state transition.

Local transaction intent persists a 33-byte canonical kernel excess before submission. Canonical page evidence can only confirm an existing submitted intent; unknown excesses never create transactions. Identical evidence is idempotent, while conflicting confirmation evidence enters reconciliation. Full rescan uses an encrypted sidecar `RescanPlan` outside the active-generation pointer. Its `PREPARED`, `SCANNING`, and `READY_TO_ACTIVATE` progress preserves the prior canonical generation; only final activation publishes replacement cursor, outputs, and transaction lifecycle changes in one ordinary generation commit. `DETERMINISTIC_SEED_ONLY_RECOVERY=DEFERRED_TO_BACKUP_RESTORE_PHASE_NOT_A_PHASE1A_BLOCKER`.
The sidecar is versioned and carries exact target identity plus page-number and next-page-height cursors. Its transition guard permits only `PREPARED → SCANNING → VALIDATING_TARGET → READY_TO_ACTIVATE → ACTIVATING → COMPLETE`, with `INVALIDATED` and `FAILED` terminal. A restart first revalidates the target through the existing identity/hash/ancestry policy; invalid evidence transitions only the staged sidecar to `INVALIDATED` and leaves the active canonical generation unchanged. Automatic page replay/resume remains incomplete.

`next_page_height` is the first height not yet durably represented by provisional effects. A page must begin exactly there, use the expected page token, end at or before the target, and advances the cursor only after its whole effect is staged; the final page enters `VALIDATING_TARGET` immediately. Activation stages a complete encrypted generation before publishing the existing active pointer; recovery converges from either pointer state and retains a durable idempotent `COMPLETE` plan.

Backend implementation status: `FUNCTIONAL_CORE_IMPLEMENTED`. The canonical lifecycle, encrypted atomic generations, real identity/ancestry adapter, ScanTarget synchronization, kernel evidence, redacted node probe, known-output matching, and staged full-rescan activation are implemented. Remaining backend assurance coverage is `ACTIVATING_FAIL_CLOSED_MATRIX_COVERAGE_PARTIAL` and `CLEANUP_CRASH_RESUME_COVERAGE_PENDING`; these are follow-up tests, not detected functional failures or blockers for native desktop integration. Overall remaining Phase 1A work is `NATIVE_TAURI_RUNTIME_AND_FRONTEND_INTEGRATION`.

The native Tauri v2 runtime now manages one `DesktopApplication` state and registers the nineteen Phase 1A invoke commands. Its single main-window capability grants only `core:default`; no shell, process, filesystem, HTTP, clipboard, updater, notification, global-shortcut, dialog, or frontend-network plugin is enabled. The frontend uses a production-only native invoke adapter, redacted backend projections, guarded forms, explicit full-rescan confirmation, and bounded status refresh. Backend assurance coverage remains follow-up work; Phase 1A functional gaps are none.

## Tauri and frontend boundary

The shell exports command-shaped methods for application status, wallet lifecycle, account projection, redacted node configuration, probe, synchronization, diagnostics, and shutdown. Password validation occurs before delegation; returned command errors discard underlying secret-bearing details. The frontend clears password inputs after submission, keeps no `localStorage` or `sessionStorage`, shows experimental/unaudited status without functional gating, and projects backend balances rather than calculating authority in JavaScript.

## Phase 1B dependencies

Phase 1B must add a fully negotiated DOM node transport after authoritative response fixtures are available; actual Tauri `invoke_handler` wiring and packaging; durable private transaction contexts; DOM-native send/receive and slate lifecycle; backup/restore/migration; full reorg executor; and the approved vectors and hardened secret-domain construction details. Those omissions are not represented as completed functionality.

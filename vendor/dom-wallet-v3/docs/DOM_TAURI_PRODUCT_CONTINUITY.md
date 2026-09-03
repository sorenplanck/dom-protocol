# DOM Tauri Product Continuity

**Status:** ACCEPTED_PRODUCT_DIRECTION
**Pinned DOM evidence commit:** `aa7f389a157af1b1a486dcb7e27cb80e7b543de3`
**Scope:** V3 product and desktop-architecture continuity; this document selects no cryptographic construction.

## Authority and continuity rule

The governing order is DOM consensus and approved protocol semantics, then validated DOM Wallet V1/V2 product continuity, then Epic engineering properties only where the DOM evidence demonstrates a gap. V3 remains a DOM wallet: DOM semantics > validated DOM Wallet continuity > Epic gap-solving strategy.

Tauri and the established DOM desktop product direction are the selected V3 baseline. This is not an authorization to preserve unsafe V1/V2 state ownership, storage, or secret handling.

## Pinned desktop evidence

The pinned tree contains a Tauri 2 desktop application under `wallet-desktop/`.

| Product area | Pinned evidence | V3 continuity decision |
| --- | --- | --- |
| Desktop shell and package identity | `wallet-desktop/src-tauri/tauri.conf.json:3-10` (`productName`, `identifier`, frontend distribution); `src-tauri/Cargo.toml` | Retain Tauri desktop direction and DOM Wallet identity. |
| Capability boundary | `wallet-desktop/src-tauri/capabilities/default.json:1-` (`default` main-window capability); `src-tauri/src/lib.rs:1449-1485` (`invoke_handler`) | Replace broad command exposure with explicit V3 capability APIs; do not expose domain secrets. |
| Rust desktop orchestration | `src-tauri/src/lib.rs`; `wallet_manager.rs`; `managed_storage.rs`; `node_host.rs`; `node_rpc.rs`; `settings.rs`; `auto_backup.rs`; `wallet_registry.rs` | Preserve native orchestration, platform integration, managed storage, and local-node presentation while refactoring state ownership behind V3 interfaces. |
| Frontend direction | `wallet-desktop/ui/index.html`, `ui/src/main.js`, `ui/src/screens.js`, `ui/src/api.js`, `ui/styles.css` | Preserve DOM information architecture and dark-bronze-paper visual language; do not substitute an Epic CLI or UI. |
| Visual assets | `ui/assets/dom-coin.png` and the Cormorant Garamond, Spectral, and JetBrains Mono assets | Preserve the DOM symbol and established typography direction. The V3 repository banner remains the authoritative V3 visual asset. |

The pinned application uses a lightweight frontend served by the Tauri shell rather than an Epic-derived product surface. `ui/src/api.js:30-114` maps renderer actions to Tauri commands. `ui/src/main.js:172-175` chooses login or first-run onboarding. `ui/src/screens.js:95-185` contains named login and onboarding flows; `screens.js:188-191` describes create flow with managed wallet storage and per-wallet node setup.

## Product workflows to preserve

V3 must preserve the product concepts, not the old internal implementation:

- First-run onboarding, wallet creation, recovery-phrase restore, full-backup restore, opening an existing wallet, and explicit lock/unlock. Pinned evidence: `ui/src/api.js:32-47`, `screens.js:166-184`.
- Account and wallet presentation, balance and maturity presentation, send, receive, slate exchange, transaction history, and local-node controls. Pinned command bridge evidence: `ui/src/api.js:69-114`; backend command registration: `src-tauri/src/lib.rs:1449-1485`.
- Backup and recovery surfaces that distinguish seed recovery from full backup. `screens.js:118` and `174-176` explicitly communicate that random receive/change material requires the encrypted backup; V3 must retain this honesty and improve it with the V3 backup contract.
- Settings, node configuration, logs/diagnostics, notifications, automatic-backup failure presentation, and recovery uncertainty. Evidence: `ui/src/screens.js:15-49`, `api.js:102-113`.
- Native file dialogs and backend-controlled paths. `ui/src/api.js:81-100` records that backup dialogs are opened by the backend and that the renderer does not receive vault paths in the normal flow.

## Visual and interaction identity

V3 retains the DOM Wallet identity, official DOM symbol, dark-bronze-paper presentation, friendly named-wallet onboarding, balance-first home presentation, explicit recovery surfaces, and local-node management. It must not copy Epic UI, CLI structure, Owner/Foreign API surfaces, transport UX, visual language, or workflow design.

The existing frontend already provides useful protected properties: `ui/src/screens.js:11-13` states that passwords and phrases are not stored in its shared settings object; `api.js:66-68` limits registry results to names and networks; `api.js:151-171` maps errors to user-safe messages rather than raw stack traces. V3 shall preserve those properties while moving enforcement into typed backend capability contracts.

## V3 architecture boundary

The following ownership boundary is mandatory.

| Layer | V3 responsibility | Prohibited responsibility |
| --- | --- | --- |
| Tauri shell | Window lifecycle, capability registration, native dialogs, platform integration, event delivery | Consensus decisions, fund-secret ownership, raw cryptographic operations |
| Frontend presentation | Rendering, user intent capture, uncertainty and recovery status, accessibility | Root secrets, private nonces, blindings, raw private contexts, state/backup keys, canonical state mutation |
| Capability APIs | Typed, least-privilege commands; request correlation; redacted result types | Returning secret-bearing records or allowing renderer-selected persistence paths |
| Lifecycle orchestration | Durable intent ordering, retries, restart recovery, external-effect coordination | Replacing canonical domain invariants with UI state |
| Canonical domain state and storage | Output, transaction, reservation, context, non-reuse, generation, and recovery invariants | Frontend-owned mutable mirrors |
| ChainSource and DOM adapters | Bounded DOM evidence, DOM transaction/slate compatibility, typed failure | UI-defined chain trust or cryptographic-domain decisions |
| Cryptography | Approved secret-domain construction, canonical encoding, secret wrappers | Unapproved labels, mappings, KDF profiles, or envelope parameters |

The frontend never receives root secrets, private nonces, blindings, raw contexts, state-encryption keys, backup keys, or long-lived capability credentials. Tauri command responses, events, logs, errors, telemetry, support bundles, filenames, and public identifiers must redact such material. Password and recovery-phrase entry may cross a narrowly scoped unlock/create/restore command boundary only; they must not enter frontend state stores, diagnostics, or retained command history.

## Backend couplings V3 must replace

The pinned app is useful product evidence, but several implementation couplings are not V3 authority:

- The renderer command bridge is not a V3 authorization model. V3 will replace it with explicit least-privilege capabilities and scoped unlock sessions.
- V1 `ReceiveRequest.blinding_hex` at `crates/dom-wallet/src/types.rs:269-281` is an exposed secret representation and is rejected. No V3 UI or IPC response may reproduce it.
- The V1 password-only backup path at `crates/dom-wallet/src/backup.rs:171-220` and the legacy password-derived coinbase fallback documented in `crates/dom-wallet/src/wallet.rs:2102-2152` are compatibility evidence, not V3 constructions.
- V2 encrypted state, full-backup, and pending-slate persistence are protected properties to preserve only through the independently reviewed DEC-V3-SECRET-DOMAINS construction.

## UX for uncertainty, recovery, and migration

The UI must visibly distinguish: locked, unlocked, pending external effect, provisional chain evidence, recovery required, restored-from-seed limitations, full-backup completeness, migration uncertainty, and fail-closed errors. It must never imply confirmed balance, recoverability, or transaction completion when canonical evidence is absent.

Migration retains familiar onboarding and account presentation, but V2 import must remain explicit, dry-run capable, non-destructive until activation, wrong-chain rejecting, and clear about local-only secrets or contexts that cannot be reconstructed from a seed. Credential rotation may alter V3 access material but must never alter authoritative DOM fund derivation.

## Testability, accessibility, and platform constraints

V3 must make presentation testable through typed view models and deterministic capability results. Required test categories include permission denial, secret-redaction checks, lock/session expiry, command replay and concurrency, native-dialog cancellation, offline and recovery state, stale-chain uncertainty, restart while a lifecycle is pending, migration failure, keyboard-only navigation, readable contrast, scalable text, and platform-safe path handling. No UI test may require a renderer to observe a secret.

## Epic exclusions and constrained use

Epic contributes only verified gap-solving properties recorded in [the Epic secret-domain study](../reports/EPIC_SECRET_DOMAIN_REFERENCE_STUDY.md): persistence before dependent external effects, retryable private context, deletion after completion, repair/recovery categories, privilege separation, hostile-input handling, and assurance categories. Epic does not supply the V3 desktop shell, visual design, DOM transaction/slate formats, cryptographic parameters, APIs, transports, or product workflow.

## Implementation constraints

1. Retain Tauri and the DOM product identity; do not replace them with an Epic product architecture.
2. Preserve stable product workflows behind V3 capability APIs and canonical domain services.
3. Keep all consensus, secret-domain, state, storage, and ChainSource authority outside the frontend.
4. Apply the approved StableView policy and DOM-W2-SYNC-001 through backend state, then render typed uncertainty to the user.
5. Do not implement DEC-V3-SECRET-DOMAINS until independent cryptographic review selects or rejects a family and specifies the construction and vectors.

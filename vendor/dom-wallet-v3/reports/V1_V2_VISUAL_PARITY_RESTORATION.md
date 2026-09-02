# V1/V2 Visual Parity Restoration

## Read-only visual references

- V1 visual reference: `/home/leonardov/dom-protocol`, tag `wallet-v0.3.1`, commit `e03128d215c110cb3c6a44a53f679d36baaebc08`.
- V2 visual reference: `/home/leonardov/dom-protocol`, tag `wallet-v2.0.1`, commit `1c143ad9231d6ee0b014bf89188eea5a9e1cd4a6`.
- Both were verified as DOM Wallet desktop sources by their `origin` remote (`github.com:sorenplanck/dom-protocol`), Tauri product name `DOM Wallet`, desktop UI source, DOM asset set, and the visible `Unlock`, `Create wallet`, and `Locate existing wallet` flows.

They are temporary read-only design references. DOM Wallet V3 does not import, build, link, package, or require either source tree at runtime or release time; both may be removed after visual acceptance.

## Visual source matrix

| V3 screen | Primary authority | Restored visual vocabulary |
|---|---|---|
| Wallet access | V2, confirmed by V1 | centered coin, 520px access card, bronze primary action, ghost actions for Create/Locate |
| Dashboard | V2 | 220px sidebar, DOM brand lockup, bronze balance hierarchy, cards and status pills |
| Pay / exchange | V2 | card layout, text/QR exchange panels, bronze/ghost action hierarchy |
| Receive / history | V2 | native empty state, transaction-oriented card/table vocabulary |
| Node / settings | V2 | ordinary status card with technical values restricted to advanced disclosure |
| Responsive shell | V2 | sidebar-to-grid breakpoint and compact entry layout |

Source measurements retained: dark palette `#0c0807`, `#15100c`, `#1d160f`, bronze highlight `#c89a63`, 10px card radius, 220px desktop sidebar, 880px content maximum, 1180×820 reference window, 120px entry symbol, and Cormorant/Spectral hierarchy with local/system fallbacks.

## Required thirteen-screen coverage matrix

| # | Legacy source | Legacy path | V3 destination | Legacy user actions | Existing V3 Tauri commands | Status |
|---:|---|---|---|---|---|---|
| 1 | V2 `wallet-v2.0.1` | `wallet-desktop/ui/src/screens.js:renderLogin` | Access screen | unlock by saved wallet name, locate, create, restore | `wallet_open`, `wallet_unlock`, `wallet_create_recoverable`, `wallet_restore_from_mnemonic` | CONSOLIDATED_AND_VALIDATED |
| 2 | V2 `wallet-v2.0.1` | `screens.js:renderWelcome` | Access screen | create, restore, open | `wallet_create_recoverable`, `wallet_open`, `wallet_restore_from_mnemonic` | CONSOLIDATED_AND_VALIDATED |
| 3 | V2 `wallet-v2.0.1` | `screens.js:renderCreate` | Create panel | create encrypted wallet and confirm recovery phrase | `wallet_create_recoverable`, `wallet_recovery_phrase_confirm` | RESTORED_AND_VALIDATED |
| 4 | V2 `wallet-v2.0.1` | `screens.js:renderRestore` | Restore panel | restore wallet from recovery phrase | `wallet_restore_from_mnemonic` | RESTORED_AND_VALIDATED |
| 5 | V2 `wallet-v2.0.1` | `screens.js:renderOpen` | Locate panel | choose/open existing wallet | `wallet_open` | RESTORED_AND_VALIDATED |
| 6 | V2 `wallet-v2.0.1` | `screens.js:renderUnlock` | Access screen | unlock existing wallet | `wallet_unlock` | RESTORED_AND_VALIDATED |
| 7 | V2 `wallet-v2.0.1` | `screens.js:renderDashboard` | Dashboard | view balances, lock, synchronization | `wallet_summary`, `wallet_lock`, `synchronization_*` | RESTORED_AND_VALIDATED structurally |
| 8 | V2 `wallet-v2.0.1` | `screens.js:renderPay` | Pay | create, exchange, finalize, submit/retry/cancel | `transaction_*`, `slate_*` | RESTORED_AND_VALIDATED structurally |
| 9 | V2 `wallet-v2.0.1` | `screens.js:renderReceive` | Receive | import request and create/export response | `slate_request_import`, `slate_response_create`, `slate_response_export` | CONSOLIDATED_AND_VALIDATED in Pay exchange |
| 10 | V2 `wallet-v2.0.1` | `screens.js:renderHistory` | History | view transaction status/detail | `transaction_list`, `transaction_detail_redacted` | RESTORED_AND_VALIDATED structurally |
| 11 | V2 `wallet-v2.0.1` | `screens.js:renderNode` | Node status | embedded lifecycle and synchronization | `embedded_node_status`, `synchronization_*` | RESTORED_AND_VALIDATED structurally |
| 12 | V2 `wallet-v2.0.1` | `screens.js:renderBackup` | Backup screen | export/restore encrypted wallet backup | `wallet_backup_export`, `wallet_backup_import` | RESTORED_AND_VALIDATED |
| 13 | V2 `wallet-v2.0.1` | `screens.js:renderSettings` | Settings | settings, lock/error diagnostics | `diagnostics_redacted`, `wallet_lock` | RESTORED_AND_VALIDATED structurally |

Rows 1 and 2 consolidate the V2 Login/Welcome navigation into the existing V3
access surface; every V2 action is available there. Restore and backup are now
backed by narrowly scoped V3 commands, not by frontend state or legacy code.

## V3 files changed

- `frontend/index.html`
- `frontend/styles.css`
- `frontend/main.js`
- `frontend/build.mjs`
- `frontend/assets/dom-coin.png` (DOM-owned V2 visual asset only)
- `frontend/tests/visual-parity.test.mjs`
- `frontend/tests/release-workflow.test.mjs`
- `crates/dom-wallet-domain/src/lib.rs` (optional recovery eligibility metadata)
- `crates/dom-wallet-core/src/lib.rs` (BIP-39 creation/restore and backup service methods)
- `crates/dom-wallet-storage/src/lib.rs` (authenticated atomic backup container)
- `src-tauri/src/lib.rs` and `src-tauri/src/main.rs` (five narrow recovery/backup commands)
- `docs/WALLET_RECOVERY_AND_BACKUP.md`
- `reports/V3_RECOVERY_BACKUP_SECURITY_REPORT.md`
- `.github/workflows/release-wallet.yml`
- `docs/RELEASING.md`

V1/V2 remain visual references only. Wallet V3 uses its embedded DOM Core,
canonical scanner, structured submission, Address v1, recovery Slate v4,
Recovery Capsule v1 outputs, and seed-only restoration. No legacy runtime,
remote HTTP backend, or visual-reference repository is packaged.

## IPC and security proof

`frontend/main.js` retains an explicit V3 command allow-list and uses only
`window.__TAURI__?.core?.invoke`. The view layer does not use browser
persistence, direct fetch, direct node RPC, eval-like execution, or production
mocks. Password and phrase fields are cleared after completion or cancellation.
The phrase is rendered only during the one-time creation ceremony and cleared
when it closes. The interface only renders redacted backend DTOs and retains
uncertainty-safe submission calls.

## Release pipeline

The historical `build-wallet.yml` at both V1/V2 references uses `wallet-v*` tags and native Ubuntu/macOS/Windows Tauri builds. V3 now has an independent tag-only workflow:

- locked `npm ci` and Cargo `--locked` builds from `${GITHUB_REF}`;
- exact tagged commit recorded in the workflow summary;
- Linux AppImage, DEB, RPM; macOS DMG and application archive; Windows EXE and MSI required before upload;
- build jobs have read-only contents permission; only the one publish job has `contents: write`;
- no `release: created` or `release: published` trigger; exactly one post-matrix job creates/updates the release;
- ordinary pushes have no publishing trigger; workflow dispatch builds validation artifacts without publishing;
- no legacy repository is used by the workflow.

Installers are unsigned for the experimental release. Operating-system warnings
are expected. This does not authorize real-fund use.

## Validation

- Thirteen screen contracts are asserted by frontend structural tests.
- The frontend command allow-list exactly matches the 42 Tauri commands.
- Frontend syntax, tests, production build, and static release-workflow tests
  are mandatory release gates.
- Browser-backed 1180x820 screenshots are generated outside the repository.
- V1/V2 source trees are absent from Cargo, npm, Tauri, and workflow inputs.

## Remaining visual differences

The legacy DOM-owned coin image is included. V3 uses system/local font fallbacks
rather than copying legacy font binaries. No legacy code or dependency is
included.

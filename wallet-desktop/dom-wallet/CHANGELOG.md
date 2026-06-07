# Changelog

All notable changes to DOM Wallet are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
semantic versioning where the protocol allows.

## [0.2.0] — V2: Transactional wallet

Purely additive on top of V1. Existing V1 wallets open unchanged — no
migration step, no reinstall, no re-creation. The encrypted `wallet.dat` is
never rewritten.

### Added

- **Send / Receive with two modes**, chosen per transaction:
  - **Mode A — Slatepack** (async, encrypted): `dom1…` ephemeral addresses,
    `BEGINDOMPACK… ENDDOMPACK` envelopes, x25519 + ChaCha20Poly1305 (age-style)
    encryption of the slate to the recipient.
  - **Mode B — Simple** (sync, trusted parties): compact `DOMRR1…` receive
    descriptors with the blinding factor encrypted for the owner.
- **Transaction history** unified across sent / received / coinbase, filterable
  by mode (Slatepack / Simple / Coinbase).
- **Pending-transaction widget** on the Dashboard with clear state indicators
  (waiting for counterparty → awaiting confirmation → confirmed / expired /
  cancelled) and per-transaction cancel.
- **Background expiry** sweep (every 60s) that releases reserved inputs of
  expired sender-side slates via the crate's `cancel_tx`.
- **Settings → Transactions**: default mode, slate/descriptor expiry, advanced
  fee toggle, auto-generate-new-address toggle.
- New Tauri commands (Slatepack: get/generate address, create send, receive,
  finalize; Simple: create receive request, parse/send/cancel descriptor;
  shared: cancel pending, list pending, full history) and lifecycle events
  (`tx://*`, `wallet://pending_changed`).
- New backend modules `slatepack/`, `descriptor/`, `pending/` with unit tests
  (address round-trip, seal/open, envelope encode/decode, descriptor round-trip,
  blinding encryption, sidecar persistence, expiry).
- Frontend components: `ModeSelector`, `AmountInput`, `FeeSelector`,
  `SlatepackInput/Output`, `DescriptorInput/Output`, `PendingTxCard`,
  `PendingWidget`, `ConfirmSendModal`, `TxDetailsModal`.
- `qrcode` dependency for QR display of addresses, slatepacks, and descriptors.

### Design decisions (safety)

- **No parallel pending/locking ledger.** Output reservation and pending state
  use the `dom-wallet` crate's authoritative two-phase reservation and
  `cancel_tx`. V2 only stores UI-facing metadata in a `v2-meta.json` sidecar.
- **Wallet file untouched.** The V1→V2 "migration" is the creation of an empty
  sidecar on first open; the encrypted wallet payload is never rewritten.

### Known limitations (flagged `// VERIFICAR` in source)

- Slatepack response envelopes are not re-encrypted to the sender (slate bytes
  remain protocol-integrity-protected).
- Descriptor owner key (encrypts stored Slatepack keypair secrets at rest) is
  derived locally; the crate does not expose a master key.

### Security (post-audit hardening)

- Slatepack keypair secrets in `v2-meta.json` are now sealed with an Argon2id
  key derived from the wallet password + per-wallet salt (in memory only,
  zeroized on lock), replacing the former path/network-derived key.
- Durable atomic writes (flush+fsync+rename+dir-fsync) with `.bak` snapshots for
  the sidecar and settings; corrupt files are quarantined and surfaced as
  recovery errors instead of silently resetting to empty/defaults.
- `slatepack_finalize` validates a matching outgoing-Slatepack pending record in
  an expected state before broadcasting (fail-closed).
- Amount parsing rejects empty/zero/malformed values; descriptor creation
  rejects `fee_min > fee_max`.
- Mode B blinding field renamed `enc_blinding` → `wrapped_blinding`; it is
  transport obfuscation, not access control (documented + UI warning).
- Explicit CSPRNG for Slatepack ephemeral keys; address docs reconciled to
  x25519. Change-password UI disabled (no rekey API) without a pointless backup.
- CI fails any release tag that still tracks `branch = "main"` for `dom-*`
  crates or lacks a committed `Cargo.lock`.

### Security (deep line-by-line audit follow-up)

- **D-01:** `validate()` now rejects `auto_lock_minutes == Some(0)` (which would
  re-lock the wallet on every watcher tick); use "never" to disable.
- **D-02:** the Receive (Slatepack) UI states that the response leg is not
  encrypted to the sender, advising a private return channel.
- **D-03:** x25519 `seal`/`open` now screen peer keys against the known
  low-order encodings and reject a degenerate all-zero shared secret
  (defense-in-depth; the zero AEAD nonce remains safe via fresh ephemerals).
- **D-04:** `slatepack/encryption.rs` header corrected — x25519 throughout, no
  ed25519↔x25519 conversion.
- **D-05:** documented in-code why loopback-HTTP RPC with a per-launch, never-
  logged `Zeroizing` bearer token is acceptable for the wallet's scope.
- **D-06:** update mandatory-flag now reads STRUCTURED release metadata
  (```dom-release block or JSON `"mandatory"`), falling back to the tag
  heuristic only when absent; version parsing is strict (non-numeric components
  no longer silently coerce to 0).

## [0.1.0] — V1: Mining wallet

- Embedded full DOM node, mining, coinbase rewards, live log streaming,
  onboarding (create / recover), dashboard, history (coinbase), settings,
  auto-backup, auto-lock, GitHub update check, cross-platform installers.

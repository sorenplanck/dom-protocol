# DOM Wallet

The official desktop wallet for [DOM](https://github.com/sorenplanck/dom-protocol) — a privacy-focused, RandomX-mined, Mimblewimble cryptocurrency. DOM Wallet runs a **full DOM node embedded** in the app, mines, and receives coinbase rewards into an encrypted wallet.

> _"Not a store of value. A means of exchange."_

**This is V2 — a transactional wallet.** It runs a full node, mines, holds coinbase rewards, and now sends and receives DOM between users via two interactive modes — **Slatepack** (async, encrypted) and **Simple** (direct receive descriptors). V2 is purely additive on top of V1: the same wallet file opens with no migration, reinstall, or re-creation.

![DOM](src-tauri/assets/logo.png)

---

## What V1 does

- Runs a full DOM node embedded in one process (P2P, consensus, IBD, mining)
- Hosts an encrypted wallet that receives coinbase rewards from local mining
- **Streams the node's logs live** to a dedicated Node tab (the headline feature)
- Start / stop / restart the node and toggle mining from the UI
- Onboarding: create a new 24-word wallet or recover from a BIP-39 seed
- Dashboard: spendable / total / pending balance + coinbase maturity progress
- History: coinbase rewards from local mining
- Settings: network, ports, directories, auto-lock, mining, theme, backups
- Automatic encrypted backup before every wallet write (keeps the last 10)
- Auto-lock after inactivity (configurable)
- Update check via the GitHub Releases API (mandatory hard-fork banner)
- Cross-platform installers built on GitHub Actions (Windows, macOS, Linux)

### What V1 deliberately does **not** do (deferred to V2)

Send, receive-from-others, Slatepack, transaction history beyond coinbase, and pending-transaction management. The Send/Receive tabs are present as "Coming in V2" placeholders, the backend commands return `not_in_v1`, and the event/state types already accommodate them — so V2 is additive.

## What V2 adds

V2 implements interactive send and receive with **two complementary modes**, chosen per transaction:

**Mode A — Slatepack (async, recommended).** Sender and receiver need not be online together. The receiver shares a `dom1…` Slatepack address; the sender builds a slate, encrypts it to that address (x25519 + ChaCha20Poly1305, age-style), and shares a `BEGINDOMPACK… ENDDOMPACK` envelope over any channel. The receiver processes it and returns a response envelope; the sender finalizes and broadcasts. Encrypted in transit, expires if not completed.

**Mode B — Simple (sync, trusted parties).** The receiver generates a compact `DOMRR1…` descriptor (QR-friendly) carrying the commitment and an *encrypted* blinding factor. The sender parses it, picks a fee within the receiver's range, and broadcasts directly. Fewer steps; the descriptor itself is not encrypted in transit, so it is for trusted parties or secure channels (the UI warns).

Both modes feed a unified **transaction history** (sent / received / coinbase, filterable by mode) and a **pending-transaction widget** on the Dashboard with clear state indicators (waiting for counterparty → awaiting confirmation → confirmed / expired / cancelled).

### How V2 reuses the protocol crates (and what it does *not* reimplement)

A deliberate, safety-driven design decision: the `dom-wallet` crate already owns the financial truth, so V2 orchestrates it rather than duplicating it.

- **Output locking & pending state** use the crate's own two-phase reservation (`build_spend_unreserved` → `reserve_built_spend`) and `cancel_tx`. V2 does **not** keep a parallel ledger of locked outputs — that would be the classic Mimblewimble double-spend bug. The crate locks atomically and persists on every change.
- **Wallet file is never rewritten.** The "V1 → V2 migration" is non-destructive by construction: V2-only artifacts (ephemeral Slatepack keypairs, emitted descriptors, UI-facing pending metadata) live in a separate `v2-meta.json` sidecar inside the wallet directory. Opening a V1 wallet simply finds no sidecar and creates an empty one. The encrypted `wallet.dat` is untouched. (The crate already versions its own schema; our app wallets are crate-`V2` already because they are seed-derived.)
- **Slatepack transport** (envelope + encryption) and the **`DOMRR1` descriptor** are the genuinely new pieces V2 implements, because the crate serializes a `Slate`/`ReceiveRequestDescriptor` but does not define the over-the-wire envelope. These are pure transport, fully unit-tested.

### V2 honest limitations (flagged in code as `// VERIFICAR`)

- **Slatepack response sealing.** The receiver's response envelope is not re-encrypted to the sender (the sender's address is not carried in the envelope sent *to* the receiver). The slate bytes are still integrity-protected by the protocol; encrypting the response would require the UI to also capture the sender's address.
- **Descriptor owner key** (used only to encrypt stored Slatepack keypair secrets at rest) is derived locally (network + wallet path) because the crate does not expose its master key.

### A corrected design call on Mode B (Simple)

The brief's Mode B contained an internal contradiction: it required the receive descriptor's blinding factor to be "encrypted with a key only the recipient knows," yet also required the sender to "build the transaction directly using the descriptor." Those cannot both hold — `Wallet::build_spend` needs the recipient blinding **in the clear** (verified in the crate's own `spend_e2e` integration test, where the blinding travels plaintext with the comment *"in prod this would be wallet B over Slatepack"*). The blinding identifies the output the sender is funding, so the sender must learn it to pay.

V2 resolves this the way the protocol actually works: the descriptor carries the blinding wrapped with a key derived from its own public material, so the holder (sender) can recover it — transport obfuscation, not access control. **Confidentiality in Mode B is the channel's responsibility**, which is exactly what the brief assumes elsewhere ("Simple mode is not encrypted; use only with trusted parties or over secure channels"). Users who need confidentiality against the channel use Slatepack (Mode A), which encrypts to the recipient's address. The result: both modes are fully functional, and the security guarantee is stated honestly rather than implied falsely.

---

## Architecture

Five non-negotiable principles, learned from Grin++/Beam:

1. **Single process, separate async tasks.** Node, wallet, log capture, and RPC client all run inside one Tauri process, communicating over tokio channels and Tauri events — no HTTP loopback to external processes for orchestration.
2. **The wallet observes the node, never commands it.** The node owns consensus; the wallet only reads (status over loopback RPC, events). If the wallet hangs, the node keeps mining; if the node pauses, the wallet just stops updating — it never corrupts state.
3. **Secrets are zeroized.** Passwords are wrapped in `Zeroizing` on arrival; the RPC bearer token is generated per launch and never written to disk; the crate's encrypted store keeps seed bytes at rest.
4. **Backup before every write.** A timestamped copy of `wallet.dat` is made before mutating wallet state — a lost blinding factor in Mimblewimble is unspendable money.
5. **Update mechanism from day one.** The app checks GitHub Releases on startup and shows a mandatory banner for hard-fork releases (tags containing `MANDATORY`).

```
Process: DOM Wallet (Tauri)
├── Frontend: React + TypeScript (Vite)
└── Backend (Rust):
    ├── Embedded node task        (dom_node::DomNode::init/run)
    ├── Wallet manager            (wraps dom_wallet::WalletDir)
    ├── Log capture + broadcast   (tracing Layer → ring buffer → Tauri events)
    ├── Local RPC + metrics client (blocking, via spawn_blocking)
    └── Background tasks: status poll, auto-lock, log forward, update check
```

The wallet **reuses** the DOM protocol crates (`dom-wallet`, `dom-node`, `dom-core`, `dom-consensus`, `dom-rpc`) as **git dependencies** — no crypto, consensus, P2P, or wallet logic is reimplemented here. Pin a concrete `rev` in `src-tauri/Cargo.toml` before tagging a release so the wallet and the protocol it embeds are locked together.

---

## Build

### Local

```bash
git clone <this repo>
cd dom-wallet
npm install
npm run tauri dev      # development
npm run tauri build    # production installers
```

The DOM protocol crates are fetched from GitHub automatically (git dependencies); no sibling checkout is needed.

### System dependencies

**Ubuntu/Debian**
```bash
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev \
  clang cmake pkg-config
```

**macOS**
```bash
xcode-select --install
brew install cmake
```

**Windows**
- WebView2 (pre-installed on Windows 10+)
- Visual Studio Build Tools with the C++ workload
- Clang / LLVM (for `randomx-rs`)

### GitHub builds (tag-triggered)

Push a tag to build installers for all three platforms and publish a draft Release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

For a hard-fork release, include `MANDATORY` in the tag so the in-app updater shows a red banner:

```bash
git tag v0.3.0-MANDATORY-HARD-FORK
git push origin v0.3.0-MANDATORY-HARD-FORK
```

Installers produced: `.msi` + `.exe` (Windows), `.dmg` + `.app` (macOS), `.AppImage` + `.deb` (Linux).

---

## Testing

```bash
# Frontend (vitest): format conversion, seed validation, component rendering
npm run test

# Backend (cargo): wallet lifecycle, backup rotation, log buffer, metrics parse,
# update-version comparison, settings round-trip
cd src-tauri && cargo test
```

---

## Security notes

- No telemetry, no analytics, no auto-sent crash reports.
- Only outbound network: DOM P2P, loopback RPC, DNS seeds, and `api.github.com` for update checks.
- `wallet.dat` is created `0600` on Unix; the RPC bearer token lives in memory only.
- The recovery phrase is shown **only at creation**. The encrypted store keeps seed *bytes*, not the words — so the phrase cannot be re-displayed later. Save it when you create the wallet.

### V2 security hardening (post-audit)

An adversarial source audit of V2 drove the following fixes:

- **Sidecar secrets are sealed under a password-derived key.** Slatepack keypair secrets in `v2-meta.json` are encrypted with a key derived from the wallet password via **Argon2id** over a per-wallet random salt, held in memory only and zeroized on lock. Reading `v2-meta.json` no longer reveals those secrets without the password. (The salt itself is non-secret by design.)
- **Durable, fail-closed persistence.** `v2-meta.json` and `settings.json` are written temp→flush→fsync→rename→fsync-dir, keep a `.bak`, and on parse failure are **quarantined** (`.corrupt.<ts>`) with a recovery error — never silently reset to empty/defaults. The owner-key derivation refuses to run against a corrupt sidecar, so a fresh salt is never minted over still-sealed secrets.
- **Finalize is state-validated.** `slatepack_finalize` requires a matching outgoing-Slatepack pending record in an expected state *before* broadcasting; it fails closed otherwise.
- **Input validation.** Amounts must be strictly positive and well-formed (`.5`, `.`, empty, zero all rejected); descriptor creation rejects `fee_min > fee_max`.
- **Mode B honesty.** The descriptor's blinding is `wrapped_blinding` (transport obfuscation recoverable by the holder), not "encrypted" — naming and a non-dismissible UI warning make the trusted-channel requirement explicit. Use Slatepack (Mode A) for channel confidentiality.

### Releasing reproducibly (required)

For local development the `dom-*` crates track `branch = "main"`. **Before tagging a release** you must pin every `dom-*` dependency in `src-tauri/Cargo.toml` to an immutable `rev = "<commit-sha>"` and commit `src-tauri/Cargo.lock`. The CI workflow **fails any tag build** that still contains a `branch =` dom dependency or lacks a committed lockfile, so a release can never silently embed a different protocol than it was tested against (this also matters for hard-fork coordination).

---

## Roadmap

| Feature | Version |
| --- | --- |
| Embedded node, mining, coinbase, live logs, backups, updates | **V1 (this release)** |
| Send (interactive Slatepack) | V2 |
| Receive from other users (slate descriptors) | V2 |
| Full transaction history + pending management | V2 |

V2 is designed to be additive: the backend command surface, event types, and wallet state fields already exist. Implementing the deferred commands and pages ships V2 with no backend rewrite.

---

## Known gaps in V1

- **Change password** is gated behind a `// VERIFICAR` marker: the `dom-wallet` crate does not currently expose a rekey/`change_password` API, so the command verifies the current password and backs up, then reports honestly that re-encryption needs a crate-level API. This is a protocol-team item, not a wallet bug.
- Coinbase detection in the UI relies on `wallet://new_coinbase` events; if the node's event emission for that channel differs from the assumed payload, the History tab will need the real event wired (see `src/lib/events.ts`).

## License

MIT — see [LICENSE](LICENSE). Matches the DOM protocol.

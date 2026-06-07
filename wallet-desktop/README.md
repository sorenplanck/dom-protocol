# DOM Wallet — official desktop wallet with an integrated node

A Tauri v2 desktop application (Rust backend + web frontend) that runs a full
**DOM** node *inside* the wallet, streams the node's logs live, and lets you
create/restore wallets, send and receive DOM, and control mining — without ever
touching a terminal.

> **Not a store of value. A means of exchange.**

This app does **not** reimplement any cryptography, consensus, P2P, or wallet
logic. It depends on the real crates from the
[`dom-protocol`](https://github.com/sorenplanck/dom-protocol) repository
(`dom-wallet`, `dom-node`, `dom-core`, `dom-consensus`, `dom-rpc`, …) by path,
and orchestrates them.

---

## Architecture

```
┌───────────────────────────── DOM Wallet (this app) ─────────────────────────┐
│  Web frontend (ui/)            Rust backend (src-tauri/src/)                  │
│  ─ Onboarding / Unlock         ─ lib.rs        Tauri commands + log streaming │
│  ─ Dashboard                   ─ wallet_manager.rs   wraps dom_wallet::WalletDir│
│  ─ Send / Receive (QR)         ─ node_host.rs        embeds dom_node::DomNode  │
│  ─ History                     ─ settings.rs         DOM_* env / NodeConfig    │
│  ─ Node / Logs (live stream)   ─ log_capture.rs      tracing → UI events       │
│  ─ Settings                    ─ metrics.rs          Prometheus scrape         │
└──────────────────────────────────────────────────────────────────────────────┘
        │                                   │
        │ Tauri IPC (no secrets cross it)   │ in-process
        ▼                                   ▼
  recipient/amount, logs            dom_node::DomNode::init(cfg).run()
                                    RPC 127.0.0.1 (Bearer token, auto)
```

**Integrated node.** On entering the app the backend builds a
`dom_config::NodeConfig` from your settings, exports the matching `DOM_*`
environment variables, then runs `DomNode::init(config)` + `node.run()` on a
Tokio task. `request_shutdown()` stops it; the Node/Logs tab can start, stop and
restart it.

**Live logs.** The node logs through `tracing`. Because it runs in-process, a
custom `tracing_subscriber` layer captures every event into a broadcast channel
and forwards it to the UI as `node-log` events — with a defensive scrubber so a
password/seed-looking line can never reach the screen.

**RPC token.** `dom-rpc` resolves its bearer token from `DOM_RPC_TOKEN`, else
`~/.dom/rpc_token`, else it generates one. The app generates a token, exports
`DOM_RPC_TOKEN` *before* the node starts, and uses the same token in the
wallet's `NodeRpcClient`. No copy-paste, no terminal.

---

## Paying someone (slate protocol)

Sending DOM to another person is **interactive** (Mimblewimble, Grin-style) —
not address-based like Bitcoin. The slate is exchanged twice:

1. **Pagar → Enviar (step 1):** sender calls `create_send_slate(amount, fee,
   height)`; the app shows the slate as hex (copy/QR/file) to hand to the
   recipient. The payment is **not complete yet**.
2. **Receber (step 2):** recipient imports that slate, calls
   `receive_slate(slate, height)`, and returns the responded slate to the sender.
3. **Pagar → Finalizar (step 3):** sender imports the responded slate, calls
   `finalize_slate(slate, height)` → `Transaction`, and the app submits it to the
   node. "Transação enviada à rede."

The slate carries only **public** data, so it is safe to copy/paste or scan.
Secrets stay in the wallet's encrypted state in the Rust backend. The three
functions live in `dom-wallet`; the `Slate` type in `dom_tx::slate`; (de)serialization
via the `DomSerialize`/`DomDeserialize` traits (`to_bytes`/`from_bytes`). The
older single-party `build_spend` remains available but is not used for
person-to-person payments.

> Requires the `dom-protocol` `main` branch (commit `dda98d8` or later), where
> the slate was merged. The CI checks out `main` by default.

## Units

- **1 DOM = 100,000,000 noms** (8 decimals). Amounts display as `X.XXXXXXXX DOM`.
- Ticker **DOM**. Initial block reward **33 DOM**.
- The Dashboard distinguishes **total** vs **spendable**; immature coinbase
  shows as **pending**.

---

## Repository layout

```
dom-wallet-desktop/
├── src-tauri/
│   ├── Cargo.toml            # path deps into ../dom-protocol/crates/*
│   ├── tauri.conf.json       # "DOM Wallet", org.domprotocol.wallet, icons
│   ├── build.rs
│   ├── capabilities/default.json
│   ├── icons/                # generated from the DOM medallion
│   └── src/
│       ├── lib.rs            # state, commands, log streaming, app setup
│       ├── main.rs
│       ├── wallet_manager.rs # dom_wallet::WalletDir operations
│       ├── node_host.rs      # embedded DomNode lifecycle + token
│       ├── settings.rs       # NodeSettings ↔ NodeConfig + DOM_* env
│       ├── log_capture.rs    # tracing broadcast layer (+secret scrub)
│       └── metrics.rs        # Prometheus /metrics scrape
├── ui/
│   ├── index.html
│   ├── styles.css            # palette sampled from the DOM coin
│   ├── assets/dom-coin.png
│   └── src/{api,screens,main}.js
└── .github/workflows/build-wallet.yml
```

---

## Building locally

You need the two repos side by side:

```
some-dir/
├── dom-wallet-desktop/   (this repo)
└── dom-protocol/         (git clone https://github.com/sorenplanck/dom-protocol)
```

Prerequisites:

- Rust (stable, ≥ 1.75) — https://rustup.rs
- Tauri v2 CLI: `cargo install tauri-cli --version "^2"`
- **C/C++ toolchain for RandomX** (`randomx-rs` is pulled in via `dom-pow`):
  - **Linux:** `webkit2gtk-4.1`, `libappindicator3`, `librsvg2`, plus `clang`, `cmake`, `build-essential`, `pkg-config`
  - **macOS:** Xcode command-line tools + `brew install cmake`
  - **Windows:** Visual Studio Build Tools (MSVC), plus LLVM (`clang`) and CMake; set `LIBCLANG_PATH` to the LLVM `bin` folder

Then:

```bash
cd dom-wallet-desktop
cargo tauri dev      # run in development
cargo tauri build    # produce a native installer in src-tauri/target/release/bundle
```

The frontend is plain HTML/CSS/JS served statically (no Node build step).

---

## Building via GitHub (primary path)

Push a tag like `v0.1.0`, or run the **Build DOM Wallet** workflow manually
(`workflow_dispatch`). The workflow:

1. Checks out this repo and `sorenplanck/dom-protocol` **side by side** so the
   path dependencies resolve.
2. Installs Tauri system libraries and the RandomX C toolchain per platform.
3. Builds with `tauri-apps/tauri-action` on `windows-latest`, `macos-latest`,
   `ubuntu-latest`.
4. Produces installers — Windows `.msi`/`.exe`, macOS `.dmg` (universal), Linux
   `.AppImage`/`.deb` — and attaches them to a draft GitHub Release.

If `dom-protocol` is private, add a `DOM_PROTOCOL_PAT` secret and uncomment the
`token:` line in the checkout step.

---

## Security

- Seed and keys are encrypted at rest by `dom-wallet` (ChaCha20-Poly1305,
  password-derived). Sensitive types are zeroized.
- The unlocked wallet lives only in the Rust backend. **The seed and keys never
  cross the Tauri IPC boundary.** Passwords are passed in a single command and
  dropped.
- Passwords and seeds are never logged; the log pipeline additionally scrubs
  secret-looking lines.
- No telemetry or analytics. The only network activity is the node's P2P and the
  local RPC (`127.0.0.1`).
- No sensitive data is stored in `localStorage` — only non-sensitive node
  preferences (network, ports, data dir).
- Onboarding forces you to record the recovery phrase and confirm it.

> **On "show seed":** DOM wallets store the seed as encrypted *bytes*, not as
> recoverable words. The mnemonic cannot be re-derived after creation — so it is
> only shown once, during onboarding. Keep your written backup safe. This is a
> deliberate property of the `dom-wallet` crate, not a limitation of this app.

---

## Notes / assumptions

- Transaction **History** is backed by the wallet journal. This build shows a
  high-level view; a dedicated typed `history` command can be added if the
  `dom-wallet` journal read API is surfaced through a Tauri command.
- Peer count, mining state and blocks-mined come from the node's Prometheus
  `/metrics` endpoint (`DOM_METRICS_LISTEN_ADDR`).

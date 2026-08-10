<div align="center">

# DOM Protocol

### Not a store of value. A means of exchange.

**DOM is an independent Mimblewimble Layer 1 secured by CPU-oriented RandomX proof of work.  
Confidential by construction, deterministic by design, and built to circulate.**

![Mainnet](https://img.shields.io/badge/mainnet-live-2ea44f)
![Release](https://img.shields.io/badge/release-v1.0.0-0969da)
![Consensus](https://img.shields.io/badge/consensus-Mimblewimble-8B7DF0)
![PoW](https://img.shields.io/badge/PoW-RandomX-3FB68B)
![License](https://img.shields.io/badge/license-MIT-blue)

[Mainnet Release](https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0) ·
[DOM Wallet V3](https://github.com/sorenplanck/dom-wallet-v3/releases) ·
[Website](https://dom-protocol.org) ·
[Whitepaper](WHITEPAPER.md) ·
[Documentation](docs/) ·
[Security](SECURITY.md)

</div>

> [!IMPORTANT]
> The canonical DOM Mainnet launch source is the immutable Git tag
> [`v1.0.0`](https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0),
> pointing to commit
> [`6c58b0383c095384cd0150cabf074aa00fb57b17`](https://github.com/sorenplanck/dom-protocol/commit/6c58b0383c095384cd0150cabf074aa00fb57b17).
> Build production Mainnet software from a published release tag, not from an
> arbitrary development branch.

---

## Contents

- [Overview](#overview)
- [Mainnet status](#mainnet-status)
- [Fair launch](#fair-launch)
- [Monetary policy](#monetary-policy)
- [Consensus and cryptography](#consensus-and-cryptography)
- [Network identities](#network-identities)
- [Protocol limits](#protocol-limits)
- [Official software](#official-software)
- [Build from source](#build-from-source)
- [Run a Mainnet node](#run-a-mainnet-node)
- [Systemd deployment](#systemd-deployment)
- [RPC and metrics](#rpc-and-metrics)
- [Solo CPU mining](#solo-cpu-mining)
- [DOM Wallet V3](#dom-wallet-v3)
- [Security and verification](#security-and-verification)
- [Reproducible builds](#reproducible-builds)
- [Repository layout](#repository-layout)
- [Development and testing](#development-and-testing)
- [Future Layer 2 work](#future-layer-2-work)
- [Contributing](#contributing)
- [Security disclosure](#security-disclosure)
- [License](#license)

---

## Overview

DOM is a permissionless monetary network built around the Mimblewimble
construction. Transaction amounts are hidden inside Pedersen commitments and
proven valid with bounded Bulletproof range proofs. Transaction aggregation and
cut-through reduce redundant historical data while every full node independently
validates consensus, proof of work, signatures, range proofs, supply invariants,
state transitions, and chain selection.

DOM uses RandomX proof of work. The mining algorithm is designed to remain
accessible to general-purpose CPUs rather than depending exclusively on
specialized hardware. Difficulty is adjusted with deterministic integer ASERT
arithmetic.

The implementation follows a fail-closed philosophy:

- missing or unknown network selection is rejected before startup side effects;
- malformed and noncanonical encodings are rejected;
- arithmetic used in consensus paths is checked;
- incomplete or inconsistent persisted state is treated as corruption;
- public protocol identities are bound to fixed genesis values and chain IDs;
- RPC and metrics remain disabled unless explicitly enabled;
- mining on public networks requires a compatible local wallet and otherwise
  remains disabled.

DOM is a protocol, not a custodial service. No protocol component can arbitrarily
mint coins, freeze balances, reverse valid ownership, or allocate coins to the
founder outside the public consensus schedule.

---

## Mainnet status

DOM Mainnet is public and the initial bootstrap node is online.

| Item | Value |
|---|---|
| **Network** | Mainnet |
| **Release** | `v1.0.0` |
| **Release branch** | `release/mainnet` |
| **DOM Core commit** | `6c58b0383c095384cd0150cabf074aa00fb57b17` |
| **Protocol version** | `2` |
| **Public DNS seed** | `seed1.dom-protocol.org` |
| **Public P2P endpoint** | `seed1.dom-protocol.org:33369` |
| **Direct IP fallback** | `168.100.9.70:33369` |
| **P2P transport** | TCP with authenticated Noise handshake |
| **Bootstrap-node mining** | Disabled |
| **Bootstrap service** | `dom-mainnet.service` |
| **Public RPC** | Disabled; RPC is not exposed by the seed |

**Launch snapshot — 2026-07-18:** the public bootstrap node started at height
`0` with mining disabled. Height is a live network value and changes after valid
proof-of-work blocks are produced.

The initial seed exists to provide public peer discovery, synchronization,
transaction relay, and block relay. It does not receive a protocol allocation and
does not mine on behalf of the project.

### Mainnet identity

```text
Genesis hash:
182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce

Chain ID:
f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b

Genesis timestamp:
1784071429 (2026-07-14T23:23:49Z)

Genesis nonce:
7150

Genesis RandomX digest:
000003bda0b141656e3a086fbb2e018321ed2611c9d5a723bf9b85cce9baf3ab

Genesis inscription:
Not a store of value. A means of exchange.
```

The canonical Mainnet genesis economic body is empty:

```text
Inputs:        0
Outputs:       0
Kernels:       0
Transactions:  0
Issued subsidy: 0 DOM
```

Height `1`, not height `0`, is the first reward-bearing Mainnet block.

---

## Fair launch

DOM launched with public proof of work and without a private monetary
allocation.

```text
Premine:              none
ICO:                  none
Presale:              none
Private round:        none
Public prelaunch mining network: none
Founder allocation:   none
Team allocation:      none
Investor allocation:  none
Foundation reserve:   none
Protocol treasury:    none
Developer tax:        none
Genesis issuance:     0 DOM
Initial distribution: permissionless proof-of-work mining
```

The project does not promise price appreciation, exchange listings, investment
returns, market liquidity, or profitability from mining. DOM is experimental
open-source monetary software and participation carries technical, operational,
cryptographic, and market risk.

---

## Monetary policy

All monetary quantities are represented internally in **noms**.

```text
1 DOM = 100,000,000 noms
```

| Parameter | Consensus value |
|---|---:|
| **Genesis issuance** | `0 DOM` |
| **First reward-bearing height** | `1` |
| **Initial block subsidy** | `33 DOM` (`3,300,000,000 noms`) |
| **Reward epoch interval** | `330,000 blocks` |
| **Reward epochs** | `55` entries, including the terminal zero entry |
| **Epoch transition rule** | `next = floor(previous × 67 / 100)` |
| **Exact maximum issuance** | `3,299,996,676,900,000 noms` |
| **Exact maximum issuance in DOM** | `32,999,966.769 DOM` |
| **Coinbase maturity** | `1,000 blocks` |
| **Target block interval** | `120 seconds` |
| **Ordinary transaction fees in v1.0.0** | `100% to the block miner` |

The exact issuance is slightly below 33 million DOM because Mainnet genesis
issues zero coins and the reward schedule uses deterministic integer arithmetic.
Floating-point arithmetic is forbidden in consensus monetary calculations.

---

## Consensus and cryptography

| Component | Implementation |
|---|---|
| **Ledger construction** | Mimblewimble |
| **Proof of work** | RandomX |
| **Difficulty adjustment** | ASERT, 288-block half-life (`34,560 s`) |
| **Consensus hashing** | Tagged/domain-separated BLAKE2b-256 |
| **Commitments** | Pedersen commitments over secp256k1 |
| **Signatures** | Schnorr over secp256k1 with chain-ID binding |
| **Range proofs** | Fixed final Bulletproof format |
| **Canonical range-proof size** | `739 bytes` |
| **Wallet V3 recovery capsule** | `96 bytes` |
| **Maximum provable value** | `2^52 - 1 noms` |
| **Authenticated transport** | Noise protocol |
| **Transaction relay** | Dandelion++ stem/fluff routing |
| **Chain state** | LMDB-backed canonical state with corruption detection |
| **Accumulated work** | Full-width `U256` total difficulty |

### Determinism requirements

Consensus code avoids dependence on:

- host pointer width or Rust memory layout;
- locale, environment-dependent formatting, or floating point;
- unordered iteration where order affects canonical bytes;
- unchecked network-controlled arithmetic;
- implicit padding or trailing-byte acceptance;
- unknown network fallback behavior.

Canonical serialization uses explicit integer widths, explicit endian rules,
bounded allocations, checked length arithmetic, and trailing-byte rejection.

---

## Network identities

| Parameter | Mainnet | Testnet | Regtest |
|---|---|---|---|
| **Magic** | `0x444F4D31` (`DOM1`) | `0x444F4D54` (`DOMT`) | `0x444F4D52` (`DOMR`) |
| **P2P port** | `33369` | `33370` | `33371` |
| **Default RPC port** | `33372` | `33373` | `33374` |
| **Genesis hash** | `182e10af…4e9325ce` | `2ab5e6c7…5cd65821` | `fdda027e…dee3fe1f` |
| **Chain ID** | `f9831fad…bcf1165b` | `de1168ce…53ff770` | `22384b4c…abd698e1` |

Full Mainnet values are shown in [Mainnet identity](#mainnet-identity). Network
magic and chain ID are enforced during handshake; nodes from different networks
must not peer successfully.

---

## Protocol limits

| Limit | Value |
|---|---:|
| Maximum block weight | `40,000` units |
| Maximum transaction weight | `4,000` units |
| Maximum inputs per transaction | `255` |
| Maximum outputs per transaction | `255` |
| Maximum kernels per transaction | `16` |
| Maximum transactions per block | `5,000` |
| Canonical range-proof bytes | `739` |
| Defensive proof-size bound | `768` bytes |
| Wallet V3 recovery capsule | `96` bytes |
| Maximum output proof envelope | `835` bytes |
| Canonical Wallet V3 TransactionOutput | `872` bytes |
| Maximum serialized block size | `16 MiB` |
| Maximum logical P2P message | `16 MiB + 64 KiB` |
| Maximum headers per message | `2,000` |
| Maximum block hashes per data request | `128` |
| Maximum block locator hashes | `32` |
| Maximum future Mainnet timestamp | `120 seconds` |
| Median-time window | `11 blocks` |

Consensus limits and local relay policy are distinct. Policy may reject an item
that consensus could theoretically accept, but policy must never make an invalid
block valid.

---

## Official software

### DOM Core

- Repository: <https://github.com/sorenplanck/dom-protocol>
- Mainnet release: <https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0>
- Release branch: <https://github.com/sorenplanck/dom-protocol/tree/release/mainnet>
- Canonical release commit: `6c58b0383c095384cd0150cabf074aa00fb57b17`

### DOM Wallet V3

The canonical user-facing wallet is maintained and released separately:

- Repository: <https://github.com/sorenplanck/dom-wallet-v3>
- Releases: <https://github.com/sorenplanck/dom-wallet-v3/releases>

Legacy and internal wallet crates that remain in the Core workspace are not the
canonical end-user download channel. Users should obtain Wallet V3 only from its
official release page.

### Public explorer

The Core repository contains the explorer implementation. The public Mainnet
explorer endpoint will be announced through the official website and release
channels after deployment. An explorer is informational; consensus is determined
by validating nodes.

### Checksums

When compiled binaries are attached to a release, use only the checksums
published with that same official GitHub release. Do not trust unofficial mirrors
or checksums copied into third-party messages.

---

## Build from source

### Requirements

- Git
- Rust `1.75` or newer compatible toolchain
- Cargo
- A C/C++ build toolchain suitable for RandomX dependencies
- Common Linux build packages such as `build-essential`, `clang`, `cmake`, and
  `pkg-config`

Example on Ubuntu or Debian:

```bash
sudo apt update
sudo apt install -y build-essential clang cmake pkg-config git curl

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Build the exact Mainnet release

```bash
git clone https://github.com/sorenplanck/dom-protocol.git
cd dom-protocol
git checkout --detach v1.0.0

# Confirm the exact audited release commit.
test "$(git rev-parse HEAD)" = \
  "6c58b0383c095384cd0150cabf074aa00fb57b17"

cargo build --release --locked -p dom-node -p dom-cli -p dom-explorer
```

Release binaries are written to:

```text
target/release/dom-node
target/release/dom-cli
target/release/dom-explorer
```

---

## Run a Mainnet node

The network must be selected explicitly. A missing, padded, mixed-case, or
unknown `DOM_NETWORK` value fails closed before node initialization.

### Validating and relay-only node

```bash
mkdir -p "$HOME/.local/share/dom/mainnet"

DOM_NETWORK=mainnet \
DOM_SEED_PEERS="seed1.dom-protocol.org:33369" \
DOM_MINE=false \
DOM_DATA_DIR="$HOME/.local/share/dom/mainnet" \
DOM_P2P_LISTEN_ADDR="0.0.0.0:33369" \
DOM_LOG=info \
./target/release/dom-node
```

Direct-IP bootstrap fallback:

```bash
DOM_NETWORK=mainnet \
DOM_SEED_PEERS="168.100.9.70:33369" \
DOM_MINE=false \
DOM_DATA_DIR="$HOME/.local/share/dom/mainnet" \
DOM_P2P_LISTEN_ADDR="0.0.0.0:33369" \
DOM_LOG=info \
./target/release/dom-node
```

### Connectivity checks

```bash
getent ahostsv4 seed1.dom-protocol.org
nc -vz seed1.dom-protocol.org 33369
```

To accept inbound peers, allow TCP port `33369` through the host and provider
firewalls. For example, when using UFW:

```bash
sudo ufw allow 33369/tcp
sudo ufw status
```

An outbound-only node can still validate and synchronize, but publicly reachable
nodes improve network resilience.

### Initial DNS rollout note

During the initial Mainnet rollout, some secondary hardcoded seed hostnames may
not yet resolve. Resolution warnings for inactive secondary seeds are operational
warnings, not consensus failures. Use the verified `seed1.dom-protocol.org:33369`
or direct-IP endpoint above and confirm that at least one peer connection is
established.

---

## Systemd deployment

The following example runs a non-mining Mainnet node as an unprivileged service.
Review paths and hardening settings for your distribution before installation.

```bash
sudo install -m 0755 target/release/dom-node /usr/local/bin/dom-node
sudo useradd --system --home-dir /var/lib/dom-mainnet \
  --shell /usr/sbin/nologin dom 2>/dev/null || true
sudo install -d -o dom -g dom -m 0750 /var/lib/dom-mainnet

sudo tee /etc/systemd/system/dom-mainnet.service >/dev/null <<'UNIT'
[Unit]
Description=DOM Protocol Mainnet Node
After=network-online.target time-sync.target
Wants=network-online.target time-sync.target

[Service]
Type=simple
User=dom
Group=dom
WorkingDirectory=/var/lib/dom-mainnet
ExecStart=/usr/local/bin/dom-node

Environment=DOM_NETWORK=mainnet
Environment=DOM_DATA_DIR=/var/lib/dom-mainnet
Environment=DOM_P2P_LISTEN_ADDR=0.0.0.0:33369
Environment=DOM_SEED_PEERS=seed1.dom-protocol.org:33369
Environment=DOM_MINE=false
Environment=DOM_LOG=info

Restart=always
RestartSec=5
LimitNOFILE=65536

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/dom-mainnet
LockPersonality=true
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now dom-mainnet.service
sudo systemctl status dom-mainnet.service --no-pager
```

Follow logs:

```bash
sudo journalctl -u dom-mainnet.service -f
```

Verify the listener:

```bash
sudo ss -lntp | grep 33369
```

---

## RPC and metrics

RPC and metrics are disabled by default.

### Enable loopback RPC

```bash
DOM_NETWORK=mainnet \
DOM_SEED_PEERS="seed1.dom-protocol.org:33369" \
DOM_MINE=false \
DOM_DATA_DIR="$HOME/.local/share/dom/mainnet" \
DOM_P2P_LISTEN_ADDR="0.0.0.0:33369" \
DOM_RPC_LISTEN_ADDR=default \
DOM_LOG=info \
./target/release/dom-node
```

For Mainnet, `default` resolves to:

```text
127.0.0.1:33372
```

The RPC includes sensitive wallet-related operations. Keep it on loopback or a
strictly controlled private network and use bearer authentication. Never expose
RPC directly to the public Internet.

### Enable loopback metrics

Add:

```bash
DOM_METRICS_LISTEN_ADDR=default
```

The default metrics endpoint is:

```text
127.0.0.1:3371
```

Metrics reveal operational and topology information and should not be exposed
publicly without access controls.

---

## Solo CPU mining

The public bootstrap node does **not** mine. Mining is permissionless and can be
started by any participant running the released software.

> [!CAUTION]
> Public-network mining requires a compatible encrypted wallet directory.
> The node opens an existing wallet; it does not silently create a replacement.
> If the wallet is missing, invalid, locked elsewhere, or cannot be decrypted,
> mining stays disabled or fails closed. Back up the wallet recovery material
> before mining.

Example:

```bash
read -rsp "Miner wallet password: " DOM_WALLET_PASSWORD
echo
export DOM_WALLET_PASSWORD

DOM_NETWORK=mainnet \
DOM_SEED_PEERS="seed1.dom-protocol.org:33369" \
DOM_MINE=true \
DOM_MINER_THREADS="$(nproc)" \
DOM_WALLET_PATH="/absolute/path/to/compatible/wallet-directory" \
DOM_DATA_DIR="$HOME/.local/share/dom/mainnet-miner" \
DOM_P2P_LISTEN_ADDR="0.0.0.0:33369" \
DOM_LOG=info \
./target/release/dom-node

unset DOM_WALLET_PASSWORD
```

`DOM_MINER_THREADS` is a local resource setting and does not change consensus.
The implementation clamps the worker count to the supported range.

Do not place a wallet password or recovery phrase in:

- a public shell script;
- Git history;
- screenshots;
- a world-readable environment file;
- a public systemd unit;
- an issue report or support message.

For unattended mining, use a root-readable environment file, systemd credentials,
or a dedicated secret manager and restrict all filesystem permissions.

---

## DOM Wallet V3

DOM Wallet V3 is the official user-facing wallet distribution:

- <https://github.com/sorenplanck/dom-wallet-v3>
- <https://github.com/sorenplanck/dom-wallet-v3/releases>

Wallet security rules:

1. Download only from the official Wallet V3 release page.
2. Verify the release version and published checksums.
3. Record the recovery phrase offline.
4. Never share the recovery phrase or wallet password.
5. Test recovery before storing meaningful funds.
6. Keep independent encrypted backups.
7. Treat unsolicited support messages and wallet mirrors as hostile.

DOM Core and DOM Wallet V3 are separate release lines. A Core tag does not
implicitly publish or update the wallet, and a Wallet V3 release does not alter
Mainnet consensus.

---

## Security and verification

DOM Core `v1.0.0` was produced after a project-operated final engineering
campaign covering consensus, cryptography, storage, networking, reproducibility,
and formal methods.

The campaign included, among other gates:

- deterministic and adversarial multi-node synchronization;
- Initial Block Download and replay determinism;
- reorganization, fork-choice, tie-break, and persistence tests;
- RandomX seed-transition and persisted-seed validation;
- mempool admission, fee, maturity, duplication, and selection invariants;
- corruption detection and fail-closed storage recovery;
- malformed, truncated, oversized, and adversarial P2P messages;
- property-based testing;
- fuzzing of available Core targets;
- Kani bounded/refinement harnesses;
- selected Miri execution paths;
- supply-chain reachability analysis for Core binaries;
- byte-identical reproducible node, CLI, and explorer builds;
- independent genesis and chain-identity reproduction.

Final project classification:

```text
DOM CORE FINAL CAMPAIGN PASSED
```

This was an internal/project-run engineering verification campaign. It must not
be represented as an independent third-party financial, legal, or security
audit. Passing a large test campaign does not prove that software is free of all
unknown defects.

### Selected fail-closed properties

- unknown network values are rejected before storage or listeners are opened;
- Mainnet genesis identity is fixed and independently reproducible;
- Mainnet genesis issues zero DOM;
- the complete canonical block body is committed and validated;
- invalid or noncanonical persisted records are rejected;
- future timestamp and ASERT arithmetic use explicit checked boundaries;
- unknown-network proof-of-work selection is rejected;
- malformed range-proof points are rejected before native verification;
- RPC-generated bearer-token files are created owner-only;
- public RPC is disabled unless explicitly enabled.

---

## Reproducible builds

The final campaign reproduced the intended Core binaries byte-for-byte using a
fixed source-date epoch and disabled incremental compilation.

Example reproduction environment:

```bash
export SOURCE_DATE_EPOCH=1784071429
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=2

cargo build --release --locked -p dom-node -p dom-cli -p dom-explorer
sha256sum target/release/dom-node \
          target/release/dom-cli \
          target/release/dom-explorer
```

For a meaningful comparison, perform the second build in a clean checkout and a
separate target directory using the same toolchain, lockfile, target triple, and
environment.

---

## Repository layout

The repository is a Rust workspace containing the consensus implementation,
network services, developer tools, legacy/internal wallet components, tests, and
an excluded Tauri desktop application.

```text
dom-protocol/
├── crates/
│   ├── dom-core/                Consensus constants, primitive types, fee policy
│   ├── dom-serialization/       Canonical bounded encoding and decoding
│   ├── dom-crypto/              Schnorr, Pedersen, range proofs, recovery data
│   ├── dom-pmmr/                Prunable Merkle Mountain Range
│   ├── dom-pow/                 RandomX, ASERT, targets, accumulated work
│   ├── dom-consensus/           Transaction and block validation
│   ├── dom-chain/               Chain state, fork choice, reorg, genesis
│   ├── dom-store/               LMDB persistence and corruption checks
│   ├── dom-mempool/             Admission, validation, selection, reconciliation
│   ├── dom-wire/                Noise transport, codec, handshake, P2P messages
│   ├── dom-node/                Node orchestration, IBD, relay, mining, RPC bridge
│   ├── dom-rpc/                 HTTP RPC server and bearer-token handling
│   ├── dom-cli/                 Core command-line tools
│   ├── dom-explorer/            Explorer service
│   ├── dom-tx/                  Transaction and recoverable-output construction
│   ├── dom-slate/               Interactive slate protocol
│   ├── dom-test-vectors/        Frozen and adversarial vectors
│   ├── dom-integration-tests/   Multi-node and end-to-end tests
│   ├── dom-wallet*/             Legacy/internal wallet and compatibility crates
│   └── dom-*-runner/            Test and campaign orchestration tools
├── wallet-desktop/              Excluded Tauri desktop application
├── test-vectors/                Canonical genesis and protocol vectors
├── docs/                        Protocol and operator documentation
├── deploy/                      Deployment examples and systemd configuration
├── audit/                       Historical audit and hardening materials
├── WHITEPAPER.md
├── SECURITY.md
└── Cargo.toml
```

The official end-user Wallet V3 is maintained in its own repository and release
channel, as described above.

---

## Development and testing

Install the repository toolchain and run the standard quality gates:

```bash
cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Some integration, fuzz, formal-verification, mining, and multi-node campaigns are
resource intensive and must use isolated data directories, target directories,
and ports.

Consensus-sensitive changes require more than ordinary unit tests. Depending on
the affected subsystem, contributors should add:

- deterministic positive and negative vectors;
- property-based invariants;
- differential tests;
- reorg and restart coverage;
- malformed serialization cases;
- fuzz targets;
- Kani or other bounded proofs where practical;
- release-mode regression coverage;
- an explicit impact statement for genesis, chain ID, serialization, PoW,
  monetary policy, wallet recovery formats, and P2P compatibility.

---

## Future Layer 2 work

A future **DOM Layer 2 Settlement Protocol (DL2P)** is being specified as a
post-Mainnet extension so independently developed L2 systems can eventually use
DOM for settlement, custody, proofs, and data availability.

DL2P is **not active in Mainnet v1.0.0**. In particular:

- v1.0.0 does not claim general rollup support;
- no L2 settlement fee split is active in v1.0.0;
- ordinary v1.0.0 transaction fees continue to follow current Core consensus;
- future L2 functionality requires independent RFCs, versioned formats,
  explicit consensus activation, test vectors, formal conservation models,
  Regtest validation, public review, and release-specific testing;
- future work must preserve the frozen v1.0.0 genesis identity and must not
  opportunistically repurpose existing Wallet V3 or V2 consensus fields.

The architectural objective is to evolve DOM into a privacy-oriented proof-of-
work settlement layer without informally changing the released L1 rules.

---

## Contributing

Issues and pull requests are welcome.

- Development changes should target the appropriate development branch.
- `release/mainnet` is the release line and should receive only reviewed release
  documentation or deliberate versioned hotfixes.
- Never rewrite or move a published release tag.
- Every consensus-sensitive change must identify its affected authority and
  include suitable regression evidence.
- Keep code, comments, commits, and technical documentation in English.

Before opening a pull request:

```bash
cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

---

## Security disclosure

Do not disclose exploitable vulnerabilities in a public issue before a fix or
mitigation is available.

See [SECURITY.md](SECURITY.md) for the private reporting process.

General technical issues:

<https://github.com/sorenplanck/dom-protocol/issues>

Project contact:

- **Author:** Soren Planck
- **Email:** `sorenplanck@tutamail.com`

---

## Official links

- Website: <https://dom-protocol.org>
- DOM Core: <https://github.com/sorenplanck/dom-protocol>
- Core v1.0.0: <https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0>
- Mainnet release branch: <https://github.com/sorenplanck/dom-protocol/tree/release/mainnet>
- DOM Wallet V3: <https://github.com/sorenplanck/dom-wallet-v3>
- Wallet V3 releases: <https://github.com/sorenplanck/dom-wallet-v3/releases>
- Public seed: `seed1.dom-protocol.org:33369`
- Direct seed fallback: `168.100.9.70:33369`
- Issues: <https://github.com/sorenplanck/dom-protocol/issues>

Treat any social-media, Telegram, Discord, wallet, binary mirror, or support
account not linked from the official website or repositories as unofficial.

---

## License

DOM Protocol is released under the [MIT License](LICENSE).

The software is provided "as is", without warranty of any kind. Review the code,
verify release identities and checksums, protect wallet recovery material, and
operate nodes at your own risk.

---

<div align="center">

**No premine. No ICO. No founder allocation. Mainnet from block zero.**

*Not a store of value. A means of exchange.*

</div>

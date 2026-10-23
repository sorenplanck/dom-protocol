<div align="center">

# DOM Protocol

### Not a store of value. A means of exchange.

**DOM is an independent Mimblewimble Layer 1 secured by CPU-oriented RandomX proof of work.  
Confidential by construction, deterministic by design, and built to circulate.**

![Mainnet](https://img.shields.io/badge/mainnet-live-2ea44f)
![Consensus](https://img.shields.io/badge/consensus-Mimblewimble-8B7DF0)
![PoW](https://img.shields.io/badge/PoW-RandomX-3FB68B)
![License](https://img.shields.io/badge/license-MIT-blue)

[DOM Core](https://github.com/sorenplanck/dom-protocol) ·
[DOM Wallet V3](https://github.com/sorenplanck/dom-wallet-v3/releases) ·
[Website](https://dom-protocol.org) ·
[Whitepaper](WHITEPAPER.md) ·
[Documentation](docs/) ·
[Security](SECURITY.md)

</div>

> [!IMPORTANT]
> The immutable `v1.0.0` tag records the historical Mainnet launch source.
> It predates the block version 3 consensus upgrade and cannot synchronize
> the current chain.
>
> For current node software, consult [Official software](#official-software)
> and the release documentation.
>
> The `mainnetswap` development branch also contains interoperability work.
> Its presence does not establish production deployment or release approval.

---

## Contents

- [Overview](#overview)
- [Mainnet and source versions](#mainnet-and-source-versions)
- [Fair launch](#fair-launch)
- [Monetary policy](#monetary-policy)
- [Consensus and cryptography](#consensus-and-cryptography)
- [Network identities](#network-identities)
- [Protocol limits](#protocol-limits)
- [Official software](#official-software)
- [Ecosystem and repository scope](#ecosystem-and-repository-scope)
- [Build from source](#build-from-source)
- [Run a node](#run-a-node)
- [RPC and metrics](#rpc-and-metrics)
- [Solo CPU mining](#solo-cpu-mining)
- [DOM Wallet V3](#dom-wallet-v3)
- [Repository layout](#repository-layout)
- [Development and testing](#development-and-testing)
- [Interoperability development](#interoperability-development)
- [Future Layer 2 work](#future-layer-2-work)
- [Security and verification](#security-and-verification)
- [Reproducible builds](#reproducible-builds)
- [Contributing](#contributing)
- [Security disclosure](#security-disclosure)
- [Official links](#official-links)
- [License](#license)

---

## Overview

DOM is a permissionless monetary network built around the Mimblewimble
construction.

Transaction amounts are hidden inside Pedersen commitments and proven valid
with bounded Bulletproof range proofs. Transaction aggregation and cut-through
reduce redundant historical data while validating nodes independently check
consensus, proof of work, signatures, range proofs, supply invariants, state
transitions and chain selection.

DOM uses RandomX proof of work. The mining algorithm is designed for
general-purpose CPUs. Difficulty adjustment uses deterministic integer ASERT
arithmetic.

The implementation follows a fail-closed approach:

- Missing or unknown network selection is rejected before node initialization.
- Malformed and noncanonical encodings are rejected.
- Consensus arithmetic uses explicit bounds and checked operations.
- Incomplete or inconsistent persisted state is treated as corruption.
- Public network identities are bound to fixed genesis values and chain IDs.
- RPC and metrics remain disabled unless explicitly enabled.
- Public-network mining requires a compatible local wallet.

DOM is a protocol, not a custodial service. Its consensus rules do not provide
an administrative mechanism to mint arbitrary coins, freeze balances or allocate
funds outside the public issuance schedule.

---

## Mainnet and source versions

The repository documents the following network and release identities:

| Item | Value |
|---|---|
| Network | Mainnet |
| Core workspace version | `0.2.0` |
| Release line referenced by current documentation | `release/mainnetv2` |
| Historical launch release | `v1.0.0` |
| Historical launch commit | `6c58b0383c095384cd0150cabf074aa00fb57b17` |
| Selected interoperability development branch | `mainnetswap` |
| Public DNS seed | `seed1.dom-protocol.org` |
| Public P2P endpoint | `seed1.dom-protocol.org:33369` |
| Direct IP fallback | `168.100.9.70:33369` |
| P2P transport | TCP with authenticated Noise handshake |
| Bootstrap-node mining configuration | Disabled |
| Public bootstrap RPC configuration | Disabled |

Source versions, published releases and live network availability are distinct.
Check the official release documentation before deploying a node.

### Block version 3

Mainnet consensus requires:

| Height | Required block version |
|---|---:|
| Below `12,500` | `2` |
| At or above `12,500` | `3` |

The activation height is a compile-time consensus constant:

```text
BLOCK_VERSION_LEGACY          = 2
BLOCK_VERSION_V3              = 3
MAINNET_V3_ACTIVATION_HEIGHT  = 12_500
```

A node built before this upgrade cannot validate the post-activation chain.
Changing a runtime setting cannot add the missing consensus rules.

Block versions and the P2P wire protocol are separate concepts. Consult
`crates/dom-core/src/constants.rs` for the exact values in the selected
revision.

Testnet and Regtest require block version 3 from their first post-genesis
block while preserving their frozen genesis identities.

See the
[block v3 implementation report](docs/HARD_FORK_V3_IMPLEMENTATION_REPORT.md)
for the activation rules and validation details.

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
Inputs:          0
Outputs:         0
Kernels:         0
Transactions:    0
Issued subsidy:  0 DOM
```

Height `1` is the first reward-bearing Mainnet block.

---

## Fair launch

DOM launched with public proof of work and without a private monetary
allocation.

```text
Premine:                       none
ICO:                           none
Presale:                       none
Private round:                 none
Public prelaunch mining:       none
Founder allocation:            none
Team allocation:               none
Investor allocation:           none
Foundation reserve:            none
Protocol treasury:             none
Developer tax:                  none
Genesis issuance:              0 DOM
Initial distribution:          permissionless proof-of-work mining
```

The project does not promise price appreciation, exchange listings, investment
returns, market liquidity or profitability from mining.

---

## Monetary policy

All monetary quantities are represented internally in **noms**.

```text
1 DOM = 100,000,000 noms
```

| Parameter | Consensus value |
|---|---:|
| Genesis issuance | `0 DOM` |
| First reward-bearing height | `1` |
| Initial block subsidy | `33 DOM` |
| Initial block subsidy in noms | `3,300,000,000` |
| Reward epoch interval | `330,000 blocks` |
| Reward epochs | `55`, including the terminal zero entry |
| Epoch transition | `next = floor(previous × 67 / 100)` |
| Exact maximum issuance | `3,299,996,676,900,000 noms` |
| Exact maximum issuance in DOM | `32,999,966.769 DOM` |
| Mainnet coinbase maturity | `1,000 blocks` |
| Target block interval | `120 seconds` |
| Ordinary transaction fees in the launch release | `100% to the block miner` |

The exact issuance is slightly below 33 million DOM because Mainnet genesis
issues zero coins and the reward schedule uses deterministic integer arithmetic.

Floating-point arithmetic is not used for consensus monetary calculations.

---

## Consensus and cryptography

| Component | Implementation |
|---|---|
| Ledger construction | Mimblewimble |
| Proof of work | RandomX |
| Difficulty adjustment | ASERT |
| ASERT half-life | `288 blocks`, or `34,560 seconds` |
| Consensus hashing | Tagged/domain-separated BLAKE2b-256 |
| Commitments | Pedersen commitments over secp256k1 |
| Signatures | Schnorr over secp256k1 with chain-ID binding |
| Range proofs | Fixed final Bulletproof format |
| Canonical range-proof size | `739 bytes` |
| Wallet V3 recovery capsule | `96 bytes` |
| Maximum provable value | `2^52 - 1 noms` |
| Authenticated transport | Noise protocol |
| Transaction relay | Dandelion++ stem/fluff routing |
| Chain state | LMDB-backed canonical state |
| Accumulated work | Full-width `U256` total difficulty |

### Determinism

Consensus code must avoid dependence on:

- Host pointer width or Rust memory layout.
- Locale or environment-dependent formatting.
- Floating-point arithmetic.
- Unordered iteration when order affects canonical bytes.
- Unchecked network-controlled arithmetic.
- Implicit padding.
- Acceptance of trailing bytes.
- Unknown-network fallback behavior.

Canonical serialization uses explicit integer widths, explicit byte ordering,
bounded allocations, checked length arithmetic and trailing-byte rejection.

---

## Network identities

| Parameter | Mainnet | Testnet | Regtest |
|---|---|---|---|
| Magic | `0x444F4D31` (`DOM1`) | `0x444F4D54` (`DOMT`) | `0x444F4D52` (`DOMR`) |
| P2P port | `33369` | `33370` | `33371` |
| Default RPC port | `33372` | `33373` | `33374` |
| Genesis hash | `182e10af…4e9325ce` | `2ab5e6c7…5cd65821` | `fdda027e…dee3fe1f` |
| Chain ID | `f9831fad…bcf1165b` | `de1168ce…53ff770` | `22384b4c…abd698e1` |

Full Mainnet values are shown under
[Mainnet identity](#mainnet-identity).

Network magic and chain ID are enforced during the handshake. Nodes from
different networks must not peer successfully.

Regtest is intended for isolated local development. See
[Regtest documentation](docs/REGTEST.md).

---

## Protocol limits

| Limit | Value |
|---|---:|
| Maximum block weight | `40,000 units` |
| Maximum transaction weight | `4,000 units` |
| Maximum inputs per transaction | `255` |
| Maximum outputs per transaction | `255` |
| Maximum kernels per transaction | `16` |
| Maximum transactions per block | `5,000` |
| Canonical range-proof bytes | `739` |
| Defensive proof-size bound | `768 bytes` |
| Wallet V3 recovery capsule | `96 bytes` |
| Maximum output proof envelope | `835 bytes` |
| Canonical Wallet V3 TransactionOutput | `872 bytes` |
| Maximum serialized block size | `16 MiB` |
| Maximum logical P2P message | `16 MiB + 64 KiB` |
| Maximum headers per message | `2,000` |
| Maximum block hashes per data request | `128` |
| Maximum block locator hashes | `32` |
| Maximum future Mainnet timestamp | `120 seconds` |
| Median-time window | `11 blocks` |

Consensus limits and local relay policy are distinct. Local policy may reject
an item that consensus could accept, but it must never make an invalid block
valid.

---

## Official software

### DOM Core

- Repository: <https://github.com/sorenplanck/dom-protocol>
- Release line referenced by current documentation:
  <https://github.com/sorenplanck/dom-protocol/tree/release/mainnetv2>
- Historical launch release:
  <https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0>

The launch tag records the genesis-time build. It predates the block version 3
upgrade and must not be treated as a current Mainnet synchronization build.

Use the release instructions and source revision appropriate to the network
you intend to run.

### DOM Wallet V3

The user-facing Wallet V3 is maintained and released separately:

- Repository: <https://github.com/sorenplanck/dom-wallet-v3>
- Releases: <https://github.com/sorenplanck/dom-wallet-v3/releases>

Legacy and internal wallet crates in the Core workspace are separate from
the Wallet V3 end-user distribution.

### Explorer

The Core repository contains the explorer implementation.

An explorer provides information about the chain; consensus is determined by
validating nodes.

### Checksums

When compiled binaries are attached to a release, verify them against the
checksums published with that same official release.

---

## Ecosystem and repository scope

The public repositories serve different development workflows. Their
branches, lockfiles and release histories must be evaluated separately.

| Repository | Development ref | Scope |
|---|---|---|
| [dom-protocol](https://github.com/sorenplanck/dom-protocol) | `mainnetswap` | Core node, consensus, RPC, CLI, wallet libraries and an additive interoperability workspace, including `dom-interopd`. |
| [dom-wallet](https://github.com/sorenplanck/dom-wallet) | `main` | A Core-derived workspace with wallet libraries and an excluded Tauri desktop application under `wallet-desktop/`. |

The separately released
[DOM Wallet V3](https://github.com/sorenplanck/dom-wallet-v3)
remains the user-facing distribution described above.

Neither the `dom-wallet` checkout nor the source under
`vendor/dom-wallet-v3/` automatically represents the latest published Wallet V3
release.

Both public Core-derived workspaces request Rust `stable`. The manifests'
`rust-version = "1.75"` is not a guarantee that every dependency in the current
lockfiles builds with Rust 1.75.

Use each repository's `rust-toolchain.toml` and preserve its committed
lockfile.

---

## Build from source

### Requirements

- Git.
- Rust selected by `rust-toolchain.toml`.
- Cargo.
- A C/C++ toolchain suitable for the native cryptographic and RandomX
  dependencies.
- CMake and pkg-config.

Example system packages on Ubuntu or Debian:

```bash
sudo apt update
sudo apt install -y build-essential clang cmake pkg-config git curl
```

Install Rust through the official rustup distribution:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Development build

From the selected repository checkout:

```bash
rustup show

cargo build --locked \
  -p dom-node \
  -p dom-cli \
  -p dom-explorer
```

Debug binaries are written to:

```text
target/debug/dom-node
target/debug/dom-cli
target/debug/dom-explorer
```

For an optimized build of the selected source revision:

```bash
cargo build --release --locked \
  -p dom-node \
  -p dom-cli \
  -p dom-explorer
```

Release binaries are written to:

```text
target/release/dom-node
target/release/dom-cli
target/release/dom-explorer
```

A successful development build is not a production release or a Mainnet
compatibility certification.

### Historical launch reproduction

The following commands reproduce the historical launch source. This source
predates the block v3 activation.

Run this example in a separate checkout without local changes:

```bash
git clone https://github.com/sorenplanck/dom-protocol.git
cd dom-protocol

git checkout --detach v1.0.0

test "$(git rev-parse HEAD)" = \
  "6c58b0383c095384cd0150cabf074aa00fb57b17"

cargo build --release --locked \
  -p dom-node \
  -p dom-cli \
  -p dom-explorer
```

Do not use this historical binary to synchronize the post-upgrade Mainnet
chain.

---

## Run a node

The network must be selected explicitly.

A missing, padded, mixed-case or unknown `DOM_NETWORK` value is rejected
before node initialization.

### Mainnet validation and relay

Use a build compatible with the current consensus rules:

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

Connectivity checks:

```bash
getent ahostsv4 seed1.dom-protocol.org
nc -vz seed1.dom-protocol.org 33369
```

Accepting inbound peers requires TCP port `33369` to be reachable through
the host and provider firewalls.

An outbound-only node can still validate and synchronize.

### Local Regtest

Regtest provides an isolated development network with separate network
identity and local development parameters.

```bash
mkdir -p "$HOME/.local/share/dom/regtest"

DOM_NETWORK=regtest \
DOM_MINE=false \
DOM_DATA_DIR="$HOME/.local/share/dom/regtest" \
DOM_P2P_LISTEN_ADDR="127.0.0.1:33371" \
DOM_LOG=info \
./target/debug/dom-node
```

Use separate data directories and ports when running multiple local nodes.

See [Regtest documentation](docs/REGTEST.md) for mining and multi-node
workflows.

### Service deployment

For unattended operation, run the node under a dedicated unprivileged
account and use the repository's deployment documentation.

Start with:

- [Deployment documentation](docs/DEPLOYMENT.md)
- [Backbone systemd documentation](docs/BACKBONE_SYSTEMD.md)
- [Deployment examples](deploy/)

Review paths, permissions, network selection and service hardening before
installation.

---

## RPC and metrics

RPC and metrics are disabled by default.

### Authenticated loopback RPC

Standalone RPC requires a bearer-token file. Create an owner-only token file
without placing the token in shell history:

```bash
install -d -m 0700 "$HOME/.local/share/dom"

python3 - <<'PY'
from pathlib import Path
import os
import secrets

path = Path.home() / ".local/share/dom/rpc.token"

if not path.exists():
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(secrets.token_hex(32))
PY
```

Enable RPC:

```bash
DOM_NETWORK=mainnet \
DOM_SEED_PEERS="seed1.dom-protocol.org:33369" \
DOM_MINE=false \
DOM_DATA_DIR="$HOME/.local/share/dom/mainnet" \
DOM_P2P_LISTEN_ADDR="0.0.0.0:33369" \
DOM_RPC_LISTEN_ADDR=default \
DOM_RPC_BEARER_TOKEN_FILE="$HOME/.local/share/dom/rpc.token" \
DOM_LOG=info \
./target/release/dom-node
```

For Mainnet, the default RPC listener is:

```text
127.0.0.1:33372
```

Keep RPC on loopback and use bearer authentication. Do not expose it directly
to the public Internet.

Consult [RPC documentation](docs/RPC.md) and
[wallet-safe RPC documentation](docs/WALLET_SAFE_RPC.md).

### Loopback metrics

Enable the default metrics listener with:

```bash
DOM_METRICS_LISTEN_ADDR=default
```

The default endpoint is:

```text
127.0.0.1:3371
```

Metrics contain operational and topology information. Restrict access
appropriately.

---

## Solo CPU mining

Mining is permissionless.

The documented public bootstrap-node configuration does not mine.

Public-network mining requires a compatible encrypted wallet directory.
The node opens an existing wallet; it does not silently create a replacement.

If the wallet is missing, invalid, locked elsewhere or cannot be decrypted,
mining remains disabled or startup fails closed.

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

`DOM_MINER_THREADS` is a local resource setting and does not change
consensus. The implementation clamps it to the supported range.

Back up wallet recovery material before mining.

Do not place passwords or recovery phrases in Git history, public scripts,
screenshots, issue reports or world-readable files.

For unattended operation, use the supported owner-only password-file
configuration or an appropriately restricted service credential mechanism.

---

## DOM Wallet V3

DOM Wallet V3 is the official user-facing wallet distribution:

- <https://github.com/sorenplanck/dom-wallet-v3>
- <https://github.com/sorenplanck/dom-wallet-v3/releases>

Recommended wallet practices:

1. Download from the official release page.
2. Verify the release version and published checksums.
3. Record the recovery phrase offline.
4. Never share the recovery phrase or wallet password.
5. Test recovery before storing meaningful funds.
6. Maintain independent encrypted backups.

DOM Core and DOM Wallet V3 have separate release histories.

A Core release does not implicitly publish or update the wallet. A wallet
release does not change Mainnet consensus.

The Tauri application under `wallet-desktop/` has its own build
requirements. Consult its README rather than assuming a Core workspace build
produces a desktop installer.

---

## Repository layout

The workspace contains Core consensus and services, wallet components,
interoperability services and acceptance harnesses.

```text
dom-protocol/
├── crates/
│   ├── dom-core/                 Constants and primitive types
│   ├── dom-config/               Network and node configuration
│   ├── dom-serialization/        Canonical encoding and decoding
│   ├── dom-crypto/               Signatures, commitments and proofs
│   ├── dom-pmmr/                 Prunable Merkle Mountain Range
│   ├── dom-pow/                  RandomX, ASERT and accumulated work
│   ├── dom-consensus/            Transaction and block validation
│   ├── dom-chain/                Chain state, fork choice and reorg
│   ├── dom-store/                LMDB persistence
│   ├── dom-mempool/              Admission and reconciliation
│   ├── dom-wire/                 P2P transport and messages
│   ├── dom-node/                 Full-node orchestration
│   ├── dom-rpc/                  Authenticated HTTP RPC
│   ├── dom-cli/                  Command-line tools
│   ├── dom-explorer/             Explorer service
│   ├── dom-faucet/               Test-network faucet
│   ├── dom-tx/                   Transaction construction
│   ├── dom-slate/                Interactive slate protocol
│   ├── dom-wallet*/              Wallet and compatibility libraries
│   ├── dom-test-vectors/         Frozen and adversarial vectors
│   ├── dom-integration-tests/    Integration and end-to-end tests
│   ├── dom-*-runner/             Test orchestration
│   ├── dom-interopd/             Interoperability daemon
│   ├── adapters/                 Chain adapter components
│   ├── route-*/                  Route composition and execution
│   ├── settlement-coordinator/   Settlement orchestration
│   └── f*-*/                    Models and acceptance harnesses
├── wallet-desktop/               Excluded Tauri desktop application
├── vendor/dom-wallet-v3/         Vendored Wallet V3 source
├── contracts/                   EVM contracts
├── programs/                    Solana programs
├── external-gpl/                Separately scoped sidecar sources
├── test-vectors/                 Canonical protocol vectors
├── docs/                         Technical and operator documentation
├── deploy/                       Deployment examples
├── audit/                        Audit and hardening materials
├── WHITEPAPER.md
├── SECURITY.md
└── Cargo.toml
```

Excluded applications, contracts, programs and sidecars may require separate
toolchains, dependencies and build commands.

---

## Development and testing

Use the selected repository toolchain and committed lockfile.

Standard Rust checks:

```bash
cargo fmt --all --check

cargo check --workspace --all-targets --locked

cargo clippy --workspace --all-targets --locked -- -D warnings

cargo test --workspace --locked
```

For focused development, run the relevant package suites before expanding
to the full workspace.

Examples:

```bash
cargo test --locked -p dom-core -p dom-config -p dom-rpc

cargo test --locked -p dom-wallet2 -p dom-wallet-keys

cargo test --locked -p route-executor -p settlement-coordinator
```

Some integration, fuzz, formal-verification, mining and multi-node campaigns
are resource intensive. Use isolated data directories, target directories
and ports where required.

Consensus-sensitive changes require evidence appropriate to the affected
rules, including:

- Deterministic positive and negative vectors.
- Property-based invariants.
- Differential tests.
- Reorganization and restart coverage.
- Malformed serialization cases.
- Fuzz targets.
- Bounded proofs where practical.
- Release-mode regression coverage.
- Explicit impact statements for genesis, chain ID, serialization, proof of
  work, monetary policy, wallet recovery and P2P compatibility.

A passing subset of tests does not establish that the full CI, release
workflow or live network integration has passed.

---

## Interoperability development

The `mainnetswap` workspace contains interoperability components alongside
the Core node:

- Scriptless protocol and storage.
- Settlement coordination.
- Route composition and execution.
- Relay and solver services.
- Bitcoin, EVM, Solana and Monero adapter families.

Workspace membership does not establish that a route is operational or that
new consensus rules have been activated.

Start with:

- [Injection record](docs/interop/INJECTION-RECORD.md)
- [Daemon operations runbook](docs/interop/runbooks/DOM-INTEROPD-OPERATIONS.md)

The injection record is explicitly marked **NOT RATIFIED**.

`dom-interopd` defaults to the `development` feature. Its simulation and
production workflows have separate requirements.

Selecting the `production` feature alone does not produce an operational
artifact. The operations runbook documents artifact requirements, startup
refusals, state recovery, secret handling and known route limits.

Validate each component with its documented feature flags and committed
lockfile.

Simulation, production artifact checks and live-chain execution establish
different properties. Public-chain scenarios, Bitcoin node services,
contract execution and external signing infrastructure need their own
prerequisites and evidence.

Interoperability development and the future L2 proposal below have distinct
scopes. Adapter code and settlement harnesses do not establish general
rollup support.

---

## Future Layer 2 work

A future **DOM Layer 2 Settlement Protocol (DL2P)** is being specified as a
post-Mainnet extension so independently developed systems can eventually use
DOM for settlement, custody, proofs and data availability.

DL2P is not active in the historical Mainnet `v1.0.0` release.

Future L2 functionality requires:

- Independent RFCs.
- Versioned formats.
- Explicit consensus activation where necessary.
- Test vectors.
- Conservation models.
- Regtest validation.
- Public review.
- Release-specific testing.

Future work must preserve the frozen genesis identity and must not
informally repurpose existing wallet or consensus fields.

The architectural objective is to support settlement functionality while
preserving explicit, reviewable L1 consensus rules.

---

## Security and verification

The repository contains engineering verification and audit materials
covering consensus, cryptography, storage, networking and build procedures.

Consult the source reports and their pinned revisions before applying a
historical result to a current build.

The documented verification work includes:

- Multi-node synchronization.
- Initial Block Download and replay determinism.
- Reorganization and fork-choice behavior.
- Persistence and restart handling.
- RandomX seed transitions.
- Mempool admission and fee invariants.
- Storage corruption detection.
- Malformed and oversized P2P input handling.
- Property-based testing.
- Fuzz targets.
- Kani harnesses and selected Miri paths.
- Supply-chain analysis.
- Reproducible build procedures.
- Genesis and chain-identity reproduction.

Project-operated verification and independent review are different forms of
evidence. Neither establishes that later commits are free of defects.

### Fail-closed properties

The implementation includes checks intended to ensure that:

- Unknown networks are rejected before storage or listeners are opened.
- Mainnet genesis identity remains fixed.
- Genesis issuance is zero.
- Canonical block bodies are committed and validated.
- Invalid persisted records are rejected.
- Timestamp and difficulty calculations respect explicit boundaries.
- Malformed proof encodings are rejected.
- RPC authentication material is protected by filesystem permissions.
- Public RPC remains disabled unless explicitly configured.

Read [SECURITY.md](SECURITY.md) for the disclosure process.

---

## Reproducible builds

A meaningful reproducibility comparison requires the same:

- Source revision.
- Toolchain.
- Lockfile.
- Target triple.
- Build configuration.
- Relevant environment settings.

Use separate build directories and different absolute source paths.

Example controls:

```bash
export SOURCE_DATE_EPOCH=1784071429
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=2

export RUSTFLAGS="--remap-path-prefix=$PWD=/build \
--remap-path-prefix=$HOME/.cargo=/cargo \
--remap-path-prefix=$HOME/.rustup=/rustup"

cargo build --release --locked \
  -p dom-node \
  -p dom-cli \
  -p dom-explorer

sha256sum \
  target/release/dom-node \
  target/release/dom-cli \
  target/release/dom-explorer
```

Adapt path remapping when `CARGO_HOME` or `RUSTUP_HOME` uses a different
location.

Cargo discovers configuration in ancestor directories. Avoid unrelated
configuration affecting one side of the comparison.

Two successful builds are not evidence of byte reproducibility unless their
artifacts are actually compared.

---

## Contributing

Issues and contributions are welcome.

- Target the appropriate development branch.
- Reserve release-line changes for reviewed release work and deliberate
  versioned fixes.
- Never rewrite or move a published release tag.
- Preserve committed dependency lockfiles.
- Identify the authority and compatibility implications of consensus changes.
- Include regression evidence appropriate to the affected behavior.
- Keep code, comments and technical documentation in English.

Before submitting changes:

```bash
cargo fmt --all --check

cargo check --workspace --all-targets --locked

cargo clippy --workspace --all-targets --locked -- -D warnings

cargo test --workspace --locked
```

Follow any additional checks required by the selected component and its CI
configuration.

---

## Security disclosure

Do not disclose exploitable vulnerabilities through a public issue.

See [SECURITY.md](SECURITY.md) for the private reporting process.

General issues:

<https://github.com/sorenplanck/dom-protocol/issues>

Project contact:

- Author: Soren Planck
- Email: `sorenplanck@tutamail.com`

---

## Official links

- Website: <https://dom-protocol.org>
- DOM Core: <https://github.com/sorenplanck/dom-protocol>
- Historical launch release:
  <https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0>
- Release line referenced by current documentation:
  <https://github.com/sorenplanck/dom-protocol/tree/release/mainnetv2>
- DOM Wallet: <https://github.com/sorenplanck/dom-wallet>
- DOM Wallet V3: <https://github.com/sorenplanck/dom-wallet-v3>
- Wallet V3 releases: <https://github.com/sorenplanck/dom-wallet-v3/releases>
- Public seed: `seed1.dom-protocol.org:33369`
- Direct seed fallback: `168.100.9.70:33369`
- Issues: <https://github.com/sorenplanck/dom-protocol/issues>

Verify software distribution and support channels through the official
website and repositories.

---

## License

DOM Protocol is released under the [MIT License](LICENSE).

Separately scoped third-party and sidecar sources retain their respective
licenses. Review those licenses when building or distributing components
outside the Core release scope.

The software is provided "as is", without warranty of any kind.

---

<div align="center">

**No premine. No ICO. No founder allocation.**

*Not a store of value. A means of exchange.*

</div>

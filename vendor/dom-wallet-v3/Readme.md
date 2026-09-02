<p align="center">
  <img src="assets/dom-wallet-v3-banner.svg" alt="DOM Wallet V3 — Secure state. Deterministic recovery. Native DOM sovereignty." width="760">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-Experimental%20Desktop%20Wallet-b87333?style=flat-square" alt="Status: Experimental Desktop Wallet">
  <img src="https://img.shields.io/badge/latest%20published-v0.1.1-7a4a22?style=flat-square" alt="Latest published version: v0.1.1">
  <img src="https://img.shields.io/badge/next%20patch-v0.1.2%20in%20development-8a6a3f?style=flat-square" alt="Next patch: v0.1.2 in development">
  <img src="https://img.shields.io/badge/network-DOM%20Mainnet-3d2f22?style=flat-square" alt="Network: DOM Mainnet">
  <img src="https://img.shields.io/badge/language-Rust-7a4a22?style=flat-square" alt="Language: Rust">
  <img src="https://img.shields.io/badge/license-MIT-8a6a3f?style=flat-square" alt="License: MIT">
</p>

# DOM Wallet V3

> Secure state. Deterministic recovery. Native DOM sovereignty.

DOM Wallet V3 is the native desktop wallet architecture for the DOM Protocol.

It combines a Tauri desktop application, a canonical wallet state machine, an embedded DOM node, DOM-native recovery, Slate v4 transaction handling, chain-bound synchronization, and deterministic operational diagnostics.

The project is experimental. DOM initially has no monetary value. Do not use real funds. No independent security audit is claimed.

---

## Important Safety Notice

DOM Wallet V3 is experimental software.

Before using it, understand the following:

- DOM initially has no monetary value.
- Do not use real funds.
- Do not share your 24-word recovery phrase.
- Store your recovery phrase offline.
- Never paste a seed phrase into chat, email, issue trackers, screenshots, logs, or support messages.
- Unsigned installers may trigger operating-system warnings.
- No independent security audit is claimed.
- Mainnet launch, mining, peer discovery, wallet synchronization, and transaction behavior remain under active validation.
- Bugs may cause loss of local wallet state, failed synchronization, transaction failure, or other operational problems.
- Recovery Capsule and backup features reduce risk but do not replace safe seed storage.

---

## Project Status

### Latest published release

`wallet-v0.1.1`

The v0.1.1 patch corrected the packaged Tauri native-command bridge failure present in v0.1.0.

### Current development target

`wallet-v0.1.2`

The v0.1.2 patch is being developed to complete the following work:

- Mainnet-only user experience.
- Preconfigured embedded-node networking.
- Automatic connection to the official DOM Mainnet seeds.
- Correct wallet cursor activation on a genesis-only chain.
- Reliable peer and synchronization diagnostics.
- Restoration of the local CPU mining interface.
- Mining disabled by default.
- Protocol-correct Slate v4 send and receive flows.
- Removal of misleading unilateral address-transfer UX.
- Packaged-runtime validation against the live Mainnet bootnode.

### Current release maturity

| Area | State |
|---|---|
| Native desktop shell | Implemented |
| Tauri command bridge | Implemented in v0.1.1 |
| Embedded DOM node | Implemented |
| DOM Mainnet identity | Implemented |
| BIP-39 wallet creation and restore | Implemented |
| Recovery Capsule v1 | Implemented |
| Chain-bound backup | Implemented |
| Slate v4 protocol layer | Implemented |
| Mainnet peer discovery | Under active correction for v0.1.2 |
| Genesis-only cursor synchronization | Under active correction for v0.1.2 |
| Full mining UI | Under active restoration for v0.1.2 |
| Packaged Mainnet acceptance | In progress |
| Real-fund authorization | Not authorized |
| Independent audit | Not completed |

---

## What DOM Wallet V3 Is

DOM Wallet V3 is not a browser wallet, remote-node dashboard, or thin HTTP client.

Its intended production architecture is:

```text
Desktop UI
    ↓
Tauri command boundary
    ↓
Wallet service
    ↓
Production wallet backend
    ↓
Embedded DOM node
    ↓
Native Noise/P2P networking
    ↓
DOM Mainnet
```

The Wallet does not treat a remote HTTP API as authoritative.

The public VPS nodes are P2P bootstrapping infrastructure, not centralized wallet backends.

---

## Mainnet Identity

DOM Wallet V3 is aligned with the finalized DOM Mainnet genesis.

### Canonical Mainnet chain ID

```text
f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b
```

### Canonical Mainnet genesis hash

```text
182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce
```

### Mainnet P2P port

```text
33369
```

### Genesis inscription

```text
Not a store of value. A means of exchange.
```

### Initial monetary facts

```text
Premine: 0 noms
Height-one reward: 3,300,000,000 noms
Maximum theoretical issuance: 3,299,996,676,900,000 noms
```

---

## Mainnet-Only Product Direction

Starting with the v0.1.2 product direction, the desktop Wallet is intended to operate as a Mainnet-only user application.

The ordinary user interface must not require manual entry of:

- Network.
- Chain ID.
- Genesis hash.
- Node data directory.
- Local listen address.
- Remote RPC endpoint.
- Bootnode address.
- Seed address.
- Backend type.

The Wallet must choose the canonical Mainnet configuration automatically and fail closed when existing data belongs to another network.

Developer and protocol test environments may continue to exist in source code and automated tests, but they are not part of the ordinary end-user wallet flow.

---

## Embedded Node

The embedded DOM node is a core part of the Wallet.

When the Wallet starts, the intended lifecycle is:

```text
Wallet opens
    ↓
Embedded node starts
    ↓
Canonical Mainnet identity is verified
    ↓
Persisted peers are loaded
    ↓
Official seeds are resolved
    ↓
P2P connections are established
    ↓
Wallet cursor starts
    ↓
Canonical outputs are scanned
    ↓
Wallet becomes synchronized
```

The embedded node provides:

- Canonical chain validation.
- Native P2P networking.
- Noise handshake support.
- Peer discovery.
- Peer exchange.
- Block synchronization.
- Transaction relay.
- Local canonical chain state.
- Wallet scan support.
- Mining integration when explicitly enabled.

The embedded node must not mine automatically.

---

## Official Mainnet Seeds

The canonical seed names are:

```text
seed1.dom-protocol.org
seed2.dom-protocol.org
seed3.dom-protocol.org
```

The Wallet must use them for P2P bootstrapping.

A resilient connection policy should use:

1. previously verified persisted peers;
2. DNS seed results;
3. a fixed bootstrap fallback when required;
4. peers learned through PEX.

Failure of one seed must not prevent use of another valid seed.

Seed resolution failures must use bounded retry and backoff. They must not create an uncontrolled warning loop.

---

## Synchronization Model

DOM Wallet V3 does not consider height alone sufficient.

The canonical wallet cursor is bound to:

```text
height + block hash
```

This protects against:

- same-height reorganizations;
- lower-height reorganizations;
- stale canonical views;
- mismatched chain state;
- incomplete recovery;
- invalid source responses.

A genesis-only Mainnet is still a valid chain state.

At height `0`, the correct state is:

```text
Canonical chain height: 0
Wallet cursor height: 0
Network identity: verified
Genesis identity: verified
Synchronization result: success
```

The Wallet must not treat the absence of block `1` as a synchronization failure.

---

## Peer and Network Diagnostics

The Wallet is intended to expose truthful, redacted diagnostics.

Expected network information includes:

- Application state.
- Embedded-node lifecycle.
- Mainnet identity.
- Canonical height.
- Wallet cursor height.
- Connected inbound peers.
- Connected outbound peers.
- Total connected peers.
- Known peer count.
- Highest peer height.
- Bootstrap phase.
- Last successful peer connection.
- Last typed connection error.
- Seed-resolution summary.
- Last synchronization result.

Diagnostics must not expose:

- Seed phrases.
- Private keys.
- Wallet passwords.
- Output blindings.
- Recovery roots.
- Noise private state.
- Bearer tokens.
- Unredacted private filesystem paths.

---

## Wallet Lifecycle

The Wallet lifecycle includes:

```text
Create
Restore
Locate
Unlock
Lock
Close
```

Creation and restore use DOM-native wallet contracts.

Ordinary creation should require only:

```text
Wallet name
Password
Create
```

Mainnet and node settings are preconfigured.

### Wallet creation

A new wallet uses:

- 24-word BIP-39 recovery phrase.
- Canonical Mainnet identity.
- Encrypted local state.
- Embedded Mainnet node configuration.
- Chain-bound wallet metadata.

### Wallet restore

Restore supports:

- BIP-39 seed-only recovery.
- Chain rescan.
- Recovery Capsule v1.
- Full backup recovery where available.
- Typed failure when network identity does not match.

---

## Recovery Model

Recovery is a first-class architectural requirement.

### Seed-only recovery

Seed-only recovery can reconstruct seed-derived ownership and rescan canonical chain state.

It does not necessarily reconstruct every piece of off-chain transaction context.

### Recovery Capsule v1

Recovery Capsule v1 preserves the DOM-defined recovery material required by the Wallet without inventing custom cryptography.

### Full backup

A full backup may preserve additional state such as:

- Wallet metadata.
- Chain cursor.
- Transaction records.
- Private transaction contexts.
- Recovery evidence.
- Operational preferences.

Backups remain additional protection. They do not replace safe seed storage.

---

## Transaction Model

DOM transactions use the canonical interactive Slate v4 workflow.

DOM Wallet V3 must not present DOM as a unilateral address-transfer system.

### Sender flow

```text
Enter amount
    ↓
Estimate fee
    ↓
Optional expiry height
    ↓
Create Slate v4 request
    ↓
Export request
    ↓
Receive participant response
    ↓
Import response
    ↓
Validate signatures and context
    ↓
Finalize
    ↓
Broadcast
```

### Receiver flow

```text
Import Slate v4 request
    ↓
Validate network and chain identity
    ↓
Validate amount, fee, expiry, and version
    ↓
Complete receiver participant data
    ↓
Create response
    ↓
Export response
```

### Address v1

Address v1 may be used only where the DOM protocol actually requires it for identity, routing, or transport.

Address v1 does not replace:

- Slate construction.
- Participant completion.
- Signature validation.
- Transaction finalization.
- Broadcast.

### Production restrictions

Production code must not permit:

- Slate v3 transaction creation.
- Proof-only output creation.
- Address-only unilateral send shortcuts.
- Logging of private transaction context.
- Logging of private blindings.
- Custom recovery cryptography.

---

## Mining

DOM Wallet V3 is intended to restore the integrated local CPU mining experience available in earlier DOM wallet generations.

The required product surface is:

```text
Mining
├── Enable mining
├── CPU threads
├── Mining address
├── Hashrate
├── Current height
├── Connected peers
├── Accepted blocks
└── Start / Stop mining
```

### Mining defaults

```text
Enabled: false
Running: false
```

Opening, unlocking, restoring, synchronizing, or navigating to the Mining page must never start mining automatically.

### Enable mining

`Enable mining` permits the feature to be configured.

It does not start mining by itself.

### CPU threads

The Wallet should allow selection from `1` to the available logical CPU count.

A safe default is approximately half of available logical CPUs.

### Mining address

The mining destination must be:

- owned by the current wallet;
- validated by the DOM protocol;
- public-only;
- never derived by sending a seed or private key to the miner.

### Start mining

Mining starts only after an explicit user action.

Before starting, the Wallet should verify:

- Wallet unlocked.
- Mainnet identity valid.
- Embedded node ready.
- Wallet cursor initialized.
- Mining destination valid.
- CPU thread count valid.
- Explicit user confirmation obtained.

At height `0`, the Wallet should warn:

```text
Starting mining may produce the first post-genesis Mainnet block.
```

### Stop mining

Stopping must:

- stop work generation;
- stop active mining workers;
- preserve canonical node operation;
- avoid restarting the whole Wallet;
- report a truthful stopped state.

### Mining metrics

Metrics must come from the real miner runtime:

- Hashrate.
- Current height.
- Connected peers.
- Accepted blocks.
- Rejected or stale work.
- Last candidate time.
- Last accepted block height.
- Mining uptime.

The UI must not fabricate shares when the DOM miner does not implement pool-share semantics.

---

## Application Screens

The target desktop application includes:

- Access.
- Dashboard.
- Wallet.
- Send.
- Receive.
- Transactions.
- Recovery.
- Backup.
- Node.
- Network.
- Mining.
- Settings.
- Diagnostics.

The exact navigation may evolve, but protocol responsibilities must remain distinct.

---

## Security Properties

DOM Wallet V3 is designed around the following properties.

### Canonical state

Identity, accounts, outputs, reservations, transaction records, private contexts, cursor, and recovery evidence share one versioned model.

### Explicit state machines

Valid and invalid transitions are part of the implementation contract.

### Atomic durable operations

A logical operation either commits as one durable unit or remains recoverable as the prior generation.

### Crash recovery

Persistent operations define reopen and restart behavior.

### Idempotent replay

Repeated requests, scans, restores, and recovery plans must not create duplicate logical effects.

### Chain binding

Wallet state is bound to the canonical DOM chain identity.

### Reorganization handling

Removed receives, spends, maturity transitions, cursor movement, and local intent are reconciled explicitly.

### Secret non-reuse

Allocation and transaction-secret evidence must survive restart, restore, and migration.

### Least privilege

Unlocking, spending, receiving, backup, administration, mining, and observation use separate capability boundaries.

### Deterministic testability

Time, randomness, storage faults, crashes, sources, peer behavior, and reorganizations must be controllable in tests.

---

## Security Boundaries

Production Wallet code must preserve all of the following:

```text
Direct HTTP wallet authority: none
Slate v3 production creation: none
Proof-only output creation: none
Proof rewind dependency: none
Custom recovery cryptography: none
Browser wallet persistence: none
DOM Wallet V1/V2 runtime dependency: none
Automatic mining: none
Real-fund authorization: none
Independent-audit claim: none
```

---

## Architecture

```text
┌──────────────────────────────────────────────┐
│               Desktop Interface              │
│  Access · Dashboard · Slate · Mining · Node │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│              Tauri Command Boundary          │
│      Redacted DTOs · Typed Errors · IPC      │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│                Wallet Service                │
│ Lifecycle · Sync · Recovery · Transactions   │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│           Production Wallet Backend          │
│ Canonical state · Persistence · Reconciliation│
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│              Embedded DOM Node               │
│ P2P · Chain · Mempool · Relay · Mining      │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│                 DOM Mainnet                  │
│       Noise P2P · Seeds · PEX · Blocks       │
└──────────────────────────────────────────────┘
```

---

## Workspace Structure

| Path | Responsibility |
|---|---|
| `crates/dom-wallet-domain` | Canonical wallet state, invariants, and transitions. |
| `crates/dom-wallet-crypto` | DOM-native wallet cryptographic boundaries. |
| `crates/dom-wallet-storage` | Encrypted persistence, atomic units of work, backup, and recovery. |
| `crates/dom-wallet-chain` | Chain source, synchronization, cursor, and reorganization handling. |
| `crates/dom-wallet-protocol` | Revision-pinned DOM transaction, Slate, fee, proof, and serialization adapter. |
| `crates/dom-wallet-core` | Wallet lifecycle, orchestration, diagnostics, recovery, and capability APIs. |
| `crates/dom-wallet-tauri-shell` | Native Tauri command boundary and packaged desktop runtime. |
| `frontend` | Desktop user interface. |
| `.github/workflows` | Validation and multiplatform release automation. |
| `docs` | Architecture, implementation, release, and operational documentation. |
| `specs` | Normative Wallet V3 specifications. |
| `reports` | Engineering, validation, audit, and release evidence. |

---

## Building from Source

### Prerequisites

Typical requirements include:

- Rust toolchain defined by `rust-toolchain.toml`.
- Cargo.
- Node.js.
- npm.
- Tauri system dependencies.
- C/C++ build toolchain.
- CMake.
- pkg-config.
- OpenSSL development libraries.
- Linux WebKit/GTK dependencies where applicable.

### Frontend

```bash
cd frontend
npm ci
npm test
npm run build
```

### Rust validation

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

### Security and dependency checks

```bash
cargo audit
cargo deny check advisories
cargo deny check bans
cargo deny check licenses
cargo deny check sources
```

### Desktop development

Use the repository-defined Tauri development command.

Typical form:

```bash
cargo tauri dev
```

or:

```bash
cargo run -p dom-wallet-tauri-shell
```

The canonical command is the one documented by the current workspace scripts and package configuration.

### Production package

```bash
cargo tauri build --bundles appimage,deb,rpm -- --locked
```

Release automation also builds:

- Linux x86_64.
- Windows x86_64.
- macOS arm64.

---

## Installing a Linux Release

For the Debian package:

```bash
cd ~/Downloads
sudo apt install ./DOM.Wallet.V3_<VERSION>_amd64.deb
```

For an artifact with platform prefix:

```bash
cd ~/Downloads
sudo apt install ./dom-wallet-linux-x86_64-DOM.Wallet.V3_<VERSION>_amd64.deb
```

Confirm installation:

```bash
dpkg -s dom-wallet-v3 | grep '^Version:'
```

Launch from the desktop application menu or:

```bash
dom-wallet-v3
```

Unsigned packages may trigger warnings. Verify release checksums before installation.

---

## Release Verification

Every release should provide:

- Exact Git tag.
- Exact source commit.
- Platform-specific artifacts.
- SHA-256 checksum manifest.
- Experimental warning.
- No-real-funds warning.
- Unsigned-installer warning.
- Build workflow evidence.

Verify a downloaded artifact:

```bash
sha256sum <artifact>
```

Compare the result with the checksum published in the corresponding GitHub Release.

---

## Release History

### v0.1.0

First experimental public desktop release.

Known packaged-runtime defect:

- Native Tauri command bridge could be unavailable.
- Buttons could render but remain nonfunctional.

v0.1.0 should be treated as superseded.

### v0.1.1

Native bridge correction.

Validated:

- Packaged Tauri bridge.
- Native command invocation.
- Linux, Windows, and macOS packaging.
- Release checksums.
- Experimental release workflow.

Known active issue:

- Mainnet embedded-node peer discovery and cursor activation require correction.

### v0.1.2

In development.

Planned focus:

- Mainnet-only product flow.
- Preconfigured server and node settings.
- Real P2P connection to the official bootnode.
- Cursor activation at height `0`.
- Improved peer and sync diagnostics.
- Restored mining module.
- Protocol-correct Slate v4 interface.

---

## Testing Strategy

DOM Wallet V3 uses layered verification.

### Unit tests

- State transitions.
- Typed failures.
- Input validation.
- Fee calculations.
- Cursor invariants.
- Mining configuration.
- Slate parsing and validation.

### Property tests

- Idempotency.
- Reservation uniqueness.
- Allocation non-reuse.
- Reconciliation equivalence.
- Corruption rejection.
- Canonical serialization.

### Restart tests

- Wallet creation.
- Unlock.
- Reservation.
- Slate creation.
- Backup.
- Restore.
- Cursor movement.
- Mining start and stop.

### Reorganization tests

- Same-height reorganization.
- Lower-height reorganization.
- Removed outputs.
- Removed spends.
- Maturity rollback.
- Cursor rollback.
- Replay of local intent.

### Networking tests

- DNS seed resolution.
- Seed failure isolation.
- Bootnode fallback.
- Noise handshake.
- Peer registration.
- PEX persistence.
- Self-connection rejection.
- Connection backoff.
- Genesis-only synchronization.

### Packaged-runtime tests

A release is not accepted only because frontend tests or `cargo check` pass.

The actual packaged application must be tested for:

- Window creation.
- Native bridge.
- Mainnet identity.
- Embedded node startup.
- Peer connection.
- Cursor activation.
- Synchronization.
- Slate actions.
- Mining disabled by default.
- No secret leakage.

---

## Mainnet Operational Expectations

Before block `1` exists, a valid node may show:

```text
Canonical height: 0
Genesis: present
Peers: one or more
Mining: disabled
```

This is a valid pre-launch state.

A Wallet connected to the Mainnet node should show:

```text
Network: MAINNET
Chain ID: verified
Genesis: verified
Connected peers: at least 1
Canonical height: 0
Wallet cursor: 0
Synchronization: complete
Mining: disabled
```

No block should be mined during connectivity validation.

---

## Troubleshooting

### Native desktop command bridge unavailable

Upgrade from v0.1.0 to v0.1.1 or later.

Confirm:

```bash
dpkg -s dom-wallet-v3 | grep '^Version:'
```

### Wallet opens but does not synchronize

Check:

- Current Wallet version.
- Mainnet identity.
- Connected peer count.
- Seed resolution.
- P2P port access.
- Cursor state.
- Typed last error.

Test the public Mainnet seed:

```bash
dig seed1.dom-protocol.org +short
nc -vz seed1.dom-protocol.org 33369
```

### Height remains zero

Height `0` is expected before the first post-genesis block is mined.

The important distinction is:

```text
Height 0 + connected peers + cursor 0 = valid synchronized pre-launch state
Height 0 + no peers + null cursor = synchronization defect or disconnected node
```

### Mining does not start

Expected checks include:

- Mining feature enabled.
- Explicit Start Mining action.
- Wallet unlocked.
- Node ready.
- Cursor active.
- Valid reward destination.
- Valid CPU thread count.
- Confirmation accepted.

### Package installation warning

A local `.deb` may produce an `_apt` sandbox warning when installed from a user-owned directory.

This warning does not necessarily indicate installation failure.

Confirm the installed version afterward.

---

## Known Limitations

- Experimental software.
- No independent security audit.
- Unsigned installers.
- Real-fund use is not authorized.
- Public Mainnet validation is ongoing.
- Mining UI restoration is still in development until v0.1.2 is completed.
- Mainnet peer and cursor behavior is under active correction until v0.1.2 is completed.
- Hardware-wallet support is not implemented.
- Mobile versions are not implemented.
- Automatic Slate transport is not guaranteed.
- Exchange integration is not claimed.
- Long-duration multi-node operational evidence remains limited.

---

## Roadmap

### v0.1.2

- Mainnet-only user flow.
- Internal server configuration.
- Official seed bootstrap.
- Embedded-node Mainnet connectivity.
- Cursor activation at genesis.
- Peer diagnostics.
- Mining controls.
- Slate v4 UX correction.
- Packaged live-node acceptance.

### Near-term

- Extended multi-node testing.
- Long-running synchronization tests.
- Reorganization validation under live conditions.
- Improved transaction history.
- Better recovery UX.
- Better node and mining telemetry.
- Installer signing strategy.
- Additional seed operators.

### Future

- Hardware-wallet support.
- Optional automated Slate transport.
- Advanced node controls.
- More recovery tooling.
- Independent external review.
- Broader platform support.
- Public operational monitoring.

---

## DOM Sovereignty

DOM Wallet V3 follows only:

- DOM consensus.
- DOM cryptographic primitives.
- DOM chain identity.
- DOM transaction formats.
- DOM Slate formats.
- DOM fee and weight rules.
- DOM coinbase and maturity rules.
- DOM privacy requirements.
- DOM backup and recovery contracts.
- DOM mining rules.
- DOM P2P rules.

DOM Wallet V1 and V2 are historical sources of validated DOM behavior and lessons.

They are not runtime dependencies of V3.

External wallet projects may inform engineering methodology, but they do not define DOM protocol behavior.

```text
DOM semantics > external wallet strategy
```

---

## Specifications and Documentation

Core documentation is maintained in:

- [`specs/README.md`](specs/README.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/ENGINEERING_SOURCES.md`](docs/ENGINEERING_SOURCES.md)
- [`docs/REFERENCE_BASELINE.md`](docs/REFERENCE_BASELINE.md)
- [`docs/CONFIRMED_DESIGN_INPUTS.md`](docs/CONFIRMED_DESIGN_INPUTS.md)
- [`docs/NODE_CONFIGURATION.md`](docs/NODE_CONFIGURATION.md)
- [`docs/BUILD_AND_RUN.md`](docs/BUILD_AND_RUN.md)
- [`docs/TRANSACTION_ENGINE.md`](docs/TRANSACTION_ENGINE.md)
- [`docs/MANUAL_SLATE_EXCHANGE.md`](docs/MANUAL_SLATE_EXCHANGE.md)
- [`reports/`](reports/)

Some historical documents describe earlier project phases and may not reflect the latest release state. The tagged source, current README, release report, and release manifest take precedence for a specific version.

---

## Contributing

Contributions must preserve:

- DOM sovereignty.
- Finalized chain identity.
- Canonical wallet state.
- Explicit failure behavior.
- Deterministic recovery.
- No secret leakage.
- No hidden remote authority.
- No automatic mining.
- Protocol-correct Slate handling.
- Reproducible tests.
- Non-destructive Git history.

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before contributing.

A valid contribution should identify:

1. the governing specification;
2. the affected invariant;
3. the failure model;
4. the required tests;
5. the migration or compatibility impact;
6. the security impact.

---

## Responsible Disclosure

Do not disclose active vulnerabilities publicly before maintainers have had a reasonable opportunity to investigate.

Never include:

- seed phrases;
- private keys;
- passwords;
- wallet databases;
- output blindings;
- recovery roots;
- private Slate context;
- authentication tokens.

Use the repository security policy where available:

- [`SECURITY.md`](SECURITY.md)

---

## Authorship

Soren Planck  
<sorenplanck@tutamail.com>

Commit trailers naming a second author or automated-tool attribution are prohibited by project policy.

---

## License

DOM Wallet V3 is licensed under the MIT License.

See:

- [`LICENSE`](LICENSE)

---

<p align="center">
  <strong>DOM Wallet V3</strong><br>
  Secure state. Deterministic recovery. Native DOM sovereignty.
</p>

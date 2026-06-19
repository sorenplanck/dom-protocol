<div align="center">

# DOM Protocol

### Not a store of value. A means of exchange.

**DOM is a Mimblewimble blockchain with CPU-mined RandomX proof-of-work.
Confidential by construction, fixed in supply, and built to circulate.**

![status](https://img.shields.io/badge/status-active%20hardening-E8A23D)
![consensus](https://img.shields.io/badge/consensus-Mimblewimble-8B7DF0)
![pow](https://img.shields.io/badge/PoW-RandomX-3FB68B)
![mainnet](https://img.shields.io/badge/mainnet-not%20launched-555)

[Whitepaper](WHITEPAPER.md) · [Roadmap](docs/ROADMAP_v3.md) · [Known Issues](KNOWN_ISSUES.md)

</div>

> **Pre-launch.** The consensus, cryptography, storage, wallet, and node layers
> are implemented and under active adversarial hardening. There is no mainnet
> yet — and when it launches, it launches from block zero for everyone.

---

## Table of Contents

- [What DOM is](#what-dom-is)
- [How it launches](#how-it-launches)
- [Monetary policy](#monetary-policy)
- [Consensus](#consensus)
- [Repository layout](#repository-layout)
- [Build & run](#build--run)
- [Security & validation](#security--validation)
- [Status](#status)
- [Contributing](#contributing)
- [License](#license)

## What DOM is

DOM is sound money built to be spent, not hoarded. It uses the Mimblewimble
construction — transaction amounts are hidden inside Pedersen commitments and
proven valid with Bulletproof range proofs, while the chain stays compact through
cut-through. Proof-of-work is RandomX, which is CPU-optimized, so mining stays
accessible to ordinary hardware rather than concentrating in specialized rigs.

The design is conservative by intent: identical inputs must produce identical
results across every node and platform; partial or corrupted state must be
detected and refused rather than silently carried forward; and validation,
block structure, and resource use stay inside explicit, bounded limits. Monetary
and consensus rules are treated as infrastructure — fixed at genesis, guarded by
consensus-level assertions in the code, not adjustable later.

DOM is a protocol, not a company's product. No component — including its
author — can mint outside the schedule, freeze a balance, or seize funds. The
guarantees are enforced by the chain itself. Don't trust it; verify it.

## How it launches

DOM launches the way sound money should: **mainnet from block zero — no premine,
no private round, no public testnet.** A public testnet would create insiders —
people holding coins and running infrastructure before everyone else. DOM refuses
that. The chain is validated *before* the first block, so that everyone who joins,
joins at block zero, on equal terms.

That validation does not happen in public on a live network. It happens here,
before launch, through two mechanisms:

- **The project's own audit software** — a security framework that fuzzes the
  consensus-critical paths, checks invariants against inflation and double-spend,
  and runs a catalog of Mimblewimble attacks against the chain.
- **A private burn-in** — a real, continuous chain run by a single operator before
  block zero, to surface the time-dependent issues that only sustained operation
  reveals.

Launch is milestone-based, not calendar-based. Each gate opens only when its work
is actually done.

## Monetary policy

All values are enforced by consensus-level assertions in `dom-core` — they cannot
change without breaking the build.

| Parameter | Value |
|-----------|-------|
| **Supply cap** | 33,000,000 DOM |
| **Initial block reward** | 33 DOM |
| **Halving interval** | 330,000 blocks (~1.25 years) |
| **Halving epochs** | 55 (last reward in epoch 54) |
| **Max supply (noms)** | 3,299,999,976,900,000 |
| **Coin unit** | 1 DOM = 100,000,000 noms |
| **Coinbase maturity** | 1,000 blocks |
| **Target block time** | 2 minutes |

## Consensus

| Parameter | Value |
|-----------|-------|
| **Construction** | Mimblewimble (confidential, cut-through) |
| **PoW** | RandomX (CPU-optimized) |
| **Difficulty** | ASERT — half-life 288 blocks (34,560 s) |
| **Hash** | Blake2b-256 (tagged / domain-separated) |
| **Signatures** | Schnorr (secp256k1, BIP-340) |
| **Range proofs** | Bulletproofs (grin backend, 2^52 range) |
| **Commitments** | Pedersen (secp256k1, H_DOM via RFC 9380) |

### Limits

| Limit | Value |
|-------|-------|
| Max block weight | 40,000 units |
| Max transaction weight | 4,000 units |
| Max inputs / outputs per tx | 255 / 255 |
| Max kernels per tx | 16 |
| Max transactions per block | 5,000 |
| Max proof size | 768 bytes |
| Max block size | 16 MiB |
| Max future timestamp | 2 minutes |
| Median-time window | 11 blocks |

### Network identity

| Parameter | Mainnet | Testnet |
|-----------|---------|---------|
| Network magic | `0x444F4D31` ("DOM1") | `0x444F4D54` ("DOMT") |
| P2P port | 33369 | 33370 |
| Genesis hash | unfinalized until launch | `13236b79…247b630c` |

## Repository layout

A Rust workspace of 27 crates. The consensus-critical core is the must-audit
heart; the rest is tooling, wallets, and runtime.

```
dom-protocol/
├── dom-core/            Constants, types, errors (consensus-critical)
├── dom-crypto/          Schnorr, Pedersen, Bulletproofs, H_DOM
├── dom-serialization/   Canonical encode/decode
├── dom-pmmr/            Pruned Merkle Mountain Range
├── dom-pow/             RandomX, ASERT, difficulty math
├── dom-consensus/       Transaction & block validation
├── dom-tx/              Spend construction, transactions, coinbase
├── dom-slate/           Interactive transaction building (slate exchange)
├── dom-chain/           ChainState, connect_block, reorg
├── dom-store/           LMDB persistence
├── dom-mempool/         Mempool
├── dom-node/            P2P, mining, IBD
├── dom-wire/            Wire codec, handshake, messages
├── dom-rpc/             JSON-RPC
├── dom-config/          Config parsing
├── dom-wallet*/         Wallet (KDF, encrypted persistence, keys, app)
├── dom-integration-tests/  Multi-node & end-to-end tests
└── …                    CLI, explorer, faucet, test tooling
```

## Build & run

### Build

```bash
git clone https://github.com/sorenplanck/dom-protocol
cd dom-protocol
cargo build --release
```

### Run a testnet node

```bash
./target/release/dom-node --testnet
```

The miner is integrated and starts automatically.

### Test

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

## Security & validation

DOM treats hardening as the work, not an afterthought. Priority order is fixed:
**security > stability > usability.**

**Implemented safeguards**

- Confidential amounts via Pedersen commitments with Bulletproof range proofs
- Schnorr signatures with chain-id binding (replay protection)
- Balance equation enforced in commitment space (Mimblewimble value conservation)
- ASERT difficulty (smooth, non-exploitable retargeting)
- Coinbase maturity (1,000 blocks)
- Checked arithmetic throughout (no silent overflow)
- Tagged hashing for domain separation

**How validation works**

Findings are produced by the project's own audit software — fuzzing of
consensus-critical paths, property tests for consensus invariants (no inflation,
no double-spend), and a Mimblewimble attack catalog — and recorded as measured
engineering facts. The no-inflation invariant, for example, is verified by a
property test that drives thousands of adversarial transactions through the
balance equation; the strongest assertion is that no accepted transaction
increases the committed-value sum.

To report a vulnerability privately, see `SECURITY.md`.

## Status

| Layer | State |
|-------|-------|
| Consensus & immutability | implemented |
| Cryptographic core (Bulletproofs) | implemented |
| Storage durability & recovery | implemented |
| Multi-node & end-to-end tests | implemented |
| Security audit framework | in progress |
| Adversarial hardening | ahead |
| Private burn-in | ahead |
| Mainnet from block zero | ahead |

Full plan, without dates, in [docs/ROADMAP_v3.md](docs/ROADMAP_v3.md).

## Contributing

Issues and pull requests are welcome. Every commit must pass
`cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
and `cargo fmt --check`, and reference the relevant RFC or design note in its
message.

## Contact

- **Author:** Soren Planck
- **Email:** sorenplanck@tutamail.com
- **Repository:** github.com/sorenplanck/dom-protocol

## License

[TBD]

---

<div align="center">

**No premine. No private round. No public testnet. Mainnet from block zero, for everyone.**

</div>

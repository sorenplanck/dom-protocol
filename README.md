# DOM Protocol

**A peer-to-peer electronic cash system.**

> "Not a store of value. A means of exchange."

---

## What is DOM

DOM is a privacy-preserving cryptocurrency designed to be used as money — for everyday payments, not as a speculative asset.

Bitcoin promised peer-to-peer electronic cash. It became digital gold. DOM exists to fill the gap Bitcoin left: a fast, private, fungible currency for actual transactions.

DOM combines:

- **Mimblewimble** — transactions reveal no addresses, no amounts, no balances. Only the validity of the conservation equation `inputs = outputs + fee` is publicly verifiable.
- **RandomX proof-of-work** — CPU-friendly mining, ASIC-resistant by design. Anyone with a laptop can participate.
- **ASERT difficulty adjustment** — smooth, every-block difficulty retargeting. No oscillations, no manipulation windows.
- **Bulletproofs+ range proofs** — confidential amounts without trusted setup.
- **Cut-through** — old transaction data is pruned. The chain stays small forever.

There is no premine. No ICO. No reserved tokens. No foundation cut. Block 0 is mineable by anyone from the moment the network launches.

---

## Specification

The DOM protocol is fully specified in the [RFC documents](docs/):

- **RFC-0000** — Protocol overview
- **RFC-0008** — Balance equation, coinbase, fees, offsets
- **RFC-0009** — Cryptographic primitives (Schnorr, MuSig2, Bulletproofs+)
- **RFC-0010** — Block validation pipeline
- **RFC-0011** — Bootstrap, PMMR bagging, fee policy, RPC

The specification has been audited eight times. The audit history is in [`docs/RELEASE_BLOCKERS.md`](docs/RELEASE_BLOCKERS.md).

---

## Implementation

The reference implementation is written in Rust. The workspace contains 17 crates covering every layer of the protocol:

```
crates/
├── dom-core            fundamental types, constants, consensus parameters
├── dom-serialization   canonical binary encoding (no Serde, no JSON)
├── dom-crypto          Pedersen, Schnorr, Bulletproofs+, RFC9380 H generator
├── dom-pow             ASERT, RandomX PoW validation
├── dom-pmmr            Pruned Merkle Mountain Range
├── dom-consensus       block, transaction, cut-through, balance verification
├── dom-chain           chain state, block connection
├── dom-store           LMDB-backed persistent storage
├── dom-mempool         transaction pool
├── dom-wire            P2P protocol (Noise XX handshake, message framing)
├── dom-config          node configuration
├── dom-node            full node binary (miner, peer manager, RPC)
├── dom-tx              transaction construction (work in progress)
├── dom-wallet          wallet (work in progress)
├── dom-rpc             RPC server (work in progress)
├── dom-test-vectors    protocol conformance test vectors
└── dom-integration-tests  end-to-end tests
```

---

## Coin Parameters

| Parameter | Value |
|---|---|
| Block time | 2 minutes |
| Initial block reward | 24 DOM |
| Halving interval | 670,725 blocks (~2.55 years) |
| Total supply (approx) | 32,194,800 DOM |
| Smallest unit | 1 nom = 0.00000001 DOM |
| PoW algorithm | RandomX |
| Difficulty adjustment | ASERT (172,800s half-life) |
| Privacy | Mimblewimble + Bulletproofs+ + Dandelion++ |

---

## Build from Source

Requirements:
- Rust 1.78 or newer
- Linux, macOS, or Windows (via WSL2)
- `libclang-dev`, `build-essential`, `cmake`

```bash
git clone https://github.com/sorenplanck/dom-protocol
cd dom-protocol
cargo build --release --workspace
```

Run the full test suite:

```bash
cargo test --workspace
```

165 tests across all crates. Zero failures expected.

---

## Running a Node

```bash
./target/release/dom-node
```

The node will:
1. Verify the H generator on startup (fails fast if not finalized)
2. Open or create the data directory (`./dom-testnet-data` by default)
3. Initialize the chain (genesis if empty)
4. Listen for P2P connections on port 33370 (testnet)
5. Begin mining if configured (`mine = true`)

Configuration via `DOM_LOG` environment variable (`info`, `debug`, `trace`).

---

## Status

DOM is currently in **late testnet preparation**. The consensus protocol is feature-complete and has passed eight rounds of independent security audit. The audit history is public in `docs/RELEASE_BLOCKERS.md`.

What is finished:
- Consensus protocol (Mimblewimble + RandomX + ASERT)
- All cryptographic primitives (Pedersen, Schnorr, Bulletproofs+, hash-to-curve H generator)
- Block and transaction validation pipeline (including cut-through)
- P2P transport (Noise XX, peer manager, ban scoring constants)
- Full node binary with miner

What is in progress:
- Wallet implementation (`dom-wallet` stub)
- Transaction construction crate (`dom-tx` stub)
- RPC server (`dom-rpc` stub)
- Dandelion++ message loop integration

---

## Launch

DOM launches with no advance notice and no privileged access. The genesis timestamp is set on the day of launch. The first miner is whoever runs the binary first. There is no special treatment for early miners — difficulty adjusts to whatever hashrate joins the network.

When the network launches, the genesis hash and the chosen launch timestamp will be published in this README.

---

## Contributing

Issues and pull requests are welcome via GitHub. There is no other contact channel.

The protocol is feature-frozen for the launch. Post-launch development priorities:
- Wallet and transaction construction
- Compact block relay (BIP-152 analogue)
- Hardware wallet integration
- Block explorer

---

## License

MIT. See [LICENSE](LICENSE).

---

## Author

Soren Planck.

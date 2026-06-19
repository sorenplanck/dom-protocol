# DOM Protocol — Regtest Network

**Status:** DEV-ONLY. **NEVER for production.** Adopted 2026-05-24.

`Network::Regtest` is a third runtime network variant alongside `Mainnet`
and `Testnet`. It exists so a developer can drive the full node, miner,
wallet, P2P, RPC, and consensus pipeline on a laptop — without a 2 GB
RandomX dataset per node and without waiting 1000 blocks for a coinbase
to mature.

## Safety guarantees

Regtest is designed so it **cannot leak into a real network**:

| Property | Mainnet | Testnet | Regtest |
| --- | --- | --- | --- |
| Magic bytes (ASCII) | `DOM1` (`0x444F_4D31`) | `DOMT` (`0x444F_4D54`) | `DOMR` (`0x444F_4D52`) |
| Default P2P port | 33369 | 33370 | 33371 |
| Default listener | `0.0.0.0` | `0.0.0.0` | `127.0.0.1` |
| DNS seeds | `seed1/2.dom-protocol.org` | `testnet-seed1.dom-protocol.org` | *(none)* |
| Hardcoded peers | empty | empty | empty |
| PoW target | full ASERT difficulty | `TESTNET_TARGET_COMPACT` floor | `REGTEST_TARGET_COMPACT` |
| Coinbase maturity | 1000 blocks | 1000 blocks | 1 block |
| RandomX VM flags | `recommended \| FLAG_FULL_MEM` (~2.25 GB) | `recommended \| FLAG_FULL_MEM` | `recommended` only (~256 MB cache, no dataset) |

Because the magic byte differs, the framed handshake in `dom-wire`
rejects any peer of the wrong network at the first frame header — there
is no codepath where a Regtest node and a Mainnet node accept each
other as peers. Compile-time assertions in `dom-core/src/constants.rs`
keep the three magic bytes mutually distinct and prevent the canonical
`COINBASE_MATURITY` (1000) from drifting.

## What does *not* change in Regtest

**Consensus logic is identical.** Regtest blocks go through the same
`validate_block` -> `validate_block_transactions` -> per-tx 10-step
pipeline as Mainnet. The same Bulletproofs range proofs, Schnorr
signatures, balance equation, PMMR roots, MTP / future-timestamp gates,
and PoW hash check are enforced. The only differences are the *parameter
values* listed in the table above (target, maturity, VM flags). RFC-0009
spec is honoured byte-for-byte.

`REGTEST_TARGET_COMPACT` lives in `dom-pow` and is intentionally
dev-only. Fast mining, when explicitly enabled for tests, changes only
the PoW hash function; the miner still serializes and validates the
target returned by `compute_expected_target`.

## When to use Regtest

* Integration tests in `dom-integration-tests` (the default since 2026-05-24).
* Local manual experiments where you want a two-node testnet on one
  laptop.
* Debugging mining + wallet + RPC interactions without a 2.25 GB
  RandomX dataset.

## When NOT to use Regtest

* Anywhere that has remote peers.
* Anywhere that publishes a wallet address or accepts funds.
* CI workflows that simulate Mainnet/Testnet network conditions —
  use `Network::Testnet` for that.

## Running a Regtest node

```bash
# Default config, listens on 127.0.0.1:33371, no DNS seeds.
cargo run -p dom-node -- --network regtest --data-dir /tmp/dom-regtest-a

# Second local node, peers with the first.
cargo run -p dom-node -- \
  --network regtest \
  --data-dir /tmp/dom-regtest-b \
  --p2p-listen 127.0.0.1:33381 \
  --seed-peer 127.0.0.1:33371
```

From Rust:

```rust
let config = dom_config::NodeConfig::regtest();
```

## Memory footprint

| Configuration | Per-node RAM | Two-node total |
| --- | --- | --- |
| Mainnet / Testnet miner (`FLAG_FULL_MEM`) | ~2.5 GB | ~5 GB |
| Regtest miner (cache only) | ~300 MB | ~700 MB |
| Regtest validator (no mining) | ~50 MB | ~100 MB |

`spend_e2e` and other two-miner integration tests now complete in
well under two minutes on a developer laptop with 4 GB of free RAM.

## Pinned references

* `dom-core/src/constants.rs` — `NETWORK_MAGIC_REGTEST`,
  `P2P_PORT_REGTEST`, `REGTEST_COINBASE_MATURITY`,
  `GENESIS_HASH_REGTEST`.
* `dom-pow/src/lib.rs` — `REGTEST_TARGET_COMPACT`,
  `pow_params_for_network`, `compute_expected_target`,
  `pow_validation_mode_for_network`.
* `dom-config/src/lib.rs` — `Network::Regtest`, `NodeConfig::regtest()`.
* `dom-chain/src/chain_state.rs` — `coinbase_maturity_for_magic`.
* `dom-store/src/utxo.rs` — `UtxoEntry::is_mature_for`,
  `UtxoSet::validate_input_with_maturity`.
* `dom-wallet/src/types.rs` — `Network::Regtest`, `coinbase_maturity()`.
* `dom-node/src/miner.rs` — explicit `MiningMode` classification and
  Regtest cache-only / fast-dev mining dispatch.

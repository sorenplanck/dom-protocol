# DOM network modes

This document describes the network modes that exist in the current codebase
and how operators should use them. It is documentation only; consensus rules
are implemented in `dom-core`, `dom-config`, `dom-pow`, `dom-chain`, and
`dom-node`.

## Current implementation status

The runtime `dom_config::Network` enum currently has exactly three values:

- `Mainnet`
- `Testnet`
- `Regtest`

There is no separate `Devnet` enum variant or distinct devnet network magic in
the code today. A devnet deployment must therefore be an operational profile
using either:

- `Network::Testnet` for multi-host devnet/testnet-like operation; or
- `Network::Regtest` for local-only development and CI.

Mainnet is not finalized. `GENESIS_HASH_MAINNET` is still the zero placeholder
and startup is guarded so mainnet cannot run as finalized production.

## Network IDs and ports

| Mode | Code enum | Magic | ASCII | Default P2P port | Default listener |
| --- | --- | --- | --- | --- | --- |
| Mainnet | `Network::Mainnet` | `0x444F_4D31` | `DOM1` | `33369` | `0.0.0.0:33369` |
| Testnet | `Network::Testnet` | `0x444F_4D54` | `DOMT` | `33370` | `0.0.0.0:33370` |
| Regtest | `Network::Regtest` | `0x444F_4D52` | `DOMR` | `33371` | `127.0.0.1:33371` |
| Devnet | no distinct enum | use Testnet or Regtest | use selected network | use selected network | operator configured |

Source of truth:

- `crates/dom-core/src/constants.rs`
- `crates/dom-config/src/lib.rs`

The P2P handshake uses network magic, so nodes on different network IDs reject
each other.

## Genesis constants

| Mode | Genesis hash status | Genesis timestamp |
| --- | --- | --- |
| Mainnet | `GENESIS_HASH_MAINNET = [0u8; 32]`, not finalized | `GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER` |
| Testnet | `GENESIS_HASH_TESTNET`, pinned non-placeholder | `GENESIS_TIMESTAMP_TESTNET` |
| Regtest | `GENESIS_HASH_REGTEST = [0u8; 32]`, isolated by `DOMR` magic | `GENESIS_TIMESTAMP_TESTNET` |
| Devnet | inherits selected network | inherits selected network |

Mainnet must not be treated as production until the genesis ceremony pins the
real mainnet genesis hash and flips the corresponding readiness guards in the
same reviewed change set.

## Difficulty and mining policy

Consensus target calculation is centralized through
`dom_pow::compute_expected_target`.

| Mode | Difficulty policy | Mining hash mode |
| --- | --- | --- |
| Mainnet | ASERT from `GENESIS_TARGET_COMPACT = 0x1e00_ffff` | RandomX production path |
| Testnet | ASERT with `TESTNET_TARGET_COMPACT = 0x1e7f_ff07` floor | RandomX production/testnet path |
| Regtest | fixed `REGTEST_TARGET_COMPACT = MAX_COMPACT_TARGET` | RandomX cache-only by default; optional `FastDevOnly` only with explicit regtest fast-mining config |
| Devnet | inherits Testnet or Regtest policy | inherits selected network |

`DOM_REGTEST_FAST_MINING=1` is only for regtest/dev-test execution. The
node-side guard fails closed for mainnet/testnet so fast mining cannot weaken
production-like PoW.

Miner CPU throttling (`miner_throttle`) is local resource control only. It does
not affect target calculation, block validity, PoW preimage, wire messages, or
consensus serialization.

## Coinbase maturity

| Mode | Coinbase maturity |
| --- | --- |
| Mainnet | `COINBASE_MATURITY = 1000` |
| Testnet | `COINBASE_MATURITY = 1000` |
| Regtest | `REGTEST_COINBASE_MATURITY = 1` |
| Devnet | inherits selected network |

## Bootstrap peers

Defaults from `NodeConfig`:

| Mode | DNS seeds | Seed peers |
| --- | --- | --- |
| Mainnet | `seed1.dom-protocol.org`, `seed2.dom-protocol.org` | empty |
| Testnet | `testnet-seed1.dom-protocol.org` | empty |
| Regtest | none | empty |
| Devnet | operator configured | operator configured |

The `dom-node` binary also accepts local environment overrides:

- `DOM_SEED_PEERS` — comma-separated `host:port`
- `DOM_P2P_LISTEN_ADDR`
- `DOM_DATA_DIR`
- `DOM_WALLET_PATH`
- `DOM_WALLET_PASSWORD`
- `DOM_LOG`

Do not put wallet passwords, seed phrases, private keys, or tokens in checked-in
config examples or service files.

## Persistence paths

Defaults from `NodeConfig`:

| Mode | Data directory |
| --- | --- |
| Mainnet | `./dom-data` |
| Testnet | `./dom-testnet-data` |
| Regtest | `./dom-regtest-data` |
| Devnet | operator configured |

The backbone systemd service template uses `/var/lib/dom-backbone` via
`DOM_DATA_DIR`.

The wallet desktop app stores local application state under its app data
directory and should be pointed at the intended node URL from the UI. Portable
Windows packaging separates wallet data under `data/wallets/` and chain data
under `data/chain/`.

## Configuration examples

These examples use actual `NodeConfig` field names in JSON form. The current
`dom-node` binary constructs defaults in code and accepts environment
overrides; these examples are for operators or tooling that serialize
`NodeConfig`.

### Mainnet placeholder

Mainnet is not finalized. This example documents field names only and should
not be used for production until mainnet genesis is finalized.

```json
{
  "network": "Mainnet",
  "data_dir": "/var/lib/dom-mainnet",
  "p2p_listen_addr": "0.0.0.0:33369",
  "max_inbound": 125,
  "min_outbound": 8,
  "dns_seeds": ["seed1.dom-protocol.org", "seed2.dom-protocol.org"],
  "seed_peers": [],
  "mine": false,
  "miner_throttle": {
    "enabled": false,
    "yield_every_nonces": 0,
    "sleep_micros": 0
  },
  "miner_address": null,
  "wallet_path": null,
  "wallet_password": null,
  "log_level": "info",
  "rpc_listen_addr": null
}
```

### Testnet / public devnet backbone

```json
{
  "network": "Testnet",
  "data_dir": "/var/lib/dom-backbone",
  "p2p_listen_addr": "0.0.0.0:33370",
  "max_inbound": 50,
  "min_outbound": 4,
  "dns_seeds": ["testnet-seed1.dom-protocol.org"],
  "seed_peers": [],
  "mine": false,
  "miner_throttle": {
    "enabled": false,
    "yield_every_nonces": 0,
    "sleep_micros": 0
  },
  "miner_address": null,
  "wallet_path": null,
  "wallet_password": null,
  "log_level": "info",
  "rpc_listen_addr": null
}
```

For private devnet deployments, prefer environment overrides for peer lists:

```bash
DOM_SEED_PEERS=198.51.100.10:33370,198.51.100.11:33370
DOM_DATA_DIR=/var/lib/dom-backbone
DOM_P2P_LISTEN_ADDR=0.0.0.0:33370
DOM_LOG=info
```

### Regtest

```json
{
  "network": "Regtest",
  "data_dir": "./dom-regtest-data",
  "p2p_listen_addr": "127.0.0.1:33371",
  "max_inbound": 8,
  "min_outbound": 0,
  "dns_seeds": [],
  "seed_peers": [],
  "mine": false,
  "miner_throttle": {
    "enabled": false,
    "yield_every_nonces": 0,
    "sleep_micros": 0
  },
  "miner_address": null,
  "wallet_path": null,
  "wallet_password": null,
  "log_level": "debug",
  "rpc_listen_addr": null
}
```

Use `DOM_REGTEST_FAST_MINING=1` only for regtest/dev-test runs that need fast
local mining.

## Run a backbone node

Use the systemd service package from `docs/BACKBONE_SYSTEMD.md`.

Summary:

```bash
cargo build --release -p dom-node
sudo install -m 0755 target/release/dom-node /usr/local/bin/dom-node
sudo scripts/install_dom_backbone_systemd.sh
sudoedit /etc/dom/backbone.env
sudo ufw allow 33370/tcp
sudo systemctl start dom-backbone
sudo systemctl status dom-backbone --no-pager
journalctl -u dom-backbone -f
```

The current backbone unit is for devnet/testnet operation. It does not enable
mainnet.

## Wallet connection guidance

For devnet/testnet, configure the wallet app to connect to the selected
backbone or local node RPC endpoint. The persisted wallet app state uses:

- `wallet_dir`
- `network`
- `node_url`

For local development, a loopback node URL is appropriate. For VPS-backed
devnet/testnet operation, use the RPC endpoint exposed by that deployment. Do
not publish wallet seed phrases, private keys, passwords, or bearer tokens in
connection examples.

## Safety expectations

- `Regtest` is local/dev-only and must not be used for funds or remote peers.
- `Testnet` and devnet deployments are experimental and may reset.
- `Mainnet` is not finalized in this codebase and must remain fail-closed until
  the genesis ceremony and readiness gates complete.
- Fast mining and CPU throttle are local operational controls, not consensus
  controls.
- Consensus differences must be changed in code, reviewed as protocol changes,
  and covered by release-blocker tests.

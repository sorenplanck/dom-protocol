# Regtest: Local Development Network

**Regtest** is a specialized test network for fast local integration testing and CI pipelines. It provides instant block mining and 1-block coinbase maturity, making end-to-end tests feasible in seconds instead of hours.

## Overview

| Property | Regtest | Testnet | Mainnet |
|----------|---------|---------|---------|
| **Network Magic** | `0x444F_4D52` (DOMR) | `0x444F_4D54` (DOMT) | `0x444F_4D31` (DOM1) |
| **P2P Port** | 33371 | 33370 | 33369 |
| **PoW Target** | Trivial (all hashes pass) | Easy (findable in seconds) | Full ASERT difficulty |
| **Coinbase Maturity** | 1 block | 1000 blocks | 1000 blocks |
| **Use Case** | Local unit/integration tests | Public testnet | Production mainnet |
| **Peering** | Localhost only (127.0.0.1) | Public DNS seeds | Public seed peers |

## Security Guarantees

⚠️ **Regtest is NOT a ledger**. Do not rely on its consensus properties:

- The trivial PoW target accepts ANY RandomX hash
- No difficulty adjustment occurs
- No peer validation of PoW
- Magic byte isolation prevents accidental Mainnet/Testnet peering, but does **not** provide security

Regtest is safe to use **only** for local integration tests where you control all mining and peer connectivity.

## Usage

### Starting a Regtest Node

```bash
# Use the default regtest config
cargo run -p dom-node -- \
  --network regtest \
  --data-dir /tmp/dom-regtest \
  --mine \
  --log-level debug
```

Or create a custom TOML config:

```toml
[node]
network = "Regtest"
data_dir = "./dom-regtest-data"
p2p_listen_addr = "127.0.0.1:33371"
max_inbound = 0
min_outbound = 0
mine = true
log_level = "debug"
rpc_listen_addr = "127.0.0.1:3371"
```

### Spawning Multiple Nodes

Each regtest node must have:
1. **Unique data directory** (no sharing LMDB state)
2. **Unique RPC port** if RPC is enabled
3. **Isolated P2P port** (or use different machines)

Integration test helpers manage this automatically — see [Integration Tests](#integration-tests).

### Mining Blocks

In code:

```rust
use dom_integration_tests::helpers::mine_blocks;

// Mine 10 blocks (instant, due to trivial target)
mine_blocks(&node, 10).await?;
```

Via CLI (RPC):

```bash
# Assuming node has RPC on 127.0.0.1:3371 (set rpc_listen_addr in config)
# RPC mining is not yet exposed in v0.1.0
```

## Integration Tests

All tests in `crates/dom-integration-tests/tests/` default to **Regtest**:

```rust
// helpers.rs: test_config() uses Network::Regtest by default
pub fn test_config(name: &str, port: u16, _mine: bool) -> NodeConfig {
    NodeConfig {
        network: dom_config::Network::Regtest,
        // ...
    }
}
```

### Running Tests

```bash
# Run all integration tests
cargo test -p dom-integration-tests

# Run a specific test
cargo test -p dom-integration-tests test_wallet_coinbase_reward -- --nocapture

# See miner/node logs
RUST_LOG=dom_node=debug,dom_wire=debug cargo test -p dom-integration-tests -- --nocapture
```

### Test Patterns

**Mining blocks deterministically:**

```rust
let node = spawn_node(test_config("my-node", 44000, false)).await;
tokio::spawn(node.clone().run());

// Mine exactly 5 blocks (no auto-mining race)
mine_blocks(&node, 5).await?;

// Check wallet balance
let balance = {
    let chain = node.chain.lock().await;
    let wallet = node.wallet.as_ref().unwrap();
    let w = wallet.lock().await;
    w.balance(chain.tip_height.0)  // 1-block maturity, so coinbase is spendable immediately
};
assert!(balance.confirmed > 0);  // At Regtest maturity
```

**Spawning multiple nodes:**

```rust
let node_a = spawn_node(test_config("node-a", 44100, false)).await;
let node_b = spawn_node(test_config("node-b", 44200, false)).await;

tokio::spawn(node_a.clone().run());
tokio::spawn(node_b.clone().run());

// Connect them via hardcoded peer
// Mine on A, verify B syncs via IBD
```

## Implementation Details

### Trivial PoW

Regtest uses `REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION = [0xff_u8; 32]`.

In `miner.rs`:

```rust
let target = if node.config.network == dom_config::Network::Regtest {
    dom_core::REGTEST_TRIVIAL_TARGET_DO_NOT_USE_IN_PRODUCTION
} else if node.config.network == dom_config::Network::Testnet {
    dom_core::MAX_TARGET_BYTES
} else {
    // Mainnet: full ASERT
    asert_next_target(&anchor, timestamp, height)?
};
```

This is **gated behind an explicit Network::Regtest check**. No global flag or environment variable can accidentally enable it.

### Memory Optimization

Regtest mining skips `RandomXFlag::FLAG_FULL_MEM` (2.25 GB dataset):

```rust
let mut flags = RandomXFlag::get_recommended_flags();
if network != dom_config::Network::Regtest {
    flags |= RandomXFlag::FLAG_FULL_MEM;
}
```

This allows regtest nodes to run on low-memory systems (e.g., CI runners with 2 GB RAM).

### Magic Byte Isolation

Regtest's distinct magic bytes (`0x444F_4D52`) prevent peer connections to Mainnet/Testnet nodes:

```rust
pub const NETWORK_MAGIC_REGTEST: u32 = 0x444F_4D52;

const _: () = {
    assert!(NETWORK_MAGIC_REGTEST != NETWORK_MAGIC_MAINNET, "...");
    assert!(NETWORK_MAGIC_REGTEST != NETWORK_MAGIC_TESTNET, "...");
};
```

Compile-time asserts prevent constants from drifting.

### Coinbase Maturity

Regtest uses 1-block maturity (vs 1000-block for production):

```rust
pub const REGTEST_COINBASE_MATURITY: u64 = 1;

impl Network {
    pub fn coinbase_maturity(&self) -> u64 {
        match self {
            Network::Mainnet | Network::Testnet => dom_core::COINBASE_MATURITY,  // 1000
            Network::Regtest => dom_core::REGTEST_COINBASE_MATURITY,              // 1
        }
    }
}
```

Wallet balance calculation respects this:

```rust
let chain = node.chain.lock().await;
let wallet = node.wallet.as_ref().unwrap();
let w = wallet.lock().await;
let maturity = node.config.network.coinbase_maturity();
let balance = w.balance_with_maturity(chain.tip_height.0, maturity);
```

## Design Decisions

### Why Not Use testnet for Local Tests?

Testnet has:
- Real PoW that takes minutes per block on CPU
- 1000-block maturity (1.4 days of simulated time)
- DNS seeds requiring internet connectivity
- Public peers that may orphan your blocks

Regtest provides deterministic, fast, zero-configuration testing.

### Why Separate Network Enums?

`dom_config::Network` and `dom_wallet::Network` are distinct to:
- Avoid circular crate dependencies
- Keep wallet independent of node-specific logic
- Allow wallet to be used in other contexts (e.g., light clients)

The `wallet_network_from_config()` helper in `dom_node::wallet_helpers` bridges them.

### Why Compile-Time Asserts for Magic Bytes?

Compile-time asserts catch magic byte collisions **before binary release**:

```rust
assert!(NETWORK_MAGIC_REGTEST != NETWORK_MAGIC_MAINNET);
assert!(NETWORK_MAGIC_REGTEST != NETWORK_MAGIC_TESTNET);
```

This prevents the catastrophic peer cross-contamination bug.

## Troubleshooting

### "Connection to 127.0.0.1:33371 failed"

Check that:
- No other process is using port 33371
- Firewall allows localhost connections
- The node's P2P listener is enabled (default: yes)

### "timeout waiting for height 10"

- The miner may be hung (check logs for RandomX errors)
- Regtest block target is trivial; if mining still stalls, the issue is elsewhere
- Increase the timeout in the test if your machine is slow

### "insufficient funds" (wallet spending fails)

- Check coinbase maturity: Regtest requires 1 block, not 1000
- At height 1, only genesis is mature; mine more blocks
- Check wallet balance with `w.balance(height)` before spending

### High Memory Usage on Test Node

Regtest deliberately skips `FLAG_FULL_MEM` to save ~2 GB. If a regtest node is still using >500 MB:

- Check for transaction mempool bloat
- Verify block storage isn't persisting test data (delete `/tmp/dom-regtest-*` between runs)
- Profile with `cargo build --release && perf record -- ./target/release/dom-node --network regtest`

## Future Work

- RPC `mine` endpoint to trigger mining programmatically without spawning a loop
- Regtest-specific genesis hash (currently uses placeholder `[0u8; 32]`)
- Network reset RPC to clear LMDB state without restarting

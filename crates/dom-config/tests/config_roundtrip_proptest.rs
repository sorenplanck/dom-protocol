//! dom-shield proptest-invariante: NodeConfig serde JSON round-trip stability.
//!
//! Scope/justification: NodeConfig is operator-controlled local state, so this
//! is NOT a remote-attack surface. The invariant has value anyway because the
//! Lens-B secret-leak tripwire and the legacy-config `#[serde(default)]`
//! handling both depend on the serde derive contract being stable: a config
//! that serializes, deserializes, and re-serializes must produce the SAME bytes
//! (idempotent canonical form). A derive drift (renamed field, changed default,
//! lost `#[serde(default)]`) would silently change persisted-config semantics.
//!
//! NodeConfig does not derive PartialEq, so we assert stability on the JSON
//! canonical form (serialize -> deserialize -> serialize == serialize) across
//! randomized field values, including the secret Option fields.

use dom_config::{MinerThrottleConfig, Network, NodeConfig};
use proptest::prelude::*;

fn arb_network() -> impl Strategy<Value = Network> {
    prop_oneof![
        Just(Network::Mainnet),
        Just(Network::Testnet),
        Just(Network::Regtest),
    ]
}

fn arb_opt_string() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), ".*".prop_map(Some)]
}

prop_compose! {
    fn arb_config()(
        network in arb_network(),
        data_dir in ".*",
        p2p_listen_addr in ".*",
        max_inbound in any::<usize>(),
        min_outbound in any::<usize>(),
        dns_seeds in prop::collection::vec(".*", 0..4),
        disable_dns_seeds in any::<bool>(),
        seed_peers in prop::collection::vec(".*", 0..4),
        mine in any::<bool>(),
        throttle_enabled in any::<bool>(),
        yield_every_nonces in any::<u64>(),
        sleep_micros in any::<u64>(),
        miner_threads in any::<usize>(),
        miner_address in arb_opt_string(),
        wallet_path in arb_opt_string(),
        wallet_password in arb_opt_string(),
        log_level in ".*",
        rpc_listen_addr in arb_opt_string(),
        rpc_bearer_token in arb_opt_string(),
        metrics_listen_addr in arb_opt_string(),
    ) -> NodeConfig {
        NodeConfig {
            network,
            data_dir,
            p2p_listen_addr,
            max_inbound,
            min_outbound,
            dns_seeds,
            disable_dns_seeds,
            seed_peers,
            mine,
            miner_throttle: MinerThrottleConfig {
                enabled: throttle_enabled,
                yield_every_nonces,
                sleep_micros,
            },
            miner_threads,
            miner_address,
            wallet_path,
            wallet_password,
            log_level,
            rpc_listen_addr,
            rpc_bearer_token,
            metrics_listen_addr,
        }
    }
}

proptest! {
    /// serialize -> deserialize -> serialize is idempotent (canonical-form
    /// stability) for any field assignment.
    #[test]
    fn nodeconfig_json_roundtrip_is_stable(cfg in arb_config()) {
        let s1 = serde_json::to_string(&cfg).expect("serialize");
        let back: NodeConfig = serde_json::from_str(&s1).expect("deserialize");
        let s2 = serde_json::to_string(&back).expect("re-serialize");
        prop_assert_eq!(s1, s2, "NodeConfig JSON canonical form must be stable across round-trip");
    }
}

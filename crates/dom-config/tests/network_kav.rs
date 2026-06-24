//! dom-shield KAV-conformance: Network accessors must equal the canonical
//! `dom-core` constants, and Network's serde must reject unknown variants.
//!
//! Why this is a real (non-theater) surface: although a NodeConfig is an
//! operator-controlled local file, the *magic bytes* a node derives from its
//! configured `Network` are what enforce cross-network isolation on the wire.
//! If `Network::magic()` ever drifted from the canonical `dom-core` constant
//! (e.g. a refactor swapped a match arm), a Mainnet node could speak a
//! Testnet/Regtest magic and peer across networks. The constants live in
//! `dom-core`; this crate re-derives them via match arms. A KAV pins the
//! re-derivation to the source of truth and asserts the three magics never
//! collide. The unknown-variant rejection guards against a malformed/forged
//! config silently selecting an unintended network.

use dom_config::Network;

// ---- magic() == canonical dom-core constants -------------------------------

#[test]
fn magic_mainnet_matches_core_const() {
    assert_eq!(Network::Mainnet.magic(), dom_core::NETWORK_MAGIC_MAINNET);
}

#[test]
fn magic_testnet_matches_core_const() {
    assert_eq!(Network::Testnet.magic(), dom_core::NETWORK_MAGIC_TESTNET);
}

#[test]
fn magic_regtest_matches_core_const() {
    assert_eq!(Network::Regtest.magic(), dom_core::NETWORK_MAGIC_REGTEST);
}

/// Cross-network isolation depends on the three magics being pairwise
/// distinct. If any two collided, two networks would accept each other's
/// handshakes regardless of any other config field.
#[test]
fn magics_are_pairwise_distinct() {
    let m = Network::Mainnet.magic();
    let t = Network::Testnet.magic();
    let r = Network::Regtest.magic();
    assert_ne!(m, t, "mainnet/testnet magic collision breaks isolation");
    assert_ne!(m, r, "mainnet/regtest magic collision breaks isolation");
    assert_ne!(t, r, "testnet/regtest magic collision breaks isolation");
}

// ---- coinbase_maturity() == canonical dom-core constants -------------------

#[test]
fn coinbase_maturity_mainnet_matches_core_const() {
    assert_eq!(
        Network::Mainnet.coinbase_maturity(),
        dom_core::COINBASE_MATURITY
    );
}

#[test]
fn coinbase_maturity_testnet_matches_core_const() {
    // Testnet intentionally shares mainnet maturity.
    assert_eq!(
        Network::Testnet.coinbase_maturity(),
        dom_core::COINBASE_MATURITY
    );
}

#[test]
fn coinbase_maturity_regtest_matches_core_const() {
    assert_eq!(
        Network::Regtest.coinbase_maturity(),
        dom_core::REGTEST_COINBASE_MATURITY
    );
}

// ---- default_port() == canonical dom-core constants ------------------------

#[test]
fn default_port_mainnet_matches_core_const() {
    assert_eq!(Network::Mainnet.default_port(), dom_core::P2P_PORT_MAINNET);
}

#[test]
fn default_port_testnet_matches_core_const() {
    assert_eq!(Network::Testnet.default_port(), dom_core::P2P_PORT_TESTNET);
}

#[test]
fn default_port_regtest_matches_core_const() {
    assert_eq!(Network::Regtest.default_port(), dom_core::P2P_PORT_REGTEST);
}

// ---- Network serde: round-trip + reject unknown variant --------------------

/// Each known variant must serialize and deserialize back to itself. This is
/// the externally-named contract a config file relies on.
#[test]
fn network_serde_roundtrips_all_variants() {
    for net in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        let s = serde_json::to_string(&net).expect("serialize Network");
        let back: Network = serde_json::from_str(&s).expect("deserialize Network");
        assert_eq!(net, back, "Network serde round-trip must be stable");
    }
}

/// A forged/typo'd network name must be REJECTED, never silently coerced to a
/// default. (serde for a fieldless enum has no `#[serde(other)]` here, so this
/// confirms the absence of any catch-all that would mask an unknown network.)
#[test]
fn network_deserialize_rejects_unknown_variant() {
    let r: Result<Network, _> = serde_json::from_str("\"Mainet\""); // typo
    assert!(r.is_err(), "unknown Network variant must be rejected");

    let r2: Result<Network, _> = serde_json::from_str("\"Bitcoin\"");
    assert!(r2.is_err(), "foreign Network name must be rejected");

    // Case sensitivity: the canonical names are PascalCase.
    let r3: Result<Network, _> = serde_json::from_str("\"mainnet\"");
    assert!(
        r3.is_err(),
        "lowercase name must not deserialize (as_str() form is informational only)"
    );
}

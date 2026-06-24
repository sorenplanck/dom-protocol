//! dom-shield Lens B (secret hygiene): prove that `NodeConfig` leaks its
//! secret fields through the two channels its derives make observable.
//!
//! FINDING (DS-config-001, behaviorally confirmed, not speculative):
//! `NodeConfig` carries `wallet_password: Option<String>` and
//! `rpc_bearer_token: Option<String>` while deriving `#[derive(Debug, ...,
//! Serialize, ...)]` with NO zeroization and NO redaction. Consequences:
//!
//!   * Debug leak: any `{:?}`/`{:#?}` of a NodeConfig (a tracing span field, a
//!     `dbg!`, a panic message, an `expect("... {config:?}")`) writes the
//!     cleartext password and bearer token to logs.
//!   * Serialize leak: `serde_json::to_string(&config)` (or any serializer used
//!     to persist/echo the config back) emits the cleartext secrets, so a
//!     "save config" or "/status echo" path can write them to disk or the wire.
//!
//! Neither channel is a remote attack on its own, but both are real
//! confidentiality regressions for funds-bearing material (wallet password) and
//! an auth credential (RPC bearer token). The Debug and Serialize outputs ARE
//! observable, so this is a true behavioral test, not an [ignore] aspiration.
//!
//! This test ASSERTS THE LEAK EXISTS (current behavior). It is GREEN today and
//! documents the gap. If a future fix redacts Debug and/or skips the secrets on
//! Serialize, this test goes RED — at which point flip the assertions to
//! `assert!(!...contains...)` per the FIX text in the dom-shield report. The
//! test is therefore a tripwire on the secret-hygiene decision.

use dom_config::NodeConfig;

const WALLET_SECRET: &str = "S3cr3t-wallet-passphrase-DO-NOT-LOG";
const RPC_SECRET: &str = "bearer-tok-en-DO-NOT-LOG-7f3a9b";

fn config_with_secrets() -> NodeConfig {
    let mut c = NodeConfig::mainnet();
    c.wallet_password = Some(WALLET_SECRET.to_string());
    c.rpc_bearer_token = Some(RPC_SECRET.to_string());
    c
}

/// Debug ({:?}) of a NodeConfig currently EMBEDS the cleartext wallet password.
/// Confirms the log-leak channel for funds-bearing material.
#[test]
fn debug_output_leaks_wallet_password() {
    let c = config_with_secrets();
    let dbg = format!("{c:?}");
    assert!(
        dbg.contains(WALLET_SECRET),
        "EXPECTED-FAIL-ON-FIX: Debug no longer leaks wallet_password \
         (redaction landed) — update this assertion. Current behavior leaks it."
    );
}

/// Debug ({:?}) currently embeds the cleartext RPC bearer token.
#[test]
fn debug_output_leaks_rpc_bearer_token() {
    let c = config_with_secrets();
    let dbg = format!("{c:?}");
    assert!(
        dbg.contains(RPC_SECRET),
        "EXPECTED-FAIL-ON-FIX: Debug no longer leaks rpc_bearer_token \
         (redaction landed) — update this assertion. Current behavior leaks it."
    );
}

/// Pretty Debug ({:#?}) — used by some panic/expect paths — leaks too.
#[test]
fn pretty_debug_output_leaks_secrets() {
    let c = config_with_secrets();
    let dbg = format!("{c:#?}");
    assert!(
        dbg.contains(WALLET_SECRET) && dbg.contains(RPC_SECRET),
        "EXPECTED-FAIL-ON-FIX: pretty Debug no longer leaks secrets — update assertion."
    );
}

/// Serialize (serde_json) currently writes the cleartext wallet password.
/// Confirms the persist-/echo-to-disk leak channel.
#[test]
fn serialize_leaks_wallet_password() {
    let c = config_with_secrets();
    let json = serde_json::to_string(&c).expect("serialize NodeConfig");
    assert!(
        json.contains(WALLET_SECRET),
        "EXPECTED-FAIL-ON-FIX: Serialize no longer emits wallet_password \
         (#[serde(skip_serializing)] landed) — update this assertion."
    );
}

/// Serialize (serde_json) currently writes the cleartext RPC bearer token.
#[test]
fn serialize_leaks_rpc_bearer_token() {
    let c = config_with_secrets();
    let json = serde_json::to_string(&c).expect("serialize NodeConfig");
    assert!(
        json.contains(RPC_SECRET),
        "EXPECTED-FAIL-ON-FIX: Serialize no longer emits rpc_bearer_token \
         (#[serde(skip_serializing)] landed) — update this assertion."
    );
}

/// Cross-check: when the secret fields are None (the default mainnet config),
/// neither channel emits the sentinel strings. This isolates the leak to the
/// secret values themselves (not some incidental substring) and ensures the
/// leak tests above are not trivially always-true.
#[test]
fn no_secret_strings_when_fields_unset() {
    let c = NodeConfig::mainnet(); // wallet_password / rpc_bearer_token = None
    let dbg = format!("{c:?}");
    let json = serde_json::to_string(&c).expect("serialize NodeConfig");
    assert!(!dbg.contains(WALLET_SECRET) && !dbg.contains(RPC_SECRET));
    assert!(!json.contains(WALLET_SECRET) && !json.contains(RPC_SECRET));
}

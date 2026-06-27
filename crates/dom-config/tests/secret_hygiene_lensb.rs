//! dom-shield Lens B (secret hygiene): prove that `NodeConfig` does not leak
//! its secret fields through Debug output or serialization.
//!
//! REGRESSION COVERAGE (DS-config-001):
//! `NodeConfig` carries `wallet_password: Option<String>` and
//! `rpc_bearer_token: Option<String>`. These values must remain redacted from
//! `Debug` output and skipped during serialization. Otherwise:
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
//! an auth credential (RPC bearer token). The Debug and Serialize outputs are
//! observable, so these tests pin the safe behavior directly.

use dom_config::NodeConfig;

const WALLET_SECRET: &str = "S3cr3t-wallet-passphrase-DO-NOT-LOG";
const RPC_SECRET: &str = "bearer-tok-en-DO-NOT-LOG-7f3a9b";

fn config_with_secrets() -> NodeConfig {
    let mut c = NodeConfig::mainnet();
    c.wallet_password = Some(WALLET_SECRET.to_string());
    c.rpc_bearer_token = Some(RPC_SECRET.to_string());
    c
}

/// Debug ({:?}) of a NodeConfig must redact the cleartext wallet password.
#[test]
fn debug_output_redacts_wallet_password() {
    let c = config_with_secrets();
    let dbg = format!("{c:?}");
    assert!(!dbg.contains(WALLET_SECRET));
    assert!(dbg.contains("wallet_password: \"<redacted>\""));
}

/// Debug ({:?}) must redact the cleartext RPC bearer token.
#[test]
fn debug_output_redacts_rpc_bearer_token() {
    let c = config_with_secrets();
    let dbg = format!("{c:?}");
    assert!(!dbg.contains(RPC_SECRET));
    assert!(dbg.contains("rpc_bearer_token: \"<redacted>\""));
}

/// Pretty Debug ({:#?}) — used by some panic/expect paths — must redact too.
#[test]
fn pretty_debug_output_redacts_secrets() {
    let c = config_with_secrets();
    let dbg = format!("{c:#?}");
    assert!(!dbg.contains(WALLET_SECRET));
    assert!(!dbg.contains(RPC_SECRET));
    assert!(dbg.contains("wallet_password: \"<redacted>\""));
    assert!(dbg.contains("rpc_bearer_token: \"<redacted>\""));
}

/// Serialize (serde_json) must not write the cleartext wallet password.
#[test]
fn serialize_skips_wallet_password() {
    let c = config_with_secrets();
    let json = serde_json::to_string(&c).expect("serialize NodeConfig");
    assert!(!json.contains(WALLET_SECRET));
    assert!(!json.contains("wallet_password"));
}

/// Serialize (serde_json) must not write the cleartext RPC bearer token.
#[test]
fn serialize_skips_rpc_bearer_token() {
    let c = config_with_secrets();
    let json = serde_json::to_string(&c).expect("serialize NodeConfig");
    assert!(!json.contains(RPC_SECRET));
    assert!(!json.contains("rpc_bearer_token"));
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

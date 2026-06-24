//! dom-shield integration test families for dom-wallet-app (Soren Planck).
//!
//! Covers the genuinely *public* attackable surfaces reachable from outside the
//! crate:
//!   - `HeartbeatSession` — forged / wrong-nonce / oversized pong handling
//!     (a malicious peer fully controls the Pong payload bytes).
//!   - `storage::load_or_default` — directed corruption of `app_state.json`,
//!     including an attacker who tampers the persisted `node_url` / `wallet_dir`
//!     to redirect the wallet (SSRF / wrong-node / fund-exposure surface).
//!
//! These DO NOT touch production logic; they only exercise it. The private
//! fund-decision / secret-redaction surfaces (parse/validate_payment_request,
//! redact_secret_text, hex parsers) are covered by `#[cfg(test)]` families
//! inside `src/runtime.rs` because they are unreachable from here.

use dom_wallet::Network;
use dom_wallet_app::runtime::{
    HeartbeatError, HeartbeatEvent, HeartbeatSession, NetworkStatus, NetworkStatusState,
};
use dom_wallet_app::storage::{self, PersistedAppState, APP_STATE_FILE};
use dom_wire::message::{Command, WireMessage};
use tempfile::TempDir;

// ===========================================================================
// Family E — HeartbeatSession: forged pong handling (peer-controlled payload).
// ===========================================================================

fn connected_status() -> NetworkStatus {
    NetworkStatus {
        state: NetworkStatusState::Connected,
        connected_peer: Some("127.0.0.1:33369".to_string()),
        ..NetworkStatus::default()
    }
}

fn pong(payload: Vec<u8>) -> WireMessage {
    WireMessage {
        magic: Network::Regtest.magic(),
        command: Command::Pong,
        payload,
    }
}

// [x] VECTOR: a Pong with the wrong nonce (forged by a peer that never saw our
// ping) must NOT be accepted as a live-connection signal.
#[test]
fn forged_pong_wrong_nonce_is_rejected() {
    let mut hb = HeartbeatSession::default();
    let mut status = connected_status();
    hb.begin_ping_with_nonce(1, Network::Regtest.magic(), 0xAA);

    let err = hb
        .observe_message(&mut status, 2, &pong(0xBBu64.to_le_bytes().to_vec()))
        .expect_err("wrong nonce must reject");
    assert_eq!(
        err,
        HeartbeatError::NonceMismatch {
            expected: 0xAA,
            got: 0xBB
        }
    );
    assert_eq!(
        status.last_pong_at, None,
        "forged pong must not refresh liveness"
    );
}

// [x] VECTOR: a Pong arriving with NO ping in flight (unsolicited) must be
// rejected, not silently treated as healthy.
#[test]
fn unsolicited_pong_without_ping_is_rejected() {
    let mut hb = HeartbeatSession::default();
    let mut status = connected_status();
    let err = hb
        .observe_message(&mut status, 5, &pong(1u64.to_le_bytes().to_vec()))
        .expect_err("no ping in flight must reject");
    assert_eq!(err, HeartbeatError::NoPingInFlight);
    assert_eq!(status.last_pong_at, None);
}

// [x] VECTOR: oversized / undersized pong payloads (peer-controlled length) must
// be a clean MalformedPong error, never a panic / OOB.
#[test]
fn malformed_pong_lengths_are_rejected_cleanly() {
    let mut hb = HeartbeatSession::default();
    let mut status = connected_status();
    hb.begin_ping_with_nonce(1, Network::Regtest.magic(), 7);
    for len in [0usize, 1, 7, 9, 64, 4096] {
        let err = hb
            .observe_message(&mut status, 2, &pong(vec![0u8; len]))
            .expect_err("malformed length must reject");
        assert_eq!(err, HeartbeatError::MalformedPong { len });
    }
    assert_eq!(status.last_pong_at, None);
}

// [x] Positive control: the correct nonce IS accepted and refreshes liveness.
#[test]
fn matching_pong_is_accepted() {
    let mut hb = HeartbeatSession::default();
    let mut status = connected_status();
    hb.begin_ping_with_nonce(1, Network::Regtest.magic(), 42);
    let event = hb
        .observe_message(&mut status, 2, &pong(42u64.to_le_bytes().to_vec()))
        .expect("matching pong");
    assert_eq!(event, HeartbeatEvent::PongAccepted);
    assert_eq!(status.last_pong_at, Some(2));
}

// [x] Property: an arbitrary peer-supplied Pong payload of arbitrary length is
// EITHER rejected OR accepted only when it exactly equals the pending nonce LE
// bytes. It must never be accepted on a wrong/forged nonce and never panic.
#[test]
fn forged_pong_property_arbitrary_payload() {
    use proptest::prelude::*;
    proptest!(|(expected in any::<u64>(), payload in proptest::collection::vec(any::<u8>(), 0..40))| {
        let mut hb = HeartbeatSession::default();
        let mut status = connected_status();
        hb.begin_ping_with_nonce(1, Network::Regtest.magic(), expected);
        let result = hb.observe_message(&mut status, 2, &pong(payload.clone()));
        let is_correct = payload.len() == 8
            && u64::from_le_bytes(payload.clone().try_into().unwrap()) == expected;
        match result {
            Ok(HeartbeatEvent::PongAccepted) => prop_assert!(is_correct, "accepted a forged pong"),
            Ok(HeartbeatEvent::None) => prop_assert!(false, "pong wrongly treated as non-heartbeat"),
            Ok(HeartbeatEvent::ReconnectRequired(_)) => prop_assert!(false, "observe must not reconnect"),
            Err(_) => prop_assert!(!is_correct, "rejected the correct pong"),
        }
        if !is_correct {
            prop_assert_eq!(status.last_pong_at, None, "forged pong refreshed liveness");
        }
    });
}

// ===========================================================================
// Family F — storage::load_or_default: directed corruption of app_state.json.
// An attacker with write access to the data dir can tamper the persisted state.
// The redirect-the-wallet vectors (node_url / wallet_dir) are the SSRF / wrong-
// node surface: load must not panic, and we PIN exactly what it accepts so a
// future hardening (e.g. node_url scheme/host allowlist) has a tripwire.
// ===========================================================================

fn write_state(dir: &TempDir, body: &[u8]) {
    std::fs::create_dir_all(dir.path()).unwrap();
    std::fs::write(dir.path().join(APP_STATE_FILE), body).unwrap();
}

// [x] Truncated / partial JSON must be a clean Serialization error, not a panic.
#[test]
fn truncated_json_is_clean_error() {
    let dir = TempDir::new().unwrap();
    write_state(&dir, br#"{"wallet_dir":"#);
    assert!(storage::load_or_default(dir.path()).is_err());
}

// [x] Garbage / random bytes must be a clean error, never a panic.
#[test]
fn garbage_bytes_are_clean_error() {
    let dir = TempDir::new().unwrap();
    write_state(&dir, &[0xFF, 0x00, 0x13, 0x37, 0xDE, 0xAD]);
    assert!(storage::load_or_default(dir.path()).is_err());
}

// [x] Empty file is a clean error (serde_json rejects empty input), not default.
#[test]
fn empty_file_is_clean_error() {
    let dir = TempDir::new().unwrap();
    write_state(&dir, b"");
    assert!(storage::load_or_default(dir.path()).is_err());
}

// RED / [ignore] — FINDING-CANDIDATE (directed corruption / SSRF surface):
// `load_or_default` deserializes `node_url` as a free-form String with NO
// validation. A tampered app_state.json can redirect the wallet's RPC node to
// an arbitrary scheme/host (e.g. http://attacker.example, file://, or a LAN
// metadata endpoint) — a classic SSRF / wrong-node fund-exposure vector. There
// is no scheme/host allowlist at load time. This test asserts the HARDENED
// behavior (reject a non-loopback, non-http(s) node_url) and currently fails;
// it documents the gap. PRECISA DECISÃO HUMANA: whether load should validate
// node_url (allowlist / scheme check) or whether validation belongs at the
// connection layer. Un-ignore once a policy is chosen.
#[test]
#[ignore = "FINDING-CANDIDATE(storage/SSRF): node_url loaded without scheme/host validation; redirect-wallet via tampered app_state.json. Needs human decision on validation policy."]
fn tampered_node_url_with_hostile_scheme_is_rejected() {
    let dir = TempDir::new().unwrap();
    write_state(
        &dir,
        br#"{"wallet_dir":null,"network":null,"node_url":"file:///etc/passwd"}"#,
    );
    let loaded = storage::load_or_default(dir.path()).expect("parses today");
    // Hardened expectation: a non-http(s) scheme must not be accepted as a node URL.
    assert!(
        loaded.node_url.starts_with("http://") || loaded.node_url.starts_with("https://"),
        "hostile scheme accepted: {}",
        loaded.node_url
    );
}

// [x] Behavior PIN (documents current, un-validated acceptance — NOT an
// assertion of correctness): a tampered node_url is loaded verbatim today.
// This makes the SSRF surface explicit and gives the finding above a
// before/after contrast. If load gains validation, this pin must be revisited.
#[test]
fn pin_tampered_node_url_is_loaded_verbatim_today() {
    let dir = TempDir::new().unwrap();
    write_state(
        &dir,
        br#"{"wallet_dir":null,"network":null,"node_url":"http://attacker.example:1/"}"#,
    );
    let loaded = storage::load_or_default(dir.path()).expect("parses");
    assert_eq!(loaded.node_url, "http://attacker.example:1/");
}

// [x] Behavior PIN: a tampered wallet_dir path is loaded verbatim (no path
// confinement at the storage layer). Pins the redirect-wallet-dir surface.
#[test]
fn pin_tampered_wallet_dir_is_loaded_verbatim_today() {
    let dir = TempDir::new().unwrap();
    let body = br#"{"wallet_dir":"/tmp/attacker-controlled-wallet","network":"Regtest","node_url":"http://127.0.0.1:33369"}"#;
    write_state(&dir, body);
    let loaded = storage::load_or_default(dir.path()).expect("parses");
    assert_eq!(
        loaded.wallet_dir,
        Some(std::path::PathBuf::from("/tmp/attacker-controlled-wallet"))
    );
    assert_eq!(loaded.network, Some(Network::Regtest));
}

// [x] Unknown / extra JSON fields: confirm whether serde rejects or ignores
// them (deserialization must not panic regardless).
#[test]
fn extra_unknown_fields_do_not_panic() {
    let dir = TempDir::new().unwrap();
    let body =
        br#"{"wallet_dir":null,"network":null,"node_url":"http://127.0.0.1:33369","evil":"x"}"#;
    write_state(&dir, body);
    let _ = storage::load_or_default(dir.path()); // Ok (ignored) or Err — never panic.
}

// [x] Default sanity: PersistedAppState::default is loopback (defensive baseline).
#[test]
fn default_node_url_is_loopback() {
    let d = PersistedAppState::default();
    assert!(d.node_url.contains("127.0.0.1"));
}

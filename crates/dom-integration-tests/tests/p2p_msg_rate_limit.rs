//! Anti-flood per-category inbound message rate limit — proven on the REAL P2P
//! path (Noise handshake + Hello + `message_loop`):
//!
//! 1. flooding one category past its per-window budget scores the peer
//!    `PROTOCOL_VIOLATION (+10)` per excess message — the exact score
//!    progression proves the limiter executes inside `message_loop`;
//! 2. a flood on ONE connection does NOT consume another peer's budget (each
//!    connection has its own limiter);
//! 3. traffic within budget is never scored.
//!
//! We flood `Pong` (category Cheap): its handler is a pure no-op, so the only
//! observable effect is the rate-limit scoring — isolating exactly what we test.
//! Per-category logic, window reset, and the legitimate sync/relay burst flows
//! are covered deterministically by the unit tests in `dom_node::msg_rate_limit`.

use dom_config::Network;
use dom_consensus::derive_chain_id;
use dom_core::{Hash256, PROTOCOL_VERSION};
use dom_integration_tests::helpers::*;
use dom_node::node::DomNode;
use dom_wire::codec::NoiseCodec;
use dom_wire::handshake::{generate_static_keypair, perform_handshake_initiator};
use dom_wire::message::{Command, HelloPayload, WireMessage};
use dom_wire::peer::ban_scores;
use std::sync::Arc;
use std::time::Duration;

/// Overridden Cheap budget for the test (see `set_rate_limit_env`).
const CHEAP_BUDGET: u32 = 5;

/// Configure the per-category limiter for the test. MUST run before any peer
/// connects: `message_loop` reads the config once per connection. A large window
/// keeps the count from resetting mid-test, so the score progression is exact.
fn set_rate_limit_env() {
    std::env::set_var("DOM_TEST_RATELIMIT_WINDOW_SECS", "3600");
    std::env::set_var("DOM_TEST_RATELIMIT_CHEAP", CHEAP_BUDGET.to_string());
}

fn chain_id_for(network: Network) -> [u8; 32] {
    let genesis_hash = match network {
        Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
    };
    *derive_chain_id(network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes()
}

async fn connect_peer(node: &Arc<DomNode>) -> (tokio::net::TcpStream, NoiseCodec) {
    let config = node.config.clone();
    let mut stream = tokio::net::TcpStream::connect(&config.p2p_listen_addr)
        .await
        .expect("connect peer");
    let (privkey, _) = generate_static_keypair();
    let chain_id = chain_id_for(config.network);
    let transport =
        perform_handshake_initiator(&mut stream, &privkey, config.network.magic(), &chain_id)
            .await
            .expect("noise handshake");
    let mut codec = NoiseCodec::new(transport, config.network.magic());

    let hello = HelloPayload {
        version: PROTOCOL_VERSION,
        network_magic: config.network.magic(),
        chain_id,
        best_height: 0,
        best_hash: [0u8; 32],
        user_agent: "dom-ratelimit-test".into(),
        local_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let wire = WireMessage {
        magic: config.network.magic(),
        command: Command::Hello,
        payload: hello.to_bytes().expect("serialize hello"),
    };
    codec.send(&mut stream, &wire).await.expect("send hello");
    let resp = codec.recv(&mut stream).await.expect("recv hello");
    assert_eq!(resp.command, Command::Hello);
    (stream, codec)
}

fn pong(node: &Arc<DomNode>) -> WireMessage {
    WireMessage {
        magic: node.config.network.magic(),
        command: Command::Pong,
        payload: vec![0u8; 8],
    }
}

async fn ban_score(node: &Arc<DomNode>, peer_key: &str) -> u32 {
    node.peers.lock().await.ban_score(peer_key).unwrap_or(0)
}

async fn wait_for_ban_score(
    node: &Arc<DomNode>,
    peer_key: &str,
    target: u32,
    timeout: Duration,
) -> Result<u32, u32> {
    let start = std::time::Instant::now();
    loop {
        let score = ban_score(node, peer_key).await;
        if score >= target {
            return Ok(score);
        }
        if start.elapsed() >= timeout {
            return Err(score);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Flood `Pong` past the Cheap budget: each excess message scores exactly
/// PROTOCOL_VIOLATION (+10). A second, quiet peer is NOT penalized — proving the
/// limiter is per-connection.
#[tokio::test]
async fn message_flood_scores_per_excess_without_affecting_other_peers() {
    init_tracing();
    set_rate_limit_env();

    let port = free_local_port();
    let config = test_config("msg-rate-flood", port, false);
    let node = spawn_node(config).await;
    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port}"), 10)
        .await
        .expect("listener ready");

    // Quiet control peer — must stay at score 0 throughout.
    let (_quiet_stream, _quiet_codec) = connect_peer(&node).await;
    let quiet_key = _quiet_stream
        .local_addr()
        .expect("quiet local addr")
        .to_string();

    // Flooding peer.
    let (mut stream, mut codec) = connect_peer(&node).await;
    let flooder_key = stream.local_addr().expect("flooder local addr").to_string();

    let excess = 3u32;
    let total = CHEAP_BUDGET + excess;
    for i in 0..total {
        codec
            .send(&mut stream, &pong(&node))
            .await
            .unwrap_or_else(|e| panic!("send pong #{i} failed: {e:?}"));
    }

    // 3 excess × PROTOCOL_VIOLATION(10) = 30, below BAN_THRESHOLD(100) so the
    // connection stays alive and the score is observable.
    let expected = excess * ban_scores::PROTOCOL_VIOLATION;
    let score = wait_for_ban_score(&node, &flooder_key, expected, Duration::from_secs(10))
        .await
        .unwrap_or_else(|got| {
            panic!("flooder score plateaued at {got}, expected {expected} — rate limit not applied")
        });
    assert_eq!(
        score, expected,
        "each excess message must add exactly PROTOCOL_VIOLATION"
    );

    // The quiet peer must be untouched by the flood on the other connection.
    assert_eq!(
        ban_score(&node, &quiet_key).await,
        0,
        "a flood on one peer must not penalize another"
    );
}

/// Exactly-budget traffic is never scored.
#[tokio::test]
async fn in_budget_traffic_is_never_scored() {
    init_tracing();
    set_rate_limit_env();

    let port = free_local_port();
    let config = test_config("msg-rate-inbudget", port, false);
    let node = spawn_node(config).await;
    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port}"), 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec) = connect_peer(&node).await;
    let peer_key = stream.local_addr().expect("local addr").to_string();

    // Send budget-1 Pongs; the Ping barrier below is the budget-th Cheap message,
    // so the whole burst (Pongs + Ping) is exactly the budget — all within limit.
    for i in 0..(CHEAP_BUDGET - 1) {
        codec
            .send(&mut stream, &pong(&node))
            .await
            .unwrap_or_else(|e| panic!("send pong #{i} failed: {e:?}"));
    }

    // Round-trip a Ping/Pong as a barrier so all sent messages have been
    // processed, then assert the score is still zero.
    codec
        .send(
            &mut stream,
            &WireMessage {
                magic: node.config.network.magic(),
                command: Command::Ping,
                payload: b"barrier".to_vec(),
            },
        )
        .await
        .expect("send barrier ping");
    // Drain until our Pong barrier echo arrives (skip node's own periodic traffic).
    for _ in 0..16 {
        let m = tokio::time::timeout(Duration::from_secs(10), codec.recv(&mut stream))
            .await
            .expect("recv timeout")
            .expect("recv");
        if m.command == Command::Pong && m.payload == b"barrier".to_vec() {
            break;
        }
    }

    assert_eq!(
        ban_score(&node, &peer_key).await,
        0,
        "in-budget traffic must never be scored"
    );
}

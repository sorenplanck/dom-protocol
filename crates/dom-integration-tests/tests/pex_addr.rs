//! PEX/Addr wiring — proves on the real P2P path (Noise + Hello) that:
//!
//! 1. GetAddr receives an Addr containing the known peers (bounded by
//!    MAX_ADDR_RESPONSE);
//! 2. a second GetAddr within the 10-minute cooldown is suppressed (no Addr
//!    arrives before the control Pong — a deterministic ordering observation,
//!    not a timing observation);
//! 3. a received Addr feeds the PexManager only policy-allowed SocketAddr values;
//! 4. an Addr flood beyond MAX_ADDR_MESSAGES_PER_WINDOW increments the peer ban
//!    score by ADDRESS_FLOODING (+30) for each excess message — the exact score
//!    progression proves that rate limiting runs.

use dom_config::Network;
use dom_consensus::derive_chain_id;
use dom_core::{Hash256, PROTOCOL_VERSION};
use dom_integration_tests::helpers::*;
use dom_node::node::DomNode;
use dom_node::pex::MAX_ADDR_MESSAGES_PER_WINDOW;
use dom_wire::codec::NoiseCodec;
use dom_wire::handshake::{generate_static_keypair, perform_handshake_initiator};
use dom_wire::message::{AddrEntry, AddrPayload, Command, HelloPayload, WireMessage};
use dom_wire::peer::ban_scores;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn chain_id_for(network: Network) -> [u8; 32] {
    let genesis_hash = match network {
        Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
    };
    *derive_chain_id(network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes()
}

async fn connect_pex_peer(node: &Arc<DomNode>) -> (tokio::net::TcpStream, NoiseCodec) {
    let config = node.config.clone();
    let mut stream = tokio::net::TcpStream::connect(&config.p2p_listen_addr)
        .await
        .expect("connect pex peer");
    let (privkey, _) = generate_static_keypair();
    let chain_id = chain_id_for(config.network);
    let transport =
        perform_handshake_initiator(&mut stream, &privkey, config.network.magic(), &chain_id)
            .await
            .expect("perform Noise handshake");
    let mut codec = NoiseCodec::new(transport, config.network.magic());

    let hello = HelloPayload {
        version: PROTOCOL_VERSION,
        network_magic: config.network.magic(),
        chain_id,
        best_height: 0,
        best_hash: [0u8; 32],
        user_agent: "dom-pex-test".into(),
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
    let response = codec.recv(&mut stream).await.expect("receive hello");
    assert_eq!(response.command, Command::Hello);

    (stream, codec)
}

/// Same authenticated P2P path, but with an explicit TCP source address. This
/// lets the test model an inbound peer whose public IP is also listening on the
/// standard P2P port.
async fn connect_pex_peer_from(
    node: &Arc<DomNode>,
    source: SocketAddr,
    private_key: [u8; 32],
) -> (tokio::net::TcpStream, NoiseCodec) {
    let config = node.config.clone();
    let socket = tokio::net::TcpSocket::new_v4().expect("create source socket");
    socket.bind(source).expect("bind source address");
    let mut stream = socket
        .connect(config.p2p_listen_addr.parse().expect("node listen address"))
        .await
        .expect("connect inbound peer");
    let chain_id = chain_id_for(config.network);
    let transport =
        perform_handshake_initiator(&mut stream, &private_key, config.network.magic(), &chain_id)
            .await
            .expect("perform Noise handshake");
    let mut codec = NoiseCodec::new(transport, config.network.magic());
    let hello = HelloPayload {
        version: PROTOCOL_VERSION,
        network_magic: config.network.magic(),
        chain_id,
        best_height: 0,
        best_hash: [0u8; 32],
        user_agent: "dom-inbound-discovery-test".into(),
        local_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    codec
        .send(
            &mut stream,
            &WireMessage {
                magic: config.network.magic(),
                command: Command::Hello,
                payload: hello.to_bytes().expect("serialize hello"),
            },
        )
        .await
        .expect("send hello");
    assert_eq!(
        codec
            .recv(&mut stream)
            .await
            .expect("receive hello")
            .command,
        Command::Hello
    );
    (stream, codec)
}

fn wire(node: &Arc<DomNode>, command: Command, payload: Vec<u8>) -> WireMessage {
    WireMessage {
        magic: node.config.network.magic(),
        command,
        payload,
    }
}

/// Receive messages until one of `command` arrives, skipping the node's own
/// periodic traffic (Ping/GetAddr). Fails if `reject` arrives first.
async fn recv_until(
    stream: &mut tokio::net::TcpStream,
    codec: &mut NoiseCodec,
    command: Command,
    reject: Option<Command>,
) -> WireMessage {
    for _ in 0..16 {
        let msg = tokio::time::timeout(Duration::from_secs(10), codec.recv(stream))
            .await
            .expect("timed out waiting for message")
            .expect("recv message");
        if msg.command == command {
            return msg;
        }
        if Some(msg.command) == reject {
            panic!("received {:?} while expecting {command:?}", msg.command);
        }
    }
    panic!("did not receive {command:?} within 16 messages");
}

async fn wait_for_pex_known_count(node: &Arc<DomNode>, target: usize, timeout: Duration) -> usize {
    let start = std::time::Instant::now();
    loop {
        let count = node.pex.lock().await.known_count();
        if count >= target {
            return count;
        }
        if start.elapsed() >= timeout {
            return count;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn ban_score_of(node: &Arc<DomNode>, peer_key: &str) -> Option<u32> {
    node.peers.lock().await.ban_score(peer_key)
}

async fn wait_for_ban_score(
    node: &Arc<DomNode>,
    peer_key: &str,
    target: u32,
    timeout: Duration,
) -> Result<u32, u32> {
    let start = std::time::Instant::now();
    loop {
        let score = ban_score_of(node, peer_key).await.unwrap_or(0);
        if score >= target {
            return Ok(score);
        }
        if start.elapsed() >= timeout {
            return Err(score);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// 1. GetAddr → Addr with the PexManager peers (the configured seed here), and
/// 2. a second GetAddr within the cooldown is suppressed: the control Pong
///    arrives without an Addr preceding it.
#[tokio::test]
async fn pex_getaddr_answered_once_then_suppressed_by_cooldown() {
    init_tracing();
    let port = free_local_port();
    let mut config = test_config("pex-getaddr", port, false);
    // Regtest deliberately permits private addresses. The fixture promotes the
    // seed as if a prior outbound dial had succeeded, because unconfirmed
    // candidates must never be re-advertised.
    config.seed_peers = vec!["10.99.77.1:33369".to_string()];
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port}"), 10)
        .await
        .expect("listener ready");

    // The connector feeds the PexManager with seeds; wait for seeding.
    let known = wait_for_pex_known_count(&node, 1, Duration::from_secs(10)).await;
    assert!(known >= 1, "PEX seeding did not happen (known={known})");
    assert!(node.pex.lock().await.mark_connected("10.99.77.1:33369"));

    let (mut stream, mut codec) = connect_pex_peer(&node).await;

    // GetAddr #1 must respond with an Addr containing the seed.
    codec
        .send(&mut stream, &wire(&node, Command::GetAddr, vec![]))
        .await
        .expect("send getaddr");
    let addr_msg = recv_until(&mut stream, &mut codec, Command::Addr, None).await;
    let payload = AddrPayload::from_bytes(&addr_msg.payload).expect("decode addr payload");
    assert!(
        payload.entries.len() <= dom_node::pex::MAX_ADDR_RESPONSE,
        "Addr response above MAX_ADDR_RESPONSE: {}",
        payload.entries.len()
    );
    assert!(
        payload.entries.iter().any(|e| e.addr == "10.99.77.1:33369"),
        "Addr response must contain the seeded peer; got {:?}",
        payload.entries
    );

    // GetAddr #2 within the cooldown is suppressed. The ordering proof is that
    // the control Ping's Pong arrives with no Addr before it.
    codec
        .send(&mut stream, &wire(&node, Command::GetAddr, vec![]))
        .await
        .expect("send second getaddr");
    codec
        .send(
            &mut stream,
            &wire(&node, Command::Ping, b"pex-ctrl".to_vec()),
        )
        .await
        .expect("send control ping");
    let pong = recv_until(&mut stream, &mut codec, Command::Pong, Some(Command::Addr)).await;
    assert_eq!(pong.payload, b"pex-ctrl".to_vec());
}

/// A received Addr feeds the PexManager only valid SocketAddr values; invalid
/// entries are discarded without a crash or entering the known set.
#[tokio::test]
async fn pex_addr_message_adds_only_valid_addresses() {
    init_tracing();
    let port = free_local_port();
    let config = test_config("pex-addr-valid", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port}"), 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec) = connect_pex_peer(&node).await;

    let payload = AddrPayload {
        entries: vec![
            AddrEntry {
                addr: "10.99.77.2:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "not_a_socket_addr".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "10.99.77.3:33370".into(),
                last_seen: 1,
            },
        ],
    };
    codec
        .send(
            &mut stream,
            &wire(
                &node,
                Command::Addr,
                payload.to_bytes().expect("encode addr"),
            ),
        )
        .await
        .expect("send addr");

    // The authenticated loopback peer itself is also learned as an
    // unconfirmed inbound candidate on regtest, in addition to the two Addr
    // entries below.
    let known = wait_for_pex_known_count(&node, 3, Duration::from_secs(10)).await;
    assert!(known >= 3, "the two valid Addr entries must be added");
    let pex = node.pex.lock().await;
    let addrs: Vec<String> = pex
        .connectable_peers()
        .iter()
        .map(|p| p.addr.clone())
        .collect();
    assert!(addrs.contains(&"10.99.77.2:33370".to_string()));
    assert!(addrs.contains(&"10.99.77.3:33370".to_string()));
    assert!(!addrs.iter().any(|a| a == "not_a_socket_addr"));
}

/// An authenticated inbound peer is learned as `IP:default_p2p_port`, then is
/// promoted only after node A successfully dials node B at that endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_inbound_peer_becomes_a_confirmed_pex_candidate() {
    init_tracing();
    let port_a = free_local_port();
    let default_port = Network::Regtest.default_port();
    let mut config_a = test_config("pex-inbound-a", port_a, false);
    let mut config_b = test_config("pex-inbound-b", default_port, false);
    config_b.p2p_listen_addr = format!("127.0.0.2:{default_port}");
    // A needs an outbound slot so its connector validates the learned endpoint.
    config_a.min_outbound = 1;
    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    tokio::spawn(node_b.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port_a}"), 10)
        .await
        .expect("node A listener ready");
    wait_for_listener_ready(&format!("127.0.0.2:{default_port}"), 10)
        .await
        .expect("node B listener ready");

    let (stream, codec) = connect_pex_peer_from(
        &node_a,
        "127.0.0.2:0".parse().expect("source address"),
        node_b.noise_privkey,
    )
    .await;
    let learned = format!("127.0.0.2:{default_port}");
    let known = wait_for_pex_known_count(&node_a, 1, Duration::from_secs(10)).await;
    assert!(known >= 1, "inbound peer was not learned");
    assert!(
        !node_a.pex.lock().await.is_confirmed(&learned),
        "inbound heuristic must remain unconfirmed before a dial succeeds"
    );
    drop(codec);
    drop(stream);

    let start = std::time::Instant::now();
    loop {
        if node_a.pex.lock().await.is_confirmed(&learned) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "node A did not validate learned inbound endpoint {learned}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Addr flood: each message beyond MAX_ADDR_MESSAGES_PER_WINDOW adds exactly
/// ADDRESS_FLOODING (+30). Sending budget+3 messages yields score 90 (3 excess
/// messages × 30), below the ban threshold so the connection remains live and
/// the score remains observable. The exact progression proves the limit runs.
#[tokio::test]
async fn pex_addr_flood_scores_address_flooding() {
    init_tracing();
    let port = free_local_port();
    let config = test_config("pex-addr-flood", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port}"), 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec) = connect_pex_peer(&node).await;
    // The node scores the peer by the inbound connection's remote address, our
    // local address.
    let peer_key = stream.local_addr().expect("local addr").to_string();

    let payload = AddrPayload {
        entries: vec![AddrEntry {
            addr: "10.99.77.4:33370".into(),
            last_seen: 1,
        }],
    }
    .to_bytes()
    .expect("encode addr");

    let excess = 3u32;
    let total = MAX_ADDR_MESSAGES_PER_WINDOW + excess;
    for i in 0..total {
        codec
            .send(&mut stream, &wire(&node, Command::Addr, payload.clone()))
            .await
            .unwrap_or_else(|e| panic!("send addr #{i} failed: {e:?}"));
    }

    let expected = excess * ban_scores::ADDRESS_FLOODING; // 90 < BAN_THRESHOLD
    let score = wait_for_ban_score(&node, &peer_key, expected, Duration::from_secs(10))
        .await
        .unwrap_or_else(|got| {
            panic!("ban score plateaued at {got}, expected {expected} — flood limit not applied")
        });
    assert_eq!(
        score, expected,
        "each excess Addr message must add exactly ADDRESS_FLOODING"
    );

    // Messages within the budget are still processed normally.
    let known = wait_for_pex_known_count(&node, 1, Duration::from_secs(5)).await;
    assert!(known >= 1, "in-budget Addr must still be processed");
}

//! PEX/Addr wiring — prova, no caminho P2P REAL (Noise + Hello), que:
//!
//! 1. GetAddr é respondido com um Addr contendo os peers conhecidos (bounded
//!    por MAX_ADDR_RESPONSE);
//! 2. um segundo GetAddr dentro do cooldown de 10 min é SUPRIMIDO (nenhum Addr
//!    chega antes do Pong de controle — observável determinístico de ordem, não
//!    de timing);
//! 3. Addr recebido alimenta o PexManager só com endereços válidos
//!    (SocketAddr parseável);
//! 4. flood de Addr além de MAX_ADDR_MESSAGES_PER_WINDOW incrementa o ban
//!    score do peer em ADDRESS_FLOODING (+30) por mensagem excedente — a
//!    progressão exata do score é a prova de que o rate-limit executa.

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

/// 1. GetAddr → Addr com os peers do PexManager (aqui, o seed configurado), e
/// 2. segundo GetAddr dentro do cooldown é suprimido: o Pong de controle chega
///    sem nenhum Addr antes dele.
#[tokio::test]
async fn pex_getaddr_answered_once_then_suppressed_by_cooldown() {
    init_tracing();
    let port = free_local_port();
    let mut config = test_config("pex-getaddr", port, false);
    // Endereço sintático válido e não roteável: vira conteúdo do PEX sem que
    // uma conexão real se estabeleça.
    config.seed_peers = vec!["10.99.77.1:33369".to_string()];
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port}"), 10)
        .await
        .expect("listener ready");

    // O connector alimenta o PexManager com os seeds; espere a semeadura.
    let known = wait_for_pex_known_count(&node, 1, Duration::from_secs(10)).await;
    assert!(known >= 1, "PEX seeding did not happen (known={known})");

    let (mut stream, mut codec) = connect_pex_peer(&node).await;

    // GetAddr #1 → deve responder Addr contendo o seed.
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

    // GetAddr #2 dentro do cooldown → suprimido. Prova por ordem: o Pong do
    // nosso Ping de controle chega SEM nenhum Addr antes dele.
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

/// Addr recebido alimenta o PexManager apenas com endereços SocketAddr
/// válidos; lixo é descartado sem crash e sem entrar no known set.
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

    let known = wait_for_pex_known_count(&node, 2, Duration::from_secs(10)).await;
    assert_eq!(known, 2, "exactly the two valid addresses must be added");
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

/// Flood de Addr: cada mensagem além de MAX_ADDR_MESSAGES_PER_WINDOW soma
/// exatamente ADDRESS_FLOODING (+30). Enviamos budget+3 mensagens → score 90
/// (3 excedentes × 30), abaixo do ban para a conexão seguir viva e o score ser
/// consultável. A progressão exata é a prova de que o limite executa.
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
    // O nó pontua o peer pelo remote addr da conexão inbound = nosso local addr.
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

    // As mensagens dentro do budget foram processadas normalmente.
    let known = wait_for_pex_known_count(&node, 1, Duration::from_secs(5)).await;
    assert!(known >= 1, "in-budget Addr must still be processed");
}

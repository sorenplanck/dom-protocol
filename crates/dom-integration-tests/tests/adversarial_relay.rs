use dom_config::Network;
use dom_consensus::derive_chain_id;
use dom_core::{Hash256, PROTOCOL_VERSION};
use dom_integration_tests::helpers::*;
use dom_node::node::DomNode;
use dom_wire::codec::NoiseCodec;
use dom_wire::handshake::{generate_static_keypair, perform_handshake_initiator};
use dom_wire::message::{BlockPayload, Command, HelloPayload, WireMessage};
use std::sync::atomic::Ordering;
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

async fn connect_adversarial_peer(node: &Arc<DomNode>) -> (tokio::net::TcpStream, NoiseCodec) {
    let config = node.config.clone();
    let mut stream = tokio::net::TcpStream::connect(&config.p2p_listen_addr)
        .await
        .expect("connect adversarial peer");
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
        user_agent: "dom-adversarial-relay-test".into(),
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
    let local_addr = stream
        .local_addr()
        .expect("local adversarial addr")
        .to_string();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node
                .peers
                .lock()
                .await
                .connected_peers()
                .contains(&local_addr)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("adversarial peer should be registered before relay spam");

    (stream, codec)
}

#[tokio::test]
async fn malformed_block_relay_over_live_noise_session_is_counted_and_disconnected() {
    init_tracing();
    let config = test_config("adversarial-relay-malformed", 43410, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready("127.0.0.1:43410", 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec) = connect_adversarial_peer(&node).await;
    let malformed = WireMessage {
        magic: node.config.network.magic(),
        command: Command::Block,
        payload: vec![0xde, 0xad],
    };
    codec
        .send(&mut stream, &malformed)
        .await
        .expect("send malformed block relay");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node.metrics.malformed_block_relays.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("malformed relay metric should increment");

    let recv_result = tokio::time::timeout(Duration::from_secs(5), codec.recv(&mut stream))
        .await
        .expect("connection should close instead of hanging");
    assert!(
        recv_result.is_err(),
        "malformed block relay should terminate the session"
    );
}

#[tokio::test]
async fn duplicate_block_relay_spam_hits_quota_over_live_noise_session() {
    init_tracing();
    let config = test_config("adversarial-relay-duplicate", 43411, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready("127.0.0.1:43411", 10)
        .await
        .expect("listener ready");

    let block_bytes = {
        let chain = node.chain.lock().await;
        chain
            .store
            .get_block_body(chain.tip_hash.as_bytes())
            .expect("read genesis block body")
            .expect("genesis body must exist")
    };
    let block_payload = BlockPayload {
        block_bytes: block_bytes.clone(),
    }
    .to_bytes()
    .expect("serialize block payload");

    let (mut stream, mut codec) = connect_adversarial_peer(&node).await;
    let duplicate = WireMessage {
        magic: node.config.network.magic(),
        command: Command::Block,
        payload: block_payload,
    };

    for _ in 0..40 {
        if codec.send(&mut stream, &duplicate).await.is_err() {
            break;
        }
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node
                .metrics
                .duplicate_block_relay_quota_exceeded
                .load(Ordering::Relaxed)
                >= 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("duplicate relay quota should trigger");

    assert!(
        node.metrics
            .suppressed_duplicate_block_relays
            .load(Ordering::Relaxed)
            >= 1
    );

    let recv_result = tokio::time::timeout(Duration::from_secs(5), codec.recv(&mut stream))
        .await
        .expect("duplicate relay session should close instead of hanging");
    assert!(
        recv_result.is_err(),
        "duplicate block relay quota should terminate the session"
    );
}

use dom_config::Network;
use dom_consensus::derive_chain_id;
use dom_core::Hash256;
use dom_integration_tests::helpers::*;
use dom_wire::codec::NoiseCodec;
use dom_wire::handshake::{generate_static_keypair, perform_handshake_initiator};
use dom_wire::message::{Command, HelloPayload, WireMessage};
use std::sync::atomic::Ordering;
use std::time::Duration;

fn chain_id_for(network: Network) -> [u8; 32] {
    let genesis_hash = match network {
        Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
    };
    *derive_chain_id(network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes()
}

#[tokio::test]
async fn hello_stall_is_penalized_and_releases_inbound_slot() {
    init_tracing();
    let config = test_config("adversarial-handshake-stall", 43412, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready("127.0.0.1:43412", 10)
        .await
        .expect("listener ready");

    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:43412")
        .await
        .expect("connect stalled peer");
    let client_addr = stream.local_addr().expect("local addr");
    let (privkey, _) = generate_static_keypair();
    let chain_id = chain_id_for(node.config.network);
    let transport = perform_handshake_initiator(
        &mut stream,
        &privkey,
        node.config.network.magic(),
        &chain_id,
    )
    .await
    .expect("perform Noise handshake");
    let mut codec = NoiseCodec::new(transport, node.config.network.magic());

    let server_hello = codec.recv(&mut stream).await.expect("receive server hello");
    assert_eq!(server_hello.command, Command::Hello);

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let peers = node.peers.lock().await;
            let released = peers.pending_inbound_count() == 0;
            let penalized = peers.pending_ban_score(&client_addr.to_string()) > 0;
            drop(peers);
            if released && penalized {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("hello timeout should penalize stalled peer and release reservation");

    let recv_result = tokio::time::timeout(Duration::from_secs(5), codec.recv(&mut stream))
        .await
        .expect("stalled hello session should close instead of hanging");
    assert!(
        recv_result.is_err(),
        "peer that never replies to Hello should be disconnected"
    );
}

#[tokio::test]
async fn second_hello_after_successful_exchange_is_disconnected_and_cleans_metrics() {
    init_tracing();
    let config = test_config("adversarial-handshake-second-hello", 43413, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready("127.0.0.1:43413", 10)
        .await
        .expect("listener ready");

    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:43413")
        .await
        .expect("connect peer");
    let (privkey, _) = generate_static_keypair();
    let chain_id = chain_id_for(node.config.network);
    let transport = perform_handshake_initiator(
        &mut stream,
        &privkey,
        node.config.network.magic(),
        &chain_id,
    )
    .await
    .expect("perform Noise handshake");
    let mut codec = NoiseCodec::new(transport, node.config.network.magic());

    let server_hello = codec.recv(&mut stream).await.expect("receive server hello");
    assert_eq!(server_hello.command, Command::Hello);

    let hello = HelloPayload {
        version: dom_core::PROTOCOL_VERSION,
        network_magic: node.config.network.magic(),
        chain_id,
        best_height: 0,
        best_hash: [0u8; 32],
        user_agent: "dom-second-hello-test".into(),
        local_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    codec
        .send(
            &mut stream,
            &WireMessage {
                magic: node.config.network.magic(),
                command: Command::Hello,
                payload: hello.to_bytes().expect("serialize hello"),
            },
        )
        .await
        .expect("send initial hello");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node.peers.lock().await.connected_peers().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("peer manager should reflect successful Hello");

    codec
        .send(
            &mut stream,
            &WireMessage {
                magic: node.config.network.magic(),
                command: Command::Hello,
                payload: hello.to_bytes().expect("serialize second hello"),
            },
        )
        .await
        .expect("send second hello");

    let recv_result = tokio::time::timeout(Duration::from_secs(5), codec.recv(&mut stream))
        .await
        .expect("second hello session should close instead of hanging");
    assert!(
        recv_result.is_err(),
        "peer that sends a second Hello should be disconnected"
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node.metrics.peer_count.load(Ordering::Relaxed) == 0
                && node.metrics.inbound_peers.load(Ordering::Relaxed) == 0
                && node.peers.lock().await.connected_peers().is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("post-violation cleanup should clear connected peer metrics");
}

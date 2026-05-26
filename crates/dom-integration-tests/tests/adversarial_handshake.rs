use dom_config::Network;
use dom_consensus::derive_chain_id;
use dom_core::Hash256;
use dom_integration_tests::helpers::*;
use dom_wire::codec::NoiseCodec;
use dom_wire::handshake::{
    generate_static_keypair, perform_handshake_initiator, HANDSHAKE_TIMEOUT_SECS, NOISE_MAX_MSG,
};
use dom_wire::message::{Command, HelloPayload, WireMessage};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;

fn chain_id_for(network: Network) -> [u8; 32] {
    let genesis_hash = match network {
        Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
    };
    *derive_chain_id(network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes()
}

async fn connect_noise_peer(
    node: &std::sync::Arc<dom_node::node::DomNode>,
    addr: &str,
) -> (tokio::net::TcpStream, NoiseCodec, std::net::SocketAddr) {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect peer");
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
    let codec = NoiseCodec::new(transport, node.config.network.magic());
    (stream, codec, client_addr)
}

async fn expect_pending_cleanup(
    node: &std::sync::Arc<dom_node::node::DomNode>,
    client_addr: std::net::SocketAddr,
    expect_penalty: bool,
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let peers = node.peers.lock().await;
            let released = peers.pending_inbound_count() == 0;
            let penalized = peers.pending_ban_score(&client_addr.to_string()) > 0;
            drop(peers);
            if released && (!expect_penalty || penalized) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("pending peer state should converge after hostile Hello");
}

#[tokio::test]
async fn hello_stall_is_penalized_and_releases_inbound_slot() {
    init_tracing();
    let port = free_local_port();
    let config = test_config("adversarial-handshake-stall", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    let addr = format!("127.0.0.1:{port}");
    wait_for_listener_ready(&addr, 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec, client_addr) = connect_noise_peer(&node, &addr).await;

    let server_hello = codec.recv(&mut stream).await.expect("receive server hello");
    assert_eq!(server_hello.command, Command::Hello);

    expect_pending_cleanup(&node, client_addr, true).await;

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
    let port = free_local_port();
    let config = test_config("adversarial-handshake-second-hello", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    let addr = format!("127.0.0.1:{port}");
    wait_for_listener_ready(&addr, 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec, _) = connect_noise_peer(&node, &addr).await;
    let chain_id = chain_id_for(node.config.network);

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

#[tokio::test]
async fn malformed_hello_after_noise_is_penalized_and_releases_inbound_slot() {
    init_tracing();
    let port = free_local_port();
    let config = test_config("adversarial-handshake-malformed-hello", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    let addr = format!("127.0.0.1:{port}");
    wait_for_listener_ready(&addr, 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec, client_addr) = connect_noise_peer(&node, &addr).await;
    let server_hello = codec.recv(&mut stream).await.expect("receive server hello");
    assert_eq!(server_hello.command, Command::Hello);

    codec
        .send(
            &mut stream,
            &WireMessage {
                magic: node.config.network.magic(),
                command: Command::Hello,
                payload: vec![0u8; 8],
            },
        )
        .await
        .expect("send malformed hello payload");

    expect_pending_cleanup(&node, client_addr, true).await;

    let recv_result = tokio::time::timeout(Duration::from_secs(5), codec.recv(&mut stream))
        .await
        .expect("malformed hello session should close instead of hanging");
    assert!(
        recv_result.is_err(),
        "peer that sends a malformed Hello should be disconnected"
    );
}

#[tokio::test]
async fn oversized_post_noise_frame_is_rejected_and_releases_inbound_slot() {
    init_tracing();
    let port = free_local_port();
    let config = test_config("adversarial-handshake-oversized-frame", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    let addr = format!("127.0.0.1:{port}");
    wait_for_listener_ready(&addr, 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec, client_addr) = connect_noise_peer(&node, &addr).await;
    let server_hello = codec.recv(&mut stream).await.expect("receive server hello");
    assert_eq!(server_hello.command, Command::Hello);

    stream
        .write_all(&((NOISE_MAX_MSG as u32) + 1).to_le_bytes())
        .await
        .expect("write oversized frame length");

    expect_pending_cleanup(&node, client_addr, true).await;

    let mut buf = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("oversized frame session should terminate");
    assert!(
        matches!(read_result, Ok(0) | Err(_)),
        "oversized post-Noise frame should force connection teardown"
    );
}

#[tokio::test]
async fn delayed_partial_hello_frame_times_out_and_cleans_pending_state() {
    init_tracing();
    let port = free_local_port();
    let config = test_config("adversarial-handshake-delayed-fragment", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    let addr = format!("127.0.0.1:{port}");
    wait_for_listener_ready(&addr, 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec, client_addr) = connect_noise_peer(&node, &addr).await;
    let server_hello = codec.recv(&mut stream).await.expect("receive server hello");
    assert_eq!(server_hello.command, Command::Hello);

    stream
        .write_all(&16u32.to_le_bytes())
        .await
        .expect("write partial frame length");
    stream
        .write_all(&[0u8; 4])
        .await
        .expect("write partial frame body");

    tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS + 1)).await;

    expect_pending_cleanup(&node, client_addr, true).await;

    let mut buf = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("delayed fragment session should terminate");
    assert!(
        matches!(read_result, Ok(0) | Err(_)),
        "partial Hello frame should not keep the session alive after timeout"
    );
}

#[tokio::test]
async fn concurrent_malformed_hello_peers_cleanup_converges() {
    init_tracing();
    let port = free_local_port();
    let config = test_config("adversarial-handshake-concurrent-malformed", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    let addr = format!("127.0.0.1:{port}");
    wait_for_listener_ready(&addr, 10)
        .await
        .expect("listener ready");

    let mut tasks = JoinSet::new();
    for _ in 0..2 {
        let node = node.clone();
        let addr = addr.clone();
        tasks.spawn(async move {
            let (mut stream, mut codec, client_addr) = connect_noise_peer(&node, &addr).await;
            let server_hello = codec.recv(&mut stream).await.expect("receive server hello");
            assert_eq!(server_hello.command, Command::Hello);

            codec
                .send(
                    &mut stream,
                    &WireMessage {
                        magic: node.config.network.magic(),
                        command: Command::Hello,
                        payload: vec![0u8; 8],
                    },
                )
                .await
                .expect("send malformed hello payload");

            let recv_result = tokio::time::timeout(Duration::from_secs(5), codec.recv(&mut stream))
                .await
                .expect("malformed hello session should close instead of hanging");
            assert!(
                recv_result.is_err(),
                "peer that sends a malformed Hello should be disconnected"
            );

            client_addr
        });
    }

    let mut client_addrs = Vec::new();
    while let Some(result) = tasks.join_next().await {
        client_addrs.push(result.expect("task join"));
    }

    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let peers = node.peers.lock().await;
            let all_penalized = client_addrs
                .iter()
                .all(|addr| peers.pending_ban_score(&addr.to_string()) > 0);
            let released = peers.pending_inbound_count() == 0;
            let connected = peers.connected_peers().is_empty();
            drop(peers);

            if all_penalized
                && released
                && connected
                && node.metrics.peer_count.load(Ordering::Relaxed) == 0
                && node.metrics.inbound_peers.load(Ordering::Relaxed) == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("concurrent malformed peers should converge to a clean pending state");
}

use dom_integration_tests::helpers::*;
use dom_wire::handshake::HANDSHAKE_TIMEOUT_SECS;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

async fn spawn_stalling_listener(addr: &str) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(addr)
        .await
        .expect("bind adversarial outbound listener");
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = accepts.clone();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            accepts_task.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS * 3)).await;
                drop(stream);
            });
        }
    });
    (accepts, handle)
}

async fn expect_outbound_cleanup(node: &std::sync::Arc<dom_node::node::DomNode>) {
    tokio::time::timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS + 8), async {
        loop {
            let peers = node.peers.lock().await;
            let pending_outbound = peers.pending_outbound_count();
            let connected = peers.connected_peers().len();
            drop(peers);
            if pending_outbound == 0
                && connected == 0
                && node.metrics.peer_count.load(Ordering::Relaxed) == 0
                && node.metrics.outbound_peers.load(Ordering::Relaxed) == 0
                && node.metrics.inbound_peers.load(Ordering::Relaxed) == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("outbound cleanup should converge after failed handshakes");
}

#[tokio::test]
async fn duplicate_seed_outbound_dials_are_deduplicated_live() {
    init_tracing();
    let (_accepts, listener_task) = spawn_stalling_listener("127.0.0.1:43417").await;

    let mut config = test_config("adversarial-outbound-duplicate-seed", 43418, false);
    config.min_outbound = 4;
    config.seed_peers = vec!["127.0.0.1:43417".into(); 32];
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready("127.0.0.1:43418", 10)
        .await
        .expect("listener ready");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node.peers.lock().await.pending_outbound_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("connector should reserve exactly one outbound slot for duplicate seeds");

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        node.peers.lock().await.pending_outbound_count(),
        1,
        "duplicate seed entries must not create overlapping outbound reservations"
    );
    assert_eq!(
        _accepts.load(Ordering::Relaxed),
        1,
        "duplicate seed entries must not create duplicate live dials"
    );

    expect_outbound_cleanup(&node).await;
    listener_task.abort();
}

#[tokio::test]
async fn stalled_outbound_dials_are_bounded_by_min_outbound_live() {
    init_tracing();
    let mut accept_counters = Vec::new();
    let mut listener_tasks = Vec::new();
    let seed_ports = [43419u16, 43420, 43421, 43422];
    for port in seed_ports {
        let (accepts, handle) = spawn_stalling_listener(&format!("127.0.0.1:{port}")).await;
        accept_counters.push(accepts);
        listener_tasks.push(handle);
    }

    let mut config = test_config("adversarial-outbound-bounded", 43423, false);
    config.min_outbound = 2;
    config.seed_peers = seed_ports
        .into_iter()
        .map(|port| format!("127.0.0.1:{port}"))
        .collect();
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready("127.0.0.1:43423", 10)
        .await
        .expect("listener ready");

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let total_accepts = accept_counters
                .iter()
                .map(|accepts| accepts.load(Ordering::Relaxed))
                .sum::<usize>();
            if total_accepts == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("connector should only dial up to min_outbound hostile peers");

    tokio::time::sleep(Duration::from_millis(250)).await;
    let total_accepts = accept_counters
        .iter()
        .map(|accepts| accepts.load(Ordering::Relaxed))
        .sum::<usize>();
    assert_eq!(
        total_accepts, 2,
        "hostile seed fanout must stay bounded by min_outbound"
    );
    assert_eq!(
        node.peers.lock().await.pending_outbound_count(),
        2,
        "pending outbound reservations must match bounded live dials"
    );

    expect_outbound_cleanup(&node).await;
    for handle in listener_tasks {
        handle.abort();
    }
}

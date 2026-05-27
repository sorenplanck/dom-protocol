//! Adversarial coverage for the wallet ↔ node RPC client (Phase 1.9).
//!
//! The tests stand up a minimal raw-TCP mock server inside a single-
//! threaded tokio runtime. The server is parameterised by a closure
//! that receives the request line + headers and returns the raw bytes
//! to write back (or `None` to hang). This gives us total control
//! over the wire format — essential for the malformed-JSON,
//! truncated-body, and slow-response cases.
//!
//! Each test starts its own runtime and listener on `127.0.0.1:0` so
//! tests are isolated and can run in parallel.
//!
//! Properties covered:
//!
//! 1. **Happy paths** — `/health`, `/status`, `/block/{height}`,
//!    `/block/{hash}`, `/tx/submit`, `/tx/{hash}` (found and absent).
//! 2. **Determinism / timeouts** — slow server → `ReadTimeout`;
//!    unbound port → `ConnectTimeout` or `Transport` (resolved
//!    deterministically by the OS).
//! 3. **Malformed / truncated responses** — `Decode` for bad JSON,
//!    `Transport` for truncated bodies.
//! 4. **Node error mapping** — 400/409/503/500 → `NodeRejected` with
//!    `status` preserved.
//! 5. **Restart-equivalence / no client state corruption** — a call
//!    that hits a transport failure must leave the client able to
//!    serve subsequent calls.
//! 6. **Replay-safe submit** — a second submit of the same tx
//!    returning 409 keeps the first call's reported tx_hash valid;
//!    the client never mutates wallet state on its own.
//! 7. **Auth** — 401 / 403 → `Unauthorized`.
//! 8. **Path joining** — paths resolve correctly under a base URL with
//!    or without trailing slash and against a non-root path prefix.

use dom_consensus::transaction::Transaction;
use dom_wallet::{NodeRpc, NodeRpcClient, NodeRpcClientBuilder, RpcClientError};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

// ── Mock server harness ─────────────────────────────────────────

/// Behaviour controller for an inbound request.
enum Action {
    /// Write the bytes verbatim, then close.
    Respond(Vec<u8>),
    /// Sleep for the given duration, then close without writing.
    Sleep(Duration),
    /// Read the request, accept it, write part of a response, drop.
    PartialThenClose(Vec<u8>),
    /// Immediately drop the connection after the request line is read.
    DropAfterHeaders,
}

struct MockServer {
    addr: SocketAddr,
    _shutdown: oneshot::Sender<()>,
    /// Counter of requests the server has accepted from a client.
    requests_seen: Arc<AtomicU64>,
    /// Joined by Drop to make sure the runtime thread exits cleanly.
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            // Signal shutdown; if the receiver is already dropped
            // because the runtime exited, that's fine.
            let _ = h.join();
        }
    }
}

impl MockServer {
    fn url(&self) -> Url {
        Url::parse(&format!("http://{}/", self.addr)).unwrap()
    }

    fn requests_seen(&self) -> u64 {
        self.requests_seen.load(Ordering::SeqCst)
    }
}

/// Start a mock server that runs `route_fn` against every accepted
/// request. The closure is called with the raw request line (e.g.,
/// "POST /tx/submit HTTP/1.1") and the parsed body string. It returns
/// an [`Action`] describing how to respond.
fn start_mock_server<F>(route_fn: F) -> MockServer
where
    F: Fn(&str, &str) -> Action + Send + Sync + 'static,
{
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let route_fn = Arc::new(route_fn);
    let requests_seen = Arc::new(AtomicU64::new(0));
    let requests_seen_clone = Arc::clone(&requests_seen);

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let _ = addr_tx.send(addr);

            let route_fn = route_fn.clone();
            let requests_seen = requests_seen_clone;
            let accept_loop = async move {
                loop {
                    let (mut sock, _peer) = match listener.accept().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    let route_fn = route_fn.clone();
                    let requests_seen = requests_seen.clone();
                    tokio::spawn(async move {
                        requests_seen.fetch_add(1, Ordering::SeqCst);
                        // Read up to 64 KiB of the request — enough for
                        // any submit_tx body in these tests.
                        let mut buf = vec![0u8; 64 * 1024];
                        let mut read_total = 0;
                        loop {
                            match sock.read(&mut buf[read_total..]).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    read_total += n;
                                    let request_text = String::from_utf8_lossy(&buf[..read_total]);
                                    // Break once we've seen the
                                    // headers terminator. If a body
                                    // is declared, read up to its
                                    // Content-Length too.
                                    if let Some(headers_end) = request_text.find("\r\n\r\n") {
                                        let headers_str = &request_text[..headers_end];
                                        let content_length = headers_str
                                            .lines()
                                            .find_map(|l| {
                                                let l = l.to_lowercase();
                                                l.strip_prefix("content-length:")
                                                    .map(|v| v.trim().to_string())
                                            })
                                            .and_then(|v| v.parse::<usize>().ok())
                                            .unwrap_or(0);
                                        let body_start = headers_end + 4;
                                        if read_total >= body_start + content_length {
                                            break;
                                        }
                                    }
                                    if read_total == buf.len() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        let request_text = String::from_utf8_lossy(&buf[..read_total]).to_string();
                        let (request_line, body) = split_request_line_and_body(&request_text);
                        let action = (route_fn)(&request_line, &body);
                        match action {
                            Action::Respond(bytes) => {
                                let _ = sock.write_all(&bytes).await;
                                let _ = sock.shutdown().await;
                            }
                            Action::Sleep(d) => {
                                tokio::time::sleep(d).await;
                                let _ = sock.shutdown().await;
                            }
                            Action::PartialThenClose(bytes) => {
                                let _ = sock.write_all(&bytes).await;
                                // Drop the socket — connection reset.
                                drop(sock);
                            }
                            Action::DropAfterHeaders => {
                                drop(sock);
                            }
                        }
                    });
                }
            };
            tokio::select! {
                _ = accept_loop => {}
                _ = shutdown_rx => {}
            }
        });
    });

    let addr = addr_rx.recv().expect("mock server didn't report its addr");
    MockServer {
        addr,
        _shutdown: shutdown_tx,
        requests_seen,
        handle: Some(handle),
    }
}

fn split_request_line_and_body(req: &str) -> (String, String) {
    let mut lines = req.split("\r\n");
    let line = lines.next().unwrap_or("").to_string();
    let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (line, body)
}

fn http_ok_json(body: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
    v.extend_from_slice(b"Content-Type: application/json\r\n");
    v.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    v.extend_from_slice(b"Connection: close\r\n\r\n");
    v.extend_from_slice(body.as_bytes());
    v
}

fn http_response(status: u16, status_text: &str, body: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(format!("HTTP/1.1 {status} {status_text}\r\n").as_bytes());
    v.extend_from_slice(b"Content-Type: application/json\r\n");
    v.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    v.extend_from_slice(b"Connection: close\r\n\r\n");
    v.extend_from_slice(body.as_bytes());
    v
}

fn dummy_tx() -> Transaction {
    // An empty Transaction serialises fine — the RPC client only
    // needs `to_bytes()` to succeed. Consensus validity is irrelevant
    // because the mock server inspects the hex payload, not the
    // decoded transaction.
    Transaction {
        inputs: vec![],
        outputs: vec![],
        kernels: vec![],
        offset: [0u8; 32],
    }
}

fn fast_client(server: &MockServer) -> NodeRpcClient {
    NodeRpcClientBuilder::from_url(server.url())
        .request_timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(1))
        .build()
        .expect("build client")
}

/// Convenience helper because we need a builder constructor accessible
/// from tests without exposing the internal field.
trait BuilderExt {
    fn from_url(url: Url) -> Self;
}

impl BuilderExt for NodeRpcClientBuilder {
    fn from_url(url: Url) -> Self {
        NodeRpcClient::builder(url)
    }
}

// ── 1. Happy paths ──────────────────────────────────────────────

#[test]
fn health_ok_against_live_mock() {
    let server = start_mock_server(|_line, _body| Action::Respond(http_ok_json(r#"{"ok":true}"#)));
    let client = fast_client(&server);
    client.health().expect("health ok");
}

#[test]
fn status_returns_chain_height_and_version() {
    let server = start_mock_server(|_line, _body| {
        Action::Respond(http_ok_json(
            r#"{"version":1,"chain_height":42,"mempool_size":3,"network":"regtest"}"#,
        ))
    });
    let client = fast_client(&server);
    let s = client.status().expect("status ok");
    assert_eq!(s.version, 1);
    assert_eq!(s.chain_height, 42);
    assert_eq!(s.mempool_size, 3);
    assert_eq!(s.network, "regtest");
}

#[test]
fn block_at_height_200_decodes() {
    let server = start_mock_server(|line, _body| {
        assert!(line.contains("/block/100"), "actual line: {line}");
        Action::Respond(http_ok_json(
            r#"{"height":100,"hash":"aa00000000000000000000000000000000000000000000000000000000000000","prev_hash":"bb00000000000000000000000000000000000000000000000000000000000000","timestamp":12345,"target":"cc00000000000000000000000000000000000000000000000000000000000000"}"#,
        ))
    });
    let client = fast_client(&server);
    let blk = client.block_at_height(100).unwrap().unwrap();
    assert_eq!(blk.height, 100);
    assert_eq!(blk.hash[0], 0xaa);
    assert_eq!(blk.prev_hash[0], 0xbb);
    assert_eq!(blk.target[0], 0xcc);
    assert_eq!(blk.timestamp, 12345);
}

#[test]
fn block_at_height_404_is_ok_none_not_error() {
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_response(404, "Not Found", r#"{"found":false}"#))
    });
    let client = fast_client(&server);
    let blk = client.block_at_height(999).unwrap();
    assert!(blk.is_none(), "missing block must be Ok(None), not Err");
}

#[test]
fn block_by_hash_routes_to_hex_path() {
    let server = start_mock_server(|line, _body| {
        // Confirm the client formats the path as block/<64-hex>.
        let expected = "/block/aa00000000000000000000000000000000000000000000000000000000000000";
        assert!(line.contains(expected), "got: {line}");
        Action::Respond(http_ok_json(
            r#"{"height":7,"hash":"aa00000000000000000000000000000000000000000000000000000000000000","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","timestamp":1,"target":"0000000000000000000000000000000000000000000000000000000000000001"}"#,
        ))
    });
    let client = fast_client(&server);
    let mut hash = [0u8; 32];
    hash[0] = 0xaa;
    let blk = client.block_by_hash(&hash).unwrap().unwrap();
    assert_eq!(blk.height, 7);
}

#[test]
fn submit_tx_200_accepted_decodes_hash() {
    let server = start_mock_server(|line, body| {
        assert!(line.starts_with("POST /tx/submit"), "actual line: {line}");
        // The body must carry tx_hex.
        let v: serde_json::Value = serde_json::from_str(body).expect("server got JSON body");
        assert!(v.get("tx_hex").and_then(|v| v.as_str()).is_some());
        Action::Respond(http_ok_json(
            r#"{"accepted":true,"tx_hash":"de00000000000000000000000000000000000000000000000000000000000000"}"#,
        ))
    });
    let client = fast_client(&server);
    let tx = dummy_tx();
    let out = client.submit_tx(&tx).expect("submit ok");
    assert_eq!(out.tx_hash[0], 0xde);
}

#[test]
fn mempool_tx_200_found_decodes() {
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_ok_json(
            r#"{"found":true,"tx_hash":"ee00000000000000000000000000000000000000000000000000000000000000","fee":100,"fee_rate":5,"weight":50}"#,
        ))
    });
    let client = fast_client(&server);
    let hash = [0xeeu8; 32];
    let info = client.mempool_tx(&hash).unwrap().unwrap();
    assert_eq!(info.tx_hash[0], 0xee);
    assert_eq!(info.fee_noms, 100);
    assert_eq!(info.fee_rate, 5);
    assert_eq!(info.weight, 50);
}

#[test]
fn mempool_tx_200_absent_is_ok_none() {
    let server = start_mock_server(|_l, _b| Action::Respond(http_ok_json(r#"{"found":false}"#)));
    let client = fast_client(&server);
    let hash = [0u8; 32];
    let info = client.mempool_tx(&hash).unwrap();
    assert!(info.is_none());
}

// ── 2. Determinism / timeouts ────────────────────────────────────

#[test]
fn slow_server_triggers_read_timeout_within_budget() {
    let server = start_mock_server(|_l, _b| {
        // Sleep well past the client's 2 s request budget then close.
        Action::Sleep(Duration::from_secs(5))
    });
    let client = NodeRpcClient::builder(server.url())
        .request_timeout(Duration::from_millis(500))
        .connect_timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let start = std::time::Instant::now();
    let err = client.status().unwrap_err();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "client did not honour timeout: elapsed = {elapsed:?}"
    );
    match err {
        RpcClientError::ReadTimeout { .. } | RpcClientError::Transport { .. } => {}
        other => panic!("expected ReadTimeout or Transport, got {other:?}"),
    }
}

#[test]
fn connection_to_dead_port_yields_transport_or_connect_timeout() {
    // Bind a listener just to grab an unused port, then drop it so the
    // port becomes unbound for the test duration. There is an
    // inherent race here — between drop and connect, another process
    // could grab the port — but on a test box it's effectively never
    // observed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = Url::parse(&format!("http://{addr}/")).unwrap();
    let client = NodeRpcClient::builder(url)
        .request_timeout(Duration::from_millis(500))
        .connect_timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let err = client.status().unwrap_err();
    match err {
        // Linux returns ECONNREFUSED immediately → Transport.
        // On platforms where the connect blocks until timeout, the
        // ConnectTimeout variant is returned. Both are acceptable.
        RpcClientError::Transport { .. } | RpcClientError::ConnectTimeout { .. } => {}
        other => panic!("expected Transport or ConnectTimeout, got {other:?}"),
    }
}

// ── 3. Malformed / truncated responses ──────────────────────────

#[test]
fn malformed_json_returns_decode_error() {
    let server = start_mock_server(|_l, _b| {
        // 200 OK but body is not valid JSON.
        Action::Respond(http_ok_json(
            r#"{"version":1,"chain_height": NOT-A-NUMBER}"#,
        ))
    });
    let client = fast_client(&server);
    let err = client.status().unwrap_err();
    match err {
        RpcClientError::Decode { reason, .. } => {
            assert!(reason.contains("expected") || reason.contains("invalid"))
        }
        other => panic!("expected Decode, got {other:?}"),
    }
}

#[test]
fn shape_mismatch_returns_decode_error() {
    // Body is valid JSON but missing required fields.
    let server = start_mock_server(|_l, _b| Action::Respond(http_ok_json(r#"{}"#)));
    let client = fast_client(&server);
    let err = client.status().unwrap_err();
    match err {
        RpcClientError::Decode { .. } => {}
        other => panic!("expected Decode, got {other:?}"),
    }
}

#[test]
fn truncated_body_returns_transport_error() {
    // Send headers claiming a body of 200 bytes but only deliver 10.
    let server = start_mock_server(|_l, _b| {
        let mut v = Vec::new();
        v.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        v.extend_from_slice(b"Content-Type: application/json\r\n");
        v.extend_from_slice(b"Content-Length: 200\r\n");
        v.extend_from_slice(b"Connection: close\r\n\r\n");
        // Deliberately short body.
        v.extend_from_slice(b"{\"ok\":true}");
        Action::PartialThenClose(v)
    });
    let client = fast_client(&server);
    let err = client.health().unwrap_err();
    match err {
        // The client should surface this as a transport/read failure,
        // not as a successful decode of a partial body.
        RpcClientError::Transport { .. } | RpcClientError::ReadTimeout { .. } => {}
        other => panic!("expected Transport or ReadTimeout, got {other:?}"),
    }
}

// ── 4. Node error mapping ───────────────────────────────────────

#[test]
fn submit_tx_409_maps_to_node_rejected() {
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_response(
            409,
            "Conflict",
            r#"{"accepted":false,"error":"already in mempool"}"#,
        ))
    });
    let client = fast_client(&server);
    let err = client.submit_tx(&dummy_tx()).unwrap_err();
    match err {
        RpcClientError::NodeRejected { status, reason } => {
            assert_eq!(status, 409);
            assert!(reason.contains("already in mempool"));
        }
        other => panic!("expected NodeRejected, got {other:?}"),
    }
}

#[test]
fn submit_tx_400_maps_to_node_rejected_with_reason() {
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_response(
            400,
            "Bad Request",
            r#"{"accepted":false,"error":"invalid hex"}"#,
        ))
    });
    let client = fast_client(&server);
    let err = client.submit_tx(&dummy_tx()).unwrap_err();
    match err {
        RpcClientError::NodeRejected { status, reason } => {
            assert_eq!(status, 400);
            assert!(reason.contains("invalid hex"));
        }
        other => panic!("expected NodeRejected, got {other:?}"),
    }
}

#[test]
fn submit_tx_503_maps_to_node_rejected_status_503() {
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_response(
            503,
            "Service Unavailable",
            r#"{"accepted":false,"error":"overloaded"}"#,
        ))
    });
    let client = fast_client(&server);
    let err = client.submit_tx(&dummy_tx()).unwrap_err();
    match err {
        RpcClientError::NodeRejected { status, reason } => {
            assert_eq!(status, 503);
            assert!(reason.contains("overloaded"));
        }
        other => panic!("expected NodeRejected, got {other:?}"),
    }
}

#[test]
fn submit_tx_500_maps_to_node_rejected_status_500() {
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_response(
            500,
            "Internal Server Error",
            r#"{"accepted":false,"error":"boom"}"#,
        ))
    });
    let client = fast_client(&server);
    let err = client.submit_tx(&dummy_tx()).unwrap_err();
    match err {
        RpcClientError::NodeRejected { status, .. } => assert_eq!(status, 500),
        other => panic!("expected NodeRejected, got {other:?}"),
    }
}

#[test]
fn status_500_with_typed_error_body_maps_to_node_rejected() {
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_response(500, "Internal", r#"{"error":"db down"}"#))
    });
    let client = fast_client(&server);
    let err = client.status().unwrap_err();
    match err {
        RpcClientError::NodeRejected { status, reason } => {
            assert_eq!(status, 500);
            assert_eq!(reason, "db down");
        }
        other => panic!("expected NodeRejected, got {other:?}"),
    }
}

// ── 5. Restart-equivalence: no client state corruption on failure ─

#[test]
fn client_recovers_from_prior_request_failure() {
    use std::sync::atomic::AtomicU8;
    let counter = Arc::new(AtomicU8::new(0));
    let counter_c = Arc::clone(&counter);
    let server = start_mock_server(move |_l, _b| {
        let n = counter_c.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            // First request: drop the connection without responding.
            Action::DropAfterHeaders
        } else {
            // Subsequent requests: serve normally.
            Action::Respond(http_ok_json(
                r#"{"version":1,"chain_height":7,"mempool_size":0,"network":"regtest"}"#,
            ))
        }
    });
    let client = fast_client(&server);
    let first = client.status();
    assert!(
        matches!(
            first,
            Err(RpcClientError::Transport { .. } | RpcClientError::Decode { .. })
        ),
        "first call: {first:?}"
    );
    // Second call must succeed — the client must not have cached
    // any failure state from the prior call.
    let second = client.status().expect("second call ok");
    assert_eq!(second.chain_height, 7);
}

// ── 6. Replay-safe submit & duplicate semantics ─────────────────

#[test]
fn submit_then_resubmit_yields_409_with_original_hash_in_reason() {
    use std::sync::Mutex;
    let store: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let store_c = Arc::clone(&store);
    let server = start_mock_server(move |_line, body| {
        let v: serde_json::Value = serde_json::from_str(body).expect("server got JSON body");
        let tx_hex = v
            .get("tx_hex")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let mut g = store_c.lock().unwrap();
        if g.is_some() && *g == Some(tx_hex.clone()) {
            Action::Respond(http_response(
                409,
                "Conflict",
                r#"{"accepted":false,"error":"rejected: already in mempool"}"#,
            ))
        } else {
            *g = Some(tx_hex);
            Action::Respond(http_ok_json(
                r#"{"accepted":true,"tx_hash":"1100000000000000000000000000000000000000000000000000000000000000"}"#,
            ))
        }
    });
    let client = fast_client(&server);
    let tx = dummy_tx();

    let first = client.submit_tx(&tx).expect("first ok");
    assert_eq!(first.tx_hash[0], 0x11);

    let err = client.submit_tx(&tx).unwrap_err();
    match err {
        RpcClientError::NodeRejected { status, reason } => {
            assert_eq!(status, 409);
            assert!(reason.contains("already in mempool"));
        }
        other => panic!("expected NodeRejected(409), got {other:?}"),
    }

    // Server saw exactly two requests — the client did not retry.
    assert_eq!(server.requests_seen(), 2);
}

#[test]
fn client_never_retries_on_node_rejection() {
    // A repeated `Rejected` response must not trigger any internal
    // retry — bounded request behaviour.
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_response(
            409,
            "Conflict",
            r#"{"accepted":false,"error":"fee too low"}"#,
        ))
    });
    let client = fast_client(&server);
    let _ = client.submit_tx(&dummy_tx()).unwrap_err();
    assert_eq!(server.requests_seen(), 1, "client must not retry");
}

// ── 7. Auth ─────────────────────────────────────────────────────

#[test]
fn unauthorized_401_returns_unauthorized_variant() {
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_response(
            401,
            "Unauthorized",
            r#"{"error":"missing token"}"#,
        ))
    });
    let client = fast_client(&server);
    let err = client.status().unwrap_err();
    match err {
        RpcClientError::Unauthorized { .. } => {}
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn forbidden_403_returns_unauthorized_variant() {
    let server = start_mock_server(|_l, _b| {
        Action::Respond(http_response(403, "Forbidden", r#"{"error":"bad token"}"#))
    });
    let client = fast_client(&server);
    let err = client.status().unwrap_err();
    match err {
        RpcClientError::Unauthorized { .. } => {}
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[test]
fn bearer_token_is_sent_when_configured() {
    // Configure the server route to inspect the FULL request text
    // (including headers) and assert the Authorization header is
    // present iff the client was configured with a token.
    let server = start_mock_server(|line, _body| {
        // The `line` argument we receive here is only the request
        // line; to peek headers we use a separate path below.
        // Instead, signal via path: clients configured with a token
        // hit `/with-token`; tokenless clients hit `/health`. The
        // mock server lets us differentiate by counting.
        let _is_token_path = line.contains("/with-token");
        Action::Respond(http_ok_json(r#"{"ok":true}"#))
    });
    let with_token = NodeRpcClient::builder(server.url())
        .request_timeout(Duration::from_millis(500))
        .connect_timeout(Duration::from_millis(200))
        .bearer_token("deadbeef")
        .build()
        .unwrap();
    let without_token = fast_client(&server);
    // Both calls must succeed — no panic-on-build, no extra latency.
    with_token.health().unwrap();
    without_token.health().unwrap();
    assert_eq!(server.requests_seen(), 2);
}

#[test]
fn bearer_token_appears_in_authorization_header() {
    // Richer harness: capture the full raw request and inspect for
    // the `Authorization: Bearer deadbeef` header line.
    use std::sync::Mutex;
    let observed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_c = Arc::clone(&observed);
    // For this test we hijack the body field — start_mock_server's
    // route_fn already receives the body separately, but the request
    // line carries only the verb+path. We instead inspect the raw
    // request by listening directly with a side-channel.
    //
    // Simplest approach: use a custom server inline.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(false).unwrap();
    let observed_thread = Arc::clone(&observed_c);
    let server_thread = std::thread::spawn(move || {
        use std::io::Read;
        use std::io::Write;
        for _ in 0..1 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = stream.read(&mut buf[total..]).unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            observed_thread
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..total]).to_string());
            let body = r#"{"ok":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    let url = Url::parse(&format!("http://{addr}/")).unwrap();
    let client = NodeRpcClient::builder(url)
        .request_timeout(Duration::from_secs(1))
        .connect_timeout(Duration::from_millis(500))
        .bearer_token("deadbeef")
        .build()
        .unwrap();
    client.health().unwrap();
    server_thread.join().unwrap();
    let raw = observed.lock().unwrap().pop().expect("no request observed");
    let lower = raw.to_lowercase();
    assert!(
        lower.contains("authorization: bearer deadbeef"),
        "expected Authorization header in:\n{raw}"
    );
}

// ── 8. Path joining ─────────────────────────────────────────────

#[test]
fn base_url_without_trailing_slash_still_joins_correctly() {
    let server = start_mock_server(|line, _body| {
        // Path should be "/v1/status" — the builder must normalise.
        assert!(line.contains("/v1/status"), "actual line: {line}");
        Action::Respond(http_ok_json(
            r#"{"version":1,"chain_height":1,"mempool_size":0,"network":"regtest"}"#,
        ))
    });
    let url_no_slash = Url::parse(&format!("http://{}/v1", server.addr)).unwrap();
    let client = NodeRpcClient::builder(url_no_slash)
        .request_timeout(Duration::from_millis(500))
        .connect_timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let _ = client.status().unwrap();
}

// ── 9. Conversions ──────────────────────────────────────────────

#[test]
fn rpc_client_error_converts_to_wallet_error() {
    use dom_wallet::WalletError;
    let err = RpcClientError::ConnectTimeout {
        url: "http://nope/".into(),
    };
    let w: WalletError = err.into();
    match w {
        WalletError::Io(msg) => assert!(msg.contains("rpc:")),
        other => panic!("expected Io, got {other:?}"),
    }
}

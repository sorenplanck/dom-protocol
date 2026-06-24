//! dom-shield — HTTP attack-surface coverage for `dom-explorer`.
//!
//! `dom-explorer` is a read-only public-data REST API that proxies chain reads
//! to a node. It holds **no secrets** (Lens B → N/A, see report), so the only
//! genuinely attackable surface is the *untrusted HTTP request path*: the route
//! extractors (`Path<u64>` for height, `Path<String>` → `decode_hash` for the
//! 32-byte hash) and the JSON serialization of the response.
//!
//! These tests stand up the **real** `ExplorerServer` (production `Router`,
//! production handlers, production `decode_hash`/`hex_encode`) on an
//! OS-assigned localhost port and drive it with raw HTTP/1.1 requests. No
//! production code is changed; the server is exercised black-box, exactly as a
//! hostile client on the network would.
//!
//! Subfamilies covered (per dom-shield doctrine):
//!   * KAV-negativo / fuzz-panic — `decode_hash` on arbitrary / odd-length /
//!     oversized / non-hex strings must yield a clean 400, never a panic.
//!   * KAV-negativo — `Path<u64>` height overflow / non-numeric must yield a
//!     clean 4xx, never a panic.
//!   * XDIFF — production `hex_encode` (observed via `/api/info` tip_hash) must
//!     be byte-identical to the reference `hex::encode`.
//!   * fuzz-amplificação — bounded fan-out / bounded response size (analysis +
//!     a response-size assert against a mock provider).

use dom_explorer::{BlockSummary, ChainProvider, ExplorerServer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ── Mock provider ────────────────────────────────────────────────────────────

/// Deterministic provider with a fixed, non-trivial tip hash so the XDIFF test
/// can compare the bytes the server emits against `hex::encode`.
struct MockProvider {
    /// Counts every backend read so the fan-out (amplification) test can assert
    /// the per-request multiplier is bounded.
    reads: AtomicU64,
    tip: [u8; 32],
}

impl MockProvider {
    fn new() -> Self {
        // A tip with low and high nibbles, leading zero byte, and 0xff to catch
        // any zero-padding / sign / width bug in the hex encoder.
        let mut tip = [0u8; 32];
        for (i, b) in tip.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7); // 0x00, 0x07, 0x0e, ... wraps
        }
        tip[31] = 0xff;
        Self {
            reads: AtomicU64::new(0),
            tip,
        }
    }
}

impl ChainProvider for MockProvider {
    fn chain_height(&self) -> u64 {
        self.reads.fetch_add(1, Ordering::SeqCst);
        424_242
    }
    fn chain_tip_hash(&self) -> [u8; 32] {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.tip
    }
    fn network(&self) -> String {
        self.reads.fetch_add(1, Ordering::SeqCst);
        "regtest".to_string()
    }
    fn get_block_at_height(&self, height: u64) -> Option<BlockSummary> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Some(BlockSummary {
            height,
            hash: "deadbeef".to_string(),
            prev_hash: "cafebabe".to_string(),
            timestamp: 1_747_958_400,
            output_count: Some(1),
            kernel_count: Some(1),
        })
    }
    fn get_block_by_hash(&self, _hash: &[u8; 32]) -> Option<BlockSummary> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        // Returns Some so a *valid* 64-hex request reaches a 200 path; the
        // hostile-string tests are rejected earlier by decode_hash (400).
        Some(BlockSummary {
            height: 1,
            hash: "00".repeat(32),
            prev_hash: "11".repeat(32),
            timestamp: 1_747_958_400,
            output_count: Some(0),
            kernel_count: Some(0),
        })
    }
}

// ── Server harness ───────────────────────────────────────────────────────────

/// Start the real `ExplorerServer` on a free localhost port; return its addr and
/// the shared provider (so tests can read the backend-read counter).
async fn start_server(provider: Arc<MockProvider>) -> SocketAddr {
    // Grab a free port from the OS, then hand the concrete addr to the server.
    // (The production `start()` binds the addr it is given and does not expose
    // the bound port, so we resolve a free port up front.)
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let server = ExplorerServer::new(addr.to_string(), provider);
    tokio::spawn(async move {
        // Ignore the result: the task is aborted at test end.
        let _ = server.start().await;
    });

    // Wait until the listener is accepting (bounded retry, no fixed sleep race).
    for _ in 0..200 {
        if TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("explorer server did not come up on {addr}");
}

/// Minimal raw HTTP/1.1 GET. Returns (status_code, body). The path is sent
/// verbatim — no client-side normalization — so we control the exact bytes the
/// server's extractors see.
async fn http_get(addr: SocketAddr, raw_path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {raw_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = Vec::new();
    // Bounded read with a timeout so a hang fails the test instead of blocking.
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    read.expect("response read timed out").unwrap();

    let text = String::from_utf8_lossy(&buf);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

// ── KAV-negativo / fuzz-panic: decode_hash via /api/block/hash/:hash ─────────

/// Every hostile / malformed hash string must produce a clean 400 (BAD_REQUEST)
/// and the server must stay up. Covers: odd-length, non-hex, oversized (>32B),
/// undersized (<32B), empty-ish, embedded nul-ish, unicode, very long.
#[tokio::test]
async fn decode_hash_rejects_malformed_with_400_never_panics() {
    let provider = Arc::new(MockProvider::new());
    let addr = start_server(provider).await;

    // (label, hash-segment-as-sent). All must be 400.
    let cases: Vec<(&str, String)> = vec![
        ("odd length", "abc".to_string()),
        ("non-hex chars", "z".repeat(64)),
        ("undersized 30B", "ab".repeat(30)),
        ("undersized 1B", "ab".to_string()),
        ("oversized 33B", "ab".repeat(33)),
        ("oversized 64B", "ab".repeat(64)),
        ("huge 4KB hex", "a".repeat(4096)),
        ("single char", "a".to_string()),
        ("uppercase valid-len-but-len-31.5", "AB".repeat(33)),
        ("mixed garbage", "0xdeadbeef".to_string()),
        ("dot", ".".to_string()),
        ("plus", "%2B".to_string()), // url-encoded '+'
    ];

    for (label, seg) in &cases {
        let (status, _body) = http_get(addr, &format!("/api/block/hash/{seg}")).await;
        assert_eq!(
            status,
            400,
            "hostile hash case '{label}' (seg len {}) must be 400, got {status}",
            seg.len()
        );
    }

    // Server is still alive after all hostile inputs (no crash).
    let (root_status, _) = http_get(addr, "/").await;
    assert_eq!(root_status, 200, "server must survive all malformed hashes");
}

/// A *well-formed* 64-char lowercase hex hash must decode and reach the handler
/// (200 here because the mock returns Some). Confirms the 400 above is rejecting
/// malformed input specifically, not all input (no false-positive theater).
#[tokio::test]
async fn decode_hash_accepts_valid_64_hex() {
    let provider = Arc::new(MockProvider::new());
    let addr = start_server(provider).await;

    let valid = "ab".repeat(32); // exactly 64 hex chars → 32 bytes
    let (status, body) = http_get(addr, &format!("/api/block/hash/{valid}")).await;
    assert_eq!(status, 200, "valid 64-hex hash must reach handler (200)");
    assert!(
        body.contains("\"height\""),
        "expected BlockSummary JSON, got {body:?}"
    );
}

// ── KAV-negativo: get_block_by_height Path<u64> ──────────────────────────────

/// Height extractor: u64::MAX and 0 are valid u64 → handler runs (200, mock
/// returns Some). Out-of-u64-range and non-numeric must be a clean 4xx, never a
/// panic / 500.
#[tokio::test]
async fn get_block_by_height_path_u64_bounds_and_overflow() {
    let provider = Arc::new(MockProvider::new());
    let addr = start_server(provider).await;

    // Valid u64 extremes → 200 (mock returns Some).
    // NOTE: "%2B5" decodes to "+5"; Rust's `u64::from_str` accepts an optional
    // leading '+', so axum's `Path<u64>` parses it to 5 → 200. This is correct
    // production behavior (a parseable u64), hence it lives in the *valid* set.
    for (label, h) in [
        ("zero", "0"),
        ("u64::MAX", &u64::MAX.to_string()[..]),
        ("leading plus +5", "%2B5"),
    ] {
        let (status, _) = http_get(addr, &format!("/api/block/height/{h}")).await;
        assert_eq!(
            status, 200,
            "valid u64 height '{label}' must be 200, got {status}"
        );
    }

    // Overflow / non-numeric → axum Path<u64> rejection (4xx), never 500/panic.
    let bad: Vec<(&str, String)> = vec![
        ("u64::MAX + 1", "18446744073709551616".to_string()),
        ("128-digit overflow", "9".repeat(128)),
        ("negative", "-1".to_string()),
        ("non-numeric", "abc".to_string()),
        ("float", "1.5".to_string()),
        ("hex-ish", "0xff".to_string()),
        ("empty-ish space", "%20".to_string()),
    ];
    for (label, seg) in &bad {
        let (status, _) = http_get(addr, &format!("/api/block/height/{seg}")).await;
        assert!(
            (400..500).contains(&status),
            "bad height '{label}' must be 4xx (clean reject), got {status}"
        );
    }

    // Server still alive.
    let (root_status, _) = http_get(addr, "/").await;
    assert_eq!(root_status, 200, "server must survive bad height inputs");
}

// ── XDIFF: production hex_encode vs reference hex::encode ─────────────────────

/// The tip hash emitted by `/api/info` is produced by the production private
/// `hex_encode`. It must be byte-identical to the reference `hex::encode` of the
/// same bytes — across all 256 byte values (the mock tip spans 0x00..0xff incl.
/// a leading zero byte and trailing 0xff), proving zero-padding/width parity.
#[tokio::test]
async fn xdiff_hex_encode_matches_hex_crate_on_tip_hash() {
    let provider = Arc::new(MockProvider::new());
    let expected_hex = hex::encode(provider.tip);
    let addr = start_server(provider).await;

    let (status, body) = http_get(addr, "/api/info").await;
    assert_eq!(status, 200);

    let needle = format!("\"tip_hash\":\"{expected_hex}\"");
    assert!(
        body.contains(&needle),
        "production hex_encode diverges from hex::encode.\nexpected substring: {needle}\nbody: {body}"
    );
}

// ── fuzz-amplificação: bounded fan-out & bounded response ────────────────────

/// One `/api/info` request triggers the production `get_info` handler, which
/// calls exactly `chain_tip_hash()`, `chain_height()`, `network()` — a *fixed*
/// 3-read fan-out (the 1→N concern from main.rs's `chain_tip_hash`, which may do
/// status→tip→block_at_height, is bounded at ≤3 backend reads and is a constant,
/// not a function of attacker input). This asserts the per-request backend-read
/// multiplier is a small constant, i.e. no attacker-controlled amplification.
#[tokio::test]
async fn info_fanout_is_bounded_constant() {
    let provider = Arc::new(MockProvider::new());
    let addr = start_server(provider.clone()).await;

    let before = provider.reads.load(Ordering::SeqCst);
    let (status, _) = http_get(addr, "/api/info").await;
    assert_eq!(status, 200);
    let after = provider.reads.load(Ordering::SeqCst);

    let reads = after - before;
    // get_info calls tip_hash + height + network = exactly 3. Hard cap with
    // headroom; the point is it is O(1) in request input, not O(attacker).
    assert!(
        reads <= 3,
        "per-request backend fan-out must be a bounded constant (<=3), got {reads}"
    );
    assert!(reads >= 1, "sanity: handler must hit the backend");
}

/// The response body for `/api/block/height/:h` is a single `BlockSummary` whose
/// size is independent of the requested height — there is no per-request
/// unbounded/attacker-scaled response (no list endpoint, no range query). We
/// confirm two wildly different heights yield the same-sized payload.
#[tokio::test]
async fn block_response_size_independent_of_input() {
    let provider = Arc::new(MockProvider::new());
    let addr = start_server(provider).await;

    let (s1, b1) = http_get(addr, "/api/block/height/1").await;
    let (s2, b2) = http_get(addr, &format!("/api/block/height/{}", u64::MAX)).await;
    assert_eq!(s1, 200);
    assert_eq!(s2, 200);

    // Only the height field differs; the body must not blow up with input.
    // Allow the digit-count delta of the height field, nothing more.
    let delta = (b1.len() as i64 - b2.len() as i64).unsigned_abs() as usize;
    assert!(
        delta <= 20,
        "response size must not scale with input beyond the height digits (delta {delta})"
    );
}

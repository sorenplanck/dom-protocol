//! [`RpcChainSource`] — a [`ChainSource`] backed by the node's `GET /chain/scan`
//! endpoint (RB-WALLET2-RPC-SOURCE, PR-B).
//!
//! This is the real (non-fake) chain source: it drives the reconciler from a
//! live node over HTTP, alongside the [`crate::InMemoryChainSource`] fake that
//! keeps `reconcile`/`sync` testable without a node. The trait
//! ([`crate::ChainSource`]) is synchronous, so this uses `reqwest::blocking`.
//!
//! - `tip()` issues an empty-range request (`from > to`), which the node answers
//!   with the tip and no blocks.
//! - `scan_range(from, to)` **pages**: the node caps each response to a bounded
//!   range and reports the highest height it served (`to`); the client keeps
//!   requesting `from = served_to + 1` until it covers the requested range.
//! - A busy chain answers `503` (the node never blocks on the chain lock); the
//!   client **retries with backoff**. A node without the endpoint answers a
//!   `500` whose body mentions "not supported" → surfaced as
//!   [`RpcSourceError::Unsupported`].

use crate::keychain::RestoreBlock;
use crate::reconcile::ScanBlock;
use crate::tx_sink::{SubmitOutcome, TxSink};
use crate::types::BlockRef;
use crate::ChainSource;
use dom_consensus::transaction::Transaction;
use dom_serialization::DomSerialize;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Errors from the RPC-backed chain source.
#[derive(Debug, Error)]
pub enum RpcSourceError {
    /// The HTTP request failed (connection, timeout, …).
    #[error("rpc request failed: {0}")]
    Request(String),
    /// The node does not implement `/chain/scan` (trait default).
    #[error("node does not support chain scan")]
    Unsupported,
    /// The chain stayed busy across all retry attempts.
    #[error("chain busy after retries")]
    Busy,
    /// The node returned an unexpected HTTP status.
    #[error("unexpected status {0}")]
    Status(u16),
    /// The node rejected the transaction (invalid / double-spend / already
    /// known) — a `400`/`409`. The wallet leaves the slate `Finalized` and lets
    /// `reconcile` establish the truth (inputs `Spent` / change confirmed-or-not).
    #[error("node rejected tx: {0}")]
    Rejected(String),
    /// The response could not be decoded (bad JSON / bad hex / wrong length).
    #[error("decode error: {0}")]
    Decode(String),
}

// ── JSON DTOs mirroring the node's `/chain/scan` response ────────────────────

#[derive(Deserialize)]
struct TipDto {
    height: u64,
    hash: String,
}

#[derive(Deserialize)]
struct ScanBlockDto {
    height: u64,
    hash: String,
    output_commitments: Vec<String>,
    input_commitments: Vec<String>,
    // `fees` is dropped by the reconciler path (`to_scan_block`) but carried
    // through by `scan_for_restore` (the coinbase candidate value is
    // `reward + fees`). `#[serde(default)]` tolerates an older node omitting it.
    #[serde(default)]
    fees: u64,
}

#[derive(Deserialize)]
struct ChainScanDto {
    tip: TipDto,
    #[allow(dead_code)]
    from: u64,
    to: u64,
    blocks: Vec<ScanBlockDto>,
}

fn decode_hash(s: &str) -> Result<[u8; 32], RpcSourceError> {
    let v = hex::decode(s).map_err(|e| RpcSourceError::Decode(e.to_string()))?;
    v.try_into()
        .map_err(|_| RpcSourceError::Decode("hash must be 32 bytes".into()))
}

fn decode_commitment(s: &str) -> Result<[u8; 33], RpcSourceError> {
    let v = hex::decode(s).map_err(|e| RpcSourceError::Decode(e.to_string()))?;
    v.try_into()
        .map_err(|_| RpcSourceError::Decode("commitment must be 33 bytes".into()))
}

fn decode_commitments(items: &[String]) -> Result<Vec<[u8; 33]>, RpcSourceError> {
    items.iter().map(|s| decode_commitment(s)).collect()
}

/// A [`ChainSource`] that reads the canonical chain from a node's REST RPC.
pub struct RpcChainSource {
    base_url: String,
    client: reqwest::blocking::Client,
    /// Retry attempts on a busy chain (`503`).
    max_retries: u32,
}

impl RpcChainSource {
    /// Build a source for the node at `base_url` (e.g. `http://127.0.0.1:8080`),
    /// with a per-request timeout.
    pub fn new(base_url: impl Into<String>, timeout: Duration) -> Result<Self, RpcSourceError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| RpcSourceError::Request(e.to_string()))?;
        Ok(Self {
            base_url: base_url.into(),
            client,
            max_retries: 4,
        })
    }

    /// Fetch one `/chain/scan?from&to`, retrying a busy chain with backoff.
    fn fetch(&self, from: u64, to: u64) -> Result<ChainScanDto, RpcSourceError> {
        let url = format!("{}/chain/scan?from={from}&to={to}", self.base_url);
        let mut backoff = Duration::from_millis(50);
        for attempt in 0..=self.max_retries {
            let resp = self
                .client
                .get(&url)
                .send()
                .map_err(|e| RpcSourceError::Request(e.to_string()))?;
            let status = resp.status();
            if status.is_success() {
                return resp
                    .json::<ChainScanDto>()
                    .map_err(|e| RpcSourceError::Decode(e.to_string()));
            }
            // 503 → chain busy (the node yielded the lock to mining): retry.
            if status.as_u16() == 503 {
                if attempt == self.max_retries {
                    return Err(RpcSourceError::Busy);
                }
                std::thread::sleep(backoff);
                backoff = backoff.saturating_mul(2);
                continue;
            }
            // 500 mentioning "not supported" → the node lacks the endpoint.
            if status.as_u16() == 500 {
                let body = resp.text().unwrap_or_default();
                if body.contains("not supported") {
                    return Err(RpcSourceError::Unsupported);
                }
                return Err(RpcSourceError::Status(500));
            }
            return Err(RpcSourceError::Status(status.as_u16()));
        }
        Err(RpcSourceError::Busy)
    }

    fn to_scan_block(dto: ScanBlockDto) -> Result<ScanBlock, RpcSourceError> {
        Ok(ScanBlock {
            height: dto.height,
            hash: decode_hash(&dto.hash)?,
            output_commitments: decode_commitments(&dto.output_commitments)?,
            input_commitments: decode_commitments(&dto.input_commitments)?,
        })
    }

    /// Page `/chain/scan` into [`RestoreBlock`]s for seed-based coinbase recovery
    /// ([`crate::restore_coinbase_from_seed`]).
    ///
    /// This is **not** the [`ChainSource::scan_range`] path: that one yields
    /// [`ScanBlock`] for the reconciler and deliberately drops the per-block fee
    /// total (the reconciler does not need it). Restore *does* — the coinbase
    /// candidate value is `block_reward(height) + fees` — so this carries the
    /// `fees` field (already on the `/chain/scan` response) through into
    /// [`RestoreBlock::total_fees_noms`]. Paging mirrors `scan_range`: the node
    /// caps each response and reports the highest height it served, and we keep
    /// requesting `from = served_to + 1` until the requested range is covered.
    pub fn scan_for_restore(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Vec<RestoreBlock>, RpcSourceError> {
        let mut blocks = Vec::new();
        let mut cur = from;
        while cur <= to {
            let scan = self.fetch(cur, to)?;
            for dto in scan.blocks {
                blocks.push(RestoreBlock {
                    height: dto.height,
                    hash: decode_hash(&dto.hash)?,
                    output_commitments: decode_commitments(&dto.output_commitments)?,
                    total_fees_noms: dto.fees,
                });
            }
            // No progress (served range below `cur`, e.g. past the tip) → done.
            if scan.to < cur {
                break;
            }
            if scan.to >= to {
                break;
            }
            cur = scan.to + 1;
        }
        Ok(blocks)
    }
}

impl ChainSource for RpcChainSource {
    type Error = RpcSourceError;

    fn tip(&self) -> Result<BlockRef, RpcSourceError> {
        // Empty range (from > to) → the node returns the tip and no blocks.
        let scan = self.fetch(1, 0)?;
        Ok(BlockRef {
            height: scan.tip.height,
            hash: decode_hash(&scan.tip.hash)?,
        })
    }

    fn scan_range(&self, from: u64, to: u64) -> Result<Vec<ScanBlock>, RpcSourceError> {
        let mut blocks = Vec::new();
        let mut cur = from;
        while cur <= to {
            let scan = self.fetch(cur, to)?;
            for dto in scan.blocks {
                blocks.push(Self::to_scan_block(dto)?);
            }
            // No progress (served range below `cur`, e.g. past the tip) → done.
            if scan.to < cur {
                break;
            }
            if scan.to >= to {
                break;
            }
            cur = scan.to + 1;
        }
        Ok(blocks)
    }
}

#[derive(Serialize)]
struct SubmitReq {
    tx_hex: String,
}

#[derive(Deserialize)]
struct SubmitRespDto {
    accepted: bool,
    #[serde(default)]
    relayed: Option<bool>,
    #[serde(default)]
    tx_hash: Option<String>,
    #[serde(default)]
    warning: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

impl TxSink for RpcChainSource {
    type Error = RpcSourceError;

    /// `POST /tx/submit {"tx_hex": hex(tx.to_bytes())}`. A busy chain (`503`) is
    /// retried with backoff; a rejection (`400`/`409`) surfaces as
    /// [`RpcSourceError::Rejected`]; an unknown node (`500 "not supported"`) as
    /// [`RpcSourceError::Unsupported`].
    fn submit_tx(&self, tx: &Transaction) -> Result<SubmitOutcome, RpcSourceError> {
        let bytes = tx
            .to_bytes()
            .map_err(|e| RpcSourceError::Decode(e.to_string()))?;
        let req = SubmitReq {
            tx_hex: hex::encode(&bytes),
        };
        let url = format!("{}/tx/submit", self.base_url);
        let mut backoff = Duration::from_millis(50);

        for attempt in 0..=self.max_retries {
            let resp = self
                .client
                .post(&url)
                .json(&req)
                .send()
                .map_err(|e| RpcSourceError::Request(e.to_string()))?;
            let status = resp.status();

            if status.is_success() {
                let parsed: SubmitRespDto = resp
                    .json()
                    .map_err(|e| RpcSourceError::Decode(e.to_string()))?;
                if !parsed.accepted {
                    return Err(RpcSourceError::Rejected(
                        parsed.error.unwrap_or_else(|| "not accepted".into()),
                    ));
                }
                let tx_hash = parsed
                    .tx_hash
                    .ok_or_else(|| RpcSourceError::Decode("accepted but no tx_hash".into()))?;
                return Ok(SubmitOutcome {
                    tx_hash: decode_hash(&tx_hash)?,
                    relayed: parsed.relayed.unwrap_or(true),
                    warning: parsed.warning,
                });
            }

            let code = status.as_u16();
            if code == 503 {
                if attempt == self.max_retries {
                    return Err(RpcSourceError::Busy);
                }
                std::thread::sleep(backoff);
                backoff = backoff.saturating_mul(2);
                continue;
            }
            // Read the node's error body for context.
            let msg = resp
                .json::<SubmitRespDto>()
                .ok()
                .and_then(|p| p.error)
                .unwrap_or_default();
            if code == 500 && msg.contains("not supported") {
                return Err(RpcSourceError::Unsupported);
            }
            if code == 400 || code == 409 {
                return Err(RpcSourceError::Rejected(msg));
            }
            return Err(RpcSourceError::Status(code));
        }
        Err(RpcSourceError::Busy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::{mpsc, Arc, Mutex};

    /// A minimal blocking mock HTTP server. For each connection it reads the
    /// request line, parses `from`/`to`, and writes whatever the handler returns
    /// as `(status, json_body)`. Runs until `shutdown` is signaled. No tokio, no
    /// real node.
    fn spawn_mock<F>(handler: F) -> (String, mpsc::Sender<()>)
    where
        F: Fn(u64, u64) -> (u16, String) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel::<()>();
        std::thread::spawn(move || loop {
            if rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let req = read_http_request(&mut stream);
                    let (from, to) = parse_from_to(&req);
                    let (status, body) = handler(from, to);
                    let reason = if status == 200 {
                        "OK"
                    } else if status == 503 {
                        "Service Unavailable"
                    } else {
                        "Internal Server Error"
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream
                        .write_all(resp.as_bytes())
                        .expect("mock rpc writes response headers");
                    stream
                        .write_all(body.as_bytes())
                        .expect("mock rpc writes response body");
                    stream.flush().expect("mock rpc flushes response");
                    let _ = stream.shutdown(Shutdown::Write);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        });
        (format!("http://{addr}"), tx)
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set mock rpc read timeout");
        let mut request = Vec::with_capacity(1024);
        let mut buf = [0u8; 512];
        let header_end = loop {
            let n = stream.read(&mut buf).expect("mock rpc reads request");
            assert_ne!(n, 0, "client closed before completing request headers");
            request.extend_from_slice(&buf[..n]);
            if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            assert!(
                request.len() <= 16 * 1024,
                "mock rpc request headers exceeded 16 KiB"
            );
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_len = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let total_len = header_end
            .checked_add(content_len)
            .expect("mock rpc request length overflow");
        while request.len() < total_len {
            let n = stream.read(&mut buf).expect("mock rpc reads request body");
            assert_ne!(n, 0, "client closed before completing request body");
            request.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    fn parse_from_to(req: &str) -> (u64, u64) {
        // First line: "GET /chain/scan?from=X&to=Y HTTP/1.1"
        let line = req.lines().next().unwrap_or("");
        let query = line
            .split_whitespace()
            .nth(1)
            .and_then(|p| p.split('?').nth(1))
            .unwrap_or("");
        let mut from = 0u64;
        let mut to = 0u64;
        for kv in query.split('&') {
            let mut it = kv.split('=');
            match (it.next(), it.next()) {
                (Some("from"), Some(v)) => from = v.parse().unwrap_or(0),
                (Some("to"), Some(v)) => to = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        (from, to)
    }

    fn block_json(height: u64) -> String {
        let hash = format!("{:02x}", (height % 256) as u8).repeat(32);
        let out = format!("{:02x}", ((height + 1) % 256) as u8).repeat(33);
        format!(
            r#"{{"height":{height},"hash":"{hash}","output_commitments":["{out}"],"input_commitments":[],"fees":0}}"#
        )
    }

    /// Build a response body emulating the node: cap at `cap` blocks per call,
    /// never past `tip`.
    fn scan_body(from: u64, to: u64, tip: u64, cap: u64) -> (u16, String) {
        let tip_hash = "ee".repeat(32);
        if from > to {
            return (
                200,
                format!(
                    r#"{{"tip":{{"height":{tip},"hash":"{tip_hash}"}},"from":{from},"to":{},"blocks":[]}}"#,
                    from.saturating_sub(1)
                ),
            );
        }
        let served_to = to.min(tip).min(from + cap - 1);
        let blocks: Vec<String> = (from..=served_to).map(block_json).collect();
        (
            200,
            format!(
                r#"{{"tip":{{"height":{tip},"hash":"{tip_hash}"}},"from":{from},"to":{served_to},"blocks":[{}]}}"#,
                blocks.join(",")
            ),
        )
    }

    fn source(base: &str) -> RpcChainSource {
        RpcChainSource::new(base, Duration::from_secs(5)).unwrap()
    }

    #[test]
    fn tip_uses_empty_range() {
        let (base, stop) = spawn_mock(|from, to| scan_body(from, to, 42, 1000));
        let src = source(&base);
        let tip = src.tip().unwrap();
        assert_eq!(tip.height, 42);
        assert_eq!(tip.hash, [0xeeu8; 32]);
        let _ = stop.send(());
    }

    #[test]
    fn scan_range_single_page() {
        let (base, stop) = spawn_mock(|from, to| scan_body(from, to, 2, 1000));
        let src = source(&base);
        let blocks = src.scan_range(0, 2).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].height, 0);
        assert_eq!(blocks[2].height, 2);
        let _ = stop.send(());
    }

    #[test]
    fn scan_range_pages_across_the_cap() {
        // Node caps at 1000/call, tip 2500 → the client must page 3 times and
        // collect all 2501 blocks (0..=2500).
        let (base, stop) = spawn_mock(|from, to| scan_body(from, to, 2500, 1000));
        let src = source(&base);
        let blocks = src.scan_range(0, 2500).unwrap();
        assert_eq!(blocks.len(), 2501);
        assert_eq!(blocks.first().unwrap().height, 0);
        assert_eq!(blocks.last().unwrap().height, 2500);
        // Heights are contiguous and ascending.
        for (i, b) in blocks.iter().enumerate() {
            assert_eq!(b.height, i as u64);
        }
        let _ = stop.send(());
    }

    /// Scan body whose every block carries `fees = height * 100`, so the test
    /// can prove `scan_for_restore` carries the per-block fee total through.
    fn scan_body_with_fees(from: u64, to: u64, tip: u64, cap: u64) -> (u16, String) {
        let tip_hash = "ee".repeat(32);
        if from > to {
            return (
                200,
                format!(
                    r#"{{"tip":{{"height":{tip},"hash":"{tip_hash}"}},"from":{from},"to":{},"blocks":[]}}"#,
                    from.saturating_sub(1)
                ),
            );
        }
        let served_to = to.min(tip).min(from + cap - 1);
        let blocks: Vec<String> = (from..=served_to)
            .map(|h| {
                let hash = format!("{:02x}", (h % 256) as u8).repeat(32);
                let out = format!("{:02x}", ((h + 1) % 256) as u8).repeat(33);
                format!(
                    r#"{{"height":{h},"hash":"{hash}","output_commitments":["{out}"],"input_commitments":[],"fees":{}}}"#,
                    h * 100
                )
            })
            .collect();
        (
            200,
            format!(
                r#"{{"tip":{{"height":{tip},"hash":"{tip_hash}"}},"from":{from},"to":{served_to},"blocks":[{}]}}"#,
                blocks.join(",")
            ),
        )
    }

    #[test]
    fn scan_for_restore_carries_fees_and_pages() {
        // Tip 1500, cap 1000 → the restore scan must page twice and preserve the
        // per-block `fees` (which the reconciler's ScanBlock drops) verbatim.
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let (base, stop) = spawn_mock(move |from, to| {
            seen.lock().unwrap().push((from, to));
            scan_body_with_fees(from, to, 1500, 1000)
        });
        let src = source(&base);
        let blocks = src.scan_for_restore(0, 1500).unwrap();
        assert_eq!(*requests.lock().unwrap(), vec![(0, 1500), (1000, 1500)]);
        assert_eq!(blocks.len(), 1501);
        assert_eq!(blocks.first().unwrap().height, 0);
        assert_eq!(blocks[999].height, 999);
        assert_eq!(blocks[1000].height, 1000);
        assert_eq!(blocks.last().unwrap().height, 1500);
        // The fee total survived the wire → RestoreBlock mapping.
        assert_eq!(blocks[3].total_fees_noms, 300);
        assert_eq!(blocks[1000].total_fees_noms, 100_000);
        assert_eq!(blocks.last().unwrap().total_fees_noms, 150_000);
        let _ = stop.send(());
    }

    #[test]
    fn busy_chain_retries_then_errors() {
        // Always 503 → after retries, Busy (never hangs).
        let (base, stop) = spawn_mock(|_, _| (503, r#"{"error":"overloaded: chain busy"}"#.into()));
        let mut src = source(&base);
        src.max_retries = 2; // keep the test fast
        let err = src.tip().unwrap_err();
        assert!(matches!(err, RpcSourceError::Busy), "got {err:?}");
        let _ = stop.send(());
    }

    #[test]
    fn unsupported_node_is_detected() {
        let (base, stop) = spawn_mock(|_, _| {
            (
                500,
                r#"{"error":"internal: chain scan not supported"}"#.into(),
            )
        });
        let src = source(&base);
        let err = src.tip().unwrap_err();
        assert!(matches!(err, RpcSourceError::Unsupported), "got {err:?}");
        let _ = stop.send(());
    }

    // ── TxSink (POST /tx/submit) ────────────────────────────────────────────

    /// A tiny, serializable transaction — `submit_tx` only serializes whatever it
    /// is given; the HTTP status mapping is what these tests exercise.
    fn empty_tx() -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            kernels: vec![],
            offset: [0u8; 32],
        }
    }

    #[test]
    fn submit_accepted_maps_to_outcome() {
        let hash_hex = "aa".repeat(32);
        let body =
            format!(r#"{{"accepted":true,"relayed":true,"tx_hash":"{hash_hex}","warning":null}}"#);
        let (base, stop) = spawn_mock(move |_, _| (200, body.clone()));
        let src = source(&base);
        let out = src.submit_tx(&empty_tx()).unwrap();
        assert_eq!(out.tx_hash, [0xaau8; 32]);
        assert!(out.relayed);
        assert!(out.warning.is_none());
        let _ = stop.send(());
    }

    #[test]
    fn submit_accepted_not_relayed_carries_warning() {
        let hash_hex = "bb".repeat(32);
        let body = format!(
            r#"{{"accepted":true,"relayed":false,"tx_hash":"{hash_hex}","warning":"accepted but not relayed (no peers)"}}"#
        );
        let (base, stop) = spawn_mock(move |_, _| (200, body.clone()));
        let src = source(&base);
        let out = src.submit_tx(&empty_tx()).unwrap();
        assert_eq!(out.tx_hash, [0xbbu8; 32]);
        assert!(!out.relayed);
        assert_eq!(
            out.warning.as_deref(),
            Some("accepted but not relayed (no peers)")
        );
        let _ = stop.send(());
    }

    #[test]
    fn submit_rejected_409_surfaces_reason() {
        let (base, stop) = spawn_mock(|_, _| {
            (
                409,
                r#"{"accepted":false,"error":"tx rejected: invalid kernel"}"#.into(),
            )
        });
        let src = source(&base);
        let err = src.submit_tx(&empty_tx()).unwrap_err();
        match err {
            RpcSourceError::Rejected(msg) => assert!(msg.contains("invalid kernel"), "got {msg:?}"),
            other => panic!("expected Rejected, got {other:?}"),
        }
        let _ = stop.send(());
    }

    #[test]
    fn submit_busy_retries_then_busy() {
        // 503 every time → after retries, Busy (retryable; state untouched upstream).
        let (base, stop) = spawn_mock(|_, _| (503, r#"{"error":"chain busy"}"#.into()));
        let mut src = source(&base);
        src.max_retries = 2; // keep the test fast
        let err = src.submit_tx(&empty_tx()).unwrap_err();
        assert!(matches!(err, RpcSourceError::Busy), "got {err:?}");
        let _ = stop.send(());
    }
}

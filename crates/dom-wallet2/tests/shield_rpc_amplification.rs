//! dom-shield — RPC source DoS / amplification probe (hostile node body size).
//!
//! Vector: `RpcChainSource::fetch` does `resp.json::<ChainScanDto>()` with NO
//! explicit response-body size cap. A hostile node (the wallet connects to a
//! node it does not necessarily control) can answer a single `/chain/scan`
//! request with an arbitrarily large body, forcing the wallet to buffer and
//! parse it (memory amplification: one small request -> huge allocation).
//!
//! This probe drives the REAL `RpcChainSource` against a mock node that returns a
//! large, well-formed body and asserts the client completes without panicking
//! (documenting that it DOES buffer the whole body — the resource-limit finding).
//! It deliberately uses a bounded-but-large body so the suite stays fast; the
//! finding is that there is no client-side cap, not that this specific size OOMs.

use dom_wallet2::{ChainSource, RpcChainSource};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

/// Minimal mock node returning a fixed `(status, body)` for any request.
fn spawn_mock(status: u16, body: String) -> (String, mpsc::Sender<()>) {
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
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    });
    (format!("http://{addr}"), tx)
}

#[test]
fn rpc_buffers_large_node_body_without_cap() {
    // A well-formed scan response padded with a large blocks array: thousands of
    // blocks, each a small JSON object. ~ a few MB — proves the client buffers
    // and parses an unbounded body (no client-side size limit).
    let n_blocks = 20_000usize;
    let tip_hash = "ee".repeat(32);
    let mut blocks = String::with_capacity(n_blocks * 160);
    for h in 0..n_blocks {
        if h > 0 {
            blocks.push(',');
        }
        let hash = format!("{:02x}", (h % 256) as u8).repeat(32);
        let out = format!("{:02x}", ((h + 1) % 256) as u8).repeat(33);
        blocks.push_str(&format!(
            r#"{{"height":{h},"hash":"{hash}","output_commitments":["{out}"],"input_commitments":[],"fees":0}}"#
        ));
    }
    let body = format!(
        r#"{{"tip":{{"height":{n},"hash":"{tip_hash}"}},"from":0,"to":{to},"blocks":[{blocks}]}}"#,
        n = n_blocks,
        to = n_blocks - 1
    );
    let approx_mb = body.len() as f64 / 1_048_576.0;

    let (base, stop) = spawn_mock(200, body);
    let src = RpcChainSource::new(&base, Duration::from_secs(30)).unwrap();

    // The client buffers + parses the whole body. It must not panic; that it
    // SUCCEEDS on a multi-MB body from one small request is the amplification
    // finding (no client-side response size cap).
    let res = src.scan_range(0, (n_blocks - 1) as u64);
    let _ = stop.send(());

    assert!(
        res.is_ok(),
        "client failed to parse a large node body (unexpected): {res:?}"
    );
    let blocks = res.unwrap();
    assert_eq!(blocks.len(), n_blocks);
    eprintln!(
        "DOCUMENTED (RPC amplification): RpcChainSource buffered+parsed a \
         {approx_mb:.1} MB body from one request with NO client-side size cap"
    );
}

//! dom-shield — RPC response allocation bound against a hostile node.
//!
//! A node can advertise or stream a response larger than the wallet's fixed
//! allocation budget. The real source must reject it before JSON allocation or
//! parsing rather than buffering attacker-selected data.

use dom_wallet2::{ChainSource, RpcChainSource, RpcSourceError, MAX_RPC_SCAN_RESPONSE_BYTES};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::Duration;

/// Advertise an oversized body without allocating the advertised bytes.
fn spawn_oversized_mock(status: u16, declared_length: usize) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("mock node accepts request");
        read_http_headers(&mut stream);
        let headers = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(headers.as_bytes())
            .expect("mock node writes response headers");
        stream.flush().expect("mock node flushes response");
        stream
            .shutdown(Shutdown::Write)
            .expect("mock node shuts down write half");
    });
    (format!("http://{addr}"), handle)
}

fn read_http_headers(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set mock node read timeout");
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 512];
    loop {
        let read = stream.read(&mut buffer).expect("mock node reads request");
        assert_ne!(read, 0, "client closed before completing request headers");
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return;
        }
        assert!(
            request.len() <= 16 * 1024,
            "mock node request headers exceeded 16 KiB"
        );
    }
}

#[test]
fn rpc_rejects_oversized_node_body_before_buffering() {
    let (base, server) = spawn_oversized_mock(200, MAX_RPC_SCAN_RESPONSE_BYTES.saturating_add(1));
    let source = RpcChainSource::new(&base, Duration::from_secs(30)).unwrap();
    let result = source.scan_range(0, 0);
    server.join().expect("mock node thread exits cleanly");
    assert!(
        matches!(
            result,
            Err(RpcSourceError::ResponseTooLarge {
                limit: MAX_RPC_SCAN_RESPONSE_BYTES
            })
        ),
        "oversized response was not rejected at the fixed boundary: {result:?}"
    );
}

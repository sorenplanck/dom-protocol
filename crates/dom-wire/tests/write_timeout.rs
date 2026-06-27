//! Anti-slowloris write-timeout coverage for [`dom_wire::codec::NoiseCodec`].
//!
//! Audit finding (P2P hardening): P2P writes had no timeout. A peer that
//! deliberately stops reading lets our kernel send buffer fill, after which
//! `write_all` blocks forever and pins the per-peer task. `NoiseCodec::send`
//! now bounds each frame write (`WRITE_TIMEOUT_SECS`, overridable in tests via
//! `DOM_TEST_WRITE_TIMEOUT_SECS`).
//!
//! Runs in its own test binary so the short `DOM_TEST_WRITE_TIMEOUT_SECS`
//! override cannot race the in-crate unit tests' normal-sized sends.

use std::time::Duration;

use dom_core::DomError;
use dom_wire::codec::NoiseCodec;
use dom_wire::handshake::{
    generate_static_keypair, perform_handshake_initiator, perform_handshake_responder,
};
use dom_wire::message::{Command, WireMessage};

const MAGIC: u32 = dom_core::NETWORK_MAGIC_REGTEST;
const CHAIN_ID: [u8; 32] = [0x42u8; 32];

/// Stand up a real Noise_XX session over loopback TCP and wrap both ends in
/// `NoiseCodec`s.
async fn connected_codecs() -> (
    tokio::net::TcpStream,
    NoiseCodec,
    tokio::net::TcpStream,
    NoiseCodec,
) {
    let (ipriv, _) = generate_static_keypair();
    let (rpriv, _) = generate_static_keypair();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let responder = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let t = perform_handshake_responder(&mut s, &rpriv, MAGIC, &CHAIN_ID)
            .await
            .unwrap();
        (s, t)
    });

    let mut istream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let it = perform_handshake_initiator(&mut istream, &ipriv, MAGIC, &CHAIN_ID)
        .await
        .unwrap();
    let (rstream, rt) = responder.await.unwrap();
    (
        istream,
        NoiseCodec::new(it, MAGIC),
        rstream,
        NoiseCodec::new(rt, MAGIC),
    )
}

/// A peer that never reads must NOT pin our write task forever: the per-frame
/// write timeout fires, `send` returns structured write-timeout misbehavior,
/// and other tasks keep running throughout.
#[tokio::test]
async fn write_times_out_against_non_reading_peer() {
    // Both tests in this (isolated) binary set the SAME short value and never
    // remove it: a `remove_var` in one test would race the other's in-flight
    // sends and let them fall back to the 30s production default.
    std::env::set_var("DOM_TEST_WRITE_TIMEOUT_SECS", "1");

    let (a, ca, b, _cb) = connected_codecs().await;
    // `b` is the peer end. We deliberately NEVER read from it and keep it alive
    // (dropping it would close the socket and turn the stall into a connection
    // reset instead of the timeout we are testing).

    // An independent task must keep making progress while the write is stalled —
    // proving the stuck write does not freeze the runtime / other peer tasks.
    let independent = tokio::spawn(async {
        let mut ticks = 0u32;
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            ticks += 1;
        }
        ticks
    });

    // Send near-max (16 MiB) messages until one blocks and the write timeout
    // fires. A single such message already exceeds the combined kernel send
    // buffer + peer recv window on any normal host, so it blocks part-way and
    // times out within ~1s; the small loop is a cross-platform backstop.
    let sender = tokio::spawn(async move {
        let mut a = a;
        let mut ca = ca;
        let big = WireMessage {
            magic: MAGIC,
            command: Command::Block,
            payload: vec![0u8; 16 * 1024 * 1024],
        };
        for _ in 0..8 {
            if let Err(e) = ca.send(&mut a, &big).await {
                return Some(e);
            }
        }
        None
    });

    assert_eq!(
        independent.await.unwrap(),
        5,
        "an independent task must progress while the write is stalled"
    );

    // Bound the wait so a regression (no timeout) fails the test instead of
    // hanging CI forever.
    let result = tokio::time::timeout(Duration::from_secs(30), sender)
        .await
        .expect("send task must finish via write timeout, not hang")
        .unwrap();

    let err = result.expect("a send against a non-reading peer must time out");
    assert!(
        matches!(
            &err,
            DomError::PeerMisbehavior {
                kind: dom_core::PeerMisbehavior::WriteTimeout,
                ..
            }
        ),
        "expected a structured write-timeout misbehavior, got: {err:?}"
    );

    drop(b); // keep the non-reading peer alive until the assertions are done
}

/// A well-behaved peer that drains the socket is never affected by the write
/// timeout, even when it is configured very short.
#[tokio::test]
async fn normal_write_unaffected_when_peer_drains() {
    std::env::set_var("DOM_TEST_WRITE_TIMEOUT_SECS", "1");

    let (mut a, mut ca, mut b, mut cb) = connected_codecs().await;

    const COUNT: usize = 8;
    let reader = tokio::spawn(async move {
        for _ in 0..COUNT {
            cb.recv(&mut b).await.expect("recv ok");
        }
    });

    let msg = WireMessage {
        magic: MAGIC,
        command: Command::Tx,
        payload: vec![0xCDu8; 4096],
    };
    for i in 0..COUNT {
        ca.send(&mut a, &msg)
            .await
            .unwrap_or_else(|e| panic!("normal send #{i} must succeed, got: {e:?}"));
    }

    reader.await.unwrap();
}

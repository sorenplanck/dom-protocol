//! Noise_XX_25519_ChaChaPoly_BLAKE2s handshake with chain_id prologue binding.
//!
//! RFC-0005: transport is Noise_XX.
//! RFC-0009 Section 4.3: chain_id bound to Noise prologue.
//!
//! Prologue = `DOM` || protocol version (4-byte LE) || network magic (4-byte LE) || chain ID (32 bytes)
//!
//! Any MITM modification to the prologue causes MAC failure — detected cryptographically.

use dom_core::{DomError, PeerMisbehavior, WIRE_PROTOCOL_VERSION};
use snow::{Builder, HandshakeState, TransportState};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum Noise message size.
pub const NOISE_MAX_MSG: usize = 65535;

/// Timeout for completing the Noise handshake (3 messages).
/// If not completed within this time, connection is dropped.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Runtime handshake timeout.
///
/// Production keeps using [`HANDSHAKE_TIMEOUT_SECS`]. Integration tests can
/// set `DOM_TEST_HANDSHAKE_TIMEOUT_SECS` to shorten wall-clock waits without
/// changing production defaults.
pub fn handshake_timeout_secs() -> u64 {
    std::env::var("DOM_TEST_HANDSHAKE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(HANDSHAKE_TIMEOUT_SECS)
}

/// Idle timeout for established connections.
/// Peers that send no messages for this long are disconnected.
pub const IDLE_TIMEOUT_SECS: u64 = 60;

/// Idle timeout used while an established connection is actively serving IBD.
///
/// IBD block bodies can be large and validation can be CPU intensive.  The
/// normal one-minute liveness policy is appropriate for an idle relay session,
/// but is too aggressive for a request/validate/request synchronization loop.
/// This only changes local connection scheduling; it does not affect the wire
/// protocol or any consensus rule.
pub const IBD_IDLE_TIMEOUT_SECS: u64 = 5 * 60;

/// Per-frame write timeout for established connections.
///
/// Anti-slowloris: a peer that deliberately stops reading lets our kernel send
/// buffer fill, after which `write_all` blocks forever and pins the per-peer
/// task (and any broadcast — relay/fluff/stem — that awaits it). Bounding each
/// frame write disconnects such a peer instead of hanging. Chosen between the
/// read idle timeout (60s) and the handshake timeout (10s): generous enough for
/// any honest, congested-but-draining link, short enough to bound the stall.
pub const WRITE_TIMEOUT_SECS: u64 = 30;

/// Runtime write timeout.
///
/// Production keeps using [`WRITE_TIMEOUT_SECS`]. Tests can set
/// `DOM_TEST_WRITE_TIMEOUT_SECS` to shorten wall-clock waits without changing
/// production defaults (mirrors [`handshake_timeout_secs`]).
pub fn write_timeout_secs() -> u64 {
    std::env::var("DOM_TEST_WRITE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(WRITE_TIMEOUT_SECS)
}

/// Prologue versions this build can speak, most preferred first.
///
/// A Noise prologue is NOT negotiated: it is mixed into the handshake hash, so
/// two peers that derive different bytes fail AEAD verification and never
/// complete. Raising `WIRE_PROTOCOL_VERSION` alone would therefore partition
/// the network instantly rather than degrade gracefully — every v3 node would
/// be unable to reach every v2 node.
///
/// Strategy B (spec A1): the initiator tries each version in order and
/// reconnects on failure, and the responder accepts any of them. The cost is
/// one extra connection per cross-version pair, once; peer connections are
/// long-lived, so it is cheap. The benefit is that a canary rollout becomes
/// possible at all.
///
/// Ordering is significant: the newest version must come first so that two
/// upgraded nodes settle on it immediately and never pay the retry.
pub const SUPPORTED_PROLOGUE_VERSIONS: &[u32] = &[3, 2];

/// Marker the responder embeds in its message-3 read failure when the peer
/// hung up after being sent message 2.
///
/// In Noise_XX the initiator is the first side able to detect a prologue
/// mismatch: message 2 carries the responder's static key under an AEAD whose
/// hash includes the prologue, so the initiator fails there and closes —
/// message 3 is never written. The responder therefore never observes the
/// "msg3 decrypt" failure the evidence rule was originally written around; it
/// observes an EOF. This marker records the one thing that EOF does prove:
/// the peer spoke real Noise up to message 2 and then gave up.
///
/// It rides on a `DomError::Internal`, which the node's scoring rules exempt
/// from ban points — an aborted cross-version handshake is expected traffic,
/// not misbehaviour.
pub const RESPONDER_ABORTED_AFTER_MSG2: &str = "peer closed after msg2";

/// Whether a handshake failure is evidence of a prologue version mismatch.
///
/// Two shapes qualify, and only these two:
///
/// - an AEAD failure on a MAC-carrying message (msg2 for the initiator, msg3
///   for the responder): both sides ran real Noise and their transcripts
///   diverged;
/// - the responder being hung up on straight after it wrote msg2
///   ([`RESPONDER_ABORTED_AFTER_MSG2`]): the initiator got far enough to read
///   msg2 and bailed, which is what a prologue mismatch looks like from this
///   end.
///
/// Everything else — an EOF before msg1, timeouts, connection resets — is a
/// peer that went away or never spoke Noise at all, and MUST NOT demote
/// version memory: a readiness probe, a port scanner, or a monitoring health
/// check that connects and closes would otherwise walk every real peer at
/// that IP down to the oldest version (the exact failure a poisoned-memory
/// test caught). Reaching the marker costs a well-formed message 1, so a bare
/// connect-and-close still proves nothing.
pub fn is_prologue_mismatch(err: &DomError) -> bool {
    match err {
        DomError::Invalid(msg) => {
            (msg.contains("noise read msg2") || msg.contains("noise read msg3"))
                && msg.contains("decrypt")
        }
        // The abort keeps the non-punishable `Internal` kind it has always had;
        // only the marker distinguishes it from an ordinary framing failure.
        DomError::Internal(msg) => msg.contains(RESPONDER_ABORTED_AFTER_MSG2),
        _ => false,
    }
}

/// Build the Noise prologue that binds chain_id to the transport.
///
/// RFC-0009: prologue = `DOM` || `u32_le(WIRE_PROTOCOL_VERSION)` || `u32_le(NETWORK_MAGIC)` || chain ID (32 bytes).
pub fn build_prologue(network_magic: u32, chain_id: &[u8; 32]) -> Vec<u8> {
    build_prologue_versioned(WIRE_PROTOCOL_VERSION, network_magic, chain_id)
}

/// Build the Noise prologue for an explicit protocol version.
///
/// Same layout as [`build_prologue`], with the version supplied by the caller
/// instead of taken from the compile-time constant. This is what makes a
/// version-tolerant handshake possible: the wire bytes for a given version stay
/// fixed forever, independent of which version this build prefers.
pub fn build_prologue_versioned(version: u32, network_magic: u32, chain_id: &[u8; 32]) -> Vec<u8> {
    let mut prologue = Vec::with_capacity(3 + 4 + 4 + 32);
    prologue.extend_from_slice(b"DOM");
    prologue.extend_from_slice(&version.to_le_bytes());
    prologue.extend_from_slice(&network_magic.to_le_bytes());
    prologue.extend_from_slice(chain_id);
    prologue
}

/// Build a Noise_XX initiator (outbound connection).
pub fn build_initiator(
    static_privkey: &[u8; 32],
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<HandshakeState, DomError> {
    build_initiator_versioned(
        static_privkey,
        WIRE_PROTOCOL_VERSION,
        network_magic,
        chain_id,
    )
}

/// Build a Noise_XX initiator pinned to an explicit prologue version.
pub fn build_initiator_versioned(
    static_privkey: &[u8; 32],
    version: u32,
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<HandshakeState, DomError> {
    let prologue = build_prologue_versioned(version, network_magic, chain_id);
    Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(static_privkey)
        .prologue(&prologue)
        .build_initiator()
        .map_err(|e| DomError::Internal(format!("noise initiator build: {e}")))
}

/// Build a Noise_XX responder (inbound connection).
pub fn build_responder(
    static_privkey: &[u8; 32],
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<HandshakeState, DomError> {
    build_responder_versioned(
        static_privkey,
        WIRE_PROTOCOL_VERSION,
        network_magic,
        chain_id,
    )
}

/// Build a Noise_XX responder pinned to an explicit prologue version.
pub fn build_responder_versioned(
    static_privkey: &[u8; 32],
    version: u32,
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<HandshakeState, DomError> {
    let prologue = build_prologue_versioned(version, network_magic, chain_id);
    Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(static_privkey)
        .prologue(&prologue)
        .build_responder()
        .map_err(|e| DomError::Internal(format!("noise responder build: {e}")))
}

/// Generate a new Noise static keypair for this node.
pub fn generate_static_keypair() -> ([u8; 32], [u8; 32]) {
    use rand::RngCore;
    let mut privkey = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut privkey);
    clamp_static_privkey(&mut privkey);
    let public = derive_static_pubkey(&privkey);
    (privkey, public)
}

/// Clamp a Noise static private key for X25519 use.
pub fn clamp_static_privkey(privkey: &mut [u8; 32]) {
    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;
}

/// Derive the public X25519 key for a clamped Noise static private key.
pub fn derive_static_pubkey(static_privkey: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*static_privkey);
    let public = x25519_dalek::PublicKey::from(&secret);
    *public.as_bytes()
}

/// Complete the Noise_XX handshake (3 messages: -> e, <- e, ee, s, es, -> s, se).
/// Returns the TransportState for subsequent encrypted communication.
/// Perform Noise_XX handshake as initiator with timeout.
///
/// AUDIT FIX: Wrapped entire handshake in timeout to prevent Slowloris.
/// Without timeout, adversary can hold 125 connections in partial handshake
/// indefinitely, exhausting all inbound slots.
pub async fn perform_handshake_initiator(
    stream: &mut tokio::net::TcpStream,
    static_privkey: &[u8; 32],
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<TransportState, DomError> {
    perform_handshake_initiator_versioned(
        stream,
        static_privkey,
        WIRE_PROTOCOL_VERSION,
        network_magic,
        chain_id,
    )
    .await
}

/// Perform the initiator handshake pinned to one prologue version.
///
/// A failed prologue cannot be retried on the same TCP connection: the Noise
/// state is poisoned and the peer has already seen bytes it could not
/// authenticate. The caller therefore drives the fallback by reconnecting —
/// see the dial loop in `dom-node`, which walks
/// [`SUPPORTED_PROLOGUE_VERSIONS`].
pub async fn perform_handshake_initiator_versioned(
    stream: &mut tokio::net::TcpStream,
    static_privkey: &[u8; 32],
    version: u32,
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<TransportState, DomError> {
    let timeout_secs = handshake_timeout_secs();
    tokio::time::timeout(
        tokio::time::Duration::from_secs(timeout_secs),
        perform_handshake_initiator_inner(stream, static_privkey, version, network_magic, chain_id),
    )
    .await
    .map_err(|_| {
        DomError::peer_misbehavior(
            PeerMisbehavior::HandshakeTimeout,
            format!("handshake timeout after {timeout_secs}s"),
        )
    })?
}

async fn perform_handshake_initiator_inner(
    stream: &mut tokio::net::TcpStream,
    static_privkey: &[u8; 32],
    version: u32,
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<TransportState, DomError> {
    let mut hs = build_initiator_versioned(static_privkey, version, network_magic, chain_id)?;
    let mut buf = vec![0u8; NOISE_MAX_MSG];

    // -> e  (message 1)
    let len = hs
        .write_message(&[], &mut buf)
        .map_err(|e| DomError::Internal(format!("noise write msg1: {e}")))?;
    write_framed(stream, &buf[..len]).await?;

    // <- e, ee, s, es  (message 2)
    let msg2 = read_framed(stream).await?;
    let mut payload = vec![0u8; NOISE_MAX_MSG];
    hs.read_message(&msg2, &mut payload)
        .map_err(|e| DomError::Invalid(format!("noise read msg2: {e}")))?;

    // -> s, se  (message 3)
    let len = hs
        .write_message(&[], &mut buf)
        .map_err(|e| DomError::Internal(format!("noise write msg3: {e}")))?;
    write_framed(stream, &buf[..len]).await?;

    hs.into_transport_mode()
        .map_err(|e| DomError::Internal(format!("noise transport mode: {e}")))
}

/// Complete handshake as responder.
pub async fn perform_handshake_responder(
    stream: &mut tokio::net::TcpStream,
    static_privkey: &[u8; 32],
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<TransportState, DomError> {
    perform_handshake_responder_versioned(
        stream,
        static_privkey,
        WIRE_PROTOCOL_VERSION,
        network_magic,
        chain_id,
    )
    .await
}

/// Perform the responder handshake pinned to one prologue version.
///
/// The responder cannot probe: the version has to be chosen before anything is
/// known about the initiator. A mismatch surfaces here as the initiator
/// hanging up right after msg2 (it detects the divergence first, when
/// decrypting msg2), reported as an `Internal` error carrying
/// [`RESPONDER_ABORTED_AFTER_MSG2`]. The caller supplies the version from
/// per-peer memory and treats that failure as the signal to lead with the next
/// older version when this peer reconnects — which the existing dial loops
/// already do on their own.
pub async fn perform_handshake_responder_versioned(
    stream: &mut tokio::net::TcpStream,
    static_privkey: &[u8; 32],
    version: u32,
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<TransportState, DomError> {
    let timeout_secs = handshake_timeout_secs();
    tokio::time::timeout(
        tokio::time::Duration::from_secs(timeout_secs),
        perform_handshake_responder_inner(stream, static_privkey, version, network_magic, chain_id),
    )
    .await
    .map_err(|_| {
        DomError::peer_misbehavior(
            PeerMisbehavior::HandshakeTimeout,
            format!("handshake timeout after {timeout_secs}s"),
        )
    })?
}

async fn perform_handshake_responder_inner(
    stream: &mut tokio::net::TcpStream,
    static_privkey: &[u8; 32],
    version: u32,
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<TransportState, DomError> {
    let mut hs = build_responder_versioned(static_privkey, version, network_magic, chain_id)?;
    let mut buf = vec![0u8; NOISE_MAX_MSG];

    // <- e  (message 1)
    let msg1 = read_framed(stream).await?;
    let mut payload = vec![0u8; NOISE_MAX_MSG];
    hs.read_message(&msg1, &mut payload)
        .map_err(|e| DomError::Invalid(format!("noise read msg1: {e}")))?;

    // -> e, ee, s, es  (message 2)
    let len = hs
        .write_message(&[], &mut buf)
        .map_err(|e| DomError::Internal(format!("noise write msg2: {e}")))?;
    write_framed(stream, &buf[..len]).await?;

    // <- s, se  (message 3)
    //
    // A peer that read msg2 and then closed is the responder-side signature of
    // a prologue mismatch (see `RESPONDER_ABORTED_AFTER_MSG2`), so the failure
    // is tagged rather than surfacing as a bare framing error. Everything
    // needed for that inference already happened: msg1 parsed, msg2 went out.
    //
    // Deliberately still an `Internal` error: an abort is not misbehaviour, and
    // the node's scoring rules give `Internal` no ban points. Tagging it as
    // `Invalid` would make every cross-version peer accrue violations for
    // doing exactly what the protocol forces it to do.
    //
    // Only the I/O shape (`Internal` — the peer hung up or the read timed out)
    // is tagged. Every other failure kind keeps its original classification:
    // a peer that follows msg2 with an oversized frame is `Malformed` and must
    // stay punishable — laundering it into the abort marker would both waive
    // its ban points and demote this IP's version memory on garbage.
    let msg3 = read_framed(stream).await.map_err(|e| match e {
        DomError::Internal(io) => DomError::Internal(format!(
            "noise read msg3: {RESPONDER_ABORTED_AFTER_MSG2}: {io}"
        )),
        other => other,
    })?;
    hs.read_message(&msg3, &mut payload)
        .map_err(|e| DomError::Invalid(format!("noise read msg3: {e}")))?;

    hs.into_transport_mode()
        .map_err(|e| DomError::Internal(format!("noise transport mode: {e}")))
}

/// Write a length-prefixed frame: u32_le(len) || data.
pub async fn write_framed(stream: &mut tokio::net::TcpStream, data: &[u8]) -> Result<(), DomError> {
    use tokio::io::AsyncWriteExt;
    let len = (data.len() as u32).to_le_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| DomError::Internal(format!("write frame len: {e}")))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| DomError::Internal(format!("write frame data: {e}")))?;
    Ok(())
}

/// Read a length-prefixed frame.
pub async fn read_framed(stream: &mut tokio::net::TcpStream) -> Result<Vec<u8>, DomError> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| DomError::Internal(format!("read frame len: {e}")))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > NOISE_MAX_MSG {
        return Err(DomError::Malformed(format!("frame too large: {len}")));
    }
    let mut data = vec![0u8; len];
    stream
        .read_exact(&mut data)
        .await
        .map_err(|e| DomError::Internal(format!("read frame data: {e}")))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prologue_is_deterministic() {
        let chain_id = [0xABu8; 32];
        let p1 = build_prologue(dom_core::NETWORK_MAGIC_MAINNET, &chain_id);
        let p2 = build_prologue(dom_core::NETWORK_MAGIC_MAINNET, &chain_id);
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_chain_id_different_prologue() {
        let p1 = build_prologue(dom_core::NETWORK_MAGIC_MAINNET, &[0u8; 32]);
        let p2 = build_prologue(dom_core::NETWORK_MAGIC_MAINNET, &[1u8; 32]);
        assert_ne!(p1, p2);
    }

    #[test]
    fn mainnet_testnet_different_prologue() {
        let chain_id = [0u8; 32];
        let p1 = build_prologue(dom_core::NETWORK_MAGIC_MAINNET, &chain_id);
        let p2 = build_prologue(dom_core::NETWORK_MAGIC_TESTNET, &chain_id);
        assert_ne!(p1, p2, "different networks must have different prologues");
    }

    #[test]
    fn prologue_contains_dom_prefix() {
        let p = build_prologue(dom_core::NETWORK_MAGIC_MAINNET, &[0u8; 32]);
        assert_eq!(&p[0..3], b"DOM");
    }

    // §7, A1 — the version-tolerant prologue. WITHOUT THESE, THE NETWORK
    // PARTITIONS on the next version bump.

    /// The poisoned-memory regression: a visitor that connects and closes
    /// (readiness probe, scanner, health check) produces IO-class errors,
    /// never AEAD ones — and must not count as version evidence.
    #[test]
    fn only_aead_transcript_failures_count_as_prologue_mismatch() {
        assert!(is_prologue_mismatch(&DomError::Invalid(
            "noise read msg2: decrypt error".into()
        )));
        assert!(is_prologue_mismatch(&DomError::Invalid(
            "noise read msg3: decrypt error".into()
        )));
        assert!(!is_prologue_mismatch(&DomError::Internal(
            "read frame len: early eof".into()
        )));
        assert!(!is_prologue_mismatch(&DomError::Invalid(
            "noise read msg1: invalid input".into()
        )));
        assert!(!is_prologue_mismatch(&DomError::peer_misbehavior(
            PeerMisbehavior::HandshakeTimeout,
            "handshake timeout after 10s",
        )));
    }

    #[test]
    fn prologue_differs_between_versions() {
        let chain_id = [0xABu8; 32];
        assert_ne!(
            build_prologue_versioned(2, dom_core::NETWORK_MAGIC_MAINNET, &chain_id),
            build_prologue_versioned(3, dom_core::NETWORK_MAGIC_MAINNET, &chain_id),
        );
    }

    #[test]
    fn versioned_prologue_matches_legacy_v2_bytes_exactly() {
        // The v2 bytes must stay what deployed v2 nodes derive today: any
        // difference and this build cannot ever complete a handshake with
        // them, whatever the retry logic does.
        let chain_id = [0x5Au8; 32];
        let mut expected = Vec::new();
        expected.extend_from_slice(b"DOM");
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&dom_core::NETWORK_MAGIC_MAINNET.to_le_bytes());
        expected.extend_from_slice(&chain_id);
        assert_eq!(
            build_prologue_versioned(2, dom_core::NETWORK_MAGIC_MAINNET, &chain_id),
            expected
        );
    }

    #[test]
    fn supported_versions_lead_with_the_newest() {
        assert_eq!(SUPPORTED_PROLOGUE_VERSIONS[0], WIRE_PROTOCOL_VERSION);
        assert!(
            SUPPORTED_PROLOGUE_VERSIONS.windows(2).all(|w| w[0] > w[1]),
            "fallback must walk strictly downwards"
        );
        assert!(
            SUPPORTED_PROLOGUE_VERSIONS.contains(&2),
            "dropping v2 support is a flag day, not a code cleanup"
        );
    }

    /// §7: `v3_node_completes_noise_handshake_with_v2_node`.
    ///
    /// A v3 initiator reaching a v2-only responder: the first attempt fails on
    /// AEAD, and the reconnect with the v2 prologue completes. Modelled
    /// end-to-end over loopback TCP with a fresh connection per attempt,
    /// exactly as the dial loop reconnects — a failed prologue poisons the
    /// Noise state, so retrying on the same socket is not a thing.
    #[tokio::test]
    async fn v3_node_completes_noise_handshake_with_v2_node() {
        let (ipriv, _) = generate_static_keypair();
        let (rpriv, _) = generate_static_keypair();
        let magic = dom_core::NETWORK_MAGIC_REGTEST;
        let chain_id = [0x42u8; 32];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // A v2 node: always the v2 prologue, no tolerance, accepts two
        // connections (the failed cross-version attempt, then the retry).
        let responder = tokio::spawn(async move {
            let mut completed = None;
            for _ in 0..2 {
                let (mut s, _) = listener.accept().await.unwrap();
                if let Ok(t) =
                    perform_handshake_responder_versioned(&mut s, &rpriv, 2, magic, &chain_id).await
                {
                    completed = Some(t);
                    break;
                }
            }
            completed.expect("v2 responder never completed a handshake")
        });

        // The v3 initiator walks SUPPORTED_PROLOGUE_VERSIONS with a fresh
        // connection per version, as connect_outbound does.
        let mut transport = None;
        for version in SUPPORTED_PROLOGUE_VERSIONS {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            match perform_handshake_initiator_versioned(&mut s, &ipriv, *version, magic, &chain_id)
                .await
            {
                Ok(t) => {
                    assert_eq!(*version, 2, "settled version must be the peer's");
                    transport = Some(t);
                    break;
                }
                Err(_) => continue,
            }
        }
        assert!(
            transport.is_some(),
            "v3 initiator never reached the v2 node"
        );
        responder.await.unwrap();
    }

    /// §7: `v2_node_completes_noise_handshake_with_v3_node`.
    ///
    /// The inverse direction, and the one initiator retries cannot rescue: a
    /// v2 initiator has no fallback logic at all. What saves it is that a v2
    /// dial loop treats a failed handshake as retryable and redials, while the
    /// v3 responder demotes its per-peer version after the failure — so the
    /// second attempt meets a v2 prologue. Modelled with the responder walking
    /// its versions across two accepted connections.
    #[tokio::test]
    async fn v2_node_completes_noise_handshake_with_v3_node() {
        let (ipriv, _) = generate_static_keypair();
        let (rpriv, _) = generate_static_keypair();
        let magic = dom_core::NETWORK_MAGIC_REGTEST;
        let chain_id = [0x42u8; 32];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // A v3 node accepting: leads with v3, and after the expected failure
        // answers the reconnect with v2 (ProloguePreferences::demote_after_failure
        // is what drives this walk in dom-node).
        let responder = tokio::spawn(async move {
            let mut completed = None;
            for version in SUPPORTED_PROLOGUE_VERSIONS {
                let (mut s, _) = listener.accept().await.unwrap();
                match perform_handshake_responder_versioned(
                    &mut s, &rpriv, *version, magic, &chain_id,
                )
                .await
                {
                    Ok(t) => {
                        assert_eq!(*version, 2, "settled version must be the initiator's");
                        completed = Some(t);
                        break;
                    }
                    Err(_) => continue,
                }
            }
            completed.expect("v3 responder never completed with the v2 initiator")
        });

        // A v2 node dialing: always the v2 prologue; redials once after the
        // failure, as its dial loop does for any retryable failure.
        let mut transport = None;
        for _ in 0..2 {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            if let Ok(t) =
                perform_handshake_initiator_versioned(&mut s, &ipriv, 2, magic, &chain_id).await
            {
                transport = Some(t);
                break;
            }
        }
        assert!(
            transport.is_some(),
            "v2 initiator never reached the v3 node"
        );
        responder.await.unwrap();
    }

    /// Regression for the 2026-09-08 inbound outage.
    ///
    /// The test above walks the responder through its versions by hand, so it
    /// passed while production could not: what decides the walk in dom-node is
    /// `is_prologue_mismatch` applied to the error the responder actually
    /// gets. A v2 initiator fails when it decrypts msg2 and hangs up without
    /// writing msg3, so the responder never sees an AEAD failure — it sees an
    /// EOF. Unless that EOF is evidence, per-peer memory never demotes and no
    /// cross-version peer can ever connect inbound.
    #[tokio::test]
    async fn responder_reads_an_abort_after_msg2_as_prologue_evidence() {
        let (ipriv, _) = generate_static_keypair();
        let (rpriv, _) = generate_static_keypair();
        let magic = dom_core::NETWORK_MAGIC_REGTEST;
        let chain_id = [0x42u8; 32];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            perform_handshake_responder_versioned(&mut s, &rpriv, 3, magic, &chain_id).await
        });

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let initiator_err =
            perform_handshake_initiator_versioned(&mut s, &ipriv, 2, magic, &chain_id)
                .await
                .expect_err("a v2 initiator cannot complete against a v3 responder");
        assert!(
            is_prologue_mismatch(&initiator_err),
            "initiator side lost its evidence: {initiator_err:?}"
        );
        drop(s);

        let responder_err = responder
            .await
            .unwrap()
            .expect_err("the responder cannot complete either");
        assert!(
            is_prologue_mismatch(&responder_err),
            "responder must treat the abort as version evidence, got: {responder_err:?}"
        );
        // The kind matters as much as the marker: dom-node exempts `Internal`
        // from ban points, so promoting this to `Invalid` would fine the other
        // hub +10 every time it probes and drags it towards a ban.
        assert!(
            matches!(responder_err, DomError::Internal(_)),
            "an aborted cross-version handshake must stay unpunishable, got: {responder_err:?}"
        );
    }

    /// The other half of the rule: reaching the marker costs a well-formed
    /// message 1, so a readiness probe or port scanner that connects and
    /// closes still proves nothing and cannot walk an IP's version memory down.
    #[tokio::test]
    async fn a_connect_and_close_probe_is_not_prologue_evidence() {
        let (rpriv, _) = generate_static_keypair();
        let magic = dom_core::NETWORK_MAGIC_REGTEST;
        let chain_id = [0x42u8; 32];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            perform_handshake_responder_versioned(&mut s, &rpriv, 3, magic, &chain_id).await
        });

        drop(tokio::net::TcpStream::connect(addr).await.unwrap());

        let err = responder
            .await
            .unwrap()
            .expect_err("a probe that sends nothing cannot complete");
        assert!(
            !is_prologue_mismatch(&err),
            "a probe that never spoke Noise must not demote anything, got: {err:?}"
        );
    }

    /// The abort marker must only tag the I/O shape of the msg3 read. A peer
    /// that follows msg2 with an oversized frame is `Malformed`, and has to
    /// stay that way: laundering it into the marker would both waive its ban
    /// points and demote the IP's version memory on garbage.
    #[tokio::test]
    async fn an_oversized_frame_after_msg2_stays_malformed_and_is_not_evidence() {
        let (ipriv, _) = generate_static_keypair();
        let (rpriv, _) = generate_static_keypair();
        let magic = dom_core::NETWORK_MAGIC_REGTEST;
        let chain_id = [0x42u8; 32];

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            perform_handshake_responder_versioned(&mut s, &rpriv, 3, magic, &chain_id).await
        });

        // Real Noise up to msg2, same prologue version — then garbage.
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut hs = build_initiator_versioned(&ipriv, 3, magic, &chain_id).unwrap();
        let mut buf = vec![0u8; NOISE_MAX_MSG];
        let len = hs.write_message(&[], &mut buf).unwrap();
        write_framed(&mut s, &buf[..len]).await.unwrap();
        let _msg2 = read_framed(&mut s).await.unwrap();
        let oversized = ((NOISE_MAX_MSG + 1) as u32).to_le_bytes();
        {
            use tokio::io::AsyncWriteExt;
            s.write_all(&oversized).await.unwrap();
        }

        let err = responder
            .await
            .unwrap()
            .expect_err("an oversized msg3 frame cannot complete");
        assert!(
            matches!(err, DomError::Malformed(_)),
            "an oversized frame must keep its punishable kind, got: {err:?}"
        );
        assert!(
            !is_prologue_mismatch(&err),
            "a framing violation must not demote version memory, got: {err:?}"
        );
    }

    /// §7: `v3_node_accepts_v2_handshake_and_vice_versa` — the degenerate
    /// same-version cases must keep working on both prologue values.
    #[tokio::test]
    async fn same_version_handshakes_complete_on_both_prologues() {
        for version in SUPPORTED_PROLOGUE_VERSIONS {
            let version = *version;
            let (ipriv, _) = generate_static_keypair();
            let (rpriv, _) = generate_static_keypair();
            let magic = dom_core::NETWORK_MAGIC_REGTEST;
            let chain_id = [0x42u8; 32];

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let responder = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                perform_handshake_responder_versioned(&mut s, &rpriv, version, magic, &chain_id)
                    .await
                    .unwrap()
            });
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            perform_handshake_initiator_versioned(&mut s, &ipriv, version, magic, &chain_id)
                .await
                .unwrap_or_else(|e| panic!("v{version} <-> v{version} failed: {e}"));
            responder.await.unwrap();
        }
    }

    #[test]
    fn generate_keypair_produces_different_keys() {
        let (priv1, pub1) = generate_static_keypair();
        let (priv2, pub2) = generate_static_keypair();
        assert_ne!(priv1, priv2);
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn derive_static_pubkey_is_stable_for_same_private_key() {
        let mut privkey = [7u8; 32];
        clamp_static_privkey(&mut privkey);
        let pub1 = derive_static_pubkey(&privkey);
        let pub2 = derive_static_pubkey(&privkey);
        assert_eq!(pub1, pub2);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cancel-safe framed read (added to fix tokio::select! cancellation bug).
//
// `read_framed` performs two `read_exact` calls (length, then data). When used
// inside `tokio::select!`, if the future is cancelled between those reads,
// bytes already consumed from the socket are lost from the application's view,
// but the socket position has advanced — desynchronizing the framing. The next
// `read_framed` would read payload bytes as a length prefix and produce
// "frame too large" errors.
//
// `ReadState` holds partial-read progress so the operation can be safely
// resumed after cancellation.
// ─────────────────────────────────────────────────────────────────────────────

/// Resumable state for length-prefixed reads.
///
/// `Default` is `Idle`. Pass `&mut ReadState` to `read_framed_cancel_safe` so
/// that any partial progress survives `tokio::select!` cancellation.
#[derive(Debug, Default)]
pub enum ReadState {
    /// No read in progress.
    #[default]
    Idle,
    /// Reading the 4-byte length prefix.
    ReadingLen {
        /// Length-prefix bytes buffer (4 bytes).
        buf: [u8; 4],
        /// Number of bytes filled so far (0..=4).
        filled: usize,
    },
    /// Reading the payload of known length.
    ReadingData {
        /// Payload buffer pre-allocated to the announced length.
        buf: Vec<u8>,
        /// Number of bytes filled so far (0..=buf.len()).
        filled: usize,
    },
}

/// Read a length-prefixed frame, resumable across cancellation.
///
/// Unlike `read_framed`, this function persists partial progress in `state` so
/// it is safe to use inside `tokio::select!`. On any return path (Ok, Err,
/// or future cancellation), `state` reflects exactly what has been consumed
/// from the socket.
pub async fn read_framed_cancel_safe(
    stream: &mut tokio::net::TcpStream,
    state: &mut ReadState,
) -> Result<Vec<u8>, DomError> {
    use tokio::io::AsyncReadExt;

    // Phase 1: read length prefix.
    loop {
        match state {
            ReadState::Idle => {
                *state = ReadState::ReadingLen {
                    buf: [0u8; 4],
                    filled: 0,
                };
            }
            ReadState::ReadingLen { buf, filled } => {
                if *filled == 4 {
                    let len = u32::from_le_bytes(*buf) as usize;
                    if len > NOISE_MAX_MSG {
                        // Reset state so a future caller is not stuck.
                        *state = ReadState::Idle;
                        return Err(DomError::Malformed(format!("frame too large: {len}")));
                    }
                    *state = ReadState::ReadingData {
                        buf: vec![0u8; len],
                        filled: 0,
                    };
                    continue;
                }
                let n = stream
                    .read(&mut buf[*filled..])
                    .await
                    .map_err(|e| DomError::Internal(format!("read frame len: {e}")))?;
                if n == 0 {
                    *state = ReadState::Idle;
                    return Err(DomError::Internal("read frame len: early eof".into()));
                }
                *filled += n;
            }
            ReadState::ReadingData { buf, filled } => {
                if *filled == buf.len() {
                    // Take ownership of the buffer and reset state atomically.
                    let mut taken = ReadState::Idle;
                    std::mem::swap(state, &mut taken);
                    if let ReadState::ReadingData { buf, .. } = taken {
                        return Ok(buf);
                    } else {
                        unreachable!("state swapped from ReadingData");
                    }
                }
                let n = stream
                    .read(&mut buf[*filled..])
                    .await
                    .map_err(|e| DomError::Internal(format!("read frame data: {e}")))?;
                if n == 0 {
                    *state = ReadState::Idle;
                    return Err(DomError::Internal("read frame data: early eof".into()));
                }
                *filled += n;
            }
        }
    }
}

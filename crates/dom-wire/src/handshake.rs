//! Noise_XX_25519_ChaChaPoly_BLAKE2s handshake with chain_id prologue binding.
//!
//! RFC-0005: transport is Noise_XX.
//! RFC-0009 Section 4.3: chain_id bound to Noise prologue.
//!
//! Prologue = "DOM" || PROTOCOL_VERSION[4 LE] || NETWORK_MAGIC[4 LE] || chain_id[32]
//!
//! Any MITM modification to the prologue causes MAC failure — detected cryptographically.

use dom_core::{DomError, PROTOCOL_VERSION};
use snow::{Builder, HandshakeState, TransportState};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum Noise message size.
pub const NOISE_MAX_MSG: usize = 65535;

/// Timeout for completing the Noise handshake (3 messages).
/// If not completed within this time, connection is dropped.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Idle timeout for established connections.
/// Peers that send no messages for this long are disconnected.
pub const IDLE_TIMEOUT_SECS: u64 = 60;

/// Build the Noise prologue that binds chain_id to the transport.
///
/// RFC-0009: prologue = "DOM" || u32_le(PROTOCOL_VERSION) || u32_le(NETWORK_MAGIC) || chain_id[32]
pub fn build_prologue(network_magic: u32, chain_id: &[u8; 32]) -> Vec<u8> {
    let mut prologue = Vec::with_capacity(3 + 4 + 4 + 32);
    prologue.extend_from_slice(b"DOM");
    prologue.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
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
    let prologue = build_prologue(network_magic, chain_id);
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
    let prologue = build_prologue(network_magic, chain_id);
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
    // Curve25519 key clamping
    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;
    // Derive public key via x25519-dalek
    let secret = x25519_dalek::StaticSecret::from(privkey);
    let public = x25519_dalek::PublicKey::from(&secret);
    (privkey, *public.as_bytes())
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
    tokio::time::timeout(
        tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        perform_handshake_initiator_inner(stream, static_privkey, network_magic, chain_id),
    )
    .await
    .map_err(|_| {
        DomError::PolicyRejected(format!("handshake timeout after {HANDSHAKE_TIMEOUT_SECS}s"))
    })?
}

async fn perform_handshake_initiator_inner(
    stream: &mut tokio::net::TcpStream,
    static_privkey: &[u8; 32],
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<TransportState, DomError> {
    let mut hs = build_initiator(static_privkey, network_magic, chain_id)?;
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
    tokio::time::timeout(
        tokio::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        perform_handshake_responder_inner(stream, static_privkey, network_magic, chain_id),
    )
    .await
    .map_err(|_| {
        DomError::PolicyRejected(format!("handshake timeout after {HANDSHAKE_TIMEOUT_SECS}s"))
    })?
}

async fn perform_handshake_responder_inner(
    stream: &mut tokio::net::TcpStream,
    static_privkey: &[u8; 32],
    network_magic: u32,
    chain_id: &[u8; 32],
) -> Result<TransportState, DomError> {
    let mut hs = build_responder(static_privkey, network_magic, chain_id)?;
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
    let msg3 = read_framed(stream).await?;
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

    #[test]
    fn generate_keypair_produces_different_keys() {
        let (priv1, pub1) = generate_static_keypair();
        let (priv2, pub2) = generate_static_keypair();
        assert_ne!(priv1, priv2);
        assert_ne!(pub1, pub2);
    }
}

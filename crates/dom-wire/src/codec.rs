//! Noise-encrypted message codec for tokio streams.

use crate::handshake::{read_framed_cancel_safe, write_framed, ReadState};
use crate::message::WireMessage;
use dom_core::DomError;
use snow::TransportState;

/// Encrypted connection wrapper.
pub struct NoiseCodec {
    transport: TransportState,
    network_magic: u32,
    /// Cancel-safe read state (preserved across tokio::select! cancellation).
    read_state: ReadState,
}

impl NoiseCodec {
    /// Create from completed Noise handshake.
    pub fn new(transport: TransportState, network_magic: u32) -> Self {
        Self {
            transport,
            network_magic,
            read_state: ReadState::Idle,
        }
    }

    /// Remote static Noise public key learned during Noise_XX, if present.
    pub fn remote_noise_pubkey(&self) -> Option<[u8; 32]> {
        self.transport
            .get_remote_static()
            .and_then(|key| key.try_into().ok())
    }

    /// Encrypt and send a message.
    pub async fn send(
        &mut self,
        stream: &mut tokio::net::TcpStream,
        msg: &WireMessage,
    ) -> Result<(), DomError> {
        let plaintext = msg.to_bytes();
        let mut ciphertext = vec![0u8; plaintext.len() + 16]; // +16 for AEAD tag
        let len = self
            .transport
            .write_message(&plaintext, &mut ciphertext)
            .map_err(|e| DomError::Internal(format!("noise encrypt: {e}")))?;
        write_framed(stream, &ciphertext[..len]).await
    }

    /// Receive and decrypt a message with idle timeout.
    ///
    /// AUDIT FIX: Added idle timeout to prevent resource exhaustion.
    pub async fn recv(
        &mut self,
        stream: &mut tokio::net::TcpStream,
    ) -> Result<WireMessage, DomError> {
        let ciphertext = tokio::time::timeout(
            tokio::time::Duration::from_secs(crate::handshake::IDLE_TIMEOUT_SECS),
            read_framed_cancel_safe(stream, &mut self.read_state),
        )
        .await
        .map_err(|_| {
            dom_core::DomError::PolicyRejected(format!(
                "idle timeout after {}s",
                crate::handshake::IDLE_TIMEOUT_SECS
            ))
        })??;
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| DomError::Invalid(format!("noise decrypt: {e}")))?;
        WireMessage::from_bytes(&plaintext[..len], self.network_magic)
    }
}

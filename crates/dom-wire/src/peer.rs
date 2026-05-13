//! Peer connection state machine.

use std::net::SocketAddr;
use std::time::Instant;

/// Ban score thresholds for common protocol violations.
pub mod ban_scores {
    /// Malformed message (parse failure, bad encoding).
    pub const MALFORMED_MESSAGE: u32 = 20;
    /// Invalid PoW in block header.
    pub const INVALID_POW: u32 = 50;
    /// Wrong chain_id — not our network. Immediate ban.
    pub const WRONG_CHAIN_ID: u32 = 100;
    /// Address flooding (>100 addrs/hour).
    pub const ADDRESS_FLOODING: u32 = 30;
    /// Invalid Schnorr signature in transaction.
    pub const INVALID_SIGNATURE: u32 = 25;
    /// Sending transaction with invalid structure.
    pub const INVALID_TX_STRUCTURE: u32 = 15;
    /// Sending unrequested data / protocol violation.
    pub const PROTOCOL_VIOLATION: u32 = 10;
    /// Ban threshold — score >= this → peer is banned.
    pub const BAN_THRESHOLD: u32 = 100;
}

/// State of a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// TCP connection established, Noise handshake in progress.
    Handshaking,
    /// Noise handshake complete, Hello exchange in progress.
    HelloExchange,
    /// Fully connected and ready for protocol messages.
    Connected,
    /// Peer has been banned.
    Banned,
    /// Connection closed.
    Disconnected,
}

/// Peer connection metadata.
#[derive(Debug)]
pub struct PeerInfo {
    /// Remote address.
    pub addr: SocketAddr,
    /// Whether this is an outbound connection.
    pub outbound: bool,
    /// Current connection state.
    pub state: PeerState,
    /// Time of connection establishment.
    pub connected_at: Instant,
    /// Best height the peer claims.
    pub best_height: u64,
    /// Best hash the peer claims.
    pub best_hash: [u8; 32],
    /// User agent string.
    pub user_agent: String,
    /// Cumulative ban score (> 100 → ban).
    pub ban_score: u32,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_recv: u64,
}

impl PeerInfo {
    /// Create for a new connection.
    pub fn new(addr: SocketAddr, outbound: bool) -> Self {
        Self {
            addr, outbound,
            state: PeerState::Handshaking,
            connected_at: Instant::now(),
            best_height: 0,
            best_hash: [0u8; 32],
            user_agent: String::new(),
            ban_score: 0,
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }

    /// Add to ban score. Returns true if peer should be banned (score >= 100).
    pub fn add_ban_score(&mut self, score: u32) -> bool {
        self.ban_score = self.ban_score.saturating_add(score);
        if self.ban_score >= 100 {
            self.state = PeerState::Banned;
            true
        } else {
            false
        }
    }

    /// Connection duration.
    pub fn uptime_secs(&self) -> u64 {
        self.connected_at.elapsed().as_secs()
    }
}

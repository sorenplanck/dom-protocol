//! Peer address storage.

use dom_core::DomError;

/// A known peer address.
#[derive(Debug, Clone)]
pub struct PeerAddr {
    /// IP:port string.
    pub addr: String,
    /// Unix timestamp of last successful connection.
    pub last_seen: u64,
    /// Number of consecutive failed connections.
    pub failures: u32,
}

impl PeerAddr {
    /// Serialize for LMDB.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.last_seen.to_le_bytes());
        out.extend_from_slice(&self.failures.to_le_bytes());
        out
    }

    /// Deserialize from LMDB.
    pub fn from_bytes(addr: String, bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() < 12 {
            return Err(DomError::Malformed("peer entry too short".into()));
        }
        let last_seen = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let failures = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        Ok(Self { addr, last_seen, failures })
    }

    /// Whether this peer should be tried (not too many failures).
    pub fn is_connectable(&self) -> bool {
        self.failures < 10
    }
}

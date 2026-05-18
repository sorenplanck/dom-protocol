//! Wire protocol message types (RFC-0005, DOM_v6_1_Wire_Protocol_RFC).

use dom_core::DomError;

/// All P2P message command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Handshake / version exchange.
    Hello = 0x01,
    /// Liveness ping.
    Ping = 0x02,
    /// Liveness pong.
    Pong = 0x03,
    /// Inventory announcement (block hashes, tx hashes).
    Inv = 0x04,
    /// Request block headers.
    GetHeaders = 0x05,
    /// Block headers response.
    Headers = 0x06,
    /// Request full block.
    GetBlock = 0x07,
    /// Full block response.
    Block = 0x08,
    /// Transaction broadcast.
    Tx = 0x09,
    /// Request peer addresses.
    GetAddr = 0x0A,
    /// Peer addresses response.
    Addr = 0x0B,
    /// Request block data for IBD (headers-first sync).
    GetBlockData = 0x0C,
}

impl Command {
    /// Parse from byte.
    pub fn from_byte(b: u8) -> Result<Self, DomError> {
        match b {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::Ping),
            0x03 => Ok(Self::Pong),
            0x04 => Ok(Self::Inv),
            0x05 => Ok(Self::GetHeaders),
            0x06 => Ok(Self::Headers),
            0x07 => Ok(Self::GetBlock),
            0x08 => Ok(Self::Block),
            0x09 => Ok(Self::Tx),
            0x0A => Ok(Self::GetAddr),
            0x0B => Ok(Self::Addr),
            0x0C => Ok(Self::GetBlockData),
            other => Err(DomError::Malformed(format!(
                "unknown command 0x{other:02x}"
            ))),
        }
    }
}

/// Maximum payload size per message (prevents memory exhaustion DoS).
pub const MAX_MESSAGE_PAYLOAD: usize = 16 * 1024 * 1024; // 16 MiB

/// Wire message with framing.
#[derive(Debug, Clone)]
pub struct WireMessage {
    /// Magic bytes — must match network.
    pub magic: u32,
    /// Command type.
    pub command: Command,
    /// Payload bytes (decrypted, after Noise layer).
    pub payload: Vec<u8>,
}

impl WireMessage {
    /// Serialize to bytes (before Noise encryption).
    /// Format: magic[4 LE] + command[1] + length[4 LE] + checksum[4 LE] + payload
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.payload.len() as u32;
        let checksum = compute_checksum(&self.payload);
        let mut out = Vec::with_capacity(13 + self.payload.len());
        out.extend_from_slice(&self.magic.to_le_bytes());
        out.push(self.command as u8);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse from bytes. Validates magic, length, and checksum.
    ///
    /// Returns DomError with appropriate ban score annotation:
    /// - Malformed → +20 ban score (per ban_scores::MALFORMED_MESSAGE)
    /// - Invalid (wrong magic = wrong chain) → +100 ban score (immediate ban)
    pub fn from_bytes(data: &[u8], expected_magic: u32) -> Result<Self, DomError> {
        if data.len() < 13 {
            return Err(DomError::Malformed("message too short [ban+20]".into()));
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != expected_magic {
            // Wrong magic = wrong chain or wrong network — immediate ban
            return Err(DomError::Invalid(format!(
                "magic mismatch: got 0x{magic:08x}, expected 0x{expected_magic:08x} [ban+100]"
            )));
        }
        let command = Command::from_byte(data[4])?;
        let length = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
        let checksum = u32::from_le_bytes(data[9..13].try_into().unwrap());
        if length > MAX_MESSAGE_PAYLOAD {
            return Err(DomError::Malformed(format!(
                "payload length {length} > MAX_MESSAGE_PAYLOAD"
            )));
        }
        if data.len() != 13 + length {
            return Err(DomError::Malformed("payload length mismatch".into()));
        }
        let payload = data[13..].to_vec();
        let expected_checksum = compute_checksum(&payload);
        if checksum != expected_checksum {
            return Err(DomError::Malformed("checksum mismatch".into()));
        }
        Ok(Self {
            magic,
            command,
            payload,
        })
    }
}

/// Simple 4-byte checksum: first 4 bytes of Blake2b-256(payload).
fn compute_checksum(data: &[u8]) -> u32 {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(data);
    let result = h.finalize();
    u32::from_le_bytes([result[0], result[1], result[2], result[3]])
}

/// Hello message payload — version handshake.
#[derive(Debug, Clone)]
pub struct HelloPayload {
    /// Protocol version.
    pub version: u32,
    /// Network magic (redundant but explicit).
    pub network_magic: u32,
    /// Chain ID (32 bytes).
    pub chain_id: [u8; 32],
    /// Best block height this peer knows about.
    pub best_height: u64,
    /// Best block hash this peer knows about.
    pub best_hash: [u8; 32],
    /// User agent string (max 256 bytes per RFC-0005).
    pub user_agent: String,
}

impl HelloPayload {
    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        let ua = self.user_agent.as_bytes();
        if ua.len() > dom_core::MAX_USER_AGENT_BYTES {
            return Err(DomError::Invalid("user agent too long".into()));
        }
        let mut out = Vec::with_capacity(4 + 4 + 32 + 8 + 32 + 2 + ua.len());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.network_magic.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.best_height.to_le_bytes());
        out.extend_from_slice(&self.best_hash);
        out.extend_from_slice(&(ua.len() as u16).to_le_bytes());
        out.extend_from_slice(ua);
        Ok(out)
    }

    /// Deserialize.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DomError> {
        if data.len() < 82 {
            return Err(DomError::Malformed("hello payload too short".into()));
        }
        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let network_magic = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let chain_id: [u8; 32] = data[8..40].try_into().unwrap();
        let best_height = u64::from_le_bytes(data[40..48].try_into().unwrap());
        let best_hash: [u8; 32] = data[48..80].try_into().unwrap();
        let ua_len = u16::from_le_bytes(data[80..82].try_into().unwrap()) as usize;
        if ua_len > dom_core::MAX_USER_AGENT_BYTES {
            return Err(DomError::Malformed("user agent too long".into()));
        }
        if data.len() < 82 + ua_len {
            return Err(DomError::Malformed("hello truncated".into()));
        }
        let user_agent = String::from_utf8_lossy(&data[82..82 + ua_len]).into_owned();
        Ok(Self {
            version,
            network_magic,
            chain_id,
            best_height,
            best_hash,
            user_agent,
        })
    }
}

/// Inventory item type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InvType {
    /// A block hash.
    Block = 0x01,
    /// A transaction hash.
    Tx = 0x02,
}

/// A single inventory item.
#[derive(Debug, Clone)]
pub struct InvItem {
    /// Type.
    pub inv_type: InvType,
    /// Hash (32 bytes).
    pub hash: [u8; 32],
}

/// GetHeaders request: peer asks for headers starting at the first match
/// of `locator_hashes` (newest first), up to `stop_hash` (or MAX_HEADERS_PER_MSG).
#[derive(Debug, Clone)]
pub struct GetHeadersPayload {
    /// Block hashes from newest-to-genesis as a sparse locator (BIP-31 style).
    pub locator_hashes: Vec<[u8; 32]>,
    /// Stop hash; all-zero means "send up to MAX_HEADERS_PER_MSG".
    pub stop_hash: [u8; 32],
}

impl GetHeadersPayload {
    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        if self.locator_hashes.len() > dom_core::MAX_LOCATOR_HASHES {
            return Err(DomError::Invalid("too many locator hashes".into()));
        }
        let mut out = Vec::with_capacity(2 + self.locator_hashes.len() * 32 + 32);
        out.extend_from_slice(&(self.locator_hashes.len() as u16).to_le_bytes());
        for h in &self.locator_hashes {
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&self.stop_hash);
        Ok(out)
    }

    /// Deserialize.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DomError> {
        if data.len() < 2 + 32 {
            return Err(DomError::Malformed("getheaders too short".into()));
        }
        let n = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
        if n > dom_core::MAX_LOCATOR_HASHES {
            return Err(DomError::Malformed(format!("too many locator hashes: {n}")));
        }
        let expected_len = 2 + n * 32 + 32;
        if data.len() != expected_len {
            return Err(DomError::Malformed(format!(
                "getheaders length mismatch: got {} expected {expected_len}",
                data.len()
            )));
        }
        let mut locator_hashes = Vec::with_capacity(n);
        for i in 0..n {
            let s = 2 + i * 32;
            locator_hashes.push(data[s..s + 32].try_into().unwrap());
        }
        let stop_hash: [u8; 32] = data[2 + n * 32..2 + n * 32 + 32].try_into().unwrap();
        Ok(Self {
            locator_hashes,
            stop_hash,
        })
    }
}

/// Headers response: list of header bytes (each serialized BlockHeader).
#[derive(Debug, Clone)]
pub struct HeadersPayload {
    /// Serialized headers in chain order (oldest first).
    pub headers: Vec<Vec<u8>>,
}

impl HeadersPayload {
    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        if self.headers.len() > dom_core::MAX_HEADERS_PER_MSG {
            return Err(DomError::Invalid("too many headers".into()));
        }
        let mut out =
            Vec::with_capacity(2 + self.headers.iter().map(|h| 4 + h.len()).sum::<usize>());
        out.extend_from_slice(&(self.headers.len() as u16).to_le_bytes());
        for h in &self.headers {
            out.extend_from_slice(&(h.len() as u32).to_le_bytes());
            out.extend_from_slice(h);
        }
        Ok(out)
    }

    /// Deserialize.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DomError> {
        if data.len() < 2 {
            return Err(DomError::Malformed("headers too short".into()));
        }
        let n = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
        if n > dom_core::MAX_HEADERS_PER_MSG {
            return Err(DomError::Malformed(format!("too many headers: {n}")));
        }
        let mut headers = Vec::with_capacity(n);
        let mut pos = 2;
        for _ in 0..n {
            if data.len() < pos + 4 {
                return Err(DomError::Malformed("header length truncated".into()));
            }
            let hlen = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if hlen > 1024 {
                return Err(DomError::Malformed(format!("header too large: {hlen}")));
            }
            if data.len() < pos + hlen {
                return Err(DomError::Malformed("header bytes truncated".into()));
            }
            headers.push(data[pos..pos + hlen].to_vec());
            pos += hlen;
        }
        Ok(Self { headers })
    }
}

/// GetBlockData request: list of block hashes the requester wants bodies for.
#[derive(Debug, Clone)]
pub struct GetBlockDataPayload {
    /// Block hashes to fetch (up to MAX_GETBLOCKDATA_HASHES).
    pub hashes: Vec<[u8; 32]>,
}

impl GetBlockDataPayload {
    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        if self.hashes.len() > dom_core::MAX_GETBLOCKDATA_HASHES {
            return Err(DomError::Invalid("too many block hashes".into()));
        }
        let mut out = Vec::with_capacity(2 + self.hashes.len() * 32);
        out.extend_from_slice(&(self.hashes.len() as u16).to_le_bytes());
        for h in &self.hashes {
            out.extend_from_slice(h);
        }
        Ok(out)
    }

    /// Deserialize.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DomError> {
        if data.len() < 2 {
            return Err(DomError::Malformed("getblockdata too short".into()));
        }
        let n = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
        if n > dom_core::MAX_GETBLOCKDATA_HASHES {
            return Err(DomError::Malformed(format!("too many hashes: {n}")));
        }
        if data.len() != 2 + n * 32 {
            return Err(DomError::Malformed("getblockdata length mismatch".into()));
        }
        let mut hashes = Vec::with_capacity(n);
        for i in 0..n {
            let s = 2 + i * 32;
            hashes.push(data[s..s + 32].try_into().unwrap());
        }
        Ok(Self { hashes })
    }
}

/// Block payload: full serialized Block (header + coinbase + transactions).
#[derive(Debug, Clone)]
pub struct BlockPayload {
    /// Serialized block bytes (Block::to_bytes()).
    pub block_bytes: Vec<u8>,
}

impl BlockPayload {
    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        if self.block_bytes.len() > dom_core::MAX_BLOCK_SERIALIZED_SIZE {
            return Err(DomError::Invalid("block too large".into()));
        }
        let mut out = Vec::with_capacity(4 + self.block_bytes.len());
        out.extend_from_slice(&(self.block_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.block_bytes);
        Ok(out)
    }

    /// Deserialize.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DomError> {
        if data.len() < 4 {
            return Err(DomError::Malformed("block payload too short".into()));
        }
        let n = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        if n > dom_core::MAX_BLOCK_SERIALIZED_SIZE {
            return Err(DomError::Malformed(format!("block too large: {n}")));
        }
        if data.len() != 4 + n {
            return Err(DomError::Malformed("block payload length mismatch".into()));
        }
        Ok(Self {
            block_bytes: data[4..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_message_roundtrip() {
        let msg = WireMessage {
            magic: dom_core::NETWORK_MAGIC_MAINNET,
            command: Command::Ping,
            payload: b"dom-ping".to_vec(),
        };
        let bytes = msg.to_bytes();
        let msg2 = WireMessage::from_bytes(&bytes, dom_core::NETWORK_MAGIC_MAINNET).unwrap();
        assert_eq!(msg2.command, Command::Ping);
        assert_eq!(msg2.payload, b"dom-ping");
    }

    #[test]
    fn wrong_magic_rejected() {
        let msg = WireMessage {
            magic: dom_core::NETWORK_MAGIC_MAINNET,
            command: Command::Ping,
            payload: vec![],
        };
        let bytes = msg.to_bytes();
        assert!(WireMessage::from_bytes(&bytes, dom_core::NETWORK_MAGIC_TESTNET).is_err());
    }

    #[test]
    fn getheaders_roundtrip() {
        let p = GetHeadersPayload {
            locator_hashes: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            stop_hash: [9u8; 32],
        };
        let bytes = p.to_bytes().unwrap();
        let p2 = GetHeadersPayload::from_bytes(&bytes).unwrap();
        assert_eq!(p2.locator_hashes.len(), 3);
        assert_eq!(p2.locator_hashes[0], [1u8; 32]);
        assert_eq!(p2.stop_hash, [9u8; 32]);
    }

    #[test]
    fn headers_roundtrip() {
        let p = HeadersPayload {
            headers: vec![vec![0u8; 200], vec![1u8; 200], vec![2u8; 200]],
        };
        let bytes = p.to_bytes().unwrap();
        let p2 = HeadersPayload::from_bytes(&bytes).unwrap();
        assert_eq!(p2.headers.len(), 3);
        assert_eq!(p2.headers[0].len(), 200);
    }

    #[test]
    fn getblockdata_roundtrip() {
        let p = GetBlockDataPayload {
            hashes: vec![[7u8; 32]; 5],
        };
        let bytes = p.to_bytes().unwrap();
        let p2 = GetBlockDataPayload::from_bytes(&bytes).unwrap();
        assert_eq!(p2.hashes.len(), 5);
        assert_eq!(p2.hashes[2], [7u8; 32]);
    }

    #[test]
    fn block_payload_roundtrip() {
        let p = BlockPayload {
            block_bytes: vec![0xab; 1024],
        };
        let bytes = p.to_bytes().unwrap();
        let p2 = BlockPayload::from_bytes(&bytes).unwrap();
        assert_eq!(p2.block_bytes.len(), 1024);
        assert_eq!(p2.block_bytes[100], 0xab);
    }

    #[test]
    fn headers_too_many_rejected() {
        let p = HeadersPayload {
            headers: vec![vec![0u8; 10]; dom_core::MAX_HEADERS_PER_MSG + 1],
        };
        assert!(p.to_bytes().is_err());
    }

    #[test]
    fn corrupted_checksum_rejected() {
        let msg = WireMessage {
            magic: dom_core::NETWORK_MAGIC_MAINNET,
            command: Command::Ping,
            payload: vec![1, 2, 3],
        };
        let mut bytes = msg.to_bytes();
        bytes[9] ^= 0xFF; // corrupt checksum
        assert!(WireMessage::from_bytes(&bytes, dom_core::NETWORK_MAGIC_MAINNET).is_err());
    }

    #[test]
    fn hello_payload_roundtrip() {
        let hello = HelloPayload {
            version: dom_core::PROTOCOL_VERSION,
            network_magic: dom_core::NETWORK_MAGIC_MAINNET,
            chain_id: [0xCCu8; 32],
            best_height: 12345,
            best_hash: [0xAAu8; 32],
            user_agent: "dom-node/0.1.0".into(),
        };
        let bytes = hello.to_bytes().unwrap();
        let hello2 = HelloPayload::from_bytes(&bytes).unwrap();
        assert_eq!(hello2.best_height, 12345);
        assert_eq!(hello2.user_agent, "dom-node/0.1.0");
        assert_eq!(hello2.chain_id, [0xCCu8; 32]);
    }
}

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
    /// Local Unix timestamp at handshake time (added in PROTOCOL_VERSION 2).
    /// Used for peer time discipline evaluation.
    pub local_timestamp: u64,
}

impl HelloPayload {
    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        let ua = self.user_agent.as_bytes();
        if ua.len() > dom_core::MAX_USER_AGENT_BYTES {
            return Err(DomError::Invalid("user agent too long".into()));
        }
        let mut out = Vec::with_capacity(4 + 4 + 32 + 8 + 32 + 2 + ua.len() + 8);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.network_magic.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.best_height.to_le_bytes());
        out.extend_from_slice(&self.best_hash);
        out.extend_from_slice(&(ua.len() as u16).to_le_bytes());
        out.extend_from_slice(ua);
        // local_timestamp: PROTOCOL_VERSION 2 (Doc 4.5b — time discipline)
        out.extend_from_slice(&self.local_timestamp.to_le_bytes());
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
        // local_timestamp: 8 bytes after user_agent (added in PROTOCOL_VERSION 2)
        let ts_offset = 82 + ua_len;
        if data.len() != ts_offset && data.len() != ts_offset + 8 {
            return Err(DomError::Malformed(format!(
                "hello length mismatch: expected {ts_offset} or {}, got {}",
                ts_offset + 8,
                data.len()
            )));
        }
        let local_timestamp = if data.len() >= ts_offset + 8 {
            u64::from_le_bytes(data[ts_offset..ts_offset + 8].try_into().unwrap())
        } else {
            0 // backward compat: peers on PROTOCOL_VERSION 1 omit this field
        };
        Ok(Self {
            version,
            network_magic,
            chain_id,
            best_height,
            best_hash,
            user_agent,
            local_timestamp,
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
        if pos != data.len() {
            return Err(DomError::Malformed(format!(
                "headers trailing bytes: parsed {pos}, total {}",
                data.len()
            )));
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

/// Maximum addresses in a single Addr message (anti-flood / anti-OOM).
/// Must stay in sync with the PEX sharing bound (dom-node reuses this constant).
pub const MAX_ADDRS_PER_MESSAGE: usize = 1_000;

/// One peer address entry in an Addr message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrEntry {
    /// Peer address as "ip:port" string (max 255 bytes on the wire).
    pub addr: String,
    /// Unix timestamp the sender last saw this peer.
    pub last_seen: u64,
}

/// GetAddr request: ask a peer for addresses it knows. Carries no body —
/// from_bytes rejects any payload so a bloated GetAddr is a malformed message.
#[derive(Debug, Clone)]
pub struct GetAddrPayload;

impl GetAddrPayload {
    /// Serialize (empty body).
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        Ok(Vec::new())
    }

    /// Deserialize. GetAddr must have an empty payload.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DomError> {
        if !data.is_empty() {
            return Err(DomError::Malformed(format!(
                "getaddr payload must be empty, got {} bytes",
                data.len()
            )));
        }
        Ok(Self)
    }
}

/// Addr response: list of peer addresses with last-seen timestamps.
/// Format: count[u16 LE] + per entry (len[u8] + addr bytes + last_seen[u64 LE]).
#[derive(Debug, Clone)]
pub struct AddrPayload {
    /// Peer address entries (up to MAX_ADDRS_PER_MESSAGE).
    pub entries: Vec<AddrEntry>,
}

/// Minimum wire size of one Addr entry: len byte + empty addr + timestamp.
const ADDR_ENTRY_MIN_BYTES: usize = 1 + 8;

impl AddrPayload {
    /// Serialize.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        if self.entries.len() > MAX_ADDRS_PER_MESSAGE {
            return Err(DomError::Invalid("too many addrs".into()));
        }
        let mut out = Vec::with_capacity(
            2 + self
                .entries
                .iter()
                .map(|e| ADDR_ENTRY_MIN_BYTES + e.addr.len())
                .sum::<usize>(),
        );
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for entry in &self.entries {
            let addr_bytes = entry.addr.as_bytes();
            if addr_bytes.len() > u8::MAX as usize {
                return Err(DomError::Invalid("addr string too long".into()));
            }
            out.push(addr_bytes.len() as u8);
            out.extend_from_slice(addr_bytes);
            out.extend_from_slice(&entry.last_seen.to_le_bytes());
        }
        Ok(out)
    }

    /// Deserialize. Rejects oversized counts, truncated payloads, and trailing
    /// bytes; allocates only after the declared count is proven plausible.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DomError> {
        if data.len() < 2 {
            return Err(DomError::Malformed("addr payload too short".into()));
        }
        let count = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
        if count > MAX_ADDRS_PER_MESSAGE {
            return Err(DomError::Malformed("addr count exceeds limit".into()));
        }
        // Anti-OOM: the declared count must fit in the bytes actually present
        // before any allocation sized by it.
        if data.len() < 2 + count * ADDR_ENTRY_MIN_BYTES {
            return Err(DomError::Malformed("addr payload truncated".into()));
        }
        let mut entries = Vec::with_capacity(count);
        let mut pos = 2usize;
        for _ in 0..count {
            if pos >= data.len() {
                return Err(DomError::Malformed("addr payload truncated".into()));
            }
            let len = data[pos] as usize;
            pos += 1;
            if pos + len + 8 > data.len() {
                return Err(DomError::Malformed("addr payload truncated".into()));
            }
            let addr = String::from_utf8_lossy(&data[pos..pos + len]).into_owned();
            pos += len;
            let last_seen = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;
            entries.push(AddrEntry { addr, last_seen });
        }
        if pos != data.len() {
            return Err(DomError::Malformed("addr trailing bytes".into()));
        }
        Ok(Self { entries })
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
    fn headers_exact_payload_accepted() {
        let p = HeadersPayload {
            headers: vec![vec![0u8; 200], vec![1u8; 200]],
        };
        let bytes = p.to_bytes().unwrap();
        assert!(HeadersPayload::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn headers_trailing_bytes_rejected() {
        let p = HeadersPayload {
            headers: vec![vec![0u8; 200], vec![1u8; 200]],
        };
        let mut bytes = p.to_bytes().unwrap();
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(HeadersPayload::from_bytes(&bytes).is_err());
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
            local_timestamp: 0,
        };
        let bytes = hello.to_bytes().unwrap();
        let hello2 = HelloPayload::from_bytes(&bytes).unwrap();
        assert_eq!(hello2.best_height, 12345);
        assert_eq!(hello2.user_agent, "dom-node/0.1.0");
        assert_eq!(hello2.chain_id, [0xCCu8; 32]);
    }

    fn hello_payload_for_tests() -> HelloPayload {
        HelloPayload {
            version: dom_core::PROTOCOL_VERSION,
            network_magic: dom_core::NETWORK_MAGIC_MAINNET,
            chain_id: [0xCCu8; 32],
            best_height: 12345,
            best_hash: [0xAAu8; 32],
            user_agent: "dom-node/0.1.0".into(),
            local_timestamp: 1_717_171_717,
        }
    }

    #[test]
    fn hello_v2_exact_payload_accepted() {
        let hello = hello_payload_for_tests();
        let bytes = hello.to_bytes().unwrap();
        let parsed = HelloPayload::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.local_timestamp, hello.local_timestamp);
    }

    #[test]
    fn hello_v1_exact_payload_accepted() {
        let hello = hello_payload_for_tests();
        let mut bytes = hello.to_bytes().unwrap();
        let ts_offset = bytes.len() - 8;
        bytes.truncate(ts_offset);

        let parsed = HelloPayload::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.local_timestamp, 0);
        assert_eq!(parsed.user_agent, hello.user_agent);
    }

    #[test]
    fn hello_trailing_bytes_rejected() {
        let hello = hello_payload_for_tests();
        let mut bytes = hello.to_bytes().unwrap();
        bytes.extend_from_slice(&[0xde, 0xad]);
        assert!(HelloPayload::from_bytes(&bytes).is_err());
    }

    #[test]
    fn hello_truncated_timestamp_rejected() {
        let hello = hello_payload_for_tests();
        let bytes = hello.to_bytes().unwrap();
        let ts_offset = bytes.len() - 8;

        for extra_ts_bytes in 1..8 {
            let truncated = &bytes[..ts_offset + extra_ts_bytes];
            assert!(
                HelloPayload::from_bytes(truncated).is_err(),
                "accepted timestamp with {extra_ts_bytes} byte(s)"
            );
        }
    }
}

#[cfg(test)]
mod parser_boundary_tests {
    // AUDIT-003: Deterministic boundary tests. Full coverage requires running
    // fuzz targets (fuzz_wire_message, fuzz_validate_block, etc.) on Linux with
    // cargo-fuzz before mainnet. Every parser must return Err (never panic) on
    // crafted/truncated input.
    use super::*;

    const TEST_MAGIC: u32 = dom_core::NETWORK_MAGIC_MAINNET;

    /// Build a well-framed message (correct length + checksum) for the negatives
    /// that only corrupt one field.
    fn frame(command: Command, payload: &[u8]) -> Vec<u8> {
        WireMessage {
            magic: TEST_MAGIC,
            command,
            payload: payload.to_vec(),
        }
        .to_bytes()
    }

    // 1. Empty frame → Err, not panic.
    #[test]
    fn empty_frame_errs() {
        assert!(WireMessage::from_bytes(&[], TEST_MAGIC).is_err());
    }

    // 2. Declared length > MAX_MESSAGE_PAYLOAD → Err.
    #[test]
    fn frame_length_over_max_errs() {
        let mut data = TEST_MAGIC.to_le_bytes().to_vec();
        data.push(Command::Ping as u8);
        data.extend_from_slice(&((MAX_MESSAGE_PAYLOAD as u32) + 1).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // checksum (rejected earlier on length)
        assert!(WireMessage::from_bytes(&data, TEST_MAGIC).is_err());
    }

    // 3. Wrong checksum → Err.
    #[test]
    fn frame_bad_checksum_errs() {
        let mut data = frame(Command::Ping, &[1, 2, 3]);
        data[9] ^= 0xFF; // flip a checksum byte
        assert!(WireMessage::from_bytes(&data, TEST_MAGIC).is_err());
    }

    // 4. GetHeaders with n == MAX_LOCATOR_HASHES → Ok.
    #[test]
    fn getheaders_max_locator_ok() {
        let p = GetHeadersPayload {
            locator_hashes: vec![[1u8; 32]; dom_core::MAX_LOCATOR_HASHES],
            stop_hash: [0u8; 32],
        };
        let bytes = p.to_bytes().unwrap();
        assert!(GetHeadersPayload::from_bytes(&bytes).is_ok());
    }

    // 5. GetHeaders with n == MAX_LOCATOR_HASHES + 1 → Err.
    #[test]
    fn getheaders_over_max_locator_errs() {
        let n = dom_core::MAX_LOCATOR_HASHES + 1;
        let mut data = (n as u16).to_le_bytes().to_vec();
        data.resize(2 + n * 32 + 32, 0u8);
        assert!(GetHeadersPayload::from_bytes(&data).is_err());
    }

    // 6. GetHeaders truncated mid-hash → Err, not panic.
    #[test]
    fn getheaders_truncated_hash_errs() {
        // Declares 2 locator hashes but supplies 1.5 hashes and no stop hash.
        let mut data = 2u16.to_le_bytes().to_vec();
        data.resize(2 + 32 + 16, 0u8);
        assert!(GetHeadersPayload::from_bytes(&data).is_err());
    }

    // 7. Headers count declared larger than bytes available → Err, not panic.
    #[test]
    fn headers_count_exceeds_data_errs() {
        let data = 5u16.to_le_bytes().to_vec(); // 5 headers declared, no bodies
        assert!(HeadersPayload::from_bytes(&data).is_err());
    }

    // 7b. Headers with hlen pointing past the buffer → Err, not panic
    //     (exercises the data[pos..pos+hlen] bound check).
    #[test]
    fn headers_hlen_beyond_data_errs() {
        let mut data = 1u16.to_le_bytes().to_vec();
        data.extend_from_slice(&500u32.to_le_bytes()); // hlen = 500
        data.resize(data.len() + 10, 0u8); // only 10 bytes of body
        assert!(HeadersPayload::from_bytes(&data).is_err());
    }

    // 8. Headers with hlen > 1024 → Err.
    #[test]
    fn headers_hlen_too_large_errs() {
        let mut data = 1u16.to_le_bytes().to_vec();
        data.extend_from_slice(&2048u32.to_le_bytes()); // hlen = 2048 > 1024
        data.resize(data.len() + 2048, 0u8);
        assert!(HeadersPayload::from_bytes(&data).is_err());
    }

    // 9. Empty payload for commands that require a body → Err.
    #[test]
    fn empty_payload_for_body_commands_errs() {
        assert!(GetHeadersPayload::from_bytes(&[]).is_err());
        assert!(HeadersPayload::from_bytes(&[]).is_err());
        assert!(GetBlockDataPayload::from_bytes(&[]).is_err());
        assert!(HelloPayload::from_bytes(&[]).is_err());
    }

    // 10. Huge declared length (u32::MAX) with short data → Err, not panic/OOM.
    #[test]
    fn frame_huge_length_short_data_errs() {
        let mut data = TEST_MAGIC.to_le_bytes().to_vec();
        data.push(Command::Headers as u8);
        data.extend_from_slice(&u32::MAX.to_le_bytes()); // ~4.29 GB declared
        data.extend_from_slice(&0u32.to_le_bytes()); // checksum
        assert!(WireMessage::from_bytes(&data, TEST_MAGIC).is_err());
    }
}

#[cfg(test)]
mod addr_payload_tests {
    use super::*;

    fn entry(addr: &str, last_seen: u64) -> AddrEntry {
        AddrEntry {
            addr: addr.into(),
            last_seen,
        }
    }

    #[test]
    fn addr_roundtrip() {
        let p = AddrPayload {
            entries: vec![
                entry("127.0.0.1:33370", 1_700_000_000),
                entry("192.168.1.1:8080", 1_700_000_001),
            ],
        };
        let bytes = p.to_bytes().unwrap();
        let p2 = AddrPayload::from_bytes(&bytes).unwrap();
        assert_eq!(p2.entries, p.entries);
    }

    #[test]
    fn addr_empty_roundtrip() {
        let p = AddrPayload { entries: vec![] };
        let bytes = p.to_bytes().unwrap();
        assert_eq!(bytes, 0u16.to_le_bytes());
        assert!(AddrPayload::from_bytes(&bytes).unwrap().entries.is_empty());
    }

    #[test]
    fn addr_max_count_accepted() {
        let p = AddrPayload {
            entries: vec![entry("10.0.0.1:33369", 1); MAX_ADDRS_PER_MESSAGE],
        };
        let bytes = p.to_bytes().unwrap();
        let p2 = AddrPayload::from_bytes(&bytes).unwrap();
        assert_eq!(p2.entries.len(), MAX_ADDRS_PER_MESSAGE);
    }

    #[test]
    fn addr_encode_rejects_over_max_count() {
        let p = AddrPayload {
            entries: vec![entry("10.0.0.1:33369", 1); MAX_ADDRS_PER_MESSAGE + 1],
        };
        assert!(p.to_bytes().is_err());
    }

    #[test]
    fn addr_decode_rejects_oversized_count() {
        // Declared count just above the cap, no bodies. Must reject on the
        // count check, before any allocation sized by it.
        let bytes = ((MAX_ADDRS_PER_MESSAGE + 1) as u16).to_le_bytes();
        let err = AddrPayload::from_bytes(&bytes).expect_err("oversized count must reject");
        assert!(
            format!("{err}").contains("addr count exceeds limit"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn addr_decode_rejects_huge_count_short_data_without_alloc() {
        // u16::MAX entries declared with 2 bytes of data: rejected by the
        // count cap (and by the plausibility check), never allocating.
        let bytes = u16::MAX.to_le_bytes();
        assert!(AddrPayload::from_bytes(&bytes).is_err());
    }

    #[test]
    fn addr_decode_rejects_count_exceeding_available_bytes() {
        // Count within the cap but more entries declared than bytes present.
        let mut bytes = 100u16.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 30]); // far less than 100 * 9 bytes
        let err = AddrPayload::from_bytes(&bytes).expect_err("implausible count must reject");
        assert!(
            format!("{err}").contains("addr payload truncated"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn addr_decode_rejects_too_short() {
        let err = AddrPayload::from_bytes(&[0x01]).expect_err("missing count must reject");
        assert!(
            format!("{err}").contains("addr payload too short"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn addr_decode_rejects_truncated_entry() {
        let p = AddrPayload {
            entries: vec![entry("127.0.0.1:33370", 1_700_000_000)],
        };
        let mut bytes = p.to_bytes().unwrap();
        // Declare a second entry but supply only a partial body.
        bytes[0..2].copy_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&[0x0f, b'1', b'2', b'7']);
        let err = AddrPayload::from_bytes(&bytes).expect_err("truncated entry must reject");
        assert!(
            format!("{err}").contains("addr payload truncated"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn addr_decode_rejects_trailing_bytes() {
        let p = AddrPayload {
            entries: vec![entry("127.0.0.1:33370", 1_700_000_000)],
        };
        let mut bytes = p.to_bytes().unwrap();
        bytes.push(0xff);
        let err = AddrPayload::from_bytes(&bytes).expect_err("trailing byte must reject");
        assert!(
            format!("{err}").contains("addr trailing bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn addr_encode_rejects_oversized_addr_string() {
        let p = AddrPayload {
            entries: vec![entry(&"x".repeat(256), 1)],
        };
        assert!(p.to_bytes().is_err());
    }

    #[test]
    fn getaddr_empty_roundtrip() {
        let bytes = GetAddrPayload.to_bytes().unwrap();
        assert!(bytes.is_empty());
        assert!(GetAddrPayload::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn getaddr_nonempty_payload_rejected() {
        let err = GetAddrPayload::from_bytes(&[0x00]).expect_err("getaddr body must reject");
        assert!(
            format!("{err}").contains("getaddr payload must be empty"),
            "unexpected error: {err}"
        );
    }
}

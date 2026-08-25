//! Durable framing of the vault's records.
//!
//! Every persisted record has a magic, a version, a **readable prefix** with
//! the reservation identifier and a CRC32 at the end. The readable prefix is
//! deliberate: a torn write is detected by the CRC but still leaves visible
//! *which* reservation was hit, so the vault burns the identified reservation
//! instead of losing the record silently.
//!
//! The CRC32 here **is not cryptography** and does not replace any DOM
//! primitive: it is only a torn-write detector. No tag, no hash and no
//! cryptographic verification is invented in this crate (I15).

use crate::{Result, VaultError};

/// Framing version this binary knows how to read and write.
pub(crate) const FRAME_VERSION: u16 = 1;

/// Fixed header size: magic + version + readable prefix.
const HEADER_LEN: usize = 8 + 2 + 32;
/// Size of the integrity trailer.
const TRAILER_LEN: usize = 4;

/// CRC32 (reflected IEEE polynomial), computed without a static table.
///
/// A torn-write detector, not a cryptographic primitive.
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Deterministic serializer for durable records.
pub(crate) struct FrameWriter {
    bytes: Vec<u8>,
}

impl FrameWriter {
    /// Starts a record with magic, version and readable prefix.
    pub(crate) fn new(magic: &[u8; 8], readable_prefix: &[u8; 32]) -> Self {
        let mut bytes = Vec::with_capacity(HEADER_LEN + 64);
        bytes.extend_from_slice(magic);
        bytes.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        bytes.extend_from_slice(readable_prefix);
        Self { bytes }
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    pub(crate) fn digest(&mut self, value: &[u8; 32]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn optional_digest(&mut self, value: Option<&[u8; 32]>) {
        match value {
            Some(digest) => {
                self.bytes.push(1);
                self.bytes.extend_from_slice(digest);
            }
            None => {
                self.bytes.push(0);
                self.bytes.extend_from_slice(&[0u8; 32]);
            }
        }
    }

    pub(crate) fn optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(number) => {
                self.bytes.push(1);
                self.bytes.extend_from_slice(&number.to_le_bytes());
            }
            None => {
                self.bytes.push(0);
                self.bytes.extend_from_slice(&0u64.to_le_bytes());
            }
        }
    }

    /// Writes opaque bytes preceded by their exact length.
    pub(crate) fn blob(&mut self, value: &[u8]) -> Result<()> {
        let length = u32::try_from(value.len()).map_err(|_| VaultError::CounterOverflow)?;
        self.bytes.extend_from_slice(&length.to_le_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Closes the record by appending the CRC32 of everything before it.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        let checksum = crc32(&self.bytes);
        self.bytes.extend_from_slice(&checksum.to_le_bytes());
        self.bytes
    }
}

/// Strict reader: any divergence fails closed, with no partial salvage.
pub(crate) struct FrameReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> FrameReader<'a> {
    /// Validates magic, version, CRC and readable prefix before any field.
    ///
    /// Returns `CorruptState` for invalid framing. When the CRC fails but the
    /// readable prefix is intact, the caller can still learn which
    /// reservation to burn, because the prefix is read before verification.
    pub(crate) fn open(
        bytes: &'a [u8],
        magic: &[u8; 8],
        expected_prefix: &[u8; 32],
    ) -> Result<Self> {
        if bytes.len() < HEADER_LEN + TRAILER_LEN {
            return Err(VaultError::CorruptState);
        }
        let body_len = bytes.len() - TRAILER_LEN;
        if &bytes[..8] != magic {
            return Err(VaultError::CorruptState);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != FRAME_VERSION {
            return Err(VaultError::UnsupportedVersion);
        }
        if &bytes[10..HEADER_LEN] != expected_prefix.as_slice() {
            return Err(VaultError::CorruptState);
        }
        let stored = u32::from_le_bytes([
            bytes[body_len],
            bytes[body_len + 1],
            bytes[body_len + 2],
            bytes[body_len + 3],
        ]);
        if stored != crc32(&bytes[..body_len]) {
            return Err(VaultError::CorruptState);
        }
        Ok(Self {
            bytes: &bytes[..body_len],
            cursor: HEADER_LEN,
        })
    }

    /// Reads only the readable prefix of a possibly torn record.
    pub(crate) fn readable_prefix(bytes: &[u8]) -> Option<[u8; 32]> {
        let slice = bytes.get(10..HEADER_LEN)?;
        let mut prefix = [0u8; 32];
        if slice.len() != prefix.len() {
            return None;
        }
        prefix.copy_from_slice(slice);
        Some(prefix)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(VaultError::CorruptState)?;
        let slice = self
            .bytes
            .get(self.cursor..end)
            .ok_or(VaultError::CorruptState)?;
        self.cursor = end;
        Ok(slice)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        let slice = self.take(1)?;
        slice.first().copied().ok_or(VaultError::CorruptState)
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        let slice = self.take(8)?;
        let array: [u8; 8] = slice.try_into().map_err(|_| VaultError::CorruptState)?;
        Ok(u64::from_le_bytes(array))
    }

    pub(crate) fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            // A byte outside the closed domain is corruption, never "probably false".
            _ => Err(VaultError::CorruptState),
        }
    }

    pub(crate) fn digest(&mut self) -> Result<[u8; 32]> {
        let slice = self.take(32)?;
        slice.try_into().map_err(|_| VaultError::CorruptState)
    }

    pub(crate) fn optional_digest(&mut self) -> Result<Option<[u8; 32]>> {
        let present = self.bool()?;
        let digest = self.digest()?;
        Ok(present.then_some(digest))
    }

    pub(crate) fn optional_u64(&mut self) -> Result<Option<u64>> {
        let present = self.bool()?;
        let value = self.u64()?;
        Ok(present.then_some(value))
    }

    pub(crate) fn blob(&mut self) -> Result<Vec<u8>> {
        let slice = self.take(4)?;
        let array: [u8; 4] = slice.try_into().map_err(|_| VaultError::CorruptState)?;
        let length =
            usize::try_from(u32::from_le_bytes(array)).map_err(|_| VaultError::CorruptState)?;
        Ok(self.take(length)?.to_vec())
    }

    /// Requires the record to have been consumed in full.
    ///
    /// Leftover bytes are a silent extension: fail closed.
    pub(crate) fn finish(self) -> Result<()> {
        if self.cursor != self.bytes.len() {
            return Err(VaultError::CorruptState);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: &[u8; 8] = b"DOMTESTF";

    fn sample() -> Vec<u8> {
        let mut writer = FrameWriter::new(MAGIC, &[7; 32]);
        writer.u8(3);
        writer.u64(9);
        writer.optional_digest(Some(&[1; 32]));
        writer.optional_u64(None);
        writer.blob(&[4, 5, 6]).expect("blob");
        writer.finish()
    }

    #[test]
    fn frames_roundtrip_exactly() {
        let bytes = sample();
        let mut reader = FrameReader::open(&bytes, MAGIC, &[7; 32]).expect("frame");
        assert_eq!(reader.u8().expect("u8"), 3);
        assert_eq!(reader.u64().expect("u64"), 9);
        assert_eq!(reader.optional_digest().expect("digest"), Some([1; 32]));
        assert_eq!(reader.optional_u64().expect("u64"), None);
        assert_eq!(reader.blob().expect("blob"), vec![4, 5, 6]);
        reader.finish().expect("exact consumption");
    }

    #[test]
    fn every_single_byte_mutation_fails_closed() {
        let bytes = sample();
        for index in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[index] ^= 0x01;
            let opened = FrameReader::open(&mutated, MAGIC, &[7; 32]);
            assert!(
                opened.is_err(),
                "a mutation at byte {index} must fail closed"
            );
        }
    }

    #[test]
    fn truncation_and_extension_fail_closed() {
        let bytes = sample();
        for length in 0..bytes.len() {
            assert!(FrameReader::open(&bytes[..length], MAGIC, &[7; 32]).is_err());
        }
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(FrameReader::open(&extended, MAGIC, &[7; 32]).is_err());
    }

    #[test]
    fn torn_record_still_identifies_its_reservation() {
        let mut bytes = sample();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(FrameReader::open(&bytes, MAGIC, &[7; 32]).is_err());
        assert_eq!(
            FrameReader::readable_prefix(&bytes),
            Some([7; 32]),
            "a torn write must still say WHICH reservation to burn"
        );
    }

    #[test]
    fn wrong_prefix_and_wrong_magic_fail_closed() {
        let bytes = sample();
        assert!(FrameReader::open(&bytes, MAGIC, &[8; 32]).is_err());
        assert!(FrameReader::open(&bytes, b"OTHERMAG", &[7; 32]).is_err());
    }
}

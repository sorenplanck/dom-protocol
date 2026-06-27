//! # dom-serialization
//!
//! Canonical serialization layer for the DOM protocol.
//!
//! Source of truth: DOM_RFC_0002_Serialization_Limits.md
//!
//! ## Rules (all consensus-critical)
//!
//! - All integers encoded little-endian.
//! - Decoders MUST reject trailing bytes.
//! - Decoders MUST reject malformed scalars and points.
//! - Vec allocations MUST pre-validate length against consensus limits.
//! - All length arithmetic MUST use checked operations.
//! - Partial decodes of malformed vectors are FORBIDDEN.
//! - Auto-correction of malformed lengths is FORBIDDEN.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::arithmetic_side_effects)]

use dom_core::DomError;

// ── Writer ────────────────────────────────────────────────────────────────────

/// Canonical byte writer.
///
/// Appends data to an internal buffer in DOM canonical encoding.
/// All integers are little-endian. No implicit padding.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Create a new empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with pre-allocated capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Write a single byte.
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write u16 little-endian.
    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write u32 little-endian.
    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write u64 little-endian.
    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write u128 little-endian.
    pub fn write_u128(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write raw bytes without length prefix.
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Write a length-prefixed byte vector (u32 LE length prefix).
    ///
    /// Returns error if length exceeds u32::MAX.
    pub fn write_vec(&mut self, data: &[u8]) -> Result<(), DomError> {
        let len: u32 = data
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("vec length exceeds u32".into()))?;
        self.write_u32(len);
        self.write_bytes(data);
        Ok(())
    }

    /// Write a length-prefixed list of serializable items.
    pub fn write_list<T: DomSerialize>(&mut self, items: &[T]) -> Result<(), DomError> {
        let len: u32 = items
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("list length exceeds u32".into()))?;
        self.write_u32(len);
        for item in items {
            item.serialize(self)?;
        }
        Ok(())
    }

    /// Consume writer and return the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Current length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether writer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

// ── Reader ────────────────────────────────────────────────────────────────────

/// Canonical byte reader.
///
/// Reads from a byte slice with strict bounds checking.
/// Any attempt to read past the end returns `DomError::Malformed`.
/// After full deserialization, callers MUST call `finish()` to confirm
/// no trailing bytes remain — trailing bytes are consensus-invalid.
#[derive(Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Create a new reader over a byte slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current read position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Remaining bytes.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Consume `n` bytes. Returns error if insufficient data.
    fn consume(&mut self, n: usize) -> Result<&'a [u8], DomError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| DomError::Malformed("position arithmetic overflow".into()))?;
        if end > self.data.len() {
            return Err(DomError::Malformed(format!(
                "unexpected EOF: need {n} bytes at pos {}, have {}",
                self.pos,
                self.remaining()
            )));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8, DomError> {
        Ok(self.consume(1)?[0])
    }

    /// Read u16 little-endian.
    pub fn read_u16(&mut self) -> Result<u16, DomError> {
        let b = self.consume(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read u32 little-endian.
    pub fn read_u32(&mut self) -> Result<u32, DomError> {
        let b = self.consume(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read u64 little-endian.
    pub fn read_u64(&mut self) -> Result<u64, DomError> {
        let b = self.consume(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    /// Read u128 little-endian.
    pub fn read_u128(&mut self) -> Result<u128, DomError> {
        let b = self.consume(16)?;
        Ok(u128::from_le_bytes(b.try_into().unwrap()))
    }

    /// Read exactly `n` bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DomError> {
        self.consume(n)
    }

    /// Read exactly `N` bytes into a fixed array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DomError> {
        let slice = self.consume(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(arr)
    }

    /// Read a length-prefixed byte vector.
    ///
    /// The length prefix is u32 LE. Rejects if length exceeds `max_len`.
    /// Uses checked arithmetic — no implicit overflow.
    pub fn read_vec(&mut self, max_len: usize) -> Result<Vec<u8>, DomError> {
        let len = self.read_u32()? as usize;
        if len > max_len {
            return Err(DomError::Malformed(format!(
                "vec length {len} exceeds limit {max_len}"
            )));
        }
        Ok(self.consume(len)?.to_vec())
    }

    /// Read a length-prefixed list of deserializable items.
    ///
    /// Rejects if count exceeds `max_count`.
    pub fn read_list<T: DomDeserialize>(&mut self, max_count: usize) -> Result<Vec<T>, DomError> {
        let count = self.read_u32()? as usize;
        if count > max_count {
            return Err(DomError::Malformed(format!(
                "list count {count} exceeds limit {max_count}"
            )));
        }
        let min_item_size = std::mem::size_of::<T>().max(1);
        let remaining = self.data.len().saturating_sub(self.pos);
        let max_by_remaining = remaining / min_item_size;
        if count > max_by_remaining {
            return Err(DomError::Malformed(format!(
                "list count {count} exceeds remaining byte budget {remaining} for minimum item size {min_item_size}"
            )));
        }
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(T::deserialize(self)?);
        }
        Ok(items)
    }

    /// Assert that all bytes have been consumed.
    ///
    /// MUST be called after deserialization. Trailing bytes are
    /// consensus-invalid (DOM_RFC_0002).
    pub fn finish(self) -> Result<(), DomError> {
        if self.pos != self.data.len() {
            return Err(DomError::Malformed(format!(
                "trailing bytes: {} byte(s) unconsumed",
                self.data.len().saturating_sub(self.pos)
            )));
        }
        Ok(())
    }
}

// ── Traits ────────────────────────────────────────────────────────────────────

/// Canonical serialization trait.
pub trait DomSerialize {
    /// Serialize into a writer.
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError>;

    /// Convenience: serialize to a new Vec<u8>.
    fn to_bytes(&self) -> Result<Vec<u8>, DomError> {
        let mut w = Writer::new();
        self.serialize(&mut w)?;
        Ok(w.finish())
    }
}

/// Canonical deserialization trait.
pub trait DomDeserialize: Sized {
    /// Deserialize from a reader.
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError>;

    /// Convenience: deserialize from a full byte slice.
    /// Rejects trailing bytes automatically.
    fn from_bytes(data: &[u8]) -> Result<Self, DomError> {
        let mut r = Reader::new(data);
        let val = Self::deserialize(&mut r)?;
        r.finish()?;
        Ok(val)
    }
}

// ── Hash256 impls ─────────────────────────────────────────────────────────────

impl DomSerialize for dom_core::Hash256 {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_bytes(self.as_bytes());
        Ok(())
    }
}

impl DomDeserialize for dom_core::Hash256 {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let arr = r.read_array::<32>()?;
        Ok(dom_core::Hash256::from_bytes(arr))
    }
}

// ── BlockHeight / Timestamp / Amount impls ────────────────────────────────────

impl DomSerialize for dom_core::BlockHeight {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u64(self.0);
        Ok(())
    }
}

impl DomDeserialize for dom_core::BlockHeight {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(dom_core::BlockHeight(r.read_u64()?))
    }
}

impl DomSerialize for dom_core::Timestamp {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u64(self.0);
        Ok(())
    }
}

impl DomDeserialize for dom_core::Timestamp {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(dom_core::Timestamp(r.read_u64()?))
    }
}

impl DomSerialize for dom_core::Amount {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u64(self.noms());
        Ok(())
    }
}

impl DomDeserialize for dom_core::Amount {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        dom_core::Amount::from_noms(r.read_u64()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::{Amount, Hash256, COIN_UNIT};

    fn roundtrip<T: DomSerialize + DomDeserialize + PartialEq + std::fmt::Debug>(v: &T) {
        let bytes = v.to_bytes().unwrap();
        let decoded = T::from_bytes(&bytes).unwrap();
        assert_eq!(*v, decoded);
    }

    #[test]
    fn u8_roundtrip() {
        let mut w = Writer::new();
        w.write_u8(0xff);
        let b = w.finish();
        let mut r = Reader::new(&b);
        assert_eq!(r.read_u8().unwrap(), 0xff);
        r.finish().unwrap();
    }

    #[test]
    fn u64_little_endian() {
        let mut w = Writer::new();
        w.write_u64(0x0102_0304_0506_0708);
        let b = w.finish();
        // Little-endian: LSB first
        assert_eq!(b, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn trailing_bytes_rejected() {
        let data = [0u8; 9]; // 8 bytes for u64 + 1 trailing
        let mut r = Reader::new(&data);
        r.read_u64().unwrap();
        assert!(r.finish().is_err());
    }

    #[test]
    fn vec_max_len_enforced() {
        let mut w = Writer::new();
        w.write_u32(100); // claimed length 100
        w.write_bytes(&[0u8; 10]); // only 10 bytes
        let b = w.finish();
        let mut r = Reader::new(&b);
        // max_len = 200 but actual data is short → EOF error
        assert!(r.read_vec(200).is_err());
    }

    #[test]
    fn vec_over_limit_rejected() {
        let mut w = Writer::new();
        w.write_u32(1000); // claimed 1000 but limit is 5
        w.write_bytes(&[0u8; 1000]);
        let b = w.finish();
        let mut r = Reader::new(&b);
        assert!(r.read_vec(5).is_err());
    }

    #[test]
    fn hash256_roundtrip() {
        let h = Hash256::from_bytes([0x42u8; 32]);
        roundtrip(&h);
    }

    #[test]
    fn amount_roundtrip() {
        let a = Amount::from_noms(369 * COIN_UNIT).unwrap();
        roundtrip(&a);
    }

    #[test]
    fn empty_reader_eof() {
        let mut r = Reader::new(&[]);
        assert!(r.read_u8().is_err());
    }
}

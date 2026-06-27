//! proptest-invariante — serialization properties NOT already covered by
//! tests/roundtrip_proptest.rs.
//!
//!   - write_list / read_list COUNT roundtrip (the existing file only covers
//!     scalar/vec roundtrip, never list count).
//!   - endianness stability: the wire bytes of an integer equal its `to_le_bytes`
//!     for ALL inputs (no big-endian / host-endian drift).
//!
//! No production change.

use dom_core::BlockHeight;
use dom_serialization::{Reader, Writer};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// write_list followed by read_list reproduces the same items in order,
    /// for any count up to a generous bound, and the count prefix roundtrips.
    #[test]
    fn list_count_roundtrip(values in proptest::collection::vec(any::<u64>(), 0..300)) {
        let items: Vec<BlockHeight> = values.iter().copied().map(BlockHeight).collect();
        let mut w = Writer::new();
        w.write_list(&items).expect("write_list");
        let buf = w.finish();

        let mut r = Reader::new(&buf);
        let back: Vec<BlockHeight> = r.read_list::<BlockHeight>(1024).expect("read_list");
        prop_assert!(r.finish().is_ok(), "exact read-back leaves no trailing bytes");
        prop_assert_eq!(back.len(), items.len());
        prop_assert_eq!(back, items);
    }

    /// Endianness stability for u16: written bytes == to_le_bytes, for all inputs.
    #[test]
    fn endianness_u16_is_le(v in any::<u16>()) {
        let mut w = Writer::new();
        w.write_u16(v);
        prop_assert_eq!(w.finish(), v.to_le_bytes().to_vec());
    }

    /// Endianness stability for u32.
    #[test]
    fn endianness_u32_is_le(v in any::<u32>()) {
        let mut w = Writer::new();
        w.write_u32(v);
        prop_assert_eq!(w.finish(), v.to_le_bytes().to_vec());
    }

    /// Endianness stability for u64.
    #[test]
    fn endianness_u64_is_le(v in any::<u64>()) {
        let mut w = Writer::new();
        w.write_u64(v);
        prop_assert_eq!(w.finish(), v.to_le_bytes().to_vec());
    }

    /// Endianness stability for u128.
    #[test]
    fn endianness_u128_is_le(v in any::<u128>()) {
        let mut w = Writer::new();
        w.write_u128(v);
        prop_assert_eq!(w.finish(), v.to_le_bytes().to_vec());
    }

    /// Endianness READ stability: an integer encoded as to_le_bytes is read back
    /// to the same value (decoder is LE for all inputs, no host-endian leak).
    #[test]
    fn endianness_read_u64_is_le(v in any::<u64>()) {
        let bytes = v.to_le_bytes();
        let mut r = Reader::new(&bytes);
        prop_assert_eq!(r.read_u64().unwrap(), v);
        prop_assert!(r.finish().is_ok());
    }
}

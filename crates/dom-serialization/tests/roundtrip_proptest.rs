//! F4-equivalent — canonical serialization ROUNDTRIP invariants (proptest).
//!
//! One family, one scaffolding: for every round-trippable type and primitive,
//! `from_bytes(to_bytes(x)) == x`, and the Reader/Writer primitives read back
//! exactly what was written. Plus the negative contract that from_bytes rejects
//! trailing bytes. Collapses all dom-serialization roundtrip vectors into a
//! handful of parameterized properties. No production change.

use dom_core::{Amount, BlockHeight, Hash256, Timestamp};
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn hash256_roundtrip(bytes in proptest::array::uniform32(any::<u8>())) {
        let h = Hash256::from_bytes(bytes); // inherent ctor: [u8;32] -> Hash256
        let encoded = DomSerialize::to_bytes(&h).unwrap();
        // Disambiguate from Hash256's inherent from_bytes([u8;32]).
        let back = <Hash256 as DomDeserialize>::from_bytes(&encoded).unwrap();
        prop_assert_eq!(back, h);
    }

    #[test]
    fn block_height_roundtrip(v in any::<u64>()) {
        let x = BlockHeight(v);
        prop_assert_eq!(BlockHeight::from_bytes(&x.to_bytes().unwrap()).unwrap(), x);
    }

    #[test]
    fn timestamp_roundtrip(v in any::<u64>()) {
        let x = Timestamp(v);
        prop_assert_eq!(Timestamp::from_bytes(&x.to_bytes().unwrap()).unwrap(), x);
    }

    #[test]
    fn amount_roundtrip(v in any::<u64>()) {
        // Only valid Amounts roundtrip; from_noms rejects out-of-range (skip those).
        let a = match Amount::from_noms(v) {
            Ok(a) => a,
            Err(_) => return Ok(()),
        };
        prop_assert_eq!(Amount::from_bytes(&a.to_bytes().unwrap()).unwrap(), a);
    }

    /// Reader/Writer primitive roundtrip: a mixed sequence written then read back
    /// in order must reproduce every value (covers write_u8/u16/u32/u64 +
    /// write_vec/read_vec + read_array).
    #[test]
    fn writer_reader_primitive_roundtrip(
        a in any::<u8>(), b in any::<u16>(), c in any::<u32>(), d in any::<u64>(),
        arr in proptest::array::uniform32(any::<u8>()),
        v in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut w = Writer::new();
        w.write_u8(a);
        w.write_u16(b);
        w.write_u32(c);
        w.write_u64(d);
        w.write_bytes(&arr);
        w.write_vec(&v).expect("write_vec");
        let buf = w.finish();

        let mut r = Reader::new(&buf);
        prop_assert_eq!(r.read_u8().unwrap(), a);
        prop_assert_eq!(r.read_u16().unwrap(), b);
        prop_assert_eq!(r.read_u32().unwrap(), c);
        prop_assert_eq!(r.read_u64().unwrap(), d);
        prop_assert_eq!(r.read_array::<32>().unwrap(), arr);
        prop_assert_eq!(r.read_vec(4096).unwrap(), v);
        prop_assert!(r.finish().is_ok(), "no trailing bytes after exact read-back");
    }

    /// Negative: from_bytes must REJECT trailing bytes (canonical, no slack).
    #[test]
    fn from_bytes_rejects_trailing_bytes(v in any::<u64>(), tail in 1u8..=8) {
        let x = BlockHeight(v);
        let mut bytes = x.to_bytes().unwrap();
        bytes.extend(std::iter::repeat(0u8).take(tail as usize));
        prop_assert!(BlockHeight::from_bytes(&bytes).is_err(), "trailing bytes must be rejected");
    }
}

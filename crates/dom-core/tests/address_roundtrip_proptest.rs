//! F4-equivalent — bech32m address roundtrip invariant (proptest).
//!
//! Strengthens the two example-based roundtrip tests in src/address.rs into a
//! randomized property: for ANY compressed-key-shaped 33-byte payload and
//! EITHER network,
//! `decode(encode(addr)) == addr`. Algebraic/codec invariant over valid inputs
//! (negative/parse rejection is covered by src/address.rs unit tests). No
//! production change.

use dom_core::Address;
use proptest::prelude::*;

fn payload_strategy() -> impl Strategy<Value = [u8; 33]> {
    proptest::collection::vec(any::<u8>(), 33).prop_map(|v| {
        let mut a = [0u8; 33];
        a.copy_from_slice(&v);
        a[0] = if a[1] & 1 == 0 { 0x02 } else { 0x03 };
        a
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn address_bech32m_roundtrip(payload in payload_strategy(), is_mainnet in any::<bool>()) {
        let addr = Address::new(payload, is_mainnet);
        let encoded = addr.encode();
        let decoded = Address::decode(&encoded).expect("address must decode its own encoding");
        prop_assert_eq!(decoded, addr);
    }
}

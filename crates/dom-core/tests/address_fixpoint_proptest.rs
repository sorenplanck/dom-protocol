//! dom-shield — `Address` canonical-fixpoint property (proptest).
//!
//! Distinct from `address_roundtrip_proptest.rs` (which proves
//! decode(encode(addr)) == addr at the STRUCT level). This proves the encoder's
//! output is a fixpoint of the STRING transform encode∘decode: re-encoding a
//! decoded canonical address reproduces the byte-identical string, and that
//! canonical encoder output is always all-lowercase (BIP-350 canonical form).
//!
//! A failure here means the encoder is non-canonical (two strings for one
//! address, or a non-lowercase canonical form) — an address-malleability /
//! display-inconsistency vector. Public API only; no production change.

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

    /// Canonical-fixpoint: encode(decode(encode(addr))) == encode(addr), and the
    /// canonical string is strictly lowercase ASCII (BIP-350 canonical spelling).
    #[test]
    fn address_encode_is_canonical_fixpoint(payload in payload_strategy(), is_mainnet in any::<bool>()) {
        let addr = Address::new(payload, is_mainnet);
        let s1 = addr.encode();

        // Canonical output must be all-lowercase (no uppercase chars at all).
        prop_assert!(
            s1.chars().all(|c| !c.is_ascii_uppercase()),
            "canonical address must be all-lowercase: {}", s1
        );

        let decoded = Address::decode(&s1).expect("canonical address must decode");
        let s2 = decoded.encode();
        prop_assert_eq!(s1, s2, "encode is not a fixpoint of decode∘encode");
    }
}

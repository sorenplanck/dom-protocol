//! dom-shield — dom-store proptest-invariante (extends F4f, no overlap).
//!
//! F4f (persisted_roundtrip_proptest.rs) proves `from_bytes(to_bytes(x))==x`
//! over WELL-FORMED records. It does NOT exercise arbitrary/hostile byte
//! strings nor the maturity boundary. This file fills exactly those gaps:
//!
//!  * UtxoEntry::from_bytes / PeerAddr::from_bytes are TOTAL over arbitrary
//!    bytes — every input is either a clean Err or a non-panicking Ok. This is
//!    the property the fuzz-panic family would assert; recorded here as proptest
//!    because the parsers are fixed-offset and bounded (COVERAGE #8) so a full
//!    cargo-fuzz target would add coverage breadth but not a new property.
//!  * is_mature_for boundary: mature ⇔ current - created >= maturity, with
//!    saturating semantics, for non-overflowing inputs.
//!
//! No production change.

use dom_core::COINBASE_MATURITY;
use dom_store::{PeerAddr, UtxoEntry};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// UtxoEntry::from_bytes is total: only records with the nine-byte fixed
    /// prefix and a canonical 0/1 coinbase flag parse; every other byte string
    /// is rejected without panicking.
    #[test]
    fn utxo_from_bytes_total_over_arbitrary_bytes(buf in proptest::collection::vec(any::<u8>(), 0..1200)) {
        match UtxoEntry::from_bytes(&buf) {
            Ok(e) => {
                prop_assert!(buf.len() >= 9, "Ok only for >= 9 bytes");
                prop_assert!(buf[8] <= 1, "Ok only for canonical flag bytes");
                prop_assert_eq!(e.proof.len(), buf.len() - 9, "proof is exactly the tail");
            }
            Err(_) => {
                prop_assert!(buf.len() < 9 || buf[8] > 1, "Err only for malformed prefix or flag");
            }
        }
    }

    /// PeerAddr::from_bytes accepts exactly its canonical 12-byte encoding and
    /// rejects every truncated or trailing-byte variant.
    #[test]
    fn peer_from_bytes_total_over_arbitrary_bytes(
        addr in "[a-z0-9.:]{0,40}",
        buf in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        match PeerAddr::from_bytes(addr, &buf) {
            Ok(_) => prop_assert_eq!(buf.len(), 12),
            Err(_) => prop_assert_ne!(buf.len(), 12),
        }
    }

    /// is_mature_for boundary property (non-overflowing inputs): a coinbase is
    /// mature exactly when current_height - block_height >= maturity, under
    /// saturating subtraction. Bounds keep block_height + maturity from
    /// overflowing so this property test stays orthogonal to RED-DS-STORE-001.
    #[test]
    fn is_mature_for_boundary_property(
        block_height in 0u64..1_000_000,
        delta in 0u64..1_000_000,
        maturity in 0u64..1_000_000,
    ) {
        let current = block_height.saturating_add(delta);
        let e = UtxoEntry { block_height, is_coinbase: true, proof: vec![] };
        let expected = current.saturating_sub(block_height) >= maturity;
        prop_assert_eq!(e.is_mature_for(current, maturity), expected);
    }

    /// Non-coinbase outputs are mature unconditionally, for any heights/maturity.
    #[test]
    fn non_coinbase_always_mature(
        block_height in any::<u64>(),
        current in any::<u64>(),
        maturity in any::<u64>(),
    ) {
        let e = UtxoEntry { block_height, is_coinbase: false, proof: vec![] };
        prop_assert!(e.is_mature_for(current, maturity));
        let _ = COINBASE_MATURITY;
    }
}

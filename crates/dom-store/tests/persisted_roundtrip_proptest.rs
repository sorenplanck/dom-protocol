//! F4-equivalent — persisted-state ROUNDTRIP invariants (proptest).
//!
//! Correctness of on-disk recovery: `from_bytes(to_bytes(x))` must reproduce x
//! for every persisted record. This is distinct from the fuzz-panic family
//! (dom-store parsers are bounded / out-of-scope for fuzz, COVERAGE #8): here we
//! prove the codec is LOSSLESS, so a clean shutdown reloads identically. Collapses
//! the UtxoEntry/PeerAddr serialization vectors. No production change.

use dom_store::{PeerAddr, UtxoEntry};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn utxo_entry_roundtrip(
        block_height in any::<u64>(),
        is_coinbase in any::<bool>(),
        proof in proptest::collection::vec(any::<u8>(), 0..800),
    ) {
        let e = UtxoEntry { block_height, is_coinbase, proof: proof.clone() };
        let back = UtxoEntry::from_bytes(&e.to_bytes()).expect("utxo entry must roundtrip");
        prop_assert_eq!(back.block_height, block_height);
        prop_assert_eq!(back.is_coinbase, is_coinbase);
        prop_assert_eq!(back.proof, proof);
    }

    #[test]
    fn peer_addr_roundtrip(
        addr in "[a-z0-9.:\\[\\]]{1,48}",
        last_seen in any::<u64>(),
        failures in any::<u32>(),
    ) {
        let p = PeerAddr { addr: addr.clone(), last_seen, failures };
        // to_bytes encodes only last_seen+failures; addr is the key, passed back in.
        let back = PeerAddr::from_bytes(addr.clone(), &p.to_bytes()).expect("peer addr must roundtrip");
        prop_assert_eq!(back.addr, addr);
        prop_assert_eq!(back.last_seen, last_seen);
        prop_assert_eq!(back.failures, failures);
    }
}

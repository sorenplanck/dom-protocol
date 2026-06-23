//! F4-equivalent — P2P wire-message ROUNDTRIP invariants (proptest).
//!
//! Network-controlled surface: every payload that a peer sends must survive
//! `from_bytes(to_bytes(x)) == x`. The fuzz-panic family (11 dom-wire fuzz
//! targets) proves no crash on hostile input; this proves the codec is LOSSLESS
//! on well-formed input (no field dropped/aliased). Sizes are kept well under the
//! protocol caps (locator 32, getblockdata 128, headers 2000). No production change.

use dom_wire::message::{
    BlockPayload, Command, GetBlockDataPayload, GetHeadersPayload, HeadersPayload, HelloPayload,
    WireMessage,
};
use proptest::prelude::*;

fn hash32() -> impl Strategy<Value = [u8; 32]> {
    proptest::array::uniform32(any::<u8>())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn hello_payload_roundtrip(
        version in any::<u32>(),
        network_magic in any::<u32>(),
        chain_id in hash32(),
        best_height in any::<u64>(),
        best_hash in hash32(),
        user_agent in "[ -~]{0,200}",
        local_timestamp in any::<u64>(),
    ) {
        let p = HelloPayload {
            version, network_magic, chain_id, best_height, best_hash,
            user_agent: user_agent.clone(), local_timestamp,
        };
        let back = HelloPayload::from_bytes(&p.to_bytes().unwrap()).expect("hello roundtrip");
        prop_assert_eq!(back.version, version);
        prop_assert_eq!(back.network_magic, network_magic);
        prop_assert_eq!(back.chain_id, chain_id);
        prop_assert_eq!(back.best_height, best_height);
        prop_assert_eq!(back.best_hash, best_hash);
        prop_assert_eq!(back.user_agent, user_agent);
        prop_assert_eq!(back.local_timestamp, local_timestamp);
    }

    #[test]
    fn get_headers_payload_roundtrip(
        locator_hashes in proptest::collection::vec(hash32(), 0..16),
        stop_hash in hash32(),
    ) {
        let p = GetHeadersPayload { locator_hashes: locator_hashes.clone(), stop_hash };
        let back = GetHeadersPayload::from_bytes(&p.to_bytes().unwrap()).expect("getheaders roundtrip");
        prop_assert_eq!(back.locator_hashes, locator_hashes);
        prop_assert_eq!(back.stop_hash, stop_hash);
    }

    #[test]
    fn get_block_data_payload_roundtrip(hashes in proptest::collection::vec(hash32(), 0..32)) {
        let p = GetBlockDataPayload { hashes: hashes.clone() };
        let back = GetBlockDataPayload::from_bytes(&p.to_bytes().unwrap()).expect("getblockdata roundtrip");
        prop_assert_eq!(back.hashes, hashes);
    }

    #[test]
    fn headers_payload_roundtrip(
        headers in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..80), 0..16),
    ) {
        let p = HeadersPayload { headers: headers.clone() };
        let back = HeadersPayload::from_bytes(&p.to_bytes().unwrap()).expect("headers roundtrip");
        prop_assert_eq!(back.headers, headers);
    }

    #[test]
    fn block_payload_roundtrip(block_bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let p = BlockPayload { block_bytes: block_bytes.clone() };
        let back = BlockPayload::from_bytes(&p.to_bytes().unwrap()).expect("block roundtrip");
        prop_assert_eq!(back.block_bytes, block_bytes);
    }

    #[test]
    fn wire_message_roundtrip(
        magic in any::<u32>(),
        cmd_idx in 0usize..10,
        payload in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let command = [
            Command::Hello, Command::Ping, Command::Pong, Command::Inv, Command::GetHeaders,
            Command::Headers, Command::GetBlock, Command::Block, Command::Tx, Command::GetAddr,
        ][cmd_idx];
        let m = WireMessage { magic, command, payload: payload.clone() };
        let back = WireMessage::from_bytes(&m.to_bytes(), magic).expect("wire message roundtrip");
        prop_assert_eq!(back.magic, magic);
        prop_assert_eq!(back.command, command);
        prop_assert_eq!(back.payload, payload);
    }
}

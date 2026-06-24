#![no_main]
//! Fuzz target: the block-decode path the node runs on peer-supplied bytes.
//!
//! `node.rs::decode_relay_block` and `decode_ibd_block_response` are private but
//! are thin wrappers over exactly this sequence:
//!     BlockPayload::from_bytes(payload) -> Block::from_bytes(payload.block_bytes)
//! followed (IBD path) by a header re-hash + expected-hash compare. This target
//! reproduces that node-side dispatch over arbitrary WireMessage Block payloads
//! to ensure neither decode step nor the re-hash panics on hostile input.
use dom_serialization::{DomDeserialize, DomSerialize};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Relay-block path: parse the payload wrapper, then the inner block.
    if let Ok(payload) = dom_wire::message::BlockPayload::from_bytes(data) {
        if let Ok(block) = dom_consensus::Block::from_bytes(&payload.block_bytes) {
            // IBD path re-hashes the header and compares against an expected
            // hash — exercise the serialize+hash step the node performs.
            if let Ok(header_bytes) = block.header.to_bytes() {
                let _ = dom_crypto::hash::blake2b_256(&header_bytes);
            }
        }
    }
});

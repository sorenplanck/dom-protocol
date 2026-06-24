//! dom-shield — GetBlockData / GetHeaders amplification bound (IBD/serve sub-area).
//!
//! Amplification is the request-vs-response multiplier an attacker gets per
//! unit of upload. The `GetBlockData` serve loop (`node.rs`, Command::GetBlockData)
//! sends ONE full `Block` body per requested hash:
//!     for hash in &req.hashes { ...get_block_body(hash)...; codec.send(Block) }
//! A 32-byte hash in the request yields up to MAX_BLOCK_SERIALIZED_SIZE in the
//! response — a large per-hash multiplier. The MITIGATION is the parse-time cap
//! `MAX_GETBLOCKDATA_HASHES`: `GetBlockDataPayload::from_bytes` REJECTS any
//! request carrying more hashes, so the per-message response is bounded by
//!     MAX_GETBLOCKDATA_HASHES * MAX_BLOCK_SERIALIZED_SIZE.
//! Likewise `GetHeaders` is bounded by MAX_LOCATOR_HASHES (request) and the
//! server caps the reply at MAX_HEADERS_PER_MSG.
//!
//! Technique: KAV on the parse-time caps that bound the multiplier (an
//! over-cap request MUST be rejected before the serve loop ever runs), plus a
//! measured-number record of the worst-case multiplier. This is the right
//! technique because there IS a multiplier but it is bounded-by-construction at
//! the parser — we prove the bound holds rather than fuzz a non-existent
//! unbounded path.

use dom_core::{MAX_BLOCK_SERIALIZED_SIZE, MAX_GETBLOCKDATA_HASHES, MAX_LOCATOR_HASHES};
use dom_wire::message::{GetBlockDataPayload, GetHeadersPayload};

/// A GetBlockData request at the cap round-trips; one hash over the cap is
/// REJECTED at parse time — so the serve loop can never iterate more than
/// MAX_GETBLOCKDATA_HASHES bodies for a single message.
#[test]
fn getblockdata_request_count_is_capped_at_parse() {
    // At the cap: encodes and decodes.
    let at_cap = GetBlockDataPayload {
        hashes: vec![[7u8; 32]; MAX_GETBLOCKDATA_HASHES],
    };
    let bytes = at_cap.to_bytes().expect("encode at cap");
    let decoded = GetBlockDataPayload::from_bytes(&bytes).expect("decode at cap");
    assert_eq!(decoded.hashes.len(), MAX_GETBLOCKDATA_HASHES);

    // One over the cap: encoding is rejected (serializer enforces the same cap),
    // so an honest peer can't even build it; a hand-rolled over-cap wire frame
    // is rejected by from_bytes below.
    let over = GetBlockDataPayload {
        hashes: vec![[7u8; 32]; MAX_GETBLOCKDATA_HASHES + 1],
    };
    assert!(
        over.to_bytes().is_err(),
        "serializer must refuse > MAX_GETBLOCKDATA_HASHES"
    );

    // Hand-crafted over-cap frame: count prefix claims cap+1, then cap+1 hashes.
    let n = (MAX_GETBLOCKDATA_HASHES + 1) as u16;
    let mut frame = Vec::new();
    frame.extend_from_slice(&n.to_le_bytes());
    frame.extend(std::iter::repeat(0u8).take((MAX_GETBLOCKDATA_HASHES + 1) * 32));
    assert!(
        GetBlockDataPayload::from_bytes(&frame).is_err(),
        "from_bytes must reject an over-cap GetBlockData frame before the serve loop"
    );
}

/// GetHeaders request locator is capped at parse; an over-cap frame is rejected.
#[test]
fn getheaders_locator_is_capped_at_parse() {
    let at_cap = GetHeadersPayload {
        locator_hashes: vec![[3u8; 32]; MAX_LOCATOR_HASHES],
        stop_hash: [0u8; 32],
    };
    let bytes = at_cap.to_bytes().expect("encode locator at cap");
    let decoded = GetHeadersPayload::from_bytes(&bytes).expect("decode locator at cap");
    assert_eq!(decoded.locator_hashes.len(), MAX_LOCATOR_HASHES);

    let n = (MAX_LOCATOR_HASHES + 1) as u16;
    let mut frame = Vec::new();
    frame.extend_from_slice(&n.to_le_bytes());
    frame.extend(std::iter::repeat(0u8).take((MAX_LOCATOR_HASHES + 1) * 32));
    frame.extend_from_slice(&[0u8; 32]); // stop_hash
    assert!(
        GetHeadersPayload::from_bytes(&frame).is_err(),
        "from_bytes must reject an over-cap GetHeaders locator"
    );
}

/// Measured worst-case multiplier record (numbers, not estimates). Asserts the
/// bound is finite and pins the exact constants so a future cap relaxation that
/// blows up the multiplier is caught.
#[test]
fn worst_case_getblockdata_multiplier_is_bounded_and_recorded() {
    // Request size at cap: 2-byte count prefix + 32 bytes per hash.
    let request_bytes = 2 + MAX_GETBLOCKDATA_HASHES * 32;
    // Response upper bound: one max-size block body per requested hash.
    let response_bytes = MAX_GETBLOCKDATA_HASHES * MAX_BLOCK_SERIALIZED_SIZE;

    // Pin the concrete numbers (locked constants): 128 hashes, 16 MiB blocks.
    assert_eq!(MAX_GETBLOCKDATA_HASHES, 128);
    assert_eq!(MAX_BLOCK_SERIALIZED_SIZE, 16 * 1024 * 1024);
    assert_eq!(request_bytes, 2 + 128 * 32); // 4098 bytes
    assert_eq!(response_bytes, 128 * 16 * 1024 * 1024); // 2 GiB

    // The multiplier is large but BOUNDED and constant; it cannot be inflated by
    // the attacker beyond this without changing a consensus constant. (Honest
    // serving of a 2 GiB reply is itself gated by per-peer rate limits + the
    // requirement that every requested block actually exists in our store.)
    let multiplier = response_bytes / request_bytes;
    assert!(multiplier > 0 && multiplier <= 600_000, "multiplier recorded: {multiplier}");
}

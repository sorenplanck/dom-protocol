//! KAV-negativo — decoders MUST reject malformed / out-of-bound inputs.
//!
//! RFC-0002 negative contracts:
//!   - Trailing bytes are consensus-invalid → `finish()` / `from_bytes` reject.
//!   - `Amount` > MAX_SUPPLY_NOMS must be rejected on decode.
//!   - `read_vec`  : declared length > max_len rejected.
//!   - `read_list` : declared count  > max_count rejected.
//!   - Short buffers (declared len/count exceeds available bytes) → EOF error.
//!
//! No production change.

use dom_core::{Amount, BlockHeight, Hash256};
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};

// ── Trailing-byte rejection (extends the in-crate trailing test) ────────────────

#[test]
fn finish_rejects_one_trailing_byte() {
    let mut buf = BlockHeight(7).to_bytes().unwrap(); // 8 bytes
    buf.push(0x00); // +1 trailing
    let mut r = Reader::new(&buf);
    let _ = r.read_u64().unwrap();
    assert!(r.finish().is_err(), "single trailing byte must be rejected");
}

#[test]
fn from_bytes_rejects_trailing_on_hash256() {
    let mut buf = DomSerialize::to_bytes(&Hash256::from_bytes([1u8; 32])).unwrap();
    buf.push(0xFF);
    assert!(<Hash256 as DomDeserialize>::from_bytes(&buf).is_err());
}

#[test]
fn from_bytes_rejects_trailing_on_amount() {
    let mut buf = Amount::from_noms(1234).unwrap().to_bytes().unwrap();
    buf.extend_from_slice(&[0u8; 4]);
    assert!(Amount::from_bytes(&buf).is_err());
}

// ── Amount > MAX_SUPPLY rejected on DECODE ──────────────────────────────────────

#[test]
fn amount_decode_above_max_supply_rejected() {
    // Craft the wire form of MAX_SUPPLY_NOMS + 1 directly (u64 LE) and confirm
    // the deserializer (which routes through from_noms) rejects it.
    let over = dom_core::constants::MAX_SUPPLY_NOMS
        .checked_add(1)
        .expect("MAX_SUPPLY_NOMS+1 fits in u64");
    let bytes = over.to_le_bytes().to_vec();
    let decoded = Amount::from_bytes(&bytes);
    assert!(
        decoded.is_err(),
        "Amount decode of MAX_SUPPLY+1 must be rejected, got {decoded:?}"
    );
}

#[test]
fn amount_decode_u64_max_rejected() {
    let bytes = u64::MAX.to_le_bytes().to_vec();
    assert!(Amount::from_bytes(&bytes).is_err());
}

#[test]
fn amount_decode_exact_max_supply_accepted() {
    // Boundary the other way: exactly MAX_SUPPLY must decode (no off-by-one).
    let bytes = dom_core::constants::MAX_SUPPLY_NOMS.to_le_bytes().to_vec();
    let a = Amount::from_bytes(&bytes).expect("exactly MAX_SUPPLY must decode");
    assert_eq!(a.noms(), dom_core::constants::MAX_SUPPLY_NOMS);
}

// ── read_vec: declared length over limit rejected ───────────────────────────────

#[test]
fn read_vec_len_over_max_rejected() {
    let mut w = Writer::new();
    w.write_u32(1000); // declared 1000
    w.write_bytes(&[0u8; 1000]); // payload present so this is purely the limit check
    let buf = w.finish();
    let mut r = Reader::new(&buf);
    assert!(r.read_vec(5).is_err(), "len 1000 > max 5 must be rejected");
}

#[test]
fn read_vec_len_at_max_accepted() {
    // Boundary: len == max_len is allowed (the guard is strict `>`).
    let mut w = Writer::new();
    w.write_u32(5);
    w.write_bytes(&[0xAA; 5]);
    let buf = w.finish();
    let mut r = Reader::new(&buf);
    let v = r.read_vec(5).expect("len == max must be accepted");
    assert_eq!(v, vec![0xAA; 5]);
    r.finish().unwrap();
}

#[test]
fn read_vec_short_buffer_eof() {
    // Declared length within limit but buffer too short → EOF, not partial decode.
    let mut w = Writer::new();
    w.write_u32(100); // declared 100
    w.write_bytes(&[0u8; 10]); // only 10 available
    let buf = w.finish();
    let mut r = Reader::new(&buf);
    assert!(r.read_vec(200).is_err(), "short buffer must EOF, not partial");
}

// ── read_list: declared count over limit rejected ───────────────────────────────

#[test]
fn read_list_count_over_max_rejected() {
    let mut w = Writer::new();
    w.write_u32(1000); // declared 1000 items
    let buf = w.finish();
    let mut r = Reader::new(&buf);
    let res = r.read_list::<BlockHeight>(5);
    assert!(res.is_err(), "count 1000 > max 5 must be rejected");
}

#[test]
fn read_list_short_buffer_eof() {
    // Declared count within limit but not enough bytes for the items.
    // 3 BlockHeights declared (count <= max) but only 1 item of payload present.
    let mut w = Writer::new();
    w.write_u32(3); // declared 3 items
    w.write_u64(42); // only 1 item's worth of bytes
    let buf = w.finish();
    let mut r = Reader::new(&buf);
    let res = r.read_list::<BlockHeight>(16);
    assert!(res.is_err(), "missing item bytes must EOF, not partial decode");
}

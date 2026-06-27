//! KAV-drift-congelado / KAV-conformância — GOLDEN byte-vector freeze.
//!
//! Doubles as the XDIFF cross-version drift guard: these are the exact wire
//! bytes mandated by DOM_RFC_0002 (little-endian integers, u32 length prefix).
//! The EXPECTED bytes here are derived by reasoning from the SPEC LAYOUT, not
//! captured from the code's output — so any format drift (endianness flip,
//! prefix-width change, padding) in either the writer OR the reader is caught.
//!
//! Spec layout (RFC-0002):
//!   - All integers little-endian (LSB first).
//!   - `write_vec`  : u32 LE length prefix, then raw bytes.
//!   - `write_list` : u32 LE count prefix, then each item serialized in order.
//!   - Hash256      : 32 raw bytes, NO length prefix.
//!   - BlockHeight / Timestamp / Amount : a single u64 LE (8 bytes).
//!
//! No production change. Read-only over behavior.

use dom_core::{Amount, BlockHeight, Hash256, Timestamp, COIN_UNIT};
use dom_serialization::{DomSerialize, Reader, Writer};

// ── Primitive integer golden bytes (Writer side) ───────────────────────────────

#[test]
fn golden_write_u8() {
    let mut w = Writer::new();
    w.write_u8(0xAB);
    assert_eq!(w.finish(), vec![0xAB]);
}

#[test]
fn golden_write_u16_le() {
    // 0x1234 → LSB first → [0x34, 0x12]
    let mut w = Writer::new();
    w.write_u16(0x1234);
    assert_eq!(w.finish(), vec![0x34, 0x12]);
}

#[test]
fn golden_write_u32_le() {
    // 0x1234_5678 → [0x78, 0x56, 0x34, 0x12]
    let mut w = Writer::new();
    w.write_u32(0x1234_5678);
    assert_eq!(w.finish(), vec![0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn golden_write_u64_le() {
    // 0x0102_0304_0506_0708 → LSB first
    let mut w = Writer::new();
    w.write_u64(0x0102_0304_0506_0708);
    assert_eq!(
        w.finish(),
        vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    );
}

#[test]
fn golden_write_u128_le() {
    // 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10 → LSB first
    let mut w = Writer::new();
    w.write_u128(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10);
    assert_eq!(
        w.finish(),
        vec![
            0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
            0x02, 0x01,
        ]
    );
}

// ── write_vec golden bytes: u32 LE length prefix + payload ──────────────────────

#[test]
fn golden_write_vec_layout() {
    let mut w = Writer::new();
    w.write_vec(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    // len = 4 → u32 LE [0x04,0x00,0x00,0x00], then the 4 payload bytes.
    assert_eq!(
        w.finish(),
        vec![0x04, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]
    );
}

#[test]
fn golden_write_vec_empty() {
    let mut w = Writer::new();
    w.write_vec(&[]).unwrap();
    // len = 0 → u32 LE zeros, no payload.
    assert_eq!(w.finish(), vec![0x00, 0x00, 0x00, 0x00]);
}

// ── write_list golden bytes: u32 LE count prefix + items in order ───────────────

#[test]
fn golden_write_list_layout() {
    // Three BlockHeights: 1, 2, 0x0100. Each is u64 LE (8 bytes).
    let items = vec![BlockHeight(1), BlockHeight(2), BlockHeight(0x0100)];
    let mut w = Writer::new();
    w.write_list(&items).unwrap();
    let mut expected = vec![0x03, 0x00, 0x00, 0x00]; // count = 3 (u32 LE)
    expected.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0, 0]); // 1
    expected.extend_from_slice(&[0x02, 0, 0, 0, 0, 0, 0, 0]); // 2
    expected.extend_from_slice(&[0x00, 0x01, 0, 0, 0, 0, 0, 0]); // 0x0100
    assert_eq!(w.finish(), expected);
}

#[test]
fn golden_write_list_empty() {
    let items: Vec<BlockHeight> = Vec::new();
    let mut w = Writer::new();
    w.write_list(&items).unwrap();
    assert_eq!(w.finish(), vec![0x00, 0x00, 0x00, 0x00]); // count = 0
}

// ── Domain-type golden bytes (full to_bytes wire form) ──────────────────────────

#[test]
fn golden_hash256_wire() {
    // 32 raw bytes, NO length prefix. Distinct pattern so a truncation/padding
    // drift is visible.
    let mut raw = [0u8; 32];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    let h = Hash256::from_bytes(raw);
    let bytes = DomSerialize::to_bytes(&h).unwrap();
    assert_eq!(
        bytes.len(),
        32,
        "Hash256 wire form must be exactly 32 bytes"
    );
    assert_eq!(bytes, raw.to_vec());
}

#[test]
fn golden_block_height_wire() {
    // 0x0000_0000_DEAD_BEEF → u64 LE
    let h = BlockHeight(0x0000_0000_DEAD_BEEF);
    let bytes = h.to_bytes().unwrap();
    assert_eq!(bytes, vec![0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn golden_timestamp_wire() {
    // 1_700_000_000 (a real-ish unix ts) → u64 LE
    let t = Timestamp(1_700_000_000);
    let bytes = t.to_bytes().unwrap();
    // 1_700_000_000 = 0x6553_F100
    assert_eq!(bytes, vec![0x00, 0xF1, 0x53, 0x65, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn golden_amount_wire() {
    // 369 * COIN_UNIT noms → u64 LE.
    let noms = 369u64 * COIN_UNIT; // 369 * 100_000_000 = 36_900_000_000 = 0x8_9769_5100
    let a = Amount::from_noms(noms).unwrap();
    let bytes = a.to_bytes().unwrap();
    // 36_900_000_000 = 0x0000_0008_9769_5100 → LE = 00 51 69 97 08 00 00 00
    assert_eq!(bytes, vec![0x00, 0x51, 0x69, 0x97, 0x08, 0x00, 0x00, 0x00]);
    // Sanity: independently confirm the LE decomposition equals the value.
    let reconstructed = u64::from_le_bytes(bytes.clone().try_into().unwrap());
    assert_eq!(reconstructed, noms);
}

// ── Reader-side golden conformance: bytes → value (decode the frozen form) ───────

#[test]
fn golden_read_back_primitives_le() {
    // Feed the exact spec bytes and confirm the Reader decodes them LE.
    let mut r = Reader::new(&[0x34, 0x12]);
    assert_eq!(r.read_u16().unwrap(), 0x1234);
    r.finish().unwrap();

    let mut r = Reader::new(&[0x78, 0x56, 0x34, 0x12]);
    assert_eq!(r.read_u32().unwrap(), 0x1234_5678);
    r.finish().unwrap();

    let mut r = Reader::new(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    assert_eq!(r.read_u64().unwrap(), 0x0102_0304_0506_0708);
    r.finish().unwrap();
}

#[test]
fn golden_read_vec_from_frozen_bytes() {
    // [len=4 LE][DE AD BE EF]
    let buf = [0x04, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    let mut r = Reader::new(&buf);
    assert_eq!(r.read_vec(16).unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    r.finish().unwrap();
}

//! Hand-rolled canonical ABI codec over 32-byte words.
//!
//! Why hand-rolled: I14 forbids treating a serde-style deserializer as a
//! cryptographic wire format and forbids allocating before a cap has been
//! validated. A generic ABI library gives neither guarantee cheaply, and the
//! surface this adapter needs is tiny — every type the `ConditionLockV2` API
//! touches (`bytes32`, `address`, `uintN`, and a struct made only of those) is
//! *static*, so ABI encoding degenerates into "concatenate 32-byte words".
//!
//! Canonicity rules enforced on decode:
//!
//! - the byte length must be an exact multiple of 32 and must match the exact
//!   word count the caller declared — **trailing bytes are never ignored**;
//!   extra data is a rejection, not a truncation;
//! - `address` must have its 12 high bytes zero;
//! - `uint8` / `uint16` / `uint32` / `uint64` must have all bytes above their
//!   width zero;
//! - `bool` must be exactly `0` or `1`;
//! - the word count is checked against [`MAX_ABI_WORDS`] *before* any `Vec` is
//!   allocated.
//!
//! Everything is big-endian, exactly as the EVM lays it out.

use counterparty_api::AdapterError;
use sha3::{Digest, Keccak256};

use crate::error::{check_cap, Result};

/// One ABI word.
pub type Word = [u8; 32];

/// Maximum number of 32-byte words this codec will ever materialise.
///
/// Sized well above anything the `ConditionLockV2` surface produces (the widest
/// frame is the 10-word `LockTerms` struct) while still bounding a hostile
/// endpoint that answers a log query with megabytes of `data` (I14).
pub const MAX_ABI_WORDS: usize = 64;

/// Maximum accepted length, in bytes, of a log `data` field.
pub const MAX_LOG_DATA_BYTES: usize = MAX_ABI_WORDS * 32;

/// Maximum accepted length, in bytes, of calldata produced or parsed here.
pub const MAX_CALLDATA_BYTES: usize = 4 + MAX_ABI_WORDS * 32;

/// Maximum number of topics accepted on a log (EVM hard limit is 4).
pub const MAX_LOG_TOPICS: usize = 4;

/// keccak256 — the EVM hash, used for topic0, selectors, the codehash check and
/// the §1 binding derivation.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut w = [0u8; 32];
    w.copy_from_slice(&out);
    w
}

/// Canonical Solidity event signature of `LockOpened`.
pub const SIG_LOCK_OPENED: &str =
    "LockOpened(bytes32,bytes32,address,address,address,uint256,address,uint64)";
/// Canonical Solidity event signature of `Claimed`.
pub const SIG_CLAIMED: &str = "Claimed(bytes32,bytes32,address,uint256)";
/// Canonical Solidity event signature of `Refunded`.
pub const SIG_REFUNDED: &str = "Refunded(bytes32,bytes32,address,uint256)";
/// Canonical Solidity event signature of `PayoutDeferred`.
pub const SIG_PAYOUT_DEFERRED: &str = "PayoutDeferred(address,address,uint256)";
/// Canonical Solidity event signature of `Withdrawal`.
pub const SIG_WITHDRAWAL: &str = "Withdrawal(address,address,address,uint256)";

/// Canonical signature of `open(LockTerms)`, with the struct flattened into the
/// tuple form the ABI selector is computed over.
pub const SIG_OPEN: &str =
    "open((bytes32,uint8,bytes32,bytes32,bytes32,address,uint256,address,address,uint64))";
/// Canonical signature of `claim(bytes32,uint256)`.
pub const SIG_CLAIM: &str = "claim(bytes32,uint256)";
/// Canonical signature of `refund(bytes32)`.
pub const SIG_REFUND: &str = "refund(bytes32)";

/// `topic0` of an event: keccak256 over its canonical signature string.
pub fn event_topic0(signature: &str) -> [u8; 32] {
    keccak256(signature.as_bytes())
}

/// 4-byte function selector: the first four bytes of keccak256 over the
/// canonical signature string.
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// Number of non-indexed data words carried by `LockOpened`
/// (`beneficiary`, `asset`, `amount`, `adaptorAddress`, `deadline`).
pub const LOCK_OPENED_DATA_WORDS: usize = 5;
/// Number of non-indexed data words carried by `Claimed` (`t`).
pub const CLAIMED_DATA_WORDS: usize = 1;
/// Number of non-indexed data words carried by `Refunded` (`amount`).
pub const REFUNDED_DATA_WORDS: usize = 1;
/// Topic count of `LockOpened`, `Claimed` and `Refunded`: `topic0` plus three
/// indexed parameters.
pub const SETTLEMENT_EVENT_TOPICS: usize = 4;

// ---------------------------------------------------------------------------
// encoding
// ---------------------------------------------------------------------------

/// Encodes a `bytes32` (identity — it is already a word).
pub fn word_bytes32(v: [u8; 32]) -> Word {
    v
}

/// Encodes an `address` (right-aligned in a 32-byte word).
pub fn word_address(v: [u8; 20]) -> Word {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&v);
    w
}

/// Encodes a `uint8`.
pub fn word_u8(v: u8) -> Word {
    let mut w = [0u8; 32];
    w[31] = v;
    w
}

/// Encodes a `uint16`.
pub fn word_u16(v: u16) -> Word {
    let mut w = [0u8; 32];
    w[30..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Encodes a `uint64`.
pub fn word_u64(v: u64) -> Word {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Encodes a `uint128` into a `uint256` word.
pub fn word_u128(v: u128) -> Word {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// Encodes a `uint256` already held as 32 big-endian bytes.
pub fn word_u256(v: [u8; 32]) -> Word {
    v
}

/// Concatenates words into an `abi.encode` payload.
///
/// Every type in this crate's surface is static, so `abi.encode` of a list of
/// values is exactly the concatenation of their words — there is no head/tail
/// split and no offset to get wrong.
pub fn concat_words(words: &[Word]) -> Result<Vec<u8>> {
    check_cap(words.len(), MAX_ABI_WORDS)?;
    let mut out = Vec::with_capacity(words.len() * 32);
    for w in words {
        out.extend_from_slice(w);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// decoding
// ---------------------------------------------------------------------------

/// Splits a static ABI payload into exactly `expected` words.
///
/// Rejects any length that is not `expected * 32`, which simultaneously rejects
/// truncation, padding and trailing bytes (I14). The cap is validated before
/// the `Vec` is allocated.
pub fn split_words(data: &[u8], expected: usize) -> Result<Vec<Word>> {
    check_cap(expected, MAX_ABI_WORDS)?;
    check_cap(data.len(), MAX_LOG_DATA_BYTES)?;
    if data.len() != expected * 32 {
        return Err(AdapterError::EvidenceInvalid);
    }
    let mut out = Vec::with_capacity(expected);
    for chunk in data.chunks_exact(32) {
        let mut w = [0u8; 32];
        w.copy_from_slice(chunk);
        out.push(w);
    }
    Ok(out)
}

/// Decodes an `address`, rejecting any non-zero high byte (non-canonical).
pub fn decode_address(w: &Word) -> Result<[u8; 20]> {
    if w[..12].iter().any(|b| *b != 0) {
        return Err(AdapterError::EvidenceInvalid);
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[12..]);
    Ok(a)
}

/// Decodes a `uint8`, rejecting non-canonical padding.
pub fn decode_u8(w: &Word) -> Result<u8> {
    if w[..31].iter().any(|b| *b != 0) {
        return Err(AdapterError::EvidenceInvalid);
    }
    Ok(w[31])
}

/// Decodes a `uint16`, rejecting non-canonical padding.
pub fn decode_u16(w: &Word) -> Result<u16> {
    if w[..30].iter().any(|b| *b != 0) {
        return Err(AdapterError::EvidenceInvalid);
    }
    Ok(u16::from_be_bytes([w[30], w[31]]))
}

/// Decodes a `uint32`, rejecting non-canonical padding.
pub fn decode_u32(w: &Word) -> Result<u32> {
    if w[..28].iter().any(|b| *b != 0) {
        return Err(AdapterError::EvidenceInvalid);
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&w[28..]);
    Ok(u32::from_be_bytes(b))
}

/// Decodes a `uint64`, rejecting non-canonical padding.
pub fn decode_u64(w: &Word) -> Result<u64> {
    if w[..24].iter().any(|b| *b != 0) {
        return Err(AdapterError::EvidenceInvalid);
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&w[24..]);
    Ok(u64::from_be_bytes(b))
}

/// Decodes a `uint128` out of a `uint256` word, rejecting overflow.
pub fn decode_u128(w: &Word) -> Result<u128> {
    if w[..16].iter().any(|b| *b != 0) {
        return Err(AdapterError::BoundsExceeded);
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(&w[16..]);
    Ok(u128::from_be_bytes(b))
}

/// Decodes a `bool`, rejecting anything other than `0` or `1`.
pub fn decode_bool(w: &Word) -> Result<bool> {
    if w[..31].iter().any(|b| *b != 0) || w[31] > 1 {
        return Err(AdapterError::EvidenceInvalid);
    }
    Ok(w[31] == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_matches_known_vectors() {
        // The two canonical anchors everyone can check by hand.
        assert_eq!(
            keccak256(b""),
            [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70
            ]
        );
        // keccak256("Transfer(address,address,uint256)") — the ERC-20 topic0
        // every explorer shows.
        let t = event_topic0("Transfer(address,address,uint256)");
        assert_eq!(
            t[..4],
            [0xdd, 0xf2, 0x52, 0xad],
            "topic0 derivation disagrees with the canonical ERC-20 Transfer topic"
        );
    }

    #[test]
    fn event_topics_are_distinct_and_stable() {
        let sigs = [
            SIG_LOCK_OPENED,
            SIG_CLAIMED,
            SIG_REFUNDED,
            SIG_PAYOUT_DEFERRED,
            SIG_WITHDRAWAL,
        ];
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for s in sigs {
            let t = event_topic0(s);
            assert!(!seen.contains(&t), "topic0 collision on {s}");
            seen.push(t);
        }
        // Determinism.
        assert_eq!(event_topic0(SIG_CLAIMED), event_topic0(SIG_CLAIMED));
    }

    #[test]
    fn selectors_are_four_bytes_of_keccak() {
        let s = selector(SIG_CLAIM);
        assert_eq!(s, [keccak256(SIG_CLAIM.as_bytes())[0], s[1], s[2], s[3]]);
        assert_ne!(selector(SIG_OPEN), selector(SIG_REFUND));
    }

    #[test]
    fn word_encoders_are_right_aligned() {
        assert_eq!(word_u8(0xAB)[31], 0xAB);
        assert!(word_u8(0xAB)[..31].iter().all(|b| *b == 0));
        assert_eq!(&word_address([0x11; 20])[12..], &[0x11u8; 20]);
        assert!(word_address([0x11; 20])[..12].iter().all(|b| *b == 0));
        assert_eq!(word_u64(u64::MAX)[24..], [0xFF; 8]);
        assert_eq!(word_u16(0x0102)[30..], [0x01, 0x02]);
        assert_eq!(word_u128(u128::MAX)[16..], [0xFF; 16]);
    }

    #[test]
    fn split_words_rejects_truncation_padding_and_trailing_bytes() {
        let ok = vec![0u8; 64];
        assert_eq!(split_words(&ok, 2).map(|v| v.len()), Ok(2));
        assert_eq!(split_words(&ok, 1), Err(AdapterError::EvidenceInvalid));
        assert_eq!(split_words(&ok, 3), Err(AdapterError::EvidenceInvalid));
        assert_eq!(
            split_words(&[0u8; 63], 2),
            Err(AdapterError::EvidenceInvalid)
        );
        assert_eq!(
            split_words(&[0u8; 65], 2),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn split_words_caps_before_allocating() {
        assert_eq!(
            split_words(&[], MAX_ABI_WORDS + 1),
            Err(AdapterError::BoundsExceeded)
        );
        assert_eq!(
            split_words(&vec![0u8; MAX_LOG_DATA_BYTES + 32], 1),
            Err(AdapterError::BoundsExceeded)
        );
    }

    #[test]
    fn scalar_decoders_reject_non_canonical_padding() {
        let mut w = word_address([0x22; 20]);
        assert_eq!(decode_address(&w), Ok([0x22; 20]));
        w[0] = 1;
        assert_eq!(decode_address(&w), Err(AdapterError::EvidenceInvalid));

        let mut w = word_u64(7);
        assert_eq!(decode_u64(&w), Ok(7));
        w[23] = 1;
        assert_eq!(decode_u64(&w), Err(AdapterError::EvidenceInvalid));

        let mut w = word_u8(1);
        assert_eq!(decode_u8(&w), Ok(1));
        assert_eq!(decode_bool(&w), Ok(true));
        w[31] = 2;
        assert_eq!(decode_bool(&w), Err(AdapterError::EvidenceInvalid));

        let mut w = word_u16(9);
        assert_eq!(decode_u16(&w), Ok(9));
        w[29] = 1;
        assert_eq!(decode_u16(&w), Err(AdapterError::EvidenceInvalid));

        let mut w = word_u128(9);
        assert_eq!(decode_u128(&w), Ok(9));
        w[0] = 1;
        assert_eq!(decode_u128(&w), Err(AdapterError::BoundsExceeded));

        let mut w = [0u8; 32];
        w[28..].copy_from_slice(&7u32.to_be_bytes());
        assert_eq!(decode_u32(&w), Ok(7));
        w[27] = 1;
        assert_eq!(decode_u32(&w), Err(AdapterError::EvidenceInvalid));
    }

    #[test]
    fn concat_words_caps_before_allocating() {
        let too_many = vec![[0u8; 32]; MAX_ABI_WORDS + 1];
        assert_eq!(
            concat_words(&too_many),
            Err(AdapterError::BoundsExceeded),
            "I14: cap must be validated before the allocation"
        );
        assert_eq!(
            concat_words(&[[1u8; 32], [2u8; 32]]).map(|v| v.len()),
            Ok(64)
        );
    }
}

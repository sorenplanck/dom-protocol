//! Serialization test vectors.

use dom_core::{Amount, BlockHeight, Hash256, COIN_UNIT};
use dom_serialization::{DomDeserialize, DomSerialize};

/// Verify that all primitive types round-trip through serialization.
pub fn verify_all_roundtrips() -> Result<(), String> {
    // Hash256
    let h = Hash256::from_bytes([0xABu8; 32]);
    let bytes = h.to_bytes().map_err(|e| e.to_string())?;
    let h2 = Hash256::from_bytes(bytes.try_into().map_err(|_| "invalid length".to_string())?);
    if h != h2 { return Err("Hash256 roundtrip failed".into()); }

    // BlockHeight
    let bh = BlockHeight(12_345_678);
    let bytes = bh.to_bytes().map_err(|e| e.to_string())?;
    let bh2 = BlockHeight::from_bytes(&bytes).map_err(|e| e.to_string())?;
    if bh != bh2 { return Err("BlockHeight roundtrip failed".into()); }

    // Amount
    let a = Amount::from_noms(369 * COIN_UNIT).map_err(|e| e.to_string())?;
    let bytes = a.to_bytes().map_err(|e| e.to_string())?;
    let a2 = Amount::from_bytes(&bytes).map_err(|e| e.to_string())?;
    if a != a2 { return Err("Amount roundtrip failed".into()); }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_serialization::{Reader, Writer};
    use dom_core::COIN_UNIT;

    #[test]
    fn all_primitives_roundtrip() {
        // These use the DomSerialize/DomDeserialize traits tested in dom-serialization
        // Verify the key protocol values specifically

        // 369 DOM reward
        let reward = Amount::from_noms(369 * COIN_UNIT).unwrap();
        let bytes = reward.to_bytes().unwrap();
        assert_eq!(bytes.len(), 8); // u64 LE
        // 369 * 100_000_000 = 36_900_000_000 = 0x8984_7680
        let expected: u64 = 369 * COIN_UNIT;
        assert_eq!(bytes, expected.to_le_bytes());

        // Genesis height
        let genesis = BlockHeight::GENESIS;
        let bytes = genesis.to_bytes().unwrap();
        assert_eq!(bytes, 0u64.to_le_bytes());

        // Hash256 zero
        let zero = Hash256::ZERO;
        let bytes = zero.to_bytes().unwrap();
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn u64_is_little_endian() {
        let mut w = Writer::new();
        w.write_u64(1u64); // 1 in LE = [1, 0, 0, 0, 0, 0, 0, 0]
        let bytes = w.finish();
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..], &[0u8; 7]);
    }

    #[test]
    fn malformed_amount_rejected() {
        // Amount > MAX_SUPPLY_NOMS should be rejected
        let too_large = u64::MAX;
        let mut w = Writer::new();
        w.write_u64(too_large);
        let bytes = w.finish();
        assert!(Amount::from_bytes(&bytes).is_err());
    }
}

//! Primitive types used throughout the DOM protocol.

use crate::error::DomError;
use zeroize::Zeroize;

/// A 32-byte hash value (Blake2b-256 output).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// The all-zero hash (used as genesis prev_hash sentinel).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Construct from raw bytes.
    #[inline]
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Return raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse from a hex string (64 hex chars).
    pub fn from_hex(s: &str) -> Result<Self, DomError> {
        let bytes = hex::decode(s).map_err(|e| DomError::Malformed(format!("invalid hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DomError::Malformed("hash must be 32 bytes".into()))?;
        Ok(Self(arr))
    }

    /// Encode to lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl std::fmt::Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ── Block Height ─────────────────────────────────────────────────────────────

/// Block height (genesis = 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockHeight(pub u64);

impl BlockHeight {
    /// Genesis block height.
    pub const GENESIS: Self = Self(0);

    /// Checked increment.
    pub fn checked_next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    /// Returns the halving epoch for this height.
    /// epoch = height / HALVING_INTERVAL
    pub fn halving_epoch(self) -> u64 {
        self.0
            .checked_div(crate::constants::HALVING_INTERVAL)
            .expect("HALVING_INTERVAL is non-zero")
    }
}

impl std::fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Timestamp ────────────────────────────────────────────────────────────────

/// Unix timestamp in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Checked difference: self - other, None on underflow.
    pub fn checked_sub(self, other: Self) -> Option<u64> {
        self.0.checked_sub(other.0)
    }

    /// Checked addition of seconds.
    pub fn checked_add_secs(self, secs: u64) -> Option<Self> {
        self.0.checked_add(secs).map(Self)
    }
}

// ── Amount (noms) ─────────────────────────────────────────────────────────────

/// Amount in noms (smallest unit). 1 DOM = 100_000_000 noms.
///
/// Arithmetic is always checked to prevent overflow/underflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub struct Amount(u64);

impl Amount {
    /// Zero amount.
    pub const ZERO: Self = Self(0);

    /// Maximum possible amount (total supply ceiling).
    pub const MAX: Self = Self(crate::constants::MAX_SUPPLY_NOMS);

    /// Construct from noms.
    pub fn from_noms(noms: u64) -> Result<Self, DomError> {
        if noms > crate::constants::MAX_SUPPLY_NOMS {
            return Err(DomError::Invalid(format!(
                "amount {noms} exceeds MAX_SUPPLY_NOMS"
            )));
        }
        Ok(Self(noms))
    }

    /// Raw noms value.
    pub fn noms(self) -> u64 {
        self.0
    }

    /// Checked addition.
    pub fn checked_add(self, other: Self) -> Result<Self, DomError> {
        let sum = self
            .0
            .checked_add(other.0)
            .ok_or_else(|| DomError::Invalid("amount addition overflow".into()))?;
        Self::from_noms(sum)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, other: Self) -> Result<Self, DomError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or_else(|| DomError::Invalid("amount subtraction underflow".into()))
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dom = (self.0 as f64) / (crate::constants::COIN_UNIT as f64);
        let noms = self.0 % crate::constants::COIN_UNIT;
        write!(f, "{dom}.{noms:08} DOM")
    }
}

// ── Block Reward Calculator ───────────────────────────────────────────────────

/// Compute the block subsidy for a given height.
///
/// Returns 0 for any height in epoch >= HALVING_EPOCHS (after all coins issued).
/// Uses the deterministic pre-computed BLOCK_REWARD_TABLE — no floating-point,
/// no recomputation. Reproducible bit-exact across all architectures.
pub fn block_reward(height: BlockHeight) -> Amount {
    let epoch = height.halving_epoch();
    if epoch >= crate::constants::HALVING_EPOCHS as u64 {
        return Amount::ZERO;
    }
    let idx = usize::try_from(epoch).expect("epoch < HALVING_EPOCHS (55) always fits in usize");
    Amount(crate::constants::BLOCK_REWARD_TABLE[idx])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;

    #[test]
    fn genesis_reward_is_33_dom() {
        let r = block_reward(BlockHeight::GENESIS);
        assert_eq!(r.noms(), INITIAL_BLOCK_REWARD);
        assert_eq!(r.noms(), 33 * COIN_UNIT);
    }

    #[test]
    fn first_halving_applies_67_percent() {
        let h = BlockHeight(HALVING_INTERVAL);
        let r = block_reward(h);
        assert_eq!(r.noms(), (INITIAL_BLOCK_REWARD * 67) / 100);
    }

    #[test]
    fn second_halving() {
        let h = BlockHeight(HALVING_INTERVAL.checked_mul(2).unwrap());
        let r = block_reward(h);
        let expected = ((INITIAL_BLOCK_REWARD * 67) / 100 * 67) / 100;
        assert_eq!(r.noms(), expected);
    }

    #[test]
    fn reward_eventually_zero() {
        let h = BlockHeight(HALVING_INTERVAL.checked_mul(HALVING_EPOCHS as u64).unwrap());
        assert_eq!(block_reward(h), Amount::ZERO);
    }

    #[test]
    fn reward_zero_at_epoch_54() {
        let h = BlockHeight(HALVING_INTERVAL.checked_mul(54).unwrap());
        assert_eq!(block_reward(h).noms(), 0);
    }

    #[test]
    fn amount_checked_add_overflow() {
        let a = Amount(u64::MAX - 1);
        let b = Amount(2);
        assert!(a.checked_add(b).is_err());
    }

    #[test]
    fn hash256_roundtrip() {
        let bytes = [0xabu8; 32];
        let h = Hash256::from_bytes(bytes);
        assert_eq!(h.as_bytes(), &bytes);
        let hex = h.to_hex();
        let h2 = Hash256::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn block_height_halving_epoch() {
        assert_eq!(BlockHeight(0).halving_epoch(), 0);
        assert_eq!(BlockHeight(HALVING_INTERVAL - 1).halving_epoch(), 0);
        assert_eq!(BlockHeight(HALVING_INTERVAL).halving_epoch(), 1);
        assert_eq!(BlockHeight(HALVING_INTERVAL * 2).halving_epoch(), 2);
    }
}

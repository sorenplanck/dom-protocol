#![allow(missing_docs)]
//! Block header types and validation.
//!
//! DOM_RFC_0007_Validation_Order.md — Block validation steps 1-7.

use dom_core::{
    BlockHeight, DomError, Hash256, Timestamp, MAX_FUTURE_BLOCK_TIME, FUTURE_BLOCK_SOFT_BUFFER_SECS, MEDIAN_TIME_WINDOW,
    PROTOCOL_VERSION,
};
use dom_pow::CompactTarget;
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};
use primitive_types::U256;

/// DOM block header.
///
/// Serialization order per DOM_v6_1_Serialization_RFC.md:
/// version, height, prev_hash, timestamp, output_root, kernel_root,
/// rangeproof_root, total_kernel_offset, target, total_difficulty, pow
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// Protocol version.
    pub version: u32,
    /// Block height (genesis = 0).
    pub height: BlockHeight,
    /// Hash of the previous block header.
    pub prev_hash: Hash256,
    /// Unix timestamp.
    pub timestamp: Timestamp,
    /// PMMR root of transaction outputs.
    pub output_root: Hash256,
    /// PMMR root of transaction kernels.
    pub kernel_root: Hash256,
    /// PMMR root of range proofs.
    pub rangeproof_root: Hash256,
    /// Sum of all transaction kernel offsets.
    pub total_kernel_offset: [u8; 32],
    /// Compact target (difficulty).
    pub target: CompactTarget,
    /// Cumulative difficulty of this chain (U256 — full precision, 32 bytes big-endian).
    pub total_difficulty: U256,
    /// Proof of work data.
    pub pow: ProofOfWork,
}

impl BlockHeader {
    /// Canonical byte sequence hashed by RandomX for proof-of-work.
    ///
    /// This MUST match exactly between miner and validator or consensus breaks.
    /// Field order: version, prev_hash, height, timestamp, output_root,
    /// kernel_root, rangeproof_root, total_kernel_offset, target,
    /// total_difficulty (32-byte big-endian), nonce.
    pub fn pow_preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(200);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(self.prev_hash.as_bytes());
        out.extend_from_slice(&self.height.0.to_le_bytes());
        out.extend_from_slice(&self.timestamp.0.to_le_bytes());
        out.extend_from_slice(self.output_root.as_bytes());
        out.extend_from_slice(self.kernel_root.as_bytes());
        out.extend_from_slice(self.rangeproof_root.as_bytes());
        out.extend_from_slice(&self.total_kernel_offset);
        out.extend_from_slice(&self.target.0.to_le_bytes());
        let mut td = [0u8; 32];
        self.total_difficulty.to_big_endian(&mut td);
        out.extend_from_slice(&td);
        out.extend_from_slice(&self.pow.nonce.to_le_bytes());
        out
    }
}

/// Proof of work attachment to a block header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOfWork {
    /// RandomX nonce (8 bytes).
    pub nonce: u64,
    /// RandomX proof hash (32 bytes).
    pub randomx_hash: Hash256,
}

impl DomSerialize for ProofOfWork {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u64(self.nonce);
        self.randomx_hash.serialize(w)?;
        Ok(())
    }
}

impl DomDeserialize for ProofOfWork {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(Self {
            nonce: r.read_u64()?,
            randomx_hash: Hash256::deserialize(r)?,
        })
    }
}

impl DomSerialize for BlockHeader {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u32(self.version);
        self.height.serialize(w)?;
        self.prev_hash.serialize(w)?;
        self.timestamp.serialize(w)?;
        self.output_root.serialize(w)?;
        self.kernel_root.serialize(w)?;
        self.rangeproof_root.serialize(w)?;
        w.write_bytes(&self.total_kernel_offset);
        self.target.serialize(w)?;
        // U256 serialized as 32 bytes big-endian
        let mut td_bytes = [0u8; 32];
        self.total_difficulty.to_big_endian(&mut td_bytes);
        w.write_bytes(&td_bytes);
        self.pow.serialize(w)?;
        Ok(())
    }
}

impl DomDeserialize for BlockHeader {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(Self {
            version: r.read_u32()?,
            height: BlockHeight::deserialize(r)?,
            prev_hash: Hash256::deserialize(r)?,
            timestamp: Timestamp::deserialize(r)?,
            output_root: Hash256::deserialize(r)?,
            kernel_root: Hash256::deserialize(r)?,
            rangeproof_root: Hash256::deserialize(r)?,
            total_kernel_offset: r.read_array::<32>()?,
            target: CompactTarget::deserialize(r)?,
            total_difficulty: {
                let bytes = r.read_array::<32>()?;
                U256::from_big_endian(&bytes)
            },
            pow: ProofOfWork::deserialize(r)?,
        })
    }
}

/// Validate block header syntax (step 2 of RFC-0007 block validation).
pub fn validate_header_syntax(header: &BlockHeader) -> Result<(), DomError> {
    // Version check
    if header.version != PROTOCOL_VERSION {
        return Err(DomError::Invalid(format!(
            "unsupported block version: {} (expected {})",
            header.version, PROTOCOL_VERSION
        )));
    }
    // Genesis must have zero prev_hash
    if header.height == BlockHeight::GENESIS && header.prev_hash != Hash256::ZERO {
        return Err(DomError::Invalid(
            "genesis block must have zero prev_hash".into(),
        ));
    }
    // Non-genesis must have non-zero prev_hash
    if header.height != BlockHeight::GENESIS && header.prev_hash == Hash256::ZERO {
        return Err(DomError::Invalid(
            "non-genesis block must have non-zero prev_hash".into(),
        ));
    }
    // AUDIT: total_kernel_offset must be a canonical scalar in [0, n-1]
    // Non-canonical offsets are Malformed (not Invalid) per RFC-0010 §4.4
    validate_kernel_offset_canonical(&header.total_kernel_offset)?;
    Ok(())
}

/// Validate total_kernel_offset is a canonical secp256k1 scalar in [0, n-1].
/// RFC-0010 §4.4: non-canonical offset is Malformed.
fn validate_kernel_offset_canonical(offset: &[u8; 32]) -> Result<(), DomError> {
    // secp256k1 order n (big-endian)
    const SECP256K1_N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    // offset >= n is non-canonical (zero is valid — zero offset means no graph privacy)
    for i in 0..32 {
        if offset[i] < SECP256K1_N[i] {
            return Ok(());
        }
        if offset[i] > SECP256K1_N[i] {
            return Err(DomError::Malformed(
                "total_kernel_offset >= secp256k1 order n — non-canonical scalar".into(),
            ));
        }
    }
    // offset == n: also non-canonical (must be in [0, n-1])
    Err(DomError::Malformed(
        "total_kernel_offset == secp256k1 order n — non-canonical scalar".into(),
    ))
}

/// Check that the block timestamp is not too far in the future (step 5).
///
/// Returns TemporarilyInvalid if timestamp > now + MAX_FUTURE_BLOCK_TIME.
pub fn validate_future_timestamp(header: &BlockHeader, now: Timestamp) -> Result<(), DomError> {
    let limit = now
        .checked_add_secs(MAX_FUTURE_BLOCK_TIME)
        .ok_or_else(|| DomError::Internal("timestamp limit overflow".into()))?;
    if header.timestamp > limit {
        return Err(DomError::TemporarilyInvalid(format!(
            "block timestamp {} too far in future (limit {})",
            header.timestamp.0, limit.0
        )));
    }
    Ok(())
}

/// Validate block timestamp with soft buffer support.
///
/// Returns a 3-way decision:
/// - `Ok(TimestampDecision::Accept)`: timestamp is within `now + MAX_FUTURE_BLOCK_TIME`
/// - `Ok(TimestampDecision::Defer)`: timestamp is within the soft buffer; defer for re-evaluation
/// - `Err(DomError::TemporarilyInvalid)`: timestamp beyond hard limit; reject
///
/// The hard consensus rule remains `MAX_FUTURE_BLOCK_TIME = 120s`. The soft buffer
/// adds `FUTURE_BLOCK_SOFT_BUFFER_SECS = 60s` of grace period during which blocks
/// are held in a queue for re-validation instead of being immediately discarded.
/// This reduces orphan rates from transient clock drift.
pub fn validate_future_timestamp_with_buffer(
    header: &BlockHeader,
    now: Timestamp,
) -> Result<TimestampDecision, DomError> {
    let hard_limit = now
        .checked_add_secs(MAX_FUTURE_BLOCK_TIME)
        .ok_or_else(|| DomError::Invalid("timestamp overflow".into()))?;

    let soft_limit = now
        .checked_add_secs(MAX_FUTURE_BLOCK_TIME + FUTURE_BLOCK_SOFT_BUFFER_SECS)
        .ok_or_else(|| DomError::Invalid("timestamp overflow".into()))?;

    if header.timestamp.0 > soft_limit.0 {
        return Err(DomError::TemporarilyInvalid(format!(
            "block timestamp {} too far in future (soft limit {})",
            header.timestamp.0,
            soft_limit.0
        )));
    }

    if header.timestamp.0 > hard_limit.0 {
        return Ok(TimestampDecision::Defer);
    }

    Ok(TimestampDecision::Accept)
}

/// Decision returned by `validate_future_timestamp_with_buffer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampDecision {
    /// Timestamp is within hard limit; block can be processed.
    Accept,
    /// Timestamp is within soft buffer; hold for re-evaluation.
    Defer,
}

/// Validate median-time-past (step 4).
///
/// Block timestamp must be strictly greater than the median of the last
/// MEDIAN_TIME_WINDOW ancestors' timestamps.
pub fn validate_median_time_past(
    header: &BlockHeader,
    ancestor_timestamps: &[Timestamp],
) -> Result<(), DomError> {
    if ancestor_timestamps.len() < MEDIAN_TIME_WINDOW {
        // Not enough ancestors yet (early in the chain)
        return Ok(());
    }
    let mut sorted: Vec<u64> = ancestor_timestamps
        .iter()
        .take(MEDIAN_TIME_WINDOW)
        .map(|t| t.0)
        .collect();
    sorted.sort_unstable();
    let median = sorted[MEDIAN_TIME_WINDOW / 2];

    if header.timestamp.0 <= median {
        return Err(DomError::Invalid(format!(
            "block timestamp {} not greater than median-time-past {}",
            header.timestamp.0, median
        )));
    }
    Ok(())
}

/// Validate PoW (step 6): block hash must meet the target.
/// Validate proof-of-work via RandomX.
///
/// `seed` is the 32-byte hash of the block at `randomx_seed_height(header.height)`.
/// For early blocks (height < 2048), the seed is [0u8; 32] by convention.
///
/// Verifies:
///   1. RandomX(seed, header.pow_preimage()) == header.pow.randomx_hash
///   2. header.pow.randomx_hash meets the target
pub fn validate_pow(header: &BlockHeader, seed: &[u8; 32]) -> Result<(), DomError> {
    let target = header
        .target
        .to_target()
        .map_err(|e| DomError::Invalid(format!("invalid compact target: {e}")))?;
    let preimage = header.pow_preimage();
    let claimed_hash = header.pow.randomx_hash.as_bytes();
    let ok = dom_pow::validate_pow_randomx(&preimage, claimed_hash, seed, &target)?;
    if !ok {
        return Err(DomError::Invalid(
            "proof-of-work invalid: RandomX hash mismatch or does not meet target".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_header() -> BlockHeader {
        BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight::GENESIS,
            prev_hash: Hash256::ZERO,
            timestamp: Timestamp(1_704_067_200),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0x1f00_ffff),
            total_difficulty: U256::one(),
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        }
    }

    #[test]
    fn genesis_header_valid_syntax() {
        assert!(validate_header_syntax(&dummy_header()).is_ok());
    }

    #[test]
    fn genesis_nonzero_prev_hash_rejected() {
        let mut h = dummy_header();
        h.prev_hash = Hash256::from_bytes([0x01u8; 32]);
        assert!(validate_header_syntax(&h).is_err());
    }

    #[test]
    fn wrong_version_rejected() {
        let mut h = dummy_header();
        h.version = 99;
        assert!(validate_header_syntax(&h).is_err());
    }

    #[test]
    fn future_timestamp_rejected() {
        let h = dummy_header();
        let now = Timestamp(100); // now is before block timestamp
                                  // block timestamp 1_704_067_200 >> now 100 + MAX_FUTURE_BLOCK_TIME
        assert!(validate_future_timestamp(&h, now).is_err());
    }

    #[test]
    fn header_serialization_roundtrip() {
        use dom_serialization::{DomDeserialize, DomSerialize};
        let h = dummy_header();
        let bytes = h.to_bytes().unwrap();
        let h2 = BlockHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn median_time_past_enforced() {
        let mut h = dummy_header();
        h.timestamp = Timestamp(100);
        // Ancestors all have timestamp 200 → median = 200 > block timestamp 100
        let ancestors = vec![Timestamp(200); MEDIAN_TIME_WINDOW];
        assert!(validate_median_time_past(&h, &ancestors).is_err());
    }
}

//! Bitcoin CSV encoding and cross-chain timing policy (Annex M M.2.3/M.8).
//!
//! M.8 deliberately compares neither block heights nor native timelock units
//! directly.  Native deadlines are projected to checked intervals measured in
//! seconds.  Once real funding evidence exists, each relative interval is
//! placed on an absolute timestamp interval before the conservative side is
//! used for the cross-chain inequality.

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

use crate::types::BitcoinNetworkV1;

/// The disable flag: when set in nSequence, the relative lock-time is off.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// The type flag: 0 = block units, 1 = 512-second units.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
/// The 16-bit value mask.
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_FFFF;

/// Frozen version of the lab's additive M.8 pre-funding policy encoding.
pub const M8_POLICY_VERSION: u16 = 1;
/// Magic of the canonical M.8 pre-funding policy encoding.
pub const M8_POLICY_MAGIC: &[u8; 8] = b"DOMM8P1\0";
/// Domain separator for [`M8TimingPolicyV1::policy_digest`].
pub const M8_POLICY_DOMAIN: &[u8] = b"DOM-INTEROP/M8-TIMING-POLICY/V1\0";
/// Frozen version of the lab's additive M.8 funding-anchor encoding.
pub const M8_ANCHORS_VERSION: u16 = 1;
/// Magic of the canonical M.8 funding-anchor encoding.
pub const M8_ANCHORS_MAGIC: &[u8; 8] = b"DOMM8A1\0";
/// Domain separator for [`M8FundingAnchorsV1::evidence_digest`].
pub const M8_ANCHORS_DOMAIN: &[u8] = b"DOM-INTEROP/M8-FUNDING-ANCHORS/V1\0";
/// Number of block intervals spanning Bitcoin's 11-block MTP sample.
pub const BTC_MTP_SAMPLE_INTERVALS: u64 = 10;

/// A native refund timelock, including the real funding anchor required by
/// Annex M M.8.1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimelockSpecV1 {
    /// A DOM height-locked refund.
    DomHeight {
        /// Height of the confirmed DOM funding anchor.
        base_height: u64,
        /// Number of DOM blocks after the anchor.
        delta_blocks: u64,
    },
    /// A Bitcoin BIP68 block-based relative refund.
    BtcBlocks {
        /// Height of the confirmed Bitcoin funding anchor.
        base_height: u64,
        /// Number of Bitcoin blocks after the anchor.
        delta_blocks: u16,
    },
    /// A Bitcoin BIP68 MTP-based relative refund in 512-second units.
    BtcTime512s {
        /// Median-time-past of the confirmed Bitcoin funding anchor.
        base_mtp: u64,
        /// Number of 512-second BIP68 units after the anchor.
        units: u16,
    },
}

/// Conservative seconds interval for a native refund deadline.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimeIntervalV1 {
    /// Earliest time at which the deadline can be reached.
    pub earliest_seconds: u64,
    /// Latest time at which the deadline can be reached.
    pub latest_seconds: u64,
}

/// Explicit timing bounds for one chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChainTimingBoundsV1 {
    /// Minimum permitted duration of a block interval.
    pub min_block_seconds: u32,
    /// Maximum permitted duration of a block interval.
    pub max_block_seconds: u32,
    /// Time budget assigned to the maximum accepted reorg.
    pub max_reorg_seconds: u32,
    /// Time budget assigned to observing and validating chain evidence.
    pub observation_seconds: u32,
    /// Time budget assigned to broadcasting the reacting transaction.
    pub broadcast_seconds: u32,
}

/// Frozen M.8 relation between the first and second refund paths.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CrossChainWindowV1 {
    /// Refund deadline of the leg that can reveal the adaptor secret first.
    pub first_refund: TimelockSpecV1,
    /// Refund deadline of the reacting leg.
    pub second_refund: TimelockSpecV1,
    /// Explicit observation, reaction, reorg and broadcast budget.
    pub safety_margin_seconds: u64,
    /// Digest of the immutable pre-funding timing policy.
    pub policy_digest: [u8; 32],
}

/// Explicit Bitcoin finality policy required by Annex M M.8.3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinFinalityPolicyV1 {
    /// Bitcoin network on which evidence is accepted.
    pub network: BitcoinNetworkV1,
    /// Confirmations required before accepting evidence.
    pub minimum_confirmations: u32,
    /// Maximum reorg depth handled by the ordinary recovery policy.
    pub maximum_reorg_depth: u32,
    /// Whether an independently verified header chain is mandatory.
    pub require_header_chain: bool,
    /// Whether the block's witness commitment must be verified.
    pub require_witness_commitment: bool,
    /// Public identifier of the selected finality policy.
    pub policy_id: [u8; 32],
    /// Explicit finality-policy version.
    pub version: u32,
}

/// A native delay without a chain anchor.
///
/// This additive lab type exists so policy can be frozen before funding while
/// real bases are bound later from confirmed chain evidence.  It does not
/// replace [`TimelockSpecV1`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimelockOffsetV1 {
    /// A DOM delay measured in blocks.
    DomBlocks {
        /// Number of DOM blocks after confirmed funding.
        delta_blocks: u64,
    },
    /// A Bitcoin BIP68 delay measured in blocks.
    BtcBlocks {
        /// Number of Bitcoin blocks after confirmed funding.
        delta_blocks: u16,
    },
    /// A Bitcoin BIP68 delay measured in 512-second MTP units.
    BtcTime512s {
        /// Number of 512-second units after confirmed funding.
        units: u16,
    },
}

/// Immutable pre-funding M.8 policy used by the versioned two-phase lab
/// model.
///
/// The digest commits to the settlement terms hash, both native offsets,
/// safety margin, both timing-bound sets and every finality-policy field.
/// No funding anchor appears here because it does not exist yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct M8TimingPolicyV1 {
    /// Hash of the already frozen `kaystra_core::SettlementTermsV1` bytes.
    ///
    /// This crate intentionally stores it as an opaque digest to preserve the
    /// adapter boundary and avoid a dependency on `kaystra-core`.
    pub settlement_terms_hash: [u8; 32],
    /// Native delay of the first refund path.
    pub first_refund: TimelockOffsetV1,
    /// Native delay of the second refund path.
    pub second_refund: TimelockOffsetV1,
    /// Explicit cross-chain safety margin.
    pub safety_margin_seconds: u64,
    /// DOM timing assumptions accepted by both participants.
    pub dom_bounds: ChainTimingBoundsV1,
    /// Bitcoin timing assumptions accepted by both participants.
    pub btc_bounds: ChainTimingBoundsV1,
    /// Bitcoin evidence/finality requirements accepted by both participants.
    pub bitcoin_finality: BitcoinFinalityPolicyV1,
}

/// Confirmed DOM funding anchor obtained from the real DOM scanner.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DomFundingAnchorV1 {
    /// Canonical DOM funding transaction identifier.
    pub funding_txid: [u8; 32],
    /// Canonical hash of the containing DOM block.
    pub block_hash: [u8; 32],
    /// Height of the containing DOM block.
    pub height: u64,
    /// Scanner-verified timestamp of the containing DOM block, in Unix
    /// seconds, used as the absolute DOM deadline-interval anchor.
    pub block_time_seconds: u64,
}

/// Confirmed Bitcoin funding anchor obtained from Bitcoin evidence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinFundingAnchorV1 {
    /// Bitcoin funding transaction id in canonical internal byte order.
    pub funding_txid: [u8; 32],
    /// Bitcoin block hash in canonical internal byte order.
    pub block_hash: [u8; 32],
    /// Height of the containing Bitcoin block.
    pub height: u64,
    /// Median-time-past at the funding anchor.
    pub median_time_past: u64,
}

/// Post-confirmation evidence object that binds real anchors to one immutable
/// pre-funding policy without mutating that policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct M8FundingAnchorsV1 {
    /// Terms hash copied from the frozen pre-funding policy.
    pub settlement_terms_hash: [u8; 32],
    /// Digest of the frozen pre-funding policy.
    pub policy_digest: [u8; 32],
    /// Confirmed DOM funding evidence.
    pub dom: DomFundingAnchorV1,
    /// Confirmed Bitcoin funding evidence.
    pub bitcoin: BitcoinFundingAnchorV1,
}

/// Validated result of binding real funding anchors to a pre-funding policy.
///
/// Possession of this value proves that digest binding and the M.8 inequality
/// passed.  Signing code should require this value before generating nonces.
#[derive(PartialEq, Eq, Debug)]
pub struct AnchoredCrossChainWindowV1 {
    /// Frozen terms hash against which signing permits are checked.
    settlement_terms_hash: [u8; 32],
    /// Exact M.8 window with real bases.
    window: CrossChainWindowV1,
    /// Digest of the post-confirmation anchor evidence.
    anchor_evidence_digest: [u8; 32],
}

/// A CSV delay expressed in its native unit (M.2.2). Block units and
/// 512-second units never mix (M.2.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinCsvDelayV1 {
    /// Relative delay in blocks.
    Blocks(u16),
    /// Relative delay in 512-second (MTP) units.
    Time512s(u16),
}

/// Timelock encoding failures.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TimelockError {
    /// The encoded value would set the disable flag (unreachable for
    /// 16-bit inputs, checked defensively).
    #[error("disable flag set")]
    DisableFlagSet,
    /// A chain timing profile has a zero block duration or an inverted range.
    #[error("invalid chain timing bounds")]
    InvalidTimingBounds,
    /// A checked addition or multiplication overflowed.
    #[error("timelock arithmetic overflow")]
    Overflow,
    /// Both refunds belong to the same chain; this is not a cross-chain path.
    #[error("refunds do not form a DOM-Bitcoin window")]
    InvalidCrossChainTopology,
    /// The latest safe first refund falls after the earliest second refund.
    #[error("unsafe cross-chain window")]
    UnsafeCrossChainWindow,
    /// The declared margin does not cover the explicit chain policy budgets.
    #[error("cross-chain safety margin does not cover timing policy")]
    InsufficientSafetyMargin,
    /// The Bitcoin finality policy is internally inconsistent.
    #[error("invalid Bitcoin finality policy")]
    InvalidFinalityPolicy,
    /// A policy digest does not match canonical pre-funding policy bytes.
    #[error("M.8 policy digest mismatch")]
    PolicyDigestMismatch,
    /// Anchor evidence refers to different frozen settlement terms.
    #[error("M.8 settlement terms hash mismatch")]
    TermsHashMismatch,
    /// A required post-confirmation transaction or block identifier is absent.
    #[error("missing M.8 funding anchor evidence")]
    MissingAnchorEvidence,
    /// BLAKE2b-256 could not be initialized or finalized.
    #[error("M.8 digest initialization failed")]
    HashInitialization,
    /// Canonical M.8 bytes carry an unknown magic prefix.
    #[error("invalid M.8 encoding magic")]
    InvalidEncodingMagic,
    /// Canonical M.8 bytes carry an unsupported version.
    #[error("unsupported M.8 encoding version")]
    UnsupportedEncodingVersion,
    /// Canonical M.8 bytes end before the expected field is complete.
    #[error("truncated M.8 encoding")]
    TruncatedEncoding,
    /// Canonical M.8 bytes carry data after the final field.
    #[error("trailing bytes in M.8 encoding")]
    TrailingBytes,
    /// Canonical M.8 bytes carry an unknown enum or boolean discriminant.
    #[error("unknown discriminant in M.8 encoding")]
    UnknownDiscriminant,
    /// A native timelock base does not equal its authenticated funding anchor.
    #[error("M.8 timelock base does not match funding evidence")]
    AnchorBaseMismatch,
}

fn validate_bounds(bounds: &ChainTimingBoundsV1) -> Result<(), TimelockError> {
    if bounds.min_block_seconds == 0
        || bounds.max_block_seconds == 0
        || bounds.min_block_seconds > bounds.max_block_seconds
    {
        return Err(TimelockError::InvalidTimingBounds);
    }
    Ok(())
}

fn is_dom(spec: &TimelockSpecV1) -> bool {
    matches!(spec, TimelockSpecV1::DomHeight { .. })
}

/// Computes the conservative minimum margin represented by the explicit M.8
/// timing-bound fields.
///
/// A reaction can cross both observation boundaries.  The sum therefore
/// covers the reorg, observation and broadcast budgets of both chains.  This
/// is an additive lab rule: Annex M requires those risks to be covered but
/// does not publish the arithmetic that produces `safety_margin_seconds`.
pub fn minimum_safety_margin_seconds(
    dom_bounds: &ChainTimingBoundsV1,
    btc_bounds: &ChainTimingBoundsV1,
) -> Result<u64, TimelockError> {
    validate_bounds(dom_bounds)?;
    validate_bounds(btc_bounds)?;
    [
        dom_bounds.max_reorg_seconds,
        dom_bounds.observation_seconds,
        dom_bounds.broadcast_seconds,
        btc_bounds.max_reorg_seconds,
        btc_bounds.observation_seconds,
        btc_bounds.broadcast_seconds,
    ]
    .into_iter()
    .try_fold(0u64, |sum, value| {
        sum.checked_add(u64::from(value))
            .ok_or(TimelockError::Overflow)
    })
}

fn checked_blocks_interval(
    base_height: u64,
    delta_blocks: u64,
    bounds: &ChainTimingBoundsV1,
) -> Result<TimeIntervalV1, TimelockError> {
    validate_bounds(bounds)?;
    // The absolute native deadline is validated even though normalization is
    // expressed from the common funding reference and therefore uses delta.
    base_height
        .checked_add(delta_blocks)
        .ok_or(TimelockError::Overflow)?;
    let earliest_seconds = delta_blocks
        .checked_mul(u64::from(bounds.min_block_seconds))
        .ok_or(TimelockError::Overflow)?;
    let latest_seconds = delta_blocks
        .checked_mul(u64::from(bounds.max_block_seconds))
        .ok_or(TimelockError::Overflow)?;
    Ok(TimeIntervalV1 {
        earliest_seconds,
        latest_seconds,
    })
}

/// Projects a native timelock onto a checked seconds interval from its native
/// funding reference (Annex M M.8.2).
///
/// Block-based locks use the selected chain's minimum and maximum block
/// duration. A BIP68 MTP lock includes both its 512-second quantization and a
/// conservative lab bound for the complete 11-block median sample. This
/// function returns a relative interval; real funding evidence later places
/// that interval on an absolute timestamp range in
/// [`bind_and_validate_funding_anchors`].
pub fn normalize_to_seconds(
    spec: &TimelockSpecV1,
    dom_bounds: &ChainTimingBoundsV1,
    btc_bounds: &ChainTimingBoundsV1,
) -> Result<TimeIntervalV1, TimelockError> {
    match *spec {
        TimelockSpecV1::DomHeight {
            base_height,
            delta_blocks,
        } => checked_blocks_interval(base_height, delta_blocks, dom_bounds),
        TimelockSpecV1::BtcBlocks {
            base_height,
            delta_blocks,
        } => checked_blocks_interval(base_height, u64::from(delta_blocks), btc_bounds),
        TimelockSpecV1::BtcTime512s { base_mtp, units } => {
            validate_bounds(btc_bounds)?;
            let nominal_seconds = u64::from(units)
                .checked_mul(512)
                .ok_or(TimelockError::Overflow)?;
            let (earliest_seconds, latest_seconds) = if units == 0 {
                (0, 0)
            } else {
                let median_sample_uncertainty = BTC_MTP_SAMPLE_INTERVALS
                    .checked_mul(u64::from(btc_bounds.max_block_seconds))
                    .ok_or(TimelockError::Overflow)?;
                let earliest = nominal_seconds.saturating_sub(median_sample_uncertainty);
                let latest = nominal_seconds
                    .checked_add(511)
                    .and_then(|value| value.checked_add(median_sample_uncertainty))
                    .ok_or(TimelockError::Overflow)?;
                (earliest, latest)
            };
            base_mtp
                .checked_add(latest_seconds)
                .ok_or(TimelockError::Overflow)?;
            Ok(TimeIntervalV1 {
                earliest_seconds,
                latest_seconds,
            })
        }
    }
}

/// Enforces the mandatory M.8 inequality using the conservative endpoint of
/// each deadline interval.
pub fn validate_cross_chain_window(
    window: &CrossChainWindowV1,
    dom_bounds: &ChainTimingBoundsV1,
    btc_bounds: &ChainTimingBoundsV1,
) -> Result<(), TimelockError> {
    validate_bounds(dom_bounds)?;
    validate_bounds(btc_bounds)?;
    if is_dom(&window.first_refund) == is_dom(&window.second_refund) {
        return Err(TimelockError::InvalidCrossChainTopology);
    }
    if window.safety_margin_seconds < minimum_safety_margin_seconds(dom_bounds, btc_bounds)? {
        return Err(TimelockError::InsufficientSafetyMargin);
    }
    let l1 = normalize_to_seconds(&window.first_refund, dom_bounds, btc_bounds)?;
    let l2 = normalize_to_seconds(&window.second_refund, dom_bounds, btc_bounds)?;
    let protected_latest = l1
        .latest_seconds
        .checked_add(window.safety_margin_seconds)
        .ok_or(TimelockError::Overflow)?;
    if protected_latest > l2.earliest_seconds {
        return Err(TimelockError::UnsafeCrossChainWindow);
    }
    Ok(())
}

impl BitcoinFinalityPolicyV1 {
    /// Validates all M.8.3 consistency rules that are independent of live
    /// chain evidence.
    pub fn validate(&self) -> Result<(), TimelockError> {
        if self.minimum_confirmations == 0
            || self.maximum_reorg_depth == 0
            || self.policy_id == [0; 32]
            || self.version == 0
        {
            return Err(TimelockError::InvalidFinalityPolicy);
        }
        Ok(())
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

fn put_offset(out: &mut Vec<u8>, offset: TimelockOffsetV1) {
    match offset {
        TimelockOffsetV1::DomBlocks { delta_blocks } => {
            out.push(0x01);
            put_u64(out, delta_blocks);
        }
        TimelockOffsetV1::BtcBlocks { delta_blocks } => {
            out.push(0x02);
            put_u16(out, delta_blocks);
        }
        TimelockOffsetV1::BtcTime512s { units } => {
            out.push(0x03);
            put_u16(out, units);
        }
    }
}

fn put_bounds(out: &mut Vec<u8>, bounds: ChainTimingBoundsV1) {
    put_u32(out, bounds.min_block_seconds);
    put_u32(out, bounds.max_block_seconds);
    put_u32(out, bounds.max_reorg_seconds);
    put_u32(out, bounds.observation_seconds);
    put_u32(out, bounds.broadcast_seconds);
}

/// Bounds-checked reader for the additive canonical M.8 lab formats.
struct CanonicalCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> CanonicalCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TimelockError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(TimelockError::TruncatedEncoding)?;
        if end > self.bytes.len() {
            return Err(TimelockError::TruncatedEncoding);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], TimelockError> {
        let mut value = [0u8; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, TimelockError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, TimelockError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32, TimelockError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, TimelockError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn take_offset(cursor: &mut CanonicalCursor<'_>) -> Result<TimelockOffsetV1, TimelockError> {
    match cursor.take_u8()? {
        0x01 => Ok(TimelockOffsetV1::DomBlocks {
            delta_blocks: cursor.take_u64()?,
        }),
        0x02 => Ok(TimelockOffsetV1::BtcBlocks {
            delta_blocks: cursor.take_u16()?,
        }),
        0x03 => Ok(TimelockOffsetV1::BtcTime512s {
            units: cursor.take_u16()?,
        }),
        _ => Err(TimelockError::UnknownDiscriminant),
    }
}

fn take_bounds(cursor: &mut CanonicalCursor<'_>) -> Result<ChainTimingBoundsV1, TimelockError> {
    Ok(ChainTimingBoundsV1 {
        min_block_seconds: cursor.take_u32()?,
        max_block_seconds: cursor.take_u32()?,
        max_reorg_seconds: cursor.take_u32()?,
        observation_seconds: cursor.take_u32()?,
        broadcast_seconds: cursor.take_u32()?,
    })
}

fn take_bool(cursor: &mut CanonicalCursor<'_>) -> Result<bool, TimelockError> {
    match cursor.take_u8()? {
        0x00 => Ok(false),
        0x01 => Ok(true),
        _ => Err(TimelockError::UnknownDiscriminant),
    }
}

fn take_network(cursor: &mut CanonicalCursor<'_>) -> Result<BitcoinNetworkV1, TimelockError> {
    match cursor.take_u8()? {
        0x01 => Ok(BitcoinNetworkV1::Regtest),
        0x02 => Ok(BitcoinNetworkV1::CustomSignet),
        0x03 => Ok(BitcoinNetworkV1::PublicSignet),
        _ => Err(TimelockError::UnknownDiscriminant),
    }
}

fn blake2b_256(domain: &[u8], body: &[u8]) -> Result<[u8; 32], TimelockError> {
    let mut hash = Blake2bVar::new(32).map_err(|_| TimelockError::HashInitialization)?;
    hash.update(domain);
    hash.update(body);
    let mut digest = [0u8; 32];
    hash.finalize_variable(&mut digest)
        .map_err(|_| TimelockError::HashInitialization)?;
    Ok(digest)
}

fn offset_is_dom(offset: TimelockOffsetV1) -> bool {
    matches!(offset, TimelockOffsetV1::DomBlocks { .. })
}

impl M8TimingPolicyV1 {
    /// Validates bounds, topology and the explicit Bitcoin finality policy.
    pub fn validate(&self) -> Result<(), TimelockError> {
        validate_bounds(&self.dom_bounds)?;
        validate_bounds(&self.btc_bounds)?;
        self.bitcoin_finality.validate()?;
        if offset_is_dom(self.first_refund) == offset_is_dom(self.second_refund) {
            return Err(TimelockError::InvalidCrossChainTopology);
        }
        Ok(())
    }

    /// Canonical big-endian bytes committed by [`Self::policy_digest`].
    ///
    /// The encoding is additive lab format `DOMM8P1`, not a replacement for
    /// any Annex M `DOMBTC` wire artifact.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TimelockError> {
        self.validate()?;
        let mut out = Vec::with_capacity(192);
        out.extend_from_slice(M8_POLICY_MAGIC);
        put_u16(&mut out, M8_POLICY_VERSION);
        out.extend_from_slice(&self.settlement_terms_hash);
        put_offset(&mut out, self.first_refund);
        put_offset(&mut out, self.second_refund);
        put_u64(&mut out, self.safety_margin_seconds);
        put_bounds(&mut out, self.dom_bounds);
        put_bounds(&mut out, self.btc_bounds);
        out.push(self.bitcoin_finality.network as u8);
        put_u32(&mut out, self.bitcoin_finality.minimum_confirmations);
        put_u32(&mut out, self.bitcoin_finality.maximum_reorg_depth);
        put_bool(&mut out, self.bitcoin_finality.require_header_chain);
        put_bool(&mut out, self.bitcoin_finality.require_witness_commitment);
        out.extend_from_slice(&self.bitcoin_finality.policy_id);
        put_u32(&mut out, self.bitcoin_finality.version);
        Ok(out)
    }

    /// Strict inverse of [`Self::canonical_bytes`].
    ///
    /// Unknown magic, versions, offset/network/boolean tags, truncation,
    /// trailing bytes and invalid policy fields all fail closed.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, TimelockError> {
        let mut cursor = CanonicalCursor::new(bytes);
        if cursor.take(M8_POLICY_MAGIC.len())? != M8_POLICY_MAGIC {
            return Err(TimelockError::InvalidEncodingMagic);
        }
        if cursor.take_u16()? != M8_POLICY_VERSION {
            return Err(TimelockError::UnsupportedEncodingVersion);
        }
        let policy = Self {
            settlement_terms_hash: cursor.take_array()?,
            first_refund: take_offset(&mut cursor)?,
            second_refund: take_offset(&mut cursor)?,
            safety_margin_seconds: cursor.take_u64()?,
            dom_bounds: take_bounds(&mut cursor)?,
            btc_bounds: take_bounds(&mut cursor)?,
            bitcoin_finality: BitcoinFinalityPolicyV1 {
                network: take_network(&mut cursor)?,
                minimum_confirmations: cursor.take_u32()?,
                maximum_reorg_depth: cursor.take_u32()?,
                require_header_chain: take_bool(&mut cursor)?,
                require_witness_commitment: take_bool(&mut cursor)?,
                policy_id: cursor.take_array()?,
                version: cursor.take_u32()?,
            },
        };
        if !cursor.finished() {
            return Err(TimelockError::TrailingBytes);
        }
        policy.validate()?;
        Ok(policy)
    }

    /// Canonical policy digest: BLAKE2b-256 over a fixed domain separator and
    /// [`Self::canonical_bytes`].
    pub fn policy_digest(&self) -> Result<[u8; 32], TimelockError> {
        blake2b_256(M8_POLICY_DOMAIN, &self.canonical_bytes()?)
    }
}

impl M8FundingAnchorsV1 {
    fn validate_present(&self) -> Result<(), TimelockError> {
        if self.dom.funding_txid == [0; 32]
            || self.dom.block_hash == [0; 32]
            || self.bitcoin.funding_txid == [0; 32]
            || self.bitcoin.block_hash == [0; 32]
        {
            return Err(TimelockError::MissingAnchorEvidence);
        }
        Ok(())
    }

    /// Canonical big-endian encoding of the post-confirmation evidence
    /// binding.  It is separate from policy bytes and therefore cannot mutate
    /// pre-funding terms.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TimelockError> {
        self.validate_present()?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(M8_ANCHORS_MAGIC);
        put_u16(&mut out, M8_ANCHORS_VERSION);
        out.extend_from_slice(&self.settlement_terms_hash);
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.dom.funding_txid);
        out.extend_from_slice(&self.dom.block_hash);
        put_u64(&mut out, self.dom.height);
        put_u64(&mut out, self.dom.block_time_seconds);
        out.extend_from_slice(&self.bitcoin.funding_txid);
        out.extend_from_slice(&self.bitcoin.block_hash);
        put_u64(&mut out, self.bitcoin.height);
        put_u64(&mut out, self.bitcoin.median_time_past);
        Ok(out)
    }

    /// Strict inverse of [`Self::canonical_bytes`].
    ///
    /// This decoder establishes structural canonicality only.  The decoded
    /// policy digest and terms hash are authenticated by
    /// [`bind_and_validate_funding_anchors`].
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, TimelockError> {
        let mut cursor = CanonicalCursor::new(bytes);
        if cursor.take(M8_ANCHORS_MAGIC.len())? != M8_ANCHORS_MAGIC {
            return Err(TimelockError::InvalidEncodingMagic);
        }
        if cursor.take_u16()? != M8_ANCHORS_VERSION {
            return Err(TimelockError::UnsupportedEncodingVersion);
        }
        let anchors = Self {
            settlement_terms_hash: cursor.take_array()?,
            policy_digest: cursor.take_array()?,
            dom: DomFundingAnchorV1 {
                funding_txid: cursor.take_array()?,
                block_hash: cursor.take_array()?,
                height: cursor.take_u64()?,
                block_time_seconds: cursor.take_u64()?,
            },
            bitcoin: BitcoinFundingAnchorV1 {
                funding_txid: cursor.take_array()?,
                block_hash: cursor.take_array()?,
                height: cursor.take_u64()?,
                median_time_past: cursor.take_u64()?,
            },
        };
        if !cursor.finished() {
            return Err(TimelockError::TrailingBytes);
        }
        anchors.validate_present()?;
        Ok(anchors)
    }

    /// Digest of the immutable post-confirmation anchor evidence object.
    pub fn evidence_digest(&self) -> Result<[u8; 32], TimelockError> {
        blake2b_256(M8_ANCHORS_DOMAIN, &self.canonical_bytes()?)
    }
}

impl AnchoredCrossChainWindowV1 {
    /// Returns the frozen terms hash bound in both policy and anchor evidence.
    #[must_use]
    pub fn settlement_terms_hash(&self) -> [u8; 32] {
        self.settlement_terms_hash
    }

    /// Returns the exact normative M.8 window derived from real chain bases.
    #[must_use]
    pub fn window(&self) -> &CrossChainWindowV1 {
        &self.window
    }

    /// Returns the digest that binds the post-confirmation anchor evidence.
    #[must_use]
    pub fn anchor_evidence_digest(&self) -> [u8; 32] {
        self.anchor_evidence_digest
    }
}

fn bind_offset(offset: TimelockOffsetV1, anchors: &M8FundingAnchorsV1) -> TimelockSpecV1 {
    match offset {
        TimelockOffsetV1::DomBlocks { delta_blocks } => TimelockSpecV1::DomHeight {
            base_height: anchors.dom.height,
            delta_blocks,
        },
        TimelockOffsetV1::BtcBlocks { delta_blocks } => TimelockSpecV1::BtcBlocks {
            base_height: anchors.bitcoin.height,
            delta_blocks,
        },
        TimelockOffsetV1::BtcTime512s { units } => TimelockSpecV1::BtcTime512s {
            base_mtp: anchors.bitcoin.median_time_past,
            units,
        },
    }
}

fn anchored_absolute_interval(
    spec: &TimelockSpecV1,
    anchors: &M8FundingAnchorsV1,
    dom_bounds: &ChainTimingBoundsV1,
    btc_bounds: &ChainTimingBoundsV1,
) -> Result<TimeIntervalV1, TimelockError> {
    let relative = normalize_to_seconds(spec, dom_bounds, btc_bounds)?;
    let (base_earliest, base_latest) = match *spec {
        TimelockSpecV1::DomHeight { base_height, .. } => {
            if base_height != anchors.dom.height {
                return Err(TimelockError::AnchorBaseMismatch);
            }
            (
                anchors.dom.block_time_seconds,
                anchors.dom.block_time_seconds,
            )
        }
        TimelockSpecV1::BtcBlocks { base_height, .. } => {
            if base_height != anchors.bitcoin.height {
                return Err(TimelockError::AnchorBaseMismatch);
            }
            // A block-height CSV delay is anchored to a block, while the
            // evidence object exposes that block's MTP rather than an exact
            // wall-clock timestamp.  Annex M does not publish the conversion
            // formula.  This LAB candidate conservatively places the funding
            // block within the full 11-header median sample span frozen in the
            // timing policy.  The lower endpoint floors at the Unix epoch;
            // the upper endpoint and all later additions are checked.
            let sample_uncertainty = BTC_MTP_SAMPLE_INTERVALS
                .checked_mul(u64::from(btc_bounds.max_block_seconds))
                .ok_or(TimelockError::Overflow)?;
            (
                anchors
                    .bitcoin
                    .median_time_past
                    .saturating_sub(sample_uncertainty),
                anchors
                    .bitcoin
                    .median_time_past
                    .checked_add(sample_uncertainty)
                    .ok_or(TimelockError::Overflow)?,
            )
        }
        TimelockSpecV1::BtcTime512s { base_mtp, .. } => {
            if base_mtp != anchors.bitcoin.median_time_past {
                return Err(TimelockError::AnchorBaseMismatch);
            }
            // `normalize_to_seconds` already includes the 11-header sample
            // uncertainty and 512-second quantization for this native MTP
            // lock.  Adding another anchor interval here would double-count
            // that uncertainty.
            (
                anchors.bitcoin.median_time_past,
                anchors.bitcoin.median_time_past,
            )
        }
    };
    Ok(TimeIntervalV1 {
        earliest_seconds: base_earliest
            .checked_add(relative.earliest_seconds)
            .ok_or(TimelockError::Overflow)?,
        latest_seconds: base_latest
            .checked_add(relative.latest_seconds)
            .ok_or(TimelockError::Overflow)?,
    })
}

fn validate_anchored_cross_chain_window(
    window: &CrossChainWindowV1,
    anchors: &M8FundingAnchorsV1,
    dom_bounds: &ChainTimingBoundsV1,
    btc_bounds: &ChainTimingBoundsV1,
) -> Result<(), TimelockError> {
    validate_bounds(dom_bounds)?;
    validate_bounds(btc_bounds)?;
    if is_dom(&window.first_refund) == is_dom(&window.second_refund) {
        return Err(TimelockError::InvalidCrossChainTopology);
    }
    if window.safety_margin_seconds < minimum_safety_margin_seconds(dom_bounds, btc_bounds)? {
        return Err(TimelockError::InsufficientSafetyMargin);
    }
    let first = anchored_absolute_interval(&window.first_refund, anchors, dom_bounds, btc_bounds)?;
    let second =
        anchored_absolute_interval(&window.second_refund, anchors, dom_bounds, btc_bounds)?;
    let protected_latest = first
        .latest_seconds
        .checked_add(window.safety_margin_seconds)
        .ok_or(TimelockError::Overflow)?;
    if protected_latest > second.earliest_seconds {
        return Err(TimelockError::UnsafeCrossChainWindow);
    }
    Ok(())
}

/// Binds scanner-verified funding anchors to an immutable pre-funding policy
/// and validates M.8 before nonce generation or signing.
///
/// This function never edits `policy`.  A mismatch in terms, policy digest,
/// missing evidence, arithmetic, topology or the cross-chain inequality fails
/// closed and produces no [`AnchoredCrossChainWindowV1`].
pub fn bind_and_validate_funding_anchors(
    policy: &M8TimingPolicyV1,
    anchors: &M8FundingAnchorsV1,
) -> Result<AnchoredCrossChainWindowV1, TimelockError> {
    policy.validate()?;
    anchors.validate_present()?;
    if anchors.settlement_terms_hash != policy.settlement_terms_hash {
        return Err(TimelockError::TermsHashMismatch);
    }
    let policy_digest = policy.policy_digest()?;
    if anchors.policy_digest != policy_digest {
        return Err(TimelockError::PolicyDigestMismatch);
    }
    let window = CrossChainWindowV1 {
        first_refund: bind_offset(policy.first_refund, anchors),
        second_refund: bind_offset(policy.second_refund, anchors),
        safety_margin_seconds: policy.safety_margin_seconds,
        policy_digest,
    };
    validate_anchored_cross_chain_window(&window, anchors, &policy.dom_bounds, &policy.btc_bounds)?;
    Ok(AnchoredCrossChainWindowV1 {
        settlement_terms_hash: policy.settlement_terms_hash,
        window,
        anchor_evidence_digest: anchors.evidence_digest()?,
    })
}

/// Encodes a CSV delay to the nSequence value of the spending input
/// (M.2.3). The disable flag is always off; only the type flag and the
/// 16-bit value survive the mask.
pub fn encode_csv(delay: BitcoinCsvDelayV1) -> Result<u32, TimelockError> {
    let value = match delay {
        BitcoinCsvDelayV1::Blocks(v) => u32::from(v),
        BitcoinCsvDelayV1::Time512s(v) => SEQUENCE_LOCKTIME_TYPE_FLAG | u32::from(v),
    };
    if value & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
        return Err(TimelockError::DisableFlagSet);
    }
    Ok(value & (SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK))
}

/// Encodes the CSV delay as a Bitcoin script number (minimal encoding),
/// for the `<csv_delay>` push of the refund leaf (M.2.1). CSV operands
/// are non-negative and bounded by the 16-bit delay, so at most 3 bytes.
pub fn script_number_minimal(value: u32) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut v = value;
    while v > 0 {
        out.push((v & 0xff) as u8);
        v >>= 8;
    }
    // If the most-significant byte has its high bit set, push a zero byte
    // so the number is not read as negative (minimal-push rule).
    if out.last().is_some_and(|b| b & 0x80 != 0) {
        out.push(0x00);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_and_time_encode_distinctly() {
        assert_eq!(encode_csv(BitcoinCsvDelayV1::Blocks(144)).unwrap(), 144);
        assert_eq!(
            encode_csv(BitcoinCsvDelayV1::Time512s(6)).unwrap(),
            SEQUENCE_LOCKTIME_TYPE_FLAG | 6
        );
        // The two units never collide.
        assert_ne!(
            encode_csv(BitcoinCsvDelayV1::Blocks(6)).unwrap(),
            encode_csv(BitcoinCsvDelayV1::Time512s(6)).unwrap()
        );
    }

    #[test]
    fn disable_flag_never_set_for_16bit_inputs() {
        for v in [0u16, 1, 0x7fff, 0xffff] {
            assert!(
                encode_csv(BitcoinCsvDelayV1::Blocks(v)).unwrap() & SEQUENCE_LOCKTIME_DISABLE_FLAG
                    == 0
            );
            assert!(
                encode_csv(BitcoinCsvDelayV1::Time512s(v)).unwrap()
                    & SEQUENCE_LOCKTIME_DISABLE_FLAG
                    == 0
            );
        }
    }

    #[test]
    fn script_number_minimal_matches_known_values() {
        assert_eq!(script_number_minimal(0), Vec::<u8>::new());
        assert_eq!(script_number_minimal(1), vec![0x01]);
        assert_eq!(script_number_minimal(144), vec![0x90, 0x00]); // high bit set -> pad
        assert_eq!(script_number_minimal(127), vec![0x7f]);
        assert_eq!(script_number_minimal(128), vec![0x80, 0x00]);
        assert_eq!(script_number_minimal(258), vec![0x02, 0x01]);
    }
}

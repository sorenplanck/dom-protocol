//! Genesis-rooted Regtest header authority for Bitcoin evidence V2.
//!
//! Regtest deliberately has a fixed proof-of-work limit and no retargeting.
//! This authority therefore rejects every self-declared `nBits` value other
//! than `0x207fffff`, validates proof of work against that fixed target, and
//! authenticates one continuous chain from the canonical Regtest genesis to
//! the evidence confirmation tip. The checkpoint is an optimization and a
//! frozen replay boundary, never an alternative trust root: it can only be
//! constructed by validating its complete genesis-rooted ancestry.

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::pow::{CompactTarget, Target, Work};
use bitcoin::{block::Header, Block, Network};

use crate::evidence_v2::{BitcoinEvidenceNetworkV2, KeystoneBitcoinEvidenceV2};

use super::{
    canonical_evidence_digest_v2, confirmation_chain_digest_v2,
    preflight_full_block_transaction_count_v2, AuthenticatedBlockV2,
};

const REGTEST_POLICY_DOMAIN_V2: &[u8] = b"DOM/BTC-EVIDENCE/V2/REGTEST-POLICY\0";
const REGTEST_CHAIN_INITIAL_DOMAIN_V2: &[u8] = b"DOM/BTC-EVIDENCE/V2/REGTEST-CHAIN-INITIAL\0";
const REGTEST_CHAIN_APPEND_DOMAIN_V2: &[u8] = b"DOM/BTC-EVIDENCE/V2/REGTEST-CHAIN-APPEND\0";
const REGTEST_CHECKPOINT_DOMAIN_V2: &[u8] = b"DOM/BTC-EVIDENCE/V2/REGTEST-CHECKPOINT\0";
const REGTEST_AUTHORITY_DOMAIN_V2: &[u8] = b"DOM/BTC-EVIDENCE/V2/REGTEST-HEADER-AUTHORITY\0";

/// Fail-closed errors emitted by the genesis-rooted Regtest V2 authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegtestHeaderAuthorityErrorV2 {
    /// Confirmation depth is zero or exceeds the V2 successor bound.
    #[error("invalid Regtest confirmation-depth policy")]
    InvalidConfirmationDepth,
    /// A genesis-rooted checkpoint proof was empty.
    #[error("empty Regtest genesis ancestry")]
    EmptyGenesisAncestry,
    /// A checkpoint or continuation ancestry exceeded its hard bound before
    /// any header was decoded.
    #[error("Regtest ancestry exceeds its hard bound")]
    AncestryBoundExceeded,
    /// The V2 complete block exceeded its pre-deserialization bound.
    #[error("Regtest V2 complete block exceeds its hard bound")]
    FullBlockBoundExceeded,
    /// The successor vector exceeded its bound before any successor header was
    /// decoded.
    #[error("Regtest V2 successor list exceeds its hard bound")]
    SuccessorBoundExceeded,
    /// The first checkpoint header was not the exact canonical Regtest
    /// genesis header.
    #[error("Regtest checkpoint is not rooted at the canonical genesis")]
    ForeignGenesisRoot,
    /// A fixed-width header or the full block failed consensus decoding.
    #[error("Regtest header or full block parse failed")]
    ParseFailed,
    /// Re-encoding did not reproduce the exact supplied bytes.
    #[error("Regtest header or full block encoding is non-canonical")]
    NonCanonicalEncoding,
    /// A header declared `nBits` other than the fixed Regtest value.
    #[error("unexpected Regtest nBits")]
    UnexpectedBits,
    /// A header hash does not satisfy the fixed Regtest target.
    #[error("invalid Regtest proof of work")]
    InvalidProofOfWork,
    /// A header does not name the immediately preceding authenticated header.
    #[error("broken Regtest header linkage")]
    BrokenHeaderLink,
    /// A header timestamp is not strictly greater than the rolling median of
    /// the preceding eleven (or all available) headers.
    #[error("Regtest median-time-past violation")]
    MedianTimePastViolation,
    /// Header height arithmetic overflowed.
    #[error("Regtest header height overflow")]
    HeightOverflow,
    /// The explicit containing-block height does not equal checkpoint height
    /// plus the exact continuation length.
    #[error("Regtest containing-block height mismatch")]
    HeightMismatch,
    /// The complete block header is not the terminal header of the supplied
    /// checkpoint continuation.
    #[error("Regtest complete block is not the authenticated ancestry tip")]
    FullBlockHeaderMismatch,
    /// Evidence selected another network or genesis.
    #[error("Regtest evidence network identity mismatch")]
    NetworkIdentityMismatch,
    /// Evidence did not carry the canonical digest of this fixed Regtest
    /// policy.
    #[error("Regtest evidence policy digest mismatch")]
    PolicyDigestMismatch,
    /// Evidence did not carry the exact genesis-rooted checkpoint digest owned
    /// by this authority.
    #[error("Regtest evidence checkpoint digest mismatch")]
    CheckpointDigestMismatch,
    /// Evidence requested a different minimum confirmation depth.
    #[error("Regtest evidence confirmation policy mismatch")]
    ConfirmationPolicyMismatch,
    /// The successor count does not meet the fixed policy. Depth includes the
    /// containing block, so depth `N` requires exactly at least `N - 1`
    /// successors.
    #[error("insufficient Regtest confirmations")]
    InsufficientConfirmations,
    /// The complete block's canonical transaction-count prefix was invalid.
    #[error("invalid Regtest V2 full-block transaction count")]
    InvalidFullBlockTransactionCount,
    /// A canonical evidence digest could not be produced from a supposedly
    /// valid V2 object.
    #[error("failed to bind canonical Regtest V2 evidence")]
    EvidenceBindingFailed,
}

/// Fixed, code-first Regtest header policy used by evidence V2.
///
/// The only operator-selected field is the minimum confirmation depth. The
/// network, genesis, expected `nBits`, MTP span and all allocation bounds are
/// compile-time facts included in [`Self::digest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegtestHeaderPolicyV2 {
    minimum_confirmation_depth: u32,
    digest: [u8; 32],
}

impl RegtestHeaderPolicyV2 {
    /// Bitcoin Core's fixed Regtest compact target.
    pub const EXPECTED_BITS: u32 = 0x207f_ffff;
    /// Bitcoin Core's median-time-past sample size.
    pub const MEDIAN_TIME_PAST_SPAN: usize = 11;
    /// Maximum headers accepted from the canonical genesis through a retained
    /// checkpoint, including genesis and checkpoint.
    pub const MAX_GENESIS_ROOTED_HEADERS: usize = 100_001;
    /// Maximum headers accepted after a retained checkpoint through and
    /// including the evidence block.
    pub const MAX_CONTINUATION_HEADERS: usize = 100_000;

    /// Creates the fixed Regtest policy for an explicit depth.
    pub fn new(minimum_confirmation_depth: u32) -> Result<Self, RegtestHeaderAuthorityErrorV2> {
        let maximum_depth = KeystoneBitcoinEvidenceV2::MAX_CONFIRMATION_HEADERS
            .checked_add(1)
            .ok_or(RegtestHeaderAuthorityErrorV2::InvalidConfirmationDepth)?;
        if minimum_confirmation_depth == 0 || minimum_confirmation_depth > maximum_depth {
            return Err(RegtestHeaderAuthorityErrorV2::InvalidConfirmationDepth);
        }
        Ok(Self {
            minimum_confirmation_depth,
            digest: regtest_policy_digest_v2(minimum_confirmation_depth),
        })
    }

    /// Minimum depth, counting the containing block as depth one.
    #[must_use]
    pub const fn minimum_confirmation_depth(&self) -> u32 {
        self.minimum_confirmation_depth
    }

    /// Canonical digest that the V2 evidence must carry as its policy binding.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Opaque genesis-rooted Regtest checkpoint.
///
/// A checkpoint cannot be created from a height/hash assertion. Construction
/// verifies every header from the exact canonical genesis, including fixed
/// `nBits`, linkage, proof of work and rolling MTP. Its digest therefore pins
/// the precise fork and cumulative work used by subsequent evidence.
#[derive(Clone)]
pub struct RegtestHeaderCheckpointV2 {
    state: HeaderChainStateV2,
    digest: [u8; 32],
}

impl RegtestHeaderCheckpointV2 {
    /// Creates the canonical height-zero checkpoint.
    pub fn genesis() -> Result<Self, RegtestHeaderAuthorityErrorV2> {
        let raw = canonical_regtest_genesis_header_v2()?;
        Self::from_genesis_ancestry(&[raw])
    }

    /// Validates an exact sequence from Regtest genesis through the desired
    /// checkpoint, inclusive.
    ///
    /// The length cap is checked before decoding the first caller-provided
    /// header.
    pub fn from_genesis_ancestry(
        headers: &[[u8; 80]],
    ) -> Result<Self, RegtestHeaderAuthorityErrorV2> {
        if headers.is_empty() {
            return Err(RegtestHeaderAuthorityErrorV2::EmptyGenesisAncestry);
        }
        if headers.len() > RegtestHeaderPolicyV2::MAX_GENESIS_ROOTED_HEADERS {
            return Err(RegtestHeaderAuthorityErrorV2::AncestryBoundExceeded);
        }
        let canonical_genesis = canonical_regtest_genesis_header_v2()?;
        if headers[0] != canonical_genesis {
            return Err(RegtestHeaderAuthorityErrorV2::ForeignGenesisRoot);
        }

        let mut state = HeaderChainStateV2::from_canonical_genesis(canonical_genesis)?;
        for raw_header in &headers[1..] {
            state.append_raw(*raw_header)?;
        }
        let digest = regtest_checkpoint_digest_v2(&state);
        Ok(Self { state, digest })
    }

    /// Height of the authenticated checkpoint.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.state.height
    }

    /// Hash of the authenticated checkpoint in Bitcoin internal byte order.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.state.tip_hash
    }

    /// Canonical checkpoint digest required in evidence V2.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Cumulative work from genesis through this checkpoint, big-endian.
    #[must_use]
    pub fn chain_work(&self) -> [u8; 32] {
        self.state.chain_work.to_be_bytes()
    }

    /// Rolling median-time-past at this checkpoint.
    #[must_use]
    pub fn median_time_past(&self) -> u32 {
        self.state.median_time_past()
    }
}

/// The only production authority capable of constructing
/// [`AuthenticatedBlockV2`] in this crate.
///
/// It owns a fixed Regtest policy and a genesis-rooted checkpoint. Calling
/// [`Self::authenticate`] proves the exact continuation through the mandatory
/// full block and all V2 successors, then binds route, terms, policy,
/// checkpoint and the complete canonical evidence codec into the result.
pub struct RegtestHeaderAuthorityV2 {
    policy: RegtestHeaderPolicyV2,
    checkpoint: RegtestHeaderCheckpointV2,
}

impl RegtestHeaderAuthorityV2 {
    /// Creates an authority from an already genesis-authenticated checkpoint.
    #[must_use]
    pub const fn new(policy: RegtestHeaderPolicyV2, checkpoint: RegtestHeaderCheckpointV2) -> Self {
        Self { policy, checkpoint }
    }

    /// Fixed policy owned by this authority.
    #[must_use]
    pub const fn policy(&self) -> &RegtestHeaderPolicyV2 {
        &self.policy
    }

    /// Exact genesis-rooted checkpoint owned by this authority.
    #[must_use]
    pub const fn checkpoint(&self) -> &RegtestHeaderCheckpointV2 {
        &self.checkpoint
    }

    /// Authenticates one complete V2 Regtest evidence object.
    ///
    /// `continuation_after_checkpoint` contains every header strictly after
    /// the retained checkpoint through and including the header of
    /// `evidence.full_block_bytes()`. It is empty only when that full block is
    /// exactly the checkpoint block. Successor headers come exclusively from
    /// the bounded V2 evidence codec.
    pub fn authenticate(
        &self,
        evidence: &KeystoneBitcoinEvidenceV2,
        continuation_after_checkpoint: &[[u8; 80]],
    ) -> Result<AuthenticatedBlockV2, RegtestHeaderAuthorityErrorV2> {
        self.preflight(evidence, continuation_after_checkpoint)?;

        preflight_full_block_transaction_count_v2(evidence.full_block_bytes())
            .map_err(|_| RegtestHeaderAuthorityErrorV2::InvalidFullBlockTransactionCount)?;
        let block: Block = deserialize(evidence.full_block_bytes())
            .map_err(|_| RegtestHeaderAuthorityErrorV2::ParseFailed)?;
        if serialize(&block) != evidence.full_block_bytes() {
            return Err(RegtestHeaderAuthorityErrorV2::NonCanonicalEncoding);
        }

        let continuation_count = u64::try_from(continuation_after_checkpoint.len())
            .map_err(|_| RegtestHeaderAuthorityErrorV2::HeightOverflow)?;
        let expected_block_height = self
            .checkpoint
            .state
            .height
            .checked_add(continuation_count)
            .ok_or(RegtestHeaderAuthorityErrorV2::HeightOverflow)?;
        if expected_block_height != evidence.header_policy().block_height() {
            return Err(RegtestHeaderAuthorityErrorV2::HeightMismatch);
        }

        let mut state = self.checkpoint.state.clone();
        for raw_header in continuation_after_checkpoint {
            state.append_raw(*raw_header)?;
        }
        let full_block_header: [u8; 80] = serialize(&block.header)
            .try_into()
            .map_err(|_| RegtestHeaderAuthorityErrorV2::NonCanonicalEncoding)?;
        if state.tip_raw != full_block_header || state.height != expected_block_height {
            return Err(RegtestHeaderAuthorityErrorV2::FullBlockHeaderMismatch);
        }

        let containing_block_hash = state.tip_hash;
        for raw_header in evidence.confirmation_headers() {
            state.append_raw(*raw_header)?;
        }

        let confirmation_depth = u32::try_from(evidence.confirmation_headers().len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(RegtestHeaderAuthorityErrorV2::HeightOverflow)?;
        if confirmation_depth < self.policy.minimum_confirmation_depth {
            return Err(RegtestHeaderAuthorityErrorV2::InsufficientConfirmations);
        }
        let evidence_digest = canonical_evidence_digest_v2(evidence)
            .map_err(|_| RegtestHeaderAuthorityErrorV2::EvidenceBindingFailed)?;
        let confirmation_chain_digest =
            confirmation_chain_digest_v2(&block.header, evidence.confirmation_headers());
        let chain_work = state.chain_work.to_be_bytes();
        let median_time_past = state.median_time_past();
        let header_authority_digest = regtest_header_authority_digest_v2(
            evidence,
            RegtestHeaderAuthorityDigestFactsV2 {
                policy_digest: self.policy.digest,
                checkpoint_digest: self.checkpoint.digest,
                evidence_digest,
                block_hash: containing_block_hash,
                tip_hash: state.tip_hash,
                tip_height: state.height,
                confirmation_depth,
                confirmation_chain_digest,
                genesis_rooted_chain_digest: state.chain_digest,
                chain_work,
                median_time_past,
            },
        );

        Ok(AuthenticatedBlockV2 {
            _authority_seal: RegtestAuthenticationSealV2::new(),
            network: BitcoinEvidenceNetworkV2::Regtest,
            network_genesis_hash: canonical_regtest_genesis_hash_v2(),
            block_hash: containing_block_hash,
            block_height: expected_block_height,
            confirmation_tip_hash: state.tip_hash,
            confirmation_tip_height: state.height,
            confirmation_depth,
            confirmation_chain_digest,
            minimum_confirmation_depth: self.policy.minimum_confirmation_depth,
            policy_digest: self.policy.digest,
            checkpoint_digest: self.checkpoint.digest,
            evidence_digest,
            genesis_rooted_chain_digest: state.chain_digest,
            confirmation_tip_chain_work: chain_work,
            confirmation_tip_median_time_past: median_time_past,
            header_authority_digest,
        })
    }

    fn preflight(
        &self,
        evidence: &KeystoneBitcoinEvidenceV2,
        continuation_after_checkpoint: &[[u8; 80]],
    ) -> Result<(), RegtestHeaderAuthorityErrorV2> {
        if evidence.full_block_bytes().is_empty()
            || evidence.full_block_bytes().len()
                > KeystoneBitcoinEvidenceV2::MAX_FULL_BLOCK_BYTES as usize
        {
            return Err(RegtestHeaderAuthorityErrorV2::FullBlockBoundExceeded);
        }
        if continuation_after_checkpoint.len() > RegtestHeaderPolicyV2::MAX_CONTINUATION_HEADERS {
            return Err(RegtestHeaderAuthorityErrorV2::AncestryBoundExceeded);
        }
        if evidence.confirmation_headers().len()
            > KeystoneBitcoinEvidenceV2::MAX_CONFIRMATION_HEADERS as usize
        {
            return Err(RegtestHeaderAuthorityErrorV2::SuccessorBoundExceeded);
        }

        let binding = evidence.header_policy();
        if binding.network() != BitcoinEvidenceNetworkV2::Regtest
            || binding.network_genesis_hash() != canonical_regtest_genesis_hash_v2()
        {
            return Err(RegtestHeaderAuthorityErrorV2::NetworkIdentityMismatch);
        }
        if binding.policy_digest() != self.policy.digest {
            return Err(RegtestHeaderAuthorityErrorV2::PolicyDigestMismatch);
        }
        if binding.checkpoint_digest() != self.checkpoint.digest {
            return Err(RegtestHeaderAuthorityErrorV2::CheckpointDigestMismatch);
        }
        if binding.minimum_confirmation_depth() != self.policy.minimum_confirmation_depth {
            return Err(RegtestHeaderAuthorityErrorV2::ConfirmationPolicyMismatch);
        }
        Ok(())
    }
}

/// Private construction seal retained inside the concrete Regtest authority.
///
/// The parent verifier can store this field but no sibling module can create a
/// value because the tuple field and constructor are private here.
pub(super) struct RegtestAuthenticationSealV2(());

impl RegtestAuthenticationSealV2 {
    const fn new() -> Self {
        Self(())
    }
}

#[derive(Clone)]
struct HeaderChainStateV2 {
    height: u64,
    tip_hash: [u8; 32],
    tip_raw: [u8; 80],
    timestamps: [u32; RegtestHeaderPolicyV2::MEDIAN_TIME_PAST_SPAN],
    timestamp_count: usize,
    chain_work: Work,
    chain_digest: [u8; 32],
}

impl HeaderChainStateV2 {
    fn from_canonical_genesis(
        raw_genesis: [u8; 80],
    ) -> Result<Self, RegtestHeaderAuthorityErrorV2> {
        let header = decode_header_v2(raw_genesis)?;
        validate_regtest_pow_v2(&header)?;
        let mut timestamps = [0u32; RegtestHeaderPolicyV2::MEDIAN_TIME_PAST_SPAN];
        timestamps[0] = header.time;
        Ok(Self {
            height: 0,
            tip_hash: header.block_hash().to_raw_hash().to_byte_array(),
            tip_raw: raw_genesis,
            timestamps,
            timestamp_count: 1,
            chain_work: fixed_regtest_target_v2().to_work(),
            chain_digest: initial_chain_digest_v2(raw_genesis),
        })
    }

    fn append_raw(&mut self, raw_header: [u8; 80]) -> Result<(), RegtestHeaderAuthorityErrorV2> {
        let header = decode_header_v2(raw_header)?;
        if header.prev_blockhash.to_raw_hash().to_byte_array() != self.tip_hash {
            return Err(RegtestHeaderAuthorityErrorV2::BrokenHeaderLink);
        }
        validate_regtest_pow_v2(&header)?;
        if header.time <= self.median_time_past() {
            return Err(RegtestHeaderAuthorityErrorV2::MedianTimePastViolation);
        }
        let height = self
            .height
            .checked_add(1)
            .ok_or(RegtestHeaderAuthorityErrorV2::HeightOverflow)?;
        let hash = header.block_hash().to_raw_hash().to_byte_array();
        let chain_digest = append_chain_digest_v2(self.chain_digest, height, raw_header);
        self.push_timestamp(header.time);
        self.height = height;
        self.tip_hash = hash;
        self.tip_raw = raw_header;
        self.chain_work = self.chain_work + fixed_regtest_target_v2().to_work();
        self.chain_digest = chain_digest;
        Ok(())
    }

    fn median_time_past(&self) -> u32 {
        let mut sample = self.timestamps;
        sample[..self.timestamp_count].sort_unstable();
        sample[self.timestamp_count / 2]
    }

    fn push_timestamp(&mut self, timestamp: u32) {
        if self.timestamp_count < self.timestamps.len() {
            self.timestamps[self.timestamp_count] = timestamp;
            self.timestamp_count += 1;
            return;
        }
        self.timestamps.copy_within(1.., 0);
        self.timestamps[self.timestamps.len() - 1] = timestamp;
    }
}

fn validate_regtest_pow_v2(header: &Header) -> Result<(), RegtestHeaderAuthorityErrorV2> {
    if header.bits.to_consensus() != RegtestHeaderPolicyV2::EXPECTED_BITS {
        return Err(RegtestHeaderAuthorityErrorV2::UnexpectedBits);
    }
    header
        .validate_pow(fixed_regtest_target_v2())
        .map_err(|_| RegtestHeaderAuthorityErrorV2::InvalidProofOfWork)?;
    Ok(())
}

fn decode_header_v2(raw: [u8; 80]) -> Result<Header, RegtestHeaderAuthorityErrorV2> {
    let header: Header =
        deserialize(&raw).map_err(|_| RegtestHeaderAuthorityErrorV2::ParseFailed)?;
    if serialize(&header) != raw {
        return Err(RegtestHeaderAuthorityErrorV2::NonCanonicalEncoding);
    }
    Ok(header)
}

fn fixed_regtest_target_v2() -> Target {
    Target::from_compact(CompactTarget::from_consensus(
        RegtestHeaderPolicyV2::EXPECTED_BITS,
    ))
}

fn canonical_regtest_genesis_header_v2() -> Result<[u8; 80], RegtestHeaderAuthorityErrorV2> {
    serialize(&genesis_block(Network::Regtest).header)
        .try_into()
        .map_err(|_| RegtestHeaderAuthorityErrorV2::NonCanonicalEncoding)
}

fn canonical_regtest_genesis_hash_v2() -> [u8; 32] {
    genesis_block(Network::Regtest)
        .block_hash()
        .to_raw_hash()
        .to_byte_array()
}

fn regtest_policy_digest_v2(minimum_confirmation_depth: u32) -> [u8; 32] {
    let mut engine = bitcoin::hashes::sha256d::Hash::engine();
    engine.input(REGTEST_POLICY_DOMAIN_V2);
    engine.input(&2u16.to_be_bytes());
    engine.input(&canonical_regtest_genesis_hash_v2());
    engine.input(&RegtestHeaderPolicyV2::EXPECTED_BITS.to_be_bytes());
    engine.input(
        &u32::try_from(RegtestHeaderPolicyV2::MEDIAN_TIME_PAST_SPAN)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    engine.input(
        &u32::try_from(RegtestHeaderPolicyV2::MAX_GENESIS_ROOTED_HEADERS)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    engine.input(
        &u32::try_from(RegtestHeaderPolicyV2::MAX_CONTINUATION_HEADERS)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    engine.input(&KeystoneBitcoinEvidenceV2::MAX_FULL_BLOCK_BYTES.to_be_bytes());
    engine.input(&KeystoneBitcoinEvidenceV2::MAX_CONFIRMATION_HEADERS.to_be_bytes());
    engine.input(&minimum_confirmation_depth.to_be_bytes());
    bitcoin::hashes::sha256d::Hash::from_engine(engine).to_byte_array()
}

fn initial_chain_digest_v2(raw_genesis: [u8; 80]) -> [u8; 32] {
    let mut engine = bitcoin::hashes::sha256d::Hash::engine();
    engine.input(REGTEST_CHAIN_INITIAL_DOMAIN_V2);
    engine.input(&0u64.to_be_bytes());
    engine.input(&raw_genesis);
    bitcoin::hashes::sha256d::Hash::from_engine(engine).to_byte_array()
}

fn append_chain_digest_v2(
    previous_digest: [u8; 32],
    height: u64,
    raw_header: [u8; 80],
) -> [u8; 32] {
    let mut engine = bitcoin::hashes::sha256d::Hash::engine();
    engine.input(REGTEST_CHAIN_APPEND_DOMAIN_V2);
    engine.input(&previous_digest);
    engine.input(&height.to_be_bytes());
    engine.input(&raw_header);
    bitcoin::hashes::sha256d::Hash::from_engine(engine).to_byte_array()
}

fn regtest_checkpoint_digest_v2(state: &HeaderChainStateV2) -> [u8; 32] {
    let mut engine = bitcoin::hashes::sha256d::Hash::engine();
    engine.input(REGTEST_CHECKPOINT_DOMAIN_V2);
    engine.input(&2u16.to_be_bytes());
    engine.input(&canonical_regtest_genesis_hash_v2());
    engine.input(&state.height.to_be_bytes());
    engine.input(&state.tip_hash);
    engine.input(&state.tip_raw);
    engine.input(&state.chain_digest);
    engine.input(&state.chain_work.to_be_bytes());
    let timestamp_count = u32::try_from(state.timestamp_count).unwrap_or(u32::MAX);
    engine.input(&timestamp_count.to_be_bytes());
    for timestamp in &state.timestamps[..state.timestamp_count] {
        engine.input(&timestamp.to_be_bytes());
    }
    bitcoin::hashes::sha256d::Hash::from_engine(engine).to_byte_array()
}

fn regtest_header_authority_digest_v2(
    evidence: &KeystoneBitcoinEvidenceV2,
    facts: RegtestHeaderAuthorityDigestFactsV2,
) -> [u8; 32] {
    let mut engine = bitcoin::hashes::sha256d::Hash::engine();
    engine.input(REGTEST_AUTHORITY_DOMAIN_V2);
    engine.input(&2u16.to_be_bytes());
    engine.input(&canonical_regtest_genesis_hash_v2());
    engine.input(&evidence.route().settlement_id());
    engine.input(&evidence.route().terms_hash());
    engine.input(&facts.policy_digest);
    engine.input(&facts.checkpoint_digest);
    engine.input(&facts.evidence_digest);
    engine.input(&facts.block_hash);
    engine.input(&evidence.header_policy().block_height().to_be_bytes());
    engine.input(&facts.tip_hash);
    engine.input(&facts.tip_height.to_be_bytes());
    engine.input(&facts.confirmation_depth.to_be_bytes());
    engine.input(&facts.confirmation_chain_digest);
    engine.input(&facts.genesis_rooted_chain_digest);
    engine.input(&facts.chain_work);
    engine.input(&facts.median_time_past.to_be_bytes());
    bitcoin::hashes::sha256d::Hash::from_engine(engine).to_byte_array()
}

#[derive(Clone, Copy)]
struct RegtestHeaderAuthorityDigestFactsV2 {
    policy_digest: [u8; 32],
    checkpoint_digest: [u8; 32],
    evidence_digest: [u8; 32],
    block_hash: [u8; 32],
    tip_hash: [u8; 32],
    tip_height: u64,
    confirmation_depth: u32,
    confirmation_chain_digest: [u8; 32],
    genesis_rooted_chain_digest: [u8; 32],
    chain_work: [u8; 32],
    median_time_past: u32,
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::blockdata::block::Version;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
        Txid, Witness,
    };

    use crate::evidence_v2::{
        BitcoinEvidenceRouteBindingV2, BitcoinHeaderPolicyBindingV2, BitcoinOutPointV2,
        BitcoinOutcomeV2, BitcoinTransactionClaimV2,
    };
    use crate::{verify_evidence_v2, EvidenceVerificationErrorV2};

    use super::*;

    struct RegtestEvidenceFixtureV2 {
        authority: RegtestHeaderAuthorityV2,
        evidence: KeystoneBitcoinEvidenceV2,
        continuation: Vec<[u8; 80]>,
        containing_block: Block,
    }

    fn authentication_error(
        result: Result<AuthenticatedBlockV2, RegtestHeaderAuthorityErrorV2>,
    ) -> RegtestHeaderAuthorityErrorV2 {
        result.err().expect("adversarial authentication must fail")
    }

    fn raw_header(header: &Header) -> [u8; 80] {
        serialize(header)
            .try_into()
            .expect("Bitcoin header is exactly 80 bytes")
    }

    fn mine_header(header: &mut Header) {
        let target = header.target();
        while header.validate_pow(target).is_err() {
            header.nonce = header.nonce.checked_add(1).expect("easy Regtest target");
        }
    }

    fn next_header(previous: &Header, time: u32) -> Header {
        let mut header = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: previous.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(RegtestHeaderPolicyV2::EXPECTED_BITS),
            nonce: 0,
        };
        mine_header(&mut header);
        header
    }

    fn claimed_transaction() -> Transaction {
        let mut witness = Witness::new();
        witness.push([0x11; 64]);
        Transaction {
            version: TxVersion(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(Hash::from_byte_array([0x33; 32])),
                    vout: 7,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd),
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn fixture(
        checkpoint_height: u64,
        minimum_depth: u32,
        successor_count: usize,
    ) -> RegtestEvidenceFixtureV2 {
        let genesis = genesis_block(Network::Regtest);
        let mut checkpoint_headers = vec![raw_header(&genesis.header)];
        let mut previous = genesis.header;
        for offset in 1..=checkpoint_height {
            let offset = u32::try_from(offset).expect("test height fits u32");
            let header = next_header(&previous, genesis.header.time.saturating_add(offset));
            checkpoint_headers.push(raw_header(&header));
            previous = header;
        }
        let checkpoint = RegtestHeaderCheckpointV2::from_genesis_ancestry(&checkpoint_headers)
            .expect("valid genesis-rooted checkpoint");
        let policy = RegtestHeaderPolicyV2::new(minimum_depth).expect("valid Regtest depth policy");

        let transaction = claimed_transaction();
        let mut containing_header = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: previous.block_hash(),
            merkle_root: TxMerkleNode::from_raw_hash(transaction.compute_txid().to_raw_hash()),
            time: previous.time.saturating_add(1),
            bits: CompactTarget::from_consensus(RegtestHeaderPolicyV2::EXPECTED_BITS),
            nonce: 0,
        };
        mine_header(&mut containing_header);
        let containing_block = Block {
            header: containing_header,
            txdata: vec![transaction.clone()],
        };
        let continuation = vec![raw_header(&containing_block.header)];

        let mut successors = Vec::with_capacity(successor_count);
        let mut successor_previous = containing_block.header;
        for offset in 1..=successor_count {
            let offset = u32::try_from(offset).expect("test depth fits u32");
            let header = next_header(
                &successor_previous,
                containing_block.header.time.saturating_add(offset),
            );
            successors.push(raw_header(&header));
            successor_previous = header;
        }

        let route =
            BitcoinEvidenceRouteBindingV2::new([0x41; 32], [0x42; 32]).expect("route binding");
        let header_policy = BitcoinHeaderPolicyBindingV2::new(
            BitcoinEvidenceNetworkV2::Regtest,
            genesis.block_hash().to_raw_hash().to_byte_array(),
            checkpoint_height.saturating_add(1),
            policy.digest(),
            checkpoint.digest(),
            minimum_depth,
        )
        .expect("header-policy binding");
        let claim = BitcoinTransactionClaimV2::new(
            transaction.compute_txid().to_raw_hash().to_byte_array(),
            transaction.compute_wtxid().to_raw_hash().to_byte_array(),
            BitcoinOutPointV2::new(
                transaction.input[0]
                    .previous_output
                    .txid
                    .to_raw_hash()
                    .to_byte_array(),
                transaction.input[0].previous_output.vout,
            )
            .expect("claimed outpoint"),
            1,
            0,
            BitcoinOutcomeV2::KeyPathClaim,
        )
        .expect("transaction claim");
        let evidence = KeystoneBitcoinEvidenceV2::new(
            route,
            header_policy,
            claim,
            serialize(&containing_block),
            successors,
        )
        .expect("bounded V2 evidence");

        RegtestEvidenceFixtureV2 {
            authority: RegtestHeaderAuthorityV2::new(policy, checkpoint),
            evidence,
            continuation,
            containing_block,
        }
    }

    fn replace_header_policy(
        evidence: &KeystoneBitcoinEvidenceV2,
        header_policy: BitcoinHeaderPolicyBindingV2,
    ) -> KeystoneBitcoinEvidenceV2 {
        KeystoneBitcoinEvidenceV2::new(
            *evidence.route(),
            header_policy,
            *evidence.transaction(),
            evidence.full_block_bytes().to_vec(),
            evidence.confirmation_headers().to_vec(),
        )
        .expect("replacement remains structurally bounded")
    }

    fn replace_block(
        evidence: &KeystoneBitcoinEvidenceV2,
        block: &Block,
    ) -> KeystoneBitcoinEvidenceV2 {
        KeystoneBitcoinEvidenceV2::new(
            *evidence.route(),
            *evidence.header_policy(),
            *evidence.transaction(),
            serialize(block),
            evidence.confirmation_headers().to_vec(),
        )
        .expect("replacement block remains bounded")
    }

    #[test]
    fn authority_authenticates_genesis_checkpoint_mtp_depth_and_chainwork() {
        let fixture = fixture(12, 2, 1);
        let authenticated = fixture
            .authority
            .authenticate(&fixture.evidence, &fixture.continuation)
            .expect("complete Regtest ancestry is authenticated");

        assert_eq!(authenticated.block_height(), 13);
        assert_eq!(authenticated.confirmation_tip_height(), 14);
        assert_eq!(authenticated.confirmation_depth(), 2);
        assert_ne!(authenticated.genesis_rooted_chain_digest(), [0; 32]);
        assert_ne!(authenticated.header_authority_digest(), [0; 32]);
        assert_eq!(
            fixture.authority.checkpoint().median_time_past(),
            genesis_block(Network::Regtest)
                .header
                .time
                .saturating_add(7)
        );

        let expected_single_work = fixed_regtest_target_v2().to_work();
        let checkpoint_work = Work::from_be_bytes(fixture.authority.checkpoint().chain_work());
        let mut expected_tip_work = checkpoint_work;
        // Exactly two headers follow the checkpoint here: the containing
        // block and its one successor. Counting the containing header both as
        // continuation and full-block input would make this assertion fail.
        for _ in 0..=fixture.evidence.confirmation_headers().len() {
            expected_tip_work = expected_tip_work + expected_single_work;
        }
        assert_eq!(
            authenticated.confirmation_tip_chain_work(),
            expected_tip_work.to_be_bytes()
        );
    }

    #[test]
    fn authority_rejects_self_declared_bits_broken_link_rolling_mtp_and_height() {
        // At height 12 the retained window is exactly heights 2..=12. Its
        // median is height 7, proving the candidate header is compared with
        // the preceding eleven headers and is not itself part of the sample.
        let fixture = fixture(12, 2, 1);
        assert_eq!(
            fixture.authority.checkpoint().median_time_past(),
            genesis_block(Network::Regtest)
                .header
                .time
                .saturating_add(7)
        );

        let mut wrong_bits_block = fixture.containing_block.clone();
        wrong_bits_block.header.bits = CompactTarget::from_consensus(0x207f_fffe);
        wrong_bits_block.header.nonce = 0;
        mine_header(&mut wrong_bits_block.header);
        let wrong_bits_evidence = replace_block(&fixture.evidence, &wrong_bits_block);
        assert_eq!(
            authentication_error(fixture.authority.authenticate(
                &wrong_bits_evidence,
                &[raw_header(&wrong_bits_block.header)],
            )),
            RegtestHeaderAuthorityErrorV2::UnexpectedBits
        );

        let mut broken_link_block = fixture.containing_block.clone();
        broken_link_block.header.prev_blockhash = BlockHash::all_zeros();
        broken_link_block.header.nonce = 0;
        mine_header(&mut broken_link_block.header);
        let broken_link_evidence = replace_block(&fixture.evidence, &broken_link_block);
        assert_eq!(
            authentication_error(fixture.authority.authenticate(
                &broken_link_evidence,
                &[raw_header(&broken_link_block.header)],
            ),),
            RegtestHeaderAuthorityErrorV2::BrokenHeaderLink
        );

        let mut mtp_block = fixture.containing_block.clone();
        mtp_block.header.time = fixture.authority.checkpoint().median_time_past();
        mtp_block.header.nonce = 0;
        mine_header(&mut mtp_block.header);
        let mtp_evidence = replace_block(&fixture.evidence, &mtp_block);
        assert_eq!(
            authentication_error(
                fixture
                    .authority
                    .authenticate(&mtp_evidence, &[raw_header(&mtp_block.header)]),
            ),
            RegtestHeaderAuthorityErrorV2::MedianTimePastViolation
        );

        let wrong_height_policy = BitcoinHeaderPolicyBindingV2::new(
            BitcoinEvidenceNetworkV2::Regtest,
            fixture.evidence.header_policy().network_genesis_hash(),
            fixture
                .evidence
                .header_policy()
                .block_height()
                .saturating_add(1),
            fixture.authority.policy().digest(),
            fixture.authority.checkpoint().digest(),
            fixture.authority.policy().minimum_confirmation_depth(),
        )
        .expect("wrong height is structurally valid");
        let wrong_height_evidence = replace_header_policy(&fixture.evidence, wrong_height_policy);
        assert_eq!(
            authentication_error(
                fixture
                    .authority
                    .authenticate(&wrong_height_evidence, &fixture.continuation),
            ),
            RegtestHeaderAuthorityErrorV2::HeightMismatch
        );
    }

    #[test]
    fn checkpoint_and_policy_are_exact_genesis_rooted_replay_boundaries() {
        assert_eq!(
            RegtestHeaderCheckpointV2::from_genesis_ancestry(&[])
                .err()
                .expect("empty ancestry fails"),
            RegtestHeaderAuthorityErrorV2::EmptyGenesisAncestry
        );
        assert_eq!(
            RegtestHeaderCheckpointV2::from_genesis_ancestry(&[[0; 80]])
                .err()
                .expect("foreign genesis fails"),
            RegtestHeaderAuthorityErrorV2::ForeignGenesisRoot
        );

        let fixture = fixture(2, 2, 1);
        let wrong_policy_binding = BitcoinHeaderPolicyBindingV2::new(
            BitcoinEvidenceNetworkV2::Regtest,
            fixture.evidence.header_policy().network_genesis_hash(),
            fixture.evidence.header_policy().block_height(),
            [0x91; 32],
            fixture.authority.checkpoint().digest(),
            fixture.authority.policy().minimum_confirmation_depth(),
        )
        .expect("wrong policy digest remains structurally non-zero");
        assert_eq!(
            authentication_error(fixture.authority.authenticate(
                &replace_header_policy(&fixture.evidence, wrong_policy_binding),
                &fixture.continuation,
            ),),
            RegtestHeaderAuthorityErrorV2::PolicyDigestMismatch
        );

        let wrong_checkpoint_binding = BitcoinHeaderPolicyBindingV2::new(
            BitcoinEvidenceNetworkV2::Regtest,
            fixture.evidence.header_policy().network_genesis_hash(),
            fixture.evidence.header_policy().block_height(),
            fixture.authority.policy().digest(),
            [0x92; 32],
            fixture.authority.policy().minimum_confirmation_depth(),
        )
        .expect("wrong checkpoint digest remains structurally non-zero");
        assert_eq!(
            authentication_error(fixture.authority.authenticate(
                &replace_header_policy(&fixture.evidence, wrong_checkpoint_binding),
                &fixture.continuation,
            ),),
            RegtestHeaderAuthorityErrorV2::CheckpointDigestMismatch
        );
    }

    #[test]
    fn depth_counts_the_inclusion_block_and_reorg_proof_cannot_be_reused() {
        let depth_one = fixture(1, 1, 0);
        let depth_one_authentication = depth_one
            .authority
            .authenticate(&depth_one.evidence, &depth_one.continuation)
            .expect("inclusion block alone is depth one");
        assert_eq!(depth_one_authentication.confirmation_depth(), 1);
        assert_eq!(
            depth_one_authentication.confirmation_tip_hash(),
            depth_one_authentication.block_hash()
        );

        let fixture = fixture(1, 2, 1);
        let original_authentication = fixture
            .authority
            .authenticate(&fixture.evidence, &fixture.continuation)
            .expect("one successor gives depth two");
        let original_successor: Header = deserialize(&fixture.evidence.confirmation_headers()[0])
            .expect("valid successor fixture");
        let mut replacement_successor = original_successor;
        replacement_successor.merkle_root =
            TxMerkleNode::from_raw_hash(Hash::from_byte_array([0x55; 32]));
        replacement_successor.nonce = 0;
        mine_header(&mut replacement_successor);
        let reorg_evidence = KeystoneBitcoinEvidenceV2::new(
            *fixture.evidence.route(),
            *fixture.evidence.header_policy(),
            *fixture.evidence.transaction(),
            fixture.evidence.full_block_bytes().to_vec(),
            vec![raw_header(&replacement_successor)],
        )
        .expect("alternate successor remains bounded");

        let replacement_authentication = fixture
            .authority
            .authenticate(&reorg_evidence, &fixture.continuation)
            .expect("alternate fork requires its own exact authentication");
        assert_ne!(
            original_authentication.evidence_digest(),
            replacement_authentication.evidence_digest()
        );
        assert_ne!(
            original_authentication.genesis_rooted_chain_digest(),
            replacement_authentication.genesis_rooted_chain_digest()
        );
        assert_eq!(
            verify_evidence_v2(&reorg_evidence, &original_authentication).unwrap_err(),
            EvidenceVerificationErrorV2::AuthenticatedEvidenceMismatch
        );
    }
}

//! Store-free real-chain anchor authority for the F7 composition.
//!
//! The only constructor of [`VerifiedF7AnchorAuthorizationV1`] drives the
//! concrete authenticated DOM scanner, verifies a complete Bitcoin funding
//! block and genesis-rooted header chain with the pinned `bitcoin` crate, and
//! evaluates the frozen M.8 policy.  No caller-built block identifier, raw
//! anchor digest, Boolean, or trait implementation can mint the capability.
//! The crate deliberately has no dependency on either durable Store.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use adapter_btc::timelock::{
    bind_and_validate_funding_anchors, AnchoredCrossChainWindowV1, BitcoinFundingAnchorV1,
    DomFundingAnchorV1, M8FundingAnchorsV1, M8TimingPolicyV1, TimelockError,
};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{block::Header, Block, Network, Transaction};
use dom_scriptless_chain_adapter::{
    ChainAdapterError, DomHttpChainAdapterV1, ScriptlessScanCursorV1, MAX_SCRIPTLESS_SCAN_BLOCKS_V1,
};
use kaystra_core::types::LockMechanism;
use kaystra_core::{SettlementTermsV1, TermsError};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum number of Bitcoin ancestry or confirmation headers accepted by
/// one F7 validation.  The isolated regtest chains are intentionally small;
/// this bound prevents an unbounded allocation or proof walk.
pub const MAX_F7_HEADER_CHAIN: usize = 1_000_000;

/// Maximum number of authenticated DOM scanner pages walked by one F7
/// validation attempt (at most 1,048,576 blocks under the scanner's fixed
/// 64-block page limit).
pub const MAX_F7_DOM_SCAN_PAGES: usize = 16_384;

const DOM_FUNDING_SCAN_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const DOM_FUNDING_SCAN_TIMEOUT: Duration = Duration::from_secs(120);

/// Public, non-secret inputs that are not already derivable from canonical
/// settlement terms or the authenticated scanners.
pub struct F7AnchorValidationRequestV1<'a> {
    /// Canonical, validated settlement terms. Session, settlement, finality
    /// and adaptor-point bindings are derived from this value.
    pub terms: &'a SettlementTermsV1,
    /// Immutable pre-funding M.8 timing/finality policy.
    pub timing_policy: &'a M8TimingPolicyV1,
    /// Exact DOM funding transaction authorized by the Contracts Store.
    pub expected_dom_funding_txid: [u8; 32],
    /// Exact 2-of-2 confidential output created by DOM funding.
    pub expected_dom_shared_output_commitment: [u8; 33],
    /// Exact Bitcoin funding transaction frozen by the route.
    pub expected_bitcoin_funding_txid: [u8; 32],
    /// Canonical DOM claim template hash already frozen by the DOM funding
    /// authority.
    pub expected_dom_claim_template_hash: [u8; 32],
    /// Exact DSC1 transcript at the post-anchor claim-round boundary.
    pub expected_dom_claim_round_start_transcript_hash: [u8; 32],
    /// Height of the Bitcoin block encoded in
    /// [`Self::canonical_bitcoin_funding_block`].
    pub bitcoin_funding_block_height: u64,
    /// Full consensus encoding of the Bitcoin funding block.
    pub canonical_bitcoin_funding_block: &'a [u8],
    /// Exactly one canonical header per height from genesis up to, but not
    /// including, the funding block.
    pub bitcoin_ancestry_headers: &'a [[u8; 80]],
    /// Canonical successor headers after the funding block. Their count plus
    /// the funding block itself defines the proven confirmation depth.
    pub bitcoin_confirmation_headers: &'a [[u8; 80]],
}

/// Fail-closed errors from complete F7 real-anchor validation.
#[derive(Debug, thiserror::Error)]
pub enum F7AnchorAuthorityError {
    /// Canonical settlement terms are malformed or inconsistent.
    #[error("invalid canonical settlement terms")]
    Terms(#[from] TermsError),
    /// The authenticated DOM scanner rejected identity, linkage, canonical
    /// bytes, finality, or the requested exact funding output.
    #[error("authenticated DOM funding evidence rejected")]
    Dom(#[from] ChainAdapterError),
    /// The DOM funding transaction was absent, duplicated, mismatched, or
    /// below the finality depth frozen in settlement terms.
    #[error("DOM funding evidence mismatch")]
    DomFundingMismatch,
    /// The Bitcoin proof is malformed, inconsistent, or belongs to another
    /// network.
    #[error("invalid Bitcoin funding evidence")]
    InvalidBitcoinEvidence,
    /// The exact Bitcoin funding transaction is absent or duplicated.
    #[error("Bitcoin funding transaction inclusion mismatch")]
    BitcoinFundingMismatch,
    /// A real-chain confirmation depth does not satisfy frozen terms.
    #[error("frozen finality policy is not satisfied")]
    InsufficientFinality,
    /// Public route bindings do not agree with canonical terms and policy.
    #[error("F7 route binding mismatch")]
    RouteBindingMismatch,
    /// A bounded scanner/proof walk exceeded the laboratory limit.
    #[error("F7 anchor evidence bound exceeded")]
    BoundsExceeded,
    /// M.8 rejected the policy, anchor binding, or conservative window.
    #[error("M.8 anchor binding failed: {0}")]
    Timelock(#[from] TimelockError),
}

/// Intermediate, non-forgeable Bitcoin position obtained from a complete
/// block and linked proof-of-work header chain.
///
/// This value remains public for evidence diagnostics, but it cannot mint a
/// Store authorization by itself. Only [`verify_f7_route_anchor_authority`]
/// combines it with a concrete authenticated DOM scan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifiedBitcoinFundingEvidenceV1 {
    funding_txid: [u8; 32],
    block_hash: [u8; 32],
    height: u64,
    median_time_past: u64,
    confirmation_depth: u32,
}

impl VerifiedBitcoinFundingEvidenceV1 {
    /// Canonical Bitcoin transaction identifier in internal byte order.
    #[must_use]
    pub const fn funding_txid(&self) -> [u8; 32] {
        self.funding_txid
    }

    /// Canonical funding-block identifier in internal byte order.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    /// Height of the canonical funding block.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// BIP68 base MTP of the block immediately preceding funding.
    #[must_use]
    pub const fn median_time_past(&self) -> u64 {
        self.median_time_past
    }

    /// Proven depth including the funding block itself.
    #[must_use]
    pub const fn confirmation_depth(&self) -> u32 {
        self.confirmation_depth
    }
}

struct VerifiedDomFundingEvidenceV1 {
    chain_id: [u8; 32],
    funding_txid: [u8; 32],
    block_hash: [u8; 32],
    height: u64,
    block_time_seconds: u64,
    confirmation_depth: u32,
}

/// Linear proof that complete real DOM and Bitcoin anchor validation passed
/// for one exact post-anchor DOM claim authorization.
///
/// The type has no public constructor, codec, `Clone`, `Copy`, `Debug`, or
/// equality implementation. A production Contracts Store consumes it by
/// value and persists all bindings before issuing any claim-signing
/// capability.
pub struct VerifiedF7AnchorAuthorizationV1 {
    dom_chain_id: [u8; 32],
    session_id: [u8; 32],
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
    anchor_evidence_digest: [u8; 32],
    dom_funding_id: [u8; 32],
    bitcoin_funding_id: [u8; 32],
    bitcoin_chain_registry_id: [u8; 32],
    dom_shared_output_commitment: [u8; 33],
    claim_template_hash: [u8; 32],
    claim_round_start_transcript_hash: [u8; 32],
    adaptor_point_bytes: [u8; 33],
    dom_confirmation_depth: u32,
    bitcoin_confirmation_depth: u32,
}

impl VerifiedF7AnchorAuthorizationV1 {
    /// Authenticated DOM chain identifier returned by the real scanner.
    #[must_use]
    pub const fn dom_chain_id(&self) -> &[u8; 32] {
        &self.dom_chain_id
    }

    /// Exact DOM Contracts signing session.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Exact Interop settlement route.
    #[must_use]
    pub const fn settlement_id(&self) -> &[u8; 32] {
        &self.settlement_id
    }

    /// Hash of canonical settlement terms validated by this authority.
    #[must_use]
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }

    /// Canonical pre-funding M.8 policy digest.
    #[must_use]
    pub const fn m8_policy_digest(&self) -> &[u8; 32] {
        &self.m8_policy_digest
    }

    /// Digest of the complete post-confirmation anchor evidence object.
    #[must_use]
    pub const fn anchor_evidence_digest(&self) -> &[u8; 32] {
        &self.anchor_evidence_digest
    }

    /// Exact canonical DOM funding transaction identifier.
    #[must_use]
    pub const fn dom_funding_id(&self) -> &[u8; 32] {
        &self.dom_funding_id
    }

    /// Exact canonical Bitcoin funding transaction identifier.
    #[must_use]
    pub const fn bitcoin_funding_id(&self) -> &[u8; 32] {
        &self.bitcoin_funding_id
    }

    /// Counterparty-chain registry identifier frozen in canonical terms.
    ///
    /// The Bitcoin proof independently fixes the regtest genesis. This field
    /// keeps the separate Interop registry binding explicit for Store audit;
    /// the repository does not invent a registry-id-to-genesis mapping.
    #[must_use]
    pub const fn bitcoin_chain_registry_id(&self) -> &[u8; 32] {
        &self.bitcoin_chain_registry_id
    }

    /// Exact confidential DOM output proven to occur once in funding.
    #[must_use]
    pub const fn dom_shared_output_commitment(&self) -> &[u8; 33] {
        &self.dom_shared_output_commitment
    }

    /// Canonical DOM claim template bound before funding.
    #[must_use]
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }

    /// Exact post-anchor claim-round predecessor transcript.
    #[must_use]
    pub const fn claim_round_start_transcript_hash(&self) -> &[u8; 32] {
        &self.claim_round_start_transcript_hash
    }

    /// Canonical SEC1 compressed adaptor point from settlement terms.
    #[must_use]
    pub const fn adaptor_point_bytes(&self) -> &[u8; 33] {
        &self.adaptor_point_bytes
    }

    /// DOM confirmation depth proven against canonical scanner linkage.
    #[must_use]
    pub const fn dom_confirmation_depth(&self) -> u32 {
        self.dom_confirmation_depth
    }

    /// Bitcoin confirmation depth proven by linked proof-of-work headers.
    #[must_use]
    pub const fn bitcoin_confirmation_depth(&self) -> u32 {
        self.bitcoin_confirmation_depth
    }
}

/// Linear bundle emitted by the one complete validator.
///
/// The Contracts authorization and both participant-specific Bitcoin nonce
/// authorizations are split only after all real evidence and M.8 checks pass.
pub struct VerifiedF7RouteAnchorAuthorizationsV1 {
    contracts: VerifiedF7AnchorAuthorizationV1,
    bitcoin_signers: [AnchoredCrossChainWindowV1; 2],
}

impl VerifiedF7RouteAnchorAuthorizationsV1 {
    /// Consumes the aggregate result into the Contracts Store capability and
    /// the two linear Bitcoin signer authorizations.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        VerifiedF7AnchorAuthorizationV1,
        [AnchoredCrossChainWindowV1; 2],
    ) {
        (self.contracts, self.bitcoin_signers)
    }
}

/// Verifies a complete Bitcoin funding block and its confirmation chain.
///
/// This diagnostic boundary does not issue the final F7 authorization. The
/// full gate is [`verify_f7_route_anchor_authority`], which also drives the
/// concrete authenticated DOM scanner and evaluates M.8.
pub fn verify_bitcoin_funding_evidence(
    policy: &M8TimingPolicyV1,
    expected_funding_txid: [u8; 32],
    block_height: u64,
    canonical_block_bytes: &[u8],
    ancestry_header_bytes: &[[u8; 80]],
    confirmation_header_bytes: &[[u8; 80]],
) -> Result<VerifiedBitcoinFundingEvidenceV1, F7AnchorAuthorityError> {
    policy.validate()?;
    if expected_funding_txid == [0; 32]
        || canonical_block_bytes.is_empty()
        || ancestry_header_bytes.len() > MAX_F7_HEADER_CHAIN
        || confirmation_header_bytes.len() > MAX_F7_HEADER_CHAIN
        || usize::try_from(block_height).ok() != Some(ancestry_header_bytes.len())
    {
        return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
    }
    let expected_network = match policy.bitcoin_finality.network {
        adapter_btc::types::BitcoinNetworkV1::Regtest => Network::Regtest,
        adapter_btc::types::BitcoinNetworkV1::CustomSignet
        | adapter_btc::types::BitcoinNetworkV1::PublicSignet => {
            return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence)
        }
    };
    let block: Block = deserialize(canonical_block_bytes)
        .map_err(|_| F7AnchorAuthorityError::InvalidBitcoinEvidence)?;
    if !block.check_merkle_root()
        || (policy.bitcoin_finality.require_witness_commitment && !block.check_witness_commitment())
    {
        return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
    }
    let occurrences = block
        .txdata
        .iter()
        .filter(|transaction| transaction_id(transaction) == expected_funding_txid)
        .count();
    if occurrences != 1 {
        return Err(F7AnchorAuthorityError::BitcoinFundingMismatch);
    }

    let funding_header = &block.header;
    let canonical_genesis = genesis_block(expected_network).header;
    let canonical_genesis_hash = canonical_genesis.block_hash();
    let required_regtest_target = canonical_genesis.target();
    let mut previous_ancestor = None;
    let mut recent_times = Vec::with_capacity(11);
    for (height, raw) in ancestry_header_bytes.iter().enumerate() {
        let header: Header =
            deserialize(raw).map_err(|_| F7AnchorAuthorityError::InvalidBitcoinEvidence)?;
        if header.target() != required_regtest_target {
            return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
        }
        let hash = header
            .validate_pow(header.target())
            .map_err(|_| F7AnchorAuthorityError::InvalidBitcoinEvidence)?;
        if height == 0 {
            if hash != canonical_genesis_hash {
                return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
            }
        } else if header.prev_blockhash
            != previous_ancestor.ok_or(F7AnchorAuthorityError::InvalidBitcoinEvidence)?
        {
            return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
        }
        if height != 0 && u64::from(header.time) <= median_time(&recent_times)? {
            return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
        }
        previous_ancestor = Some(hash);
        push_recent_time(&mut recent_times, u64::from(header.time));
    }
    if block_height == 0 {
        if funding_header.block_hash() != canonical_genesis_hash {
            return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
        }
    } else if funding_header.prev_blockhash
        != previous_ancestor.ok_or(F7AnchorAuthorityError::InvalidBitcoinEvidence)?
    {
        return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
    }
    if funding_header.target() != required_regtest_target {
        return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
    }
    let funding_base_median_time_past = median_time(&recent_times)?;
    if block_height != 0 && u64::from(funding_header.time) <= funding_base_median_time_past {
        return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
    }
    let mut previous = funding_header
        .validate_pow(funding_header.target())
        .map_err(|_| F7AnchorAuthorityError::InvalidBitcoinEvidence)?;
    push_recent_time(&mut recent_times, u64::from(funding_header.time));
    for raw in confirmation_header_bytes {
        let header: Header =
            deserialize(raw).map_err(|_| F7AnchorAuthorityError::InvalidBitcoinEvidence)?;
        if header.target() != required_regtest_target
            || header.prev_blockhash != previous
            || u64::from(header.time) <= median_time(&recent_times)?
        {
            return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
        }
        previous = header
            .validate_pow(header.target())
            .map_err(|_| F7AnchorAuthorityError::InvalidBitcoinEvidence)?;
        push_recent_time(&mut recent_times, u64::from(header.time));
    }
    let confirmation_depth = u32::try_from(confirmation_header_bytes.len())
        .ok()
        .and_then(|depth| depth.checked_add(1))
        .ok_or(F7AnchorAuthorityError::BoundsExceeded)?;
    if confirmation_depth < policy.bitcoin_finality.minimum_confirmations {
        return Err(F7AnchorAuthorityError::InsufficientFinality);
    }

    Ok(VerifiedBitcoinFundingEvidenceV1 {
        funding_txid: expected_funding_txid,
        block_hash: funding_header.block_hash().to_raw_hash().to_byte_array(),
        height: block_height,
        median_time_past: funding_base_median_time_past,
        confirmation_depth,
    })
}

/// Drives both real-chain evidence paths and mints the only accepted F7
/// post-anchor authorization bundle.
///
/// `dom` is a concrete authenticated HTTP adapter, not a caller-implemented
/// trait. The function scans from the canonical genesis cursor through one
/// linked tip, proves exact DOM funding/output inclusion and finality, proves
/// Bitcoin inclusion/finality from full consensus bytes, and evaluates M.8
/// before any capability is returned.
pub fn verify_f7_route_anchor_authority(
    dom: &DomHttpChainAdapterV1,
    request: F7AnchorValidationRequestV1<'_>,
) -> Result<VerifiedF7RouteAnchorAuthorizationsV1, F7AnchorAuthorityError> {
    request.terms.validate()?;
    let terms_hash = request.terms.terms_hash()?;
    let policy_digest = request.timing_policy.policy_digest()?;
    if request.timing_policy.settlement_terms_hash != terms_hash
        || request.timing_policy.bitcoin_finality.minimum_confirmations
            != request.terms.counterparty_leg.finality.min_confirmations
        || request.timing_policy.bitcoin_finality.maximum_reorg_depth
            != request.terms.counterparty_leg.finality.max_reorg_depth
        || request.terms.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
        || request.terms.counterparty_leg.mechanism != LockMechanism::SchnorrAdaptor
        || request.expected_dom_funding_txid == [0; 32]
        || request.expected_dom_shared_output_commitment == [0; 33]
        || request.expected_bitcoin_funding_txid == [0; 32]
        || request.expected_dom_claim_template_hash == [0; 32]
        || request.expected_dom_claim_round_start_transcript_hash == [0; 32]
    {
        return Err(F7AnchorAuthorityError::RouteBindingMismatch);
    }

    let dom_evidence = verify_dom_funding_evidence(
        dom,
        request.expected_dom_funding_txid,
        request.expected_dom_shared_output_commitment,
        request.terms.dom_leg.finality.min_confirmations,
    )?;
    require_dom_chain_binding(request.terms, &dom_evidence)?;
    let bitcoin_evidence = verify_bitcoin_funding_evidence(
        request.timing_policy,
        request.expected_bitcoin_funding_txid,
        request.bitcoin_funding_block_height,
        request.canonical_bitcoin_funding_block,
        request.bitcoin_ancestry_headers,
        request.bitcoin_confirmation_headers,
    )?;
    let anchors = M8FundingAnchorsV1 {
        settlement_terms_hash: terms_hash,
        policy_digest,
        dom: DomFundingAnchorV1 {
            funding_txid: dom_evidence.funding_txid,
            block_hash: dom_evidence.block_hash,
            height: dom_evidence.height,
            block_time_seconds: dom_evidence.block_time_seconds,
        },
        bitcoin: BitcoinFundingAnchorV1 {
            funding_txid: bitcoin_evidence.funding_txid,
            block_hash: bitcoin_evidence.block_hash,
            height: bitcoin_evidence.height,
            median_time_past: bitcoin_evidence.median_time_past,
        },
    };
    let anchor_evidence_digest = anchors.evidence_digest()?;
    let first = bind_and_validate_funding_anchors(request.timing_policy, &anchors)?;
    let second = bind_and_validate_funding_anchors(request.timing_policy, &anchors)?;
    let contracts = VerifiedF7AnchorAuthorizationV1 {
        dom_chain_id: dom_evidence.chain_id,
        session_id: request.terms.session_id.0,
        settlement_id: request.terms.settlement_id.0,
        terms_hash,
        m8_policy_digest: policy_digest,
        anchor_evidence_digest,
        dom_funding_id: dom_evidence.funding_txid,
        bitcoin_funding_id: bitcoin_evidence.funding_txid,
        bitcoin_chain_registry_id: request.terms.counterparty_leg.chain_id.0,
        dom_shared_output_commitment: request.expected_dom_shared_output_commitment,
        claim_template_hash: request.expected_dom_claim_template_hash,
        claim_round_start_transcript_hash: request.expected_dom_claim_round_start_transcript_hash,
        adaptor_point_bytes: request.terms.adaptor_point_sec1,
        dom_confirmation_depth: dom_evidence.confirmation_depth,
        bitcoin_confirmation_depth: bitcoin_evidence.confirmation_depth,
    };
    Ok(VerifiedF7RouteAnchorAuthorizationsV1 {
        contracts,
        bitcoin_signers: [first, second],
    })
}

fn verify_dom_funding_evidence(
    dom: &DomHttpChainAdapterV1,
    expected_funding_txid: [u8; 32],
    expected_shared_output_commitment: [u8; 33],
    minimum_confirmations: u32,
) -> Result<VerifiedDomFundingEvidenceV1, F7AnchorAuthorityError> {
    if expected_funding_txid == [0; 32]
        || expected_shared_output_commitment == [0; 33]
        || minimum_confirmations == 0
    {
        return Err(F7AnchorAuthorityError::RouteBindingMismatch);
    }
    let scan_deadline = Instant::now()
        .checked_add(DOM_FUNDING_SCAN_TIMEOUT)
        .ok_or(F7AnchorAuthorityError::BoundsExceeded)?;
    let mut cursor = ScriptlessScanCursorV1::genesis();
    let mut found = None;
    for _ in 0..MAX_F7_DOM_SCAN_PAGES {
        let page = loop {
            match dom.scan_page(cursor, MAX_SCRIPTLESS_SCAN_BLOCKS_V1) {
                Ok(page) => break page,
                Err(ChainAdapterError::TemporarilyUnavailable)
                    if Instant::now() < scan_deadline =>
                {
                    thread::sleep(DOM_FUNDING_SCAN_RETRY_INTERVAL);
                }
                Err(error) => return Err(error.into()),
            }
        };
        for block in &page.blocks {
            for transaction in &block.transactions {
                if transaction.tx_hash != expected_funding_txid {
                    continue;
                }
                if found.is_some() {
                    return Err(F7AnchorAuthorityError::DomFundingMismatch);
                }
                let created = transaction
                    .transaction
                    .outputs
                    .iter()
                    .filter(|output| {
                        output.commitment.as_bytes() == &expected_shared_output_commitment
                    })
                    .count();
                if created != 1
                    || transaction.spends_commitment(&expected_shared_output_commitment)
                    || transaction.location.block_hash != block.block_hash
                    || transaction.location.block_height != block.height
                {
                    return Err(F7AnchorAuthorityError::DomFundingMismatch);
                }
                found = Some((block.block_hash, block.height, block.timestamp));
            }
        }
        cursor = page.next_cursor;
        if page.reached_snapshot_tip {
            let (block_hash, height, block_time_seconds) =
                found.ok_or(F7AnchorAuthorityError::DomFundingMismatch)?;
            let depth = page
                .identity
                .tip_height
                .checked_sub(height)
                .and_then(|distance| distance.checked_add(1))
                .ok_or(F7AnchorAuthorityError::DomFundingMismatch)?;
            let confirmation_depth =
                u32::try_from(depth).map_err(|_| F7AnchorAuthorityError::BoundsExceeded)?;
            if confirmation_depth < minimum_confirmations {
                return Err(F7AnchorAuthorityError::InsufficientFinality);
            }
            return Ok(VerifiedDomFundingEvidenceV1 {
                chain_id: page.identity.chain_id,
                funding_txid: expected_funding_txid,
                block_hash,
                height,
                block_time_seconds,
                confirmation_depth,
            });
        }
    }
    Err(F7AnchorAuthorityError::BoundsExceeded)
}

fn require_dom_chain_binding(
    terms: &SettlementTermsV1,
    evidence: &VerifiedDomFundingEvidenceV1,
) -> Result<(), F7AnchorAuthorityError> {
    if evidence.chain_id == terms.dom_leg.chain_id.0 {
        Ok(())
    } else {
        Err(F7AnchorAuthorityError::RouteBindingMismatch)
    }
}

fn transaction_id(transaction: &Transaction) -> [u8; 32] {
    transaction.compute_txid().to_raw_hash().to_byte_array()
}

fn push_recent_time(recent_times: &mut Vec<u64>, time: u64) {
    if recent_times.len() == 11 {
        recent_times.remove(0);
    }
    recent_times.push(time);
}

fn median_time(recent_times: &[u64]) -> Result<u64, F7AnchorAuthorityError> {
    if recent_times.is_empty() || recent_times.len() > 11 {
        return Err(F7AnchorAuthorityError::InvalidBitcoinEvidence);
    }
    let mut ordered = recent_times.to_vec();
    ordered.sort_unstable();
    ordered
        .get(ordered.len() / 2)
        .copied()
        .ok_or(F7AnchorAuthorityError::InvalidBitcoinEvidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaystra_core::types::{
        AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1,
        ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec,
    };
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(VerifiedF7AnchorAuthorizationV1: Clone, Copy, core::fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(VerifiedF7RouteAnchorAuthorizationsV1: Clone, Copy, core::fmt::Debug, Eq, PartialEq);

    fn terms(dom_chain_id: [u8; 32]) -> SettlementTermsV1 {
        let finality = FinalityPolicyV1 {
            min_confirmations: 1,
            max_reorg_depth: 1,
        };
        SettlementTermsV1 {
            settlement_id: SettlementId([1; 32]),
            session_id: SessionId([2; 32]),
            intent_hash: IntentHash([3; 32]),
            solver_id: SolverId([4; 32]),
            roster: [ParticipantId([5; 32]), ParticipantId([6; 32])],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId(dom_chain_id),
                asset_id: AssetId([7; 32]),
                amount: 1,
                beneficiary: ParticipantId([5; 32]),
                refund_to: ParticipantId([6; 32]),
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 10 },
                finality,
                adapter_profile_hash: [8; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId([9; 32]),
                asset_id: AssetId([10; 32]),
                amount: 1,
                beneficiary: ParticipantId([6; 32]),
                refund_to: ParticipantId([5; 32]),
                mechanism: LockMechanism::SchnorrAdaptor,
                deadline: TimelockSpec::BtcTime512s { value: 10 },
                finality,
                adapter_profile_hash: [11; 32],
            },
            adaptor_point_sec1: {
                let mut point = [12; 33];
                point[0] = 2;
                point
            },
            fee_limit: FeeLimitV1 {
                dom_max: 1,
                counterparty_max: 1,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 10,
            },
            assurance_policy_hash: None,
            policy_version: 1,
            metadata: Vec::new(),
        }
    }

    #[test]
    fn valid_other_dom_chain_cannot_authorize_frozen_route() {
        let evidence = VerifiedDomFundingEvidenceV1 {
            chain_id: [0xa1; 32],
            funding_txid: [0xa2; 32],
            block_hash: [0xa3; 32],
            height: 10,
            block_time_seconds: 1_700_000_000,
            confirmation_depth: 2,
        };
        assert!(matches!(
            require_dom_chain_binding(&terms([0xb1; 32]), &evidence),
            Err(F7AnchorAuthorityError::RouteBindingMismatch)
        ));
        assert!(require_dom_chain_binding(&terms([0xa1; 32]), &evidence).is_ok());
    }
}

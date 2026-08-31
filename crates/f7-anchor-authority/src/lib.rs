//! Store-free real-chain anchor authority for the F7 composition.
//!
//! V1 authority types remain readable for historical recovery, but their
//! public entrypoint refuses every fresh mint. The only productive constructor
//! emits [`VerifiedF7AnchorAuthorizationV2`]: it drives the concrete
//! authenticated DOM scanner, verifies a complete Bitcoin funding block and
//! genesis-rooted header chain with the pinned `bitcoin` crate, reauthenticates
//! explicit FinalClaim roles and bilateral readiness, and evaluates the frozen
//! M.8 policy. No caller-built block identifier, raw anchor digest, Boolean, or
//! trait implementation can mint the capability. The crate deliberately has
//! no dependency on either durable Store.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use adapter_btc::timelock::{
    bind_and_validate_funding_anchors, AnchoredCrossChainWindowV1, BitcoinFundingAnchorV1,
    DomFundingAnchorV1, M8FundingAnchorsV1, M8TimingPolicyV1, TimelockError, TimelockOffsetV1,
};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{block::Header, Block, Network, Transaction};
use dom_adaptor::DirectionV1;
use dom_final_claim_binding::{
    ComposedSettlementLegV1, FinalClaimBindingError, FinalClaimRevealModeV1,
    FinalClaimRoleBindingV1, FinalClaimSecretSourceV1, OperationalM8ReadyBindingV2,
};
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

/// Canonical role-bound inputs for productive F7 post-anchor validation.
///
/// Settlement terms, template hashes, shared output, adaptor point, role
/// selection and source scope come only from the self-contained role and ready
/// bindings. They are never reconstructed from participant order, direction,
/// or composed-route position.
pub struct F7AnchorValidationRequestV2<'a> {
    /// Complete canonical final-claim role binding for this DOM settlement.
    pub final_claim_role_binding: &'a FinalClaimRoleBindingV1,
    /// Deterministic bilateral readiness binding signed by both 0x11 voters.
    pub ready_binding: &'a OperationalM8ReadyBindingV2,
    /// Complete immutable M.8 timing/finality policy.
    pub timing_policy: &'a M8TimingPolicyV1,
    /// Exact DOM funding transaction authorized and committed by Contracts.
    pub expected_dom_funding_txid: [u8; 32],
    /// Exact Bitcoin funding transaction frozen by the route.
    pub expected_bitcoin_funding_txid: [u8; 32],
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
    /// Canonical successor headers after the funding block.
    pub bitcoin_confirmation_headers: &'a [[u8; 80]],
}

/// Fail-closed errors from complete F7 real-anchor validation.
#[derive(Debug, thiserror::Error)]
pub enum F7AnchorAuthorityError {
    /// Legacy V1 is retained only for reading/recovery compatibility and may
    /// never create a fresh post-anchor claim authority.
    #[error("F7 V1 is recovery-only and cannot mint a new claim authority")]
    LegacyV1RecoveryOnly,
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
    /// A final-claim role or deterministic-ready binding failed canonical
    /// reauthentication.
    #[error("final-claim role/readiness binding rejected: {0}")]
    FinalClaimBinding(#[from] FinalClaimBindingError),
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
    observed_tip_hash: [u8; 32],
    observed_tip_height: u64,
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
    dom_funding_block_hash: [u8; 32],
    dom_funding_block_height: u64,
    dom_observed_tip_hash: [u8; 32],
    dom_observed_tip_height: u64,
    bitcoin_funding_id: [u8; 32],
    bitcoin_chain_registry_id: [u8; 32],
    dom_shared_output_commitment: [u8; 33],
    claim_template_hash: [u8; 32],
    claim_round_start_transcript_hash: [u8; 32],
    adaptor_point_bytes: [u8; 33],
    dom_minimum_confirmations: u32,
    dom_confirmation_depth: u32,
    bitcoin_confirmation_depth: u32,
}

/// Linear productive F7 authorization bound to explicit FinalClaim roles and
/// deterministic bilateral M.8 readiness.
///
/// The type has no public constructor, codec, `Clone`, `Copy`, `Debug`, or
/// equality implementation. All IDs and modes are copied from a fully
/// reauthenticated role binding; none is inferred from roster index, route
/// direction, or composed-leg position.
pub struct VerifiedF7AnchorAuthorizationV2 {
    dom_chain_id: [u8; 32],
    session_id: [u8; 32],
    settlement_id: [u8; 32],
    route_id: [u8; 32],
    composition_binding_digest: [u8; 32],
    final_claim_role_binding_digest: [u8; 32],
    ready_binding_digest: [u8; 32],
    roster_digest: [u8; 32],
    secret_source_scope_digest: [u8; 32],
    terms_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
    anchor_evidence_digest: [u8; 32],
    adaptor_secret_origin_id: [u8; 32],
    dom_claim_sender_id: [u8; 32],
    final_claim_receiver_id: [u8; 32],
    reveal_mode: FinalClaimRevealModeV1,
    secret_source: FinalClaimSecretSourceV1,
    route_leg: ComposedSettlementLegV1,
    sender_direction: DirectionV1,
    receiver_direction: DirectionV1,
    origin_direction: DirectionV1,
    dom_funding_id: [u8; 32],
    dom_funding_block_hash: [u8; 32],
    dom_funding_block_height: u64,
    dom_observed_tip_hash: [u8; 32],
    dom_observed_tip_height: u64,
    bitcoin_funding_id: [u8; 32],
    bitcoin_chain_registry_id: [u8; 32],
    dom_shared_output_commitment: [u8; 33],
    funding_template_hash: [u8; 32],
    claim_template_hash: [u8; 32],
    refund_template_hash: [u8; 32],
    claim_round_start_transcript_hash: [u8; 32],
    adaptor_point_bytes: [u8; 33],
    dom_minimum_confirmations: u32,
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

    /// Canonical block identifier containing the exact DOM funding transaction.
    #[must_use]
    pub const fn dom_funding_block_hash(&self) -> &[u8; 32] {
        &self.dom_funding_block_hash
    }

    /// Canonical height containing the exact DOM funding transaction.
    #[must_use]
    pub const fn dom_funding_block_height(&self) -> u64 {
        self.dom_funding_block_height
    }

    /// Canonical DOM tip identifier against which funding depth was proven.
    #[must_use]
    pub const fn dom_observed_tip_hash(&self) -> &[u8; 32] {
        &self.dom_observed_tip_hash
    }

    /// Canonical DOM tip height against which funding depth was proven.
    #[must_use]
    pub const fn dom_observed_tip_height(&self) -> u64 {
        self.dom_observed_tip_height
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

    /// Minimum DOM confirmation depth frozen in canonical settlement terms.
    #[must_use]
    pub const fn dom_minimum_confirmations(&self) -> u32 {
        self.dom_minimum_confirmations
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

impl VerifiedF7AnchorAuthorizationV2 {
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

    /// Exact Interop settlement identifier.
    #[must_use]
    pub const fn settlement_id(&self) -> &[u8; 32] {
        &self.settlement_id
    }

    /// Exact composed route identifier.
    #[must_use]
    pub const fn route_id(&self) -> &[u8; 32] {
        &self.route_id
    }

    /// Digest of the exact composed-route binding.
    #[must_use]
    pub const fn composition_binding_digest(&self) -> &[u8; 32] {
        &self.composition_binding_digest
    }

    /// Digest of the complete final-claim role binding.
    #[must_use]
    pub const fn final_claim_role_binding_digest(&self) -> &[u8; 32] {
        &self.final_claim_role_binding_digest
    }

    /// Digest of the deterministic bilateral readiness binding.
    #[must_use]
    pub const fn ready_binding_digest(&self) -> &[u8; 32] {
        &self.ready_binding_digest
    }

    /// Digest of the complete DOM participant roster.
    #[must_use]
    pub const fn roster_digest(&self) -> &[u8; 32] {
        &self.roster_digest
    }

    /// Digest of the exact pre-funding secret-source scope.
    #[must_use]
    pub const fn secret_source_scope_digest(&self) -> &[u8; 32] {
        &self.secret_source_scope_digest
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

    /// Participant that originally generated the adaptor secret.
    #[must_use]
    pub const fn adaptor_secret_origin_id(&self) -> &[u8; 32] {
        &self.adaptor_secret_origin_id
    }

    /// Participant exclusively authorized to adapt and broadcast the DOM claim.
    #[must_use]
    pub const fn dom_claim_sender_id(&self) -> &[u8; 32] {
        &self.dom_claim_sender_id
    }

    /// Bilateral peer authorized to receive the FinalClaim message.
    #[must_use]
    pub const fn final_claim_receiver_id(&self) -> &[u8; 32] {
        &self.final_claim_receiver_id
    }

    /// Explicit reveal order authenticated by the role binding.
    #[must_use]
    pub const fn reveal_mode(&self) -> FinalClaimRevealModeV1 {
        self.reveal_mode
    }

    /// Explicit source from which the DOM sender may obtain the secret.
    #[must_use]
    pub const fn secret_source(&self) -> FinalClaimSecretSourceV1 {
        self.secret_source
    }

    /// Composed route leg used only as scope, never as role selection.
    #[must_use]
    pub const fn route_leg(&self) -> ComposedSettlementLegV1 {
        self.route_leg
    }

    /// Roster-derived direction of the explicit DOM claim sender.
    #[must_use]
    pub const fn sender_direction(&self) -> DirectionV1 {
        self.sender_direction
    }

    /// Roster-derived direction of the explicit FinalClaim receiver.
    #[must_use]
    pub const fn receiver_direction(&self) -> DirectionV1 {
        self.receiver_direction
    }

    /// Roster-derived direction of the explicit adaptor-secret origin.
    #[must_use]
    pub const fn origin_direction(&self) -> DirectionV1 {
        self.origin_direction
    }

    /// Exact canonical DOM funding transaction identifier.
    #[must_use]
    pub const fn dom_funding_id(&self) -> &[u8; 32] {
        &self.dom_funding_id
    }

    /// Canonical DOM block identifier containing funding.
    #[must_use]
    pub const fn dom_funding_block_hash(&self) -> &[u8; 32] {
        &self.dom_funding_block_hash
    }

    /// Canonical DOM height containing funding.
    #[must_use]
    pub const fn dom_funding_block_height(&self) -> u64 {
        self.dom_funding_block_height
    }

    /// Canonical DOM tip identifier used to prove funding depth.
    #[must_use]
    pub const fn dom_observed_tip_hash(&self) -> &[u8; 32] {
        &self.dom_observed_tip_hash
    }

    /// Canonical DOM tip height used to prove funding depth.
    #[must_use]
    pub const fn dom_observed_tip_height(&self) -> u64 {
        self.dom_observed_tip_height
    }

    /// Exact canonical Bitcoin funding transaction identifier.
    #[must_use]
    pub const fn bitcoin_funding_id(&self) -> &[u8; 32] {
        &self.bitcoin_funding_id
    }

    /// Counterparty-chain registry identifier frozen in settlement terms.
    #[must_use]
    pub const fn bitcoin_chain_registry_id(&self) -> &[u8; 32] {
        &self.bitcoin_chain_registry_id
    }

    /// Exact confidential DOM output proven once in funding.
    #[must_use]
    pub const fn dom_shared_output_commitment(&self) -> &[u8; 33] {
        &self.dom_shared_output_commitment
    }

    /// Canonical DOM funding template frozen before authorization.
    #[must_use]
    pub const fn funding_template_hash(&self) -> &[u8; 32] {
        &self.funding_template_hash
    }

    /// Canonical DOM claim template frozen before funding.
    #[must_use]
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }

    /// Canonical DOM refund template frozen before funding.
    #[must_use]
    pub const fn refund_template_hash(&self) -> &[u8; 32] {
        &self.refund_template_hash
    }

    /// Exact post-anchor claim-round predecessor transcript.
    #[must_use]
    pub const fn claim_round_start_transcript_hash(&self) -> &[u8; 32] {
        &self.claim_round_start_transcript_hash
    }

    /// Canonical SEC1 compressed adaptor point from the role binding.
    #[must_use]
    pub const fn adaptor_point_bytes(&self) -> &[u8; 33] {
        &self.adaptor_point_bytes
    }

    /// Minimum DOM confirmation depth frozen in settlement terms.
    #[must_use]
    pub const fn dom_minimum_confirmations(&self) -> u32 {
        self.dom_minimum_confirmations
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

/// Linear role-bound V2 bundle emitted by the complete productive validator.
pub struct VerifiedF7RouteAnchorAuthorizationsV2 {
    contracts: VerifiedF7AnchorAuthorizationV2,
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

impl VerifiedF7RouteAnchorAuthorizationsV2 {
    /// Consumes the V2 aggregate into the role-bound Contracts capability and
    /// the two linear Bitcoin signer authorizations.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        VerifiedF7AnchorAuthorizationV2,
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

/// Recovery-only V1 compatibility entrypoint.
///
/// The signature and V1 public types remain available so historical callers
/// and retained-record recovery code continue to compile, but a fresh V1
/// anchor authorization is never minted. Productive validation must use
/// [`verify_f7_route_anchor_authority_v2`].
pub fn verify_f7_route_anchor_authority(
    _dom: &DomHttpChainAdapterV1,
    _request: F7AnchorValidationRequestV1<'_>,
) -> Result<VerifiedF7RouteAnchorAuthorizationsV1, F7AnchorAuthorityError> {
    refuse_legacy_v1_new_authority()
}

fn refuse_legacy_v1_new_authority<T>() -> Result<T, F7AnchorAuthorityError> {
    Err(F7AnchorAuthorityError::LegacyV1RecoveryOnly)
}

/// Drives both real-chain evidence paths and mints the role-bound productive
/// F7 V2 authorization bundle.
///
/// The role and ready values are canonical closed types. This function
/// reserializes the role, redecodes the ready binding against that exact role,
/// roundtrips the complete policy, checks reveal-order topology, then derives
/// every DOM template/output/role fact from those objects before scanning.
/// No participant index or direction selects a role.
pub fn verify_f7_route_anchor_authority_v2(
    dom: &DomHttpChainAdapterV1,
    request: F7AnchorValidationRequestV2<'_>,
) -> Result<VerifiedF7RouteAnchorAuthorizationsV2, F7AnchorAuthorityError> {
    let role = request.final_claim_role_binding;
    let ready = request.ready_binding;
    let terms = role.terms();
    terms.validate()?;

    // Canonical reconstruction is deliberate even though both types have
    // private fields: the F7 boundary never trusts a digest without its exact
    // complete object.
    let role_bytes = role.canonical_bytes()?;
    let role_digest = role.digest()?;
    if role_bytes.is_empty() {
        return Err(F7AnchorAuthorityError::RouteBindingMismatch);
    }
    let ready_bytes = ready.canonical_bytes();
    let rebound_ready = OperationalM8ReadyBindingV2::decode_canonical(role, &ready_bytes)?;
    if &rebound_ready != ready {
        return Err(F7AnchorAuthorityError::RouteBindingMismatch);
    }
    let ready_digest = ready.digest();

    let policy_bytes = request.timing_policy.canonical_bytes()?;
    let canonical_policy = M8TimingPolicyV1::decode_canonical(&policy_bytes)?;
    if canonical_policy != *request.timing_policy {
        return Err(F7AnchorAuthorityError::RouteBindingMismatch);
    }
    let terms_hash = terms.terms_hash()?;
    let policy_digest = canonical_policy.policy_digest()?;
    let source_scope = role.source_scope();
    let expected_refund_height = match terms.dom_leg.deadline {
        kaystra_core::types::TimelockSpec::BlockHeight { value } => value,
        kaystra_core::types::TimelockSpec::TimestampSeconds { .. }
        | kaystra_core::types::TimelockSpec::BtcTime512s { .. } => {
            return Err(F7AnchorAuthorityError::RouteBindingMismatch)
        }
    };

    if canonical_policy.settlement_terms_hash != terms_hash
        || canonical_policy.bitcoin_finality.minimum_confirmations
            != terms.counterparty_leg.finality.min_confirmations
        || canonical_policy.bitcoin_finality.maximum_reorg_depth
            != terms.counterparty_leg.finality.max_reorg_depth
        || !reveal_order_matches_policy(role.reveal_mode(), &canonical_policy)
        || terms.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
        || terms.counterparty_leg.mechanism != LockMechanism::SchnorrAdaptor
        || ready.final_claim_role_binding_digest() != role_digest
        || ready_digest == [0; 32]
        || ready.terms_hash() != terms_hash
        || ready.m8_policy_digest() != policy_digest
        || ready.refund_unlock_height() != expected_refund_height
        || ready.claim_kernel_index() != 0
        || source_scope.route_id() != role.route_id()
        || source_scope.composition_binding_digest() != role.composition_binding_digest()
        || source_scope.reveal_mode() != role.reveal_mode()
        || source_scope.secret_source() != role.secret_source()
        || source_scope.adaptor_secret_origin_id() != role.adaptor_secret_origin_id()
        || source_scope.dom_claim_sender_id() != role.dom_claim_sender_id()
        || request.expected_dom_funding_txid == [0; 32]
        || request.expected_bitcoin_funding_txid == [0; 32]
        || request.expected_dom_claim_round_start_transcript_hash == [0; 32]
    {
        return Err(F7AnchorAuthorityError::RouteBindingMismatch);
    }

    let dom_minimum_confirmations = terms.dom_leg.finality.min_confirmations;
    let dom_evidence = verify_dom_funding_evidence(
        dom,
        request.expected_dom_funding_txid,
        ready.shared_output_commitment(),
        ready.funding_template_hash(),
        dom_minimum_confirmations,
    )?;
    require_dom_chain_binding(terms, &dom_evidence)?;
    let observed_dom_depth = dom_evidence
        .observed_tip_height
        .checked_sub(dom_evidence.height)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|depth| u32::try_from(depth).ok());
    if dom_evidence.observed_tip_hash == [0; 32]
        || observed_dom_depth != Some(dom_evidence.confirmation_depth)
        || dom_evidence.confirmation_depth < dom_minimum_confirmations
    {
        return Err(F7AnchorAuthorityError::InsufficientFinality);
    }

    let bitcoin_evidence = verify_bitcoin_funding_evidence(
        &canonical_policy,
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
    let first = bind_and_validate_funding_anchors(&canonical_policy, &anchors)?;
    let second = bind_and_validate_funding_anchors(&canonical_policy, &anchors)?;
    let contracts = VerifiedF7AnchorAuthorizationV2 {
        dom_chain_id: dom_evidence.chain_id,
        session_id: terms.session_id.0,
        settlement_id: terms.settlement_id.0,
        route_id: role.route_id(),
        composition_binding_digest: role.composition_binding_digest(),
        final_claim_role_binding_digest: role_digest,
        ready_binding_digest: ready_digest,
        roster_digest: role.roster_digest(),
        secret_source_scope_digest: role.secret_source_scope_digest(),
        terms_hash,
        m8_policy_digest: policy_digest,
        anchor_evidence_digest,
        adaptor_secret_origin_id: role.adaptor_secret_origin_id().0,
        dom_claim_sender_id: role.dom_claim_sender_id().0,
        final_claim_receiver_id: role.final_claim_receiver_id().0,
        reveal_mode: role.reveal_mode(),
        secret_source: role.secret_source(),
        route_leg: role.route_leg(),
        sender_direction: role.sender_direction(),
        receiver_direction: role.receiver_direction(),
        origin_direction: role.origin_direction(),
        dom_funding_id: dom_evidence.funding_txid,
        dom_funding_block_hash: dom_evidence.block_hash,
        dom_funding_block_height: dom_evidence.height,
        dom_observed_tip_hash: dom_evidence.observed_tip_hash,
        dom_observed_tip_height: dom_evidence.observed_tip_height,
        bitcoin_funding_id: bitcoin_evidence.funding_txid,
        bitcoin_chain_registry_id: terms.counterparty_leg.chain_id.0,
        dom_shared_output_commitment: ready.shared_output_commitment(),
        funding_template_hash: ready.funding_template_hash(),
        claim_template_hash: ready.claim_template_hash(),
        refund_template_hash: ready.refund_template_hash(),
        claim_round_start_transcript_hash: request.expected_dom_claim_round_start_transcript_hash,
        adaptor_point_bytes: ready.adaptor_point_sec1(),
        dom_minimum_confirmations,
        dom_confirmation_depth: dom_evidence.confirmation_depth,
        bitcoin_confirmation_depth: bitcoin_evidence.confirmation_depth,
    };
    Ok(VerifiedF7RouteAnchorAuthorizationsV2 {
        contracts,
        bitcoin_signers: [first, second],
    })
}

fn reveal_order_matches_policy(
    reveal_mode: FinalClaimRevealModeV1,
    policy: &M8TimingPolicyV1,
) -> bool {
    let first_is_dom = matches!(policy.first_refund, TimelockOffsetV1::DomBlocks { .. });
    let second_is_dom = matches!(policy.second_refund, TimelockOffsetV1::DomBlocks { .. });
    match reveal_mode {
        FinalClaimRevealModeV1::DomRevealsFirst => first_is_dom && !second_is_dom,
        FinalClaimRevealModeV1::DomReactsToCounterpartyReveal => !first_is_dom && second_is_dom,
    }
}

fn verify_dom_funding_evidence(
    dom: &DomHttpChainAdapterV1,
    expected_funding_txid: [u8; 32],
    expected_shared_output_commitment: [u8; 33],
    expected_funding_template_hash: [u8; 32],
    minimum_confirmations: u32,
) -> Result<VerifiedDomFundingEvidenceV1, F7AnchorAuthorityError> {
    if expected_funding_txid == [0; 32]
        || expected_shared_output_commitment == [0; 33]
        || expected_funding_template_hash == [0; 32]
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
                if transaction.tx_hash() != expected_funding_txid {
                    continue;
                }
                if found.is_some() {
                    return Err(F7AnchorAuthorityError::DomFundingMismatch);
                }
                require_exact_dom_funding_template_hash(
                    transaction.template_hash(),
                    expected_funding_template_hash,
                )?;
                let created = transaction
                    .transaction()
                    .outputs
                    .iter()
                    .filter(|output| {
                        output.commitment.as_bytes() == &expected_shared_output_commitment
                    })
                    .count();
                if created != 1
                    || transaction.spends_commitment(&expected_shared_output_commitment)
                    || transaction.location().block_hash() != block.block_hash
                    || transaction.location().block_height() != block.height
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
                observed_tip_hash: page.identity.tip_hash,
                observed_tip_height: page.identity.tip_height,
                confirmation_depth,
            });
        }
    }
    Err(F7AnchorAuthorityError::BoundsExceeded)
}

fn require_exact_dom_funding_template_hash(
    observed: Result<[u8; 32], ChainAdapterError>,
    expected: [u8; 32],
) -> Result<(), F7AnchorAuthorityError> {
    let observed = observed.map_err(|_| F7AnchorAuthorityError::DomFundingMismatch)?;
    if expected == [0; 32] || observed != expected {
        Err(F7AnchorAuthorityError::DomFundingMismatch)
    } else {
        Ok(())
    }
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
    use adapter_btc::timelock::{BitcoinFinalityPolicyV1, ChainTimingBoundsV1};
    use adapter_btc::types::BitcoinNetworkV1;
    use kaystra_core::types::{
        AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1,
        ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec,
    };
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(VerifiedF7AnchorAuthorizationV1: Clone, Copy, core::fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(VerifiedF7RouteAnchorAuthorizationsV1: Clone, Copy, core::fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(VerifiedF7AnchorAuthorizationV2: Clone, Copy, core::fmt::Debug, Eq, PartialEq);
    assert_not_impl_any!(VerifiedF7RouteAnchorAuthorizationsV2: Clone, Copy, core::fmt::Debug, Eq, PartialEq);

    fn timing_policy(
        first_refund: TimelockOffsetV1,
        second_refund: TimelockOffsetV1,
    ) -> M8TimingPolicyV1 {
        let bounds = ChainTimingBoundsV1 {
            min_block_seconds: 1,
            max_block_seconds: 2,
            max_reorg_seconds: 1,
            observation_seconds: 1,
            broadcast_seconds: 1,
        };
        M8TimingPolicyV1 {
            settlement_terms_hash: [1; 32],
            first_refund,
            second_refund,
            safety_margin_seconds: 6,
            dom_bounds: bounds,
            btc_bounds: bounds,
            bitcoin_finality: BitcoinFinalityPolicyV1 {
                network: BitcoinNetworkV1::Regtest,
                minimum_confirmations: 1,
                maximum_reorg_depth: 1,
                require_header_chain: true,
                require_witness_commitment: true,
                policy_id: [2; 32],
                version: 1,
            },
        }
    }

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
            observed_tip_hash: [0xa4; 32],
            observed_tip_height: 11,
            confirmation_depth: 2,
        };
        assert!(matches!(
            require_dom_chain_binding(&terms([0xb1; 32]), &evidence),
            Err(F7AnchorAuthorityError::RouteBindingMismatch)
        ));
        assert!(require_dom_chain_binding(&terms([0xa1; 32]), &evidence).is_ok());
    }

    #[test]
    fn v1_new_authority_is_unconditionally_recovery_only() {
        assert!(matches!(
            refuse_legacy_v1_new_authority::<VerifiedF7RouteAnchorAuthorizationsV1>(),
            Err(F7AnchorAuthorityError::LegacyV1RecoveryOnly)
        ));
    }

    #[test]
    fn observed_dom_funding_template_must_match_ready_binding_exactly() {
        let expected = [0xc1; 32];
        assert!(require_exact_dom_funding_template_hash(Ok(expected), expected).is_ok());

        assert!(matches!(
            require_exact_dom_funding_template_hash(Ok([0xc2; 32]), expected),
            Err(F7AnchorAuthorityError::DomFundingMismatch)
        ));
        assert!(matches!(
            require_exact_dom_funding_template_hash(
                Err(ChainAdapterError::InvalidEvidence),
                expected,
            ),
            Err(F7AnchorAuthorityError::DomFundingMismatch)
        ));
        assert!(matches!(
            require_exact_dom_funding_template_hash(Ok([0; 32]), [0; 32]),
            Err(F7AnchorAuthorityError::DomFundingMismatch)
        ));
    }

    #[test]
    fn reveal_mode_selects_policy_order_without_using_direction_or_index() {
        let dom_first = timing_policy(
            TimelockOffsetV1::DomBlocks { delta_blocks: 10 },
            TimelockOffsetV1::BtcBlocks { delta_blocks: 20 },
        );
        assert!(reveal_order_matches_policy(
            FinalClaimRevealModeV1::DomRevealsFirst,
            &dom_first
        ));
        assert!(!reveal_order_matches_policy(
            FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
            &dom_first
        ));

        let bitcoin_first = timing_policy(
            TimelockOffsetV1::BtcTime512s { units: 10 },
            TimelockOffsetV1::DomBlocks { delta_blocks: 20 },
        );
        assert!(reveal_order_matches_policy(
            FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
            &bitcoin_first
        ));
        assert!(!reveal_order_matches_policy(
            FinalClaimRevealModeV1::DomRevealsFirst,
            &bitcoin_first
        ));
    }
}

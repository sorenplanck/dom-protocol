//! Real DOM node adapter for the F7 settlement engine.
//!
//! This crate is the explicit replacement for `adapter-dom-sim`. It consumes
//! only the authenticated full-fidelity scanner from `dom-contracts`, maps
//! canonical real-DOM transactions to neutral settlement records, and uses
//! `dom-leg` to verify and extract an adaptor secret from a confirmed claim.
//! No simulator, mock verifier or locally invented transaction format exists
//! on this path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod terminal_finality;

pub use terminal_finality::{
    VerifiedDomClaimFinalityV1, VerifiedDomClaimReorgV1, VerifiedDomFundingFinalityV1,
    VerifiedDomFundingReorgV1, VerifiedDomRefundFinalityV1, VerifiedDomRefundReorgV1,
};

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use counterparty_api::RevealedSecretBytes;
use dom_adaptor::{
    ClaimObservationError, DomClaimObservationTagV1, EarlyShareRevealV1,
    ExactDomClaimBroadcasterV1, ExactDomClaimObservationSourceV1, FinalSignatureOpeningContextV1,
    NonceRevealV1, ObservedClaimBindingV1, ObservedClaimFactsV1, ObservedClaimLocationV1,
    SchnorrSignature, TrustedChainIdV1, VerifiedDomClaimObservationV1,
};
use dom_leg::{
    AggregateSigningKey, BoundRound, CallerSuppliedIdentitySessionRequestV1, DomLegSession,
    LegError, PreSignatureBytes, SessionBindings,
};
use dom_scriptless_chain_adapter::{
    canonical_transaction_hash_v1, CanonicalBlockEvidenceV1, CanonicalTransactionEvidenceV1,
    ChainAdapterError, DomHttpChainAdapterV1, ObservedDomIdentityV1, ScriptlessScanCursorV1,
    SubmissionReceiptV1, SubmissionStateV1, MAX_SCRIPTLESS_SCAN_BLOCKS_V1,
};
use dom_scriptless_store::{
    AuthenticatedContractsRefundV1, ContractsSessionStoreV1, DomTransactionValidationContextV1,
    ExactDomFundingBroadcasterV1, ExactDomRefundBroadcasterV1, FundingBroadcastV1,
    PreparedOperationalFinalClaimSubmissionV2, RealDomContractFactsV2, RefundBroadcastV1,
    RetainedClaimRoundFactsV2, SessionStoreError,
};
use kaystra_core::settlement_engine::{
    ChainCursorV1, ChainRecordV1, ChainSourceErrorV1, ChainSourceV1, EffectOutcome, EffectSinkV1,
};
use kaystra_core::state::{Effect, EvidenceRefV1};
use kaystra_core::store_port::ClaimedEffectV1;
use kaystra_core::types::{ChainId, SettlementId};

type Blake2b256 = Blake2b<U32>;

const CURSOR_MAGIC: &[u8; 8] = b"DOMF7C1\0";
const CURSOR_VERSION: u16 = 1;
const CURSOR_PREFIX_LEN: usize = 8 + 2 + 2 + 8;
const CURSOR_ENTRY_LEN: usize = 8 + 32;
const CURSOR_DIGEST_LEN: usize = 32;
const CURSOR_DOMAIN: &[u8] = b"DOM-INTEROP/F7-DOM-CURSOR/V1\0";
const REFUND_EVIDENCE_DOMAIN: &[u8] = b"DOM-INTEROP/F7-DOM-REFUND-EVIDENCE/V1\0";
const MAX_CURSOR_HISTORY: usize = 4_096;
const MAX_SNAPSHOT_SCAN_PAGES: usize = 16_384;

/// Real-DOM adapter errors outside the neutral engine taxonomy.
#[derive(Debug, thiserror::Error)]
pub enum RealDomError {
    /// Authenticated scanner or canonical evidence failure.
    #[error("real DOM scanner: {0}")]
    Chain(#[from] ChainAdapterError),
    /// DOM adaptor verification or extraction failure.
    #[error("real DOM claim verification: {0}")]
    Leg(#[from] LegError),
    /// Retained Contracts Store authentication or lifecycle failure.
    #[error("real DOM Contracts authority: {0}")]
    Store(#[from] SessionStoreError),
    /// A mutex was poisoned by an interrupted owner.
    #[error("real DOM runtime lock poisoned")]
    LockPoisoned,
    /// Cursor bytes, chain position or configured transaction identity failed.
    #[error("invalid real DOM evidence")]
    InvalidEvidence,
    /// The observed claim contradicted the proved adaptor opening.
    #[error("real DOM claim observation: {0}")]
    Observation(#[from] ClaimObservationError),
    /// A fixed cursor or history bound was exceeded.
    #[error("real DOM adapter bound exceeded")]
    BoundsExceeded,
    /// The requested canonical transaction was not found.
    #[error("real DOM transaction evidence not found")]
    EvidenceNotFound,
    /// The authenticated finality policy cannot be represented by this runtime.
    #[error("invalid real DOM finality policy")]
    FinalityPolicyInvalid,
    /// The exact canonical transaction has not reached the frozen depth.
    #[error("insufficient real DOM confirmation depth")]
    InsufficientConfirmations,
    /// The exact transaction is still present on the canonical chain.
    #[error("real DOM transaction remains canonical")]
    TransactionStillCanonical,
    /// The canonical fork exceeds the authenticated recovery window.
    #[error("real DOM reorganization exceeds policy")]
    ReorgBeyondPolicy,
}

/// Canonical real-DOM transaction evidence returned by the authenticated
/// scanner and revalidated against its exact chain reference.
///
/// Its fields are deliberately private. Composition code cannot manufacture
/// an M.8 funding anchor from identifiers supplied in a request; it must first
/// obtain this value from [`RealDomRpcRuntimeV1::verified_transaction`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CanonicalDomTransactionEvidenceV1 {
    evidence: CanonicalTransactionEvidenceV1,
    block_time_seconds: u64,
}

/// Confirmed canonical DOM funding evidence bound to the exact shared output.
///
/// Unlike the generic transaction evidence used by the claim scanner, this
/// value can only be issued after the real-node runtime proves that the
/// transaction creates the expected shared commitment exactly once, does not
/// spend it, and has reached the caller's frozen confirmation policy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CanonicalDomFundingEvidenceV1 {
    evidence: CanonicalTransactionEvidenceV1,
    block_time_seconds: u64,
    shared_output_commitment: [u8; 33],
    observed_tip_height: u64,
    observed_tip_hash: [u8; 32],
    confirmation_depth: u32,
}

/// Canonical DOM refund evidence bound to the exact retained Contracts
/// artifact, its consumed funding authorization, and the real scanner.
///
/// This value is deliberately linear: it has no public constructor, codec,
/// `Clone`, `Copy`, or byte accessor. It can be issued only after the Store
/// has entered `RefundBroadcast` (or its durable `Refunded` successor) and
/// authenticates the scanner's exact canonical transaction bytes.
pub struct VerifiedDomRefundEvidenceV1 {
    canonical: CanonicalDomTransactionEvidenceV1,
    contracts: AuthenticatedContractsRefundV1,
    evidence_digest: [u8; 32],
}

impl core::fmt::Debug for VerifiedDomRefundEvidenceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedDomRefundEvidenceV1")
            .field("session_id", self.contracts.session_id())
            .field("tx_hash", self.contracts.transaction_hash())
            .field("block_height", &self.canonical.block_height())
            .field("canonical_bytes", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl VerifiedDomRefundEvidenceV1 {
    /// Contracts session owning the exact persisted refund.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        *self.contracts.session_id()
    }

    /// Canonical BLAKE2b-256 refund transaction identity.
    #[must_use]
    pub const fn tx_hash(&self) -> [u8; 32] {
        *self.contracts.transaction_hash()
    }

    /// Canonical containing-block identity.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.canonical.block_hash()
    }

    /// Canonical containing-block height.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.canonical.block_height()
    }

    /// Timestamp authenticated by the exact canonical containing header.
    #[must_use]
    pub const fn block_time_seconds(&self) -> u64 {
        self.canonical.block_time_seconds()
    }

    /// Position of the refund in its canonical block.
    #[must_use]
    pub const fn transaction_index(&self) -> u32 {
        self.canonical.transaction_index()
    }

    /// Domain-separated digest covering scanner location and all public
    /// Contracts artifact/consumption/history bindings.
    #[must_use]
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }
}

impl CanonicalDomTransactionEvidenceV1 {
    /// Canonical BLAKE2b-256 transaction identity.
    #[must_use]
    pub const fn tx_hash(&self) -> [u8; 32] {
        self.evidence.tx_hash()
    }

    /// Canonical containing-block identity.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.evidence.location().block_hash()
    }

    /// Canonical containing-block height.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.evidence.location().block_height()
    }

    /// Timestamp authenticated by the exact canonical containing header.
    #[must_use]
    pub const fn block_time_seconds(&self) -> u64 {
        self.block_time_seconds
    }

    /// Position of the transaction in its canonical block.
    #[must_use]
    pub const fn transaction_index(&self) -> u32 {
        self.evidence.location().transaction_index()
    }

    /// Exact canonical transaction bytes returned by the real scanner.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.evidence.canonical_bytes()
    }
}

impl CanonicalDomFundingEvidenceV1 {
    /// Canonical BLAKE2b-256 funding transaction identity.
    #[must_use]
    pub const fn tx_hash(&self) -> [u8; 32] {
        self.evidence.tx_hash()
    }

    /// Canonical containing-block identity.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.evidence.location().block_hash()
    }

    /// Canonical containing-block height.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.evidence.location().block_height()
    }

    /// Timestamp authenticated by the exact canonical containing header.
    #[must_use]
    pub const fn block_time_seconds(&self) -> u64 {
        self.block_time_seconds
    }

    /// Exact shared output proven to occur once in the funding transaction.
    #[must_use]
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        self.shared_output_commitment
    }

    /// Snapshot tip against which confirmation depth was evaluated.
    #[must_use]
    pub const fn observed_tip_height(&self) -> u64 {
        self.observed_tip_height
    }

    /// Canonical snapshot tip hash paired with [`Self::observed_tip_height`].
    #[must_use]
    pub const fn observed_tip_hash(&self) -> [u8; 32] {
        self.observed_tip_hash
    }

    /// Confirmation depth including the funding block itself.
    #[must_use]
    pub const fn confirmation_depth(&self) -> u32 {
        self.confirmation_depth
    }

    /// Exact canonical transaction bytes returned by the real scanner.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.evidence.canonical_bytes()
    }
}

/// Frozen transaction identities for one DOM Scriptless settlement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RealDomContractV1 {
    /// Neutral registry identifier used by the settlement engine.
    pub chain_id: ChainId,
    /// Shared 2-of-2 confidential output commitment.
    pub shared_output_commitment: [u8; 33],
    /// Fully signed funding transaction identifier.
    pub funding_tx_hash: [u8; 32],
    /// Signature-omitting canonical claim template hash.
    pub claim_template_hash: [u8; 32],
    /// Fully signed pre-authorized refund transaction identifier.
    pub refund_tx_hash: [u8; 32],
    /// Claim kernel carrying the final adaptor signature.
    pub claim_kernel_index: u32,
}

impl RealDomContractV1 {
    /// Rejects zero, duplicate and unbounded configuration before any RPC.
    pub fn validate(&self) -> Result<(), RealDomError> {
        if self.chain_id.0 == [0_u8; 32]
            || self.shared_output_commitment == [0_u8; 33]
            || self.funding_tx_hash == [0_u8; 32]
            || self.claim_template_hash == [0_u8; 32]
            || self.refund_tx_hash == [0_u8; 32]
            || self.funding_tx_hash == self.refund_tx_hash
            || usize::try_from(self.claim_kernel_index).is_err()
        {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct CursorStateV1 {
    next_height: u64,
    history: Vec<(u64, [u8; 32])>,
}

impl CursorStateV1 {
    fn genesis() -> Self {
        Self {
            next_height: 0,
            history: Vec::new(),
        }
    }

    fn validate(&self) -> Result<(), RealDomError> {
        if self.history.len() > MAX_CURSOR_HISTORY {
            return Err(RealDomError::BoundsExceeded);
        }
        if self.history.is_empty() {
            if self.next_height != 0 {
                return Err(RealDomError::InvalidEvidence);
            }
            return Ok(());
        }
        for pair in self.history.windows(2) {
            if pair[0].0.checked_add(1) != Some(pair[1].0) {
                return Err(RealDomError::InvalidEvidence);
            }
        }
        let (last_height, last_hash) = self
            .history
            .last()
            .copied()
            .ok_or(RealDomError::InvalidEvidence)?;
        if last_hash == [0_u8; 32] || last_height.checked_add(1) != Some(self.next_height) {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(())
    }

    fn append(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        history_limit: usize,
    ) -> Result<(), RealDomError> {
        if height != self.next_height || block_hash == [0_u8; 32] {
            return Err(RealDomError::InvalidEvidence);
        }
        self.history.push((height, block_hash));
        self.next_height = height.checked_add(1).ok_or(RealDomError::BoundsExceeded)?;
        if self.history.len() > history_limit {
            let excess = self.history.len() - history_limit;
            self.history.drain(..excess);
        }
        self.validate()
    }

    fn rewind_one(&mut self) -> Result<(u64, [u8; 32]), RealDomError> {
        let removed = self.history.pop().ok_or(RealDomError::InvalidEvidence)?;
        self.next_height = removed.0;
        self.validate()?;
        Ok(removed)
    }

    fn scanner_cursor(&self) -> ScriptlessScanCursorV1 {
        ScriptlessScanCursorV1 {
            next_height: self.next_height,
            anchor_hash: self.history.last().map(|entry| entry.1),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, RealDomError> {
        self.validate()?;
        let count = u16::try_from(self.history.len()).map_err(|_| RealDomError::BoundsExceeded)?;
        let body_len = CURSOR_PREFIX_LEN
            .checked_add(
                self.history
                    .len()
                    .checked_mul(CURSOR_ENTRY_LEN)
                    .ok_or(RealDomError::BoundsExceeded)?,
            )
            .ok_or(RealDomError::BoundsExceeded)?;
        let mut bytes = Vec::with_capacity(
            body_len
                .checked_add(CURSOR_DIGEST_LEN)
                .ok_or(RealDomError::BoundsExceeded)?,
        );
        bytes.extend_from_slice(CURSOR_MAGIC);
        bytes.extend_from_slice(&CURSOR_VERSION.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&self.next_height.to_le_bytes());
        for (height, hash) in &self.history {
            bytes.extend_from_slice(&height.to_le_bytes());
            bytes.extend_from_slice(hash);
        }
        let digest = cursor_digest(&bytes);
        bytes.extend_from_slice(&digest);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RealDomError> {
        if bytes.len() < CURSOR_PREFIX_LEN + CURSOR_DIGEST_LEN
            || &bytes[..8] != CURSOR_MAGIC
            || u16::from_le_bytes([bytes[8], bytes[9]]) != CURSOR_VERSION
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let count = usize::from(u16::from_le_bytes([bytes[10], bytes[11]]));
        if count > MAX_CURSOR_HISTORY {
            return Err(RealDomError::BoundsExceeded);
        }
        let expected_len = CURSOR_PREFIX_LEN
            .checked_add(
                count
                    .checked_mul(CURSOR_ENTRY_LEN)
                    .ok_or(RealDomError::BoundsExceeded)?,
            )
            .and_then(|length| length.checked_add(CURSOR_DIGEST_LEN))
            .ok_or(RealDomError::BoundsExceeded)?;
        if bytes.len() != expected_len {
            return Err(RealDomError::InvalidEvidence);
        }
        let digest_offset = expected_len - CURSOR_DIGEST_LEN;
        if cursor_digest(&bytes[..digest_offset]) != bytes[digest_offset..] {
            return Err(RealDomError::InvalidEvidence);
        }
        let next_height = read_u64(&bytes[12..20])?;
        let mut history = Vec::with_capacity(count);
        let mut offset = CURSOR_PREFIX_LEN;
        for _ in 0..count {
            let height = read_u64(&bytes[offset..offset + 8])?;
            let mut hash = [0_u8; 32];
            hash.copy_from_slice(&bytes[offset + 8..offset + CURSOR_ENTRY_LEN]);
            history.push((height, hash));
            offset += CURSOR_ENTRY_LEN;
        }
        let state = Self {
            next_height,
            history,
        };
        state.validate()?;
        Ok(state)
    }

    fn into_core(self) -> Result<ChainCursorV1, RealDomError> {
        let (height, anchor) = self.history.last().copied().unwrap_or((0, [0_u8; 32]));
        Ok(ChainCursorV1 {
            bytes: self.encode()?,
            height,
            anchor,
        })
    }

    fn from_core(cursor: &ChainCursorV1) -> Result<Self, RealDomError> {
        let state = Self::decode(&cursor.bytes)?;
        let (height, anchor) = state.history.last().copied().unwrap_or((0, [0_u8; 32]));
        if cursor.height != height || cursor.anchor != anchor {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(state)
    }
}

fn cursor_digest(bytes: &[u8]) -> [u8; 32] {
    Blake2b256::new()
        .chain_update(CURSOR_DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn read_u64(bytes: &[u8]) -> Result<u64, RealDomError> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| RealDomError::InvalidEvidence)?;
    Ok(u64::from_le_bytes(array))
}

#[derive(Default)]
struct RuntimeCacheV1 {
    blocks: BTreeMap<u64, ([u8; 32], u64)>,
    transactions: BTreeMap<[u8; 32], CanonicalTransactionEvidenceV1>,
}

/// Shared authenticated RPC runtime used by the source and claim consumer.
pub struct RealDomRpcRuntimeV1 {
    adapter: DomHttpChainAdapterV1,
    cache: Mutex<RuntimeCacheV1>,
    history_limit: usize,
}

impl core::fmt::Debug for RealDomRpcRuntimeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RealDomRpcRuntimeV1")
            .field("history_limit", &self.history_limit)
            .finish_non_exhaustive()
    }
}

impl RealDomRpcRuntimeV1 {
    /// Creates a runtime with an explicit restart/reorg history bound.
    pub fn new(adapter: DomHttpChainAdapterV1, history_limit: usize) -> Result<Self, RealDomError> {
        if history_limit == 0 || history_limit > MAX_CURSOR_HISTORY {
            return Err(RealDomError::BoundsExceeded);
        }
        Ok(Self {
            adapter,
            cache: Mutex::new(RuntimeCacheV1::default()),
            history_limit,
        })
    }

    /// Submit one exact Contracts-owned funding outbox through this runtime's
    /// sole authenticated node client.
    pub fn submit_persisted_funding(
        &self,
        broadcast: FundingBroadcastV1,
    ) -> Result<SubmissionReceiptV1, RealDomError> {
        broadcast
            .dispatch_with(&mut RealDomExactBroadcasterV1::new(&self.adapter))
            .map_err(RealDomError::Chain)
    }

    /// Submit one exact Contracts-owned refund outbox through this runtime's
    /// sole authenticated node client.
    pub fn submit_persisted_refund(
        &self,
        broadcast: RefundBroadcastV1,
    ) -> Result<SubmissionReceiptV1, RealDomError> {
        broadcast
            .dispatch_with(&mut RealDomExactBroadcasterV1::new(&self.adapter))
            .map_err(RealDomError::Chain)
    }

    /// Submit the exact already-exposed V2 FinalClaim retained by Contracts.
    /// The handle owns the bytes; neither they nor the bearer leave the two
    /// authorities that already hold them.
    pub fn submit_persisted_final_claim_v2(
        &self,
        prepared: &PreparedOperationalFinalClaimSubmissionV2,
    ) -> Result<SubmissionReceiptV1, RealDomError> {
        prepared
            .submit_with(&self.adapter)
            .map_err(RealDomError::Chain)
    }

    fn cache(&self) -> Result<MutexGuard<'_, RuntimeCacheV1>, RealDomError> {
        self.cache.lock().map_err(|_| RealDomError::LockPoisoned)
    }

    /// Resolve the current refund validation context from one authenticated tip.
    ///
    /// Height and chain identity come from the same full-fidelity scanner used
    /// by terminal finality. Wall time is read inside this trusted adapter
    /// boundary, so callers cannot lower the height, transplant a chain, or
    /// select an earlier timestamp to make a retained timelock appear valid.
    pub fn current_transaction_validation_context(
        &self,
    ) -> Result<DomTransactionValidationContextV1, RealDomError> {
        let (state, identity) = self.scan_through_with_tip(0)?;
        let (_, identity) = self.scan_snapshot_to_tip(state, identity)?;
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RealDomError::InvalidEvidence)?
            .as_secs();
        Ok(DomTransactionValidationContextV1::new(
            identity.tip_height,
            self.adapter.expected_identity().chain_id,
            now_unix_seconds,
        ))
    }

    fn cache_blocks(&self, blocks: &[CanonicalBlockEvidenceV1]) -> Result<(), RealDomError> {
        let mut cache = self.cache()?;
        for block in blocks {
            if cache
                .blocks
                .get(&block.height)
                .is_some_and(|(existing_hash, existing_time)| {
                    existing_hash != &block.block_hash || *existing_time != block.timestamp
                })
            {
                cache.blocks.retain(|height, _| *height < block.height);
                cache
                    .transactions
                    .retain(|_, transaction| transaction.location().block_height() < block.height);
            }
            cache
                .blocks
                .insert(block.height, (block.block_hash, block.timestamp));
            for transaction in &block.transactions {
                cache
                    .transactions
                    .insert(transaction.tx_hash(), transaction.clone());
            }
        }
        Ok(())
    }

    fn scan_state(
        &self,
        state: &CursorStateV1,
        max_blocks: u64,
    ) -> Result<
        (
            Vec<CanonicalBlockEvidenceV1>,
            CursorStateV1,
            ObservedDomIdentityV1,
        ),
        RealDomError,
    > {
        let page = self.adapter.scan_page(state.scanner_cursor(), max_blocks)?;
        self.cache_blocks(&page.blocks)?;
        let mut next = state.clone();
        for block in &page.blocks {
            next.append(block.height, block.block_hash, self.history_limit)?;
        }
        if next.scanner_cursor() != page.next_cursor {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok((page.blocks, next, page.identity))
    }

    fn scan_through(&self, height: u64) -> Result<CursorStateV1, RealDomError> {
        self.scan_through_with_tip(height).map(|(state, _)| state)
    }

    fn scan_through_with_tip(
        &self,
        height: u64,
    ) -> Result<(CursorStateV1, ObservedDomIdentityV1), RealDomError> {
        let mut state = CursorStateV1::genesis();
        loop {
            let remaining = height
                .checked_sub(state.next_height)
                .and_then(|value| value.checked_add(1))
                .unwrap_or(1)
                .min(MAX_SCRIPTLESS_SCAN_BLOCKS_V1);
            let (_, next, identity) = self.scan_state(&state, remaining)?;
            if next.next_height > height {
                return Ok((next, identity));
            }
            let after_tip = identity
                .tip_height
                .checked_add(1)
                .ok_or(RealDomError::BoundsExceeded)?;
            if next.next_height == state.next_height || next.next_height > after_tip {
                return Err(RealDomError::EvidenceNotFound);
            }
            state = next;
        }
    }

    fn scan_snapshot_to_tip(
        &self,
        mut state: CursorStateV1,
        mut identity: ObservedDomIdentityV1,
    ) -> Result<(CursorStateV1, ObservedDomIdentityV1), RealDomError> {
        for _ in 0..MAX_SNAPSHOT_SCAN_PAGES {
            if state.next_height > identity.tip_height {
                let (tip_height, tip_hash) = state
                    .history
                    .last()
                    .copied()
                    .ok_or(RealDomError::InvalidEvidence)?;
                if tip_height != identity.tip_height || tip_hash != identity.tip_hash {
                    return Err(RealDomError::InvalidEvidence);
                }
                return Ok((state, identity));
            }
            let (_, next, next_identity) =
                self.scan_state(&state, MAX_SCRIPTLESS_SCAN_BLOCKS_V1)?;
            if next.next_height == state.next_height {
                return Err(RealDomError::EvidenceNotFound);
            }
            state = next;
            identity = next_identity;
        }
        Err(RealDomError::BoundsExceeded)
    }

    fn cursor_at(&self, height: u64) -> Result<CursorStateV1, RealDomError> {
        let scanned = self.scan_through(height)?;
        let history = scanned
            .history
            .into_iter()
            .filter(|entry| entry.0 <= height)
            .collect::<Vec<_>>();
        let state = Self::tail_state(history, self.history_limit)?;
        if state.next_height != height.checked_add(1).ok_or(RealDomError::BoundsExceeded)? {
            return Err(RealDomError::EvidenceNotFound);
        }
        Ok(state)
    }

    fn tail_state(
        mut history: Vec<(u64, [u8; 32])>,
        history_limit: usize,
    ) -> Result<CursorStateV1, RealDomError> {
        if history.len() > history_limit {
            let excess = history.len() - history_limit;
            history.drain(..excess);
        }
        let next_height = history
            .last()
            .and_then(|entry| entry.0.checked_add(1))
            .unwrap_or(0);
        let state = CursorStateV1 {
            next_height,
            history,
        };
        state.validate()?;
        Ok(state)
    }

    /// Loads exact evidence by canonical reference, rescanning after restart
    /// when the in-memory cache is empty.
    ///
    /// The ancestry walk still runs; only its tip is dropped. A caller that has
    /// to carry the tip — the observation boundary is the one that does — takes
    /// [`Self::transaction_with_proved_tip`] instead.
    pub fn transaction(
        &self,
        evidence: &EvidenceRefV1,
    ) -> Result<CanonicalTransactionEvidenceV1, RealDomError> {
        self.transaction_with_proved_tip(evidence)
            .map(|(transaction, _)| transaction)
    }

    /// Loads exact evidence together with the canonical tip its block was
    /// proved, by unbroken header linkage, to be an ancestor of.
    ///
    /// Why the walk runs all the way to the tip, and not only to the observed
    /// height: a scan that stops at the block it was looking for proves that
    /// the node served a hash-linked prefix ending there, and nothing at all
    /// about how that prefix relates to any tip. It cannot distinguish a block
    /// buried under a hundred successors from a block that was orphaned by a
    /// reorganisation, because the two look identical from below. A consumer
    /// handed only `(height, block_id)` therefore has to fetch a tip from
    /// somewhere else to judge depth, and any tip fetched somewhere else may
    /// belong to a different branch — which is precisely the pairing that lets
    /// an orphaned claim pass a depth test.
    ///
    /// `scan_snapshot_to_tip` is what closes it: it continues the same
    /// anchored cursor, page by prev-hash-linked page, until the accumulated
    /// history's last entry *is* the reported tip, identity included. Every
    /// block between the observed one and that tip is therefore linked, so the
    /// observed block is an ancestor of it. This is the same walk
    /// `verified_funding` and `canonical_terminal_snapshot` already perform;
    /// the claim path had been the one caller that skipped it.
    ///
    /// What remains trusted, and is not verified by anything here: that the tip
    /// the node reports is the tip of the honest chain. The scanner's
    /// `canonical` flag and snapshot identity
    /// (`dom-scriptless-chain-adapter/src/lib.rs:786` and `:794`) are the node's
    /// word. **This is trust in the node**, it is the real boundary of the
    /// design, and it is deliberate: a light client cannot do better without
    /// consensus-weight evidence. What the walk removes is the strictly weaker
    /// failure — a claim that is not on the chain leading to the tip the node
    /// itself named.
    pub fn transaction_with_proved_tip(
        &self,
        evidence: &EvidenceRefV1,
    ) -> Result<(CanonicalTransactionEvidenceV1, ObservedDomIdentityV1), RealDomError> {
        // Always re-read the canonical chain through the anchored scanner. A
        // cached transaction may belong to a branch invalidated after its
        // durable outbox effect was created.
        //
        // A zero block reference is the documented "resolve" contract of
        // `dom_refund_evidence_ref`: the caller supplies only the transaction
        // identity and asks the scanner to resolve and authenticate the
        // canonical location, rather than asserting one. The previous code
        // scanned "through height 0" and then required the found location to
        // equal the zero fields, which cannot ever succeed — the refund
        // terminal confirmation was unreachable by construction in every
        // execution shape, resumed or fresh (F-20260819T000139Z). In resolve
        // mode the scan runs to the canonical tip and the located transaction's
        // own authenticated location is returned.
        let resolve_mode = self.validate_evidence_scope(evidence)?;
        let anchor_height = if resolve_mode {
            0
        } else {
            evidence.block_height
        };
        let (state, identity) = self.scan_through_with_tip(anchor_height)?;
        let (_, identity) = self.scan_snapshot_to_tip(state, identity)?;
        let transaction = self.cached_transaction_on_walked_chain(&evidence.tx_id, &identity)?;
        let transaction = if resolve_mode {
            if transaction.tx_hash() != evidence.tx_id {
                return Err(RealDomError::InvalidEvidence);
            }
            transaction
        } else {
            validate_evidence_reference(evidence, transaction)?
        };
        Ok((transaction, identity))
    }

    /// Validate the authenticated chain and the closed anchored/resolve shapes.
    ///
    /// Resolve mode deliberately carries only `(chain_id, tx_id)`: its event
    /// index, height and anchor are all zero. A half-zero location is neither an
    /// anchored reference nor resolve mode and is rejected before any scan.
    fn validate_evidence_scope(&self, evidence: &EvidenceRefV1) -> Result<bool, RealDomError> {
        validate_evidence_scope_v1(self.adapter.expected_identity().chain_id, evidence)
    }

    /// Reads one cached transaction after discarding everything the walk just
    /// contradicted.
    ///
    /// The cache is keyed by transaction identity and survives across scans, so
    /// without this an entry left behind by a branch that has since been
    /// reorganised away could still be returned. Two rules retire such
    /// residue: nothing above the proved tip may be read at all, and a
    /// transaction is kept only if the walked chain holds its exact block
    /// identity at its own height. Copied from `canonical_terminal_snapshot`,
    /// which already applied both.
    fn cached_transaction_on_walked_chain(
        &self,
        tx_id: &[u8; 32],
        identity: &ObservedDomIdentityV1,
    ) -> Result<CanonicalTransactionEvidenceV1, RealDomError> {
        let mut cache = self.cache()?;
        cache
            .blocks
            .retain(|height, _| *height <= identity.tip_height);
        let canonical_blocks = cache.blocks.clone();
        cache.transactions.retain(|_, transaction| {
            transaction.location().block_height() <= identity.tip_height
                && canonical_blocks
                    .get(&transaction.location().block_height())
                    .is_some_and(|(hash, _)| hash == &transaction.location().block_hash())
        });
        cache
            .transactions
            .get(tx_id)
            .cloned()
            .ok_or(RealDomError::EvidenceNotFound)
    }

    /// Refetches and revalidates one canonical transaction, returning an
    /// opaque evidence value suitable for the F7 M.8 anchor bridge.
    pub fn verified_transaction(
        &self,
        evidence: &EvidenceRefV1,
    ) -> Result<CanonicalDomTransactionEvidenceV1, RealDomError> {
        let evidence = self.transaction(evidence)?;
        let block_time_seconds = authenticated_block_time(
            &self.cache()?.blocks,
            evidence.location().block_height(),
            evidence.location().block_hash(),
        )?;
        Ok(CanonicalDomTransactionEvidenceV1 {
            evidence,
            block_time_seconds,
        })
    }

    /// Revalidates one canonical funding transaction and its finality depth.
    ///
    /// `minimum_confirmations` is supplied by frozen settlement terms.  A
    /// zero policy, a different transaction, duplicate shared output, spend of
    /// the same commitment, or insufficient canonical depth fails closed.
    pub fn verified_funding(
        &self,
        evidence: &EvidenceRefV1,
        expected_tx_hash: [u8; 32],
        expected_shared_output_commitment: [u8; 33],
        minimum_confirmations: u32,
    ) -> Result<CanonicalDomFundingEvidenceV1, RealDomError> {
        if expected_tx_hash == [0; 32]
            || expected_shared_output_commitment == [0; 33]
            || minimum_confirmations == 0
        {
            return Err(RealDomError::InvalidEvidence);
        }
        // Resolve-mode and anchored references both use the same unbroken walk
        // through the reported tip. The transaction is then retained only if
        // its own authenticated block remains on that exact walked branch.
        let (transaction, identity) = self.transaction_with_proved_tip(evidence)?;
        let created = transaction
            .transaction()
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &expected_shared_output_commitment)
            .count();
        if transaction.tx_hash() != expected_tx_hash
            || created != 1
            || transaction.spends_commitment(&expected_shared_output_commitment)
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let depth = identity
            .tip_height
            .checked_sub(transaction.location().block_height())
            .and_then(|distance| distance.checked_add(1))
            .ok_or(RealDomError::InvalidEvidence)?;
        let confirmation_depth = u32::try_from(depth).map_err(|_| RealDomError::BoundsExceeded)?;
        if confirmation_depth < minimum_confirmations {
            return Err(RealDomError::InsufficientConfirmations);
        }
        let block_time_seconds = authenticated_block_time(
            &self.cache()?.blocks,
            transaction.location().block_height(),
            transaction.location().block_hash(),
        )?;
        Ok(CanonicalDomFundingEvidenceV1 {
            evidence: transaction,
            block_time_seconds,
            shared_output_commitment: expected_shared_output_commitment,
            observed_tip_height: identity.tip_height,
            observed_tip_hash: identity.tip_hash,
            confirmation_depth,
        })
    }

    /// Refetches a canonical refund and binds it to the exact durable
    /// Contracts Store artifact and consumed funding authorization.
    ///
    /// Scanner-first evidence is rejected by the Store until the refund has
    /// crossed its linear exact-byte broadcast authority. The returned value
    /// therefore proves both canonical-chain inclusion and provenance from
    /// the pre-authorized refund persisted before funding.
    pub fn verified_contracts_refund(
        &self,
        store: &ContractsSessionStoreV1,
        session_id: [u8; 32],
        evidence: &EvidenceRefV1,
    ) -> Result<VerifiedDomRefundEvidenceV1, RealDomError> {
        if session_id == [0; 32] {
            return Err(RealDomError::InvalidEvidence);
        }
        let canonical = self.verified_transaction(evidence)?;
        let contracts =
            store.authenticate_persisted_refund(session_id, canonical.canonical_bytes())?;
        if contracts.session_id() != &session_id
            || contracts.transaction_hash() != &canonical.tx_hash()
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let evidence_digest = digest_parts(
            REFUND_EVIDENCE_DOMAIN,
            &[
                contracts.session_id(),
                contracts.transaction_hash(),
                contracts.exact_bytes_digest(),
                contracts.funding_artifact_digest(),
                contracts.funding_consumption_digest(),
                contracts.funding_broadcast_record_digest(),
                contracts.refund_phase_record_digest(),
                &canonical.block_hash(),
                &canonical.block_height().to_be_bytes(),
                &canonical.block_time_seconds().to_be_bytes(),
                &canonical.transaction_index().to_be_bytes(),
            ],
        );
        Ok(VerifiedDomRefundEvidenceV1 {
            canonical,
            contracts,
            evidence_digest,
        })
    }
}

fn validate_evidence_scope_v1(
    expected_chain_id: [u8; 32],
    evidence: &EvidenceRefV1,
) -> Result<bool, RealDomError> {
    if evidence.chain_id.0 != expected_chain_id || evidence.tx_id == [0; 32] {
        return Err(RealDomError::InvalidEvidence);
    }
    let zero_height = evidence.block_height == 0;
    let zero_anchor = evidence.block_anchor == [0; 32];
    if zero_height != zero_anchor || (zero_height && evidence.event_index != 0) {
        return Err(RealDomError::InvalidEvidence);
    }
    Ok(zero_height)
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    Digest::update(&mut hasher, domain);
    for part in parts {
        Digest::update(&mut hasher, (part.len() as u64).to_be_bytes());
        Digest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn authenticated_block_time(
    blocks: &BTreeMap<u64, ([u8; 32], u64)>,
    block_height: u64,
    block_hash: [u8; 32],
) -> Result<u64, RealDomError> {
    blocks
        .get(&block_height)
        .filter(|(authenticated_hash, _)| authenticated_hash == &block_hash)
        .map(|(_, timestamp)| *timestamp)
        .ok_or(RealDomError::InvalidEvidence)
}

fn validate_evidence_reference(
    evidence: &EvidenceRefV1,
    transaction: CanonicalTransactionEvidenceV1,
) -> Result<CanonicalTransactionEvidenceV1, RealDomError> {
    if transaction.tx_hash() != evidence.tx_id
        || transaction.location().block_height() != evidence.block_height
        || transaction.location().block_hash() != evidence.block_anchor
        || transaction.location().transaction_index() != evidence.event_index
    {
        return Err(RealDomError::InvalidEvidence);
    }
    Ok(transaction)
}

/// Rebuilds the frozen contract from the Contracts Store's retained facts.
///
/// A pure mapping and deliberately nothing more. The six retained fields
/// correspond one to one with [`RealDomContractV1`], and the shape refusals a
/// contract must survive — no zero field, funding not equal to refund — are
/// [`RealDomContractV1::validate`], which [`RealDomClaimVerifierV1::new`] runs
/// on the way in. Running them here as well would put one rule in two places.
///
/// The retained `refund_tx_hash` is not reverified against the refund bytes:
/// the Store's funding-gate codec refuses to decode a record at all unless the
/// identifier recomputed from those bytes equals the frozen one, so any facts
/// value in hand already carries that equality, and going back to the bytes to
/// confirm it would compare the Store against itself.
#[must_use]
pub fn real_dom_contract_from_facts_v2(facts: &RealDomContractFactsV2) -> RealDomContractV1 {
    RealDomContractV1 {
        chain_id: ChainId(*facts.chain_id()),
        shared_output_commitment: *facts.shared_output_commitment(),
        funding_tx_hash: *facts.funding_tx_hash(),
        claim_template_hash: *facts.claim_template_hash(),
        refund_tx_hash: *facts.refund_tx_hash(),
        claim_kernel_index: facts.claim_kernel_index(),
    }
}

/// Reassembles the leg session of one retained V2 Claim adaptor round.
///
/// The Store cannot return this type and says so: `dom-leg` publishes the
/// session in two shapes behind a feature and is one of the only two crates
/// allowed to depend on `dom-adaptor`, so it returns the round's facts and the
/// assembly happens here.
///
/// `trusted_chain_id` comes from the authenticated chain adapter's frozen
/// identity, and it is the only chain identity this function ever *uses*: the
/// retained `chain_id` is what it is checked **against**, and appears nowhere
/// else. That direction is the point — a chain identity read out of a record is
/// not authenticated by having been read out of a record — and it is stated as
/// a property of every line below, not of the function in general.
///
/// The aggregate signing key is derived, not received, and derived without a
/// secret. `dom-adaptor` §2.2.6 admits no route that skips share-proof
/// verification, and `AggregateSigningKey::from_verified_share_proofs_v1` is
/// the shareless one: it requires and verifies a proof for **every** roster
/// entry before any public point is added. The retained `0x04` share reveals
/// are decoded for exactly that, and none is skipped — the signer's route
/// excepts the local participant, and here there is no local participant.
///
/// The nonce aggregates are likewise derived rather than received: the retained
/// `0x0d` reveals are decoded and [`BoundRound::bind`] computes the binding
/// factor, the bound nonces, `R` and `R̂` from them.
///
/// **What it does not establish.** That the facts are this session's. Every
/// gate here is the facts against each other, and a set of facts that is
/// internally consistent passes them all whoever assembled it. The caller must
/// have read `facts` from the Contracts Store's own
/// `retained_claim_round_facts_v2`; see
/// [`RealDomClaimVerifierV1::from_retained_facts_v2`] for the whole of that
/// argument. Nothing below is a substitute for it.
pub fn dom_leg_session_from_retained_round_v2(
    facts: &RetainedClaimRoundFactsV2,
    trusted_chain_id: &TrustedChainIdV1,
) -> Result<DomLegSession, RealDomError> {
    if trusted_chain_id.as_bytes() != facts.chain_id() {
        return Err(RealDomError::InvalidEvidence);
    }

    let bindings = SessionBindings::open_with_caller_supplied_identity_v1(
        CallerSuppliedIdentitySessionRequestV1 {
            chain_id: *trusted_chain_id,
            contract_kind: facts.contract_kind(),
            roster: facts.roster().clone(),
            purpose: facts.purpose(),
            adaptor_point: Some(facts.adaptor_point().clone()),
            canonical_transaction_bytes: facts.canonical_transaction_bytes(),
            kernel_message_digest: *facts.kernel_message_digest(),
            terms_hash: *facts.terms_hash(),
            recovery_binding_hash: *facts.recovery_binding_hash(),
            session_id: *facts.session_id(),
            expected_initial_transcript_hash: *facts.initial_transcript_hash(),
            // The reveal transcript, because that is the one the retained
            // pre-signature is bound to and the one the session will be asked
            // to match when that pre-signature is rehydrated.
            transcript_hash: *facts.reveal_transcript_hash(),
        },
    )?;

    // Validates this decode, not the Store's own crossing of bytes and hash:
    // the constructor recomputed the signature-omitting hash from the retained
    // canonical bytes, and it has to be the hash the Store retained beside them.
    if bindings.template_hash() != facts.template_hash() {
        return Err(RealDomError::InvalidEvidence);
    }

    let participant_ids: Vec<[u8; 32]> = bindings
        .roster()
        .entries()
        .iter()
        .map(|entry| *entry.participant_id())
        .collect();

    let mut proofs = Vec::with_capacity(facts.share_proof_payloads().len());
    for payload in facts.share_proof_payloads() {
        let reveal = EarlyShareRevealV1::from_bytes_against_frozen_context(
            payload,
            // The authenticated chain, not the retained one. The equality
            // above makes the two identical today, so this is inert — and it
            // is written this way so that it stays correct if that guard ever
            // moves, weakens, or is bypassed by a new path into this function.
            trusted_chain_id.as_bytes(),
            &participant_ids,
            facts.early_share_context_commitment(),
        )
        .map_err(LegError::from)?;
        proofs.push((reveal.statement().clone(), reveal.proof().clone()));
    }
    // Every roster entry, none skipped. The signer's route skips the local
    // participant because a signer does not prove knowledge to itself; here
    // there is no local participant, so there is nothing to except.
    let aggregate = AggregateSigningKey::from_verified_share_proofs_v1(&bindings, &proofs)?;

    let mut reveals = Vec::with_capacity(facts.nonce_reveal_payloads().len());
    for payload in facts.nonce_reveal_payloads() {
        reveals.push(NonceRevealV1::from_bytes(payload).map_err(LegError::from)?);
    }
    let round = BoundRound::bind(&bindings, &aggregate, &reveals)?;
    Ok(DomLegSession::new(bindings, round))
}

/// Public-only claim verifier bound to one DOM adaptor session and pre-signature.
pub struct RealDomClaimVerifierV1 {
    session: DomLegSession,
    pre_signature: PreSignatureBytes,
    contract: RealDomContractV1,
}

impl core::fmt::Debug for RealDomClaimVerifierV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RealDomClaimVerifierV1")
            .field("claim_template_hash", &self.contract.claim_template_hash)
            .finish_non_exhaustive()
    }
}

impl RealDomClaimVerifierV1 {
    /// Freezes the already verified public round and exact pre-signature bytes.
    pub fn new(
        session: DomLegSession,
        pre_signature: PreSignatureBytes,
        contract: RealDomContractV1,
    ) -> Result<Self, RealDomError> {
        contract.validate()?;
        // The contract's registry chain identifier and the session's trusted
        // chain identifier are two independent facts that must name one chain.
        // Freezing the check here closes it once for every consumer of this
        // verifier — `verify_and_extract`, `observe_exact_claim` and the chain
        // source — instead of leaving each of them to remember it.
        if pre_signature.claim_template_hash() != contract.claim_template_hash
            || session.bindings().chain_id().as_bytes() != &contract.chain_id.0
        {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(Self {
            session,
            pre_signature,
            contract,
        })
    }

    /// Rebuilds the verifier from the Contracts Store's retained facts.
    ///
    /// This is the middle link. The Store conducts the signing round and keeps
    /// every byte of it, but it cannot hand over a leg session: `dom-leg`
    /// publishes that type in two shapes behind a feature and is the only crate
    /// authorized to depend on `dom-adaptor`, so the Store hands over facts and
    /// this crate — which already depends on both — does the assembly.
    ///
    /// It takes **no signing share**, and that is the point rather than an
    /// omission. Verifying a claim is a public computation: the only thing this
    /// path needed a participant for was the aggregate signing key, and
    /// `AggregateSigningKey::from_verified_share_proofs_v1` produces it from the
    /// retained share proofs alone. So the vault's secret never has to reach
    /// this crate, and every argument below is public protocol data — two
    /// retained facts values, the authenticated chain identity, and the exact
    /// bytes of the retained pre-signature.
    ///
    /// Three re-derivations are checked on the way through, and they are the
    /// three the Store's own documentation says a consumer must make rather
    /// than assume: the session identity, through the transcript tie-back
    /// inside [`SessionBindings::open_with_caller_supplied_identity_v1`]; the
    /// claim template hash, recomputed here from the retained canonical bytes,
    /// which validates **this** decode and not the Store's own crossing of the
    /// two; and the retained pre-signature, which is put through
    /// [`DomLegSession::pre_signature_from_wire`] before the verifier is minted
    /// so that template, reveal transcript and adaptor point are crossed
    /// against the reassembled session at once instead of at the first
    /// observation.
    ///
    /// Two things are deliberately **not** rechecked, both because the Store's
    /// documentation establishes them and repeating them would be a second copy
    /// of a rule with one owner: the retained `refund_tx_hash`, which the gate
    /// codec refuses to decode without, and the early-share context
    /// commitment, which the early transport authority record recomputes on
    /// decode.
    ///
    /// **What none of this establishes, and this is the layer that has to say
    /// it.** Every check above is a check of the facts *against each other*.
    /// Not one of them asks where the facts came from, and not one of them
    /// could: the transcript tie-back inside
    /// [`SessionBindings::open_with_caller_supplied_identity_v1`] documents
    /// that it proves the supplied session identity is the one the supplied
    /// initial transcript commits to and **nothing about the provenance of
    /// either**, and it names the caller — this function — as the party that
    /// answers for provenance. So it is answered here, concretely: the two
    /// facts values must be the ones
    /// `ContractsSessionStoreV1::retained_claim_round_facts_v2` and
    /// `ContractsSessionStoreV1::real_dom_contract_facts_v2` returned, for the
    /// same session, out of the durable authenticated record. **A session
    /// assembled from facts obtained anywhere else establishes nothing**, no
    /// matter that all three constructors return `Ok` — a caller holding
    /// public protocol data can produce a set of facts that is internally
    /// consistent at every one of these gates, because internal consistency is
    /// all they test.
    ///
    /// A concrete consequence, so this is not read as ceremony: a verifier
    /// built from facts a peer supplied will happily prove that some claim
    /// opens some adaptor point. It will not be **this** session's claim, and
    /// nothing between here and the extraction boundary will notice, because
    /// every later check is against this same session.
    pub fn from_retained_facts_v2(
        round: &RetainedClaimRoundFactsV2,
        contract: &RealDomContractFactsV2,
        trusted_chain_id: &TrustedChainIdV1,
        pre_signature_bytes: &[u8],
    ) -> Result<Self, RealDomError> {
        let session = dom_leg_session_from_retained_round_v2(round, trusted_chain_id)?;
        // The wire form is built here, from the exact bytes the Store retained,
        // so no `dom-leg` type appears in this signature and the caller needs no
        // edge to that crate.
        let pre_signature = PreSignatureBytes::from_slice(pre_signature_bytes)?;
        // Crosses template, reveal transcript and adaptor point against the
        // session in one call. The value is dropped: what is wanted is the
        // refusal, and `Self::new` takes the wire bytes.
        let _ = session.pre_signature_from_wire(&pre_signature)?;
        Self::new(
            session,
            pre_signature,
            real_dom_contract_from_facts_v2(contract),
        )
    }

    /// Verifies the claim template and final signature and returns `t` only
    /// after the DOM authority proves `t*G == T`.
    pub fn verify_and_extract(
        &self,
        transaction: &CanonicalTransactionEvidenceV1,
    ) -> Result<RevealedSecretBytes, RealDomError> {
        if !transaction.spends_commitment(&self.contract.shared_output_commitment)
            || transaction.template_hash()? != self.contract.claim_template_hash
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let index = usize::try_from(self.contract.claim_kernel_index)
            .map_err(|_| RealDomError::BoundsExceeded)?;
        let signature = transaction.kernel_signature(index)?;
        self.session
            .extract_revealed_secret(&self.pre_signature, signature)
            .map_err(Into::into)
    }
}

/// One canonical claim together with the tip its block was proved to be an
/// ancestor of.
///
/// This type is the observation boundary's `Evidence`, and it exists to make
/// the ancestry proof unskippable rather than merely recommended. Its fields
/// are private and its constructor is private, so the only value of it that can
/// ever exist in this process is one that
/// [`RealDomRpcRuntimeV1::transaction_with_proved_tip`] produced from a walk
/// that terminated at the reported tip. No caller — in this crate or any other
/// — can assemble a claim location and a tip that came from two different chain
/// reads and present the pair as an observation, because there is no expression
/// that builds this value from parts.
///
/// The alternative shape, passing the tip as two more arguments beside the
/// transaction, was rejected for exactly that reason: it would type-check for a
/// caller that fetched the tip from anywhere at all.
pub struct ProvedClaimObservationEvidenceV1 {
    transaction: CanonicalTransactionEvidenceV1,
    tip_height: u64,
    tip_id: [u8; 32],
}

impl ProvedClaimObservationEvidenceV1 {
    /// Seals the result of one ancestry-proving walk.
    ///
    /// Private on purpose: see the type documentation. The only production
    /// caller is [`RealDomClaimConsumerV1::observe`], which passes the tip the
    /// walk it just ran terminated at, and never a tip from anywhere else.
    fn sealed(
        transaction: CanonicalTransactionEvidenceV1,
        tip_height: u64,
        tip_id: [u8; 32],
    ) -> Self {
        Self {
            transaction,
            tip_height,
            tip_id,
        }
    }

    /// Canonical transaction the walk authenticated.
    #[must_use]
    pub const fn transaction(&self) -> &CanonicalTransactionEvidenceV1 {
        &self.transaction
    }

    /// Height of the tip the observed block was proved to descend to.
    #[must_use]
    pub const fn tip_height(&self) -> u64 {
        self.tip_height
    }

    /// Identity of that same tip.
    #[must_use]
    pub const fn tip_id(&self) -> &[u8; 32] {
        &self.tip_id
    }
}

impl ExactDomClaimObservationSourceV1 for RealDomClaimVerifierV1 {
    type Error = RealDomError;
    type Evidence = ProvedClaimObservationEvidenceV1;

    /// Verifies one observed canonical claim without ever exporting `t`.
    ///
    /// This is deliberately the same cross-check set as
    /// [`RealDomClaimVerifierV1::verify_and_extract`], with three differences
    /// that matter for a receiver's durable exposure marker:
    ///
    /// * the canonical transaction identity is **recomputed from the observed
    ///   bytes** and required to equal the identity the scanner reported, so a
    ///   scanner that mislabels a transaction cannot drive an exposure marker;
    /// * the adaptor opening terminates in the unit-returning authority path, so
    ///   the revealed scalar is proved and then dropped. Extraction of `t`
    ///   remains exclusively in [`RealDomClaimConsumerV1::consume`], which may
    ///   only run after the durable marker exists;
    /// * the evidence is a [`ProvedClaimObservationEvidenceV1`], not a bare
    ///   canonical transaction, so the observed location and the tip it was
    ///   proved to descend to travel together into the sealed facts. The
    ///   exposure marker downstream measures burial against that exact pair,
    ///   and never against a tip it had to go and find for itself.
    fn observe_exact_claim(
        &self,
        evidence: &ProvedClaimObservationEvidenceV1,
        tag: DomClaimObservationTagV1,
    ) -> Result<VerifiedDomClaimObservationV1, RealDomError> {
        let observed = evidence.transaction();
        let recomputed = canonical_transaction_hash_v1(observed.canonical_bytes())?;
        if recomputed != observed.tx_hash()
            || !observed.spends_commitment(&self.contract.shared_output_commitment)
            || observed.template_hash()? != self.contract.claim_template_hash
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let index = usize::try_from(self.contract.claim_kernel_index)
            .map_err(|_| RealDomError::BoundsExceeded)?;
        let signature = SchnorrSignature::from_bytes(observed.kernel_signature(index)?)
            .map_err(|_| RealDomError::InvalidEvidence)?;
        let pre = self.session.pre_signature_from_wire(&self.pre_signature)?;
        let bindings = self.session.bindings();
        // Every identity below is the locally derived one, never the one the
        // scanner reported: `recomputed` comes from the observed bytes and the
        // template/output come from the frozen contract.
        let binding = ObservedClaimBindingV1 {
            tx_hash: recomputed,
            shared_output_commitment: self.contract.shared_output_commitment,
            kernel_index: self.contract.claim_kernel_index,
        };
        let proof = pre
            .prove_observed_claim_opens_adaptor_point_v1(
                &signature,
                &FinalSignatureOpeningContextV1 {
                    expected_claim_template_hash: bindings.template_hash(),
                    expected_transcript_hash: bindings.transcript_hash(),
                    signing_key: self.session.round().aggregate_signing_key().public_key(),
                    chain_id: bindings.chain_id().as_bytes(),
                    kernel_message: bindings.kernel_message_digest(),
                },
                binding,
            )
            .map_err(LegError::from)?;
        Ok(VerifiedDomClaimObservationV1::from_verified_opening_v1(
            proof,
            tag,
            ObservedClaimFactsV1 {
                chain_id: *bindings.chain_id().as_bytes(),
                session_id: *bindings.session_id(),
                tx_hash: recomputed,
                template_hash: self.contract.claim_template_hash,
                shared_output_commitment: self.contract.shared_output_commitment,
                location: ObservedClaimLocationV1 {
                    block_height: observed.location().block_height(),
                    block_hash: observed.location().block_hash(),
                    transaction_index: observed.location().transaction_index(),
                },
                // The location and the tip are one fact here because one walk
                // produced both. This is the obligation the observation source
                // trait states and the only place in the process that can meet
                // it: nothing downstream ever holds the chain.
                observed_tip_height: evidence.tip_height(),
                observed_tip_id: *evidence.tip_id(),
            },
        )?)
    }
}

/// Real DOM source for exactly one settlement.
pub struct RealDomChainSourceV1 {
    runtime: Arc<RealDomRpcRuntimeV1>,
    contract: RealDomContractV1,
    claim_verifier: Arc<RealDomClaimVerifierV1>,
}

impl core::fmt::Debug for RealDomChainSourceV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RealDomChainSourceV1")
            .field("chain_id", &self.contract.chain_id)
            .finish_non_exhaustive()
    }
}

impl RealDomChainSourceV1 {
    /// Binds a source to one runtime and one immutable contract.
    pub fn new(
        runtime: Arc<RealDomRpcRuntimeV1>,
        contract: RealDomContractV1,
        claim_verifier: Arc<RealDomClaimVerifierV1>,
    ) -> Result<Self, RealDomError> {
        contract.validate()?;
        if claim_verifier.contract != contract {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(Self {
            runtime,
            contract,
            claim_verifier,
        })
    }

    fn records_for_blocks(
        &self,
        blocks: &[CanonicalBlockEvidenceV1],
    ) -> Result<Vec<ChainRecordV1>, RealDomError> {
        let mut records = Vec::new();
        for block in blocks {
            for transaction in &block.transactions {
                let evidence = EvidenceRefV1 {
                    chain_id: self.contract.chain_id,
                    tx_id: transaction.tx_hash(),
                    event_index: transaction.location().transaction_index(),
                    block_height: block.height,
                    block_anchor: block.block_hash,
                };
                if transaction.tx_hash() == self.contract.funding_tx_hash {
                    if !transaction.creates_commitment(&self.contract.shared_output_commitment) {
                        return Err(RealDomError::InvalidEvidence);
                    }
                    records.push(ChainRecordV1::Funding { evidence });
                    continue;
                }
                if !transaction.spends_commitment(&self.contract.shared_output_commitment) {
                    continue;
                }
                if transaction.tx_hash() == self.contract.refund_tx_hash {
                    records.push(ChainRecordV1::Refund { evidence });
                } else if transaction.template_hash()? == self.contract.claim_template_hash {
                    let _public_after_claim =
                        self.claim_verifier.verify_and_extract(transaction)?;
                    records.push(ChainRecordV1::Claim { evidence });
                } else {
                    return Err(RealDomError::InvalidEvidence);
                }
            }
        }
        Ok(records)
    }
}

impl ChainSourceV1 for RealDomChainSourceV1 {
    fn chain_id(&self) -> ChainId {
        self.contract.chain_id
    }

    fn genesis_cursor(&self) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        CursorStateV1::genesis()
            .into_core()
            .map_err(map_source_error)
    }

    fn cursor_at(&self, height: u64) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        self.runtime
            .cursor_at(height)
            .and_then(CursorStateV1::into_core)
            .map_err(map_source_error)
    }

    fn scan(
        &self,
        from: &ChainCursorV1,
    ) -> Result<(Vec<ChainRecordV1>, ChainCursorV1), ChainSourceErrorV1> {
        let mut state = CursorStateV1::from_core(from).map_err(map_source_error)?;
        match self
            .runtime
            .scan_state(&state, MAX_SCRIPTLESS_SCAN_BLOCKS_V1)
        {
            Ok((blocks, next, _)) => {
                let records = self.records_for_blocks(&blocks).map_err(map_source_error)?;
                let cursor = next.into_core().map_err(map_source_error)?;
                Ok((records, cursor))
            }
            Err(RealDomError::Chain(ChainAdapterError::ReorgDetected)) => {
                let (from_height, old_anchor) = state
                    .history
                    .last()
                    .copied()
                    .ok_or(ChainSourceErrorV1::StaleCursor)?;
                if state.history.len() == 1 && from_height > 0 {
                    state = self
                        .runtime
                        .cursor_at(from_height - 1)
                        .map_err(map_source_error)?;
                } else {
                    let removed = state.rewind_one().map_err(map_source_error)?;
                    if removed != (from_height, old_anchor) {
                        return Err(ChainSourceErrorV1::InvalidEvidence);
                    }
                }
                let cursor = state.into_core().map_err(map_source_error)?;
                Ok((
                    vec![ChainRecordV1::Reorg {
                        from_height,
                        old_anchor,
                    }],
                    cursor,
                ))
            }
            Err(error) => Err(map_source_error(error)),
        }
    }

    fn tip_height(&self) -> Result<u64, ChainSourceErrorV1> {
        self.runtime
            .scan_state(&CursorStateV1::genesis(), 1)
            .map(|(_, _, identity)| identity.tip_height)
            .map_err(map_source_error)
    }
}

/// Restart-safe consumer of a confirmed DOM claim reference.
pub struct RealDomClaimConsumerV1 {
    runtime: Arc<RealDomRpcRuntimeV1>,
    verifier: Arc<RealDomClaimVerifierV1>,
}

/// Optional consumer of the scalar already verified and extracted by the
/// canonical real-DOM claim path. The scalar is borrowed only for this call;
/// implementations must not place it in Kaystra state or outbox payloads.
pub trait RevealedSecretSinkV1: Send {
    /// Consume a verified public-after-claim scalar for an additive route leg.
    fn consume_revealed_secret(
        &mut self,
        effect: &ClaimedEffectV1,
        evidence: &EvidenceRefV1,
        revealed: &RevealedSecretBytes,
    ) -> EffectOutcome;
}

/// Narrow adapter used by the Contracts Store's linear funding/refund
/// capabilities. Exact bytes are borrowed only for the duration of the
/// authenticated DOM RPC call and are never retained by this adapter.
pub struct RealDomExactBroadcasterV1<'a> {
    adapter: &'a DomHttpChainAdapterV1,
}

impl<'a> RealDomExactBroadcasterV1<'a> {
    /// Binds one exact-byte broadcaster to the frozen real-DOM client.
    pub const fn new(adapter: &'a DomHttpChainAdapterV1) -> Self {
        Self { adapter }
    }
}

impl ExactDomFundingBroadcasterV1 for RealDomExactBroadcasterV1<'_> {
    type Error = ChainAdapterError;
    type Receipt = SubmissionReceiptV1;

    fn broadcast_exact_funding(
        &mut self,
        exact_bytes: &[u8],
    ) -> Result<Self::Receipt, Self::Error> {
        self.adapter.submit_canonical_transaction(exact_bytes)
    }
}

impl ExactDomRefundBroadcasterV1 for RealDomExactBroadcasterV1<'_> {
    type Error = ChainAdapterError;
    type Receipt = SubmissionReceiptV1;

    fn broadcast_exact_refund(&mut self, exact_bytes: &[u8]) -> Result<Self::Receipt, Self::Error> {
        self.adapter.submit_canonical_transaction(exact_bytes)
    }
}

impl ExactDomClaimBroadcasterV1 for RealDomExactBroadcasterV1<'_> {
    type Error = ChainAdapterError;
    type Receipt = SubmissionReceiptV1;

    fn broadcast_exact_claim(&mut self, exact_bytes: &[u8]) -> Result<Self::Receipt, Self::Error> {
        self.adapter.submit_canonical_transaction(exact_bytes)
    }
}

/// Real-DOM effect sink with byte-identical funding/refund retransmission and
/// canonical claim-evidence consumption.
pub struct RealDomEffectSinkV1 {
    adapter: DomHttpChainAdapterV1,
    session_store: ContractsSessionStoreV1,
    initial_funding: Option<FundingBroadcastV1>,
    settlement_id: SettlementId,
    session_id: [u8; 32],
    claim_consumer: RealDomClaimConsumerV1,
    consumed_claims: Vec<EvidenceRefV1>,
    revealed_secret_sink: Option<Box<dyn RevealedSecretSinkV1>>,
}

impl core::fmt::Debug for RealDomEffectSinkV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RealDomEffectSinkV1")
            .field("settlement_id", &self.settlement_id)
            .field("consumed_claims", &self.consumed_claims.len())
            .field(
                "has_revealed_secret_sink",
                &self.revealed_secret_sink.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl RealDomEffectSinkV1 {
    /// Composes a newly finalized funding capability with its durable Store.
    /// No transaction byte vector is accepted at this boundary.
    pub fn new(
        adapter: DomHttpChainAdapterV1,
        session_store: ContractsSessionStoreV1,
        initial_funding: FundingBroadcastV1,
        settlement_id: SettlementId,
        session_id: [u8; 32],
        claim_consumer: RealDomClaimConsumerV1,
    ) -> Result<Self, RealDomError> {
        if settlement_id.0 == [0; 32] || session_id == [0; 32] {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(Self {
            adapter,
            session_store,
            initial_funding: Some(initial_funding),
            settlement_id,
            session_id,
            claim_consumer,
            consumed_claims: Vec::new(),
            revealed_secret_sink: None,
        })
    }

    /// Reopens the real outbox after a process restart. Funding authority is
    /// recovered only from the Store's durable consumed state.
    pub fn resume(
        adapter: DomHttpChainAdapterV1,
        session_store: ContractsSessionStoreV1,
        settlement_id: SettlementId,
        session_id: [u8; 32],
        claim_consumer: RealDomClaimConsumerV1,
    ) -> Result<Self, RealDomError> {
        if settlement_id.0 == [0; 32] || session_id == [0; 32] {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(Self {
            adapter,
            session_store,
            initial_funding: None,
            settlement_id,
            session_id,
            claim_consumer,
            consumed_claims: Vec::new(),
            revealed_secret_sink: None,
        })
    }

    /// Installs an additive consumer for an already-verified revealed scalar.
    /// Existing DOM-only callers remain unchanged when no sink is installed.
    #[must_use]
    pub fn with_revealed_secret_sink(mut self, sink: Box<dyn RevealedSecretSinkV1>) -> Self {
        self.revealed_secret_sink = Some(sink);
        self
    }

    /// Public evidence references whose claim scalar was verified/consumed.
    pub fn consumed_claims(&self) -> &[EvidenceRefV1] {
        &self.consumed_claims
    }

    fn submit_funding(&mut self) -> EffectOutcome {
        let mut broadcaster = RealDomExactBroadcasterV1::new(&self.adapter);
        if let Some(initial) = self.initial_funding.take() {
            return match initial.dispatch_with(&mut broadcaster) {
                Ok(receipt) => submission_outcome(receipt),
                Err(error) => submission_error_outcome(error),
            };
        }
        match self.session_store.resend_funding_broadcast(self.session_id) {
            Ok(retransmission) => match retransmission.dispatch_with(&mut broadcaster) {
                Ok(receipt) => submission_outcome(receipt),
                Err(error) => submission_error_outcome(error),
            },
            Err(error) => store_error_outcome(error),
        }
    }

    fn submit_refund(&mut self) -> EffectOutcome {
        let page = match self.adapter.scan_page(ScriptlessScanCursorV1::genesis(), 1) {
            Ok(page) => page,
            Err(error) => return submission_error_outcome(error),
        };
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return EffectOutcome::Rejected,
        };
        let context = DomTransactionValidationContextV1::new(
            page.identity.tip_height,
            self.adapter.expected_identity().chain_id,
            now,
        );
        let refund = match self
            .session_store
            .load_refund_broadcast(self.session_id, context)
        {
            Ok(refund) => refund,
            Err(error) => return store_error_outcome(error),
        };
        let mut broadcaster = RealDomExactBroadcasterV1::new(&self.adapter);
        match refund.dispatch_with(&mut broadcaster) {
            Ok(receipt) => submission_outcome(receipt),
            Err(error) => submission_error_outcome(error),
        }
    }
}

fn submission_error_outcome(error: ChainAdapterError) -> EffectOutcome {
    if error == ChainAdapterError::TemporarilyUnavailable {
        EffectOutcome::RetryLater
    } else {
        EffectOutcome::Rejected
    }
}

fn store_error_outcome(error: SessionStoreError) -> EffectOutcome {
    if matches!(
        error,
        SessionStoreError::Filesystem | SessionStoreError::StoreBusy
    ) {
        EffectOutcome::RetryLater
    } else {
        EffectOutcome::Rejected
    }
}

fn submission_outcome(receipt: SubmissionReceiptV1) -> EffectOutcome {
    submission_facts_outcome(receipt.state(), receipt.was_relayed())
}

fn submission_facts_outcome(state: SubmissionStateV1, relayed: bool) -> EffectOutcome {
    if state == SubmissionStateV1::Confirmed || relayed {
        EffectOutcome::Completed
    } else {
        // A newly accepted/already-mempool transaction with no relay peer is
        // volatile. Keep the durable outbox pending until it reaches a peer
        // or becomes canonical.
        EffectOutcome::RetryLater
    }
}

impl EffectSinkV1 for RealDomEffectSinkV1 {
    fn execute(&mut self, effect: &ClaimedEffectV1) -> EffectOutcome {
        if effect.settlement_id != self.settlement_id {
            return EffectOutcome::Rejected;
        }
        match &effect.kind {
            Effect::AuthorizeFunding => self.submit_funding(),
            Effect::ArmRefundPath => self.submit_refund(),
            Effect::RequestClaimConsumption { evidence } => {
                match self.claim_consumer.consume(evidence) {
                    Ok(revealed) => {
                        if let Some(sink) = self.revealed_secret_sink.as_mut() {
                            let outcome = sink.consume_revealed_secret(effect, evidence, &revealed);
                            if !matches!(outcome, EffectOutcome::Completed) {
                                return outcome;
                            }
                        }
                        if !self.consumed_claims.contains(evidence) {
                            self.consumed_claims.push(*evidence);
                        }
                        EffectOutcome::Completed
                    }
                    Err(RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable))
                    | Err(RealDomError::LockPoisoned) => EffectOutcome::RetryLater,
                    Err(_) => EffectOutcome::Rejected,
                }
            }
            Effect::RecordTerminalOutcome(_) => EffectOutcome::Completed,
            // Revalidation is an engine/scanner responsibility and must not
            // be represented as a successful external side effect.
            Effect::RevalidateFrom { .. } => EffectOutcome::Rejected,
        }
    }
}

impl core::fmt::Debug for RealDomClaimConsumerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RealDomClaimConsumerV1")
            .finish_non_exhaustive()
    }
}

impl RealDomClaimConsumerV1 {
    /// Shares the real scanner and public claim verifier with the source.
    pub fn new(runtime: Arc<RealDomRpcRuntimeV1>, verifier: Arc<RealDomClaimVerifierV1>) -> Self {
        Self { runtime, verifier }
    }

    /// Refetches the exact canonical transaction by public chain reference and
    /// proves the adaptor opening **without** exporting the scalar.
    ///
    /// This is the sibling of [`Self::consume`]: same chain-identity gate, and
    /// the same ancestry-proving walk over the canonical chain. It diverges in
    /// two places, not one. At the end, `observe` terminates in the
    /// unit-returning observation boundary and yields a linear capability while
    /// `consume` terminates in the extraction that returns `t`; and at the
    /// refetch, `observe` keeps the tip the walk proved while `consume` lets it
    /// go. The doc on this method used to claim the prologue was shared
    /// *verbatim*, which stopped being true the moment the tip had to survive
    /// the refetch — and the assertion that enforced the claim is now written
    /// against the divergence instead.
    ///
    /// The split is the whole ordering guarantee for a receiving leg: `observe`
    /// is what mints the durable irreversible exposure marker in the DOM
    /// Contracts store, and `consume` may only run afterwards. Nothing here
    /// enforces that by itself; the token minted by that store does, at the call
    /// sites that hold it.
    ///
    /// One asymmetry with `consume`, and it is the point of this method: the
    /// refetch here keeps the tip the ancestry walk terminated at, and seals it
    /// with the transaction. `consume` runs the same walk and drops the tip
    /// because it has nothing to carry it to, whereas the marker this mints is
    /// irreversible and its burial depth is judged downstream — so the pair the
    /// depth is judged on has to come from here, proved, rather than be
    /// assembled later from two unrelated chain reads.
    pub fn observe(
        &self,
        evidence: &EvidenceRefV1,
    ) -> Result<VerifiedDomClaimObservationV1, RealDomError> {
        if evidence.chain_id != self.verifier.contract.chain_id {
            return Err(RealDomError::InvalidEvidence);
        }
        let (transaction, identity) = self.runtime.transaction_with_proved_tip(evidence)?;
        self.verifier.observe_exact_claim(
            &ProvedClaimObservationEvidenceV1::sealed(
                transaction,
                identity.tip_height,
                identity.tip_hash,
            ),
            DomClaimObservationTagV1::CounterpartyClaimObserved,
        )
    }

    /// Refetches the exact canonical transaction by public chain reference and
    /// extracts the now-public scalar through `dom-leg`.
    pub fn consume(&self, evidence: &EvidenceRefV1) -> Result<RevealedSecretBytes, RealDomError> {
        if evidence.chain_id != self.verifier.contract.chain_id {
            return Err(RealDomError::InvalidEvidence);
        }
        let transaction = self.runtime.transaction(evidence)?;
        self.verifier.verify_and_extract(&transaction)
    }
}

fn map_source_error(error: RealDomError) -> ChainSourceErrorV1 {
    match error {
        RealDomError::Chain(ChainAdapterError::ReorgDetected) => ChainSourceErrorV1::StaleCursor,
        RealDomError::Chain(ChainAdapterError::TemporarilyUnavailable)
        | RealDomError::Store(SessionStoreError::Filesystem | SessionStoreError::StoreBusy)
        | RealDomError::LockPoisoned => ChainSourceErrorV1::Unavailable,
        RealDomError::Chain(ChainAdapterError::IdentityMismatch) => {
            ChainSourceErrorV1::IdentityMismatch
        }
        RealDomError::Chain(ChainAdapterError::BoundsExceeded) | RealDomError::BoundsExceeded => {
            ChainSourceErrorV1::BoundsExceeded
        }
        // A `ClaimObservationError` is a semantic contradiction between the
        // observed facts and the proved adaptor opening. Retrying cannot repair
        // it, so it shares the definitive `InvalidEvidence` outcome rather than
        // the `Unavailable` one.
        RealDomError::Chain(_)
        | RealDomError::Store(_)
        | RealDomError::Leg(_)
        | RealDomError::Observation(_)
        | RealDomError::InvalidEvidence
        | RealDomError::EvidenceNotFound
        | RealDomError::FinalityPolicyInvalid
        | RealDomError::InsufficientConfirmations
        | RealDomError::TransactionStillCanonical
        | RealDomError::ReorgBeyondPolicy => ChainSourceErrorV1::InvalidEvidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the executable source text of one `fn`/`impl` body by its
    /// header, with every comment line removed.
    ///
    /// Comments are stripped deliberately: these assertions are about what the
    /// code *reaches*, and a doc comment that names a forbidden symbol in order
    /// to contrast with it must not be mistaken for a call to it.
    fn source_block(header: &str, terminator: &str) -> String {
        let source = include_str!("lib.rs");
        // `clippy::panic`, `unwrap_used` and `expect_used` are denied for this
        // crate, tests included, so an absent anchor returns an empty block and
        // the caller asserts on it instead.
        let Some(start) = source.find(header) else {
            return String::new();
        };
        let Some(offset) = source[start..].find(terminator) else {
            return String::new();
        };
        let end = start + offset;
        source[start..end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn evidence_scope_accepts_only_closed_resolve_or_exact_anchor_shape() {
        let chain_id = [0x41; 32];
        let resolve = EvidenceRefV1 {
            chain_id: ChainId(chain_id),
            tx_id: [0x42; 32],
            event_index: 0,
            block_height: 0,
            block_anchor: [0; 32],
        };
        assert!(matches!(
            validate_evidence_scope_v1(chain_id, &resolve),
            Ok(true)
        ));

        let anchored = EvidenceRefV1 {
            event_index: 3,
            block_height: 7,
            block_anchor: [0x43; 32],
            ..resolve
        };
        assert!(matches!(
            validate_evidence_scope_v1(chain_id, &anchored),
            Ok(false)
        ));

        for invalid in [
            EvidenceRefV1 {
                chain_id: ChainId([0x44; 32]),
                ..resolve
            },
            EvidenceRefV1 {
                event_index: 1,
                ..resolve
            },
            EvidenceRefV1 {
                block_height: 1,
                ..resolve
            },
            EvidenceRefV1 {
                block_anchor: [0x45; 32],
                ..resolve
            },
        ] {
            assert!(matches!(
                validate_evidence_scope_v1(chain_id, &invalid),
                Err(RealDomError::InvalidEvidence)
            ));
        }
    }

    #[test]
    fn claim_observation_never_reaches_the_extraction_path() {
        // The observation boundary exists so a receiver can mint a durable
        // exposure marker *before* `t` is extracted. If it ever called the
        // extraction path itself, the ordering guarantee would be vacuous.
        let observation = source_block(
            "impl ExactDomClaimObservationSourceV1 for RealDomClaimVerifierV1 {",
            "\n/// Real DOM source for exactly one settlement.",
        );
        assert!(!observation.is_empty(), "observation boundary not found");
        for forbidden in [
            "verify_and_extract",
            "extract_revealed_secret",
            "RevealedSecretBytes",
            "AdaptorSecret",
        ] {
            assert!(
                !observation.contains(forbidden),
                "the observation boundary must not reach {forbidden}"
            );
        }
        assert!(observation.contains("prove_observed_claim_opens_adaptor_point_v1"));
        assert!(observation.contains("canonical_transaction_hash_v1"));
    }

    #[test]
    fn observe_and_consume_share_the_same_prologue() {
        // Both must gate on the frozen chain identity and refetch through the
        // anchored scanner before diverging. They no longer share the refetch
        // *expression*, and that is the correction, not a regression: only
        // `observe` keeps the tip the walk proved, because only `observe` mints
        // a capability whose burial depth is judged later. `consume` runs the
        // same walk through `transaction`, which discards the tip it has
        // nowhere to put.
        let observe = source_block(
            "    pub fn observe(",
            "    /// Refetches the exact canonical",
        );
        let consume = source_block("    pub fn consume(", "\n}\n\nfn map_source_error");
        assert!(
            !observe.is_empty() && !consume.is_empty(),
            "siblings not found"
        );
        for shared in [
            "if evidence.chain_id != self.verifier.contract.chain_id {",
            "return Err(RealDomError::InvalidEvidence);",
        ] {
            assert!(observe.contains(shared), "observe lost the shared prologue");
            assert!(consume.contains(shared), "consume lost the shared prologue");
        }
        assert!(
            observe.contains("self.runtime.transaction_with_proved_tip(evidence)?"),
            "observe must refetch through the tip-preserving walk"
        );
        assert!(
            observe.contains("ProvedClaimObservationEvidenceV1::sealed"),
            "observe must seal the location and the proved tip together"
        );
        assert!(
            !observe.contains("let transaction = self.runtime.transaction(evidence)?;"),
            "observe must never fall back to the refetch that drops the tip"
        );
        assert!(consume.contains("self.runtime.transaction(evidence)?"));
        assert!(observe.contains("observe_exact_claim"));
        assert!(!observe.contains("extract_revealed_secret"));
        assert!(consume.contains("verify_and_extract"));
        assert!(!consume.contains("observe_exact_claim"));
    }

    /// The refetch must reach the tip, not stop at the block it was asked for.
    ///
    /// This is a source assertion and is labelled as one. The behavioural test
    /// it stands in for — serve a claim on a branch, reorganise the node,
    /// observe, and require the refusal — cannot be written in this crate:
    /// `fixture_runtime` points at `http://127.0.0.1:1` because there is no
    /// node fixture here at all, and every scanner-touching path fails at the
    /// transport before it can reach a rule. What this guard does buy is real:
    /// the regression it exists against is a one-line one, the deletion of the
    /// walk that closes the chain against the reported tip, and that deletion
    /// is exactly what it fails on.
    #[test]
    fn the_canonical_refetch_walks_to_the_reported_tip() {
        let proving = source_block(
            "    pub fn transaction_with_proved_tip(",
            "    /// Reads one cached transaction after discarding",
        );
        assert!(!proving.is_empty(), "the proving refetch was not found");
        assert!(
            proving.contains("self.scan_snapshot_to_tip(state, identity)?"),
            "the refetch must close the hash-linked walk against the reported tip"
        );
        assert!(
            !proving.contains("let _ = self.scan_through("),
            "the refetch must not discard the walk the tip has to come from"
        );
        // And the convenience wrapper must stay a wrapper: if it ever grew a
        // scan of its own, `consume` and the F7 bridge would quietly lose the
        // ancestry proof while `observe` kept it.
        let wrapper = source_block(
            "    pub fn transaction(",
            "    /// Loads exact evidence together with",
        );
        assert!(!wrapper.is_empty(), "the refetch wrapper was not found");
        assert!(
            wrapper.contains("self.transaction_with_proved_tip(evidence)"),
            "the wrapper must delegate to the proving refetch"
        );
        assert!(
            !wrapper.contains("scan_through"),
            "the wrapper must not scan on its own"
        );
    }

    // ---- crypto-real DOM claim fixture -------------------------------------
    //
    // Ported from the public molds `dom-leg/tests/composed_routes.rs:69-222` and
    // `dom-leg/src/round.rs:1455-1478`. Every step is the real pinned round: two
    // identities, share PoK, aggregate signing key, nonce commit/reveal,
    // partials, an adaptor pre-signature bound to `T`, byte-identical wire
    // transport, and adaptation with the real `t`. Nothing here is a stub.
    //
    // `unwrap_used`, `expect_used` and `panic` are denied for this crate, tests
    // included, so the whole fixture propagates with `?` into a boxed error.
    //
    // `RealDomError` does not derive `PartialEq`, so every negative below
    // asserts its variant with `matches!` rather than `assert_eq!`.

    use dom_adaptor::{
        AdaptorSecret, ContractKindV1, DirectionV1, PartialSignatureV1, ParticipantIdentityV1,
        ParticipantRosterV1, PurposeV1, Result as AdaptorResult, SessionIdRegistryV1,
        SigningPhaseV1, SigningShareV1, TrustedChainIdV1,
    };
    use dom_consensus::{Transaction, TransactionInput, TransactionKernel, TransactionOutput};
    use dom_core::Amount;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use dom_crypto::{Hash256, PublicKey, SecretKey};
    use dom_leg::round::build_claim_pre_signature;
    // `DomLegSession` and `PreSignatureBytes` already arrive through `super::*`.
    use dom_leg::{
        BoundRound, LegParticipant, LocalSigningShare, SessionBindings, SessionOpenRequest,
    };
    use dom_scriptless_chain_adapter::{BearerTokenV1, ExpectedDomIdentityV1};
    use dom_serialization::DomSerialize;
    use std::time::Duration;
    use zeroize::Zeroizing;

    type FixtureResult<T> = core::result::Result<T, Box<dyn std::error::Error>>;

    const FIXTURE_NETWORK_MAGIC: u32 = dom_core::NETWORK_MAGIC_REGTEST;
    const FIXTURE_GENESIS: [u8; 32] = dom_core::GENESIS_HASH_REGTEST;

    struct MemoryRegistry(Vec<[u8; 32]>);

    impl SessionIdRegistryV1 for MemoryRegistry {
        fn register_unique_session_id(&mut self, session_id: &[u8; 32]) -> AdaptorResult<bool> {
            if self.0.contains(session_id) {
                return Ok(false);
            }
            self.0.push(*session_id);
            Ok(true)
        }
    }

    fn fixture_chain() -> TrustedChainIdV1 {
        TrustedChainIdV1::from_authenticated_genesis(
            FIXTURE_NETWORK_MAGIC,
            &Hash256::from_bytes(FIXTURE_GENESIS),
        )
    }

    fn fixture_share(byte: u8) -> FixtureResult<LocalSigningShare> {
        Ok(LocalSigningShare::from_be_bytes(Zeroizing::new(
            [byte; 32],
        ))?)
    }

    fn fixture_signing_pub(byte: u8) -> FixtureResult<PublicKey> {
        Ok(SigningShareV1::from_be_bytes([byte; 32])?
            .public_key()
            .clone())
    }

    fn fixture_identity_pub(byte: u8) -> FixtureResult<PublicKey> {
        Ok(SecretKey::from_bytes(&[byte; 32])?.public_key().clone())
    }

    /// A full-width canonical scalar `t`, never a degenerate constant.
    fn fixture_route_scalar() -> [u8; 32] {
        let mut t = [0u8; 32];
        for (index, byte) in t.iter_mut().enumerate() {
            let step = u8::try_from(index % 200).unwrap_or(0);
            *byte = (0x11_u8.wrapping_add(step)) | 0x01;
        }
        t[0] = 0x2b;
        t
    }

    fn fixture_commitment(value: u64, blinding: u8) -> FixtureResult<Commitment> {
        Ok(Commitment::commit(
            value,
            &BlindingFactor::from_bytes([blinding; 32])?,
        ))
    }

    fn fixture_kernel(excess: Commitment, lock_height: u64) -> FixtureResult<TransactionKernel> {
        Ok(TransactionKernel {
            features: dom_core::KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(0)?,
            lock_height,
            excess,
            excess_signature: [0; 65],
        })
    }

    /// The exact unsigned claim template: one input spending the shared output
    /// and one kernel. The observed claim is byte-identical to this plus the
    /// final adaptor signature, so `canonical_template_v1` — which omits
    /// signatures — yields the same hash for both by construction.
    fn fixture_claim_template(shared_output: &Commitment) -> FixtureResult<Transaction> {
        Ok(Transaction {
            inputs: vec![TransactionInput {
                commitment: shared_output.clone(),
            }],
            outputs: Vec::new(),
            kernels: vec![fixture_kernel(fixture_commitment(0, 0x42)?, 0)?],
            offset: [0x33; 32],
        })
    }

    /// Funding: creates the shared output. Its canonical identity is recomputed,
    /// never chosen, so the contract can name it truthfully.
    fn fixture_funding_transaction(shared_output: &Commitment) -> FixtureResult<Transaction> {
        let mut kernel = fixture_kernel(fixture_commitment(0, 0x52)?, 0)?;
        kernel.excess_signature = [0x01; 65];
        Ok(Transaction {
            inputs: vec![TransactionInput {
                commitment: fixture_commitment(1_000, 0x51)?,
            }],
            outputs: vec![TransactionOutput {
                commitment: shared_output.clone(),
                proof: vec![0_u8; dom_crypto::RANGE_PROOF_SIZE],
            }],
            kernels: vec![kernel],
            offset: [0x35; 32],
        })
    }

    /// Refund: spends the shared output with a template that is deliberately not
    /// the claim template, so only its identity can classify it.
    fn fixture_refund_transaction(shared_output: &Commitment) -> FixtureResult<Transaction> {
        let mut kernel = fixture_kernel(fixture_commitment(0, 0x53)?, 42)?;
        kernel.excess_signature = [0x02; 65];
        Ok(Transaction {
            inputs: vec![TransactionInput {
                commitment: shared_output.clone(),
            }],
            outputs: Vec::new(),
            kernels: vec![kernel],
            offset: [0x36; 32],
        })
    }

    fn fixture_tx_hash(tx: &Transaction) -> FixtureResult<[u8; 32]> {
        Ok(canonical_transaction_hash_v1(&tx.to_bytes()?)?)
    }

    /// Fixture evidence built through the one public constructor.
    ///
    /// It no longer assembles the value field by field, because the type no
    /// longer lets anyone do that. The identity is derived from the bytes
    /// here exactly as it is on the scanner path, so a fixture cannot make an
    /// evidence the production path could not have produced — which is the
    /// property the seal exists for, and the reason this helper stopped being
    /// the repository's only forger.
    fn fixture_evidence(tx: &Transaction) -> FixtureResult<CanonicalTransactionEvidenceV1> {
        Ok(CanonicalTransactionEvidenceV1::from_canonical_bytes_at(
            9,
            [0x81; 32],
            1,
            tx.to_bytes()?,
        )?)
    }

    /// Wraps fixture evidence with the tip an ancestry walk would have proved.
    ///
    /// `fixture_evidence` places the claim at height 9, so a tip at 13 is that
    /// same block buried five deep. These tests exercise the verifier, not the
    /// walk: the walk needs a node to serve pages and this crate has no node
    /// fixture, as `fixture_runtime` records in the endpoint it points at.
    fn fixture_proved_observation(
        evidence: CanonicalTransactionEvidenceV1,
    ) -> ProvedClaimObservationEvidenceV1 {
        ProvedClaimObservationEvidenceV1::sealed(evidence, 13, [0x82; 32])
    }

    fn fixture_single_tx_block(
        transactions: Vec<CanonicalTransactionEvidenceV1>,
    ) -> CanonicalBlockEvidenceV1 {
        CanonicalBlockEvidenceV1 {
            height: 9,
            block_hash: [0x81; 32],
            previous_block_hash: [0x80; 32],
            canonical_header_bytes: vec![0x01; 32],
            timestamp: 1_700_000_000,
            transactions,
        }
    }

    /// A real runtime bound to a closed loopback endpoint. Neither constructor
    /// performs a request — `DomHttpChainAdapterV1::new` only validates identity
    /// and URL, `RealDomRpcRuntimeV1::new` only validates the history bound —
    /// and `records_for_blocks` never touches the runtime. No node, no mock.
    fn fixture_runtime(contract: &RealDomContractV1) -> FixtureResult<Arc<RealDomRpcRuntimeV1>> {
        let identity = ExpectedDomIdentityV1 {
            network: "regtest".to_owned(),
            network_magic: FIXTURE_NETWORK_MAGIC,
            chain_id: contract.chain_id.0,
            genesis_hash: FIXTURE_GENESIS,
            // Read from the pinned constants, never written as literals: the
            // identity gate compares against these exact values, so a hardcoded
            // number would silently rot the moment either version moves.
            protocol_version: dom_core::PROTOCOL_VERSION,
            range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        };
        let adapter = DomHttpChainAdapterV1::new(
            "http://127.0.0.1:1",
            identity,
            BearerTokenV1::new("no-request-is-ever-made".to_owned())?,
            Duration::from_millis(50),
            Duration::from_millis(50),
        )?;
        Ok(Arc::new(RealDomRpcRuntimeV1::new(adapter, 16)?))
    }

    struct ClaimFixture {
        session: DomLegSession,
        wire: PreSignatureBytes,
        contract: RealDomContractV1,
        claim_tx: Transaction,
        funding_tx: Transaction,
        refund_tx: Transaction,
        shared_output: Commitment,
        secret: [u8; 32],
    }

    /// `DomLegSession` is deliberately not `Clone`, so each test builds its own
    /// round rather than sharing one. That keeps `dom-leg` untouched.
    fn claim_fixture() -> FixtureResult<ClaimFixture> {
        let chain = fixture_chain();
        let secret = fixture_route_scalar();
        let adaptor_point = AdaptorSecret::from_be_bytes(secret)?.public_point()?;

        let mut entries = vec![
            ParticipantIdentityV1::new(
                &chain,
                fixture_identity_pub(0x21)?,
                fixture_signing_pub(0x31)?,
                DirectionV1::Initiator,
            )?,
            ParticipantIdentityV1::new(
                &chain,
                fixture_identity_pub(0x22)?,
                fixture_signing_pub(0x32)?,
                DirectionV1::Responder,
            )?,
        ];
        entries.sort_by_key(|entry| *entry.participant_id());
        let roster = ParticipantRosterV1::new(entries)?;
        let initiator = *roster
            .entries()
            .first()
            .ok_or(RealDomError::InvalidEvidence)?
            .participant_id();

        let shared_output = fixture_commitment(1_000, 0x41)?;
        let template_tx = fixture_claim_template(&shared_output)?;

        let bindings = SessionBindings::open(
            SessionOpenRequest {
                chain_id: chain,
                contract_kind: ContractKindV1::WitnessOrTimeout,
                roster: roster.clone(),
                initiator_participant_id: initiator,
                purpose: PurposeV1::ClaimAdaptor,
                adaptor_point: Some(adaptor_point),
                template_tx: &template_tx,
                kernel_message_digest: [0x44; 32],
                opening_direction: DirectionV1::Initiator,
                opening_phase: SigningPhaseV1::SigNonceCommit,
                terms_hash: [0x55; 32],
                recovery_binding_hash: [0x66; 32],
            },
            &mut MemoryRegistry(Vec::new()),
        )?;

        let initiator_signing = fixture_signing_pub(0x31)?;
        let mut joined = Vec::new();
        for entry in bindings.roster().entries().to_vec() {
            let local = if entry.signing_public_key() == &initiator_signing {
                fixture_share(0x31)?
            } else {
                fixture_share(0x32)?
            };
            joined.push(LegParticipant::join(&bindings, local, entry)?);
        }
        let second = joined.pop().ok_or(RealDomError::InvalidEvidence)?;
        let first = joined.pop().ok_or(RealDomError::InvalidEvidence)?;

        let proof_a = first.prove_share(&bindings)?;
        let proof_b = second.prove_share(&bindings)?;
        // Both sides must accept the counterparty's share PoK and derive the
        // same aggregate signing key. Accepting on one side only would leave
        // the round half-run and the equality below unproved.
        let aggregate = first.accept_share_proofs(&bindings, &[proof_b])?;
        let mirrored = second.accept_share_proofs(&bindings, &[proof_a])?;
        assert_eq!(aggregate, mirrored, "both sides aggregate the same key");

        let (nonces_a, commit_a) = first.begin_round(&bindings)?;
        let (nonces_b, commit_b) = second.begin_round(&bindings)?;
        let reveal_a = first.reveal(&bindings, &nonces_a);
        let reveal_b = second.reveal(&bindings, &nonces_b);
        bindings.check_reveal_opens_commitment(
            second.identity().participant_id(),
            &commit_b,
            &reveal_b,
        )?;
        bindings.check_reveal_opens_commitment(
            first.identity().participant_id(),
            &commit_a,
            &reveal_a,
        )?;

        let round = BoundRound::bind(&bindings, &aggregate, &[reveal_a, reveal_b])?;
        let partial_a = first.sign_partial(&bindings, &round, nonces_a)?;
        let partial_b = second.sign_partial(&bindings, &round, nonces_b)?;
        let mut partials = vec![partial_a, partial_b];
        partials.sort_by_key(PartialSignatureV1::participant_index);

        let pre = build_claim_pre_signature(&bindings, &round, &partials)?;
        let wire = PreSignatureBytes::from_slice(&pre.to_bytes())?;
        let template_hash = *bindings.template_hash();
        let session = DomLegSession::new(bindings, round);
        let final_signature = session.adapt_claim_from_wire(&wire, &Zeroizing::new(secret))?;

        let mut claim_tx = template_tx;
        let signature: [u8; 65] = final_signature
            .as_slice()
            .try_into()
            .map_err(|_| RealDomError::InvalidEvidence)?;
        if let Some(kernel) = claim_tx.kernels.first_mut() {
            kernel.excess_signature = signature;
        }

        // Funding and refund identities are recomputed from their canonical
        // bytes before the contract names them. A chosen hash would never match
        // `records_for_blocks`, which compares against the real identity.
        let funding_tx = fixture_funding_transaction(&shared_output)?;
        let refund_tx = fixture_refund_transaction(&shared_output)?;
        let contract = RealDomContractV1 {
            chain_id: ChainId(*chain.as_bytes()),
            shared_output_commitment: *shared_output.as_bytes(),
            funding_tx_hash: fixture_tx_hash(&funding_tx)?,
            claim_template_hash: template_hash,
            refund_tx_hash: fixture_tx_hash(&refund_tx)?,
            claim_kernel_index: 0,
        };

        Ok(ClaimFixture {
            session,
            wire,
            contract,
            claim_tx,
            funding_tx,
            refund_tx,
            shared_output,
            secret,
        })
    }

    // ---- Group A: RealDomClaimVerifierV1 -----------------------------------

    #[test]
    fn production_real_claim_verifier_accepts_the_exact_adapted_claim() -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let evidence = fixture_evidence(&fixture.claim_tx)?;
        let verifier =
            RealDomClaimVerifierV1::new(fixture.session, fixture.wire, fixture.contract)?;
        assert_eq!(
            verifier
                .verify_and_extract(&evidence)?
                .expose_scalar_bytes(),
            fixture.secret
        );
        Ok(())
    }

    #[test]
    fn production_real_claim_verifier_rejects_a_divergent_template_hash() -> FixtureResult<()> {
        // The template hash is frozen at construction, so a contract whose
        // template disagrees with the pre-signature cannot even mint a verifier.
        // That is strictly stronger than rejecting it later, per evidence.
        let fixture = claim_fixture()?;
        let mut contract = fixture.contract;
        contract.claim_template_hash = [0x99; 32];
        assert!(matches!(
            RealDomClaimVerifierV1::new(fixture.session, fixture.wire, contract),
            Err(RealDomError::InvalidEvidence)
        ));
        Ok(())
    }

    #[test]
    fn production_real_claim_verifier_rejects_a_foreign_shared_output() -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let mut foreign = fixture.claim_tx.clone();
        if let Some(input) = foreign.inputs.first_mut() {
            input.commitment = fixture_commitment(1_000, 0x43)?;
        }
        let evidence = fixture_evidence(&foreign)?;
        let verifier =
            RealDomClaimVerifierV1::new(fixture.session, fixture.wire, fixture.contract)?;
        assert!(matches!(
            verifier.verify_and_extract(&evidence),
            Err(RealDomError::InvalidEvidence)
        ));
        Ok(())
    }

    #[test]
    fn production_real_claim_verifier_rejects_a_signature_that_does_not_open_the_adaptor_point(
    ) -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let mut tampered = fixture.claim_tx.clone();
        if let Some(kernel) = tampered.kernels.first_mut() {
            kernel.excess_signature[64] ^= 0x01;
        }
        let evidence = fixture_evidence(&tampered)?;
        let verifier =
            RealDomClaimVerifierV1::new(fixture.session, fixture.wire, fixture.contract)?;
        assert!(matches!(
            verifier.verify_and_extract(&evidence),
            Err(RealDomError::Leg(_))
        ));
        Ok(())
    }

    #[test]
    fn production_real_claim_verifier_rejects_an_out_of_range_kernel_index() -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let mut contract = fixture.contract;
        contract.claim_kernel_index = 7;
        let evidence = fixture_evidence(&fixture.claim_tx)?;
        let verifier = RealDomClaimVerifierV1::new(fixture.session, fixture.wire, contract)?;
        assert!(matches!(
            verifier.verify_and_extract(&evidence),
            Err(RealDomError::Chain(ChainAdapterError::InvalidEvidence))
        ));
        Ok(())
    }

    // ---- Group B: ExactDomClaimObservationSourceV1 -------------------------

    #[test]
    fn production_claim_observation_matches_verify_and_extract_on_the_exact_claim(
    ) -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let evidence = fixture_evidence(&fixture.claim_tx)?;
        let contract = fixture.contract;
        let shared_output = fixture.shared_output;
        let secret = fixture.secret;
        let verifier = RealDomClaimVerifierV1::new(fixture.session, fixture.wire, contract)?;
        let observed = verifier.observe_exact_claim(
            &fixture_proved_observation(evidence.clone()),
            DomClaimObservationTagV1::CounterpartyClaimObserved,
        )?;
        assert_eq!(observed.tx_hash(), &evidence.tx_hash());
        assert_eq!(observed.template_hash(), &contract.claim_template_hash);
        assert_eq!(
            observed.shared_output_commitment(),
            shared_output.as_bytes()
        );
        assert_eq!(observed.chain_id(), &contract.chain_id.0);
        assert_eq!(observed.kernel_index(), 0);
        assert_eq!(observed.location().block_height, 9);
        // The tip the refetch proved travels into the capability, so the
        // depth predicate downstream is handed an ancestry-bearing pair
        // instead of having to pair this location with a tip of its own.
        assert_eq!(observed.observed_tip_height(), 13);
        assert_eq!(observed.observed_tip_id(), &[0x82; 32]);
        // The same evidence still reveals `t` through the extraction path, so
        // the observation is not accepting something weaker.
        assert_eq!(
            verifier
                .verify_and_extract(&evidence)?
                .expose_scalar_bytes(),
            secret
        );
        Ok(())
    }

    // `production_claim_observation_rejects_tx_hash_not_recomputed_from_bytes`
    // used to sit here. It set `evidence.tx_hash = [0x9a; 32]` on honest bytes
    // and proved the observation boundary refused the mislabelled identity.
    // `CanonicalTransactionEvidenceV1` now derives the identity from the bytes
    // and exposes no way to set one, so that state is not refuted but
    // unrepresentable, and the test moved to the `compile_fail` doctest on the
    // type itself. A test that cannot construct its own premise has nothing
    // left to assert; the compiler makes the assertion instead.

    #[test]
    fn production_claim_observation_rejects_a_signature_that_does_not_open_the_adaptor_point(
    ) -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let mut tampered = fixture.claim_tx.clone();
        if let Some(kernel) = tampered.kernels.first_mut() {
            kernel.excess_signature[64] ^= 0x01;
        }
        let evidence = fixture_evidence(&tampered)?;
        let verifier =
            RealDomClaimVerifierV1::new(fixture.session, fixture.wire, fixture.contract)?;
        assert!(matches!(
            verifier.observe_exact_claim(
                &fixture_proved_observation(evidence.clone()),
                DomClaimObservationTagV1::CounterpartyClaimObserved
            ),
            Err(RealDomError::Leg(_))
        ));
        Ok(())
    }

    #[test]
    fn production_claim_observation_rejects_a_foreign_shared_output() -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let mut foreign = fixture.claim_tx.clone();
        if let Some(input) = foreign.inputs.first_mut() {
            input.commitment = fixture_commitment(1_000, 0x43)?;
        }
        let evidence = fixture_evidence(&foreign)?;
        let verifier =
            RealDomClaimVerifierV1::new(fixture.session, fixture.wire, fixture.contract)?;
        assert!(matches!(
            verifier.observe_exact_claim(
                &fixture_proved_observation(evidence.clone()),
                DomClaimObservationTagV1::CounterpartyClaimObserved
            ),
            Err(RealDomError::InvalidEvidence)
        ));
        Ok(())
    }

    // ---- Group C: RealDomChainSourceV1 -------------------------------------

    #[test]
    fn production_real_chain_source_classifies_funding_refund_and_claim_records(
    ) -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let contract = fixture.contract;
        let block = fixture_single_tx_block(vec![
            fixture_evidence(&fixture.funding_tx)?,
            fixture_evidence(&fixture.refund_tx)?,
            fixture_evidence(&fixture.claim_tx)?,
        ]);
        let verifier = RealDomClaimVerifierV1::new(fixture.session, fixture.wire, contract)?;
        let source =
            RealDomChainSourceV1::new(fixture_runtime(&contract)?, contract, Arc::new(verifier))?;
        let records = source.records_for_blocks(&[block])?;
        assert_eq!(records.len(), 3);
        assert!(matches!(records[0], ChainRecordV1::Funding { .. }));
        assert!(matches!(records[1], ChainRecordV1::Refund { .. }));
        assert!(matches!(records[2], ChainRecordV1::Claim { .. }));
        Ok(())
    }

    #[test]
    fn production_real_chain_source_rejects_a_foreign_transaction_that_spends_the_shared_output(
    ) -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let contract = fixture.contract;
        // Spends the shared output, but is neither the refund identity nor the
        // claim template: the `else` arm must refuse it.
        let mut foreign = fixture.claim_tx.clone();
        foreign.offset = [0x34; 32];
        let block = fixture_single_tx_block(vec![fixture_evidence(&foreign)?]);
        let verifier = RealDomClaimVerifierV1::new(fixture.session, fixture.wire, contract)?;
        let source =
            RealDomChainSourceV1::new(fixture_runtime(&contract)?, contract, Arc::new(verifier))?;
        assert!(matches!(
            source.records_for_blocks(&[block]),
            Err(RealDomError::InvalidEvidence)
        ));
        Ok(())
    }

    #[test]
    fn production_real_chain_source_rejects_funding_that_does_not_create_the_shared_output(
    ) -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let mut contract = fixture.contract;
        let mut broken = fixture.funding_tx.clone();
        broken.outputs.clear();
        // Still named as the funding transaction, so the funding arm is taken
        // and must then refuse the missing shared output. The naming now moves
        // to the contract rather than to the evidence: an evidence's identity
        // is derived from its own bytes and cannot be told to lie, so the way
        // to make the classifier take the funding arm is to have the frozen
        // contract name the transaction that is really there.
        contract.funding_tx_hash = fixture_tx_hash(&broken)?;
        let block = fixture_single_tx_block(vec![fixture_evidence(&broken)?]);
        let verifier = RealDomClaimVerifierV1::new(fixture.session, fixture.wire, contract)?;
        let source =
            RealDomChainSourceV1::new(fixture_runtime(&contract)?, contract, Arc::new(verifier))?;
        assert!(matches!(
            source.records_for_blocks(&[block]),
            Err(RealDomError::InvalidEvidence)
        ));
        Ok(())
    }

    // ---- Group D: RealDomClaimConsumerV1 -----------------------------------

    #[test]
    fn production_real_claim_consumer_rejects_a_foreign_chain_reference() -> FixtureResult<()> {
        let fixture = claim_fixture()?;
        let contract = fixture.contract;
        let verifier = RealDomClaimVerifierV1::new(fixture.session, fixture.wire, contract)?;
        let consumer = RealDomClaimConsumerV1::new(fixture_runtime(&contract)?, Arc::new(verifier));
        let foreign = EvidenceRefV1 {
            chain_id: ChainId([0xAE; 32]),
            tx_id: [0x13; 32],
            event_index: 0,
            block_height: 9,
            block_anchor: [0x81; 32],
        };
        // Both siblings gate identically and fail before any request, so this
        // negative needs no node endpoint.
        assert!(matches!(
            consumer.consume(&foreign),
            Err(RealDomError::InvalidEvidence)
        ));
        assert!(matches!(
            consumer.observe(&foreign),
            Err(RealDomError::InvalidEvidence)
        ));
        Ok(())
    }

    #[test]
    fn production_verify_and_extract_returns_the_exact_adapted_scalar() -> FixtureResult<()> {
        // Behavioural proof that introducing `observe` did not change what the
        // extraction path returns: the bytes are still exactly the `t` that
        // adapted the signature, and they still open the committed point `T`.
        let fixture = claim_fixture()?;
        let evidence = fixture_evidence(&fixture.claim_tx)?;
        let secret = fixture.secret;
        let verifier =
            RealDomClaimVerifierV1::new(fixture.session, fixture.wire, fixture.contract)?;
        let revealed = verifier.verify_and_extract(&evidence)?;
        assert_eq!(revealed.expose_scalar_bytes(), secret);
        assert_eq!(
            AdaptorSecret::from_be_bytes(revealed.expose_scalar_bytes())?.public_point()?,
            AdaptorSecret::from_be_bytes(secret)?.public_point()?,
        );
        // Observing the same evidence yields no scalar at all.
        let observed = verifier.observe_exact_claim(
            &fixture_proved_observation(evidence.clone()),
            DomClaimObservationTagV1::CounterpartyClaimObserved,
        )?;
        assert_eq!(observed.tx_hash(), &evidence.tx_hash());
        Ok(())
    }

    #[test]
    fn transaction_time_requires_the_authenticated_block_hash() {
        let blocks = BTreeMap::from([(7_u64, ([0x31_u8; 32], 1_700_000_007_u64))]);
        assert!(matches!(
            authenticated_block_time(&blocks, 7, [0x31_u8; 32]),
            Ok(1_700_000_007)
        ));
        assert!(matches!(
            authenticated_block_time(&blocks, 7, [0x32_u8; 32]),
            Err(RealDomError::InvalidEvidence)
        ));
        assert!(matches!(
            authenticated_block_time(&blocks, 8, [0x31_u8; 32]),
            Err(RealDomError::InvalidEvidence)
        ));
    }

    #[test]
    fn cursor_roundtrip_is_canonical_and_tamper_evident() -> Result<(), RealDomError> {
        let mut cursor = CursorStateV1::genesis();
        for height in 0_u64..8 {
            let byte = u8::try_from(height + 1).map_err(|_| RealDomError::BoundsExceeded)?;
            cursor.append(height, [byte; 32], 16)?;
        }
        let bytes = cursor.encode()?;
        assert_eq!(CursorStateV1::decode(&bytes)?, cursor);
        let mut tampered = bytes;
        tampered[20] ^= 1;
        assert!(CursorStateV1::decode(&tampered).is_err());
        Ok(())
    }

    #[test]
    fn cursor_history_is_bounded_and_rewinds_one_canonical_block() -> Result<(), RealDomError> {
        let mut cursor = CursorStateV1::genesis();
        for height in 0_u64..10 {
            let byte = u8::try_from(height + 1).map_err(|_| RealDomError::BoundsExceeded)?;
            cursor.append(height, [byte; 32], 4)?;
        }
        assert_eq!(cursor.history.len(), 4);
        assert_eq!(cursor.history[0].0, 6);
        assert_eq!(cursor.rewind_one()?, (9, [10_u8; 32]));
        assert_eq!(cursor.next_height, 9);
        assert_eq!(cursor.history.last().map(|entry| entry.0), Some(8));
        Ok(())
    }

    #[test]
    fn core_cursor_fields_cannot_diverge_from_authority_bytes() -> Result<(), RealDomError> {
        let mut state = CursorStateV1::genesis();
        state.append(0, [7_u8; 32], 8)?;
        let mut core = state.into_core()?;
        core.anchor = [9_u8; 32];
        assert!(CursorStateV1::from_core(&core).is_err());
        Ok(())
    }

    #[test]
    fn submission_completes_only_after_relay_or_confirmation() {
        assert_eq!(
            submission_facts_outcome(SubmissionStateV1::New, false),
            EffectOutcome::RetryLater
        );
        assert_eq!(
            submission_facts_outcome(SubmissionStateV1::Mempool, false),
            EffectOutcome::RetryLater
        );
        assert_eq!(
            submission_facts_outcome(SubmissionStateV1::Mempool, true),
            EffectOutcome::Completed
        );
        assert_eq!(
            submission_facts_outcome(SubmissionStateV1::Confirmed, false),
            EffectOutcome::Completed
        );
    }
}

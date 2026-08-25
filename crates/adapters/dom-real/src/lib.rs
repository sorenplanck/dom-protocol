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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use counterparty_api::RevealedSecretBytes;
use dom_leg::{DomLegSession, LegError, PreSignatureBytes};
use dom_scriptless_chain_adapter::{
    CanonicalBlockEvidenceV1, CanonicalTransactionEvidenceV1, ChainAdapterError,
    DomHttpChainAdapterV1, ObservedDomIdentityV1, ScriptlessScanCursorV1, SubmissionReceiptV1,
    SubmissionStateV1, MAX_SCRIPTLESS_SCAN_BLOCKS_V1,
};
use dom_scriptless_store::{
    AuthenticatedContractsRefundV1, ContractsSessionStoreV1, DomTransactionValidationContextV1,
    ExactDomFundingBroadcasterV1, ExactDomRefundBroadcasterV1, FundingBroadcastV1,
    SessionStoreError,
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
    /// A fixed cursor or history bound was exceeded.
    #[error("real DOM adapter bound exceeded")]
    BoundsExceeded,
    /// The requested canonical transaction was not found.
    #[error("real DOM transaction evidence not found")]
    EvidenceNotFound,
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
        self.evidence.tx_hash
    }

    /// Canonical containing-block identity.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.evidence.location.block_hash
    }

    /// Canonical containing-block height.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.evidence.location.block_height
    }

    /// Timestamp authenticated by the exact canonical containing header.
    #[must_use]
    pub const fn block_time_seconds(&self) -> u64 {
        self.block_time_seconds
    }

    /// Position of the transaction in its canonical block.
    #[must_use]
    pub const fn transaction_index(&self) -> u32 {
        self.evidence.location.transaction_index
    }

    /// Exact canonical transaction bytes returned by the real scanner.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.evidence.canonical_bytes
    }
}

impl CanonicalDomFundingEvidenceV1 {
    /// Canonical BLAKE2b-256 funding transaction identity.
    #[must_use]
    pub const fn tx_hash(&self) -> [u8; 32] {
        self.evidence.tx_hash
    }

    /// Canonical containing-block identity.
    #[must_use]
    pub const fn block_hash(&self) -> [u8; 32] {
        self.evidence.location.block_hash
    }

    /// Canonical containing-block height.
    #[must_use]
    pub const fn block_height(&self) -> u64 {
        self.evidence.location.block_height
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
        &self.evidence.canonical_bytes
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

    fn cache(&self) -> Result<MutexGuard<'_, RuntimeCacheV1>, RealDomError> {
        self.cache.lock().map_err(|_| RealDomError::LockPoisoned)
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
                    .retain(|_, transaction| transaction.location.block_height < block.height);
            }
            cache
                .blocks
                .insert(block.height, (block.block_hash, block.timestamp));
            for transaction in &block.transactions {
                cache
                    .transactions
                    .insert(transaction.tx_hash, transaction.clone());
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
    pub fn transaction(
        &self,
        evidence: &EvidenceRefV1,
    ) -> Result<CanonicalTransactionEvidenceV1, RealDomError> {
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
        if evidence.block_height == 0 && evidence.block_anchor == [0; 32] {
            let (state, identity) = self.scan_through_with_tip(0)?;
            let _ = self.scan_snapshot_to_tip(state, identity)?;
            let transaction = self
                .cache()?
                .transactions
                .get(&evidence.tx_id)
                .cloned()
                .ok_or(RealDomError::EvidenceNotFound)?;
            if transaction.tx_hash != evidence.tx_id {
                return Err(RealDomError::InvalidEvidence);
            }
            return Ok(transaction);
        }
        let _ = self.scan_through(evidence.block_height)?;
        let transaction = self
            .cache()?
            .transactions
            .get(&evidence.tx_id)
            .cloned()
            .ok_or(RealDomError::EvidenceNotFound)?;
        validate_evidence_reference(evidence, transaction)
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
            evidence.location.block_height,
            evidence.location.block_hash,
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
        // Scan the funding block and every canonical successor through one
        // anchored cursor. This prevents combining transaction inclusion from
        // one branch with a confirmation depth read from another snapshot.
        let (state, identity) = self.scan_through_with_tip(evidence.block_height)?;
        let (_, identity) = self.scan_snapshot_to_tip(state, identity)?;
        let transaction = self
            .cache()?
            .transactions
            .get(&evidence.tx_id)
            .cloned()
            .ok_or(RealDomError::EvidenceNotFound)?;
        let transaction = validate_evidence_reference(evidence, transaction)?;
        let created = transaction
            .transaction
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &expected_shared_output_commitment)
            .count();
        if transaction.tx_hash != expected_tx_hash
            || created != 1
            || transaction.spends_commitment(&expected_shared_output_commitment)
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let depth = identity
            .tip_height
            .checked_sub(transaction.location.block_height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(RealDomError::InvalidEvidence)?;
        let confirmation_depth = u32::try_from(depth).map_err(|_| RealDomError::BoundsExceeded)?;
        if confirmation_depth < minimum_confirmations {
            return Err(RealDomError::InvalidEvidence);
        }
        let block_time_seconds = authenticated_block_time(
            &self.cache()?.blocks,
            transaction.location.block_height,
            transaction.location.block_hash,
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
    if transaction.tx_hash != evidence.tx_id
        || transaction.location.block_height != evidence.block_height
        || transaction.location.block_hash != evidence.block_anchor
        || transaction.location.transaction_index != evidence.event_index
    {
        return Err(RealDomError::InvalidEvidence);
    }
    Ok(transaction)
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
        if pre_signature.claim_template_hash() != contract.claim_template_hash {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(Self {
            session,
            pre_signature,
            contract,
        })
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
                    tx_id: transaction.tx_hash,
                    event_index: transaction.location.transaction_index,
                    block_height: block.height,
                    block_anchor: block.block_hash,
                };
                if transaction.tx_hash == self.contract.funding_tx_hash {
                    if !transaction.creates_commitment(&self.contract.shared_output_commitment) {
                        return Err(RealDomError::InvalidEvidence);
                    }
                    records.push(ChainRecordV1::Funding { evidence });
                    continue;
                }
                if !transaction.spends_commitment(&self.contract.shared_output_commitment) {
                    continue;
                }
                if transaction.tx_hash == self.contract.refund_tx_hash {
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
}

impl core::fmt::Debug for RealDomEffectSinkV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RealDomEffectSinkV1")
            .field("settlement_id", &self.settlement_id)
            .field("consumed_claims", &self.consumed_claims.len())
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
        })
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
    if receipt.state == SubmissionStateV1::Confirmed || receipt.relayed {
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
                    Ok(_) => {
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
        RealDomError::Chain(_)
        | RealDomError::Store(_)
        | RealDomError::Leg(_)
        | RealDomError::InvalidEvidence
        | RealDomError::EvidenceNotFound => ChainSourceErrorV1::InvalidEvidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let receipt = |state, relayed| SubmissionReceiptV1 {
            tx_hash: [1_u8; 32],
            relayed,
            state,
        };
        assert_eq!(
            submission_outcome(receipt(SubmissionStateV1::New, false)),
            EffectOutcome::RetryLater
        );
        assert_eq!(
            submission_outcome(receipt(SubmissionStateV1::Mempool, false)),
            EffectOutcome::RetryLater
        );
        assert_eq!(
            submission_outcome(receipt(SubmissionStateV1::Mempool, true)),
            EffectOutcome::Completed
        );
        assert_eq!(
            submission_outcome(receipt(SubmissionStateV1::Confirmed, false)),
            EffectOutcome::Completed
        );
    }
}

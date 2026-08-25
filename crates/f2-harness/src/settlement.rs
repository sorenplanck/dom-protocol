//! F2 adapter: `dom-sim` observations as `EventEnvelopeV1` inputs and
//! outbox effects as real chain submissions (build order step 10).
//!
//! This module is the ADAPTER half of the §3 architectural limit — "the
//! chain adapter verifies the evidence and produces a neutral event". It
//! is also the place where the secret stops: `dom-sim` reveals `t` on the
//! claim spend, and this adapter never forwards it. The engine receives
//! [`ChainRecordV1::Claim`] with a public reference only; consuming that
//! reference cryptographically is the F1 boundary's job, reached through
//! the `RequestClaimConsumption` effect.
//!
//! `dom-sim` is NOT the DOM (I13/I15): it simulates chain semantics, never
//! cryptography. Swapping it for the real node happens in F7.

use std::cell::RefCell;
use std::rc::Rc;

use adapter_dom_sim::{
    encode_cursor, DetailedRecord, LockState, ObservedKind, RejectReason, SimChain, SimTx,
    SubmitResult,
};
use counterparty_api::ChainCursor;
use kaystra_core::settlement_engine::{
    ChainCursorV1, ChainRecordV1, ChainSourceErrorV1, ChainSourceV1, EffectOutcome, EffectSinkV1,
};
use kaystra_core::state::{Effect, EvidenceRefV1};
use kaystra_core::store_port::ClaimedEffectV1;
use kaystra_core::types::ChainId;

/// Shared simulated chain, scoped to one settlement's lock.
///
/// Cloning shares the same chain: the test keeps one handle to mine
/// blocks and inject reorgs while the engine holds another.
#[derive(Clone)]
pub struct SimSettlementChain {
    inner: Rc<RefCell<SimChain>>,
    chain_id: ChainId,
    lock_id: [u8; 32],
}

impl SimSettlementChain {
    /// New chain observing `lock_id` on `chain_id`.
    pub fn new(chain_id: ChainId, lock_id: [u8; 32]) -> Self {
        Self {
            inner: Rc::new(RefCell::new(SimChain::new())),
            chain_id,
            lock_id,
        }
    }

    /// The lock this settlement funds.
    pub fn lock_id(&self) -> [u8; 32] {
        self.lock_id
    }

    /// Mines `n` blocks.
    pub fn advance(&self, n: u64) {
        self.inner.borrow_mut().advance(n);
    }

    /// Injects a reorg of `depth` blocks.
    pub fn inject_reorg(&self, depth: u64) {
        self.inner.borrow_mut().inject_reorg(depth);
    }

    /// Tip height.
    pub fn height(&self) -> u64 {
        self.inner.borrow().height()
    }

    /// State of the settlement's lock on the canonical chain.
    pub fn lock_state(&self) -> LockState {
        self.inner.borrow().lock_state(self.lock_id)
    }

    /// The counterparty claims the lock, revealing the secret ON CHAIN.
    /// The secret goes no further than this call: nothing returns it to
    /// the engine.
    pub fn submit_claim(&self, revealed: [u8; 32]) -> SubmitResult {
        self.inner.borrow_mut().submit(SimTx::Claim {
            lock_id: self.lock_id,
            revealed,
        })
    }

    /// Models the counterparty of a composed route watching THIS lock's
    /// claim on chain and extracting the revealed scalar `t` from the claim
    /// spend — exactly what the downstream leg of a `A -> DOM -> B` route
    /// does before it can finalize its own lock. The engine adapter drops
    /// the secret (that is the whole point of §18/I1); a real party watching
    /// the origin chain reads `t` straight out of the claim. Returns the
    /// revealed bytes of the first claim of this settlement's lock, if any.
    ///
    /// This never feeds the engine and never touches the durable store; it
    /// is the chain-layer observation the counterparty performs off to the
    /// side, so it cannot violate the "secret never reaches the database"
    /// invariant the engine boundary enforces.
    pub fn observe_revealed_secret(&self) -> Option<[u8; 32]> {
        use counterparty_api::{ChainCursor, ObservedEvent};
        let (events, _) = self.inner.borrow().scan(&ChainCursor::default());
        events.into_iter().find_map(|event| match event {
            ObservedEvent::LockClaimed {
                lock_id, revealed, ..
            } if lock_id == self.lock_id => Some(revealed.0),
            _ => None,
        })
    }

    /// Whether an evidence reference still resolves on the canonical
    /// chain at exactly the position it claims.
    pub fn resolves(&self, evidence: &EvidenceRefV1) -> bool {
        match self.inner.borrow().inclusion_of(&evidence.tx_id) {
            Some((height, anchor, index)) => {
                height == evidence.block_height
                    && anchor == evidence.block_anchor
                    && index == evidence.event_index
            }
            None => false,
        }
    }

    fn cursor(&self, height: u64) -> ChainCursorV1 {
        let anchor = self.inner.borrow().anchor_of(height).unwrap_or([0u8; 32]);
        ChainCursorV1 {
            bytes: encode_cursor(height, anchor).0,
            height,
            anchor,
        }
    }
}

impl ChainSourceV1 for SimSettlementChain {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn genesis_cursor(&self) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        Ok(self.cursor(0))
    }

    fn cursor_at(&self, height: u64) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        Ok(self.cursor(height.min(self.height())))
    }

    fn scan(
        &self,
        from: &ChainCursorV1,
    ) -> Result<(Vec<ChainRecordV1>, ChainCursorV1), ChainSourceErrorV1> {
        let (records, next) = self
            .inner
            .borrow()
            .scan_detailed(&ChainCursor(from.bytes.clone()));
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            match record {
                DetailedRecord::Reorged {
                    from_height,
                    old_anchor,
                } => out.push(ChainRecordV1::Reorg {
                    from_height,
                    old_anchor,
                }),
                DetailedRecord::Observed(observed) => {
                    if observed.lock_id != self.lock_id {
                        continue;
                    }
                    let evidence = EvidenceRefV1 {
                        chain_id: self.chain_id,
                        tx_id: observed.tx_id,
                        event_index: observed.event_index,
                        block_height: observed.block_height,
                        block_anchor: observed.block_anchor,
                    };
                    // The secret revealed by a claim is NOT carried over:
                    // the engine gets the reference and nothing else.
                    out.push(match observed.kind {
                        ObservedKind::LockOpened => ChainRecordV1::Funding { evidence },
                        ObservedKind::LockClaimed => ChainRecordV1::Claim { evidence },
                        ObservedKind::LockRefunded => ChainRecordV1::Refund { evidence },
                    });
                }
            }
        }
        let (height, anchor) = decode(&next);
        Ok((
            out,
            ChainCursorV1 {
                bytes: next.0,
                height,
                anchor,
            },
        ))
    }

    fn tip_height(&self) -> Result<u64, ChainSourceErrorV1> {
        Ok(self.height())
    }
}

fn decode(cursor: &ChainCursor) -> (u64, [u8; 32]) {
    if cursor.0.len() != 40 {
        return (0, [0u8; 32]);
    }
    let mut height = [0u8; 8];
    height.copy_from_slice(&cursor.0[..8]);
    let mut anchor = [0u8; 32];
    anchor.copy_from_slice(&cursor.0[8..]);
    (u64::from_be_bytes(height), anchor)
}

/// What the sink did with one effect, for test assertions.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SinkAction {
    /// Funding submitted to the chain.
    FundingSubmitted,
    /// Refund submitted to the chain.
    RefundSubmitted,
    /// Refund refused for now (timelock not expired on chain).
    RefundDeferred,
    /// Claim evidence handed to the F1 boundary and accepted.
    ClaimConsumed(EvidenceRefV1),
    /// Claim evidence no longer resolves: refused, never guessed.
    ClaimEvidenceGone,
    /// Terminal outcome notified.
    TerminalNotified,
}

/// Effect sink over the simulated chain.
///
/// Submissions are rebuilt from IMMUTABLE settlement configuration, so a
/// resend is byte-identical and the chain deduplicates it (I7).
pub struct SimEffectSink {
    chain: SimSettlementChain,
    refund_not_before_height: u64,
    actions: Vec<SinkAction>,
    fail_next: usize,
}

impl SimEffectSink {
    /// New sink for a settlement whose refund is executable from
    /// `refund_not_before_height`.
    pub fn new(chain: SimSettlementChain, refund_not_before_height: u64) -> Self {
        Self {
            chain,
            refund_not_before_height,
            actions: Vec::new(),
            fail_next: 0,
        }
    }

    /// Makes the next `n` executions fail transiently (crash/partition
    /// injection for the C8–C9 failpoints).
    pub fn fail_next(&mut self, n: usize) {
        self.fail_next = n;
    }

    /// Everything the sink did, in order.
    pub fn actions(&self) -> &[SinkAction] {
        &self.actions
    }

    /// How many times one action kind happened.
    pub fn count(&self, predicate: impl Fn(&SinkAction) -> bool) -> usize {
        self.actions.iter().filter(|a| predicate(a)).count()
    }

    /// Evidence references handed to the F1 boundary.
    pub fn claim_consumptions(&self) -> Vec<EvidenceRefV1> {
        self.actions
            .iter()
            .filter_map(|a| match a {
                SinkAction::ClaimConsumed(evidence) => Some(*evidence),
                _ => None,
            })
            .collect()
    }
}

impl EffectSinkV1 for SimEffectSink {
    fn execute(&mut self, effect: &ClaimedEffectV1) -> EffectOutcome {
        if self.fail_next > 0 {
            self.fail_next -= 1;
            return EffectOutcome::RetryLater;
        }
        match &effect.kind {
            Effect::AuthorizeFunding => {
                let result = self.chain.inner.borrow_mut().submit(SimTx::Lock {
                    lock_id: self.chain.lock_id,
                });
                self.actions.push(SinkAction::FundingSubmitted);
                match result {
                    // A lock already in the mempool or on chain is the
                    // same economic fact (I7 dedupe by bytes).
                    SubmitResult::Accepted { .. }
                    | SubmitResult::Rejected(RejectReason::DuplicateLock) => {
                        EffectOutcome::Completed
                    }
                    SubmitResult::Rejected(_) => EffectOutcome::Rejected,
                }
            }
            Effect::ArmRefundPath => {
                let result = self.chain.inner.borrow_mut().submit(SimTx::Refund {
                    lock_id: self.chain.lock_id,
                    not_before_height: self.refund_not_before_height,
                });
                match result {
                    SubmitResult::Accepted { .. } => {
                        self.actions.push(SinkAction::RefundSubmitted);
                        EffectOutcome::Completed
                    }
                    SubmitResult::Rejected(RejectReason::TimelockNotExpired) => {
                        self.actions.push(SinkAction::RefundDeferred);
                        EffectOutcome::RetryLater
                    }
                    SubmitResult::Rejected(_) => EffectOutcome::Rejected,
                }
            }
            Effect::RequestClaimConsumption { evidence } => {
                // F1 boundary stand-in: re-verify that the reference
                // still resolves before consuming it. A reference the
                // chain no longer holds is refused, never assumed.
                if self.chain.resolves(evidence) {
                    self.actions.push(SinkAction::ClaimConsumed(*evidence));
                    EffectOutcome::Completed
                } else {
                    self.actions.push(SinkAction::ClaimEvidenceGone);
                    EffectOutcome::Rejected
                }
            }
            Effect::RecordTerminalOutcome(_) => {
                self.actions.push(SinkAction::TerminalNotified);
                EffectOutcome::Completed
            }
            // Revalidation never reaches the sink: the engine executes it
            // against its own scanner.
            Effect::RevalidateFrom { .. } => EffectOutcome::Rejected,
        }
    }
}

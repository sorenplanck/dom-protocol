//! Offline broadcast seam over the deterministic EVM mock.
//!
//! # What this is, and what it is not
//!
//! `adapter_evm::mock::MockChain` reproduces the JSON-RPC *read* surface. It
//! has no notion of a transaction: a test appends logs to it directly. To run
//! the whole composition offline — engine, port, outbox, adapter — something
//! has to close that loop and turn an authorised artifact into the log the
//! contract would have emitted. That is this module.
//!
//! It simulates **chain semantics only**, in exactly the sense
//! `adapter-dom-sim` is allowed to (Foundation §4.5): inclusion in a block,
//! byte-identical dedupe, one settlement outcome per lock. It does **not**
//! execute EVM bytecode, does not check signatures, and — the important one —
//! does **not** stand in for anything cryptographic. Every scalar it puts in a
//! `Claimed` log is one the caller genuinely holds; it never invents a `t`, a
//! point or a signature. The real contract's acceptance rule is proved against
//! the real contract, on Anvil, in `tests/e2e_anvil.rs`.
//!
//! It also never signs, exactly like the production seam it stands in for: it
//! is handed the finished unsigned artifact and does the node's half of the
//! job, not the wallet's.

use std::cell::RefCell;
use std::collections::BTreeSet;

use crate::error::{HarnessError, Result};
use crate::port::{BroadcastOutcome, Broadcaster};
use crate::shared::SharedRpc;
use adapter_evm::abi::{selector, SIG_CLAIM, SIG_OPEN, SIG_REFUND};
use adapter_evm::binding::LockTerms;
use adapter_evm::mock::MockChain;
use adapter_evm::UnsignedEvmCall;

/// Turns authorised artifacts into blocks on a [`MockChain`].
pub struct MockBroadcaster {
    chain: SharedRpc<MockChain>,
    funder: [u8; 20],
    terms: LockTerms,
    seen: RefCell<BTreeSet<(u8, [u8; 32])>>,
    settled: RefCell<BTreeSet<[u8; 32]>>,
    broadcast_log: RefCell<Vec<(u8, [u8; 32])>>,
}

impl MockBroadcaster {
    /// A seam over `chain` for the settlement described by `terms`.
    pub fn new(chain: SharedRpc<MockChain>, funder: [u8; 20], terms: LockTerms) -> Self {
        Self {
            chain,
            funder,
            terms,
            seen: RefCell::new(BTreeSet::new()),
            settled: RefCell::new(BTreeSet::new()),
            broadcast_log: RefCell::new(Vec::new()),
        }
    }

    /// Every `(selector-tag, lock_id)` this seam accepted, in order. Lets a
    /// test assert that a resend after a restart did not produce a second
    /// inclusion.
    pub fn accepted(&self) -> Vec<(u8, [u8; 32])> {
        self.broadcast_log.borrow().clone()
    }

    fn tag(call: &UnsignedEvmCall) -> Result<u8> {
        let head = call.calldata.get(..4).ok_or(HarnessError::Misconfigured)?;
        if head == selector(SIG_OPEN) {
            Ok(1)
        } else if head == selector(SIG_CLAIM) {
            Ok(2)
        } else if head == selector(SIG_REFUND) {
            Ok(3)
        } else {
            Err(HarnessError::Misconfigured)
        }
    }
}

impl Broadcaster for MockBroadcaster {
    fn broadcast(&self, call: &UnsignedEvmCall) -> Result<BroadcastOutcome> {
        let tag = Self::tag(call)?;
        let key = (tag, call.lock_id);
        if self.seen.borrow().contains(&key) {
            // I7: the same bytes offered twice are the same transaction.
            return Ok(BroadcastOutcome::Duplicate);
        }
        // I4, as the chain enforces it: one settlement outcome per lock.
        if tag != 1 && self.settled.borrow().contains(&call.lock_id) {
            return Err(HarnessError::BroadcastRefused);
        }

        let terms = self.terms;
        let funder = self.funder;
        let lock_id = call.lock_id;
        let binding = call.binding;
        // For a claim the scalar is the second ABI word of the calldata. It is
        // read here and never rendered anywhere (I6).
        let mut secret = [0u8; 32];
        if tag == 2 {
            let raw = call
                .calldata
                .get(36..68)
                .ok_or(HarnessError::Misconfigured)?;
            secret.copy_from_slice(raw);
        }

        let appended = self.chain.with_mut(|c| {
            c.push_block();
            match tag {
                1 => c.push_lock_opened(
                    lock_id,
                    binding,
                    funder,
                    terms.beneficiary,
                    terms.asset,
                    terms.amount,
                    terms.adaptor_address,
                    terms.deadline,
                ),
                2 => c.push_claimed(lock_id, binding, terms.beneficiary, secret),
                _ => c.push_refunded(lock_id, binding, funder, terms.amount),
            }
        })?;
        appended.map_err(HarnessError::Adapter)?;

        self.seen.borrow_mut().insert(key);
        if tag != 1 {
            self.settled.borrow_mut().insert(lock_id);
        }
        self.broadcast_log.borrow_mut().push(key);
        Ok(BroadcastOutcome::Accepted)
    }
}

/// A broadcast seam that records artifacts and puts nothing anywhere.
///
/// Used where the point of the test is the durable log rather than the chain.
#[derive(Default)]
pub struct RecordingBroadcaster {
    calls: RefCell<Vec<UnsignedEvmCall>>,
}

impl RecordingBroadcaster {
    /// Encoded bytes of everything offered, in order.
    pub fn offered(&self) -> Vec<Vec<u8>> {
        self.calls.borrow().iter().map(|c| c.encode()).collect()
    }
}

impl Broadcaster for RecordingBroadcaster {
    fn broadcast(&self, call: &UnsignedEvmCall) -> Result<BroadcastOutcome> {
        self.calls.borrow_mut().push(call.clone());
        Ok(BroadcastOutcome::Accepted)
    }
}

/// A broadcast seam that always refuses. Proves that a refused broadcast is
/// reported rather than assumed away.
pub struct RefusingBroadcaster;

impl Broadcaster for RefusingBroadcaster {
    fn broadcast(&self, _call: &UnsignedEvmCall) -> Result<BroadcastOutcome> {
        Err(HarnessError::BroadcastRefused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adapter_evm::abi::word_u128;
    use adapter_evm::adapter::UNSIGNED_CALL_VERSION;
    use adapter_evm::binding::{adaptor_address_of_scalar, Direction};

    fn terms() -> LockTerms {
        let mut t = [0u8; 32];
        t[31] = 7;
        LockTerms {
            dom_chain_id: [0x11; 32],
            direction: Direction::DomToEvm.as_u8(),
            session_id: [0x22; 32],
            terms_hash: [0x33; 32],
            participants_hash: [0x44; 32],
            asset: [0u8; 20],
            amount: word_u128(1_000),
            beneficiary: [0xBE; 20],
            adaptor_address: adaptor_address_of_scalar(&t).expect("canonical"),
            deadline: 1_900_000_000,
        }
    }

    fn open_call() -> UnsignedEvmCall {
        let mut calldata = selector(SIG_OPEN).to_vec();
        calldata.extend_from_slice(&[0u8; 320]);
        UnsignedEvmCall {
            version: UNSIGNED_CALL_VERSION,
            chain_id: 31337,
            to: [0xC0; 20],
            value: [0u8; 32],
            gas_limit_hint: 300_000,
            lock_id: [0xAA; 32],
            binding: [0xBB; 32],
            calldata,
        }
    }

    #[test]
    fn an_open_becomes_a_block_with_a_lock_opened_log() {
        let chain = SharedRpc::new(MockChain::new(31337, [0xC0; 20]));
        let b = MockBroadcaster::new(chain.clone(), [0xF0; 20], terms());
        assert_eq!(b.broadcast(&open_call()), Ok(BroadcastOutcome::Accepted));
        assert_eq!(chain.with(|c| c.height()), Ok(1));
    }

    #[test]
    fn identical_bytes_are_deduplicated_rather_than_mined_twice() {
        let chain = SharedRpc::new(MockChain::new(31337, [0xC0; 20]));
        let b = MockBroadcaster::new(chain.clone(), [0xF0; 20], terms());
        b.broadcast(&open_call()).expect("first");
        assert_eq!(b.broadcast(&open_call()), Ok(BroadcastOutcome::Duplicate));
        assert_eq!(chain.with(|c| c.height()), Ok(1), "I7: one inclusion");
        assert_eq!(b.accepted().len(), 1);
    }

    #[test]
    fn an_unknown_selector_is_refused_rather_than_guessed() {
        let chain = SharedRpc::new(MockChain::new(31337, [0xC0; 20]));
        let b = MockBroadcaster::new(chain, [0xF0; 20], terms());
        let mut call = open_call();
        call.calldata[0] ^= 0xFF;
        assert_eq!(b.broadcast(&call), Err(HarnessError::Misconfigured));
    }

    #[test]
    fn a_second_settlement_of_one_lock_is_refused() {
        // I4 as the chain imposes it.
        let chain = SharedRpc::new(MockChain::new(31337, [0xC0; 20]));
        let b = MockBroadcaster::new(chain, [0xF0; 20], terms());
        let mut refund = open_call();
        refund.calldata = selector(SIG_REFUND).to_vec();
        refund.calldata.extend_from_slice(&[0u8; 32]);
        assert_eq!(b.broadcast(&refund), Ok(BroadcastOutcome::Accepted));
        let mut claim = open_call();
        claim.calldata = selector(SIG_CLAIM).to_vec();
        claim.calldata.extend_from_slice(&[0u8; 64]);
        assert_eq!(b.broadcast(&claim), Err(HarnessError::BroadcastRefused));
    }

    #[test]
    fn the_refusing_seam_never_pretends_to_have_sent_anything() {
        assert_eq!(
            RefusingBroadcaster.broadcast(&open_call()),
            Err(HarnessError::BroadcastRefused)
        );
    }
}

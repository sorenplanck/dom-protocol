//! `EvmChainPort` — the EVM (counterparty) leg driver.
//!
//! # Where this sits under the §24 engine (B-DOM)
//!
//! `main`'s ratified settlement engine drives the **DOM leg**: its
//! `ChainSourceV1`/`EffectSinkV1` are bound to `terms.dom_leg`, which is a
//! block-height chain (dom-sim, reusing `f2-harness`). The **EVM leg is the
//! counterparty** — a real `ConditionLockV2` on a timestamp chain — and it is
//! not something the engine observes through a `ChainPort`. This driver is what
//! the harness uses to act on that counterparty leg: fund it, observe its
//! finalized state, claim it (publishing `t`), or refund it after the deadline.
//!
//! # Three seams, deliberately separate
//!
//! - **observation** is the adapter's job. This driver only translates: it
//!   calls [`CounterpartyAdapter::observe`] and hands the neutral events on. It
//!   adds no interpretation, because interpretation of chain evidence belongs to
//!   the adapter of that chain (I9).
//! - **authorisation and broadcast** are *not* the adapter's job, and not this
//!   driver's either. The adapter produces a deterministic unsigned artifact;
//!   the driver records it durably in the [`crate::outbox`] and hands it to a
//!   [`Broadcaster`]. No key ever enters this crate.
//! - **the clock** is its own seam ([`ChainClock`]), because the EVM leg's
//!   timelock is a wall-clock deadline and neither the adapter nor the engine
//!   has a notion of wall-clock time.
//!
//! # `finalized_height` is the finalized height, not the tip
//!
//! Confirmation policy on the EVM leg must run on finalized facts only.
//! Returning the chain tip would let an unfinalized block look confirmable,
//! which is precisely what A4-EVM forbids. So this driver reports the
//! **finalized** height: the same checkpoint the adapter refuses to surface
//! events above. When the endpoint cannot serve `finalized`, it reports the
//! last height it did serve (initially `0`) — the fail-closed direction, a
//! lower height confirms fewer things, never more.
//!
//! # One clock per leg, no crossing
//!
//! Under B-DOM the two legs stay in their own timelock domains: the engine
//! arms the DOM-leg refund in the block-height domain (handled entirely by the
//! reused `f2-harness` sink), and this driver refunds the EVM leg in the
//! timestamp domain against the contract's own `deadline`. Because there is no
//! block-height instruction crossing onto the timestamp chain, there is no
//! domain bridge here at all — the crossing the v0.5 harness had to guard
//! simply does not occur. The domain-safety machinery still exists and is still
//! exercised in [`crate::timelock`]; this driver just never needs to bridge.

use std::cell::{Cell, RefCell};

use adapter_evm::binding::LockTerms;
use adapter_evm::rpc::JsonRpc;
use adapter_evm::{EvmAdapter, EvmAdapterConfig, UnsignedEvmCall};
use counterparty_api::{
    AdaptorPointBytes, ChainCursor, CounterpartyAdapter, NeutralTerms, ObservedEvent,
    RevealedSecretBytes, TimelockDomain,
};

use crate::error::{HarnessError, Result};
use crate::outbox::{idempotency_key, Outbox, OutboxLog, SubmissionIntent, SubmitOutcome};
use crate::routes::{build_refund_call, rederive, EvmDeployment};
use crate::shared::SharedRpc;
use crate::timelock::{TimelockPoint, TimelockPolicy};

/// Events requested per `observe` call. Below the neutral hard ceiling
/// (`counterparty_api::MAX_EVENTS_PER_OBSERVE`), which is applied on top of it.
pub const MAX_EVENTS_PER_TICK: usize = 256;

/// What happened to an artifact handed to the broadcast seam.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BroadcastOutcome {
    /// The bytes were accepted for inclusion.
    Accepted,
    /// The chain already had them (byte-identical dedupe, I7).
    Duplicate,
    /// Not now, but the same bytes may be offered again later.
    RetryLater,
}

/// Whatever authorises and broadcasts an unsigned artifact.
///
/// This trait is the signing boundary. Implementations live **outside** the
/// adapter and outside this crate's production path: the Anvil harness
/// implements it by shelling out to `cast send` with a well-known development
/// key, so that the artifact the adapter produced is proved to be a real,
/// broadcastable transaction while every signing concern stays out here.
pub trait Broadcaster {
    /// Offers the exact bytes recorded in the outbox. Must be idempotent for
    /// byte-identical input (I7).
    fn broadcast(&self, call: &UnsignedEvmCall) -> Result<BroadcastOutcome>;
}

/// The EVM leg's wall clock, as the chain reports it.
pub trait ChainClock {
    /// Current chain time. Must be in the [`TimelockDomain::Timestamp`] domain.
    fn now(&self) -> Result<TimelockPoint>;
}

/// A clock that answers a fixed reading, moved by the test that owns it.
pub struct FixedClock(Cell<u64>);

impl FixedClock {
    /// A clock reading `t` seconds.
    pub fn new(t: u64) -> Self {
        Self(Cell::new(t))
    }
    /// Moves the clock to `t`.
    pub fn set(&self, t: u64) {
        self.0.set(t);
    }
}

impl ChainClock for FixedClock {
    fn now(&self) -> Result<TimelockPoint> {
        Ok(TimelockPoint::timestamp(self.0.get()))
    }
}

/// Static configuration of the driver: one settlement, one deployment.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EvmPortConfig {
    /// Deployment identity used for every derivation.
    pub deployment: EvmDeployment,
    /// Neutral terms handed to `prepare_lock`.
    pub neutral: NeutralTerms,
    /// Adaptor point `T` the lock commits to.
    pub adaptor_point: AdaptorPointBytes,
    /// Full lock terms, needed for `refund` and for cross-checks.
    pub terms: LockTerms,
    /// EVM-side timelock policy (timestamps).
    pub timelock: TimelockPolicy,
}

/// Counters a test can read to see what the driver refused and why, without the
/// driver ever logging anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PortStats {
    /// `observe` calls that failed; no events were surfaced for them.
    pub scan_failures: usize,
    /// Refunds refused because the deadline had not safely passed.
    pub refunds_refused_for_timelock: usize,
    /// Submissions refused by the outbox (equivocation or capacity).
    pub outbox_refusals: usize,
    /// Artifacts the broadcast seam reported as already known.
    pub duplicate_broadcasts: usize,
}

/// The EVM (counterparty) leg driver.
pub struct EvmChainPort<R: JsonRpc, B: Broadcaster, C: ChainClock, J: OutboxLog> {
    cfg: EvmPortConfig,
    adapter: EvmAdapter<SharedRpc<R>>,
    rpc: SharedRpc<R>,
    outbox: Outbox<J>,
    broadcaster: B,
    clock: C,
    last_finalized: Cell<u64>,
    stats: Cell<PortStats>,
    last_error: RefCell<Option<HarnessError>>,
}

impl<R: JsonRpc, B: Broadcaster, C: ChainClock, J: OutboxLog> EvmChainPort<R, B, C, J> {
    /// Builds a driver over an already-shared transport.
    ///
    /// Re-registers the settlement's lock with the adapter (`track_lock`),
    /// which is what a restart must do: the adapter's knowledge of which locks
    /// are its own is in-memory, and the durable half of that knowledge is the
    /// terms this driver is configured with.
    pub fn new(
        cfg: EvmPortConfig,
        adapter_cfg: EvmAdapterConfig,
        rpc: SharedRpc<R>,
        outbox: Outbox<J>,
        broadcaster: B,
        clock: C,
    ) -> Result<Self> {
        if cfg.timelock.domain != TimelockDomain::Timestamp {
            return Err(HarnessError::Misconfigured);
        }
        if adapter_cfg.chain_id != cfg.deployment.chain_id
            || adapter_cfg.contract != cfg.deployment.contract
            || adapter_cfg.funder != cfg.deployment.funder
        {
            return Err(HarnessError::Misconfigured);
        }
        let adapter = EvmAdapter::new(adapter_cfg, rpc.clone())?;
        adapter.track_lock(&cfg.terms)?;
        Ok(Self {
            cfg,
            adapter,
            rpc,
            outbox,
            broadcaster,
            clock,
            last_finalized: Cell::new(0),
            stats: Cell::new(PortStats::default()),
            last_error: RefCell::new(None),
        })
    }

    /// The adapter, for evidence collection and revealed-secret queries.
    pub fn adapter(&self) -> &EvmAdapter<SharedRpc<R>> {
        &self.adapter
    }

    /// The durable submission log.
    pub fn outbox(&self) -> &Outbox<J> {
        &self.outbox
    }

    /// The shared transport, so a test can move the world forward.
    pub fn rpc(&self) -> &SharedRpc<R> {
        &self.rpc
    }

    /// The broadcast seam.
    pub fn broadcaster(&self) -> &B {
        &self.broadcaster
    }

    /// The clock seam.
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Counters of what was refused.
    pub fn stats(&self) -> PortStats {
        self.stats.get()
    }

    /// The most recent refusal, if any.
    pub fn last_error(&self) -> Option<HarnessError> {
        self.last_error.borrow().clone()
    }

    /// The scalar this observer saw published for `lock_id`, if any. Survives
    /// reorgs by construction — see `adapter_evm::revealed`.
    pub fn revealed_secret(&self, lock_id: &[u8; 32]) -> Result<Option<RevealedSecretBytes>> {
        Ok(self.adapter.revealed_secret(lock_id)?)
    }

    /// `(binding, lock_id)` of the configured settlement.
    pub fn identity(&self) -> Result<([u8; 32], [u8; 32])> {
        rederive(&self.cfg.deployment, &self.cfg.terms)
    }

    /// Hands the durable log and the broadcast seam back, so a restart can
    /// rebuild the driver on top of them. This is the "process died" seam.
    pub fn into_parts(self) -> (Outbox<J>, B, C) {
        (self.outbox, self.broadcaster, self.clock)
    }

    fn note(&self, e: HarnessError) {
        *self.last_error.borrow_mut() = Some(e);
    }

    fn bump(&self, f: impl FnOnce(&mut PortStats)) {
        let mut s = self.stats.get();
        f(&mut s);
        self.stats.set(s);
    }

    /// Records an artifact durably and then offers it to the broadcast seam.
    ///
    /// The order is not negotiable: durable first, wire second. A crash between
    /// the two replays the same bytes; a crash the other way round could send
    /// bytes nobody remembers sending.
    fn record_and_broadcast(
        &mut self,
        intent: SubmissionIntent,
        lock_id: [u8; 32],
        call: &UnsignedEvmCall,
    ) -> Result<BroadcastOutcome> {
        let key = idempotency_key(
            self.cfg.deployment.chain_id,
            &self.cfg.deployment.contract,
            &lock_id,
            intent,
        );
        let outcome = self.outbox.submit(key, intent, call)?;
        // Whether the record was new or replayed, what goes on the wire is what
        // the log holds — never a freshly computed variant of it (I7).
        let bytes = self
            .outbox
            .get(&key)
            .ok_or(HarnessError::Outbox(
                crate::outbox::OutboxError::CorruptRecord,
            ))?
            .call
            .clone();
        if outcome == SubmitOutcome::ReplayedIdentical {
            self.bump(|s| s.duplicate_broadcasts += 1);
        }
        self.broadcaster.broadcast(&bytes)
    }

    /// Funds the EVM leg: builds `open(LockTerms)` from the adapter's
    /// deterministic artifact, records it durably, and broadcasts it.
    ///
    /// On failure the relevant counter is bumped and the refusal noted; the
    /// error is returned untouched — nothing is papered over.
    pub fn submit_funding(&mut self, lock_id: [u8; 32]) -> Result<BroadcastOutcome> {
        let artifact = self
            .adapter
            .prepare_lock_blocking(&self.cfg.neutral, &self.cfg.adaptor_point)
            .map_err(HarnessError::from);
        let result = artifact.and_then(|artifact| {
            let call = UnsignedEvmCall::decode(&artifact.bytes)?;
            if call.lock_id != lock_id {
                // A different settlement than this driver was configured for.
                return Err(HarnessError::Misconfigured);
            }
            self.record_and_broadcast(SubmissionIntent::OpenLock, lock_id, &call)
        });
        if let Err(e) = &result {
            if matches!(e, HarnessError::Outbox(_)) {
                self.bump(|s| s.outbox_refusals += 1);
            }
            self.note(e.clone());
        }
        result
    }

    /// Refunds the EVM leg after its contract `deadline`.
    ///
    /// This is the EVM leg's failure path and it is purely timestamp-domain:
    /// the contract compares against `block.timestamp`, and the driver refuses
    /// to broadcast until the deadline has *safely* passed — the observation
    /// margins applied in the expiry direction, so a stale view cannot make the
    /// driver refund early. No engine instruction and no domain bridge are
    /// involved (see the module header).
    pub fn submit_refund(&mut self, lock_id: [u8; 32]) -> Result<BroadcastOutcome> {
        let result = self.submit_refund_inner(lock_id);
        if let Err(e) = &result {
            match e {
                HarnessError::Timelock(_) => self.bump(|s| s.refunds_refused_for_timelock += 1),
                HarnessError::Outbox(_) => self.bump(|s| s.outbox_refusals += 1),
                _ => {}
            }
            self.note(e.clone());
        }
        result
    }

    fn submit_refund_inner(&mut self, lock_id: [u8; 32]) -> Result<BroadcastOutcome> {
        let now = self.clock.now()?;
        self.cfg
            .timelock
            .require_expired(now, TimelockPoint::timestamp(self.cfg.terms.deadline))?;

        let (binding, derived) = rederive(&self.cfg.deployment, &self.cfg.terms)?;
        if derived != lock_id {
            return Err(HarnessError::Misconfigured);
        }
        let call = build_refund_call(&self.cfg.deployment, lock_id, binding)?;
        self.record_and_broadcast(SubmissionIntent::Refund, lock_id, &call)
    }

    /// Authorises and broadcasts the EVM `claim(lockId, t)` produced by the
    /// DOM→EVM route. The claim is driven by whichever side holds the secret,
    /// through this method.
    pub fn submit_claim(&mut self, call: &UnsignedEvmCall) -> Result<BroadcastOutcome> {
        let lock_id = call.lock_id;
        let result = self.record_and_broadcast(SubmissionIntent::Claim, lock_id, call);
        if let Err(e) = &result {
            if matches!(e, HarnessError::Outbox(_)) {
                self.bump(|s| s.outbox_refusals += 1);
            }
            self.note(e.clone());
        }
        result
    }

    /// Observes the EVM leg: the neutral events at or below the finalized
    /// checkpoint, and the advanced cursor. Fails closed — an endpoint error
    /// surfaces nothing and does not move the cursor.
    pub fn observe(&self, cursor: &ChainCursor) -> (Vec<ObservedEvent>, ChainCursor) {
        // `CounterpartyAdapter` is async because a real endpoint is remote;
        // this driver is sync. `pollster` is the whole bridge: no runtime, no
        // spawning, no hidden concurrency.
        match pollster::block_on(self.adapter.observe(cursor, MAX_EVENTS_PER_TICK)) {
            Ok(pair) => pair,
            Err(e) => {
                self.bump(|s| s.scan_failures += 1);
                self.note(HarnessError::Adapter(e));
                (Vec::new(), cursor.clone())
            }
        }
    }

    /// The finalized height of the EVM leg (never the tip). See the module
    /// header for why this is the fail-closed reading.
    pub fn finalized_height(&self) -> u64 {
        match adapter_evm::finality::fetch_finalized(&self.rpc) {
            Ok(head) => {
                self.last_finalized.set(head.height);
                head.height
            }
            Err(e) => {
                self.note(HarnessError::Adapter(e));
                self.last_finalized.get()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use counterparty_api::TimelockDomain;

    #[test]
    fn the_fixed_clock_reports_the_timestamp_domain() {
        let c = FixedClock::new(1_000);
        assert_eq!(c.now().expect("clock"), TimelockPoint::timestamp(1_000));
        c.set(2_000);
        assert_eq!(c.now().expect("clock").value, 2_000);
        assert_eq!(
            c.now().expect("clock").domain,
            TimelockDomain::Timestamp,
            "the EVM leg is never a block-height domain"
        );
    }

    /// A compile-time tripwire: the per-tick budget may never exceed the
    /// neutral hard ceiling, or the adapter would silently clamp it.
    const _: () = assert!(MAX_EVENTS_PER_TICK <= counterparty_api::MAX_EVENTS_PER_OBSERVE);
}

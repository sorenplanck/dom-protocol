//! `f3-harness` — the integration and end-to-end harness for gate **G-F3**.
//!
//! Foundation Document DOM Interop v0.2.1 §4.3, §4.4, §4.5, §4.7, §5, §6, §7
//! (F3), §8; F3 interface spec section 4.
//!
//! # What this crate composes (B-DOM)
//!
//! Nothing here is a new mechanism. Every piece already exists and is frozen;
//! this crate wires them together and proves the wiring:
//!
//! | piece | owner | role here |
//! |---|---|---|
//! | `kaystra_core::SettlementEngine` (F2 §24) | F2 | the ratified settlement state machine, unchanged; it drives the **DOM leg** |
//! | `f2_harness::{SimSettlementChain, SimEffectSink}` | F1/F2 | the DOM leg as `ChainSourceV1`/`EffectSinkV1`, reused verbatim |
//! | `adapter_evm::EvmAdapter` | F3 adapter workstream | observes the **EVM (counterparty) leg**, produces unsigned artifacts |
//! | [`port::EvmChainPort`] | F3 | drives the EVM leg (fund / observe / claim / refund) around the adapter |
//! | `dom_leg::DomLegSession` | F1 | the **only** door to the DOM authority (adapt/extract) |
//!
//! ## Why the engine drives the DOM leg, and the EVM leg is the counterparty
//!
//! `main`'s ratified §24 `SettlementEngine::open` binds its `ChainSourceV1` to
//! `terms.dom_leg` and requires that leg's timelock to be `BlockHeight`. The
//! EVM leg is the *counterparty* leg and is timestamp-domain, so the ratified
//! engine models the DOM leg and only the DOM leg — it cannot be made to drive
//! the EVM leg without editing G-F2 code, which is out of bounds. The harness
//! therefore composes exactly as G-F2 does on the DOM side (reusing
//! `SimSettlementChain`/`SimEffectSink`) and adds the EVM leg as the
//! counterparty: observed by `adapter-evm`, its finalized `Claimed(t)` feeding
//! the DOM claim consumption through the routes/seam. No security check of the
//! v0.5 composition is dropped; see `docs/normative/F3-F5-RECONCILIATION-PLAN.md`.
//!
//! # The DOM leg is live
//!
//! `dom_leg::DomLegSession::{adapt_claim, extract_secret}` now perform the real
//! `AdaptorPreSignatureV1::{verify, adapt, extract}` against the pinned
//! authority, on a session built with
//! `DomLegSession::with_aggregate_signing_key`. This harness calls them at the
//! real call sites, with all pre-validation in the real order. A refusal is
//! still propagated untouched — nothing is worked around, nothing is
//! fabricated, no success is simulated (I13).
//!
//! ## Which claim the real-crypto tests prove, and which they do not
//!
//! The only source of a genuinely valid pre-signature at the pinned revision is
//! the **frozen SCAD0 corpus** inside the pinned checkout: the vault-driven
//! route is unreachable from downstream code, because every constructor of
//! `ValidatedSigningRoundStateV1` is `pub(crate)` *and*
//! `#[cfg(any(test, fuzzing))]`. Those eight vectors verify only under the
//! corpus's own bindings — chain id `[0xAD; 32]`, the fixed kernel message,
//! `claim_template_hash = [0x22; 32]`, `transcript_hash = [0x33; 32]`, and the
//! signing key derived from each kernel's excess.
//!
//! So `tests/g_f3_pin.rs` proves **"the crypto seam is real and both routes
//! call it correctly"**. It does **not** prove *"a full session with
//! project-chosen terms was signed end to end"*. Those are different claims,
//! and nothing in this crate may be read as the second one.
//!
//! For the end-to-end flows the DOM leg is `dom-sim`, which simulates *chain
//! semantics* and never cryptography (Foundation §4.5) — the same arrangement
//! `f2-harness` already runs. **dom-sim is not the DOM; it confers no network
//! compatibility; the swap for the real node happens in F7 under its
//! eligibility gate.** What G-F3 requires to be real is the EVM side, and it
//! is: a real `ConditionLockV2` on a real EVM, with `t` taken from a real
//! on-chain `Claimed` log.
//!
//! # Invariants this crate is responsible for
//!
//! - **I1** — no key material anywhere. The driver produces an *unsigned*
//!   artifact and hands it to a [`port::Broadcaster`]; signing happens outside,
//!   by whoever owns the funds. See [`port`].
//! - **I6** — `t` is never logged, `Debug`-printed or returned in an error.
//!   Every type here that can hold it has a redacting `Debug`, and every error
//!   variant is payload-free or carries only heights.
//! - **I7** — a submission is keyed by an idempotency key and stored durably;
//!   a restart resends byte-identical bytes and the same key with different
//!   bytes is a hard error. See [`outbox`].
//! - **I9** — chain evidence is interpreted only by the adapter of that chain.
//!   This crate never parses a log.
//! - **I11** — a reorg invalidates the *settlement effect*, never the publicity
//!   of a revealed scalar.
//! - **I14** — no `unwrap`/`expect`/panic on untrusted input, every length
//!   capped before allocation, no trailing bytes ignored.
//!
//! # Gas is a named constant, not an estimate
//!
//! The contract's optimistic payout push only fires above a `gasleft()` floor,
//! and the path *below* that floor succeeds. `eth_estimateGas` searches for the
//! lowest succeeding limit and therefore always picks the degraded branch. See
//! [`gas`] for the measured figures and the limits this harness supplies
//! instead.
//!
//! # Offline by construction
//!
//! The default build reaches no network: the offline suite drives
//! `adapter_evm::mock::MockChain` and `dom-sim`. The Anvil end-to-end tests are
//! `#[ignore]`d unless `F3_ANVIL_RPC` is set and need the `rpc-http` feature.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod evm_sim;
pub mod gas;
pub mod outbox;
pub mod port;
pub mod routes;
pub mod seam;
pub mod shared;
pub mod timelock;

pub use error::{HarnessError, Result};
pub use evm_sim::{MockBroadcaster, RecordingBroadcaster, RefusingBroadcaster};
pub use gas::{
    settlement_gas_limit, ERC20_CLAIM_ESTIMATED_GAS, ERC20_CLAIM_PUSH_GAS,
    ERC20_SETTLEMENT_GAS_LIMIT, NATIVE_CLAIM_ESTIMATED_GAS, NATIVE_CLAIM_PUSH_GAS,
    NATIVE_SETTLEMENT_GAS_LIMIT,
};
pub use outbox::{
    idempotency_key, IdempotencyKey, MemoryLog, Outbox, OutboxError, OutboxLog, StoreLog,
    SubmissionIntent,
};
pub use port::{
    BroadcastOutcome, Broadcaster, ChainClock, EvmChainPort, EvmPortConfig, FixedClock, PortStats,
};
pub use routes::{
    build_claim_call, build_refund_call, dom_to_evm, evm_to_dom, evm_to_dom_from_evidence,
    rederive, refund_after_deadline, verify_scalar_opens_both_commitments, DomClaimAuthorisation,
    DomToEvmInput, EvmDeployment, EvmEvidenceToDomInput, EvmToDomInput,
};
pub use seam::DomLegOps;
pub use shared::SharedRpc;
pub use timelock::{bridge, DeclaredDomainBridge, TimelockError, TimelockPoint, TimelockPolicy};

/// The DOM leg, reused verbatim from the ratified G-F2 harness.
///
/// Re-exported rather than reimplemented: the DOM-side chain semantics this
/// harness needs (funding/claim/refund observation as `ChainRecordV1`, timelock
/// by height, byte-identical dedupe, injectable reorg) are exactly what
/// `f2-harness` already drives as a §24 `ChainSourceV1`/`EffectSinkV1`, and a
/// second copy could drift from it. This is the single-engine, one-authority
/// guarantee: F2, F3 and F5 all settle through the same ratified engine.
pub use f2_harness::{SimEffectSink, SimSettlementChain};

/// Submits the authorised DOM claim to the dom-sim leg.
///
/// Deliberately a separate step from [`routes::evm_to_dom`]: the route can only
/// produce a [`routes::DomClaimAuthorisation`] when the DOM leg actually
/// adapted the pre-signature, so there is no code path that submits a DOM claim
/// without one. When the DOM leg refuses, this function is never reached.
///
/// The claim closes the same lock the authorisation names; the reused
/// `SimSettlementChain` is scoped to exactly one lock, so a mismatched
/// authorisation is refused rather than applied to the wrong lock.
pub fn submit_dom_claim(
    dom: &SimSettlementChain,
    authorisation: &DomClaimAuthorisation,
    revealed: &counterparty_api::RevealedSecretBytes,
) -> adapter_dom_sim::SubmitResult {
    if authorisation.lock_id != dom.lock_id() {
        return adapter_dom_sim::SubmitResult::Rejected(adapter_dom_sim::RejectReason::UnknownLock);
    }
    dom.submit_claim(revealed.expose_scalar_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaystra_core::settlement_engine::ChainSourceV1;
    use kaystra_core::types::ChainId;

    #[test]
    fn the_dom_leg_is_the_ratified_f2_one() {
        // A statement asserted so it is visible in the report: this harness
        // reuses the G-F2 §24 chain source rather than a second copy, so F2 and
        // F3 settle through one ratified engine.
        let chain = SimSettlementChain::new(ChainId([0xAD; 32]), [0x11; 32]);
        chain.advance(2);
        assert_eq!(
            ChainSourceV1::tip_height(&chain),
            Ok(2),
            "the reused DOM leg must still behave like the F2 one"
        );
    }
}

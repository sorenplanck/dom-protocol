//! Composed cross-chain route binding — NOT RATIFIED.
//!
//! One route `X -> DOM -> Y` (Foundation Document §1.2: the DOM is the hub)
//! is TWO settlements sharing ONE adaptor point `T = t*G`:
//!
//! - the **upstream** settlement (the user's input side), and
//! - the **downstream** settlement (the user's output side, whose claim
//!   publishes `t` on its chain).
//!
//! The secret of one leg IS the key of the other: claiming the downstream
//! leg reveals the scalar `t` that opens the upstream leg. Nothing in any
//! message layer can add to that guarantee — the composed-route proofs
//! (levels 1-3, `laboratory/reports/COMPOSED_ROUTES_FEASIBILITY.md`) bind
//! the legs only through `T`, and this crate keeps that honest picture:
//! it never couples the two engines, it only REFUSES compositions whose
//! cryptographic and timing preconditions do not hold.
//!
//! ## What binding enforces, all fail-closed with named refusals (I13)
//!
//! 1. **One `T`, on the curve, byte for byte.** Both settlements' terms
//!    must commit the same SEC1-compressed adaptor point; the point must
//!    decode to a real curve point (checked through the same secp helper
//!    the EVM leg uses — I15); and each terms object must be valid on its
//!    own ([`kaystra_core::terms::SettlementTermsV1::validate`]).
//! 2. **One hub.** Both DOM legs must sit on the SAME DOM chain — the
//!    hub of §1.2 is one chain, and only deadlines on one chain share a
//!    clock.
//! 3. **The timelock ladder, compared only inside one clock.** Deadlines
//!    on different chains do not share a clock — the same height number
//!    means different times on chains with different block intervals —
//!    so the ladder is enforced pairwise where a clock IS shared, and
//!    refuses everything else (A4: compare, never convert):
//!    - the two DOM-leg deadlines (same hub chain, one clock): upstream
//!      must mature at least `hub_margin` after downstream;
//!    - the two counterparty-leg deadlines: comparable when both are
//!      `TimestampSeconds` (the clock every chain shares), or when both
//!      legs sit on the SAME counterparty chain with the same variant;
//!      upstream must mature at least `counterparty_margin` after
//!      downstream. Heights on two different counterparty chains refuse.
//!
//!    Each settlement's own DOM↔counterparty window is that settlement's
//!    M.8 business (`bind_and_validate_funding_anchors`, the validator
//!    that produced `UnsafeCrossChainWindow` in B-F7-013) and is NOT
//!    re-implemented here; with each settlement internally coherent, the
//!    two same-clock pair checks order the whole route.
//! 4. **DOM transit conservation.** The DOM amount leaving the upstream
//!    settlement equals the DOM amount entering the downstream one —
//!    funds transit the hub, they do not rest there (swap-tab design
//!    premise 1, agreed with the operator).
//!
//! ## What the runtime gates enforce
//!
//! 5. **The funding order** ([`authorize_funding`]). No chain is touched
//!    before BOTH refunds are armed (I5, lifted to the composition); the
//!    downstream leg — the one whose claim reveals `t` — funds LAST, and
//!    only after the upstream funding is CONFIRMED (`Settling`, i.e. the
//!    upstream finality policy is already satisfied; a reorg deeper than
//!    that policy is the per-settlement recovery's domain, not a window
//!    this gate can close).
//! 6. **The hand-off** ([`ComposedBindingV1::verify_revealed_scalar`]).
//!    A scalar observed on the downstream chain is released to the
//!    upstream claim only if `t*G` equals the committed `T` — recomputed
//!    through the same secp helper the EVM leg uses (I15), never a
//!    second implementation. A wrong scalar is refused by name and never
//!    propagated.
//! 7. **The composed fee, once.** The treasury share is the composed
//!    rate over the transit amount, charged once per route
//!    ([`rfq::fee_policy`]), never the simple rate twice.
//!
//! The binding digest is `BLAKE2b-256(domain || len(up) || up-canonical
//! || len(dn) || dn-canonical || hub_margin || counterparty_margin)` —
//! the A3 pattern, with each variable-length encoding length-prefixed so
//! no byte can migrate across the upstream/downstream boundary without
//! changing the digest.
//!
//! The revealed scalar `t` lives only in zeroizing memory here, is never
//! logged, never encoded and never stored — the durable stores are the
//! engines' business and the level-2 proof sweeps both for `t` (spec §18
//! / I1); the integration test of this crate repeats that sweep.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::state::SettlementState;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{Digest32, TimelockSpec};
use rfq::fee_policy::{treasury_share, FeePolicyRefusal, RouteShapeV1};
use zeroize::Zeroizing;

/// Domain tag of [`ComposedBindingV1::binding_digest`] (A3 pattern:
/// `BLAKE2b-256(domain || canonical bytes)`, same construction as
/// `SettlementTermsV1::terms_hash` and the F6 object digests).
pub const COMPOSED_BINDING_DOMAIN: &[u8] = b"DOM-INTEROP/COMPOSED-BINDING/V1\0";

/// Everything a composition can refuse, by name (I13). Every refusal is
/// terminal for the attempted step: there is no partial composition.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ComposerRefusal {
    /// One of the two terms objects fails its own validation.
    #[error("invalid settlement terms")]
    InvalidTerms,
    /// The committed adaptor point does not decode to a curve point.
    #[error("invalid adaptor point")]
    InvalidAdaptorPoint,
    /// The two settlements do not commit the same adaptor point.
    #[error("adaptor point mismatch")]
    AdaptorPointMismatch,
    /// The two settlements are not distinct (same settlement id or same
    /// session id): a route needs two independent escape hatches.
    #[error("settlements not distinct")]
    SettlementsNotDistinct,
    /// The two DOM legs sit on different chains. The hub is ONE chain;
    /// two "DOM" clocks cannot anchor one ladder.
    #[error("hub chain mismatch")]
    HubChainMismatch,
    /// A same-clock deadline pair spans two `TimelockSpec` variants.
    /// A4: deadlines are compared, never converted.
    #[error("mixed timelock domains")]
    MixedTimelockDomains,
    /// The counterparty deadlines are heights on two DIFFERENT chains:
    /// height numbers on different chains do not share a clock, and a
    /// ladder over them would be cryptographically meaningless. Express
    /// both as `TimestampSeconds`, or keep both legs on one chain.
    #[error("cross-chain clock mismatch")]
    CrossChainClockMismatch,
    /// The upstream refund window opens too early on a shared clock:
    /// this is the window in which one leg could refund while the other
    /// still settles — the exact scenario composition must make
    /// impossible.
    #[error("unsafe composed window")]
    UnsafeComposedWindow,
    /// An explicit safety margin is zero. The margins are the composed
    /// analogue of `CrossChainWindowV1::safety_margin_seconds` (M.8):
    /// each must be a real, positive budget.
    #[error("zero safety margin")]
    ZeroSafetyMargin,
    /// The DOM amount leaving the upstream settlement differs from the
    /// DOM amount entering the downstream one.
    #[error("dom transit mismatch")]
    DomTransitMismatch,
    /// A funding step was requested out of order (see
    /// [`authorize_funding`] for the only permitted order).
    #[error("funding out of order")]
    FundingOutOfOrder,
    /// The observed scalar does not open the committed point: `t*G` is
    /// not `T`, or `t` is not a canonical secp256k1 scalar.
    #[error("wrong secret")]
    WrongSecret,
    /// The composed fee could not be computed.
    #[error("fee policy refusal: {0}")]
    Fee(#[from] FeePolicyRefusal),
    /// Hash initialization failed (theoretical; kept named, never a panic — I14).
    #[error("hash initialization")]
    HashInitialization,
}

/// The explicit composed-window policy: how much later each upstream
/// deadline must mature than its same-clock downstream counterpart.
///
/// Explicit on purpose, like `CrossChainWindowV1.safety_margin_seconds`:
/// the budget for observing the downstream reveal, validating it and
/// broadcasting the upstream claim is POLICY, committed into the binding
/// digest — never an implicit constant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ComposedWindowPolicyV1 {
    /// Minimum distance between the downstream and upstream DOM-leg
    /// deadlines, in the hub clock's units (blocks). Must be > 0.
    pub hub_margin: u64,
    /// Minimum distance between the downstream and upstream
    /// counterparty-leg deadlines, in their shared clock's units
    /// (seconds when both are `TimestampSeconds`). Must be > 0.
    pub counterparty_margin: u64,
}

/// Which side of the composition a step refers to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ComposedLeg {
    /// The user's input settlement; claimed LAST, with the revealed `t`.
    Upstream,
    /// The user's output settlement; claimed FIRST, revealing `t`.
    Downstream,
}

/// The revealed route scalar, verified against the committed `T`.
///
/// Exists only through [`ComposedBindingV1::verify_revealed_scalar`]; the
/// bytes zeroize on drop, and `Debug` is redacted (I6: a secret is never
/// echoed).
pub struct RouteScalar(Zeroizing<[u8; 32]>);

impl RouteScalar {
    /// The scalar bytes, for the upstream claim path only.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for RouteScalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RouteScalar(REDACTED)")
    }
}

/// A validated composition of two settlements into one route.
///
/// The fields are private: the ONLY way a `ComposedBindingV1` exists is
/// through [`ComposedBindingV1::bind`], so holding one is proof that every
/// precondition in the module docs held at binding time. Fail-closed by
/// construction.
#[derive(Clone, Debug)]
pub struct ComposedBindingV1 {
    upstream: SettlementTermsV1,
    downstream: SettlementTermsV1,
    policy: ComposedWindowPolicyV1,
    binding_digest: Digest32,
}

/// One same-clock ladder rung: `up` must mature at least `margin` after
/// `dn`, both already established to share one clock and one variant.
fn rung_holds(up: u64, dn: u64, margin: u64) -> bool {
    up >= dn.saturating_add(margin)
}

impl ComposedBindingV1 {
    /// Validate and freeze a composition. Every refusal is terminal;
    /// nothing about a refused composition is usable.
    pub fn bind(
        upstream: SettlementTermsV1,
        downstream: SettlementTermsV1,
        policy: ComposedWindowPolicyV1,
    ) -> Result<Self, ComposerRefusal> {
        // 0. The explicit margins must be real budgets.
        if policy.hub_margin == 0 || policy.counterparty_margin == 0 {
            return Err(ComposerRefusal::ZeroSafetyMargin);
        }

        // 1. Each settlement must be valid on its own terms.
        upstream
            .validate()
            .map_err(|_| ComposerRefusal::InvalidTerms)?;
        downstream
            .validate()
            .map_err(|_| ComposerRefusal::InvalidTerms)?;

        // 2. Two independent settlements, not one wearing two hats.
        if upstream.settlement_id == downstream.settlement_id
            || upstream.session_id == downstream.session_id
        {
            return Err(ComposerRefusal::SettlementsNotDistinct);
        }

        // 3. One T, byte for byte, and ON THE CURVE. The byte comparison
        //    makes the two settlements one route; the curve check makes
        //    the committed point openable at all — a malformed T would
        //    leave both legs claimable by no one (refund-only), which is
        //    safe but must refuse at binding, not at claim time.
        if upstream.adaptor_point_sec1 != downstream.adaptor_point_sec1 {
            return Err(ComposerRefusal::AdaptorPointMismatch);
        }
        adapter_evm::binding::adaptor_address(&upstream.adaptor_point_sec1)
            .map_err(|_| ComposerRefusal::InvalidAdaptorPoint)?;

        // 4. One hub: both DOM legs on the same chain, or no shared
        //    clock exists for the hub rung of the ladder.
        if upstream.dom_leg.chain_id != downstream.dom_leg.chain_id {
            return Err(ComposerRefusal::HubChainMismatch);
        }

        // 5. The ladder, pairwise inside one clock (module docs §3).
        //    Hub rung: same chain by check 4, so one clock; same variant
        //    required (A4), upstream >= downstream + hub_margin.
        match (upstream.dom_leg.deadline, downstream.dom_leg.deadline) {
            (TimelockSpec::BlockHeight { value: up }, TimelockSpec::BlockHeight { value: dn }) => {
                if !rung_holds(up, dn, policy.hub_margin) {
                    return Err(ComposerRefusal::UnsafeComposedWindow);
                }
            }
            (
                TimelockSpec::TimestampSeconds { value: up },
                TimelockSpec::TimestampSeconds { value: dn },
            ) => {
                if !rung_holds(up, dn, policy.hub_margin) {
                    return Err(ComposerRefusal::UnsafeComposedWindow);
                }
            }
            _ => return Err(ComposerRefusal::MixedTimelockDomains),
        }
        //    Counterparty rung: seconds are the clock every chain
        //    shares; heights are one clock only on ONE chain.
        match (
            upstream.counterparty_leg.deadline,
            downstream.counterparty_leg.deadline,
        ) {
            (
                TimelockSpec::TimestampSeconds { value: up },
                TimelockSpec::TimestampSeconds { value: dn },
            ) => {
                if !rung_holds(up, dn, policy.counterparty_margin) {
                    return Err(ComposerRefusal::UnsafeComposedWindow);
                }
            }
            (TimelockSpec::BlockHeight { value: up }, TimelockSpec::BlockHeight { value: dn }) => {
                if upstream.counterparty_leg.chain_id != downstream.counterparty_leg.chain_id {
                    return Err(ComposerRefusal::CrossChainClockMismatch);
                }
                if !rung_holds(up, dn, policy.counterparty_margin) {
                    return Err(ComposerRefusal::UnsafeComposedWindow);
                }
            }
            _ => return Err(ComposerRefusal::MixedTimelockDomains),
        }

        // 6. DOM transit conservation: what leaves the hub is what
        //    entered it.
        if upstream.dom_leg.amount != downstream.dom_leg.amount {
            return Err(ComposerRefusal::DomTransitMismatch);
        }

        // 7. Freeze: BLAKE2b-256(domain || len || up canonical || len ||
        //    dn canonical || margins BE). Length prefixes make the
        //    upstream/downstream boundary unambiguous; only valid terms
        //    encode, so the digest exists only for a composition that
        //    passed every check above.
        let up_bytes = upstream
            .canonical_bytes()
            .map_err(|_| ComposerRefusal::InvalidTerms)?;
        let dn_bytes = downstream
            .canonical_bytes()
            .map_err(|_| ComposerRefusal::InvalidTerms)?;
        let mut h = Blake2bVar::new(32).map_err(|_| ComposerRefusal::HashInitialization)?;
        h.update(COMPOSED_BINDING_DOMAIN);
        h.update(&(up_bytes.len() as u64).to_be_bytes());
        h.update(&up_bytes);
        h.update(&(dn_bytes.len() as u64).to_be_bytes());
        h.update(&dn_bytes);
        h.update(&policy.hub_margin.to_be_bytes());
        h.update(&policy.counterparty_margin.to_be_bytes());
        let mut binding_digest = [0u8; 32];
        h.finalize_variable(&mut binding_digest)
            .map_err(|_| ComposerRefusal::HashInitialization)?;

        Ok(Self {
            upstream,
            downstream,
            policy,
            binding_digest,
        })
    }

    /// The upstream settlement's frozen terms.
    pub fn upstream(&self) -> &SettlementTermsV1 {
        &self.upstream
    }

    /// The downstream settlement's frozen terms.
    pub fn downstream(&self) -> &SettlementTermsV1 {
        &self.downstream
    }

    /// The explicit window policy committed into the digest.
    pub fn policy(&self) -> ComposedWindowPolicyV1 {
        self.policy
    }

    /// The shared adaptor point `T`, SEC1 compressed.
    pub fn adaptor_point_sec1(&self) -> [u8; 33] {
        self.upstream.adaptor_point_sec1
    }

    /// The binding digest: commits both settlements' canonical bytes
    /// (length-prefixed) and the window policy.
    pub fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }

    /// The hand-off: accept a scalar observed on the downstream chain
    /// only if it opens the committed point.
    ///
    /// `t*G` is recomputed through `adapter_evm::binding` — the same secp
    /// helper the EVM contract check, the level-1 proof and the level-2
    /// engine proof already rely on (I15) — and compared byte-for-byte
    /// with the SEC1 `T` both settlements committed. A non-canonical or
    /// wrong scalar refuses by name and never leaves this function.
    pub fn verify_revealed_scalar(
        &self,
        observed: &[u8; 32],
    ) -> Result<RouteScalar, ComposerRefusal> {
        let point = adapter_evm::binding::adaptor_point_of_scalar(observed)
            .map_err(|_| ComposerRefusal::WrongSecret)?;
        if point != self.upstream.adaptor_point_sec1 {
            return Err(ComposerRefusal::WrongSecret);
        }
        Ok(RouteScalar(Zeroizing::new(*observed)))
    }

    /// The composed treasury share over the DOM transit amount, charged
    /// once per route (fee ADR: the solver pays it and prices it into
    /// the quote; `fee_policy`: composed rate once, never simple twice).
    pub fn composed_treasury_share(&self) -> Result<u128, ComposerRefusal> {
        Ok(treasury_share(
            self.upstream.dom_leg.amount,
            RouteShapeV1::Composed,
        )?)
    }
}

/// The ONLY permitted funding order of a composition.
///
/// - **Upstream funds first**, and only when BOTH settlements have their
///   refund armed (`ReadyToFund`): no chain is committed before both
///   escape hatches exist (I5, lifted to the composition).
/// - **Downstream funds last**, and only when the upstream funding is
///   confirmed (`Settling`, i.e. the upstream finality policy already
///   held): the leg whose claim reveals `t` must be the last to lock, so
///   `t` can never become claimable while the upstream leg is still
///   unfunded. A reorg deeper than the upstream finality policy after
///   this gate is the per-settlement recovery's domain — no message
///   layer can close that window, only the policy's depth.
///
/// Everything else refuses. The caller drives its two engines; this
/// function is the gate it must pass before dispatching each funding.
pub fn authorize_funding(
    leg: ComposedLeg,
    upstream_state: SettlementState,
    downstream_state: SettlementState,
) -> Result<(), ComposerRefusal> {
    match leg {
        ComposedLeg::Upstream => {
            if upstream_state == SettlementState::ReadyToFund
                && downstream_state == SettlementState::ReadyToFund
            {
                Ok(())
            } else {
                Err(ComposerRefusal::FundingOutOfOrder)
            }
        }
        ComposedLeg::Downstream => {
            if downstream_state == SettlementState::ReadyToFund
                && upstream_state == SettlementState::Settling
            {
                Ok(())
            } else {
                Err(ComposerRefusal::FundingOutOfOrder)
            }
        }
    }
}

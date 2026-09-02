//! Composed cross-chain route binding — RATIFIED (explicit operator
//! decision, 2026-09-02; the signed register is
//! `docs/interop/ratifications/e13-executadas/RATIFICACAO-DECISOES-EXECUTADAS-v2.md`
//! §2.1, kept local by policy).
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
//!    hub of §1.2 is one chain, use the same DOM asset and adapter profile,
//!    and both use the DOM adaptor 2-of-2 mechanism. Only deadlines on one
//!    chain share a clock.
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
//! 4. **DOM transit conservation.** Both settlements execute the same route
//!    intent under one policy version, require refund-before-funding, and the
//!    DOM asset and amount leaving the upstream settlement equal the asset and
//!    amount entering the downstream one. A numeric amount without its asset
//!    denomination is never conservation.
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
//! V2 is an explicit, separate constructor for mixed native clocks. Its
//! digest additionally commits the complete threshold-signed policy digest,
//! fresh evidence digest and sequence, issuance/freshness boundary, final
//! durable-store revalidation time, and both worst-case interval proofs. A V2
//! binding is an authenticated admission snapshot, not permission to fund
//! after its exposed `valid_until`; every later economic action still needs a
//! current capability from the durable time authority.
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
pub use dom_final_claim_binding::{
    ComposedFinalClaimRolePlanInputV1, ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1,
    FinalClaimBindingError, FinalClaimRevealModeV1, FinalClaimRoleSelectionV1,
    FinalClaimSecretSourceScopeInputV1, FinalClaimSecretSourceScopeV1, FinalClaimSecretSourceV1,
    COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN, FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN,
};
use kaystra_core::state::SettlementState;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{Digest32, TimelockSpec};
use rfq::fee_policy::{treasury_share, FeePolicyRefusal, RouteShapeV1};
use route_time_anchor::{
    route_scope_digest, CurrentRouteTimeLadderV2, LadderIntervalProofV2,
    VerifiedFrozenRouteTimeLadderV2,
};
use zeroize::Zeroizing;

/// Domain tag of [`ComposedBindingV1::binding_digest`] (A3 pattern:
/// `BLAKE2b-256(domain || canonical bytes)`, same construction as
/// `SettlementTermsV1::terms_hash` and the F6 object digests).
pub const COMPOSED_BINDING_DOMAIN: &[u8] = b"DOM-INTEROP/COMPOSED-BINDING/V1\0";

/// Domain tag for [`ComposedBindingV2::binding_digest`]. V2 commits the exact
/// authenticated time policy, live evidence and conservative interval proof;
/// it never changes the byte format or acceptance rules of V1.
pub const COMPOSED_BINDING_DOMAIN_V2: &[u8] = b"DOM-INTEROP/COMPOSED-BINDING/V2\0";

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
    /// The two DOM legs name different assets, so equal integers do not
    /// represent conserved value.
    #[error("hub asset mismatch")]
    HubAssetMismatch,
    /// The two DOM legs were interpreted under different adapter profiles.
    #[error("hub adapter profile mismatch")]
    HubProfileMismatch,
    /// A DOM leg does not use the scriptless adaptor 2-of-2 mechanism.
    #[error("invalid DOM hub locking mechanism")]
    InvalidHubMechanism,
    /// The two settlements do not execute the same originating route intent.
    #[error("route intent mismatch")]
    RouteIntentMismatch,
    /// The two settlements interpret their fields under different policies.
    #[error("route policy version mismatch")]
    RoutePolicyMismatch,
    /// One settlement does not commit to arming its refund before funding.
    #[error("refund-before-funding policy is required")]
    UnsafeRecoveryPolicy,
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
    /// The supplied time capability was issued for different settlement
    /// terms or for the opposite upstream/downstream order.
    #[error("authenticated route time scope mismatch")]
    TimeAnchorMismatch,
    /// The explicit bilateral FinalClaim roles or source scopes do not bind
    /// byte-exactly to this composition and its two settlement terms.
    #[error("invalid composed final-claim role plan")]
    InvalidFinalClaimRolePlan,
    /// The opaque time capability contains a zero, reversed, overflowing or
    /// otherwise non-conservative ladder commitment.
    #[error("invalid authenticated route time proof")]
    InvalidTimeAnchorProof,
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
/// Exists only through a verified V1 or V2 binding's
/// `verify_revealed_scalar` method; the bytes zeroize on drop, and `Debug` is
/// redacted (I6: a secret is never echoed).
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
    dn.checked_add(margin)
        .is_some_and(|minimum_upstream| up >= minimum_upstream)
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

        if upstream.intent_hash != downstream.intent_hash {
            return Err(ComposerRefusal::RouteIntentMismatch);
        }
        if upstream.policy_version != downstream.policy_version {
            return Err(ComposerRefusal::RoutePolicyMismatch);
        }
        if !upstream.recovery.refund_before_funding || !downstream.recovery.refund_before_funding {
            return Err(ComposerRefusal::UnsafeRecoveryPolicy);
        }

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
        if upstream.dom_leg.asset_id != downstream.dom_leg.asset_id {
            return Err(ComposerRefusal::HubAssetMismatch);
        }
        if upstream.dom_leg.adapter_profile_hash != downstream.dom_leg.adapter_profile_hash {
            return Err(ComposerRefusal::HubProfileMismatch);
        }
        if upstream.dom_leg.mechanism != kaystra_core::types::LockMechanism::DomAdaptor2of2
            || downstream.dom_leg.mechanism != kaystra_core::types::LockMechanism::DomAdaptor2of2
        {
            return Err(ComposerRefusal::InvalidHubMechanism);
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

        // 6. DOM transit conservation: chain, asset and profile were already
        //    proven identical; now require the denominated quantities to
        //    match as well.
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

/// A composition whose mixed native timelocks were compared only through a
/// fresh, threshold-authenticated V2 time capability.
///
/// Unlike [`ComposedBindingV1`], this binding can represent a three-chain
/// `EVM -> DOM -> Bitcoin` route. It does not convert clocks itself. New
/// admission consumes [`CurrentRouteTimeLadderV2`], which can be minted only by
/// the exclusively locked durable route-time authority after authenticating
/// registry profiles, fixed canonical checkpoints, timing bounds, freshness
/// and the current evidence revision. Recovery consumes only the separate
/// opaque [`VerifiedFrozenRouteTimeLadderV2`] reconstructed from the exact
/// historical policy/evidence retained by that authority.
#[derive(Debug)]
pub struct ComposedBindingV2 {
    upstream: SettlementTermsV1,
    downstream: SettlementTermsV1,
    route_scope_digest: Digest32,
    time_policy_digest: Digest32,
    time_evidence_digest: Digest32,
    time_proof_digest: Digest32,
    evidence_sequence: u64,
    time_proof_issued_at_seconds: u64,
    time_proof_valid_until_seconds: u64,
    time_proof_validated_at_seconds: u64,
    hub_time_proof: LadderIntervalProofV2,
    counterparty_time_proof: LadderIntervalProofV2,
    binding_digest: Digest32,
}

impl ComposedBindingV2 {
    /// Validates the non-temporal route invariants and consumes an exact,
    /// authenticated worst-case ladder proof for these two terms.
    ///
    /// The proof is move-only. A different terms byte, reversed leg order,
    /// zero digest, reversed interval or overflowing inequality fails closed.
    pub fn bind(
        upstream: SettlementTermsV1,
        downstream: SettlementTermsV1,
        time_proof: CurrentRouteTimeLadderV2<'_>,
    ) -> Result<Self, ComposerRefusal> {
        let facts = V2TimeProofFacts::from(&time_proof);
        Self::bind_with_time_facts(upstream, downstream, facts)
    }

    /// Reconstructs the exact original binding from a historically verified
    /// ladder proof recovered by the durable time authority.
    ///
    /// This constructor does not authorize new funding and performs no current
    /// freshness check. It consumes an opaque proof whose signed policy,
    /// evidence row, issuance window and conservative rungs were rederived
    /// against retained history. Both constructors share this type's single
    /// invariant and digest implementation, so recovery cannot silently use a
    /// second composition format.
    pub fn bind_recovered(
        upstream: SettlementTermsV1,
        downstream: SettlementTermsV1,
        time_proof: VerifiedFrozenRouteTimeLadderV2,
    ) -> Result<Self, ComposerRefusal> {
        let facts = V2TimeProofFacts::from(&time_proof);
        Self::bind_with_time_facts(upstream, downstream, facts)
    }

    fn bind_with_time_facts(
        upstream: SettlementTermsV1,
        downstream: SettlementTermsV1,
        time_proof: V2TimeProofFacts,
    ) -> Result<Self, ComposerRefusal> {
        validate_v2_route_shape(&upstream, &downstream)?;

        let upstream_terms_hash = upstream
            .terms_hash()
            .map_err(|_| ComposerRefusal::InvalidTerms)?;
        let downstream_terms_hash = downstream
            .terms_hash()
            .map_err(|_| ComposerRefusal::InvalidTerms)?;
        let route_scope_digest = route_scope_digest(&upstream, &downstream)
            .map_err(|_| ComposerRefusal::TimeAnchorMismatch)?;
        if time_proof.upstream_terms_hash != upstream_terms_hash
            || time_proof.downstream_terms_hash != downstream_terms_hash
            || time_proof.route_scope_digest != route_scope_digest
        {
            return Err(ComposerRefusal::TimeAnchorMismatch);
        }

        let time_policy_digest = time_proof.policy_digest;
        let time_evidence_digest = time_proof.evidence_digest;
        let time_proof_digest = time_proof.binding_digest;
        let evidence_sequence = time_proof.evidence_sequence;
        let time_proof_issued_at_seconds = time_proof.issued_at_seconds;
        let time_proof_valid_until_seconds = time_proof.valid_until_seconds;
        let time_proof_validated_at_seconds = time_proof.validated_at_seconds;
        let hub_time_proof = time_proof.hub;
        let counterparty_time_proof = time_proof.counterparty;
        if time_policy_digest == [0; 32]
            || time_evidence_digest == [0; 32]
            || time_proof_digest == [0; 32]
            || evidence_sequence == 0
            || time_proof_validated_at_seconds < time_proof_issued_at_seconds
            || time_proof_validated_at_seconds >= time_proof_valid_until_seconds
            || !time_rung_is_conservative(hub_time_proof)
            || !time_rung_is_conservative(counterparty_time_proof)
        {
            return Err(ComposerRefusal::InvalidTimeAnchorProof);
        }

        let upstream_bytes = upstream
            .canonical_bytes()
            .map_err(|_| ComposerRefusal::InvalidTerms)?;
        let downstream_bytes = downstream
            .canonical_bytes()
            .map_err(|_| ComposerRefusal::InvalidTerms)?;
        let upstream_len =
            u64::try_from(upstream_bytes.len()).map_err(|_| ComposerRefusal::InvalidTerms)?;
        let downstream_len =
            u64::try_from(downstream_bytes.len()).map_err(|_| ComposerRefusal::InvalidTerms)?;
        let mut hash = Blake2bVar::new(32).map_err(|_| ComposerRefusal::HashInitialization)?;
        hash.update(COMPOSED_BINDING_DOMAIN_V2);
        hash.update(&upstream_len.to_be_bytes());
        hash.update(&upstream_bytes);
        hash.update(&downstream_len.to_be_bytes());
        hash.update(&downstream_bytes);
        hash.update(&route_scope_digest);
        hash.update(&time_policy_digest);
        hash.update(&time_evidence_digest);
        hash.update(&time_proof_digest);
        hash.update(&evidence_sequence.to_be_bytes());
        hash.update(&time_proof_issued_at_seconds.to_be_bytes());
        hash.update(&time_proof_valid_until_seconds.to_be_bytes());
        hash.update(&time_proof_validated_at_seconds.to_be_bytes());
        update_time_rung_digest(&mut hash, hub_time_proof);
        update_time_rung_digest(&mut hash, counterparty_time_proof);
        let mut binding_digest = [0u8; 32];
        hash.finalize_variable(&mut binding_digest)
            .map_err(|_| ComposerRefusal::HashInitialization)?;

        Ok(Self {
            upstream,
            downstream,
            route_scope_digest,
            time_policy_digest,
            time_evidence_digest,
            time_proof_digest,
            evidence_sequence,
            time_proof_issued_at_seconds,
            time_proof_valid_until_seconds,
            time_proof_validated_at_seconds,
            hub_time_proof,
            counterparty_time_proof,
            binding_digest,
        })
    }

    /// The upstream settlement's exact frozen terms.
    pub fn upstream(&self) -> &SettlementTermsV1 {
        &self.upstream
    }

    /// The downstream settlement's exact frozen terms.
    pub fn downstream(&self) -> &SettlementTermsV1 {
        &self.downstream
    }

    /// Length-delimited digest of the ordered upstream/downstream terms.
    pub const fn route_scope_digest(&self) -> Digest32 {
        self.route_scope_digest
    }

    /// Digest of the threshold-authenticated static timing policy.
    pub const fn time_policy_digest(&self) -> Digest32 {
        self.time_policy_digest
    }

    /// Digest of the fresh threshold-authenticated checkpoint evidence.
    pub const fn time_evidence_digest(&self) -> Digest32 {
        self.time_evidence_digest
    }

    /// Digest of the exact worst-case ladder capability consumed at binding.
    pub const fn time_proof_digest(&self) -> Digest32 {
        self.time_proof_digest
    }

    /// Monotonic checkpoint-evidence sequence used for this binding.
    pub const fn evidence_sequence(&self) -> u64 {
        self.evidence_sequence
    }

    /// Trusted second at which the time authority issued the consumed proof.
    pub const fn time_proof_issued_at_seconds(&self) -> u64 {
        self.time_proof_issued_at_seconds
    }

    /// First trusted second at which freshness or a relative funding-anchor
    /// horizon makes this binding unusable for a new economic action.
    pub const fn time_proof_valid_until_seconds(&self) -> u64 {
        self.time_proof_valid_until_seconds
    }

    /// Trusted second of the final durable-store revalidation immediately
    /// consumed by this binding.
    pub const fn time_proof_validated_at_seconds(&self) -> u64 {
        self.time_proof_validated_at_seconds
    }

    /// Proven DOM-height rung projected to conservative absolute seconds.
    pub const fn hub_time_proof(&self) -> LadderIntervalProofV2 {
        self.hub_time_proof
    }

    /// Proven mixed counterparty rung projected to conservative seconds.
    pub const fn counterparty_time_proof(&self) -> LadderIntervalProofV2 {
        self.counterparty_time_proof
    }

    /// Shared adaptor point `T`, SEC1 compressed.
    pub fn adaptor_point_sec1(&self) -> [u8; 33] {
        self.upstream.adaptor_point_sec1
    }

    /// Final V2 commitment to exact terms, policy, evidence and both interval
    /// inequalities.
    pub const fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }

    /// Bind explicit bilateral FinalClaim roles and already constructed
    /// source scopes to this exact composition.
    ///
    /// No role or claim template is inferred from roster position, transport
    /// direction, or upstream/downstream position.  Both selections are
    /// authenticated against their exact settlement terms, shared `T`, route
    /// scope, and this binding digest.
    pub fn bind_final_claim_role_plan(
        &self,
        route_id: Digest32,
        upstream_explicit: FinalClaimRoleSelectionV1,
        downstream_explicit: FinalClaimRoleSelectionV1,
    ) -> Result<ComposedFinalClaimRolePlanV1, ComposerRefusal> {
        ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
            route_id,
            route_scope_digest: self.route_scope_digest,
            composition_binding_digest: self.binding_digest,
            upstream_terms: &self.upstream,
            downstream_terms: &self.downstream,
            upstream_selection: upstream_explicit,
            downstream_selection: downstream_explicit,
        })
        .map_err(|_| ComposerRefusal::InvalidFinalClaimRolePlan)
    }

    /// Accepts a revealed scalar only when `t*G` is the route's committed
    /// adaptor point.
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

    /// Composed treasury share over the DOM transit amount, charged once.
    pub fn composed_treasury_share(&self) -> Result<u128, ComposerRefusal> {
        Ok(treasury_share(
            self.upstream.dom_leg.amount,
            RouteShapeV1::Composed,
        )?)
    }
}

#[derive(Clone, Copy)]
struct V2TimeProofFacts {
    upstream_terms_hash: Digest32,
    downstream_terms_hash: Digest32,
    route_scope_digest: Digest32,
    policy_digest: Digest32,
    evidence_digest: Digest32,
    binding_digest: Digest32,
    evidence_sequence: u64,
    issued_at_seconds: u64,
    valid_until_seconds: u64,
    validated_at_seconds: u64,
    hub: LadderIntervalProofV2,
    counterparty: LadderIntervalProofV2,
}

impl From<&CurrentRouteTimeLadderV2<'_>> for V2TimeProofFacts {
    fn from(proof: &CurrentRouteTimeLadderV2<'_>) -> Self {
        Self {
            upstream_terms_hash: proof.upstream_terms_hash(),
            downstream_terms_hash: proof.downstream_terms_hash(),
            route_scope_digest: proof.route_scope_digest(),
            policy_digest: proof.policy_digest(),
            evidence_digest: proof.evidence_digest(),
            binding_digest: proof.binding_digest(),
            evidence_sequence: proof.evidence_sequence(),
            issued_at_seconds: proof.issued_at_seconds(),
            valid_until_seconds: proof.valid_until_seconds(),
            validated_at_seconds: proof.validated_at_seconds(),
            hub: proof.hub_proof(),
            counterparty: proof.counterparty_proof(),
        }
    }
}

impl From<&VerifiedFrozenRouteTimeLadderV2> for V2TimeProofFacts {
    fn from(proof: &VerifiedFrozenRouteTimeLadderV2) -> Self {
        Self {
            upstream_terms_hash: proof.upstream_terms_hash(),
            downstream_terms_hash: proof.downstream_terms_hash(),
            route_scope_digest: proof.route_scope_digest(),
            policy_digest: proof.policy_digest(),
            evidence_digest: proof.evidence_digest(),
            binding_digest: proof.binding_digest(),
            evidence_sequence: proof.evidence_sequence(),
            issued_at_seconds: proof.issued_at_seconds(),
            valid_until_seconds: proof.valid_until_seconds(),
            validated_at_seconds: proof.validated_at_seconds(),
            hub: proof.hub_proof(),
            counterparty: proof.counterparty_proof(),
        }
    }
}

fn validate_v2_route_shape(
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
) -> Result<(), ComposerRefusal> {
    upstream
        .validate()
        .map_err(|_| ComposerRefusal::InvalidTerms)?;
    downstream
        .validate()
        .map_err(|_| ComposerRefusal::InvalidTerms)?;
    if upstream.intent_hash != downstream.intent_hash {
        return Err(ComposerRefusal::RouteIntentMismatch);
    }
    if upstream.policy_version != downstream.policy_version {
        return Err(ComposerRefusal::RoutePolicyMismatch);
    }
    if !upstream.recovery.refund_before_funding || !downstream.recovery.refund_before_funding {
        return Err(ComposerRefusal::UnsafeRecoveryPolicy);
    }
    if upstream.settlement_id == downstream.settlement_id
        || upstream.session_id == downstream.session_id
    {
        return Err(ComposerRefusal::SettlementsNotDistinct);
    }
    if upstream.adaptor_point_sec1 != downstream.adaptor_point_sec1 {
        return Err(ComposerRefusal::AdaptorPointMismatch);
    }
    adapter_evm::binding::adaptor_address(&upstream.adaptor_point_sec1)
        .map_err(|_| ComposerRefusal::InvalidAdaptorPoint)?;
    if upstream.dom_leg.chain_id != downstream.dom_leg.chain_id {
        return Err(ComposerRefusal::HubChainMismatch);
    }
    if upstream.dom_leg.asset_id != downstream.dom_leg.asset_id {
        return Err(ComposerRefusal::HubAssetMismatch);
    }
    if upstream.dom_leg.adapter_profile_hash != downstream.dom_leg.adapter_profile_hash {
        return Err(ComposerRefusal::HubProfileMismatch);
    }
    if upstream.dom_leg.mechanism != kaystra_core::types::LockMechanism::DomAdaptor2of2
        || downstream.dom_leg.mechanism != kaystra_core::types::LockMechanism::DomAdaptor2of2
    {
        return Err(ComposerRefusal::InvalidHubMechanism);
    }
    if upstream.dom_leg.amount != downstream.dom_leg.amount {
        return Err(ComposerRefusal::DomTransitMismatch);
    }
    Ok(())
}

fn time_rung_is_conservative(proof: LadderIntervalProofV2) -> bool {
    proof.margin_seconds != 0
        && proof.upstream.earliest_seconds <= proof.upstream.latest_seconds
        && proof.downstream.earliest_seconds <= proof.downstream.latest_seconds
        && proof
            .downstream
            .latest_seconds
            .checked_add(proof.margin_seconds)
            .is_some_and(|minimum| proof.upstream.earliest_seconds >= minimum)
}

fn update_time_rung_digest(hash: &mut Blake2bVar, proof: LadderIntervalProofV2) {
    hash.update(&proof.upstream.earliest_seconds.to_be_bytes());
    hash.update(&proof.upstream.latest_seconds.to_be_bytes());
    hash.update(&proof.downstream.earliest_seconds.to_be_bytes());
    hash.update(&proof.downstream.latest_seconds.to_be_bytes());
    hash.update(&proof.margin_seconds.to_be_bytes());
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

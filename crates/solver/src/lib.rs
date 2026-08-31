//! The reference solver — NOT RATIFIED.
//!
//! The ratified F6 machinery (`rfq`) has both sides of the market fully
//! specified — objects, admissibility (§4.1 + AD-1), the selection
//! total order (§4.3) — but until now "solver" existed in the
//! repository only as an identifier (`SolverId`). This crate is the
//! missing counterparty: it consumes an [`RfqV1`] and produces a
//! [`QuoteV1`] that the ratified admissibility ACCEPTS, or refuses by
//! name.
//!
//! What it deliberately is and is not:
//!
//! - **An explicit pricing policy, not an oracle.** The quote is priced
//!   by [`SolverPolicyV1`] — a rate, a spread and deadline offsets the
//!   operator of the solver chooses. Nothing here invents market data.
//! - **The fee ADR made operational.** The protocol fee is the
//!   solver's cost, priced into its spread ("the solver pays the fee
//!   and prices it into the quote" — the ratified answer to fee
//!   problem 1); the user still compares one number, `net_output`.
//! - **Fail-closed.** A quote that cannot meet the RFQ's own
//!   protection bound (`minimum_output` / `maximum_input`), or whose
//!   fee would break the RFQ's `fee_limit` cap, is refused HERE —
//!   never emitted for the initiator's admissibility to reject.
//! - **Signed by the pinned backend.** The BIP340 signature over
//!   `quote_id` comes from the same D-013 backend the admissibility
//!   facts verify with (I15). The secret lives in zeroizing memory and
//!   is never echoed (I6).
//! - **Bond facts are the F4 ledger's, not ours.** The exclusive bond
//!   reservation (§4.1.6-8) is an input ([`BondFactsV1`]); this crate
//!   never fabricates one.
//!
//! Arithmetic discipline: all pricing is checked u128; rounding always
//! favours the REFUSAL side — the output the user is promised rounds
//! DOWN, the fee and required input round UP — so an accepted quote can
//! only ever deliver at least what it says.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use btc_crypto::SecpContext;
use kaystra_core::types::{ChainId, Digest32, ParticipantId, TimelockSpec};
use rfq::selection::validate_dom_centrality;
use rfq::{QuoteV1, RfqModeV1, RfqV1};
use zeroize::Zeroizing;

/// Basis-point denominator of the spread.
pub const BPS_DENOMINATOR: u128 = 10_000;

/// Everything the solver can refuse, by name (I13).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SolverRefusal {
    /// The RFQ fails its own validation.
    #[error("malformed rfq")]
    MalformedRfq,
    /// The route does not contain the DOM on exactly one leg (AD-1.1).
    #[error("route excludes the dom")]
    RouteExcludesDom,
    /// The policy's rate is degenerate (a zero numerator or denominator).
    #[error("zero rate")]
    ZeroRate,
    /// Checked pricing arithmetic overflowed.
    #[error("overflow")]
    Overflow,
    /// The priced `net_output` cannot reach the RFQ's `minimum_output`.
    #[error("cannot meet the minimum output")]
    CannotMeetMinimum,
    /// The priced `total_input` exceeds the RFQ's `maximum_input`.
    #[error("cannot beat the maximum input")]
    CannotBeatMaximumInput,
    /// The priced fee exceeds the RFQ's consolidated fee cap.
    #[error("fee above the rfq limit")]
    FeeAboveLimit,
    /// The pinned backend refused to sign.
    #[error("signing refused")]
    SigningRefused,
    /// An emitted object failed its own construction (surfaced, never
    /// swallowed — I14).
    #[error("object construction")]
    ObjectConstruction,
}

/// The solver's explicit pricing policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SolverPolicyV1 {
    /// Conversion rate numerator: `gross_output = input * num / den`.
    pub rate_num: u128,
    /// Conversion rate denominator.
    pub rate_den: u128,
    /// The solver's consolidated spread, in basis points — its revenue
    /// AND the pocket the protocol fee is paid from (fee ADR).
    pub spread_bps: u128,
    /// Execution deadline: `quote_deadline + this`, same domain (A4).
    pub execution_delta: u64,
    /// Quote expiry: `quote_deadline + this`, same domain (A4).
    pub expiry_delta: u64,
}

/// The F4 bond reservation backing the quote — produced by the F4
/// ledger, carried here verbatim (§4.1.6-8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BondFactsV1 {
    /// The EXCLUSIVE reservation id.
    pub reservation_id: Digest32,
    /// The bond policy version the reservation was priced under.
    pub policy_version: u32,
}

/// The reference solver: one identity, one policy, one signing key.
pub struct ReferenceSolverV1 {
    solver_id: ParticipantId,
    policy: SolverPolicyV1,
    secret: Zeroizing<[u8; 32]>,
    secp: SecpContext,
}

impl core::fmt::Debug for ReferenceSolverV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // I6: the secret is never echoed.
        f.debug_struct("ReferenceSolverV1")
            .field("solver_id", &self.solver_id)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// `value + delta` inside the SAME timelock variant (A4: no conversion).
fn offset(spec: TimelockSpec, delta: u64) -> Result<TimelockSpec, SolverRefusal> {
    let bump = |v: u64| v.checked_add(delta).ok_or(SolverRefusal::Overflow);
    Ok(match spec {
        TimelockSpec::BlockHeight { value } => TimelockSpec::BlockHeight {
            value: bump(value)?,
        },
        TimelockSpec::TimestampSeconds { value } => TimelockSpec::TimestampSeconds {
            value: bump(value)?,
        },
        TimelockSpec::BtcTime512s { value } => TimelockSpec::BtcTime512s {
            value: bump(value)?,
        },
    })
}

fn mul_div_floor(a: u128, num: u128, den: u128) -> Result<u128, SolverRefusal> {
    // Defensive: every caller proves den != 0 first, but this helper
    // must be safe on its own (audit hardening AB-6).
    if den == 0 {
        return Err(SolverRefusal::ZeroRate);
    }
    a.checked_mul(num)
        .ok_or(SolverRefusal::Overflow)
        .map(|p| p / den)
}

fn mul_div_ceil(a: u128, num: u128, den: u128) -> Result<u128, SolverRefusal> {
    if den == 0 {
        return Err(SolverRefusal::ZeroRate);
    }
    let p = a.checked_mul(num).ok_or(SolverRefusal::Overflow)?;
    p.checked_add(den - 1)
        .ok_or(SolverRefusal::Overflow)
        .map(|s| s / den)
}

impl ReferenceSolverV1 {
    /// Build a solver. The secret is moved into zeroizing memory.
    pub fn new(
        solver_id: ParticipantId,
        policy: SolverPolicyV1,
        secret: [u8; 32],
        secp_seed: [u8; 32],
    ) -> Self {
        Self {
            solver_id,
            policy,
            secret: Zeroizing::new(secret),
            secp: SecpContext::new(&secp_seed),
        }
    }

    /// Price and sign an answer to `rfq`, or refuse by name.
    ///
    /// Rounding: the user's `net_output` rounds DOWN, the fee and the
    /// required input round UP — an accepted quote only over-delivers.
    pub fn answer(
        &self,
        rfq: &RfqV1,
        dom_chain_id: ChainId,
        bond: BondFactsV1,
        aux_rand: [u8; 32],
    ) -> Result<QuoteV1, SolverRefusal> {
        rfq.validate().map_err(|_| SolverRefusal::MalformedRfq)?;
        validate_dom_centrality(rfq, dom_chain_id).map_err(|_| SolverRefusal::RouteExcludesDom)?;
        if self.policy.rate_num == 0 || self.policy.rate_den == 0 {
            return Err(SolverRefusal::ZeroRate);
        }

        let (total_input, net_output, total_fee) = match rfq.mode {
            RfqModeV1::ExactIn {
                input_amount,
                minimum_output,
            } => {
                let gross =
                    mul_div_floor(input_amount, self.policy.rate_num, self.policy.rate_den)?;
                let fee = mul_div_ceil(gross, self.policy.spread_bps, BPS_DENOMINATOR)?;
                let net = gross
                    .checked_sub(fee)
                    .ok_or(SolverRefusal::CannotMeetMinimum)?;
                if net < minimum_output {
                    return Err(SolverRefusal::CannotMeetMinimum);
                }
                (input_amount, net, fee)
            }
            RfqModeV1::ExactOut {
                exact_output,
                maximum_input,
            } => {
                let fee = mul_div_ceil(exact_output, self.policy.spread_bps, BPS_DENOMINATOR)?;
                let gross = exact_output
                    .checked_add(fee)
                    .ok_or(SolverRefusal::Overflow)?;
                let input = mul_div_ceil(gross, self.policy.rate_den, self.policy.rate_num)?;
                if input > maximum_input {
                    return Err(SolverRefusal::CannotBeatMaximumInput);
                }
                (input, exact_output, fee)
            }
        };

        // The RFQ's consolidated fee cap (§4.1.4 + AD-1.2), refused
        // HERE rather than emitted for the initiator to reject.
        let Some(fee_cap) = rfq
            .fee_limit
            .dom_max
            .checked_add(rfq.fee_limit.counterparty_max)
        else {
            return Err(SolverRefusal::FeeAboveLimit);
        };
        if total_fee > fee_cap {
            return Err(SolverRefusal::FeeAboveLimit);
        }

        let execution_deadline = offset(rfq.quote_deadline, self.policy.execution_delta)?;
        let expiry = offset(rfq.quote_deadline, self.policy.expiry_delta)?;

        // Two-pass construction: the id is content-derived and the
        // signature is NOT digested, so signing the unsigned object's
        // id and rebuilding yields the same id (checked below, I14).
        let unsigned = QuoteV1::create(
            rfq.rfq_id,
            self.solver_id,
            rfq.route,
            net_output,
            total_input,
            total_fee,
            execution_deadline,
            bond.reservation_id,
            bond.policy_version,
            expiry,
            [0u8; 64],
        )
        .map_err(|_| SolverRefusal::ObjectConstruction)?;
        let (signature, _xonly) = self
            .secp
            .sign_bip340(&self.secret, &unsigned.quote_id, &aux_rand)
            .map_err(|_| SolverRefusal::SigningRefused)?;
        let signed = QuoteV1::create(
            rfq.rfq_id,
            self.solver_id,
            rfq.route,
            net_output,
            total_input,
            total_fee,
            execution_deadline,
            bond.reservation_id,
            bond.policy_version,
            expiry,
            signature,
        )
        .map_err(|_| SolverRefusal::ObjectConstruction)?;
        if signed.quote_id != unsigned.quote_id {
            return Err(SolverRefusal::ObjectConstruction);
        }
        Ok(signed)
    }

    /// The x-only public key admissibility verifies the quote signature
    /// against (the solver's roster key).
    pub fn xonly_key(&self) -> Result<[u8; 32], SolverRefusal> {
        self.secp
            .sign_bip340(&self.secret, &[0u8; 32], &[0u8; 32])
            .map(|(_, xonly)| xonly)
            .map_err(|_| SolverRefusal::SigningRefused)
    }
}

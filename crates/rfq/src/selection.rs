//! The ratified A5 selection function (F6 spec §4, Addendum AD-1).
//!
//! This is the PURE core the f6-model checker adjudicates exhaustively:
//! admissibility (§4.1 + AD-1) and winner selection (§4.3) over data
//! alone. Facts only the roster, clock and bond layers can attest —
//! membership, signature validity, exclusive reservation, exposure
//! coverage — enter as [`CandidateFactsV1`] inputs; this function
//! ADJUDICATES the ratified rule over them and never re-derives them.
//! Arrival order can not affect anything here: candidates are judged
//! individually and compared under a total published order (I12).

use crate::{
    candidate_set_digest, ChainId, LegDirectionV1, QuoteV1, RfqModeV1, RfqObjectError, RfqV1,
    SelectionV1, TimelockSpec,
};
use kaystra_core::types::Digest32;

/// I14: the candidate book is bounded BEFORE anything is examined or
/// allocated. 64 quotes per RFQ is far above any plausible v1 book.
pub const MAX_CANDIDATES: usize = 64;

/// Facts the session layer attests about one candidate — everything in
/// the §4.1 list that data alone cannot prove. The selection function
/// trusts these as INPUTS (their production is the roster/bond layers'
/// job, steps 3-5 of the build order) and applies the ratified rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CandidateFactsV1 {
    /// §4.1.1 — the solver is in the roster at the applicable snapshot.
    pub solver_registered: bool,
    /// §4.1.1 — the BIP340 signature over `quote_id` verifies against
    /// the solver's canonical roster key.
    pub signature_valid: bool,
    /// §4.1.6 + §4.1.8 — the F4 bond reservation exists and this quote
    /// holds it EXCLUSIVELY (no capacity double-commitment).
    pub bond_reserved_exclusive: bool,
    /// §4.1.7 — the reservation covers the economic exposure computed
    /// by the F4 policy for THIS quote.
    pub exposure_covered: bool,
    /// Tie-break 4 input: the reservation's coverage EXCESS over the
    /// required exposure, in the bond asset's smallest unit.
    pub coverage_excess: u128,
    /// §4.1.9 — the solver is not suspended and not under slashing.
    pub solver_active: bool,
    /// §4.1.10 — the quote's policy version is accepted by the session.
    pub policy_version_accepted: bool,
}

/// Named refusals of §4.1 + AD-1 (I13). A candidate is admissible iff
/// none of these applies; the FIRST failure in ratified order is
/// reported (the order below is the §4.1 enumeration order).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AdmissibilityRefusal {
    /// The RFQ itself fails structural validation.
    #[error("malformed rfq")]
    MalformedRfq,
    /// The quote fails structural validation (§4.1.1: canonical).
    #[error("malformed quote")]
    MalformedQuote,
    /// §4.1.1 — solver not in the roster snapshot.
    #[error("solver not registered")]
    SolverNotRegistered,
    /// §4.1.1 — roster-key signature does not verify.
    #[error("invalid solver signature")]
    InvalidSignature,
    /// A deadline (or `now`) lives outside the RFQ's timelock domain
    /// (A4: refused, never converted).
    #[error("wrong timelock domain")]
    WrongTimelockDomain,
    /// §4.1.2 — the quote is expired at `now`.
    #[error("quote expired")]
    Expired,
    /// §4.1.3 — the quote answers a different RFQ.
    #[error("quote answers a different rfq")]
    WrongRfq,
    /// §4.1.3 — the quote's route is not byte-identical to the RFQ's.
    #[error("route divergence")]
    RouteDivergence,
    /// AD-1.1 — the route does not contain the session's DOM chain on
    /// exactly one leg (DOM centrality of the settlement unit).
    #[error("route excludes the DOM")]
    RouteExcludesDom,
    /// AD-1.3 — `ExactIn`: the quote's `total_input` is not the RFQ's
    /// fixed `input_amount`.
    #[error("input amount mismatch")]
    InputMismatch,
    /// AD-1.3 — `ExactOut`: the quote's `net_output` is not the RFQ's
    /// fixed `exact_output`.
    #[error("output amount mismatch")]
    OutputMismatch,
    /// §4.1.4 — `ExactIn`: `net_output` below `minimum_output`.
    #[error("below the minimum output")]
    BelowMinimumOutput,
    /// §4.1.4 — `ExactOut`: `total_input` above `maximum_input`.
    #[error("above the maximum input")]
    AboveMaximumInput,
    /// §4.1.4 + AD-1.2 — consolidated fee above the ratified bound.
    #[error("fee above the ratified limit")]
    FeeAboveLimit,
    /// §4.1.6/8 — no exclusive F4 bond reservation.
    #[error("bond not exclusively reserved")]
    BondNotReserved,
    /// §4.1.7 — exposure not covered by the F4 policy computation.
    #[error("exposure not covered")]
    ExposureNotCovered,
    /// §4.1.9 — solver suspended or under slashing.
    #[error("solver suspended")]
    SolverSuspended,
    /// §4.1.10 — policy version not accepted by the session.
    #[error("policy version rejected")]
    PolicyVersionRejected,
}

/// Failures of the selection as a whole (I13).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SelectionError {
    /// More candidates than [`MAX_CANDIDATES`] (I14: bound first).
    #[error("too many candidates")]
    TooManyCandidates,
    /// No candidate survived admissibility.
    #[error("no admissible quote")]
    NoAdmissibleQuote,
    /// AD-1.4 — two distinct admissible quotes from the SAME solver are
    /// equal on every ratified key; the ratified tie chain has no
    /// unique winner and the selection refuses rather than inventing
    /// an unratified tie-break.
    #[error("tie unresolved under the ratified chain")]
    TieUnresolved,
    /// The candidate-set digest could not be computed.
    #[error("digest failure: {0}")]
    Digest(RfqObjectError),
}

/// The full outcome: the recorded selection plus the per-candidate
/// adjudication (quote id, refusal or admissible), in candidate order —
/// the audit trail that lets any observer recompute and disprove the
/// choice (I12).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SelectionOutcomeV1 {
    /// The recorded selection.
    pub selection: SelectionV1,
    /// Per-candidate verdicts: `None` = admissible.
    pub verdicts: Vec<(Digest32, Option<AdmissibilityRefusal>)>,
}

fn timelock_value(spec: TimelockSpec) -> u64 {
    match spec {
        TimelockSpec::BlockHeight { value }
        | TimelockSpec::TimestampSeconds { value }
        | TimelockSpec::BtcTime512s { value } => value,
    }
}

/// AD-1.1: the route must contain the DOM chain on exactly one leg.
fn dom_leg_count(rfq: &RfqV1, dom_chain_id: ChainId) -> usize {
    rfq.route
        .legs
        .iter()
        .filter(|leg| leg.chain_id == dom_chain_id)
        .count()
}

/// §4.1 + AD-1 admissibility of one candidate, refusals in the ratified
/// enumeration order. Pure: same inputs, same verdict.
pub fn admissibility(
    rfq: &RfqV1,
    quote: &QuoteV1,
    facts: &CandidateFactsV1,
    dom_chain_id: ChainId,
    now: TimelockSpec,
) -> Result<(), AdmissibilityRefusal> {
    // §4.1.1 — canonical encodings and identities.
    if rfq.validate().is_err() {
        return Err(AdmissibilityRefusal::MalformedRfq);
    }
    if quote.validate().is_err() {
        return Err(AdmissibilityRefusal::MalformedQuote);
    }
    if !facts.solver_registered {
        return Err(AdmissibilityRefusal::SolverNotRegistered);
    }
    if !facts.signature_valid {
        return Err(AdmissibilityRefusal::InvalidSignature);
    }
    // §4.1.2 — unexpired, with every clock in the RFQ's domain (A4).
    if !rfq.timelock_domain.contains(now)
        || !rfq.timelock_domain.contains(quote.expiry)
        || !rfq.timelock_domain.contains(quote.execution_deadline)
    {
        return Err(AdmissibilityRefusal::WrongTimelockDomain);
    }
    if timelock_value(now) > timelock_value(quote.expiry) {
        return Err(AdmissibilityRefusal::Expired);
    }
    // §4.1.3 — exact correspondence.
    if quote.rfq_id != rfq.rfq_id {
        return Err(AdmissibilityRefusal::WrongRfq);
    }
    if quote.route != rfq.route {
        return Err(AdmissibilityRefusal::RouteDivergence);
    }
    // AD-1.1 — DOM centrality of the settlement unit.
    if dom_leg_count(rfq, dom_chain_id) != 1 {
        return Err(AdmissibilityRefusal::RouteExcludesDom);
    }
    // §4.1.4 + AD-1.3 — mode exactness and the user's protection bound.
    match rfq.mode {
        RfqModeV1::ExactIn {
            input_amount,
            minimum_output,
        } => {
            if quote.total_input != input_amount {
                return Err(AdmissibilityRefusal::InputMismatch);
            }
            if quote.net_output < minimum_output {
                return Err(AdmissibilityRefusal::BelowMinimumOutput);
            }
        }
        RfqModeV1::ExactOut {
            exact_output,
            maximum_input,
        } => {
            if quote.net_output != exact_output {
                return Err(AdmissibilityRefusal::OutputMismatch);
            }
            if quote.total_input > maximum_input {
                return Err(AdmissibilityRefusal::AboveMaximumInput);
            }
        }
    }
    // §4.1.4 + AD-1.2 — the consolidated fee against the ratified caps.
    let fee_cap = rfq
        .fee_limit
        .dom_max
        .saturating_add(rfq.fee_limit.counterparty_max);
    if quote.total_fee > fee_cap {
        return Err(AdmissibilityRefusal::FeeAboveLimit);
    }
    // §4.1.6-10 — the attested facts.
    if !facts.bond_reserved_exclusive {
        return Err(AdmissibilityRefusal::BondNotReserved);
    }
    if !facts.exposure_covered {
        return Err(AdmissibilityRefusal::ExposureNotCovered);
    }
    if !facts.solver_active {
        return Err(AdmissibilityRefusal::SolverSuspended);
    }
    if !facts.policy_version_accepted {
        return Err(AdmissibilityRefusal::PolicyVersionRejected);
    }
    Ok(())
}

/// `true` when candidate `a` beats candidate `b` under the ratified
/// §4.3 order. STRICT: equal-on-every-key returns `false` both ways,
/// which is how the AD-1.4 self-tie surfaces.
fn beats(
    a: (&QuoteV1, &CandidateFactsV1),
    b: (&QuoteV1, &CandidateFactsV1),
    mode: RfqModeV1,
) -> bool {
    // 1-2. Best verifiable economic outcome.
    let econ = match mode {
        RfqModeV1::ExactIn { .. } => a.0.net_output.cmp(&b.0.net_output).reverse(),
        RfqModeV1::ExactOut { .. } => a.0.total_input.cmp(&b.0.total_input),
    };
    // 3. Shortest execution deadline (same domain: admissibility).
    let deadline =
        timelock_value(a.0.execution_deadline).cmp(&timelock_value(b.0.execution_deadline));
    // 4. Greatest excess F4 coverage.
    let coverage = a.1.coverage_excess.cmp(&b.1.coverage_excess).reverse();
    // 5. Lexicographically smallest canonical solver id, byte by byte.
    let solver = a.0.solver.0.cmp(&b.0.solver.0);
    econ.then(deadline).then(coverage).then(solver) == std::cmp::Ordering::Less
}

/// The ratified selection: adjudicates every candidate, picks the
/// winner under the §4.3 total order, and records the arrival-order-
/// independent candidate-set digest. Candidate ORDER cannot influence
/// the outcome: the winner is the unique admissible candidate that no
/// other admissible candidate beats, and equal-key duplicates from one
/// solver refuse by name (AD-1.4).
pub fn select_winner(
    rfq: &RfqV1,
    candidates: &[(QuoteV1, CandidateFactsV1)],
    dom_chain_id: ChainId,
    now: TimelockSpec,
) -> Result<SelectionOutcomeV1, SelectionError> {
    if candidates.len() > MAX_CANDIDATES {
        return Err(SelectionError::TooManyCandidates);
    }
    let verdicts: Vec<(Digest32, Option<AdmissibilityRefusal>)> = candidates
        .iter()
        .map(|(quote, facts)| {
            (
                quote.quote_id,
                admissibility(rfq, quote, facts, dom_chain_id, now).err(),
            )
        })
        .collect();

    let admissible: Vec<&(QuoteV1, CandidateFactsV1)> = candidates
        .iter()
        .zip(verdicts.iter())
        .filter(|(_, (_, refusal))| refusal.is_none())
        .map(|(candidate, _)| candidate)
        .collect();
    if admissible.is_empty() {
        return Err(SelectionError::NoAdmissibleQuote);
    }

    // The winner: beaten by nobody. The ratified chain is a total order
    // up to full key equality, so either exactly one such candidate
    // exists, or two candidates are equal on every key — same solver id
    // included — and AD-1.4 refuses.
    let mut winner: Option<&(QuoteV1, CandidateFactsV1)> = None;
    for candidate in &admissible {
        let beaten = admissible
            .iter()
            .any(|other| beats((&other.0, &other.1), (&candidate.0, &candidate.1), rfq.mode));
        if beaten {
            continue;
        }
        match winner {
            None => winner = Some(candidate),
            Some(current) if current.0.quote_id == candidate.0.quote_id => {}
            Some(_) => return Err(SelectionError::TieUnresolved),
        }
    }
    let Some((winning_quote, _)) = winner else {
        // Unreachable with a finite strict partial order, kept as a
        // named failure rather than a panic (I14).
        return Err(SelectionError::TieUnresolved);
    };

    let all_ids: Vec<Digest32> = candidates.iter().map(|(quote, _)| quote.quote_id).collect();
    let inputs_digest = candidate_set_digest(&all_ids).map_err(SelectionError::Digest)?;
    Ok(SelectionOutcomeV1 {
        selection: SelectionV1 {
            rfq_id: rfq.rfq_id,
            winning_quote: winning_quote.quote_id,
            inputs_digest,
        },
        verdicts,
    })
}

/// AD-1.1 as a standalone check for the RFQ intake path: refuses an
/// RFQ whose route does not contain the session's DOM chain on exactly
/// one leg, and (defensively) a route whose shape is invalid.
pub fn validate_dom_centrality(rfq: &RfqV1, dom_chain_id: ChainId) -> Result<(), RfqObjectError> {
    rfq.route.validate()?;
    let dom_legs = rfq
        .route
        .legs
        .iter()
        .filter(|leg| leg.chain_id == dom_chain_id)
        .count();
    if dom_legs != 1 {
        return Err(RfqObjectError::RouteExcludesDom);
    }
    let _ = LegDirectionV1::UserGives; // direction is orthogonal to centrality
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AssetId, FeeLimitV1, ParticipantId, PolicyId, RfqModeV1, RouteLegV1, RouteV1,
        TimelockDomainV1,
    };

    const DOM: ChainId = ChainId([0xD0; 32]);

    fn ts(value: u64) -> TimelockSpec {
        TimelockSpec::TimestampSeconds { value }
    }

    fn dom_route() -> RouteV1 {
        RouteV1 {
            legs: [
                RouteLegV1 {
                    chain_id: DOM,
                    asset: AssetId([0x12; 32]),
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: ChainId([0xE7; 32]),
                    asset: AssetId([0x22; 32]),
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        }
    }

    fn sample_rfq(route: RouteV1) -> RfqV1 {
        RfqV1::create(
            ParticipantId([0x31; 32]),
            route,
            RfqModeV1::ExactIn {
                input_amount: 100,
                minimum_output: 90,
            },
            FeeLimitV1 {
                dom_max: 5,
                counterparty_max: 5,
            },
            TimelockDomainV1::TimestampSeconds,
            ts(1_000),
            PolicyId([0x41; 32]),
            1,
            [0x51; 32],
        )
        .unwrap()
    }

    fn facts() -> CandidateFactsV1 {
        CandidateFactsV1 {
            solver_registered: true,
            signature_valid: true,
            bond_reserved_exclusive: true,
            exposure_covered: true,
            coverage_excess: 0,
            solver_active: true,
            policy_version_accepted: true,
        }
    }

    fn quote(rfq: &RfqV1, net: u128, seed: u8) -> QuoteV1 {
        QuoteV1::create(
            rfq.rfq_id,
            ParticipantId([0x61; 32]),
            rfq.route,
            net,
            100,
            4,
            ts(2_000),
            [seed; 32],
            1,
            ts(1_500),
            [seed; 64],
        )
        .unwrap()
    }

    #[test]
    fn best_net_output_wins_and_order_is_irrelevant() {
        let rfq = sample_rfq(dom_route());
        let a = quote(&rfq, 95, 1);
        let b = quote(&rfq, 97, 2);
        for book in [[a, b], [b, a]] {
            let outcome = select_winner(
                &rfq,
                &[(book[0], facts()), (book[1], facts())],
                DOM,
                ts(500),
            )
            .unwrap();
            assert_eq!(outcome.selection.winning_quote, b.quote_id);
        }
    }

    #[test]
    fn dom_centrality_is_enforced_at_intake_and_admissibility() {
        let mut foreign = dom_route();
        foreign.legs[0].chain_id = ChainId([0xE8; 32]);
        let rfq = sample_rfq(foreign);
        assert_eq!(
            validate_dom_centrality(&rfq, DOM).unwrap_err(),
            RfqObjectError::RouteExcludesDom
        );
        let q = quote(&rfq, 95, 3);
        assert_eq!(
            admissibility(&rfq, &q, &facts(), DOM, ts(500)).unwrap_err(),
            AdmissibilityRefusal::RouteExcludesDom
        );
    }

    #[test]
    fn self_tie_refuses_by_name() {
        let rfq = sample_rfq(dom_route());
        let a = quote(&rfq, 95, 4);
        let b = quote(&rfq, 95, 5); // distinct reservation, same keys
        assert_ne!(a.quote_id, b.quote_id);
        assert_eq!(
            select_winner(&rfq, &[(a, facts()), (b, facts())], DOM, ts(500)).unwrap_err(),
            SelectionError::TieUnresolved
        );
    }
}

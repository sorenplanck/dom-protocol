//! F6 V2 objects with explicit negotiation and chain-native refund clocks.
//!
//! V1 is intentionally unchanged. V2 separates the one clock used only for
//! quote negotiation from each settlement face's native refund clock. No
//! conversion between clock kinds or chains exists in this module.

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

use crate::{
    selection::CandidateFactsV1, AssetId, ChainId, FeeLimitV1, LegDirectionV1, ParticipantId,
    PolicyId, RfqModeV1, RouteLegV1,
};
use kaystra_core::types::Digest32;

const ZERO_DIGEST: Digest32 = [0; 32];
const ROUTE_LEGS_V2: usize = 2;
const RFQ_V2_MAGIC: &[u8; 8] = b"DOMIRFQ2";
const QUOTE_V2_MAGIC: &[u8; 8] = b"DOMIQTE2";
const ACCEPTANCE_V2_MAGIC: &[u8; 8] = b"DOMIACC2";
const SELECTION_V2_MAGIC: &[u8; 8] = b"DOMISEL2";
const WIRE_VERSION_V2: u16 = 2;
const RFQ_ID_DOMAIN_V2: &[u8] = b"DOM-INTEROP/F6-RFQ/V2\0";
const QUOTE_ID_DOMAIN_V2: &[u8] = b"DOM-INTEROP/F6-QUOTE/V2\0";
const TERMS_DOMAIN_V2: &[u8] = b"DOM-INTEROP/F6-TERMS/V2\0";
const CANDIDATE_SET_DOMAIN_V2: &[u8] = b"DOM-INTEROP/F6-CANDIDATES/V2\0";

/// F6 V2 codec, binding and admissibility refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum F6V2Refusal {
    /// A required digest, value, amount or version is zero.
    #[error("zero or invalid F6 V2 field")]
    InvalidField,
    /// Exactly one give and one receive leg are required.
    #[error("invalid F6 V2 route topology")]
    InvalidRoute,
    /// Bytes ended before the canonical object ended.
    #[error("truncated F6 V2 object")]
    Truncated,
    /// Magic, wire version or a closed enum tag is unknown.
    #[error("unsupported F6 V2 encoding")]
    UnsupportedEncoding,
    /// Canonical bytes contain a trailing suffix.
    #[error("trailing F6 V2 bytes")]
    TrailingBytes,
    /// A content-derived identifier is not exact.
    #[error("F6 V2 identifier mismatch")]
    IdMismatch,
    /// RFQ, quote, composition or settlement position diverges.
    #[error("F6 V2 cross-object binding mismatch")]
    BindingMismatch,
    /// Negotiation clocks differ byte-for-byte.
    #[error("F6 V2 negotiation clock mismatch")]
    NegotiationClockMismatch,
    /// A refund or payout face does not match its route leg and chain.
    #[error("F6 V2 settlement face mismatch")]
    FaceMismatch,
    /// The candidate is no longer within its negotiation window.
    #[error("F6 V2 negotiation window expired")]
    Expired,
    /// Solver roster or signature authority is absent.
    #[error("F6 V2 solver identity refused")]
    SolverIdentity,
    /// Exclusive bond or economic exposure is not covered.
    #[error("F6 V2 assurance refused")]
    Assurance,
    /// Solver status or policy version is not current.
    #[error("F6 V2 solver status or policy refused")]
    SolverPolicy,
    /// Quote amounts or fee violate the RFQ.
    #[error("F6 V2 economics refused")]
    Economics,
    /// Exactly one leg of this settlement must be DOM.
    #[error("F6 V2 settlement excludes or duplicates DOM")]
    DomCentrality,
    /// A bounded collection exceeds its V2 limit.
    #[error("F6 V2 bound exceeded")]
    BoundExceeded,
    /// No candidate survived V2 admissibility.
    #[error("no admissible F6 V2 quote")]
    NoAdmissibleQuote,
    /// The ratified comparison keys do not yield one unique winner.
    #[error("F6 V2 candidate tie is unresolved")]
    TieUnresolved,
    /// A checked arithmetic operation overflowed.
    #[error("F6 V2 arithmetic overflow")]
    Overflow,
    /// BLAKE2b-256 could not be initialized or finalized.
    #[error("F6 V2 digest failure")]
    Digest,
}

/// Position of one DOM-centred settlement inside a composed route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SettlementPositionV2 {
    /// Input chain to DOM.
    Upstream = 1,
    /// DOM to output chain.
    Downstream = 2,
}

/// Native clock kind. Chain identity is always carried separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeClockKindV2 {
    /// Absolute chain block height.
    BlockHeight = 1,
    /// Absolute chain timestamp in seconds.
    TimestampSeconds = 2,
    /// Bitcoin BIP68/MTP units of 512 seconds.
    BitcoinTime512 = 3,
}

/// Clock used only for quote submission, expiry and execution windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiationClockV2 {
    /// Exact chain whose authenticated checkpoint advances this clock.
    pub chain_id: ChainId,
    /// Exact adapter/chain profile that interprets the checkpoint.
    pub profile_digest: Digest32,
    /// Authority-defined nonzero policy/evidence scope within that profile.
    pub authority_scope: Digest32,
    /// Native representation of values emitted by that authority.
    pub kind: NativeClockKindV2,
}

impl NegotiationClockV2 {
    /// Refuses an unscoped clock and BIP68, which is a relative refund
    /// constraint rather than a negotiation clock.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        if self.chain_id.0 == ZERO_DIGEST
            || self.profile_digest == ZERO_DIGEST
            || self.authority_scope == ZERO_DIGEST
            || self.kind == NativeClockKindV2::BitcoinTime512
        {
            return Err(F6V2Refusal::InvalidField);
        }
        Ok(())
    }
}

/// One point on the exact negotiation clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiationInstantV2 {
    /// Exact clock authority and representation.
    pub clock: NegotiationClockV2,
    /// Native value, never converted by F6.
    pub value: u64,
}

impl NegotiationInstantV2 {
    /// Refuses zero or unscoped instants.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        self.clock.validate()?;
        if self.value == 0 {
            return Err(F6V2Refusal::InvalidField);
        }
        Ok(())
    }
}

/// Public value extracted from a move-only production time capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiationObservationV2 {
    /// Exact authenticated negotiation clock.
    pub clock: NegotiationClockV2,
    /// Current value on that clock.
    pub value: u64,
}

impl NegotiationObservationV2 {
    /// Refuses an observation that is not on a usable exact clock.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        self.clock.validate()?;
        if self.value == 0 {
            return Err(F6V2Refusal::InvalidField);
        }
        Ok(())
    }
}

/// One native refund deadline scoped to one exact chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedTimelockV2 {
    /// Chain whose consensus interprets the value.
    pub chain_id: ChainId,
    /// Chain-native clock representation.
    pub kind: NativeClockKindV2,
    /// Native value, never compared to another scope by this crate.
    pub value: u64,
}

impl ScopedTimelockV2 {
    /// Refuses zero chain or value.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        if self.chain_id.0 == ZERO_DIGEST || self.value == 0 {
            return Err(F6V2Refusal::InvalidField);
        }
        Ok(())
    }
}

/// One DOM-centred settlement; a composed route uses two RFQs linked by the
/// same `composition_id` and opposite settlement positions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteV2 {
    /// Shared identifier of the complete X→DOM→Y composition.
    pub composition_id: Digest32,
    /// Upstream or downstream settlement position.
    pub position: SettlementPositionV2,
    /// Exactly one give and one receive leg. DOM centrality is validated
    /// against the authenticated DOM chain identifier at composition time.
    pub legs: [RouteLegV1; ROUTE_LEGS_V2],
}

impl RouteV2 {
    /// Validates fixed topology and all chain/asset identities.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        let gives = self
            .legs
            .iter()
            .filter(|leg| leg.direction == LegDirectionV1::UserGives)
            .count();
        if self.composition_id == ZERO_DIGEST
            || gives != 1
            || self.legs[0].chain_id == self.legs[1].chain_id
            || self
                .legs
                .iter()
                .any(|leg| leg.chain_id.0 == ZERO_DIGEST || leg.asset.0 == ZERO_DIGEST)
        {
            return Err(F6V2Refusal::InvalidRoute);
        }
        Ok(())
    }

    /// Asset supplied by the user in this settlement.
    pub fn input_asset(self) -> Result<AssetId, F6V2Refusal> {
        self.validate()?;
        self.legs
            .iter()
            .find(|leg| leg.direction == LegDirectionV1::UserGives)
            .map(|leg| leg.asset)
            .ok_or(F6V2Refusal::InvalidRoute)
    }

    fn leg_on(self, chain_id: ChainId) -> Result<RouteLegV1, F6V2Refusal> {
        let mut matching = self
            .legs
            .iter()
            .copied()
            .filter(|leg| leg.chain_id == chain_id);
        let leg = matching.next().ok_or(F6V2Refusal::DomCentrality)?;
        if matching.next().is_some() {
            return Err(F6V2Refusal::DomCentrality);
        }
        Ok(leg)
    }
}

/// Request for one settlement quote inside a linked composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RfqV2 {
    /// Content-derived identifier.
    pub rfq_id: Digest32,
    /// Requesting participant.
    pub initiator: ParticipantId,
    /// Explicit linked-settlement route.
    pub route: RouteV2,
    /// Exact-in or exact-out protection.
    pub mode: RfqModeV1,
    /// Consolidated fee ceilings.
    pub fee_limit: FeeLimitV1,
    /// Exact clock used only for negotiation.
    pub negotiation_clock: NegotiationClockV2,
    /// Last value at which a new quote may be offered.
    pub quote_deadline: NegotiationInstantV2,
    /// Assurance policy identifier.
    pub assurance_policy_ref: PolicyId,
    /// Accepted policy version.
    pub policy_version: u32,
    /// Relay/F6 session.
    pub session_id: Digest32,
}

/// Caller-supplied RFQ fields. The content-derived identifier is never
/// caller-shaped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RfqRequestV2 {
    /// Requesting participant.
    pub initiator: ParticipantId,
    /// Exact settlement position and composition.
    pub route: RouteV2,
    /// Exact-in/out protection.
    pub mode: RfqModeV1,
    /// Consolidated fee ceilings.
    pub fee_limit: FeeLimitV1,
    /// Exact authenticated negotiation clock.
    pub negotiation_clock: NegotiationClockV2,
    /// Last value at which a quote may be offered.
    pub quote_deadline: NegotiationInstantV2,
    /// Assurance policy identifier.
    pub assurance_policy_ref: PolicyId,
    /// Accepted policy version.
    pub policy_version: u32,
    /// Relay/F6 session.
    pub session_id: Digest32,
}

/// Solver quote for one V2 RFQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteV2 {
    /// Content-derived quote identifier.
    pub quote_id: Digest32,
    /// Exact RFQ.
    pub rfq_id: Digest32,
    /// Solver identity.
    pub solver: ParticipantId,
    /// Exact linked-settlement route.
    pub route: RouteV2,
    /// User's net output.
    pub net_output: u128,
    /// User's total input.
    pub total_input: u128,
    /// Consolidated total fee.
    pub total_fee: u128,
    /// Latest permitted execution on the negotiation clock.
    pub execution_deadline: NegotiationInstantV2,
    /// Exclusive inventory/bond reservation.
    pub bond_reservation_id: Digest32,
    /// Exact bond policy version.
    pub bond_policy_version: u32,
    /// Quote expiry on the negotiation clock.
    pub expiry: NegotiationInstantV2,
    /// BIP340 signature over `quote_id`.
    pub solver_signature: [u8; 64],
}

/// Caller-supplied quote fields. The content-derived identifier is never
/// caller-shaped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteProposalV2 {
    /// Exact RFQ.
    pub rfq_id: Digest32,
    /// Solver identity.
    pub solver: ParticipantId,
    /// Exact settlement route.
    pub route: RouteV2,
    /// User's net output.
    pub net_output: u128,
    /// User's total input.
    pub total_input: u128,
    /// Consolidated total fee.
    pub total_fee: u128,
    /// Latest permitted execution.
    pub execution_deadline: NegotiationInstantV2,
    /// Exclusive inventory/bond reservation.
    pub bond_reservation_id: Digest32,
    /// Exact bond policy version.
    pub bond_policy_version: u32,
    /// Quote expiry.
    pub expiry: NegotiationInstantV2,
    /// BIP340 signature over the derived quote identifier.
    pub solver_signature: [u8; 64],
}

/// Refund and payout commitment of one exact route face.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefundFaceV2 {
    /// Give/receive face in the corresponding route position.
    pub direction: LegDirectionV1,
    /// Chain that interprets both payout and refund artifacts.
    pub chain_id: ChainId,
    /// Native refund deadline on the same chain.
    pub refund_deadline: ScopedTimelockV2,
    /// Adapter-produced payout destination commitment.
    pub payout_commitment: Digest32,
}

/// Accepted V2 terms. Refund clocks may differ; they are only bound, never
/// numerically compared here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TermsBindingV2 {
    /// Wire/protocol version 2.
    pub protocol_version: u16,
    /// Accepted RFQ.
    pub rfq_id: Digest32,
    /// Accepted quote.
    pub quote_id: Digest32,
    /// Explicit composition and settlement position.
    pub route: RouteV2,
    /// User input asset.
    pub input_asset: AssetId,
    /// Exact-in/out mode.
    pub mode: RfqModeV1,
    /// Consolidated total fee.
    pub total_fee: u128,
    /// Winning solver.
    pub solver_id: ParticipantId,
    /// Exclusive reservation.
    pub bond_reservation_id: Digest32,
    /// Bond policy version.
    pub bond_policy_version: u32,
    /// Execution deadline on the negotiation clock.
    pub execution_deadline: NegotiationInstantV2,
    /// Two route faces in exact route-leg order.
    pub faces: [RefundFaceV2; ROUTE_LEGS_V2],
    /// Quote expiry on the negotiation clock.
    pub quote_expiry: NegotiationInstantV2,
    /// Session.
    pub session_id: Digest32,
}

/// V2 acceptance explicitly names the linked composition position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptanceV2 {
    /// Accepted terms digest.
    pub terms_hash: Digest32,
    /// Exact RFQ.
    pub rfq_id: Digest32,
    /// Exact quote.
    pub quote_id: Digest32,
    /// Linked composition.
    pub composition_id: Digest32,
    /// Settlement position inside the composition.
    pub position: SettlementPositionV2,
    /// Initiator that accepted.
    pub accepted_by: ParticipantId,
}

/// V2 deterministic-selection commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionV2 {
    /// Exact RFQ.
    pub rfq_id: Digest32,
    /// Linked composition.
    pub composition_id: Digest32,
    /// Settlement position inside the composition.
    pub position: SettlementPositionV2,
    /// Winning quote.
    pub winning_quote: Digest32,
    /// Digest of the complete candidate set.
    pub inputs_digest: Digest32,
}

/// Full deterministic V2 selection audit trail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionOutcomeV2 {
    /// Position-scoped winning commitment.
    pub selection: SelectionV2,
    /// Candidate-order audit verdicts; `None` means admissible.
    pub verdicts: Vec<(Digest32, Option<F6V2Refusal>)>,
}

/// Validates that two settlement RFQs form one exact X→DOM→Y route. No
/// timing conversion or economic inference is performed.
pub fn validate_composed_pair_v2(
    first: &RfqV2,
    second: &RfqV2,
    dom_chain_id: ChainId,
) -> Result<(), F6V2Refusal> {
    first.validate()?;
    second.validate()?;
    if dom_chain_id.0 == ZERO_DIGEST {
        return Err(F6V2Refusal::InvalidField);
    }
    let (upstream, downstream) = match (first.route.position, second.route.position) {
        (SettlementPositionV2::Upstream, SettlementPositionV2::Downstream) => (first, second),
        (SettlementPositionV2::Downstream, SettlementPositionV2::Upstream) => (second, first),
        _ => return Err(F6V2Refusal::BindingMismatch),
    };
    if upstream.route.composition_id != downstream.route.composition_id
        || upstream.initiator != downstream.initiator
        || upstream.session_id != downstream.session_id
        || upstream.negotiation_clock != downstream.negotiation_clock
    {
        return Err(F6V2Refusal::BindingMismatch);
    }
    let upstream_dom = upstream.route.leg_on(dom_chain_id)?;
    let downstream_dom = downstream.route.leg_on(dom_chain_id)?;
    if upstream_dom.direction != LegDirectionV1::UserReceives
        || downstream_dom.direction != LegDirectionV1::UserGives
        || upstream_dom.asset != downstream_dom.asset
    {
        return Err(F6V2Refusal::DomCentrality);
    }
    let upstream_external = upstream
        .route
        .legs
        .iter()
        .find(|leg| leg.chain_id != dom_chain_id)
        .ok_or(F6V2Refusal::DomCentrality)?;
    let downstream_external = downstream
        .route
        .legs
        .iter()
        .find(|leg| leg.chain_id != dom_chain_id)
        .ok_or(F6V2Refusal::DomCentrality)?;
    if upstream_external.direction != LegDirectionV1::UserGives
        || downstream_external.direction != LegDirectionV1::UserReceives
    {
        return Err(F6V2Refusal::InvalidRoute);
    }
    Ok(())
}

impl RfqV2 {
    /// Creates and content-addresses a V2 RFQ.
    pub fn create(request: RfqRequestV2) -> Result<Self, F6V2Refusal> {
        let mut value = Self {
            rfq_id: ZERO_DIGEST,
            initiator: request.initiator,
            route: request.route,
            mode: request.mode,
            fee_limit: request.fee_limit,
            negotiation_clock: request.negotiation_clock,
            quote_deadline: request.quote_deadline,
            assurance_policy_ref: request.assurance_policy_ref,
            policy_version: request.policy_version,
            session_id: request.session_id,
        };
        value.rfq_id = value.derive_id()?;
        value.validate()?;
        Ok(value)
    }

    /// Validates topology, nonzero authority and content-derived id.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        self.route.validate()?;
        self.negotiation_clock.validate()?;
        self.quote_deadline.validate()?;
        let (first, second) = mode_amounts(self.mode);
        if self.initiator.0 == ZERO_DIGEST
            || self.session_id == ZERO_DIGEST
            || self.assurance_policy_ref.0 == ZERO_DIGEST
            || self.policy_version == 0
            || first == 0
            || second == 0
        {
            return Err(F6V2Refusal::InvalidField);
        }
        if self.quote_deadline.clock != self.negotiation_clock {
            return Err(F6V2Refusal::NegotiationClockMismatch);
        }
        if self.rfq_id != self.derive_id()? {
            return Err(F6V2Refusal::IdMismatch);
        }
        Ok(())
    }

    /// Canonical strict V2 wire bytes.
    pub fn canonical_bytes(self) -> Result<Vec<u8>, F6V2Refusal> {
        self.validate()?;
        let body = self.body_bytes();
        let mut output = Vec::with_capacity(body.len() + 32);
        output.extend_from_slice(RFQ_V2_MAGIC);
        put_u16(&mut output, WIRE_VERSION_V2);
        output.extend_from_slice(&self.rfq_id);
        output.extend_from_slice(&body);
        Ok(output)
    }

    /// Strict V2 decoder; trailing bytes are refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, F6V2Refusal> {
        let mut cursor = Cursor::new(bytes);
        require_header(&mut cursor, RFQ_V2_MAGIC)?;
        let rfq_id = cursor.digest()?;
        let value = Self {
            rfq_id,
            initiator: ParticipantId(cursor.digest()?),
            route: take_route(&mut cursor)?,
            mode: take_mode(&mut cursor)?,
            fee_limit: FeeLimitV1 {
                dom_max: cursor.u128()?,
                counterparty_max: cursor.u128()?,
            },
            negotiation_clock: take_negotiation_clock(&mut cursor)?,
            quote_deadline: take_negotiation_instant(&mut cursor)?,
            assurance_policy_ref: PolicyId(cursor.digest()?),
            policy_version: cursor.u32()?,
            session_id: cursor.digest()?,
        };
        cursor.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        Ok(value)
    }

    fn derive_id(self) -> Result<Digest32, F6V2Refusal> {
        digest(RFQ_ID_DOMAIN_V2, &self.body_bytes())
    }

    fn body_bytes(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(384);
        put_participant(&mut output, self.initiator);
        put_route(&mut output, self.route);
        put_mode(&mut output, self.mode);
        put_u128(&mut output, self.fee_limit.dom_max);
        put_u128(&mut output, self.fee_limit.counterparty_max);
        put_negotiation_clock(&mut output, self.negotiation_clock);
        put_negotiation_instant(&mut output, self.quote_deadline);
        output.extend_from_slice(&self.assurance_policy_ref.0);
        put_u32(&mut output, self.policy_version);
        output.extend_from_slice(&self.session_id);
        output
    }
}

impl QuoteV2 {
    /// Creates and content-addresses a V2 quote.
    pub fn create(proposal: QuoteProposalV2) -> Result<Self, F6V2Refusal> {
        let mut value = Self {
            quote_id: ZERO_DIGEST,
            rfq_id: proposal.rfq_id,
            solver: proposal.solver,
            route: proposal.route,
            net_output: proposal.net_output,
            total_input: proposal.total_input,
            total_fee: proposal.total_fee,
            execution_deadline: proposal.execution_deadline,
            bond_reservation_id: proposal.bond_reservation_id,
            bond_policy_version: proposal.bond_policy_version,
            expiry: proposal.expiry,
            solver_signature: proposal.solver_signature,
        };
        value.quote_id = value.derive_id()?;
        value.validate()?;
        Ok(value)
    }

    /// Validates structural fields and content-derived id.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        self.route.validate()?;
        self.execution_deadline.validate()?;
        self.expiry.validate()?;
        if self.rfq_id == ZERO_DIGEST
            || self.solver.0 == ZERO_DIGEST
            || self.bond_reservation_id == ZERO_DIGEST
            || self.net_output == 0
            || self.total_input == 0
            || self.bond_policy_version == 0
        {
            return Err(F6V2Refusal::InvalidField);
        }
        if self.execution_deadline.clock != self.expiry.clock {
            return Err(F6V2Refusal::NegotiationClockMismatch);
        }
        if self.quote_id != self.derive_id()? {
            return Err(F6V2Refusal::IdMismatch);
        }
        Ok(())
    }

    /// Canonical strict V2 wire bytes.
    pub fn canonical_bytes(self) -> Result<Vec<u8>, F6V2Refusal> {
        self.validate()?;
        let body = self.body_bytes();
        let mut output = Vec::with_capacity(body.len() + 32 + 64 + 10);
        output.extend_from_slice(QUOTE_V2_MAGIC);
        put_u16(&mut output, WIRE_VERSION_V2);
        output.extend_from_slice(&self.quote_id);
        output.extend_from_slice(&body);
        output.extend_from_slice(&self.solver_signature);
        Ok(output)
    }

    /// Strict V2 decoder; trailing bytes are refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, F6V2Refusal> {
        let mut cursor = Cursor::new(bytes);
        require_header(&mut cursor, QUOTE_V2_MAGIC)?;
        let quote_id = cursor.digest()?;
        let value = Self {
            quote_id,
            rfq_id: cursor.digest()?,
            solver: ParticipantId(cursor.digest()?),
            route: take_route(&mut cursor)?,
            net_output: cursor.u128()?,
            total_input: cursor.u128()?,
            total_fee: cursor.u128()?,
            execution_deadline: take_negotiation_instant(&mut cursor)?,
            bond_reservation_id: cursor.digest()?,
            bond_policy_version: cursor.u32()?,
            expiry: take_negotiation_instant(&mut cursor)?,
            solver_signature: cursor.array()?,
        };
        cursor.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        Ok(value)
    }

    fn derive_id(self) -> Result<Digest32, F6V2Refusal> {
        digest(QUOTE_ID_DOMAIN_V2, &self.body_bytes())
    }

    fn body_bytes(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(384);
        output.extend_from_slice(&self.rfq_id);
        put_participant(&mut output, self.solver);
        put_route(&mut output, self.route);
        put_u128(&mut output, self.net_output);
        put_u128(&mut output, self.total_input);
        put_u128(&mut output, self.total_fee);
        put_negotiation_instant(&mut output, self.execution_deadline);
        output.extend_from_slice(&self.bond_reservation_id);
        put_u32(&mut output, self.bond_policy_version);
        put_negotiation_instant(&mut output, self.expiry);
        output
    }
}

impl TermsBindingV2 {
    /// Assembles exact V2 terms without comparing heterogeneous refund clocks.
    pub fn from_parts(
        rfq: &RfqV2,
        quote: &QuoteV2,
        faces: [RefundFaceV2; ROUTE_LEGS_V2],
    ) -> Result<Self, F6V2Refusal> {
        rfq.validate()?;
        quote.validate()?;
        if quote.rfq_id != rfq.rfq_id || quote.route != rfq.route {
            return Err(F6V2Refusal::BindingMismatch);
        }
        if quote.execution_deadline.clock != rfq.negotiation_clock
            || quote.expiry.clock != rfq.negotiation_clock
        {
            return Err(F6V2Refusal::NegotiationClockMismatch);
        }
        for (face, leg) in faces.iter().zip(rfq.route.legs.iter()) {
            face.refund_deadline.validate()?;
            if face.direction != leg.direction
                || face.chain_id != leg.chain_id
                || face.refund_deadline.chain_id != leg.chain_id
                || face.payout_commitment == ZERO_DIGEST
            {
                return Err(F6V2Refusal::FaceMismatch);
            }
        }
        let value = Self {
            protocol_version: WIRE_VERSION_V2,
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            route: rfq.route,
            input_asset: rfq.route.input_asset()?,
            mode: rfq.mode,
            total_fee: quote.total_fee,
            solver_id: quote.solver,
            bond_reservation_id: quote.bond_reservation_id,
            bond_policy_version: quote.bond_policy_version,
            execution_deadline: quote.execution_deadline,
            faces,
            quote_expiry: quote.expiry,
            session_id: rfq.session_id,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates every internal V2 binding available without replaying the
    /// originating RFQ and quote. Cross-object replay remains mandatory at
    /// the production authority boundary.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        if self.protocol_version != WIRE_VERSION_V2 {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        self.route.validate()?;
        self.execution_deadline.validate()?;
        self.quote_expiry.validate()?;
        let (first, second) = mode_amounts(self.mode);
        if [
            self.rfq_id,
            self.quote_id,
            self.solver_id.0,
            self.bond_reservation_id,
            self.session_id,
        ]
        .contains(&ZERO_DIGEST)
            || self.bond_policy_version == 0
            || first == 0
            || second == 0
            || self.input_asset != self.route.input_asset()?
        {
            return Err(F6V2Refusal::InvalidField);
        }
        if self.execution_deadline.clock != self.quote_expiry.clock {
            return Err(F6V2Refusal::NegotiationClockMismatch);
        }
        for (face, leg) in self.faces.iter().zip(self.route.legs.iter()) {
            face.refund_deadline.validate()?;
            if face.direction != leg.direction
                || face.chain_id != leg.chain_id
                || face.refund_deadline.chain_id != leg.chain_id
                || face.payout_commitment == ZERO_DIGEST
            {
                return Err(F6V2Refusal::FaceMismatch);
            }
        }
        Ok(())
    }

    /// Canonical terms encoding.
    pub fn canonical_bytes(self) -> Result<Vec<u8>, F6V2Refusal> {
        self.validate()?;
        let mut output = Vec::with_capacity(640);
        put_u16(&mut output, self.protocol_version);
        output.extend_from_slice(&self.rfq_id);
        output.extend_from_slice(&self.quote_id);
        put_route(&mut output, self.route);
        output.extend_from_slice(&self.input_asset.0);
        put_mode(&mut output, self.mode);
        put_u128(&mut output, self.total_fee);
        put_participant(&mut output, self.solver_id);
        output.extend_from_slice(&self.bond_reservation_id);
        put_u32(&mut output, self.bond_policy_version);
        put_negotiation_instant(&mut output, self.execution_deadline);
        for face in self.faces {
            put_refund_face(&mut output, face);
        }
        put_negotiation_instant(&mut output, self.quote_expiry);
        output.extend_from_slice(&self.session_id);
        Ok(output)
    }

    /// Strict terms decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, F6V2Refusal> {
        let mut cursor = Cursor::new(bytes);
        let value = Self {
            protocol_version: cursor.u16()?,
            rfq_id: cursor.digest()?,
            quote_id: cursor.digest()?,
            route: take_route(&mut cursor)?,
            input_asset: AssetId(cursor.digest()?),
            mode: take_mode(&mut cursor)?,
            total_fee: cursor.u128()?,
            solver_id: ParticipantId(cursor.digest()?),
            bond_reservation_id: cursor.digest()?,
            bond_policy_version: cursor.u32()?,
            execution_deadline: take_negotiation_instant(&mut cursor)?,
            faces: [
                take_refund_face(&mut cursor)?,
                take_refund_face(&mut cursor)?,
            ],
            quote_expiry: take_negotiation_instant(&mut cursor)?,
            session_id: cursor.digest()?,
        };
        cursor.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        Ok(value)
    }

    /// Domain-separated V2 terms digest.
    pub fn terms_hash(self) -> Result<Digest32, F6V2Refusal> {
        digest(TERMS_DOMAIN_V2, &self.canonical_bytes()?)
    }
}

impl AcceptanceV2 {
    /// Creates an acceptance from the exact canonical V2 terms.
    pub fn from_terms(
        terms: &TermsBindingV2,
        accepted_by: ParticipantId,
    ) -> Result<Self, F6V2Refusal> {
        terms.validate()?;
        let value = Self {
            terms_hash: terms.terms_hash()?,
            rfq_id: terms.rfq_id,
            quote_id: terms.quote_id,
            composition_id: terms.route.composition_id,
            position: terms.route.position,
            accepted_by,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates exact V2 binding fields.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        if [
            self.terms_hash,
            self.rfq_id,
            self.quote_id,
            self.composition_id,
            self.accepted_by.0,
        ]
        .contains(&ZERO_DIGEST)
        {
            return Err(F6V2Refusal::InvalidField);
        }
        Ok(())
    }

    /// Replays the exact acceptance binding against canonical terms.
    pub fn validate_against(self, terms: &TermsBindingV2) -> Result<(), F6V2Refusal> {
        self.validate()?;
        terms.validate()?;
        if self.terms_hash != terms.terms_hash()?
            || self.rfq_id != terms.rfq_id
            || self.quote_id != terms.quote_id
            || self.composition_id != terms.route.composition_id
            || self.position != terms.route.position
        {
            return Err(F6V2Refusal::BindingMismatch);
        }
        Ok(())
    }

    /// Canonical strict V2 wire bytes.
    pub fn canonical_bytes(self) -> Result<Vec<u8>, F6V2Refusal> {
        self.validate()?;
        let mut output = Vec::with_capacity(171);
        output.extend_from_slice(ACCEPTANCE_V2_MAGIC);
        put_u16(&mut output, WIRE_VERSION_V2);
        output.extend_from_slice(&self.terms_hash);
        output.extend_from_slice(&self.rfq_id);
        output.extend_from_slice(&self.quote_id);
        output.extend_from_slice(&self.composition_id);
        output.push(self.position as u8);
        put_participant(&mut output, self.accepted_by);
        Ok(output)
    }

    /// Strict V2 decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, F6V2Refusal> {
        let mut cursor = Cursor::new(bytes);
        require_header(&mut cursor, ACCEPTANCE_V2_MAGIC)?;
        let value = Self {
            terms_hash: cursor.digest()?,
            rfq_id: cursor.digest()?,
            quote_id: cursor.digest()?,
            composition_id: cursor.digest()?,
            position: take_position(&mut cursor)?,
            accepted_by: ParticipantId(cursor.digest()?),
        };
        cursor.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        Ok(value)
    }
}

impl SelectionV2 {
    /// Creates the deterministic candidate commitment for one exact RFQ.
    pub fn from_candidates(
        rfq: &RfqV2,
        winning_quote: Digest32,
        quote_ids: &[Digest32],
    ) -> Result<Self, F6V2Refusal> {
        rfq.validate()?;
        if winning_quote == ZERO_DIGEST || !quote_ids.contains(&winning_quote) {
            return Err(F6V2Refusal::BindingMismatch);
        }
        let value = Self {
            rfq_id: rfq.rfq_id,
            composition_id: rfq.route.composition_id,
            position: rfq.route.position,
            winning_quote,
            inputs_digest: candidate_set_digest_v2(
                rfq.route.composition_id,
                rfq.route.position,
                rfq.rfq_id,
                quote_ids,
            )?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Creates a selection committed to an authenticated candidate-authority
    /// snapshot. The digest must cover the exact facts used to rank quotes,
    /// not merely their identifiers.
    pub fn from_authority_snapshot(
        rfq: &RfqV2,
        winning_quote: Digest32,
        candidate_quote_ids: &[Digest32],
        authority_snapshot_digest: Digest32,
    ) -> Result<Self, F6V2Refusal> {
        rfq.validate()?;
        if winning_quote == ZERO_DIGEST
            || authority_snapshot_digest == ZERO_DIGEST
            || !candidate_quote_ids.contains(&winning_quote)
        {
            return Err(F6V2Refusal::BindingMismatch);
        }
        let value = Self {
            rfq_id: rfq.rfq_id,
            composition_id: rfq.route.composition_id,
            position: rfq.route.position,
            winning_quote,
            inputs_digest: authority_snapshot_digest,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates exact V2 binding fields.
    pub fn validate(self) -> Result<(), F6V2Refusal> {
        if [
            self.rfq_id,
            self.composition_id,
            self.winning_quote,
            self.inputs_digest,
        ]
        .contains(&ZERO_DIGEST)
        {
            return Err(F6V2Refusal::InvalidField);
        }
        Ok(())
    }

    /// Replays the selection against the exact RFQ and complete candidates.
    pub fn validate_against(self, rfq: &RfqV2, quote_ids: &[Digest32]) -> Result<(), F6V2Refusal> {
        self.validate()?;
        rfq.validate()?;
        if self.rfq_id != rfq.rfq_id
            || self.composition_id != rfq.route.composition_id
            || self.position != rfq.route.position
            || !quote_ids.contains(&self.winning_quote)
            || self.inputs_digest
                != candidate_set_digest_v2(
                    rfq.route.composition_id,
                    rfq.route.position,
                    rfq.rfq_id,
                    quote_ids,
                )?
        {
            return Err(F6V2Refusal::BindingMismatch);
        }
        Ok(())
    }

    /// Replays a production selection against the exact authority snapshot.
    pub fn validate_against_authority_snapshot(
        self,
        rfq: &RfqV2,
        quote_ids: &[Digest32],
        authority_snapshot_digest: Digest32,
    ) -> Result<(), F6V2Refusal> {
        self.validate()?;
        rfq.validate()?;
        if authority_snapshot_digest == ZERO_DIGEST
            || self.rfq_id != rfq.rfq_id
            || self.composition_id != rfq.route.composition_id
            || self.position != rfq.route.position
            || !quote_ids.contains(&self.winning_quote)
            || self.inputs_digest != authority_snapshot_digest
        {
            return Err(F6V2Refusal::BindingMismatch);
        }
        Ok(())
    }

    /// Canonical strict V2 wire bytes.
    pub fn canonical_bytes(self) -> Result<Vec<u8>, F6V2Refusal> {
        self.validate()?;
        let mut output = Vec::with_capacity(139);
        output.extend_from_slice(SELECTION_V2_MAGIC);
        put_u16(&mut output, WIRE_VERSION_V2);
        output.extend_from_slice(&self.rfq_id);
        output.extend_from_slice(&self.composition_id);
        output.push(self.position as u8);
        output.extend_from_slice(&self.winning_quote);
        output.extend_from_slice(&self.inputs_digest);
        Ok(output)
    }

    /// Strict V2 decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, F6V2Refusal> {
        let mut cursor = Cursor::new(bytes);
        require_header(&mut cursor, SELECTION_V2_MAGIC)?;
        let value = Self {
            rfq_id: cursor.digest()?,
            composition_id: cursor.digest()?,
            position: take_position(&mut cursor)?,
            winning_quote: cursor.digest()?,
            inputs_digest: cursor.digest()?,
        };
        cursor.finish()?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(F6V2Refusal::UnsupportedEncoding);
        }
        Ok(value)
    }
}

/// Pure ratified V2 candidate admissibility. The observation is compared only
/// on the exact negotiation clock; refund clocks do not enter this function.
pub fn admissibility_v2(
    rfq: &RfqV2,
    quote: &QuoteV2,
    facts: &CandidateFactsV1,
    dom_chain_id: ChainId,
    current: NegotiationObservationV2,
) -> Result<(), F6V2Refusal> {
    rfq.validate()?;
    quote.validate()?;
    current.validate()?;
    if current.clock != rfq.negotiation_clock
        || quote.expiry.clock != rfq.negotiation_clock
        || quote.execution_deadline.clock != rfq.negotiation_clock
    {
        return Err(F6V2Refusal::NegotiationClockMismatch);
    }
    if current.value > rfq.quote_deadline.value
        || current.value > quote.expiry.value
        || current.value > quote.execution_deadline.value
    {
        return Err(F6V2Refusal::Expired);
    }
    if quote.rfq_id != rfq.rfq_id || quote.route != rfq.route {
        return Err(F6V2Refusal::BindingMismatch);
    }
    if rfq
        .route
        .legs
        .iter()
        .filter(|leg| leg.chain_id == dom_chain_id)
        .count()
        != 1
    {
        return Err(F6V2Refusal::DomCentrality);
    }
    if !facts.solver_registered || !facts.signature_valid {
        return Err(F6V2Refusal::SolverIdentity);
    }
    if !facts.bond_reserved_exclusive || !facts.exposure_covered {
        return Err(F6V2Refusal::Assurance);
    }
    if !facts.solver_active || !facts.policy_version_accepted {
        return Err(F6V2Refusal::SolverPolicy);
    }
    match rfq.mode {
        RfqModeV1::ExactIn {
            input_amount,
            minimum_output,
        } if quote.total_input == input_amount && quote.net_output >= minimum_output => {}
        RfqModeV1::ExactOut {
            exact_output,
            maximum_input,
        } if quote.net_output == exact_output && quote.total_input <= maximum_input => {}
        _ => return Err(F6V2Refusal::Economics),
    }
    let fee_cap = rfq
        .fee_limit
        .dom_max
        .checked_add(rfq.fee_limit.counterparty_max)
        .ok_or(F6V2Refusal::Overflow)?;
    if quote.total_fee > fee_cap || quote.bond_policy_version != rfq.policy_version {
        return Err(F6V2Refusal::Economics);
    }
    Ok(())
}

/// Deterministic V2 winner selection. Every admissible deadline is already on
/// the exact same negotiation clock, so only native values are compared.
pub fn select_winner_v2(
    rfq: &RfqV2,
    candidates: &[(QuoteV2, CandidateFactsV1)],
    dom_chain_id: ChainId,
    current: NegotiationObservationV2,
) -> Result<SelectionOutcomeV2, F6V2Refusal> {
    let all_ids: Vec<Digest32> = candidates.iter().map(|(quote, _)| quote.quote_id).collect();
    let inputs_digest = candidate_set_digest_v2(
        rfq.route.composition_id,
        rfq.route.position,
        rfq.rfq_id,
        &all_ids,
    )?;
    select_winner_with_authority_digest_v2(rfq, candidates, dom_chain_id, current, inputs_digest)
}

/// Deterministically selects using a digest issued by the candidate authority
/// over quotes and every ranking/admissibility fact.
pub fn select_winner_with_authority_digest_v2(
    rfq: &RfqV2,
    candidates: &[(QuoteV2, CandidateFactsV1)],
    dom_chain_id: ChainId,
    current: NegotiationObservationV2,
    authority_snapshot_digest: Digest32,
) -> Result<SelectionOutcomeV2, F6V2Refusal> {
    if candidates.is_empty()
        || candidates.len() > crate::selection::MAX_CANDIDATES
        || authority_snapshot_digest == ZERO_DIGEST
    {
        return Err(F6V2Refusal::BoundExceeded);
    }
    let verdicts: Vec<(Digest32, Option<F6V2Refusal>)> = candidates
        .iter()
        .map(|(quote, facts)| {
            (
                quote.quote_id,
                admissibility_v2(rfq, quote, facts, dom_chain_id, current).err(),
            )
        })
        .collect();
    let admissible: Vec<&(QuoteV2, CandidateFactsV1)> = candidates
        .iter()
        .zip(verdicts.iter())
        .filter(|(_, (_, refusal))| refusal.is_none())
        .map(|(candidate, _)| candidate)
        .collect();
    if admissible.is_empty() {
        return Err(F6V2Refusal::NoAdmissibleQuote);
    }
    let mut winner: Option<&(QuoteV2, CandidateFactsV1)> = None;
    for candidate in &admissible {
        if admissible
            .iter()
            .any(|other| v2_beats(other, candidate, rfq.mode))
        {
            continue;
        }
        match winner {
            None => winner = Some(candidate),
            Some(current_winner) if current_winner.0.quote_id == candidate.0.quote_id => {}
            Some(_) => return Err(F6V2Refusal::TieUnresolved),
        }
    }
    let winning_quote = winner.ok_or(F6V2Refusal::TieUnresolved)?.0.quote_id;
    Ok(SelectionOutcomeV2 {
        selection: SelectionV2 {
            rfq_id: rfq.rfq_id,
            composition_id: rfq.route.composition_id,
            position: rfq.route.position,
            winning_quote,
            inputs_digest: authority_snapshot_digest,
        },
        verdicts,
    })
}

fn v2_beats(
    candidate: &(QuoteV2, CandidateFactsV1),
    other: &(QuoteV2, CandidateFactsV1),
    mode: RfqModeV1,
) -> bool {
    let economics = match mode {
        RfqModeV1::ExactIn { .. } => candidate.0.net_output.cmp(&other.0.net_output).reverse(),
        RfqModeV1::ExactOut { .. } => candidate.0.total_input.cmp(&other.0.total_input),
    };
    let deadline = candidate
        .0
        .execution_deadline
        .value
        .cmp(&other.0.execution_deadline.value);
    let coverage = candidate
        .1
        .coverage_excess
        .cmp(&other.1.coverage_excess)
        .reverse();
    let solver = candidate.0.solver.0.cmp(&other.0.solver.0);
    economics.then(deadline).then(coverage).then(solver) == std::cmp::Ordering::Less
}

/// V2 candidate-set digest bound to one composition position and RFQ.
pub fn candidate_set_digest_v2(
    composition_id: Digest32,
    position: SettlementPositionV2,
    rfq_id: Digest32,
    quote_ids: &[Digest32],
) -> Result<Digest32, F6V2Refusal> {
    if composition_id == ZERO_DIGEST || rfq_id == ZERO_DIGEST || quote_ids.contains(&ZERO_DIGEST) {
        return Err(F6V2Refusal::InvalidField);
    }
    if quote_ids.is_empty() || quote_ids.len() > crate::selection::MAX_CANDIDATES {
        return Err(F6V2Refusal::BoundExceeded);
    }
    let mut ids = quote_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != quote_ids.len() {
        return Err(F6V2Refusal::BindingMismatch);
    }
    let mut bytes = Vec::with_capacity(65 + ids.len() * 32);
    bytes.extend_from_slice(&composition_id);
    bytes.push(position as u8);
    bytes.extend_from_slice(&rfq_id);
    for id in ids {
        bytes.extend_from_slice(&id);
    }
    digest(CANDIDATE_SET_DOMAIN_V2, &bytes)
}

fn mode_amounts(mode: RfqModeV1) -> (u128, u128) {
    match mode {
        RfqModeV1::ExactIn {
            input_amount,
            minimum_output,
        } => (input_amount, minimum_output),
        RfqModeV1::ExactOut {
            exact_output,
            maximum_input,
        } => (exact_output, maximum_input),
    }
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u128(output: &mut Vec<u8>, value: u128) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_participant(output: &mut Vec<u8>, value: ParticipantId) {
    output.extend_from_slice(&value.0);
}

fn put_route(output: &mut Vec<u8>, route: RouteV2) {
    output.extend_from_slice(&route.composition_id);
    output.push(route.position as u8);
    for leg in route.legs {
        output.extend_from_slice(&leg.chain_id.0);
        output.extend_from_slice(&leg.asset.0);
        output.push(match leg.direction {
            LegDirectionV1::UserGives => 1,
            LegDirectionV1::UserReceives => 2,
        });
    }
}

fn put_mode(output: &mut Vec<u8>, mode: RfqModeV1) {
    match mode {
        RfqModeV1::ExactIn {
            input_amount,
            minimum_output,
        } => {
            output.push(1);
            put_u128(output, input_amount);
            put_u128(output, minimum_output);
        }
        RfqModeV1::ExactOut {
            exact_output,
            maximum_input,
        } => {
            output.push(2);
            put_u128(output, exact_output);
            put_u128(output, maximum_input);
        }
    }
}

fn put_negotiation_clock(output: &mut Vec<u8>, clock: NegotiationClockV2) {
    output.extend_from_slice(&clock.chain_id.0);
    output.extend_from_slice(&clock.profile_digest);
    output.extend_from_slice(&clock.authority_scope);
    output.push(clock.kind as u8);
}

fn put_negotiation_instant(output: &mut Vec<u8>, instant: NegotiationInstantV2) {
    put_negotiation_clock(output, instant.clock);
    put_u64(output, instant.value);
}

fn put_scoped_timelock(output: &mut Vec<u8>, value: ScopedTimelockV2) {
    output.extend_from_slice(&value.chain_id.0);
    output.push(value.kind as u8);
    put_u64(output, value.value);
}

fn put_refund_face(output: &mut Vec<u8>, face: RefundFaceV2) {
    output.push(match face.direction {
        LegDirectionV1::UserGives => 1,
        LegDirectionV1::UserReceives => 2,
    });
    output.extend_from_slice(&face.chain_id.0);
    put_scoped_timelock(output, face.refund_deadline);
    output.extend_from_slice(&face.payout_commitment);
}

fn require_header(cursor: &mut Cursor<'_>, magic: &[u8; 8]) -> Result<(), F6V2Refusal> {
    if cursor.take(8)? != magic || cursor.u16()? != WIRE_VERSION_V2 {
        return Err(F6V2Refusal::UnsupportedEncoding);
    }
    Ok(())
}

fn take_route(cursor: &mut Cursor<'_>) -> Result<RouteV2, F6V2Refusal> {
    let composition_id = cursor.digest()?;
    let position = take_position(cursor)?;
    let legs = [take_leg(cursor)?, take_leg(cursor)?];
    Ok(RouteV2 {
        composition_id,
        position,
        legs,
    })
}

fn take_position(cursor: &mut Cursor<'_>) -> Result<SettlementPositionV2, F6V2Refusal> {
    match cursor.u8()? {
        1 => Ok(SettlementPositionV2::Upstream),
        2 => Ok(SettlementPositionV2::Downstream),
        _ => Err(F6V2Refusal::UnsupportedEncoding),
    }
}

fn take_leg(cursor: &mut Cursor<'_>) -> Result<RouteLegV1, F6V2Refusal> {
    Ok(RouteLegV1 {
        chain_id: ChainId(cursor.digest()?),
        asset: AssetId(cursor.digest()?),
        direction: take_direction(cursor)?,
    })
}

fn take_direction(cursor: &mut Cursor<'_>) -> Result<LegDirectionV1, F6V2Refusal> {
    match cursor.u8()? {
        1 => Ok(LegDirectionV1::UserGives),
        2 => Ok(LegDirectionV1::UserReceives),
        _ => Err(F6V2Refusal::UnsupportedEncoding),
    }
}

fn take_mode(cursor: &mut Cursor<'_>) -> Result<RfqModeV1, F6V2Refusal> {
    match cursor.u8()? {
        1 => Ok(RfqModeV1::ExactIn {
            input_amount: cursor.u128()?,
            minimum_output: cursor.u128()?,
        }),
        2 => Ok(RfqModeV1::ExactOut {
            exact_output: cursor.u128()?,
            maximum_input: cursor.u128()?,
        }),
        _ => Err(F6V2Refusal::UnsupportedEncoding),
    }
}

fn take_clock_kind(cursor: &mut Cursor<'_>) -> Result<NativeClockKindV2, F6V2Refusal> {
    match cursor.u8()? {
        1 => Ok(NativeClockKindV2::BlockHeight),
        2 => Ok(NativeClockKindV2::TimestampSeconds),
        3 => Ok(NativeClockKindV2::BitcoinTime512),
        _ => Err(F6V2Refusal::UnsupportedEncoding),
    }
}

fn take_negotiation_clock(cursor: &mut Cursor<'_>) -> Result<NegotiationClockV2, F6V2Refusal> {
    Ok(NegotiationClockV2 {
        chain_id: ChainId(cursor.digest()?),
        profile_digest: cursor.digest()?,
        authority_scope: cursor.digest()?,
        kind: take_clock_kind(cursor)?,
    })
}

fn take_negotiation_instant(cursor: &mut Cursor<'_>) -> Result<NegotiationInstantV2, F6V2Refusal> {
    Ok(NegotiationInstantV2 {
        clock: take_negotiation_clock(cursor)?,
        value: cursor.u64()?,
    })
}

fn take_scoped_timelock(cursor: &mut Cursor<'_>) -> Result<ScopedTimelockV2, F6V2Refusal> {
    Ok(ScopedTimelockV2 {
        chain_id: ChainId(cursor.digest()?),
        kind: take_clock_kind(cursor)?,
        value: cursor.u64()?,
    })
}

fn take_refund_face(cursor: &mut Cursor<'_>) -> Result<RefundFaceV2, F6V2Refusal> {
    Ok(RefundFaceV2 {
        direction: take_direction(cursor)?,
        chain_id: ChainId(cursor.digest()?),
        refund_deadline: take_scoped_timelock(cursor)?,
        payout_commitment: cursor.digest()?,
    })
}

fn digest(domain: &[u8], bytes: &[u8]) -> Result<Digest32, F6V2Refusal> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| F6V2Refusal::Digest)?;
    hasher.update(domain);
    hasher.update(bytes);
    let mut output = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| F6V2Refusal::Digest)?;
    if output == ZERO_DIGEST {
        return Err(F6V2Refusal::Digest);
    }
    Ok(output)
}

struct Cursor<'bytes> {
    bytes: &'bytes [u8],
    position: usize,
}

impl<'bytes> Cursor<'bytes> {
    fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'bytes [u8], F6V2Refusal> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(F6V2Refusal::Overflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(F6V2Refusal::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], F6V2Refusal> {
        self.take(N)?.try_into().map_err(|_| F6V2Refusal::Truncated)
    }

    fn digest(&mut self) -> Result<Digest32, F6V2Refusal> {
        self.array()
    }

    fn u8(&mut self) -> Result<u8, F6V2Refusal> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, F6V2Refusal> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, F6V2Refusal> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, F6V2Refusal> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u128(&mut self) -> Result<u128, F6V2Refusal> {
        Ok(u128::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), F6V2Refusal> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(F6V2Refusal::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOM_CHAIN: ChainId = ChainId([0xD0; 32]);
    const EVM_CHAIN: ChainId = ChainId([0xE1; 32]);
    const BTC_CHAIN: ChainId = ChainId([0xB7; 32]);
    const DOM_ASSET: AssetId = AssetId([0xDA; 32]);
    const EVM_ASSET: AssetId = AssetId([0xEA; 32]);
    const BTC_ASSET: AssetId = AssetId([0xBA; 32]);

    fn clock() -> NegotiationClockV2 {
        NegotiationClockV2 {
            chain_id: DOM_CHAIN,
            profile_digest: [0x31; 32],
            authority_scope: [0x32; 32],
            kind: NativeClockKindV2::BlockHeight,
        }
    }

    fn instant(value: u64) -> NegotiationInstantV2 {
        NegotiationInstantV2 {
            clock: clock(),
            value,
        }
    }

    fn upstream_route(composition_id: Digest32) -> RouteV2 {
        RouteV2 {
            composition_id,
            position: SettlementPositionV2::Upstream,
            legs: [
                RouteLegV1 {
                    chain_id: EVM_CHAIN,
                    asset: EVM_ASSET,
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: DOM_CHAIN,
                    asset: DOM_ASSET,
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        }
    }

    fn downstream_route(composition_id: Digest32) -> RouteV2 {
        RouteV2 {
            composition_id,
            position: SettlementPositionV2::Downstream,
            legs: [
                RouteLegV1 {
                    chain_id: DOM_CHAIN,
                    asset: DOM_ASSET,
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: BTC_CHAIN,
                    asset: BTC_ASSET,
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        }
    }

    fn request(route: RouteV2) -> RfqRequestV2 {
        RfqRequestV2 {
            initiator: ParticipantId([0x41; 32]),
            route,
            mode: RfqModeV1::ExactIn {
                input_amount: 100,
                minimum_output: 90,
            },
            fee_limit: FeeLimitV1 {
                dom_max: 4,
                counterparty_max: 6,
            },
            negotiation_clock: clock(),
            quote_deadline: instant(1_100),
            assurance_policy_ref: PolicyId([0x42; 32]),
            policy_version: 3,
            session_id: [0x43; 32],
        }
    }

    fn rfq(route: RouteV2) -> Result<RfqV2, F6V2Refusal> {
        RfqV2::create(request(route))
    }

    fn quote(rfq: &RfqV2) -> Result<QuoteV2, F6V2Refusal> {
        QuoteV2::create(QuoteProposalV2 {
            rfq_id: rfq.rfq_id,
            solver: ParticipantId([0x51; 32]),
            route: rfq.route,
            net_output: 95,
            total_input: 100,
            total_fee: 7,
            execution_deadline: instant(1_080),
            bond_reservation_id: [0x52; 32],
            bond_policy_version: 3,
            expiry: instant(1_050),
            solver_signature: [0x53; 64],
        })
    }

    fn upstream_faces() -> [RefundFaceV2; ROUTE_LEGS_V2] {
        [
            RefundFaceV2 {
                direction: LegDirectionV1::UserGives,
                chain_id: EVM_CHAIN,
                refund_deadline: ScopedTimelockV2 {
                    chain_id: EVM_CHAIN,
                    kind: NativeClockKindV2::TimestampSeconds,
                    value: 2_000_000_000,
                },
                payout_commitment: [0x61; 32],
            },
            RefundFaceV2 {
                direction: LegDirectionV1::UserReceives,
                chain_id: DOM_CHAIN,
                refund_deadline: ScopedTimelockV2 {
                    chain_id: DOM_CHAIN,
                    kind: NativeClockKindV2::BlockHeight,
                    value: 1_250,
                },
                payout_commitment: [0x62; 32],
            },
        ]
    }

    fn terms() -> Result<TermsBindingV2, F6V2Refusal> {
        let rfq = rfq(upstream_route([0x11; 32]))?;
        let quote = quote(&rfq)?;
        TermsBindingV2::from_parts(&rfq, &quote, upstream_faces())
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

    #[test]
    fn v2_codecs_are_canonical_and_strict() -> Result<(), F6V2Refusal> {
        let rfq = rfq(upstream_route([0x11; 32]))?;
        let quote = quote(&rfq)?;
        let terms = TermsBindingV2::from_parts(&rfq, &quote, upstream_faces())?;
        let acceptance = AcceptanceV2::from_terms(&terms, rfq.initiator)?;
        let selection = SelectionV2::from_candidates(&rfq, quote.quote_id, &[quote.quote_id])?;

        let rfq_bytes = rfq.canonical_bytes()?;
        let quote_bytes = quote.canonical_bytes()?;
        let terms_bytes = terms.canonical_bytes()?;
        let acceptance_bytes = acceptance.canonical_bytes()?;
        let selection_bytes = selection.canonical_bytes()?;
        assert_eq!(RfqV2::decode(&rfq_bytes)?, rfq);
        assert_eq!(QuoteV2::decode(&quote_bytes)?, quote);
        assert_eq!(TermsBindingV2::decode(&terms_bytes)?, terms);
        assert_eq!(AcceptanceV2::decode(&acceptance_bytes)?, acceptance);
        assert_eq!(SelectionV2::decode(&selection_bytes)?, selection);

        for mut bytes in [
            rfq_bytes,
            quote_bytes,
            terms_bytes,
            acceptance_bytes,
            selection_bytes,
        ] {
            bytes.push(0xA5);
            assert_eq!(
                decode_by_magic_or_terms(&bytes),
                Err(F6V2Refusal::TrailingBytes)
            );
        }
        for mut bytes in [
            rfq.canonical_bytes()?,
            quote.canonical_bytes()?,
            terms.canonical_bytes()?,
            acceptance.canonical_bytes()?,
            selection.canonical_bytes()?,
        ] {
            let _ = bytes.pop();
            assert_eq!(
                decode_by_magic_or_terms(&bytes),
                Err(F6V2Refusal::Truncated)
            );
        }
        Ok(())
    }

    #[test]
    fn production_selection_refuses_stale_candidate_authority_snapshot() -> Result<(), F6V2Refusal>
    {
        let rfq = rfq(upstream_route([0x11; 32]))?;
        let quote = quote(&rfq)?;
        let ids = [quote.quote_id];
        let selection =
            SelectionV2::from_authority_snapshot(&rfq, quote.quote_id, &ids, [0xa1; 32])?;
        selection.validate_against_authority_snapshot(&rfq, &ids, [0xa1; 32])?;
        assert_eq!(
            selection.validate_against_authority_snapshot(&rfq, &ids, [0xa2; 32]),
            Err(F6V2Refusal::BindingMismatch)
        );
        let current = NegotiationObservationV2 {
            clock: rfq.negotiation_clock,
            value: 1_000,
        };
        let first = select_winner_with_authority_digest_v2(
            &rfq,
            &[(quote, facts())],
            DOM_CHAIN,
            current,
            [0xa1; 32],
        )?;
        let mut refreshed_facts = facts();
        refreshed_facts.coverage_excess = 1;
        let refreshed = select_winner_with_authority_digest_v2(
            &rfq,
            &[(quote, refreshed_facts)],
            DOM_CHAIN,
            current,
            [0xa2; 32],
        )?;
        assert_ne!(
            first.selection.inputs_digest,
            refreshed.selection.inputs_digest
        );
        assert_eq!(
            first.selection.validate_against_authority_snapshot(
                &rfq,
                &ids,
                refreshed.selection.inputs_digest,
            ),
            Err(F6V2Refusal::BindingMismatch)
        );
        Ok(())
    }

    fn decode_by_magic_or_terms(bytes: &[u8]) -> Result<(), F6V2Refusal> {
        if bytes.starts_with(RFQ_V2_MAGIC) {
            RfqV2::decode(bytes).map(|_| ())
        } else if bytes.starts_with(QUOTE_V2_MAGIC) {
            QuoteV2::decode(bytes).map(|_| ())
        } else if bytes.starts_with(ACCEPTANCE_V2_MAGIC) {
            AcceptanceV2::decode(bytes).map(|_| ())
        } else if bytes.starts_with(SELECTION_V2_MAGIC) {
            SelectionV2::decode(bytes).map(|_| ())
        } else {
            TermsBindingV2::decode(bytes).map(|_| ())
        }
    }

    #[test]
    fn v2_identifier_and_suffix_tampering_are_refused() -> Result<(), F6V2Refusal> {
        let rfq = rfq(upstream_route([0x11; 32]))?;
        let quote = quote(&rfq)?;
        let terms = TermsBindingV2::from_parts(&rfq, &quote, upstream_faces())?;
        let acceptance = AcceptanceV2::from_terms(&terms, rfq.initiator)?;
        let mut rfq_bytes = rfq.canonical_bytes()?;
        let mut quote_bytes = quote.canonical_bytes()?;
        rfq_bytes[10] ^= 1;
        quote_bytes[10] ^= 1;
        assert_eq!(RfqV2::decode(&rfq_bytes), Err(F6V2Refusal::IdMismatch));
        assert_eq!(QuoteV2::decode(&quote_bytes), Err(F6V2Refusal::IdMismatch));
        let mut acceptance_bytes = acceptance.canonical_bytes()?;
        let position_offset = acceptance_bytes
            .len()
            .checked_sub(33)
            .ok_or(F6V2Refusal::Overflow)?;
        acceptance_bytes[position_offset] = 0xFF;
        assert_eq!(
            AcceptanceV2::decode(&acceptance_bytes),
            Err(F6V2Refusal::UnsupportedEncoding)
        );
        let mut v1_header = Vec::from(*b"DOMIRFQ1");
        put_u16(&mut v1_header, 1);
        assert_eq!(
            RfqV2::decode(&v1_header),
            Err(F6V2Refusal::UnsupportedEncoding)
        );
        Ok(())
    }

    #[test]
    fn negotiation_clock_binds_chain_profile_scope_and_kind() -> Result<(), F6V2Refusal> {
        let rfq = rfq(upstream_route([0x11; 32]))?;
        let quote = quote(&rfq)?;
        admissibility_v2(
            &rfq,
            &quote,
            &facts(),
            DOM_CHAIN,
            NegotiationObservationV2 {
                clock: clock(),
                value: 1_000,
            },
        )?;
        for transplanted in [
            NegotiationClockV2 {
                chain_id: EVM_CHAIN,
                ..clock()
            },
            NegotiationClockV2 {
                profile_digest: [0x71; 32],
                ..clock()
            },
            NegotiationClockV2 {
                authority_scope: [0x72; 32],
                ..clock()
            },
            NegotiationClockV2 {
                kind: NativeClockKindV2::TimestampSeconds,
                ..clock()
            },
        ] {
            assert_eq!(
                admissibility_v2(
                    &rfq,
                    &quote,
                    &facts(),
                    DOM_CHAIN,
                    NegotiationObservationV2 {
                        clock: transplanted,
                        value: 1_000,
                    },
                ),
                Err(F6V2Refusal::NegotiationClockMismatch)
            );
        }
        let bip68 = NegotiationClockV2 {
            kind: NativeClockKindV2::BitcoinTime512,
            ..clock()
        };
        assert_eq!(bip68.validate(), Err(F6V2Refusal::InvalidField));
        Ok(())
    }

    #[test]
    fn heterogeneous_refunds_are_bound_without_clock_conversion() -> Result<(), F6V2Refusal> {
        let terms = terms()?;
        assert_eq!(
            terms.faces[0].refund_deadline.kind,
            NativeClockKindV2::TimestampSeconds
        );
        assert_eq!(
            terms.faces[1].refund_deadline.kind,
            NativeClockKindV2::BlockHeight
        );
        terms.validate()
    }

    #[test]
    fn face_chain_and_payout_transplants_are_refused() -> Result<(), F6V2Refusal> {
        let original = terms()?;
        let acceptance = AcceptanceV2::from_terms(&original, ParticipantId([0x41; 32]))?;

        let mut wrong_chain = original;
        wrong_chain.faces[0].chain_id = BTC_CHAIN;
        assert_eq!(wrong_chain.validate(), Err(F6V2Refusal::FaceMismatch));

        let mut wrong_deadline_chain = original;
        wrong_deadline_chain.faces[0].refund_deadline.chain_id = BTC_CHAIN;
        assert_eq!(
            wrong_deadline_chain.validate(),
            Err(F6V2Refusal::FaceMismatch)
        );

        let mut payout_transplant = original;
        payout_transplant.faces.swap(0, 1);
        assert_eq!(payout_transplant.validate(), Err(F6V2Refusal::FaceMismatch));

        let mut opaque_payout_transplant = original;
        opaque_payout_transplant.faces[0].payout_commitment = [0x99; 32];
        opaque_payout_transplant.validate()?;
        assert_eq!(
            acceptance.validate_against(&opaque_payout_transplant),
            Err(F6V2Refusal::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn composed_pair_requires_opposite_positions_and_exact_dom_hub() -> Result<(), F6V2Refusal> {
        let composition_id = [0x11; 32];
        let upstream = rfq(upstream_route(composition_id))?;
        let downstream = rfq(downstream_route(composition_id))?;
        validate_composed_pair_v2(&upstream, &downstream, DOM_CHAIN)?;

        let same_position = rfq(upstream_route(composition_id))?;
        assert_eq!(
            validate_composed_pair_v2(&upstream, &same_position, DOM_CHAIN),
            Err(F6V2Refusal::BindingMismatch)
        );
        let wrong_composition = rfq(downstream_route([0x12; 32]))?;
        assert_eq!(
            validate_composed_pair_v2(&upstream, &wrong_composition, DOM_CHAIN),
            Err(F6V2Refusal::BindingMismatch)
        );
        let mut wrong_dom_route = downstream_route(composition_id);
        wrong_dom_route.legs[0].asset = AssetId([0xDC; 32]);
        let wrong_dom = rfq(wrong_dom_route)?;
        assert_eq!(
            validate_composed_pair_v2(&upstream, &wrong_dom, DOM_CHAIN),
            Err(F6V2Refusal::DomCentrality)
        );
        Ok(())
    }

    #[test]
    fn selection_and_acceptance_replay_are_position_scoped() -> Result<(), F6V2Refusal> {
        let rfq = rfq(upstream_route([0x11; 32]))?;
        let quote = quote(&rfq)?;
        let terms = TermsBindingV2::from_parts(&rfq, &quote, upstream_faces())?;
        let acceptance = AcceptanceV2::from_terms(&terms, rfq.initiator)?;
        acceptance.validate_against(&terms)?;
        let selection = SelectionV2::from_candidates(&rfq, quote.quote_id, &[quote.quote_id])?;
        selection.validate_against(&rfq, &[quote.quote_id])?;

        let mut wrong_acceptance = acceptance;
        wrong_acceptance.position = SettlementPositionV2::Downstream;
        assert_eq!(
            wrong_acceptance.validate_against(&terms),
            Err(F6V2Refusal::BindingMismatch)
        );
        let mut wrong_selection = selection;
        wrong_selection.composition_id = [0x77; 32];
        assert_eq!(
            wrong_selection.validate_against(&rfq, &[quote.quote_id]),
            Err(F6V2Refusal::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn candidate_commitment_refuses_empty_duplicate_zero_and_cross_scope() -> Result<(), F6V2Refusal>
    {
        let rfq = rfq(upstream_route([0x11; 32]))?;
        let quote = quote(&rfq)?;
        assert_eq!(
            candidate_set_digest_v2(
                rfq.route.composition_id,
                rfq.route.position,
                rfq.rfq_id,
                &[],
            ),
            Err(F6V2Refusal::BoundExceeded)
        );
        assert_eq!(
            candidate_set_digest_v2(
                rfq.route.composition_id,
                rfq.route.position,
                rfq.rfq_id,
                &[quote.quote_id, quote.quote_id],
            ),
            Err(F6V2Refusal::BindingMismatch)
        );
        assert_eq!(
            candidate_set_digest_v2(
                rfq.route.composition_id,
                rfq.route.position,
                rfq.rfq_id,
                &[ZERO_DIGEST],
            ),
            Err(F6V2Refusal::InvalidField)
        );
        let digest = candidate_set_digest_v2(
            rfq.route.composition_id,
            rfq.route.position,
            rfq.rfq_id,
            &[quote.quote_id],
        )?;
        let other_position = candidate_set_digest_v2(
            rfq.route.composition_id,
            SettlementPositionV2::Downstream,
            rfq.rfq_id,
            &[quote.quote_id],
        )?;
        let other_composition = candidate_set_digest_v2(
            [0x12; 32],
            rfq.route.position,
            rfq.rfq_id,
            &[quote.quote_id],
        )?;
        assert_ne!(digest, other_position);
        assert_ne!(digest, other_composition);
        Ok(())
    }

    #[test]
    fn v2_selection_is_arrival_order_independent_and_position_scoped() -> Result<(), F6V2Refusal> {
        let rfq = rfq(upstream_route([0x11; 32]))?;
        let first = quote(&rfq)?;
        let second = QuoteV2::create(QuoteProposalV2 {
            rfq_id: rfq.rfq_id,
            solver: ParticipantId([0x54; 32]),
            route: rfq.route,
            net_output: 96,
            total_input: 100,
            total_fee: 7,
            execution_deadline: instant(1_080),
            bond_reservation_id: [0x55; 32],
            bond_policy_version: 3,
            expiry: instant(1_050),
            solver_signature: [0x56; 64],
        })?;
        let current = NegotiationObservationV2 {
            clock: clock(),
            value: 1_000,
        };
        let forward = select_winner_v2(
            &rfq,
            &[(first, facts()), (second, facts())],
            DOM_CHAIN,
            current,
        )?;
        let reverse = select_winner_v2(
            &rfq,
            &[(second, facts()), (first, facts())],
            DOM_CHAIN,
            current,
        )?;
        assert_eq!(forward.selection.winning_quote, second.quote_id);
        assert_eq!(forward.selection, reverse.selection);
        assert_eq!(forward.selection.position, SettlementPositionV2::Upstream);
        Ok(())
    }
}

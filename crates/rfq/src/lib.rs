//! Normative RFQ objects of the F6 specification §3 (D-018, adopted
//! 2026-08-10): [`RfqV1`], [`QuoteV1`], [`TermsBindingV1`],
//! [`AcceptanceV1`], [`SelectionV1`] — their canonical wire encodings
//! and authority hashes.
//!
//! The codec follows the F2 §6.2 / F4 §5 discipline exactly: leading
//! magic, frozen wire version, fixed field order, big-endian integers,
//! `u8` tags for enums, every length checked before allocation, strict
//! decode that fails closed on truncation, unknown tags and trailing
//! bytes, and `decode(encode(x)) == x` proven by vectors and property
//! tests.
//!
//! Everything here is PUBLIC data. The solver's quote signature is
//! carried as opaque bytes at this layer; its BIP340 verification
//! against the canonical roster key happens in the admissibility check
//! (F6 spec §4.1, build-order step 3) — carrying bytes grants nothing.

#![forbid(unsafe_code)]

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;

// Re-exported so downstream F6 crates can name the field types through
// rfq without importing kaystra-core or uspe themselves (the uspe
// precedent).
pub use kaystra_core::types::{AssetId, ChainId, FeeLimitV1, ParticipantId, TimelockSpec};
pub use uspe::objects::PolicyId;

pub mod fee_policy;
pub mod selection;
/// Versioned heterogeneous-clock F6 objects for production routes.
pub mod v2;

/// Leading magic of every canonical [`RfqV1`] encoding.
pub const RFQ_MAGIC: &[u8; 8] = b"DOMIRFQ1";
/// Leading magic of every canonical [`QuoteV1`] encoding.
pub const QUOTE_MAGIC: &[u8; 8] = b"DOMIQTE1";
/// Leading magic of every canonical [`AcceptanceV1`] encoding.
pub const ACCEPTANCE_MAGIC: &[u8; 8] = b"DOMIACC1";
/// Leading magic of every canonical [`SelectionV1`] encoding.
pub const SELECTION_MAGIC: &[u8; 8] = b"DOMISEL1";
/// Frozen wire version shared by the four F6 objects. Any other version
/// fails closed.
pub const F6_WIRE_VERSION: u16 = 1;
/// Frozen `protocol_version` committed by the terms binding (the first
/// item of the ratified §4.2 list).
pub const F6_PROTOCOL_VERSION: u16 = 1;

/// Domain-separation prefix of the RFQ id digest.
pub const RFQ_DOMAIN: &[u8] = b"DOM-INTEROP/F6-RFQ/V1\0";
/// Domain-separation prefix of the quote id digest.
pub const QUOTE_DOMAIN: &[u8] = b"DOM-INTEROP/F6-QUOTE/V1\0";
/// Domain-separation prefix of the ratified `terms_hash` (spec §4.2).
pub const TERMS_DOMAIN: &[u8] = b"DOM-INTEROP/F6-TERMS/V1\0";
/// Domain-separation prefix of the candidate-set digest (spec §3,
/// `SelectionV1.inputs_digest`).
pub const SELECTION_DOMAIN: &[u8] = b"DOM-INTEROP/F6-SELECTION/V1\0";

/// v1 routes have exactly two legs: what the user gives and what the
/// user receives (the settlement structure of the F2 terms). A later
/// multi-hop route is a new wire version, never a silent extension.
pub const ROUTE_LEGS: usize = 2;

/// One leg of a route: the chain, the asset, and which way value moves
/// from the USER's point of view.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RouteLegV1 {
    /// Chain the leg settles on (32-byte registry id).
    pub chain_id: ChainId,
    /// Asset of the leg (32-byte registry id).
    pub asset: AssetId,
    /// Direction of the leg from the user's point of view.
    pub direction: LegDirectionV1,
}

/// Direction of one route leg.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LegDirectionV1 {
    /// The user gives this asset.
    UserGives,
    /// The user receives this asset.
    UserReceives,
}

/// The v1 route: exactly [`ROUTE_LEGS`] ordered legs, one give and one
/// receive ([`RouteV1::validate`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RouteV1 {
    /// The ordered legs.
    pub legs: [RouteLegV1; ROUTE_LEGS],
}

/// What the RFQ fixes and what it bounds (F6 spec §3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RfqModeV1 {
    /// The input is fixed; the quote competes on output.
    ExactIn {
        /// The exact amount the user gives (smallest unit).
        input_amount: u128,
        /// The least the user accepts to receive; below it, no deal.
        minimum_output: u128,
    },
    /// The output is fixed; the quote competes on input.
    ExactOut {
        /// The exact amount the user must receive.
        exact_output: u128,
        /// The most the user accepts to pay; above it, no deal.
        maximum_input: u128,
    },
}

/// The single timelock domain of one settlement (F6 spec §3
/// `timelock_domain`, the F4 rule): every deadline of the RFQ, its
/// quotes and its terms binding must live here. Comparing across
/// domains would require a conversion, which A4 forbids — mixed
/// domains are refused, never converted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimelockDomainV1 {
    /// Absolute block heights.
    BlockHeight,
    /// Absolute UNIX timestamps in seconds.
    TimestampSeconds,
    /// BTC relative time in 512-second units.
    BtcTime512s,
}

impl TimelockDomainV1 {
    /// The wire tag — identical to the corresponding `TimelockSpec`
    /// variant tag, so a deadline's domain check is a tag equality.
    fn tag(self) -> u8 {
        match self {
            TimelockDomainV1::BlockHeight => 0x01,
            TimelockDomainV1::TimestampSeconds => 0x02,
            TimelockDomainV1::BtcTime512s => 0x03,
        }
    }

    /// Whether the given deadline lives in this domain.
    pub fn contains(self, deadline: TimelockSpec) -> bool {
        timelock_parts(deadline).0 == self.tag()
    }
}

/// A request for quotes (F6 spec §3). The `rfq_id` is derived from the
/// content, never chosen — see [`RfqV1::create`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RfqV1 {
    /// Digest of every other field; an RFQ whose id does not match its
    /// content is invalid.
    pub rfq_id: Digest32,
    /// The requesting participant.
    pub initiator: ParticipantId,
    /// The route to quote.
    pub route: RouteV1,
    /// Exact-in or exact-out, with the user's protection bound.
    pub mode: RfqModeV1,
    /// The RATIFIED F2 fee bound (a quote above it is inadmissible by
    /// the already-ratified rule, F6 spec §3).
    pub fee_limit: FeeLimitV1,
    /// The settlement's single timelock domain (spec §3, the F4 rule).
    pub timelock_domain: TimelockDomainV1,
    /// Deadline for quotes; must live in `timelock_domain`.
    pub quote_deadline: TimelockSpec,
    /// The F4 policy quotes must satisfy (exposure coverage — §4.1.7).
    pub assurance_policy_ref: PolicyId,
    /// Policy version the session accepts (§4.1.10).
    pub policy_version: u32,
    /// Session this RFQ belongs to.
    pub session_id: Digest32,
}

/// A solver's quote (F6 spec §3). The `quote_id` is derived from the
/// content; the signature signs the id and is verified against the
/// roster at admissibility, not here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QuoteV1 {
    /// Digest of every content field (everything but the signature).
    pub quote_id: Digest32,
    /// The RFQ this quote answers.
    pub rfq_id: Digest32,
    /// The quoting solver.
    pub solver: ParticipantId,
    /// Must equal the RFQ route exactly (checked at admissibility —
    /// cross-object, spec §4.1.3).
    pub route: RouteV1,
    /// Exact-in: what the user receives, all costs netted.
    pub net_output: u128,
    /// Exact-out: what the user pays, all costs consolidated.
    pub total_input: u128,
    /// Every cost, consolidated; no cost may exist outside it (§4.1.5).
    pub total_fee: u128,
    /// The solver's execution deadline.
    pub execution_deadline: TimelockSpec,
    /// The EXCLUSIVE F4 bond reservation backing this quote (§4.1.6-8).
    pub bond_reservation_id: Digest32,
    /// Version of the bond policy the reservation was priced under.
    pub bond_policy_version: u32,
    /// Quote expiry (§4.1.2).
    pub expiry: TimelockSpec,
    /// BIP340 signature by the solver's canonical roster key over
    /// `quote_id` (32 bytes). Opaque at this layer.
    pub solver_signature: [u8; 64],
}

/// The ratified §4.2 terms binding: everything the `terms_hash` must
/// commit, assembled from a matching (RFQ, quote) pair plus the
/// per-leg refund deadlines and payout commitments.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TermsBindingV1 {
    /// [`F6_PROTOCOL_VERSION`].
    pub protocol_version: u16,
    /// The accepted RFQ.
    pub rfq_id: Digest32,
    /// The accepted quote.
    pub quote_id: Digest32,
    /// The route both sides agreed on.
    pub route: RouteV1,
    /// The asset the user gives (the route's give leg, committed
    /// explicitly per the ratified list).
    pub input_asset: AssetId,
    /// The RFQ mode — commits `input_amount`, `minimum_output` or
    /// `exact_output`, `maximum_input` (the ratified quartet).
    pub mode: RfqModeV1,
    /// The quote's consolidated fee.
    pub total_fee: u128,
    /// The winning solver.
    pub solver_id: ParticipantId,
    /// The exclusive bond reservation.
    pub bond_reservation_id: Digest32,
    /// The bond policy version.
    pub bond_policy_version: u32,
    /// The solver's execution deadline.
    pub execution_deadline: TimelockSpec,
    /// Refund deadline of each route leg, in route order.
    pub refund_deadlines: [TimelockSpec; ROUTE_LEGS],
    /// Payout commitment of each route leg, in route order (digest of
    /// the leg's payout destination, computed by the owning adapter —
    /// I9: this layer never interprets chain bytes).
    pub payout_commitments: [Digest32; ROUTE_LEGS],
    /// The quote's expiry, committed so a late acceptance is provable.
    pub quote_expiry: TimelockSpec,
    /// The session.
    pub session_id: Digest32,
}

/// The recorded acceptance (F6 spec §3, §4.2 step 5). Both parties
/// persist it; the journaled transition that creates it is build-order
/// step 3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AcceptanceV1 {
    /// The ratified terms binding digest ([`TermsBindingV1::terms_hash`]).
    pub terms_hash: Digest32,
    /// The accepted RFQ.
    pub rfq_id: Digest32,
    /// The accepted quote.
    pub quote_id: Digest32,
    /// Who accepted.
    pub accepted_by: ParticipantId,
}

/// The recorded selection (F6 spec §3): which quote won and the digest
/// of the full candidate set, so any observer can recompute and
/// disprove the choice (I12).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SelectionV1 {
    /// The RFQ selected for.
    pub rfq_id: Digest32,
    /// The winning quote.
    pub winning_quote: Digest32,
    /// [`candidate_set_digest`] over EVERY admissible candidate.
    pub inputs_digest: Digest32,
}

/// Validation and strict-decoding failures of the F6 objects. Every
/// variant is fail-closed and named (I13).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RfqObjectError {
    /// Encoding does not start with the object's frozen magic.
    #[error("invalid magic")]
    InvalidMagic,
    /// Wire version outside the frozen set.
    #[error("invalid version")]
    InvalidVersion,
    /// Encoding ends before the structure is complete.
    #[error("truncated encoding")]
    TruncatedEncoding,
    /// An enum/flag byte carries a tag outside its frozen set.
    #[error("unknown enum tag")]
    UnknownTag,
    /// Bytes remain after the structure is complete.
    #[error("trailing bytes")]
    TrailingBytes,
    /// The route does not have exactly one give and one receive leg.
    #[error("invalid route shape")]
    InvalidRouteShape,
    /// A fixed amount or protection bound is zero: an RFQ that fixes
    /// nothing or protects nothing is refused, never defaulted.
    #[error("zero amount")]
    ZeroAmount,
    /// The object's derived id does not match its content.
    #[error("id does not bind the content")]
    IdMismatch,
    /// The quote does not answer the given RFQ (`rfq_id` divergence).
    #[error("quote does not answer this rfq")]
    RfqMismatch,
    /// The quote's route is not byte-identical to the RFQ's.
    #[error("route divergence")]
    RouteMismatch,
    /// Deadlines given to the terms binding do not live in the RFQ's
    /// single timelock domain (A4: no silent conversion).
    #[error("mixed timelock domains")]
    MixedTimelockDomains,
    /// AD-1.1: the route does not contain the session's DOM chain on
    /// exactly one leg (DOM centrality of the settlement unit).
    #[error("route excludes the DOM")]
    RouteExcludesDom,
    /// The BLAKE2b-256 instance could not be initialized.
    #[error("hash initialization failed")]
    HashInitialization,
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u128(out: &mut Vec<u8>, v: u128) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_timelock(out: &mut Vec<u8>, v: TimelockSpec) {
    let (tag, value) = timelock_parts(v);
    out.push(tag);
    put_u64(out, value);
}

/// (domain tag, value) of a timelock, for same-domain checks.
fn timelock_parts(v: TimelockSpec) -> (u8, u64) {
    match v {
        TimelockSpec::BlockHeight { value } => (0x01, value),
        TimelockSpec::TimestampSeconds { value } => (0x02, value),
        TimelockSpec::BtcTime512s { value } => (0x03, value),
    }
}

fn put_route(out: &mut Vec<u8>, route: &RouteV1) {
    for leg in &route.legs {
        out.extend_from_slice(&leg.chain_id.0);
        out.extend_from_slice(&leg.asset.0);
        out.push(match leg.direction {
            LegDirectionV1::UserGives => 0x01,
            LegDirectionV1::UserReceives => 0x02,
        });
    }
}

fn put_mode(out: &mut Vec<u8>, mode: RfqModeV1) {
    match mode {
        RfqModeV1::ExactIn {
            input_amount,
            minimum_output,
        } => {
            out.push(0x01);
            put_u128(out, input_amount);
            put_u128(out, minimum_output);
        }
        RfqModeV1::ExactOut {
            exact_output,
            maximum_input,
        } => {
            out.push(0x02);
            put_u128(out, exact_output);
            put_u128(out, maximum_input);
        }
    }
}

/// Strict big-endian cursor over one encoding. Every read is
/// bounds-checked and fails closed.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], RfqObjectError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(RfqObjectError::TruncatedEncoding)?;
        if end > self.bytes.len() {
            return Err(RfqObjectError::TruncatedEncoding);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], RfqObjectError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8, RfqObjectError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, RfqObjectError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32, RfqObjectError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, RfqObjectError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_u128(&mut self) -> Result<u128, RfqObjectError> {
        Ok(u128::from_be_bytes(self.take_array()?))
    }

    fn take_32(&mut self) -> Result<[u8; 32], RfqObjectError> {
        self.take_array()
    }

    fn finished(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn take_timelock(c: &mut Cursor<'_>) -> Result<TimelockSpec, RfqObjectError> {
    let tag = c.take_u8()?;
    let value = c.take_u64()?;
    match tag {
        0x01 => Ok(TimelockSpec::BlockHeight { value }),
        0x02 => Ok(TimelockSpec::TimestampSeconds { value }),
        0x03 => Ok(TimelockSpec::BtcTime512s { value }),
        _ => Err(RfqObjectError::UnknownTag),
    }
}

fn take_route(c: &mut Cursor<'_>) -> Result<RouteV1, RfqObjectError> {
    let mut legs = [RouteLegV1 {
        chain_id: ChainId([0u8; 32]),
        asset: AssetId([0u8; 32]),
        direction: LegDirectionV1::UserGives,
    }; ROUTE_LEGS];
    for leg in &mut legs {
        let chain_id = ChainId(c.take_32()?);
        let asset = AssetId(c.take_32()?);
        let direction = match c.take_u8()? {
            0x01 => LegDirectionV1::UserGives,
            0x02 => LegDirectionV1::UserReceives,
            _ => return Err(RfqObjectError::UnknownTag),
        };
        *leg = RouteLegV1 {
            chain_id,
            asset,
            direction,
        };
    }
    Ok(RouteV1 { legs })
}

fn take_mode(c: &mut Cursor<'_>) -> Result<RfqModeV1, RfqObjectError> {
    match c.take_u8()? {
        0x01 => Ok(RfqModeV1::ExactIn {
            input_amount: c.take_u128()?,
            minimum_output: c.take_u128()?,
        }),
        0x02 => Ok(RfqModeV1::ExactOut {
            exact_output: c.take_u128()?,
            maximum_input: c.take_u128()?,
        }),
        _ => Err(RfqObjectError::UnknownTag),
    }
}

fn digest32(domain: &[u8], bytes: &[u8]) -> Result<Digest32, RfqObjectError> {
    let mut h = Blake2bVar::new(32).map_err(|_| RfqObjectError::HashInitialization)?;
    h.update(domain);
    h.update(bytes);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out)
        .map_err(|_| RfqObjectError::HashInitialization)?;
    Ok(out)
}

impl RouteV1 {
    /// Exactly one give and one receive leg (v1 shape).
    pub fn validate(&self) -> Result<(), RfqObjectError> {
        let gives = self
            .legs
            .iter()
            .filter(|l| l.direction == LegDirectionV1::UserGives)
            .count();
        if gives != 1 {
            return Err(RfqObjectError::InvalidRouteShape);
        }
        Ok(())
    }

    /// The asset of the give leg — `input_asset` of the terms binding.
    pub fn input_asset(&self) -> Result<AssetId, RfqObjectError> {
        self.validate()?;
        self.legs
            .iter()
            .find(|l| l.direction == LegDirectionV1::UserGives)
            .map(|l| l.asset)
            .ok_or(RfqObjectError::InvalidRouteShape)
    }
}

impl RfqModeV1 {
    fn validate(&self) -> Result<(), RfqObjectError> {
        let (a, b) = match *self {
            RfqModeV1::ExactIn {
                input_amount,
                minimum_output,
            } => (input_amount, minimum_output),
            RfqModeV1::ExactOut {
                exact_output,
                maximum_input,
            } => (exact_output, maximum_input),
        };
        if a == 0 || b == 0 {
            return Err(RfqObjectError::ZeroAmount);
        }
        Ok(())
    }
}

impl RfqV1 {
    /// Creates an RFQ, deriving the binding id over the content.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        initiator: ParticipantId,
        route: RouteV1,
        mode: RfqModeV1,
        fee_limit: FeeLimitV1,
        timelock_domain: TimelockDomainV1,
        quote_deadline: TimelockSpec,
        assurance_policy_ref: PolicyId,
        policy_version: u32,
        session_id: Digest32,
    ) -> Result<Self, RfqObjectError> {
        let mut rfq = Self {
            rfq_id: [0u8; 32],
            initiator,
            route,
            mode,
            fee_limit,
            timelock_domain,
            quote_deadline,
            assurance_policy_ref,
            policy_version,
            session_id,
        };
        rfq.rfq_id = rfq.derive_id()?;
        rfq.validate()?;
        Ok(rfq)
    }

    /// Canonical encoding of every field EXCEPT the id, in wire order.
    fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(304);
        out.extend_from_slice(RFQ_MAGIC);
        put_u16(&mut out, F6_WIRE_VERSION);
        out.extend_from_slice(&self.initiator.0);
        put_route(&mut out, &self.route);
        put_mode(&mut out, self.mode);
        put_u128(&mut out, self.fee_limit.dom_max);
        put_u128(&mut out, self.fee_limit.counterparty_max);
        out.push(self.timelock_domain.tag());
        put_timelock(&mut out, self.quote_deadline);
        out.extend_from_slice(&self.assurance_policy_ref.0);
        put_u32(&mut out, self.policy_version);
        out.extend_from_slice(&self.session_id);
        out
    }

    /// `BLAKE2b-256(RFQ_DOMAIN || body_bytes)`: the id an RFQ with this
    /// content MUST carry.
    pub fn derive_id(&self) -> Result<Digest32, RfqObjectError> {
        digest32(RFQ_DOMAIN, &self.body_bytes())
    }

    /// Structural validity + id binding. The quote deadline must live
    /// in the RFQ's declared timelock domain (spec §3; A4: refused,
    /// never converted).
    pub fn validate(&self) -> Result<(), RfqObjectError> {
        self.route.validate()?;
        self.mode.validate()?;
        if !self.timelock_domain.contains(self.quote_deadline) {
            return Err(RfqObjectError::MixedTimelockDomains);
        }
        if self.rfq_id != self.derive_id()? {
            return Err(RfqObjectError::IdMismatch);
        }
        Ok(())
    }

    /// Canonical wire: magic, version, id, then the body fields.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RfqObjectError> {
        self.validate()?;
        let body = self.body_bytes();
        let mut out = Vec::with_capacity(body.len() + 32);
        out.extend_from_slice(&body[..RFQ_MAGIC.len() + 2]);
        out.extend_from_slice(&self.rfq_id);
        out.extend_from_slice(&body[RFQ_MAGIC.len() + 2..]);
        Ok(out)
    }

    /// Strict decoder; same fail-closed rules as every F6 codec, plus
    /// the id-binding check.
    pub fn decode(bytes: &[u8]) -> Result<Self, RfqObjectError> {
        let mut c = Cursor::new(bytes);
        if c.take(RFQ_MAGIC.len())? != RFQ_MAGIC {
            return Err(RfqObjectError::InvalidMagic);
        }
        if c.take_u16()? != F6_WIRE_VERSION {
            return Err(RfqObjectError::InvalidVersion);
        }
        let rfq_id = c.take_32()?;
        let initiator = ParticipantId(c.take_32()?);
        let route = take_route(&mut c)?;
        let mode = take_mode(&mut c)?;
        let fee_limit = FeeLimitV1 {
            dom_max: c.take_u128()?,
            counterparty_max: c.take_u128()?,
        };
        let timelock_domain = match c.take_u8()? {
            0x01 => TimelockDomainV1::BlockHeight,
            0x02 => TimelockDomainV1::TimestampSeconds,
            0x03 => TimelockDomainV1::BtcTime512s,
            _ => return Err(RfqObjectError::UnknownTag),
        };
        let quote_deadline = take_timelock(&mut c)?;
        let assurance_policy_ref = PolicyId(c.take_32()?);
        let policy_version = c.take_u32()?;
        let session_id = c.take_32()?;
        if !c.finished() {
            return Err(RfqObjectError::TrailingBytes);
        }
        let rfq = Self {
            rfq_id,
            initiator,
            route,
            mode,
            fee_limit,
            timelock_domain,
            quote_deadline,
            assurance_policy_ref,
            policy_version,
            session_id,
        };
        rfq.validate()?;
        Ok(rfq)
    }
}

impl QuoteV1 {
    /// Creates a quote, deriving the binding id over the content. The
    /// signature is provided by the caller (the solver signs
    /// `quote_id`) and is NOT part of the digested content.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        rfq_id: Digest32,
        solver: ParticipantId,
        route: RouteV1,
        net_output: u128,
        total_input: u128,
        total_fee: u128,
        execution_deadline: TimelockSpec,
        bond_reservation_id: Digest32,
        bond_policy_version: u32,
        expiry: TimelockSpec,
        solver_signature: [u8; 64],
    ) -> Result<Self, RfqObjectError> {
        let mut quote = Self {
            quote_id: [0u8; 32],
            rfq_id,
            solver,
            route,
            net_output,
            total_input,
            total_fee,
            execution_deadline,
            bond_reservation_id,
            bond_policy_version,
            expiry,
            solver_signature,
        };
        quote.quote_id = quote.derive_id()?;
        quote.validate()?;
        Ok(quote)
    }

    /// Canonical encoding of every content field EXCEPT the id and the
    /// signature, in wire order.
    fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(304);
        out.extend_from_slice(QUOTE_MAGIC);
        put_u16(&mut out, F6_WIRE_VERSION);
        out.extend_from_slice(&self.rfq_id);
        out.extend_from_slice(&self.solver.0);
        put_route(&mut out, &self.route);
        put_u128(&mut out, self.net_output);
        put_u128(&mut out, self.total_input);
        put_u128(&mut out, self.total_fee);
        put_timelock(&mut out, self.execution_deadline);
        out.extend_from_slice(&self.bond_reservation_id);
        put_u32(&mut out, self.bond_policy_version);
        put_timelock(&mut out, self.expiry);
        out
    }

    /// `BLAKE2b-256(QUOTE_DOMAIN || body_bytes)`: the id a quote with
    /// this content MUST carry — and the 32-byte message the solver's
    /// BIP340 signature signs.
    pub fn derive_id(&self) -> Result<Digest32, RfqObjectError> {
        digest32(QUOTE_DOMAIN, &self.body_bytes())
    }

    /// Structural validity + id binding. Cross-object checks (route
    /// equality with the RFQ, fee bound, bond coverage, roster
    /// membership, signature) are the §4.1 admissibility rule.
    pub fn validate(&self) -> Result<(), RfqObjectError> {
        self.route.validate()?;
        if self.quote_id != self.derive_id()? {
            return Err(RfqObjectError::IdMismatch);
        }
        Ok(())
    }

    /// Canonical wire: magic, version, id, body fields, signature last.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RfqObjectError> {
        self.validate()?;
        let body = self.body_bytes();
        let mut out = Vec::with_capacity(body.len() + 32 + 64);
        out.extend_from_slice(&body[..QUOTE_MAGIC.len() + 2]);
        out.extend_from_slice(&self.quote_id);
        out.extend_from_slice(&body[QUOTE_MAGIC.len() + 2..]);
        out.extend_from_slice(&self.solver_signature);
        Ok(out)
    }

    /// Strict decoder; same fail-closed rules, plus the id binding.
    pub fn decode(bytes: &[u8]) -> Result<Self, RfqObjectError> {
        let mut c = Cursor::new(bytes);
        if c.take(QUOTE_MAGIC.len())? != QUOTE_MAGIC {
            return Err(RfqObjectError::InvalidMagic);
        }
        if c.take_u16()? != F6_WIRE_VERSION {
            return Err(RfqObjectError::InvalidVersion);
        }
        let quote_id = c.take_32()?;
        let rfq_id = c.take_32()?;
        let solver = ParticipantId(c.take_32()?);
        let route = take_route(&mut c)?;
        let net_output = c.take_u128()?;
        let total_input = c.take_u128()?;
        let total_fee = c.take_u128()?;
        let execution_deadline = take_timelock(&mut c)?;
        let bond_reservation_id = c.take_32()?;
        let bond_policy_version = c.take_u32()?;
        let expiry = take_timelock(&mut c)?;
        let solver_signature: [u8; 64] = c.take_array()?;
        if !c.finished() {
            return Err(RfqObjectError::TrailingBytes);
        }
        let quote = Self {
            quote_id,
            rfq_id,
            solver,
            route,
            net_output,
            total_input,
            total_fee,
            execution_deadline,
            bond_reservation_id,
            bond_policy_version,
            expiry,
            solver_signature,
        };
        quote.validate()?;
        Ok(quote)
    }
}

impl TermsBindingV1 {
    /// Assembles the ratified binding from a matching (RFQ, quote) pair
    /// plus the per-leg refund deadlines and payout commitments.
    /// Refuses a quote that does not answer the RFQ, a route
    /// divergence, and any deadline outside the RFQ's timelock domain
    /// (A4: never converted, always refused).
    pub fn from_parts(
        rfq: &RfqV1,
        quote: &QuoteV1,
        refund_deadlines: [TimelockSpec; ROUTE_LEGS],
        payout_commitments: [Digest32; ROUTE_LEGS],
    ) -> Result<Self, RfqObjectError> {
        rfq.validate()?;
        quote.validate()?;
        if quote.rfq_id != rfq.rfq_id {
            return Err(RfqObjectError::RfqMismatch);
        }
        if quote.route != rfq.route {
            return Err(RfqObjectError::RouteMismatch);
        }
        for deadline in refund_deadlines
            .iter()
            .chain([&quote.execution_deadline, &quote.expiry])
        {
            if !rfq.timelock_domain.contains(*deadline) {
                return Err(RfqObjectError::MixedTimelockDomains);
            }
        }
        Ok(Self {
            protocol_version: F6_PROTOCOL_VERSION,
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
            refund_deadlines,
            payout_commitments,
            quote_expiry: quote.expiry,
            session_id: rfq.session_id,
        })
    }

    /// Canonical encoding of the ratified §4.2 commitment list, in the
    /// ratified order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        put_u16(&mut out, self.protocol_version);
        out.extend_from_slice(&self.rfq_id);
        out.extend_from_slice(&self.quote_id);
        put_route(&mut out, &self.route);
        out.extend_from_slice(&self.input_asset.0);
        put_mode(&mut out, self.mode);
        put_u128(&mut out, self.total_fee);
        out.extend_from_slice(&self.solver_id.0);
        out.extend_from_slice(&self.bond_reservation_id);
        put_u32(&mut out, self.bond_policy_version);
        put_timelock(&mut out, self.execution_deadline);
        for deadline in &self.refund_deadlines {
            put_timelock(&mut out, *deadline);
        }
        for commitment in &self.payout_commitments {
            out.extend_from_slice(commitment);
        }
        put_timelock(&mut out, self.quote_expiry);
        out.extend_from_slice(&self.session_id);
        out
    }

    /// The ratified `terms_hash`:
    /// `BLAKE2b-256(TERMS_DOMAIN || canonical_bytes)`. After
    /// acceptance, any material change changes this value — which is
    /// exactly why a change requires a new quote and a new approval.
    pub fn terms_hash(&self) -> Result<Digest32, RfqObjectError> {
        digest32(TERMS_DOMAIN, &self.canonical_bytes())
    }
}

impl AcceptanceV1 {
    /// Canonical wire encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(138);
        out.extend_from_slice(ACCEPTANCE_MAGIC);
        put_u16(&mut out, F6_WIRE_VERSION);
        out.extend_from_slice(&self.terms_hash);
        out.extend_from_slice(&self.rfq_id);
        out.extend_from_slice(&self.quote_id);
        out.extend_from_slice(&self.accepted_by.0);
        out
    }

    /// Strict decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, RfqObjectError> {
        let mut c = Cursor::new(bytes);
        if c.take(ACCEPTANCE_MAGIC.len())? != ACCEPTANCE_MAGIC {
            return Err(RfqObjectError::InvalidMagic);
        }
        if c.take_u16()? != F6_WIRE_VERSION {
            return Err(RfqObjectError::InvalidVersion);
        }
        let terms_hash = c.take_32()?;
        let rfq_id = c.take_32()?;
        let quote_id = c.take_32()?;
        let accepted_by = ParticipantId(c.take_32()?);
        if !c.finished() {
            return Err(RfqObjectError::TrailingBytes);
        }
        Ok(Self {
            terms_hash,
            rfq_id,
            quote_id,
            accepted_by,
        })
    }
}

/// Digest of the full candidate set: the quote ids are SORTED
/// lexicographically before hashing, so the digest is independent of
/// arrival order — the ratified rule that keeps the Relay out of the
/// selection (spec §4.3).
pub fn candidate_set_digest(quote_ids: &[Digest32]) -> Result<Digest32, RfqObjectError> {
    let mut sorted: Vec<Digest32> = quote_ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut bytes = Vec::with_capacity(sorted.len() * 32);
    for id in &sorted {
        bytes.extend_from_slice(id);
    }
    digest32(SELECTION_DOMAIN, &bytes)
}

impl SelectionV1 {
    /// Canonical wire encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(106);
        out.extend_from_slice(SELECTION_MAGIC);
        put_u16(&mut out, F6_WIRE_VERSION);
        out.extend_from_slice(&self.rfq_id);
        out.extend_from_slice(&self.winning_quote);
        out.extend_from_slice(&self.inputs_digest);
        out
    }

    /// Strict decoder.
    pub fn decode(bytes: &[u8]) -> Result<Self, RfqObjectError> {
        let mut c = Cursor::new(bytes);
        if c.take(SELECTION_MAGIC.len())? != SELECTION_MAGIC {
            return Err(RfqObjectError::InvalidMagic);
        }
        if c.take_u16()? != F6_WIRE_VERSION {
            return Err(RfqObjectError::InvalidVersion);
        }
        let rfq_id = c.take_32()?;
        let winning_quote = c.take_32()?;
        let inputs_digest = c.take_32()?;
        if !c.finished() {
            return Err(RfqObjectError::TrailingBytes);
        }
        Ok(Self {
            rfq_id,
            winning_quote,
            inputs_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(x: u8) -> [u8; 32] {
        [x; 32]
    }

    fn sample_route() -> RouteV1 {
        RouteV1 {
            legs: [
                RouteLegV1 {
                    chain_id: ChainId(b32(0x11)),
                    asset: AssetId(b32(0x12)),
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: ChainId(b32(0x21)),
                    asset: AssetId(b32(0x22)),
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        }
    }

    fn ts(value: u64) -> TimelockSpec {
        TimelockSpec::TimestampSeconds { value }
    }

    fn sample_rfq() -> RfqV1 {
        RfqV1::create(
            ParticipantId(b32(0x31)),
            sample_route(),
            RfqModeV1::ExactIn {
                input_amount: 1_000,
                minimum_output: 950,
            },
            FeeLimitV1 {
                dom_max: 50,
                counterparty_max: 40,
            },
            TimelockDomainV1::TimestampSeconds,
            ts(10_000),
            PolicyId(b32(0x41)),
            1,
            b32(0x51),
        )
        .unwrap()
    }

    fn sample_quote() -> QuoteV1 {
        QuoteV1::create(
            sample_rfq().rfq_id,
            ParticipantId(b32(0x61)),
            sample_route(),
            980,
            1_000,
            20,
            ts(20_000),
            b32(0x71),
            1,
            ts(9_000),
            [0xabu8; 64],
        )
        .unwrap()
    }

    fn sample_binding() -> TermsBindingV1 {
        TermsBindingV1::from_parts(
            &sample_rfq(),
            &sample_quote(),
            [ts(30_000), ts(40_000)],
            [b32(0x81), b32(0x82)],
        )
        .unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rfq_roundtrip_is_the_identity() {
        let rfq = sample_rfq();
        assert_eq!(RfqV1::decode(&rfq.canonical_bytes().unwrap()).unwrap(), rfq);
    }

    #[test]
    fn quote_roundtrip_is_the_identity() {
        let quote = sample_quote();
        assert_eq!(
            QuoteV1::decode(&quote.canonical_bytes().unwrap()).unwrap(),
            quote
        );
    }

    #[test]
    fn acceptance_and_selection_roundtrip() {
        let acceptance = AcceptanceV1 {
            terms_hash: sample_binding().terms_hash().unwrap(),
            rfq_id: sample_rfq().rfq_id,
            quote_id: sample_quote().quote_id,
            accepted_by: ParticipantId(b32(0x31)),
        };
        assert_eq!(
            AcceptanceV1::decode(&acceptance.canonical_bytes()).unwrap(),
            acceptance
        );
        let selection = SelectionV1 {
            rfq_id: sample_rfq().rfq_id,
            winning_quote: sample_quote().quote_id,
            inputs_digest: candidate_set_digest(&[sample_quote().quote_id]).unwrap(),
        };
        assert_eq!(
            SelectionV1::decode(&selection.canonical_bytes()).unwrap(),
            selection
        );
    }

    /// Frozen vectors: encoding lengths and authority digests of the
    /// samples above. A codec change that alters any byte breaks these
    /// on purpose (spec §3: vectors are frozen at first implementation
    /// and never edited).
    #[test]
    fn frozen_vectors_hold() {
        let rfq = sample_rfq();
        let rfq_bytes = rfq.canonical_bytes().unwrap();
        assert_eq!(&rfq_bytes[..10], b"DOMIRFQ1\x00\x01");
        assert_eq!(rfq_bytes.len(), 347);
        assert_eq!(
            hex(&rfq.rfq_id),
            "e4345d8ecbe1394ebb28db0961edeca1ca02dc04fb8aec54cc9d1d18e89353ef",
        );

        let quote = sample_quote();
        let quote_bytes = quote.canonical_bytes().unwrap();
        assert_eq!(&quote_bytes[..10], b"DOMIQTE1\x00\x01");
        assert_eq!(quote_bytes.len(), 402);
        assert_eq!(
            hex(&quote.quote_id),
            "7d9cde80a6aa8c238b78696e85864e71cc79b8c63adb3f966b7cb31cad67a598",
        );

        let binding = sample_binding();
        assert_eq!(binding.canonical_bytes().len(), 477);
        assert_eq!(
            hex(&binding.terms_hash().unwrap()),
            "cdd7dff5cea06db9a9ce081db65a08d8573668c5f65408b7f661f0b912aeec19",
        );

        assert_eq!(
            hex(&candidate_set_digest(&[quote.quote_id]).unwrap()),
            "fb797713dca0866748f397431a61a90612a22613913376f3f97cefd6bf4b5ce0",
        );
    }

    #[test]
    fn zero_amounts_are_refused() {
        for mode in [
            RfqModeV1::ExactIn {
                input_amount: 0,
                minimum_output: 950,
            },
            RfqModeV1::ExactIn {
                input_amount: 1_000,
                minimum_output: 0,
            },
            RfqModeV1::ExactOut {
                exact_output: 0,
                maximum_input: 1,
            },
            RfqModeV1::ExactOut {
                exact_output: 1,
                maximum_input: 0,
            },
        ] {
            let mut rfq = sample_rfq();
            rfq.mode = mode;
            rfq.rfq_id = rfq.derive_id().unwrap();
            assert_eq!(rfq.validate().unwrap_err(), RfqObjectError::ZeroAmount);
        }
    }

    #[test]
    fn out_of_domain_quote_deadline_is_refused() {
        // The spec-listed timelock_domain field governs: a deadline in
        // any other domain is refused, never converted (A4).
        let mut rfq = sample_rfq();
        rfq.quote_deadline = TimelockSpec::BlockHeight { value: 10_000 };
        rfq.rfq_id = rfq.derive_id().unwrap();
        assert_eq!(
            rfq.validate().unwrap_err(),
            RfqObjectError::MixedTimelockDomains
        );
    }

    #[test]
    fn route_needs_exactly_one_give_and_one_receive() {
        for direction in [LegDirectionV1::UserGives, LegDirectionV1::UserReceives] {
            let mut route = sample_route();
            route.legs[0].direction = direction;
            route.legs[1].direction = direction;
            assert_eq!(
                route.validate().unwrap_err(),
                RfqObjectError::InvalidRouteShape
            );
        }
    }

    #[test]
    fn ids_bind_the_content() {
        let mut rfq = sample_rfq();
        rfq.session_id[0] ^= 0x01;
        assert_eq!(rfq.validate().unwrap_err(), RfqObjectError::IdMismatch);

        let mut quote = sample_quote();
        quote.total_fee += 1;
        assert_eq!(quote.validate().unwrap_err(), RfqObjectError::IdMismatch);

        // The signature is NOT digested content: a different signature
        // over the same content keeps the same id (the roster check
        // adjudicates it, spec §4.1.1).
        let mut resigned = sample_quote();
        resigned.solver_signature = [0xcd; 64];
        assert!(resigned.validate().is_ok());
        assert_eq!(resigned.quote_id, sample_quote().quote_id);
    }

    #[test]
    fn rfq_decode_rejects_any_single_byte_flip() {
        let bytes = sample_rfq().canonical_bytes().unwrap();
        for i in 0..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[i] ^= 0x01;
            assert!(
                RfqV1::decode(&flipped).is_err(),
                "byte {i} flipped and the rfq still decoded"
            );
        }
    }

    #[test]
    fn quote_decode_rejects_any_content_byte_flip() {
        let bytes = sample_quote().canonical_bytes().unwrap();
        // Everything but the trailing 64 signature bytes is id-bound;
        // a signature flip decodes (the roster check owns it).
        for i in 0..bytes.len() - 64 {
            let mut flipped = bytes.clone();
            flipped[i] ^= 0x01;
            assert!(
                QuoteV1::decode(&flipped).is_err(),
                "byte {i} flipped and the quote still decoded"
            );
        }
    }

    #[test]
    fn decode_rejects_truncation_and_trailing() {
        let bytes = sample_rfq().canonical_bytes().unwrap();
        for cut in [0, 1, 9, 10, bytes.len() - 1] {
            assert_eq!(
                RfqV1::decode(&bytes[..cut]).unwrap_err(),
                RfqObjectError::TruncatedEncoding,
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert_eq!(
            RfqV1::decode(&trailing).unwrap_err(),
            RfqObjectError::TrailingBytes
        );
    }

    #[test]
    fn terms_binding_refuses_mismatches() {
        let rfq = sample_rfq();
        let mut foreign = sample_quote();
        foreign.rfq_id = b32(0x99);
        foreign.quote_id = foreign.derive_id().unwrap();
        assert_eq!(
            TermsBindingV1::from_parts(
                &rfq,
                &foreign,
                [ts(30_000), ts(40_000)],
                [b32(0x81), b32(0x82)]
            )
            .unwrap_err(),
            RfqObjectError::RfqMismatch
        );

        let mut wrong_route = sample_quote();
        wrong_route.route.legs.swap(0, 1);
        wrong_route.quote_id = wrong_route.derive_id().unwrap();
        assert_eq!(
            TermsBindingV1::from_parts(
                &rfq,
                &wrong_route,
                [ts(30_000), ts(40_000)],
                [b32(0x81), b32(0x82)]
            )
            .unwrap_err(),
            RfqObjectError::RouteMismatch
        );

        assert_eq!(
            TermsBindingV1::from_parts(
                &rfq,
                &sample_quote(),
                [TimelockSpec::BlockHeight { value: 5 }, ts(40_000)],
                [b32(0x81), b32(0x82)]
            )
            .unwrap_err(),
            RfqObjectError::MixedTimelockDomains
        );
    }

    #[test]
    fn terms_hash_commits_every_ratified_field() {
        // Flipping ANY byte of the canonical binding changes the hash:
        // the after-acceptance immutability rule (§4.2) rests on this.
        let binding = sample_binding();
        let h = binding.terms_hash().unwrap();
        let bytes = binding.canonical_bytes();
        for i in 0..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[i] ^= 0x01;
            let other = digest32(TERMS_DOMAIN, &flipped).unwrap();
            assert_ne!(h, other, "byte {i} does not participate in terms_hash");
        }
    }

    #[test]
    fn candidate_set_digest_is_arrival_order_independent() {
        let a = b32(0xa1);
        let b = b32(0xb2);
        let c = b32(0xc3);
        let d1 = candidate_set_digest(&[a, b, c]).unwrap();
        let d2 = candidate_set_digest(&[c, a, b]).unwrap();
        let d3 = candidate_set_digest(&[b, c, a, a]).unwrap(); // dup collapses
        assert_eq!(d1, d2);
        assert_eq!(d1, d3);
        let smaller = candidate_set_digest(&[a, b]).unwrap();
        assert_ne!(d1, smaller, "the set content participates");
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        fn arb_timelock() -> impl Strategy<Value = TimelockSpec> {
            (0u8..3, any::<u64>()).prop_map(|(tag, value)| match tag {
                0 => TimelockSpec::BlockHeight { value },
                1 => TimelockSpec::TimestampSeconds { value },
                _ => TimelockSpec::BtcTime512s { value },
            })
        }

        proptest! {
            #[test]
            fn rfq_roundtrip(
                initiator in any::<[u8; 32]>(),
                give_chain in any::<[u8; 32]>(),
                give_asset in any::<[u8; 32]>(),
                recv_chain in any::<[u8; 32]>(),
                recv_asset in any::<[u8; 32]>(),
                input_amount in 1u128..,
                minimum_output in 1u128..,
                dom_max in any::<u128>(),
                counterparty_max in any::<u128>(),
                quote_deadline in arb_timelock(),
                policy in any::<[u8; 32]>(),
                policy_version in any::<u32>(),
                session in any::<[u8; 32]>(),
            ) {
                let rfq = RfqV1::create(
                    ParticipantId(initiator),
                    RouteV1 { legs: [
                        RouteLegV1 { chain_id: ChainId(give_chain), asset: AssetId(give_asset), direction: LegDirectionV1::UserGives },
                        RouteLegV1 { chain_id: ChainId(recv_chain), asset: AssetId(recv_asset), direction: LegDirectionV1::UserReceives },
                    ]},
                    RfqModeV1::ExactIn { input_amount, minimum_output },
                    FeeLimitV1 { dom_max, counterparty_max },
                    match quote_deadline {
                        TimelockSpec::BlockHeight { .. } => TimelockDomainV1::BlockHeight,
                        TimelockSpec::TimestampSeconds { .. } => TimelockDomainV1::TimestampSeconds,
                        TimelockSpec::BtcTime512s { .. } => TimelockDomainV1::BtcTime512s,
                    },
                    quote_deadline,
                    PolicyId(policy),
                    policy_version,
                    session,
                ).unwrap();
                let bytes = rfq.canonical_bytes().unwrap();
                prop_assert_eq!(RfqV1::decode(&bytes).unwrap(), rfq);
            }

            #[test]
            fn quote_roundtrip(
                rfq_id in any::<[u8; 32]>(),
                solver in any::<[u8; 32]>(),
                net_output in any::<u128>(),
                total_input in any::<u128>(),
                total_fee in any::<u128>(),
                execution_deadline in arb_timelock(),
                reservation in any::<[u8; 32]>(),
                bond_policy_version in any::<u32>(),
                expiry in arb_timelock(),
                sig in any::<[u8; 32]>(),
            ) {
                let mut solver_signature = [0u8; 64];
                solver_signature[..32].copy_from_slice(&sig);
                let quote = QuoteV1::create(
                    rfq_id,
                    ParticipantId(solver),
                    RouteV1 { legs: [
                        RouteLegV1 { chain_id: ChainId([1; 32]), asset: AssetId([2; 32]), direction: LegDirectionV1::UserGives },
                        RouteLegV1 { chain_id: ChainId([3; 32]), asset: AssetId([4; 32]), direction: LegDirectionV1::UserReceives },
                    ]},
                    net_output,
                    total_input,
                    total_fee,
                    execution_deadline,
                    reservation,
                    bond_policy_version,
                    expiry,
                    solver_signature,
                ).unwrap();
                let bytes = quote.canonical_bytes().unwrap();
                prop_assert_eq!(QuoteV1::decode(&bytes).unwrap(), quote);
            }
        }
    }
}

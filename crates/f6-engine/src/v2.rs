//! F6 V2 durable binding ledger.
//!
//! V1 frames and state remain untouched. Every V2 event carries the exact
//! composition and settlement position, so a reservation, selection, binding
//! or release cannot be transplanted across the two settlement RFQs.

use std::collections::BTreeMap;
use std::path::Path;

use kaystra_core::types::Digest32;
use rfq::selection::CandidateFactsV1;
use rfq::v2::{
    admissibility_v2, select_winner_v2, AcceptanceV2, F6V2Refusal, NegotiationObservationV2,
    QuoteV2, RefundFaceV2, RfqV2, SelectionOutcomeV2, SettlementPositionV2, TermsBindingV2,
};
use rfq::{ChainId, ParticipantId};

use crate::{BindingLog, EngineError};

/// Journal kind reserved for F6 V2. V1 remains `0xF601`.
pub const F6_V2_JOURNAL_KIND: u16 = 0xF602;
/// Leading magic of a V2 binding frame.
pub const FRAME_MAGIC_V2: &[u8; 8] = b"DOMIF6J2";
/// Frozen V2 frame version.
pub const FRAME_WIRE_VERSION_V2: u16 = 2;
/// Maximum canonical V2 frame size.
pub const MAX_FRAME_BYTES_V2: usize = 512;

const ZERO_DIGEST: Digest32 = [0; 32];

/// One V2 binding event. Every variant includes its exact composition scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingEventV2 {
    /// Exclusive reservation for one quote.
    Reserved {
        /// Linked route composition.
        composition_id: Digest32,
        /// Settlement position.
        position: SettlementPositionV2,
        /// Exclusive reservation identifier.
        reservation_id: Digest32,
        /// Exact RFQ.
        rfq_id: Digest32,
        /// Exact quote.
        quote_id: Digest32,
        /// Solver holding the reservation.
        solver: ParticipantId,
    },
    /// Deterministic candidate selection.
    Selected {
        /// Linked route composition.
        composition_id: Digest32,
        /// Settlement position.
        position: SettlementPositionV2,
        /// Exact RFQ.
        rfq_id: Digest32,
        /// Winning quote.
        winning_quote: Digest32,
        /// Complete candidate-set digest.
        inputs_digest: Digest32,
    },
    /// Atomic accepted binding.
    Bound {
        /// Linked route composition.
        composition_id: Digest32,
        /// Settlement position.
        position: SettlementPositionV2,
        /// Exact RFQ.
        rfq_id: Digest32,
        /// Exact quote.
        quote_id: Digest32,
        /// Bound solver.
        solver: ParticipantId,
        /// Accepting participant.
        accepted_by: ParticipantId,
        /// Consumed reservation.
        reservation_id: Digest32,
        /// Canonical V2 terms hash.
        terms_hash: Digest32,
    },
    /// One losing reservation is spent and cannot be reused.
    Released {
        /// Linked route composition.
        composition_id: Digest32,
        /// Settlement position.
        position: SettlementPositionV2,
        /// Exact reservation.
        reservation_id: Digest32,
        /// Exact RFQ originally reserved.
        rfq_id: Digest32,
        /// Exact quote originally reserved.
        quote_id: Digest32,
        /// Exact solver originally holding it.
        solver: ParticipantId,
    },
}

/// Named fail-closed V2 ledger refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BindingRefusalV2 {
    /// An event contains a zero or internally invalid scope.
    #[error("invalid F6 V2 event scope")]
    InvalidScope,
    /// Reservation is already active or bound.
    #[error("reservation already in use")]
    ReservationInUse,
    /// Reservation was released and is permanently spent.
    #[error("reservation spent")]
    ReservationSpent,
    /// Reservation is unknown.
    #[error("reservation unknown")]
    ReservationUnknown,
    /// Event scope/RFQ/quote does not match the reservation.
    #[error("reservation binding mismatch")]
    ReservationBindingMismatch,
    /// Event solver does not own the reservation.
    #[error("reservation holder mismatch")]
    ReservationHolderMismatch,
    /// Reservation has already been consumed.
    #[error("reservation already bound")]
    ReservationAlreadyBound,
    /// The scoped RFQ has already been selected.
    #[error("scoped rfq already selected")]
    RfqAlreadySelected,
    /// The scoped RFQ has already been bound.
    #[error("scoped rfq already bound")]
    RfqAlreadyBound,
    /// No selection exists for this exact composition position.
    #[error("binding has no exact V2 selection")]
    BindWithoutSelection,
    /// Bound quote differs from the exact selected winner.
    #[error("binding quote differs from V2 selection")]
    SelectionQuoteMismatch,
    /// Selection names a quote without an exact active reservation.
    #[error("selected quote has no exact reservation")]
    SelectionWithoutReservation,
    /// Reservation capacity bound exceeded.
    #[error("too many reservations")]
    TooManyReservations,
}

/// Durable V2 engine failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EngineErrorV2 {
    /// Pure ledger refusal; nothing was appended.
    #[error("refused: {0}")]
    Refused(#[from] BindingRefusalV2),
    /// RFQ/quote/clock/terms V2 refusal.
    #[error("F6 V2 refusal: {0}")]
    F6(#[from] F6V2Refusal),
    /// Underlying strict log failure.
    #[error("log: {0}")]
    Log(String),
    /// Store contains another journal kind.
    #[error("foreign record in F6 V2 journal")]
    ForeignRecord,
    /// Frame is noncanonical, unknown or malformed.
    #[error("undecodable F6 V2 frame")]
    UndecodableFrame,
    /// Frame revisions are not contiguous.
    #[error("F6 V2 revision gap")]
    RevisionGap,
    /// Replayed event is refused by the pure ledger.
    #[error("F6 V2 replay divergence: {0}")]
    ReplayDivergence(BindingRefusalV2),
    /// Replay exceeds the common journal bound.
    #[error("F6 V2 journal too large")]
    JournalTooLarge,
    /// Parties hold different exact V2 bindings.
    #[error("F6 V2 binding divergence")]
    BindingDivergence,
}

type ResultV2<T> = Result<T, EngineErrorV2>;
type ScopedRfqKeyV2 = (Digest32, u8, Digest32);

mod accepted_binding_seal {
    pub trait Sealed {}
}

/// Read-only exact accepted binding view. Fields have no public constructor;
/// production consumers obtain it only from a sealed replayed authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedBindingViewV2 {
    composition_id: Digest32,
    position: SettlementPositionV2,
    rfq_id: Digest32,
    quote_id: Digest32,
    solver: ParticipantId,
    accepted_by: ParticipantId,
    reservation_id: Digest32,
    terms_hash: Digest32,
}

impl AcceptedBindingViewV2 {
    /// Exact composition identifier.
    pub fn composition_id(self) -> Digest32 {
        self.composition_id
    }

    /// Exact settlement position.
    pub fn position(self) -> SettlementPositionV2 {
        self.position
    }

    /// Exact RFQ identifier.
    pub fn rfq_id(self) -> Digest32 {
        self.rfq_id
    }

    /// Exact quote identifier.
    pub fn quote_id(self) -> Digest32 {
        self.quote_id
    }

    /// Exact solver.
    pub fn solver(self) -> ParticipantId {
        self.solver
    }

    /// Exact participant that accepted the terms.
    pub fn accepted_by(self) -> ParticipantId {
        self.accepted_by
    }

    /// Exact consumed reservation.
    pub fn reservation_id(self) -> Digest32 {
        self.reservation_id
    }

    /// Exact canonical terms hash.
    pub fn terms_hash(self) -> Digest32 {
        self.terms_hash
    }

    /// Reconstructs the canonical accepted event solely from replayed state.
    /// Consumers may commit this event, but cannot substitute any of its
    /// composition, participant, reservation or terms fields.
    pub fn binding_event(self) -> BindingEventV2 {
        BindingEventV2::Bound {
            composition_id: self.composition_id,
            position: self.position,
            rfq_id: self.rfq_id,
            quote_id: self.quote_id,
            solver: self.solver,
            accepted_by: self.accepted_by,
            reservation_id: self.reservation_id,
            terms_hash: self.terms_hash,
        }
    }
}

/// Sealed read-only authority for an accepted V2 binding. External callers
/// cannot implement this trait or mint an accepted view.
pub trait AcceptedBindingAuthorityV2: accepted_binding_seal::Sealed {
    /// Returns an accepted binding only for the complete exact scope.
    fn accepted_binding_v2(
        &self,
        composition_id: Digest32,
        position: SettlementPositionV2,
        rfq_id: Digest32,
    ) -> Option<AcceptedBindingViewV2>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveReservationV2 {
    composition_id: Digest32,
    position: SettlementPositionV2,
    rfq_id: Digest32,
    quote_id: Digest32,
    solver: ParticipantId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservationStateV2 {
    Active(ActiveReservationV2),
    Bound,
    Spent,
}

/// One exact completed V2 binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundRecordV2 {
    /// Linked route composition.
    pub composition_id: Digest32,
    /// Settlement position.
    pub position: SettlementPositionV2,
    /// Winning quote.
    pub quote_id: Digest32,
    /// Executing solver.
    pub solver: ParticipantId,
    /// Accepting participant.
    pub accepted_by: ParticipantId,
    /// Consumed reservation.
    pub reservation_id: Digest32,
    /// Canonical V2 terms hash.
    pub terms_hash: Digest32,
}

/// One exact V2 selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedRecordV2 {
    /// Winning quote.
    pub winning_quote: Digest32,
    /// Complete candidate-set digest.
    pub inputs_digest: Digest32,
}

/// Pure replayable V2 binding state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BindingLedgerV2 {
    reservations: BTreeMap<Digest32, ReservationStateV2>,
    bindings: BTreeMap<ScopedRfqKeyV2, BoundRecordV2>,
    selections: BTreeMap<ScopedRfqKeyV2, SelectedRecordV2>,
}

impl BindingLedgerV2 {
    /// Fresh V2 ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Exact binding, if present.
    pub fn binding(
        &self,
        composition_id: Digest32,
        position: SettlementPositionV2,
        rfq_id: Digest32,
    ) -> Option<&BoundRecordV2> {
        self.bindings
            .get(&scoped_key(composition_id, position, rfq_id))
    }

    /// Exact selection, if present.
    pub fn selection(
        &self,
        composition_id: Digest32,
        position: SettlementPositionV2,
        rfq_id: Digest32,
    ) -> Option<&SelectedRecordV2> {
        self.selections
            .get(&scoped_key(composition_id, position, rfq_id))
    }

    /// Whether the active reservation backs the complete V2 scope.
    pub fn reservation_backs(
        &self,
        reservation_id: Digest32,
        composition_id: Digest32,
        position: SettlementPositionV2,
        rfq_id: Digest32,
        quote_id: Digest32,
        solver: ParticipantId,
    ) -> bool {
        self.reservations.get(&reservation_id)
            == Some(&ReservationStateV2::Active(ActiveReservationV2 {
                composition_id,
                position,
                rfq_id,
                quote_id,
                solver,
            }))
    }

    /// Applies one event. Refusal mutates no state.
    pub fn apply(&mut self, event: &BindingEventV2) -> Result<(), BindingRefusalV2> {
        validate_event(event)?;
        let mut next = self.clone();
        next.apply_validated(event)?;
        *self = next;
        Ok(())
    }

    fn apply_validated(&mut self, event: &BindingEventV2) -> Result<(), BindingRefusalV2> {
        match *event {
            BindingEventV2::Reserved {
                composition_id,
                position,
                reservation_id,
                rfq_id,
                quote_id,
                solver,
            } => {
                match self.reservations.get(&reservation_id) {
                    Some(ReservationStateV2::Active(_) | ReservationStateV2::Bound) => {
                        return Err(BindingRefusalV2::ReservationInUse);
                    }
                    Some(ReservationStateV2::Spent) => {
                        return Err(BindingRefusalV2::ReservationSpent);
                    }
                    None => {}
                }
                if self.reservations.len() >= crate::MAX_RESERVATIONS {
                    return Err(BindingRefusalV2::TooManyReservations);
                }
                self.reservations.insert(
                    reservation_id,
                    ReservationStateV2::Active(ActiveReservationV2 {
                        composition_id,
                        position,
                        rfq_id,
                        quote_id,
                        solver,
                    }),
                );
            }
            BindingEventV2::Selected {
                composition_id,
                position,
                rfq_id,
                winning_quote,
                inputs_digest,
            } => {
                let key = scoped_key(composition_id, position, rfq_id);
                if self.selections.contains_key(&key) {
                    return Err(BindingRefusalV2::RfqAlreadySelected);
                }
                if !self.reservations.values().any(|state| {
                    matches!(state, ReservationStateV2::Active(active)
                        if active.composition_id == composition_id
                            && active.position == position
                            && active.rfq_id == rfq_id
                            && active.quote_id == winning_quote)
                }) {
                    return Err(BindingRefusalV2::SelectionWithoutReservation);
                }
                self.selections.insert(
                    key,
                    SelectedRecordV2 {
                        winning_quote,
                        inputs_digest,
                    },
                );
            }
            BindingEventV2::Bound {
                composition_id,
                position,
                rfq_id,
                quote_id,
                solver,
                accepted_by,
                reservation_id,
                terms_hash,
            } => {
                let key = scoped_key(composition_id, position, rfq_id);
                if self.bindings.contains_key(&key) {
                    return Err(BindingRefusalV2::RfqAlreadyBound);
                }
                match self.selections.get(&key) {
                    None => return Err(BindingRefusalV2::BindWithoutSelection),
                    Some(selected) if selected.winning_quote != quote_id => {
                        return Err(BindingRefusalV2::SelectionQuoteMismatch);
                    }
                    Some(_) => {}
                }
                let expected = ActiveReservationV2 {
                    composition_id,
                    position,
                    rfq_id,
                    quote_id,
                    solver,
                };
                match self.reservations.get(&reservation_id) {
                    None => return Err(BindingRefusalV2::ReservationUnknown),
                    Some(ReservationStateV2::Spent) => {
                        return Err(BindingRefusalV2::ReservationSpent);
                    }
                    Some(ReservationStateV2::Bound) => {
                        return Err(BindingRefusalV2::ReservationAlreadyBound);
                    }
                    Some(ReservationStateV2::Active(active)) if active.solver != solver => {
                        return Err(BindingRefusalV2::ReservationHolderMismatch);
                    }
                    Some(ReservationStateV2::Active(active)) if *active != expected => {
                        return Err(BindingRefusalV2::ReservationBindingMismatch);
                    }
                    Some(ReservationStateV2::Active(_)) => {}
                }
                self.reservations
                    .insert(reservation_id, ReservationStateV2::Bound);
                self.bindings.insert(
                    key,
                    BoundRecordV2 {
                        composition_id,
                        position,
                        quote_id,
                        solver,
                        accepted_by,
                        reservation_id,
                        terms_hash,
                    },
                );
            }
            BindingEventV2::Released {
                composition_id,
                position,
                reservation_id,
                rfq_id,
                quote_id,
                solver,
            } => {
                let expected = ActiveReservationV2 {
                    composition_id,
                    position,
                    rfq_id,
                    quote_id,
                    solver,
                };
                match self.reservations.get(&reservation_id) {
                    None => return Err(BindingRefusalV2::ReservationUnknown),
                    Some(ReservationStateV2::Spent) => {
                        return Err(BindingRefusalV2::ReservationSpent);
                    }
                    Some(ReservationStateV2::Bound) => {
                        return Err(BindingRefusalV2::ReservationAlreadyBound);
                    }
                    Some(ReservationStateV2::Active(active)) if active.solver != solver => {
                        return Err(BindingRefusalV2::ReservationHolderMismatch);
                    }
                    Some(ReservationStateV2::Active(active)) if *active != expected => {
                        return Err(BindingRefusalV2::ReservationBindingMismatch);
                    }
                    Some(ReservationStateV2::Active(_)) => {}
                }
                self.reservations
                    .insert(reservation_id, ReservationStateV2::Spent);
            }
        }
        Ok(())
    }
}

fn scoped_key(
    composition_id: Digest32,
    position: SettlementPositionV2,
    rfq_id: Digest32,
) -> ScopedRfqKeyV2 {
    (composition_id, position as u8, rfq_id)
}

fn validate_event(event: &BindingEventV2) -> Result<(), BindingRefusalV2> {
    let contains_zero = match event {
        BindingEventV2::Reserved {
            composition_id,
            reservation_id,
            rfq_id,
            quote_id,
            solver,
            ..
        } => [
            *composition_id,
            *reservation_id,
            *rfq_id,
            *quote_id,
            solver.0,
        ]
        .contains(&ZERO_DIGEST),
        BindingEventV2::Selected {
            composition_id,
            rfq_id,
            winning_quote,
            inputs_digest,
            ..
        } => [*composition_id, *rfq_id, *winning_quote, *inputs_digest].contains(&ZERO_DIGEST),
        BindingEventV2::Bound {
            composition_id,
            rfq_id,
            quote_id,
            solver,
            accepted_by,
            reservation_id,
            terms_hash,
            ..
        } => [
            *composition_id,
            *rfq_id,
            *quote_id,
            solver.0,
            accepted_by.0,
            *reservation_id,
            *terms_hash,
        ]
        .contains(&ZERO_DIGEST),
        BindingEventV2::Released {
            composition_id,
            reservation_id,
            rfq_id,
            quote_id,
            solver,
            ..
        } => [
            *composition_id,
            *reservation_id,
            *rfq_id,
            *quote_id,
            solver.0,
        ]
        .contains(&ZERO_DIGEST),
    };
    if contains_zero {
        return Err(BindingRefusalV2::InvalidScope);
    }
    Ok(())
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_scope(output: &mut Vec<u8>, composition_id: Digest32, position: SettlementPositionV2) {
    output.extend_from_slice(&composition_id);
    output.push(position as u8);
}

/// Canonical V2 binding frame.
pub fn encode_frame_v2(revision: u64, event: &BindingEventV2) -> ResultV2<Vec<u8>> {
    validate_event(event)?;
    let mut output = Vec::with_capacity(MAX_FRAME_BYTES_V2);
    output.extend_from_slice(FRAME_MAGIC_V2);
    put_u16(&mut output, FRAME_WIRE_VERSION_V2);
    put_u64(&mut output, revision);
    match *event {
        BindingEventV2::Reserved {
            composition_id,
            position,
            reservation_id,
            rfq_id,
            quote_id,
            solver,
        } => {
            output.push(1);
            put_scope(&mut output, composition_id, position);
            output.extend_from_slice(&reservation_id);
            output.extend_from_slice(&rfq_id);
            output.extend_from_slice(&quote_id);
            output.extend_from_slice(&solver.0);
        }
        BindingEventV2::Selected {
            composition_id,
            position,
            rfq_id,
            winning_quote,
            inputs_digest,
        } => {
            output.push(2);
            put_scope(&mut output, composition_id, position);
            output.extend_from_slice(&rfq_id);
            output.extend_from_slice(&winning_quote);
            output.extend_from_slice(&inputs_digest);
        }
        BindingEventV2::Bound {
            composition_id,
            position,
            rfq_id,
            quote_id,
            solver,
            accepted_by,
            reservation_id,
            terms_hash,
        } => {
            output.push(3);
            put_scope(&mut output, composition_id, position);
            output.extend_from_slice(&rfq_id);
            output.extend_from_slice(&quote_id);
            output.extend_from_slice(&solver.0);
            output.extend_from_slice(&accepted_by.0);
            output.extend_from_slice(&reservation_id);
            output.extend_from_slice(&terms_hash);
        }
        BindingEventV2::Released {
            composition_id,
            position,
            reservation_id,
            rfq_id,
            quote_id,
            solver,
        } => {
            output.push(4);
            put_scope(&mut output, composition_id, position);
            output.extend_from_slice(&reservation_id);
            output.extend_from_slice(&rfq_id);
            output.extend_from_slice(&quote_id);
            output.extend_from_slice(&solver.0);
        }
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

    fn take(&mut self, length: usize) -> ResultV2<&'bytes [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(EngineErrorV2::UndecodableFrame)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(EngineErrorV2::UndecodableFrame)?;
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> ResultV2<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| EngineErrorV2::UndecodableFrame)
    }

    fn digest(&mut self) -> ResultV2<Digest32> {
        self.array()
    }

    fn u8(&mut self) -> ResultV2<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> ResultV2<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> ResultV2<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn position(&mut self) -> ResultV2<SettlementPositionV2> {
        match self.u8()? {
            1 => Ok(SettlementPositionV2::Upstream),
            2 => Ok(SettlementPositionV2::Downstream),
            _ => Err(EngineErrorV2::UndecodableFrame),
        }
    }

    fn finish(self) -> ResultV2<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(EngineErrorV2::UndecodableFrame)
        }
    }
}

/// Strict V2 frame decoder.
pub fn decode_frame_v2(bytes: &[u8]) -> ResultV2<(u64, BindingEventV2)> {
    if bytes.len() > MAX_FRAME_BYTES_V2 {
        return Err(EngineErrorV2::UndecodableFrame);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(FRAME_MAGIC_V2.len())? != FRAME_MAGIC_V2
        || cursor.u16()? != FRAME_WIRE_VERSION_V2
    {
        return Err(EngineErrorV2::UndecodableFrame);
    }
    let revision = cursor.u64()?;
    let tag = cursor.u8()?;
    let composition_id = cursor.digest()?;
    let position = cursor.position()?;
    let event = match tag {
        1 => BindingEventV2::Reserved {
            composition_id,
            position,
            reservation_id: cursor.digest()?,
            rfq_id: cursor.digest()?,
            quote_id: cursor.digest()?,
            solver: ParticipantId(cursor.digest()?),
        },
        2 => BindingEventV2::Selected {
            composition_id,
            position,
            rfq_id: cursor.digest()?,
            winning_quote: cursor.digest()?,
            inputs_digest: cursor.digest()?,
        },
        3 => BindingEventV2::Bound {
            composition_id,
            position,
            rfq_id: cursor.digest()?,
            quote_id: cursor.digest()?,
            solver: ParticipantId(cursor.digest()?),
            accepted_by: ParticipantId(cursor.digest()?),
            reservation_id: cursor.digest()?,
            terms_hash: cursor.digest()?,
        },
        4 => BindingEventV2::Released {
            composition_id,
            position,
            reservation_id: cursor.digest()?,
            rfq_id: cursor.digest()?,
            quote_id: cursor.digest()?,
            solver: ParticipantId(cursor.digest()?),
        },
        _ => return Err(EngineErrorV2::UndecodableFrame),
    };
    cursor.finish()?;
    validate_event(&event).map_err(|_| EngineErrorV2::UndecodableFrame)?;
    if encode_frame_v2(revision, &event)?.as_slice() != bytes {
        return Err(EngineErrorV2::UndecodableFrame);
    }
    Ok((revision, event))
}

/// Strict store-backed V2 binding log.
pub struct StoreLogV2 {
    store: store::Store,
}

impl StoreLogV2 {
    /// Creates a strict production V2 journal.
    pub fn create_production(path: &Path, binding_digest: Digest32) -> ResultV2<Self> {
        let binding = store::ProductionStoreBindingV1::new(binding_digest)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        let store = store::Store::create_production(path, binding)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        Ok(Self { store })
    }

    /// Opens one exact existing production V2 journal.
    pub fn open_production(path: &Path, binding_digest: Digest32) -> ResultV2<Self> {
        let binding = store::ProductionStoreBindingV1::new(binding_digest)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        let store = store::Store::open_production(path, binding)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        Ok(Self { store })
    }

    /// Resumes only a pristine V2 journal whose creation was durably started.
    pub fn resume_create_production(path: &Path, binding_digest: Digest32) -> ResultV2<Self> {
        let binding = store::ProductionStoreBindingV1::new(binding_digest)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        let store = store::Store::resume_create_production(path, binding)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        Ok(Self { store })
    }

    /// Opens an initialized journal or completes an externally provisioned
    /// lazy-binding prefix. Both the preparation and final bindings must be
    /// exact; initialized economic state is retained across restart.
    pub fn open_or_resume_prepared_production(
        path: &Path,
        preparation_digest: Digest32,
        binding_digest: Digest32,
    ) -> ResultV2<Self> {
        let preparation = store::ProductionStoreBindingV1::new(preparation_digest)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        let binding = store::ProductionStoreBindingV1::new(binding_digest)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        let store = store::Store::open_or_resume_prepared_production(path, preparation, binding)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        Ok(Self { store })
    }
}

impl BindingLog for StoreLogV2 {
    fn append_frame(&mut self, frame: &[u8]) -> Result<(), EngineError> {
        self.store
            .append_journal(F6_V2_JOURNAL_KIND, frame)
            .map(|_| ())
            .map_err(|error| EngineError::Log(error.to_string()))
    }

    fn frames(&self) -> Result<Vec<Vec<u8>>, EngineError> {
        let entries = self
            .store
            .read_journal()
            .map_err(|error| EngineError::Log(error.to_string()))?;
        let mut frames = Vec::with_capacity(entries.len().min(crate::MAX_JOURNAL_FRAMES));
        for entry in entries {
            if entry.kind != F6_V2_JOURNAL_KIND {
                return Err(EngineError::ForeignRecord);
            }
            frames.push(entry.payload);
        }
        Ok(frames)
    }
}

/// Durable V2 ledger driver.
pub struct DurableBindingV2<L: BindingLog> {
    log: L,
    ledger: BindingLedgerV2,
    revision: u64,
}

impl<L: BindingLog> DurableBindingV2<L> {
    /// Opens and replays every V2 frame fail-closed.
    pub fn open(log: L) -> ResultV2<Self> {
        let frames = log
            .frames()
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        if frames.len() > crate::MAX_JOURNAL_FRAMES {
            return Err(EngineErrorV2::JournalTooLarge);
        }
        let mut ledger = BindingLedgerV2::new();
        for (index, frame) in frames.iter().enumerate() {
            let (revision, event) = decode_frame_v2(frame)?;
            if revision != index as u64 {
                return Err(EngineErrorV2::RevisionGap);
            }
            ledger
                .apply(&event)
                .map_err(EngineErrorV2::ReplayDivergence)?;
        }
        Ok(Self {
            log,
            ledger,
            revision: frames.len() as u64,
        })
    }

    /// Replayed V2 state.
    pub fn ledger(&self) -> &BindingLedgerV2 {
        &self.ledger
    }

    /// Next V2 frame revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Validates, appends, then exposes one transition.
    pub fn apply(&mut self, event: &BindingEventV2) -> ResultV2<()> {
        let mut next = self.ledger.clone();
        next.apply(event)?;
        let frame = encode_frame_v2(self.revision, event)?;
        self.log
            .append_frame(&frame)
            .map_err(|error| EngineErrorV2::Log(error.to_string()))?;
        self.ledger = next;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(EngineErrorV2::RevisionGap)?;
        Ok(())
    }

    /// Runs deterministic V2 selection with reservation facts derived from
    /// this ledger, then commits the position-scoped outcome.
    pub fn select_and_record(
        &mut self,
        rfq: &RfqV2,
        candidates: &[(QuoteV2, CandidateFactsV1)],
        dom_chain_id: ChainId,
        current: NegotiationObservationV2,
    ) -> ResultV2<SelectionOutcomeV2> {
        let attested: Vec<(QuoteV2, CandidateFactsV1)> = candidates
            .iter()
            .map(|(quote, facts)| {
                let mut exact = *facts;
                exact.bond_reserved_exclusive = self.ledger.reservation_backs(
                    quote.bond_reservation_id,
                    rfq.route.composition_id,
                    rfq.route.position,
                    rfq.rfq_id,
                    quote.quote_id,
                    quote.solver,
                );
                (*quote, exact)
            })
            .collect();
        let outcome = select_winner_v2(rfq, &attested, dom_chain_id, current)?;
        self.apply(&BindingEventV2::Selected {
            composition_id: outcome.selection.composition_id,
            position: outcome.selection.position,
            rfq_id: outcome.selection.rfq_id,
            winning_quote: outcome.selection.winning_quote,
            inputs_digest: outcome.selection.inputs_digest,
        })?;
        Ok(outcome)
    }

    /// Revalidates the winner, builds exact V2 terms, and commits one atomic
    /// binding frame.
    pub fn bind_selected(&mut self, input: BindSelectedV2<'_>) -> ResultV2<AcceptanceV2> {
        let mut exact = *input.facts;
        exact.bond_reserved_exclusive = self.ledger.reservation_backs(
            input.quote.bond_reservation_id,
            input.rfq.route.composition_id,
            input.rfq.route.position,
            input.rfq.rfq_id,
            input.quote.quote_id,
            input.quote.solver,
        );
        admissibility_v2(
            input.rfq,
            input.quote,
            &exact,
            input.dom_chain_id,
            input.current,
        )?;
        let terms = TermsBindingV2::from_parts(input.rfq, input.quote, input.faces)?;
        let acceptance = AcceptanceV2::from_terms(&terms, input.accepted_by)?;
        self.apply(&BindingEventV2::Bound {
            composition_id: input.rfq.route.composition_id,
            position: input.rfq.route.position,
            rfq_id: input.rfq.rfq_id,
            quote_id: input.quote.quote_id,
            solver: input.quote.solver,
            accepted_by: input.accepted_by,
            reservation_id: input.quote.bond_reservation_id,
            terms_hash: acceptance.terms_hash,
        })?;
        Ok(acceptance)
    }
}

impl<L: BindingLog> accepted_binding_seal::Sealed for DurableBindingV2<L> {}

impl<L: BindingLog> AcceptedBindingAuthorityV2 for DurableBindingV2<L> {
    fn accepted_binding_v2(
        &self,
        composition_id: Digest32,
        position: SettlementPositionV2,
        rfq_id: Digest32,
    ) -> Option<AcceptedBindingViewV2> {
        self.ledger
            .binding(composition_id, position, rfq_id)
            .map(|record| AcceptedBindingViewV2 {
                composition_id,
                position,
                rfq_id,
                quote_id: record.quote_id,
                solver: record.solver,
                accepted_by: record.accepted_by,
                reservation_id: record.reservation_id,
                terms_hash: record.terms_hash,
            })
    }
}

/// Typed V2 binding inputs; avoids an ambiguous positional API.
pub struct BindSelectedV2<'objects> {
    /// Exact RFQ.
    pub rfq: &'objects RfqV2,
    /// Exact selected quote.
    pub quote: &'objects QuoteV2,
    /// Authenticated external facts; reservation is overwritten from ledger.
    pub facts: &'objects CandidateFactsV1,
    /// Exact DOM chain identity.
    pub dom_chain_id: ChainId,
    /// Move-only production time capability's extracted observation.
    pub current: NegotiationObservationV2,
    /// Adapter-authenticated refund/payout faces.
    pub faces: [RefundFaceV2; 2],
    /// Exact accepting participant.
    pub accepted_by: ParticipantId,
}

/// Returns true only when both parties replay the same exact V2 binding.
pub fn binding_complete_v2<A: BindingLog, B: BindingLog>(
    first: &DurableBindingV2<A>,
    second: &DurableBindingV2<B>,
    composition_id: Digest32,
    position: SettlementPositionV2,
    rfq_id: Digest32,
) -> ResultV2<bool> {
    match (
        first.ledger().binding(composition_id, position, rfq_id),
        second.ledger().binding(composition_id, position, rfq_id),
    ) {
        (Some(left), Some(right)) if left == right => Ok(true),
        (Some(_), Some(_)) => Err(EngineErrorV2::BindingDivergence),
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use rfq::v2::{
        NativeClockKindV2, NegotiationClockV2, NegotiationInstantV2, QuoteProposalV2, RfqRequestV2,
        RouteV2, ScopedTimelockV2,
    };
    use rfq::{AssetId, FeeLimitV1, LegDirectionV1, PolicyId, RfqModeV1, RouteLegV1};

    use super::*;

    const DOM_CHAIN: ChainId = ChainId([0xD0; 32]);
    const EVM_CHAIN: ChainId = ChainId([0xE1; 32]);
    const DOM_ASSET: AssetId = AssetId([0xDA; 32]);
    const EVM_ASSET: AssetId = AssetId([0xEA; 32]);

    #[derive(Clone, Default)]
    struct SharedLog {
        frames: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl BindingLog for SharedLog {
        fn append_frame(&mut self, frame: &[u8]) -> Result<(), EngineError> {
            self.frames.borrow_mut().push(frame.to_vec());
            Ok(())
        }

        fn frames(&self) -> Result<Vec<Vec<u8>>, EngineError> {
            Ok(self.frames.borrow().clone())
        }
    }

    struct FailingLog;

    impl BindingLog for FailingLog {
        fn append_frame(&mut self, _frame: &[u8]) -> Result<(), EngineError> {
            Err(EngineError::Log("injected append failure".to_owned()))
        }

        fn frames(&self) -> Result<Vec<Vec<u8>>, EngineError> {
            Ok(Vec::new())
        }
    }

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

    fn route() -> RouteV2 {
        RouteV2 {
            composition_id: [0x11; 32],
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

    fn rfq() -> Result<RfqV2, F6V2Refusal> {
        RfqV2::create(RfqRequestV2 {
            initiator: ParticipantId([0x41; 32]),
            route: route(),
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
        })
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

    fn facts() -> CandidateFactsV1 {
        CandidateFactsV1 {
            solver_registered: true,
            signature_valid: true,
            bond_reserved_exclusive: false,
            exposure_covered: true,
            coverage_excess: 0,
            solver_active: true,
            policy_version_accepted: true,
        }
    }

    fn faces() -> [RefundFaceV2; 2] {
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

    fn reserved(rfq: &RfqV2, quote: &QuoteV2) -> BindingEventV2 {
        BindingEventV2::Reserved {
            composition_id: rfq.route.composition_id,
            position: rfq.route.position,
            reservation_id: quote.bond_reservation_id,
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
        }
    }

    #[test]
    fn v2_frames_are_distinct_canonical_and_strict() -> Result<(), EngineErrorV2> {
        let rfq = rfq()?;
        let quote = quote(&rfq)?;
        let events = [
            reserved(&rfq, &quote),
            BindingEventV2::Selected {
                composition_id: rfq.route.composition_id,
                position: rfq.route.position,
                rfq_id: rfq.rfq_id,
                winning_quote: quote.quote_id,
                inputs_digest: [0x71; 32],
            },
            BindingEventV2::Bound {
                composition_id: rfq.route.composition_id,
                position: rfq.route.position,
                rfq_id: rfq.rfq_id,
                quote_id: quote.quote_id,
                solver: quote.solver,
                accepted_by: rfq.initiator,
                reservation_id: quote.bond_reservation_id,
                terms_hash: [0x72; 32],
            },
            BindingEventV2::Released {
                composition_id: rfq.route.composition_id,
                position: rfq.route.position,
                reservation_id: quote.bond_reservation_id,
                rfq_id: rfq.rfq_id,
                quote_id: quote.quote_id,
                solver: quote.solver,
            },
        ];
        for (revision, event) in events.iter().enumerate() {
            let bytes = encode_frame_v2(revision as u64, event)?;
            assert_eq!(decode_frame_v2(&bytes)?, (revision as u64, *event));
            let mut trailing = bytes;
            trailing.push(0xA5);
            assert_eq!(
                decode_frame_v2(&trailing),
                Err(EngineErrorV2::UndecodableFrame)
            );
        }
        let v1 = crate::encode_frame(
            0,
            &crate::BindingEventV1::Released {
                reservation_id: [0x73; 32],
            },
        );
        assert_eq!(decode_frame_v2(&v1), Err(EngineErrorV2::UndecodableFrame));
        Ok(())
    }

    #[test]
    fn reservation_release_and_selection_refuse_scope_transplant() -> Result<(), EngineErrorV2> {
        let rfq = rfq()?;
        let quote = quote(&rfq)?;
        let mut ledger = BindingLedgerV2::new();
        ledger.apply(&reserved(&rfq, &quote))?;

        let transplanted_selection = BindingEventV2::Selected {
            composition_id: [0x19; 32],
            position: rfq.route.position,
            rfq_id: rfq.rfq_id,
            winning_quote: quote.quote_id,
            inputs_digest: [0x71; 32],
        };
        assert_eq!(
            ledger.apply(&transplanted_selection),
            Err(BindingRefusalV2::SelectionWithoutReservation)
        );
        let transplanted_release = BindingEventV2::Released {
            composition_id: rfq.route.composition_id,
            position: SettlementPositionV2::Downstream,
            reservation_id: quote.bond_reservation_id,
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
        };
        assert_eq!(
            ledger.apply(&transplanted_release),
            Err(BindingRefusalV2::ReservationBindingMismatch)
        );
        let exact_release = BindingEventV2::Released {
            composition_id: rfq.route.composition_id,
            position: rfq.route.position,
            reservation_id: quote.bond_reservation_id,
            rfq_id: rfq.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
        };
        ledger.apply(&exact_release)?;
        assert_eq!(
            ledger.apply(&reserved(&rfq, &quote)),
            Err(BindingRefusalV2::ReservationSpent)
        );
        Ok(())
    }

    #[test]
    fn durable_v2_select_bind_and_replay_preserve_exact_scope() -> Result<(), EngineErrorV2> {
        let rfq = rfq()?;
        let quote = quote(&rfq)?;
        let log = SharedLog::default();
        let mut binding = DurableBindingV2::open(log.clone())?;
        binding.apply(&reserved(&rfq, &quote))?;
        let current = NegotiationObservationV2 {
            clock: clock(),
            value: 1_000,
        };
        let outcome = binding.select_and_record(&rfq, &[(quote, facts())], DOM_CHAIN, current)?;
        assert_eq!(outcome.selection.winning_quote, quote.quote_id);
        let acceptance = binding.bind_selected(BindSelectedV2 {
            rfq: &rfq,
            quote: &quote,
            facts: &facts(),
            dom_chain_id: DOM_CHAIN,
            current,
            faces: faces(),
            accepted_by: rfq.initiator,
        })?;
        let replayed = DurableBindingV2::open(log)?;
        let record = replayed
            .ledger()
            .binding(rfq.route.composition_id, rfq.route.position, rfq.rfq_id)
            .ok_or(EngineErrorV2::BindingDivergence)?;
        assert_eq!(record.terms_hash, acceptance.terms_hash);
        assert_eq!(record.position, SettlementPositionV2::Upstream);
        assert!(replayed
            .ledger()
            .binding(
                rfq.route.composition_id,
                SettlementPositionV2::Downstream,
                rfq.rfq_id,
            )
            .is_none());
        Ok(())
    }

    #[test]
    fn append_failure_never_exposes_reserved_state() -> Result<(), EngineErrorV2> {
        let rfq = rfq()?;
        let quote = quote(&rfq)?;
        let mut binding = DurableBindingV2::open(FailingLog)?;
        assert_eq!(
            binding.apply(&reserved(&rfq, &quote)),
            Err(EngineErrorV2::Log(
                "log: injected append failure".to_owned()
            ))
        );
        assert!(!binding.ledger().reservation_backs(
            quote.bond_reservation_id,
            rfq.route.composition_id,
            rfq.route.position,
            rfq.rfq_id,
            quote.quote_id,
            quote.solver,
        ));
        Ok(())
    }
}

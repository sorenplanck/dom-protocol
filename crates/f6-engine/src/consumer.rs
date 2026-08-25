//! The recipient-side payload check ratified by D-019.
//!
//! The ratified division of labour, verbatim: "The Relay stays
//! forbidden from decoding the payload. The policy authorizes the
//! HEADER; the recipient consumer decodes and verifies that the inner
//! object corresponds to the message_kind, to the sender, to the
//! settlement and to the bindings."
//!
//! That is why this module lives in `f6-engine` and not in `relay`.
//! `relay` does not depend on `rfq` and therefore cannot decode an F6
//! object even by accident: the structural claim "the Relay never
//! decodes payloads" is a fact about the dependency graph, not a
//! promise about discipline. Everything here runs AFTER the §5.4
//! pipeline returned an [`AcceptedEnvelopeV1`] — step 10, and only
//! step 10.
//!
//! What the check can bind is exactly what the ratified V1 objects
//! carry, and no more:
//!
//! | kind       | sender field   | settlement binding      |
//! |------------|----------------|-------------------------|
//! | RfqV1      | `initiator`    | `session_id` + `rfq_id` |
//! | QuoteV1    | `solver`       | `rfq_id`                |
//! | AcceptanceV1 | `accepted_by` | `rfq_id`               |
//! | SelectionV1  | (none)       | `rfq_id`                |
//!
//! `SelectionV1` carries no participant field in the ratified object
//! (F6 spec §3), so its attribution is the authenticated envelope's
//! `sender_id` under the D-019 role mapping — there is nothing inside
//! the object to cross-check, and none is invented here.

use kaystra_core::types::Digest32;
use relay::auth::{message_type, AcceptedEnvelopeV1};
use relay::ParticipantId;
use rfq::{AcceptanceV1, QuoteV1, RfqObjectError, RfqV1, SelectionV1};

/// The session facts a consumer holds locally and checks every payload
/// against. They are the recipient's own durable state, never taken
/// from the message being judged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionBindingV1 {
    /// The session (the envelope's `session_id` is checked against this
    /// by §5.4 step 4; the payload is checked against it here).
    pub session_id: Digest32,
    /// The RFQ this session is quoting for — the settlement binding
    /// every later object carries.
    pub rfq_id: Digest32,
}

/// One payload accepted as the object its `message_type` names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PayloadObjectV1 {
    /// `0x0001` — the request for quotes.
    Rfq(RfqV1),
    /// `0x0002` — a solver's quote.
    Quote(QuoteV1),
    /// `0x0003` — the initiator's acceptance.
    Acceptance(AcceptanceV1),
    /// `0x0004` — the initiator's adjudication.
    Selection(SelectionV1),
}

impl PayloadObjectV1 {
    /// The `message_type` this object may travel under.
    pub fn message_type(&self) -> u16 {
        match self {
            PayloadObjectV1::Rfq(_) => message_type::RFQ,
            PayloadObjectV1::Quote(_) => message_type::QUOTE,
            PayloadObjectV1::Acceptance(_) => message_type::ACCEPTANCE,
            PayloadObjectV1::Selection(_) => message_type::SELECTION,
        }
    }
}

/// Named refusals of the consumer check (I13). Each names the single
/// correspondence that failed, so a refusal is diagnostic rather than a
/// blanket "bad payload".
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ConsumerRefusal {
    /// The envelope's `message_type` is outside the closed D-019
    /// registry. Unreachable through the production pipeline (step 6
    /// refuses it first) and refused here anyway: a consumer must not
    /// depend on an upstream check to be safe.
    #[error("unknown message kind")]
    UnknownMessageKind,
    /// The payload bytes do not decode as the object the
    /// `message_type` names. The F6 codecs validate on decode — the
    /// frozen magic, the enum tags, the absence of trailing bytes and
    /// the object's own content-derived identifier — so this one
    /// refusal covers "wrong object", "malformed object" and "object
    /// whose id does not bind its content" alike.
    #[error("payload does not decode as the declared object: {0}")]
    PayloadDecode(RfqObjectError),
    /// The object names a participant other than the envelope's
    /// authenticated sender.
    #[error("payload sender does not match the authenticated sender")]
    SenderMismatch,
    /// The object belongs to a different session.
    #[error("payload session does not match the envelope session")]
    SessionMismatch,
    /// The object binds a different RFQ than this session's.
    #[error("payload rfq does not match the session binding")]
    RfqMismatch,
}

/// Decodes an accepted envelope's payload and checks the four ratified
/// correspondences (kind, sender, settlement, bindings).
///
/// `accepted` MUST come from [`relay::auth::accept_envelope`]: this
/// function assumes the signature, roster membership, role permission,
/// replay state and transcript continuity are already settled, and
/// checks only what the pipeline deliberately does not — the meaning of
/// the opaque bytes.
pub fn accept_payload(
    accepted: &AcceptedEnvelopeV1,
    session: &SessionBindingV1,
) -> Result<PayloadObjectV1, ConsumerRefusal> {
    let envelope = &accepted.envelope;
    let sender = envelope.sender_id;
    let payload = envelope.payload.as_slice();

    match envelope.message_type {
        message_type::RFQ => {
            let object = RfqV1::decode(payload).map_err(ConsumerRefusal::PayloadDecode)?;
            check_sender(object.initiator, sender)?;
            if object.session_id != envelope.session_id {
                return Err(ConsumerRefusal::SessionMismatch);
            }
            if object.session_id != session.session_id {
                return Err(ConsumerRefusal::SessionMismatch);
            }
            check_rfq(object.rfq_id, session)?;
            Ok(PayloadObjectV1::Rfq(object))
        }
        message_type::QUOTE => {
            let object = QuoteV1::decode(payload).map_err(ConsumerRefusal::PayloadDecode)?;
            check_sender(object.solver, sender)?;
            check_rfq(object.rfq_id, session)?;
            Ok(PayloadObjectV1::Quote(object))
        }
        message_type::ACCEPTANCE => {
            let object = AcceptanceV1::decode(payload).map_err(ConsumerRefusal::PayloadDecode)?;
            check_sender(object.accepted_by, sender)?;
            check_rfq(object.rfq_id, session)?;
            Ok(PayloadObjectV1::Acceptance(object))
        }
        message_type::SELECTION => {
            let object = SelectionV1::decode(payload).map_err(ConsumerRefusal::PayloadDecode)?;
            check_rfq(object.rfq_id, session)?;
            Ok(PayloadObjectV1::Selection(object))
        }
        _ => Err(ConsumerRefusal::UnknownMessageKind),
    }
}

fn check_sender(
    claimed: ParticipantId,
    authenticated: ParticipantId,
) -> Result<(), ConsumerRefusal> {
    if claimed != authenticated {
        return Err(ConsumerRefusal::SenderMismatch);
    }
    Ok(())
}

fn check_rfq(rfq_id: Digest32, session: &SessionBindingV1) -> Result<(), ConsumerRefusal> {
    if rfq_id != session.rfq_id {
        return Err(ConsumerRefusal::RfqMismatch);
    }
    Ok(())
}

//! Small, fixed-width canonical codec for durable route material.
//!
//! This intentionally avoids a general-purpose deserializer.  Lengths are
//! checked before allocation, enum tags have one representation, integer
//! endianness is fixed, and trailing bytes are rejected.

use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use thiserror::Error;

use crate::model::{
    validate_effect, validate_effect_dispatch, validate_effect_reference, validate_event,
    validate_exposure, validate_frozen_admission_checkpoint_v2, validate_timer, ActionIntentV1,
    ActionKindV1, ActionStateV1, CoordinationPhaseV1, Digest32, EffectDispatchV1, EffectPriorityV1,
    EffectReferenceV1, ExposureSourceV1, FrozenBindingsV1, FrozenRouteAdmissionCheckpointV2,
    FrozenRouteTimeFactsV2, HealthStateV1, LegIdV1, LegSnapshotV1, PublicExposureV1,
    RefundBindingsV1, RouteEffectV1, RouteEventV1, RouteSnapshotV1, RouteTimerV1,
    SecretVisibilityV1, TimerKindV1, MAX_EFFECT_PAYLOAD_BYTES_V1,
};

/// Hard cap for every top-level canonical object.
pub const MAX_CANONICAL_BYTES_V1: usize = 1_048_576;

const SNAPSHOT_MAGIC: &[u8; 4] = b"DRS1";
const ADMISSION_CHECKPOINT_MAGIC_V2: &[u8; 4] = b"DRA2";
const EVENT_MAGIC: &[u8; 4] = b"DRE1";
const EFFECT_MAGIC: &[u8; 4] = b"DRX1";
const TIMER_MAGIC: &[u8; 4] = b"DRT1";

/// Canonical codec failure without echoing potentially sensitive bytes.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CodecErrorV1 {
    /// The encoded object or a bounded field exceeds its limit.
    #[error("canonical object exceeds its bound")]
    TooLarge,
    /// Input ended before the declared object was complete.
    #[error("truncated canonical object")]
    Truncated,
    /// A magic prefix or enum tag is unknown.
    #[error("invalid canonical tag")]
    InvalidTag,
    /// Bytes remained after the one expected object.
    #[error("trailing bytes after canonical object")]
    TrailingBytes,
    /// Values violate route invariants or use a zero identity.
    #[error("invalid canonical value")]
    InvalidValue,
}

/// Fixed canonical encode/decode contract used by the journal and outbox.
pub trait CanonicalCodecV1: Sized {
    /// Encode one object using its versioned canonical representation.
    fn encode_canonical(&self) -> Result<Vec<u8>, CodecErrorV1>;

    /// Decode one complete object and reject non-canonical/trailing input.
    fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecErrorV1>;
}

/// Compute the protocol's domain-neutral BLAKE2b-256 byte commitment.
pub fn digest_bytes_v1(bytes: &[u8]) -> Digest32 {
    digest_v1(bytes)
}

pub(crate) fn digest_v1(bytes: &[u8]) -> Digest32 {
    let mut hasher = Blake2b::<U32>::new();
    Digest::update(&mut hasher, bytes);
    hasher.finalize().into()
}

pub(crate) fn domain_digest_v1(domain: &[u8], parts: &[&[u8]]) -> Digest32 {
    let mut hasher = Blake2b::<U32>::new();
    Digest::update(&mut hasher, (domain.len() as u64).to_be_bytes());
    Digest::update(&mut hasher, domain);
    for part in parts {
        Digest::update(&mut hasher, (part.len() as u64).to_be_bytes());
        Digest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new(magic: &[u8; 4]) -> Self {
        Self {
            bytes: magic.to_vec(),
        }
    }

    fn extend(&mut self, value: &[u8]) -> Result<(), CodecErrorV1> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(CodecErrorV1::TooLarge)?;
        if next > MAX_CANONICAL_BYTES_V1 {
            return Err(CodecErrorV1::TooLarge);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), CodecErrorV1> {
        self.extend(&[value])
    }

    fn bool(&mut self, value: bool) -> Result<(), CodecErrorV1> {
        self.u8(u8::from(value))
    }

    fn u32(&mut self, value: u32) -> Result<(), CodecErrorV1> {
        self.extend(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), CodecErrorV1> {
        self.extend(&value.to_be_bytes())
    }

    fn digest(&mut self, value: &Digest32) -> Result<(), CodecErrorV1> {
        self.extend(value)
    }

    fn optional<T>(
        &mut self,
        value: &Option<T>,
        encode: impl FnOnce(&mut Self, &T) -> Result<(), CodecErrorV1>,
    ) -> Result<(), CodecErrorV1> {
        match value {
            None => self.u8(0),
            Some(inner) => {
                self.u8(1)?;
                encode(self, inner)
            }
        }
    }

    fn bounded_bytes(&mut self, value: &[u8], max: usize) -> Result<(), CodecErrorV1> {
        if value.len() > max || value.len() > u32::MAX as usize {
            return Err(CodecErrorV1::TooLarge);
        }
        self.u32(value.len() as u32)?;
        self.extend(value)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8; 4]) -> Result<Self, CodecErrorV1> {
        if bytes.len() > MAX_CANONICAL_BYTES_V1 {
            return Err(CodecErrorV1::TooLarge);
        }
        if bytes.len() < magic.len() {
            return Err(CodecErrorV1::Truncated);
        }
        if &bytes[..magic.len()] != magic {
            return Err(CodecErrorV1::InvalidTag);
        }
        Ok(Self {
            bytes,
            cursor: magic.len(),
        })
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], CodecErrorV1> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(CodecErrorV1::TooLarge)?;
        if end > self.bytes.len() {
            return Err(CodecErrorV1::Truncated);
        }
        let result = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8, CodecErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, CodecErrorV1> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecErrorV1::InvalidTag),
        }
    }

    fn u32(&mut self) -> Result<u32, CodecErrorV1> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| CodecErrorV1::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, CodecErrorV1> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| CodecErrorV1::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn digest(&mut self) -> Result<Digest32, CodecErrorV1> {
        self.take(32)?
            .try_into()
            .map_err(|_| CodecErrorV1::Truncated)
    }

    fn optional<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, CodecErrorV1>,
    ) -> Result<Option<T>, CodecErrorV1> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(decode(self)?)),
            _ => Err(CodecErrorV1::InvalidTag),
        }
    }

    fn bounded_bytes(&mut self, max: usize) -> Result<Vec<u8>, CodecErrorV1> {
        let len = self.u32()? as usize;
        if len > max || len > MAX_CANONICAL_BYTES_V1 {
            return Err(CodecErrorV1::TooLarge);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(self) -> Result<(), CodecErrorV1> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(CodecErrorV1::TrailingBytes)
        }
    }
}

impl CanonicalCodecV1 for RouteSnapshotV1 {
    fn encode_canonical(&self) -> Result<Vec<u8>, CodecErrorV1> {
        self.validate()?;
        let mut writer = Writer::new(SNAPSHOT_MAGIC);
        writer.digest(&self.route_id)?;
        writer.u64(self.revision)?;
        encode_coordination(&mut writer, self.coordination)?;
        encode_leg(&mut writer, &self.upstream)?;
        encode_leg(&mut writer, &self.downstream)?;
        encode_secret(&mut writer, &self.secret_visibility)?;
        encode_health(&mut writer, self.health)?;
        writer.optional(&self.bindings, encode_bindings)?;
        writer.optional(&self.refunds, encode_refunds)?;
        writer.bool(self.aborted_unfunded)?;
        writer.u64(self.last_event_sequence)?;
        writer.digest(&self.last_event_digest)?;
        Ok(writer.finish())
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecErrorV1> {
        let mut reader = Reader::new(bytes, SNAPSHOT_MAGIC)?;
        let snapshot = Self {
            route_id: reader.digest()?,
            revision: reader.u64()?,
            coordination: decode_coordination(&mut reader)?,
            upstream: decode_leg(&mut reader)?,
            downstream: decode_leg(&mut reader)?,
            secret_visibility: decode_secret(&mut reader)?,
            health: decode_health(&mut reader)?,
            bindings: reader.optional(decode_bindings)?,
            refunds: reader.optional(decode_refunds)?,
            aborted_unfunded: reader.bool()?,
            last_event_sequence: reader.u64()?,
            last_event_digest: reader.digest()?,
        };
        reader.finish()?;
        snapshot.validate()?;
        Ok(snapshot)
    }
}

impl CanonicalCodecV1 for FrozenRouteAdmissionCheckpointV2 {
    fn encode_canonical(&self) -> Result<Vec<u8>, CodecErrorV1> {
        validate_frozen_admission_checkpoint_v2(self)?;
        let mut writer = Writer::new(ADMISSION_CHECKPOINT_MAGIC_V2);
        encode_frozen_admission_checkpoint_v2(&mut writer, self)?;
        Ok(writer.finish())
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecErrorV1> {
        let mut reader = Reader::new(bytes, ADMISSION_CHECKPOINT_MAGIC_V2)?;
        let value = decode_frozen_admission_checkpoint_v2(&mut reader)?;
        reader.finish()?;
        validate_frozen_admission_checkpoint_v2(&value)?;
        Ok(value)
    }
}

impl CanonicalCodecV1 for RouteEventV1 {
    fn encode_canonical(&self) -> Result<Vec<u8>, CodecErrorV1> {
        validate_event(self)?;
        let mut writer = Writer::new(EVENT_MAGIC);
        match self {
            Self::FreezeTerms(value) => {
                writer.u8(0)?;
                encode_bindings(&mut writer, value)?;
            }
            Self::FreezeTermsV2(value) => {
                writer.u8(14)?;
                encode_frozen_admission_checkpoint_v2(&mut writer, value)?;
            }
            Self::ArmRefunds(value) => {
                writer.u8(1)?;
                encode_refunds(&mut writer, value)?;
            }
            Self::CommitAction(intent) => {
                writer.u8(2)?;
                encode_intent(&mut writer, intent)?;
            }
            Self::ReauthorizeCommittedAction {
                prior_effect_id,
                non_externalization_evidence_digest,
                intent,
            } => {
                writer.u8(11)?;
                writer.digest(prior_effect_id)?;
                writer.digest(non_externalization_evidence_digest)?;
                encode_intent(&mut writer, intent)?;
            }
            Self::ReauthorizePartiallyExternalizedCustody {
                prior_effect_id,
                partial_externalization_evidence_digest,
                intent,
            } => {
                writer.u8(12)?;
                writer.digest(prior_effect_id)?;
                writer.digest(partial_externalization_evidence_digest)?;
                encode_intent(&mut writer, intent)?;
            }
            Self::CustodyProgressRecorded {
                leg,
                kind,
                effect_id,
                progress_evidence_digest,
                exposure,
            } => {
                writer.u8(13)?;
                encode_leg_id(&mut writer, *leg)?;
                encode_action_kind(&mut writer, *kind)?;
                writer.digest(effect_id)?;
                writer.digest(progress_evidence_digest)?;
                writer.optional(exposure, encode_exposure)?;
            }
            Self::ActionExternalized {
                leg,
                kind,
                effect_id,
                transaction_id,
                exposure,
            } => {
                writer.u8(3)?;
                encode_leg_id(&mut writer, *leg)?;
                encode_action_kind(&mut writer, *kind)?;
                writer.digest(effect_id)?;
                writer.digest(transaction_id)?;
                writer.optional(exposure, encode_exposure)?;
            }
            Self::ActionFinalized {
                leg,
                kind,
                transaction_id,
                evidence_digest,
            } => {
                writer.u8(4)?;
                encode_leg_id(&mut writer, *leg)?;
                encode_action_kind(&mut writer, *kind)?;
                writer.digest(transaction_id)?;
                writer.digest(evidence_digest)?;
            }
            Self::ObservationInvalidated {
                leg,
                kind,
                transaction_id,
                reorg_evidence_digest,
            } => {
                writer.u8(5)?;
                encode_leg_id(&mut writer, *leg)?;
                encode_action_kind(&mut writer, *kind)?;
                writer.digest(transaction_id)?;
                writer.digest(reorg_evidence_digest)?;
            }
            Self::SecretObserved(exposure) => {
                writer.u8(6)?;
                encode_exposure(&mut writer, exposure)?;
            }
            Self::SetHealth {
                target,
                reason_digest,
            } => {
                writer.u8(7)?;
                encode_health(&mut writer, *target)?;
                writer.digest(reason_digest)?;
            }
            Self::ScheduleTimer {
                kind,
                deadline_unix_ms,
                context_digest,
            } => {
                writer.u8(8)?;
                encode_timer_kind(&mut writer, *kind)?;
                writer.u64(*deadline_unix_ms)?;
                writer.digest(context_digest)?;
            }
            Self::CancelTimer { timer_id } => {
                writer.u8(9)?;
                writer.digest(timer_id)?;
            }
            Self::AbortUnfunded { reason_digest } => {
                writer.u8(10)?;
                writer.digest(reason_digest)?;
            }
        }
        Ok(writer.finish())
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecErrorV1> {
        let mut reader = Reader::new(bytes, EVENT_MAGIC)?;
        let event = match reader.u8()? {
            0 => Self::FreezeTerms(decode_bindings(&mut reader)?),
            1 => Self::ArmRefunds(decode_refunds(&mut reader)?),
            2 => Self::CommitAction(decode_intent(&mut reader)?),
            3 => Self::ActionExternalized {
                leg: decode_leg_id(&mut reader)?,
                kind: decode_action_kind(&mut reader)?,
                effect_id: reader.digest()?,
                transaction_id: reader.digest()?,
                exposure: reader.optional(decode_exposure)?,
            },
            4 => Self::ActionFinalized {
                leg: decode_leg_id(&mut reader)?,
                kind: decode_action_kind(&mut reader)?,
                transaction_id: reader.digest()?,
                evidence_digest: reader.digest()?,
            },
            5 => Self::ObservationInvalidated {
                leg: decode_leg_id(&mut reader)?,
                kind: decode_action_kind(&mut reader)?,
                transaction_id: reader.digest()?,
                reorg_evidence_digest: reader.digest()?,
            },
            6 => Self::SecretObserved(decode_exposure(&mut reader)?),
            7 => Self::SetHealth {
                target: decode_health(&mut reader)?,
                reason_digest: reader.digest()?,
            },
            8 => Self::ScheduleTimer {
                kind: decode_timer_kind(&mut reader)?,
                deadline_unix_ms: reader.u64()?,
                context_digest: reader.digest()?,
            },
            9 => Self::CancelTimer {
                timer_id: reader.digest()?,
            },
            10 => Self::AbortUnfunded {
                reason_digest: reader.digest()?,
            },
            11 => Self::ReauthorizeCommittedAction {
                prior_effect_id: reader.digest()?,
                non_externalization_evidence_digest: reader.digest()?,
                intent: decode_intent(&mut reader)?,
            },
            12 => Self::ReauthorizePartiallyExternalizedCustody {
                prior_effect_id: reader.digest()?,
                partial_externalization_evidence_digest: reader.digest()?,
                intent: decode_intent(&mut reader)?,
            },
            13 => Self::CustodyProgressRecorded {
                leg: decode_leg_id(&mut reader)?,
                kind: decode_action_kind(&mut reader)?,
                effect_id: reader.digest()?,
                progress_evidence_digest: reader.digest()?,
                exposure: reader.optional(decode_exposure)?,
            },
            14 => Self::FreezeTermsV2(Box::new(decode_frozen_admission_checkpoint_v2(
                &mut reader,
            )?)),
            _ => return Err(CodecErrorV1::InvalidTag),
        };
        reader.finish()?;
        validate_event(&event)?;
        Ok(event)
    }
}

impl CanonicalCodecV1 for RouteEffectV1 {
    fn encode_canonical(&self) -> Result<Vec<u8>, CodecErrorV1> {
        validate_effect(self)?;
        let mut writer = Writer::new(EFFECT_MAGIC);
        writer.digest(&self.route_id)?;
        writer.digest(&self.effect_id)?;
        writer.u64(self.fencing_epoch)?;
        encode_leg_id(&mut writer, self.leg)?;
        encode_action_kind(&mut writer, self.kind)?;
        encode_priority(&mut writer, self.priority)?;
        writer.digest(&self.semantic_digest)?;
        writer.bool(self.contains_route_secret)?;
        encode_dispatch(&mut writer, &self.dispatch)?;
        Ok(writer.finish())
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecErrorV1> {
        let mut reader = Reader::new(bytes, EFFECT_MAGIC)?;
        let effect = Self {
            route_id: reader.digest()?,
            effect_id: reader.digest()?,
            fencing_epoch: reader.u64()?,
            leg: decode_leg_id(&mut reader)?,
            kind: decode_action_kind(&mut reader)?,
            priority: decode_priority(&mut reader)?,
            semantic_digest: reader.digest()?,
            contains_route_secret: reader.bool()?,
            dispatch: decode_dispatch(&mut reader)?,
        };
        reader.finish()?;
        validate_effect(&effect)?;
        Ok(effect)
    }
}

impl CanonicalCodecV1 for RouteTimerV1 {
    fn encode_canonical(&self) -> Result<Vec<u8>, CodecErrorV1> {
        validate_timer(self)?;
        let mut writer = Writer::new(TIMER_MAGIC);
        writer.digest(&self.route_id)?;
        writer.digest(&self.timer_id)?;
        writer.u64(self.fencing_epoch)?;
        encode_timer_kind(&mut writer, self.kind)?;
        writer.u64(self.deadline_unix_ms)?;
        writer.digest(&self.context_digest)?;
        Ok(writer.finish())
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, CodecErrorV1> {
        let mut reader = Reader::new(bytes, TIMER_MAGIC)?;
        let timer = Self {
            route_id: reader.digest()?,
            timer_id: reader.digest()?,
            fencing_epoch: reader.u64()?,
            kind: decode_timer_kind(&mut reader)?,
            deadline_unix_ms: reader.u64()?,
            context_digest: reader.digest()?,
        };
        reader.finish()?;
        validate_timer(&timer)?;
        Ok(timer)
    }
}

fn encode_coordination(
    writer: &mut Writer,
    value: CoordinationPhaseV1,
) -> Result<(), CodecErrorV1> {
    writer.u8(match value {
        CoordinationPhaseV1::Negotiating => 0,
        CoordinationPhaseV1::TermsFrozen => 1,
        CoordinationPhaseV1::RefundsArmed => 2,
        CoordinationPhaseV1::Funding => 3,
        CoordinationPhaseV1::Settling => 4,
        CoordinationPhaseV1::Recovery => 5,
        CoordinationPhaseV1::Terminal => 6,
    })
}

fn decode_coordination(reader: &mut Reader<'_>) -> Result<CoordinationPhaseV1, CodecErrorV1> {
    match reader.u8()? {
        0 => Ok(CoordinationPhaseV1::Negotiating),
        1 => Ok(CoordinationPhaseV1::TermsFrozen),
        2 => Ok(CoordinationPhaseV1::RefundsArmed),
        3 => Ok(CoordinationPhaseV1::Funding),
        4 => Ok(CoordinationPhaseV1::Settling),
        5 => Ok(CoordinationPhaseV1::Recovery),
        6 => Ok(CoordinationPhaseV1::Terminal),
        _ => Err(CodecErrorV1::InvalidTag),
    }
}

fn encode_health(writer: &mut Writer, value: HealthStateV1) -> Result<(), CodecErrorV1> {
    writer.u8(match value {
        HealthStateV1::Running => 0,
        HealthStateV1::Degraded => 1,
        HealthStateV1::RecoveryOnly => 2,
        HealthStateV1::ManualIntervention => 3,
    })
}

fn decode_health(reader: &mut Reader<'_>) -> Result<HealthStateV1, CodecErrorV1> {
    match reader.u8()? {
        0 => Ok(HealthStateV1::Running),
        1 => Ok(HealthStateV1::Degraded),
        2 => Ok(HealthStateV1::RecoveryOnly),
        3 => Ok(HealthStateV1::ManualIntervention),
        _ => Err(CodecErrorV1::InvalidTag),
    }
}

fn encode_leg_id(writer: &mut Writer, value: LegIdV1) -> Result<(), CodecErrorV1> {
    writer.u8(match value {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    })
}

fn decode_leg_id(reader: &mut Reader<'_>) -> Result<LegIdV1, CodecErrorV1> {
    match reader.u8()? {
        0 => Ok(LegIdV1::Upstream),
        1 => Ok(LegIdV1::Downstream),
        _ => Err(CodecErrorV1::InvalidTag),
    }
}

fn encode_action_kind(writer: &mut Writer, value: ActionKindV1) -> Result<(), CodecErrorV1> {
    writer.u8(match value {
        ActionKindV1::Funding => 0,
        ActionKindV1::Claim => 1,
        ActionKindV1::Refund => 2,
    })
}

fn decode_action_kind(reader: &mut Reader<'_>) -> Result<ActionKindV1, CodecErrorV1> {
    match reader.u8()? {
        0 => Ok(ActionKindV1::Funding),
        1 => Ok(ActionKindV1::Claim),
        2 => Ok(ActionKindV1::Refund),
        _ => Err(CodecErrorV1::InvalidTag),
    }
}

fn encode_priority(writer: &mut Writer, value: EffectPriorityV1) -> Result<(), CodecErrorV1> {
    writer.u8(match value {
        EffectPriorityV1::Normal => 0,
        EffectPriorityV1::Recovery => 1,
        EffectPriorityV1::SecretPublicUrgent => 2,
    })
}

fn decode_priority(reader: &mut Reader<'_>) -> Result<EffectPriorityV1, CodecErrorV1> {
    match reader.u8()? {
        0 => Ok(EffectPriorityV1::Normal),
        1 => Ok(EffectPriorityV1::Recovery),
        2 => Ok(EffectPriorityV1::SecretPublicUrgent),
        _ => Err(CodecErrorV1::InvalidTag),
    }
}

fn encode_timer_kind(writer: &mut Writer, value: TimerKindV1) -> Result<(), CodecErrorV1> {
    writer.u8(match value {
        TimerKindV1::Deadline => 0,
        TimerKindV1::Retry => 1,
        TimerKindV1::Reconcile => 2,
    })
}

fn decode_timer_kind(reader: &mut Reader<'_>) -> Result<TimerKindV1, CodecErrorV1> {
    match reader.u8()? {
        0 => Ok(TimerKindV1::Deadline),
        1 => Ok(TimerKindV1::Retry),
        2 => Ok(TimerKindV1::Reconcile),
        _ => Err(CodecErrorV1::InvalidTag),
    }
}

fn encode_exposure(writer: &mut Writer, value: &PublicExposureV1) -> Result<(), CodecErrorV1> {
    validate_exposure(value)?;
    writer.u8(match value.source {
        ExposureSourceV1::Mempool => 0,
        ExposureSourceV1::Externalized => 1,
        ExposureSourceV1::Block => 2,
        ExposureSourceV1::PeerEvidence => 3,
    })?;
    writer.digest(&value.chain_id)?;
    writer.digest(&value.transaction_id)?;
    writer.digest(&value.evidence_digest)?;
    writer.u64(value.observed_at_unix_ms)
}

fn decode_exposure(reader: &mut Reader<'_>) -> Result<PublicExposureV1, CodecErrorV1> {
    let source = match reader.u8()? {
        0 => ExposureSourceV1::Mempool,
        1 => ExposureSourceV1::Externalized,
        2 => ExposureSourceV1::Block,
        3 => ExposureSourceV1::PeerEvidence,
        _ => return Err(CodecErrorV1::InvalidTag),
    };
    let exposure = PublicExposureV1 {
        source,
        chain_id: reader.digest()?,
        transaction_id: reader.digest()?,
        evidence_digest: reader.digest()?,
        observed_at_unix_ms: reader.u64()?,
    };
    validate_exposure(&exposure)?;
    Ok(exposure)
}

fn encode_reference(writer: &mut Writer, value: &EffectReferenceV1) -> Result<(), CodecErrorV1> {
    validate_effect_reference(value)?;
    writer.digest(&value.effect_id)?;
    writer.u64(value.fencing_epoch)?;
    writer.digest(&value.semantic_digest)?;
    writer.bool(value.contains_route_secret)?;
    writer.optional(&value.expected_transaction_id, |writer, digest| {
        writer.digest(digest)
    })
}

fn decode_reference(reader: &mut Reader<'_>) -> Result<EffectReferenceV1, CodecErrorV1> {
    let value = EffectReferenceV1 {
        effect_id: reader.digest()?,
        fencing_epoch: reader.u64()?,
        semantic_digest: reader.digest()?,
        contains_route_secret: reader.bool()?,
        expected_transaction_id: reader.optional(Reader::digest)?,
    };
    validate_effect_reference(&value)?;
    Ok(value)
}

fn encode_action_state(writer: &mut Writer, value: &ActionStateV1) -> Result<(), CodecErrorV1> {
    match value {
        ActionStateV1::NotPrepared => writer.u8(0),
        ActionStateV1::Committed(effect) => {
            writer.u8(1)?;
            encode_reference(writer, effect)
        }
        ActionStateV1::Externalized {
            effect,
            transaction_id,
        } => {
            writer.u8(2)?;
            encode_reference(writer, effect)?;
            writer.digest(transaction_id)
        }
        ActionStateV1::Final {
            effect,
            transaction_id,
            evidence_digest,
        } => {
            writer.u8(3)?;
            encode_reference(writer, effect)?;
            writer.digest(transaction_id)?;
            writer.digest(evidence_digest)
        }
        ActionStateV1::FinalityInvalidated {
            effect,
            transaction_id,
            prior_evidence_digest,
            reorg_evidence_digest,
        } => {
            writer.u8(4)?;
            encode_reference(writer, effect)?;
            writer.digest(transaction_id)?;
            writer.digest(prior_evidence_digest)?;
            writer.digest(reorg_evidence_digest)
        }
    }
}

fn decode_action_state(reader: &mut Reader<'_>) -> Result<ActionStateV1, CodecErrorV1> {
    match reader.u8()? {
        0 => Ok(ActionStateV1::NotPrepared),
        1 => Ok(ActionStateV1::Committed(decode_reference(reader)?)),
        2 => Ok(ActionStateV1::Externalized {
            effect: decode_reference(reader)?,
            transaction_id: reader.digest()?,
        }),
        3 => Ok(ActionStateV1::Final {
            effect: decode_reference(reader)?,
            transaction_id: reader.digest()?,
            evidence_digest: reader.digest()?,
        }),
        4 => Ok(ActionStateV1::FinalityInvalidated {
            effect: decode_reference(reader)?,
            transaction_id: reader.digest()?,
            prior_evidence_digest: reader.digest()?,
            reorg_evidence_digest: reader.digest()?,
        }),
        _ => Err(CodecErrorV1::InvalidTag),
    }
}

fn encode_leg(writer: &mut Writer, value: &LegSnapshotV1) -> Result<(), CodecErrorV1> {
    encode_action_state(writer, &value.funding)?;
    encode_action_state(writer, &value.claim)?;
    encode_action_state(writer, &value.refund)
}

fn decode_leg(reader: &mut Reader<'_>) -> Result<LegSnapshotV1, CodecErrorV1> {
    Ok(LegSnapshotV1 {
        funding: decode_action_state(reader)?,
        claim: decode_action_state(reader)?,
        refund: decode_action_state(reader)?,
    })
}

fn encode_secret(writer: &mut Writer, value: &SecretVisibilityV1) -> Result<(), CodecErrorV1> {
    match value {
        SecretVisibilityV1::Private => writer.u8(0),
        SecretVisibilityV1::Public { first_exposure } => {
            writer.u8(1)?;
            encode_exposure(writer, first_exposure)
        }
    }
}

fn decode_secret(reader: &mut Reader<'_>) -> Result<SecretVisibilityV1, CodecErrorV1> {
    match reader.u8()? {
        0 => Ok(SecretVisibilityV1::Private),
        1 => Ok(SecretVisibilityV1::Public {
            first_exposure: decode_exposure(reader)?,
        }),
        _ => Err(CodecErrorV1::InvalidTag),
    }
}

fn encode_bindings(writer: &mut Writer, value: &FrozenBindingsV1) -> Result<(), CodecErrorV1> {
    writer.digest(&value.terms_digest)?;
    writer.digest(&value.profile_bundle_digest)?;
    writer.digest(&value.deployment_bundle_digest)
}

fn decode_bindings(reader: &mut Reader<'_>) -> Result<FrozenBindingsV1, CodecErrorV1> {
    Ok(FrozenBindingsV1 {
        terms_digest: reader.digest()?,
        profile_bundle_digest: reader.digest()?,
        deployment_bundle_digest: reader.digest()?,
    })
}

fn encode_frozen_admission_checkpoint_v2(
    writer: &mut Writer,
    value: &FrozenRouteAdmissionCheckpointV2,
) -> Result<(), CodecErrorV1> {
    validate_frozen_admission_checkpoint_v2(value)?;
    writer.digest(&value.network_id)?;
    writer.digest(&value.route_id)?;
    encode_bindings(writer, &value.bindings)?;
    writer.digest(&value.composition_v2_digest)?;
    writer.u64(value.registry_epoch)?;
    writer.digest(&value.registry_manifest_digest)?;
    writer.digest(&value.upstream_terms_digest)?;
    writer.digest(&value.downstream_terms_digest)?;
    writer.digest(&value.upstream_roster_snapshot)?;
    writer.digest(&value.downstream_roster_snapshot)?;
    writer.digest(&value.participant_bindings_digest)?;
    writer.digest(&value.relay_binding_digest)?;
    writer.digest(&value.registry_authority_set_digest)?;
    writer.digest(&value.time_policy_authority_set_digest)?;
    writer.digest(&value.time_evidence_authority_set_digest)?;
    writer.digest(&value.time.route_scope_digest)?;
    writer.digest(&value.time.policy_digest)?;
    writer.digest(&value.time.evidence_digest)?;
    writer.digest(&value.time.proof_digest)?;
    writer.u64(value.time.evidence_sequence)?;
    writer.u64(value.time.issued_at_seconds)?;
    writer.u64(value.time.valid_until_seconds)?;
    writer.u64(value.time.validated_at_seconds)
}

fn decode_frozen_admission_checkpoint_v2(
    reader: &mut Reader<'_>,
) -> Result<FrozenRouteAdmissionCheckpointV2, CodecErrorV1> {
    let value = FrozenRouteAdmissionCheckpointV2 {
        network_id: reader.digest()?,
        route_id: reader.digest()?,
        bindings: decode_bindings(reader)?,
        composition_v2_digest: reader.digest()?,
        registry_epoch: reader.u64()?,
        registry_manifest_digest: reader.digest()?,
        upstream_terms_digest: reader.digest()?,
        downstream_terms_digest: reader.digest()?,
        upstream_roster_snapshot: reader.digest()?,
        downstream_roster_snapshot: reader.digest()?,
        participant_bindings_digest: reader.digest()?,
        relay_binding_digest: reader.digest()?,
        registry_authority_set_digest: reader.digest()?,
        time_policy_authority_set_digest: reader.digest()?,
        time_evidence_authority_set_digest: reader.digest()?,
        time: FrozenRouteTimeFactsV2 {
            route_scope_digest: reader.digest()?,
            policy_digest: reader.digest()?,
            evidence_digest: reader.digest()?,
            proof_digest: reader.digest()?,
            evidence_sequence: reader.u64()?,
            issued_at_seconds: reader.u64()?,
            valid_until_seconds: reader.u64()?,
            validated_at_seconds: reader.u64()?,
        },
    };
    validate_frozen_admission_checkpoint_v2(&value)?;
    Ok(value)
}

fn encode_refunds(writer: &mut Writer, value: &RefundBindingsV1) -> Result<(), CodecErrorV1> {
    writer.digest(&value.upstream_refund_digest)?;
    writer.digest(&value.downstream_refund_digest)
}

fn decode_refunds(reader: &mut Reader<'_>) -> Result<RefundBindingsV1, CodecErrorV1> {
    Ok(RefundBindingsV1 {
        upstream_refund_digest: reader.digest()?,
        downstream_refund_digest: reader.digest()?,
    })
}

fn encode_dispatch(writer: &mut Writer, value: &EffectDispatchV1) -> Result<(), CodecErrorV1> {
    match value {
        EffectDispatchV1::RunnerPayload {
            payload,
            payload_digest,
        } => {
            writer.u8(0)?;
            writer.bounded_bytes(payload, MAX_EFFECT_PAYLOAD_BYTES_V1)?;
            writer.digest(payload_digest)
        }
        EffectDispatchV1::ExternalCustody {
            custody_digest,
            transaction_id,
        } => {
            writer.u8(1)?;
            writer.digest(custody_digest)?;
            writer.digest(transaction_id)
        }
    }
}

fn decode_dispatch(reader: &mut Reader<'_>) -> Result<EffectDispatchV1, CodecErrorV1> {
    match reader.u8()? {
        0 => Ok(EffectDispatchV1::RunnerPayload {
            payload: reader.bounded_bytes(MAX_EFFECT_PAYLOAD_BYTES_V1)?,
            payload_digest: reader.digest()?,
        }),
        1 => Ok(EffectDispatchV1::ExternalCustody {
            custody_digest: reader.digest()?,
            transaction_id: reader.digest()?,
        }),
        _ => Err(CodecErrorV1::InvalidTag),
    }
}

fn encode_intent(writer: &mut Writer, value: &ActionIntentV1) -> Result<(), CodecErrorV1> {
    validate_effect_dispatch(&value.dispatch, value.contains_route_secret)?;
    encode_leg_id(writer, value.leg)?;
    encode_action_kind(writer, value.kind)?;
    writer.digest(&value.semantic_digest)?;
    writer.bool(value.contains_route_secret)?;
    encode_dispatch(writer, &value.dispatch)
}

fn decode_intent(reader: &mut Reader<'_>) -> Result<ActionIntentV1, CodecErrorV1> {
    let value = ActionIntentV1 {
        leg: decode_leg_id(reader)?,
        kind: decode_action_kind(reader)?,
        semantic_digest: reader.digest()?,
        contains_route_secret: reader.bool()?,
        dispatch: decode_dispatch(reader)?,
    };
    validate_effect_dispatch(&value.dispatch, value.contains_route_secret)?;
    Ok(value)
}

fn encode_priority_rank(value: EffectPriorityV1) -> i64 {
    match value {
        EffectPriorityV1::Normal => 0,
        EffectPriorityV1::Recovery => 1,
        EffectPriorityV1::SecretPublicUrgent => 2,
    }
}

pub(crate) fn priority_rank_v1(value: EffectPriorityV1) -> i64 {
    encode_priority_rank(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> Digest32 {
        [value; 32]
    }

    fn frozen_admission_v2() -> FrozenRouteAdmissionCheckpointV2 {
        FrozenRouteAdmissionCheckpointV2 {
            network_id: id(1),
            route_id: id(2),
            bindings: FrozenBindingsV1 {
                terms_digest: id(3),
                profile_bundle_digest: id(4),
                deployment_bundle_digest: id(5),
            },
            composition_v2_digest: id(6),
            registry_epoch: 7,
            registry_manifest_digest: id(5),
            upstream_terms_digest: id(8),
            downstream_terms_digest: id(9),
            upstream_roster_snapshot: id(10),
            downstream_roster_snapshot: id(11),
            participant_bindings_digest: id(12),
            relay_binding_digest: id(13),
            registry_authority_set_digest: id(14),
            time_policy_authority_set_digest: id(15),
            time_evidence_authority_set_digest: id(16),
            time: FrozenRouteTimeFactsV2 {
                route_scope_digest: id(17),
                policy_digest: id(18),
                evidence_digest: id(19),
                proof_digest: id(20),
                evidence_sequence: 21,
                issued_at_seconds: 1_000,
                valid_until_seconds: 2_000,
                validated_at_seconds: 1_100,
            },
        }
    }

    #[test]
    fn frozen_admission_v2_codec_and_event_tag_are_exact() {
        let checkpoint = frozen_admission_v2();
        let bytes = checkpoint.encode_canonical().expect("checkpoint encoding");
        assert_eq!(bytes.len(), 684);
        assert_eq!(
            digest_bytes_v1(&bytes),
            [
                42, 10, 181, 30, 149, 210, 222, 35, 144, 64, 252, 179, 108, 61, 6, 146, 19, 148,
                21, 105, 221, 178, 42, 214, 33, 98, 198, 76, 43, 189, 241, 250,
            ]
        );
        assert_eq!(
            FrozenRouteAdmissionCheckpointV2::decode_canonical(&bytes),
            Ok(checkpoint.clone())
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            FrozenRouteAdmissionCheckpointV2::decode_canonical(&trailing),
            Err(CodecErrorV1::TrailingBytes)
        );

        let event = RouteEventV1::FreezeTermsV2(Box::new(checkpoint));
        let event_bytes = event.encode_canonical().expect("event encoding");
        assert_eq!(event_bytes.len(), 685);
        assert_eq!(event_bytes[EVENT_MAGIC.len()], 14);
        assert_eq!(RouteEventV1::decode_canonical(&event_bytes), Ok(event));
    }

    #[test]
    fn snapshot_codec_is_exact_and_rejects_trailing_bytes() {
        let snapshot = RouteSnapshotV1::new(id(1)).expect("valid route id");
        let bytes = snapshot.encode_canonical().expect("encode");
        assert_eq!(RouteSnapshotV1::decode_canonical(&bytes), Ok(snapshot));

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            RouteSnapshotV1::decode_canonical(&trailing),
            Err(CodecErrorV1::TrailingBytes)
        );
    }

    #[test]
    fn payload_length_is_checked_before_allocation() {
        let mut bytes = EVENT_MAGIC.to_vec();
        bytes.push(2); // CommitAction
        bytes.push(0); // upstream
        bytes.push(0); // funding
        bytes.extend_from_slice(&id(2));
        bytes.push(0); // does not contain secret
        bytes.push(0); // runner payload
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            RouteEventV1::decode_canonical(&bytes),
            Err(CodecErrorV1::TooLarge)
        );
    }

    #[test]
    fn partial_custody_reauthorization_has_a_distinct_canonical_tag() {
        let event = RouteEventV1::ReauthorizePartiallyExternalizedCustody {
            prior_effect_id: id(40),
            partial_externalization_evidence_digest: id(41),
            intent: ActionIntentV1 {
                leg: LegIdV1::Downstream,
                kind: ActionKindV1::Claim,
                semantic_digest: id(42),
                contains_route_secret: true,
                dispatch: EffectDispatchV1::ExternalCustody {
                    custody_digest: id(43),
                    transaction_id: id(44),
                },
            },
        };
        let bytes = event.encode_canonical().expect("canonical partial resume");
        assert_eq!(bytes[EVENT_MAGIC.len()], 12);
        assert_eq!(RouteEventV1::decode_canonical(&bytes), Ok(event));

        let payload = vec![0x45; 8];
        let invalid = RouteEventV1::ReauthorizePartiallyExternalizedCustody {
            prior_effect_id: id(46),
            partial_externalization_evidence_digest: id(47),
            intent: ActionIntentV1 {
                leg: LegIdV1::Upstream,
                kind: ActionKindV1::Funding,
                semantic_digest: id(48),
                contains_route_secret: false,
                dispatch: EffectDispatchV1::RunnerPayload {
                    payload_digest: digest_v1(&payload),
                    payload,
                },
            },
        };
        assert_eq!(invalid.encode_canonical(), Err(CodecErrorV1::InvalidValue));
    }

    #[test]
    fn custody_progress_has_a_distinct_canonical_tag_and_externalized_exposure() {
        let event = RouteEventV1::CustodyProgressRecorded {
            leg: LegIdV1::Downstream,
            kind: ActionKindV1::Claim,
            effect_id: id(50),
            progress_evidence_digest: id(51),
            exposure: Some(PublicExposureV1 {
                source: ExposureSourceV1::Externalized,
                chain_id: id(52),
                transaction_id: id(53),
                evidence_digest: id(54),
                observed_at_unix_ms: 55,
            }),
        };
        let bytes = event
            .encode_canonical()
            .expect("canonical custody progress");
        assert_eq!(bytes[EVENT_MAGIC.len()], 13);
        assert_eq!(RouteEventV1::decode_canonical(&bytes), Ok(event));

        let invalid = RouteEventV1::CustodyProgressRecorded {
            leg: LegIdV1::Downstream,
            kind: ActionKindV1::Claim,
            effect_id: id(50),
            progress_evidence_digest: id(51),
            exposure: Some(PublicExposureV1 {
                source: ExposureSourceV1::PeerEvidence,
                chain_id: id(52),
                transaction_id: id(53),
                evidence_digest: id(54),
                observed_at_unix_ms: 55,
            }),
        };
        assert_eq!(invalid.encode_canonical(), Err(CodecErrorV1::InvalidValue));
    }

    #[test]
    fn impossible_snapshot_is_rejected_on_decode_and_before_encode() {
        let snapshot = RouteSnapshotV1::new(id(1)).expect("valid route id");
        let mut impossible_phase = snapshot.encode_canonical().expect("encode");
        // magic (4) + route id (32) + revision (8) = coordination tag.
        impossible_phase[44] = 3; // Funding without any action/refund.
        assert_eq!(
            RouteSnapshotV1::decode_canonical(&impossible_phase),
            Err(CodecErrorV1::InvalidValue)
        );

        let mut missing_refunds = snapshot;
        missing_refunds.upstream.funding = ActionStateV1::Committed(EffectReferenceV1 {
            effect_id: id(2),
            fencing_epoch: 1,
            semantic_digest: id(3),
            contains_route_secret: false,
            expected_transaction_id: None,
        });
        missing_refunds.recompute_coordination();
        assert_eq!(
            missing_refunds.encode_canonical(),
            Err(CodecErrorV1::InvalidValue)
        );

        let mut impossible_downstream = RouteSnapshotV1::new(id(10)).expect("route");
        impossible_downstream.bindings = Some(FrozenBindingsV1 {
            terms_digest: id(11),
            profile_bundle_digest: id(12),
            deployment_bundle_digest: id(13),
        });
        impossible_downstream.refunds = Some(RefundBindingsV1 {
            upstream_refund_digest: id(14),
            downstream_refund_digest: id(15),
        });
        impossible_downstream.downstream.funding = ActionStateV1::Committed(EffectReferenceV1 {
            effect_id: id(16),
            fencing_epoch: 1,
            semantic_digest: id(17),
            contains_route_secret: false,
            expected_transaction_id: None,
        });
        impossible_downstream.health = HealthStateV1::RecoveryOnly;
        impossible_downstream.recompute_coordination();
        assert_eq!(
            impossible_downstream.encode_canonical(),
            Err(CodecErrorV1::InvalidValue)
        );

        let mut never_final_upstream = RouteSnapshotV1::new(id(20)).expect("route");
        never_final_upstream.bindings = Some(FrozenBindingsV1 {
            terms_digest: id(21),
            profile_bundle_digest: id(22),
            deployment_bundle_digest: id(23),
        });
        never_final_upstream.refunds = Some(RefundBindingsV1 {
            upstream_refund_digest: id(24),
            downstream_refund_digest: id(25),
        });
        never_final_upstream.upstream.funding = ActionStateV1::Externalized {
            effect: EffectReferenceV1 {
                effect_id: id(26),
                fencing_epoch: 1,
                semantic_digest: id(27),
                contains_route_secret: false,
                expected_transaction_id: None,
            },
            transaction_id: id(28),
        };
        never_final_upstream.upstream.claim = ActionStateV1::Committed(EffectReferenceV1 {
            effect_id: id(29),
            fencing_epoch: 1,
            semantic_digest: id(30),
            contains_route_secret: true,
            expected_transaction_id: Some(id(31)),
        });
        never_final_upstream.secret_visibility = SecretVisibilityV1::Public {
            first_exposure: PublicExposureV1 {
                source: ExposureSourceV1::PeerEvidence,
                chain_id: id(32),
                transaction_id: id(33),
                evidence_digest: id(34),
                observed_at_unix_ms: 1,
            },
        };
        never_final_upstream.health = HealthStateV1::RecoveryOnly;
        never_final_upstream.recompute_coordination();
        assert_eq!(
            never_final_upstream.encode_canonical(),
            Err(CodecErrorV1::InvalidValue)
        );
    }
}

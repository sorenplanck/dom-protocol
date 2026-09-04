//! Durable core of the vault, typed only by primitive values.
//!
//! This layer does not know `NonceVaultV1`: it knows reservations, monotonic
//! revisions, persisted artifacts and spent artifacts. The translation to the
//! `dom-adaptor` types lives in [`crate::vault`]. The separation exists so
//! that durability is testable without the pin's `pub(crate)` constructors.
//!
//! # Durable model
//!
//! The `store` only knows how to write immutable opaque records (`put_opaque`
//! refuses to overwrite with different bytes). That is why the reservation
//! state is **append-only per revision**: each transition writes a new record
//! at the key `reservation_id || revision` and only then advances the
//! monotonic anchor via CAS.
//!
//! This ordering is what provides fail-closed detection:
//!
//! * a record present at a revision ahead of the anchor ⇒ incomplete
//!   transition or anchor rollback ⇒ [`VaultError::RollbackDetected`];
//! * an anchor ahead with no corresponding record ⇒ [`VaultError::CorruptState`];
//! * invalid CRC or framing ⇒ [`VaultError::CorruptState`], with the readable
//!   prefix still saying which reservation to burn.

use std::collections::{BTreeMap, BTreeSet};

use dom_adaptor::{
    audit_bound_nonce_secret_plaintext_v1, exposure_outbound_digest_v1, ExposureKindV1,
    NonceSecretPlaintextAuditBindingV1, PurposeV1,
};
use zeroize::Zeroizing;

use crate::framing::{FrameReader, FrameWriter};
use crate::{namespace, Result, VaultError};

/// Magic of the reservation record.
const MAGIC_RESERVATION: &[u8; 8] = b"DOMVRSV1";
/// Magic of the public artifact record.
const MAGIC_ARTIFACT: &[u8; 8] = b"DOMVARV1";
/// Magic of the sealed record of the nonce pair.
const MAGIC_SEALED: &[u8; 8] = b"DOMVSSV1";
const PRODUCTION_AUDIT_MAX_ROWS: u64 = 100_000;
const PRODUCTION_AUDIT_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const PRODUCTION_AUDIT_MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;

/// Semantic discriminants of the append-only journal.
pub(crate) const JOURNAL_CLAIM: u16 = 0x0001;
pub(crate) const JOURNAL_DERIVATION_ATTEMPT: u16 = 0x0002;
pub(crate) const JOURNAL_SEAL: u16 = 0x0003;
pub(crate) const JOURNAL_OPEN: u16 = 0x0004;
pub(crate) const JOURNAL_STAGE_ATTEMPT: u16 = 0x0005;
pub(crate) const JOURNAL_PERSIST: u16 = 0x0006;
pub(crate) const JOURNAL_AUTHORIZE: u16 = 0x0007;
pub(crate) const JOURNAL_SPEND: u16 = 0x0008;
pub(crate) const JOURNAL_TERMINAL: u16 = 0x0009;

/// Durable monotonic state of the reservation, in the local one-byte encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StateCode {
    /// Budget and slot reserved.
    Reserved,
    /// Exact commitment durable and spent.
    CommitmentAuthorized,
    /// Exact reveal durable and spent.
    RevealAuthorized,
    /// Partial spent; secret material closed off.
    ConsumedPartialAuthorized,
    /// Aborted before any public material could exist.
    AbortedBeforePublicMaterial,
    /// Aborted when public material could have existed.
    ConsumedOnAbort,
    /// Ambiguous restore: nonce burned out of conservatism.
    Burned,
}

impl StateCode {
    pub(crate) const fn to_byte(self) -> u8 {
        match self {
            Self::Reserved => 1,
            Self::CommitmentAuthorized => 2,
            Self::RevealAuthorized => 3,
            Self::ConsumedPartialAuthorized => 4,
            Self::AbortedBeforePublicMaterial => 5,
            Self::ConsumedOnAbort => 6,
            Self::Burned => 7,
        }
    }

    pub(crate) fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            1 => Ok(Self::Reserved),
            2 => Ok(Self::CommitmentAuthorized),
            3 => Ok(Self::RevealAuthorized),
            4 => Ok(Self::ConsumedPartialAuthorized),
            5 => Ok(Self::AbortedBeforePublicMaterial),
            6 => Ok(Self::ConsumedOnAbort),
            7 => Ok(Self::Burned),
            // Closed registry: an unknown byte is corruption, never a default.
            _ => Err(VaultError::CorruptState),
        }
    }

    /// A terminal state never becomes live again.
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ConsumedPartialAuthorized
                | Self::AbortedBeforePublicMaterial
                | Self::ConsumedOnAbort
                | Self::Burned
        )
    }
}

/// Durable reference to an already-spent artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpentRef {
    pub(crate) permit_id: [u8; 32],
    pub(crate) outbound_digest: [u8; 32],
}

/// Canonical identity of a reservation, fixed at claim time and immutable afterwards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReservationIdentity {
    pub(crate) reservation_id: [u8; 32],
    pub(crate) request_lookup: [u8; 32],
    pub(crate) session_id: [u8; 32],
    pub(crate) participant_id: [u8; 32],
    pub(crate) purpose: u8,
    pub(crate) template_hash: [u8; 32],
    pub(crate) key_id: [u8; 32],
    pub(crate) counterparty: [u8; 32],
    pub(crate) context_binding_digest: [u8; 32],
    pub(crate) nonce_epoch: u64,
}

/// Complete durable record of a reservation, at an exact revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReservationRecord {
    pub(crate) identity: ReservationIdentity,
    pub(crate) revision: u64,
    pub(crate) state: StateCode,
    pub(crate) retry_counter: Option<u64>,
    pub(crate) attempt_digest: Option<[u8; 32]>,
    pub(crate) stage_digest: Option<[u8; 32]>,
    pub(crate) sealed: bool,
    pub(crate) spent_commitment: Option<SpentRef>,
    pub(crate) spent_reveal: Option<SpentRef>,
    pub(crate) spent_partial: Option<SpentRef>,
}

impl ReservationRecord {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = FrameWriter::new(MAGIC_RESERVATION, &self.identity.reservation_id);
        writer.digest(&self.identity.request_lookup);
        writer.digest(&self.identity.session_id);
        writer.digest(&self.identity.participant_id);
        writer.u8(self.identity.purpose);
        writer.digest(&self.identity.template_hash);
        writer.digest(&self.identity.key_id);
        writer.digest(&self.identity.counterparty);
        writer.digest(&self.identity.context_binding_digest);
        writer.u64(self.identity.nonce_epoch);
        writer.u64(self.revision);
        writer.u8(self.state.to_byte());
        writer.optional_u64(self.retry_counter);
        writer.optional_digest(self.attempt_digest.as_ref());
        writer.optional_digest(self.stage_digest.as_ref());
        writer.bool(self.sealed);
        encode_spent(&mut writer, self.spent_commitment.as_ref());
        encode_spent(&mut writer, self.spent_reveal.as_ref());
        encode_spent(&mut writer, self.spent_partial.as_ref());
        Ok(writer.finish())
    }

    fn decode(bytes: &[u8], reservation_id: &[u8; 32]) -> Result<Self> {
        let mut reader = FrameReader::open(bytes, MAGIC_RESERVATION, reservation_id)?;
        let identity = ReservationIdentity {
            reservation_id: *reservation_id,
            request_lookup: reader.digest()?,
            session_id: reader.digest()?,
            participant_id: reader.digest()?,
            purpose: reader.u8()?,
            template_hash: reader.digest()?,
            key_id: reader.digest()?,
            counterparty: reader.digest()?,
            context_binding_digest: reader.digest()?,
            nonce_epoch: reader.u64()?,
        };
        let record = Self {
            identity,
            revision: reader.u64()?,
            state: StateCode::from_byte(reader.u8()?)?,
            retry_counter: reader.optional_u64()?,
            attempt_digest: reader.optional_digest()?,
            stage_digest: reader.optional_digest()?,
            sealed: reader.bool()?,
            spent_commitment: decode_spent(&mut reader)?,
            spent_reveal: decode_spent(&mut reader)?,
            spent_partial: decode_spent(&mut reader)?,
        };
        reader.finish()?;
        Ok(record)
    }

    /// Returns the spent reference of the requested kind.
    pub(crate) fn spent(&self, kind: u8) -> Option<&SpentRef> {
        match kind {
            1 => self.spent_commitment.as_ref(),
            2 => self.spent_reveal.as_ref(),
            3 => self.spent_partial.as_ref(),
            _ => None,
        }
    }
}

fn encode_spent(writer: &mut FrameWriter, value: Option<&SpentRef>) {
    match value {
        Some(reference) => {
            writer.bool(true);
            writer.digest(&reference.permit_id);
            writer.digest(&reference.outbound_digest);
        }
        None => {
            writer.bool(false);
            writer.digest(&[0u8; 32]);
            writer.digest(&[0u8; 32]);
        }
    }
}

fn decode_spent(reader: &mut FrameReader<'_>) -> Result<Option<SpentRef>> {
    let present = reader.bool()?;
    let permit_id = reader.digest()?;
    let outbound_digest = reader.digest()?;
    if !present {
        return Ok(None);
    }
    if permit_id == [0; 32] || outbound_digest == [0; 32] {
        return Err(VaultError::CorruptState);
    }
    Ok(Some(SpentRef {
        permit_id,
        outbound_digest,
    }))
}

/// Durable record of an exact public artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArtifactRecord {
    pub(crate) permit_id: [u8; 32],
    pub(crate) reservation_id: [u8; 32],
    pub(crate) request_lookup: [u8; 32],
    pub(crate) kind: u8,
    pub(crate) outbound_digest: [u8; 32],
    pub(crate) session_id: [u8; 32],
    pub(crate) participant_id: [u8; 32],
    pub(crate) purpose: u8,
    pub(crate) bound_digest: [u8; 32],
    pub(crate) nonce_epoch: u64,
    pub(crate) bytes: Vec<u8>,
}

impl ArtifactRecord {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = FrameWriter::new(MAGIC_ARTIFACT, &self.reservation_id);
        writer.digest(&self.permit_id);
        writer.digest(&self.request_lookup);
        writer.u8(self.kind);
        writer.digest(&self.outbound_digest);
        writer.digest(&self.session_id);
        writer.digest(&self.participant_id);
        writer.u8(self.purpose);
        writer.digest(&self.bound_digest);
        writer.u64(self.nonce_epoch);
        writer.blob(&self.bytes)?;
        Ok(writer.finish())
    }

    fn decode(bytes: &[u8], reservation_id: &[u8; 32]) -> Result<Self> {
        let mut reader = FrameReader::open(bytes, MAGIC_ARTIFACT, reservation_id)?;
        let record = Self {
            permit_id: reader.digest()?,
            reservation_id: *reservation_id,
            request_lookup: reader.digest()?,
            kind: reader.u8()?,
            outbound_digest: reader.digest()?,
            session_id: reader.digest()?,
            participant_id: reader.digest()?,
            purpose: reader.u8()?,
            bound_digest: reader.digest()?,
            nonce_epoch: reader.u64()?,
            bytes: reader.blob()?,
        };
        reader.finish()?;
        if record.permit_id == [0; 32] || record.outbound_digest == [0; 32] {
            return Err(VaultError::CorruptState);
        }
        Ok(record)
    }

    fn validate_content(&self) -> Result<()> {
        let kind = ExposureKindV1::try_from(self.kind).map_err(|_| VaultError::CorruptState)?;
        let digest =
            exposure_outbound_digest_v1(kind, &self.bytes).map_err(|_| VaultError::CorruptState)?;
        let purpose = PurposeV1::try_from(self.purpose).map_err(|_| VaultError::CorruptState)?;
        if digest.as_bytes() != &self.outbound_digest
            || !purpose.is_strict_v1_authorized()
            || [
                self.permit_id,
                self.reservation_id,
                self.request_lookup,
                self.session_id,
                self.participant_id,
                self.outbound_digest,
                self.bound_digest,
            ]
            .contains(&[0; 32])
            || self.nonce_epoch == 0
        {
            return Err(VaultError::CorruptState);
        }
        Ok(())
    }
}

type ArtifactKeyV1 = ([u8; 32], u8);
type ReservationHistoryV1 = BTreeMap<u64, ReservationRecord>;

struct SemanticSnapshotV1 {
    reservations: BTreeMap<[u8; 32], ReservationHistoryV1>,
    request_lookups: BTreeMap<[u8; 32], [u8; 32]>,
    custody: BTreeMap<[u8; 32], ([u8; 32], [u8; 32])>,
    abandoned: BTreeMap<[u8; 32], ([u8; 32], [u8; 32])>,
    session_tombstones: BTreeSet<[u8; 32]>,
    sealed: BTreeSet<[u8; 32]>,
    burned: BTreeSet<[u8; 32]>,
    persisted: BTreeMap<ArtifactKeyV1, ArtifactRecord>,
    authorized: BTreeMap<ArtifactKeyV1, ArtifactRecord>,
    spent: BTreeMap<[u8; 32], ArtifactRecord>,
    spent_index: BTreeMap<([u8; 32], u8), [u8; 32]>,
    reservation_anchors: BTreeMap<[u8; 32], u64>,
    key_budgets: BTreeMap<[u8; 32], u64>,
    counterparty_budgets: BTreeMap<[u8; 32], u64>,
    nonce_epoch: Option<u64>,
    revision_journal: BTreeMap<([u8; 32], u64), u16>,
    persisted_journal: BTreeSet<([u8; 32], u8, [u8; 32])>,
    authorized_journal: BTreeSet<([u8; 32], u8, [u8; 32])>,
    spent_journal: BTreeSet<[u8; 32]>,
}

impl SemanticSnapshotV1 {
    fn new() -> Self {
        Self {
            reservations: BTreeMap::new(),
            request_lookups: BTreeMap::new(),
            custody: BTreeMap::new(),
            abandoned: BTreeMap::new(),
            session_tombstones: BTreeSet::new(),
            sealed: BTreeSet::new(),
            burned: BTreeSet::new(),
            persisted: BTreeMap::new(),
            authorized: BTreeMap::new(),
            spent: BTreeMap::new(),
            spent_index: BTreeMap::new(),
            reservation_anchors: BTreeMap::new(),
            key_budgets: BTreeMap::new(),
            counterparty_budgets: BTreeMap::new(),
            nonce_epoch: None,
            revision_journal: BTreeMap::new(),
            persisted_journal: BTreeSet::new(),
            authorized_journal: BTreeSet::new(),
            spent_journal: BTreeSet::new(),
        }
    }
}

fn audit_semantic_snapshot(
    snapshot: &store::ProductionAuditSnapshotV1,
    limits: VaultLimits,
) -> Result<()> {
    let mut semantic = SemanticSnapshotV1::new();
    parse_opaque_records(snapshot, &mut semantic)?;
    parse_revision_records(snapshot, &mut semantic)?;
    validate_reservation_histories(&semantic)?;
    parse_journal_records(snapshot, &mut semantic)?;
    validate_semantic_cross_links(snapshot, &semantic, limits)
}

fn parse_opaque_records(
    snapshot: &store::ProductionAuditSnapshotV1,
    semantic: &mut SemanticSnapshotV1,
) -> Result<()> {
    for row in snapshot.opaque_records() {
        let namespace = row.namespace();
        let key = row.key();
        let value = row.value();
        if namespace == namespace::RESERVATION {
            let (reservation_id, revision) = parse_record_key(key)?;
            let record = ReservationRecord::decode(value, &reservation_id)?;
            validate_reservation_record(&record)?;
            if record.revision != revision
                || semantic
                    .reservations
                    .entry(reservation_id)
                    .or_default()
                    .insert(revision, record)
                    .is_some()
            {
                return Err(VaultError::CorruptState);
            }
        } else if namespace == namespace::REQUEST_LOOKUP {
            let lookup = exact_nonzero_digest(key)?;
            let reservation_id = exact_nonzero_digest(value)?;
            if semantic
                .request_lookups
                .insert(lookup, reservation_id)
                .is_some()
            {
                return Err(VaultError::CorruptState);
            }
        } else if namespace == namespace::LOOKUP_CUSTODY || namespace == namespace::LOOKUP_ABANDONED
        {
            let lookup = exact_nonzero_digest(key)?;
            let (session, digest) = crate::custody::decode_record(value)?;
            let target = if namespace == namespace::LOOKUP_CUSTODY {
                &mut semantic.custody
            } else {
                &mut semantic.abandoned
            };
            if target
                .insert(lookup, (*session.as_bytes(), digest))
                .is_some()
            {
                return Err(VaultError::CorruptState);
            }
        } else if namespace == namespace::SESSION_TOMBSTONE {
            let session_id = exact_nonzero_digest(key)?;
            if value != [1] || !semantic.session_tombstones.insert(session_id) {
                return Err(VaultError::CorruptState);
            }
        } else if namespace == namespace::SEALED_SECRET {
            let reservation_id = exact_nonzero_digest(key)?;
            if !semantic.sealed.insert(reservation_id) {
                return Err(VaultError::CorruptState);
            }
        } else if namespace == namespace::BURN_MARKER {
            let reservation_id = exact_nonzero_digest(key)?;
            if value != [1] || !semantic.burned.insert(reservation_id) {
                return Err(VaultError::CorruptState);
            }
        } else if namespace == namespace::PERSISTED_ARTIFACT
            || namespace == namespace::AUTHORIZED_ARTIFACT
        {
            let (reservation_id, kind) = parse_artifact_key(key)?;
            let record = ArtifactRecord::decode(value, &reservation_id)?;
            record.validate_content()?;
            if record.kind != kind {
                return Err(VaultError::CorruptState);
            }
            let target = if namespace == namespace::PERSISTED_ARTIFACT {
                &mut semantic.persisted
            } else {
                &mut semantic.authorized
            };
            if target.insert((reservation_id, kind), record).is_some() {
                return Err(VaultError::CorruptState);
            }
        } else if namespace == namespace::SPENT_ARTIFACT {
            let permit_id = exact_nonzero_digest(key)?;
            let reservation_id =
                FrameReader::readable_prefix(value).ok_or(VaultError::CorruptState)?;
            let record = ArtifactRecord::decode(value, &reservation_id)?;
            record.validate_content()?;
            if record.permit_id != permit_id || semantic.spent.insert(permit_id, record).is_some() {
                return Err(VaultError::CorruptState);
            }
        } else if namespace == namespace::SPENT_INDEX {
            let (lookup, kind) = parse_artifact_key(key)?;
            let permit_id = exact_nonzero_digest(value)?;
            if semantic
                .spent_index
                .insert((lookup, kind), permit_id)
                .is_some()
            {
                return Err(VaultError::CorruptState);
            }
        } else {
            return Err(VaultError::CorruptState);
        }
    }
    Ok(())
}

fn parse_revision_records(
    snapshot: &store::ProductionAuditSnapshotV1,
    semantic: &mut SemanticSnapshotV1,
) -> Result<()> {
    for row in snapshot.revisions() {
        let entity = row.entity();
        if entity.len() != 33 || row.revision() == 0 {
            return Err(VaultError::CorruptState);
        }
        let key = exact_digest(&entity[1..])?;
        let replaced = match entity[0] {
            b'r' if key != [0; 32] => semantic
                .reservation_anchors
                .insert(key, row.revision())
                .is_some(),
            b'k' if key != [0; 32] => semantic.key_budgets.insert(key, row.revision()).is_some(),
            b'c' if key != [0; 32] => semantic
                .counterparty_budgets
                .insert(key, row.revision())
                .is_some(),
            b'e' if key == [0; 32] => semantic.nonce_epoch.replace(row.revision()).is_some(),
            _ => return Err(VaultError::CorruptState),
        };
        if replaced {
            return Err(VaultError::CorruptState);
        }
    }
    Ok(())
}

fn parse_journal_records(
    snapshot: &store::ProductionAuditSnapshotV1,
    semantic: &mut SemanticSnapshotV1,
) -> Result<()> {
    for row in snapshot.journal() {
        let kind = row.kind();
        let payload = row.payload();
        match kind {
            JOURNAL_CLAIM
            | JOURNAL_DERIVATION_ATTEMPT
            | JOURNAL_SEAL
            | JOURNAL_OPEN
            | JOURNAL_STAGE_ATTEMPT
            | JOURNAL_TERMINAL => {
                insert_revision_journal(semantic, kind, payload)?;
            }
            JOURNAL_PERSIST | JOURNAL_AUTHORIZE => {
                if payload.len() == 40 {
                    insert_revision_journal(semantic, kind, payload)?;
                } else {
                    let reservation_id =
                        FrameReader::readable_prefix(payload).ok_or(VaultError::CorruptState)?;
                    let artifact = ArtifactRecord::decode(payload, &reservation_id)?;
                    artifact.validate_content()?;
                    let retained = if kind == JOURNAL_PERSIST {
                        semantic.persisted.get(&(reservation_id, artifact.kind))
                    } else {
                        semantic.authorized.get(&(reservation_id, artifact.kind))
                    }
                    .ok_or(VaultError::CorruptState)?;
                    if retained != &artifact {
                        return Err(VaultError::CorruptState);
                    }
                    let audit_key = (reservation_id, artifact.kind, artifact.permit_id);
                    let inserted = if kind == JOURNAL_PERSIST {
                        semantic.persisted_journal.insert(audit_key)
                    } else {
                        semantic.authorized_journal.insert(audit_key)
                    };
                    if !inserted {
                        return Err(VaultError::CorruptState);
                    }
                }
            }
            JOURNAL_SPEND => {
                if payload.len() == 40 {
                    insert_revision_journal(semantic, kind, payload)?;
                } else {
                    let permit_id = exact_nonzero_digest(payload)?;
                    if !semantic.spent.contains_key(&permit_id) {
                        return Err(VaultError::CorruptState);
                    }
                    if !semantic.spent_journal.insert(permit_id) {
                        return Err(VaultError::CorruptState);
                    }
                }
            }
            _ => return Err(VaultError::CorruptState),
        }
    }
    Ok(())
}

fn insert_revision_journal(
    semantic: &mut SemanticSnapshotV1,
    kind: u16,
    payload: &[u8],
) -> Result<()> {
    let (reservation_id, revision) = parse_record_key(payload)?;
    if !semantic
        .reservations
        .get(&reservation_id)
        .is_some_and(|history| history.contains_key(&revision))
        || semantic
            .revision_journal
            .insert((reservation_id, revision), kind)
            .is_some()
    {
        return Err(VaultError::CorruptState);
    }
    Ok(())
}

fn exact_digest(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| VaultError::CorruptState)
}

fn exact_nonzero_digest(bytes: &[u8]) -> Result<[u8; 32]> {
    let digest = exact_digest(bytes)?;
    if digest == [0; 32] {
        return Err(VaultError::CorruptState);
    }
    Ok(digest)
}

fn parse_record_key(bytes: &[u8]) -> Result<([u8; 32], u64)> {
    if bytes.len() != 40 {
        return Err(VaultError::CorruptState);
    }
    let reservation_id = exact_nonzero_digest(&bytes[..32])?;
    let revision = u64::from_le_bytes(
        bytes[32..]
            .try_into()
            .map_err(|_| VaultError::CorruptState)?,
    );
    if revision == 0 {
        return Err(VaultError::CorruptState);
    }
    Ok((reservation_id, revision))
}

fn parse_artifact_key(bytes: &[u8]) -> Result<([u8; 32], u8)> {
    if bytes.len() != 33 {
        return Err(VaultError::CorruptState);
    }
    let digest = exact_nonzero_digest(&bytes[..32])?;
    let kind = bytes[32];
    ExposureKindV1::try_from(kind).map_err(|_| VaultError::CorruptState)?;
    Ok((digest, kind))
}

fn validate_reservation_record(record: &ReservationRecord) -> Result<()> {
    let purpose =
        PurposeV1::try_from(record.identity.purpose).map_err(|_| VaultError::CorruptState)?;
    if !purpose.is_strict_v1_authorized()
        || [
            record.identity.reservation_id,
            record.identity.request_lookup,
            record.identity.session_id,
            record.identity.participant_id,
            record.identity.template_hash,
            record.identity.key_id,
            record.identity.counterparty,
            record.identity.context_binding_digest,
        ]
        .contains(&[0; 32])
        || record.identity.nonce_epoch == 0
        || record.revision == 0
        || record.retry_counter.is_some() != record.attempt_digest.is_some()
        || record.attempt_digest == Some([0; 32])
        || record.stage_digest == Some([0; 32])
        || (record.stage_digest.is_some() && record.attempt_digest.is_none())
        || (record.sealed && record.attempt_digest.is_none())
    {
        return Err(VaultError::CorruptState);
    }
    validate_record_state_shape(record)
}

fn validate_record_state_shape(record: &ReservationRecord) -> Result<()> {
    for spent in [
        record.spent_commitment.as_ref(),
        record.spent_reveal.as_ref(),
        record.spent_partial.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if spent.permit_id == [0; 32] || spent.outbound_digest == [0; 32] {
            return Err(VaultError::CorruptState);
        }
    }
    let valid = match record.state {
        StateCode::Reserved => {
            record.spent_commitment.is_none()
                && record.spent_reveal.is_none()
                && record.spent_partial.is_none()
        }
        StateCode::CommitmentAuthorized => {
            record.sealed
                && record.spent_commitment.is_some()
                && record.spent_reveal.is_none()
                && record.spent_partial.is_none()
        }
        StateCode::RevealAuthorized => {
            record.sealed
                && record.spent_commitment.is_some()
                && record.spent_reveal.is_some()
                && record.spent_partial.is_none()
        }
        StateCode::ConsumedPartialAuthorized => {
            record.sealed
                && record.spent_commitment.is_some()
                && record.spent_reveal.is_some()
                && record.spent_partial.is_some()
        }
        StateCode::AbortedBeforePublicMaterial => {
            !record.sealed
                && record.retry_counter.is_none()
                && record.attempt_digest.is_none()
                && record.stage_digest.is_none()
                && record.spent_commitment.is_none()
                && record.spent_reveal.is_none()
                && record.spent_partial.is_none()
        }
        StateCode::ConsumedOnAbort => {
            record.spent_partial.is_none()
                && (record.attempt_digest.is_some()
                    || record.sealed
                    || record.spent_commitment.is_some()
                    || record.spent_reveal.is_some())
        }
        StateCode::Burned => false,
    };
    if !valid {
        return Err(VaultError::CorruptState);
    }
    Ok(())
}

fn validate_reservation_histories(semantic: &SemanticSnapshotV1) -> Result<()> {
    if semantic.reservations.len() != semantic.reservation_anchors.len() {
        return Err(VaultError::CorruptState);
    }
    for (reservation_id, history) in &semantic.reservations {
        let anchor = semantic
            .reservation_anchors
            .get(reservation_id)
            .copied()
            .ok_or(VaultError::CorruptState)?;
        if usize::try_from(anchor).map_err(|_| VaultError::CorruptState)? != history.len() {
            return Err(VaultError::RollbackDetected);
        }
        let first = history.get(&1).ok_or(VaultError::CorruptState)?;
        if first.identity.reservation_id != *reservation_id
            || first.revision != 1
            || first.state != StateCode::Reserved
            || first.retry_counter.is_some()
            || first.attempt_digest.is_some()
            || first.stage_digest.is_some()
            || first.sealed
            || first.spent_commitment.is_some()
            || first.spent_reveal.is_some()
            || first.spent_partial.is_some()
        {
            return Err(VaultError::CorruptState);
        }
        let mut prior = first;
        for revision in 2..=anchor {
            let current = history.get(&revision).ok_or(VaultError::RollbackDetected)?;
            validate_reservation_transition(prior, current)?;
            prior = current;
        }
    }
    Ok(())
}

fn validate_reservation_transition(
    prior: &ReservationRecord,
    current: &ReservationRecord,
) -> Result<()> {
    if prior.state.is_terminal()
        || prior.identity != current.identity
        || current.revision != prior.revision + 1
        || !option_is_monotonic(prior.retry_counter, current.retry_counter)
        || !option_is_monotonic(prior.attempt_digest, current.attempt_digest)
        || (prior.sealed && !current.sealed)
        || !option_is_monotonic(
            prior.spent_commitment.as_ref(),
            current.spent_commitment.as_ref(),
        )
        || !option_is_monotonic(prior.spent_reveal.as_ref(), current.spent_reveal.as_ref())
        || !option_is_monotonic(prior.spent_partial.as_ref(), current.spent_partial.as_ref())
    {
        return Err(VaultError::CorruptState);
    }
    if prior.stage_digest != current.stage_digest {
        let valid_stage_change = match (prior.stage_digest, current.stage_digest) {
            (None, Some(_)) => matches!(
                prior.state,
                StateCode::CommitmentAuthorized | StateCode::RevealAuthorized
            ),
            (Some(_), Some(_)) => prior.state == StateCode::RevealAuthorized,
            _ => false,
        };
        if !valid_stage_change {
            return Err(VaultError::CorruptState);
        }
    }
    let valid_state = if current.state == prior.state {
        true
    } else {
        matches!(
            (prior.state, current.state),
            (StateCode::Reserved, StateCode::CommitmentAuthorized)
                | (StateCode::CommitmentAuthorized, StateCode::RevealAuthorized)
                | (
                    StateCode::RevealAuthorized,
                    StateCode::ConsumedPartialAuthorized
                )
                | (_, StateCode::AbortedBeforePublicMaterial)
                | (_, StateCode::ConsumedOnAbort)
        )
    };
    if !valid_state {
        return Err(VaultError::CorruptState);
    }
    validate_reservation_record(current)
}

fn option_is_monotonic<T: PartialEq>(prior: Option<T>, current: Option<T>) -> bool {
    match (prior, current) {
        (None, _) => true,
        (Some(left), Some(right)) => left == right,
        (Some(_), None) => false,
    }
}

fn validate_semantic_cross_links(
    snapshot: &store::ProductionAuditSnapshotV1,
    semantic: &SemanticSnapshotV1,
    _limits: VaultLimits,
) -> Result<()> {
    let mut seen_sessions = BTreeSet::new();
    let mut seen_epochs = BTreeSet::new();
    let mut key_counts: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut counterparty_counts: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut maximum_epoch = 0_u64;

    if semantic.request_lookups.len() != semantic.reservations.len() {
        return Err(VaultError::CorruptState);
    }
    for (reservation_id, history) in &semantic.reservations {
        let current = history
            .last_key_value()
            .map(|(_, record)| record)
            .ok_or(VaultError::CorruptState)?;
        if semantic
            .request_lookups
            .get(&current.identity.request_lookup)
            != Some(reservation_id)
            || semantic
                .custody
                .get(&current.identity.request_lookup)
                .is_some_and(|custody| {
                    custody
                        != &(
                            current.identity.session_id,
                            current.identity.context_binding_digest,
                        )
                })
            || semantic
                .abandoned
                .contains_key(&current.identity.request_lookup)
            || !semantic
                .session_tombstones
                .contains(&current.identity.session_id)
            || !seen_sessions.insert(current.identity.session_id)
            || !seen_epochs.insert(current.identity.nonce_epoch)
            || semantic.sealed.contains(reservation_id) != current.sealed
            || semantic.burned.contains(reservation_id) != current.state.is_terminal()
        {
            return Err(VaultError::CorruptState);
        }
        maximum_epoch = maximum_epoch.max(current.identity.nonce_epoch);
        increment_count(&mut key_counts, current.identity.key_id)?;
        increment_count(&mut counterparty_counts, current.identity.counterparty)?;
        validate_revision_journal(history, semantic)?;
    }
    if !semantic.reservations.is_empty()
        && semantic
            .nonce_epoch
            .map_or(true, |epoch| epoch < maximum_epoch)
    {
        return Err(VaultError::RollbackDetected);
    }
    for (key, count) in key_counts {
        if semantic.key_budgets.get(&key).copied().unwrap_or(0) < count {
            return Err(VaultError::RollbackDetected);
        }
    }
    for (counterparty, count) in counterparty_counts {
        if semantic
            .counterparty_budgets
            .get(&counterparty)
            .copied()
            .unwrap_or(0)
            < count
        {
            return Err(VaultError::RollbackDetected);
        }
    }
    for (lookup, abandoned) in &semantic.abandoned {
        if semantic.custody.get(lookup) != Some(abandoned)
            || semantic.request_lookups.contains_key(lookup)
        {
            return Err(VaultError::CorruptState);
        }
    }
    audit_sealed_rows(snapshot, semantic)?;
    validate_artifact_cross_links(semantic)
}

fn increment_count(counts: &mut BTreeMap<[u8; 32], u64>, key: [u8; 32]) -> Result<()> {
    let current = counts.get(&key).copied().unwrap_or(0);
    counts.insert(
        key,
        current.checked_add(1).ok_or(VaultError::CounterOverflow)?,
    );
    Ok(())
}

fn validate_revision_journal(
    history: &ReservationHistoryV1,
    semantic: &SemanticSnapshotV1,
) -> Result<()> {
    let first = history.get(&1).ok_or(VaultError::CorruptState)?;
    if semantic
        .revision_journal
        .get(&(first.identity.reservation_id, 1))
        != Some(&JOURNAL_CLAIM)
    {
        return Err(VaultError::CorruptState);
    }
    let anchor = u64::try_from(history.len()).map_err(|_| VaultError::CounterOverflow)?;
    for revision in 2..=anchor {
        let prior = history
            .get(&(revision - 1))
            .ok_or(VaultError::CorruptState)?;
        let current = history.get(&revision).ok_or(VaultError::CorruptState)?;
        let kind = semantic
            .revision_journal
            .get(&(current.identity.reservation_id, revision))
            .copied()
            .ok_or(VaultError::CorruptState)?;
        validate_revision_kind(prior, current, kind)?;
    }
    Ok(())
}

fn validate_revision_kind(
    prior: &ReservationRecord,
    current: &ReservationRecord,
    kind: u16,
) -> Result<()> {
    let attempt_changed = prior.retry_counter != current.retry_counter
        || prior.attempt_digest != current.attempt_digest;
    let sealed_changed = prior.sealed != current.sealed;
    let stage_changed = prior.stage_digest != current.stage_digest;
    let commitment_changed = prior.spent_commitment != current.spent_commitment;
    let reveal_changed = prior.spent_reveal != current.spent_reveal;
    let partial_changed = prior.spent_partial != current.spent_partial;
    let state_changed = prior.state != current.state;
    let spent_changed = commitment_changed || reveal_changed || partial_changed;
    let expected = if spent_changed {
        if !(state_changed
            && usize::from(commitment_changed)
                + usize::from(reveal_changed)
                + usize::from(partial_changed)
                == 1)
        {
            return Err(VaultError::CorruptState);
        }
        JOURNAL_SPEND
    } else if state_changed {
        if !current.state.is_terminal() {
            return Err(VaultError::CorruptState);
        }
        JOURNAL_TERMINAL
    } else if attempt_changed {
        JOURNAL_DERIVATION_ATTEMPT
    } else if sealed_changed {
        JOURNAL_SEAL
    } else if stage_changed {
        JOURNAL_STAGE_ATTEMPT
    } else {
        if !matches!(kind, JOURNAL_OPEN | JOURNAL_PERSIST | JOURNAL_AUTHORIZE) {
            return Err(VaultError::CorruptState);
        }
        return Ok(());
    };
    let change_count = usize::from(attempt_changed)
        + usize::from(sealed_changed)
        + usize::from(stage_changed)
        + usize::from(spent_changed)
        + usize::from(state_changed && !spent_changed);
    if kind != expected || change_count != 1 {
        return Err(VaultError::CorruptState);
    }
    Ok(())
}

fn audit_sealed_rows(
    snapshot: &store::ProductionAuditSnapshotV1,
    semantic: &SemanticSnapshotV1,
) -> Result<()> {
    for row in snapshot
        .opaque_records()
        .iter()
        .filter(|row| row.namespace() == namespace::SEALED_SECRET)
    {
        let reservation_id = exact_nonzero_digest(row.key())?;
        let current = semantic
            .reservations
            .get(&reservation_id)
            .and_then(BTreeMap::last_key_value)
            .map(|(_, record)| record)
            .ok_or(VaultError::CorruptState)?;
        let retry_counter = current.retry_counter.ok_or(VaultError::CorruptState)?;
        let purpose =
            PurposeV1::try_from(current.identity.purpose).map_err(|_| VaultError::CorruptState)?;
        let expected = NonceSecretPlaintextAuditBindingV1::new(
            reservation_id,
            current.identity.participant_id,
            current.identity.key_id,
            current.identity.session_id,
            purpose,
            current.identity.template_hash,
            retry_counter,
        )
        .map_err(|_| VaultError::CorruptState)?;
        let mut reader = FrameReader::open(row.value(), MAGIC_SEALED, &reservation_id)?;
        let plaintext = Zeroizing::new(reader.blob()?);
        reader.finish()?;
        audit_bound_nonce_secret_plaintext_v1(plaintext, &expected)
            .map_err(|_| VaultError::CorruptState)?;
    }
    Ok(())
}

fn validate_artifact_cross_links(semantic: &SemanticSnapshotV1) -> Result<()> {
    let mut permit_ids = BTreeSet::new();
    let mut persisted_counts: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let mut authorized_counts: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for ((reservation_id, kind), artifact) in &semantic.persisted {
        let current = current_reservation(semantic, reservation_id)?;
        validate_artifact_identity(current, artifact)?;
        validate_artifact_stage(current, *kind)?;
        if !permit_ids.insert(artifact.permit_id)
            || !semantic
                .persisted_journal
                .contains(&(*reservation_id, *kind, artifact.permit_id))
        {
            return Err(VaultError::CorruptState);
        }
        increment_usize(&mut persisted_counts, *reservation_id)?;
    }
    for ((reservation_id, kind), artifact) in &semantic.authorized {
        if semantic.persisted.get(&(*reservation_id, *kind)) != Some(artifact)
            || !semantic
                .authorized_journal
                .contains(&(*reservation_id, *kind, artifact.permit_id))
        {
            return Err(VaultError::CorruptState);
        }
        increment_usize(&mut authorized_counts, *reservation_id)?;
    }
    for (permit_id, artifact) in &semantic.spent {
        let key = (artifact.reservation_id, artifact.kind);
        let current = current_reservation(semantic, &artifact.reservation_id)?;
        let spent_ref = current
            .spent(artifact.kind)
            .ok_or(VaultError::CorruptState)?;
        if semantic.persisted.get(&key) != Some(artifact)
            || semantic.authorized.get(&key) != Some(artifact)
            || spent_ref.permit_id != *permit_id
            || spent_ref.outbound_digest != artifact.outbound_digest
            || semantic
                .spent_index
                .get(&(artifact.request_lookup, artifact.kind))
                != Some(permit_id)
            || !semantic.spent_journal.contains(permit_id)
        {
            return Err(VaultError::CorruptState);
        }
    }
    for ((lookup, kind), permit_id) in &semantic.spent_index {
        let artifact = semantic
            .spent
            .get(permit_id)
            .ok_or(VaultError::CorruptState)?;
        if artifact.request_lookup != *lookup || artifact.kind != *kind {
            return Err(VaultError::CorruptState);
        }
    }
    for (reservation_id, history) in &semantic.reservations {
        let current = history
            .last_key_value()
            .map(|(_, record)| record)
            .ok_or(VaultError::CorruptState)?;
        for (kind, reference) in [
            (1_u8, current.spent_commitment.as_ref()),
            (2_u8, current.spent_reveal.as_ref()),
            (3_u8, current.spent_partial.as_ref()),
        ] {
            if let Some(reference) = reference {
                let artifact = semantic
                    .spent
                    .get(&reference.permit_id)
                    .ok_or(VaultError::CorruptState)?;
                if artifact.reservation_id != *reservation_id
                    || artifact.kind != kind
                    || artifact.outbound_digest != reference.outbound_digest
                {
                    return Err(VaultError::CorruptState);
                }
            }
        }
        let persisted_revisions = semantic
            .revision_journal
            .iter()
            .filter(|((id, _), kind)| id == reservation_id && **kind == JOURNAL_PERSIST)
            .count();
        let authorized_revisions = semantic
            .revision_journal
            .iter()
            .filter(|((id, _), kind)| id == reservation_id && **kind == JOURNAL_AUTHORIZE)
            .count();
        let spent_revisions = semantic
            .revision_journal
            .iter()
            .filter(|((id, _), kind)| id == reservation_id && **kind == JOURNAL_SPEND)
            .count();
        if persisted_revisions != persisted_counts.get(reservation_id).copied().unwrap_or(0)
            || authorized_revisions != authorized_counts.get(reservation_id).copied().unwrap_or(0)
            || spent_revisions
                != [
                    current.spent_commitment.as_ref(),
                    current.spent_reveal.as_ref(),
                    current.spent_partial.as_ref(),
                ]
                .into_iter()
                .flatten()
                .count()
        {
            return Err(VaultError::CorruptState);
        }
    }
    Ok(())
}

fn current_reservation<'a>(
    semantic: &'a SemanticSnapshotV1,
    reservation_id: &[u8; 32],
) -> Result<&'a ReservationRecord> {
    semantic
        .reservations
        .get(reservation_id)
        .and_then(BTreeMap::last_key_value)
        .map(|(_, record)| record)
        .ok_or(VaultError::CorruptState)
}

fn validate_artifact_identity(
    reservation: &ReservationRecord,
    artifact: &ArtifactRecord,
) -> Result<()> {
    if artifact.reservation_id != reservation.identity.reservation_id
        || artifact.request_lookup != reservation.identity.request_lookup
        || artifact.session_id != reservation.identity.session_id
        || artifact.participant_id != reservation.identity.participant_id
        || artifact.purpose != reservation.identity.purpose
        || artifact.bound_digest != reservation.identity.context_binding_digest
        || artifact.nonce_epoch != reservation.identity.nonce_epoch
    {
        return Err(VaultError::CorruptState);
    }
    Ok(())
}

fn validate_artifact_stage(reservation: &ReservationRecord, kind: u8) -> Result<()> {
    let valid = match ExposureKindV1::try_from(kind).map_err(|_| VaultError::CorruptState)? {
        ExposureKindV1::NonceCommitment => reservation.sealed,
        ExposureKindV1::NonceReveal => reservation.spent_commitment.is_some(),
        ExposureKindV1::PartialSignature => reservation.spent_reveal.is_some(),
    };
    if !valid {
        return Err(VaultError::CorruptState);
    }
    Ok(())
}

fn increment_usize(counts: &mut BTreeMap<[u8; 32], usize>, key: [u8; 32]) -> Result<()> {
    let current = counts.get(&key).copied().unwrap_or(0);
    counts.insert(
        key,
        current.checked_add(1).ok_or(VaultError::CounterOverflow)?,
    );
    Ok(())
}

/// Durable caps per signing key and per counterparty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultLimits {
    /// Reservation cap over the lifetime of a key.
    pub per_key: u64,
    /// Reservation cap per counterparty bucket.
    pub per_counterparty: u64,
}

impl Default for VaultLimits {
    fn default() -> Self {
        // With no cap configured, the counters remain durable and monotonic:
        // the budget is always charged, it just is not limited by policy.
        Self {
            per_key: u64::MAX,
            per_counterparty: u64::MAX,
        }
    }
}

/// Scope of the budget that blocked a reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetScopeLocal {
    /// Key lifetime cap.
    Key,
    /// Per-counterparty cap.
    Counterparty,
}

/// Durable core on top of the neutral `store`.
pub struct DurableVaultCore {
    store: store::Store,
    limits: VaultLimits,
    quarantined: bool,
    production_audit: bool,
}

impl core::fmt::Debug for DurableVaultCore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableVaultCore([redacted])")
    }
}

fn revision_entity(prefix: u8, key: &[u8; 32]) -> Vec<u8> {
    let mut entity = Vec::with_capacity(33);
    entity.push(prefix);
    entity.extend_from_slice(key);
    entity
}

fn record_key(reservation_id: &[u8; 32], revision: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(reservation_id);
    key.extend_from_slice(&revision.to_le_bytes());
    key
}

fn artifact_key(reservation_id: &[u8; 32], kind: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.extend_from_slice(reservation_id);
    key.push(kind);
    key
}

fn stage_index_key(request_lookup: &[u8; 32], kind: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.extend_from_slice(request_lookup);
    key.push(kind);
    key
}

impl DurableVaultCore {
    /// Opens the core on top of an already-durable `store`.
    pub fn new(store: store::Store) -> Self {
        Self {
            store,
            limits: VaultLimits::default(),
            quarantined: false,
            production_audit: false,
        }
    }

    /// Opens the core with configured budget caps.
    pub fn with_limits(store: store::Store, limits: VaultLimits) -> Self {
        Self {
            store,
            limits,
            quarantined: false,
            production_audit: false,
        }
    }

    /// Opens a strict production core only after a complete bounded semantic audit.
    pub fn open_production(store: store::Store, limits: VaultLimits) -> Result<Self> {
        let mut core = Self {
            store,
            limits,
            quarantined: false,
            production_audit: true,
        };
        core.audit_production_state()?;
        Ok(core)
    }

    /// Re-audit every retained production row before a public authority boundary.
    pub(crate) fn audit_if_production(&mut self) -> Result<()> {
        if self.production_audit {
            self.audit_production_state()?;
        }
        Ok(())
    }

    fn audit_production_state(&mut self) -> Result<()> {
        let limits = store::ProductionAuditLimitsV1::new(
            PRODUCTION_AUDIT_MAX_ROWS,
            PRODUCTION_AUDIT_MAX_TOTAL_BYTES,
            PRODUCTION_AUDIT_MAX_RECORD_BYTES,
        )?;
        let snapshot = self.store.production_audit_snapshot(limits)?;
        let outcome = audit_semantic_snapshot(&snapshot, self.limits);
        self.guard(outcome)
    }

    /// Reports whether adaptor operations are blocked pending reconciliation.
    pub fn is_quarantined(&self) -> bool {
        self.quarantined
    }

    /// Marks irreversible quarantine for this in-memory instance.
    ///
    /// Every detection of rollback, divergence or corruption goes through
    /// here: the vault never resumes operating on its own after seeing
    /// incoherent state.
    pub(crate) fn quarantine(&mut self) {
        self.quarantined = true;
    }

    fn guard<T>(&mut self, outcome: Result<T>) -> Result<T> {
        if matches!(
            outcome,
            Err(VaultError::CorruptState)
                | Err(VaultError::RollbackDetected)
                | Err(VaultError::UnsupportedVersion)
        ) {
            self.quarantine();
        }
        outcome
    }

    /// Permanently registers a never-before-seen session identifier.
    pub(crate) fn claim_session_id(&mut self, session_id: &[u8; 32]) -> Result<()> {
        let mut registry = crate::DurableSessionIdRegistry::new(&mut self.store);
        if registry.register_unique_session_id(session_id)? {
            Ok(())
        } else {
            Err(VaultError::SessionIdReused)
        }
    }

    /// Charges a durable monotonic counter and returns the new value.
    fn charge(&mut self, prefix: u8, key: &[u8; 32]) -> Result<u64> {
        let entity = revision_entity(prefix, key);
        let current = self.store.revision(&entity)?;
        Ok(self.store.compare_and_swap_revision(&entity, current)?)
    }

    /// Returns the next nonce epoch, strictly monotonic and nonzero.
    pub(crate) fn next_nonce_epoch(&mut self) -> Result<u64> {
        self.charge(b'e', &[0u8; 32])
    }

    /// Charges the applicable budgets before any secret generation.
    pub(crate) fn charge_budgets(
        &mut self,
        key_id: &[u8; 32],
        counterparty: &[u8; 32],
    ) -> core::result::Result<(), (VaultError, Option<BudgetScopeLocal>)> {
        let used_key = self.charge(b'k', key_id).map_err(|error| (error, None))?;
        if used_key > self.limits.per_key {
            return Err((VaultError::BudgetExhausted, Some(BudgetScopeLocal::Key)));
        }
        let used_counterparty = self
            .charge(b'c', counterparty)
            .map_err(|error| (error, None))?;
        if used_counterparty > self.limits.per_counterparty {
            return Err((
                VaultError::BudgetExhausted,
                Some(BudgetScopeLocal::Counterparty),
            ));
        }
        Ok(())
    }

    /// Writes the first revision of a reservation and indexes its public lookup.
    pub(crate) fn insert_reservation(
        &mut self,
        identity: ReservationIdentity,
    ) -> Result<ReservationRecord> {
        let entity = revision_entity(b'r', &identity.reservation_id);
        if self.store.revision(&entity)? != 0 {
            return Err(VaultError::IdempotencyConflict);
        }
        if self
            .store
            .opaque(namespace::REQUEST_LOOKUP, &identity.request_lookup)?
            .is_some()
        {
            // The same public lookup can never name two reservations.
            return Err(VaultError::IdempotencyConflict);
        }
        let record = ReservationRecord {
            identity,
            revision: 1,
            state: StateCode::Reserved,
            retry_counter: None,
            attempt_digest: None,
            stage_digest: None,
            sealed: false,
            spent_commitment: None,
            spent_reveal: None,
            spent_partial: None,
        };
        let encoded = record.encode()?;
        self.store.put_opaque(
            namespace::RESERVATION,
            &record_key(&record.identity.reservation_id, 1),
            &encoded,
        )?;
        self.store.put_opaque(
            namespace::REQUEST_LOOKUP,
            &record.identity.request_lookup,
            &record.identity.reservation_id,
        )?;
        self.store.compare_and_swap_revision(&entity, 0)?;
        self.store.append_journal(
            JOURNAL_CLAIM,
            &record_key(&record.identity.reservation_id, 1),
        )?;
        Ok(record)
    }

    /// Loads the authenticated current revision of a reservation.
    pub(crate) fn load(&mut self, reservation_id: &[u8; 32]) -> Result<ReservationRecord> {
        let outcome = self.load_inner(reservation_id);
        self.guard(outcome)
    }

    fn load_inner(&self, reservation_id: &[u8; 32]) -> Result<ReservationRecord> {
        let entity = revision_entity(b'r', reservation_id);
        let revision = self.store.revision(&entity)?;
        if revision == 0 {
            return Err(VaultError::ReservationNotFound);
        }
        // A record ahead of the anchor means an incomplete transition or an
        // anchor rollback. In both cases the state is ambiguous: fail closed.
        let ahead = revision.checked_add(1).ok_or(VaultError::CounterOverflow)?;
        if self
            .store
            .opaque(namespace::RESERVATION, &record_key(reservation_id, ahead))?
            .is_some()
        {
            return Err(VaultError::RollbackDetected);
        }
        let bytes = self
            .store
            .opaque(
                namespace::RESERVATION,
                &record_key(reservation_id, revision),
            )?
            .ok_or(VaultError::CorruptState)?;
        let record = ReservationRecord::decode(&bytes, reservation_id)?;
        if record.revision != revision {
            return Err(VaultError::CorruptState);
        }
        Ok(record)
    }

    /// Resolves the public resume lookup.
    pub(crate) fn load_by_lookup(
        &mut self,
        request_lookup: &[u8; 32],
    ) -> Result<Option<ReservationRecord>> {
        let Some(raw) = self
            .store
            .opaque(namespace::REQUEST_LOOKUP, request_lookup)?
        else {
            return Ok(None);
        };
        let reservation_id: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            self.quarantine();
            VaultError::CorruptState
        })?;
        self.load(&reservation_id).map(Some)
    }

    /// Writes the next revision and only then advances the monotonic anchor.
    ///
    /// Deliberate ordering: the durable content never lags behind the anchor,
    /// so a successful CAS means everything is already on disk.
    pub(crate) fn commit(
        &mut self,
        record: &mut ReservationRecord,
        journal_kind: u16,
    ) -> Result<()> {
        let outcome = self.commit_inner(record, journal_kind);
        self.guard(outcome)
    }

    fn commit_inner(&mut self, record: &mut ReservationRecord, journal_kind: u16) -> Result<()> {
        let entity = revision_entity(b'r', &record.identity.reservation_id);
        let current = record.revision;
        let next = current.checked_add(1).ok_or(VaultError::CounterOverflow)?;
        let mut candidate = record.clone();
        candidate.revision = next;
        let encoded = candidate.encode()?;
        self.store.put_opaque(
            namespace::RESERVATION,
            &record_key(&record.identity.reservation_id, next),
            &encoded,
        )?;
        self.store.compare_and_swap_revision(&entity, current)?;
        self.store.append_journal(
            journal_kind,
            &record_key(&record.identity.reservation_id, next),
        )?;
        *record = candidate;
        Ok(())
    }

    /// Seals the secret record and re-reads it before declaring success.
    pub(crate) fn seal_secret(
        &mut self,
        reservation_id: &[u8; 32],
        plaintext: &Zeroizing<Vec<u8>>,
    ) -> Result<()> {
        let mut writer = FrameWriter::new(MAGIC_SEALED, reservation_id);
        writer.blob(plaintext.as_slice())?;
        let encoded = writer.finish();
        self.store
            .put_opaque(namespace::SEALED_SECRET, reservation_id, &encoded)?;
        // Mandatory re-read: "sealed" only exists after coming back from disk.
        let reread = self
            .store
            .opaque(namespace::SEALED_SECRET, reservation_id)?
            .ok_or(VaultError::StorageUnavailable)?;
        if reread != encoded {
            self.quarantine();
            return Err(VaultError::CorruptState);
        }
        let verified = self.open_secret(reservation_id)?;
        if verified.as_slice() != plaintext.as_slice() {
            self.quarantine();
            return Err(VaultError::CorruptState);
        }
        Ok(())
    }

    /// Opens the sealed record, refusing burned reservations.
    pub(crate) fn open_secret(&mut self, reservation_id: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        if self
            .store
            .opaque(namespace::BURN_MARKER, reservation_id)?
            .is_some()
        {
            return Err(VaultError::InvalidTransition);
        }
        let bytes = self
            .store
            .opaque(namespace::SEALED_SECRET, reservation_id)?
            .ok_or(VaultError::ReservationNotFound)?;
        let outcome = (|| {
            let mut reader = FrameReader::open(&bytes, MAGIC_SEALED, reservation_id)?;
            let plaintext = Zeroizing::new(reader.blob()?);
            reader.finish()?;
            Ok(plaintext)
        })();
        self.guard(outcome)
    }

    /// Marks the reservation as burned for all future access to the secret.
    pub(crate) fn burn_secret(&mut self, reservation_id: &[u8; 32]) -> Result<()> {
        self.store
            .put_opaque(namespace::BURN_MARKER, reservation_id, &[1u8])?;
        Ok(())
    }

    /// Persists the computed artifact before any authorization.
    pub(crate) fn put_persisted_artifact(&mut self, record: &ArtifactRecord) -> Result<()> {
        let encoded = record.encode()?;
        self.store.put_opaque(
            namespace::PERSISTED_ARTIFACT,
            &artifact_key(&record.reservation_id, record.kind),
            &encoded,
        )?;
        self.store.append_journal(JOURNAL_PERSIST, &encoded)?;
        Ok(())
    }

    /// Re-reads the persisted artifact of an exact kind.
    pub(crate) fn persisted_artifact(
        &mut self,
        reservation_id: &[u8; 32],
        kind: u8,
    ) -> Result<ArtifactRecord> {
        let bytes = self
            .store
            .opaque(
                namespace::PERSISTED_ARTIFACT,
                &artifact_key(reservation_id, kind),
            )?
            .ok_or(VaultError::ReservationNotFound)?;
        let outcome = ArtifactRecord::decode(&bytes, reservation_id);
        let record = self.guard(outcome)?;
        if record.kind != kind {
            self.quarantine();
            return Err(VaultError::CorruptState);
        }
        Ok(record)
    }

    /// Durably marks the authorization of the exact already-persisted artifact.
    pub(crate) fn authorize_artifact(&mut self, record: &ArtifactRecord) -> Result<()> {
        let encoded = record.encode()?;
        self.store.put_opaque(
            namespace::AUTHORIZED_ARTIFACT,
            &artifact_key(&record.reservation_id, record.kind),
            &encoded,
        )?;
        self.store.append_journal(JOURNAL_AUTHORIZE, &encoded)?;
        Ok(())
    }

    /// Re-reads the authorized artifact, refusing what was never authorized.
    pub(crate) fn authorized_artifact(
        &mut self,
        reservation_id: &[u8; 32],
        kind: u8,
    ) -> Result<ArtifactRecord> {
        let bytes = self
            .store
            .opaque(
                namespace::AUTHORIZED_ARTIFACT,
                &artifact_key(reservation_id, kind),
            )?
            .ok_or(VaultError::InvalidTransition)?;
        let outcome = ArtifactRecord::decode(&bytes, reservation_id);
        self.guard(outcome)
    }

    /// Spends the permit **durably** and only then returns the re-read record.
    ///
    /// No artifact byte leaves here before the spent record is on disk,
    /// indexed and successfully re-read.
    pub(crate) fn spend_artifact(&mut self, record: &ArtifactRecord) -> Result<ArtifactRecord> {
        let encoded = record.encode()?;
        self.store
            .put_opaque(namespace::SPENT_ARTIFACT, &record.permit_id, &encoded)?;
        self.store.put_opaque(
            namespace::SPENT_INDEX,
            &stage_index_key(&record.request_lookup, record.kind),
            &record.permit_id,
        )?;
        self.store
            .append_journal(JOURNAL_SPEND, &record.permit_id)?;
        self.spent_artifact(&record.permit_id)
    }

    /// Re-reads the exact spent artifact by the permit's public lookup.
    pub(crate) fn spent_artifact(&mut self, permit_id: &[u8; 32]) -> Result<ArtifactRecord> {
        let bytes = self
            .store
            .opaque(namespace::SPENT_ARTIFACT, permit_id)?
            .ok_or(VaultError::ReservationNotFound)?;
        let reservation_id = FrameReader::readable_prefix(&bytes).ok_or_else(|| {
            self.quarantine();
            VaultError::CorruptState
        })?;
        let outcome = ArtifactRecord::decode(&bytes, &reservation_id);
        let record = self.guard(outcome)?;
        if &record.permit_id != permit_id {
            self.quarantine();
            return Err(VaultError::CorruptState);
        }
        Ok(record)
    }

    /// Resolves a stage's spent permit from the request lookup.
    pub(crate) fn spent_permit_for_stage(
        &mut self,
        request_lookup: &[u8; 32],
        kind: u8,
    ) -> Result<[u8; 32]> {
        let raw = self
            .store
            .opaque(
                namespace::SPENT_INDEX,
                &stage_index_key(request_lookup, kind),
            )?
            .ok_or(VaultError::ReservationNotFound)?;
        raw.as_slice().try_into().map_err(|_| {
            self.quarantine();
            VaultError::CorruptState
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production_store(seed: u8) -> (tempfile::TempDir, store::Store) {
        let dir = tempfile::tempdir().expect("production tempdir");
        // The strict authority refuses a parent that is not owner-only, and a
        // fresh tempdir inherits the process umask (0o755 under the usual
        // 022). Pin it, the same way store's own f2_schema fixtures and
        // dom-wallet's owner_only_tempdir do.
        std::fs::set_permissions(
            dir.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .expect("owner-only production tempdir");
        let binding =
            store::ProductionStoreBindingV1::new([seed; 32]).expect("nonzero production binding");
        let store = store::Store::create_production(&dir.path().join("vault.db"), binding)
            .expect("strict production store");
        (dir, store)
    }

    fn complete_reserved_production_store(seed: u8) -> (tempfile::TempDir, store::Store) {
        let (dir, store) = production_store(seed);
        let mut core = DurableVaultCore::new(store);
        let identity = identity(1);
        core.claim_session_id(&identity.session_id)
            .expect("session tombstone");
        core.charge_budgets(&identity.key_id, &identity.counterparty)
            .expect("budget counters");
        assert_eq!(core.next_nonce_epoch().expect("nonce epoch"), 1);
        core.insert_reservation(identity)
            .expect("complete reservation");
        (dir, core.store)
    }

    fn assert_production_semantic_rejection(store: store::Store) {
        assert!(matches!(
            DurableVaultCore::open_production(store, VaultLimits::default()),
            Err(VaultError::CorruptState | VaultError::RollbackDetected)
        ));
    }

    fn core() -> (tempfile::TempDir, DurableVaultCore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store::Store::open(&dir.path().join("vault.db")).expect("open");
        (dir, DurableVaultCore::new(store))
    }

    pub(crate) fn identity(seed: u8) -> ReservationIdentity {
        ReservationIdentity {
            reservation_id: [seed; 32],
            request_lookup: [seed.wrapping_add(1); 32],
            session_id: [seed.wrapping_add(2); 32],
            participant_id: [seed.wrapping_add(3); 32],
            purpose: 1,
            template_hash: [seed.wrapping_add(4); 32],
            key_id: [seed.wrapping_add(5); 32],
            counterparty: [seed.wrapping_add(6); 32],
            context_binding_digest: [seed.wrapping_add(7); 32],
            nonce_epoch: 1,
        }
    }

    #[test]
    fn reservation_records_roundtrip_through_the_frame() {
        let record = ReservationRecord {
            identity: identity(1),
            revision: 4,
            state: StateCode::CommitmentAuthorized,
            retry_counter: Some(9),
            attempt_digest: Some([2; 32]),
            stage_digest: None,
            sealed: true,
            spent_commitment: Some(SpentRef {
                permit_id: [3; 32],
                outbound_digest: [4; 32],
            }),
            spent_reveal: None,
            spent_partial: None,
        };
        let encoded = record.encode().expect("encode");
        let decoded = ReservationRecord::decode(&encoded, &[1; 32]).expect("decode");
        assert_eq!(decoded, record);
    }

    #[test]
    fn production_audit_accepts_only_empty_or_complete_semantic_state() {
        let (_empty_dir, empty) = production_store(0xa1);
        assert!(DurableVaultCore::open_production(empty, VaultLimits::default()).is_ok());

        let (_reserved_dir, reserved) = complete_reserved_production_store(0xa2);
        assert!(DurableVaultCore::open_production(reserved, VaultLimits::default()).is_ok());
    }

    #[test]
    fn production_audit_rejects_unknown_namespace_revision_and_journal_registries() {
        let (_namespace_dir, mut namespace_store) = production_store(0xb1);
        namespace_store
            .put_opaque(b"foreign/namespace", &[1], &[2])
            .expect("plant unknown namespace");
        assert_production_semantic_rejection(namespace_store);

        let (_revision_dir, mut revision_store) = production_store(0xb2);
        revision_store
            .compare_and_swap_revision(b"foreign-revision", 0)
            .expect("plant unknown revision");
        assert_production_semantic_rejection(revision_store);

        let (_journal_dir, mut journal_store) = production_store(0xb3);
        journal_store
            .append_journal(u16::MAX, b"foreign-journal")
            .expect("plant unknown journal kind");
        assert_production_semantic_rejection(journal_store);
    }

    #[test]
    fn production_audit_rejects_malformed_rows_and_orphan_indices() {
        let (_record_dir, mut record_store) = production_store(0xc1);
        record_store
            .put_opaque(
                namespace::RESERVATION,
                &record_key(&[1; 32], 1),
                b"not-a-framed-reservation",
            )
            .expect("plant malformed reservation");
        assert_production_semantic_rejection(record_store);

        let (_lookup_dir, mut lookup_store) = production_store(0xc2);
        lookup_store
            .put_opaque(namespace::REQUEST_LOOKUP, &[1; 32], &[2; 32])
            .expect("plant orphan lookup");
        assert_production_semantic_rejection(lookup_store);

        let (_sealed_dir, mut sealed_store) = complete_reserved_production_store(0xc3);
        sealed_store
            .put_opaque(namespace::SEALED_SECRET, &[1; 32], b"foreign-sealed-row")
            .expect("plant incoherent sealed row");
        assert_production_semantic_rejection(sealed_store);

        let (_artifact_dir, mut artifact_store) = complete_reserved_production_store(0xc4);
        let persisted = artifact(2);
        artifact_store
            .put_opaque(
                namespace::PERSISTED_ARTIFACT,
                &artifact_key(&persisted.reservation_id, persisted.kind),
                &persisted.encode().expect("artifact frame"),
            )
            .expect("plant incoherent artifact");
        assert_production_semantic_rejection(artifact_store);

        let (_spent_dir, mut spent_store) = complete_reserved_production_store(0xc5);
        let spent = artifact(3);
        spent_store
            .put_opaque(
                namespace::SPENT_ARTIFACT,
                &spent.permit_id,
                &spent.encode().expect("spent frame"),
            )
            .expect("plant incoherent spent row");
        assert_production_semantic_rejection(spent_store);
    }

    #[test]
    fn production_audit_rejects_revision_gaps_and_budget_or_epoch_rollback() {
        let (_gap_dir, gap_store) = complete_reserved_production_store(0xd1);
        let mut gap_core = DurableVaultCore::new(gap_store);
        let mut third = gap_core.load(&[1; 32]).expect("current reservation");
        third.revision = 3;
        gap_core
            .store
            .put_opaque(
                namespace::RESERVATION,
                &record_key(&[1; 32], 3),
                &third.encode().expect("third revision"),
            )
            .expect("plant revision ahead of anchor");
        gap_core
            .store
            .compare_and_swap_revision(&revision_entity(b'r', &[1; 32]), 1)
            .expect("advance anchor across a gap");
        assert_production_semantic_rejection(gap_core.store);

        let (_budget_dir, budget_store) = complete_reserved_production_store(0xd2);
        let mut budget_core = DurableVaultCore::new(budget_store);
        let first = identity(1);
        let mut second = identity(20);
        second.key_id = first.key_id;
        second.counterparty = first.counterparty;
        budget_core
            .claim_session_id(&second.session_id)
            .expect("second session");
        second.nonce_epoch = budget_core.next_nonce_epoch().expect("second epoch");
        budget_core
            .insert_reservation(second)
            .expect("reservation without matching budget charge");
        assert_production_semantic_rejection(budget_core.store);

        let (_epoch_dir, epoch_store) = complete_reserved_production_store(0xd3);
        let mut epoch_core = DurableVaultCore::new(epoch_store);
        let mut second = identity(30);
        second.nonce_epoch = 2;
        epoch_core
            .claim_session_id(&second.session_id)
            .expect("second session");
        epoch_core
            .charge_budgets(&second.key_id, &second.counterparty)
            .expect("second budgets");
        epoch_core
            .insert_reservation(second)
            .expect("reservation ahead of retained epoch");
        assert_production_semantic_rejection(epoch_core.store);
    }

    #[test]
    fn production_audit_rejects_cross_reservation_session_transplant() {
        let (_dir, store) = complete_reserved_production_store(0xe1);
        let mut core = DurableVaultCore::new(store);
        let first = identity(1);
        let mut second = identity(40);
        second.session_id = first.session_id;
        core.charge_budgets(&second.key_id, &second.counterparty)
            .expect("second budgets");
        second.nonce_epoch = core.next_nonce_epoch().expect("second epoch");
        core.insert_reservation(second)
            .expect("plant duplicate retained session");
        assert_production_semantic_rejection(core.store);
    }

    #[test]
    fn a_second_claim_of_the_same_identity_fails() {
        let (_dir, mut core) = core();
        core.insert_reservation(identity(1)).expect("first claim");
        let repeated = core.insert_reservation(identity(1));
        assert!(
            matches!(repeated, Err(VaultError::IdempotencyConflict)),
            "claiming the same reservation twice must fail closed"
        );
    }

    #[test]
    fn a_second_claim_of_the_same_request_lookup_fails() {
        let (_dir, mut core) = core();
        core.insert_reservation(identity(1)).expect("first claim");
        let mut colliding = identity(50);
        colliding.request_lookup = identity(1).request_lookup;
        assert!(matches!(
            core.insert_reservation(colliding),
            Err(VaultError::IdempotencyConflict)
        ));
    }

    #[test]
    fn reservations_survive_reopening_the_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        {
            let store = store::Store::open(&path).expect("open");
            let mut core = DurableVaultCore::new(store);
            let mut record = core.insert_reservation(identity(1)).expect("claim");
            record.retry_counter = Some(7);
            record.sealed = true;
            core.commit(&mut record, JOURNAL_DERIVATION_ATTEMPT)
                .expect("commit");
        }
        let store = store::Store::open(&path).expect("reopen");
        let mut core = DurableVaultCore::new(store);
        let record = core.load(&[1; 32]).expect("durable after restart");
        assert_eq!(record.revision, 2);
        assert_eq!(record.retry_counter, Some(7));
        assert!(record.sealed);
    }

    #[test]
    fn a_record_ahead_of_the_anchor_is_a_fail_closed_rollback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        let mut store = store::Store::open(&path).expect("open");
        let mut core = DurableVaultCore::new(store);
        let mut record = core.insert_reservation(identity(1)).expect("claim");
        core.commit(&mut record, JOURNAL_SEAL).expect("commit");
        drop(core);

        // Simulates an anchor rollback: the content remains, the revision goes back.
        store = store::Store::open(&path).expect("reopen");
        let mut core = DurableVaultCore::new(store);
        let forged = ReservationRecord {
            revision: 3,
            ..record.clone()
        };
        core.store
            .put_opaque(
                namespace::RESERVATION,
                &record_key(&[1; 32], 3),
                &forged.encode().expect("encode"),
            )
            .expect("plant");
        assert!(matches!(
            core.load(&[1; 32]),
            Err(VaultError::RollbackDetected)
        ));
        assert!(core.is_quarantined(), "a rollback must trigger quarantine");
    }

    #[test]
    fn a_corrupt_record_fails_closed_and_quarantines() {
        let (_dir, mut core) = core();
        let record = core.insert_reservation(identity(1)).expect("claim");
        let mut bytes = core
            .store
            .opaque(
                namespace::RESERVATION,
                &record_key(&record.identity.reservation_id, 1),
            )
            .expect("read")
            .expect("present");
        // Corrupts the record of the next revision and advances the anchor to
        // it, exactly what a torn write would leave behind.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        core.store
            .put_opaque(
                namespace::RESERVATION,
                &record_key(&record.identity.reservation_id, 2),
                &bytes,
            )
            .expect("plant");
        core.store
            .compare_and_swap_revision(&revision_entity(b'r', &record.identity.reservation_id), 1)
            .expect("advance anchor");
        assert!(matches!(
            core.load(&record.identity.reservation_id),
            Err(VaultError::CorruptState)
        ));
        assert!(
            core.is_quarantined(),
            "corruption must quarantine the vault, never be ignored"
        );
    }

    #[test]
    fn an_anchor_without_its_record_fails_closed() {
        let (_dir, mut core) = core();
        let record = core.insert_reservation(identity(1)).expect("claim");
        core.store
            .compare_and_swap_revision(&revision_entity(b'r', &record.identity.reservation_id), 1)
            .expect("advance anchor past the last record");
        assert!(matches!(
            core.load(&record.identity.reservation_id),
            Err(VaultError::CorruptState)
        ));
    }

    #[test]
    fn sealing_verifies_the_reread_and_burning_closes_the_secret() {
        let (_dir, mut core) = core();
        core.insert_reservation(identity(1)).expect("claim");
        let plaintext = Zeroizing::new(vec![9u8; 400]);
        core.seal_secret(&[1; 32], &plaintext).expect("seal");
        let opened = core.open_secret(&[1; 32]).expect("open");
        assert_eq!(opened.as_slice(), plaintext.as_slice());
        core.burn_secret(&[1; 32]).expect("burn");
        assert!(matches!(
            core.open_secret(&[1; 32]),
            Err(VaultError::InvalidTransition)
        ));
    }

    fn artifact(seed: u8) -> ArtifactRecord {
        ArtifactRecord {
            permit_id: [seed.wrapping_add(80); 32],
            reservation_id: [1; 32],
            request_lookup: identity(1).request_lookup,
            kind: 1,
            outbound_digest: [seed.wrapping_add(90); 32],
            session_id: identity(1).session_id,
            participant_id: identity(1).participant_id,
            purpose: 1,
            bound_digest: identity(1).context_binding_digest,
            nonce_epoch: 1,
            bytes: vec![seed; 35],
        }
    }

    #[test]
    fn spending_is_durable_before_the_bytes_are_returned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        let record = artifact(2);
        {
            let store = store::Store::open(&path).expect("open");
            let mut core = DurableVaultCore::new(store);
            core.insert_reservation(identity(1)).expect("claim");
            core.put_persisted_artifact(&record).expect("persist");
            let returned = core.spend_artifact(&record).expect("spend");
            assert_eq!(returned, record);
        }
        // The returned bytes came from a record that was already on disk.
        let store = store::Store::open(&path).expect("reopen");
        let mut core = DurableVaultCore::new(store);
        let after_restart = core.spent_artifact(&record.permit_id).expect("spent");
        assert_eq!(after_restart.bytes, record.bytes);
        assert_eq!(
            core.spent_permit_for_stage(&record.request_lookup, 1)
                .expect("index"),
            record.permit_id
        );
    }

    #[test]
    fn resending_returns_byte_identical_bytes_after_a_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        let record = artifact(3);
        {
            let store = store::Store::open(&path).expect("open");
            let mut core = DurableVaultCore::new(store);
            core.insert_reservation(identity(1)).expect("claim");
            core.spend_artifact(&record).expect("spend");
        }
        for _ in 0..3 {
            let store = store::Store::open(&path).expect("reopen");
            let mut core = DurableVaultCore::new(store);
            let resent = core.spent_artifact(&record.permit_id).expect("resend");
            assert_eq!(
                resent.bytes, record.bytes,
                "resend must return the recorded bytes, never recomputed ones"
            );
        }
    }

    #[test]
    fn budgets_are_charged_durably_and_fail_closed_at_the_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        let limits = VaultLimits {
            per_key: 2,
            per_counterparty: 5,
        };
        let store = store::Store::open(&path).expect("open");
        let mut core = DurableVaultCore::with_limits(store, limits);
        let key = [11u8; 32];
        let counterparty = [12u8; 32];
        core.charge_budgets(&key, &counterparty).expect("first");
        core.charge_budgets(&key, &counterparty).expect("second");
        let third = core.charge_budgets(&key, &counterparty);
        assert!(matches!(
            third,
            Err((VaultError::BudgetExhausted, Some(BudgetScopeLocal::Key)))
        ));
        drop(core);

        // The budget is durable: reopening does not refund any balance.
        let store = store::Store::open(&path).expect("reopen");
        let mut core = DurableVaultCore::with_limits(store, limits);
        assert!(core.charge_budgets(&key, &counterparty).is_err());
    }

    #[test]
    fn nonce_epochs_are_strictly_monotonic_and_nonzero() {
        let (_dir, mut core) = core();
        let first = core.next_nonce_epoch().expect("first");
        let second = core.next_nonce_epoch().expect("second");
        assert_eq!(first, 1);
        assert!(second > first);
    }
}

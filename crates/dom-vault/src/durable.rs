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

use zeroize::Zeroizing;

use crate::framing::{FrameReader, FrameWriter};
use crate::{namespace, Result, VaultError};

/// Magic of the reservation record.
const MAGIC_RESERVATION: &[u8; 8] = b"DOMVRSV1";
/// Magic of the public artifact record.
const MAGIC_ARTIFACT: &[u8; 8] = b"DOMVARV1";
/// Magic of the sealed record of the nonce pair.
const MAGIC_SEALED: &[u8; 8] = b"DOMVSSV1";

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
        }
    }

    /// Opens the core with configured budget caps.
    pub fn with_limits(store: store::Store, limits: VaultLimits) -> Self {
        Self {
            store,
            limits,
            quarantined: false,
        }
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

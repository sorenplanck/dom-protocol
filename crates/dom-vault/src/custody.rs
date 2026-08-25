//! Durable custody of the reservation lookup (`ReservationLookupCustodyV1`).
//!
//! This is the boundary the `VaultBackedSignerV1` invokes BEFORE vault
//! admission (`claim_fresh` persists the lookup here and only then calls
//! `claim_fresh_reservation`). The pin's contract requires: persisting and
//! re-reading the exact lookup with the binding digest and the session id;
//! and irreversibly abandoning a record that resolved to no occurrence in the
//! vault (`resume_claimed` → `RetryNotFound`).
//!
//! Durable model: a write-once record per lookup in `LOOKUP_CUSTODY` (byte
//! equivocation fails closed in the `store` itself), and a write-once
//! tombstone in `LOOKUP_ABANDONED`. An abandoned lookup never comes back:
//! persisting the same lookup again after abandonment is rejected.

use dom_adaptor::{
    DurableReservationLookupV1, PreparedFreshReservationV1, ReservationLookupCustodyV1,
    ReservationRequestLookupV1, SessionId,
};

use crate::{namespace, Result, VaultError};

const CUSTODY_MAGIC: &[u8; 8] = b"DOMLKCT1";
const RECORD_LEN: usize = 8 + 32 + 32;

fn encode_record(session_id: &SessionId, binding_digest: &[u8; 32]) -> [u8; RECORD_LEN] {
    let mut bytes = [0u8; RECORD_LEN];
    bytes[..8].copy_from_slice(CUSTODY_MAGIC);
    bytes[8..40].copy_from_slice(session_id.as_bytes());
    bytes[40..72].copy_from_slice(binding_digest);
    bytes
}

fn decode_record(bytes: &[u8]) -> Result<(SessionId, [u8; 32])> {
    if bytes.len() != RECORD_LEN || &bytes[..8] != CUSTODY_MAGIC {
        return Err(VaultError::CorruptState);
    }
    let mut session = [0u8; 32];
    session.copy_from_slice(&bytes[8..40]);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[40..72]);
    let session = SessionId::from_bytes(session).map_err(|_| VaultError::CorruptState)?;
    if digest == [0u8; 32] {
        return Err(VaultError::CorruptState);
    }
    Ok((session, digest))
}

/// One-shot evidence that the lookup was made durable and re-read byte for byte.
pub struct DurableLookup {
    request_lookup: ReservationRequestLookupV1,
    context_binding_digest: [u8; 32],
    session_id: SessionId,
}

impl DurableReservationLookupV1 for DurableLookup {
    fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.request_lookup
    }

    fn context_binding_digest(&self) -> &[u8; 32] {
        &self.context_binding_digest
    }

    fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

/// Durable lookup custody on top of the neutral `store`.
pub struct DurableLookupCustody<'a> {
    store: &'a mut store::Store,
}

impl<'a> DurableLookupCustody<'a> {
    /// Opens the custody on top of an already-open `store`.
    pub fn new(store: &'a mut store::Store) -> Self {
        Self { store }
    }

    fn read_record(
        &self,
        lookup: &ReservationRequestLookupV1,
    ) -> Result<Option<(SessionId, [u8; 32])>> {
        match self
            .store
            .opaque(namespace::LOOKUP_CUSTODY, lookup.as_bytes())?
        {
            None => Ok(None),
            Some(bytes) => decode_record(&bytes).map(Some),
        }
    }
}

impl ReservationLookupCustodyV1 for DurableLookupCustody<'_> {
    type Error = VaultError;
    type DurableLookup = DurableLookup;

    fn persist_prepared_lookup(
        &mut self,
        prepared: &PreparedFreshReservationV1,
    ) -> core::result::Result<Self::DurableLookup, Self::Error> {
        let lookup = prepared.request_lookup();
        // An already-abandoned lookup is never readmitted (irreversible abandonment).
        if self
            .store
            .opaque(namespace::LOOKUP_ABANDONED, lookup.as_bytes())?
            .is_some()
        {
            return Err(VaultError::InvalidTransition);
        }
        let record = encode_record(prepared.session_id(), prepared.context_binding_digest());
        // Write-once: the same lookup with different bytes fails closed in the store.
        self.store
            .put_opaque(namespace::LOOKUP_CUSTODY, lookup.as_bytes(), &record)?;
        // Re-read what became durable — the evidence comes from disk, not RAM.
        let (session_id, context_binding_digest) = self
            .read_record(lookup)?
            .ok_or(VaultError::StorageUnavailable)?;
        if session_id.as_bytes() != prepared.session_id().as_bytes()
            || &context_binding_digest != prepared.context_binding_digest()
        {
            return Err(VaultError::CorruptState);
        }
        let request_lookup = ReservationRequestLookupV1::from_bytes(*lookup.as_bytes())
            .map_err(|_| VaultError::CorruptState)?;
        Ok(DurableLookup {
            request_lookup,
            context_binding_digest,
            session_id,
        })
    }

    fn abandon_before_vault_claim(
        &mut self,
        lookup: &ReservationRequestLookupV1,
        session_id: &SessionId,
        context_binding_digest: &[u8; 32],
    ) -> core::result::Result<(), Self::Error> {
        // Only a retained record can be abandoned — and exactly that one (fail-closed).
        let (stored_session, stored_digest) = self
            .read_record(lookup)?
            .ok_or(VaultError::ReservationNotFound)?;
        if stored_session.as_bytes() != session_id.as_bytes()
            || &stored_digest != context_binding_digest
        {
            return Err(VaultError::CorruptState);
        }
        let record = encode_record(session_id, context_binding_digest);
        self.store
            .put_opaque(namespace::LOOKUP_ABANDONED, lookup.as_bytes(), &record)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `persist_prepared_lookup` takes `PreparedFreshReservationV1`, whose
    // constructor is sealed in the pin (it is only born inside the
    // VaultBackedSignerV1). It will be exercised end to end once the P0 patch
    // unlocks the signer; here we test what IS constructible: the codec and
    // the abandonment path over a real durable record.

    fn store_with_record(lookup: &[u8; 32], record: &[u8]) -> (tempfile::TempDir, store::Store) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = store::Store::open(&dir.path().join("custody.db")).expect("open");
        store
            .put_opaque(namespace::LOOKUP_CUSTODY, lookup, record)
            .expect("retained record");
        (dir, store)
    }

    #[test]
    fn abandon_requires_the_exact_retained_record() {
        let session = SessionId::from_bytes([7u8; 32]).expect("session");
        let digest = [9u8; 32];
        let lookup_bytes = [3u8; 32];
        let record = encode_record(&session, &digest);
        let (_dir, mut store) = store_with_record(&lookup_bytes, &record);
        let lookup = ReservationRequestLookupV1::from_bytes(lookup_bytes).expect("lookup");

        let mut custody = DurableLookupCustody::new(&mut store);
        // Divergent digest: fail closed, nothing is tombstoned.
        assert!(matches!(
            custody.abandon_before_vault_claim(&lookup, &session, &[8u8; 32]),
            Err(VaultError::CorruptState)
        ));
        // Exact record: abandonment accepted and idempotent.
        custody
            .abandon_before_vault_claim(&lookup, &session, &digest)
            .expect("abandonment");
        custody
            .abandon_before_vault_claim(&lookup, &session, &digest)
            .expect("idempotent abandonment (same bytes)");
        // The tombstone became durable.
        assert!(store
            .opaque(namespace::LOOKUP_ABANDONED, &lookup_bytes)
            .expect("read")
            .is_some());
    }

    #[test]
    fn abandon_of_an_unknown_lookup_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = store::Store::open(&dir.path().join("custody.db")).expect("open");
        let mut custody = DurableLookupCustody::new(&mut store);
        let lookup = ReservationRequestLookupV1::from_bytes([5u8; 32]).expect("lookup");
        let session = SessionId::from_bytes([7u8; 32]).expect("session");
        assert!(matches!(
            custody.abandon_before_vault_claim(&lookup, &session, &[9u8; 32]),
            Err(VaultError::ReservationNotFound)
        ));
    }

    #[test]
    fn tombstone_survives_reopen() {
        let session = SessionId::from_bytes([7u8; 32]).expect("session");
        let digest = [9u8; 32];
        let lookup_bytes = [3u8; 32];
        let record = encode_record(&session, &digest);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("custody.db");
        {
            let mut store = store::Store::open(&path).expect("open");
            store
                .put_opaque(namespace::LOOKUP_CUSTODY, &lookup_bytes, &record)
                .expect("record");
            let lookup = ReservationRequestLookupV1::from_bytes(lookup_bytes).expect("lookup");
            DurableLookupCustody::new(&mut store)
                .abandon_before_vault_claim(&lookup, &session, &digest)
                .expect("abandonment");
        }
        let store = store::Store::open(&path).expect("reopen");
        assert!(store
            .opaque(namespace::LOOKUP_ABANDONED, &lookup_bytes)
            .expect("read")
            .is_some());
    }

    #[test]
    fn record_codec_is_exact_and_fail_closed() {
        let session = SessionId::from_bytes([7u8; 32]).expect("session");
        let record = encode_record(&session, &[9u8; 32]);
        let (decoded_session, digest) = decode_record(&record).expect("roundtrip");
        assert_eq!(decoded_session.as_bytes(), session.as_bytes());
        assert_eq!(digest, [9u8; 32]);

        assert!(
            decode_record(&record[..RECORD_LEN - 1]).is_err(),
            "truncated"
        );
        let mut wrong_magic = record;
        wrong_magic[0] ^= 1;
        assert!(decode_record(&wrong_magic).is_err(), "magic");
        let mut zero_session = record;
        zero_session[8..40].fill(0);
        assert!(decode_record(&zero_session).is_err(), "zero session");
        let mut zero_digest = record;
        zero_digest[40..72].fill(0);
        assert!(decode_record(&zero_digest).is_err(), "zero digest");
    }
}

//! The durable one-shot nonce vault (Annex M M.6.4, M.6.5, M.10).

use std::path::Path;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroize;

use crate::entropy::{EntropySource, OsEntropy};
use crate::permit::{BitcoinNoncePermitV1, BitcoinNonceReservationIdV1};
use crate::seal::{open_secret, seal_secret};
use crate::secret::OneShotSessionSecrandV1;
use crate::state::{
    ArtifactKind, BitcoinNonceStateV1, PersistedArtifactDescriptorV1, PublicAbortReasonV1,
};
use crate::BitcoinNonceSealKeyV1;

/// Vault failures. No variant carries secret material (M.21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    /// The underlying storage failed or is unavailable.
    #[error("storage unavailable")]
    StorageUnavailable,
    /// The stored state is corrupt (unknown discriminant, missing row).
    #[error("corrupt vault state")]
    CorruptState,
    /// The reservation does not exist.
    #[error("no such reservation")]
    NoSuchReservation,
    /// The permit does not match the reservation's binding — equivocation.
    #[error("permit binding mismatch")]
    BindingMismatch,
    /// The reservation was already consumed (one-shot violation attempt).
    #[error("nonce already consumed")]
    AlreadyConsumed,
    /// The reservation is in the wrong state for this transition.
    #[error("illegal state transition")]
    IllegalTransition,
    /// A lost compare-and-swap on the monotonic revision.
    #[error("revision conflict")]
    RevisionConflict,
    /// The requested artifact was not persisted.
    #[error("no such artifact")]
    NoSuchArtifact,
    /// Secure entropy was unavailable.
    #[error("entropy unavailable")]
    EntropyUnavailable,
    /// The route-owner sealing key is empty or otherwise invalid.
    #[error("invalid nonce sealing key")]
    InvalidSealKey,
    /// A sealed nonce owner failed authenticated decryption.
    #[error("nonce owner authentication failed")]
    SealAuthenticationFailed,
    /// A restartable nonce operation requires a sealed owner record.
    #[error("sealed nonce owner unavailable")]
    SealedOwnerUnavailable,
    /// The retained owner-only nonce-key store was unavailable.
    #[error("nonce sealing-key store unavailable")]
    KeyStoreUnavailable,
    /// A nonce-key store object has the wrong type, owner, mode, link count,
    /// binding, or authenticated contents.
    #[error("invalid nonce sealing-key store object")]
    InvalidKeyStoreObject,
}

const SCHEMA_VERSION: i64 = 3;
const OUTBOUND_DOMAIN: &[u8] = b"DOM-INTEROP/BTC/F5/V1/VAULT-ARTIFACT\0";
const CONTINUATION_DOMAIN: &[u8] = b"DOM-INTEROP/BTC/F7/NONCE-CONTINUATION/V1\0";

/// The one-shot nonce vault over a durable SQLite database (M.6, M.10).
pub struct BitcoinNonceVault<E: EntropySource = OsEntropy> {
    connection: Connection,
    entropy: E,
    logical_clock: i64,
}

impl BitcoinNonceVault<OsEntropy> {
    /// Opens (or creates) the vault at `path` with the OS entropy source,
    /// applying migrations and reconciling crash-interrupted reservations.
    pub fn open(path: &Path) -> Result<Self, VaultError> {
        Self::open_with_entropy(path, OsEntropy)
    }
}

impl<E: EntropySource> BitcoinNonceVault<E> {
    /// Opens the vault with a caller-supplied entropy source (tests inject
    /// a deterministic one; production uses [`OsEntropy`]).
    pub fn open_with_entropy(path: &Path, entropy: E) -> Result<Self, VaultError> {
        let connection = Connection::open(path).map_err(|_| VaultError::StorageUnavailable)?;
        Self::configure(&connection)?;
        let mut vault = Self {
            connection,
            entropy,
            logical_clock: 0,
        };
        vault.migrate()?;
        vault.reconcile_on_open()?;
        Ok(vault)
    }

    fn configure(connection: &Connection) -> Result<(), VaultError> {
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(|_| VaultError::StorageUnavailable)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(VaultError::StorageUnavailable);
        }
        // FULL: the vault must survive kill -9, not just a panic (M.6.5).
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| VaultError::StorageUnavailable)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| VaultError::StorageUnavailable)?;
        Ok(())
    }

    fn migrate(&mut self) -> Result<(), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let found: i64 = tx
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|_| VaultError::StorageUnavailable)?;
        if found > SCHEMA_VERSION {
            return Err(VaultError::CorruptState);
        }
        if found < 1 {
            tx.execute_batch(
                "CREATE TABLE btc_nonce_reservations (
                     reservation_id BLOB PRIMARY KEY CHECK(length(reservation_id) = 32),
                     binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32),
                     state          INTEGER NOT NULL,
                     revision       INTEGER NOT NULL CHECK(revision >= 0),
                     created_at      INTEGER NOT NULL
                 ) STRICT;
                 CREATE TABLE btc_nonce_artifacts (
                     reservation_id BLOB NOT NULL
                         REFERENCES btc_nonce_reservations(reservation_id),
                     artifact_kind  INTEGER NOT NULL,
                     bytes          BLOB NOT NULL,
                     byte_length    INTEGER NOT NULL,
                     outbound_digest BLOB NOT NULL CHECK(length(outbound_digest) = 32),
                     exposed        INTEGER NOT NULL CHECK(exposed IN (0,1)),
                     PRIMARY KEY (reservation_id, artifact_kind)
                 ) STRICT;",
            )
            .map_err(|_| VaultError::StorageUnavailable)?;
        }
        if found < 2 {
            tx.execute_batch(
                "CREATE TABLE btc_m8_anchor_bindings (
                     reservation_id       BLOB PRIMARY KEY
                         REFERENCES btc_nonce_reservations(reservation_id),
                     anchor_evidence_digest BLOB NOT NULL
                         CHECK(length(anchor_evidence_digest) = 32),
                     CHECK(anchor_evidence_digest != zeroblob(32))
                 ) STRICT;",
            )
            .map_err(|_| VaultError::StorageUnavailable)?;
        }
        if found < 3 {
            tx.execute_batch(
                "CREATE TABLE btc_nonce_owners (
                     reservation_id BLOB PRIMARY KEY
                         REFERENCES btc_nonce_reservations(reservation_id),
                     continuation_binding_digest BLOB NOT NULL
                         CHECK(length(continuation_binding_digest) = 32),
                     sealed_session_secrand BLOB,
                     public_nonce_digest BLOB NOT NULL
                         CHECK(length(public_nonce_digest) = 32),
                     tombstoned INTEGER NOT NULL CHECK(tombstoned IN (0,1)),
                     CHECK((tombstoned = 0 AND sealed_session_secrand IS NOT NULL)
                        OR (tombstoned = 1 AND sealed_session_secrand IS NULL))
                 ) STRICT;",
            )
            .map_err(|_| VaultError::StorageUnavailable)?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|_| VaultError::StorageUnavailable)?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok(())
    }

    /// Crash reconciliation.
    ///
    /// Legacy memory-only attempts remain fail-closed and are aborted. F7
    /// attempts with a complete, non-tombstoned sealed owner plus a persisted
    /// public nonce survive and are reopened explicitly by the route owner.
    /// Corrupt/incomplete owner records are terminal; a normal crash is not.
    fn reconcile_on_open(&mut self) -> Result<(), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        // Advance the logical clock past any stored row so new rows sort
        // after old ones deterministically.
        let max_clock: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(created_at), 0) FROM btc_nonce_reservations",
                [],
                |r| r.get(0),
            )
            .map_err(|_| VaultError::StorageUnavailable)?;
        tx.execute(
            "UPDATE btc_nonce_reservations
                 SET state = ?1, revision = revision + 1
                 WHERE state IN (?2, ?3, ?4)
                   AND NOT EXISTS (
                       SELECT 1 FROM btc_nonce_owners owner
                       WHERE owner.reservation_id = btc_nonce_reservations.reservation_id
                         AND owner.tombstoned = 0
                         AND owner.sealed_session_secrand IS NOT NULL
                         AND EXISTS (
                             SELECT 1 FROM btc_nonce_artifacts artifact
                             WHERE artifact.reservation_id = owner.reservation_id
                               AND artifact.artifact_kind = ?5
                               AND artifact.outbound_digest = owner.public_nonce_digest
                         )
                   )",
            rusqlite::params![
                BitcoinNonceStateV1::Aborted as i64,
                BitcoinNonceStateV1::ConsumptionCommitted as i64,
                BitcoinNonceStateV1::PublicArtifactCommitted as i64,
                BitcoinNonceStateV1::PublicArtifactExposed as i64,
                ArtifactKind::PublicNonce as i64,
            ],
        )
        .map_err(|_| VaultError::StorageUnavailable)?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        self.logical_clock = max_clock;
        Ok(())
    }

    fn next_clock(&mut self) -> i64 {
        self.logical_clock += 1;
        self.logical_clock
    }

    /// Reserves a nonce (M.6.4). Idempotent for the same permit: the
    /// reservation id is derived from the permit, so re-reserving returns
    /// the same id without disturbing an in-progress reservation.
    pub fn reserve(
        &mut self,
        permit: &BitcoinNoncePermitV1,
    ) -> Result<BitcoinNonceReservationIdV1, VaultError> {
        self.reserve_with_m8_binding(permit, None)
    }

    /// Reserves an F7 nonce and atomically binds the reservation to the exact
    /// post-confirmation M.8 anchor-evidence digest before any nonce material
    /// exists.
    ///
    /// A reservation id can acquire only one such binding. A retry with the
    /// same digest is idempotent; a stale/reorged digest fails closed. The
    /// legacy [`Self::reserve`] path refuses an M.8-bound reservation.
    pub fn reserve_after_m8(
        &mut self,
        permit: &BitcoinNoncePermitV1,
        anchor_evidence_digest: &[u8; 32],
    ) -> Result<BitcoinNonceReservationIdV1, VaultError> {
        if *anchor_evidence_digest == [0; 32] {
            return Err(VaultError::BindingMismatch);
        }
        self.reserve_with_m8_binding(permit, Some(anchor_evidence_digest))
    }

    fn reserve_with_m8_binding(
        &mut self,
        permit: &BitcoinNoncePermitV1,
        expected_anchor: Option<&[u8; 32]>,
    ) -> Result<BitcoinNonceReservationIdV1, VaultError> {
        let id = permit.reservation_id();
        let binding = permit.binding_digest();
        let clock = self.next_clock();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT binding_digest FROM btc_nonce_reservations WHERE reservation_id = ?1",
                [&id.0[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        let had_existing = existing.is_some();
        match existing.as_ref() {
            Some(stored) => {
                if stored.as_slice() != binding {
                    return Err(VaultError::BindingMismatch);
                }
                // Idempotent re-reservation.
            }
            None => {
                tx.execute(
                    "INSERT INTO btc_nonce_reservations
                         (reservation_id, binding_digest, state, revision, created_at)
                         VALUES (?1, ?2, ?3, 0, ?4)",
                    rusqlite::params![
                        &id.0[..],
                        &binding[..],
                        BitcoinNonceStateV1::Reserved as i64,
                        clock,
                    ],
                )
                .map_err(|_| VaultError::StorageUnavailable)?;
            }
        }
        let stored_anchor: Option<Vec<u8>> = tx
            .query_row(
                "SELECT anchor_evidence_digest FROM btc_m8_anchor_bindings
                     WHERE reservation_id = ?1",
                [&id.0[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        match (expected_anchor, stored_anchor) {
            (None, None) => {}
            (None, Some(_)) | (Some(_), None) if had_existing => {
                return Err(VaultError::BindingMismatch)
            }
            (None, Some(_)) => return Err(VaultError::CorruptState),
            (Some(expected), Some(stored)) if stored.as_slice() == expected => {}
            (Some(_), Some(_)) => return Err(VaultError::BindingMismatch),
            (Some(expected), None) => {
                tx.execute(
                    "INSERT INTO btc_m8_anchor_bindings
                         (reservation_id, anchor_evidence_digest) VALUES (?1, ?2)",
                    rusqlite::params![&id.0[..], &expected[..]],
                )
                .map_err(|_| VaultError::StorageUnavailable)?;
            }
        }
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok(id)
    }

    /// Reads a reservation's (state, revision), validating the binding.
    fn load_checked(
        tx: &rusqlite::Transaction<'_>,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        expected_anchor: Option<&[u8; 32]>,
    ) -> Result<(BitcoinNonceStateV1, i64), VaultError> {
        let row: Option<(Vec<u8>, i64, i64)> = tx
            .query_row(
                "SELECT binding_digest, state, revision
                     FROM btc_nonce_reservations WHERE reservation_id = ?1",
                [&id.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (binding, state_raw, revision) = row.ok_or(VaultError::NoSuchReservation)?;
        if binding != permit.binding_digest() {
            return Err(VaultError::BindingMismatch);
        }
        Self::validate_m8_binding(tx, id, expected_anchor)?;
        let state = BitcoinNonceStateV1::from_i64(state_raw).ok_or(VaultError::CorruptState)?;
        Ok((state, revision))
    }

    fn validate_m8_binding(
        tx: &rusqlite::Transaction<'_>,
        id: &BitcoinNonceReservationIdV1,
        expected_anchor: Option<&[u8; 32]>,
    ) -> Result<(), VaultError> {
        let stored: Option<Vec<u8>> = tx
            .query_row(
                "SELECT anchor_evidence_digest FROM btc_m8_anchor_bindings
                     WHERE reservation_id = ?1",
                [&id.0[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        match (expected_anchor, stored) {
            (None, None) => Ok(()),
            (Some(expected), Some(stored)) if stored.as_slice() == expected => Ok(()),
            _ => Err(VaultError::BindingMismatch),
        }
    }

    /// Revalidates the durable F7 anchor binding after restart or before an
    /// outbound retry. No state is changed.
    pub fn verify_m8_anchor_binding(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        anchor_evidence_digest: &[u8; 32],
    ) -> Result<(), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| VaultError::StorageUnavailable)?;
        Self::load_checked(&tx, id, permit, Some(anchor_evidence_digest))?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)
    }

    fn cas_state(
        tx: &rusqlite::Transaction<'_>,
        id: &BitcoinNonceReservationIdV1,
        expected_revision: i64,
        new_state: BitcoinNonceStateV1,
    ) -> Result<(), VaultError> {
        let changed = tx
            .execute(
                "UPDATE btc_nonce_reservations
                     SET state = ?1, revision = ?2
                     WHERE reservation_id = ?3 AND revision = ?4",
                rusqlite::params![
                    new_state as i64,
                    expected_revision + 1,
                    &id.0[..],
                    expected_revision,
                ],
            )
            .map_err(|_| VaultError::StorageUnavailable)?;
        if changed != 1 {
            return Err(VaultError::RevisionConflict);
        }
        Ok(())
    }

    /// Consumes the reservation exactly once, generating and returning the
    /// one-shot `session_secrand` (M.6.4, M.6.5). The consumption witness
    /// is committed and fsync-durable BEFORE the secret is returned, so a
    /// crash cannot yield a second consumption. The secret itself is never
    /// persisted.
    pub fn consume(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
    ) -> Result<OneShotSessionSecrandV1, VaultError> {
        self.consume_with_m8_binding(id, permit, None)
    }

    /// Consumes an F7 reservation only when the caller presents the exact
    /// anchor-evidence digest durably bound by [`Self::reserve_after_m8`].
    pub fn consume_after_m8(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        anchor_evidence_digest: &[u8; 32],
    ) -> Result<OneShotSessionSecrandV1, VaultError> {
        self.consume_with_m8_binding(id, permit, Some(anchor_evidence_digest))
    }

    fn consume_with_m8_binding(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        expected_anchor: Option<&[u8; 32]>,
    ) -> Result<OneShotSessionSecrandV1, VaultError> {
        // Draw entropy first so a failure aborts before any state change.
        let mut secrand = [0u8; 32];
        self.entropy
            .fill(&mut secrand)
            .map_err(|_| VaultError::EntropyUnavailable)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (state, revision) = Self::load_checked(&tx, id, permit, expected_anchor)?;
        match state {
            BitcoinNonceStateV1::Reserved => {}
            BitcoinNonceStateV1::ConsumptionCommitted
            | BitcoinNonceStateV1::PublicArtifactCommitted
            | BitcoinNonceStateV1::PublicArtifactExposed
            | BitcoinNonceStateV1::PartialArtifactCommitted
            | BitcoinNonceStateV1::Spent => return Err(VaultError::AlreadyConsumed),
            BitcoinNonceStateV1::Aborted | BitcoinNonceStateV1::Equivocated => {
                return Err(VaultError::IllegalTransition)
            }
        }
        Self::cas_state(&tx, id, revision, BitcoinNonceStateV1::ConsumptionCommitted)?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        // Only AFTER the durable commit does the secret leave.
        Ok(OneShotSessionSecrandV1::new(secrand))
    }

    /// Atomically generates, seals and persists a restartable nonce owner and
    /// its exact canonical public nonce before returning any public bytes.
    ///
    /// The callback is expected to call only the pinned backend nonce
    /// generator. Its returned secret backend state remains memory-only; the
    /// durable owner stores authenticated `session_secrand`, from which the
    /// same backend state is reconstructed after a crash. Both the sealed
    /// owner and PubNonce are committed in one `BEGIN IMMEDIATE` transaction
    /// under `synchronous=FULL`.
    pub fn prepare_restartable_public_nonce_after_m8<R>(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        anchor_evidence_digest: &[u8; 32],
        continuation_binding_digest: &[u8; 32],
        seal_key: &BitcoinNonceSealKeyV1,
        generate: impl FnOnce(&[u8; 32]) -> Result<(R, [u8; 66]), ()>,
    ) -> Result<(R, [u8; 66], PersistedArtifactDescriptorV1), VaultError> {
        let mut secrand = [0u8; 32];
        self.entropy
            .fill(&mut secrand)
            .map_err(|_| VaultError::EntropyUnavailable)?;
        let mut sealing_nonce = [0u8; 12];
        getrandom::getrandom(&mut sealing_nonce).map_err(|_| VaultError::EntropyUnavailable)?;
        let generated = generate(&secrand).map_err(|_| VaultError::SealedOwnerUnavailable);
        let (owner, public_nonce) = match generated {
            Ok(value) => value,
            Err(error) => {
                secrand.zeroize();
                return Err(error);
            }
        };
        let sealed = seal_secret(
            seal_key,
            id,
            permit,
            Some(anchor_evidence_digest),
            continuation_binding_digest,
            sealing_nonce,
            &secrand,
        );
        secrand.zeroize();
        sealing_nonce.zeroize();
        let sealed = sealed?;
        let digest = Self::outbound_digest(id, ArtifactKind::PublicNonce, &public_nonce);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (state, revision) = Self::load_checked(&tx, id, permit, Some(anchor_evidence_digest))?;
        if state != BitcoinNonceStateV1::Reserved {
            return Err(VaultError::AlreadyConsumed);
        }
        tx.execute(
            "INSERT INTO btc_nonce_owners
                 (reservation_id, continuation_binding_digest,
                  sealed_session_secrand, public_nonce_digest, tombstoned)
                 VALUES (?1, ?2, ?3, ?4, 0)",
            rusqlite::params![
                &id.0[..],
                &continuation_binding_digest[..],
                &sealed,
                &digest[..]
            ],
        )
        .map_err(|_| VaultError::StorageUnavailable)?;
        tx.execute(
            "INSERT INTO btc_nonce_artifacts
                 (reservation_id, artifact_kind, bytes, byte_length,
                  outbound_digest, exposed)
                 VALUES (?1, ?2, ?3, 66, ?4, 0)",
            rusqlite::params![
                &id.0[..],
                ArtifactKind::PublicNonce as i64,
                &public_nonce[..],
                &digest[..]
            ],
        )
        .map_err(|_| VaultError::StorageUnavailable)?;
        Self::cas_state(
            &tx,
            id,
            revision,
            BitcoinNonceStateV1::PublicArtifactCommitted,
        )?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok((
            owner,
            public_nonce,
            PersistedArtifactDescriptorV1 {
                reservation_id: id.0,
                artifact_kind: ArtifactKind::PublicNonce as u8,
                outbound_digest: digest,
                byte_length: 66,
            },
        ))
    }

    /// Reopens the exact sealed nonce owner after restart and reconstructs it
    /// only if the pinned backend reproduces the byte-identical persisted
    /// PubNonce. The callback never receives data before AEAD and all durable
    /// bindings have been authenticated.
    pub fn reopen_restartable_nonce_after_m8<R>(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        anchor_evidence_digest: &[u8; 32],
        continuation_binding_digest: &[u8; 32],
        seal_key: &BitcoinNonceSealKeyV1,
        reconstruct: impl FnOnce(&[u8; 32]) -> Result<(R, [u8; 66]), ()>,
    ) -> Result<(R, [u8; 66], PersistedArtifactDescriptorV1), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (state, _) = Self::load_checked(&tx, id, permit, Some(anchor_evidence_digest))?;
        if !matches!(
            state,
            BitcoinNonceStateV1::PublicArtifactCommitted
                | BitcoinNonceStateV1::PublicArtifactExposed
        ) {
            return Err(VaultError::IllegalTransition);
        }
        let owner: Option<(Vec<u8>, Vec<u8>, i64)> = tx
            .query_row(
                "SELECT continuation_binding_digest, sealed_session_secrand, tombstoned
                     FROM btc_nonce_owners WHERE reservation_id = ?1",
                [&id.0[..]],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (stored_binding, sealed, tombstoned) =
            owner.ok_or(VaultError::SealedOwnerUnavailable)?;
        if stored_binding.as_slice() != continuation_binding_digest || tombstoned != 0 {
            return Err(VaultError::BindingMismatch);
        }
        let (public_nonce, public_digest) =
            Self::load_artifact_bytes(&tx, id, ArtifactKind::PublicNonce)?;
        let fixed_public: [u8; 66] = public_nonce
            .try_into()
            .map_err(|_| VaultError::CorruptState)?;
        let secret = open_secret(
            seal_key,
            id,
            permit,
            Some(anchor_evidence_digest),
            continuation_binding_digest,
            &sealed,
        )?;
        let (owner, reconstructed_public) =
            reconstruct(&secret).map_err(|_| VaultError::SealAuthenticationFailed)?;
        if reconstructed_public != fixed_public
            || Self::outbound_digest(id, ArtifactKind::PublicNonce, &fixed_public) != public_digest
        {
            return Err(VaultError::SealAuthenticationFailed);
        }
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok((
            owner,
            fixed_public,
            PersistedArtifactDescriptorV1 {
                reservation_id: id.0,
                artifact_kind: ArtifactKind::PublicNonce as u8,
                outbound_digest: public_digest,
                byte_length: 66,
            },
        ))
    }

    /// Reopens the public, already-partially-signed continuation after the
    /// sealed owner was atomically tombstoned. No secret is decrypted or
    /// reconstructed; both exact outbound artifacts are returned only from
    /// their durable rows for byte-identical retransmission.
    pub fn reopen_tombstoned_partial_after_m8(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        anchor_evidence_digest: &[u8; 32],
        continuation_binding_digest: &[u8; 32],
    ) -> Result<
        (
            [u8; 66],
            [u8; 32],
            PersistedArtifactDescriptorV1,
            PersistedArtifactDescriptorV1,
        ),
        VaultError,
    > {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (state, _) = Self::load_checked(&tx, id, permit, Some(anchor_evidence_digest))?;
        if !matches!(
            state,
            BitcoinNonceStateV1::PartialArtifactCommitted | BitcoinNonceStateV1::Spent
        ) || !Self::owner_is_tombstoned(&tx, id)?
        {
            return Err(VaultError::IllegalTransition);
        }
        let stored_binding: Vec<u8> = tx
            .query_row(
                "SELECT continuation_binding_digest FROM btc_nonce_owners
                     WHERE reservation_id = ?1",
                [&id.0[..]],
                |row| row.get(0),
            )
            .map_err(|_| VaultError::StorageUnavailable)?;
        if stored_binding.as_slice() != continuation_binding_digest {
            return Err(VaultError::BindingMismatch);
        }
        let (public_bytes, public_digest) =
            Self::load_artifact_bytes(&tx, id, ArtifactKind::PublicNonce)?;
        let (partial_bytes, partial_digest) =
            Self::load_artifact_bytes(&tx, id, ArtifactKind::PartialSignature)?;
        let public: [u8; 66] = public_bytes
            .try_into()
            .map_err(|_| VaultError::CorruptState)?;
        let partial: [u8; 32] = partial_bytes
            .try_into()
            .map_err(|_| VaultError::CorruptState)?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok((
            public,
            partial,
            PersistedArtifactDescriptorV1 {
                reservation_id: id.0,
                artifact_kind: ArtifactKind::PublicNonce as u8,
                outbound_digest: public_digest,
                byte_length: 66,
            },
            PersistedArtifactDescriptorV1 {
                reservation_id: id.0,
                artifact_kind: ArtifactKind::PartialSignature as u8,
                outbound_digest: partial_digest,
                byte_length: 32,
            },
        ))
    }

    fn outbound_digest(
        id: &BitcoinNonceReservationIdV1,
        kind: ArtifactKind,
        bytes: &[u8],
    ) -> [u8; 32] {
        let mut h = Blake2bVar::new(32).expect("BLAKE2b-256 output size is valid"); // I14-ALLOW: fixed 32-byte output is always valid
        h.update(OUTBOUND_DOMAIN);
        h.update(&id.0);
        h.update(&[kind as u8]);
        h.update(bytes);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out)
            .expect("BLAKE2b-256 output size is valid"); // I14-ALLOW: fixed 32-byte output
        out
    }

    /// Canonical public continuation binding used by the sealed nonce owner.
    /// It includes every public signing input required to deterministically
    /// reconstruct the backend secnonce and check the persisted PubNonce.
    #[must_use]
    pub fn continuation_binding_digest(
        permit: &BitcoinNoncePermitV1,
        signer_public_key: &[u8; 33],
        key_aggregation_digest: &[u8; 32],
        output_xonly: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = Blake2bVar::new(32).expect("BLAKE2b-256 output size is valid"); // I14-ALLOW
        h.update(CONTINUATION_DOMAIN);
        h.update(&permit.binding_digest());
        h.update(signer_public_key);
        h.update(key_aggregation_digest);
        h.update(output_xonly);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out)
            .expect("BLAKE2b-256 output size is valid"); // I14-ALLOW
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_artifact(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        kind: ArtifactKind,
        bytes: &[u8],
        from: BitcoinNonceStateV1,
        to: BitcoinNonceStateV1,
        expected_anchor: Option<&[u8; 32]>,
    ) -> Result<PersistedArtifactDescriptorV1, VaultError> {
        let digest = Self::outbound_digest(id, kind, bytes);
        let byte_length = u32::try_from(bytes.len()).map_err(|_| VaultError::CorruptState)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (state, revision) = Self::load_checked(&tx, id, permit, expected_anchor)?;
        if state != from {
            // Idempotent redelivery: the artifact already exists with the
            // same digest and the state already advanced.
            if let Some(existing) = Self::load_artifact_digest(&tx, id, kind)? {
                if existing == digest {
                    if kind == ArtifactKind::PartialSignature
                        && expected_anchor.is_some()
                        && !Self::owner_is_tombstoned(&tx, id)?
                    {
                        return Err(VaultError::CorruptState);
                    }
                    tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
                    return Ok(PersistedArtifactDescriptorV1 {
                        reservation_id: id.0,
                        artifact_kind: kind as u8,
                        outbound_digest: digest,
                        byte_length,
                    });
                }
            }
            return Err(VaultError::IllegalTransition);
        }
        tx.execute(
            "INSERT INTO btc_nonce_artifacts
                 (reservation_id, artifact_kind, bytes, byte_length, outbound_digest, exposed)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![
                &id.0[..],
                kind as i64,
                bytes,
                byte_length as i64,
                &digest[..]
            ],
        )
        .map_err(|_| VaultError::StorageUnavailable)?;
        if kind == ArtifactKind::PartialSignature && expected_anchor.is_some() {
            let changed = tx
                .execute(
                    "UPDATE btc_nonce_owners
                         SET sealed_session_secrand = NULL, tombstoned = 1
                         WHERE reservation_id = ?1
                           AND tombstoned = 0
                           AND sealed_session_secrand IS NOT NULL",
                    [&id.0[..]],
                )
                .map_err(|_| VaultError::StorageUnavailable)?;
            if changed != 1 {
                return Err(VaultError::SealedOwnerUnavailable);
            }
        }
        Self::cas_state(&tx, id, revision, to)?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok(PersistedArtifactDescriptorV1 {
            reservation_id: id.0,
            artifact_kind: kind as u8,
            outbound_digest: digest,
            byte_length,
        })
    }

    fn load_artifact_digest(
        tx: &rusqlite::Transaction<'_>,
        id: &BitcoinNonceReservationIdV1,
        kind: ArtifactKind,
    ) -> Result<Option<[u8; 32]>, VaultError> {
        let row: Option<Vec<u8>> = tx
            .query_row(
                "SELECT outbound_digest FROM btc_nonce_artifacts
                     WHERE reservation_id = ?1 AND artifact_kind = ?2",
                rusqlite::params![&id.0[..], kind as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        match row {
            None => Ok(None),
            Some(v) => {
                let arr: [u8; 32] = v.try_into().map_err(|_| VaultError::CorruptState)?;
                Ok(Some(arr))
            }
        }
    }

    fn owner_is_tombstoned(
        tx: &rusqlite::Transaction<'_>,
        id: &BitcoinNonceReservationIdV1,
    ) -> Result<bool, VaultError> {
        let row: Option<(Option<Vec<u8>>, i64)> = tx
            .query_row(
                "SELECT sealed_session_secrand, tombstoned
                     FROM btc_nonce_owners WHERE reservation_id = ?1",
                [&id.0[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        Ok(matches!(row, Some((None, 1))))
    }

    /// Persists the public nonce bytes durably (M.6.5). Must follow a
    /// consumption; the bytes may not be exposed until this commit lands.
    pub fn persist_public_nonce(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        bytes: &[u8],
    ) -> Result<PersistedArtifactDescriptorV1, VaultError> {
        self.persist_artifact(
            id,
            permit,
            ArtifactKind::PublicNonce,
            bytes,
            BitcoinNonceStateV1::ConsumptionCommitted,
            BitcoinNonceStateV1::PublicArtifactCommitted,
            None,
        )
    }

    /// Persists an F7 public nonce only under the exact durable M.8 binding.
    pub fn persist_public_nonce_after_m8(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        anchor_evidence_digest: &[u8; 32],
        bytes: &[u8],
    ) -> Result<PersistedArtifactDescriptorV1, VaultError> {
        self.persist_artifact(
            id,
            permit,
            ArtifactKind::PublicNonce,
            bytes,
            BitcoinNonceStateV1::ConsumptionCommitted,
            BitcoinNonceStateV1::PublicArtifactCommitted,
            Some(anchor_evidence_digest),
        )
    }

    /// Authorizes exposure of a persisted public nonce and returns its
    /// bytes (M.6.5). Only now may the bytes leave the process. Idempotent
    /// after the first exposure.
    pub fn expose(
        &mut self,
        descriptor: &PersistedArtifactDescriptorV1,
    ) -> Result<Vec<u8>, VaultError> {
        self.expose_with_m8_binding(descriptor, None)
    }

    /// Authorizes exposure of an F7 public nonce only after revalidating the
    /// exact anchor-evidence digest retained with its reservation.
    pub fn expose_after_m8(
        &mut self,
        descriptor: &PersistedArtifactDescriptorV1,
        anchor_evidence_digest: &[u8; 32],
    ) -> Result<Vec<u8>, VaultError> {
        self.expose_with_m8_binding(descriptor, Some(anchor_evidence_digest))
    }

    fn expose_with_m8_binding(
        &mut self,
        descriptor: &PersistedArtifactDescriptorV1,
        expected_anchor: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, VaultError> {
        let id = BitcoinNonceReservationIdV1(descriptor.reservation_id);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let state_raw: Option<i64> = tx
            .query_row(
                "SELECT state FROM btc_nonce_reservations WHERE reservation_id = ?1",
                [&id.0[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        let state_raw = state_raw.ok_or(VaultError::NoSuchReservation)?;
        let state = BitcoinNonceStateV1::from_i64(state_raw).ok_or(VaultError::CorruptState)?;
        Self::validate_m8_binding(&tx, &id, expected_anchor)?;
        let (bytes, digest) = Self::load_artifact_bytes(&tx, &id, ArtifactKind::PublicNonce)?;
        if digest != descriptor.outbound_digest {
            return Err(VaultError::BindingMismatch);
        }
        match state {
            BitcoinNonceStateV1::PublicArtifactCommitted => {
                let revision: i64 = tx
                    .query_row(
                        "SELECT revision FROM btc_nonce_reservations WHERE reservation_id = ?1",
                        [&id.0[..]],
                        |r| r.get(0),
                    )
                    .map_err(|_| VaultError::StorageUnavailable)?;
                tx.execute(
                    "UPDATE btc_nonce_artifacts SET exposed = 1
                         WHERE reservation_id = ?1 AND artifact_kind = ?2",
                    rusqlite::params![&id.0[..], ArtifactKind::PublicNonce as i64],
                )
                .map_err(|_| VaultError::StorageUnavailable)?;
                Self::cas_state(
                    &tx,
                    &id,
                    revision,
                    BitcoinNonceStateV1::PublicArtifactExposed,
                )?;
            }
            BitcoinNonceStateV1::PublicArtifactExposed
            | BitcoinNonceStateV1::PartialArtifactCommitted
            | BitcoinNonceStateV1::Spent => {
                // Already exposed at least once: idempotent re-exposure.
            }
            _ => return Err(VaultError::IllegalTransition),
        }
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok(bytes)
    }

    fn load_artifact_bytes(
        tx: &rusqlite::Transaction<'_>,
        id: &BitcoinNonceReservationIdV1,
        kind: ArtifactKind,
    ) -> Result<(Vec<u8>, [u8; 32]), VaultError> {
        let row: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT bytes, outbound_digest FROM btc_nonce_artifacts
                     WHERE reservation_id = ?1 AND artifact_kind = ?2",
                rusqlite::params![&id.0[..], kind as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (bytes, digest_vec) = row.ok_or(VaultError::NoSuchArtifact)?;
        let digest: [u8; 32] = digest_vec
            .try_into()
            .map_err(|_| VaultError::CorruptState)?;
        Ok((bytes, digest))
    }

    /// Persists the partial signature durably (M.6.5). Must follow
    /// exposure of the public nonce.
    pub fn persist_partial_signature(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        bytes: &[u8],
    ) -> Result<PersistedArtifactDescriptorV1, VaultError> {
        self.persist_artifact(
            id,
            permit,
            ArtifactKind::PartialSignature,
            bytes,
            BitcoinNonceStateV1::PublicArtifactExposed,
            BitcoinNonceStateV1::PartialArtifactCommitted,
            None,
        )
    }

    /// Persists an F7 partial signature only under the exact durable M.8
    /// binding established before nonce generation.
    pub fn persist_partial_signature_after_m8(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        anchor_evidence_digest: &[u8; 32],
        bytes: &[u8],
    ) -> Result<PersistedArtifactDescriptorV1, VaultError> {
        self.persist_artifact(
            id,
            permit,
            ArtifactKind::PartialSignature,
            bytes,
            BitcoinNonceStateV1::PublicArtifactExposed,
            BitcoinNonceStateV1::PartialArtifactCommitted,
            Some(anchor_evidence_digest),
        )
    }

    /// Byte-identical resend of an already-persisted artifact (M.6.5,
    /// M.10.5): the stored bytes are returned verbatim; nothing is
    /// recomputed.
    pub fn resend(
        &mut self,
        descriptor: &PersistedArtifactDescriptorV1,
    ) -> Result<Vec<u8>, VaultError> {
        self.resend_with_m8_binding(descriptor, None)
    }

    /// Reacquires byte-identical F7 outbound bytes only after revalidating
    /// the same post-confirmation anchor digest used before nonce creation.
    pub fn resend_after_m8(
        &mut self,
        descriptor: &PersistedArtifactDescriptorV1,
        anchor_evidence_digest: &[u8; 32],
    ) -> Result<Vec<u8>, VaultError> {
        self.resend_with_m8_binding(descriptor, Some(anchor_evidence_digest))
    }

    fn resend_with_m8_binding(
        &mut self,
        descriptor: &PersistedArtifactDescriptorV1,
        expected_anchor: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, VaultError> {
        let id = BitcoinNonceReservationIdV1(descriptor.reservation_id);
        let kind = match descriptor.artifact_kind {
            1 => ArtifactKind::PublicNonce,
            2 => ArtifactKind::PartialSignature,
            _ => return Err(VaultError::CorruptState),
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| VaultError::StorageUnavailable)?;
        Self::validate_m8_binding(&tx, &id, expected_anchor)?;
        let (bytes, digest) = Self::load_artifact_bytes(&tx, &id, kind)?;
        if digest != descriptor.outbound_digest {
            return Err(VaultError::BindingMismatch);
        }
        Ok(bytes)
    }

    /// Marks a completed reservation as spent (M.6.3).
    pub fn mark_spent(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
    ) -> Result<(), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (state, revision) = Self::load_checked(&tx, id, permit, None)?;
        if state != BitcoinNonceStateV1::PartialArtifactCommitted {
            return Err(VaultError::IllegalTransition);
        }
        Self::cas_state(&tx, id, revision, BitcoinNonceStateV1::Spent)?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok(())
    }

    /// Marks an F7 reservation spent only after revalidating the exact anchor
    /// binding retained across restart.
    pub fn mark_spent_after_m8(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        permit: &BitcoinNoncePermitV1,
        anchor_evidence_digest: &[u8; 32],
    ) -> Result<(), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (state, revision) = Self::load_checked(&tx, id, permit, Some(anchor_evidence_digest))?;
        if state != BitcoinNonceStateV1::PartialArtifactCommitted {
            return Err(VaultError::IllegalTransition);
        }
        Self::cas_state(&tx, id, revision, BitcoinNonceStateV1::Spent)?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok(())
    }

    /// Aborts a live reservation to a terminal state (M.6.3). Terminal
    /// states never return to a live state; aborting a terminal
    /// reservation is a no-op success for idempotency, EXCEPT that an
    /// already-Spent reservation is not "aborted".
    pub fn abort(
        &mut self,
        id: &BitcoinNonceReservationIdV1,
        _reason: PublicAbortReasonV1,
    ) -> Result<(), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| VaultError::StorageUnavailable)?;
        let row: Option<(i64, i64)> = tx
            .query_row(
                "SELECT state, revision FROM btc_nonce_reservations WHERE reservation_id = ?1",
                [&id.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        let (state_raw, revision) = row.ok_or(VaultError::NoSuchReservation)?;
        let state = BitcoinNonceStateV1::from_i64(state_raw).ok_or(VaultError::CorruptState)?;
        if state.is_terminal() {
            tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
            return Ok(());
        }
        Self::cas_state(&tx, id, revision, BitcoinNonceStateV1::Aborted)?;
        tx.commit().map_err(|_| VaultError::StorageUnavailable)?;
        Ok(())
    }

    /// Reads the current durable state of a reservation (for tests and
    /// reconciliation reporting).
    pub fn state_of(
        &self,
        id: &BitcoinNonceReservationIdV1,
    ) -> Result<BitcoinNonceStateV1, VaultError> {
        let raw: Option<i64> = self
            .connection
            .query_row(
                "SELECT state FROM btc_nonce_reservations WHERE reservation_id = ?1",
                [&id.0[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| VaultError::StorageUnavailable)?;
        let raw = raw.ok_or(VaultError::NoSuchReservation)?;
        BitcoinNonceStateV1::from_i64(raw).ok_or(VaultError::CorruptState)
    }
}

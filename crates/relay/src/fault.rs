//! Explicit, capability-bound Relay fault controls.
//!
//! This module exists only for crate tests or the default-off
//! `relay-fault-injection` feature. A normal production build has no abort or
//! database-destruction entry point. Every cut is bound to one public database
//! identity and, for ACK loss, one exact idempotency key. A durable fired
//! marker precedes process abort/database deletion so a supervisor can
//! authenticate the intended fault without reading payload bytes.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;

use crate::production::{
    database_loss_marker, validate_owner_file, validate_root, ProductionRelayError,
    ProductionRelayV1, RelayDatabaseIdV1, DATABASE_LOSS_DOMAIN, FILE_MODE,
    RELAY_DATABASE_FILE_NAME, RELAY_DATABASE_LOSS_MARKER_NAME,
};
use crate::server::{AckV1, IdempotencyKeyV1};

/// Durable marker created immediately before the process-loss abort.
pub const RELAY_PROCESS_LOSS_MARKER_NAME: &str = "relay-process-loss-fired.v1";

const PROCESS_MAGIC: &[u8; 8] = b"DOMRLYP1";
const MARKER_VERSION: u16 = 1;
const PROCESS_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-PROCESS-LOSS/V1\0";
const PROCESS_MARKER_LEN: usize = 8 + 2 + 32 + 32 + 32 + 32;

/// One-shot authority to abort exactly after one new envelope commit and
/// before its ACK can be returned.
pub struct RelayProcessLossFaultV1 {
    database_id: RelayDatabaseIdV1,
    key: IdempotencyKeyV1,
    envelope_digest: Digest32,
}

impl core::fmt::Debug for RelayProcessLossFaultV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RelayProcessLossFaultV1")
            .field("database_id", &self.database_id)
            .field("key", &self.key)
            .field("envelope_digest", &self.envelope_digest)
            .finish()
    }
}

impl RelayProcessLossFaultV1 {
    /// Binds the destructive cut to one database, key and envelope digest.
    pub const fn new(
        database_id: RelayDatabaseIdV1,
        key: IdempotencyKeyV1,
        envelope_digest: Digest32,
    ) -> Self {
        Self {
            database_id,
            key,
            envelope_digest,
        }
    }
}

/// One-shot authority to destroy only the exact SQLite files of one open
/// Relay database. The retained root identity and lock are never removed.
pub struct RelayDatabaseLossFaultV1 {
    database_id: RelayDatabaseIdV1,
}

impl core::fmt::Debug for RelayDatabaseLossFaultV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("RelayDatabaseLossFaultV1")
            .field(&self.database_id)
            .finish()
    }
}

impl RelayDatabaseLossFaultV1 {
    /// Binds the destructive cut to one database identity.
    pub const fn new(database_id: RelayDatabaseIdV1) -> Self {
        Self { database_id }
    }
}

/// Public receipt that the exact database-loss marker and deletion completed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RelayDatabaseLossReceiptV1 {
    database_id: RelayDatabaseIdV1,
    marker_digest: Digest32,
}

impl RelayDatabaseLossReceiptV1 {
    /// Database whose files were removed.
    pub const fn database_id(&self) -> RelayDatabaseIdV1 {
        self.database_id
    }

    /// Digest of the durable public loss marker.
    pub const fn marker_digest(&self) -> &Digest32 {
        &self.marker_digest
    }
}

impl ProductionRelayV1 {
    /// Commits a new row, durably publishes the exact fired marker and aborts
    /// before returning the ACK. If the row already existed (the resumed
    /// exact resend), this method returns the persisted ACK and does not abort
    /// again.
    pub fn submit_with_process_loss_fault(
        &mut self,
        raw: &[u8],
        fault: RelayProcessLossFaultV1,
    ) -> Result<AckV1, ProductionRelayError> {
        if self.database_id() != fault.database_id {
            return Err(ProductionRelayError::WrongDatabaseIdentity);
        }
        let envelope = crate::RelayEnvelopeV1::decode(raw).map_err(ProductionRelayError::Codec)?;
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(ProductionRelayError::Codec)?;
        if IdempotencyKeyV1::of(&envelope) != fault.key || envelope_digest != fault.envelope_digest
        {
            return Err(ProductionRelayError::InvalidConfiguration);
        }
        let (ack, inserted) = self.submit_durable(raw)?;
        if ack.digest != fault.envelope_digest {
            return Err(ProductionRelayError::CorruptState);
        }
        if inserted {
            publish_process_marker(
                &self.root_path_for_fault(),
                fault.database_id,
                &fault.key,
                &fault.envelope_digest,
            )?;
            std::process::abort();
        }
        Ok(ack)
    }

    /// Closes SQLite, publishes a durable database-loss marker, removes only
    /// the exact database/WAL/SHM objects, and fsyncs the retained root.
    ///
    /// This consumes the open Relay, preventing any use-after-loss. Opening
    /// afterwards returns `DatabaseMissing`; only authenticated
    /// reconstruction may make the root usable again.
    pub fn destroy_database_with_fault(
        self,
        fault: RelayDatabaseLossFaultV1,
    ) -> Result<RelayDatabaseLossReceiptV1, ProductionRelayError> {
        if self.database_id() != fault.database_id {
            return Err(ProductionRelayError::WrongDatabaseIdentity);
        }
        let (connection, root, config, lock) = self.into_fault_parts();
        drop(connection);
        validate_root(&root)?;
        let marker = database_loss_marker(config.database_id())?;
        publish_marker(&root, RELAY_DATABASE_LOSS_MARKER_NAME, &marker, false)?;
        reject_unknown_database_objects(&root)?;
        let database = root.join(RELAY_DATABASE_FILE_NAME);
        if !database
            .try_exists()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?
        {
            return Err(ProductionRelayError::DatabaseMissing);
        }
        for name in [
            RELAY_DATABASE_FILE_NAME.to_owned(),
            format!("{RELAY_DATABASE_FILE_NAME}-wal"),
            format!("{RELAY_DATABASE_FILE_NAME}-shm"),
        ] {
            let path = root.join(name);
            match path.try_exists() {
                Ok(true) => {
                    validate_owner_file(&path)?;
                    fs::remove_file(path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
                }
                Ok(false) => {}
                Err(_) => return Err(ProductionRelayError::StorageUnavailable),
            }
        }
        File::open(&root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProductionRelayError::StorageUnavailable)?;
        drop(lock);
        let marker_digest = digest_parts(DATABASE_LOSS_DOMAIN, &[&marker])?;
        Ok(RelayDatabaseLossReceiptV1 {
            database_id: config.database_id(),
            marker_digest,
        })
    }

    fn root_path_for_fault(&self) -> std::path::PathBuf {
        // Kept private to the fault-enabled build; production APIs never
        // disclose the retained root path.
        self.fault_root_clone()
    }
}

/// Verifies the exact public fired marker after the child process aborted.
pub fn verify_process_loss_marker_v1(
    root: &Path,
    database_id: RelayDatabaseIdV1,
    key: &IdempotencyKeyV1,
    envelope_digest: &Digest32,
) -> Result<bool, ProductionRelayError> {
    validate_root(root)?;
    let path = root.join(RELAY_PROCESS_LOSS_MARKER_NAME);
    if !path
        .try_exists()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?
    {
        return Ok(false);
    }
    validate_owner_file(&path)?;
    let bytes = read_bounded(&path, PROCESS_MARKER_LEN)?;
    Ok(bytes == process_marker(database_id, key, envelope_digest)?.as_slice())
}

/// Verifies the exact public marker after the bounded database-loss cut.
pub fn verify_database_loss_marker_v1(
    root: &Path,
    database_id: RelayDatabaseIdV1,
) -> Result<bool, ProductionRelayError> {
    validate_root(root)?;
    let path = root.join(RELAY_DATABASE_LOSS_MARKER_NAME);
    if !path
        .try_exists()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?
    {
        return Ok(false);
    }
    validate_owner_file(&path)?;
    let expected = database_loss_marker(database_id)?;
    Ok(read_bounded(&path, expected.len())? == expected.as_slice())
}

fn publish_process_marker(
    root: &Path,
    database_id: RelayDatabaseIdV1,
    key: &IdempotencyKeyV1,
    envelope_digest: &Digest32,
) -> Result<(), ProductionRelayError> {
    let marker = process_marker(database_id, key, envelope_digest)?;
    publish_marker(root, RELAY_PROCESS_LOSS_MARKER_NAME, &marker, true)
}

fn publish_marker(
    root: &Path,
    name: &str,
    bytes: &[u8],
    reject_existing: bool,
) -> Result<(), ProductionRelayError> {
    validate_root(root)?;
    let path = root.join(name);
    if path
        .try_exists()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?
    {
        if reject_existing {
            return Err(ProductionRelayError::CorruptState);
        }
        validate_owner_file(&path)?;
        if read_bounded(&path, bytes.len())? == bytes {
            return Ok(());
        }
        return Err(ProductionRelayError::CorruptState);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&path)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    validate_owner_file(&path)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)
}

fn process_marker(
    database_id: RelayDatabaseIdV1,
    key: &IdempotencyKeyV1,
    envelope_digest: &Digest32,
) -> Result<[u8; PROCESS_MARKER_LEN], ProductionRelayError> {
    let key_digest = key_digest(key)?;
    let checksum = digest_parts(
        PROCESS_DOMAIN,
        &[
            database_id.as_bytes(),
            key_digest.as_slice(),
            envelope_digest.as_slice(),
        ],
    )?;
    let mut marker = [0_u8; PROCESS_MARKER_LEN];
    marker[..8].copy_from_slice(PROCESS_MAGIC);
    marker[8..10].copy_from_slice(&MARKER_VERSION.to_be_bytes());
    marker[10..42].copy_from_slice(database_id.as_bytes());
    marker[42..74].copy_from_slice(&key_digest);
    marker[74..106].copy_from_slice(envelope_digest);
    marker[106..].copy_from_slice(&checksum);
    Ok(marker)
}

fn key_digest(key: &IdempotencyKeyV1) -> Result<Digest32, ProductionRelayError> {
    digest_parts(
        PROCESS_DOMAIN,
        &[
            key.session_id.as_slice(),
            key.sender_id.0.as_slice(),
            key.recipient_id.0.as_slice(),
            key.sequence.to_be_bytes().as_slice(),
        ],
    )
}

fn reject_unknown_database_objects(root: &Path) -> Result<(), ProductionRelayError> {
    for entry in fs::read_dir(root).map_err(|_| ProductionRelayError::StorageUnavailable)? {
        let entry = entry.map_err(|_| ProductionRelayError::StorageUnavailable)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ProductionRelayError::InvalidConfiguration)?;
        if name.starts_with(RELAY_DATABASE_FILE_NAME) && !matches_database_object(&name) {
            return Err(ProductionRelayError::CorruptState);
        }
    }
    Ok(())
}

fn matches_database_object(name: &str) -> bool {
    name == RELAY_DATABASE_FILE_NAME
        || name == format!("{RELAY_DATABASE_FILE_NAME}-wal")
        || name == format!("{RELAY_DATABASE_FILE_NAME}-shm")
}

fn read_bounded(path: &Path, expected: usize) -> Result<Vec<u8>, ProductionRelayError> {
    let mut file = File::open(path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
    let mut bytes = Vec::with_capacity(expected + 1);
    Read::by_ref(&mut file)
        .take((expected + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if bytes.len() != expected {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(bytes)
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ProductionRelayError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ProductionRelayError::CorruptState)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0_u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProductionRelayError::CorruptState)?;
    Ok(digest)
}

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use btc_crypto::SecpContext;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;

use crate::signed::MAX_SIGNED_BYTES;
use crate::{
    AuthoritySetV1, RegistryError, RegistryValidationPolicyV1, ResolvedRegistryV1, Result,
    SignedRegistryV1,
};

const SCHEMA_VERSION: i64 = 1;
const MAX_HISTORY_ROWS: u64 = 4_096;
#[cfg(target_os = "linux")]
const DIRECTORY_MODE: u32 = 0o700;
#[cfg(target_os = "linux")]
const FILE_MODE: u32 = 0o600;

/// Result of atomically installing an authenticated registry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstallOutcomeV1 {
    /// A strictly newer epoch became current.
    Installed,
    /// The same canonical manifest was already current.
    AlreadyCurrent,
}

/// SQLite/WAL authority for the monotonic current deployment registry.
pub struct RegistryStoreV1 {
    connection: Connection,
}

impl core::fmt::Debug for RegistryStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RegistryStoreV1([redacted path])")
    }
}

impl RegistryStoreV1 {
    /// Compatibility open-or-create path for developer tools. Production
    /// composition roots must use [`Self::create`] or [`Self::open_existing`]
    /// so loss cannot silently become a fresh empty database.
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path).map_err(|_| RegistryError::StorageUnavailable)?;
        configure(&connection)?;
        let mut store = Self { connection };
        store.migrate()?;
        validate_backend_and_schema(&store.connection)?;
        Ok(store)
    }

    /// Creates one new owner-only registry database and refuses replacement.
    pub fn create(path: &Path) -> Result<Self> {
        if fs::symlink_metadata(path).is_ok() {
            return Err(RegistryError::DatabasePresent);
        }
        #[cfg(target_os = "linux")]
        validate_owner_directory(
            path.parent()
                .ok_or(RegistryError::InvalidStorageAuthority)?,
        )?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(target_os = "linux")]
        options.mode(FILE_MODE);
        let file = options
            .open(path)
            .map_err(|_| RegistryError::StorageUnavailable)?;
        file.sync_all()
            .map_err(|_| RegistryError::StorageUnavailable)?;
        drop(file);
        #[cfg(target_os = "linux")]
        validate_owner_file(path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| RegistryError::StorageUnavailable)?;
        configure(&connection)?;
        validate_database_path(&connection, path)?;
        let mut store = Self { connection };
        store.migrate()?;
        validate_backend_and_schema(&store.connection)?;
        Ok(store)
    }

    /// Opens only a pre-existing owner-only registry and never initializes or
    /// repairs schema. Missing, symlinked or structurally divergent state is a
    /// startup refusal.
    pub fn open_existing(path: &Path) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(RegistryError::DatabaseMissing)
            }
            Err(_) => return Err(RegistryError::StorageUnavailable),
        }
        #[cfg(target_os = "linux")]
        {
            validate_owner_directory(
                path.parent()
                    .ok_or(RegistryError::InvalidStorageAuthority)?,
            )?;
            validate_owner_file(path)?;
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| RegistryError::StorageUnavailable)?;
        configure(&connection)?;
        validate_database_path(&connection, path)?;
        validate_backend_and_schema(&connection)?;
        Ok(Self { connection })
    }

    fn migrate(&mut self) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RegistryError::StorageUnavailable)?;
        let found: i64 = transaction
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|_| RegistryError::StorageUnavailable)?;
        if found > SCHEMA_VERSION {
            return Err(RegistryError::CorruptState);
        }
        if found < 1 {
            transaction
                .execute_batch(
                    "CREATE TABLE registry_current (
                         singleton      INTEGER PRIMARY KEY CHECK(singleton = 1),
                         epoch_be       BLOB NOT NULL CHECK(length(epoch_be) = 8),
                         manifest_digest BLOB NOT NULL CHECK(length(manifest_digest) = 32),
                         network_id     BLOB NOT NULL CHECK(length(network_id) = 32),
                         signed_bytes   BLOB NOT NULL,
                         installed_at_be BLOB NOT NULL CHECK(length(installed_at_be) = 8)
                     ) STRICT;
                     CREATE TABLE registry_history (
                         manifest_digest BLOB PRIMARY KEY CHECK(length(manifest_digest) = 32),
                         epoch_be       BLOB NOT NULL CHECK(length(epoch_be) = 8),
                         network_id     BLOB NOT NULL CHECK(length(network_id) = 32),
                         signed_bytes   BLOB NOT NULL,
                         installed_at_be BLOB NOT NULL CHECK(length(installed_at_be) = 8)
                     ) STRICT;",
                )
                .map_err(|_| RegistryError::StorageUnavailable)?;
        }
        transaction
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|_| RegistryError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| RegistryError::StorageUnavailable)
    }

    /// Verifies and atomically installs a strictly newer manifest.
    ///
    /// `policy.minimum_epoch` must be anchored outside this replaceable SQLite
    /// file. That external pin is what detects restoration of an older complete
    /// database; the in-file epoch prevents ordinary stale updates.
    pub fn install(
        &mut self,
        signed: &SignedRegistryV1,
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        policy: RegistryValidationPolicyV1,
    ) -> Result<(InstallOutcomeV1, ResolvedRegistryV1)> {
        let resolved = signed.verify(authorities, secp, policy)?;
        let signed_bytes = signed.canonical_bytes()?;
        let digest = resolved.manifest_digest();
        let epoch = resolved.epoch();
        let network_id = resolved.manifest().network_id;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RegistryError::StorageUnavailable)?;
        validate_stored_blob_bounds(&transaction)?;
        let history_high_watermark =
            authenticate_history(&transaction, authorities, secp, policy.expected_network_id)?;
        let current = transaction
            .query_row(
                "SELECT epoch_be, manifest_digest, network_id, signed_bytes
                 FROM registry_current WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| RegistryError::StorageUnavailable)?;
        if let Some((stored_epoch, stored_digest, stored_network, stored_signed)) = current {
            // The duplicate columns are indexes only. Authenticate the retained
            // envelope before using any of them for a monotonicity decision.
            // Freshness and the external minimum are intentionally not applied
            // to retained material: an expired epoch must still prevent an
            // authenticated rollback while a replacement is installed.
            let retained = SignedRegistryV1::decode(&stored_signed)
                .and_then(|value| {
                    value.verify_authenticity(authorities, secp, policy.expected_network_id)
                })
                .map_err(|_| RegistryError::CorruptState)?;
            let indexed_epoch = decode_u64(&stored_epoch)?;
            let indexed_digest = decode_32(&stored_digest)?;
            let indexed_network = decode_32(&stored_network)?;
            let retained_epoch = retained.epoch();
            let retained_digest = retained.manifest_digest();
            let retained_network = retained.manifest().network_id;
            if indexed_epoch != retained_epoch
                || indexed_digest != retained_digest
                || indexed_network != retained_network
            {
                return Err(RegistryError::CorruptState);
            }
            if match history_high_watermark.as_ref() {
                None => true,
                Some((history_epoch, history_digest)) => {
                    *history_epoch != retained_epoch || *history_digest != retained_digest
                }
            } {
                return Err(RegistryError::CorruptState);
            }
            if let Some((history_epoch, history_digest)) = history_high_watermark {
                if epoch < history_epoch || (epoch == history_epoch && digest != history_digest) {
                    return Err(RegistryError::Rollback);
                }
            }
            if epoch < retained_epoch || (epoch == retained_epoch && digest != retained_digest) {
                return Err(RegistryError::Rollback);
            }
            if epoch == retained_epoch {
                if retained_network != network_id {
                    return Err(RegistryError::CorruptState);
                }
                transaction
                    .commit()
                    .map_err(|_| RegistryError::StorageUnavailable)?;
                return Ok((InstallOutcomeV1::AlreadyCurrent, resolved));
            }
        } else if history_high_watermark.is_some() {
            return Err(RegistryError::CorruptState);
        }
        transaction
            .execute(
                "INSERT INTO registry_history(
                     manifest_digest, epoch_be, network_id, signed_bytes, installed_at_be
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(manifest_digest) DO NOTHING",
                params![
                    digest.as_slice(),
                    epoch.to_be_bytes().as_slice(),
                    network_id.as_slice(),
                    signed_bytes.as_slice(),
                    policy.now_seconds.to_be_bytes().as_slice(),
                ],
            )
            .map_err(|_| RegistryError::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO registry_current(
                     singleton, epoch_be, manifest_digest, network_id,
                     signed_bytes, installed_at_be
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(singleton) DO UPDATE SET
                     epoch_be = excluded.epoch_be,
                     manifest_digest = excluded.manifest_digest,
                     network_id = excluded.network_id,
                     signed_bytes = excluded.signed_bytes,
                     installed_at_be = excluded.installed_at_be",
                params![
                    epoch.to_be_bytes().as_slice(),
                    digest.as_slice(),
                    network_id.as_slice(),
                    signed_bytes.as_slice(),
                    policy.now_seconds.to_be_bytes().as_slice(),
                ],
            )
            .map_err(|_| RegistryError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| RegistryError::StorageUnavailable)?;
        Ok((InstallOutcomeV1::Installed, resolved))
    }

    /// Loads and re-verifies the durable current registry under current policy.
    pub fn load_current(
        &self,
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        policy: RegistryValidationPolicyV1,
    ) -> Result<Option<ResolvedRegistryV1>> {
        let stored = self
            .connection
            .query_row(
                "SELECT epoch_be, manifest_digest, network_id, signed_bytes
                 FROM registry_current WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| RegistryError::StorageUnavailable)?;
        let Some((epoch_bytes, digest_bytes, network_bytes, signed_bytes)) = stored else {
            return Ok(None);
        };
        let stored_epoch = decode_u64(&epoch_bytes)?;
        let stored_digest = decode_32(&digest_bytes)?;
        let stored_network = decode_32(&network_bytes)?;
        let signed = SignedRegistryV1::decode(&signed_bytes)?;
        let resolved = signed.verify(authorities, secp, policy)?;
        if resolved.epoch() != stored_epoch
            || resolved.manifest_digest() != stored_digest
            || resolved.manifest().network_id != stored_network
        {
            return Err(RegistryError::CorruptState);
        }
        Ok(Some(resolved))
    }

    /// Loads one exact historical registry by its authenticated manifest
    /// digest for recovery of an already-admitted route. Freshness and the
    /// external minimum are intentionally not reapplied: they govern new
    /// admissions, while open routes must retain their frozen epoch.
    pub fn load_pinned(
        &self,
        manifest_digest: [u8; 32],
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        expected_network_id: [u8; 32],
    ) -> Result<Option<ResolvedRegistryV1>> {
        if manifest_digest == [0; 32] || expected_network_id == [0; 32] {
            return Err(RegistryError::ZeroField);
        }
        let length: Option<i64> = self
            .connection
            .query_row(
                "SELECT length(signed_bytes) FROM registry_history
                 WHERE manifest_digest = ?1",
                params![manifest_digest.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| RegistryError::StorageUnavailable)?;
        let Some(length) = length else {
            return Ok(None);
        };
        if length < 0 || usize::try_from(length).map_or(true, |value| value > MAX_SIGNED_BYTES) {
            return Err(RegistryError::CorruptState);
        }
        let (epoch_bytes, network_bytes, signed_bytes): (Vec<u8>, Vec<u8>, Vec<u8>) = self
            .connection
            .query_row(
                "SELECT epoch_be, network_id, signed_bytes FROM registry_history
                 WHERE manifest_digest = ?1",
                params![manifest_digest.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| RegistryError::StorageUnavailable)?;
        let indexed_epoch = decode_u64(&epoch_bytes)?;
        let indexed_network = decode_32(&network_bytes)?;
        let resolved = SignedRegistryV1::decode(&signed_bytes)
            .and_then(|value| value.verify_authenticity(authorities, secp, expected_network_id))
            .map_err(|_| RegistryError::CorruptState)?;
        if resolved.manifest_digest() != manifest_digest
            || resolved.epoch() != indexed_epoch
            || resolved.manifest().network_id != indexed_network
        {
            return Err(RegistryError::CorruptState);
        }
        Ok(Some(resolved))
    }

    /// Reads the durable epoch without treating it as authenticated runtime data.
    pub fn current_epoch(&self) -> Result<Option<u64>> {
        let value = self
            .connection
            .query_row(
                "SELECT epoch_be FROM registry_current WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| RegistryError::StorageUnavailable)?;
        value.map(|bytes| decode_u64(&bytes)).transpose()
    }
}

fn configure(connection: &Connection) -> Result<()> {
    connection
        .busy_timeout(Duration::from_millis(5_000))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(RegistryError::StorageUnavailable);
    }
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| RegistryError::StorageUnavailable)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| RegistryError::StorageUnavailable)?;
    connection
        .pragma_update(None, "read_uncommitted", "OFF")
        .map_err(|_| RegistryError::StorageUnavailable)?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| RegistryError::StorageUnavailable)?;
    connection
        .pragma_update(None, "secure_delete", "ON")
        .map_err(|_| RegistryError::StorageUnavailable)?;
    connection
        .set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let read_uncommitted: i64 = connection
        .query_row("PRAGMA read_uncommitted", [], |row| row.get(0))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let secure_delete: i64 = connection
        .query_row("PRAGMA secure_delete", [], |row| row.get(0))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    if synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || secure_delete != 1
        || busy_timeout != 5_000
    {
        return Err(RegistryError::CorruptState);
    }
    Ok(())
}

fn validate_backend_and_schema(connection: &Connection) -> Result<()> {
    let quick: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    if quick != "ok" {
        return Err(RegistryError::CorruptState);
    }
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| RegistryError::StorageUnavailable)?;
    if version != SCHEMA_VERSION {
        return Err(RegistryError::CorruptState);
    }
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'",
        )
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let mut objects = BTreeSet::new();
    for row in rows {
        objects.insert(row.map_err(|_| RegistryError::StorageUnavailable)?);
    }
    let expected = BTreeSet::from([
        (
            "table".to_owned(),
            "registry_current".to_owned(),
            "registry_current".to_owned(),
        ),
        (
            "table".to_owned(),
            "registry_history".to_owned(),
            "registry_history".to_owned(),
        ),
    ]);
    if objects != expected {
        return Err(RegistryError::CorruptState);
    }
    // These reads audit the exact required columns and STRICT-compatible
    // types without trusting an attacker-added view or trigger.
    let _current_columns = connection
        .prepare(
            "SELECT singleton, epoch_be, manifest_digest, network_id,
                    signed_bytes, installed_at_be FROM registry_current LIMIT 0",
        )
        .map_err(|_| RegistryError::CorruptState)?;
    let _history_columns = connection
        .prepare(
            "SELECT manifest_digest, epoch_be, network_id, signed_bytes,
                    installed_at_be FROM registry_history LIMIT 0",
        )
        .map_err(|_| RegistryError::CorruptState)?;
    Ok(())
}

fn validate_database_path(connection: &Connection, expected_path: &Path) -> Result<()> {
    let expected =
        fs::canonicalize(expected_path).map_err(|_| RegistryError::InvalidStorageAuthority)?;
    if expected != expected_path {
        return Err(RegistryError::InvalidStorageAuthority);
    }
    let mut statement = connection
        .prepare("PRAGMA database_list")
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let mut saw_main = false;
    for row in rows {
        let (name, path) = row.map_err(|_| RegistryError::StorageUnavailable)?;
        match name.as_str() {
            "main" if Path::new(&path) == expected => saw_main = true,
            "temp" if path.is_empty() => {}
            _ => return Err(RegistryError::InvalidStorageAuthority),
        }
    }
    if !saw_main {
        return Err(RegistryError::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owner_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RegistryError::InvalidStorageAuthority)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != DIRECTORY_MODE
        || metadata.nlink() == 0
    {
        return Err(RegistryError::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owner_file(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RegistryError::InvalidStorageAuthority)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(RegistryError::InvalidStorageAuthority);
    }
    Ok(())
}

fn validate_stored_blob_bounds(transaction: &rusqlite::Transaction<'_>) -> Result<()> {
    let maximum: Option<i64> = transaction
        .query_row(
            "SELECT MAX(blob_length) FROM (
                 SELECT length(signed_bytes) AS blob_length FROM registry_current
                 UNION ALL
                 SELECT length(signed_bytes) AS blob_length FROM registry_history
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RegistryError::StorageUnavailable)?;
    if maximum.is_some_and(|value| {
        value < 0 || usize::try_from(value).map_or(true, |length| length > MAX_SIGNED_BYTES)
    }) {
        return Err(RegistryError::CorruptState);
    }
    Ok(())
}

fn authenticate_history(
    transaction: &rusqlite::Transaction<'_>,
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
    expected_network_id: [u8; 32],
) -> Result<Option<(u64, [u8; 32])>> {
    let count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM registry_history", [], |row| {
            row.get(0)
        })
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let count = u64::try_from(count).map_err(|_| RegistryError::CorruptState)?;
    if count > MAX_HISTORY_ROWS {
        return Err(RegistryError::BoundExceeded);
    }
    let mut statement = transaction
        .prepare(
            "SELECT epoch_be, manifest_digest, network_id, signed_bytes
             FROM registry_history",
        )
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|_| RegistryError::StorageUnavailable)?;
    let mut epochs = BTreeMap::new();
    for row in rows {
        let (epoch_bytes, digest_bytes, network_bytes, signed_bytes) =
            row.map_err(|_| RegistryError::StorageUnavailable)?;
        let indexed_epoch = decode_u64(&epoch_bytes)?;
        let indexed_digest = decode_32(&digest_bytes)?;
        let indexed_network = decode_32(&network_bytes)?;
        let retained = SignedRegistryV1::decode(&signed_bytes)
            .and_then(|value| value.verify_authenticity(authorities, secp, expected_network_id))
            .map_err(|_| RegistryError::CorruptState)?;
        if retained.epoch() != indexed_epoch
            || retained.manifest_digest() != indexed_digest
            || retained.manifest().network_id != indexed_network
        {
            return Err(RegistryError::CorruptState);
        }
        if epochs
            .insert(indexed_epoch, indexed_digest)
            .is_some_and(|previous| previous != indexed_digest)
        {
            return Err(RegistryError::CorruptState);
        }
    }
    Ok(epochs.into_iter().next_back())
}

fn decode_u64(bytes: &[u8]) -> Result<u64> {
    let array: [u8; 8] = bytes.try_into().map_err(|_| RegistryError::CorruptState)?;
    Ok(u64::from_be_bytes(array))
}

fn decode_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| RegistryError::CorruptState)
}

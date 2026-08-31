//! Owner-only durable Bitcoin actuation store.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use adapter_btc::timelock::AnchoredCrossChainWindowV1;
use adapter_btc_live::{
    ArmedBitcoinFundingV1, BitcoinCoreNetworkV1, BitcoinCoreRpcClientV1,
    BitcoinExternalFundingCustodyV1, BitcoinPrebroadcastStoreV1,
};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::Transaction;
use btc_crypto::NonceParity;
use btc_vault::{BitcoinNonceSealKeyV1, BitcoinNonceVault, VaultError};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

#[cfg(target_os = "linux")]
use rustix::fs::{flock, fstat, FileType, FlockOperation, Mode};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;

use crate::model::{
    chain_identity_digest, digest, funding_custody_locator, terminal_custody_locator,
    validate_replacement, validate_terminal_transaction, BitcoinActionV1, BitcoinActuationScopeV1,
    BitcoinBroadcastReceiptV1, BitcoinDurableOperationViewV1, BitcoinFundingCustodyViewV1,
    BitcoinOperationBindingViewV1, BitcoinOperationKindV1, BitcoinOperationLocatorV1,
    BitcoinOperationStageV1, BitcoinOperationViewV1, BitcoinPortCallJournalStatusV1,
    BitcoinPortCallKeyV1, BitcoinPortCallKindV1, BitcoinPortCallOutcomeV1, BitcoinReconciliationV1,
    BitcoinStorageLeaseStatusV1, ExactBitcoinTransactionV1,
};
use crate::rpc::{BitcoinRpcBroadcastV1, BitcoinRpcLookupV1, BitcoinRpcV1};
use crate::signer::{
    aggregate_pre_signature, expose_local_pubnonce, produce_local_partial,
    validate_claim_authority, AggregatePreSignatureRequestV1, BitcoinClaimSessionV1,
    BitcoinLocalPartialV1, BitcoinLocalPubNonceV1, BitcoinParticipantClaimAuthorityV1,
    BitcoinPreSignatureV1,
};
use crate::{BitcoinActuatorErrorV1, Result};

// Deliberately no in-place migration: opening an older shape must fail closed
// instead of inventing durable outcomes for child-port calls that may already
// have returned before the journal existed.
const SCHEMA_VERSION: i64 = 4;
const APPLICATION_ID: i64 = 0x444f_4d42;
const OWNER_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/OWNER/V1\0";
const MAX_LEASE_MS: u64 = 24 * 60 * 60 * 1000;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

type ClaimTakeoverRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type ClaimIdentityRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

/// Durable Bitcoin actuator composition root.
///
/// A process retains one owner identity and an exclusive lock on an exact
/// owner-only SQLite authority. Raw claim/refund transactions never leave the
/// store except for the one bounded RPC call. The type intentionally has no
/// `Debug`, `Clone`, or codec implementation.
pub struct DurableBitcoinActuatorV1 {
    connection: Connection,
    owner_digest: [u8; 32],
    path: PathBuf,
    lock_path: PathBuf,
    authority_file: File,
    lock_file: File,
    authority_identity: RetainedFileIdentityV1,
    lock_identity: RetainedFileIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedFileIdentityV1 {
    device: u64,
    inode: u64,
}

struct OpenedAuthorityV1 {
    connection: Connection,
    authority_file: File,
    lock_file: File,
    authority_identity: RetainedFileIdentityV1,
    lock_identity: RetainedFileIdentityV1,
    lock_path: PathBuf,
}

struct PersistLookupRequestV1<'a> {
    effect_id: [u8; 32],
    raw: &'a [u8],
    old_stage: BitcoinOperationStageV1,
    never_sent: bool,
    lookup: BitcoinRpcLookupV1,
    minimum_confirmations: u32,
    now_ms: u64,
}

/// One route-scoped participant signing invocation.
///
/// Grouping the exact durable scope, participant authority, session, time
/// authorization, nonce custody and monotonic instant prevents call sites
/// from silently reordering or omitting a signing boundary.
pub struct BitcoinClaimSigningContextV1<'a> {
    /// Exact route/effect/action capability.
    pub scope: &'a BitcoinActuationScopeV1,
    /// Sole participant authority owned by this process.
    pub authority: &'a BitcoinParticipantClaimAuthorityV1,
    /// Exact two-party adaptor-signing session.
    pub session: &'a BitcoinClaimSessionV1,
    /// Authenticated cross-chain timing authorization.
    pub authorization: AnchoredCrossChainWindowV1,
    /// Key that seals participant nonce custody.
    pub seal_key: &'a BitcoinNonceSealKeyV1,
    /// Retained, route-bound participant nonce authority.
    pub participant_state: &'a mut BitcoinParticipantNonceVaultV1,
    /// Monotonic operation instant in milliseconds.
    pub now_ms: u64,
}

/// Retained owner of one route-bound Bitcoin participant nonce authority.
///
/// The database path, descriptors, process lock and underlying generic vault
/// are deliberately private. Signing can reach nonce custody only through the
/// exact participant authority captured by this handle.
pub struct BitcoinParticipantNonceVaultV1 {
    vault: BitcoinNonceVault,
    authority_digest: [u8; 32],
    path: PathBuf,
    lock_path: PathBuf,
    authority_file: File,
    lock_file: File,
    authority_identity: RetainedFileIdentityV1,
    lock_identity: RetainedFileIdentityV1,
}

impl BitcoinParticipantNonceVaultV1 {
    /// Creates one new owner-only participant nonce authority.
    pub fn create(path: &Path, authority: &BitcoinParticipantClaimAuthorityV1) -> Result<Self> {
        Self::open(path, authority, AuthorityOpenModeV1::Create)
    }

    /// Reopens one fully initialized participant nonce authority.
    pub fn open_existing(
        path: &Path,
        authority: &BitcoinParticipantClaimAuthorityV1,
    ) -> Result<Self> {
        Self::open(path, authority, AuthorityOpenModeV1::OpenExisting)
    }

    /// Completes only an authenticated, economically empty creation prefix.
    pub fn resume_create_production(
        path: &Path,
        authority: &BitcoinParticipantClaimAuthorityV1,
    ) -> Result<Self> {
        Self::open(path, authority, AuthorityOpenModeV1::ResumeCreate)
    }

    /// Public commitment to the sole participant key authority this vault
    /// accepts.
    pub const fn authority_digest(&self) -> [u8; 32] {
        self.authority_digest
    }

    /// Prove that an initialized participant state is still economically empty.
    ///
    /// This is used only by an external ordered provisioning journal when a
    /// later authority in the same crash prefix has already been published.
    pub fn require_empty_production(&self) -> Result<()> {
        self.audit_storage()?;
        self.vault
            .require_empty_production()
            .map_err(map_participant_vault_open_error)?;
        self.audit_storage()
    }

    #[cfg(target_os = "linux")]
    fn open(
        path: &Path,
        authority: &BitcoinParticipantClaimAuthorityV1,
        mode: AuthorityOpenModeV1,
    ) -> Result<Self> {
        let binding = authority.authority_digest();
        if binding == [0; 32] {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        let opened = open_authority(path, mode)?;
        let OpenedAuthorityV1 {
            connection,
            authority_file,
            lock_file,
            authority_identity,
            lock_identity,
            lock_path,
        } = opened;
        drop(connection);
        test_creation_crash_hook("participant-before-schema");
        let vault = match mode {
            AuthorityOpenModeV1::Create => BitcoinNonceVault::initialize_production(path, binding)
                .map_err(map_participant_vault_open_error)?,
            AuthorityOpenModeV1::OpenExisting => BitcoinNonceVault::open_production(path, binding)
                .map_err(map_participant_vault_open_error)?,
            AuthorityOpenModeV1::ResumeCreate => {
                match BitcoinNonceVault::open_production(path, binding) {
                    Ok(vault) => {
                        vault
                            .require_empty_production()
                            .map_err(map_participant_vault_open_error)?;
                        vault
                    }
                    Err(VaultError::CreationIncomplete) => {
                        BitcoinNonceVault::initialize_production(path, binding)
                            .map_err(map_participant_vault_open_error)?
                    }
                    Err(error) => return Err(map_participant_vault_open_error(error)),
                }
            }
        };
        test_creation_crash_hook("participant-after-schema");
        let state = Self {
            vault,
            authority_digest: binding,
            path: path.to_path_buf(),
            lock_path,
            authority_file,
            lock_file,
            authority_identity,
            lock_identity,
        };
        state.audit_storage()?;
        sync_parent(path)?;
        Ok(state)
    }

    #[cfg(not(target_os = "linux"))]
    fn open(
        path: &Path,
        authority: &BitcoinParticipantClaimAuthorityV1,
        mode: AuthorityOpenModeV1,
    ) -> Result<Self> {
        let _ = (path, authority, mode);
        Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
    }

    pub(crate) fn with_vault<T>(
        &mut self,
        authority: &BitcoinParticipantClaimAuthorityV1,
        operation: impl FnOnce(&mut BitcoinNonceVault) -> Result<T>,
    ) -> Result<T> {
        if authority.authority_digest() != self.authority_digest {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        self.audit_storage()?;
        let result = operation(&mut self.vault);
        self.audit_storage()?;
        result
    }

    fn audit_storage(&self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
        #[cfg(target_os = "linux")]
        {
            validate_retained_file(
                &self.path,
                &self.authority_file,
                self.authority_identity,
                false,
            )?;
            validate_retained_file(&self.lock_path, &self.lock_file, self.lock_identity, true)?;
            validate_sidecars(&self.path)
        }
    }
}

fn map_participant_vault_open_error(error: VaultError) -> BitcoinActuatorErrorV1 {
    match error {
        VaultError::CreationIncomplete => BitcoinActuatorErrorV1::CreationIncomplete,
        VaultError::CorruptState => BitcoinActuatorErrorV1::CorruptState,
        _ => BitcoinActuatorErrorV1::ClaimNonceCustody,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityOpenModeV1 {
    Create,
    OpenExisting,
    ResumeCreate,
}

#[cfg(target_os = "linux")]
fn open_authority(path: &Path, mode: AuthorityOpenModeV1) -> Result<OpenedAuthorityV1> {
    validate_parent(path)?;
    let lock_path = lock_path(path);
    if mode == AuthorityOpenModeV1::Create {
        ensure_sidecars_absent(path)?;
        if std::fs::symlink_metadata(path).is_ok() || std::fs::symlink_metadata(&lock_path).is_ok()
        {
            return Err(BitcoinActuatorErrorV1::DatabasePresent);
        }
    }
    let lock_file = match mode {
        AuthorityOpenModeV1::Create => OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&lock_path)
            .map_err(map_create_error)?,
        AuthorityOpenModeV1::OpenExisting | AuthorityOpenModeV1::ResumeCreate => OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    if std::fs::symlink_metadata(path).is_ok() {
                        BitcoinActuatorErrorV1::InvalidStorageAuthority
                    } else {
                        BitcoinActuatorErrorV1::DatabaseMissing
                    }
                } else {
                    BitcoinActuatorErrorV1::InvalidStorageAuthority
                }
            })?,
    };
    validate_lock_file(&lock_path, &lock_file)?;
    let lock_identity = retained_identity(&lock_file)?;
    flock(lock_file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| BitcoinActuatorErrorV1::LeaseHeld)?;
    if mode == AuthorityOpenModeV1::Create {
        lock_file
            .sync_all()
            .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
        sync_parent(&lock_path)?;
        test_creation_crash_hook("after-lock-fsync");
    }

    let authority_file = match mode {
        AuthorityOpenModeV1::Create => create_database_file(path)?,
        AuthorityOpenModeV1::OpenExisting => OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BitcoinActuatorErrorV1::CreationIncomplete
            } else {
                BitcoinActuatorErrorV1::InvalidStorageAuthority
            }
        })?,
        AuthorityOpenModeV1::ResumeCreate => {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    create_database_file(path)?
                }
                Err(_) => return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority),
            }
        }
    };
    validate_authority_file(path, &authority_file)?;
    validate_sqlite_header(&authority_file, mode != AuthorityOpenModeV1::OpenExisting)?;
    let authority_identity = retained_identity(&authority_file)?;
    validate_sidecars_for_mode(path, mode)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    if retained_identity(&authority_file)? != authority_identity
        || named_identity(path)? != authority_identity
        || retained_identity(&lock_file)? != lock_identity
        || named_identity(&lock_path)? != lock_identity
    {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(OpenedAuthorityV1 {
        connection,
        authority_file,
        lock_file,
        authority_identity,
        lock_identity,
        lock_path,
    })
}

#[cfg(target_os = "linux")]
fn create_database_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(map_create_error)?;
    file.sync_all()
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    sync_parent(path)?;
    test_creation_crash_hook("after-database-fsync");
    Ok(file)
}

fn map_create_error(error: std::io::Error) -> BitcoinActuatorErrorV1 {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        BitcoinActuatorErrorV1::DatabasePresent
    } else {
        BitcoinActuatorErrorV1::InvalidStorageAuthority
    }
}

impl DurableBitcoinActuatorV1 {
    /// Creates a new owner-only authority database and refuses replacement.
    pub fn create(path: &Path, owner_id: [u8; 32]) -> Result<Self> {
        if owner_id == [0; 32] {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
        }
        #[cfg(target_os = "linux")]
        {
            let owner_digest = digest(OWNER_DOMAIN, &owner_id)?;
            let mut opened = open_authority(path, AuthorityOpenModeV1::Create)?;
            configure_creation(&opened.connection)?;
            initialize_schema(&mut opened.connection)?;
            configure(&opened.connection, true)?;
            test_creation_crash_hook("after-wal-transition");
            let store = Self {
                connection: opened.connection,
                owner_digest,
                path: path.to_path_buf(),
                lock_path: opened.lock_path,
                authority_file: opened.authority_file,
                lock_file: opened.lock_file,
                authority_identity: opened.authority_identity,
                lock_identity: opened.lock_identity,
            };
            store.audit_storage()?;
            sync_parent(path)?;
            Ok(store)
        }
    }

    /// Opens an existing authority without creating or migrating anything.
    pub fn open_existing(path: &Path, owner_id: [u8; 32]) -> Result<Self> {
        if owner_id == [0; 32] {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
        }
        #[cfg(target_os = "linux")]
        {
            let owner_digest = digest(OWNER_DOMAIN, &owner_id)?;
            let opened = open_authority(path, AuthorityOpenModeV1::OpenExisting)?;
            let version: i64 = opened
                .connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))?;
            let journal: String =
                opened
                    .connection
                    .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
            if version == 0 {
                return Err(BitcoinActuatorErrorV1::CreationIncomplete);
            }
            if !journal.eq_ignore_ascii_case("wal") {
                return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
            }
            configure(&opened.connection, false)?;
            let store = Self {
                connection: opened.connection,
                owner_digest,
                path: path.to_path_buf(),
                lock_path: opened.lock_path,
                authority_file: opened.authority_file,
                lock_file: opened.lock_file,
                authority_identity: opened.authority_identity,
                lock_identity: opened.lock_identity,
            };
            store.audit_storage()?;
            Ok(store)
        }
    }

    /// Resumes only a root whose durable provisioning journal proves creation began.
    ///
    /// The exact empty lock must already exist. The database may be absent,
    /// empty, pristine SQLite, or a fully initialized V4 authority containing
    /// no economic state. No generic open-or-create fallback exists.
    pub fn resume_create_production(path: &Path, owner_id: [u8; 32]) -> Result<Self> {
        if owner_id == [0; 32] {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
        }
        #[cfg(target_os = "linux")]
        {
            let owner_digest = digest(OWNER_DOMAIN, &owner_id)?;
            let mut opened = open_authority(path, AuthorityOpenModeV1::ResumeCreate)?;
            let version: i64 = opened
                .connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))?;
            let journal: String =
                opened
                    .connection
                    .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
            let objects: i64 = opened.connection.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            if version == 0 && objects == 0 {
                if !journal.eq_ignore_ascii_case("delete") {
                    return Err(BitcoinActuatorErrorV1::CorruptState);
                }
                configure_creation(&opened.connection)?;
                initialize_schema(&mut opened.connection)?;
            } else {
                audit_schema(&opened.connection)?;
                require_no_economic_state(&opened.connection)?;
                if journal.eq_ignore_ascii_case("delete") {
                    configure_creation(&opened.connection)?;
                } else if journal.eq_ignore_ascii_case("wal") {
                    configure(&opened.connection, false)?;
                } else {
                    return Err(BitcoinActuatorErrorV1::CorruptState);
                }
            }
            if !journal.eq_ignore_ascii_case("wal") {
                configure(&opened.connection, true)?;
            }
            let store = Self {
                connection: opened.connection,
                owner_digest,
                path: path.to_path_buf(),
                lock_path: opened.lock_path,
                authority_file: opened.authority_file,
                lock_file: opened.lock_file,
                authority_identity: opened.authority_identity,
                lock_identity: opened.lock_identity,
            };
            store.audit_storage()?;
            sync_parent(path)?;
            Ok(store)
        }
    }

    /// Acquires or takes over the process authority with a monotonic fence.
    pub fn acquire_lease(
        &mut self,
        now_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<BitcoinStorageLeaseStatusV1> {
        self.audit_storage()?;
        validate_time(now_ms, lease_duration_ms)?;
        let expires_at_ms = now_ms
            .checked_add(lease_duration_ms)
            .ok_or(BitcoinActuatorErrorV1::InvalidTime)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        let current: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT owner_digest, fence_epoch, expires_at_ms FROM authority_lease WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let fence_epoch = match current {
            Some((owner, fence, expires)) => {
                let owner = array_32(owner)?;
                let fence = decode_u64(&fence)?;
                let expires = decode_u64(&expires)?;
                if owner != self.owner_digest && expires > now_ms {
                    return Err(BitcoinActuatorErrorV1::LeaseHeld);
                }
                if owner == self.owner_digest && expires > now_ms {
                    transaction.execute(
                        "UPDATE authority_lease SET expires_at_ms = ?1 WHERE singleton = 1",
                        params![u64_blob(expires_at_ms)],
                    )?;
                    fence
                } else {
                    let next = fence
                        .checked_add(1)
                        .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
                    transaction.execute(
                        "UPDATE authority_lease SET owner_digest = ?1, fence_epoch = ?2, expires_at_ms = ?3 WHERE singleton = 1",
                        params![self.owner_digest.as_slice(), u64_blob(next), u64_blob(expires_at_ms)],
                    )?;
                    next
                }
            }
            None => {
                transaction.execute(
                    "INSERT INTO authority_lease(singleton, owner_digest, fence_epoch, expires_at_ms) VALUES(1, ?1, ?2, ?3)",
                    params![self.owner_digest.as_slice(), u64_blob(1), u64_blob(expires_at_ms)],
                )?;
                1
            }
        };
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(BitcoinStorageLeaseStatusV1 {
            fence_epoch,
            expires_at_ms,
        })
    }

    /// Renews the current owner without changing its fencing epoch.
    pub fn renew_lease(
        &mut self,
        fence_epoch: u64,
        now_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<BitcoinStorageLeaseStatusV1> {
        self.audit_storage()?;
        validate_time(now_ms, lease_duration_ms)?;
        let expires_at_ms = now_ms
            .checked_add(lease_duration_ms)
            .ok_or(BitcoinActuatorErrorV1::InvalidTime)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_lease(&transaction, &self.owner_digest, fence_epoch, now_ms)?;
        let changed = transaction.execute(
            "UPDATE authority_lease SET expires_at_ms = ?1 WHERE singleton = 1 AND owner_digest = ?2 AND fence_epoch = ?3",
            params![u64_blob(expires_at_ms), self.owner_digest.as_slice(), u64_blob(fence_epoch)],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::StaleFencing);
        }
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(BitcoinStorageLeaseStatusV1 {
            fence_epoch,
            expires_at_ms,
        })
    }

    /// Returns the last durably retained terminal-operation state by effect.
    ///
    /// This is a recovery/observation read, not a fresh chain observation: it
    /// performs no RPC, requires no live scope lease and does not advance the
    /// actuator's monotonic clock.  Callers that need current chain state must
    /// use `reconcile_terminal` first and then read this view.
    pub fn terminal_operation(&self, effect_id: [u8; 32]) -> Result<BitcoinOperationViewV1> {
        self.audit_storage()?;
        load_operation(&self.connection, effect_id)?
            .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?
            .view()
    }

    /// Returns the last durably retained funding-custody state by effect.
    ///
    /// Like [`Self::terminal_operation`], this does not contact Bitcoin Core,
    /// validate a lease or advance time.  It exposes only the state produced
    /// by the most recent durable funding transition.
    pub fn funding_operation(&self, effect_id: [u8; 32]) -> Result<BitcoinFundingCustodyViewV1> {
        self.audit_storage()?;
        load_funding(&self.connection, effect_id)?
            .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?
            .view()
    }

    /// Atomically reopens and authenticates one durable scope and raw-free view.
    pub fn operation_binding(
        &mut self,
        lease: BitcoinStorageLeaseStatusV1,
        kind: BitcoinOperationKindV1,
        effect_id: [u8; 32],
        now_ms: u64,
    ) -> Result<BitcoinOperationBindingViewV1> {
        self.audit_storage()?;
        let transaction = self.connection.transaction()?;
        advance_clock(&transaction, now_ms)?;
        let binding = load_operation_binding(
            &transaction,
            &self.owner_digest,
            lease,
            kind,
            effect_id,
            now_ms,
        )?;
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(binding)
    }

    /// Durably reserves or replays one exact coordinator child-port call.
    ///
    /// A `(call_kind, coordinator_attempt_id)` pair is globally unique. Reuse
    /// with another request or custody binding fails closed.
    pub fn begin_port_call(
        &mut self,
        lease: BitcoinStorageLeaseStatusV1,
        key: BitcoinPortCallKeyV1,
        now_ms: u64,
    ) -> Result<BitcoinPortCallJournalStatusV1> {
        self.audit_storage()?;
        validate_port_call_key(&key)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_journal_binding(&transaction, &self.owner_digest, lease, &key, now_ms)?;
        if let Some(existing) =
            load_port_call(&transaction, key.call_kind, key.coordinator_attempt_id)?
        {
            require_port_call_key(&existing, &key)?;
            let status = existing.status()?;
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(status);
        }
        transaction.execute(
            "INSERT INTO port_call_journal(
                call_kind,coordinator_attempt_id,request_digest,operation_kind,effect_id,
                scope_digest,custody_locator,outcome_bytes,outcome_digest,created_at_ms,committed_at_ms
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,NULL,NULL,?8,NULL)",
            params![
                i64::from(key.call_kind.tag()),
                key.coordinator_attempt_id.as_slice(),
                key.request_digest.as_slice(),
                i64::from(key.locator.kind().tag()),
                key.locator.effect_id().as_slice(),
                key.locator.scope_digest().as_slice(),
                key.locator.custody_locator().as_slice(),
                u64_blob(now_ms),
            ],
        )?;
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(BitcoinPortCallJournalStatusV1::Pending)
    }

    /// Commits a public stable outcome before it can be returned to a caller.
    ///
    /// Recommitting the exact outcome is an idempotent replay. A different
    /// outcome for the same attempt is an idempotency conflict.
    pub fn commit_port_call_outcome(
        &mut self,
        lease: BitcoinStorageLeaseStatusV1,
        key: BitcoinPortCallKeyV1,
        outcome: BitcoinPortCallOutcomeV1,
        now_ms: u64,
    ) -> Result<BitcoinPortCallOutcomeV1> {
        self.audit_storage()?;
        validate_port_call_key(&key)?;
        outcome.validate_for(key.call_kind)?;
        let outcome_bytes = outcome.canonical_bytes();
        let outcome_digest = outcome.digest()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_journal_binding(&transaction, &self.owner_digest, lease, &key, now_ms)?;
        let existing = load_port_call(&transaction, key.call_kind, key.coordinator_attempt_id)?
            .ok_or(BitcoinActuatorErrorV1::InvalidState)?;
        require_port_call_key(&existing, &key)?;
        if let BitcoinPortCallJournalStatusV1::Committed(committed) = existing.status()? {
            if committed.canonical_bytes() != outcome_bytes {
                return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
            }
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(committed);
        }
        let changed = transaction.execute(
            "UPDATE port_call_journal SET outcome_bytes=?1,outcome_digest=?2,committed_at_ms=?3
             WHERE call_kind=?4 AND coordinator_attempt_id=?5
               AND outcome_bytes IS NULL AND outcome_digest IS NULL AND committed_at_ms IS NULL",
            params![
                outcome_bytes.as_slice(),
                outcome_digest.as_slice(),
                u64_blob(now_ms),
                i64::from(key.call_kind.tag()),
                key.coordinator_attempt_id.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
        }
        let committed = load_port_call(&transaction, key.call_kind, key.coordinator_attempt_id)?
            .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        require_port_call_key(&committed, &key)?;
        let result = match committed.status()? {
            BitcoinPortCallJournalStatusV1::Committed(value) => value,
            BitcoinPortCallJournalStatusV1::Pending => {
                return Err(BitcoinActuatorErrorV1::CorruptState)
            }
        };
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(result)
    }

    /// Persists exact claim/refund bytes before any broadcast can occur.
    pub fn prepare_terminal(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        exact: ExactBitcoinTransactionV1,
        now_ms: u64,
    ) -> Result<BitcoinOperationViewV1> {
        self.prepare_terminal_retained(scope, &exact, now_ms)
    }

    /// Persists exact terminal bytes while their scoped owner retains the
    /// source value for an idempotent retry after a pre-commit failure.
    pub fn prepare_terminal_retained(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        exact: &ExactBitcoinTransactionV1,
        now_ms: u64,
    ) -> Result<BitcoinOperationViewV1> {
        self.audit_storage()?;
        validate_terminal_transaction(scope, exact)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        if let Some(existing) = load_operation(&transaction, scope.effect_id())? {
            require_operation_scope(&existing, scope)?;
            if existing.raw_transaction != exact.raw
                || existing.txid != exact.txid
                || existing.wtxid != exact.wtxid
                || existing.intent_digest != exact.intent_digest
                || existing.invariant_digest != exact.invariant_digest
            {
                return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
            }
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
            return existing.view();
        }
        transaction.execute(
            "INSERT INTO operations(
                effect_id, route_id, leg, action, fence_epoch, scope_bytes, scope_digest,
                txid, wtxid, intent_digest, invariant_digest, raw_transaction,
                active_generation, active_fee_sat, send_attempts, stage, confirmations,
                block_hash, block_height, evidence_digest, created_at_ms, updated_at_ms
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,0,?13,0,?14,0,NULL,NULL,NULL,?15,?15)",
            params![
                scope.effect_id().as_slice(),
                scope.route_id().as_slice(),
                i64::from(scope.leg().tag()),
                i64::from(scope.action().tag()),
                u64_blob(scope.fence_epoch()),
                scope.canonical_bytes(),
                scope.scope_digest().as_slice(),
                exact.txid.as_slice(),
                exact.wtxid.as_slice(),
                exact.intent_digest.as_slice(),
                exact.invariant_digest.as_slice(),
                exact.raw,
                u64_blob(scope.fee_policy().initial_fee_sat),
                i64::from(BitcoinOperationStageV1::Prepared.tag()),
                u64_blob(now_ms),
            ],
        )?;
        transaction.execute(
            "INSERT INTO transaction_attempts(effect_id,generation,txid,wtxid,intent_digest,invariant_digest,raw_transaction,fee_sat) VALUES(?1,0,?2,?3,?4,?5,?6,?7)",
            params![
                scope.effect_id().as_slice(), exact.txid.as_slice(), exact.wtxid.as_slice(),
                exact.intent_digest.as_slice(), exact.invariant_digest.as_slice(), exact.raw,
                u64_blob(scope.fee_policy().initial_fee_sat),
            ],
        )?;
        let stored = load_operation(&transaction, scope.effect_id())?
            .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        stored.view()
    }

    /// Broadcasts the active exact transaction with persist-before-send ordering.
    pub fn broadcast_terminal<R: BitcoinRpcV1>(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        rpc: &mut R,
        now_ms: u64,
    ) -> Result<BitcoinBroadcastReceiptV1> {
        self.audit_storage()?;
        rpc.verify_scope(scope)?;
        let (raw, txid, intent_digest, attempt, already_complete) = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            advance_clock(&transaction, now_ms)?;
            require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
            let stored = load_operation(&transaction, scope.effect_id())?
                .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
            require_operation_scope(&stored, scope)?;
            if !scope.action().is_terminal() {
                return Err(BitcoinActuatorErrorV1::InvalidScope);
            }
            require_terminal_choice(&transaction, scope, stored.txid)?;
            if stored.stage == BitcoinOperationStageV1::Final {
                audit_runtime_state(&transaction, &self.owner_digest)?;
                transaction.commit()?;
                self.audit_storage()?;
                (
                    stored.raw_transaction,
                    stored.txid,
                    stored.intent_digest,
                    stored.send_attempts,
                    true,
                )
            } else {
                let attempt = stored
                    .send_attempts
                    .checked_add(1)
                    .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
                transaction.execute(
                    "UPDATE operations SET send_attempts=?1, stage=?2, updated_at_ms=?3 WHERE effect_id=?4 AND fence_epoch=?5",
                    params![
                        i64::from(attempt), i64::from(BitcoinOperationStageV1::SendAttempted.tag()),
                        u64_blob(now_ms), scope.effect_id().as_slice(), u64_blob(scope.fence_epoch()),
                    ],
                )?;
                audit_runtime_state(&transaction, &self.owner_digest)?;
                transaction.commit()?;
                self.audit_storage()?;
                (
                    stored.raw_transaction,
                    stored.txid,
                    stored.intent_digest,
                    attempt,
                    false,
                )
            }
        };
        if already_complete {
            return Ok(BitcoinBroadcastReceiptV1 {
                effect_id: scope.effect_id(),
                txid,
                intent_digest,
                already_known: true,
                attempt,
            });
        }
        let outcome = rpc.broadcast_exact(&raw, txid);
        self.audit_storage()?;
        let already_known = match outcome {
            Ok(BitcoinRpcBroadcastV1::Accepted { txid: returned }) if returned == txid => false,
            Ok(BitcoinRpcBroadcastV1::AlreadyKnown { txid: returned }) if returned == txid => true,
            Ok(_) => return Err(BitcoinActuatorErrorV1::TransactionMismatch),
            Err(_broadcast_error) => {
                let lookup = rpc.lookup_exact(txid);
                self.audit_storage()?;
                match lookup {
                    Ok(BitcoinRpcLookupV1::Mempool(observed))
                        if observed.raw_transaction == raw =>
                    {
                        true
                    }
                    Ok(BitcoinRpcLookupV1::Confirmed { transaction, .. })
                        if transaction.raw_transaction == raw =>
                    {
                        true
                    }
                    Ok(BitcoinRpcLookupV1::Absent { evidence_digest }) => {
                        self.mark_ambiguous(scope, evidence_digest, now_ms)?;
                        return Err(BitcoinActuatorErrorV1::ExternalizationAmbiguous);
                    }
                    Ok(_) => return Err(BitcoinActuatorErrorV1::TransactionMismatch),
                    Err(_) => return Err(BitcoinActuatorErrorV1::ExternalizationAmbiguous),
                }
            }
        };
        self.audit_storage()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        let stored = load_operation(&transaction, scope.effect_id())?
            .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
        require_operation_scope(&stored, scope)?;
        if stored.txid != txid
            || stored.intent_digest != intent_digest
            || stored.send_attempts != attempt
        {
            return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
        }
        transaction.execute(
            "UPDATE operations SET stage=?1, updated_at_ms=?2 WHERE effect_id=?3 AND fence_epoch=?4",
            params![
                i64::from(BitcoinOperationStageV1::BroadcastAcknowledged.tag()),
                u64_blob(now_ms), scope.effect_id().as_slice(), u64_blob(scope.fence_epoch()),
            ],
        )?;
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(BitcoinBroadcastReceiptV1 {
            effect_id: scope.effect_id(),
            txid,
            intent_digest,
            already_known,
            attempt,
        })
    }

    /// Reconciles the exact active bytes against mempool and canonical chain.
    pub fn reconcile_terminal<R: BitcoinRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        rpc: &mut R,
        now_ms: u64,
        post_rpc_time: F,
    ) -> Result<BitcoinReconciliationV1> {
        self.audit_storage()?;
        rpc.verify_scope(scope)?;
        let (raw, txid, stage, never_sent) = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Deferred)?;
            require_clock_not_regressed(&transaction, now_ms)?;
            require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
            let stored = load_operation(&transaction, scope.effect_id())?
                .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
            require_operation_scope(&stored, scope)?;
            let result = (
                stored.raw_transaction,
                stored.txid,
                stored.stage,
                stored.active_generation == 0 && stored.send_attempts == 0,
            );
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
            result
        };
        let lookup = rpc.lookup_exact(txid);
        self.audit_storage()?;
        let lookup = lookup?;
        let post_rpc_now_ms = post_rpc_time()?;
        require_post_rpc_time(now_ms, post_rpc_now_ms)?;
        self.persist_terminal_lookup(scope, &raw, stage, never_sent, lookup, post_rpc_now_ms)
    }

    /// Persists a semantically fixed, fee-increased RBF generation before send.
    pub fn prepare_replacement(
        &mut self,
        current_scope: &BitcoinActuationScopeV1,
        replacement_scope: &BitcoinActuationScopeV1,
        replacement: ExactBitcoinTransactionV1,
        now_ms: u64,
    ) -> Result<BitcoinOperationViewV1> {
        self.audit_storage()?;
        if !current_scope.same_replacement_family(replacement_scope)
            || replacement_scope.expected_txid() != replacement.txid
            || replacement_scope.intent_digest() != replacement.intent_digest
        {
            return Err(BitcoinActuatorErrorV1::UnsafeReplacement);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, current_scope, now_ms)?;
        let stored = load_operation(&transaction, current_scope.effect_id())?
            .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
        require_operation_scope(&stored, current_scope)?;
        if stored.stage != BitcoinOperationStageV1::MempoolObserved {
            return Err(BitcoinActuatorErrorV1::InvalidState);
        }
        let previous: Transaction = deserialize(&stored.raw_transaction)
            .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
        let new_fee = validate_replacement(
            &previous,
            &replacement.transaction,
            stored.active_fee_sat,
            current_scope.fee_policy(),
        )?;
        let generation = stored
            .active_generation
            .checked_add(1)
            .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        transaction.execute(
            "INSERT INTO transaction_attempts(effect_id,generation,txid,wtxid,intent_digest,invariant_digest,raw_transaction,fee_sat) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                current_scope.effect_id().as_slice(), i64::from(generation),
                replacement.txid.as_slice(), replacement.wtxid.as_slice(),
                replacement.intent_digest.as_slice(), replacement.invariant_digest.as_slice(),
                replacement.raw, u64_blob(new_fee),
            ],
        )?;
        transaction.execute(
            "UPDATE operations SET scope_bytes=?1,scope_digest=?2,txid=?3,wtxid=?4,
                 intent_digest=?5,invariant_digest=?6,raw_transaction=?7,
                 active_generation=?8,active_fee_sat=?9,stage=?10,confirmations=0,
                 block_hash=NULL,block_height=NULL,evidence_digest=NULL,updated_at_ms=?11
             WHERE effect_id=?12 AND fence_epoch=?13",
            params![
                replacement_scope.canonical_bytes(),
                replacement_scope.scope_digest().as_slice(),
                replacement.txid.as_slice(),
                replacement.wtxid.as_slice(),
                replacement.intent_digest.as_slice(),
                replacement.invariant_digest.as_slice(),
                replacement.raw,
                i64::from(generation),
                u64_blob(new_fee),
                i64::from(BitcoinOperationStageV1::Prepared.tag()),
                u64_blob(now_ms),
                current_scope.effect_id().as_slice(),
                u64_blob(current_scope.fence_epoch()),
            ],
        )?;
        transaction.execute(
            "UPDATE terminal_choice SET txid=?1 WHERE route_id=?2 AND leg=?3 AND effect_id=?4",
            params![
                replacement.txid.as_slice(),
                replacement_scope.route_id().as_slice(),
                i64::from(replacement_scope.leg().tag()),
                replacement_scope.effect_id().as_slice(),
            ],
        )?;
        let updated = load_operation(&transaction, replacement_scope.effect_id())?
            .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        require_operation_scope(&updated, replacement_scope)?;
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        updated.view()
    }

    /// Explicitly reconciles and re-fences an old-generation terminal effect.
    pub fn reconcile_takeover<R: BitcoinRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        new_scope: &BitcoinActuationScopeV1,
        rpc: &mut R,
        now_ms: u64,
        post_rpc_time: F,
    ) -> Result<BitcoinReconciliationV1> {
        self.audit_storage()?;
        rpc.verify_scope(new_scope)?;
        let (old_scope_bytes, raw, txid, stage, never_sent, old_fence) = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Deferred)?;
            require_clock_not_regressed(&transaction, now_ms)?;
            require_lease(
                &transaction,
                &self.owner_digest,
                new_scope.fence_epoch(),
                now_ms,
            )?;
            let stored = load_operation(&transaction, new_scope.effect_id())?
                .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
            if stored.fence_epoch >= new_scope.fence_epoch() {
                return Err(BitcoinActuatorErrorV1::StaleFencing);
            }
            let result = (
                stored.scope_bytes,
                stored.raw_transaction,
                stored.txid,
                stored.stage,
                stored.active_generation == 0 && stored.send_attempts == 0,
                stored.fence_epoch,
            );
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
            result
        };
        if !scope_bytes_match_except_fence(&old_scope_bytes, &new_scope.canonical_bytes()) {
            return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
        }
        let lookup = rpc.lookup_exact(txid);
        self.audit_storage()?;
        let lookup = lookup?;
        let reconciliation = classify_lookup(
            &raw,
            stage,
            never_sent,
            &lookup,
            new_scope.minimum_confirmations(),
        )?;
        let post_rpc_now_ms = post_rpc_time()?;
        require_post_rpc_time(now_ms, post_rpc_now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, post_rpc_now_ms)?;
        require_lease(
            &transaction,
            &self.owner_digest,
            new_scope.fence_epoch(),
            post_rpc_now_ms,
        )?;
        let changed = transaction.execute(
            "UPDATE operations SET fence_epoch=?1,scope_bytes=?2,scope_digest=?3,updated_at_ms=?4
             WHERE effect_id=?5 AND fence_epoch=?6",
            params![
                u64_blob(new_scope.fence_epoch()),
                new_scope.canonical_bytes(),
                new_scope.scope_digest().as_slice(),
                u64_blob(post_rpc_now_ms),
                new_scope.effect_id().as_slice(),
                u64_blob(old_fence),
            ],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::StaleFencing);
        }
        persist_lookup_row(
            &transaction,
            PersistLookupRequestV1 {
                effect_id: new_scope.effect_id(),
                raw: &raw,
                old_stage: stage,
                never_sent,
                lookup,
                minimum_confirmations: new_scope.minimum_confirmations(),
                now_ms: post_rpc_now_ms,
            },
        )?;
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(reconciliation)
    }

    /// Records payload-free `btc-live` custody only after its refund is durable.
    pub fn record_armed_funding(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        armed: &ArmedBitcoinFundingV1,
        now_ms: u64,
    ) -> Result<BitcoinFundingCustodyViewV1> {
        self.audit_storage()?;
        if scope.action() != BitcoinActionV1::Funding {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        let custody = armed
            .external_funding_custody()
            .map_err(|_| BitcoinActuatorErrorV1::FundingNotArmed)?;
        validate_funding_scope(scope, armed, &custody)?;
        let summary = armed.funding_summary();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        if let Some(existing) = load_funding(&transaction, scope.effect_id())? {
            require_funding_scope(&existing, scope, &custody, summary.funding_wtxid())?;
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
            return existing.view();
        }
        transaction.execute(
            "INSERT INTO funding_custody(
                effect_id,route_id,leg,fence_epoch,scope_bytes,scope_digest,txid,wtxid,
                refund_record_digest,custody_digest,send_attempts,stage,confirmations,
                block_hash,block_height,evidence_digest,created_at_ms,updated_at_ms
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,?11,0,NULL,NULL,NULL,?12,?12)",
            params![
                scope.effect_id().as_slice(),
                scope.route_id().as_slice(),
                i64::from(scope.leg().tag()),
                u64_blob(scope.fence_epoch()),
                scope.canonical_bytes(),
                scope.scope_digest().as_slice(),
                custody.funding_txid().as_slice(),
                summary.funding_wtxid().as_slice(),
                custody.refund_record_digest().as_slice(),
                custody.custody_digest().as_slice(),
                i64::from(BitcoinOperationStageV1::Prepared.tag()),
                u64_blob(now_ms),
            ],
        )?;
        let stored = load_funding(&transaction, scope.effect_id())?
            .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        stored.view()
    }

    /// Calls the sole `btc-live` funding broadcaster after custody is durable.
    pub fn broadcast_armed_funding(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        live_store: &BitcoinPrebroadcastStoreV1,
        live_rpc: &BitcoinCoreRpcClientV1,
        armed: &mut ArmedBitcoinFundingV1,
        now_ms: u64,
    ) -> Result<BitcoinBroadcastReceiptV1> {
        self.audit_storage()?;
        let custody = armed
            .external_funding_custody()
            .map_err(|_| BitcoinActuatorErrorV1::FundingNotArmed)?;
        validate_funding_scope(scope, armed, &custody)?;
        validate_live_funding_rpc(scope, &custody, live_rpc)?;
        let attempt = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            advance_clock(&transaction, now_ms)?;
            require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
            let stored = load_funding(&transaction, scope.effect_id())?
                .ok_or(BitcoinActuatorErrorV1::FundingNotArmed)?;
            require_funding_scope(
                &stored,
                scope,
                &custody,
                armed.funding_summary().funding_wtxid(),
            )?;
            if stored.stage == BitcoinOperationStageV1::Final {
                audit_runtime_state(&transaction, &self.owner_digest)?;
                transaction.commit()?;
                self.audit_storage()?;
                return Ok(BitcoinBroadcastReceiptV1 {
                    effect_id: scope.effect_id(),
                    txid: stored.txid,
                    intent_digest: stored.custody_digest,
                    already_known: true,
                    attempt: stored.send_attempts,
                });
            }
            let attempt = stored
                .send_attempts
                .checked_add(1)
                .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
            transaction.execute(
                "UPDATE funding_custody SET send_attempts=?1,stage=?2,updated_at_ms=?3 WHERE effect_id=?4 AND fence_epoch=?5",
                params![
                    i64::from(attempt), i64::from(BitcoinOperationStageV1::SendAttempted.tag()),
                    u64_blob(now_ms), scope.effect_id().as_slice(), u64_blob(scope.fence_epoch()),
                ],
            )?;
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
            attempt
        };
        let receipt = live_store
            .broadcast_armed_funding(live_rpc, armed)
            .map_err(|_| BitcoinActuatorErrorV1::LiveFunding)?;
        if receipt.transaction_id() != custody.funding_txid() {
            return Err(BitcoinActuatorErrorV1::TransactionMismatch);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        let changed = transaction.execute(
            "UPDATE funding_custody SET stage=?1,updated_at_ms=?2 WHERE effect_id=?3 AND fence_epoch=?4 AND send_attempts=?5",
            params![
                i64::from(BitcoinOperationStageV1::BroadcastAcknowledged.tag()),
                u64_blob(now_ms), scope.effect_id().as_slice(), u64_blob(scope.fence_epoch()),
                i64::from(attempt),
            ],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
        }
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(BitcoinBroadcastReceiptV1 {
            effect_id: scope.effect_id(),
            txid: receipt.transaction_id(),
            intent_digest: custody.custody_digest(),
            already_known: receipt.already_known(),
            attempt,
        })
    }

    /// Reconciles opaque funding by exact txid and witness txid.
    pub fn reconcile_funding<R: BitcoinRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        rpc: &mut R,
        now_ms: u64,
        post_rpc_time: F,
    ) -> Result<BitcoinReconciliationV1> {
        self.audit_storage()?;
        rpc.verify_scope(scope)?;
        let (txid, wtxid, stage) = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Deferred)?;
            require_clock_not_regressed(&transaction, now_ms)?;
            require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
            let stored = load_funding(&transaction, scope.effect_id())?
                .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
            if stored.scope_bytes != scope.canonical_bytes() {
                return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
            }
            let result = (stored.txid, stored.wtxid, stored.stage);
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
            result
        };
        let lookup = rpc.lookup_exact(txid);
        self.audit_storage()?;
        let lookup = lookup?;
        let (result, new_stage, confirmations, block_hash, block_height, evidence_digest) =
            match lookup {
                BitcoinRpcLookupV1::Absent { evidence_digest }
                    if stage == BitcoinOperationStageV1::Prepared =>
                {
                    (
                        BitcoinReconciliationV1::ProvenNotExternalized,
                        stage,
                        0,
                        None,
                        None,
                        evidence_digest,
                    )
                }
                BitcoinRpcLookupV1::Absent { evidence_digest } => (
                    BitcoinReconciliationV1::Ambiguous,
                    BitcoinOperationStageV1::Ambiguous,
                    0,
                    None,
                    None,
                    evidence_digest,
                ),
                BitcoinRpcLookupV1::Mempool(transaction) => {
                    require_funding_transaction(&transaction.raw_transaction, txid, wtxid)?;
                    (
                        BitcoinReconciliationV1::ExactMempool,
                        BitcoinOperationStageV1::MempoolObserved,
                        0,
                        None,
                        None,
                        transaction.evidence_digest,
                    )
                }
                BitcoinRpcLookupV1::Confirmed {
                    transaction,
                    block_hash,
                    block_height,
                    confirmations,
                } => {
                    require_funding_transaction(&transaction.raw_transaction, txid, wtxid)?;
                    let finality = confirmations >= scope.minimum_confirmations();
                    (
                        if finality {
                            BitcoinReconciliationV1::ExactFinal {
                                confirmations,
                                block_height,
                            }
                        } else {
                            BitcoinReconciliationV1::ExactConfirmed {
                                confirmations,
                                block_height,
                            }
                        },
                        if finality {
                            BitcoinOperationStageV1::Final
                        } else {
                            BitcoinOperationStageV1::Confirmed
                        },
                        confirmations,
                        Some(block_hash),
                        Some(block_height),
                        transaction.evidence_digest,
                    )
                }
            };
        if evidence_digest == [0; 32] {
            return Err(BitcoinActuatorErrorV1::TransactionMismatch);
        }
        let post_rpc_now_ms = post_rpc_time()?;
        require_post_rpc_time(now_ms, post_rpc_now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, post_rpc_now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, post_rpc_now_ms)?;
        let changed = transaction.execute(
            "UPDATE funding_custody SET stage=?1,confirmations=?2,block_hash=?3,block_height=?4,evidence_digest=?5,updated_at_ms=?6 WHERE effect_id=?7 AND fence_epoch=?8",
            params![
                i64::from(new_stage.tag()), i64::from(confirmations),
                block_hash.map(|value| value.to_vec()), block_height.map(u64_blob),
                evidence_digest.as_slice(), u64_blob(post_rpc_now_ms), scope.effect_id().as_slice(),
                u64_blob(scope.fence_epoch()),
            ],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::StaleFencing);
        }
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(result)
    }

    /// Reconciles an old-generation opaque funding record against Core and
    /// only then transfers it to the current fencing epoch.
    pub fn reconcile_funding_takeover<R: BitcoinRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        new_scope: &BitcoinActuationScopeV1,
        rpc: &mut R,
        now_ms: u64,
        post_rpc_time: F,
    ) -> Result<BitcoinReconciliationV1> {
        self.audit_storage()?;
        if new_scope.action() != BitcoinActionV1::Funding {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        rpc.verify_scope(new_scope)?;
        let (old_scope_bytes, txid, wtxid, stage, old_fence) = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Deferred)?;
            require_clock_not_regressed(&transaction, now_ms)?;
            require_lease(
                &transaction,
                &self.owner_digest,
                new_scope.fence_epoch(),
                now_ms,
            )?;
            let stored = load_funding(&transaction, new_scope.effect_id())?
                .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
            if stored.fence_epoch >= new_scope.fence_epoch() {
                return Err(BitcoinActuatorErrorV1::StaleFencing);
            }
            let result = (
                stored.scope_bytes,
                stored.txid,
                stored.wtxid,
                stored.stage,
                stored.fence_epoch,
            );
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
            result
        };
        if !scope_bytes_match_except_fence(&old_scope_bytes, &new_scope.canonical_bytes()) {
            return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
        }
        let lookup = rpc.lookup_exact(txid);
        self.audit_storage()?;
        let lookup = lookup?;
        let (reconciliation, new_stage, confirmations, block_hash, block_height, evidence_digest) =
            classify_funding_lookup(
                txid,
                wtxid,
                stage,
                lookup,
                new_scope.minimum_confirmations(),
            )?;
        let post_rpc_now_ms = post_rpc_time()?;
        require_post_rpc_time(now_ms, post_rpc_now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, post_rpc_now_ms)?;
        require_lease(
            &transaction,
            &self.owner_digest,
            new_scope.fence_epoch(),
            post_rpc_now_ms,
        )?;
        let changed = transaction.execute(
            "UPDATE funding_custody SET fence_epoch=?1,scope_bytes=?2,scope_digest=?3,stage=?4,confirmations=?5,block_hash=?6,block_height=?7,evidence_digest=?8,updated_at_ms=?9 WHERE effect_id=?10 AND fence_epoch=?11",
            params![
                u64_blob(new_scope.fence_epoch()), new_scope.canonical_bytes(),
                new_scope.scope_digest().as_slice(), i64::from(new_stage.tag()),
                i64::from(confirmations), block_hash.map(|value| value.to_vec()),
                block_height.map(u64_blob), evidence_digest.as_slice(), u64_blob(post_rpc_now_ms),
                new_scope.effect_id().as_slice(), u64_blob(old_fence),
            ],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::StaleFencing);
        }
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(reconciliation)
    }

    /// Creates or replays this participant's nonce and persists it before it
    /// is returned to authenticated peer transport.
    pub fn expose_claim_pubnonce(
        &mut self,
        context: BitcoinClaimSigningContextV1<'_>,
    ) -> Result<BitcoinLocalPubNonceV1> {
        let BitcoinClaimSigningContextV1 {
            scope,
            authority,
            session,
            authorization,
            seal_key,
            participant_state,
            now_ms,
        } = context;
        self.audit_storage()?;
        let session_digest = require_claim_session(scope, authority, session)?;
        {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            advance_clock(&transaction, now_ms)?;
            require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
            insert_or_check_claim_identity(&transaction, scope, authority, session_digest, now_ms)?;
            let (participant_id, authority_digest, local_pubnonce) = transaction.query_row(
                "SELECT participant_id,authority_digest,local_pubnonce FROM claim_transcripts WHERE effect_id=?1",
                params![scope.effect_id().as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Option<Vec<u8>>>(2)?)),
            )?;
            require_claim_identity(
                &participant_id,
                &authority_digest,
                authority,
                session_digest,
                &transaction,
                scope.effect_id(),
                scope.fence_epoch(),
            )?;
            if let Some(bytes) = local_pubnonce {
                let bytes = array_66(bytes)?;
                audit_runtime_state(&transaction, &self.owner_digest)?;
                transaction.commit()?;
                self.audit_storage()?;
                return Ok(BitcoinLocalPubNonceV1 {
                    session_digest,
                    participant_id: authority.participant_id(),
                    bytes,
                });
            }
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
        }

        // The nonce vault persists and seals the reservation before this call
        // yields public bytes. The actuator then journals those exact bytes.
        let local = expose_local_pubnonce(
            authority,
            session,
            authorization,
            seal_key,
            participant_state,
        )?;
        if local.session_digest != session_digest
            || local.participant_id != authority.participant_id()
        {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        insert_or_check_claim_identity(&transaction, scope, authority, session_digest, now_ms)?;
        let changed = transaction.execute(
            "UPDATE claim_transcripts SET local_pubnonce=COALESCE(local_pubnonce,?1),updated_at_ms=?2 WHERE effect_id=?3 AND (local_pubnonce IS NULL OR local_pubnonce=?1)",
            params![local.bytes.as_slice(), u64_blob(now_ms), scope.effect_id().as_slice()],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
        }
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(local)
    }

    /// Persists the remote public nonce before producing the local partial.
    pub fn produce_claim_partial(
        &mut self,
        context: BitcoinClaimSigningContextV1<'_>,
        remote_pubnonce: [u8; 66],
    ) -> Result<BitcoinLocalPartialV1> {
        let BitcoinClaimSigningContextV1 {
            scope,
            authority,
            session,
            authorization,
            seal_key,
            participant_state,
            now_ms,
        } = context;
        self.audit_storage()?;
        let session_digest = require_claim_session(scope, authority, session)?;
        {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            advance_clock(&transaction, now_ms)?;
            require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
            insert_or_check_claim_identity(&transaction, scope, authority, session_digest, now_ms)?;
            bind_claim_bytes(
                &transaction,
                scope.effect_id(),
                "remote_pubnonce",
                &remote_pubnonce,
                now_ms,
            )?;
            let (partial, transcript, parity) = transaction.query_row(
                "SELECT local_partial,transcript_digest,nonce_parity FROM claim_transcripts WHERE effect_id=?1",
                params![scope.effect_id().as_slice()],
                |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?, row.get::<_, Option<i64>>(2)?)),
            )?;
            if let Some(partial) = partial {
                let partial = array_32(partial)?;
                let transcript = array_32(transcript.ok_or(BitcoinActuatorErrorV1::CorruptState)?)?;
                let parity = decode_parity(parity.ok_or(BitcoinActuatorErrorV1::CorruptState)?)?;
                audit_runtime_state(&transaction, &self.owner_digest)?;
                transaction.commit()?;
                self.audit_storage()?;
                return Ok(BitcoinLocalPartialV1 {
                    session_digest,
                    transcript_digest: transcript,
                    participant_id: authority.participant_id(),
                    nonce_parity: parity,
                    bytes: partial,
                });
            }
            audit_runtime_state(&transaction, &self.owner_digest)?;
            transaction.commit()?;
            self.audit_storage()?;
        }

        let local = produce_local_partial(
            authority,
            session,
            authorization,
            seal_key,
            participant_state,
            remote_pubnonce,
        )?;
        if local.session_digest != session_digest
            || local.participant_id != authority.participant_id()
        {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        insert_or_check_claim_identity(&transaction, scope, authority, session_digest, now_ms)?;
        bind_claim_bytes(
            &transaction,
            scope.effect_id(),
            "remote_pubnonce",
            &remote_pubnonce,
            now_ms,
        )?;
        let changed = transaction.execute(
            "UPDATE claim_transcripts SET local_partial=COALESCE(local_partial,?1),transcript_digest=COALESCE(transcript_digest,?2),nonce_parity=COALESCE(nonce_parity,?3),updated_at_ms=?4 WHERE effect_id=?5 AND (local_partial IS NULL OR local_partial=?1) AND (transcript_digest IS NULL OR transcript_digest=?2) AND (nonce_parity IS NULL OR nonce_parity=?3)",
            params![
                local.bytes.as_slice(), local.transcript_digest.as_slice(),
                encode_parity(local.nonce_parity), u64_blob(now_ms), scope.effect_id().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
        }
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(local)
    }

    /// Persists the remote partial before verifying it and aggregating the
    /// exact adaptor pre-signature. Invalid peer material remains auditable.
    pub fn aggregate_claim_pre_signature(
        &mut self,
        context: BitcoinClaimSigningContextV1<'_>,
        remote_pubnonce: [u8; 66],
        remote_partial: [u8; 32],
    ) -> Result<BitcoinPreSignatureV1> {
        let BitcoinClaimSigningContextV1 {
            scope,
            authority,
            session,
            authorization,
            seal_key,
            participant_state,
            now_ms,
        } = context;
        self.audit_storage()?;
        let session_digest = require_claim_session(scope, authority, session)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        insert_or_check_claim_identity(&transaction, scope, authority, session_digest, now_ms)?;
        bind_claim_bytes(
            &transaction,
            scope.effect_id(),
            "remote_pubnonce",
            &remote_pubnonce,
            now_ms,
        )?;
        bind_claim_bytes(
            &transaction,
            scope.effect_id(),
            "remote_partial",
            &remote_partial,
            now_ms,
        )?;
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;

        let pre_signature = aggregate_pre_signature(AggregatePreSignatureRequestV1 {
            authority,
            session,
            authorization,
            seal_key,
            participant_state,
            remote_pubnonce,
            remote_partial,
        })?;
        if pre_signature.session_digest != session_digest {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        let changed = transaction.execute(
            "UPDATE claim_transcripts SET transcript_digest=COALESCE(transcript_digest,?1),nonce_parity=COALESCE(nonce_parity,?2),verified_remote_partial=1,updated_at_ms=?3 WHERE effect_id=?4 AND (transcript_digest IS NULL OR transcript_digest=?1) AND (nonce_parity IS NULL OR nonce_parity=?2)",
            params![
                pre_signature.transcript_digest.as_slice(),
                encode_parity(pre_signature.nonce_parity), u64_blob(now_ms),
                scope.effect_id().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
        }
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(pre_signature)
    }

    /// Re-fences an existing claim transcript without creating a new nonce
    /// session. This is the only signing takeover path.
    pub fn reconcile_claim_takeover(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        authority: &BitcoinParticipantClaimAuthorityV1,
        session: &BitcoinClaimSessionV1,
        now_ms: u64,
    ) -> Result<()> {
        self.audit_storage()?;
        let session_digest = require_claim_session(scope, authority, session)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_lease(
            &transaction,
            &self.owner_digest,
            scope.fence_epoch(),
            now_ms,
        )?;
        let existing: Option<ClaimTakeoverRow> = transaction
            .query_row(
                "SELECT route_id,participant_id,authority_digest,session_digest,fence_epoch FROM claim_transcripts WHERE effect_id=?1",
                params![scope.effect_id().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let (route, participant, authority_digest, stored_session, old_fence) =
            existing.ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
        if array_32(route)? != scope.route_id()
            || array_32(participant)? != authority.participant_id()
            || array_32(authority_digest)? != authority.authority_digest()
            || array_32(stored_session)? != session_digest
        {
            return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
        }
        let old_fence = decode_u64(&old_fence)?;
        if old_fence >= scope.fence_epoch() {
            return Err(BitcoinActuatorErrorV1::StaleFencing);
        }
        let changed = transaction.execute(
            "UPDATE claim_transcripts SET fence_epoch=?1,updated_at_ms=?2 WHERE effect_id=?3 AND fence_epoch=?4",
            params![
                u64_blob(scope.fence_epoch()), u64_blob(now_ms),
                scope.effect_id().as_slice(), u64_blob(old_fence),
            ],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::StaleFencing);
        }
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(())
    }

    fn mark_ambiguous(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        evidence_digest: [u8; 32],
        now_ms: u64,
    ) -> Result<()> {
        self.audit_storage()?;
        if evidence_digest == [0; 32] {
            return Err(BitcoinActuatorErrorV1::TransactionMismatch);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        let changed = transaction.execute(
            "UPDATE operations SET stage=?1,evidence_digest=?2,confirmations=0,block_hash=NULL,block_height=NULL,updated_at_ms=?3 WHERE effect_id=?4 AND fence_epoch=?5",
            params![
                i64::from(BitcoinOperationStageV1::Ambiguous.tag()),
                evidence_digest.as_slice(), u64_blob(now_ms),
                scope.effect_id().as_slice(), u64_blob(scope.fence_epoch()),
            ],
        )?;
        if changed != 1 {
            return Err(BitcoinActuatorErrorV1::StaleFencing);
        }
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(())
    }

    fn persist_terminal_lookup(
        &mut self,
        scope: &BitcoinActuationScopeV1,
        raw: &[u8],
        old_stage: BitcoinOperationStageV1,
        never_sent: bool,
        lookup: BitcoinRpcLookupV1,
        now_ms: u64,
    ) -> Result<BitcoinReconciliationV1> {
        self.audit_storage()?;
        let reconciliation = classify_lookup(
            raw,
            old_stage,
            never_sent,
            &lookup,
            scope.minimum_confirmations(),
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &self.owner_digest, scope, now_ms)?;
        persist_lookup_row(
            &transaction,
            PersistLookupRequestV1 {
                effect_id: scope.effect_id(),
                raw,
                old_stage,
                never_sent,
                lookup,
                minimum_confirmations: scope.minimum_confirmations(),
                now_ms,
            },
        )?;
        audit_runtime_state(&transaction, &self.owner_digest)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(reconciliation)
    }

    fn audit_storage(&self) -> Result<()> {
        audit_connection_config(&self.connection, "wal")?;
        audit_schema(&self.connection)?;
        audit_runtime_state(&self.connection, &self.owner_digest)?;
        #[cfg(target_os = "linux")]
        {
            validate_retained_file(
                &self.path,
                &self.authority_file,
                self.authority_identity,
                false,
            )?;
            validate_retained_file(&self.lock_path, &self.lock_file, self.lock_identity, true)?;
            validate_sidecars(&self.path)?;
        }
        Ok(())
    }
}

fn audit_runtime_state(connection: &Connection, _current_owner_digest: &[u8; 32]) -> Result<()> {
    const MAX_ECONOMIC_ROWS: i64 = 1_000_000;
    audit_port_call_journal(connection)?;
    let economic_rows: i64 = connection.query_row(
        "SELECT
           (SELECT COUNT(*) FROM operations) +
           (SELECT COUNT(*) FROM transaction_attempts) +
           (SELECT COUNT(*) FROM terminal_choice) +
           (SELECT COUNT(*) FROM funding_custody) +
           (SELECT COUNT(*) FROM claim_transcripts)",
        [],
        |row| row.get(0),
    )?;
    if !(0..=MAX_ECONOMIC_ROWS).contains(&economic_rows) {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let high_water: Option<Vec<u8>> = connection
        .query_row(
            "SELECT high_water_ms FROM monotonic_clock WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if high_water
        .as_deref()
        .map(decode_u64)
        .transpose()?
        .is_some_and(|value| value == 0)
    {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let lease: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT owner_digest,fence_epoch,expires_at_ms FROM authority_lease WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((owner, fence, expiry)) = lease {
        if array_32(owner)? == [0; 32] || decode_u64(&fence)? == 0 || decode_u64(&expiry)? == 0 {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
    }
    let participant_binding: Option<Vec<u8>> = connection
        .query_row(
            "SELECT participant_id FROM participant_binding WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if participant_binding
        .as_ref()
        .map(|participant| array_32(participant.clone()))
        .transpose()?
        .is_some_and(|participant| participant == [0; 32])
    {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let relational_violations: i64 = connection.query_row(
        "SELECT
           (SELECT COUNT(*) FROM transaction_attempts a LEFT JOIN operations o ON o.effect_id=a.effect_id WHERE o.effect_id IS NULL) +
           (SELECT COUNT(*) FROM terminal_choice t LEFT JOIN operations o ON o.effect_id=t.effect_id WHERE o.effect_id IS NULL OR o.route_id<>t.route_id OR o.leg<>t.leg OR o.action<>t.action OR o.txid<>t.txid) +
           (SELECT COUNT(*) FROM claim_transcripts c LEFT JOIN operations o ON o.effect_id=c.effect_id WHERE o.effect_id IS NOT NULL AND (o.route_id<>c.route_id OR o.fence_epoch<>c.fence_epoch OR o.action<>2)) +
           (SELECT COUNT(*) FROM claim_transcripts c LEFT JOIN participant_binding p ON p.singleton=1 WHERE p.participant_id IS NULL OR p.participant_id<>c.participant_id) +
           (SELECT COUNT(*) FROM claim_transcripts WHERE
                participant_id=zeroblob(32) OR authority_digest=zeroblob(32) OR session_digest=zeroblob(32)
                OR created_at_ms=zeroblob(8) OR updated_at_ms=zeroblob(8) OR updated_at_ms<created_at_ms
                OR (local_partial IS NOT NULL AND (local_pubnonce IS NULL OR remote_pubnonce IS NULL OR transcript_digest IS NULL OR nonce_parity IS NULL))
                OR (remote_partial IS NOT NULL AND (local_partial IS NULL OR remote_pubnonce IS NULL))
                OR ((transcript_digest IS NULL)<>(nonce_parity IS NULL))
                OR (verified_remote_partial=1 AND (local_pubnonce IS NULL OR remote_pubnonce IS NULL OR local_partial IS NULL OR remote_partial IS NULL OR transcript_digest IS NULL OR nonce_parity IS NULL))) +
           (SELECT COUNT(*) FROM operations o LEFT JOIN transaction_attempts a ON a.effect_id=o.effect_id AND a.generation=o.active_generation WHERE a.effect_id IS NULL OR a.txid<>o.txid OR a.wtxid<>o.wtxid OR a.intent_digest<>o.intent_digest OR a.invariant_digest<>o.invariant_digest OR a.raw_transaction<>o.raw_transaction OR a.fee_sat<>o.active_fee_sat)",
        [],
        |row| row.get(0),
    )?;
    if relational_violations != 0 {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let operation_ids = bounded_digest_keys(connection, "operations")?;
    for effect_id in operation_ids {
        let stored =
            load_operation(connection, effect_id)?.ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        let locator = BitcoinOperationLocatorV1 {
            kind: BitcoinOperationKindV1::Terminal,
            effect_id,
            scope_digest: stored.scope_digest,
            custody_locator: terminal_custody_locator(
                stored.scope_digest,
                stored.txid,
                stored.wtxid,
                stored.intent_digest,
                stored.invariant_digest,
            )?,
        };
        audit_operation_locator(connection, locator)?;
    }
    let funding_ids = bounded_digest_keys(connection, "funding_custody")?;
    for effect_id in funding_ids {
        let stored =
            load_funding(connection, effect_id)?.ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        let locator = BitcoinOperationLocatorV1 {
            kind: BitcoinOperationKindV1::Funding,
            effect_id,
            scope_digest: stored.scope_digest,
            custody_locator: funding_custody_locator(
                stored.scope_digest,
                stored.txid,
                stored.wtxid,
                stored.refund_record_digest,
                stored.custody_digest,
            )?,
        };
        audit_operation_locator(connection, locator)?;
    }
    Ok(())
}

fn bounded_digest_keys(connection: &Connection, table: &str) -> Result<Vec<[u8; 32]>> {
    let statement = match table {
        "operations" => "SELECT effect_id FROM operations ORDER BY effect_id",
        "funding_custody" => "SELECT effect_id FROM funding_custody ORDER BY effect_id",
        _ => return Err(BitcoinActuatorErrorV1::CorruptState),
    };
    let mut query = connection.prepare(statement)?;
    let rows = query.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut keys = Vec::new();
    for row in rows {
        if keys.len() >= 1_000_000 {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        keys.push(array_32(row?)?);
    }
    Ok(keys)
}

struct StoredOperation {
    route_id: [u8; 32],
    effect_id: [u8; 32],
    leg: crate::BitcoinLegV1,
    action: BitcoinActionV1,
    fence_epoch: u64,
    scope_bytes: Vec<u8>,
    scope_digest: [u8; 32],
    txid: [u8; 32],
    wtxid: [u8; 32],
    intent_digest: [u8; 32],
    invariant_digest: [u8; 32],
    raw_transaction: Vec<u8>,
    active_generation: u32,
    active_fee_sat: u64,
    send_attempts: u32,
    stage: BitcoinOperationStageV1,
    confirmations: u32,
    block_hash: Option<[u8; 32]>,
    block_height: Option<u64>,
    evidence_digest: Option<[u8; 32]>,
}

impl StoredOperation {
    fn view(&self) -> Result<BitcoinOperationViewV1> {
        Ok(BitcoinOperationViewV1 {
            route_id: self.route_id,
            effect_id: self.effect_id,
            action: self.action,
            fence_epoch: self.fence_epoch,
            txid: self.txid,
            intent_digest: self.intent_digest,
            generation: self.active_generation,
            send_attempts: self.send_attempts,
            stage: self.stage,
            confirmations: self.confirmations,
            block_hash: self.block_hash,
            block_height: self.block_height,
            evidence_digest: self.evidence_digest,
        })
    }
}

struct StoredFunding {
    route_id: [u8; 32],
    effect_id: [u8; 32],
    leg: crate::BitcoinLegV1,
    fence_epoch: u64,
    scope_bytes: Vec<u8>,
    scope_digest: [u8; 32],
    txid: [u8; 32],
    wtxid: [u8; 32],
    refund_record_digest: [u8; 32],
    custody_digest: [u8; 32],
    send_attempts: u32,
    stage: BitcoinOperationStageV1,
    confirmations: u32,
    block_hash: Option<[u8; 32]>,
    block_height: Option<u64>,
    evidence_digest: Option<[u8; 32]>,
}

impl StoredFunding {
    fn view(&self) -> Result<BitcoinFundingCustodyViewV1> {
        Ok(BitcoinFundingCustodyViewV1 {
            route_id: self.route_id,
            effect_id: self.effect_id,
            txid: self.txid,
            refund_record_digest: self.refund_record_digest,
            custody_digest: self.custody_digest,
            fence_epoch: self.fence_epoch,
            send_attempts: self.send_attempts,
            stage: self.stage,
            confirmations: self.confirmations,
            block_hash: self.block_hash,
            block_height: self.block_height,
            evidence_digest: self.evidence_digest,
        })
    }
}

struct StoredPortCall {
    call_kind: BitcoinPortCallKindV1,
    coordinator_attempt_id: [u8; 32],
    request_digest: [u8; 32],
    locator: BitcoinOperationLocatorV1,
    outcome_bytes: Option<Vec<u8>>,
    outcome_digest: Option<[u8; 32]>,
    created_at_ms: u64,
    committed_at_ms: Option<u64>,
}

impl StoredPortCall {
    fn status(&self) -> Result<BitcoinPortCallJournalStatusV1> {
        if self.created_at_ms == 0 {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        match (
            self.outcome_bytes.as_deref(),
            self.outcome_digest,
            self.committed_at_ms,
        ) {
            (None, None, None) => Ok(BitcoinPortCallJournalStatusV1::Pending),
            (Some(bytes), Some(stored_digest), Some(committed_at_ms))
                if committed_at_ms >= self.created_at_ms =>
            {
                let outcome = BitcoinPortCallOutcomeV1::from_canonical_bytes(bytes)?;
                outcome.validate_for(self.call_kind)?;
                if outcome.digest()? != stored_digest {
                    return Err(BitcoinActuatorErrorV1::CorruptState);
                }
                Ok(BitcoinPortCallJournalStatusV1::Committed(outcome))
            }
            _ => Err(BitcoinActuatorErrorV1::CorruptState),
        }
    }
}

const SCHEMA_SQL: &str = r#"
CREATE TABLE actuator_meta(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(schema_version=4)
) STRICT;
CREATE TABLE monotonic_clock(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    high_water_ms BLOB NOT NULL CHECK(length(high_water_ms)=8)
) STRICT;
CREATE TABLE authority_lease(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    owner_digest BLOB NOT NULL CHECK(length(owner_digest)=32),
    fence_epoch BLOB NOT NULL CHECK(length(fence_epoch)=8),
    expires_at_ms BLOB NOT NULL CHECK(length(expires_at_ms)=8)
) STRICT;
CREATE TABLE participant_binding(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    participant_id BLOB NOT NULL CHECK(length(participant_id)=32)
) STRICT;
CREATE TABLE operations(
    effect_id BLOB PRIMARY KEY CHECK(length(effect_id)=32),
    route_id BLOB NOT NULL CHECK(length(route_id)=32),
    leg INTEGER NOT NULL CHECK(leg IN (1,2)),
    action INTEGER NOT NULL CHECK(action IN (2,3)),
    fence_epoch BLOB NOT NULL CHECK(length(fence_epoch)=8),
    scope_bytes BLOB NOT NULL CHECK(length(scope_bytes)=554),
    scope_digest BLOB NOT NULL CHECK(length(scope_digest)=32),
    txid BLOB NOT NULL CHECK(length(txid)=32),
    wtxid BLOB NOT NULL CHECK(length(wtxid)=32),
    intent_digest BLOB NOT NULL CHECK(length(intent_digest)=32),
    invariant_digest BLOB NOT NULL CHECK(length(invariant_digest)=32),
    raw_transaction BLOB NOT NULL CHECK(length(raw_transaction) BETWEEN 1 AND 4000000),
    active_generation INTEGER NOT NULL CHECK(active_generation BETWEEN 0 AND 4294967295),
    active_fee_sat BLOB NOT NULL CHECK(length(active_fee_sat)=8),
    send_attempts INTEGER NOT NULL CHECK(send_attempts BETWEEN 0 AND 4294967295),
    stage INTEGER NOT NULL CHECK(stage BETWEEN 1 AND 7),
    confirmations INTEGER NOT NULL CHECK(confirmations BETWEEN 0 AND 4294967295),
    block_hash BLOB CHECK(block_hash IS NULL OR length(block_hash)=32),
    block_height BLOB CHECK(block_height IS NULL OR length(block_height)=8),
    evidence_digest BLOB CHECK(evidence_digest IS NULL OR length(evidence_digest)=32),
    created_at_ms BLOB NOT NULL CHECK(length(created_at_ms)=8),
    updated_at_ms BLOB NOT NULL CHECK(length(updated_at_ms)=8)
) STRICT;
CREATE TABLE transaction_attempts(
    effect_id BLOB NOT NULL CHECK(length(effect_id)=32),
    generation INTEGER NOT NULL CHECK(generation BETWEEN 0 AND 4294967295),
    txid BLOB NOT NULL CHECK(length(txid)=32),
    wtxid BLOB NOT NULL CHECK(length(wtxid)=32),
    intent_digest BLOB NOT NULL CHECK(length(intent_digest)=32),
    invariant_digest BLOB NOT NULL CHECK(length(invariant_digest)=32),
    raw_transaction BLOB NOT NULL CHECK(length(raw_transaction) BETWEEN 1 AND 4000000),
    fee_sat BLOB NOT NULL CHECK(length(fee_sat)=8),
    PRIMARY KEY(effect_id,generation),
    FOREIGN KEY(effect_id) REFERENCES operations(effect_id) ON DELETE RESTRICT
) STRICT;
CREATE TABLE terminal_choice(
    route_id BLOB NOT NULL CHECK(length(route_id)=32),
    leg INTEGER NOT NULL CHECK(leg IN (1,2)),
    action INTEGER NOT NULL CHECK(action IN (2,3)),
    effect_id BLOB NOT NULL UNIQUE CHECK(length(effect_id)=32),
    txid BLOB NOT NULL CHECK(length(txid)=32),
    PRIMARY KEY(route_id,leg),
    FOREIGN KEY(effect_id) REFERENCES operations(effect_id) ON DELETE RESTRICT
) STRICT;
CREATE TABLE funding_custody(
    effect_id BLOB PRIMARY KEY CHECK(length(effect_id)=32),
    route_id BLOB NOT NULL CHECK(length(route_id)=32),
    leg INTEGER NOT NULL CHECK(leg IN (1,2)),
    fence_epoch BLOB NOT NULL CHECK(length(fence_epoch)=8),
    scope_bytes BLOB NOT NULL CHECK(length(scope_bytes)=554),
    scope_digest BLOB NOT NULL CHECK(length(scope_digest)=32),
    txid BLOB NOT NULL CHECK(length(txid)=32),
    wtxid BLOB NOT NULL CHECK(length(wtxid)=32),
    refund_record_digest BLOB NOT NULL CHECK(length(refund_record_digest)=32),
    custody_digest BLOB NOT NULL CHECK(length(custody_digest)=32),
    send_attempts INTEGER NOT NULL CHECK(send_attempts BETWEEN 0 AND 4294967295),
    stage INTEGER NOT NULL CHECK(stage BETWEEN 1 AND 7),
    confirmations INTEGER NOT NULL CHECK(confirmations BETWEEN 0 AND 4294967295),
    block_hash BLOB CHECK(block_hash IS NULL OR length(block_hash)=32),
    block_height BLOB CHECK(block_height IS NULL OR length(block_height)=8),
    evidence_digest BLOB CHECK(evidence_digest IS NULL OR length(evidence_digest)=32),
    created_at_ms BLOB NOT NULL CHECK(length(created_at_ms)=8),
    updated_at_ms BLOB NOT NULL CHECK(length(updated_at_ms)=8)
) STRICT;
CREATE TABLE claim_transcripts(
    effect_id BLOB PRIMARY KEY CHECK(length(effect_id)=32),
    route_id BLOB NOT NULL CHECK(length(route_id)=32),
    fence_epoch BLOB NOT NULL CHECK(length(fence_epoch)=8),
    participant_id BLOB NOT NULL CHECK(length(participant_id)=32),
    participant_role INTEGER NOT NULL CHECK(participant_role IN (1,2)),
    authority_digest BLOB NOT NULL CHECK(length(authority_digest)=32),
    session_digest BLOB NOT NULL CHECK(length(session_digest)=32),
    local_pubnonce BLOB CHECK(local_pubnonce IS NULL OR length(local_pubnonce)=66),
    remote_pubnonce BLOB CHECK(remote_pubnonce IS NULL OR length(remote_pubnonce)=66),
    transcript_digest BLOB CHECK(transcript_digest IS NULL OR length(transcript_digest)=32),
    local_partial BLOB CHECK(local_partial IS NULL OR length(local_partial)=32),
    remote_partial BLOB CHECK(remote_partial IS NULL OR length(remote_partial)=32),
    nonce_parity INTEGER CHECK(nonce_parity IS NULL OR nonce_parity IN (0,1)),
    verified_remote_partial INTEGER NOT NULL CHECK(verified_remote_partial IN (0,1)),
    created_at_ms BLOB NOT NULL CHECK(length(created_at_ms)=8),
    updated_at_ms BLOB NOT NULL CHECK(length(updated_at_ms)=8)
) STRICT;
CREATE TABLE port_call_journal(
    call_kind INTEGER NOT NULL CHECK(call_kind IN (1,2,3)),
    coordinator_attempt_id BLOB NOT NULL CHECK(length(coordinator_attempt_id)=32),
    request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
    operation_kind INTEGER NOT NULL CHECK(operation_kind IN (1,2)),
    effect_id BLOB NOT NULL CHECK(length(effect_id)=32),
    scope_digest BLOB NOT NULL CHECK(length(scope_digest)=32),
    custody_locator BLOB NOT NULL CHECK(length(custody_locator)=32),
    outcome_bytes BLOB CHECK(outcome_bytes IS NULL OR length(outcome_bytes)=66),
    outcome_digest BLOB CHECK(outcome_digest IS NULL OR length(outcome_digest)=32),
    created_at_ms BLOB NOT NULL CHECK(length(created_at_ms)=8),
    committed_at_ms BLOB CHECK(committed_at_ms IS NULL OR length(committed_at_ms)=8),
    PRIMARY KEY(call_kind,coordinator_attempt_id,request_digest),
    UNIQUE(call_kind,coordinator_attempt_id),
    CHECK((outcome_bytes IS NULL AND outcome_digest IS NULL AND committed_at_ms IS NULL)
       OR (outcome_bytes IS NOT NULL AND outcome_digest IS NOT NULL AND committed_at_ms IS NOT NULL))
) STRICT;
"#;

fn configure(connection: &Connection, allow_journal_transition: bool) -> Result<()> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    let mode: String = if allow_journal_transition {
        connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?
    } else {
        connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?
    };
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    configure_common(connection)?;
    audit_connection_config(connection, "wal")
}

fn configure_creation(connection: &Connection) -> Result<()> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    configure_common(connection)?;
    audit_connection_config(connection, "delete")
}

fn configure_common(connection: &Connection) -> Result<()> {
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "read_uncommitted", "OFF")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection.set_db_config(defensive, true)? || !connection.db_config(defensive)? {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

fn audit_connection_config(connection: &Connection, expected_journal: &str) -> Result<()> {
    let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.query_row("PRAGMA read_uncommitted", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let secure_delete: i64 = connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    let temp_store: i64 = connection.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case(expected_journal)
        || synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || secure_delete != 1
        || temp_store != 2
        || busy_timeout != 5_000
    {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

fn initialize_schema(connection: &mut Connection) -> Result<()> {
    test_creation_crash_hook("before-schema-transaction");
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != 0 {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    transaction.execute_batch(SCHEMA_SQL)?;
    transaction.execute(
        "INSERT INTO actuator_meta(singleton,schema_version) VALUES(1,?1)",
        params![SCHEMA_VERSION],
    )?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    test_creation_crash_hook("before-schema-commit");
    transaction.commit()?;
    test_creation_crash_hook("after-schema-commit");
    Ok(())
}

fn audit_schema(connection: &Connection) -> Result<()> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let mut foreign_key_check = connection.prepare("PRAGMA foreign_key_check")?;
    let foreign_key_violation = foreign_key_check.exists([])?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let meta: i64 = connection.query_row(
        "SELECT schema_version FROM actuator_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if integrity != "ok"
        || foreign_key_violation
        || version != SCHEMA_VERSION
        || application_id != APPLICATION_ID
        || meta != SCHEMA_VERSION
    {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let actual = schema_objects(connection)?;
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA_SQL)?;
    let expected = schema_objects(&reference)?;
    if actual != expected {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    Ok(())
}

fn audit_port_call_journal(connection: &Connection) -> Result<()> {
    const MAX_JOURNAL_ROWS: i64 = 1_000_000;
    let count: i64 = connection.query_row("SELECT COUNT(*) FROM port_call_journal", [], |row| {
        row.get(0)
    })?;
    if !(0..=MAX_JOURNAL_ROWS).contains(&count) {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let keys = {
        let mut statement = connection.prepare(
            "SELECT call_kind,coordinator_attempt_id FROM port_call_journal
             ORDER BY call_kind,coordinator_attempt_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut keys = Vec::with_capacity(
            usize::try_from(count).map_err(|_| BitcoinActuatorErrorV1::CorruptState)?,
        );
        for row in rows {
            let (kind, attempt_id) = row?;
            keys.push((
                BitcoinPortCallKindV1::from_tag(i64_u8(kind)?)?,
                array_32(attempt_id)?,
            ));
        }
        keys
    };
    for (kind, attempt_id) in keys {
        let stored = load_port_call(connection, kind, attempt_id)?
            .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        audit_operation_locator(connection, stored.locator)?;
    }
    Ok(())
}

fn require_no_economic_state(connection: &Connection) -> Result<()> {
    let count: i64 = connection.query_row(
        "SELECT
           (SELECT COUNT(*) FROM monotonic_clock) +
           (SELECT COUNT(*) FROM authority_lease) +
           (SELECT COUNT(*) FROM participant_binding) +
           (SELECT COUNT(*) FROM operations) +
           (SELECT COUNT(*) FROM transaction_attempts) +
           (SELECT COUNT(*) FROM terminal_choice) +
           (SELECT COUNT(*) FROM funding_custody) +
           (SELECT COUNT(*) FROM claim_transcripts) +
           (SELECT COUNT(*) FROM port_call_journal)",
        [],
        |row| row.get(0),
    )?;
    if count != 0 {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    Ok(())
}

#[cfg(test)]
fn test_creation_crash_hook(boundary: &str) {
    if std::env::var("DOM_BTC_ACTUATOR_TEST_CRASH_BOUNDARY").as_deref() == Ok(boundary) {
        std::process::exit(86);
    }
}

#[cfg(not(test))]
fn test_creation_crash_hook(_boundary: &str) {}

fn audit_operation_locator(
    connection: &Connection,
    locator: BitcoinOperationLocatorV1,
) -> Result<()> {
    let expected = match locator.kind {
        BitcoinOperationKindV1::Terminal => {
            let stored = load_operation(connection, locator.effect_id)?
                .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
            let scope = BitcoinActuationScopeV1::from_canonical_bytes(&stored.scope_bytes)?;
            require_operation_scope(&stored, &scope)
                .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
            BitcoinOperationLocatorV1 {
                kind: locator.kind,
                effect_id: stored.effect_id,
                scope_digest: stored.scope_digest,
                custody_locator: terminal_custody_locator(
                    stored.scope_digest,
                    stored.txid,
                    stored.wtxid,
                    stored.intent_digest,
                    stored.invariant_digest,
                )?,
            }
        }
        BitcoinOperationKindV1::Funding => {
            let stored = load_funding(connection, locator.effect_id)?
                .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
            let scope = BitcoinActuationScopeV1::from_canonical_bytes(&stored.scope_bytes)?;
            if scope.action() != BitcoinActionV1::Funding
                || stored.route_id != scope.route_id()
                || stored.effect_id != scope.effect_id()
                || stored.leg != scope.leg()
                || stored.fence_epoch != scope.fence_epoch()
                || stored.scope_digest != scope.scope_digest()
                || stored.txid != scope.expected_txid()
                || stored.custody_digest != scope.intent_digest()
                || Some(stored.refund_record_digest) != scope.refund_record_digest()
            {
                return Err(BitcoinActuatorErrorV1::CorruptState);
            }
            BitcoinOperationLocatorV1 {
                kind: locator.kind,
                effect_id: stored.effect_id,
                scope_digest: stored.scope_digest,
                custody_locator: funding_custody_locator(
                    stored.scope_digest,
                    stored.txid,
                    stored.wtxid,
                    stored.refund_record_digest,
                    stored.custody_digest,
                )?,
            }
        }
    };
    if locator != expected {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    Ok(())
}

type SchemaObject = (String, String, String, String);

fn schema_objects(connection: &Connection) -> Result<std::collections::BTreeSet<SchemaObject>> {
    const MAX_OBJECTS: i64 = 24;
    const MAX_SCHEMA_BYTES: i64 = 262_144;
    let (count, maximum, total): (i64, Option<i64>, Option<i64>) = connection.query_row(
        "SELECT COUNT(*),MAX(length(sql)),SUM(length(sql)) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if !(0..=MAX_OBJECTS).contains(&count)
        || maximum.is_some_and(|value| !(0..=MAX_SCHEMA_BYTES).contains(&value))
        || total.is_some_and(|value| !(0..=MAX_SCHEMA_BYTES).contains(&value))
    {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let mut statement = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut objects = std::collections::BTreeSet::new();
    for row in rows {
        if !objects.insert(row?) {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
    }
    Ok(objects)
}

fn validate_time(now_ms: u64, duration_ms: u64) -> Result<()> {
    if now_ms == 0 || duration_ms == 0 || duration_ms > MAX_LEASE_MS {
        return Err(BitcoinActuatorErrorV1::InvalidTime);
    }
    now_ms
        .checked_add(duration_ms)
        .ok_or(BitcoinActuatorErrorV1::InvalidTime)?;
    Ok(())
}

fn advance_clock(transaction: &rusqlite::Transaction<'_>, now_ms: u64) -> Result<()> {
    if now_ms == 0 {
        return Err(BitcoinActuatorErrorV1::InvalidTime);
    }
    let previous = transaction
        .query_row(
            "SELECT high_water_ms FROM monotonic_clock WHERE singleton=1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    match previous {
        Some(bytes) if decode_u64(&bytes)? > now_ms => Err(BitcoinActuatorErrorV1::InvalidTime),
        Some(_) => {
            transaction.execute(
                "UPDATE monotonic_clock SET high_water_ms=?1 WHERE singleton=1",
                params![u64_blob(now_ms)],
            )?;
            Ok(())
        }
        None => {
            transaction.execute(
                "INSERT INTO monotonic_clock(singleton,high_water_ms) VALUES(1,?1)",
                params![u64_blob(now_ms)],
            )?;
            Ok(())
        }
    }
}

fn require_clock_not_regressed(transaction: &rusqlite::Transaction<'_>, now_ms: u64) -> Result<()> {
    if now_ms == 0 {
        return Err(BitcoinActuatorErrorV1::InvalidTime);
    }
    let previous = transaction
        .query_row(
            "SELECT high_water_ms FROM monotonic_clock WHERE singleton=1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    if previous
        .map(|bytes| decode_u64(&bytes))
        .transpose()?
        .is_some_and(|retained| retained > now_ms)
    {
        return Err(BitcoinActuatorErrorV1::InvalidTime);
    }
    Ok(())
}

fn require_post_rpc_time(initial_now_ms: u64, post_rpc_now_ms: u64) -> Result<()> {
    if post_rpc_now_ms < initial_now_ms {
        return Err(BitcoinActuatorErrorV1::InvalidTime);
    }
    Ok(())
}

fn require_lease(
    transaction: &rusqlite::Transaction<'_>,
    owner_digest: &[u8; 32],
    fence_epoch: u64,
    now_ms: u64,
) -> Result<()> {
    let lease: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT owner_digest,fence_epoch,expires_at_ms FROM authority_lease WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (owner, fence, expires) = lease.ok_or(BitcoinActuatorErrorV1::StaleFencing)?;
    if array_32(owner)? != *owner_digest
        || decode_u64(&fence)? != fence_epoch
        || decode_u64(&expires)? <= now_ms
    {
        return Err(BitcoinActuatorErrorV1::StaleFencing);
    }
    Ok(())
}

fn require_scope_lease(
    transaction: &rusqlite::Transaction<'_>,
    owner_digest: &[u8; 32],
    scope: &BitcoinActuationScopeV1,
    now_ms: u64,
) -> Result<()> {
    if scope.valid_until_ms() < now_ms {
        return Err(BitcoinActuatorErrorV1::InvalidTime);
    }
    require_lease(transaction, owner_digest, scope.fence_epoch(), now_ms)
}

fn load_operation_binding(
    transaction: &rusqlite::Transaction<'_>,
    owner_digest: &[u8; 32],
    lease: BitcoinStorageLeaseStatusV1,
    kind: BitcoinOperationKindV1,
    effect_id: [u8; 32],
    now_ms: u64,
) -> Result<BitcoinOperationBindingViewV1> {
    if effect_id == [0; 32] || lease.expires_at_ms <= now_ms {
        return Err(BitcoinActuatorErrorV1::StaleFencing);
    }
    require_lease(transaction, owner_digest, lease.fence_epoch, now_ms)?;
    let (scope, operation, locator) = match kind {
        BitcoinOperationKindV1::Terminal => {
            let stored = load_operation(transaction, effect_id)?
                .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
            let scope = BitcoinActuationScopeV1::from_canonical_bytes(&stored.scope_bytes)?;
            require_scope_lease(transaction, owner_digest, &scope, now_ms)?;
            require_operation_scope(&stored, &scope)
                .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
            let locator = BitcoinOperationLocatorV1 {
                kind,
                effect_id,
                scope_digest: scope.scope_digest(),
                custody_locator: terminal_custody_locator(
                    stored.scope_digest,
                    stored.txid,
                    stored.wtxid,
                    stored.intent_digest,
                    stored.invariant_digest,
                )?,
            };
            (
                scope,
                BitcoinDurableOperationViewV1::Terminal(stored.view()?),
                locator,
            )
        }
        BitcoinOperationKindV1::Funding => {
            let stored = load_funding(transaction, effect_id)?
                .ok_or(BitcoinActuatorErrorV1::EffectNotFound)?;
            let scope = BitcoinActuationScopeV1::from_canonical_bytes(&stored.scope_bytes)?;
            require_scope_lease(transaction, owner_digest, &scope, now_ms)?;
            if scope.action() != BitcoinActionV1::Funding
                || stored.route_id != scope.route_id()
                || stored.effect_id != scope.effect_id()
                || stored.leg != scope.leg()
                || stored.fence_epoch != scope.fence_epoch()
                || stored.scope_digest != scope.scope_digest()
                || stored.txid != scope.expected_txid()
                || stored.custody_digest != scope.intent_digest()
                || Some(stored.refund_record_digest) != scope.refund_record_digest()
            {
                return Err(BitcoinActuatorErrorV1::CorruptState);
            }
            let locator = BitcoinOperationLocatorV1 {
                kind,
                effect_id,
                scope_digest: scope.scope_digest(),
                custody_locator: funding_custody_locator(
                    stored.scope_digest,
                    stored.txid,
                    stored.wtxid,
                    stored.refund_record_digest,
                    stored.custody_digest,
                )?,
            };
            (
                scope,
                BitcoinDurableOperationViewV1::Funding(stored.view()?),
                locator,
            )
        }
    };
    let chain_identity_digest = chain_identity_digest(&scope)?;
    Ok(BitcoinOperationBindingViewV1 {
        scope,
        operation,
        locator,
        chain_identity_digest,
    })
}

fn validate_port_call_key(key: &BitcoinPortCallKeyV1) -> Result<()> {
    if key.coordinator_attempt_id == [0; 32]
        || key.request_digest == [0; 32]
        || key.locator.effect_id == [0; 32]
        || key.locator.scope_digest == [0; 32]
        || key.locator.custody_locator == [0; 32]
    {
        return Err(BitcoinActuatorErrorV1::InvalidScope);
    }
    Ok(())
}

fn require_journal_binding(
    transaction: &rusqlite::Transaction<'_>,
    owner_digest: &[u8; 32],
    lease: BitcoinStorageLeaseStatusV1,
    key: &BitcoinPortCallKeyV1,
    now_ms: u64,
) -> Result<()> {
    let binding = load_operation_binding(
        transaction,
        owner_digest,
        lease,
        key.locator.kind,
        key.locator.effect_id,
        now_ms,
    )?;
    if binding.locator != key.locator {
        return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn load_port_call(
    transaction: &Connection,
    sought_kind: BitcoinPortCallKindV1,
    sought_attempt_id: [u8; 32],
) -> Result<Option<StoredPortCall>> {
    let row = transaction
        .query_row(
            "SELECT call_kind,coordinator_attempt_id,request_digest,operation_kind,effect_id,
                    scope_digest,custody_locator,outcome_bytes,outcome_digest,created_at_ms,committed_at_ms
             FROM port_call_journal WHERE call_kind=?1 AND coordinator_attempt_id=?2",
            params![i64::from(sought_kind.tag()), sought_attempt_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                ))
            },
        )
        .optional()?;
    let Some((
        call_kind,
        coordinator_attempt_id,
        request_digest,
        operation_kind,
        effect_id,
        scope_digest,
        custody_locator,
        outcome_bytes,
        outcome_digest,
        created_at_ms,
        committed_at_ms,
    )) = row
    else {
        return Ok(None);
    };
    let value = StoredPortCall {
        call_kind: BitcoinPortCallKindV1::from_tag(i64_u8(call_kind)?)?,
        coordinator_attempt_id: array_32(coordinator_attempt_id)?,
        request_digest: array_32(request_digest)?,
        locator: BitcoinOperationLocatorV1 {
            kind: BitcoinOperationKindV1::from_tag(i64_u8(operation_kind)?)?,
            effect_id: array_32(effect_id)?,
            scope_digest: array_32(scope_digest)?,
            custody_locator: array_32(custody_locator)?,
        },
        outcome_bytes,
        outcome_digest: outcome_digest.map(array_32).transpose()?,
        created_at_ms: decode_u64(&created_at_ms)?,
        committed_at_ms: committed_at_ms
            .map(|value| decode_u64(&value))
            .transpose()?,
    };
    if value.call_kind != sought_kind
        || value.coordinator_attempt_id != sought_attempt_id
        || value.request_digest == [0; 32]
        || value.locator.effect_id == [0; 32]
        || value.locator.scope_digest == [0; 32]
        || value.locator.custody_locator == [0; 32]
    {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    value.status()?;
    Ok(Some(value))
}

fn require_port_call_key(existing: &StoredPortCall, key: &BitcoinPortCallKeyV1) -> Result<()> {
    if existing.call_kind != key.call_kind
        || existing.coordinator_attempt_id != key.coordinator_attempt_id
        || existing.request_digest != key.request_digest
        || existing.locator != key.locator
    {
        return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn load_operation(
    transaction: &Connection,
    effect_id: [u8; 32],
) -> Result<Option<StoredOperation>> {
    let row = transaction
        .query_row(
            "SELECT route_id,effect_id,leg,action,fence_epoch,scope_bytes,scope_digest,txid,wtxid,intent_digest,invariant_digest,raw_transaction,active_generation,active_fee_sat,send_attempts,stage,confirmations,block_hash,block_height,evidence_digest FROM operations WHERE effect_id=?1",
            params![effect_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?, row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?, row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?, row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?, row.get::<_, Vec<u8>>(11)?,
                    row.get::<_, i64>(12)?, row.get::<_, Vec<u8>>(13)?,
                    row.get::<_, i64>(14)?, row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, Option<Vec<u8>>>(17)?,
                    row.get::<_, Option<Vec<u8>>>(18)?,
                    row.get::<_, Option<Vec<u8>>>(19)?,
                ))
            },
        )
        .optional()?;
    let Some((
        route_id,
        effect_id,
        leg,
        action,
        fence_epoch,
        scope_bytes,
        scope_digest,
        txid,
        wtxid,
        intent_digest,
        invariant_digest,
        raw_transaction,
        active_generation,
        active_fee_sat,
        send_attempts,
        stage,
        confirmations,
        block_hash,
        block_height,
        evidence_digest,
    )) = row
    else {
        return Ok(None);
    };
    let exact = ExactBitcoinTransactionV1::from_consensus_bytes(raw_transaction)
        .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
    let scope_digest = array_32(scope_digest)?;
    if exact.txid != array_32(txid)?
        || exact.wtxid != array_32(wtxid)?
        || exact.intent_digest != array_32(intent_digest)?
        || exact.invariant_digest != array_32(invariant_digest)?
        || scope_bytes.len() < 32
        || scope_bytes[scope_bytes.len() - 32..] != scope_digest
    {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let stage = BitcoinOperationStageV1::from_tag(i64_u8(stage)?)?;
    let confirmations = i64_u32(confirmations)?;
    let block_hash = block_hash.map(array_32).transpose()?;
    let block_height = block_height.map(|value| decode_u64(&value)).transpose()?;
    let evidence_digest = evidence_digest.map(array_32).transpose()?;
    validate_persisted_observation(
        stage,
        confirmations,
        block_hash,
        block_height,
        evidence_digest,
    )?;
    Ok(Some(StoredOperation {
        route_id: array_32(route_id)?,
        effect_id: array_32(effect_id)?,
        leg: crate::BitcoinLegV1::from_tag(i64_u8(leg)?)?,
        action: BitcoinActionV1::from_tag(i64_u8(action)?)?,
        fence_epoch: decode_u64(&fence_epoch)?,
        scope_bytes,
        scope_digest,
        txid: exact.txid,
        wtxid: exact.wtxid,
        intent_digest: exact.intent_digest,
        invariant_digest: exact.invariant_digest,
        raw_transaction: exact.raw,
        active_generation: i64_u32(active_generation)?,
        active_fee_sat: decode_u64(&active_fee_sat)?,
        send_attempts: i64_u32(send_attempts)?,
        stage,
        confirmations,
        block_hash,
        block_height,
        evidence_digest,
    }))
}

fn load_funding(transaction: &Connection, effect_id: [u8; 32]) -> Result<Option<StoredFunding>> {
    let row = transaction
        .query_row(
            "SELECT route_id,effect_id,leg,fence_epoch,scope_bytes,scope_digest,txid,wtxid,refund_record_digest,custody_digest,send_attempts,stage,confirmations,block_hash,block_height,evidence_digest FROM funding_custody WHERE effect_id=?1",
            params![effect_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?, row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?, row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, i64>(10)?, row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Option<Vec<u8>>>(13)?,
                    row.get::<_, Option<Vec<u8>>>(14)?,
                    row.get::<_, Option<Vec<u8>>>(15)?,
                ))
            },
        )
        .optional()?;
    let Some((
        route_id,
        effect_id,
        leg,
        fence_epoch,
        scope_bytes,
        scope_digest,
        txid,
        wtxid,
        refund_record_digest,
        custody_digest,
        send_attempts,
        stage,
        confirmations,
        block_hash,
        block_height,
        evidence_digest,
    )) = row
    else {
        return Ok(None);
    };
    let scope_digest = array_32(scope_digest)?;
    let txid = array_32(txid)?;
    let wtxid = array_32(wtxid)?;
    let refund_record_digest = array_32(refund_record_digest)?;
    let custody_digest = array_32(custody_digest)?;
    if scope_bytes.len() < 32
        || scope_bytes[scope_bytes.len() - 32..] != scope_digest
        || txid == [0; 32]
        || wtxid == [0; 32]
        || refund_record_digest == [0; 32]
        || custody_digest == [0; 32]
    {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let stage = BitcoinOperationStageV1::from_tag(i64_u8(stage)?)?;
    let confirmations = i64_u32(confirmations)?;
    let block_hash = block_hash.map(array_32).transpose()?;
    let block_height = block_height.map(|value| decode_u64(&value)).transpose()?;
    let evidence_digest = evidence_digest.map(array_32).transpose()?;
    validate_persisted_observation(
        stage,
        confirmations,
        block_hash,
        block_height,
        evidence_digest,
    )?;
    Ok(Some(StoredFunding {
        route_id: array_32(route_id)?,
        effect_id: array_32(effect_id)?,
        leg: crate::BitcoinLegV1::from_tag(i64_u8(leg)?)?,
        fence_epoch: decode_u64(&fence_epoch)?,
        scope_bytes,
        scope_digest,
        txid,
        wtxid,
        refund_record_digest,
        custody_digest,
        send_attempts: i64_u32(send_attempts)?,
        stage,
        confirmations,
        block_hash,
        block_height,
        evidence_digest,
    }))
}

fn require_operation_scope(
    stored: &StoredOperation,
    scope: &BitcoinActuationScopeV1,
) -> Result<()> {
    if stored.route_id != scope.route_id()
        || stored.effect_id != scope.effect_id()
        || stored.leg != scope.leg()
        || stored.action != scope.action()
        || stored.fence_epoch != scope.fence_epoch()
        || stored.scope_bytes != scope.canonical_bytes()
        || stored.scope_digest != scope.scope_digest()
        || stored.txid != scope.expected_txid()
        || stored.intent_digest != scope.intent_digest()
    {
        return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn validate_persisted_observation(
    stage: BitcoinOperationStageV1,
    confirmations: u32,
    block_hash: Option<[u8; 32]>,
    block_height: Option<u64>,
    evidence_digest: Option<[u8; 32]>,
) -> Result<()> {
    if block_hash.is_some_and(|value| value == [0; 32])
        || evidence_digest.is_some_and(|value| value == [0; 32])
        || block_hash.is_some() != block_height.is_some()
    {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    match stage {
        BitcoinOperationStageV1::Confirmed | BitcoinOperationStageV1::Final
            if confirmations > 0
                && block_hash.is_some()
                && block_height.is_some()
                && evidence_digest.is_some() =>
        {
            Ok(())
        }
        BitcoinOperationStageV1::Confirmed | BitcoinOperationStageV1::Final => {
            Err(BitcoinActuatorErrorV1::CorruptState)
        }
        _ if confirmations == 0 && block_hash.is_none() && block_height.is_none() => Ok(()),
        _ => Err(BitcoinActuatorErrorV1::CorruptState),
    }
}

fn require_funding_scope(
    stored: &StoredFunding,
    scope: &BitcoinActuationScopeV1,
    custody: &BitcoinExternalFundingCustodyV1,
    funding_wtxid: [u8; 32],
) -> Result<()> {
    if stored.route_id != scope.route_id()
        || stored.effect_id != scope.effect_id()
        || stored.leg != scope.leg()
        || stored.fence_epoch != scope.fence_epoch()
        || stored.scope_bytes != scope.canonical_bytes()
        || stored.scope_digest != scope.scope_digest()
        || stored.txid != custody.funding_txid()
        || stored.wtxid != funding_wtxid
        || stored.refund_record_digest != custody.refund_record_digest()
        || stored.custody_digest != custody.custody_digest()
    {
        return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn validate_funding_scope(
    scope: &BitcoinActuationScopeV1,
    armed: &ArmedBitcoinFundingV1,
    custody: &BitcoinExternalFundingCustodyV1,
) -> Result<()> {
    let summary = armed.funding_summary();
    if scope.action() != BitcoinActionV1::Funding
        || scope.expected_txid() != custody.funding_txid()
        || scope.intent_digest() != custody.custody_digest()
        || scope.refund_record_digest() != Some(custody.refund_record_digest())
        || custody.refund_record_digest() != armed.refund_record_digest()
        || custody.funding_txid() != summary.funding_txid()
        || custody.contract_amount_sat() != summary.contract_amount_sat()
        || custody.actual_fee_sat() != summary.actual_fee_sat()
        || scope.contract_amount_sat() != custody.contract_amount_sat()
        || scope.fee_policy().initial_fee_sat != custody.actual_fee_sat()
        || scope.fee_policy().change_vout.is_some()
        || !funding_network_matches(scope.network(), custody.network())
        || scope.genesis_hash() != custody.genesis_hash()
        || scope.signet_challenge_digest() != custody.signet_challenge_digest()
        || custody.custody_digest() == [0; 32]
    {
        return Err(BitcoinActuatorErrorV1::FundingNotArmed);
    }
    Ok(())
}

fn validate_live_funding_rpc(
    scope: &BitcoinActuationScopeV1,
    custody: &BitcoinExternalFundingCustodyV1,
    rpc: &BitcoinCoreRpcClientV1,
) -> Result<()> {
    if rpc.network() != custody.network()
        || rpc.genesis_hash() != custody.genesis_hash()
        || rpc
            .signet_challenge_digest()
            .map_err(|_| BitcoinActuatorErrorV1::RpcScopeMismatch)?
            != custody.signet_challenge_digest()
        || !funding_network_matches(scope.network(), rpc.network())
        || scope.genesis_hash() != rpc.genesis_hash()
        || scope.signet_challenge_digest()
            != rpc
                .signet_challenge_digest()
                .map_err(|_| BitcoinActuatorErrorV1::RpcScopeMismatch)?
    {
        return Err(BitcoinActuatorErrorV1::RpcScopeMismatch);
    }
    Ok(())
}

const fn funding_network_matches(
    profile: adapter_btc::types::BitcoinNetworkV1,
    live: BitcoinCoreNetworkV1,
) -> bool {
    matches!(
        (profile, live),
        (
            adapter_btc::types::BitcoinNetworkV1::Regtest,
            BitcoinCoreNetworkV1::Regtest
        ) | (
            adapter_btc::types::BitcoinNetworkV1::PublicSignet,
            BitcoinCoreNetworkV1::PublicSignet
        ) | (
            adapter_btc::types::BitcoinNetworkV1::CustomSignet,
            BitcoinCoreNetworkV1::CustomSignet
        )
    )
}

fn require_terminal_choice(
    transaction: &rusqlite::Transaction<'_>,
    scope: &BitcoinActuationScopeV1,
    txid: [u8; 32],
) -> Result<()> {
    let existing: Option<(i64, Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT action,effect_id,txid FROM terminal_choice WHERE route_id=?1 AND leg=?2",
            params![scope.route_id().as_slice(), i64::from(scope.leg().tag())],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match existing {
        Some((action, effect, chosen_txid)) => {
            if i64_u8(action)? == scope.action().tag()
                && array_32(effect)? == scope.effect_id()
                && array_32(chosen_txid)? == txid
            {
                Ok(())
            } else {
                Err(BitcoinActuatorErrorV1::TerminalConflict)
            }
        }
        None => {
            transaction.execute(
                "INSERT INTO terminal_choice(route_id,leg,action,effect_id,txid) VALUES(?1,?2,?3,?4,?5)",
                params![
                    scope.route_id().as_slice(), i64::from(scope.leg().tag()),
                    i64::from(scope.action().tag()), scope.effect_id().as_slice(), txid.as_slice(),
                ],
            )?;
            Ok(())
        }
    }
}

fn classify_lookup(
    raw: &[u8],
    old_stage: BitcoinOperationStageV1,
    never_sent: bool,
    lookup: &BitcoinRpcLookupV1,
    minimum_confirmations: u32,
) -> Result<BitcoinReconciliationV1> {
    match lookup {
        BitcoinRpcLookupV1::Absent { evidence_digest } => {
            if *evidence_digest == [0; 32] {
                return Err(BitcoinActuatorErrorV1::TransactionMismatch);
            }
            if old_stage == BitcoinOperationStageV1::Prepared && never_sent {
                Ok(BitcoinReconciliationV1::ProvenNotExternalized)
            } else {
                Ok(BitcoinReconciliationV1::Ambiguous)
            }
        }
        BitcoinRpcLookupV1::Mempool(transaction) => {
            require_exact_rpc_transaction(raw, transaction)?;
            Ok(BitcoinReconciliationV1::ExactMempool)
        }
        BitcoinRpcLookupV1::Confirmed {
            transaction,
            block_hash,
            block_height,
            confirmations,
        } => {
            require_exact_rpc_transaction(raw, transaction)?;
            if *block_hash == [0; 32] || *confirmations == 0 {
                return Err(BitcoinActuatorErrorV1::TransactionMismatch);
            }
            if *confirmations >= minimum_confirmations {
                Ok(BitcoinReconciliationV1::ExactFinal {
                    confirmations: *confirmations,
                    block_height: *block_height,
                })
            } else {
                Ok(BitcoinReconciliationV1::ExactConfirmed {
                    confirmations: *confirmations,
                    block_height: *block_height,
                })
            }
        }
    }
}

fn persist_lookup_row(
    transaction: &rusqlite::Transaction<'_>,
    request: PersistLookupRequestV1<'_>,
) -> Result<()> {
    let PersistLookupRequestV1 {
        effect_id,
        raw,
        old_stage,
        never_sent,
        lookup,
        minimum_confirmations,
        now_ms,
    } = request;
    let (stage, confirmations, block_hash, block_height, evidence_digest) = match lookup {
        BitcoinRpcLookupV1::Absent { evidence_digest } => (
            if old_stage == BitcoinOperationStageV1::Prepared && never_sent {
                BitcoinOperationStageV1::Prepared
            } else {
                BitcoinOperationStageV1::Ambiguous
            },
            0,
            None,
            None,
            evidence_digest,
        ),
        BitcoinRpcLookupV1::Mempool(transaction) => {
            require_exact_rpc_transaction(raw, &transaction)?;
            (
                BitcoinOperationStageV1::MempoolObserved,
                0,
                None,
                None,
                transaction.evidence_digest,
            )
        }
        BitcoinRpcLookupV1::Confirmed {
            transaction,
            block_hash,
            block_height,
            confirmations,
        } => {
            require_exact_rpc_transaction(raw, &transaction)?;
            if block_hash == [0; 32] || confirmations == 0 {
                return Err(BitcoinActuatorErrorV1::TransactionMismatch);
            }
            (
                if confirmations >= minimum_confirmations {
                    BitcoinOperationStageV1::Final
                } else {
                    BitcoinOperationStageV1::Confirmed
                },
                confirmations,
                Some(block_hash),
                Some(block_height),
                transaction.evidence_digest,
            )
        }
    };
    if evidence_digest == [0; 32] {
        return Err(BitcoinActuatorErrorV1::TransactionMismatch);
    }
    let changed = transaction.execute(
        "UPDATE operations SET stage=?1,confirmations=?2,block_hash=?3,block_height=?4,evidence_digest=?5,updated_at_ms=?6 WHERE effect_id=?7 AND raw_transaction=?8",
        params![
            i64::from(stage.tag()), i64::from(confirmations),
            block_hash.map(|value| value.to_vec()), block_height.map(u64_blob),
            evidence_digest.as_slice(), u64_blob(now_ms), effect_id.as_slice(), raw,
        ],
    )?;
    if changed != 1 {
        return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn require_exact_rpc_transaction(
    expected_raw: &[u8],
    observed: &crate::rpc::BitcoinRpcTransactionV1,
) -> Result<()> {
    if observed.raw_transaction != expected_raw || observed.evidence_digest == [0; 32] {
        return Err(BitcoinActuatorErrorV1::TransactionMismatch);
    }
    let transaction: Transaction =
        deserialize(expected_raw).map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
    if serialize(&transaction) != expected_raw {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    Ok(())
}

fn require_funding_transaction(
    raw: &[u8],
    expected_txid: [u8; 32],
    expected_wtxid: [u8; 32],
) -> Result<()> {
    let transaction: Transaction =
        deserialize(raw).map_err(|_| BitcoinActuatorErrorV1::TransactionMismatch)?;
    if serialize(&transaction) != raw
        || transaction.compute_txid().to_raw_hash().to_byte_array() != expected_txid
        || transaction.compute_wtxid().to_raw_hash().to_byte_array() != expected_wtxid
    {
        return Err(BitcoinActuatorErrorV1::TransactionMismatch);
    }
    Ok(())
}

type FundingLookupClassification = (
    BitcoinReconciliationV1,
    BitcoinOperationStageV1,
    u32,
    Option<[u8; 32]>,
    Option<u64>,
    [u8; 32],
);

fn classify_funding_lookup(
    txid: [u8; 32],
    wtxid: [u8; 32],
    old_stage: BitcoinOperationStageV1,
    lookup: BitcoinRpcLookupV1,
    minimum_confirmations: u32,
) -> Result<FundingLookupClassification> {
    let result = match lookup {
        BitcoinRpcLookupV1::Absent { evidence_digest }
            if old_stage == BitcoinOperationStageV1::Prepared =>
        {
            (
                BitcoinReconciliationV1::ProvenNotExternalized,
                old_stage,
                0,
                None,
                None,
                evidence_digest,
            )
        }
        BitcoinRpcLookupV1::Absent { evidence_digest } => (
            BitcoinReconciliationV1::Ambiguous,
            BitcoinOperationStageV1::Ambiguous,
            0,
            None,
            None,
            evidence_digest,
        ),
        BitcoinRpcLookupV1::Mempool(transaction) => {
            require_funding_transaction(&transaction.raw_transaction, txid, wtxid)?;
            (
                BitcoinReconciliationV1::ExactMempool,
                BitcoinOperationStageV1::MempoolObserved,
                0,
                None,
                None,
                transaction.evidence_digest,
            )
        }
        BitcoinRpcLookupV1::Confirmed {
            transaction,
            block_hash,
            block_height,
            confirmations,
        } => {
            require_funding_transaction(&transaction.raw_transaction, txid, wtxid)?;
            if block_hash == [0; 32] || confirmations == 0 {
                return Err(BitcoinActuatorErrorV1::TransactionMismatch);
            }
            let finality = confirmations >= minimum_confirmations;
            (
                if finality {
                    BitcoinReconciliationV1::ExactFinal {
                        confirmations,
                        block_height,
                    }
                } else {
                    BitcoinReconciliationV1::ExactConfirmed {
                        confirmations,
                        block_height,
                    }
                },
                if finality {
                    BitcoinOperationStageV1::Final
                } else {
                    BitcoinOperationStageV1::Confirmed
                },
                confirmations,
                Some(block_hash),
                Some(block_height),
                transaction.evidence_digest,
            )
        }
    };
    if result.5 == [0; 32] {
        return Err(BitcoinActuatorErrorV1::TransactionMismatch);
    }
    Ok(result)
}

fn scope_bytes_match_except_fence(old: &[u8], new: &[u8]) -> bool {
    // Canonical scope prefix is route(32), effect(32), leg(1), action(1),
    // followed by fence(8). The trailing 32 bytes commit the changed fence,
    // so both regions are excluded from takeover equality.
    const FENCE_START: usize = 66;
    const FENCE_END: usize = 74;
    const EXPIRY_LEN: usize = 8;
    const DIGEST_LEN: usize = 32;
    let protected_end = old.len().saturating_sub(DIGEST_LEN + EXPIRY_LEN);
    old.len() == new.len()
        && old.len() >= FENCE_END + DIGEST_LEN + EXPIRY_LEN
        && old[..FENCE_START] == new[..FENCE_START]
        && old[FENCE_END..protected_end] == new[FENCE_END..protected_end]
}

fn require_claim_session(
    scope: &BitcoinActuationScopeV1,
    authority: &BitcoinParticipantClaimAuthorityV1,
    session: &BitcoinClaimSessionV1,
) -> Result<[u8; 32]> {
    let session_digest = session.session_digest()?;
    let expected_txid = validate_claim_authority(authority, session)?;
    let contract = scope
        .contract_outpoint()
        .ok_or(BitcoinActuatorErrorV1::InvalidScope)?;
    if scope.action() != BitcoinActionV1::Claim
        || scope.route_id() != session.route_id
        || scope.effect_id() != session.effect_id
        || scope.fence_epoch() != session.fence_epoch
        || scope.terms_digest() != session.terms_digest
        || scope.registry_digest() != session.registry_digest
        || scope.profile_digest() != session.profile_digest
        || scope.deployment_digest() != session.deployment_digest
        || scope.network() != session.network
        || scope.expected_txid() != expected_txid
        // Before a final signature exists, the claim-signing capability uses
        // the complete public session commitment as its intent. A distinct
        // final-broadcast capability later binds the exact signed bytes.
        || scope.intent_digest() != session_digest
        || contract.txid != session.funding_txid
        || contract.vout != session.funding_vout
        || scope.contract_amount_sat() != session.funding_amount_sat
        || scope.fee_policy().initial_fee_sat != session.fee_sat
        || scope.fee_policy().change_vout.is_some()
    {
        return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
    }
    Ok(session_digest)
}

fn insert_or_check_claim_identity(
    transaction: &rusqlite::Transaction<'_>,
    scope: &BitcoinActuationScopeV1,
    authority: &BitcoinParticipantClaimAuthorityV1,
    session_digest: [u8; 32],
    now_ms: u64,
) -> Result<()> {
    let participant_binding = transaction
        .query_row(
            "SELECT participant_id FROM participant_binding WHERE singleton=1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    match participant_binding {
        Some(value) => {
            if array_32(value)? != authority.participant_id() {
                return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
            }
        }
        None => {
            transaction.execute(
                "INSERT INTO participant_binding(singleton,participant_id) VALUES(1,?1)",
                params![authority.participant_id().as_slice()],
            )?;
        }
    }
    let existing: Option<ClaimIdentityRow> = transaction
        .query_row(
            "SELECT route_id,fence_epoch,participant_id,authority_digest,session_digest,participant_role FROM claim_transcripts WHERE effect_id=?1",
            params![scope.effect_id().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()?;
    match existing {
        Some((route, fence, participant, authority_digest, stored_session, role)) => {
            if array_32(route)? != scope.route_id()
                || array_32(participant)? != authority.participant_id()
                || array_32(authority_digest)? != authority.authority_digest()
                || array_32(stored_session)? != session_digest
                || i64_u8(role)? != authority.role().tag()
            {
                return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
            }
            let stored_fence = decode_u64(&fence)?;
            if stored_fence < scope.fence_epoch() {
                return Err(BitcoinActuatorErrorV1::ReconciliationRequired);
            }
            if stored_fence > scope.fence_epoch() {
                return Err(BitcoinActuatorErrorV1::StaleFencing);
            }
        }
        None => {
            transaction.execute(
                "INSERT INTO claim_transcripts(effect_id,route_id,fence_epoch,participant_id,participant_role,authority_digest,session_digest,local_pubnonce,remote_pubnonce,transcript_digest,local_partial,remote_partial,nonce_parity,verified_remote_partial,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,NULL,NULL,NULL,NULL,NULL,NULL,0,?8,?8)",
                params![
                    scope.effect_id().as_slice(), scope.route_id().as_slice(),
                    u64_blob(scope.fence_epoch()), authority.participant_id().as_slice(),
                    i64::from(authority.role().tag()), authority.authority_digest().as_slice(),
                    session_digest.as_slice(), u64_blob(now_ms),
                ],
            )?;
        }
    }
    Ok(())
}

fn require_claim_identity(
    participant_id: &[u8],
    authority_digest: &[u8],
    authority: &BitcoinParticipantClaimAuthorityV1,
    expected_session_digest: [u8; 32],
    transaction: &rusqlite::Transaction<'_>,
    effect_id: [u8; 32],
    expected_fence: u64,
) -> Result<()> {
    let (session_digest, fence): (Vec<u8>, Vec<u8>) = transaction.query_row(
        "SELECT session_digest,fence_epoch FROM claim_transcripts WHERE effect_id=?1",
        params![effect_id.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if array_32(participant_id.to_vec())? != authority.participant_id()
        || array_32(authority_digest.to_vec())? != authority.authority_digest()
        || array_32(session_digest)? != expected_session_digest
        || decode_u64(&fence)? != expected_fence
    {
        return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn bind_claim_bytes(
    transaction: &rusqlite::Transaction<'_>,
    effect_id: [u8; 32],
    column: &'static str,
    value: &[u8],
    now_ms: u64,
) -> Result<()> {
    let sql = match column {
        "remote_pubnonce" => {
            "UPDATE claim_transcripts SET remote_pubnonce=COALESCE(remote_pubnonce,?1),updated_at_ms=?2 WHERE effect_id=?3 AND (remote_pubnonce IS NULL OR remote_pubnonce=?1)"
        }
        "remote_partial" => {
            "UPDATE claim_transcripts SET remote_partial=COALESCE(remote_partial,?1),updated_at_ms=?2 WHERE effect_id=?3 AND (remote_partial IS NULL OR remote_partial=?1)"
        }
        _ => return Err(BitcoinActuatorErrorV1::CorruptState),
    };
    let changed =
        transaction.execute(sql, params![value, u64_blob(now_ms), effect_id.as_slice()])?;
    if changed != 1 {
        return Err(BitcoinActuatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

const fn encode_parity(parity: NonceParity) -> i64 {
    match parity {
        NonceParity::Even => 0,
        NonceParity::Odd => 1,
    }
}

fn decode_parity(value: i64) -> Result<NonceParity> {
    match value {
        0 => Ok(NonceParity::Even),
        1 => Ok(NonceParity::Odd),
        _ => Err(BitcoinActuatorErrorV1::CorruptState),
    }
}

fn u64_blob(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u64(value: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
    Ok(u64::from_be_bytes(bytes))
}

fn array_32(value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| BitcoinActuatorErrorV1::CorruptState)
}

fn array_66(value: Vec<u8>) -> Result<[u8; 66]> {
    value
        .try_into()
        .map_err(|_| BitcoinActuatorErrorV1::CorruptState)
}

fn i64_u8(value: i64) -> Result<u8> {
    u8::try_from(value).map_err(|_| BitcoinActuatorErrorV1::CorruptState)
}

fn i64_u32(value: i64) -> Result<u32> {
    u32::try_from(value).map_err(|_| BitcoinActuatorErrorV1::CorruptState)
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    let parent = path
        .parent()
        .ok_or(BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    let canonical = parent
        .canonicalize()
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    if canonical != parent {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != DIRECTORY_MODE
    {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_authority_file(path: &Path, file: &File) -> Result<()> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    let file_metadata = file
        .metadata()
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    let stat = fstat(file.as_fd()).map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !file_metadata.file_type().is_file()
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || path_metadata.uid() != geteuid().as_raw()
        || file_metadata.uid() != geteuid().as_raw()
        || stat.st_uid != geteuid().as_raw()
        || path_metadata.nlink() != 1
        || file_metadata.nlink() != 1
        || stat.st_nlink != 1
        || path_metadata.mode() & 0o7777 != FILE_MODE
        || file_metadata.mode() & 0o7777 != FILE_MODE
        || Mode::from_raw_mode(stat.st_mode).bits() & 0o7777 != FILE_MODE
        || path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
    {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn retained_identity(file: &File) -> Result<RetainedFileIdentityV1> {
    let metadata = file
        .metadata()
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    Ok(RetainedFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
fn named_identity(path: &Path) -> Result<RetainedFileIdentityV1> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != FILE_MODE
    {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(RetainedFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
fn validate_retained_file(
    path: &Path,
    file: &File,
    expected: RetainedFileIdentityV1,
    require_empty: bool,
) -> Result<()> {
    validate_authority_file(path, file)?;
    if retained_identity(file)? != expected
        || named_identity(path)? != expected
        || (require_empty
            && file
                .metadata()
                .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?
                .len()
                != 0)
    {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn lock_path(path: &Path) -> PathBuf {
    let mut bytes = path.as_os_str().to_os_string();
    bytes.push(".lock");
    PathBuf::from(bytes)
}

#[cfg(target_os = "linux")]
fn validate_lock_file(path: &Path, file: &File) -> Result<()> {
    validate_authority_file(path, file)?;
    if file
        .metadata()
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?
        .len()
        != 0
    {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_sqlite_header(file: &File, permit_empty: bool) -> Result<()> {
    let length = file
        .metadata()
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?
        .len();
    if length == 0 {
        return if permit_empty {
            Ok(())
        } else {
            Err(BitcoinActuatorErrorV1::CreationIncomplete)
        };
    }
    if length < 16 {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    let mut retained = file
        .try_clone()
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    retained
        .seek(SeekFrom::Start(0))
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    let mut header = [0u8; 16];
    retained
        .read_exact(&mut header)
        .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
    if &header != b"SQLite format 3\0" {
        return Err(BitcoinActuatorErrorV1::CorruptState);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sidecar_paths(path: &Path) -> [PathBuf; 3] {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    let mut journal = path.as_os_str().to_os_string();
    journal.push("-journal");
    [
        PathBuf::from(wal),
        PathBuf::from(shm),
        PathBuf::from(journal),
    ]
}

#[cfg(target_os = "linux")]
fn ensure_sidecars_absent(path: &Path) -> Result<()> {
    if sidecar_paths(path)
        .iter()
        .any(|sidecar| std::fs::symlink_metadata(sidecar).is_ok())
    {
        return Err(BitcoinActuatorErrorV1::DatabasePresent);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_sidecars(path: &Path) -> Result<()> {
    validate_sidecars_for_mode(path, AuthorityOpenModeV1::OpenExisting)
}

#[cfg(target_os = "linux")]
fn validate_sidecars_for_mode(path: &Path, mode: AuthorityOpenModeV1) -> Result<()> {
    for (sidecar, kind) in sidecar_paths(path).into_iter().zip([
        SqliteSidecarKindV1::Wal,
        SqliteSidecarKindV1::SharedMemory,
        SqliteSidecarKindV1::RollbackJournal,
    ]) {
        let metadata = match std::fs::symlink_metadata(&sidecar) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != FILE_MODE
        {
            return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
        }
        validate_sidecar_contents(&sidecar, kind, mode == AuthorityOpenModeV1::ResumeCreate)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SqliteSidecarKindV1 {
    Wal,
    SharedMemory,
    RollbackJournal,
}

#[cfg(target_os = "linux")]
fn validate_sidecar_contents(
    path: &Path,
    kind: SqliteSidecarKindV1,
    permit_pristine_journal: bool,
) -> Result<()> {
    let expected = named_identity(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    if retained_identity(&file)? != expected {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    let length = file
        .metadata()
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?
        .len();
    // SQLite may durably publish an empty owner-only sidecar before filling
    // its first header (and may leave it after a clean checkpoint). An empty
    // file carries no page, frame or rollback authority; every non-empty
    // sidecar remains subject to the exact format checks below.
    if length == 0 {
        return if retained_identity(&file)? == expected && named_identity(path)? == expected {
            Ok(())
        } else {
            Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
        };
    }
    if length < 28 {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    let mut header = [0u8; 28];
    file.read_exact(&mut header)
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    let valid = match kind {
        SqliteSidecarKindV1::Wal => {
            let magic = u32::from_be_bytes(
                header[..4]
                    .try_into()
                    .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?,
            );
            let version = u32::from_be_bytes(
                header[4..8]
                    .try_into()
                    .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?,
            );
            let encoded_page_size = u32::from_be_bytes(
                header[8..12]
                    .try_into()
                    .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?,
            );
            let page_size = if encoded_page_size == 1 {
                65_536
            } else {
                u64::from(encoded_page_size)
            };
            matches!(magic, 0x377f_0682 | 0x377f_0683)
                && version == 3_007_000
                && (512..=65_536).contains(&page_size)
                && page_size.is_power_of_two()
                && header[16..24] != [0; 8]
                && length >= 32
                && (length - 32) % (24 + page_size) == 0
        }
        SqliteSidecarKindV1::SharedMemory => {
            length >= 32_768
                && length % 32_768 == 0
                && u32::from_ne_bytes(
                    header[..4]
                        .try_into()
                        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?,
                ) == 3_007_000
                && header[12] <= 1
        }
        SqliteSidecarKindV1::RollbackJournal => {
            header[..8] == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
                || (permit_pristine_journal
                    && pristine_rollback_journal(&mut file, length, &header)?)
        }
    };
    if !valid || retained_identity(&file)? != expected || named_identity(path)? != expected {
        return Err(BitcoinActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn pristine_rollback_journal(file: &mut File, length: u64, header: &[u8; 28]) -> Result<bool> {
    if length != 512
        || header[..12] != [0; 12]
        || header[12..16] == [0; 4]
        || header[16..20] != [0; 4]
        || header[20..24] != 512u32.to_be_bytes()
        || header[24..28] != 4096u32.to_be_bytes()
    {
        return Ok(false);
    }
    let mut tail = [0u8; 512 - 28];
    file.read_exact(&mut tail)
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    Ok(tail == [0; 512 - 28])
}

#[cfg(target_os = "linux")]
fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    let directory =
        File::open(parent).map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)?;
    directory
        .sync_all()
        .map_err(|_| BitcoinActuatorErrorV1::InvalidStorageAuthority)
}

#[cfg(test)]
mod provisioning_tests {
    use std::error::Error;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use super::*;

    type TestResult = core::result::Result<(), Box<dyn Error>>;

    fn owner_directory() -> core::result::Result<tempfile::TempDir, std::io::Error> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    fn create_exact_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn pristine_journal() -> [u8; 512] {
        let mut journal = [0u8; 512];
        journal[12..16].copy_from_slice(&[1, 2, 3, 4]);
        journal[20..24].copy_from_slice(&512u32.to_be_bytes());
        journal[24..28].copy_from_slice(&4096u32.to_be_bytes());
        journal
    }

    fn assert_resume_rejects_journal(bytes: &[u8]) -> TestResult {
        let directory = owner_directory()?;
        let path = directory.path().join("actuator.sqlite");
        create_exact_file(&lock_path(&path), &[])?;
        create_exact_file(&path, &[])?;
        create_exact_file(&sidecar_paths(&path)[2], bytes)?;
        if DurableBitcoinActuatorV1::resume_create_production(&path, [0xd1; 32]).is_ok() {
            return Err(std::io::Error::other("resume accepted malformed journal").into());
        }
        Ok(())
    }

    #[test]
    fn creation_crash_child() -> TestResult {
        let Some(path) = std::env::var_os("DOM_BTC_ACTUATOR_TEST_CRASH_PATH") else {
            return Ok(());
        };
        let store = DurableBitcoinActuatorV1::create(Path::new(&path), [0xa1; 32])?;
        drop(store);
        Ok(())
    }

    #[test]
    fn subprocess_creation_boundaries_resume_only_through_explicit_api() -> TestResult {
        for boundary in [
            "after-lock-fsync",
            "after-database-fsync",
            "before-schema-transaction",
            "before-schema-commit",
            "after-schema-commit",
            "after-wal-transition",
        ] {
            let directory = owner_directory()?;
            let path = directory.path().join("actuator.sqlite");
            let status = std::process::Command::new(std::env::current_exe()?)
                .arg("--exact")
                .arg("store::provisioning_tests::creation_crash_child")
                .arg("--nocapture")
                .env("DOM_BTC_ACTUATOR_TEST_CRASH_PATH", &path)
                .env("DOM_BTC_ACTUATOR_TEST_CRASH_BOUNDARY", boundary)
                .status()?;
            if status.code() != Some(86) {
                return Err(std::io::Error::other(format!(
                    "creation boundary did not terminate: {boundary}"
                ))
                .into());
            }
            if boundary != "after-wal-transition"
                && DurableBitcoinActuatorV1::open_existing(&path, [0xa1; 32]).is_ok()
            {
                return Err(std::io::Error::other(format!(
                    "open_existing accepted incomplete boundary: {boundary}"
                ))
                .into());
            }
            let resumed = DurableBitcoinActuatorV1::resume_create_production(&path, [0xa1; 32])?;
            drop(resumed);
            let reopened = DurableBitcoinActuatorV1::open_existing(&path, [0xa1; 32])?;
            drop(reopened);
        }
        Ok(())
    }

    #[test]
    fn retained_database_lock_owner_and_schema_are_fail_closed() -> TestResult {
        let directory = owner_directory()?;
        let path = directory.path().join("actuator.sqlite");
        let mut store = DurableBitcoinActuatorV1::create(&path, [0xb1; 32])?;
        let displaced = directory.path().join("displaced.sqlite");
        std::fs::rename(&path, &displaced)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        assert!(matches!(
            store.acquire_lease(1, 1),
            Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
        ));
        drop(store);

        let path = directory.path().join("lock.sqlite");
        let mut store = DurableBitcoinActuatorV1::create(&path, [0xb2; 32])?;
        let mut lock = OpenOptions::new().write(true).open(lock_path(&path))?;
        lock.write_all(b"payload")?;
        lock.sync_all()?;
        assert!(matches!(
            store.acquire_lease(1, 1),
            Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
        ));
        drop(store);

        let path = directory.path().join("live-schema.sqlite");
        let mut store = DurableBitcoinActuatorV1::create(&path, [0xb7; 32])?;
        store
            .connection
            .pragma_update(None, "application_id", APPLICATION_ID + 1)?;
        assert!(matches!(
            store.acquire_lease(1, 1),
            Err(BitcoinActuatorErrorV1::CorruptState)
        ));
        drop(store);

        let path = directory.path().join("takeover.sqlite");
        let store = DurableBitcoinActuatorV1::create(&path, [0xb3; 32])?;
        drop(store);
        let takeover = DurableBitcoinActuatorV1::open_existing(&path, [0xb4; 32])?;
        drop(takeover);

        let connection = Connection::open(&path)?;
        connection.execute("CREATE TABLE foreign_state(value INTEGER) STRICT", [])?;
        drop(connection);
        assert!(matches!(
            DurableBitcoinActuatorV1::open_existing(&path, [0xb3; 32]),
            Err(BitcoinActuatorErrorV1::CorruptState)
        ));

        let path = directory.path().join("application.sqlite");
        let store = DurableBitcoinActuatorV1::create(&path, [0xb5; 32])?;
        drop(store);
        let connection = Connection::open(&path)?;
        connection.pragma_update(None, "application_id", APPLICATION_ID + 1)?;
        drop(connection);
        assert!(matches!(
            DurableBitcoinActuatorV1::open_existing(&path, [0xb5; 32]),
            Err(BitcoinActuatorErrorV1::CorruptState)
        ));

        let path = directory.path().join("missing-lock.sqlite");
        let store = DurableBitcoinActuatorV1::create(&path, [0xb6; 32])?;
        drop(store);
        std::fs::remove_file(lock_path(&path))?;
        assert!(matches!(
            DurableBitcoinActuatorV1::open_existing(&path, [0xb6; 32]),
            Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
        ));
        Ok(())
    }

    #[test]
    fn sidecar_near_misses_are_not_creation_authority() -> TestResult {
        let pristine = pristine_journal();
        assert_resume_rejects_journal(&pristine[..511])?;

        let mut nonzero_magic = pristine;
        nonzero_magic[0] = 1;
        assert_resume_rejects_journal(&nonzero_magic)?;

        let mut zero_nonce = pristine;
        zero_nonce[12..16].fill(0);
        assert_resume_rejects_journal(&zero_nonce)?;

        let mut wrong_sector = pristine;
        wrong_sector[20..24].copy_from_slice(&1024u32.to_be_bytes());
        assert_resume_rejects_journal(&wrong_sector)?;

        let mut wrong_page = pristine;
        wrong_page[24..28].copy_from_slice(&8192u32.to_be_bytes());
        assert_resume_rejects_journal(&wrong_page)?;

        let mut nonzero_body = pristine;
        nonzero_body[511] = 1;
        assert_resume_rejects_journal(&nonzero_body)?;

        let directory = owner_directory()?;
        let path = directory.path().join("actuator.sqlite");
        create_exact_file(&lock_path(&path), &[])?;
        create_exact_file(&path, &[])?;
        create_exact_file(&sidecar_paths(&path)[2], &pristine)?;
        let resumed = DurableBitcoinActuatorV1::resume_create_production(&path, [0xd2; 32])?;
        drop(resumed);
        let reopened = DurableBitcoinActuatorV1::open_existing(&path, [0xd2; 32])?;
        drop(reopened);

        let directory = owner_directory()?;
        let path = directory.path().join("foreign-wal.sqlite");
        let store = DurableBitcoinActuatorV1::create(&path, [0xd3; 32])?;
        drop(store);
        create_exact_file(&sidecar_paths(&path)[0], &[0; 32])?;
        assert!(matches!(
            DurableBitcoinActuatorV1::open_existing(&path, [0xd3; 32]),
            Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
        ));
        Ok(())
    }

    #[test]
    fn resume_refuses_any_economic_state() -> TestResult {
        let directory = owner_directory()?;
        let path = directory.path().join("actuator.sqlite");
        let mut store = DurableBitcoinActuatorV1::create(&path, [0xc1; 32])?;
        store.acquire_lease(1, 100)?;
        drop(store);
        assert!(matches!(
            DurableBitcoinActuatorV1::resume_create_production(&path, [0xc1; 32]),
            Err(BitcoinActuatorErrorV1::CorruptState)
        ));
        Ok(())
    }
}

#[cfg(test)]
mod fresh_time_tests {
    use std::os::unix::fs::PermissionsExt;

    use adapter_btc::timelock::ChainTimingBoundsV1;
    use adapter_btc::types::BitcoinNetworkV1;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::Network;
    use btc_crypto::SecpContext;
    use chain_profile::{ChainKindV1, ChainProfileV1};
    use deployment_registry::{
        AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, BitcoinDeploymentV1,
        ChainDeploymentV1, DomDeploymentV1, DomNetworkV1, DomRuntimeIdentityV1,
        RegistryChainProfileV1, RegistryManifestV1, RegistrySignatureV1,
        RegistryValidationPolicyV1, ResolvedBitcoinDeploymentV1, SignedRegistryV1,
    };
    use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};

    use super::*;
    use crate::{
        BitcoinActuationScopeAuthorizationV1, BitcoinFeeBumpPolicyV1, BitcoinLegV1,
        BitcoinRpcErrorV1,
    };

    type TestResult = core::result::Result<(), Box<dyn std::error::Error>>;

    struct AbsentRpcV1;

    impl BitcoinRpcV1 for AbsentRpcV1 {
        fn verify_scope(
            &mut self,
            _scope: &BitcoinActuationScopeV1,
        ) -> core::result::Result<(), BitcoinRpcErrorV1> {
            Ok(())
        }

        fn broadcast_exact(
            &mut self,
            _raw_transaction: &[u8],
            _expected_txid: [u8; 32],
        ) -> core::result::Result<BitcoinRpcBroadcastV1, BitcoinRpcErrorV1> {
            Err(BitcoinRpcErrorV1::Rejected)
        }

        fn lookup_exact(
            &mut self,
            _expected_txid: [u8; 32],
        ) -> core::result::Result<BitcoinRpcLookupV1, BitcoinRpcErrorV1> {
            Ok(BitcoinRpcLookupV1::Absent {
                evidence_digest: [0xe1; 32],
            })
        }
    }

    fn funding_deployment(
    ) -> core::result::Result<ResolvedBitcoinDeploymentV1, Box<dyn std::error::Error>> {
        let btc_chain = ChainId([0x02; 32]);
        let dom_chain = ChainId([
            0x22, 0x38, 0x4b, 0x4c, 0xbf, 0xaa, 0xe3, 0x06, 0xa7, 0xbd, 0xb2, 0x3a, 0x82, 0x24,
            0x42, 0xf7, 0xe6, 0x8f, 0xb5, 0x1f, 0x65, 0x32, 0x86, 0x97, 0xa7, 0x54, 0xa9, 0xf3,
            0xab, 0xd6, 0x98, 0xe1,
        ]);
        let btc_asset = AssetId([0x04; 32]);
        let dom_asset = AssetId([0x05; 32]);
        let timing = ChainTimingBoundsV1 {
            min_block_seconds: 1,
            max_block_seconds: 2,
            max_reorg_seconds: 10,
            observation_seconds: 2,
            broadcast_seconds: 2,
        };
        let finality = FinalityPolicyV1 {
            min_confirmations: 2,
            max_reorg_depth: 3,
        };
        let manifest = RegistryManifestV1 {
            network_id: [0x06; 32],
            epoch: 7,
            valid_from: 1,
            expires_at: 10_000,
            dom: DomDeploymentV1 {
                chain_id: dom_chain,
                genesis_hash: [
                    0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9,
                    0x76, 0xbf, 0x3e, 0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc,
                    0xa9, 0x9d, 0xde, 0xe3, 0xfe, 0x1f,
                ],
                runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
                consensus_rules_digest: [0x08; 32],
                scriptless_api_version: 1,
                timing,
                finality,
                native_asset: dom_asset,
            },
            chains: vec![RegistryChainProfileV1 {
                profile: ChainProfileV1 {
                    chain_id: btc_chain,
                    kind: ChainKindV1::Bitcoin {
                        network: BitcoinNetworkV1::Regtest,
                    },
                    timing,
                    finality,
                    native_asset: btc_asset,
                    allowed_assets: vec![],
                },
                deployment: ChainDeploymentV1::Bitcoin(BitcoinDeploymentV1 {
                    genesis_hash: genesis_block(Network::Regtest)
                        .block_hash()
                        .to_raw_hash()
                        .to_byte_array(),
                    signet_challenge: vec![],
                    max_fee_rate_sat_vbyte: 100,
                    min_relay_fee_sat_kvb: 1_000,
                }),
            }],
            assets: vec![
                AssetBindingV1 {
                    chain_id: btc_chain,
                    asset_id: btc_asset,
                    decimals: 8,
                    representation: AssetRepresentationV1::Native,
                },
                AssetBindingV1 {
                    chain_id: dom_chain,
                    asset_id: dom_asset,
                    decimals: 9,
                    representation: AssetRepresentationV1::Native,
                },
            ],
        };
        let crypto = SecpContext::new(&[0x09; 32]);
        let digest = manifest.manifest_digest()?;
        let (signature, public_key) = crypto.sign_bip340(&[0x0a; 32], &digest, &[0x0b; 32])?;
        let authorities = AuthoritySetV1::new(1, vec![public_key])?;
        let signed = SignedRegistryV1::new(
            &manifest,
            vec![RegistrySignatureV1 {
                signer_index: 0,
                signature,
            }],
        )?;
        let verified = signed.verify(
            &authorities,
            &crypto,
            RegistryValidationPolicyV1 {
                now_seconds: 100,
                expected_network_id: [0x06; 32],
                minimum_epoch: 7,
            },
        )?;
        Ok(verified
            .resolve_chain(btc_chain)
            .ok_or("missing Bitcoin chain")?
            .bitcoin_deployment_capability()?)
    }

    fn funding_scope(
        deployment: &ResolvedBitcoinDeploymentV1,
        fence_epoch: u64,
    ) -> Result<BitcoinActuationScopeV1> {
        BitcoinActuationScopeV1::authorize(BitcoinActuationScopeAuthorizationV1 {
            deployment,
            route_id: [0x11; 32],
            effect_id: [0x12; 32],
            leg: BitcoinLegV1::Downstream,
            action: BitcoinActionV1::Funding,
            fence_epoch,
            terms_digest: [0x13; 32],
            expected_txid: [0x14; 32],
            intent_digest: [0x15; 32],
            contract_outpoint: None,
            contract_amount_sat: 100_000,
            refund_record_digest: Some([0x16; 32]),
            fee_policy: BitcoinFeeBumpPolicyV1 {
                initial_fee_sat: 1_000,
                maximum_fee_sat: 5_000,
                maximum_fee_rate_sat_vbyte: 100,
                change_vout: None,
            },
            valid_until_ms: 10_000,
        })
    }

    fn plant_funding(
        store: &mut DurableBitcoinActuatorV1,
        scope: &BitcoinActuationScopeV1,
        now_ms: u64,
    ) -> Result<()> {
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_clock(&transaction, now_ms)?;
        require_scope_lease(&transaction, &store.owner_digest, scope, now_ms)?;
        transaction.execute(
            "INSERT INTO funding_custody(
                effect_id,route_id,leg,fence_epoch,scope_bytes,scope_digest,txid,wtxid,
                refund_record_digest,custody_digest,send_attempts,stage,confirmations,
                block_hash,block_height,evidence_digest,created_at_ms,updated_at_ms
             ) VALUES(?1,?2,2,?3,?4,?5,?6,?7,?8,?9,0,?10,0,NULL,NULL,NULL,?11,?11)",
            params![
                scope.effect_id().as_slice(),
                scope.route_id().as_slice(),
                u64_blob(scope.fence_epoch()),
                scope.canonical_bytes(),
                scope.scope_digest().as_slice(),
                scope.expected_txid().as_slice(),
                [0x17_u8; 32].as_slice(),
                scope
                    .refund_record_digest()
                    .ok_or(BitcoinActuatorErrorV1::InvalidScope)?
                    .as_slice(),
                scope.intent_digest().as_slice(),
                i64::from(BitcoinOperationStageV1::Prepared.tag()),
                u64_blob(now_ms),
            ],
        )?;
        audit_runtime_state(&transaction, &store.owner_digest)?;
        transaction.commit()?;
        Ok(())
    }

    fn retained_clock(store: &DurableBitcoinActuatorV1) -> Result<u64> {
        let bytes: Vec<u8> = store.connection.query_row(
            "SELECT high_water_ms FROM monotonic_clock WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        decode_u64(&bytes)
    }

    #[test]
    fn funding_reconciliation_uses_post_rpc_time_without_prelookup_mutation() -> TestResult {
        let deployment = funding_deployment()?;
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("funding.sqlite");
        let scope = funding_scope(&deployment, 1)?;
        let mut store = DurableBitcoinActuatorV1::create(&path, [0x18; 32])?;
        store.acquire_lease(100, 50)?;
        plant_funding(&mut store, &scope, 101)?;
        let before = store.funding_operation(scope.effect_id())?;
        let clock_before = retained_clock(&store)?;
        let mut rpc = AbsentRpcV1;
        assert!(matches!(
            store.reconcile_funding(&scope, &mut rpc, 149, || Ok(151)),
            Err(BitcoinActuatorErrorV1::StaleFencing)
        ));
        assert_eq!(store.funding_operation(scope.effect_id())?, before);
        assert_eq!(retained_clock(&store)?, clock_before);
        Ok(())
    }

    #[test]
    fn funding_takeover_uses_post_rpc_time_without_refencing_expired_lease() -> TestResult {
        let deployment = funding_deployment()?;
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("funding-takeover.sqlite");
        let old_scope = funding_scope(&deployment, 1)?;
        let mut store = DurableBitcoinActuatorV1::create(&path, [0x19; 32])?;
        store.acquire_lease(100, 50)?;
        plant_funding(&mut store, &old_scope, 101)?;
        drop(store);

        let mut store = DurableBitcoinActuatorV1::open_existing(&path, [0x1a; 32])?;
        assert_eq!(store.acquire_lease(151, 50)?.fence_epoch(), 2);
        let new_scope = funding_scope(&deployment, 2)?;
        let before = store.funding_operation(old_scope.effect_id())?;
        let clock_before = retained_clock(&store)?;
        let mut rpc = AbsentRpcV1;
        assert!(matches!(
            store.reconcile_funding_takeover(&new_scope, &mut rpc, 200, || Ok(202)),
            Err(BitcoinActuatorErrorV1::StaleFencing)
        ));
        assert_eq!(store.funding_operation(old_scope.effect_id())?, before);
        assert_eq!(retained_clock(&store)?, clock_before);
        Ok(())
    }
}

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::ops::Deref;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use adapter_evm::{
    abi::{
        decode_address, decode_u64, decode_u8, event_topic0, selector, split_words, SIG_CLAIM,
        SIG_CLAIMED, SIG_OPEN, SIG_REFUND, SIG_REFUNDED,
    },
    derive_binding, derive_lock_id, keccak256, LockTerms,
};
use deployment_registry::{AssetRepresentationV1, ResolvedEvmDeploymentV1};
use rusqlite::{
    config::DbConfig, params, Connection, OpenFlags, OptionalExtension, Transaction,
    TransactionBehavior,
};
#[cfg(target_os = "linux")]
use rustix::fs::{flock, FlockOperation};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;

use crate::model::{
    BroadcastDispositionV1, BroadcastOutcomeV1, Digest32, Eip1559SigningRequestV1,
    EvmActuatorLeaseV1, EvmAddressV1, EvmAttemptViewV1, EvmFeesV1, EvmObservationMutationRequestV1,
    EvmOperationBindingViewV1, EvmOperationKindV1, EvmOperationMutationRequestV1,
    EvmOperationPreparationRequestV1, EvmOperationViewV1, EvmRefundAuthorizationViewV1,
    EvmRetainedMutationKindV1, EvmSignerRoleV1, EvmTxStageV1, LeaseAcquireOutcomeV1,
    MutationOutcomeV1, MutationStatusV1, NonceSnapshotV1, ReconciliationKindV1,
    ScopedEip1559SignerV1, ScopedEvmClaimV1, ScopedEvmOpenV1, ScopedEvmRefundV1,
    ValidatedEvmLockV1, ZERO_DIGEST,
};
use crate::rpc::{
    EvmRpcV1, RpcFinalizedTimeV1, RpcLogV1, RpcReceiptLookupV1, RpcReceiptV1,
    RpcTransactionLookupV1, RpcTransactionV1,
};
use crate::transaction::{
    domain_digest, fields_digest, signing_hash, verify_and_encode_signed, Eip1559FieldsV1,
    CLAIM_CALLDATA_LEN, MAX_RAW_TRANSACTION_BYTES_V1, REFUND_CALLDATA_LEN,
};
use crate::{EvmActuatorErrorV1, Result};

use zeroize::Zeroizing;

const SCHEMA_VERSION: i64 = 3;
const APPLICATION_ID: i64 = 1_163_280_689;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_LEASE_DURATION_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_OBSERVATION_TTL_MS: u64 = 60 * 60 * 1_000;
const MAX_BUSY_TIMEOUT_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreationBoundaryV1 {
    ProcessLockPublished,
    DatabaseFileSynced,
    BeforeSchemaTransaction,
    BeforeSchemaCommit,
    SchemaCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumableCreationStateV1 {
    PristineSqlite,
    InitializedExact,
}

// SQLite returns the nullable operation locator, mutation commitment and
// resulting revision as owned blobs. Naming that wire-shaped row keeps the
// recovery path auditable without suppressing the workspace's complexity
// lint or pretending the three fields form a domain object before decoding.
type RetainedMutationRowV1 = (Option<Vec<u8>>, Vec<u8>, Vec<u8>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RefundAuthorizationV1 {
    block_number: u64,
    block_hash: Digest32,
    timestamp: u64,
    evidence_digest: Digest32,
}

struct OperationPreparationV1<'a> {
    kind: EvmOperationKindV1,
    signer_role: EvmSignerRoleV1,
    route_id: Digest32,
    effect_id: Digest32,
    semantic_digest: Digest32,
    lock: &'a ValidatedEvmLockV1,
    value: Digest32,
    calldata: &'a [u8],
    refund_authorization: Option<RefundAuthorizationV1>,
}

/// Durable SQLite/WAL authority for scoped EIP-1559 operations.
pub struct DurableEvmActuatorV1 {
    connection: Connection,
    path: PathBuf,
    database_authority: File,
    _process_lock: File,
}

struct AuditedTransaction<'connection> {
    transaction: Transaction<'connection>,
}

impl<'connection> Deref for AuditedTransaction<'connection> {
    type Target = Transaction<'connection>;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl AuditedTransaction<'_> {
    fn commit(self) -> Result<()> {
        validate_backend_and_schema(&self.transaction)?;
        audit_retained_state_in_transaction(&self.transaction)?;
        self.transaction.commit()?;
        Ok(())
    }
}

impl core::fmt::Debug for DurableEvmActuatorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableEvmActuatorV1([redacted])")
    }
}

impl DurableEvmActuatorV1 {
    /// Creates a new owner-only database. Existing paths are refused.
    pub fn create(path: &Path) -> Result<Self> {
        Self::create_with_boundary_hook(path, |_| Ok(()))
    }

    fn create_with_boundary_hook<F>(path: &Path, mut boundary: F) -> Result<Self>
    where
        F: FnMut(CreationBoundaryV1) -> Result<()>,
    {
        require_linux()?;
        validate_parent(path)?;
        require_create_path_absent(path)?;
        require_sidecars_absent(path)?;
        let process_lock = acquire_process_lock(path, true)?;
        boundary(CreationBoundaryV1::ProcessLockPublished)?;
        let database_authority = create_database_authority(path)?;
        boundary(CreationBoundaryV1::DatabaseFileSynced)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, true)?;
        validate_database_path(&connection, path)?;
        validate_open_file_identity(&database_authority, path)?;
        boundary(CreationBoundaryV1::BeforeSchemaTransaction)?;
        Self::create_schema_with_boundary_hook(&connection, || {
            boundary(CreationBoundaryV1::BeforeSchemaCommit)
        })?;
        boundary(CreationBoundaryV1::SchemaCommitted)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
            database_authority,
            _process_lock: process_lock,
        };
        store.audit_storage_authority()?;
        sync_owner_directory(path)?;
        Ok(store)
    }

    /// Resumes only an authenticated, economically empty crash prefix of an
    /// explicit production create already authorized by an external journal.
    ///
    /// The exact owner-only lock file must already exist and be exclusively
    /// acquirable. A missing database, pristine SQLite file, or exact V3 store
    /// with no retained lease, nonce, allowance, operation, attempt, or
    /// mutation may be completed. No general open-or-create fallback exists.
    pub fn resume_create_production(path: &Path) -> Result<Self> {
        require_linux()?;
        validate_parent(path)?;
        let process_lock = acquire_process_lock(path, false)?;
        let database_authority = match fs::symlink_metadata(path) {
            Ok(_) => {
                validate_owner_only_file(path)?;
                validate_resumable_sidecars(path)?;
                open_database_authority(path)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                require_sqlite_sidecars_absent(path)?;
                create_database_authority(path)?
            }
            Err(_) => return Err(EvmActuatorErrorV1::InvalidStorageAuthority),
        };
        let state = preflight_resumable_creation_state(path, &database_authority)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(
            &connection,
            state == ResumableCreationStateV1::PristineSqlite,
        )?;
        validate_database_path(&connection, path)?;
        validate_open_file_identity(&database_authority, path)?;
        match state {
            ResumableCreationStateV1::PristineSqlite => Self::create_schema(&connection)?,
            ResumableCreationStateV1::InitializedExact => {}
        }
        validate_pristine_initialized_store(&connection)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
            database_authority,
            _process_lock: process_lock,
        };
        store.audit_storage_authority()?;
        sync_owner_directory(path)?;
        Ok(store)
    }

    /// Opens an existing owner-only database without creating or migrating a
    /// missing authority.
    pub fn open_existing(path: &Path) -> Result<Self> {
        require_linux()?;
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(EvmActuatorErrorV1::DatabaseMissing)
            }
            Err(_) => return Err(EvmActuatorErrorV1::InvalidStorageAuthority),
        }
        validate_parent(path)?;
        validate_owner_only_file(path)?;
        validate_resumable_sidecars(path)?;
        let process_lock = acquire_process_lock(path, false)?;
        let database_authority = open_database_authority(path)?;
        if preflight_resumable_creation_state(path, &database_authority)?
            == ResumableCreationStateV1::PristineSqlite
        {
            return Err(EvmActuatorErrorV1::CreationIncomplete);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, false)?;
        validate_database_path(&connection, path)?;
        validate_backend_and_schema(&connection)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
            database_authority,
            _process_lock: process_lock,
        };
        store.audit_storage_authority()?;
        Ok(store)
    }

    fn create_schema(connection: &Connection) -> Result<()> {
        Self::create_schema_with_boundary_hook(connection, || Ok(()))
    }

    fn create_schema_with_boundary_hook<F>(connection: &Connection, before_commit: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(
            "CREATE TABLE evm_schema (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 version INTEGER NOT NULL
             ) STRICT;
             INSERT INTO evm_schema(singleton, version) VALUES (1, 3);

             CREATE TABLE evm_leases (
                 authority_id BLOB PRIMARY KEY CHECK(length(authority_id)=32),
                 chain_id_be BLOB NOT NULL CHECK(length(chain_id_be)=8),
                 account BLOB NOT NULL CHECK(length(account)=20),
                 owner_id BLOB NOT NULL CHECK(length(owner_id)=32),
                 fencing_epoch_be BLOB NOT NULL CHECK(length(fencing_epoch_be)=8),
                 lease_until_be BLOB NOT NULL CHECK(length(lease_until_be)=8),
                 clock_high_water_be BLOB NOT NULL CHECK(length(clock_high_water_be)=8)
             ) STRICT;

             CREATE TABLE evm_nonce_snapshots (
                 authority_id BLOB PRIMARY KEY REFERENCES evm_leases(authority_id),
                 observation_revision_be BLOB NOT NULL CHECK(length(observation_revision_be)=8),
                 allocation_revision_be BLOB NOT NULL CHECK(length(allocation_revision_be)=8),
                 pending_nonce_be BLOB NOT NULL CHECK(length(pending_nonce_be)=8),
                 evidence_digest BLOB NOT NULL CHECK(length(evidence_digest)=32),
                 observed_at_be BLOB NOT NULL CHECK(length(observed_at_be)=8),
                 valid_until_be BLOB NOT NULL CHECK(length(valid_until_be)=8)
             ) STRICT;

             CREATE TABLE evm_allowances (
                 authority_id BLOB NOT NULL REFERENCES evm_leases(authority_id),
                 token BLOB NOT NULL CHECK(length(token)=20),
                 spender BLOB NOT NULL CHECK(length(spender)=20),
                 revision_be BLOB NOT NULL CHECK(length(revision_be)=8),
                 amount BLOB NOT NULL CHECK(length(amount)=32),
                 block_number_be BLOB NOT NULL CHECK(length(block_number_be)=8),
                 block_hash BLOB NOT NULL CHECK(length(block_hash)=32),
                 evidence_digest BLOB NOT NULL CHECK(length(evidence_digest)=32),
                 registry_digest BLOB NOT NULL CHECK(length(registry_digest)=32),
                 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32),
                 asset_digest BLOB NOT NULL CHECK(length(asset_digest)=32),
                 observed_at_be BLOB NOT NULL CHECK(length(observed_at_be)=8),
                 valid_until_be BLOB NOT NULL CHECK(length(valid_until_be)=8),
                 PRIMARY KEY(authority_id, token, spender)
             ) STRICT;

             CREATE TABLE evm_operations (
                 operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=32),
                 authority_id BLOB NOT NULL REFERENCES evm_leases(authority_id),
                 route_id BLOB NOT NULL CHECK(length(route_id)=32),
                 effect_id BLOB NOT NULL CHECK(length(effect_id)=32),
                 request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
                 operation_kind INTEGER NOT NULL CHECK(operation_kind IN (1,2,3)),
                 signer_role INTEGER NOT NULL CHECK(signer_role IN (1,2)),
                 revision_be BLOB NOT NULL CHECK(length(revision_be)=8),
                 stage_tag INTEGER NOT NULL,
                 fencing_epoch_be BLOB NOT NULL CHECK(length(fencing_epoch_be)=8),
                 chain_id_be BLOB NOT NULL CHECK(length(chain_id_be)=8),
                 account BLOB NOT NULL CHECK(length(account)=20),
                 nonce_be BLOB NOT NULL CHECK(length(nonce_be)=8),
                 destination BLOB NOT NULL CHECK(length(destination)=20),
                 value BLOB NOT NULL CHECK(length(value)=32),
                 calldata BLOB NOT NULL,
                 calldata_digest BLOB NOT NULL CHECK(length(calldata_digest)=32),
                 gas_limit_be BLOB NOT NULL CHECK(length(gas_limit_be)=8),
                 max_fee_be BLOB NOT NULL CHECK(length(max_fee_be)=16),
                 max_priority_fee_be BLOB NOT NULL CHECK(length(max_priority_fee_be)=16),
                 max_fee_cap_be BLOB NOT NULL CHECK(length(max_fee_cap_be)=16),
                 max_priority_fee_cap_be BLOB NOT NULL CHECK(length(max_priority_fee_cap_be)=16),
                 registry_digest BLOB NOT NULL CHECK(length(registry_digest)=32),
                 profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32),
                 asset_digest BLOB NOT NULL CHECK(length(asset_digest)=32),
                 deployment_digest BLOB NOT NULL CHECK(length(deployment_digest)=32),
                 destination_code_hash BLOB NOT NULL CHECK(length(destination_code_hash)=32),
                 genesis_hash BLOB NOT NULL CHECK(length(genesis_hash)=32),
                 semantic_digest BLOB NOT NULL CHECK(length(semantic_digest)=32),
                 terms_digest BLOB NOT NULL CHECK(length(terms_digest)=32),
                 lock_id BLOB NOT NULL CHECK(length(lock_id)=32),
                 binding BLOB NOT NULL CHECK(length(binding)=32),
                 beneficiary BLOB NOT NULL CHECK(length(beneficiary)=20),
                 funder BLOB NOT NULL CHECK(length(funder)=20),
                 adaptor_address BLOB NOT NULL CHECK(length(adaptor_address)=20),
                 deadline_be BLOB NOT NULL CHECK(length(deadline_be)=8),
                 erc20_token BLOB CHECK(erc20_token IS NULL OR length(erc20_token)=20),
                 lock_amount BLOB NOT NULL CHECK(length(lock_amount)=32),
                 allowance_revision_be BLOB CHECK(allowance_revision_be IS NULL OR length(allowance_revision_be)=8),
                 refund_auth_block_number_be BLOB CHECK(refund_auth_block_number_be IS NULL OR length(refund_auth_block_number_be)=8),
                 refund_auth_block_hash BLOB CHECK(refund_auth_block_hash IS NULL OR length(refund_auth_block_hash)=32),
                 refund_auth_timestamp_be BLOB CHECK(refund_auth_timestamp_be IS NULL OR length(refund_auth_timestamp_be)=8),
                 refund_auth_evidence BLOB CHECK(refund_auth_evidence IS NULL OR length(refund_auth_evidence)=32),
                 current_attempt INTEGER NOT NULL,
                 transaction_hash BLOB CHECK(transaction_hash IS NULL OR length(transaction_hash)=32),
                 ambiguous_after_send INTEGER NOT NULL CHECK(ambiguous_after_send IN (0,1)),
                 secret_exposed INTEGER NOT NULL CHECK(secret_exposed IN (0,1)),
                 execution_success INTEGER CHECK(execution_success IS NULL OR execution_success IN (0,1)),
                 observed_evidence BLOB CHECK(observed_evidence IS NULL OR length(observed_evidence)=32),
                 final_block_number_be BLOB CHECK(final_block_number_be IS NULL OR length(final_block_number_be)=8),
                 final_block_hash BLOB CHECK(final_block_hash IS NULL OR length(final_block_hash)=32),
                 final_evidence BLOB CHECK(final_evidence IS NULL OR length(final_evidence)=32),
                 terminal_event_digest BLOB CHECK(terminal_event_digest IS NULL OR length(terminal_event_digest)=32),
                 finality_invalidation_evidence BLOB CHECK(finality_invalidation_evidence IS NULL OR length(finality_invalidation_evidence)=32),
                 reconciliation_kind INTEGER,
                 reconciled_from_stage INTEGER,
                 created_at_be BLOB NOT NULL CHECK(length(created_at_be)=8),
                 updated_at_be BLOB NOT NULL CHECK(length(updated_at_be)=8),
                 UNIQUE(authority_id, effect_id),
                 UNIQUE(authority_id, nonce_be)
             ) STRICT;

             CREATE TABLE evm_attempts (
                 operation_id BLOB NOT NULL REFERENCES evm_operations(operation_id),
                 attempt INTEGER NOT NULL,
                 stage_tag INTEGER NOT NULL,
                 max_fee_be BLOB NOT NULL CHECK(length(max_fee_be)=16),
                 max_priority_fee_be BLOB NOT NULL CHECK(length(max_priority_fee_be)=16),
                 signing_hash BLOB NOT NULL CHECK(length(signing_hash)=32),
                 raw_transaction BLOB NOT NULL,
                 transaction_hash BLOB NOT NULL CHECK(length(transaction_hash)=32),
                 y_parity INTEGER NOT NULL CHECK(y_parity IN (0,1)),
                 signature_r BLOB NOT NULL CHECK(length(signature_r)=32),
                 signature_s BLOB NOT NULL CHECK(length(signature_s)=32),
                 send_attempted_at_be BLOB CHECK(send_attempted_at_be IS NULL OR length(send_attempted_at_be)=8),
                 evidence_digest BLOB CHECK(evidence_digest IS NULL OR length(evidence_digest)=32),
                 replaced_by INTEGER,
                 PRIMARY KEY(operation_id, attempt)
             ) STRICT;

             CREATE TABLE evm_mutations (
                 authority_id BLOB NOT NULL REFERENCES evm_leases(authority_id),
                 mutation_id BLOB NOT NULL CHECK(length(mutation_id)=32),
                 mutation_digest BLOB NOT NULL CHECK(length(mutation_digest)=32),
                 operation_id BLOB REFERENCES evm_operations(operation_id)
                     CHECK(operation_id IS NULL OR length(operation_id)=32),
                 resulting_revision_be BLOB NOT NULL CHECK(length(resulting_revision_be)=8),
                 PRIMARY KEY(authority_id, mutation_id)
             ) STRICT;
             PRAGMA application_id = 1163280689;
             PRAGMA user_version = 3;",
        )?;
        before_commit()?;
        let version: i64 = transaction.query_row(
            "SELECT version FROM evm_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version != SCHEMA_VERSION {
            return Err(EvmActuatorErrorV1::CorruptState);
        };
        transaction.commit()?;
        Ok(())
    }

    fn immediate(&mut self) -> Result<AuditedTransaction<'_>> {
        self.audit_file_authority()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_database_path(&transaction, &self.path)?;
        validate_backend_and_schema(&transaction)?;
        audit_retained_state_in_transaction(&transaction)?;
        Ok(AuditedTransaction { transaction })
    }

    fn deferred(&self) -> Result<AuditedTransaction<'_>> {
        self.audit_file_authority()?;
        let transaction = self.connection.unchecked_transaction()?;
        validate_database_path(&transaction, &self.path)?;
        validate_backend_and_schema(&transaction)?;
        audit_retained_state_in_transaction(&transaction)?;
        Ok(AuditedTransaction { transaction })
    }

    fn audit_storage_authority(&self) -> Result<()> {
        self.deferred()?.commit()
    }

    fn audit_file_authority(&self) -> Result<()> {
        validate_parent(&self.path)?;
        validate_open_file_identity(&self.database_authority, &self.path)?;
        let process_lock_path = lock_path(&self.path);
        validate_open_file_identity(&self._process_lock, &process_lock_path)?;
        if self
            ._process_lock
            .metadata()
            .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?
            .len()
            != 0
        {
            return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
        }
        validate_resumable_sidecars(&self.path)
    }

    /// Acquires exclusive authority for the authenticated funder account.
    pub fn acquire_lease(
        &mut self,
        deployment: &ResolvedEvmDeploymentV1,
        owner_id: Digest32,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<LeaseAcquireOutcomeV1> {
        self.acquire_lease_for_role(
            deployment,
            EvmSignerRoleV1::Funder,
            owner_id,
            now_unix_ms,
            lease_duration_ms,
        )
    }

    /// Acquires exclusive authority for one account role authenticated in the
    /// resolved EVM session. Claims require `Beneficiary`; opens and the local
    /// refund policy require `Funder`.
    pub fn acquire_lease_for_role(
        &mut self,
        deployment: &ResolvedEvmDeploymentV1,
        role: EvmSignerRoleV1,
        owner_id: Digest32,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<LeaseAcquireOutcomeV1> {
        validate_id(owner_id)?;
        let config = deployment.adapter_config();
        let account = match role {
            EvmSignerRoleV1::Funder => config.funder,
            EvmSignerRoleV1::Beneficiary => config.beneficiary,
        };
        validate_time_window(now_unix_ms, lease_duration_ms, MAX_LEASE_DURATION_MS)?;
        let authority_id = authority_id(config.chain_id, account);
        let until = now_unix_ms
            .checked_add(lease_duration_ms)
            .ok_or(EvmActuatorErrorV1::InvalidTime)?;
        let transaction = self.immediate()?;
        let existing = transaction
            .query_row(
                "SELECT chain_id_be, account, owner_id, fencing_epoch_be, lease_until_be,
                        clock_high_water_be
                 FROM evm_leases WHERE authority_id=?1",
                params![authority_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()?;
        let (lease, status) = match existing {
            None => {
                let lease = EvmActuatorLeaseV1 {
                    authority_id,
                    owner_id,
                    chain_id: config.chain_id,
                    account,
                    fencing_epoch: 1,
                    lease_until_unix_ms: until,
                };
                transaction.execute(
                    "INSERT INTO evm_leases
                     (authority_id, chain_id_be, account, owner_id, fencing_epoch_be,
                      lease_until_be,clock_high_water_be)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        authority_id.as_slice(),
                        config.chain_id.to_be_bytes().as_slice(),
                        account.as_slice(),
                        owner_id.as_slice(),
                        1u64.to_be_bytes().as_slice(),
                        until.to_be_bytes().as_slice(),
                        now_unix_ms.to_be_bytes().as_slice(),
                    ],
                )?;
                (lease, MutationStatusV1::Committed)
            }
            Some((chain, stored_account, stored_owner, fence, stored_until, high_water)) => {
                if blob_u64(chain)? != config.chain_id || blob20(stored_account)? != account {
                    return Err(EvmActuatorErrorV1::CorruptState);
                }
                let stored_owner = blob32(stored_owner)?;
                let stored_fence = blob_u64(fence)?;
                let stored_until = blob_u64(stored_until)?;
                let high_water = blob_u64(high_water)?;
                if now_unix_ms < high_water {
                    return Err(EvmActuatorErrorV1::InvalidTime);
                }
                if stored_until >= now_unix_ms {
                    if stored_owner != owner_id {
                        return Err(EvmActuatorErrorV1::LeaseHeld);
                    }
                    transaction.execute(
                        "UPDATE evm_leases SET clock_high_water_be=?2 WHERE authority_id=?1",
                        params![
                            authority_id.as_slice(),
                            now_unix_ms.to_be_bytes().as_slice()
                        ],
                    )?;
                    (
                        EvmActuatorLeaseV1 {
                            authority_id,
                            owner_id,
                            chain_id: config.chain_id,
                            account,
                            fencing_epoch: stored_fence,
                            lease_until_unix_ms: stored_until,
                        },
                        MutationStatusV1::DuplicateSameBytes,
                    )
                } else {
                    let next_fence = stored_fence
                        .checked_add(1)
                        .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
                    transaction.execute(
                        "UPDATE evm_leases SET owner_id=?2, fencing_epoch_be=?3,
                         lease_until_be=?4,clock_high_water_be=?5 WHERE authority_id=?1",
                        params![
                            authority_id.as_slice(),
                            owner_id.as_slice(),
                            next_fence.to_be_bytes().as_slice(),
                            until.to_be_bytes().as_slice(),
                            now_unix_ms.to_be_bytes().as_slice(),
                        ],
                    )?;
                    (
                        EvmActuatorLeaseV1 {
                            authority_id,
                            owner_id,
                            chain_id: config.chain_id,
                            account,
                            fencing_epoch: next_fence,
                            lease_until_unix_ms: until,
                        },
                        MutationStatusV1::Committed,
                    )
                }
            }
        };
        transaction.commit()?;
        Ok(match status {
            MutationStatusV1::Committed => LeaseAcquireOutcomeV1::Acquired(lease),
            MutationStatusV1::DuplicateSameBytes => LeaseAcquireOutcomeV1::AlreadyOwned(lease),
        })
    }

    /// Renews the exact current lease without changing its fencing epoch.
    pub fn renew_lease(
        &mut self,
        lease: EvmActuatorLeaseV1,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<EvmActuatorLeaseV1> {
        validate_time_window(now_unix_ms, lease_duration_ms, MAX_LEASE_DURATION_MS)?;
        let until = now_unix_ms
            .checked_add(lease_duration_ms)
            .ok_or(EvmActuatorErrorV1::InvalidTime)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let changed = transaction.execute(
            "UPDATE evm_leases SET lease_until_be=?6
             WHERE authority_id=?1 AND owner_id=?2 AND chain_id_be=?3 AND account=?4
               AND fencing_epoch_be=?5",
            params![
                lease.authority_id.as_slice(),
                lease.owner_id.as_slice(),
                lease.chain_id.to_be_bytes().as_slice(),
                lease.account.as_slice(),
                lease.fencing_epoch.to_be_bytes().as_slice(),
                until.to_be_bytes().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(EvmActuatorErrorV1::StaleFencing);
        }
        transaction.commit()?;
        Ok(EvmActuatorLeaseV1 {
            lease_until_unix_ms: until,
            ..lease
        })
    }

    /// Returns the current evidence-bound nonce snapshot under a live lease.
    pub fn nonce_snapshot(
        &mut self,
        lease: EvmActuatorLeaseV1,
        now_unix_ms: u64,
    ) -> Result<NonceSnapshotV1> {
        let transaction = self.deferred()?;
        require_lease_read_only(&transaction, lease, now_unix_ms)?;
        let snapshot = load_nonce_snapshot(&transaction, lease.authority_id)?
            .ok_or(EvmActuatorErrorV1::MissingNonceObservation)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Refreshes `pending` nonce through the RPC authority and commits the exact
    /// evidence under observation-revision CAS.
    pub fn refresh_pending_nonce<R: EvmRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        request: EvmObservationMutationRequestV1,
        deployment: &ResolvedEvmDeploymentV1,
        rpc: &mut R,
        post_rpc_time: F,
    ) -> Result<MutationOutcomeV1<NonceSnapshotV1>> {
        let EvmObservationMutationRequestV1 {
            lease,
            mutation_id,
            expected_revision: expected_observation_revision,
            now_unix_ms,
            valid_for_ms,
        } = request;
        validate_id(mutation_id)?;
        validate_time_window(now_unix_ms, valid_for_ms, MAX_OBSERVATION_TTL_MS)?;
        validate_deployment_lease(deployment, lease)?;
        rpc_preflight(deployment, rpc)?;
        let observation = rpc.pending_nonce(lease.account)?;
        validate_id(observation.evidence_digest)?;
        let post_rpc_now_unix_ms = post_rpc_time()?;
        if post_rpc_now_unix_ms < now_unix_ms {
            return Err(EvmActuatorErrorV1::InvalidTime);
        }
        validate_time_window(post_rpc_now_unix_ms, valid_for_ms, MAX_OBSERVATION_TTL_MS)?;
        let valid_until = post_rpc_now_unix_ms
            .checked_add(valid_for_ms)
            .ok_or(EvmActuatorErrorV1::InvalidTime)?;
        let mutation_digest = domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/NONCE-OBSERVATION/V1\0",
            &[
                &lease.authority_id,
                &observation.nonce.to_be_bytes(),
                &observation.evidence_digest,
                &post_rpc_now_unix_ms.to_be_bytes(),
                &valid_until.to_be_bytes(),
            ],
        );
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, post_rpc_now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            let snapshot = load_nonce_snapshot(&transaction, lease.authority_id)?
                .ok_or(EvmActuatorErrorV1::CorruptState)?;
            transaction.commit()?;
            return Ok(MutationOutcomeV1 {
                status,
                value: snapshot,
            });
        }
        let previous = load_nonce_snapshot(&transaction, lease.authority_id)?;
        let (current_revision, allocation_revision) = previous
            .map(|value| (value.observation_revision, value.allocation_revision))
            .unwrap_or((0, 0));
        if current_revision != expected_observation_revision
            || previous.is_some_and(|value| post_rpc_now_unix_ms < value.observed_at_unix_ms)
        {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        let revision = current_revision
            .checked_add(1)
            .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
        transaction.execute(
            "INSERT INTO evm_nonce_snapshots
             (authority_id, observation_revision_be, allocation_revision_be,
              pending_nonce_be, evidence_digest, observed_at_be, valid_until_be)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(authority_id) DO UPDATE SET
               observation_revision_be=excluded.observation_revision_be,
               pending_nonce_be=excluded.pending_nonce_be,
               evidence_digest=excluded.evidence_digest,
               observed_at_be=excluded.observed_at_be,
               valid_until_be=excluded.valid_until_be",
            params![
                lease.authority_id.as_slice(),
                revision.to_be_bytes().as_slice(),
                allocation_revision.to_be_bytes().as_slice(),
                observation.nonce.to_be_bytes().as_slice(),
                observation.evidence_digest.as_slice(),
                post_rpc_now_unix_ms.to_be_bytes().as_slice(),
                valid_until.to_be_bytes().as_slice(),
            ],
        )?;
        insert_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
            None,
            revision,
        )?;
        let snapshot = NonceSnapshotV1 {
            observation_revision: revision,
            allocation_revision,
            pending_nonce: observation.nonce,
            evidence_digest: observation.evidence_digest,
            observed_at_unix_ms: post_rpc_now_unix_ms,
            valid_until_unix_ms: valid_until,
        };
        transaction.commit()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Committed,
            value: snapshot,
        })
    }

    /// Refreshes a finalized ERC-20 allowance and pinned token code hash. Native
    /// assets are refused because they require no approval subflow.
    pub fn refresh_finalized_allowance<R: EvmRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        request: EvmObservationMutationRequestV1,
        deployment: &ResolvedEvmDeploymentV1,
        rpc: &mut R,
        post_rpc_time: F,
    ) -> Result<MutationStatusV1> {
        let EvmObservationMutationRequestV1 {
            lease,
            mutation_id,
            expected_revision,
            now_unix_ms,
            valid_for_ms,
        } = request;
        validate_id(mutation_id)?;
        validate_time_window(now_unix_ms, valid_for_ms, MAX_OBSERVATION_TTL_MS)?;
        validate_deployment_lease(deployment, lease)?;
        let config = deployment.adapter_config();
        if lease.account != config.funder {
            return Err(EvmActuatorErrorV1::InvalidScope);
        }
        let (token, token_code_hash) = match deployment.asset_binding().representation {
            AssetRepresentationV1::EvmErc20 {
                token,
                token_code_hash,
            } => (token, token_code_hash),
            AssetRepresentationV1::Native => return Err(EvmActuatorErrorV1::InvalidState),
        };
        rpc_preflight(deployment, rpc)?;
        let (observed_code_hash, code_evidence) = rpc.finalized_code_hash(token)?;
        if observed_code_hash != token_code_hash || code_evidence == ZERO_DIGEST {
            return Err(EvmActuatorErrorV1::RpcScopeMismatch);
        }
        let allowance = rpc.finalized_allowance(token, lease.account, config.contract)?;
        if allowance.block_hash == ZERO_DIGEST || allowance.evidence_digest == ZERO_DIGEST {
            return Err(EvmActuatorErrorV1::RpcScopeMismatch);
        }
        let post_rpc_now_unix_ms = post_rpc_time()?;
        if post_rpc_now_unix_ms < now_unix_ms {
            return Err(EvmActuatorErrorV1::InvalidTime);
        }
        validate_time_window(post_rpc_now_unix_ms, valid_for_ms, MAX_OBSERVATION_TTL_MS)?;
        let evidence = domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/ALLOWANCE-EVIDENCE/V1\0",
            &[&code_evidence, &allowance.evidence_digest],
        );
        let valid_until = post_rpc_now_unix_ms
            .checked_add(valid_for_ms)
            .ok_or(EvmActuatorErrorV1::InvalidTime)?;
        let mutation_digest = domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/ALLOWANCE-MUTATION/V1\0",
            &[
                &lease.authority_id,
                &token,
                &config.contract,
                &allowance.amount,
                &allowance.block_number.to_be_bytes(),
                &allowance.block_hash,
                &evidence,
                &valid_until.to_be_bytes(),
            ],
        );
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, post_rpc_now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            transaction.commit()?;
            return Ok(status);
        }
        let current: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT revision_be, block_number_be FROM evm_allowances
                 WHERE authority_id=?1 AND token=?2 AND spender=?3",
                params![
                    lease.authority_id.as_slice(),
                    token.as_slice(),
                    config.contract.as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let revision = match current {
            None if expected_revision == 0 => 1,
            Some((stored_revision, stored_block)) => {
                let stored_revision = blob_u64(stored_revision)?;
                if stored_revision != expected_revision
                    || allowance.block_number < blob_u64(stored_block)?
                {
                    return Err(EvmActuatorErrorV1::RevisionConflict);
                }
                stored_revision
                    .checked_add(1)
                    .ok_or(EvmActuatorErrorV1::BoundExceeded)?
            }
            _ => return Err(EvmActuatorErrorV1::RevisionConflict),
        };
        transaction.execute(
            "INSERT INTO evm_allowances
             (authority_id,token,spender,revision_be,amount,block_number_be,block_hash,
              evidence_digest,registry_digest,profile_digest,asset_digest,
              observed_at_be,valid_until_be)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(authority_id,token,spender) DO UPDATE SET
               revision_be=excluded.revision_be, amount=excluded.amount,
               block_number_be=excluded.block_number_be, block_hash=excluded.block_hash,
               evidence_digest=excluded.evidence_digest,
               registry_digest=excluded.registry_digest,
               profile_digest=excluded.profile_digest, asset_digest=excluded.asset_digest,
               observed_at_be=excluded.observed_at_be,
               valid_until_be=excluded.valid_until_be",
            params![
                lease.authority_id.as_slice(),
                token.as_slice(),
                config.contract.as_slice(),
                revision.to_be_bytes().as_slice(),
                allowance.amount.as_slice(),
                allowance.block_number.to_be_bytes().as_slice(),
                allowance.block_hash.as_slice(),
                evidence.as_slice(),
                deployment.registry_digest().as_slice(),
                deployment.profile_digest().as_slice(),
                deployment.asset_binding_digest().as_slice(),
                post_rpc_now_unix_ms.to_be_bytes().as_slice(),
                valid_until.to_be_bytes().as_slice(),
            ],
        )?;
        insert_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
            None,
            revision,
        )?;
        transaction.commit()?;
        Ok(MutationStatusV1::Committed)
    }

    /// Atomically reserves a nonce and persists a fully validated open call.
    /// ERC-20 calls require a sufficient, non-stale finalized allowance first.
    pub fn prepare_open(
        &mut self,
        request: EvmOperationPreparationRequestV1,
        scope: &ScopedEvmOpenV1,
    ) -> Result<MutationOutcomeV1<EvmOperationViewV1>> {
        let preparation = OperationPreparationV1 {
            kind: EvmOperationKindV1::Open,
            signer_role: EvmSignerRoleV1::Funder,
            route_id: scope.route_id,
            effect_id: scope.effect_id,
            semantic_digest: scope.semantic_digest,
            lock: &scope.lock,
            value: scope.call.value,
            calldata: &scope.call.calldata,
            refund_authorization: None,
        };
        self.prepare_operation(request, &preparation)
    }

    /// Atomically reserves a beneficiary nonce and persists exact
    /// scalar-bearing claim calldata in the owner-only authority. The scoped
    /// secret is consumed and zeroized after the durable transition.
    pub fn prepare_claim(
        &mut self,
        request: EvmOperationPreparationRequestV1,
        scope: ScopedEvmClaimV1,
    ) -> Result<MutationOutcomeV1<EvmOperationViewV1>> {
        let preparation = OperationPreparationV1 {
            kind: EvmOperationKindV1::Claim,
            signer_role: EvmSignerRoleV1::Beneficiary,
            route_id: scope.route_id,
            effect_id: scope.effect_id,
            semantic_digest: scope.semantic_digest,
            lock: &scope.lock,
            value: ZERO_DIGEST,
            calldata: &scope.calldata,
            refund_authorization: None,
        };
        self.prepare_operation(request, &preparation)
    }

    /// Verifies a finalized canonical block timestamp against the exact lock
    /// deadline, then atomically reserves a funder nonce and persists the
    /// policy-scoped refund call. No caller-provided boolean/timestamp exists.
    pub fn prepare_refund<R: EvmRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        request: EvmOperationPreparationRequestV1,
        scope: &ScopedEvmRefundV1,
        rpc: &mut R,
        post_rpc_time: F,
    ) -> Result<MutationOutcomeV1<EvmOperationViewV1>> {
        validate_terminal_lease(&scope.lock, EvmSignerRoleV1::Funder, request.lease)?;
        rpc_preflight(&scope.lock.deployment, rpc)?;
        let evidence = rpc.finalized_block_time()?;
        let authorization = validate_refund_time(
            scope.lock.deployment.adapter_config().chain_id,
            scope.lock.deployment.deployment().genesis_hash,
            scope.lock.deadline,
            evidence,
        )?;
        let post_rpc_now_unix_ms = post_rpc_time()?;
        if post_rpc_now_unix_ms < request.now_unix_ms {
            return Err(EvmActuatorErrorV1::InvalidTime);
        }
        let request = EvmOperationPreparationRequestV1 {
            now_unix_ms: post_rpc_now_unix_ms,
            ..request
        };
        let preparation = OperationPreparationV1 {
            kind: EvmOperationKindV1::Refund,
            signer_role: EvmSignerRoleV1::Funder,
            route_id: scope.route_id,
            effect_id: scope.effect_id,
            semantic_digest: scope.semantic_digest,
            lock: &scope.lock,
            value: ZERO_DIGEST,
            calldata: &scope.calldata,
            refund_authorization: Some(authorization),
        };
        self.prepare_operation(request, &preparation)
    }

    fn prepare_operation(
        &mut self,
        request: EvmOperationPreparationRequestV1,
        scope: &OperationPreparationV1<'_>,
    ) -> Result<MutationOutcomeV1<EvmOperationViewV1>> {
        let EvmOperationPreparationRequestV1 {
            lease,
            mutation_id,
            operation_id,
            expected_nonce,
            fees,
            now_unix_ms,
        } = request;
        validate_id(mutation_id)?;
        validate_id(operation_id)?;
        validate_operation_scope_lease(scope, lease)?;
        validate_fees(scope.lock.deployment.deployment(), fees)?;
        let request_digest = operation_request_digest(operation_id, scope, fees)?;
        let intent_digest = operation_intent_digest(operation_id, scope, fees)?;
        let mutation_digest = domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/PREPARE/V2\0",
            &[&operation_id, &intent_digest],
        );
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            let value = load_operation_view(&transaction, operation_id)?;
            transaction.commit()?;
            return Ok(MutationOutcomeV1 { status, value });
        }
        if transaction
            .query_row(
                "SELECT 1 FROM evm_operations WHERE operation_id=?1",
                params![operation_id.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        {
            let row = load_operation_row(&transaction, operation_id)?;
            let initial_fees = operation_initial_fees(&transaction, &row)?;
            if row.authority_id != lease.authority_id
                || stored_operation_intent_digest(&row, initial_fees)? != intent_digest
            {
                return Err(EvmActuatorErrorV1::IdempotencyConflict);
            }
            let view = operation_view(&row);
            insert_mutation(
                &transaction,
                lease.authority_id,
                mutation_id,
                mutation_digest,
                Some(operation_id),
                view.revision,
            )?;
            transaction.commit()?;
            return Ok(MutationOutcomeV1 {
                status: MutationStatusV1::DuplicateSameBytes,
                value: view,
            });
        }
        let current_nonce = load_nonce_snapshot(&transaction, lease.authority_id)?
            .ok_or(EvmActuatorErrorV1::MissingNonceObservation)?;
        if current_nonce != expected_nonce {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        if current_nonce.valid_until_unix_ms < now_unix_ms {
            return Err(EvmActuatorErrorV1::StaleObservation);
        }
        let local_max: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT nonce_be FROM evm_operations WHERE authority_id=?1
                 ORDER BY nonce_be DESC LIMIT 1",
                params![lease.authority_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let next_local = match local_max {
            Some(value) => blob_u64(value)?
                .checked_add(1)
                .ok_or(EvmActuatorErrorV1::BoundExceeded)?,
            None => 0,
        };
        let nonce = current_nonce.pending_nonce.max(next_local);
        let (erc20_token, allowance_revision) =
            require_allowance_if_needed(&transaction, lease, scope, now_unix_ms)?;
        let config = scope.lock.deployment.adapter_config();
        let deployment = scope.lock.deployment.deployment();
        let fields = Eip1559FieldsV1 {
            chain_id: config.chain_id,
            nonce,
            fees,
            gas_limit: config.gas_limit_hint,
            to: config.contract,
            value: scope.value,
            calldata: Zeroizing::new(scope.calldata.to_vec()),
        };
        let calldata_digest = keccak256(&fields.calldata);
        let refund = scope.refund_authorization;
        transaction.execute(
            "INSERT INTO evm_operations
             (operation_id,authority_id,route_id,effect_id,request_digest,operation_kind,
              signer_role,revision_be,stage_tag,fencing_epoch_be,chain_id_be,account,nonce_be,destination,value,
              calldata,calldata_digest,gas_limit_be,max_fee_be,max_priority_fee_be,
              max_fee_cap_be,max_priority_fee_cap_be,registry_digest,profile_digest,
              asset_digest,deployment_digest,destination_code_hash,genesis_hash,
              semantic_digest,terms_digest,lock_id,binding,
              beneficiary,funder,adaptor_address,deadline_be,erc20_token,lock_amount,
              allowance_revision_be,refund_auth_block_number_be,refund_auth_block_hash,
              refund_auth_timestamp_be,refund_auth_evidence,current_attempt,
              transaction_hash,ambiguous_after_send,secret_exposed,execution_success,observed_evidence,
              final_block_number_be,final_block_hash,final_evidence,terminal_event_digest,
              finality_invalidation_evidence,reconciliation_kind,reconciled_from_stage,
              created_at_be,updated_at_be)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,
                     ?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,
                     ?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,?40,?41,
                     ?42,?43,
                     0,NULL,0,0,NULL,NULL,
                     NULL,NULL,NULL,NULL,NULL,
                     NULL,NULL,
                     ?44,?44)",
            params![
                operation_id.as_slice(),
                lease.authority_id.as_slice(),
                scope.route_id.as_slice(),
                scope.effect_id.as_slice(),
                request_digest.as_slice(),
                scope.kind.tag(),
                scope.signer_role.tag(),
                1u64.to_be_bytes().as_slice(),
                EvmTxStageV1::Prepared.tag(),
                lease.fencing_epoch.to_be_bytes().as_slice(),
                fields.chain_id.to_be_bytes().as_slice(),
                lease.account.as_slice(),
                nonce.to_be_bytes().as_slice(),
                fields.to.as_slice(),
                fields.value.as_slice(),
                fields.calldata.as_slice(),
                calldata_digest.as_slice(),
                fields.gas_limit.to_be_bytes().as_slice(),
                fees.max_fee_per_gas.to_be_bytes().as_slice(),
                fees.max_priority_fee_per_gas.to_be_bytes().as_slice(),
                deployment.max_fee_per_gas.to_be_bytes().as_slice(),
                deployment.max_priority_fee_per_gas.to_be_bytes().as_slice(),
                scope.lock.deployment.registry_digest().as_slice(),
                scope.lock.deployment.profile_digest().as_slice(),
                scope.lock.deployment.asset_binding_digest().as_slice(),
                deployment.deployment_digest.as_slice(),
                config.expected_code_hash.as_slice(),
                deployment.genesis_hash.as_slice(),
                scope.semantic_digest.as_slice(),
                config.terms_hash.as_slice(),
                scope.lock.lock_id.as_slice(),
                scope.lock.binding.as_slice(),
                scope.lock.beneficiary.as_slice(),
                scope.lock.funder.as_slice(),
                scope.lock.adaptor_address.as_slice(),
                scope.lock.deadline.to_be_bytes().as_slice(),
                erc20_token.map(|value| value.to_vec()),
                scope.lock.amount.as_slice(),
                allowance_revision.map(|value| value.to_be_bytes().to_vec()),
                refund.map(|value| value.block_number.to_be_bytes().to_vec()),
                refund.map(|value| value.block_hash.to_vec()),
                refund.map(|value| value.timestamp.to_be_bytes().to_vec()),
                refund.map(|value| value.evidence_digest.to_vec()),
                now_unix_ms.to_be_bytes().as_slice(),
            ],
        )?;
        let next_allocation = current_nonce
            .allocation_revision
            .checked_add(1)
            .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
        let allocation_changed = transaction.execute(
            "UPDATE evm_nonce_snapshots SET allocation_revision_be=?2
             WHERE authority_id=?1 AND allocation_revision_be=?3",
            params![
                lease.authority_id.as_slice(),
                next_allocation.to_be_bytes().as_slice(),
                current_nonce.allocation_revision.to_be_bytes().as_slice(),
            ],
        )?;
        if allocation_changed != 1 {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        insert_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
            Some(operation_id),
            1,
        )?;
        let value = load_operation_view(&transaction, operation_id)?;
        transaction.commit()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Committed,
            value,
        })
    }

    /// Obtains an exact route-scoped signature, verifies signer recovery and
    /// low-s, then obtains fresh trusted time after signer I/O and atomically
    /// persists raw bytes and tx hash only while the lease remains live.
    pub fn sign_prepared<S: ScopedEip1559SignerV1 + ?Sized, F: FnOnce() -> Result<u64>>(
        &mut self,
        request: EvmOperationMutationRequestV1,
        signer: &mut S,
        post_sign_time: F,
    ) -> Result<MutationOutcomeV1<EvmOperationViewV1>> {
        let EvmOperationMutationRequestV1 {
            lease,
            mutation_id,
            operation_id,
            expected_revision,
            now_unix_ms,
        } = request;
        validate_id(mutation_id)?;
        validate_id(operation_id)?;
        let mutation_digest = domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/SIGN/V1\0",
            &[&operation_id, &expected_revision.to_be_bytes()],
        );
        let transaction = self.deferred()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            let value = load_operation_view(&transaction, operation_id)?;
            transaction.commit()?;
            return Ok(MutationOutcomeV1 { status, value });
        }
        let row = load_operation_row(&transaction, operation_id)?;
        require_current_operation(&row, lease, expected_revision, &[EvmTxStageV1::Prepared])?;
        let attempt = 1u32;
        let fields = row.fields();
        let signing_hash_value = signing_hash(&fields)?;
        let request = signing_request(&row, &fields, signing_hash_value, lease, attempt)?;
        transaction.commit()?;

        let signature = signer.sign_eip1559(request)?;
        let (raw, transaction_hash) = verify_and_encode_signed(&fields, lease.account, signature)?;
        let post_sign_now_unix_ms = post_sign_time()?;

        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, post_sign_now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            let value = load_operation_view(&transaction, operation_id)?;
            if value.transaction_hash != Some(transaction_hash) {
                return Err(EvmActuatorErrorV1::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(MutationOutcomeV1 { status, value });
        }
        let current = load_operation_row(&transaction, operation_id)?;
        require_current_operation(
            &current,
            lease,
            expected_revision,
            &[EvmTxStageV1::Prepared],
        )?;
        if current.fields() != fields {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        insert_signed_attempt(
            &transaction,
            SignedAttemptMaterialV1 {
                operation_id,
                attempt,
                stage: EvmTxStageV1::Signed,
                fees: fields.fees,
                signing_hash: signing_hash_value,
                raw: &raw,
                transaction_hash,
                signature,
            },
        )?;
        let revision = expected_revision
            .checked_add(1)
            .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
        let changed = transaction.execute(
            "UPDATE evm_operations SET revision_be=?2, stage_tag=?3,
             current_attempt=?4, transaction_hash=?5, updated_at_be=?6
             WHERE operation_id=?1 AND revision_be=?7 AND stage_tag=?8
               AND fencing_epoch_be=?9",
            params![
                operation_id.as_slice(),
                revision.to_be_bytes().as_slice(),
                EvmTxStageV1::Signed.tag(),
                i64::from(attempt),
                transaction_hash.as_slice(),
                post_sign_now_unix_ms.to_be_bytes().as_slice(),
                expected_revision.to_be_bytes().as_slice(),
                EvmTxStageV1::Prepared.tag(),
                lease.fencing_epoch.to_be_bytes().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        insert_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
            Some(operation_id),
            revision,
        )?;
        let value = load_operation_view(&transaction, operation_id)?;
        transaction.commit()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Committed,
            value,
        })
    }

    /// Creates a same-nonce replacement from retained immutable fields and
    /// revalidates trusted time after signer I/O before persisting signature
    /// bytes or superseding the old attempt.
    pub fn replace_current<S: ScopedEip1559SignerV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        request: EvmOperationMutationRequestV1,
        replacement_fees: EvmFeesV1,
        signer: &mut S,
        post_sign_time: F,
    ) -> Result<MutationOutcomeV1<EvmOperationViewV1>> {
        let EvmOperationMutationRequestV1 {
            lease,
            mutation_id,
            operation_id,
            expected_revision,
            now_unix_ms,
        } = request;
        validate_id(mutation_id)?;
        validate_id(operation_id)?;
        let mutation_digest = domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/REPLACEMENT/V1\0",
            &[
                &operation_id,
                &expected_revision.to_be_bytes(),
                &replacement_fees.max_fee_per_gas.to_be_bytes(),
                &replacement_fees.max_priority_fee_per_gas.to_be_bytes(),
            ],
        );
        let transaction = self.deferred()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            let value = load_operation_view(&transaction, operation_id)?;
            transaction.commit()?;
            return Ok(MutationOutcomeV1 { status, value });
        }
        let row = load_operation_row(&transaction, operation_id)?;
        require_current_operation(
            &row,
            lease,
            expected_revision,
            &[
                EvmTxStageV1::SendAttempted,
                EvmTxStageV1::Observed,
                EvmTxStageV1::FinalityInvalidated,
            ],
        )?;
        validate_replacement(&row, replacement_fees)?;
        let attempt = row
            .current_attempt
            .checked_add(1)
            .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
        let mut fields = row.fields();
        fields.fees = replacement_fees;
        let signing_hash_value = signing_hash(&fields)?;
        let request = signing_request(&row, &fields, signing_hash_value, lease, attempt)?;
        transaction.commit()?;

        let signature = signer.sign_eip1559(request)?;
        let (raw, transaction_hash) = verify_and_encode_signed(&fields, lease.account, signature)?;
        let post_sign_now_unix_ms = post_sign_time()?;

        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, post_sign_now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            let value = load_operation_view(&transaction, operation_id)?;
            if value.transaction_hash != Some(transaction_hash) {
                return Err(EvmActuatorErrorV1::IdempotencyConflict);
            }
            transaction.commit()?;
            return Ok(MutationOutcomeV1 { status, value });
        }
        let current = load_operation_row(&transaction, operation_id)?;
        require_current_operation(
            &current,
            lease,
            expected_revision,
            &[
                EvmTxStageV1::SendAttempted,
                EvmTxStageV1::Observed,
                EvmTxStageV1::FinalityInvalidated,
            ],
        )?;
        validate_replacement(&current, replacement_fees)?;
        if current.current_attempt.checked_add(1) != Some(attempt) {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        let old_changed = transaction.execute(
            "UPDATE evm_attempts SET stage_tag=?3, replaced_by=?4
             WHERE operation_id=?1 AND attempt=?2 AND stage_tag IN (?5,?6,?7)",
            params![
                operation_id.as_slice(),
                i64::from(current.current_attempt),
                EvmTxStageV1::Replaced.tag(),
                i64::from(attempt),
                EvmTxStageV1::SendAttempted.tag(),
                EvmTxStageV1::Observed.tag(),
                EvmTxStageV1::FinalityInvalidated.tag(),
            ],
        )?;
        if old_changed != 1 {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
        insert_signed_attempt(
            &transaction,
            SignedAttemptMaterialV1 {
                operation_id,
                attempt,
                stage: EvmTxStageV1::Signed,
                fees: replacement_fees,
                signing_hash: signing_hash_value,
                raw: &raw,
                transaction_hash,
                signature,
            },
        )?;
        let revision = expected_revision
            .checked_add(1)
            .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
        let changed = transaction.execute(
            "UPDATE evm_operations SET revision_be=?2, stage_tag=?3,
             current_attempt=?4, transaction_hash=?5, max_fee_be=?6,
             max_priority_fee_be=?7, ambiguous_after_send=0,
             execution_success=NULL, observed_evidence=NULL,
             final_block_number_be=NULL, final_block_hash=NULL, final_evidence=NULL,
             terminal_event_digest=NULL, finality_invalidation_evidence=NULL,
             updated_at_be=?8
             WHERE operation_id=?1 AND revision_be=?9 AND fencing_epoch_be=?10",
            params![
                operation_id.as_slice(),
                revision.to_be_bytes().as_slice(),
                EvmTxStageV1::Signed.tag(),
                i64::from(attempt),
                transaction_hash.as_slice(),
                replacement_fees.max_fee_per_gas.to_be_bytes().as_slice(),
                replacement_fees
                    .max_priority_fee_per_gas
                    .to_be_bytes()
                    .as_slice(),
                post_sign_now_unix_ms.to_be_bytes().as_slice(),
                expected_revision.to_be_bytes().as_slice(),
                lease.fencing_epoch.to_be_bytes().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        insert_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
            Some(operation_id),
            revision,
        )?;
        let value = load_operation_view(&transaction, operation_id)?;
        transaction.commit()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Committed,
            value,
        })
    }

    /// Authenticates the exact row and RPC scope without writes, then commits
    /// `SendAttempted` at a fresh post-lookup time before sending. Every retry
    /// sends the same persisted bytes; an error from the send itself remains
    /// ambiguous, while a pre-send RPC error leaves durable state untouched.
    pub fn broadcast_current<R: EvmRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        request: EvmOperationMutationRequestV1,
        rpc: &mut R,
        post_rpc_time: F,
    ) -> Result<BroadcastOutcomeV1> {
        let EvmOperationMutationRequestV1 {
            lease,
            mutation_id,
            operation_id,
            expected_revision,
            now_unix_ms,
        } = request;
        validate_id(mutation_id)?;
        validate_id(operation_id)?;
        let (
            preflight_raw,
            preflight_hash,
            preflight_genesis,
            preflight_destination,
            preflight_code_hash,
            refund_deadline,
        ) = {
            let transaction = self.deferred()?;
            require_lease_read_only(&transaction, lease, now_unix_ms)?;
            let row = load_operation_row(&transaction, operation_id)?;
            if row.authority_id != lease.authority_id || row.account != lease.account {
                return Err(EvmActuatorErrorV1::InvalidScope);
            }
            if row.fencing_epoch != lease.fencing_epoch {
                return Err(EvmActuatorErrorV1::ReconciliationRequired);
            }
            if !matches!(
                row.stage,
                EvmTxStageV1::Signed | EvmTxStageV1::SendAttempted
            ) {
                return Err(EvmActuatorErrorV1::InvalidState);
            }
            let mutation_digest = domain_digest(
                b"DOM-INTEROP/EVM-ACTUATOR/SEND/V1\0",
                &[
                    &operation_id,
                    &row.current_attempt.to_be_bytes(),
                    &row.transaction_hash
                        .ok_or(EvmActuatorErrorV1::CorruptState)?,
                ],
            );
            let existing_revision = existing_mutation_revision(
                &transaction,
                lease.authority_id,
                mutation_id,
                mutation_digest,
            )?;
            let (raw, hash, attempt_stage) =
                load_attempt_payload(&transaction, operation_id, row.current_attempt)?;
            if hash
                != row
                    .transaction_hash
                    .ok_or(EvmActuatorErrorV1::CorruptState)?
                || keccak256(&raw) != hash
                || raw.first() != Some(&0x02)
                || raw.len() > MAX_RAW_TRANSACTION_BYTES_V1
            {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
            if let Some(resulting_revision) = existing_revision {
                if expected_revision.checked_add(1) != Some(resulting_revision)
                    || row.revision != resulting_revision
                    || row.stage != EvmTxStageV1::SendAttempted
                    || attempt_stage != EvmTxStageV1::SendAttempted
                {
                    return Err(EvmActuatorErrorV1::IdempotencyConflict);
                }
            } else if row.revision != expected_revision {
                return Err(EvmActuatorErrorV1::RevisionConflict);
            } else if !matches!(
                attempt_stage,
                EvmTxStageV1::Signed | EvmTxStageV1::SendAttempted
            ) {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
            let refund = if row.kind == EvmOperationKindV1::Refund
                && matches!(
                    row.stage,
                    EvmTxStageV1::Signed | EvmTxStageV1::SendAttempted
                ) {
                Some((
                    row.fields.chain_id,
                    row.genesis_hash,
                    row.fields.to,
                    row.destination_code_hash,
                    row.deadline,
                ))
            } else {
                None
            };
            transaction.commit()?;
            (
                raw,
                hash,
                row.genesis_hash,
                row.fields.to,
                row.destination_code_hash,
                refund,
            )
        };
        rpc_row_preflight(
            lease.chain_id,
            preflight_genesis,
            preflight_destination,
            preflight_code_hash,
            rpc,
        )?;
        if let Some((chain_id, genesis, destination, code_hash, deadline)) = refund_deadline {
            if chain_id != lease.chain_id
                || genesis != preflight_genesis
                || destination != preflight_destination
                || code_hash != preflight_code_hash
            {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
            validate_refund_time(chain_id, genesis, deadline, rpc.finalized_block_time()?)?;
        }
        let post_rpc_now_unix_ms = post_rpc_time()?;
        require_post_rpc_time(now_unix_ms, post_rpc_now_unix_ms)?;
        let (raw, expected_hash, genesis_hash, destination, destination_code_hash, status) = {
            let transaction = self.immediate()?;
            validate_lease(&transaction, lease, post_rpc_now_unix_ms)?;
            let row = load_operation_row(&transaction, operation_id)?;
            if row.authority_id != lease.authority_id || row.account != lease.account {
                return Err(EvmActuatorErrorV1::InvalidScope);
            }
            if row.fencing_epoch != lease.fencing_epoch {
                return Err(EvmActuatorErrorV1::ReconciliationRequired);
            }
            if !matches!(
                row.stage,
                EvmTxStageV1::Signed | EvmTxStageV1::SendAttempted
            ) {
                return Err(EvmActuatorErrorV1::InvalidState);
            }
            let mutation_digest = domain_digest(
                b"DOM-INTEROP/EVM-ACTUATOR/SEND/V1\0",
                &[
                    &operation_id,
                    &row.current_attempt.to_be_bytes(),
                    &row.transaction_hash
                        .ok_or(EvmActuatorErrorV1::CorruptState)?,
                ],
            );
            let existing_revision = existing_mutation_revision(
                &transaction,
                lease.authority_id,
                mutation_id,
                mutation_digest,
            )?;
            let (raw, hash, attempt_stage) =
                load_attempt_payload(&transaction, operation_id, row.current_attempt)?;
            if hash
                != row
                    .transaction_hash
                    .ok_or(EvmActuatorErrorV1::CorruptState)?
                || keccak256(&raw) != hash
                || raw.first() != Some(&0x02)
                || raw.len() > MAX_RAW_TRANSACTION_BYTES_V1
                || raw != preflight_raw
                || hash != preflight_hash
                || row.genesis_hash != preflight_genesis
                || row.fields.to != preflight_destination
                || row.destination_code_hash != preflight_code_hash
            {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
            let status = if let Some(resulting_revision) = existing_revision {
                if expected_revision.checked_add(1) != Some(resulting_revision)
                    || row.revision != resulting_revision
                    || row.stage != EvmTxStageV1::SendAttempted
                    || attempt_stage != EvmTxStageV1::SendAttempted
                {
                    return Err(EvmActuatorErrorV1::IdempotencyConflict);
                }
                MutationStatusV1::DuplicateSameBytes
            } else {
                if row.revision != expected_revision {
                    return Err(EvmActuatorErrorV1::RevisionConflict);
                }
                if !matches!(
                    attempt_stage,
                    EvmTxStageV1::Signed | EvmTxStageV1::SendAttempted
                ) {
                    return Err(EvmActuatorErrorV1::CorruptState);
                }
                let revision = expected_revision
                    .checked_add(1)
                    .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
                let changed = transaction.execute(
                    "UPDATE evm_operations SET revision_be=?2, stage_tag=?3,
                     ambiguous_after_send=1, secret_exposed=?7, updated_at_be=?4
                     WHERE operation_id=?1 AND revision_be=?5 AND fencing_epoch_be=?6",
                    params![
                        operation_id.as_slice(),
                        revision.to_be_bytes().as_slice(),
                        EvmTxStageV1::SendAttempted.tag(),
                        post_rpc_now_unix_ms.to_be_bytes().as_slice(),
                        expected_revision.to_be_bytes().as_slice(),
                        lease.fencing_epoch.to_be_bytes().as_slice(),
                        if row.kind == EvmOperationKindV1::Claim {
                            1
                        } else {
                            0
                        },
                    ],
                )?;
                if changed != 1 {
                    return Err(EvmActuatorErrorV1::RevisionConflict);
                }
                transaction.execute(
                    "UPDATE evm_attempts SET stage_tag=?3, send_attempted_at_be=?4
                     WHERE operation_id=?1 AND attempt=?2",
                    params![
                        operation_id.as_slice(),
                        i64::from(row.current_attempt),
                        EvmTxStageV1::SendAttempted.tag(),
                        post_rpc_now_unix_ms.to_be_bytes().as_slice(),
                    ],
                )?;
                insert_mutation(
                    &transaction,
                    lease.authority_id,
                    mutation_id,
                    mutation_digest,
                    Some(operation_id),
                    revision,
                )?;
                MutationStatusV1::Committed
            };
            transaction.commit()?;
            (
                raw,
                hash,
                row.genesis_hash,
                row.fields.to,
                row.destination_code_hash,
                status,
            )
        };
        if genesis_hash != preflight_genesis
            || destination != preflight_destination
            || destination_code_hash != preflight_code_hash
        {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
        let disposition = match rpc.send_raw_transaction(&raw) {
            Ok(returned) if returned == expected_hash => BroadcastDispositionV1::Accepted,
            Ok(_) => return Err(EvmActuatorErrorV1::ObservationMismatch),
            Err(_) => BroadcastDispositionV1::Ambiguous,
        };
        Ok(BroadcastOutcomeV1 {
            status,
            transaction_hash: expected_hash,
            disposition,
        })
    }

    /// Reconciles the current transaction with exact RPC transaction and
    /// receipt fields. `null` after any send leaves the operation ambiguous and
    /// never releases or reuses its nonce.
    pub fn observe_current<R: EvmRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        request: EvmOperationMutationRequestV1,
        rpc: &mut R,
        post_rpc_time: F,
    ) -> Result<MutationOutcomeV1<EvmOperationViewV1>> {
        let EvmOperationMutationRequestV1 {
            lease,
            mutation_id,
            operation_id,
            expected_revision,
            now_unix_ms,
        } = request;
        validate_id(mutation_id)?;
        validate_id(operation_id)?;
        let mutation_digest = domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/OBSERVE/V1\0",
            &[&operation_id, &expected_revision.to_be_bytes()],
        );
        let row = {
            let transaction = self.deferred()?;
            require_lease_read_only(&transaction, lease, now_unix_ms)?;
            if let Some(status) = existing_mutation(
                &transaction,
                lease.authority_id,
                mutation_id,
                mutation_digest,
            )? {
                let value = load_operation_view(&transaction, operation_id)?;
                transaction.commit()?;
                return Ok(MutationOutcomeV1 { status, value });
            }
            let row = load_operation_row(&transaction, operation_id)?;
            require_current_operation(
                &row,
                lease,
                expected_revision,
                &[
                    EvmTxStageV1::SendAttempted,
                    EvmTxStageV1::Observed,
                    EvmTxStageV1::Final,
                    EvmTxStageV1::FinalityInvalidated,
                ],
            )?;
            transaction.commit()?;
            row
        };
        if rpc.chain_id()? != row.fields.chain_id || rpc.genesis_hash()? != row.genesis_hash {
            return Err(EvmActuatorErrorV1::RpcScopeMismatch);
        }
        let expected_hash = row
            .transaction_hash
            .ok_or(EvmActuatorErrorV1::CorruptState)?;
        let lookup = rpc.transaction_by_hash(expected_hash)?;
        if lookup.evidence_digest == ZERO_DIGEST {
            return Err(EvmActuatorErrorV1::ObservationMismatch);
        }
        let receipt = if lookup.transaction.is_some() {
            Some(rpc.receipt(expected_hash)?)
        } else {
            None
        };
        let observation_digest = observation_digest(expected_hash, &lookup, receipt.as_ref());
        let post_rpc_now_unix_ms = post_rpc_time()?;
        require_post_rpc_time(now_unix_ms, post_rpc_now_unix_ms)?;
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, post_rpc_now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            let value = load_operation_view(&transaction, operation_id)?;
            transaction.commit()?;
            return Ok(MutationOutcomeV1 { status, value });
        }
        let current = load_operation_row(&transaction, operation_id)?;
        require_current_operation(
            &current,
            lease,
            expected_revision,
            &[
                EvmTxStageV1::SendAttempted,
                EvmTxStageV1::Observed,
                EvmTxStageV1::Final,
                EvmTxStageV1::FinalityInvalidated,
            ],
        )?;
        if current != row {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        let classified = classify_observation(&current, &lookup, receipt.as_ref())?;
        let revision = expected_revision
            .checked_add(1)
            .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
        let changed = transaction.execute(
            "UPDATE evm_operations SET revision_be=?2, stage_tag=?3,
             ambiguous_after_send=?4, execution_success=?5, observed_evidence=?6,
             final_block_number_be=?7, final_block_hash=?8, final_evidence=?9,
             terminal_event_digest=?10, finality_invalidation_evidence=?11,
             updated_at_be=?12
             WHERE operation_id=?1 AND revision_be=?13 AND fencing_epoch_be=?14",
            params![
                operation_id.as_slice(),
                revision.to_be_bytes().as_slice(),
                classified.stage.tag(),
                if classified.ambiguous { 1 } else { 0 },
                classified.success.map(|value| if value { 1 } else { 0 }),
                observation_digest.as_slice(),
                classified
                    .final_block_number
                    .map(|value| value.to_be_bytes().to_vec()),
                classified.final_block_hash.map(|value| value.to_vec()),
                classified.final_evidence.map(|value| value.to_vec()),
                classified.terminal_event_digest.map(|value| value.to_vec()),
                classified.invalidation_evidence.map(|value| value.to_vec()),
                post_rpc_now_unix_ms.to_be_bytes().as_slice(),
                expected_revision.to_be_bytes().as_slice(),
                lease.fencing_epoch.to_be_bytes().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        if !classified.ambiguous
            || classified.stage != current.stage
            || classified.stage == EvmTxStageV1::FinalityInvalidated
        {
            transaction.execute(
                "UPDATE evm_attempts SET stage_tag=?3, evidence_digest=?4
                 WHERE operation_id=?1 AND attempt=?2",
                params![
                    operation_id.as_slice(),
                    i64::from(current.current_attempt),
                    classified.stage.tag(),
                    observation_digest.as_slice(),
                ],
            )?;
        }
        insert_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
            Some(operation_id),
            revision,
        )?;
        let value = load_operation_view(&transaction, operation_id)?;
        transaction.commit()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Committed,
            value,
        })
    }

    /// Records an explicit takeover reconciliation state. Old-fence prepared or
    /// signed operations are internally proven unsent; anything that reached
    /// `SendAttempted` is queried and `null` remains blocked as `Unknown`.
    pub fn reconcile_takeover<R: EvmRpcV1, F: FnOnce() -> Result<u64>>(
        &mut self,
        request: EvmOperationMutationRequestV1,
        rpc: &mut R,
        post_rpc_time: F,
    ) -> Result<MutationOutcomeV1<EvmOperationViewV1>> {
        let EvmOperationMutationRequestV1 {
            lease,
            mutation_id,
            operation_id,
            expected_revision,
            now_unix_ms,
        } = request;
        validate_id(mutation_id)?;
        validate_id(operation_id)?;
        let mutation_digest = domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/TAKEOVER-RECONCILE/V1\0",
            &[
                &operation_id,
                &expected_revision.to_be_bytes(),
                &lease.fencing_epoch.to_be_bytes(),
            ],
        );
        let row = {
            let transaction = self.deferred()?;
            require_lease_read_only(&transaction, lease, now_unix_ms)?;
            if let Some(status) = existing_mutation(
                &transaction,
                lease.authority_id,
                mutation_id,
                mutation_digest,
            )? {
                let value = load_operation_view(&transaction, operation_id)?;
                transaction.commit()?;
                return Ok(MutationOutcomeV1 { status, value });
            }
            let row = load_operation_row(&transaction, operation_id)?;
            if row.authority_id != lease.authority_id
                || row.revision != expected_revision
                || row.fencing_epoch >= lease.fencing_epoch
                || row.stage == EvmTxStageV1::Replaced
                || (row.stage == EvmTxStageV1::Reconciled
                    && (row.reconciliation_kind != Some(ReconciliationKindV1::Unknown)
                        || !matches!(
                            row.reconciled_from_stage,
                            Some(
                                EvmTxStageV1::SendAttempted
                                    | EvmTxStageV1::Observed
                                    | EvmTxStageV1::FinalityInvalidated
                            )
                        )))
            {
                return Err(EvmActuatorErrorV1::InvalidState);
            }
            transaction.commit()?;
            row
        };
        let source_stage = if row.stage == EvmTxStageV1::Reconciled {
            row.reconciled_from_stage
                .ok_or(EvmActuatorErrorV1::CorruptState)?
        } else {
            row.stage
        };
        let (
            kind,
            observation_digest,
            final_block,
            final_block_hash,
            final_evidence,
            terminal_event_digest,
            invalidation_evidence,
            execution_success,
            commit_now_unix_ms,
        ) = match source_stage {
            EvmTxStageV1::Prepared | EvmTxStageV1::Signed => (
                ReconciliationKindV1::InternallyNeverSent,
                domain_digest(
                    b"DOM-INTEROP/EVM-ACTUATOR/NEVER-SENT/V1\0",
                    &[&operation_id, &row.revision.to_be_bytes()],
                ),
                None,
                None,
                None,
                None,
                None,
                None,
                now_unix_ms,
            ),
            EvmTxStageV1::SendAttempted
            | EvmTxStageV1::Observed
            | EvmTxStageV1::Final
            | EvmTxStageV1::FinalityInvalidated => {
                if rpc.chain_id()? != row.fields.chain_id || rpc.genesis_hash()? != row.genesis_hash
                {
                    return Err(EvmActuatorErrorV1::RpcScopeMismatch);
                }
                let hash = row
                    .transaction_hash
                    .ok_or(EvmActuatorErrorV1::CorruptState)?;
                let lookup = rpc.transaction_by_hash(hash)?;
                if lookup.evidence_digest == ZERO_DIGEST {
                    return Err(EvmActuatorErrorV1::ObservationMismatch);
                }
                let receipt = if lookup.transaction.is_some() {
                    Some(rpc.receipt(hash)?)
                } else {
                    None
                };
                if let Some(transaction_value) = lookup.transaction.as_ref() {
                    validate_rpc_transaction(&row, transaction_value)?;
                }
                let digest = observation_digest(hash, &lookup, receipt.as_ref());
                let classified = if lookup.transaction.is_none()
                    && matches!(
                        source_stage,
                        EvmTxStageV1::SendAttempted | EvmTxStageV1::Observed
                    ) {
                    (
                        ReconciliationKindV1::Unknown,
                        digest,
                        row.final_block_number,
                        row.final_block_hash,
                        row.final_evidence,
                        row.terminal_event_digest,
                        row.finality_invalidation_evidence,
                        row.execution_success,
                    )
                } else {
                    let classified = classify_observation(&row, &lookup, receipt.as_ref())?;
                    let kind = match classified.stage {
                        EvmTxStageV1::Final => ReconciliationKindV1::Final,
                        EvmTxStageV1::FinalityInvalidated => {
                            ReconciliationKindV1::FinalityInvalidated
                        }
                        _ => ReconciliationKindV1::Observed,
                    };
                    (
                        kind,
                        digest,
                        classified.final_block_number,
                        classified.final_block_hash,
                        classified.final_evidence,
                        classified.terminal_event_digest,
                        classified.invalidation_evidence,
                        classified.success,
                    )
                };
                let post_rpc_now_unix_ms = post_rpc_time()?;
                require_post_rpc_time(now_unix_ms, post_rpc_now_unix_ms)?;
                (
                    classified.0,
                    classified.1,
                    classified.2,
                    classified.3,
                    classified.4,
                    classified.5,
                    classified.6,
                    classified.7,
                    post_rpc_now_unix_ms,
                )
            }
            EvmTxStageV1::Replaced | EvmTxStageV1::Reconciled => {
                return Err(EvmActuatorErrorV1::InvalidState)
            }
        };
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, commit_now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            let value = load_operation_view(&transaction, operation_id)?;
            transaction.commit()?;
            return Ok(MutationOutcomeV1 { status, value });
        }
        let current = load_operation_row(&transaction, operation_id)?;
        if current != row {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        let revision = row
            .revision
            .checked_add(1)
            .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
        let changed = transaction.execute(
            "UPDATE evm_operations SET revision_be=?2, stage_tag=?3,
             reconciliation_kind=?4, reconciled_from_stage=?5,
             observed_evidence=?6, final_block_number_be=?7, final_block_hash=?8,
             final_evidence=?9,terminal_event_digest=?10,
             finality_invalidation_evidence=?11,execution_success=?12,
             ambiguous_after_send=?13, updated_at_be=?14
             WHERE operation_id=?1 AND revision_be=?15 AND fencing_epoch_be=?16",
            params![
                operation_id.as_slice(),
                revision.to_be_bytes().as_slice(),
                EvmTxStageV1::Reconciled.tag(),
                kind.tag(),
                source_stage.tag(),
                observation_digest.as_slice(),
                final_block.map(|value| value.to_be_bytes().to_vec()),
                final_block_hash.map(|value| value.to_vec()),
                final_evidence.map(|value| value.to_vec()),
                terminal_event_digest.map(|value| value.to_vec()),
                invalidation_evidence.map(|value| value.to_vec()),
                execution_success.map(|value| if value { 1 } else { 0 }),
                if matches!(
                    kind,
                    ReconciliationKindV1::Unknown | ReconciliationKindV1::FinalityInvalidated
                ) {
                    1
                } else {
                    0
                },
                commit_now_unix_ms.to_be_bytes().as_slice(),
                row.revision.to_be_bytes().as_slice(),
                row.fencing_epoch.to_be_bytes().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        insert_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
            Some(operation_id),
            revision,
        )?;
        let value = load_operation_view(&transaction, operation_id)?;
        transaction.commit()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Committed,
            value,
        })
    }

    /// Adopts a safely reconciled old-fence operation under the current fence.
    /// `Unknown` can never be adopted or retransmitted.
    pub fn adopt_reconciled(
        &mut self,
        lease: EvmActuatorLeaseV1,
        mutation_id: Digest32,
        operation_id: Digest32,
        expected_revision: u64,
        now_unix_ms: u64,
    ) -> Result<MutationOutcomeV1<EvmOperationViewV1>> {
        validate_id(mutation_id)?;
        validate_id(operation_id)?;
        let mutation_digest = domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/TAKEOVER-ADOPT/V1\0",
            &[
                &operation_id,
                &expected_revision.to_be_bytes(),
                &lease.fencing_epoch.to_be_bytes(),
            ],
        );
        let transaction = self.immediate()?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(status) = existing_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
        )? {
            let value = load_operation_view(&transaction, operation_id)?;
            transaction.commit()?;
            return Ok(MutationOutcomeV1 { status, value });
        }
        let row = load_operation_row(&transaction, operation_id)?;
        if row.authority_id != lease.authority_id
            || row.revision != expected_revision
            || row.stage != EvmTxStageV1::Reconciled
            || row.fencing_epoch >= lease.fencing_epoch
        {
            return Err(EvmActuatorErrorV1::InvalidState);
        }
        let kind = row
            .reconciliation_kind
            .ok_or(EvmActuatorErrorV1::CorruptState)?;
        let target = match kind {
            ReconciliationKindV1::InternallyNeverSent => row
                .reconciled_from_stage
                .filter(|stage| matches!(stage, EvmTxStageV1::Prepared | EvmTxStageV1::Signed))
                .ok_or(EvmActuatorErrorV1::CorruptState)?,
            ReconciliationKindV1::Observed => EvmTxStageV1::Observed,
            ReconciliationKindV1::Final => EvmTxStageV1::Final,
            ReconciliationKindV1::Unknown => return Err(EvmActuatorErrorV1::ReconciliationUnknown),
            ReconciliationKindV1::FinalityInvalidated => EvmTxStageV1::FinalityInvalidated,
        };
        let revision = expected_revision
            .checked_add(1)
            .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
        let changed = transaction.execute(
            "UPDATE evm_operations SET revision_be=?2, stage_tag=?3,
             fencing_epoch_be=?4, reconciliation_kind=NULL,
             reconciled_from_stage=NULL, updated_at_be=?5
             WHERE operation_id=?1 AND revision_be=?6 AND stage_tag=?7",
            params![
                operation_id.as_slice(),
                revision.to_be_bytes().as_slice(),
                target.tag(),
                lease.fencing_epoch.to_be_bytes().as_slice(),
                now_unix_ms.to_be_bytes().as_slice(),
                expected_revision.to_be_bytes().as_slice(),
                EvmTxStageV1::Reconciled.tag(),
            ],
        )?;
        if changed != 1 {
            return Err(EvmActuatorErrorV1::RevisionConflict);
        }
        if matches!(target, EvmTxStageV1::Prepared | EvmTxStageV1::Signed) {
            let cleared = transaction.execute(
                "UPDATE evm_operations SET observed_evidence=NULL
                 WHERE operation_id=?1 AND revision_be=?2 AND stage_tag=?3",
                params![
                    operation_id.as_slice(),
                    revision.to_be_bytes().as_slice(),
                    target.tag(),
                ],
            )?;
            if cleared != 1 {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
        }
        if matches!(
            target,
            EvmTxStageV1::Observed | EvmTxStageV1::Final | EvmTxStageV1::FinalityInvalidated
        ) {
            let attempt_changed = transaction.execute(
                "UPDATE evm_attempts SET stage_tag=?3, evidence_digest=(
                     SELECT observed_evidence FROM evm_operations WHERE operation_id=?1
                 ) WHERE operation_id=?1 AND attempt=?2 AND stage_tag IN (?4,?5,?6,?7)",
                params![
                    operation_id.as_slice(),
                    i64::from(row.current_attempt),
                    target.tag(),
                    EvmTxStageV1::SendAttempted.tag(),
                    EvmTxStageV1::Observed.tag(),
                    EvmTxStageV1::FinalityInvalidated.tag(),
                    EvmTxStageV1::Final.tag(),
                ],
            )?;
            if attempt_changed != 1 {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
        }
        insert_mutation(
            &transaction,
            lease.authority_id,
            mutation_id,
            mutation_digest,
            Some(operation_id),
            revision,
        )?;
        let value = load_operation_view(&transaction, operation_id)?;
        transaction.commit()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Committed,
            value,
        })
    }

    /// Loads one validated public operation view.
    pub fn operation(&self, operation_id: Digest32) -> Result<EvmOperationViewV1> {
        validate_id(operation_id)?;
        let transaction = self.deferred()?;
        let view = load_operation_view(&transaction, operation_id)?;
        transaction.commit()?;
        Ok(view)
    }

    /// Atomically loads one operation and its exact retained intent commitment
    /// under a live account lease.
    ///
    /// The row, complete attempt chain, initial fee tuple and stored operation
    /// request are reaudited in the same transaction before the intent is
    /// recomputed. No calldata, raw transaction or secret crosses this API.
    pub fn operation_binding(
        &mut self,
        lease: EvmActuatorLeaseV1,
        operation_id: Digest32,
        now_unix_ms: u64,
    ) -> Result<EvmOperationBindingViewV1> {
        validate_id(operation_id)?;
        let transaction = self.deferred()?;
        require_lease_read_only(&transaction, lease, now_unix_ms)?;
        let row = load_operation_row(&transaction, operation_id)?;
        if row.authority_id != lease.authority_id
            || row.account != lease.account
            || row.fields.chain_id != lease.chain_id
        {
            return Err(EvmActuatorErrorV1::InvalidScope);
        }
        let initial_fees = operation_initial_fees(&transaction, &row)?;
        let intent_digest = stored_operation_intent_digest(&row, initial_fees)?;
        validate_id(intent_digest).map_err(|_| EvmActuatorErrorV1::CorruptState)?;
        let operation = operation_view(&row);
        transaction.commit()?;
        Ok(EvmOperationBindingViewV1 {
            operation,
            intent_digest,
        })
    }

    /// Recovers the exact input revision of a retained operation mutation.
    ///
    /// `None` means this live account authority has no such mutation. A
    /// retained row is returned only after its operation locator, mutation
    /// family commitment, lease scope and monotonic revision are all crossed.
    /// This is the narrow crash-recovery bridge for replaying the same actuator
    /// call without guessing an earlier revision.
    pub fn retained_mutation_input_revision(
        &mut self,
        lease: EvmActuatorLeaseV1,
        kind: EvmRetainedMutationKindV1,
        mutation_id: Digest32,
        operation_id: Digest32,
        now_unix_ms: u64,
    ) -> Result<Option<u64>> {
        validate_id(mutation_id)?;
        validate_id(operation_id)?;
        let transaction = self.deferred()?;
        require_lease_read_only(&transaction, lease, now_unix_ms)?;
        let operation = load_operation_row(&transaction, operation_id)?;
        if operation.authority_id != lease.authority_id || operation.account != lease.account {
            return Err(EvmActuatorErrorV1::InvalidScope);
        }
        let retained: Option<RetainedMutationRowV1> = transaction
            .query_row(
                "SELECT operation_id,mutation_digest,resulting_revision_be
                 FROM evm_mutations WHERE authority_id=?1 AND mutation_id=?2",
                params![lease.authority_id.as_slice(), mutation_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((retained_operation, retained_digest, resulting_revision)) = retained else {
            transaction.commit()?;
            return Ok(None);
        };
        let retained_operation = retained_operation
            .ok_or(EvmActuatorErrorV1::IdempotencyConflict)
            .and_then(blob32)?;
        if retained_operation != operation_id {
            return Err(EvmActuatorErrorV1::IdempotencyConflict);
        }
        let resulting_revision = blob_u64(resulting_revision)?;
        let input_revision = resulting_revision
            .checked_sub(1)
            .ok_or(EvmActuatorErrorV1::CorruptState)?;
        if resulting_revision > operation.revision {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
        let expected_digest = match kind {
            EvmRetainedMutationKindV1::BroadcastCurrent => domain_digest(
                b"DOM-INTEROP/EVM-ACTUATOR/SEND/V1\0",
                &[
                    &operation_id,
                    &operation.current_attempt.to_be_bytes(),
                    &operation
                        .transaction_hash
                        .ok_or(EvmActuatorErrorV1::CorruptState)?,
                ],
            ),
            EvmRetainedMutationKindV1::ObserveCurrent => domain_digest(
                b"DOM-INTEROP/EVM-ACTUATOR/OBSERVE/V1\0",
                &[&operation_id, &input_revision.to_be_bytes()],
            ),
            EvmRetainedMutationKindV1::ReconcileTakeover => domain_digest(
                b"DOM-INTEROP/EVM-ACTUATOR/TAKEOVER-RECONCILE/V1\0",
                &[
                    &operation_id,
                    &input_revision.to_be_bytes(),
                    &lease.fencing_epoch.to_be_bytes(),
                ],
            ),
        };
        if blob32(retained_digest)? != expected_digest {
            return Err(EvmActuatorErrorV1::IdempotencyConflict);
        }
        transaction.commit()?;
        Ok(Some(input_revision))
    }

    /// Loads bounded public history for every signed attempt of an operation.
    pub fn attempts(&self, operation_id: Digest32) -> Result<Vec<EvmAttemptViewV1>> {
        validate_id(operation_id)?;
        let transaction = self.deferred()?;
        // Audit the complete retained attempt chain before exposing any view.
        load_operation_view(&transaction, operation_id)?;
        let output = {
            let mut statement = transaction.prepare(
                "SELECT attempt,stage_tag,max_fee_be,max_priority_fee_be,
                        signing_hash,transaction_hash
                 FROM evm_attempts WHERE operation_id=?1 ORDER BY attempt ASC LIMIT 1024",
            )?;
            let rows = statement.query_map(params![operation_id.as_slice()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })?;
            let mut output = Vec::new();
            for row in rows {
                let (attempt, stage, max_fee, priority, signing_hash_value, tx_hash) = row?;
                output.push(EvmAttemptViewV1 {
                    attempt: u32::try_from(attempt)
                        .map_err(|_| EvmActuatorErrorV1::CorruptState)?,
                    stage: EvmTxStageV1::from_tag(stage)?,
                    fees: EvmFeesV1::new(blob_u128(max_fee)?, blob_u128(priority)?)
                        .map_err(|_| EvmActuatorErrorV1::CorruptState)?,
                    signing_hash: blob32(signing_hash_value)?,
                    transaction_hash: blob32(tx_hash)?,
                });
            }
            output
        };
        transaction.commit()?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationRow {
    operation_id: Digest32,
    authority_id: Digest32,
    kind: EvmOperationKindV1,
    signer_role: EvmSignerRoleV1,
    route_id: Digest32,
    effect_id: Digest32,
    revision: u64,
    stage: EvmTxStageV1,
    fencing_epoch: u64,
    fields: Eip1559FieldsV1,
    account: EvmAddressV1,
    max_fee_cap: u128,
    max_priority_fee_cap: u128,
    registry_digest: Digest32,
    profile_digest: Digest32,
    asset_digest: Digest32,
    deployment_digest: Digest32,
    destination_code_hash: Digest32,
    genesis_hash: Digest32,
    semantic_digest: Digest32,
    terms_digest: Digest32,
    lock_id: Digest32,
    binding: Digest32,
    beneficiary: EvmAddressV1,
    funder: EvmAddressV1,
    adaptor_address: EvmAddressV1,
    deadline: u64,
    lock_amount: Digest32,
    refund_authorization: Option<RefundAuthorizationV1>,
    current_attempt: u32,
    transaction_hash: Option<Digest32>,
    ambiguous_after_send: bool,
    secret_exposed: bool,
    execution_success: Option<bool>,
    final_block_number: Option<u64>,
    final_block_hash: Option<Digest32>,
    final_evidence: Option<Digest32>,
    terminal_event_digest: Option<Digest32>,
    finality_invalidation_evidence: Option<Digest32>,
    reconciliation_kind: Option<ReconciliationKindV1>,
    reconciled_from_stage: Option<EvmTxStageV1>,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

impl OperationRow {
    fn fields(&self) -> Eip1559FieldsV1 {
        self.fields.clone()
    }
}

struct RawOperationRow {
    operation_id: Vec<u8>,
    authority_id: Vec<u8>,
    route_id: Vec<u8>,
    effect_id: Vec<u8>,
    kind: i64,
    signer_role: i64,
    revision: Vec<u8>,
    stage: i64,
    fencing_epoch: Vec<u8>,
    chain_id: Vec<u8>,
    account: Vec<u8>,
    nonce: Vec<u8>,
    destination: Vec<u8>,
    value: Vec<u8>,
    calldata: Vec<u8>,
    gas_limit: Vec<u8>,
    max_fee: Vec<u8>,
    priority_fee: Vec<u8>,
    max_fee_cap: Vec<u8>,
    priority_fee_cap: Vec<u8>,
    registry_digest: Vec<u8>,
    profile_digest: Vec<u8>,
    asset_digest: Vec<u8>,
    deployment_digest: Vec<u8>,
    destination_code_hash: Vec<u8>,
    genesis_hash: Vec<u8>,
    semantic_digest: Vec<u8>,
    terms_digest: Vec<u8>,
    lock_id: Vec<u8>,
    binding: Vec<u8>,
    beneficiary: Vec<u8>,
    funder: Vec<u8>,
    adaptor_address: Vec<u8>,
    deadline: Vec<u8>,
    lock_amount: Vec<u8>,
    refund_auth_block_number: Option<Vec<u8>>,
    refund_auth_block_hash: Option<Vec<u8>>,
    refund_auth_timestamp: Option<Vec<u8>>,
    refund_auth_evidence: Option<Vec<u8>>,
    current_attempt: i64,
    transaction_hash: Option<Vec<u8>>,
    ambiguous_after_send: i64,
    secret_exposed: i64,
    execution_success: Option<i64>,
    final_block_number: Option<Vec<u8>>,
    final_block_hash: Option<Vec<u8>>,
    final_evidence: Option<Vec<u8>>,
    terminal_event_digest: Option<Vec<u8>>,
    finality_invalidation_evidence: Option<Vec<u8>>,
    reconciliation_kind: Option<i64>,
    reconciled_from_stage: Option<i64>,
    created_at: Vec<u8>,
    updated_at: Vec<u8>,
}

struct RawAttemptIntegrityRow {
    attempt: i64,
    stage: i64,
    max_fee: Vec<u8>,
    priority_fee: Vec<u8>,
    signing_hash: Vec<u8>,
    raw_transaction: Vec<u8>,
    transaction_hash: Vec<u8>,
    y_parity: i64,
    signature_r: Vec<u8>,
    signature_s: Vec<u8>,
    send_attempted_at: Option<Vec<u8>>,
    evidence_digest: Option<Vec<u8>>,
    replaced_by: Option<i64>,
}

fn load_operation_row(
    transaction: &Transaction<'_>,
    operation_id: Digest32,
) -> Result<OperationRow> {
    let raw = transaction
        .query_row(
            "SELECT operation_id,authority_id,route_id,effect_id,operation_kind,signer_role,
                    revision_be,stage_tag,fencing_epoch_be,chain_id_be,account,nonce_be,
                    destination,value,calldata,gas_limit_be,max_fee_be,max_priority_fee_be,
                    max_fee_cap_be,max_priority_fee_cap_be,registry_digest,profile_digest,
                    asset_digest,deployment_digest,destination_code_hash,genesis_hash,
                    semantic_digest,terms_digest,lock_id,binding,beneficiary,funder,
                    adaptor_address,deadline_be,lock_amount,refund_auth_block_number_be,
                    refund_auth_block_hash,refund_auth_timestamp_be,refund_auth_evidence,
                    current_attempt,transaction_hash,ambiguous_after_send,secret_exposed,
                    execution_success,final_block_number_be,final_block_hash,final_evidence,
                    terminal_event_digest,finality_invalidation_evidence,reconciliation_kind,
                    reconciled_from_stage,created_at_be,updated_at_be
             FROM evm_operations WHERE operation_id=?1",
            params![operation_id.as_slice()],
            |row| {
                Ok(RawOperationRow {
                    operation_id: row.get(0)?,
                    authority_id: row.get(1)?,
                    route_id: row.get(2)?,
                    effect_id: row.get(3)?,
                    kind: row.get(4)?,
                    signer_role: row.get(5)?,
                    revision: row.get(6)?,
                    stage: row.get(7)?,
                    fencing_epoch: row.get(8)?,
                    chain_id: row.get(9)?,
                    account: row.get(10)?,
                    nonce: row.get(11)?,
                    destination: row.get(12)?,
                    value: row.get(13)?,
                    calldata: row.get(14)?,
                    gas_limit: row.get(15)?,
                    max_fee: row.get(16)?,
                    priority_fee: row.get(17)?,
                    max_fee_cap: row.get(18)?,
                    priority_fee_cap: row.get(19)?,
                    registry_digest: row.get(20)?,
                    profile_digest: row.get(21)?,
                    asset_digest: row.get(22)?,
                    deployment_digest: row.get(23)?,
                    destination_code_hash: row.get(24)?,
                    genesis_hash: row.get(25)?,
                    semantic_digest: row.get(26)?,
                    terms_digest: row.get(27)?,
                    lock_id: row.get(28)?,
                    binding: row.get(29)?,
                    beneficiary: row.get(30)?,
                    funder: row.get(31)?,
                    adaptor_address: row.get(32)?,
                    deadline: row.get(33)?,
                    lock_amount: row.get(34)?,
                    refund_auth_block_number: row.get(35)?,
                    refund_auth_block_hash: row.get(36)?,
                    refund_auth_timestamp: row.get(37)?,
                    refund_auth_evidence: row.get(38)?,
                    current_attempt: row.get(39)?,
                    transaction_hash: row.get(40)?,
                    ambiguous_after_send: row.get(41)?,
                    secret_exposed: row.get(42)?,
                    execution_success: row.get(43)?,
                    final_block_number: row.get(44)?,
                    final_block_hash: row.get(45)?,
                    final_evidence: row.get(46)?,
                    terminal_event_digest: row.get(47)?,
                    finality_invalidation_evidence: row.get(48)?,
                    reconciliation_kind: row.get(49)?,
                    reconciled_from_stage: row.get(50)?,
                    created_at: row.get(51)?,
                    updated_at: row.get(52)?,
                })
            },
        )
        .optional()?
        .ok_or(EvmActuatorErrorV1::OperationNotFound)?;
    let parsed = parse_operation_row(raw)?;
    validate_operation_integrity(transaction, &parsed)?;
    Ok(parsed)
}

fn parse_operation_row(raw: RawOperationRow) -> Result<OperationRow> {
    let calldata = Zeroizing::new(raw.calldata);
    if calldata.is_empty() || calldata.len() > adapter_evm::abi::MAX_CALLDATA_BYTES {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let fields = Eip1559FieldsV1 {
        chain_id: blob_u64(raw.chain_id)?,
        nonce: blob_u64(raw.nonce)?,
        fees: EvmFeesV1::new(blob_u128(raw.max_fee)?, blob_u128(raw.priority_fee)?)
            .map_err(|_| EvmActuatorErrorV1::CorruptState)?,
        gas_limit: blob_u64(raw.gas_limit)?,
        to: blob20(raw.destination)?,
        value: blob32(raw.value)?,
        calldata,
    };
    let kind = EvmOperationKindV1::from_tag(raw.kind)?;
    let signer_role = EvmSignerRoleV1::from_tag(raw.signer_role)?;
    let stage = EvmTxStageV1::from_tag(raw.stage)?;
    let current_attempt =
        u32::try_from(raw.current_attempt).map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    if (stage == EvmTxStageV1::Prepared && current_attempt != 0)
        || (stage != EvmTxStageV1::Prepared
            && current_attempt == 0
            && stage != EvmTxStageV1::Reconciled)
        || raw.ambiguous_after_send < 0
        || raw.ambiguous_after_send > 1
        || raw.secret_exposed < 0
        || raw.secret_exposed > 1
        || raw
            .execution_success
            .is_some_and(|value| value != 0 && value != 1)
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let operation_id = blob32(raw.operation_id)?;
    let stored_authority_id = blob32(raw.authority_id)?;
    let route_id = blob32(raw.route_id)?;
    let effect_id = blob32(raw.effect_id)?;
    let revision = blob_u64(raw.revision)?;
    let fencing_epoch = blob_u64(raw.fencing_epoch)?;
    let account = blob20(raw.account)?;
    let max_fee_cap = blob_u128(raw.max_fee_cap)?;
    let max_priority_fee_cap = blob_u128(raw.priority_fee_cap)?;
    let registry_digest = blob32(raw.registry_digest)?;
    let profile_digest = blob32(raw.profile_digest)?;
    let asset_digest = blob32(raw.asset_digest)?;
    let deployment_digest = blob32(raw.deployment_digest)?;
    let destination_code_hash = blob32(raw.destination_code_hash)?;
    let genesis_hash = blob32(raw.genesis_hash)?;
    let semantic_digest = blob32(raw.semantic_digest)?;
    let terms_digest = blob32(raw.terms_digest)?;
    let lock_id = blob32(raw.lock_id)?;
    let binding = blob32(raw.binding)?;
    let beneficiary = blob20(raw.beneficiary)?;
    let funder = blob20(raw.funder)?;
    let adaptor_address = blob20(raw.adaptor_address)?;
    let deadline = blob_u64(raw.deadline)?;
    let lock_amount = blob32(raw.lock_amount)?;
    let refund_parts = (
        raw.refund_auth_block_number,
        raw.refund_auth_block_hash,
        raw.refund_auth_timestamp,
        raw.refund_auth_evidence,
    );
    let refund_authorization = match refund_parts {
        (Some(number), Some(hash), Some(timestamp), Some(evidence)) => {
            Some(RefundAuthorizationV1 {
                block_number: blob_u64(number)?,
                block_hash: blob32(hash)?,
                timestamp: blob_u64(timestamp)?,
                evidence_digest: blob32(evidence)?,
            })
        }
        (None, None, None, None) => None,
        _ => return Err(EvmActuatorErrorV1::CorruptState),
    };
    let final_block_number = raw.final_block_number.map(blob_u64).transpose()?;
    let final_block_hash = raw.final_block_hash.map(blob32).transpose()?;
    let final_evidence = raw.final_evidence.map(blob32).transpose()?;
    let terminal_event_digest = raw.terminal_event_digest.map(blob32).transpose()?;
    let finality_invalidation_evidence =
        raw.finality_invalidation_evidence.map(blob32).transpose()?;
    let created_at_unix_ms = blob_u64(raw.created_at)?;
    let updated_at_unix_ms = blob_u64(raw.updated_at)?;
    if fields_digest(&fields)? == ZERO_DIGEST
        || [
            operation_id,
            stored_authority_id,
            route_id,
            effect_id,
            registry_digest,
            profile_digest,
            asset_digest,
            deployment_digest,
            destination_code_hash,
            genesis_hash,
            semantic_digest,
            terms_digest,
            lock_id,
            binding,
        ]
        .contains(&ZERO_DIGEST)
        || revision == 0
        || fencing_epoch == 0
        || account == [0; 20]
        || beneficiary == [0; 20]
        || funder == [0; 20]
        || adaptor_address == [0; 20]
        || deadline == 0
        || lock_amount == ZERO_DIGEST
        || stored_authority_id != authority_id(fields.chain_id, account)
        || max_fee_cap == 0
        || max_priority_fee_cap == 0
        || fields.fees.max_fee_per_gas > max_fee_cap
        || fields.fees.max_priority_fee_per_gas > max_priority_fee_cap
        || current_attempt > 1_024
        || created_at_unix_ms == 0
        || updated_at_unix_ms < created_at_unix_ms
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    Ok(OperationRow {
        operation_id,
        authority_id: stored_authority_id,
        kind,
        signer_role,
        route_id,
        effect_id,
        revision,
        stage,
        fencing_epoch,
        fields,
        account,
        max_fee_cap,
        max_priority_fee_cap,
        registry_digest,
        profile_digest,
        asset_digest,
        deployment_digest,
        destination_code_hash,
        genesis_hash,
        semantic_digest,
        terms_digest,
        lock_id,
        binding,
        beneficiary,
        funder,
        adaptor_address,
        deadline,
        lock_amount,
        refund_authorization,
        current_attempt,
        transaction_hash: raw.transaction_hash.map(blob32).transpose()?,
        ambiguous_after_send: raw.ambiguous_after_send == 1,
        secret_exposed: raw.secret_exposed == 1,
        execution_success: raw.execution_success.map(|value| value == 1),
        final_block_number,
        final_block_hash,
        final_evidence,
        terminal_event_digest,
        finality_invalidation_evidence,
        reconciliation_kind: raw
            .reconciliation_kind
            .map(ReconciliationKindV1::from_tag)
            .transpose()?,
        reconciled_from_stage: raw
            .reconciled_from_stage
            .map(EvmTxStageV1::from_tag)
            .transpose()?,
        created_at_unix_ms,
        updated_at_unix_ms,
    })
}

fn validate_operation_integrity(transaction: &Transaction<'_>, row: &OperationRow) -> Result<()> {
    let retained = transaction.query_row(
        "SELECT request_digest,calldata_digest,erc20_token,allowance_revision_be,
                observed_evidence
         FROM evm_operations WHERE operation_id=?1",
        params![row.operation_id.as_slice()],
        |record| {
            Ok((
                record.get::<_, Vec<u8>>(0)?,
                record.get::<_, Vec<u8>>(1)?,
                record.get::<_, Option<Vec<u8>>>(2)?,
                record.get::<_, Option<Vec<u8>>>(3)?,
                record.get::<_, Option<Vec<u8>>>(4)?,
            ))
        },
    )?;
    let request_digest = blob32(retained.0)?;
    let calldata_digest = blob32(retained.1)?;
    let erc20_token = retained.2.map(blob20).transpose()?;
    let allowance_revision = retained.3.map(blob_u64).transpose()?;
    let observed_evidence = retained.4.map(blob32).transpose()?;
    let lease: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = transaction.query_row(
        "SELECT chain_id_be,account,fencing_epoch_be,clock_high_water_be
         FROM evm_leases WHERE authority_id=?1",
        params![row.authority_id.as_slice()],
        |record| {
            Ok((
                record.get(0)?,
                record.get(1)?,
                record.get(2)?,
                record.get(3)?,
            ))
        },
    )?;
    if blob_u64(lease.0)? != row.fields.chain_id
        || blob20(lease.1)? != row.account
        || blob_u64(lease.2)? < row.fencing_epoch
        || blob_u64(lease.3)? < row.updated_at_unix_ms
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let request_fees = operation_initial_fees(transaction, row)?;
    let expected_request_digest = stored_operation_request_digest(row, request_fees)?;
    if request_digest != expected_request_digest
        || calldata_digest != keccak256(&row.fields.calldata)
        || erc20_token.is_some() != allowance_revision.is_some()
        || erc20_token == Some([0; 20])
        || allowance_revision == Some(0)
        || observed_evidence == Some(ZERO_DIGEST)
        || row.final_evidence == Some(ZERO_DIGEST)
        || row.final_block_number == Some(0)
        || row.final_block_hash == Some(ZERO_DIGEST)
        || row.terminal_event_digest == Some(ZERO_DIGEST)
        || row.finality_invalidation_evidence == Some(ZERO_DIGEST)
        || !operation_role_is_exact(row)
        || !operation_calldata_is_exact(row)?
        || !refund_authorization_is_exact(row)
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    if row.kind != EvmOperationKindV1::Open && erc20_token.is_some() {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let reconciliation = row.reconciliation_kind.zip(row.reconciled_from_stage);
    match row.stage {
        EvmTxStageV1::Prepared
            if row.current_attempt == 0
                && row.transaction_hash.is_none()
                && !row.ambiguous_after_send
                && !row.secret_exposed
                && row.execution_success.is_none()
                && observed_evidence.is_none()
                && row.final_block_number.is_none()
                && row.final_block_hash.is_none()
                && row.final_evidence.is_none()
                && row.terminal_event_digest.is_none()
                && row.finality_invalidation_evidence.is_none()
                && reconciliation.is_none() => {}
        EvmTxStageV1::Signed
            if row.current_attempt > 0
                && row.transaction_hash.is_some()
                && !row.ambiguous_after_send
                && row.secret_exposed
                    == (row.kind == EvmOperationKindV1::Claim && row.current_attempt > 1)
                && row.execution_success.is_none()
                && observed_evidence.is_none()
                && row.final_block_number.is_none()
                && row.final_block_hash.is_none()
                && row.final_evidence.is_none()
                && row.terminal_event_digest.is_none()
                && row.finality_invalidation_evidence.is_none()
                && reconciliation.is_none() => {}
        EvmTxStageV1::SendAttempted
            if row.current_attempt > 0
                && row.transaction_hash.is_some()
                && row.ambiguous_after_send
                && row.secret_exposed == (row.kind == EvmOperationKindV1::Claim)
                && row.execution_success.is_none()
                && row.final_block_number.is_none()
                && row.final_block_hash.is_none()
                && row.final_evidence.is_none()
                && row.terminal_event_digest.is_none()
                && row.finality_invalidation_evidence.is_none()
                && reconciliation.is_none() => {}
        EvmTxStageV1::Observed
            if row.current_attempt > 0
                && row.transaction_hash.is_some()
                && !row.ambiguous_after_send
                && row.secret_exposed == (row.kind == EvmOperationKindV1::Claim)
                && observed_evidence.is_some()
                && row.final_block_number.is_none()
                && row.final_block_hash.is_none()
                && row.final_evidence.is_none()
                && row.terminal_event_digest.is_none()
                && row.finality_invalidation_evidence.is_none()
                && reconciliation.is_none() => {}
        EvmTxStageV1::Final
            if row.current_attempt > 0
                && row.transaction_hash.is_some()
                && !row.ambiguous_after_send
                && row.execution_success.is_some()
                && observed_evidence.is_some()
                && row.secret_exposed == (row.kind == EvmOperationKindV1::Claim)
                && row.final_block_number.is_some()
                && row.final_block_hash.is_some()
                && row.final_evidence.is_some()
                && terminal_event_state_is_exact(row)
                && row.finality_invalidation_evidence.is_none()
                && reconciliation.is_none() => {}
        EvmTxStageV1::FinalityInvalidated
            if row.current_attempt > 0
                && row.transaction_hash.is_some()
                && observed_evidence.is_some()
                && row.secret_exposed == (row.kind == EvmOperationKindV1::Claim)
                && row.execution_success.is_some()
                && row.final_block_number.is_some()
                && row.final_block_hash.is_some()
                && row.final_evidence.is_some()
                && terminal_event_state_is_exact(row)
                && row.finality_invalidation_evidence.is_some()
                && reconciliation.is_none() => {}
        EvmTxStageV1::Reconciled => {
            validate_reconciled_integrity(
                row,
                reconciliation.ok_or(EvmActuatorErrorV1::CorruptState)?,
                observed_evidence,
                row.final_block_number,
                row.final_evidence,
            )?;
        }
        EvmTxStageV1::Replaced => return Err(EvmActuatorErrorV1::CorruptState),
        _ => return Err(EvmActuatorErrorV1::CorruptState),
    }
    validate_attempt_integrity(transaction, row, observed_evidence)
}

fn operation_initial_fees(transaction: &Transaction<'_>, row: &OperationRow) -> Result<EvmFeesV1> {
    if row.current_attempt == 0 {
        return Ok(row.fields.fees);
    }
    let (max_fee, priority): (Vec<u8>, Vec<u8>) = transaction.query_row(
        "SELECT max_fee_be,max_priority_fee_be FROM evm_attempts
         WHERE operation_id=?1 AND attempt=1",
        params![row.operation_id.as_slice()],
        |record| Ok((record.get(0)?, record.get(1)?)),
    )?;
    EvmFeesV1::new(blob_u128(max_fee)?, blob_u128(priority)?)
        .map_err(|_| EvmActuatorErrorV1::CorruptState)
}

fn stored_operation_request_digest(
    row: &OperationRow,
    request_fees: EvmFeesV1,
) -> Result<Digest32> {
    let kind = [u8::try_from(row.kind.tag()).map_err(|_| EvmActuatorErrorV1::CorruptState)?];
    let role = [u8::try_from(row.signer_role.tag()).map_err(|_| EvmActuatorErrorV1::CorruptState)?];
    let refund = row.refund_authorization;
    Ok(domain_digest(
        b"DOM-INTEROP/EVM-ACTUATOR/OPERATION-REQUEST/V2\0",
        &[
            &row.operation_id,
            &kind,
            &role,
            &row.route_id,
            &row.effect_id,
            &row.semantic_digest,
            &row.registry_digest,
            &row.profile_digest,
            &row.asset_digest,
            &row.deployment_digest,
            &row.destination_code_hash,
            &row.genesis_hash,
            &row.fields.chain_id.to_be_bytes(),
            &row.fields.to,
            &row.terms_digest,
            &row.lock_id,
            &row.binding,
            &row.beneficiary,
            &row.funder,
            &row.adaptor_address,
            &row.deadline.to_be_bytes(),
            &row.lock_amount,
            &row.fields.value,
            &row.fields.gas_limit.to_be_bytes(),
            &row.fields.calldata,
            &refund
                .map(|value| value.block_number)
                .unwrap_or(0)
                .to_be_bytes(),
            &refund.map(|value| value.block_hash).unwrap_or(ZERO_DIGEST),
            &refund
                .map(|value| value.timestamp)
                .unwrap_or(0)
                .to_be_bytes(),
            &refund
                .map(|value| value.evidence_digest)
                .unwrap_or(ZERO_DIGEST),
            &request_fees.max_fee_per_gas.to_be_bytes(),
            &request_fees.max_priority_fee_per_gas.to_be_bytes(),
        ],
    ))
}

fn stored_operation_intent_digest(row: &OperationRow, request_fees: EvmFeesV1) -> Result<Digest32> {
    let kind = [u8::try_from(row.kind.tag()).map_err(|_| EvmActuatorErrorV1::CorruptState)?];
    let role = [u8::try_from(row.signer_role.tag()).map_err(|_| EvmActuatorErrorV1::CorruptState)?];
    Ok(domain_digest(
        b"DOM-INTEROP/EVM-ACTUATOR/OPERATION-INTENT/V2\0",
        &[
            &row.operation_id,
            &kind,
            &role,
            &row.route_id,
            &row.effect_id,
            &row.semantic_digest,
            &row.registry_digest,
            &row.profile_digest,
            &row.asset_digest,
            &row.deployment_digest,
            &row.destination_code_hash,
            &row.genesis_hash,
            &row.fields.chain_id.to_be_bytes(),
            &row.fields.to,
            &row.terms_digest,
            &row.lock_id,
            &row.binding,
            &row.beneficiary,
            &row.funder,
            &row.adaptor_address,
            &row.deadline.to_be_bytes(),
            &row.lock_amount,
            &row.fields.value,
            &row.fields.gas_limit.to_be_bytes(),
            &row.fields.calldata,
            &request_fees.max_fee_per_gas.to_be_bytes(),
            &request_fees.max_priority_fee_per_gas.to_be_bytes(),
        ],
    ))
}

fn operation_role_is_exact(row: &OperationRow) -> bool {
    match row.kind {
        EvmOperationKindV1::Open | EvmOperationKindV1::Refund => {
            row.signer_role == EvmSignerRoleV1::Funder && row.account == row.funder
        }
        EvmOperationKindV1::Claim => {
            row.signer_role == EvmSignerRoleV1::Beneficiary && row.account == row.beneficiary
        }
    }
}

fn operation_calldata_is_exact(row: &OperationRow) -> Result<bool> {
    let calldata = &row.fields.calldata;
    match row.kind {
        EvmOperationKindV1::Open => {
            if calldata.len() != 4 + 10 * 32 || calldata[..4] != selector(SIG_OPEN) {
                return Ok(false);
            }
            let words =
                split_words(&calldata[4..], 10).map_err(|_| EvmActuatorErrorV1::CorruptState)?;
            let terms = LockTerms {
                dom_chain_id: words[0],
                direction: decode_u8(&words[1]).map_err(|_| EvmActuatorErrorV1::CorruptState)?,
                session_id: words[2],
                terms_hash: words[3],
                participants_hash: words[4],
                asset: decode_address(&words[5]).map_err(|_| EvmActuatorErrorV1::CorruptState)?,
                amount: words[6],
                beneficiary: decode_address(&words[7])
                    .map_err(|_| EvmActuatorErrorV1::CorruptState)?,
                adaptor_address: decode_address(&words[8])
                    .map_err(|_| EvmActuatorErrorV1::CorruptState)?,
                deadline: decode_u64(&words[9]).map_err(|_| EvmActuatorErrorV1::CorruptState)?,
            };
            let binding = derive_binding(row.fields.chain_id, &row.fields.to, &terms)
                .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
            let lock_id = derive_lock_id(&binding, &row.funder)
                .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
            let expected_value = if terms.asset == [0; 20] {
                terms.amount
            } else {
                ZERO_DIGEST
            };
            Ok(terms.terms_hash == row.terms_digest
                && terms.beneficiary == row.beneficiary
                && terms.amount == row.lock_amount
                && terms.adaptor_address == row.adaptor_address
                && terms.deadline == row.deadline
                && binding == row.binding
                && lock_id == row.lock_id
                && row.fields.value == expected_value)
        }
        EvmOperationKindV1::Claim => {
            if calldata.len() != CLAIM_CALLDATA_LEN
                || calldata[..4] != selector(SIG_CLAIM)
                || row.fields.value != ZERO_DIGEST
            {
                return Ok(false);
            }
            let mut lock_id = [0; 32];
            lock_id.copy_from_slice(&calldata[4..36]);
            let mut scalar = Zeroizing::new([0; 32]);
            scalar.copy_from_slice(&calldata[36..68]);
            let address = adapter_evm::adaptor_address_of_scalar(&scalar)
                .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
            Ok(lock_id == row.lock_id && address == row.adaptor_address)
        }
        EvmOperationKindV1::Refund => {
            if calldata.len() != REFUND_CALLDATA_LEN
                || calldata[..4] != selector(SIG_REFUND)
                || row.fields.value != ZERO_DIGEST
            {
                return Ok(false);
            }
            Ok(calldata[4..36] == row.lock_id)
        }
    }
}

fn refund_authorization_is_exact(row: &OperationRow) -> bool {
    match (row.kind, row.refund_authorization) {
        (EvmOperationKindV1::Refund, Some(value)) => {
            value.block_number > 0
                && value.block_hash != ZERO_DIGEST
                && value.timestamp >= row.deadline
                && value.evidence_digest != ZERO_DIGEST
        }
        (EvmOperationKindV1::Open | EvmOperationKindV1::Claim, None) => true,
        _ => false,
    }
}

fn terminal_event_state_is_exact(row: &OperationRow) -> bool {
    match (row.kind, row.execution_success) {
        (EvmOperationKindV1::Open, _) => row.terminal_event_digest.is_none(),
        (EvmOperationKindV1::Claim | EvmOperationKindV1::Refund, Some(true)) => {
            row.terminal_event_digest.is_some()
        }
        (EvmOperationKindV1::Claim | EvmOperationKindV1::Refund, Some(false)) => {
            row.terminal_event_digest.is_none()
        }
        _ => false,
    }
}

fn validate_reconciled_integrity(
    row: &OperationRow,
    (kind, source): (ReconciliationKindV1, EvmTxStageV1),
    observed_evidence: Option<Digest32>,
    final_block: Option<u64>,
    final_evidence: Option<Digest32>,
) -> Result<()> {
    if observed_evidence.is_none() {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let valid = match kind {
        ReconciliationKindV1::InternallyNeverSent => {
            matches!(source, EvmTxStageV1::Prepared | EvmTxStageV1::Signed)
                && !row.ambiguous_after_send
                && row.secret_exposed
                    == (row.kind == EvmOperationKindV1::Claim
                        && source == EvmTxStageV1::Signed
                        && row.current_attempt > 1)
                && row.execution_success.is_none()
                && final_block.is_none()
                && final_evidence.is_none()
                && row.final_block_hash.is_none()
                && row.terminal_event_digest.is_none()
                && row.finality_invalidation_evidence.is_none()
        }
        ReconciliationKindV1::Observed => {
            matches!(source, EvmTxStageV1::SendAttempted | EvmTxStageV1::Observed)
                && row.transaction_hash.is_some()
                && !row.ambiguous_after_send
                && row.secret_exposed == (row.kind == EvmOperationKindV1::Claim)
                && final_block.is_none()
                && final_evidence.is_none()
                && row.final_block_hash.is_none()
                && row.terminal_event_digest.is_none()
                && row.finality_invalidation_evidence.is_none()
        }
        ReconciliationKindV1::Final => {
            matches!(
                source,
                EvmTxStageV1::SendAttempted | EvmTxStageV1::Observed | EvmTxStageV1::Final
            ) && row.transaction_hash.is_some()
                && !row.ambiguous_after_send
                && row.execution_success.is_some()
                && final_block.is_some()
                && final_evidence.is_some()
                && row.final_block_hash.is_some()
                && terminal_event_state_is_exact(row)
                && row.finality_invalidation_evidence.is_none()
        }
        ReconciliationKindV1::Unknown => {
            let ordinary = matches!(source, EvmTxStageV1::SendAttempted | EvmTxStageV1::Observed)
                && row.execution_success.is_none()
                && final_block.is_none()
                && final_evidence.is_none()
                && row.final_block_hash.is_none()
                && row.terminal_event_digest.is_none()
                && row.finality_invalidation_evidence.is_none();
            let invalidated = source == EvmTxStageV1::FinalityInvalidated
                && row.execution_success.is_some()
                && final_block.is_some()
                && final_evidence.is_some()
                && row.final_block_hash.is_some()
                && terminal_event_state_is_exact(row)
                && row.finality_invalidation_evidence.is_some();
            row.transaction_hash.is_some()
                && row.ambiguous_after_send
                && row.secret_exposed == (row.kind == EvmOperationKindV1::Claim)
                && (ordinary || invalidated)
        }
        ReconciliationKindV1::FinalityInvalidated => {
            matches!(
                source,
                EvmTxStageV1::SendAttempted
                    | EvmTxStageV1::Observed
                    | EvmTxStageV1::Final
                    | EvmTxStageV1::FinalityInvalidated
            ) && row.transaction_hash.is_some()
                && row.ambiguous_after_send
                && row.secret_exposed == (row.kind == EvmOperationKindV1::Claim)
                && row.execution_success.is_some()
                && final_block.is_some()
                && final_evidence.is_some()
                && row.final_block_hash.is_some()
                && terminal_event_state_is_exact(row)
                && row.finality_invalidation_evidence.is_some()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(EvmActuatorErrorV1::CorruptState)
    }
}

fn validate_attempt_integrity(
    transaction: &Transaction<'_>,
    row: &OperationRow,
    observed_evidence: Option<Digest32>,
) -> Result<()> {
    let (count, minimum, maximum): (i64, Option<i64>, Option<i64>) = transaction.query_row(
        "SELECT COUNT(*),MIN(attempt),MAX(attempt) FROM evm_attempts WHERE operation_id=?1",
        params![row.operation_id.as_slice()],
        |record| Ok((record.get(0)?, record.get(1)?, record.get(2)?)),
    )?;
    if row.current_attempt == 0 {
        return if count == 0 {
            Ok(())
        } else {
            Err(EvmActuatorErrorV1::CorruptState)
        };
    }
    if count != i64::from(row.current_attempt)
        || minimum != Some(1)
        || maximum != Some(i64::from(row.current_attempt))
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let expected_stage = if row.stage == EvmTxStageV1::Reconciled {
        row.reconciled_from_stage
            .ok_or(EvmActuatorErrorV1::CorruptState)?
    } else {
        row.stage
    };

    let mut statement = transaction.prepare(
        "SELECT attempt,stage_tag,max_fee_be,max_priority_fee_be,signing_hash,
                raw_transaction,transaction_hash,y_parity,signature_r,signature_s,
                send_attempted_at_be,evidence_digest,replaced_by
         FROM evm_attempts WHERE operation_id=?1 ORDER BY attempt ASC",
    )?;
    let attempts = statement.query_map(params![row.operation_id.as_slice()], |record| {
        Ok(RawAttemptIntegrityRow {
            attempt: record.get(0)?,
            stage: record.get(1)?,
            max_fee: record.get(2)?,
            priority_fee: record.get(3)?,
            signing_hash: record.get(4)?,
            raw_transaction: record.get(5)?,
            transaction_hash: record.get(6)?,
            y_parity: record.get(7)?,
            signature_r: record.get(8)?,
            signature_s: record.get(9)?,
            send_attempted_at: record.get(10)?,
            evidence_digest: record.get(11)?,
            replaced_by: record.get(12)?,
        })
    })?;

    let mut expected_attempt = 1u32;
    let mut prior_fees = None;
    for retained in attempts {
        let retained = retained?;
        let raw = Zeroizing::new(retained.raw_transaction);
        let attempt =
            u32::try_from(retained.attempt).map_err(|_| EvmActuatorErrorV1::CorruptState)?;
        if attempt != expected_attempt {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
        let stage = EvmTxStageV1::from_tag(retained.stage)?;
        let fees = EvmFeesV1::new(
            blob_u128(retained.max_fee)?,
            blob_u128(retained.priority_fee)?,
        )
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
        if fees.max_fee_per_gas > row.max_fee_cap
            || fees.max_priority_fee_per_gas > row.max_priority_fee_cap
            || prior_fees.is_some_and(|prior: EvmFeesV1| {
                fees.max_fee_per_gas < prior.max_fee_per_gas
                    || fees.max_priority_fee_per_gas < prior.max_priority_fee_per_gas
                    || fees == prior
            })
        {
            return Err(EvmActuatorErrorV1::CorruptState);
        }

        let stored_signing_hash = blob32(retained.signing_hash)?;
        if raw.is_empty() || raw.len() > MAX_RAW_TRANSACTION_BYTES_V1 {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
        let stored_transaction_hash = blob32(retained.transaction_hash)?;
        let send_attempted_at = retained.send_attempted_at.map(blob_u64).transpose()?;
        let evidence_digest = retained.evidence_digest.map(blob32).transpose()?;
        if send_attempted_at == Some(0)
            || send_attempted_at.is_some_and(|value| value > row.updated_at_unix_ms)
            || evidence_digest == Some(ZERO_DIGEST)
            || !attempt_metadata_is_exact(stage, send_attempted_at, evidence_digest)
        {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
        let signature = crate::model::Eip1559SignatureV1 {
            y_parity: u8::try_from(retained.y_parity)
                .map_err(|_| EvmActuatorErrorV1::CorruptState)?,
            r: blob32(retained.signature_r)?,
            s: blob32(retained.signature_s)?,
        };
        let mut attempt_fields = row.fields();
        attempt_fields.fees = fees;
        let (expected_raw, expected_hash) =
            verify_and_encode_signed(&attempt_fields, row.account, signature)
                .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
        if stored_signing_hash
            != signing_hash(&attempt_fields).map_err(|_| EvmActuatorErrorV1::CorruptState)?
            || raw != expected_raw
            || stored_transaction_hash != expected_hash
        {
            return Err(EvmActuatorErrorV1::CorruptState);
        }

        if attempt == row.current_attempt {
            if stage != expected_stage
                || fees != row.fields.fees
                || row.transaction_hash != Some(expected_hash)
                || retained.replaced_by.is_some()
                // Reconciliation has its own operation-level observation. It
                // intentionally preserves the last signed attempt and that
                // attempt's prior receipt evidence until explicit adoption.
                || (matches!(
                    expected_stage,
                    EvmTxStageV1::Observed
                        | EvmTxStageV1::Final
                        | EvmTxStageV1::FinalityInvalidated
                ) && row.stage != EvmTxStageV1::Reconciled
                    && evidence_digest != observed_evidence)
            {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
        } else if stage != EvmTxStageV1::Replaced
            || retained.replaced_by != Some(i64::from(attempt + 1))
        {
            return Err(EvmActuatorErrorV1::CorruptState);
        }

        prior_fees = Some(fees);
        expected_attempt = expected_attempt
            .checked_add(1)
            .ok_or(EvmActuatorErrorV1::CorruptState)?;
    }
    if expected_attempt != row.current_attempt + 1 {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    Ok(())
}

fn attempt_metadata_is_exact(
    stage: EvmTxStageV1,
    send_attempted_at: Option<u64>,
    evidence_digest: Option<Digest32>,
) -> bool {
    match stage {
        EvmTxStageV1::Signed => send_attempted_at.is_none() && evidence_digest.is_none(),
        EvmTxStageV1::SendAttempted => send_attempted_at.is_some(),
        EvmTxStageV1::Observed | EvmTxStageV1::Final | EvmTxStageV1::FinalityInvalidated => {
            send_attempted_at.is_some() && evidence_digest.is_some()
        }
        EvmTxStageV1::Replaced => send_attempted_at.is_some(),
        EvmTxStageV1::Prepared | EvmTxStageV1::Reconciled => false,
    }
}

fn load_operation_view(
    transaction: &Transaction<'_>,
    operation_id: Digest32,
) -> Result<EvmOperationViewV1> {
    let row = load_operation_row(transaction, operation_id)?;
    Ok(operation_view(&row))
}

fn operation_view(row: &OperationRow) -> EvmOperationViewV1 {
    EvmOperationViewV1 {
        operation_id: row.operation_id,
        kind: row.kind,
        signer_role: row.signer_role,
        route_id: row.route_id,
        effect_id: row.effect_id,
        semantic_digest: row.semantic_digest,
        registry_digest: row.registry_digest,
        profile_digest: row.profile_digest,
        asset_binding_digest: row.asset_digest,
        deployment_digest: row.deployment_digest,
        terms_digest: row.terms_digest,
        revision: row.revision,
        stage: row.stage,
        fencing_epoch: row.fencing_epoch,
        nonce: row.fields.nonce,
        chain_id: row.fields.chain_id,
        contract: row.fields.to,
        signing_account: row.account,
        beneficiary: row.beneficiary,
        funder: row.funder,
        lock_id: row.lock_id,
        binding: row.binding,
        current_attempt: row.current_attempt,
        fees: row.fields.fees,
        transaction_hash: row.transaction_hash,
        ambiguous_after_send: row.ambiguous_after_send,
        execution_success: row.execution_success,
        secret_exposed: row.secret_exposed,
        terminal_event_digest: row.terminal_event_digest,
        final_block_number: row.final_block_number,
        final_block_hash: row.final_block_hash,
        final_evidence_digest: row.final_evidence,
        finality_invalidation_evidence_digest: row.finality_invalidation_evidence,
        refund_authorized_block: row.refund_authorization.map(|value| value.block_number),
        refund_authorization: row
            .refund_authorization
            .map(|value| EvmRefundAuthorizationViewV1 {
                block_number: value.block_number,
                block_hash: value.block_hash,
                timestamp: value.timestamp,
                evidence_digest: value.evidence_digest,
            }),
        reconciliation_kind: row.reconciliation_kind,
    }
}

fn signing_request(
    row: &OperationRow,
    fields: &Eip1559FieldsV1,
    signing_hash_value: Digest32,
    lease: EvmActuatorLeaseV1,
    attempt: u32,
) -> Result<Eip1559SigningRequestV1> {
    let calldata_digest = keccak256(&fields.calldata);
    let one_shot_attempt_id = domain_digest(
        b"DOM-INTEROP/EVM-ACTUATOR/SIGNING-ATTEMPT/V1\0",
        &[
            &row.operation_id,
            &row.route_id,
            &row.effect_id,
            &lease.fencing_epoch.to_be_bytes(),
            &attempt.to_be_bytes(),
            &signing_hash_value,
        ],
    );
    validate_id(one_shot_attempt_id)?;
    Ok(Eip1559SigningRequestV1 {
        operation_id: row.operation_id,
        operation_kind: row.kind,
        signer_role: row.signer_role,
        route_id: row.route_id,
        effect_id: row.effect_id,
        semantic_digest: row.semantic_digest,
        registry_digest: row.registry_digest,
        profile_digest: row.profile_digest,
        asset_binding_digest: row.asset_digest,
        deployment_digest: row.deployment_digest,
        terms_digest: row.terms_digest,
        lock_id: row.lock_id,
        binding: row.binding,
        beneficiary: row.beneficiary,
        funder: row.funder,
        account: row.account,
        chain_id: fields.chain_id,
        nonce: fields.nonce,
        to: fields.to,
        value: fields.value,
        calldata_digest,
        gas_limit: fields.gas_limit,
        fees: fields.fees,
        signing_hash: signing_hash_value,
        fencing_epoch: lease.fencing_epoch,
        attempt,
        one_shot_attempt_id,
    })
}

struct SignedAttemptMaterialV1<'a> {
    operation_id: Digest32,
    attempt: u32,
    stage: EvmTxStageV1,
    fees: EvmFeesV1,
    signing_hash: Digest32,
    raw: &'a [u8],
    transaction_hash: Digest32,
    signature: crate::model::Eip1559SignatureV1,
}

fn insert_signed_attempt(
    transaction: &Transaction<'_>,
    material: SignedAttemptMaterialV1<'_>,
) -> Result<()> {
    let SignedAttemptMaterialV1 {
        operation_id,
        attempt,
        stage,
        fees,
        signing_hash,
        raw,
        transaction_hash,
        signature,
    } = material;
    if raw.is_empty()
        || raw.len() > MAX_RAW_TRANSACTION_BYTES_V1
        || raw.first() != Some(&0x02)
        || keccak256(raw) != transaction_hash
    {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    transaction.execute(
        "INSERT INTO evm_attempts
         (operation_id,attempt,stage_tag,max_fee_be,max_priority_fee_be,
          signing_hash,raw_transaction,transaction_hash,y_parity,signature_r,signature_s,
          send_attempted_at_be,evidence_digest,replaced_by)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,NULL,NULL)",
        params![
            operation_id.as_slice(),
            i64::from(attempt),
            stage.tag(),
            fees.max_fee_per_gas.to_be_bytes().as_slice(),
            fees.max_priority_fee_per_gas.to_be_bytes().as_slice(),
            signing_hash.as_slice(),
            raw,
            transaction_hash.as_slice(),
            i64::from(signature.y_parity),
            signature.r.as_slice(),
            signature.s.as_slice(),
        ],
    )?;
    Ok(())
}

fn load_attempt_payload(
    transaction: &Transaction<'_>,
    operation_id: Digest32,
    attempt: u32,
) -> Result<(Zeroizing<Vec<u8>>, Digest32, EvmTxStageV1)> {
    let row = transaction
        .query_row(
            "SELECT raw_transaction,transaction_hash,stage_tag FROM evm_attempts
             WHERE operation_id=?1 AND attempt=?2",
            params![operation_id.as_slice(), i64::from(attempt)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(EvmActuatorErrorV1::CorruptState)?;
    Ok((
        Zeroizing::new(row.0),
        blob32(row.1)?,
        EvmTxStageV1::from_tag(row.2)?,
    ))
}

fn require_current_operation(
    row: &OperationRow,
    lease: EvmActuatorLeaseV1,
    expected_revision: u64,
    allowed: &[EvmTxStageV1],
) -> Result<()> {
    if row.authority_id != lease.authority_id || row.account != lease.account {
        return Err(EvmActuatorErrorV1::InvalidScope);
    }
    if row.fencing_epoch != lease.fencing_epoch {
        return Err(EvmActuatorErrorV1::ReconciliationRequired);
    }
    if row.revision != expected_revision {
        return Err(EvmActuatorErrorV1::RevisionConflict);
    }
    if !allowed.contains(&row.stage) {
        return Err(EvmActuatorErrorV1::InvalidState);
    }
    Ok(())
}

fn validate_replacement(row: &OperationRow, replacement: EvmFeesV1) -> Result<()> {
    if replacement.max_fee_per_gas < row.fields.fees.max_fee_per_gas
        || replacement.max_priority_fee_per_gas < row.fields.fees.max_priority_fee_per_gas
        || (replacement.max_fee_per_gas == row.fields.fees.max_fee_per_gas
            && replacement.max_priority_fee_per_gas == row.fields.fees.max_priority_fee_per_gas)
        || replacement.max_fee_per_gas > row.max_fee_cap
        || replacement.max_priority_fee_per_gas > row.max_priority_fee_cap
        || replacement.max_priority_fee_per_gas > replacement.max_fee_per_gas
    {
        return Err(EvmActuatorErrorV1::InvalidReplacement);
    }
    Ok(())
}

fn validate_rpc_transaction(row: &OperationRow, observed: &RpcTransactionV1) -> Result<()> {
    if Some(observed.transaction_hash) != row.transaction_hash
        || observed.chain_id != row.fields.chain_id
        || observed.from != row.account
        || observed.to != row.fields.to
        || observed.nonce != row.fields.nonce
        || observed.value != row.fields.value
        || observed.gas_limit != row.fields.gas_limit
        || observed.fees != row.fields.fees
        || observed.input.as_slice() != row.fields.calldata.as_slice()
    {
        return Err(EvmActuatorErrorV1::ObservationMismatch);
    }
    Ok(())
}

struct ClassifiedObservation {
    stage: EvmTxStageV1,
    ambiguous: bool,
    success: Option<bool>,
    final_block_number: Option<u64>,
    final_block_hash: Option<Digest32>,
    final_evidence: Option<Digest32>,
    terminal_event_digest: Option<Digest32>,
    invalidation_evidence: Option<Digest32>,
}

fn classify_observation(
    row: &OperationRow,
    lookup: &RpcTransactionLookupV1,
    receipt_lookup: Option<&RpcReceiptLookupV1>,
) -> Result<ClassifiedObservation> {
    let Some(observed) = lookup.transaction.as_ref() else {
        return if matches!(
            row.stage,
            EvmTxStageV1::Final | EvmTxStageV1::FinalityInvalidated
        ) {
            Ok(invalidated_observation(row, lookup.evidence_digest))
        } else {
            Ok(ClassifiedObservation {
                stage: EvmTxStageV1::SendAttempted,
                ambiguous: true,
                success: None,
                final_block_number: None,
                final_block_hash: None,
                final_evidence: None,
                terminal_event_digest: None,
                invalidation_evidence: None,
            })
        };
    };
    validate_rpc_transaction(row, observed)?;
    let Some(receipt_lookup) = receipt_lookup else {
        return Ok(nonfinal_observation(row, lookup.evidence_digest));
    };
    if receipt_lookup.evidence_digest == ZERO_DIGEST {
        return Err(EvmActuatorErrorV1::ObservationMismatch);
    }
    match receipt_lookup.receipt.as_ref() {
        None => Ok(nonfinal_observation(row, receipt_lookup.evidence_digest)),
        Some(receipt) => {
            if receipt.transaction_hash != observed.transaction_hash
                || receipt.chain_id != row.fields.chain_id
                || receipt.genesis_hash != row.genesis_hash
                || receipt.block_number == 0
                || receipt.block_hash == ZERO_DIGEST
                || receipt.evidence_digest == ZERO_DIGEST
            {
                return Err(EvmActuatorErrorV1::ObservationMismatch);
            }
            if receipt.finalized {
                let terminal_event_digest = if receipt.success {
                    validate_terminal_receipt(row, receipt)?
                } else {
                    if !receipt.logs.is_empty() {
                        return Err(EvmActuatorErrorV1::TerminalEventMismatch);
                    }
                    None
                };
                Ok(ClassifiedObservation {
                    stage: EvmTxStageV1::Final,
                    ambiguous: false,
                    success: Some(receipt.success),
                    final_block_number: Some(receipt.block_number),
                    final_block_hash: Some(receipt.block_hash),
                    final_evidence: Some(receipt.evidence_digest),
                    terminal_event_digest,
                    invalidation_evidence: None,
                })
            } else {
                Ok(nonfinal_observation(row, receipt.evidence_digest))
            }
        }
    }
}

fn nonfinal_observation(row: &OperationRow, evidence: Digest32) -> ClassifiedObservation {
    if matches!(
        row.stage,
        EvmTxStageV1::Final | EvmTxStageV1::FinalityInvalidated
    ) {
        invalidated_observation(row, evidence)
    } else {
        ClassifiedObservation {
            stage: EvmTxStageV1::Observed,
            ambiguous: false,
            success: None,
            final_block_number: None,
            final_block_hash: None,
            final_evidence: None,
            terminal_event_digest: None,
            invalidation_evidence: None,
        }
    }
}

fn invalidated_observation(row: &OperationRow, evidence: Digest32) -> ClassifiedObservation {
    ClassifiedObservation {
        stage: EvmTxStageV1::FinalityInvalidated,
        ambiguous: true,
        success: row.execution_success,
        final_block_number: row.final_block_number,
        final_block_hash: row.final_block_hash,
        final_evidence: row.final_evidence,
        terminal_event_digest: row.terminal_event_digest,
        invalidation_evidence: Some(domain_digest(
            b"DOM-INTEROP/EVM-ACTUATOR/FINALITY-INVALIDATED/V1\0",
            &[
                &row.operation_id,
                &row.transaction_hash.unwrap_or(ZERO_DIGEST),
                &row.final_block_hash.unwrap_or(ZERO_DIGEST),
                &evidence,
            ],
        )),
    }
}

fn validate_terminal_receipt(
    row: &OperationRow,
    receipt: &RpcReceiptV1,
) -> Result<Option<Digest32>> {
    let expected_topic = match row.kind {
        EvmOperationKindV1::Open => return Ok(None),
        EvmOperationKindV1::Claim => event_topic0(SIG_CLAIMED),
        EvmOperationKindV1::Refund => event_topic0(SIG_REFUNDED),
    };
    if receipt.logs.len() > adapter_evm::rpc::MAX_LOGS_PER_RECEIPT {
        return Err(EvmActuatorErrorV1::TerminalEventMismatch);
    }
    let mut matched = None;
    for log in &receipt.logs {
        validate_receipt_log_metadata(receipt, log)?;
        if log.address != row.fields.to || log.topics.first() != Some(&expected_topic) {
            continue;
        }
        if matched.is_some()
            || log.removed
            || log.topics.len() != 4
            || log.topics[1] != row.lock_id
            || log.topics[2] != row.binding
            || log.data.len() != 32
        {
            return Err(EvmActuatorErrorV1::TerminalEventMismatch);
        }
        let account = decode_address(&log.topics[3])
            .map_err(|_| EvmActuatorErrorV1::TerminalEventMismatch)?;
        let payload_matches = match row.kind {
            EvmOperationKindV1::Claim => {
                account == row.beneficiary
                    && row.fields.calldata.len() == CLAIM_CALLDATA_LEN
                    && log.data.as_slice() == &row.fields.calldata[36..68]
            }
            EvmOperationKindV1::Refund => {
                account == row.funder && log.data.as_slice() == row.lock_amount
            }
            EvmOperationKindV1::Open => false,
        };
        if !payload_matches {
            return Err(EvmActuatorErrorV1::TerminalEventMismatch);
        }
        matched = Some(terminal_log_digest(log));
    }
    matched
        .ok_or(EvmActuatorErrorV1::TerminalEventMismatch)
        .map(Some)
}

fn validate_receipt_log_metadata(receipt: &RpcReceiptV1, log: &RpcLogV1) -> Result<()> {
    if log.block_number != receipt.block_number
        || log.block_hash != receipt.block_hash
        || log.transaction_hash != receipt.transaction_hash
        || log.block_hash == ZERO_DIGEST
        || log.transaction_hash == ZERO_DIGEST
        || log.removed
        || log.topics.len() > adapter_evm::abi::MAX_LOG_TOPICS
        || log.data.len() > adapter_evm::abi::MAX_LOG_DATA_BYTES
    {
        return Err(EvmActuatorErrorV1::TerminalEventMismatch);
    }
    Ok(())
}

fn terminal_log_digest(log: &RpcLogV1) -> Digest32 {
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.extend_from_slice(&log.address);
    encoded.extend_from_slice(&(log.topics.len() as u64).to_be_bytes());
    for topic in &log.topics {
        encoded.extend_from_slice(topic);
    }
    encoded.extend_from_slice(&(log.data.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&log.data);
    encoded.extend_from_slice(&log.block_number.to_be_bytes());
    encoded.extend_from_slice(&log.block_hash);
    encoded.extend_from_slice(&log.transaction_hash);
    encoded.extend_from_slice(&log.log_index.to_be_bytes());
    encoded.push(u8::from(log.removed));
    domain_digest(b"DOM-INTEROP/EVM-ACTUATOR/TERMINAL-LOG/V1\0", &[&encoded])
}

fn observation_digest(
    transaction_hash: Digest32,
    lookup: &RpcTransactionLookupV1,
    receipt: Option<&RpcReceiptLookupV1>,
) -> Digest32 {
    let receipt_digest = receipt
        .map(|value| value.evidence_digest)
        .unwrap_or(ZERO_DIGEST);
    domain_digest(
        b"DOM-INTEROP/EVM-ACTUATOR/OBSERVATION/V1\0",
        &[&transaction_hash, &lookup.evidence_digest, &receipt_digest],
    )
}

fn load_nonce_snapshot(
    transaction: &Transaction<'_>,
    authority_id: Digest32,
) -> Result<Option<NonceSnapshotV1>> {
    let row = transaction
        .query_row(
            "SELECT observation_revision_be,allocation_revision_be,pending_nonce_be,
                    evidence_digest,observed_at_be,valid_until_be
             FROM evm_nonce_snapshots WHERE authority_id=?1",
            params![authority_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(observation_revision, allocation_revision, pending_nonce, evidence, observed, valid)| {
            let evidence = blob32(evidence)?;
            if evidence == ZERO_DIGEST {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
            let observed_at_unix_ms = blob_u64(observed)?;
            let valid_until_unix_ms = blob_u64(valid)?;
            if observed_at_unix_ms == 0 || valid_until_unix_ms <= observed_at_unix_ms {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
            Ok(NonceSnapshotV1 {
                observation_revision: blob_u64(observation_revision)?,
                allocation_revision: blob_u64(allocation_revision)?,
                pending_nonce: blob_u64(pending_nonce)?,
                evidence_digest: evidence,
                observed_at_unix_ms,
                valid_until_unix_ms,
            })
        },
    )
    .transpose()
}

fn require_allowance_if_needed(
    transaction: &Transaction<'_>,
    lease: EvmActuatorLeaseV1,
    scope: &OperationPreparationV1<'_>,
    now_unix_ms: u64,
) -> Result<(Option<EvmAddressV1>, Option<u64>)> {
    if scope.kind != EvmOperationKindV1::Open {
        return Ok((None, None));
    }
    let (token, _) = match scope.lock.deployment.asset_binding().representation {
        AssetRepresentationV1::Native => return Ok((None, None)),
        AssetRepresentationV1::EvmErc20 {
            token,
            token_code_hash,
        } => (token, token_code_hash),
    };
    let spender = scope.lock.deployment.adapter_config().contract;
    let row = transaction
        .query_row(
            "SELECT revision_be,amount,block_number_be,registry_digest,profile_digest,
                    asset_digest,valid_until_be
             FROM evm_allowances WHERE authority_id=?1 AND token=?2 AND spender=?3",
            params![
                lease.authority_id.as_slice(),
                token.as_slice(),
                spender.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(EvmActuatorErrorV1::AllowanceRequired)?;
    let (revision, amount, block_number, registry, profile, asset, valid_until) = row;
    let revision = blob_u64(revision)?;
    let amount = blob32(amount)?;
    let block_number = blob_u64(block_number)?;
    if blob32(registry)? != scope.lock.deployment.registry_digest()
        || blob32(profile)? != scope.lock.deployment.profile_digest()
        || blob32(asset)? != scope.lock.deployment.asset_binding_digest()
        || blob_u64(valid_until)? < now_unix_ms
    {
        return Err(EvmActuatorErrorV1::StaleObservation);
    }
    let block_number_bytes = block_number.to_be_bytes();
    let query_params = params![
        lease.authority_id.as_slice(),
        token.as_slice(),
        block_number_bytes.as_slice()
    ];
    let encumbrance_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM evm_operations
         WHERE authority_id=?1 AND erc20_token=?2
           AND (final_block_number_be IS NULL OR final_block_number_be > ?3)",
        query_params,
        |record| record.get(0),
    )?;
    if !(0..=4_096).contains(&encumbrance_count) {
        return Err(EvmActuatorErrorV1::BoundExceeded);
    }
    let mut statement = transaction.prepare(
        "SELECT lock_amount FROM evm_operations
         WHERE authority_id=?1 AND erc20_token=?2
           AND (final_block_number_be IS NULL OR final_block_number_be > ?3)
         ORDER BY nonce_be ASC LIMIT 4096",
    )?;
    let rows = statement.query_map(
        params![
            lease.authority_id.as_slice(),
            token.as_slice(),
            block_number.to_be_bytes().as_slice()
        ],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let mut encumbered = [0; 32];
    for value in rows {
        encumbered = add_word(encumbered, blob32(value?)?)?;
    }
    let needed = add_word(encumbered, scope.lock.amount)?;
    if compare_word(needed, amount).is_gt() {
        return Err(EvmActuatorErrorV1::AllowanceRequired);
    }
    Ok((Some(token), Some(revision)))
}

fn validate_deployment_lease(
    deployment: &ResolvedEvmDeploymentV1,
    lease: EvmActuatorLeaseV1,
) -> Result<()> {
    let config = deployment.adapter_config();
    let is_bound_account = lease.account == config.funder || lease.account == config.beneficiary;
    if config.chain_id != lease.chain_id
        || !is_bound_account
        || authority_id(config.chain_id, lease.account) != lease.authority_id
        || deployment.registry_digest() == ZERO_DIGEST
        || deployment.profile_digest() == ZERO_DIGEST
        || deployment.asset_binding_digest() == ZERO_DIGEST
    {
        return Err(EvmActuatorErrorV1::InvalidScope);
    }
    Ok(())
}

fn validate_terminal_lease(
    lock: &ValidatedEvmLockV1,
    role: EvmSignerRoleV1,
    lease: EvmActuatorLeaseV1,
) -> Result<()> {
    validate_deployment_lease(&lock.deployment, lease)?;
    let expected = match role {
        EvmSignerRoleV1::Funder => lock.funder,
        EvmSignerRoleV1::Beneficiary => lock.beneficiary,
    };
    if lease.account != expected || authority_id(lease.chain_id, expected) != lease.authority_id {
        return Err(EvmActuatorErrorV1::InvalidScope);
    }
    Ok(())
}

fn validate_operation_scope_lease(
    scope: &OperationPreparationV1<'_>,
    lease: EvmActuatorLeaseV1,
) -> Result<()> {
    validate_terminal_lease(scope.lock, scope.signer_role, lease)?;
    let config = scope.lock.deployment.adapter_config();
    let expected_role = match scope.kind {
        EvmOperationKindV1::Open | EvmOperationKindV1::Refund => EvmSignerRoleV1::Funder,
        EvmOperationKindV1::Claim => EvmSignerRoleV1::Beneficiary,
    };
    if scope.signer_role != expected_role
        || config.contract == [0; 20]
        || config.terms_hash == ZERO_DIGEST
        || scope.calldata.is_empty()
        || scope.calldata.len() > adapter_evm::abi::MAX_CALLDATA_BYTES
        || (scope.kind == EvmOperationKindV1::Open && scope.refund_authorization.is_some())
        || (scope.kind == EvmOperationKindV1::Claim && scope.refund_authorization.is_some())
        || (scope.kind == EvmOperationKindV1::Refund && scope.refund_authorization.is_none())
    {
        return Err(EvmActuatorErrorV1::InvalidScope);
    }
    Ok(())
}

fn validate_fees(deployment: deployment_registry::EvmDeploymentV1, fees: EvmFeesV1) -> Result<()> {
    if fees.max_fee_per_gas > deployment.max_fee_per_gas
        || fees.max_priority_fee_per_gas > deployment.max_priority_fee_per_gas
        || fees.max_priority_fee_per_gas > fees.max_fee_per_gas
    {
        return Err(EvmActuatorErrorV1::InvalidFeePolicy);
    }
    Ok(())
}

fn rpc_preflight<R: EvmRpcV1>(deployment: &ResolvedEvmDeploymentV1, rpc: &mut R) -> Result<()> {
    let config = deployment.adapter_config();
    rpc_row_preflight(
        config.chain_id,
        deployment.deployment().genesis_hash,
        config.contract,
        config.expected_code_hash,
        rpc,
    )
}

fn rpc_row_preflight<R: EvmRpcV1>(
    chain_id: u64,
    genesis_hash: Digest32,
    destination: EvmAddressV1,
    destination_code_hash: Digest32,
    rpc: &mut R,
) -> Result<()> {
    if rpc.chain_id()? != chain_id || rpc.genesis_hash()? != genesis_hash {
        return Err(EvmActuatorErrorV1::RpcScopeMismatch);
    }
    let (code_hash, evidence_digest) = rpc.finalized_code_hash(destination)?;
    if code_hash != destination_code_hash || evidence_digest == ZERO_DIGEST {
        return Err(EvmActuatorErrorV1::RpcScopeMismatch);
    }
    Ok(())
}

fn operation_request_digest(
    operation_id: Digest32,
    scope: &OperationPreparationV1<'_>,
    fees: EvmFeesV1,
) -> Result<Digest32> {
    if scope.calldata.len() > adapter_evm::abi::MAX_CALLDATA_BYTES {
        return Err(EvmActuatorErrorV1::BoundExceeded);
    }
    let config = scope.lock.deployment.adapter_config();
    let deployment = scope.lock.deployment.deployment();
    let refund = scope.refund_authorization;
    Ok(domain_digest(
        b"DOM-INTEROP/EVM-ACTUATOR/OPERATION-REQUEST/V2\0",
        &[
            &operation_id,
            &[u8::try_from(scope.kind.tag()).map_err(|_| EvmActuatorErrorV1::InvalidScope)?],
            &[u8::try_from(scope.signer_role.tag())
                .map_err(|_| EvmActuatorErrorV1::InvalidScope)?],
            &scope.route_id,
            &scope.effect_id,
            &scope.semantic_digest,
            &scope.lock.deployment.registry_digest(),
            &scope.lock.deployment.profile_digest(),
            &scope.lock.deployment.asset_binding_digest(),
            &deployment.deployment_digest,
            &config.expected_code_hash,
            &deployment.genesis_hash,
            &config.chain_id.to_be_bytes(),
            &config.contract,
            &config.terms_hash,
            &scope.lock.lock_id,
            &scope.lock.binding,
            &scope.lock.beneficiary,
            &scope.lock.funder,
            &scope.lock.adaptor_address,
            &scope.lock.deadline.to_be_bytes(),
            &scope.lock.amount,
            &scope.value,
            &config.gas_limit_hint.to_be_bytes(),
            scope.calldata,
            &refund
                .map(|value| value.block_number)
                .unwrap_or(0)
                .to_be_bytes(),
            &refund.map(|value| value.block_hash).unwrap_or(ZERO_DIGEST),
            &refund
                .map(|value| value.timestamp)
                .unwrap_or(0)
                .to_be_bytes(),
            &refund
                .map(|value| value.evidence_digest)
                .unwrap_or(ZERO_DIGEST),
            &fees.max_fee_per_gas.to_be_bytes(),
            &fees.max_priority_fee_per_gas.to_be_bytes(),
        ],
    ))
}

fn operation_intent_digest(
    operation_id: Digest32,
    scope: &OperationPreparationV1<'_>,
    fees: EvmFeesV1,
) -> Result<Digest32> {
    if scope.calldata.len() > adapter_evm::abi::MAX_CALLDATA_BYTES {
        return Err(EvmActuatorErrorV1::BoundExceeded);
    }
    let config = scope.lock.deployment.adapter_config();
    let deployment = scope.lock.deployment.deployment();
    Ok(domain_digest(
        b"DOM-INTEROP/EVM-ACTUATOR/OPERATION-INTENT/V2\0",
        &[
            &operation_id,
            &[u8::try_from(scope.kind.tag()).map_err(|_| EvmActuatorErrorV1::InvalidScope)?],
            &[u8::try_from(scope.signer_role.tag())
                .map_err(|_| EvmActuatorErrorV1::InvalidScope)?],
            &scope.route_id,
            &scope.effect_id,
            &scope.semantic_digest,
            &scope.lock.deployment.registry_digest(),
            &scope.lock.deployment.profile_digest(),
            &scope.lock.deployment.asset_binding_digest(),
            &deployment.deployment_digest,
            &config.expected_code_hash,
            &deployment.genesis_hash,
            &config.chain_id.to_be_bytes(),
            &config.contract,
            &config.terms_hash,
            &scope.lock.lock_id,
            &scope.lock.binding,
            &scope.lock.beneficiary,
            &scope.lock.funder,
            &scope.lock.adaptor_address,
            &scope.lock.deadline.to_be_bytes(),
            &scope.lock.amount,
            &scope.value,
            &config.gas_limit_hint.to_be_bytes(),
            scope.calldata,
            &fees.max_fee_per_gas.to_be_bytes(),
            &fees.max_priority_fee_per_gas.to_be_bytes(),
        ],
    ))
}

fn validate_refund_time(
    expected_chain_id: u64,
    expected_genesis_hash: Digest32,
    deadline: u64,
    evidence: RpcFinalizedTimeV1,
) -> Result<RefundAuthorizationV1> {
    if expected_chain_id == 0
        || expected_genesis_hash == ZERO_DIGEST
        || evidence.chain_id != expected_chain_id
        || evidence.genesis_hash != expected_genesis_hash
    {
        return Err(EvmActuatorErrorV1::RpcScopeMismatch);
    }
    if deadline == 0
        || evidence.block_number == 0
        || evidence.block_hash == ZERO_DIGEST
        || evidence.timestamp == 0
        || evidence.evidence_digest == ZERO_DIGEST
    {
        return Err(EvmActuatorErrorV1::ObservationMismatch);
    }
    if evidence.timestamp < deadline {
        return Err(EvmActuatorErrorV1::RefundDeadlineNotReached);
    }
    Ok(RefundAuthorizationV1 {
        block_number: evidence.block_number,
        block_hash: evidence.block_hash,
        timestamp: evidence.timestamp,
        evidence_digest: evidence.evidence_digest,
    })
}

fn authority_id(chain_id: u64, account: EvmAddressV1) -> Digest32 {
    domain_digest(
        b"DOM-INTEROP/EVM-ACTUATOR/AUTHORITY/V1\0",
        &[&chain_id.to_be_bytes(), &account],
    )
}

fn existing_mutation(
    transaction: &Transaction<'_>,
    authority_id: Digest32,
    mutation_id: Digest32,
    mutation_digest: Digest32,
) -> Result<Option<MutationStatusV1>> {
    Ok(
        existing_mutation_revision(transaction, authority_id, mutation_id, mutation_digest)?
            .map(|_| MutationStatusV1::DuplicateSameBytes),
    )
}

fn existing_mutation_revision(
    transaction: &Transaction<'_>,
    authority_id: Digest32,
    mutation_id: Digest32,
    mutation_digest: Digest32,
) -> Result<Option<u64>> {
    let stored: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT mutation_digest,resulting_revision_be FROM evm_mutations
             WHERE authority_id=?1 AND mutation_id=?2",
            params![authority_id.as_slice(), mutation_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match stored {
        None => Ok(None),
        Some((digest, revision)) => {
            if blob32(digest)? == mutation_digest {
                Ok(Some(blob_u64(revision)?))
            } else {
                Err(EvmActuatorErrorV1::IdempotencyConflict)
            }
        }
    }
}

fn insert_mutation(
    transaction: &Transaction<'_>,
    authority_id: Digest32,
    mutation_id: Digest32,
    mutation_digest: Digest32,
    operation_id: Option<Digest32>,
    resulting_revision: u64,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO evm_mutations
         (authority_id,mutation_id,mutation_digest,operation_id,resulting_revision_be)
         VALUES (?1,?2,?3,?4,?5)",
        params![
            authority_id.as_slice(),
            mutation_id.as_slice(),
            mutation_digest.as_slice(),
            operation_id.map(|value| value.to_vec()),
            resulting_revision.to_be_bytes().as_slice(),
        ],
    )?;
    Ok(())
}

fn require_lease_read_only(
    transaction: &Transaction<'_>,
    lease: EvmActuatorLeaseV1,
    now_unix_ms: u64,
) -> Result<()> {
    if now_unix_ms == 0 || now_unix_ms > lease.lease_until_unix_ms {
        return Err(EvmActuatorErrorV1::StaleFencing);
    }
    let row = transaction
        .query_row(
            "SELECT chain_id_be,account,owner_id,fencing_epoch_be,lease_until_be,
                    clock_high_water_be
             FROM evm_leases WHERE authority_id=?1",
            params![lease.authority_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(EvmActuatorErrorV1::StaleFencing)?;
    if blob_u64(row.0)? != lease.chain_id
        || blob20(row.1)? != lease.account
        || blob32(row.2)? != lease.owner_id
        || blob_u64(row.3)? != lease.fencing_epoch
        || blob_u64(row.4)? != lease.lease_until_unix_ms
    {
        return Err(EvmActuatorErrorV1::StaleFencing);
    }
    if now_unix_ms < blob_u64(row.5)? {
        return Err(EvmActuatorErrorV1::InvalidTime);
    }
    Ok(())
}

fn validate_lease(
    transaction: &Transaction<'_>,
    lease: EvmActuatorLeaseV1,
    now_unix_ms: u64,
) -> Result<()> {
    require_lease_read_only(transaction, lease, now_unix_ms)?;
    let changed = transaction.execute(
        "UPDATE evm_leases SET clock_high_water_be=?2
         WHERE authority_id=?1 AND owner_id=?3 AND fencing_epoch_be=?4
           AND clock_high_water_be<=?2",
        params![
            lease.authority_id.as_slice(),
            now_unix_ms.to_be_bytes().as_slice(),
            lease.owner_id.as_slice(),
            lease.fencing_epoch.to_be_bytes().as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(EvmActuatorErrorV1::StaleFencing);
    }
    Ok(())
}

fn require_post_rpc_time(initial_now_unix_ms: u64, post_rpc_now_unix_ms: u64) -> Result<()> {
    if post_rpc_now_unix_ms < initial_now_unix_ms {
        return Err(EvmActuatorErrorV1::InvalidTime);
    }
    Ok(())
}

fn validate_time_window(now: u64, duration: u64, maximum: u64) -> Result<()> {
    if now == 0 || duration == 0 || duration > maximum || now.checked_add(duration).is_none() {
        return Err(EvmActuatorErrorV1::InvalidTime);
    }
    Ok(())
}

fn validate_id(value: Digest32) -> Result<()> {
    if value == ZERO_DIGEST {
        return Err(EvmActuatorErrorV1::InvalidScope);
    }
    Ok(())
}

fn compare_word(left: [u8; 32], right: [u8; 32]) -> core::cmp::Ordering {
    left.cmp(&right)
}

fn add_word(left: [u8; 32], right: [u8; 32]) -> Result<[u8; 32]> {
    let mut output = [0; 32];
    let mut carry = 0u16;
    for index in (0..32).rev() {
        let value = u16::from(left[index]) + u16::from(right[index]) + carry;
        output[index] = (value & 0xff) as u8;
        carry = value >> 8;
    }
    if carry != 0 {
        return Err(EvmActuatorErrorV1::BoundExceeded);
    }
    Ok(output)
}

fn blob32(value: Vec<u8>) -> Result<Digest32> {
    value
        .try_into()
        .map_err(|_| EvmActuatorErrorV1::CorruptState)
}

fn blob20(value: Vec<u8>) -> Result<EvmAddressV1> {
    value
        .try_into()
        .map_err(|_| EvmActuatorErrorV1::CorruptState)
}

fn blob_u64(value: Vec<u8>) -> Result<u64> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    Ok(u64::from_be_bytes(bytes))
}

fn blob_u128(value: Vec<u8>) -> Result<u128> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    Ok(u128::from_be_bytes(bytes))
}

type SchemaObjectV1 = (String, String, String, String);

fn schema_objects(connection: &Connection) -> Result<BTreeSet<SchemaObjectV1>> {
    const MAX_SCHEMA_OBJECTS: i64 = 16;
    const MAX_SCHEMA_SQL_BYTES: i64 = 256 * 1024;
    let (count, maximum, total): (i64, Option<i64>, Option<i64>) = connection.query_row(
        "SELECT COUNT(*), MAX(length(sql)), SUM(length(sql))
         FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if !(0..=MAX_SCHEMA_OBJECTS).contains(&count)
        || maximum.is_some_and(|value| !(0..=MAX_SCHEMA_SQL_BYTES).contains(&value))
        || total.is_some_and(|value| !(0..=MAX_SCHEMA_SQL_BYTES).contains(&value))
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let mut statement = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut objects = BTreeSet::new();
    for row in rows {
        if !objects.insert(row?) {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
    }
    if i64::try_from(objects.len()).map_err(|_| EvmActuatorErrorV1::CorruptState)? != count {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    Ok(objects)
}

fn reference_schema_objects() -> Result<BTreeSet<SchemaObjectV1>> {
    let reference = Connection::open_in_memory()?;
    DurableEvmActuatorV1::create_schema(&reference)?;
    schema_objects(&reference)
}

fn configure_connection(connection: &Connection, install_wal: bool) -> Result<()> {
    connection.busy_timeout(Duration::from_millis(MAX_BUSY_TIMEOUT_MS))?;
    if !connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?
        || !connection.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if install_wal {
        if !mode.eq_ignore_ascii_case("wal") {
            let installed: String =
                connection
                    .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
            if !installed.eq_ignore_ascii_case("wal") {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
        }
    } else if !mode.eq_ignore_ascii_case("wal") {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA read_uncommitted = OFF;
         PRAGMA secure_delete = ON;
         PRAGMA synchronous = FULL;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(())
}

fn preflight_resumable_creation_state(
    path: &Path,
    database_authority: &File,
) -> Result<ResumableCreationStateV1> {
    validate_open_file_identity(database_authority, path)?;
    if database_authority
        .metadata()
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?
        .len()
        == 0
    {
        return Ok(ResumableCreationStateV1::PristineSqlite);
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    connection
        .busy_timeout(Duration::from_millis(MAX_BUSY_TIMEOUT_MS))
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .and_then(|_| connection.pragma_update(None, "trusted_schema", "OFF"))
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    if !connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?
        || !connection
            .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
            .map_err(|_| EvmActuatorErrorV1::CorruptState)?
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let quick: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    let foreign_key_violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    let objects = schema_objects(&connection).map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    if quick != "ok" || foreign_key_violations != 0 {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    if version == 0 {
        return if application_id == 0
            && objects.is_empty()
            && (journal_mode.eq_ignore_ascii_case("delete")
                || journal_mode.eq_ignore_ascii_case("wal"))
        {
            Ok(ResumableCreationStateV1::PristineSqlite)
        } else {
            Err(EvmActuatorErrorV1::CorruptState)
        };
    }
    if version != SCHEMA_VERSION
        || application_id != APPLICATION_ID
        || !journal_mode.eq_ignore_ascii_case("wal")
        || objects != reference_schema_objects()?
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    validate_open_file_identity(database_authority, path)?;
    Ok(ResumableCreationStateV1::InitializedExact)
}

fn validate_pristine_initialized_store(connection: &Connection) -> Result<()> {
    validate_backend_and_schema(connection)?;
    let economic_rows: i64 = connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM evm_leases) +
             (SELECT COUNT(*) FROM evm_nonce_snapshots) +
             (SELECT COUNT(*) FROM evm_allowances) +
             (SELECT COUNT(*) FROM evm_operations) +
             (SELECT COUNT(*) FROM evm_attempts) +
             (SELECT COUNT(*) FROM evm_mutations)",
        [],
        |row| row.get(0),
    )?;
    if economic_rows != 0 {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    Ok(())
}

fn validate_backend_and_schema(connection: &Connection) -> Result<()> {
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.pragma_query_value(None, "read_uncommitted", |row| row.get(0))?;
    let secure_delete: i64 =
        connection.pragma_query_value(None, "secure_delete", |row| row.get(0))?;
    let temp_store: i64 = connection.pragma_query_value(None, "temp_store", |row| row.get(0))?;
    let locking_mode: String =
        connection.pragma_query_value(None, "locking_mode", |row| row.get(0))?;
    let auto_vacuum: i64 = connection.pragma_query_value(None, "auto_vacuum", |row| row.get(0))?;
    let user_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    let foreign_key_violations: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    let schema_row: Option<(i64, i64)> = connection
        .query_row("SELECT singleton,version FROM evm_schema", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    let schema_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM evm_schema", [], |row| row.get(0))
        .map_err(|_| EvmActuatorErrorV1::CorruptState)?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || read_uncommitted != 0
        || secure_delete != 1
        || temp_store != 2
        || !locking_mode.eq_ignore_ascii_case("normal")
        || auto_vacuum != 0
        || user_version != SCHEMA_VERSION
        || application_id != APPLICATION_ID
        || quick != "ok"
        || foreign_key_violations != 0
        || schema_count != 1
        || schema_row != Some((1, SCHEMA_VERSION))
        || !connection.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?
        || schema_objects(connection)? != reference_schema_objects()?
    {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    Ok(())
}

struct RetainedLeaseAuditRowV1 {
    authority_id: Vec<u8>,
    chain_id: Vec<u8>,
    account: Vec<u8>,
    owner_id: Vec<u8>,
    fencing_epoch: Vec<u8>,
    lease_until: Vec<u8>,
    clock_high_water: Vec<u8>,
}

struct RetainedAllowanceAuditRowV1 {
    authority_id: Vec<u8>,
    token: Vec<u8>,
    spender: Vec<u8>,
    revision: Vec<u8>,
    block_hash: Vec<u8>,
    evidence_digest: Vec<u8>,
    registry_digest: Vec<u8>,
    profile_digest: Vec<u8>,
    asset_digest: Vec<u8>,
    observed_at: Vec<u8>,
    valid_until: Vec<u8>,
}

struct RetainedMutationAuditRowV1 {
    authority_id: Vec<u8>,
    mutation_id: Vec<u8>,
    mutation_digest: Vec<u8>,
    operation_id: Option<Vec<u8>>,
    resulting_revision: Vec<u8>,
}

fn audit_retained_state_in_transaction(transaction: &Transaction<'_>) -> Result<()> {
    audit_retained_leases(transaction)?;
    audit_retained_nonce_snapshots(transaction)?;
    audit_retained_allowances(transaction)?;
    audit_retained_operations(transaction)?;
    audit_retained_mutations(transaction)
}

fn audit_retained_leases(transaction: &Transaction<'_>) -> Result<()> {
    let mut statement = transaction.prepare(
        "SELECT authority_id,chain_id_be,account,owner_id,fencing_epoch_be,
                lease_until_be,clock_high_water_be
         FROM evm_leases ORDER BY authority_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(RetainedLeaseAuditRowV1 {
            authority_id: row.get(0)?,
            chain_id: row.get(1)?,
            account: row.get(2)?,
            owner_id: row.get(3)?,
            fencing_epoch: row.get(4)?,
            lease_until: row.get(5)?,
            clock_high_water: row.get(6)?,
        })
    })?;
    for retained in rows {
        let retained = retained?;
        let authority = blob32(retained.authority_id)?;
        let chain_id = blob_u64(retained.chain_id)?;
        let account = blob20(retained.account)?;
        let owner_id = blob32(retained.owner_id)?;
        let fencing_epoch = blob_u64(retained.fencing_epoch)?;
        let lease_until = blob_u64(retained.lease_until)?;
        let clock_high_water = blob_u64(retained.clock_high_water)?;
        if authority == ZERO_DIGEST
            || chain_id == 0
            || account == [0; 20]
            || owner_id == ZERO_DIGEST
            || authority != authority_id(chain_id, account)
            || fencing_epoch == 0
            || lease_until == 0
            || clock_high_water == 0
            || clock_high_water > lease_until
        {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
    }
    Ok(())
}

fn audit_retained_nonce_snapshots(transaction: &Transaction<'_>) -> Result<()> {
    let orphaned_operations: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM evm_operations AS operation
         LEFT JOIN evm_nonce_snapshots AS snapshot
           ON snapshot.authority_id=operation.authority_id
         WHERE snapshot.authority_id IS NULL",
        [],
        |row| row.get(0),
    )?;
    if orphaned_operations != 0 {
        return Err(EvmActuatorErrorV1::CorruptState);
    }
    let authority_ids = {
        let mut statement = transaction
            .prepare("SELECT authority_id FROM evm_nonce_snapshots ORDER BY authority_id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut values = Vec::new();
        for row in rows {
            values.push(blob32(row?)?);
        }
        values
    };
    for authority in authority_ids {
        let snapshot =
            load_nonce_snapshot(transaction, authority)?.ok_or(EvmActuatorErrorV1::CorruptState)?;
        let operation_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM evm_operations WHERE authority_id=?1",
            params![authority.as_slice()],
            |row| row.get(0),
        )?;
        let operation_count =
            u64::try_from(operation_count).map_err(|_| EvmActuatorErrorV1::CorruptState)?;
        if snapshot.observation_revision == 0
            || snapshot.allocation_revision != operation_count
            || snapshot.evidence_digest == ZERO_DIGEST
        {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
    }
    Ok(())
}

fn audit_retained_allowances(transaction: &Transaction<'_>) -> Result<()> {
    let mut statement = transaction.prepare(
        "SELECT authority_id,token,spender,revision_be,block_hash,evidence_digest,
                registry_digest,profile_digest,asset_digest,observed_at_be,valid_until_be
         FROM evm_allowances ORDER BY authority_id,token,spender",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(RetainedAllowanceAuditRowV1 {
            authority_id: row.get(0)?,
            token: row.get(1)?,
            spender: row.get(2)?,
            revision: row.get(3)?,
            block_hash: row.get(4)?,
            evidence_digest: row.get(5)?,
            registry_digest: row.get(6)?,
            profile_digest: row.get(7)?,
            asset_digest: row.get(8)?,
            observed_at: row.get(9)?,
            valid_until: row.get(10)?,
        })
    })?;
    for retained in rows {
        let retained = retained?;
        let authority_id = blob32(retained.authority_id)?;
        let token = blob20(retained.token)?;
        let spender = blob20(retained.spender)?;
        let revision = blob_u64(retained.revision)?;
        let observed_at = blob_u64(retained.observed_at)?;
        let valid_until = blob_u64(retained.valid_until)?;
        if authority_id == ZERO_DIGEST
            || token == [0; 20]
            || spender == [0; 20]
            || revision == 0
            || blob32(retained.block_hash)? == ZERO_DIGEST
            || blob32(retained.evidence_digest)? == ZERO_DIGEST
            || blob32(retained.registry_digest)? == ZERO_DIGEST
            || blob32(retained.profile_digest)? == ZERO_DIGEST
            || blob32(retained.asset_digest)? == ZERO_DIGEST
            || observed_at == 0
            || valid_until <= observed_at
        {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
    }
    Ok(())
}

fn audit_retained_operations(transaction: &Transaction<'_>) -> Result<()> {
    let operation_ids = {
        let mut statement =
            transaction.prepare("SELECT operation_id FROM evm_operations ORDER BY operation_id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut values = Vec::new();
        for row in rows {
            values.push(blob32(row?)?);
        }
        values
    };
    for operation_id in operation_ids {
        let row = load_operation_row(transaction, operation_id)?;
        if row.operation_id != operation_id {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
        let retained_allowance: (Option<Vec<u8>>, Option<Vec<u8>>) = transaction.query_row(
            "SELECT erc20_token,allowance_revision_be FROM evm_operations
             WHERE operation_id=?1",
            params![operation_id.as_slice()],
            |record| Ok((record.get(0)?, record.get(1)?)),
        )?;
        match retained_allowance {
            (None, None) => {}
            (Some(token), Some(revision)) => {
                let token = blob20(token)?;
                let revision = blob_u64(revision)?;
                let current: Option<Vec<u8>> = transaction
                    .query_row(
                        "SELECT revision_be FROM evm_allowances
                         WHERE authority_id=?1 AND token=?2 AND spender=?3",
                        params![
                            row.authority_id.as_slice(),
                            token.as_slice(),
                            row.fields.to.as_slice()
                        ],
                        |record| record.get(0),
                    )
                    .optional()?;
                if revision == 0
                    || current
                        .map(blob_u64)
                        .transpose()?
                        .map_or(true, |current| current < revision)
                {
                    return Err(EvmActuatorErrorV1::CorruptState);
                }
            }
            _ => return Err(EvmActuatorErrorV1::CorruptState),
        }
    }
    Ok(())
}

fn audit_retained_mutations(transaction: &Transaction<'_>) -> Result<()> {
    let mut statement = transaction.prepare(
        "SELECT authority_id,mutation_id,mutation_digest,operation_id,resulting_revision_be
         FROM evm_mutations ORDER BY authority_id,mutation_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(RetainedMutationAuditRowV1 {
            authority_id: row.get(0)?,
            mutation_id: row.get(1)?,
            mutation_digest: row.get(2)?,
            operation_id: row.get(3)?,
            resulting_revision: row.get(4)?,
        })
    })?;
    for retained in rows {
        let retained = retained?;
        let authority_id = blob32(retained.authority_id)?;
        let mutation_id = blob32(retained.mutation_id)?;
        let mutation_digest = blob32(retained.mutation_digest)?;
        let resulting_revision = blob_u64(retained.resulting_revision)?;
        if authority_id == ZERO_DIGEST
            || mutation_id == ZERO_DIGEST
            || mutation_digest == ZERO_DIGEST
            || resulting_revision == 0
        {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
        if let Some(operation_id) = retained.operation_id {
            let operation = load_operation_row(transaction, blob32(operation_id)?)?;
            if operation.authority_id != authority_id || resulting_revision > operation.revision {
                return Err(EvmActuatorErrorV1::CorruptState);
            }
        } else if !non_operation_revision_exists(transaction, authority_id, resulting_revision)? {
            return Err(EvmActuatorErrorV1::CorruptState);
        }
    }
    Ok(())
}

fn non_operation_revision_exists(
    transaction: &Transaction<'_>,
    authority_id: Digest32,
    revision: u64,
) -> Result<bool> {
    if load_nonce_snapshot(transaction, authority_id)?
        .is_some_and(|snapshot| snapshot.observation_revision >= revision)
    {
        return Ok(true);
    }
    let mut statement =
        transaction.prepare("SELECT revision_be FROM evm_allowances WHERE authority_id=?1")?;
    let rows = statement.query_map(params![authority_id.as_slice()], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    for row in rows {
        if blob_u64(row?)? >= revision {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_database_path(connection: &Connection, expected_path: &Path) -> Result<()> {
    let expected =
        fs::canonicalize(expected_path).map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    if expected != expected_path {
        return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
    }
    let mut statement = connection.prepare("PRAGMA database_list")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
    })?;
    let mut saw_main = false;
    for row in rows {
        let (name, path) = row?;
        match name.as_str() {
            "main" if Path::new(&path) == expected => saw_main = true,
            "temp" if path.is_empty() => {}
            _ => return Err(EvmActuatorErrorV1::InvalidStorageAuthority),
        }
    }
    if !saw_main {
        return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

fn require_linux() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(EvmActuatorErrorV1::LinuxRequired)
    }
}

fn lock_path(database: &Path) -> PathBuf {
    sidecar_path(database, ".lock")
}

fn require_create_path_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(EvmActuatorErrorV1::DatabasePresent),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(EvmActuatorErrorV1::InvalidStorageAuthority),
    }
}

fn acquire_process_lock(database: &Path, create: bool) -> Result<File> {
    let path = lock_path(database);
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create {
        options.create_new(true);
    }
    #[cfg(target_os = "linux")]
    options.mode(FILE_MODE);
    let file = options
        .open(&path)
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    validate_open_file_identity(&file, &path)?;
    if file
        .metadata()
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?
        .len()
        != 0
    {
        return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
    }
    #[cfg(target_os = "linux")]
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| EvmActuatorErrorV1::ProcessLocked)?;
    validate_open_file_identity(&file, &path)?;
    if create {
        file.sync_all()
            .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
        sync_owner_directory(database)?;
    }
    Ok(file)
}

fn create_database_authority(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(target_os = "linux")]
    options.mode(FILE_MODE);
    let file = options
        .open(path)
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    validate_open_file_identity(&file, path)?;
    file.sync_all()
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    sync_owner_directory(path)?;
    Ok(file)
}

fn open_database_authority(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    validate_open_file_identity(&file, path)?;
    Ok(file)
}

fn validate_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(EvmActuatorErrorV1::InvalidStorageAuthority)?;
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
    }
    let canonical =
        fs::canonicalize(parent).map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    if canonical != parent {
        return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
    }
    validate_owner_metadata(&metadata, true)
}

fn validate_owner_only_file(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
    }
    validate_owner_metadata(&metadata, false)
}

fn validate_owner_metadata(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let expected_mode = if directory { DIRECTORY_MODE } else { FILE_MODE };
        if metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o7777 != expected_mode
            || (directory && metadata.nlink() == 0)
            || (!directory && metadata.nlink() != 1)
        {
            return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (metadata, directory);
        return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_open_file_identity(file: &File, path: &Path) -> Result<()> {
    validate_owner_only_file(path)?;
    let retained = file
        .metadata()
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    let named =
        fs::symlink_metadata(path).map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_open_file_identity(_file: &File, _path: &Path) -> Result<()> {
    Err(EvmActuatorErrorV1::LinuxRequired)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SqliteSidecarKindV1 {
    Wal,
    SharedMemory,
    RollbackJournal,
}

fn validate_resumable_sidecars(path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    for (suffix, kind) in [
        ("-wal", SqliteSidecarKindV1::Wal),
        ("-shm", SqliteSidecarKindV1::SharedMemory),
        ("-journal", SqliteSidecarKindV1::RollbackJournal),
    ] {
        let sidecar = sidecar_path(path, suffix);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => validate_sqlite_sidecar_shape(&sidecar, kind)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(EvmActuatorErrorV1::InvalidStorageAuthority),
        }
    }
    #[cfg(not(target_os = "linux"))]
    return Err(EvmActuatorErrorV1::LinuxRequired);
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_sqlite_sidecar_shape(path: &Path, kind: SqliteSidecarKindV1) -> Result<()> {
    validate_owner_only_file(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    let retained = file
        .metadata()
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    let named =
        fs::symlink_metadata(path).map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(EvmActuatorErrorV1::InvalidStorageAuthority);
    }
    if retained.len() == 0 {
        return Ok(());
    }
    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?;
    let valid = match kind {
        SqliteSidecarKindV1::Wal => {
            retained.len() >= 32
                && matches!(
                    u32::from_be_bytes(
                        header[..4]
                            .try_into()
                            .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?
                    ),
                    0x377f_0682 | 0x377f_0683
                )
        }
        SqliteSidecarKindV1::SharedMemory => {
            retained.len() >= 32_768
                && retained.len() % 32_768 == 0
                && u32::from_ne_bytes(
                    header[..4]
                        .try_into()
                        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)?,
                ) == 3_007_000
        }
        SqliteSidecarKindV1::RollbackJournal => {
            retained.len() >= 28 && header == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
        }
    };
    if valid {
        Ok(())
    } else {
        Err(EvmActuatorErrorV1::InvalidStorageAuthority)
    }
}

fn require_sidecars_absent(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal", ".lock"] {
        match fs::symlink_metadata(sidecar_path(path, suffix)) {
            Ok(_) => return Err(EvmActuatorErrorV1::InvalidStorageAuthority),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(EvmActuatorErrorV1::InvalidStorageAuthority),
        }
    }
    Ok(())
}

fn require_sqlite_sidecars_absent(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        match fs::symlink_metadata(sidecar_path(path, suffix)) {
            Ok(_) => return Err(EvmActuatorErrorV1::InvalidStorageAuthority),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(EvmActuatorErrorV1::InvalidStorageAuthority),
        }
    }
    Ok(())
}

fn sync_owner_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(EvmActuatorErrorV1::InvalidStorageAuthority)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| EvmActuatorErrorV1::InvalidStorageAuthority)
}

#[cfg(test)]
mod provisioning_tests {
    use super::*;
    use std::error::Error;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    const CREATION_FAULT_PATH_ENV: &str = "EVM_ACTUATOR_TEST_CREATION_FAULT_PATH";
    const CREATION_FAULT_BOUNDARY_ENV: &str = "EVM_ACTUATOR_TEST_CREATION_FAULT_BOUNDARY";
    const LOCK_PROBE_PATH_ENV: &str = "EVM_ACTUATOR_TEST_LOCK_PROBE_PATH";
    const CREATION_CRASH_EXIT: i32 = 91;
    const LOCK_HELD_EXIT: i32 = 92;

    type TestResult<T = ()> = core::result::Result<T, Box<dyn Error>>;

    trait TestContext<T> {
        fn test_context(self, context: &'static str) -> TestResult<T>;
    }

    impl<T, E> TestContext<T> for core::result::Result<T, E>
    where
        E: core::fmt::Display,
    {
        fn test_context(self, context: &'static str) -> TestResult<T> {
            self.map_err(|error| std::io::Error::other(format!("{context}: {error}")).into())
        }
    }

    impl<T> TestContext<T> for Option<T> {
        fn test_context(self, context: &'static str) -> TestResult<T> {
            self.ok_or_else(|| std::io::Error::other(context).into())
        }
    }

    fn secure_path(name: &str) -> TestResult<(tempfile::TempDir, PathBuf)> {
        let directory = tempfile::tempdir().test_context("create temp directory")?;
        #[cfg(target_os = "linux")]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))
            .test_context("set owner-only directory mode")?;
        let path = directory.path().join(name);
        Ok((directory, path))
    }

    fn creation_boundary_name(boundary: CreationBoundaryV1) -> &'static str {
        match boundary {
            CreationBoundaryV1::ProcessLockPublished => "process-lock-published",
            CreationBoundaryV1::DatabaseFileSynced => "database-file-synced",
            CreationBoundaryV1::BeforeSchemaTransaction => "before-schema-transaction",
            CreationBoundaryV1::BeforeSchemaCommit => "before-schema-commit",
            CreationBoundaryV1::SchemaCommitted => "schema-committed",
        }
    }

    fn parse_creation_boundary(value: &str) -> TestResult<CreationBoundaryV1> {
        match value {
            "process-lock-published" => Ok(CreationBoundaryV1::ProcessLockPublished),
            "database-file-synced" => Ok(CreationBoundaryV1::DatabaseFileSynced),
            "before-schema-transaction" => Ok(CreationBoundaryV1::BeforeSchemaTransaction),
            "before-schema-commit" => Ok(CreationBoundaryV1::BeforeSchemaCommit),
            "schema-committed" => Ok(CreationBoundaryV1::SchemaCommitted),
            _ => Err(std::io::Error::other("unknown creation boundary").into()),
        }
    }

    fn stage_creation_crash(path: &Path, boundary: CreationBoundaryV1) -> TestResult {
        let executable = std::env::current_exe().test_context("resolve test executable")?;
        let status = Command::new(executable)
            .arg("--exact")
            .arg("store::provisioning_tests::creation_fault_child")
            .arg("--nocapture")
            .env(CREATION_FAULT_PATH_ENV, path)
            .env(
                CREATION_FAULT_BOUNDARY_ENV,
                creation_boundary_name(boundary),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .test_context("run creation fault child")?;
        if status.code() == Some(CREATION_CRASH_EXIT) {
            Ok(())
        } else {
            Err(std::io::Error::other(format!("creation fault child exited with {status}")).into())
        }
    }

    fn create_owner_file(path: &Path, bytes: &[u8]) -> TestResult {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(target_os = "linux")]
        options.mode(FILE_MODE);
        let mut file = options.open(path).test_context("create owner file")?;
        use std::io::Write;
        file.write_all(bytes).test_context("write owner file")?;
        file.sync_all().test_context("sync owner file")?;
        Ok(())
    }

    #[test]
    fn creation_fault_child() -> TestResult {
        let Some(path) = std::env::var_os(CREATION_FAULT_PATH_ENV) else {
            return Ok(());
        };
        let boundary_value =
            std::env::var(CREATION_FAULT_BOUNDARY_ENV).test_context("read creation boundary")?;
        let expected = parse_creation_boundary(&boundary_value)?;
        let result =
            DurableEvmActuatorV1::create_with_boundary_hook(Path::new(&path), |boundary| {
                if boundary == expected {
                    std::process::exit(CREATION_CRASH_EXIT);
                }
                Ok(())
            });
        match result {
            Ok(_) => Err(std::io::Error::other("fault boundary was not reached").into()),
            Err(error) => Err(std::io::Error::other(format!(
                "creation failed before fault boundary: {error}"
            ))
            .into()),
        }
    }

    #[test]
    fn lock_probe_child() -> TestResult {
        let Some(path) = std::env::var_os(LOCK_PROBE_PATH_ENV) else {
            return Ok(());
        };
        match DurableEvmActuatorV1::open_existing(Path::new(&path)) {
            Err(EvmActuatorErrorV1::ProcessLocked) => std::process::exit(LOCK_HELD_EXIT),
            Ok(_) => Err(std::io::Error::other("second process acquired authority").into()),
            Err(error) => Err(std::io::Error::other(format!(
                "unexpected second-process refusal: {error}"
            ))
            .into()),
        }
    }

    #[test]
    fn production_create_crash_prefixes_resume_strictly_and_idempotently() -> TestResult {
        for boundary in [
            CreationBoundaryV1::ProcessLockPublished,
            CreationBoundaryV1::DatabaseFileSynced,
            CreationBoundaryV1::BeforeSchemaTransaction,
            CreationBoundaryV1::BeforeSchemaCommit,
            CreationBoundaryV1::SchemaCommitted,
        ] {
            let (_directory, path) = secure_path(creation_boundary_name(boundary))?;
            stage_creation_crash(&path, boundary)?;
            match boundary {
                CreationBoundaryV1::ProcessLockPublished => {
                    assert!(matches!(
                        DurableEvmActuatorV1::open_existing(&path),
                        Err(EvmActuatorErrorV1::DatabaseMissing)
                    ));
                }
                CreationBoundaryV1::DatabaseFileSynced
                | CreationBoundaryV1::BeforeSchemaTransaction
                | CreationBoundaryV1::BeforeSchemaCommit => {
                    assert!(matches!(
                        DurableEvmActuatorV1::open_existing(&path),
                        Err(EvmActuatorErrorV1::CreationIncomplete)
                    ));
                }
                CreationBoundaryV1::SchemaCommitted => {
                    drop(
                        DurableEvmActuatorV1::open_existing(&path)
                            .test_context("open committed empty prefix")?,
                    );
                }
            }
            drop(
                DurableEvmActuatorV1::resume_create_production(&path)
                    .test_context("resume authenticated prefix")?,
            );
            drop(DurableEvmActuatorV1::open_existing(&path).test_context("open resumed store")?);
            drop(
                DurableEvmActuatorV1::resume_create_production(&path)
                    .test_context("idempotently resume exact empty store")?,
            );
        }
        Ok(())
    }

    #[test]
    fn strict_resume_refuses_missing_lock_foreign_state_and_malformed_sidecars() -> TestResult {
        let (_directory, missing_lock) = secure_path("missing-lock.sqlite3")?;
        create_owner_file(&missing_lock, &[])?;
        assert!(matches!(
            DurableEvmActuatorV1::resume_create_production(&missing_lock),
            Err(EvmActuatorErrorV1::InvalidStorageAuthority)
        ));

        let (_directory, foreign_schema) = secure_path("foreign-schema.sqlite3")?;
        stage_creation_crash(&foreign_schema, CreationBoundaryV1::BeforeSchemaTransaction)?;
        let connection = Connection::open(&foreign_schema).test_context("open foreign schema")?;
        connection
            .execute("CREATE TABLE foreign_state(value INTEGER) STRICT", [])
            .test_context("create foreign table")?;
        drop(connection);
        assert!(matches!(
            DurableEvmActuatorV1::resume_create_production(&foreign_schema),
            Err(EvmActuatorErrorV1::CorruptState)
        ));

        let (_directory, foreign_meta) = secure_path("foreign-meta.sqlite3")?;
        stage_creation_crash(&foreign_meta, CreationBoundaryV1::DatabaseFileSynced)?;
        let connection = Connection::open(&foreign_meta).test_context("open foreign metadata")?;
        connection
            .pragma_update(None, "application_id", 7)
            .test_context("install foreign application id")?;
        drop(connection);
        assert!(matches!(
            DurableEvmActuatorV1::resume_create_production(&foreign_meta),
            Err(EvmActuatorErrorV1::CorruptState)
        ));

        let (_directory, malformed_sidecar) = secure_path("malformed-sidecar.sqlite3")?;
        stage_creation_crash(&malformed_sidecar, CreationBoundaryV1::DatabaseFileSynced)?;
        create_owner_file(&sidecar_path(&malformed_sidecar, "-wal"), b"not-a-wal")?;
        assert!(matches!(
            DurableEvmActuatorV1::resume_create_production(&malformed_sidecar),
            Err(EvmActuatorErrorV1::InvalidStorageAuthority)
        ));
        Ok(())
    }

    #[test]
    fn open_authenticates_valid_economic_state_but_resume_requires_empty() -> TestResult {
        let (_directory, path) = secure_path("economic.sqlite3")?;
        drop(DurableEvmActuatorV1::create(&path).test_context("create economic store")?);
        let chain_id = 31_337u64;
        let account = [0x31; 20];
        let authority = authority_id(chain_id, account);
        let connection = Connection::open(&path).test_context("open economic database")?;
        connection
            .execute(
                "INSERT INTO evm_leases
                 (authority_id,chain_id_be,account,owner_id,fencing_epoch_be,
                  lease_until_be,clock_high_water_be)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    authority.as_slice(),
                    chain_id.to_be_bytes().as_slice(),
                    account.as_slice(),
                    [0x42u8; 32].as_slice(),
                    1u64.to_be_bytes().as_slice(),
                    2u64.to_be_bytes().as_slice(),
                    1u64.to_be_bytes().as_slice(),
                ],
            )
            .test_context("insert valid retained lease")?;
        drop(connection);
        drop(
            DurableEvmActuatorV1::open_existing(&path)
                .test_context("authenticate valid economic state")?,
        );
        assert!(matches!(
            DurableEvmActuatorV1::resume_create_production(&path),
            Err(EvmActuatorErrorV1::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn retained_database_and_lock_swaps_fail_closed() -> TestResult {
        let (_directory, database_path) = secure_path("database-swap.sqlite3")?;
        let store =
            DurableEvmActuatorV1::create(&database_path).test_context("create swap store")?;
        let displaced = database_path.with_extension("displaced");
        fs::rename(&database_path, &displaced).test_context("displace database")?;
        create_owner_file(&database_path, &[])?;
        assert!(matches!(
            store.operation([0x51; 32]),
            Err(EvmActuatorErrorV1::InvalidStorageAuthority)
        ));
        drop(store);

        let (_directory, lock_database) = secure_path("lock-swap.sqlite3")?;
        let store =
            DurableEvmActuatorV1::create(&lock_database).test_context("create lock swap store")?;
        let lock = lock_path(&lock_database);
        let displaced_lock = lock_database.with_extension("lock-displaced");
        fs::rename(&lock, &displaced_lock).test_context("displace process lock")?;
        create_owner_file(&lock, &[])?;
        assert!(matches!(
            store.operation([0x52; 32]),
            Err(EvmActuatorErrorV1::InvalidStorageAuthority)
        ));
        Ok(())
    }

    #[test]
    fn permissions_links_and_second_process_are_refused() -> TestResult {
        let (_directory, path) = secure_path("process-lock.sqlite3")?;
        let store = DurableEvmActuatorV1::create(&path).test_context("create locked store")?;
        let executable = std::env::current_exe().test_context("resolve test executable")?;
        let status = Command::new(executable)
            .arg("--exact")
            .arg("store::provisioning_tests::lock_probe_child")
            .arg("--nocapture")
            .env(LOCK_PROBE_PATH_ENV, &path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .test_context("run lock probe child")?;
        assert_eq!(status.code(), Some(LOCK_HELD_EXIT));
        drop(store);

        #[cfg(target_os = "linux")]
        {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
                .test_context("weaken database permissions")?;
            assert!(matches!(
                DurableEvmActuatorV1::open_existing(&path),
                Err(EvmActuatorErrorV1::InvalidStorageAuthority)
            ));
            fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE))
                .test_context("restore database permissions")?;
            let linked = path.with_extension("linked");
            fs::hard_link(&path, &linked).test_context("link database")?;
            assert!(matches!(
                DurableEvmActuatorV1::open_existing(&path),
                Err(EvmActuatorErrorV1::InvalidStorageAuthority)
            ));
        }
        Ok(())
    }
}

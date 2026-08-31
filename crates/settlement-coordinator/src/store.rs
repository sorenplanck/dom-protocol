//! Owner-only SQLite/WAL authority for two-face settlement coordination.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
#[cfg(target_os = "linux")]
use rustix::fs::{flock, FlockOperation};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;

use crate::codec::{
    aggregate_action_id, aggregate_custody_digest, deferred_child_digest, domain_digest_v1,
    stable_plan_equivalent, stable_plan_id, CanonicalSettlementPlanV1,
};
use crate::model::{
    AggregateExternalizationReceiptV1, AggregateFinalityV1, AggregateReorgV1, AggregateStageV1,
    AuthenticatedCoordinatorExposureV1, ChildDispatchRequestV1, ChildExecutionOutcomeV1,
    ChildExposureV1, ChildExternalizationReceiptV1, ChildObservationOutcomeV1,
    ChildObservationRequestV1, ChildProgressViewV1, ChildPublicExposureV1,
    ChildReconciliationOutcomeV1, ChildReconciliationRequestV1, ChildStageV1,
    CompositeSettlementPlanV1, CoordinatorDriveOutcomeV1, CoordinatorLeaseAcquireV1,
    CoordinatorLeaseV1, CoordinatorObservationOutcomeV1, CustodyTakeoverStatusV1,
    DeferredChildMaterializationCapabilityV1, Digest32, PartialCustodyProgressV1,
    PendingChildCallV1, PendingChildReconciliationV1, PlanAuthorizationRequestV1,
    SecretRequirementV1, SettlementActionV1, SettlementChildAuthorityV1, SettlementChildObserverV1,
    SettlementChildPlanV1, SettlementChildrenV1, SettlementDeferredChildAuthorityV1,
    SettlementFaceV1, SettlementPlanAuthorityV1, SettlementPlanViewV1, StoredSettlementPlanV1,
    MAX_SETTLEMENT_CHILDREN_V1, ZERO_DIGEST,
};
use crate::{CoordinatorErrorV1, Result};

const SCHEMA_VERSION: i64 = 3;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_LEASE_DURATION_MS: u64 = 86_400_000;
const MAX_PLAN_BYTES: usize = 4096;
const MAX_STORED_PLANS: u64 = 4096;
const MAX_PLAN_VERSIONS: u64 = 4096;
const MAX_JOURNAL_ENTRIES: u64 = 65_536;
const MAX_OBSERVATIONS_PER_CHILD: u64 = 65_536;
const MAX_RECONCILIATIONS_PER_CHILD: u64 = 65_536;
const CHILD_PLANNED: i64 = 1;
const CHILD_CALL_PENDING: i64 = 2;
const CHILD_EXTERNALIZED: i64 = 3;
const CHILD_FINAL: i64 = 4;
const CHILD_FINALITY_INVALIDATED: i64 = 5;
const AGGREGATE_ACTIVE: i64 = 1;
const AGGREGATE_EXTERNALIZED: i64 = 2;
const AGGREGATE_FINAL: i64 = 3;
const AGGREGATE_FINALITY_INVALIDATED: i64 = 4;
const AGGREGATE_FAILED_CLOSED: i64 = 5;
const SECRET_PRIVATE: i64 = 1;
const SECRET_EXPOSURE_POSSIBLE: i64 = 2;
const SECRET_PUBLIC: i64 = 3;
const RECONCILIATION_SUPERSEDED: i64 = 4;

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

type RetainedObservationRow = (Vec<u8>, Option<Vec<u8>>, Option<i64>, Option<Vec<u8>>);

const SCHEMA_V3: &str = "
CREATE TABLE coordinator_metadata (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
    coordinator_id BLOB NOT NULL CHECK(length(coordinator_id) = 32),
    plan_authority_id BLOB NOT NULL CHECK(length(plan_authority_id) = 32),
    clock_high_water_be BLOB NOT NULL CHECK(length(clock_high_water_be) = 8),
    created_at_be BLOB NOT NULL CHECK(length(created_at_be) = 8)
) STRICT;

CREATE TABLE settlement_plans (
    plan_id BLOB PRIMARY KEY NOT NULL CHECK(length(plan_id) = 32),
    plan_digest BLOB UNIQUE NOT NULL CHECK(length(plan_digest) = 32),
    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
    effect_id BLOB UNIQUE NOT NULL CHECK(length(effect_id) = 32),
    settlement_id BLOB NOT NULL CHECK(length(settlement_id) = 32),
    route_fence_be BLOB NOT NULL CHECK(length(route_fence_be) = 8),
    plan_bytes BLOB NOT NULL CHECK(length(plan_bytes) > 0 AND length(plan_bytes) <= 4096),
    authorization_evidence BLOB NOT NULL CHECK(length(authorization_evidence) = 32),
    aggregate_action_id BLOB UNIQUE NOT NULL CHECK(length(aggregate_action_id) = 32),
    aggregate_custody_digest BLOB UNIQUE NOT NULL CHECK(length(aggregate_custody_digest) = 32),
    stage_tag INTEGER NOT NULL CHECK(stage_tag BETWEEN 1 AND 5),
    secret_state_tag INTEGER NOT NULL CHECK(secret_state_tag BETWEEN 1 AND 3),
    revision_be BLOB NOT NULL CHECK(length(revision_be) = 8),
    journal_head BLOB NOT NULL CHECK(length(journal_head) = 32),
    first_exposure_child INTEGER CHECK(first_exposure_child BETWEEN 0 AND 1),
    first_exposure_chain BLOB CHECK(first_exposure_chain IS NULL OR length(first_exposure_chain) = 32),
    first_exposure_tx BLOB CHECK(first_exposure_tx IS NULL OR length(first_exposure_tx) = 32),
    first_exposure_evidence BLOB CHECK(first_exposure_evidence IS NULL OR length(first_exposure_evidence) = 32),
    first_exposure_observed_at_be BLOB CHECK(first_exposure_observed_at_be IS NULL OR length(first_exposure_observed_at_be) = 8),
    aggregate_receipt_digest BLOB CHECK(aggregate_receipt_digest IS NULL OR length(aggregate_receipt_digest) = 32),
    aggregate_finality_digest BLOB CHECK(aggregate_finality_digest IS NULL OR length(aggregate_finality_digest) = 32),
    aggregate_reorg_digest BLOB CHECK(aggregate_reorg_digest IS NULL OR length(aggregate_reorg_digest) = 32),
    created_at_be BLOB NOT NULL CHECK(length(created_at_be) = 8),
    updated_at_be BLOB NOT NULL CHECK(length(updated_at_be) = 8),
    CHECK((secret_state_tag = 3 AND first_exposure_child IS NOT NULL AND first_exposure_chain IS NOT NULL AND first_exposure_tx IS NOT NULL AND first_exposure_evidence IS NOT NULL AND first_exposure_observed_at_be IS NOT NULL)
       OR (secret_state_tag != 3 AND first_exposure_child IS NULL AND first_exposure_chain IS NULL AND first_exposure_tx IS NULL AND first_exposure_evidence IS NULL AND first_exposure_observed_at_be IS NULL)
       OR (secret_state_tag = 3 AND first_exposure_child IS NULL AND first_exposure_chain IS NULL AND first_exposure_tx IS NULL AND first_exposure_evidence IS NULL AND first_exposure_observed_at_be IS NULL)),
    CHECK((stage_tag >= 2 AND aggregate_receipt_digest IS NOT NULL) OR (stage_tag = 1 AND aggregate_receipt_digest IS NULL) OR stage_tag = 5),
    CHECK((stage_tag = 3 AND aggregate_finality_digest IS NOT NULL) OR stage_tag != 3)
) STRICT;

CREATE TABLE settlement_plan_versions (
    plan_id BLOB NOT NULL REFERENCES settlement_plans(plan_id) ON DELETE RESTRICT,
    version_be BLOB NOT NULL CHECK(length(version_be) = 8),
    plan_digest BLOB UNIQUE NOT NULL CHECK(length(plan_digest) = 32),
    effect_id BLOB UNIQUE NOT NULL CHECK(length(effect_id) = 32),
    route_fence_be BLOB NOT NULL CHECK(length(route_fence_be) = 8),
    plan_bytes BLOB NOT NULL CHECK(length(plan_bytes) > 0 AND length(plan_bytes) <= 4096),
    authorization_evidence BLOB NOT NULL CHECK(length(authorization_evidence) = 32),
    installed_at_be BLOB NOT NULL CHECK(length(installed_at_be) = 8),
    PRIMARY KEY(plan_id, version_be)
) STRICT;

CREATE TABLE settlement_children (
    plan_id BLOB NOT NULL REFERENCES settlement_plans(plan_id) ON DELETE RESTRICT,
    child_index INTEGER NOT NULL CHECK(child_index BETWEEN 0 AND 1),
    face_tag INTEGER NOT NULL CHECK(face_tag BETWEEN 1 AND 3),
    exposure_tag INTEGER NOT NULL CHECK(exposure_tag BETWEEN 1 AND 3),
    chain_id BLOB NOT NULL CHECK(length(chain_id) = 32),
    expected_tx_id BLOB NOT NULL CHECK(length(expected_tx_id) = 32),
    intent_digest BLOB NOT NULL CHECK(length(intent_digest) = 32),
    custody_digest BLOB NOT NULL CHECK(length(custody_digest) = 32),
    stage_tag INTEGER NOT NULL CHECK(stage_tag BETWEEN 1 AND 5),
    call_attempt_be BLOB NOT NULL CHECK(length(call_attempt_be) = 8),
    pending_attempt_id BLOB CHECK(pending_attempt_id IS NULL OR length(pending_attempt_id) = 32),
    pending_call_digest BLOB CHECK(pending_call_digest IS NULL OR length(pending_call_digest) = 32),
    last_ambiguity_evidence BLOB CHECK(last_ambiguity_evidence IS NULL OR length(last_ambiguity_evidence) = 32),
    externalization_evidence BLOB CHECK(externalization_evidence IS NULL OR length(externalization_evidence) = 32),
    finality_evidence BLOB CHECK(finality_evidence IS NULL OR length(finality_evidence) = 32),
    reorg_evidence BLOB CHECK(reorg_evidence IS NULL OR length(reorg_evidence) = 32),
    reconciliation_attempt_id BLOB CHECK(reconciliation_attempt_id IS NULL OR length(reconciliation_attempt_id) = 32),
    reconciliation_record_digest BLOB CHECK(reconciliation_record_digest IS NULL OR length(reconciliation_record_digest) = 32),
    PRIMARY KEY(plan_id, child_index),
    UNIQUE(plan_id, chain_id, expected_tx_id),
    UNIQUE(plan_id, intent_digest),
    UNIQUE(plan_id, custody_digest),
    CHECK((stage_tag = 2 AND pending_attempt_id IS NOT NULL AND pending_call_digest IS NOT NULL)
       OR (stage_tag != 2 AND pending_attempt_id IS NULL AND pending_call_digest IS NULL)),
    CHECK((stage_tag >= 3 AND externalization_evidence IS NOT NULL) OR stage_tag < 3),
    CHECK((stage_tag = 4 AND finality_evidence IS NOT NULL) OR stage_tag != 4),
    CHECK((reconciliation_attempt_id IS NULL AND reconciliation_record_digest IS NULL)
       OR (reconciliation_attempt_id IS NOT NULL AND reconciliation_record_digest IS NOT NULL))
) STRICT;

CREATE TABLE coordinator_leases (
    plan_id BLOB PRIMARY KEY NOT NULL REFERENCES settlement_plans(plan_id) ON DELETE RESTRICT,
    owner_id BLOB NOT NULL CHECK(length(owner_id) = 32),
    route_fence_be BLOB NOT NULL CHECK(length(route_fence_be) = 8),
    coordinator_fence_be BLOB NOT NULL CHECK(length(coordinator_fence_be) = 8),
    lease_until_be BLOB NOT NULL CHECK(length(lease_until_be) = 8),
    takeover_evidence BLOB CHECK(takeover_evidence IS NULL OR length(takeover_evidence) = 32),
    updated_at_be BLOB NOT NULL CHECK(length(updated_at_be) = 8)
) STRICT;

CREATE TABLE coordinator_journal (
    plan_id BLOB NOT NULL REFERENCES settlement_plans(plan_id) ON DELETE RESTRICT,
    sequence_be BLOB NOT NULL CHECK(length(sequence_be) = 8),
    event_id BLOB NOT NULL CHECK(length(event_id) = 32),
    event_tag INTEGER NOT NULL CHECK(event_tag BETWEEN 1 AND 14),
    event_digest BLOB NOT NULL CHECK(length(event_digest) = 32),
    route_fence_be BLOB NOT NULL CHECK(length(route_fence_be) = 8),
    coordinator_fence_be BLOB NOT NULL CHECK(length(coordinator_fence_be) = 8),
    previous_entry_hash BLOB NOT NULL CHECK(length(previous_entry_hash) = 32),
    entry_hash BLOB NOT NULL CHECK(length(entry_hash) = 32),
    created_at_be BLOB NOT NULL CHECK(length(created_at_be) = 8),
    PRIMARY KEY(plan_id, sequence_be),
    UNIQUE(plan_id, event_id)
) STRICT;

CREATE TABLE child_call_outcomes (
    attempt_id BLOB PRIMARY KEY NOT NULL CHECK(length(attempt_id) = 32),
    plan_id BLOB NOT NULL REFERENCES settlement_plans(plan_id) ON DELETE RESTRICT,
    child_index INTEGER NOT NULL CHECK(child_index BETWEEN 0 AND 1),
    outcome_tag INTEGER NOT NULL CHECK(outcome_tag IN (1, 2, 3)),
    outcome_digest BLOB NOT NULL CHECK(length(outcome_digest) = 32),
    created_at_be BLOB NOT NULL CHECK(length(created_at_be) = 8)
) STRICT;

CREATE TABLE child_reconciliation_calls (
    reconciliation_attempt_id BLOB PRIMARY KEY NOT NULL CHECK(length(reconciliation_attempt_id) = 32),
    plan_id BLOB NOT NULL,
    child_index INTEGER NOT NULL CHECK(child_index BETWEEN 0 AND 1),
    dispatch_attempt_id BLOB NOT NULL CHECK(length(dispatch_attempt_id) = 32),
    sequence_be BLOB NOT NULL CHECK(length(sequence_be) = 8),
    scope_tag INTEGER NOT NULL CHECK(scope_tag IN (1,2)),
    route_fence_be BLOB NOT NULL CHECK(length(route_fence_be) = 8),
    coordinator_fence_be BLOB NOT NULL CHECK(length(coordinator_fence_be) = 8),
    prior_outcome_digest BLOB NOT NULL CHECK(length(prior_outcome_digest) = 32),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    outcome_tag INTEGER CHECK(outcome_tag IS NULL OR outcome_tag IN (1,2,3,4)),
    outcome_digest BLOB CHECK(outcome_digest IS NULL OR length(outcome_digest) = 32),
    outcome_evidence BLOB CHECK(outcome_evidence IS NULL OR length(outcome_evidence) = 32),
    created_at_be BLOB NOT NULL CHECK(length(created_at_be) = 8),
    completed_at_be BLOB CHECK(completed_at_be IS NULL OR length(completed_at_be) = 8),
    FOREIGN KEY(plan_id,child_index) REFERENCES settlement_children(plan_id,child_index) ON DELETE RESTRICT,
    UNIQUE(plan_id,child_index,dispatch_attempt_id,sequence_be),
    CHECK((outcome_tag IS NULL AND outcome_digest IS NULL AND outcome_evidence IS NULL AND completed_at_be IS NULL)
       OR (outcome_tag IS NOT NULL AND outcome_digest IS NOT NULL AND outcome_evidence IS NOT NULL AND completed_at_be IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX one_pending_child_reconciliation
ON child_reconciliation_calls(plan_id,child_index)
WHERE outcome_digest IS NULL;

CREATE TABLE observation_calls (
    observation_attempt_id BLOB PRIMARY KEY NOT NULL CHECK(length(observation_attempt_id) = 32),
    plan_id BLOB NOT NULL REFERENCES settlement_plans(plan_id) ON DELETE RESTRICT,
    child_index INTEGER NOT NULL CHECK(child_index BETWEEN 0 AND 1),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    outcome_digest BLOB CHECK(outcome_digest IS NULL OR length(outcome_digest) = 32),
    result_tag INTEGER CHECK(result_tag IS NULL OR result_tag BETWEEN 1 AND 4),
    result_evidence BLOB CHECK(result_evidence IS NULL OR length(result_evidence) = 32),
    created_at_be BLOB NOT NULL CHECK(length(created_at_be) = 8),
    completed_at_be BLOB CHECK(completed_at_be IS NULL OR length(completed_at_be) = 8),
    CHECK((outcome_digest IS NULL AND result_tag IS NULL AND result_evidence IS NULL AND completed_at_be IS NULL)
       OR (outcome_digest IS NOT NULL AND result_tag IS NOT NULL AND result_evidence IS NOT NULL AND completed_at_be IS NOT NULL))
) STRICT;

CREATE TABLE coordinator_conflicts (
    conflict_id BLOB PRIMARY KEY NOT NULL CHECK(length(conflict_id) = 32),
    plan_id BLOB NOT NULL REFERENCES settlement_plans(plan_id) ON DELETE RESTRICT,
    existing_digest BLOB NOT NULL CHECK(length(existing_digest) = 32),
    conflicting_digest BLOB NOT NULL CHECK(length(conflicting_digest) = 32),
    evidence_digest BLOB NOT NULL CHECK(length(evidence_digest) = 32),
    created_at_be BLOB NOT NULL CHECK(length(created_at_be) = 8)
) STRICT;

CREATE TABLE deferred_child_materializations (
    plan_id BLOB PRIMARY KEY NOT NULL REFERENCES settlement_plans(plan_id) ON DELETE RESTRICT,
    attempt_id BLOB UNIQUE NOT NULL CHECK(length(attempt_id) = 32),
    descriptor_digest BLOB NOT NULL CHECK(length(descriptor_digest) = 32),
    exposure_evidence BLOB NOT NULL CHECK(length(exposure_evidence) = 32),
    route_fence_be BLOB NOT NULL CHECK(length(route_fence_be) = 8),
    coordinator_fence_be BLOB NOT NULL CHECK(length(coordinator_fence_be) = 8),
    record_digest BLOB NOT NULL CHECK(length(record_digest) = 32),
    state_tag INTEGER NOT NULL CHECK(state_tag IN (1,2)),
    chain_id BLOB CHECK(chain_id IS NULL OR length(chain_id) = 32),
    expected_tx_id BLOB CHECK(expected_tx_id IS NULL OR length(expected_tx_id) = 32),
    intent_digest BLOB CHECK(intent_digest IS NULL OR length(intent_digest) = 32),
    custody_digest BLOB CHECK(custody_digest IS NULL OR length(custody_digest) = 32),
    created_at_be BLOB NOT NULL CHECK(length(created_at_be) = 8),
    completed_at_be BLOB CHECK(completed_at_be IS NULL OR length(completed_at_be) = 8),
    completed_route_fence_be BLOB CHECK(completed_route_fence_be IS NULL OR length(completed_route_fence_be) = 8),
    completed_coordinator_fence_be BLOB CHECK(completed_coordinator_fence_be IS NULL OR length(completed_coordinator_fence_be) = 8),
    CHECK((state_tag = 1 AND chain_id IS NULL AND expected_tx_id IS NULL
            AND intent_digest IS NULL AND custody_digest IS NULL AND completed_at_be IS NULL
            AND completed_route_fence_be IS NULL AND completed_coordinator_fence_be IS NULL)
       OR (state_tag = 2 AND chain_id IS NOT NULL AND expected_tx_id IS NOT NULL
            AND intent_digest IS NOT NULL AND custody_digest IS NOT NULL
            AND completed_at_be IS NOT NULL AND completed_route_fence_be IS NOT NULL
            AND completed_coordinator_fence_be IS NOT NULL))
) STRICT;

PRAGMA user_version = 3;
";

/// Single-process durable settlement coordinator.
pub struct DurableSettlementCoordinatorV1 {
    connection: Connection,
    path: PathBuf,
    coordinator_id: Digest32,
    plan_authority_id: Digest32,
    database_authority: File,
    _process_lock: File,
}

impl core::fmt::Debug for DurableSettlementCoordinatorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableSettlementCoordinatorV1([redacted])")
    }
}

impl DurableSettlementCoordinatorV1 {
    /// Create a new owner-only Linux authority and pin its coordinator and
    /// plan-authority identities.
    pub fn create(
        path: &Path,
        coordinator_id: Digest32,
        plan_authority_id: Digest32,
        now_unix_ms: u64,
    ) -> Result<Self> {
        Self::create_with_boundary_hook(
            path,
            coordinator_id,
            plan_authority_id,
            now_unix_ms,
            |_| Ok(()),
        )
    }

    fn create_with_boundary_hook<F>(
        path: &Path,
        coordinator_id: Digest32,
        plan_authority_id: Digest32,
        now_unix_ms: u64,
        mut boundary: F,
    ) -> Result<Self>
    where
        F: FnMut(CreationBoundaryV1) -> Result<()>,
    {
        validate_identity(coordinator_id, plan_authority_id)?;
        require_linux()?;
        let parent = path
            .parent()
            .ok_or(CoordinatorErrorV1::InvalidStorageAuthority)?;
        validate_owner_directory(parent)?;
        require_create_path_absent(path)?;
        require_create_path_absent(&process_lock_path(path))?;
        require_sidecars_absent(path)?;
        let process_lock = acquire_process_lock(path, true)?;
        boundary(CreationBoundaryV1::ProcessLockPublished)?;
        let database_authority = create_database_authority(path)?;
        boundary(CreationBoundaryV1::DatabaseFileSynced)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        validate_open_file_identity(&database_authority, path)?;
        boundary(CreationBoundaryV1::BeforeSchemaTransaction)?;
        create_schema_and_metadata_with_boundary_hook(
            &connection,
            coordinator_id,
            plan_authority_id,
            now_unix_ms,
            || boundary(CreationBoundaryV1::BeforeSchemaCommit),
        )?;
        boundary(CreationBoundaryV1::SchemaCommitted)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
            coordinator_id,
            plan_authority_id,
            database_authority,
            _process_lock: process_lock,
        };
        store.audit_storage()?;
        sync_directory(parent)?;
        Ok(store)
    }

    /// Resume only an authenticated crash prefix of an explicit production
    /// create whose exact intent is already durable in an external journal.
    ///
    /// The owner-only process lock published by [`Self::create`] must already
    /// exist and be exclusively acquirable. The database may be absent,
    /// pristine SQLite, or the exact V2 schema plus initial metadata and no
    /// economic state. This method never opens or adopts an arbitrary store.
    pub fn resume_create_production(
        path: &Path,
        coordinator_id: Digest32,
        plan_authority_id: Digest32,
        now_unix_ms: u64,
    ) -> Result<Self> {
        validate_identity(coordinator_id, plan_authority_id)?;
        require_linux()?;
        let parent = path
            .parent()
            .ok_or(CoordinatorErrorV1::InvalidStorageAuthority)?;
        validate_owner_directory(parent)?;
        let process_lock = acquire_process_lock(path, false)?;
        let database_authority = match fs::symlink_metadata(path) {
            Ok(_) => {
                validate_owner_file(path)?;
                validate_resumable_sidecars(path)?;
                open_database_authority(path)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                require_sidecars_absent(path)?;
                create_database_authority(path)?
            }
            Err(_) => return Err(CoordinatorErrorV1::StorageUnavailable),
        };
        let state = preflight_resumable_creation_state(path, &database_authority)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        validate_open_file_identity(&database_authority, path)?;
        match state {
            ResumableCreationStateV1::PristineSqlite => create_schema_and_metadata(
                &connection,
                coordinator_id,
                plan_authority_id,
                now_unix_ms,
            )?,
            ResumableCreationStateV1::InitializedExact => {}
        }
        validate_pristine_initialized_store(&connection, coordinator_id, plan_authority_id)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
            coordinator_id,
            plan_authority_id,
            database_authority,
            _process_lock: process_lock,
        };
        store.audit_storage()?;
        validate_resumable_sidecars(path)?;
        sync_directory(parent)?;
        Ok(store)
    }

    /// Open an existing exact V2 authority. This never creates or migrates.
    pub fn open_existing(
        path: &Path,
        coordinator_id: Digest32,
        plan_authority_id: Digest32,
    ) -> Result<Self> {
        validate_identity(coordinator_id, plan_authority_id)?;
        require_linux()?;
        let parent = path
            .parent()
            .ok_or(CoordinatorErrorV1::InvalidStorageAuthority)?;
        validate_owner_directory(parent)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(CoordinatorErrorV1::DatabaseMissing)
            }
            Err(_) => return Err(CoordinatorErrorV1::StorageUnavailable),
        }
        validate_owner_file(path)?;
        validate_resumable_sidecars(path)?;
        let process_lock = acquire_process_lock(path, false)?;
        let database_authority = open_database_authority(path)?;
        if preflight_resumable_creation_state(path, &database_authority)?
            == ResumableCreationStateV1::PristineSqlite
        {
            return Err(CoordinatorErrorV1::CreationIncomplete);
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        configure_connection(&connection)?;
        let store = Self {
            connection,
            path: path.to_path_buf(),
            coordinator_id,
            plan_authority_id,
            database_authority,
            _process_lock: process_lock,
        };
        store.audit_storage()?;
        let retained: (Vec<u8>, Vec<u8>) = store
            .connection
            .query_row(
                "SELECT coordinator_id,plan_authority_id FROM coordinator_metadata WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage)?;
        if blob32(retained.0)? != coordinator_id || blob32(retained.1)? != plan_authority_id {
            return Err(CoordinatorErrorV1::InvalidStorageAuthority);
        }
        store.audit_all_plans()?;
        Ok(store)
    }

    /// Authenticates and atomically installs one strict aggregate plan.
    pub fn install_plan<A: SettlementPlanAuthorityV1>(
        &mut self,
        authority: &mut A,
        plan: CompositeSettlementPlanV1,
        now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1> {
        plan.validate()?;
        let plan_bytes = plan.encode_canonical()?;
        if plan_bytes.len() > MAX_PLAN_BYTES {
            return Err(CoordinatorErrorV1::InvalidBound);
        }
        let plan_digest = plan.canonical_digest()?;
        let plan_id = stable_plan_id(&plan)?;
        let aggregate_action = aggregate_action_id(&plan)?;
        let aggregate_custody = aggregate_custody_digest(&plan)?;
        let authorization = authority
            .authorize_plan(PlanAuthorizationRequestV1 {
                plan: &plan,
                plan_digest,
            })
            .map_err(|_| CoordinatorErrorV1::PlanAuthorityRefused)?;
        if authorization.authority_id() != self.plan_authority_id
            || authorization.plan_digest() != plan_digest
            || authorization.evidence_digest() == ZERO_DIGEST
            || authorization.valid_until_unix_ms() < now_unix_ms
        {
            return Err(CoordinatorErrorV1::InvalidPlanAuthorization);
        }

        let transaction = self.immediate(now_unix_ms)?;
        if let Some(existing) = load_plan_row_optional(&transaction, plan_id)? {
            if existing.plan_digest == plan_digest
                && existing.plan_bytes == plan_bytes
                && existing.authorization_evidence == authorization.evidence_digest()
            {
                transaction.commit().map_err(storage)?;
                return self.load_plan(plan_id);
            }
            fail_closed_conflict(
                &transaction,
                plan_id,
                existing.plan_digest,
                plan_digest,
                authorization.evidence_digest(),
                now_unix_ms,
            )?;
            transaction.commit().map_err(storage)?;
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        if let Some((existing_plan_id, existing_digest)) = transaction
            .query_row(
                "SELECT plan_id,plan_digest FROM settlement_plans WHERE effect_id=?1",
                params![plan.bindings().effect_id.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(storage)?
        {
            let existing_plan_id = blob32(existing_plan_id)?;
            fail_closed_conflict(
                &transaction,
                existing_plan_id,
                blob32(existing_digest)?,
                plan_digest,
                authorization.evidence_digest(),
                now_unix_ms,
            )?;
            transaction.commit().map_err(storage)?;
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        if let Some((existing_plan_id, existing_digest)) = transaction
            .query_row(
                "SELECT versions.plan_id,plans.plan_digest
                 FROM settlement_plan_versions AS versions
                 JOIN settlement_plans AS plans ON plans.plan_id=versions.plan_id
                 WHERE versions.effect_id=?1",
                params![plan.bindings().effect_id.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(storage)?
        {
            let existing_plan_id = blob32(existing_plan_id)?;
            fail_closed_conflict(
                &transaction,
                existing_plan_id,
                blob32(existing_digest)?,
                plan_digest,
                authorization.evidence_digest(),
                now_unix_ms,
            )?;
            transaction.commit().map_err(storage)?;
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        let stored_plans: i64 = transaction
            .query_row("SELECT COUNT(*) FROM settlement_plans", [], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        if u64::try_from(stored_plans).map_err(|_| CoordinatorErrorV1::CorruptState)?
            >= MAX_STORED_PLANS
        {
            return Err(CoordinatorErrorV1::InvalidBound);
        }

        let initial_secret_state =
            if plan.secret_requirement() == SecretRequirementV1::AlreadyPublic {
                SECRET_PUBLIC
            } else {
                SECRET_PRIVATE
            };
        transaction
            .execute(
                "INSERT INTO settlement_plans(
                    plan_id,plan_digest,route_id,effect_id,settlement_id,route_fence_be,
                    plan_bytes,authorization_evidence,aggregate_action_id,aggregate_custody_digest,
                    stage_tag,secret_state_tag,revision_be,journal_head,
                    first_exposure_child,first_exposure_chain,first_exposure_tx,first_exposure_evidence,
                    first_exposure_observed_at_be,
                    aggregate_receipt_digest,aggregate_finality_digest,aggregate_reorg_digest,
                    created_at_be,updated_at_be
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?15,?15)",
                params![
                    plan_id.as_slice(),
                    plan_digest.as_slice(),
                    plan.bindings().route_id.as_slice(),
                    plan.bindings().effect_id.as_slice(),
                    plan.bindings().settlement_id.as_slice(),
                    u64_blob(plan.bindings().fencing_epoch),
                    plan_bytes,
                    authorization.evidence_digest().as_slice(),
                    aggregate_action.as_slice(),
                    aggregate_custody.as_slice(),
                    AGGREGATE_ACTIVE,
                    initial_secret_state,
                    u64_blob(0),
                    ZERO_DIGEST.as_slice(),
                    u64_blob(now_unix_ms),
                ],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "INSERT INTO settlement_plan_versions(plan_id,version_be,plan_digest,effect_id,route_fence_be,plan_bytes,authorization_evidence,installed_at_be) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    plan_id.as_slice(), u64_blob(1), plan_digest.as_slice(),
                    plan.bindings().effect_id.as_slice(), u64_blob(plan.bindings().fencing_epoch),
                    plan.encode_canonical()?, authorization.evidence_digest().as_slice(),
                    u64_blob(now_unix_ms),
                ],
            )
            .map_err(storage)?;
        let installed_children: &[SettlementChildPlanV1] = match plan.child_layout() {
            SettlementChildrenV1::Materialized(children) => children,
            SettlementChildrenV1::FirstExposureStaged { first, .. } => core::slice::from_ref(first),
        };
        for (index, child) in installed_children.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO settlement_children(
                        plan_id,child_index,face_tag,exposure_tag,chain_id,expected_tx_id,
                        intent_digest,custody_digest,stage_tag,call_attempt_be,pending_attempt_id,
                        pending_call_digest,last_ambiguity_evidence,externalization_evidence,
                        finality_evidence,reorg_evidence,reconciliation_attempt_id,reconciliation_record_digest
                     ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
                    params![
                        plan_id.as_slice(), i64::try_from(index).map_err(|_| CoordinatorErrorV1::InvalidBound)?,
                        i64::from(child.face.tag()), i64::from(child.exposure.tag()),
                        child.chain_id.as_slice(), child.expected_transaction_id.as_slice(),
                        child.intent_digest.as_slice(), child.custody_digest.as_slice(),
                        CHILD_PLANNED, u64_blob(0),
                    ],
                )
                .map_err(storage)?;
        }
        append_journal(
            &transaction,
            JournalEventV1 {
                plan_id,
                event_tag: 1,
                event_id: domain_digest_v1(
                    b"DOM-INTEROP/SETTLEMENT-COORDINATOR/INSTALL-EVENT/V1\0",
                    &[&plan_digest],
                ),
                event_digest: plan_digest,
                route_fence: plan.bindings().fencing_epoch,
                coordinator_fence: 0,
            },
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        self.load_plan(plan_id)
    }

    /// Load and fully revalidate one aggregate plan, its children and journal.
    pub fn load_plan(&self, plan_id: Digest32) -> Result<SettlementPlanViewV1> {
        validate_digest(plan_id)?;
        self.audit_storage()?;
        audit_plan(&self.connection, plan_id)
    }

    /// Authenticate the exact first public exposure retained by one plan.
    ///
    /// The returned capability is move-only and cannot be assembled by a
    /// caller.  This method first performs the same complete audit as
    /// [`Self::load_plan`], then re-reads the plan row and requires a
    /// first-exposure Claim whose retained child identity is byte-identical to
    /// the public exposure.  It is intended solely for recovering the crash
    /// cut after the route-secret seal was fsynced but before the parent route
    /// journal committed `Public`.
    pub fn authenticate_first_public_exposure(
        &self,
        plan_id: Digest32,
    ) -> Result<AuthenticatedCoordinatorExposureV1> {
        let view = self.load_plan(plan_id)?;
        let row = load_plan_row(&self.connection, plan_id)?;
        let plan = decode_plan_row(&row)?;
        let exposure = public_exposure(&row)?.ok_or(CoordinatorErrorV1::InvalidState)?;
        let child = plan
            .materialized_child(usize::from(exposure.child_index))
            .ok_or(CoordinatorErrorV1::CorruptState)?;
        if plan.bindings().action != SettlementActionV1::Claim
            || plan.secret_requirement() != SecretRequirementV1::FirstExposureRequired
            || exposure.child_index != 0
            || child.exposure != ChildExposureV1::FirstSecretExposure
            || child.chain_id != exposure.chain_id
            || child.expected_transaction_id != exposure.transaction_id
            || view.plan_id != row.plan_id
            || view.plan_digest != row.plan_digest
            || view.revision != row.revision
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        AuthenticatedCoordinatorExposureV1::from_audited_plan(
            row.route_id,
            row.plan_id,
            row.settlement_id,
            row.plan_digest,
            row.revision,
            row.journal_head,
            exposure,
        )
    }

    /// Durably prepares, invokes, and commits the exact second child of a
    /// staged first-exposure plan.  The authority is called only after the
    /// pending descriptor attempt and its historical fences are journaled.
    /// A crash after preparation resumes the same attempt; a completed exact
    /// result is replayed without invoking the authority again.
    pub fn materialize_deferred_child_one<
        A: SettlementDeferredChildAuthorityV1,
        F: FnOnce() -> Result<u64>,
    >(
        &mut self,
        lease: CoordinatorLeaseV1,
        authority: &mut A,
        now_unix_ms: u64,
        post_authority_time: F,
    ) -> Result<SettlementPlanViewV1> {
        let materializer_authority_id = authority.authority_id();
        validate_digest(materializer_authority_id)?;
        self.load_plan(lease.plan_id)?;
        let preflight = decode_plan_row(&load_plan_row(&self.connection, lease.plan_id)?)?;
        let SettlementChildrenV1::FirstExposureStaged {
            deferred: preflight_deferred,
            ..
        } = preflight.child_layout()
        else {
            return Err(CoordinatorErrorV1::InvalidState);
        };
        if preflight_deferred.materializer_authority_id != materializer_authority_id {
            return Err(CoordinatorErrorV1::ChildAuthorityRefused);
        }
        let (capability, descriptor_digest, expected_plan_digest, expected_attempt_id) = {
            let transaction = self.immediate(now_unix_ms)?;
            validate_lease(&transaction, lease, now_unix_ms, true)?;
            audit_plan(&transaction, lease.plan_id)?;
            let row = load_plan_row(&transaction, lease.plan_id)?;
            let plan = decode_plan_row(&row)?;
            let SettlementChildrenV1::FirstExposureStaged { deferred, .. } = plan.child_layout()
            else {
                return Err(CoordinatorErrorV1::InvalidState);
            };
            if deferred.materializer_authority_id != materializer_authority_id {
                return Err(CoordinatorErrorV1::ChildAuthorityRefused);
            }
            let children = load_child_rows(&transaction, row.plan_id)?;
            validate_child_prefix(&children, &plan)?;
            if children.len() == MAX_SETTLEMENT_CHILDREN_V1 {
                transaction.commit().map_err(storage)?;
                return self.load_plan(row.plan_id);
            }
            let exposure = public_exposure(&row)?.ok_or(CoordinatorErrorV1::InvalidState)?;
            if row.stage != AGGREGATE_ACTIVE
                || row.secret_state != SECRET_PUBLIC
                || children.len() != 1
                || children[0].child_index != 0
                || children[0].stage < CHILD_EXTERNALIZED
                || exposure.child_index != 0
                || exposure.evidence_digest == ZERO_DIGEST
            {
                return Err(CoordinatorErrorV1::InvalidState);
            }
            let descriptor_digest = deferred_child_digest(deferred);
            let exposure_digest = deferred_exposure_digest(&exposure);
            let attempt_id = deferred_attempt_id(row.plan_id, descriptor_digest, exposure_digest);
            let existing = transaction
                .query_row(
                    "SELECT attempt_id,descriptor_digest,exposure_evidence,route_fence_be,
                            coordinator_fence_be,record_digest,state_tag
                     FROM deferred_child_materializations WHERE plan_id=?1",
                    params![row.plan_id.as_slice()],
                    |record| {
                        Ok((
                            record.get::<_, Vec<u8>>(0)?,
                            record.get::<_, Vec<u8>>(1)?,
                            record.get::<_, Vec<u8>>(2)?,
                            record.get::<_, Vec<u8>>(3)?,
                            record.get::<_, Vec<u8>>(4)?,
                            record.get::<_, Vec<u8>>(5)?,
                            record.get::<_, i64>(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(storage)?;
            if let Some((
                stored_attempt,
                stored_descriptor,
                stored_exposure,
                stored_route_fence,
                stored_coordinator_fence,
                stored_record,
                state,
            )) = existing
            {
                let stored_route_fence = blob_u64(stored_route_fence)?;
                let stored_coordinator_fence = blob_u64(stored_coordinator_fence)?;
                if blob32(stored_attempt)? != attempt_id
                    || blob32(stored_descriptor)? != descriptor_digest
                    || blob32(stored_exposure)? != exposure.evidence_digest
                    || blob32(stored_record)?
                        != deferred_pending_record_digest(
                            row.plan_id,
                            attempt_id,
                            descriptor_digest,
                            &exposure,
                            stored_route_fence,
                            stored_coordinator_fence,
                        )
                    || state != 1
                {
                    return Err(CoordinatorErrorV1::IdempotencyConflict);
                }
            } else {
                let record_digest = deferred_pending_record_digest(
                    row.plan_id,
                    attempt_id,
                    descriptor_digest,
                    &exposure,
                    lease.route_fencing_epoch,
                    lease.coordinator_fencing_epoch,
                );
                transaction
                    .execute(
                        "INSERT INTO deferred_child_materializations(
                            plan_id,attempt_id,descriptor_digest,exposure_evidence,
                            route_fence_be,coordinator_fence_be,record_digest,state_tag,
                            chain_id,expected_tx_id,intent_digest,custody_digest,
                            created_at_be,completed_at_be)
                         VALUES(?1,?2,?3,?4,?5,?6,?7,1,NULL,NULL,NULL,NULL,?8,NULL)",
                        params![
                            row.plan_id.as_slice(),
                            attempt_id.as_slice(),
                            descriptor_digest.as_slice(),
                            exposure.evidence_digest.as_slice(),
                            u64_blob(lease.route_fencing_epoch),
                            u64_blob(lease.coordinator_fencing_epoch),
                            record_digest.as_slice(),
                            u64_blob(now_unix_ms),
                        ],
                    )
                    .map_err(storage)?;
                append_next_journal(
                    &transaction,
                    JournalEventV1 {
                        plan_id: row.plan_id,
                        event_tag: 13,
                        event_id: attempt_id,
                        event_digest: record_digest,
                        route_fence: lease.route_fencing_epoch,
                        coordinator_fence: lease.coordinator_fencing_epoch,
                    },
                    now_unix_ms,
                )?;
            }
            let capability = DeferredChildMaterializationCapabilityV1 {
                route_id: row.route_id,
                plan_id: row.plan_id,
                plan_digest: row.plan_digest,
                attempt_id,
                bindings: plan.bindings().clone(),
                descriptor: deferred.clone(),
                exposure,
            };
            transaction.commit().map_err(storage)?;
            (capability, descriptor_digest, row.plan_digest, attempt_id)
        };

        let materialized = authority
            .materialize_deferred_child(capability)
            .map_err(|_| CoordinatorErrorV1::ChildAuthorityRefused)?;
        if authority.authority_id() != materializer_authority_id
            || materialized.authority_id() != materializer_authority_id
            || materialized.attempt_id() != expected_attempt_id
        {
            return Err(CoordinatorErrorV1::ChildAuthorityRefused);
        }
        let exact = materialized.into_child();
        exact.validate()?;
        let post_authority_now = post_authority_time()?;
        let transaction = self.immediate(post_authority_now)?;
        validate_lease(&transaction, lease, post_authority_now, true)?;
        audit_plan(&transaction, lease.plan_id)?;
        let row = load_plan_row(&transaction, lease.plan_id)?;
        let plan = decode_plan_row(&row)?;
        let SettlementChildrenV1::FirstExposureStaged { deferred, .. } = plan.child_layout() else {
            return Err(CoordinatorErrorV1::InvalidState);
        };
        let exposure = public_exposure(&row)?.ok_or(CoordinatorErrorV1::InvalidState)?;
        let children = load_child_rows(&transaction, row.plan_id)?;
        let attempt_id = deferred_attempt_id(
            row.plan_id,
            descriptor_digest,
            deferred_exposure_digest(&exposure),
        );
        if row.plan_digest != expected_plan_digest
            || row.stage != AGGREGATE_ACTIVE
            || row.secret_state != SECRET_PUBLIC
            || exposure.child_index != 0
            || children.len() != 1
            || children[0].child_index != 0
            || children[0].stage < CHILD_EXTERNALIZED
            || deferred_child_digest(deferred) != descriptor_digest
            || deferred.materializer_authority_id != materializer_authority_id
            || exact.face != deferred.face
            || exact.exposure != ChildExposureV1::UsesPublicSecret
            || exact.chain_id != deferred.chain_id
        {
            return Err(CoordinatorErrorV1::ChildReceiptMismatch);
        }
        let (retained_state, pending_record): (i64, Vec<u8>) = transaction
            .query_row(
                "SELECT state_tag,record_digest FROM deferred_child_materializations
                 WHERE plan_id=?1 AND attempt_id=?2 AND descriptor_digest=?3
                   AND exposure_evidence=?4",
                params![
                    row.plan_id.as_slice(),
                    attempt_id.as_slice(),
                    descriptor_digest.as_slice(),
                    exposure.evidence_digest.as_slice(),
                ],
                |record| Ok((record.get(0)?, record.get(1)?)),
            )
            .map_err(storage)?;
        let pending_record = blob32(pending_record)?;
        if retained_state != 1 {
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        transaction
            .execute(
                "INSERT INTO settlement_children(
                    plan_id,child_index,face_tag,exposure_tag,chain_id,expected_tx_id,
                    intent_digest,custody_digest,stage_tag,call_attempt_be,pending_attempt_id,
                    pending_call_digest,last_ambiguity_evidence,externalization_evidence,
                    finality_evidence,reorg_evidence,reconciliation_attempt_id,reconciliation_record_digest)
                 VALUES(?1,1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
                params![
                    row.plan_id.as_slice(),
                    i64::from(exact.face.tag()),
                    i64::from(exact.exposure.tag()),
                    exact.chain_id.as_slice(),
                    exact.expected_transaction_id.as_slice(),
                    exact.intent_digest.as_slice(),
                    exact.custody_digest.as_slice(),
                    CHILD_PLANNED,
                    u64_blob(0),
                ],
            )
            .map_err(storage)?;
        let changed = transaction
            .execute(
                "UPDATE deferred_child_materializations SET state_tag=2,chain_id=?2,
                    expected_tx_id=?3,intent_digest=?4,custody_digest=?5,completed_at_be=?6,
                    completed_route_fence_be=?7,completed_coordinator_fence_be=?8
                 WHERE plan_id=?1 AND state_tag=1 AND attempt_id=?9 AND record_digest=?10",
                params![
                    row.plan_id.as_slice(),
                    exact.chain_id.as_slice(),
                    exact.expected_transaction_id.as_slice(),
                    exact.intent_digest.as_slice(),
                    exact.custody_digest.as_slice(),
                    u64_blob(post_authority_now),
                    u64_blob(lease.route_fencing_epoch),
                    u64_blob(lease.coordinator_fencing_epoch),
                    attempt_id.as_slice(),
                    pending_record.as_slice(),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        append_next_journal(
            &transaction,
            JournalEventV1 {
                plan_id: row.plan_id,
                event_tag: 14,
                event_id: deferred_complete_event_id(attempt_id),
                event_digest: deferred_complete_record_digest(
                    attempt_id,
                    pending_record,
                    &exact,
                    lease.route_fencing_epoch,
                    lease.coordinator_fencing_epoch,
                ),
                route_fence: lease.route_fencing_epoch,
                coordinator_fence: lease.coordinator_fencing_epoch,
            },
            post_authority_now,
        )?;
        transaction.commit().map_err(storage)?;
        self.load_plan(row.plan_id)
    }

    /// Resolve the current plan by the exact route effect. A historical effect
    /// is reported as stale rather than silently resolving to a writable plan.
    pub fn load_plan_for_effect(&self, effect_id: Digest32) -> Result<StoredSettlementPlanV1> {
        validate_digest(effect_id)?;
        self.audit_storage()?;
        let current = self
            .connection
            .query_row(
                "SELECT plan_id FROM settlement_plans WHERE effect_id=?1",
                params![effect_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(storage)?;
        match current {
            Some(plan_id) => self.load_stored_plan(blob32(plan_id)?),
            None => {
                let historical: i64 = self
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM settlement_plan_versions WHERE effect_id=?1",
                        params![effect_id.as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(storage)?;
                if historical > 0 {
                    Err(CoordinatorErrorV1::StaleFencing)
                } else {
                    Err(CoordinatorErrorV1::PlanNotFound)
                }
            }
        }
    }

    /// Resolve an older current plan for an exact stable replacement.
    ///
    /// The lookup derives the stable aggregate action and custody commitments
    /// inside the coordinator. It then fully audits the retained plan and
    /// requires semantic equivalence that ignores only the route-derived
    /// effect and fencing generation. This is intended for the narrow crash
    /// boundary where a parent route advances its fence after durably
    /// installing, but before committing, the corresponding action.
    pub fn load_plan_for_stable_replacement(
        &self,
        replacement: &CompositeSettlementPlanV1,
    ) -> Result<StoredSettlementPlanV1> {
        replacement.validate()?;
        let expected_plan_id = stable_plan_id(replacement)?;
        let expected_action = aggregate_action_id(replacement)?;
        let expected_custody = aggregate_custody_digest(replacement)?;
        let stored = self.load_plan_for_aggregate(expected_action, expected_custody)?;
        if stored.view().plan_id != expected_plan_id
            || !stable_plan_equivalent(stored.plan(), replacement)?
        {
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        Ok(stored)
    }

    /// Resolve a plan by its stable aggregate action identity. This lookup is
    /// intended for finality/reorg observations that carry no custody digest;
    /// dispatch and refencing should use the stricter aggregate pair lookup.
    pub fn load_plan_for_aggregate_action(
        &self,
        aggregate_action_id: Digest32,
    ) -> Result<StoredSettlementPlanV1> {
        validate_digest(aggregate_action_id)?;
        self.audit_storage()?;
        let plan_id = self
            .connection
            .query_row(
                "SELECT plan_id FROM settlement_plans WHERE aggregate_action_id=?1",
                params![aggregate_action_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or(CoordinatorErrorV1::PlanNotFound)?;
        self.load_stored_plan(blob32(plan_id)?)
    }

    /// Resolve a plan across effect/fence changes using both stable aggregate
    /// commitments. Matching only one side is an idempotency conflict.
    pub fn load_plan_for_aggregate(
        &self,
        aggregate_action_id: Digest32,
        aggregate_custody_digest: Digest32,
    ) -> Result<StoredSettlementPlanV1> {
        validate_digest(aggregate_action_id)?;
        validate_digest(aggregate_custody_digest)?;
        self.audit_storage()?;
        let exact = self
            .connection
            .query_row(
                "SELECT plan_id FROM settlement_plans
                 WHERE aggregate_action_id=?1 AND aggregate_custody_digest=?2",
                params![
                    aggregate_action_id.as_slice(),
                    aggregate_custody_digest.as_slice()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(storage)?;
        if let Some(plan_id) = exact {
            return self.load_stored_plan(blob32(plan_id)?);
        }
        let partial: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM settlement_plans
                 WHERE aggregate_action_id=?1 OR aggregate_custody_digest=?2",
                params![
                    aggregate_action_id.as_slice(),
                    aggregate_custody_digest.as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if partial > 0 {
            Err(CoordinatorErrorV1::IdempotencyConflict)
        } else {
            Err(CoordinatorErrorV1::PlanNotFound)
        }
    }

    fn load_stored_plan(&self, plan_id: Digest32) -> Result<StoredSettlementPlanV1> {
        let view = self.load_plan(plan_id)?;
        if view.stage == AggregateStageV1::FailedClosed {
            return Err(CoordinatorErrorV1::FailedClosed);
        }
        let row = load_plan_row(&self.connection, plan_id)?;
        let plan = decode_plan_row(&row)?;
        if plan.bindings().effect_id != view.effect_id
            || plan.bindings().fencing_epoch != view.fencing_epoch
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        Ok(StoredSettlementPlanV1 { plan, view })
    }

    /// Acquire normal ownership under the exact current route fence.
    pub fn acquire_lease(
        &mut self,
        plan_id: Digest32,
        owner_id: Digest32,
        route_fencing_epoch: u64,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<CoordinatorLeaseAcquireV1> {
        validate_digest(owner_id)?;
        validate_lease_bound(now_unix_ms, lease_duration_ms)?;
        let transaction = self.immediate(now_unix_ms)?;
        let plan = load_plan_row(&transaction, plan_id)?;
        if plan.stage == AGGREGATE_FAILED_CLOSED {
            return Err(CoordinatorErrorV1::FailedClosed);
        }
        if route_fencing_epoch != plan.route_fence {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        let outcome = acquire_lease_row(
            &transaction,
            plan_id,
            owner_id,
            route_fencing_epoch,
            None,
            now_unix_ms,
            lease_duration_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Acquire takeover ownership under a strictly newer route fence. The
    /// route authority's nonzero takeover evidence is retained before any
    /// child reconciliation call.
    pub fn acquire_takeover_lease(
        &mut self,
        plan_id: Digest32,
        owner_id: Digest32,
        new_route_fencing_epoch: u64,
        takeover_evidence_digest: Digest32,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<CoordinatorLeaseAcquireV1> {
        validate_digest(owner_id)?;
        validate_digest(takeover_evidence_digest)?;
        validate_lease_bound(now_unix_ms, lease_duration_ms)?;
        let transaction = self.immediate(now_unix_ms)?;
        let plan = load_plan_row(&transaction, plan_id)?;
        if plan.stage == AGGREGATE_FAILED_CLOSED {
            return Err(CoordinatorErrorV1::FailedClosed);
        }
        if new_route_fencing_epoch <= plan.route_fence {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        let outcome = acquire_lease_row(
            &transaction,
            plan_id,
            owner_id,
            new_route_fencing_epoch,
            Some(takeover_evidence_digest),
            now_unix_ms,
            lease_duration_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Resumes the exact takeover generation already retained for this owner
    /// and route fence.
    ///
    /// This is intentionally narrower than [`Self::acquire_takeover_lease`]:
    /// it cannot introduce a new owner, route fence, or takeover evidence. A
    /// live lease is extended in place. An expired lease for the same
    /// owner/fence receives a new coordinator fencing generation so an older
    /// in-process capability stays stale. The plan must still precede the
    /// takeover route fence; after refencing callers use [`Self::acquire_lease`].
    pub fn resume_takeover_lease(
        &mut self,
        plan_id: Digest32,
        owner_id: Digest32,
        route_fencing_epoch: u64,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<CoordinatorLeaseAcquireV1> {
        validate_digest(owner_id)?;
        validate_lease_bound(now_unix_ms, lease_duration_ms)?;
        let lease_until = now_unix_ms
            .checked_add(lease_duration_ms)
            .ok_or(CoordinatorErrorV1::InvalidBound)?;
        let transaction = self.immediate(now_unix_ms)?;
        let plan = load_plan_row(&transaction, plan_id)?;
        if plan.stage == AGGREGATE_FAILED_CLOSED {
            return Err(CoordinatorErrorV1::FailedClosed);
        }
        if route_fencing_epoch <= plan.route_fence {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        let retained = transaction
            .query_row(
                "SELECT owner_id,route_fence_be,coordinator_fence_be,lease_until_be,
                        takeover_evidence
                 FROM coordinator_leases WHERE plan_id=?1",
                params![plan_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or(CoordinatorErrorV1::StaleFencing)?;
        let stored_owner = blob32(retained.0)?;
        let stored_route = blob_u64(retained.1)?;
        let stored_coordinator = blob_u64(retained.2)?;
        let stored_until = blob_u64(retained.3)?;
        let takeover_evidence = retained
            .4
            .map(blob32)
            .transpose()?
            .ok_or(CoordinatorErrorV1::StaleFencing)?;
        if stored_owner != owner_id
            || stored_route != route_fencing_epoch
            || takeover_evidence == ZERO_DIGEST
        {
            return Err(CoordinatorErrorV1::StaleFencing);
        }

        let (classification, coordinator_fence, until) = if stored_until >= now_unix_ms {
            (false, stored_coordinator, stored_until.max(lease_until))
        } else {
            (
                true,
                stored_coordinator
                    .checked_add(1)
                    .ok_or(CoordinatorErrorV1::InvalidBound)?,
                lease_until,
            )
        };
        let changed = transaction
            .execute(
                "UPDATE coordinator_leases SET coordinator_fence_be=?2,lease_until_be=?3,
                        updated_at_be=?4
                 WHERE plan_id=?1 AND owner_id=?5 AND route_fence_be=?6
                   AND coordinator_fence_be=?7 AND takeover_evidence=?8",
                params![
                    plan_id.as_slice(),
                    u64_blob(coordinator_fence),
                    u64_blob(until),
                    u64_blob(now_unix_ms),
                    owner_id.as_slice(),
                    u64_blob(route_fencing_epoch),
                    u64_blob(stored_coordinator),
                    takeover_evidence.as_slice(),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        let lease = CoordinatorLeaseV1 {
            plan_id,
            owner_id,
            route_fencing_epoch,
            coordinator_fencing_epoch: coordinator_fence,
            lease_until_unix_ms: until,
        };
        transaction.commit().map_err(storage)?;
        if classification {
            Ok(CoordinatorLeaseAcquireV1::Acquired(lease))
        } else {
            Ok(CoordinatorLeaseAcquireV1::AlreadyOwned(lease))
        }
    }

    /// Renew the exact live coordinator fencing generation.
    pub fn renew_lease(
        &mut self,
        lease: CoordinatorLeaseV1,
        now_unix_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<CoordinatorLeaseV1> {
        validate_lease_bound(now_unix_ms, lease_duration_ms)?;
        let until = now_unix_ms
            .checked_add(lease_duration_ms)
            .ok_or(CoordinatorErrorV1::InvalidBound)?;
        let transaction = self.immediate(now_unix_ms)?;
        validate_lease(&transaction, lease, now_unix_ms, false)?;
        let changed = transaction
            .execute(
                "UPDATE coordinator_leases SET lease_until_be=?2,updated_at_be=?3
                 WHERE plan_id=?1 AND owner_id=?4 AND route_fence_be=?5 AND coordinator_fence_be=?6",
                params![
                    lease.plan_id.as_slice(), u64_blob(until), u64_blob(now_unix_ms),
                    lease.owner_id.as_slice(), u64_blob(lease.route_fencing_epoch),
                    u64_blob(lease.coordinator_fencing_epoch),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        transaction.commit().map_err(storage)?;
        Ok(CoordinatorLeaseV1 {
            lease_until_unix_ms: until,
            ..lease
        })
    }

    fn immediate(&mut self, now_unix_ms: u64) -> Result<Transaction<'_>> {
        self.audit_storage()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        advance_clock(&transaction, now_unix_ms)?;
        Ok(transaction)
    }

    fn audit_storage(&self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or(CoordinatorErrorV1::InvalidStorageAuthority)?;
        validate_owner_directory(parent)?;
        validate_open_file_identity(&self.database_authority, &self.path)?;
        validate_open_file_identity(&self._process_lock, &process_lock_path(&self.path))?;
        if self
            ._process_lock
            .metadata()
            .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?
            .len()
            != 0
        {
            return Err(CoordinatorErrorV1::InvalidStorageAuthority);
        }
        validate_database_path(&self.connection, &self.path)?;
        validate_backend_and_schema(&self.connection)?;
        validate_owner_file(&self.path)?;
        validate_resumable_sidecars(&self.path)?;
        let retained: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = self
            .connection
            .query_row(
                "SELECT coordinator_id,plan_authority_id,clock_high_water_be,created_at_be
                 FROM coordinator_metadata WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| CoordinatorErrorV1::CorruptState)?;
        let metadata_count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM coordinator_metadata", [], |row| {
                row.get(0)
            })
            .map_err(|_| CoordinatorErrorV1::CorruptState)?;
        if blob32(retained.0)? != self.coordinator_id
            || blob32(retained.1)? != self.plan_authority_id
        {
            return Err(CoordinatorErrorV1::InvalidStorageAuthority);
        }
        if metadata_count != 1 || blob_u64(retained.2)? < blob_u64(retained.3)? {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        Ok(())
    }

    fn audit_all_plans(&self) -> Result<()> {
        let mut statement = self
            .connection
            .prepare("SELECT plan_id FROM settlement_plans ORDER BY plan_id LIMIT 4097")
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(storage)?;
        let mut plan_ids = Vec::new();
        for row in rows {
            plan_ids.push(blob32(row.map_err(storage)?)?);
        }
        if plan_ids.len() > 4096 {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        drop(statement);
        for plan_id in plan_ids {
            audit_plan(&self.connection, plan_id)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct PlanRow {
    plan_id: Digest32,
    plan_digest: Digest32,
    route_id: Digest32,
    effect_id: Digest32,
    settlement_id: Digest32,
    route_fence: u64,
    plan_bytes: Vec<u8>,
    authorization_evidence: Digest32,
    aggregate_action_id: Digest32,
    aggregate_custody_digest: Digest32,
    stage: i64,
    secret_state: i64,
    revision: u64,
    journal_head: Digest32,
    first_exposure_child: Option<u8>,
    first_exposure_chain: Option<Digest32>,
    first_exposure_tx: Option<Digest32>,
    first_exposure_evidence: Option<Digest32>,
    first_exposure_observed_at: Option<u64>,
    aggregate_receipt_digest: Option<Digest32>,
    aggregate_finality_digest: Option<Digest32>,
    aggregate_reorg_digest: Option<Digest32>,
}

struct RawPlanRow {
    plan_id: Vec<u8>,
    plan_digest: Vec<u8>,
    route_id: Vec<u8>,
    effect_id: Vec<u8>,
    settlement_id: Vec<u8>,
    route_fence: Vec<u8>,
    plan_bytes: Vec<u8>,
    authorization_evidence: Vec<u8>,
    aggregate_action_id: Vec<u8>,
    aggregate_custody_digest: Vec<u8>,
    stage: i64,
    secret_state: i64,
    revision: Vec<u8>,
    journal_head: Vec<u8>,
    first_exposure_child: Option<i64>,
    first_exposure_chain: Option<Vec<u8>>,
    first_exposure_tx: Option<Vec<u8>>,
    first_exposure_evidence: Option<Vec<u8>>,
    first_exposure_observed_at: Option<Vec<u8>>,
    aggregate_receipt_digest: Option<Vec<u8>>,
    aggregate_finality_digest: Option<Vec<u8>>,
    aggregate_reorg_digest: Option<Vec<u8>>,
}

impl RawPlanRow {
    fn decode(self) -> Result<PlanRow> {
        Ok(PlanRow {
            plan_id: blob32(self.plan_id)?,
            plan_digest: blob32(self.plan_digest)?,
            route_id: blob32(self.route_id)?,
            effect_id: blob32(self.effect_id)?,
            settlement_id: blob32(self.settlement_id)?,
            route_fence: blob_u64(self.route_fence)?,
            plan_bytes: self.plan_bytes,
            authorization_evidence: blob32(self.authorization_evidence)?,
            aggregate_action_id: blob32(self.aggregate_action_id)?,
            aggregate_custody_digest: blob32(self.aggregate_custody_digest)?,
            stage: self.stage,
            secret_state: self.secret_state,
            revision: blob_u64(self.revision)?,
            journal_head: blob32(self.journal_head)?,
            first_exposure_child: self
                .first_exposure_child
                .map(|value| u8::try_from(value).map_err(|_| CoordinatorErrorV1::CorruptState))
                .transpose()?,
            first_exposure_chain: self.first_exposure_chain.map(blob32).transpose()?,
            first_exposure_tx: self.first_exposure_tx.map(blob32).transpose()?,
            first_exposure_evidence: self.first_exposure_evidence.map(blob32).transpose()?,
            first_exposure_observed_at: self
                .first_exposure_observed_at
                .map(blob_u64)
                .transpose()?,
            aggregate_receipt_digest: self.aggregate_receipt_digest.map(blob32).transpose()?,
            aggregate_finality_digest: self.aggregate_finality_digest.map(blob32).transpose()?,
            aggregate_reorg_digest: self.aggregate_reorg_digest.map(blob32).transpose()?,
        })
    }
}

#[derive(Clone)]
struct ChildRow {
    child_index: u8,
    face: SettlementFaceV1,
    exposure: ChildExposureV1,
    chain_id: Digest32,
    expected_tx_id: Digest32,
    intent_digest: Digest32,
    custody_digest: Digest32,
    stage: i64,
    call_attempt: u64,
    pending_attempt_id: Option<Digest32>,
    pending_call_digest: Option<Digest32>,
    last_ambiguity_evidence: Option<Digest32>,
    externalization_evidence: Option<Digest32>,
    finality_evidence: Option<Digest32>,
    reorg_evidence: Option<Digest32>,
    reconciliation_attempt_id: Option<Digest32>,
    reconciliation_record_digest: Option<Digest32>,
}

struct RawChildRow {
    child_index: i64,
    face: i64,
    exposure: i64,
    chain_id: Vec<u8>,
    expected_tx_id: Vec<u8>,
    intent_digest: Vec<u8>,
    custody_digest: Vec<u8>,
    stage: i64,
    call_attempt: Vec<u8>,
    pending_attempt_id: Option<Vec<u8>>,
    pending_call_digest: Option<Vec<u8>>,
    last_ambiguity_evidence: Option<Vec<u8>>,
    externalization_evidence: Option<Vec<u8>>,
    finality_evidence: Option<Vec<u8>>,
    reorg_evidence: Option<Vec<u8>>,
    reconciliation_attempt_id: Option<Vec<u8>>,
    reconciliation_record_digest: Option<Vec<u8>>,
}

struct PendingReconciliationRow {
    attempt_id: Digest32,
    dispatch_attempt_id: Digest32,
    sequence: u64,
    scope_tag: i64,
    route_fence: u64,
    coordinator_fence: u64,
    prior_outcome_digest: Digest32,
    request_digest: Digest32,
}

struct AuditReconciliationRow {
    child_index: u8,
    dispatch_attempt_id: Digest32,
    sequence: u64,
    scope_tag: i64,
    route_fence: u64,
    coordinator_fence: u64,
    prior_outcome_digest: Digest32,
    attempt_id: Digest32,
    request_digest: Digest32,
    outcome_tag: Option<i64>,
    outcome_digest: Option<Digest32>,
    outcome_evidence: Option<Digest32>,
    created_at: u64,
    completed_at: Option<u64>,
}

struct AuditChildCallOutcomeRow {
    child_index: u8,
    attempt_id: Digest32,
    prepared_sequence: u64,
    outcome_tag: i64,
    outcome_digest: Digest32,
}

struct RawDeferredMaterializationAuditRow {
    attempt_id: Vec<u8>,
    descriptor_digest: Vec<u8>,
    exposure_evidence: Vec<u8>,
    route_fence: Vec<u8>,
    coordinator_fence: Vec<u8>,
    record_digest: Vec<u8>,
    state: i64,
    created_at: Vec<u8>,
    completed_at: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum DerivedAmbiguityV1 {
    None,
    OriginalUnknown(Digest32),
    Evidence(Digest32),
}

#[derive(Clone, Copy)]
enum DerivedChildAttemptStateV1 {
    Planned(DerivedAmbiguityV1),
    Pending {
        ambiguity: DerivedAmbiguityV1,
        reconciliation: Option<(Digest32, Digest32)>,
    },
    Externalized,
}

impl RawChildRow {
    fn decode(self) -> Result<ChildRow> {
        let child_index =
            u8::try_from(self.child_index).map_err(|_| CoordinatorErrorV1::CorruptState)?;
        if usize::from(child_index) >= MAX_SETTLEMENT_CHILDREN_V1 {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        let face = u8::try_from(self.face).map_err(|_| CoordinatorErrorV1::CorruptState)?;
        let exposure = u8::try_from(self.exposure).map_err(|_| CoordinatorErrorV1::CorruptState)?;
        Ok(ChildRow {
            child_index,
            face: SettlementFaceV1::from_tag(face).map_err(|_| CoordinatorErrorV1::CorruptState)?,
            exposure: ChildExposureV1::from_tag(exposure)
                .map_err(|_| CoordinatorErrorV1::CorruptState)?,
            chain_id: blob32(self.chain_id)?,
            expected_tx_id: blob32(self.expected_tx_id)?,
            intent_digest: blob32(self.intent_digest)?,
            custody_digest: blob32(self.custody_digest)?,
            stage: self.stage,
            call_attempt: blob_u64(self.call_attempt)?,
            pending_attempt_id: self.pending_attempt_id.map(blob32).transpose()?,
            pending_call_digest: self.pending_call_digest.map(blob32).transpose()?,
            last_ambiguity_evidence: self.last_ambiguity_evidence.map(blob32).transpose()?,
            externalization_evidence: self.externalization_evidence.map(blob32).transpose()?,
            finality_evidence: self.finality_evidence.map(blob32).transpose()?,
            reorg_evidence: self.reorg_evidence.map(blob32).transpose()?,
            reconciliation_attempt_id: self.reconciliation_attempt_id.map(blob32).transpose()?,
            reconciliation_record_digest: self
                .reconciliation_record_digest
                .map(blob32)
                .transpose()?,
        })
    }
}

const PLAN_COLUMNS: &str = "plan_id,plan_digest,route_id,effect_id,settlement_id,route_fence_be,plan_bytes,authorization_evidence,aggregate_action_id,aggregate_custody_digest,stage_tag,secret_state_tag,revision_be,journal_head,first_exposure_child,first_exposure_chain,first_exposure_tx,first_exposure_evidence,first_exposure_observed_at_be,aggregate_receipt_digest,aggregate_finality_digest,aggregate_reorg_digest";
const CHILD_COLUMNS: &str = "child_index,face_tag,exposure_tag,chain_id,expected_tx_id,intent_digest,custody_digest,stage_tag,call_attempt_be,pending_attempt_id,pending_call_digest,last_ambiguity_evidence,externalization_evidence,finality_evidence,reorg_evidence,reconciliation_attempt_id,reconciliation_record_digest";

fn raw_plan_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawPlanRow> {
    Ok(RawPlanRow {
        plan_id: row.get(0)?,
        plan_digest: row.get(1)?,
        route_id: row.get(2)?,
        effect_id: row.get(3)?,
        settlement_id: row.get(4)?,
        route_fence: row.get(5)?,
        plan_bytes: row.get(6)?,
        authorization_evidence: row.get(7)?,
        aggregate_action_id: row.get(8)?,
        aggregate_custody_digest: row.get(9)?,
        stage: row.get(10)?,
        secret_state: row.get(11)?,
        revision: row.get(12)?,
        journal_head: row.get(13)?,
        first_exposure_child: row.get(14)?,
        first_exposure_chain: row.get(15)?,
        first_exposure_tx: row.get(16)?,
        first_exposure_evidence: row.get(17)?,
        first_exposure_observed_at: row.get(18)?,
        aggregate_receipt_digest: row.get(19)?,
        aggregate_finality_digest: row.get(20)?,
        aggregate_reorg_digest: row.get(21)?,
    })
}

fn raw_child_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawChildRow> {
    Ok(RawChildRow {
        child_index: row.get(0)?,
        face: row.get(1)?,
        exposure: row.get(2)?,
        chain_id: row.get(3)?,
        expected_tx_id: row.get(4)?,
        intent_digest: row.get(5)?,
        custody_digest: row.get(6)?,
        stage: row.get(7)?,
        call_attempt: row.get(8)?,
        pending_attempt_id: row.get(9)?,
        pending_call_digest: row.get(10)?,
        last_ambiguity_evidence: row.get(11)?,
        externalization_evidence: row.get(12)?,
        finality_evidence: row.get(13)?,
        reorg_evidence: row.get(14)?,
        reconciliation_attempt_id: row.get(15)?,
        reconciliation_record_digest: row.get(16)?,
    })
}

fn load_plan_row(connection: &Connection, plan_id: Digest32) -> Result<PlanRow> {
    load_plan_row_optional(connection, plan_id)?.ok_or(CoordinatorErrorV1::PlanNotFound)
}

fn load_plan_row_optional(connection: &Connection, plan_id: Digest32) -> Result<Option<PlanRow>> {
    validate_digest(plan_id)?;
    let sql = format!("SELECT {PLAN_COLUMNS} FROM settlement_plans WHERE plan_id=?1");
    connection
        .query_row(&sql, params![plan_id.as_slice()], raw_plan_from_row)
        .optional()
        .map_err(storage)?
        .map(RawPlanRow::decode)
        .transpose()
}

fn load_child_rows(connection: &Connection, plan_id: Digest32) -> Result<Vec<ChildRow>> {
    let sql = format!(
        "SELECT {CHILD_COLUMNS} FROM settlement_children WHERE plan_id=?1 ORDER BY child_index"
    );
    let mut statement = connection.prepare(&sql).map_err(storage)?;
    let rows = statement
        .query_map(params![plan_id.as_slice()], raw_child_from_row)
        .map_err(storage)?;
    let mut children = Vec::with_capacity(MAX_SETTLEMENT_CHILDREN_V1);
    for row in rows {
        children.push(row.map_err(storage)?.decode()?);
    }
    if children.is_empty() || children.len() > MAX_SETTLEMENT_CHILDREN_V1 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(children)
}

fn load_child_row(connection: &Connection, plan_id: Digest32, child_index: u8) -> Result<ChildRow> {
    if usize::from(child_index) >= MAX_SETTLEMENT_CHILDREN_V1 {
        return Err(CoordinatorErrorV1::InvalidBound);
    }
    let sql = format!(
        "SELECT {CHILD_COLUMNS} FROM settlement_children WHERE plan_id=?1 AND child_index=?2"
    );
    connection
        .query_row(
            &sql,
            params![plan_id.as_slice(), i64::from(child_index)],
            raw_child_from_row,
        )
        .optional()
        .map_err(storage)?
        .ok_or(CoordinatorErrorV1::CorruptState)?
        .decode()
}

fn load_pending_reconciliation(
    connection: &Connection,
    plan_id: Digest32,
    child_index: u8,
) -> Result<Option<PendingReconciliationRow>> {
    connection
        .query_row(
            "SELECT reconciliation_attempt_id,dispatch_attempt_id,sequence_be,scope_tag,
                    route_fence_be,coordinator_fence_be,prior_outcome_digest,request_digest
             FROM child_reconciliation_calls
             WHERE plan_id=?1 AND child_index=?2 AND outcome_digest IS NULL",
            params![plan_id.as_slice(), i64::from(child_index)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?
        .map(
            |(attempt, dispatch, sequence, scope, route, coordinator, prior, request)| {
                Ok(PendingReconciliationRow {
                    attempt_id: blob32(attempt)?,
                    dispatch_attempt_id: blob32(dispatch)?,
                    sequence: blob_u64(sequence)?,
                    scope_tag: scope,
                    route_fence: blob_u64(route)?,
                    coordinator_fence: blob_u64(coordinator)?,
                    prior_outcome_digest: blob32(prior)?,
                    request_digest: blob32(request)?,
                })
            },
        )
        .transpose()
}

fn decode_plan_row(row: &PlanRow) -> Result<CompositeSettlementPlanV1> {
    if row.plan_bytes.len() > MAX_PLAN_BYTES {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    CompositeSettlementPlanV1::decode_canonical(&row.plan_bytes)
        .map_err(|_| CoordinatorErrorV1::CorruptState)
}

fn validate_child_prefix(children: &[ChildRow], plan: &CompositeSettlementPlanV1) -> Result<u8> {
    let valid_count = match plan.child_layout() {
        SettlementChildrenV1::Materialized(_) => children.len() == MAX_SETTLEMENT_CHILDREN_V1,
        SettlementChildrenV1::FirstExposureStaged { .. } => matches!(children.len(), 1 | 2),
    };
    if !valid_count
        || children
            .iter()
            .enumerate()
            .any(|(index, child)| usize::from(child.child_index) != index)
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let mut completed = 0usize;
    while completed < children.len() && children[completed].stage >= CHILD_EXTERNALIZED {
        completed += 1;
    }
    if children[completed..]
        .iter()
        .any(|child| child.stage >= CHILD_EXTERNALIZED)
        || children
            .iter()
            .filter(|child| child.stage == CHILD_CALL_PENDING)
            .count()
            > 1
        || children
            .iter()
            .enumerate()
            .any(|(index, child)| child.stage == CHILD_CALL_PENDING && index != completed)
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    u8::try_from(completed).map_err(|_| CoordinatorErrorV1::CorruptState)
}

fn aggregate_stage(tag: i64) -> Result<AggregateStageV1> {
    match tag {
        AGGREGATE_ACTIVE => Ok(AggregateStageV1::Active),
        AGGREGATE_EXTERNALIZED => Ok(AggregateStageV1::Externalized),
        AGGREGATE_FINAL => Ok(AggregateStageV1::Final),
        AGGREGATE_FINALITY_INVALIDATED => Ok(AggregateStageV1::FinalityInvalidated),
        AGGREGATE_FAILED_CLOSED => Ok(AggregateStageV1::FailedClosed),
        _ => Err(CoordinatorErrorV1::CorruptState),
    }
}

fn child_stage(tag: i64) -> Result<ChildStageV1> {
    match tag {
        CHILD_PLANNED => Ok(ChildStageV1::Planned),
        CHILD_CALL_PENDING => Ok(ChildStageV1::CallPending),
        CHILD_EXTERNALIZED => Ok(ChildStageV1::Externalized),
        CHILD_FINAL => Ok(ChildStageV1::Final),
        CHILD_FINALITY_INVALIDATED => Ok(ChildStageV1::FinalityInvalidated),
        _ => Err(CoordinatorErrorV1::CorruptState),
    }
}

fn audit_plan(connection: &Connection, plan_id: Digest32) -> Result<SettlementPlanViewV1> {
    let row = load_plan_row(connection, plan_id)?;
    let plan = decode_plan_row(&row)?;
    if plan
        .canonical_digest()
        .map_err(|_| CoordinatorErrorV1::CorruptState)?
        != row.plan_digest
        || stable_plan_id(&plan).map_err(|_| CoordinatorErrorV1::CorruptState)? != row.plan_id
        || aggregate_action_id(&plan).map_err(|_| CoordinatorErrorV1::CorruptState)?
            != row.aggregate_action_id
        || aggregate_custody_digest(&plan).map_err(|_| CoordinatorErrorV1::CorruptState)?
            != row.aggregate_custody_digest
        || plan.bindings().route_id != row.route_id
        || plan.bindings().effect_id != row.effect_id
        || plan.bindings().settlement_id != row.settlement_id
        || plan.bindings().fencing_epoch != row.route_fence
        || row.authorization_evidence == ZERO_DIGEST
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }

    audit_plan_versions(connection, &row)?;
    audit_journal(connection, &row)?;
    audit_call_records(connection, &row)?;
    let children = load_child_rows(connection, plan_id)?;
    let completed_prefix = validate_child_prefix(&children, &plan)?;
    audit_deferred_materialization_state(connection, &row, &plan, &children)?;
    for child in &children {
        let exact_matches = match plan.materialized_child(usize::from(child.child_index)) {
            Some(planned) => {
                child.face == planned.face
                    && child.exposure == planned.exposure
                    && child.chain_id == planned.chain_id
                    && child.expected_tx_id == planned.expected_transaction_id
                    && child.intent_digest == planned.intent_digest
                    && child.custody_digest == planned.custody_digest
            }
            None if child.child_index == 1 => {
                audit_deferred_materialized_child(connection, &row, &plan, child)?
            }
            None => false,
        };
        if !exact_matches
            || child.call_attempt == 0 && child.stage != CHILD_PLANNED
            || child.externalization_evidence.is_some() != (child.stage >= CHILD_EXTERNALIZED)
            || child.finality_evidence.is_some() != (child.stage == CHILD_FINAL)
            || child.pending_attempt_id.is_some() != (child.stage == CHILD_CALL_PENDING)
            || child.pending_call_digest.is_some() != (child.stage == CHILD_CALL_PENDING)
            || child.reconciliation_attempt_id.is_some()
                != child.reconciliation_record_digest.is_some()
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        if child.stage == CHILD_CALL_PENDING {
            let request =
                pending_dispatch_request(connection, &row, &plan, child, child.child_index)?;
            if child.pending_attempt_id != Some(request.attempt_id)
                || child.pending_call_digest != Some(child_call_record_digest(&request))
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
    }
    audit_aggregate_state(&row, &plan, &children, completed_prefix)?;
    if row.stage != AGGREGATE_FAILED_CLOSED
        && usize::from(completed_prefix) == MAX_SETTLEMENT_CHILDREN_V1
        && row.aggregate_receipt_digest != Some(child_receipts_digest(connection, &row)?)
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    if row.stage == AGGREGATE_FINAL
        && row.aggregate_finality_digest
            != Some(expected_aggregate_finality_digest(&row, &children)?)
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }

    let first_view = child_view(&children[0])?;
    let second_view = match children.get(1) {
        Some(child) => child_view(child)?,
        None => match plan.child_layout() {
            SettlementChildrenV1::FirstExposureStaged { deferred, .. } => ChildProgressViewV1 {
                child_index: 1,
                face: deferred.face,
                exposure: ChildExposureV1::UsesPublicSecret,
                stage: ChildStageV1::Deferred,
                call_attempts: 0,
                transaction_id: None,
                externalization_evidence_digest: None,
                finality_evidence_digest: None,
                reorg_evidence_digest: None,
            },
            SettlementChildrenV1::Materialized(_) => return Err(CoordinatorErrorV1::CorruptState),
        },
    };
    let child_views = [first_view, second_view];
    Ok(SettlementPlanViewV1 {
        plan_id: row.plan_id,
        plan_digest: row.plan_digest,
        effect_id: row.effect_id,
        fencing_epoch: row.route_fence,
        stage: aggregate_stage(row.stage)?,
        revision: row.revision,
        aggregate_action_id: row.aggregate_action_id,
        aggregate_custody_digest: row.aggregate_custody_digest,
        completed_prefix,
        children: child_views,
    })
}

fn child_view(child: &ChildRow) -> Result<ChildProgressViewV1> {
    Ok(ChildProgressViewV1 {
        child_index: child.child_index,
        face: child.face,
        exposure: child.exposure,
        stage: child_stage(child.stage)?,
        call_attempts: child.call_attempt,
        transaction_id: Some(child.expected_tx_id),
        externalization_evidence_digest: child.externalization_evidence,
        finality_evidence_digest: child.finality_evidence,
        reorg_evidence_digest: child.reorg_evidence,
    })
}

fn deferred_complete_event_id(attempt_id: Digest32) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/DEFERRED-COMPLETE-EVENT/V1\0",
        &[&attempt_id],
    )
}

fn deferred_attempt_id(
    plan_id: Digest32,
    descriptor_digest: Digest32,
    exposure_digest: Digest32,
) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/DEFERRED-ATTEMPT/V1\0",
        &[&plan_id, &descriptor_digest, &exposure_digest],
    )
}

fn deferred_exposure_digest(exposure: &ChildPublicExposureV1) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/DEFERRED-EXPOSURE/V1\0",
        &[
            &[exposure.child_index],
            &exposure.chain_id,
            &exposure.transaction_id,
            &exposure.evidence_digest,
            &exposure.observed_at_unix_ms.to_be_bytes(),
        ],
    )
}

fn audit_deferred_materialization_state(
    connection: &Connection,
    row: &PlanRow,
    plan: &CompositeSettlementPlanV1,
    children: &[ChildRow],
) -> Result<()> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM deferred_child_materializations WHERE plan_id=?1",
            params![row.plan_id.as_slice()],
            |record| record.get(0),
        )
        .map_err(storage)?;
    let SettlementChildrenV1::FirstExposureStaged { deferred, .. } = plan.child_layout() else {
        return if count == 0 {
            Ok(())
        } else {
            Err(CoordinatorErrorV1::CorruptState)
        };
    };
    if count == 0 {
        return if children.len() == 1 {
            Ok(())
        } else {
            Err(CoordinatorErrorV1::CorruptState)
        };
    }
    if count != 1 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let retained = connection
        .query_row(
            "SELECT attempt_id,descriptor_digest,exposure_evidence,route_fence_be,
                    coordinator_fence_be,record_digest,state_tag,created_at_be,completed_at_be
             FROM deferred_child_materializations WHERE plan_id=?1",
            params![row.plan_id.as_slice()],
            |value| {
                Ok(RawDeferredMaterializationAuditRow {
                    attempt_id: value.get(0)?,
                    descriptor_digest: value.get(1)?,
                    exposure_evidence: value.get(2)?,
                    route_fence: value.get(3)?,
                    coordinator_fence: value.get(4)?,
                    record_digest: value.get(5)?,
                    state: value.get(6)?,
                    created_at: value.get(7)?,
                    completed_at: value.get(8)?,
                })
            },
        )
        .map_err(storage)?;
    let attempt = blob32(retained.attempt_id)?;
    let descriptor = blob32(retained.descriptor_digest)?;
    let retained_evidence = blob32(retained.exposure_evidence)?;
    let route_fence = blob_u64(retained.route_fence)?;
    let coordinator_fence = blob_u64(retained.coordinator_fence)?;
    let record = blob32(retained.record_digest)?;
    let state = retained.state;
    let created_at = blob_u64(retained.created_at)?;
    let completed_at = retained.completed_at.map(blob_u64).transpose()?;
    let exposure = public_exposure(row)?.ok_or(CoordinatorErrorV1::CorruptState)?;
    let expected_record = deferred_pending_record_digest(
        row.plan_id,
        attempt,
        descriptor,
        &exposure,
        route_fence,
        coordinator_fence,
    );
    let expected_attempt =
        deferred_attempt_id(row.plan_id, descriptor, deferred_exposure_digest(&exposure));
    let pending_journal: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT sequence_be,created_at_be FROM coordinator_journal
             WHERE plan_id=?1 AND event_id=?2 AND event_tag=13 AND event_digest=?3
               AND route_fence_be=?4 AND coordinator_fence_be=?5",
            params![
                row.plan_id.as_slice(),
                attempt.as_slice(),
                expected_record.as_slice(),
                u64_blob(route_fence),
                u64_blob(coordinator_fence),
            ],
            |journal| Ok((journal.get(0)?, journal.get(1)?)),
        )
        .map_err(storage)?;
    let pending_sequence = blob_u64(pending_journal.0)?;
    let pending_journal_at = blob_u64(pending_journal.1)?;
    if attempt != expected_attempt
        || descriptor != deferred_child_digest(deferred)
        || retained_evidence != exposure.evidence_digest
        || record != expected_record
        || pending_sequence == 0
        || pending_journal_at != created_at
        || created_at < exposure.observed_at_unix_ms
        || (state == 1 && completed_at.is_some())
        || (state == 2 && completed_at.is_none())
        || row.secret_state != SECRET_PUBLIC
        || (state == 1 && children.len() != 1)
        || (state == 2 && children.len() != 2)
        || !matches!(state, 1 | 2)
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(())
}

fn deferred_pending_record_digest(
    plan_id: Digest32,
    attempt_id: Digest32,
    descriptor_digest: Digest32,
    exposure: &ChildPublicExposureV1,
    route_fence: u64,
    coordinator_fence: u64,
) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/DEFERRED-PENDING/V1\0",
        &[
            &plan_id,
            &attempt_id,
            &descriptor_digest,
            &[exposure.child_index],
            &exposure.chain_id,
            &exposure.transaction_id,
            &exposure.evidence_digest,
            &exposure.observed_at_unix_ms.to_be_bytes(),
            &route_fence.to_be_bytes(),
            &coordinator_fence.to_be_bytes(),
        ],
    )
}

fn deferred_complete_record_digest(
    attempt_id: Digest32,
    pending_record_digest: Digest32,
    child: &SettlementChildPlanV1,
    route_fence: u64,
    coordinator_fence: u64,
) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/DEFERRED-COMPLETE/V1\0",
        &[
            &attempt_id,
            &pending_record_digest,
            &[child.face.tag()],
            &[child.exposure.tag()],
            &child.chain_id,
            &child.expected_transaction_id,
            &child.intent_digest,
            &child.custody_digest,
            &route_fence.to_be_bytes(),
            &coordinator_fence.to_be_bytes(),
        ],
    )
}

fn audit_deferred_materialized_child(
    connection: &Connection,
    row: &PlanRow,
    plan: &CompositeSettlementPlanV1,
    child: &ChildRow,
) -> Result<bool> {
    let SettlementChildrenV1::FirstExposureStaged { deferred, .. } = plan.child_layout() else {
        return Ok(false);
    };
    let retained = connection
        .query_row(
            "SELECT attempt_id,descriptor_digest,exposure_evidence,route_fence_be,
                    coordinator_fence_be,record_digest,state_tag,chain_id,expected_tx_id,
                    intent_digest,custody_digest,completed_route_fence_be,
                    completed_coordinator_fence_be,created_at_be,completed_at_be
             FROM deferred_child_materializations WHERE plan_id=?1",
            params![row.plan_id.as_slice()],
            |record| {
                Ok((
                    record.get::<_, Vec<u8>>(0)?,
                    record.get::<_, Vec<u8>>(1)?,
                    record.get::<_, Vec<u8>>(2)?,
                    record.get::<_, Vec<u8>>(3)?,
                    record.get::<_, Vec<u8>>(4)?,
                    record.get::<_, Vec<u8>>(5)?,
                    record.get::<_, i64>(6)?,
                    record.get::<_, Option<Vec<u8>>>(7)?,
                    record.get::<_, Option<Vec<u8>>>(8)?,
                    record.get::<_, Option<Vec<u8>>>(9)?,
                    record.get::<_, Option<Vec<u8>>>(10)?,
                    record.get::<_, Option<Vec<u8>>>(11)?,
                    record.get::<_, Option<Vec<u8>>>(12)?,
                    record.get::<_, Vec<u8>>(13)?,
                    record.get::<_, Option<Vec<u8>>>(14)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    let Some((
        attempt,
        descriptor,
        exposure,
        route_fence,
        coordinator_fence,
        record,
        state,
        chain,
        transaction,
        intent,
        custody,
        complete_route_fence,
        complete_coordinator_fence,
        created_at,
        completed_at,
    )) = retained
    else {
        return Ok(false);
    };
    let attempt = blob32(attempt)?;
    let descriptor = blob32(descriptor)?;
    let retained_evidence = blob32(exposure)?;
    let route_fence = blob_u64(route_fence)?;
    let coordinator_fence = blob_u64(coordinator_fence)?;
    let record = blob32(record)?;
    let created_at = blob_u64(created_at)?;
    let completed_at = blob_u64(completed_at.ok_or(CoordinatorErrorV1::CorruptState)?)?;
    let exposure = public_exposure(row)?.ok_or(CoordinatorErrorV1::CorruptState)?;
    let exact = SettlementChildPlanV1 {
        face: deferred.face,
        exposure: ChildExposureV1::UsesPublicSecret,
        chain_id: blob32(chain.ok_or(CoordinatorErrorV1::CorruptState)?)?,
        expected_transaction_id: blob32(transaction.ok_or(CoordinatorErrorV1::CorruptState)?)?,
        intent_digest: blob32(intent.ok_or(CoordinatorErrorV1::CorruptState)?)?,
        custody_digest: blob32(custody.ok_or(CoordinatorErrorV1::CorruptState)?)?,
    };
    let pending = deferred_pending_record_digest(
        row.plan_id,
        attempt,
        descriptor,
        &exposure,
        route_fence,
        coordinator_fence,
    );
    let pending_journal: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT sequence_be,created_at_be FROM coordinator_journal
             WHERE plan_id=?1 AND event_id=?2 AND event_tag=13 AND event_digest=?3
               AND route_fence_be=?4 AND coordinator_fence_be=?5",
            params![
                row.plan_id.as_slice(),
                attempt.as_slice(),
                pending.as_slice(),
                u64_blob(route_fence),
                u64_blob(coordinator_fence),
            ],
            |journal| Ok((journal.get(0)?, journal.get(1)?)),
        )
        .map_err(storage)?;
    let complete_route_fence =
        blob_u64(complete_route_fence.ok_or(CoordinatorErrorV1::CorruptState)?)?;
    let complete_coordinator_fence =
        blob_u64(complete_coordinator_fence.ok_or(CoordinatorErrorV1::CorruptState)?)?;
    let complete = deferred_complete_record_digest(
        attempt,
        record,
        &exact,
        complete_route_fence,
        complete_coordinator_fence,
    );
    let complete_event = deferred_complete_event_id(attempt);
    let complete_journal: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT sequence_be,created_at_be FROM coordinator_journal
             WHERE plan_id=?1 AND event_id=?2 AND event_tag=14 AND event_digest=?3
               AND route_fence_be=?4 AND coordinator_fence_be=?5",
            params![
                row.plan_id.as_slice(),
                complete_event.as_slice(),
                complete.as_slice(),
                u64_blob(complete_route_fence),
                u64_blob(complete_coordinator_fence),
            ],
            |journal| Ok((journal.get(0)?, journal.get(1)?)),
        )
        .map_err(storage)?;
    let pending_sequence = blob_u64(pending_journal.0)?;
    let pending_journal_at = blob_u64(pending_journal.1)?;
    let complete_sequence = blob_u64(complete_journal.0)?;
    let complete_journal_at = blob_u64(complete_journal.1)?;
    Ok(state == 2
        && descriptor == deferred_child_digest(deferred)
        && retained_evidence == exposure.evidence_digest
        && record == pending
        && pending_sequence < complete_sequence
        && pending_journal_at == created_at
        && complete_journal_at == completed_at
        && created_at >= exposure.observed_at_unix_ms
        && completed_at >= created_at
        && deferred_completion_fence_is_authorized(
            connection,
            row,
            complete_route_fence,
            complete_coordinator_fence,
        )?
        && child.face == exact.face
        && child.exposure == exact.exposure
        && child.chain_id == exact.chain_id
        && child.expected_tx_id == exact.expected_transaction_id
        && child.intent_digest == exact.intent_digest
        && child.custody_digest == exact.custody_digest)
}

fn deferred_completion_fence_is_authorized(
    connection: &Connection,
    row: &PlanRow,
    route_fence: u64,
    coordinator_fence: u64,
) -> Result<bool> {
    if route_fence <= row.route_fence {
        return Ok(true);
    }
    let retained = connection
        .query_row(
            "SELECT route_fence_be,coordinator_fence_be,takeover_evidence
             FROM coordinator_leases WHERE plan_id=?1",
            params![row.plan_id.as_slice()],
            |lease| {
                Ok((
                    lease.get::<_, Vec<u8>>(0)?,
                    lease.get::<_, Vec<u8>>(1)?,
                    lease.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    let Some((retained_route, retained_coordinator, takeover_evidence)) = retained else {
        return Ok(false);
    };
    let takeover_evidence = takeover_evidence
        .map(blob32)
        .transpose()?
        .unwrap_or(ZERO_DIGEST);
    Ok(route_fence == blob_u64(retained_route)?
        && coordinator_fence <= blob_u64(retained_coordinator)?
        && takeover_evidence != ZERO_DIGEST)
}

fn require_deferred_completion_within_lease(
    connection: &Connection,
    lease: CoordinatorLeaseV1,
) -> Result<()> {
    let retained = connection
        .query_row(
            "SELECT state_tag,completed_route_fence_be,completed_coordinator_fence_be
             FROM deferred_child_materializations WHERE plan_id=?1",
            params![lease.plan_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    let Some((state, route, coordinator)) = retained else {
        return Ok(());
    };
    if state == 1 {
        return Ok(());
    }
    let route = blob_u64(route.ok_or(CoordinatorErrorV1::CorruptState)?)?;
    let coordinator = blob_u64(coordinator.ok_or(CoordinatorErrorV1::CorruptState)?)?;
    if state != 2
        || route > lease.route_fencing_epoch
        || (route == lease.route_fencing_epoch && coordinator > lease.coordinator_fencing_epoch)
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(())
}

fn audit_aggregate_state(
    row: &PlanRow,
    plan: &CompositeSettlementPlanV1,
    children: &[ChildRow],
    completed_prefix: u8,
) -> Result<()> {
    if row.stage != AGGREGATE_FAILED_CLOSED {
        if (row.stage == AGGREGATE_ACTIVE)
            != (usize::from(completed_prefix) < MAX_SETTLEMENT_CHILDREN_V1)
            || (row.stage != AGGREGATE_ACTIVE)
                != (usize::from(completed_prefix) == MAX_SETTLEMENT_CHILDREN_V1)
            || row.aggregate_receipt_digest.is_some() != (row.stage != AGGREGATE_ACTIVE)
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        match row.stage {
            AGGREGATE_EXTERNALIZED => {
                if children.len() != MAX_SETTLEMENT_CHILDREN_V1
                    || children.iter().all(|child| child.stage == CHILD_FINAL)
                    || children
                        .iter()
                        .any(|child| child.stage == CHILD_FINALITY_INVALIDATED)
                    || row.aggregate_finality_digest.is_some()
                {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
            }
            AGGREGATE_FINAL => {
                if children.len() != MAX_SETTLEMENT_CHILDREN_V1
                    || !children.iter().all(|child| child.stage == CHILD_FINAL)
                    || row.aggregate_finality_digest.is_none()
                {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
            }
            AGGREGATE_FINALITY_INVALIDATED => {
                if children.len() != MAX_SETTLEMENT_CHILDREN_V1
                    || !children
                        .iter()
                        .any(|child| child.stage == CHILD_FINALITY_INVALIDATED)
                    || row.aggregate_reorg_digest.is_none()
                {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
            }
            AGGREGATE_ACTIVE => {}
            _ => return Err(CoordinatorErrorV1::CorruptState),
        }
    }

    let exposure_fields = (
        row.first_exposure_child,
        row.first_exposure_chain,
        row.first_exposure_tx,
        row.first_exposure_evidence,
        row.first_exposure_observed_at,
    );
    match plan.secret_requirement() {
        SecretRequirementV1::None => {
            if row.secret_state != SECRET_PRIVATE
                || exposure_fields != (None, None, None, None, None)
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
        SecretRequirementV1::AlreadyPublic => {
            if row.secret_state != SECRET_PUBLIC
                || exposure_fields != (None, None, None, None, None)
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
        SecretRequirementV1::FirstExposureRequired => {
            if completed_prefix == 0 {
                let expected = if children[0].stage == CHILD_CALL_PENDING {
                    SECRET_EXPOSURE_POSSIBLE
                } else {
                    SECRET_PRIVATE
                };
                if row.secret_state != expected || exposure_fields != (None, None, None, None, None)
                {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
            } else if row.secret_state != SECRET_PUBLIC
                || row.first_exposure_child != Some(0)
                || row.first_exposure_chain != Some(children[0].chain_id)
                || row.first_exposure_tx != Some(children[0].expected_tx_id)
                || row.first_exposure_evidence.is_none()
                || row.first_exposure_observed_at.is_none()
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
    }
    Ok(())
}

fn audit_plan_versions(connection: &Connection, current: &PlanRow) -> Result<()> {
    let mut statement = connection
        .prepare(
            "SELECT version_be,plan_digest,effect_id,route_fence_be,plan_bytes,authorization_evidence
             FROM settlement_plan_versions WHERE plan_id=?1 ORDER BY version_be LIMIT 4097",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(params![current.plan_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })
        .map_err(storage)?;
    let mut expected_version = 1u64;
    let mut latest: Option<(Digest32, Digest32, u64, Vec<u8>, Digest32)> = None;
    for result in rows {
        let (version, digest, effect, fence, bytes, authorization) = result.map_err(storage)?;
        if blob_u64(version)? != expected_version || bytes.len() > MAX_PLAN_BYTES {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        let plan = CompositeSettlementPlanV1::decode_canonical(&bytes)
            .map_err(|_| CoordinatorErrorV1::CorruptState)?;
        let digest = blob32(digest)?;
        let effect = blob32(effect)?;
        let fence = blob_u64(fence)?;
        let authorization = blob32(authorization)?;
        if plan
            .canonical_digest()
            .map_err(|_| CoordinatorErrorV1::CorruptState)?
            != digest
            || plan.bindings().effect_id != effect
            || plan.bindings().fencing_epoch != fence
            || stable_plan_id(&plan).map_err(|_| CoordinatorErrorV1::CorruptState)?
                != current.plan_id
            || authorization == ZERO_DIGEST
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        latest = Some((digest, effect, fence, bytes, authorization));
        expected_version = expected_version
            .checked_add(1)
            .ok_or(CoordinatorErrorV1::CorruptState)?;
    }
    let latest = latest.ok_or(CoordinatorErrorV1::CorruptState)?;
    if latest
        != (
            current.plan_digest,
            current.effect_id,
            current.route_fence,
            current.plan_bytes.clone(),
            current.authorization_evidence,
        )
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(())
}

fn audit_journal(connection: &Connection, current: &PlanRow) -> Result<()> {
    let mut statement = connection
        .prepare(
            "SELECT sequence_be,event_id,event_tag,event_digest,route_fence_be,
                    coordinator_fence_be,previous_entry_hash,entry_hash
             FROM coordinator_journal WHERE plan_id=?1 ORDER BY sequence_be LIMIT 65537",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(params![current.plan_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        })
        .map_err(storage)?;
    let mut sequence = 0u64;
    let mut previous = ZERO_DIGEST;
    for result in rows {
        let (
            stored_sequence,
            event_id,
            tag,
            event_digest,
            route_fence,
            coordinator_fence,
            prior,
            hash,
        ) = result.map_err(storage)?;
        sequence = sequence
            .checked_add(1)
            .ok_or(CoordinatorErrorV1::CorruptState)?;
        let stored_sequence = blob_u64(stored_sequence)?;
        let event_id = blob32(event_id)?;
        let event_digest = blob32(event_digest)?;
        let route_fence = blob_u64(route_fence)?;
        let coordinator_fence = blob_u64(coordinator_fence)?;
        let prior = blob32(prior)?;
        let hash = blob32(hash)?;
        if sequence > 65_536
            || stored_sequence != sequence
            || !(1..=14).contains(&tag)
            || event_id == ZERO_DIGEST
            || event_digest == ZERO_DIGEST
            || prior != previous
            || hash
                != journal_entry_hash(
                    JournalEventV1 {
                        plan_id: current.plan_id,
                        event_tag: tag,
                        event_id,
                        event_digest,
                        route_fence,
                        coordinator_fence,
                    },
                    sequence,
                    previous,
                )
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        previous = hash;
    }
    if sequence != current.revision || previous != current.journal_head {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(())
}

fn audit_call_records(connection: &Connection, current: &PlanRow) -> Result<()> {
    let invalid_outcomes: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM child_call_outcomes WHERE plan_id=?1 AND
             (outcome_digest=zeroblob(32) OR outcome_tag NOT IN (1,2,3))",
            params![current.plan_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    let invalid_observations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM observation_calls WHERE plan_id=?1 AND
             (request_digest=zeroblob(32) OR
              ((outcome_digest IS NULL) != (completed_at_be IS NULL)) OR
              ((outcome_digest IS NULL) != (result_tag IS NULL)) OR
              ((outcome_digest IS NULL) != (result_evidence IS NULL)) OR
              (result_evidence=zeroblob(32)))",
            params![current.plan_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    let invalid_reconciliations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM child_reconciliation_calls WHERE plan_id=?1 AND
             (dispatch_attempt_id=zeroblob(32) OR prior_outcome_digest=zeroblob(32) OR
              request_digest=zeroblob(32) OR reconciliation_attempt_id=zeroblob(32) OR
              (outcome_tag IS NOT NULL AND outcome_tag NOT IN (1,2,3,4)) OR
              ((outcome_digest IS NULL) != (completed_at_be IS NULL)) OR
              ((outcome_digest IS NULL) != (outcome_tag IS NULL)) OR
              ((outcome_digest IS NULL) != (outcome_evidence IS NULL)) OR
              outcome_digest=zeroblob(32) OR outcome_evidence=zeroblob(32))",
            params![current.plan_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if invalid_outcomes != 0 || invalid_observations != 0 || invalid_reconciliations != 0 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let child_outcomes = audit_child_call_records(connection, current)?;
    audit_reconciliation_records(connection, current, &child_outcomes)
}

fn audit_child_call_records(
    connection: &Connection,
    current: &PlanRow,
) -> Result<Vec<AuditChildCallOutcomeRow>> {
    let mut statement = connection
        .prepare(
            "SELECT attempt_id,child_index,outcome_tag,outcome_digest,created_at_be
             FROM child_call_outcomes WHERE plan_id=?1",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(params![current.plan_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .map_err(storage)?;
    let mut retained = Vec::new();
    for row in rows {
        retained.push(row.map_err(storage)?);
    }
    drop(statement);
    let mut audited = Vec::with_capacity(retained.len());
    for (attempt, child_index, outcome_tag, outcome, completed_at) in retained {
        let attempt = blob32(attempt)?;
        let outcome = blob32(outcome)?;
        let completed_at = blob_u64(completed_at)?;
        let child_index =
            u8::try_from(child_index).map_err(|_| CoordinatorErrorV1::CorruptState)?;
        if attempt == ZERO_DIGEST {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        let prepared: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT created_at_be,route_fence_be,coordinator_fence_be,sequence_be
                 FROM coordinator_journal
                 WHERE plan_id=?1 AND event_id=?2 AND event_tag=2",
                params![current.plan_id.as_slice(), attempt.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(storage)?;
        let prepared_at = blob_u64(prepared.0)?;
        let prepared_route_fence = blob_u64(prepared.1)?;
        let prepared_coordinator_fence = blob_u64(prepared.2)?;
        let prepared_sequence = blob_u64(prepared.3)?;
        let event_tag = match outcome_tag {
            1 => 3,
            2 => 5,
            3 => 4,
            _ => return Err(CoordinatorErrorV1::CorruptState),
        };
        let event_id = child_completion_event_id(attempt);
        let journal: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT event_digest,created_at_be,route_fence_be,coordinator_fence_be
                 FROM coordinator_journal
                 WHERE plan_id=?1 AND event_id=?2 AND event_tag=?3",
                params![current.plan_id.as_slice(), event_id.as_slice(), event_tag],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(storage)?;
        if prepared_at == 0
            || completed_at < prepared_at
            || blob32(journal.0)? != child_completion_record_digest(outcome, completed_at)
            || blob_u64(journal.1)? != completed_at
            || blob_u64(journal.2)? != prepared_route_fence
            || blob_u64(journal.3)? != prepared_coordinator_fence
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        if outcome_tag == 2 {
            let child = load_child_row(connection, current.plan_id, child_index)?;
            let expected_outcome = domain_digest_v1(
                b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-OUTCOME/EXTERNALIZED/V1\0",
                &[&persisted_child_receipt_digest(current, &child)?],
            );
            if (child.exposure == ChildExposureV1::FirstSecretExposure
                && current.first_exposure_observed_at != Some(completed_at))
                || outcome != expected_outcome
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
        audited.push(AuditChildCallOutcomeRow {
            child_index,
            attempt_id: attempt,
            prepared_sequence,
            outcome_tag,
            outcome_digest: outcome,
        });
    }
    Ok(audited)
}

fn audit_reconciliation_records(
    connection: &Connection,
    current: &PlanRow,
    child_outcomes: &[AuditChildCallOutcomeRow],
) -> Result<()> {
    let mut statement = connection
        .prepare(
            "SELECT child_index,dispatch_attempt_id,sequence_be,scope_tag,route_fence_be,
                    coordinator_fence_be,prior_outcome_digest,reconciliation_attempt_id,
                    request_digest,outcome_tag,outcome_digest,outcome_evidence,created_at_be,
                    completed_at_be
             FROM child_reconciliation_calls WHERE plan_id=?1
             ORDER BY child_index,dispatch_attempt_id,sequence_be LIMIT 65537",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(params![current.plan_id.as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<Vec<u8>>>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, Option<Vec<u8>>>(13)?,
            ))
        })
        .map_err(storage)?;
    let mut retained = Vec::new();
    for row in rows {
        let row = row.map_err(storage)?;
        let child_index = u8::try_from(row.0).map_err(|_| CoordinatorErrorV1::CorruptState)?;
        if usize::from(child_index) >= MAX_SETTLEMENT_CHILDREN_V1 {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        retained.push(AuditReconciliationRow {
            child_index,
            dispatch_attempt_id: blob32(row.1)?,
            sequence: blob_u64(row.2)?,
            scope_tag: row.3,
            route_fence: blob_u64(row.4)?,
            coordinator_fence: blob_u64(row.5)?,
            prior_outcome_digest: blob32(row.6)?,
            attempt_id: blob32(row.7)?,
            request_digest: blob32(row.8)?,
            outcome_tag: row.9,
            outcome_digest: row.10.map(blob32).transpose()?,
            outcome_evidence: row.11.map(blob32).transpose()?,
            created_at: blob_u64(row.12)?,
            completed_at: row.13.map(blob_u64).transpose()?,
        });
        if u64::try_from(retained.len()).map_err(|_| CoordinatorErrorV1::CorruptState)?
            > MAX_RECONCILIATIONS_PER_CHILD
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
    }
    drop(statement);

    let mut active_dispatch: Option<(u8, Digest32)> = None;
    let mut expected_sequence = 0u64;
    let mut expected_prior = ZERO_DIGEST;
    let mut prior_outcome_tag: Option<i64> = None;
    let mut dispatch_record_digest = ZERO_DIGEST;
    let mut dispatch_route_fence = 0u64;
    let mut dispatch_coordinator_fence = 0u64;
    for (row_index, row) in retained.iter().enumerate() {
        let identity = (row.child_index, row.dispatch_attempt_id);
        if active_dispatch != Some(identity) {
            active_dispatch = Some(identity);
            expected_sequence = 1;
            let dispatch_record: (Vec<u8>, Vec<u8>, Vec<u8>) = connection
                .query_row(
                    "SELECT event_digest,route_fence_be,coordinator_fence_be
                     FROM coordinator_journal
                     WHERE plan_id=?1 AND event_id=?2 AND event_tag=2",
                    params![
                        current.plan_id.as_slice(),
                        row.dispatch_attempt_id.as_slice()
                    ],
                    |value| Ok((value.get(0)?, value.get(1)?, value.get(2)?)),
                )
                .map_err(storage)?;
            dispatch_record_digest = blob32(dispatch_record.0)?;
            dispatch_route_fence = blob_u64(dispatch_record.1)?;
            dispatch_coordinator_fence = blob_u64(dispatch_record.2)?;
            let original: Option<(i64, Vec<u8>)> = connection
                .query_row(
                    "SELECT outcome_tag,outcome_digest FROM child_call_outcomes
                     WHERE attempt_id=?1 AND plan_id=?2 AND child_index=?3",
                    params![
                        row.dispatch_attempt_id.as_slice(),
                        current.plan_id.as_slice(),
                        i64::from(row.child_index),
                    ],
                    |value| Ok((value.get(0)?, value.get(1)?)),
                )
                .optional()
                .map_err(storage)?;
            expected_prior = match original {
                Some((3, digest)) => blob32(digest)?,
                Some(_) => return Err(CoordinatorErrorV1::CorruptState),
                None => reconciliation_prepared_prior_digest_parts(
                    row.dispatch_attempt_id,
                    dispatch_record_digest,
                ),
            };
        } else {
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(CoordinatorErrorV1::CorruptState)?;
            if !matches!(prior_outcome_tag, Some(3 | RECONCILIATION_SUPERSEDED)) {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            let prior = retained
                .get(
                    row_index
                        .checked_sub(1)
                        .ok_or(CoordinatorErrorV1::CorruptState)?,
                )
                .ok_or(CoordinatorErrorV1::CorruptState)?;
            if prior.child_index != row.child_index
                || prior.dispatch_attempt_id != row.dispatch_attempt_id
                || row.scope_tag < prior.scope_tag
                || row.route_fence < prior.route_fence
                || row.coordinator_fence < prior.coordinator_fence
                || (row.route_fence > prior.route_fence
                    && row.coordinator_fence <= prior.coordinator_fence)
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
        if row.sequence != expected_sequence
            || row.sequence == 0
            || row.sequence > MAX_RECONCILIATIONS_PER_CHILD
            || row.created_at == 0
            || row.prior_outcome_digest != expected_prior
            || !matches!(row.scope_tag, 1 | 2)
            || (row.scope_tag == 1 && row.route_fence != dispatch_route_fence)
            || (row.scope_tag == 2 && row.route_fence <= dispatch_route_fence)
            || row.coordinator_fence < dispatch_coordinator_fence
            || reconciliation_attempt_id(
                row.dispatch_attempt_id,
                row.sequence,
                row.scope_tag,
                row.route_fence,
                row.coordinator_fence,
                row.prior_outcome_digest,
            )? != row.attempt_id
            || child_reconciliation_record_digest_parts(
                dispatch_record_digest,
                row.route_fence,
                row.coordinator_fence,
                row.attempt_id,
            ) != row.request_digest
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        let prepared: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT event_digest,route_fence_be,coordinator_fence_be,created_at_be
                 FROM coordinator_journal
                 WHERE plan_id=?1 AND event_id=?2 AND event_tag=6",
                params![current.plan_id.as_slice(), row.attempt_id.as_slice()],
                |value| Ok((value.get(0)?, value.get(1)?, value.get(2)?, value.get(3)?)),
            )
            .map_err(storage)?;
        if blob32(prepared.0)? != row.request_digest
            || blob_u64(prepared.1)? != row.route_fence
            || blob_u64(prepared.2)? != row.coordinator_fence
            || blob_u64(prepared.3)? != row.created_at
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        match (
            row.outcome_tag,
            row.outcome_digest,
            row.outcome_evidence,
            row.completed_at,
        ) {
            (Some(tag), Some(digest), Some(evidence), Some(completed_at)) => {
                if completed_at < row.created_at
                    || reconciliation_outcome_digest_from_record(tag, evidence)? != digest
                {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
                let completion_event_id = reconciliation_completion_event_id(row.attempt_id);
                let completion: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
                    .query_row(
                        "SELECT event_digest,created_at_be,route_fence_be,coordinator_fence_be
                         FROM coordinator_journal
                         WHERE plan_id=?1 AND event_id=?2 AND event_tag=7",
                        params![current.plan_id.as_slice(), completion_event_id.as_slice()],
                        |value| Ok((value.get(0)?, value.get(1)?, value.get(2)?, value.get(3)?)),
                    )
                    .map_err(storage)?;
                let completion_digest = blob32(completion.0)?;
                let completion_created_at = blob_u64(completion.1)?;
                let completion_route_fence = blob_u64(completion.2)?;
                let completion_coordinator_fence = blob_u64(completion.3)?;
                if completion_digest
                    != reconciliation_completion_record_digest(digest, completed_at)
                    || completion_created_at != completed_at
                    || completion_route_fence < row.route_fence
                    || completion_coordinator_fence < row.coordinator_fence
                    || (tag != RECONCILIATION_SUPERSEDED
                        && (completion_route_fence != row.route_fence
                            || completion_coordinator_fence != row.coordinator_fence))
                {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
                if tag == 2 {
                    let child = load_child_row(connection, current.plan_id, row.child_index)?;
                    if evidence != persisted_child_receipt_digest(current, &child)?
                        || (child.exposure == ChildExposureV1::FirstSecretExposure
                            && current.first_exposure_observed_at != Some(completed_at))
                    {
                        return Err(CoordinatorErrorV1::CorruptState);
                    }
                }
                if tag == RECONCILIATION_SUPERSEDED {
                    let next = retained
                        .get(row_index + 1)
                        .ok_or(CoordinatorErrorV1::CorruptState)?;
                    if next.child_index != row.child_index
                        || next.dispatch_attempt_id != row.dispatch_attempt_id
                        || next.sequence
                            != row
                                .sequence
                                .checked_add(1)
                                .ok_or(CoordinatorErrorV1::CorruptState)?
                        || next.route_fence < row.route_fence
                        || next.coordinator_fence <= row.coordinator_fence
                        || next.created_at < completed_at
                        || completion_route_fence != next.route_fence
                        || completion_coordinator_fence != next.coordinator_fence
                        || evidence
                            != reconciliation_supersession_evidence(
                                row.attempt_id,
                                row.request_digest,
                                next.scope_tag,
                                next.route_fence,
                                next.coordinator_fence,
                            )?
                    {
                        return Err(CoordinatorErrorV1::CorruptState);
                    }
                }
                prior_outcome_tag = Some(tag);
                expected_prior = digest;
            }
            (None, None, None, None) => {
                let completion_event_id = reconciliation_completion_event_id(row.attempt_id);
                let completions: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM coordinator_journal
                         WHERE plan_id=?1 AND event_id=?2 AND event_tag=7",
                        params![current.plan_id.as_slice(), completion_event_id.as_slice()],
                        |value| value.get(0),
                    )
                    .map_err(storage)?;
                if completions != 0 {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
                prior_outcome_tag = None;
                expected_prior = ZERO_DIGEST;
            }
            _ => return Err(CoordinatorErrorV1::CorruptState),
        }
    }

    audit_materialized_children(connection, current, child_outcomes, &retained)
}

fn audit_materialized_children(
    connection: &Connection,
    current: &PlanRow,
    child_outcomes: &[AuditChildCallOutcomeRow],
    reconciliations: &[AuditReconciliationRow],
) -> Result<()> {
    let children = load_child_rows(connection, current.plan_id)?;
    let mut all_attempts = BTreeSet::new();

    for child in &children {
        let mut attempts = BTreeMap::new();
        for outcome in child_outcomes
            .iter()
            .filter(|outcome| outcome.child_index == child.child_index)
        {
            retain_materialized_attempt(
                &mut attempts,
                outcome.attempt_id,
                outcome.prepared_sequence,
            )?;
        }
        for reconciliation in reconciliations
            .iter()
            .filter(|row| row.child_index == child.child_index)
        {
            retain_materialized_attempt(
                &mut attempts,
                reconciliation.dispatch_attempt_id,
                prepared_dispatch_sequence(
                    connection,
                    current.plan_id,
                    reconciliation.dispatch_attempt_id,
                )?,
            )?;
        }
        if let Some(pending_attempt_id) = child.pending_attempt_id {
            retain_materialized_attempt(
                &mut attempts,
                pending_attempt_id,
                prepared_dispatch_sequence(connection, current.plan_id, pending_attempt_id)?,
            )?;
        }

        let attempt_count =
            u64::try_from(attempts.len()).map_err(|_| CoordinatorErrorV1::CorruptState)?;
        if attempt_count != child.call_attempt || attempt_count > MAX_JOURNAL_ENTRIES {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        if attempts.is_empty() {
            if child.stage != CHILD_PLANNED
                || child.last_ambiguity_evidence.is_some()
                || child.reconciliation_attempt_id.is_some()
                || child.reconciliation_record_digest.is_some()
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            continue;
        }

        let mut ordered: Vec<(Digest32, u64)> = attempts.into_iter().collect();
        ordered.sort_unstable_by_key(|(_, sequence)| *sequence);
        let mut latest_state = None;
        let mut latest_request = None;
        for (offset, (attempt_id, _)) in ordered.iter().enumerate() {
            if !all_attempts.insert(*attempt_id) {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            let attempt = u64::try_from(offset)
                .map_err(|_| CoordinatorErrorV1::CorruptState)?
                .checked_add(1)
                .ok_or(CoordinatorErrorV1::CorruptState)?;
            let request =
                audited_dispatch_request(connection, current, child, attempt, *attempt_id)?;
            let original = child_outcomes.iter().find(|outcome| {
                outcome.child_index == child.child_index && outcome.attempt_id == *attempt_id
            });
            let reconciliation_chain: Vec<&AuditReconciliationRow> = reconciliations
                .iter()
                .filter(|row| {
                    row.child_index == child.child_index && row.dispatch_attempt_id == *attempt_id
                })
                .collect();
            let state = derive_materialized_attempt_state(original, &reconciliation_chain)?;
            if offset + 1 != ordered.len()
                && !matches!(state, DerivedChildAttemptStateV1::Planned(_))
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            latest_state = Some(state);
            latest_request = Some(request);
        }

        let state = latest_state.ok_or(CoordinatorErrorV1::CorruptState)?;
        let request = latest_request.ok_or(CoordinatorErrorV1::CorruptState)?;
        match state {
            DerivedChildAttemptStateV1::Planned(ambiguity) => {
                if child.stage != CHILD_PLANNED
                    || child.reconciliation_attempt_id.is_some()
                    || child.reconciliation_record_digest.is_some()
                {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
                audit_materialized_ambiguity(child, ambiguity)?;
            }
            DerivedChildAttemptStateV1::Pending {
                ambiguity,
                reconciliation,
            } => {
                if child.stage != CHILD_CALL_PENDING
                    || child.pending_attempt_id != Some(request.attempt_id)
                    || child.pending_call_digest != Some(child_call_record_digest(&request))
                {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
                match reconciliation {
                    Some((attempt_id, record_digest))
                        if child.reconciliation_attempt_id == Some(attempt_id)
                            && child.reconciliation_record_digest == Some(record_digest) => {}
                    None if child.reconciliation_attempt_id.is_none()
                        && child.reconciliation_record_digest.is_none() => {}
                    _ => return Err(CoordinatorErrorV1::CorruptState),
                }
                audit_materialized_ambiguity(child, ambiguity)?;
            }
            DerivedChildAttemptStateV1::Externalized => {
                if child.stage < CHILD_EXTERNALIZED
                    || child.last_ambiguity_evidence.is_some()
                    || child.reconciliation_attempt_id.is_some()
                    || child.reconciliation_record_digest.is_some()
                {
                    return Err(CoordinatorErrorV1::CorruptState);
                }
            }
        }
    }

    let prepared_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM coordinator_journal WHERE plan_id=?1 AND event_tag=2",
            params![current.plan_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if usize::try_from(prepared_count).map_err(|_| CoordinatorErrorV1::CorruptState)?
        != all_attempts.len()
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(())
}

fn retain_materialized_attempt(
    attempts: &mut BTreeMap<Digest32, u64>,
    attempt_id: Digest32,
    prepared_sequence: u64,
) -> Result<()> {
    use std::collections::btree_map::Entry;

    match attempts.entry(attempt_id) {
        Entry::Vacant(entry) => {
            entry.insert(prepared_sequence);
        }
        Entry::Occupied(entry) if *entry.get() == prepared_sequence => {}
        Entry::Occupied(_) => return Err(CoordinatorErrorV1::CorruptState),
    }
    Ok(())
}

fn derive_materialized_attempt_state(
    original: Option<&AuditChildCallOutcomeRow>,
    reconciliations: &[&AuditReconciliationRow],
) -> Result<DerivedChildAttemptStateV1> {
    let mut state = match original {
        Some(outcome) if outcome.outcome_tag == 1 => {
            DerivedChildAttemptStateV1::Planned(DerivedAmbiguityV1::None)
        }
        Some(outcome) if outcome.outcome_tag == 2 => DerivedChildAttemptStateV1::Externalized,
        Some(outcome) if outcome.outcome_tag == 3 => DerivedChildAttemptStateV1::Pending {
            ambiguity: DerivedAmbiguityV1::OriginalUnknown(outcome.outcome_digest),
            reconciliation: None,
        },
        Some(_) => return Err(CoordinatorErrorV1::CorruptState),
        None => DerivedChildAttemptStateV1::Pending {
            ambiguity: DerivedAmbiguityV1::None,
            reconciliation: None,
        },
    };
    if !reconciliations.is_empty()
        && !matches!(
            state,
            DerivedChildAttemptStateV1::Pending {
                reconciliation: None,
                ..
            }
        )
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }

    for reconciliation in reconciliations {
        let ambiguity = match state {
            DerivedChildAttemptStateV1::Pending { ambiguity, .. } => ambiguity,
            _ => return Err(CoordinatorErrorV1::CorruptState),
        };
        state = match (reconciliation.outcome_tag, reconciliation.outcome_evidence) {
            (None, None) => DerivedChildAttemptStateV1::Pending {
                ambiguity,
                reconciliation: Some((reconciliation.attempt_id, reconciliation.request_digest)),
            },
            (Some(1), Some(evidence)) => {
                DerivedChildAttemptStateV1::Planned(DerivedAmbiguityV1::Evidence(evidence))
            }
            (Some(2), Some(_)) => DerivedChildAttemptStateV1::Externalized,
            (Some(3), Some(evidence)) => DerivedChildAttemptStateV1::Pending {
                ambiguity: DerivedAmbiguityV1::Evidence(evidence),
                reconciliation: None,
            },
            (Some(RECONCILIATION_SUPERSEDED), Some(_)) => DerivedChildAttemptStateV1::Pending {
                ambiguity,
                reconciliation: None,
            },
            _ => return Err(CoordinatorErrorV1::CorruptState),
        };
    }
    Ok(state)
}

fn audit_materialized_ambiguity(child: &ChildRow, expected: DerivedAmbiguityV1) -> Result<()> {
    match expected {
        DerivedAmbiguityV1::None if child.last_ambiguity_evidence.is_none() => Ok(()),
        DerivedAmbiguityV1::Evidence(evidence)
            if child.last_ambiguity_evidence == Some(evidence) =>
        {
            Ok(())
        }
        DerivedAmbiguityV1::OriginalUnknown(outcome_digest) => {
            let evidence = child
                .last_ambiguity_evidence
                .ok_or(CoordinatorErrorV1::CorruptState)?;
            if original_unknown_outcome_digest(evidence) == outcome_digest {
                Ok(())
            } else {
                Err(CoordinatorErrorV1::CorruptState)
            }
        }
        _ => Err(CoordinatorErrorV1::CorruptState),
    }
}

impl DurableSettlementCoordinatorV1 {
    /// Persist or resume the next strict child call. No authority is invoked by
    /// this method; the returned move-only token proves the intent is durable.
    pub fn prepare_next_child_call(
        &mut self,
        lease: CoordinatorLeaseV1,
        now_unix_ms: u64,
    ) -> Result<PendingChildCallV1> {
        let transaction = self.immediate(now_unix_ms)?;
        let plan = validate_lease(&transaction, lease, now_unix_ms, true)?;
        if plan.stage != AGGREGATE_ACTIVE {
            return Err(CoordinatorErrorV1::InvalidState);
        }
        let decoded = decode_plan_row(&plan)?;
        let children = load_child_rows(&transaction, lease.plan_id)?;
        validate_child_prefix(&children, &decoded)?;
        let index = children
            .iter()
            .position(|child| child.stage < CHILD_EXTERNALIZED)
            .ok_or(CoordinatorErrorV1::CorruptState)?;
        if children[index].stage == CHILD_CALL_PENDING {
            let attempt_id = children[index]
                .pending_attempt_id
                .ok_or(CoordinatorErrorV1::CorruptState)?;
            let reconciliation_required: i64 = transaction
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM child_call_outcomes
                         WHERE attempt_id=?1 AND plan_id=?2 AND child_index=?3
                     ) OR EXISTS(
                         SELECT 1 FROM child_reconciliation_calls
                         WHERE dispatch_attempt_id=?1 AND plan_id=?2 AND child_index=?3
                     )",
                    params![
                        attempt_id.as_slice(),
                        lease.plan_id.as_slice(),
                        i64::try_from(index).map_err(|_| CoordinatorErrorV1::InvalidBound)?,
                    ],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if reconciliation_required != 0 {
                return Err(CoordinatorErrorV1::ReconciliationRequired);
            }
            let pending = pending_child_token(
                &transaction,
                &plan,
                &decoded,
                &children[index],
                lease,
                u8::try_from(index).map_err(|_| CoordinatorErrorV1::InvalidBound)?,
            )?;
            transaction.commit().map_err(storage)?;
            return Ok(pending);
        }
        if children[index].stage != CHILD_PLANNED
            || children[..index]
                .iter()
                .any(|child| child.stage < CHILD_EXTERNALIZED)
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        let attempt = children[index]
            .call_attempt
            .checked_add(1)
            .ok_or(CoordinatorErrorV1::InvalidBound)?;
        let child_index = u8::try_from(index).map_err(|_| CoordinatorErrorV1::InvalidBound)?;
        let request = child_dispatch_request(
            &plan,
            &decoded,
            &children[index],
            lease,
            child_index,
            attempt,
        )?;
        let call_record_digest = child_call_record_digest(&request);
        let changed = transaction
            .execute(
                "UPDATE settlement_children SET stage_tag=?3,call_attempt_be=?4,
                 pending_attempt_id=?5,pending_call_digest=?6,last_ambiguity_evidence=NULL,
                 reconciliation_attempt_id=NULL,reconciliation_record_digest=NULL
                 WHERE plan_id=?1 AND child_index=?2 AND stage_tag=?7 AND call_attempt_be=?8",
                params![
                    lease.plan_id.as_slice(),
                    i64::from(child_index),
                    CHILD_CALL_PENDING,
                    u64_blob(attempt),
                    request.attempt_id.as_slice(),
                    call_record_digest.as_slice(),
                    CHILD_PLANNED,
                    u64_blob(children[index].call_attempt),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        if children[index].exposure == ChildExposureV1::FirstSecretExposure {
            let changed = transaction
                .execute(
                    "UPDATE settlement_plans SET secret_state_tag=?2,updated_at_be=?3
                     WHERE plan_id=?1 AND secret_state_tag=?4 AND stage_tag=?5",
                    params![
                        lease.plan_id.as_slice(),
                        SECRET_EXPOSURE_POSSIBLE,
                        u64_blob(now_unix_ms),
                        SECRET_PRIVATE,
                        AGGREGATE_ACTIVE,
                    ],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
        append_next_journal(
            &transaction,
            JournalEventV1 {
                plan_id: lease.plan_id,
                event_tag: 2,
                event_id: request.attempt_id,
                event_digest: call_record_digest,
                route_fence: lease.route_fencing_epoch,
                coordinator_fence: lease.coordinator_fencing_epoch,
            },
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(PendingChildCallV1 {
            request,
            call_record_digest,
        })
    }

    /// Commit one child authority outcome. The token is linear and the store
    /// revalidates its exact persisted call record before changing progress.
    pub fn complete_child_call(
        &mut self,
        lease: CoordinatorLeaseV1,
        pending: PendingChildCallV1,
        outcome: ChildExecutionOutcomeV1,
        now_unix_ms: u64,
    ) -> Result<CoordinatorDriveOutcomeV1> {
        let outcome_digest = child_execution_outcome_digest(&outcome)?;
        let transaction = self.immediate(now_unix_ms)?;
        let plan = validate_lease(&transaction, lease, now_unix_ms, true)?;
        validate_pending_call_token(&plan, &pending, lease)?;
        if let Some((stored_tag, stored_digest)) = transaction
            .query_row(
                "SELECT outcome_tag,outcome_digest FROM child_call_outcomes WHERE attempt_id=?1",
                params![pending.request.attempt_id.as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(storage)?
        {
            if blob32(stored_digest)? != outcome_digest {
                fail_closed_conflict(
                    &transaction,
                    lease.plan_id,
                    plan.plan_digest,
                    outcome_digest,
                    pending.call_record_digest,
                    now_unix_ms,
                )?;
                transaction.commit().map_err(storage)?;
                return Err(CoordinatorErrorV1::IdempotencyConflict);
            }
            transaction.commit().map_err(storage)?;
            return match stored_tag {
                1 | 2 => self.current_drive_outcome(lease.plan_id),
                3 => match outcome {
                    ChildExecutionOutcomeV1::Unknown { evidence_digest } => {
                        Ok(CoordinatorDriveOutcomeV1::Unknown { evidence_digest })
                    }
                    _ => Err(CoordinatorErrorV1::IdempotencyConflict),
                },
                _ => Err(CoordinatorErrorV1::CorruptState),
            };
        }
        let reconciliation_started: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM child_reconciliation_calls
                 WHERE dispatch_attempt_id=?1 AND plan_id=?2 AND child_index=?3",
                params![
                    pending.request.attempt_id.as_slice(),
                    lease.plan_id.as_slice(),
                    i64::from(pending.request.child_index),
                ],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if reconciliation_started != 0 {
            return Err(CoordinatorErrorV1::ReconciliationRequired);
        }
        let child = load_child_row(&transaction, lease.plan_id, pending.request.child_index)?;
        if child.stage != CHILD_CALL_PENDING
            || child.pending_attempt_id != Some(pending.request.attempt_id)
            || child.pending_call_digest != Some(pending.call_record_digest)
            || child.call_attempt != pending.request.attempt
        {
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        match outcome {
            ChildExecutionOutcomeV1::RetryableBeforeExternalization { evidence_digest } => {
                validate_digest(evidence_digest)?;
                transaction
                    .execute(
                        "INSERT INTO child_call_outcomes(attempt_id,plan_id,child_index,outcome_tag,outcome_digest,created_at_be) VALUES(?1,?2,?3,1,?4,?5)",
                        params![
                            pending.request.attempt_id.as_slice(), lease.plan_id.as_slice(),
                            i64::from(pending.request.child_index), outcome_digest.as_slice(),
                            u64_blob(now_unix_ms),
                        ],
                    )
                    .map_err(storage)?;
                clear_pending_child(
                    &transaction,
                    lease.plan_id,
                    pending.request.child_index,
                    CHILD_PLANNED,
                    None,
                )?;
                if child.exposure == ChildExposureV1::FirstSecretExposure {
                    transaction
                        .execute(
                            "UPDATE settlement_plans SET secret_state_tag=?2,updated_at_be=?3
                             WHERE plan_id=?1 AND secret_state_tag=?4",
                            params![
                                lease.plan_id.as_slice(),
                                SECRET_PRIVATE,
                                u64_blob(now_unix_ms),
                                SECRET_EXPOSURE_POSSIBLE,
                            ],
                        )
                        .map_err(storage)?;
                }
                append_next_journal(
                    &transaction,
                    JournalEventV1 {
                        plan_id: lease.plan_id,
                        event_tag: 3,
                        event_id: child_completion_event_id(pending.request.attempt_id),
                        event_digest: child_completion_record_digest(outcome_digest, now_unix_ms),
                        route_fence: lease.route_fencing_epoch,
                        coordinator_fence: lease.coordinator_fencing_epoch,
                    },
                    now_unix_ms,
                )?;
                transaction.commit().map_err(storage)?;
                Ok(CoordinatorDriveOutcomeV1::Waiting { evidence_digest })
            }
            ChildExecutionOutcomeV1::Unknown { evidence_digest } => {
                validate_digest(evidence_digest)?;
                transaction
                    .execute(
                        "INSERT INTO child_call_outcomes(attempt_id,plan_id,child_index,outcome_tag,outcome_digest,created_at_be) VALUES(?1,?2,?3,3,?4,?5)",
                        params![
                            pending.request.attempt_id.as_slice(), lease.plan_id.as_slice(),
                            i64::from(pending.request.child_index), outcome_digest.as_slice(),
                            u64_blob(now_unix_ms),
                        ],
                    )
                    .map_err(storage)?;
                transaction
                    .execute(
                        "UPDATE settlement_children SET last_ambiguity_evidence=?3
                         WHERE plan_id=?1 AND child_index=?2 AND stage_tag=?4",
                        params![
                            lease.plan_id.as_slice(),
                            i64::from(pending.request.child_index),
                            evidence_digest.as_slice(),
                            CHILD_CALL_PENDING,
                        ],
                    )
                    .map_err(storage)?;
                append_next_journal(
                    &transaction,
                    JournalEventV1 {
                        plan_id: lease.plan_id,
                        event_tag: 4,
                        event_id: child_completion_event_id(pending.request.attempt_id),
                        event_digest: child_completion_record_digest(outcome_digest, now_unix_ms),
                        route_fence: lease.route_fencing_epoch,
                        coordinator_fence: lease.coordinator_fencing_epoch,
                    },
                    now_unix_ms,
                )?;
                transaction.commit().map_err(storage)?;
                Ok(CoordinatorDriveOutcomeV1::Unknown { evidence_digest })
            }
            ChildExecutionOutcomeV1::Externalized(receipt) => {
                validate_child_receipt(&pending.request, &receipt)?;
                transaction
                    .execute(
                        "INSERT INTO child_call_outcomes(attempt_id,plan_id,child_index,outcome_tag,outcome_digest,created_at_be) VALUES(?1,?2,?3,2,?4,?5)",
                        params![
                            pending.request.attempt_id.as_slice(), lease.plan_id.as_slice(),
                            i64::from(pending.request.child_index), outcome_digest.as_slice(),
                            u64_blob(now_unix_ms),
                        ],
                    )
                    .map_err(storage)?;
                persist_child_externalized(
                    &transaction,
                    &plan,
                    &pending.request,
                    &receipt,
                    now_unix_ms,
                )?;
                append_next_journal(
                    &transaction,
                    JournalEventV1 {
                        plan_id: lease.plan_id,
                        event_tag: 5,
                        event_id: child_completion_event_id(pending.request.attempt_id),
                        event_digest: child_completion_record_digest(outcome_digest, now_unix_ms),
                        route_fence: lease.route_fencing_epoch,
                        coordinator_fence: lease.coordinator_fencing_epoch,
                    },
                    now_unix_ms,
                )?;
                materialize_aggregate_externalization(&transaction, lease.plan_id, now_unix_ms)?;
                transaction.commit().map_err(storage)?;
                self.current_drive_outcome(lease.plan_id)
            }
        }
    }

    /// Persist and execute at most one child authority call.
    pub fn drive_one<A: SettlementChildAuthorityV1>(
        &mut self,
        lease: CoordinatorLeaseV1,
        authority: &mut A,
        now_unix_ms: u64,
    ) -> Result<CoordinatorDriveOutcomeV1> {
        let view = self.load_plan(lease.plan_id)?;
        if matches!(
            view.stage,
            AggregateStageV1::Externalized
                | AggregateStageV1::Final
                | AggregateStageV1::FinalityInvalidated
        ) {
            return self.current_drive_outcome(lease.plan_id);
        }
        if view.stage == AggregateStageV1::FailedClosed {
            return Err(CoordinatorErrorV1::FailedClosed);
        }
        let pending = self.prepare_next_child_call(lease, now_unix_ms)?;
        let outcome = authority
            .externalize_child(pending.request())
            .map_err(|_| CoordinatorErrorV1::ChildAuthorityRefused)?;
        self.complete_child_call(lease, pending, outcome, now_unix_ms)
    }

    /// Reconstruct the exact current custody outcome without invoking a child.
    ///
    /// This closes the same-fence crash boundary in which a child receipt was
    /// committed by the coordinator but the caller lost the returned partial
    /// progress before journaling it in its parent route. The supplied lease is
    /// revalidated against the current route and coordinator fences, the clock
    /// high-water advances durably, and the complete plan/journal/child state is
    /// audited before any public outcome is returned.
    pub fn current_custody_progress(
        &mut self,
        lease: CoordinatorLeaseV1,
        now_unix_ms: u64,
    ) -> Result<CoordinatorDriveOutcomeV1> {
        let transaction = self.immediate(now_unix_ms)?;
        validate_lease(&transaction, lease, now_unix_ms, true)?;
        let view = audit_plan(&transaction, lease.plan_id)?;
        let outcome = match takeover_status_from_view(&transaction, &view)? {
            CustodyTakeoverStatusV1::NothingExternalized { evidence_digest } => {
                CoordinatorDriveOutcomeV1::Waiting { evidence_digest }
            }
            CustodyTakeoverStatusV1::SafeToResumeCustody(progress)
            | CustodyTakeoverStatusV1::SecretPublicPartial(progress) => {
                CoordinatorDriveOutcomeV1::PartialProgress(progress)
            }
            CustodyTakeoverStatusV1::Unknown { evidence_digest } => {
                CoordinatorDriveOutcomeV1::Unknown { evidence_digest }
            }
            CustodyTakeoverStatusV1::AggregateExternalized(receipt) => {
                CoordinatorDriveOutcomeV1::AggregateExternalized(receipt)
            }
        };
        transaction.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Classify current custody progress for stale-fence takeover. This method
    /// never calls a child authority and never treats a pending call as absent.
    pub fn takeover_status(
        &self,
        lease: CoordinatorLeaseV1,
        now_unix_ms: u64,
    ) -> Result<CustodyTakeoverStatusV1> {
        self.audit_storage()?;
        let transaction = self.connection.unchecked_transaction().map_err(storage)?;
        let plan = validate_lease(&transaction, lease, now_unix_ms, false)?;
        if lease.route_fencing_epoch <= plan.route_fence {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        let view = audit_plan(&transaction, lease.plan_id)?;
        transaction.commit().map_err(storage)?;
        takeover_status_from_view(&self.connection, &view)
    }

    /// Persist or resume exact same-fence reconciliation of the single
    /// pending child. Every completed `Unknown` is followed by a new,
    /// digest-linked reconciliation sequence rather than changing its result.
    pub fn prepare_current_reconciliation(
        &mut self,
        lease: CoordinatorLeaseV1,
        now_unix_ms: u64,
    ) -> Result<PendingChildReconciliationV1> {
        self.prepare_reconciliation(lease, false, now_unix_ms)
    }

    /// Commit one exact same-fence reconciliation result.
    pub fn complete_current_reconciliation(
        &mut self,
        lease: CoordinatorLeaseV1,
        pending: PendingChildReconciliationV1,
        outcome: ChildReconciliationOutcomeV1,
        now_unix_ms: u64,
    ) -> Result<CoordinatorDriveOutcomeV1> {
        self.complete_reconciliation(lease, pending, outcome, false, now_unix_ms)?;
        self.current_custody_progress(lease, now_unix_ms)
    }

    /// Persist and perform at most one same-fence reconciliation authority
    /// call. This method never invokes `externalize_child`.
    pub fn reconcile_current_child_one<A: SettlementChildAuthorityV1>(
        &mut self,
        lease: CoordinatorLeaseV1,
        authority: &mut A,
        now_unix_ms: u64,
    ) -> Result<CoordinatorDriveOutcomeV1> {
        let status = self.current_custody_progress(lease, now_unix_ms)?;
        if !matches!(status, CoordinatorDriveOutcomeV1::Unknown { .. }) {
            return Ok(status);
        }
        let pending = self.prepare_current_reconciliation(lease, now_unix_ms)?;
        let outcome = authority
            .reconcile_child(pending.request())
            .map_err(|_| CoordinatorErrorV1::ChildAuthorityRefused)?;
        self.complete_current_reconciliation(lease, pending, outcome, now_unix_ms)
    }

    /// Persist or resume exact reconciliation of the single pending child
    /// under a newer route fence.
    pub fn prepare_takeover_reconciliation(
        &mut self,
        lease: CoordinatorLeaseV1,
        now_unix_ms: u64,
    ) -> Result<PendingChildReconciliationV1> {
        self.prepare_reconciliation(lease, true, now_unix_ms)
    }

    /// Commit one exact child takeover reconciliation result.
    pub fn complete_takeover_reconciliation(
        &mut self,
        lease: CoordinatorLeaseV1,
        pending: PendingChildReconciliationV1,
        outcome: ChildReconciliationOutcomeV1,
        now_unix_ms: u64,
    ) -> Result<CustodyTakeoverStatusV1> {
        self.complete_reconciliation(lease, pending, outcome, true, now_unix_ms)?;
        self.takeover_status(lease, now_unix_ms)
    }

    /// Persist and perform at most one child reconciliation authority call.
    pub fn reconcile_takeover_one<A: SettlementChildAuthorityV1>(
        &mut self,
        lease: CoordinatorLeaseV1,
        authority: &mut A,
        now_unix_ms: u64,
    ) -> Result<CustodyTakeoverStatusV1> {
        let status = self.takeover_status(lease, now_unix_ms)?;
        if !matches!(status, CustodyTakeoverStatusV1::Unknown { .. }) {
            return Ok(status);
        }
        let pending = self.prepare_takeover_reconciliation(lease, now_unix_ms)?;
        let outcome = authority
            .reconcile_child(pending.request())
            .map_err(|_| CoordinatorErrorV1::ChildAuthorityRefused)?;
        self.complete_takeover_reconciliation(lease, pending, outcome, now_unix_ms)
    }

    fn prepare_reconciliation(
        &mut self,
        lease: CoordinatorLeaseV1,
        require_takeover: bool,
        now_unix_ms: u64,
    ) -> Result<PendingChildReconciliationV1> {
        let transaction = self.immediate(now_unix_ms)?;
        let plan = validate_lease(&transaction, lease, now_unix_ms, !require_takeover)?;
        if require_takeover != (lease.route_fencing_epoch > plan.route_fence) {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        audit_call_records(&transaction, &plan)?;
        let decoded = decode_plan_row(&plan)?;
        let children = load_child_rows(&transaction, lease.plan_id)?;
        let pending_indices: Vec<usize> = children
            .iter()
            .enumerate()
            .filter_map(|(index, child)| (child.stage == CHILD_CALL_PENDING).then_some(index))
            .collect();
        if pending_indices.len() != 1 {
            return Err(CoordinatorErrorV1::InvalidState);
        }
        let index = pending_indices[0];
        let child_index = u8::try_from(index).map_err(|_| CoordinatorErrorV1::InvalidBound)?;
        let child = &children[index];
        let dispatch = pending_dispatch_request(&transaction, &plan, &decoded, child, child_index)?;
        if child.pending_attempt_id != Some(dispatch.attempt_id) {
            return Err(CoordinatorErrorV1::CorruptState);
        }

        let scope_tag = if require_takeover { 2 } else { 1 };
        let mut stale_pending = None;
        if let Some(row) = load_pending_reconciliation(&transaction, lease.plan_id, child_index)? {
            if row.dispatch_attempt_id != dispatch.attempt_id
                || row.route_fence > lease.route_fencing_epoch
                || row.coordinator_fence > lease.coordinator_fencing_epoch
                || child.reconciliation_attempt_id != Some(row.attempt_id)
                || child.reconciliation_record_digest != Some(row.request_digest)
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            let expected_attempt = reconciliation_attempt_id(
                dispatch.attempt_id,
                row.sequence,
                row.scope_tag,
                row.route_fence,
                row.coordinator_fence,
                row.prior_outcome_digest,
            )?;
            if expected_attempt != row.attempt_id {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            let request = ChildReconciliationRequestV1 {
                dispatch,
                current_route_fencing_epoch: row.route_fence,
                current_coordinator_fencing_epoch: row.coordinator_fence,
                reconciliation_attempt_id: row.attempt_id,
            };
            if child_reconciliation_record_digest(&request) != row.request_digest {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            if row.route_fence == lease.route_fencing_epoch
                && row.coordinator_fence == lease.coordinator_fencing_epoch
            {
                transaction.commit().map_err(storage)?;
                return Ok(PendingChildReconciliationV1 {
                    request,
                    reconciliation_record_digest: row.request_digest,
                });
            }
            if row.route_fence > lease.route_fencing_epoch
                || row.coordinator_fence >= lease.coordinator_fencing_epoch
            {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            stale_pending = Some(row);
        } else if child.reconciliation_attempt_id.is_some()
            || child.reconciliation_record_digest.is_some()
        {
            return Err(CoordinatorErrorV1::CorruptState);
        }

        let (sequence, prior_outcome_digest) = if let Some(row) = stale_pending.as_ref() {
            let sequence = row
                .sequence
                .checked_add(1)
                .ok_or(CoordinatorErrorV1::InvalidBound)?;
            let supersession_evidence = reconciliation_supersession_evidence(
                row.attempt_id,
                row.request_digest,
                scope_tag,
                lease.route_fencing_epoch,
                lease.coordinator_fencing_epoch,
            )?;
            let supersession_outcome_digest =
                reconciliation_supersession_outcome_digest(supersession_evidence)?;
            let changed = transaction
                .execute(
                    "UPDATE child_reconciliation_calls SET outcome_tag=?2,outcome_digest=?3,
                     outcome_evidence=?4,completed_at_be=?5
                     WHERE reconciliation_attempt_id=?1 AND outcome_digest IS NULL",
                    params![
                        row.attempt_id.as_slice(),
                        RECONCILIATION_SUPERSEDED,
                        supersession_outcome_digest.as_slice(),
                        supersession_evidence.as_slice(),
                        u64_blob(now_unix_ms),
                    ],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(CoordinatorErrorV1::StaleFencing);
            }
            append_next_journal(
                &transaction,
                JournalEventV1 {
                    plan_id: lease.plan_id,
                    event_tag: 7,
                    event_id: reconciliation_completion_event_id(row.attempt_id),
                    event_digest: reconciliation_completion_record_digest(
                        supersession_outcome_digest,
                        now_unix_ms,
                    ),
                    route_fence: lease.route_fencing_epoch,
                    coordinator_fence: lease.coordinator_fencing_epoch,
                },
                now_unix_ms,
            )?;
            (sequence, supersession_outcome_digest)
        } else {
            let retained: Option<(i64, Vec<u8>, Vec<u8>)> = transaction
                .query_row(
                    "SELECT outcome_tag,outcome_digest,sequence_be
                     FROM child_reconciliation_calls
                     WHERE plan_id=?1 AND child_index=?2 AND dispatch_attempt_id=?3
                     ORDER BY sequence_be DESC LIMIT 1",
                    params![
                        lease.plan_id.as_slice(),
                        i64::from(child_index),
                        dispatch.attempt_id.as_slice(),
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(storage)?;
            match retained {
                Some((3, outcome_digest, prior_sequence)) => {
                    let prior_sequence = blob_u64(prior_sequence)?;
                    (
                        prior_sequence
                            .checked_add(1)
                            .ok_or(CoordinatorErrorV1::InvalidBound)?,
                        blob32(outcome_digest)?,
                    )
                }
                Some((RECONCILIATION_SUPERSEDED, _, _)) => {
                    return Err(CoordinatorErrorV1::CorruptState)
                }
                Some(_) => return Err(CoordinatorErrorV1::InvalidState),
                None => {
                    let initial = transaction
                        .query_row(
                            "SELECT outcome_tag,outcome_digest FROM child_call_outcomes
                             WHERE attempt_id=?1 AND plan_id=?2 AND child_index=?3",
                            params![
                                dispatch.attempt_id.as_slice(),
                                lease.plan_id.as_slice(),
                                i64::from(child_index),
                            ],
                            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                        )
                        .optional()
                        .map_err(storage)?;
                    let prior = match initial {
                        Some((3, digest)) => blob32(digest)?,
                        Some(_) => return Err(CoordinatorErrorV1::InvalidState),
                        None => reconciliation_prepared_prior_digest(&dispatch),
                    };
                    (1, prior)
                }
            }
        };
        if sequence > MAX_RECONCILIATIONS_PER_CHILD {
            return Err(CoordinatorErrorV1::InvalidBound);
        }
        let attempt_id = reconciliation_attempt_id(
            dispatch.attempt_id,
            sequence,
            scope_tag,
            lease.route_fencing_epoch,
            lease.coordinator_fencing_epoch,
            prior_outcome_digest,
        )?;
        let request = ChildReconciliationRequestV1 {
            dispatch,
            current_route_fencing_epoch: lease.route_fencing_epoch,
            current_coordinator_fencing_epoch: lease.coordinator_fencing_epoch,
            reconciliation_attempt_id: attempt_id,
        };
        let record_digest = child_reconciliation_record_digest(&request);
        transaction
            .execute(
                "INSERT INTO child_reconciliation_calls(
                    reconciliation_attempt_id,plan_id,child_index,dispatch_attempt_id,
                    sequence_be,scope_tag,route_fence_be,coordinator_fence_be,
                    prior_outcome_digest,request_digest,outcome_tag,outcome_digest,
                    outcome_evidence,created_at_be,completed_at_be
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL,NULL,?11,NULL)",
                params![
                    attempt_id.as_slice(),
                    lease.plan_id.as_slice(),
                    i64::from(child_index),
                    request.dispatch.attempt_id.as_slice(),
                    u64_blob(sequence),
                    scope_tag,
                    u64_blob(lease.route_fencing_epoch),
                    u64_blob(lease.coordinator_fencing_epoch),
                    prior_outcome_digest.as_slice(),
                    record_digest.as_slice(),
                    u64_blob(now_unix_ms),
                ],
            )
            .map_err(storage)?;
        let changed = match stale_pending.as_ref() {
            Some(row) => transaction
                .execute(
                    "UPDATE settlement_children SET reconciliation_attempt_id=?3,
                     reconciliation_record_digest=?4 WHERE plan_id=?1 AND child_index=?2
                     AND stage_tag=?5 AND reconciliation_attempt_id=?6
                     AND reconciliation_record_digest=?7",
                    params![
                        lease.plan_id.as_slice(),
                        i64::from(child_index),
                        attempt_id.as_slice(),
                        record_digest.as_slice(),
                        CHILD_CALL_PENDING,
                        row.attempt_id.as_slice(),
                        row.request_digest.as_slice(),
                    ],
                )
                .map_err(storage)?,
            None => transaction
                .execute(
                    "UPDATE settlement_children SET reconciliation_attempt_id=?3,
                     reconciliation_record_digest=?4 WHERE plan_id=?1 AND child_index=?2
                     AND stage_tag=?5 AND reconciliation_attempt_id IS NULL",
                    params![
                        lease.plan_id.as_slice(),
                        i64::from(child_index),
                        attempt_id.as_slice(),
                        record_digest.as_slice(),
                        CHILD_CALL_PENDING,
                    ],
                )
                .map_err(storage)?,
        };
        if changed != 1 {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        append_next_journal(
            &transaction,
            JournalEventV1 {
                plan_id: lease.plan_id,
                event_tag: 6,
                event_id: attempt_id,
                event_digest: record_digest,
                route_fence: lease.route_fencing_epoch,
                coordinator_fence: lease.coordinator_fencing_epoch,
            },
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(PendingChildReconciliationV1 {
            request,
            reconciliation_record_digest: record_digest,
        })
    }

    fn complete_reconciliation(
        &mut self,
        lease: CoordinatorLeaseV1,
        pending: PendingChildReconciliationV1,
        outcome: ChildReconciliationOutcomeV1,
        require_takeover: bool,
        now_unix_ms: u64,
    ) -> Result<()> {
        let outcome_digest = child_reconciliation_outcome_digest(&outcome)?;
        let (outcome_tag, outcome_evidence) = reconciliation_outcome_record(&outcome)?;
        let transaction = self.immediate(now_unix_ms)?;
        let plan = validate_lease(&transaction, lease, now_unix_ms, !require_takeover)?;
        if require_takeover != (lease.route_fencing_epoch > plan.route_fence)
            || pending.request.current_route_fencing_epoch != lease.route_fencing_epoch
            || pending.request.current_coordinator_fencing_epoch != lease.coordinator_fencing_epoch
            || child_reconciliation_record_digest(&pending.request)
                != pending.reconciliation_record_digest
        {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        audit_call_records(&transaction, &plan)?;
        let retained = transaction
            .query_row(
                "SELECT plan_id,child_index,dispatch_attempt_id,request_digest,
                        outcome_tag,outcome_digest
                 FROM child_reconciliation_calls WHERE reconciliation_attempt_id=?1",
                params![pending.request.reconciliation_attempt_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or(CoordinatorErrorV1::IdempotencyConflict)?;
        if blob32(retained.0)? != lease.plan_id
            || retained.1 != i64::from(pending.request.dispatch.child_index)
            || blob32(retained.2)? != pending.request.dispatch.attempt_id
            || blob32(retained.3)? != pending.reconciliation_record_digest
        {
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        if retained.4 == Some(RECONCILIATION_SUPERSEDED) {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        if let Some(stored_digest) = retained.5 {
            let stored_digest = blob32(stored_digest)?;
            if stored_digest != outcome_digest {
                fail_closed_conflict(
                    &transaction,
                    lease.plan_id,
                    stored_digest,
                    outcome_digest,
                    pending.reconciliation_record_digest,
                    now_unix_ms,
                )?;
                transaction.commit().map_err(storage)?;
                return Err(CoordinatorErrorV1::IdempotencyConflict);
            }
            transaction.commit().map_err(storage)?;
            return Ok(());
        }
        let child = load_child_row(
            &transaction,
            lease.plan_id,
            pending.request.dispatch.child_index,
        )?;
        if child.stage != CHILD_CALL_PENDING
            || child.pending_attempt_id != Some(pending.request.dispatch.attempt_id)
            || child.pending_call_digest
                != Some(child_call_record_digest(&pending.request.dispatch))
            || child.reconciliation_attempt_id != Some(pending.request.reconciliation_attempt_id)
            || child.reconciliation_record_digest != Some(pending.reconciliation_record_digest)
        {
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        match outcome {
            ChildReconciliationOutcomeV1::ProvenNotExternalized { evidence_digest } => {
                validate_digest(evidence_digest)?;
                clear_pending_child(
                    &transaction,
                    lease.plan_id,
                    pending.request.dispatch.child_index,
                    CHILD_PLANNED,
                    Some(evidence_digest),
                )?;
                if child.exposure == ChildExposureV1::FirstSecretExposure {
                    transaction
                        .execute(
                            "UPDATE settlement_plans SET secret_state_tag=?2,updated_at_be=?3
                             WHERE plan_id=?1 AND secret_state_tag=?4",
                            params![
                                lease.plan_id.as_slice(),
                                SECRET_PRIVATE,
                                u64_blob(now_unix_ms),
                                SECRET_EXPOSURE_POSSIBLE,
                            ],
                        )
                        .map_err(storage)?;
                }
            }
            ChildReconciliationOutcomeV1::Externalized(receipt) => {
                validate_child_receipt(&pending.request.dispatch, &receipt)?;
                persist_child_externalized(
                    &transaction,
                    &plan,
                    &pending.request.dispatch,
                    &receipt,
                    now_unix_ms,
                )?;
                materialize_aggregate_externalization(&transaction, lease.plan_id, now_unix_ms)?;
            }
            ChildReconciliationOutcomeV1::Unknown { evidence_digest } => {
                validate_digest(evidence_digest)?;
                let changed = transaction
                    .execute(
                        "UPDATE settlement_children SET last_ambiguity_evidence=?3,
                         reconciliation_attempt_id=NULL,reconciliation_record_digest=NULL
                         WHERE plan_id=?1 AND child_index=?2 AND stage_tag=?4
                         AND reconciliation_attempt_id=?5",
                        params![
                            lease.plan_id.as_slice(),
                            i64::from(pending.request.dispatch.child_index),
                            evidence_digest.as_slice(),
                            CHILD_CALL_PENDING,
                            pending.request.reconciliation_attempt_id.as_slice(),
                        ],
                    )
                    .map_err(storage)?;
                if changed != 1 {
                    return Err(CoordinatorErrorV1::IdempotencyConflict);
                }
            }
        }
        let changed = transaction
            .execute(
                "UPDATE child_reconciliation_calls SET outcome_tag=?2,outcome_digest=?3,
                 outcome_evidence=?4,completed_at_be=?5
                 WHERE reconciliation_attempt_id=?1 AND outcome_digest IS NULL",
                params![
                    pending.request.reconciliation_attempt_id.as_slice(),
                    outcome_tag,
                    outcome_digest.as_slice(),
                    outcome_evidence.as_slice(),
                    u64_blob(now_unix_ms),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        let completion_event_id =
            reconciliation_completion_event_id(pending.request.reconciliation_attempt_id);
        append_next_journal(
            &transaction,
            JournalEventV1 {
                plan_id: lease.plan_id,
                event_tag: 7,
                event_id: completion_event_id,
                event_digest: reconciliation_completion_record_digest(outcome_digest, now_unix_ms),
                route_fence: lease.route_fencing_epoch,
                coordinator_fence: lease.coordinator_fencing_epoch,
            },
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    /// Authenticate and adopt a byte-equivalent plan under the newer route
    /// effect/fence after takeover. Stable aggregate action/custody identities
    /// must remain unchanged.
    pub fn refence_plan<A: SettlementPlanAuthorityV1>(
        &mut self,
        lease: CoordinatorLeaseV1,
        replacement: CompositeSettlementPlanV1,
        progress_evidence_digest: Digest32,
        authority: &mut A,
        now_unix_ms: u64,
    ) -> Result<SettlementPlanViewV1> {
        validate_digest(progress_evidence_digest)?;
        replacement.validate()?;
        let replacement_digest = replacement.canonical_digest()?;
        let replacement_bytes = replacement.encode_canonical()?;
        let authorization = authority
            .authorize_plan(PlanAuthorizationRequestV1 {
                plan: &replacement,
                plan_digest: replacement_digest,
            })
            .map_err(|_| CoordinatorErrorV1::PlanAuthorityRefused)?;
        if authorization.authority_id() != self.plan_authority_id
            || authorization.plan_digest() != replacement_digest
            || authorization.evidence_digest() == ZERO_DIGEST
            || authorization.valid_until_unix_ms() < now_unix_ms
        {
            return Err(CoordinatorErrorV1::InvalidPlanAuthorization);
        }
        let transaction = self.immediate(now_unix_ms)?;
        let current = validate_lease(&transaction, lease, now_unix_ms, false)?;
        if lease.route_fencing_epoch <= current.route_fence
            || replacement.bindings().fencing_epoch != lease.route_fencing_epoch
            || replacement.bindings().route_id != current.route_id
            || stable_plan_id(&replacement)? != lease.plan_id
        {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        let current_plan = decode_plan_row(&current)?;
        if !stable_plan_equivalent(&current_plan, &replacement)? {
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        let current_view = audit_plan(&transaction, lease.plan_id)?;
        require_deferred_completion_within_lease(&transaction, lease)?;
        let status = takeover_status_from_view(&transaction, &current_view)?;
        let expected_progress = takeover_progress_evidence(&transaction, &current_view)?;
        if progress_evidence_digest != expected_progress
            || matches!(status, CustodyTakeoverStatusV1::Unknown { .. })
        {
            return Err(CoordinatorErrorV1::ReconciliationRequired);
        }
        if let Some((other_plan,)) = transaction
            .query_row(
                "SELECT plan_id FROM settlement_plans WHERE effect_id=?1 AND plan_id<>?2",
                params![
                    replacement.bindings().effect_id.as_slice(),
                    lease.plan_id.as_slice()
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?,)),
            )
            .optional()
            .map_err(storage)?
        {
            let _ = other_plan;
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        if transaction
            .query_row(
                "SELECT 1 FROM settlement_plan_versions WHERE effect_id=?1",
                params![replacement.bindings().effect_id.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(storage)?
            .is_some()
        {
            return Err(CoordinatorErrorV1::IdempotencyConflict);
        }
        let version = count_plan_versions(&transaction, lease.plan_id)?
            .checked_add(1)
            .ok_or(CoordinatorErrorV1::InvalidBound)?;
        if version > MAX_PLAN_VERSIONS {
            return Err(CoordinatorErrorV1::InvalidBound);
        }
        transaction
            .execute(
                "INSERT INTO settlement_plan_versions(plan_id,version_be,plan_digest,effect_id,route_fence_be,plan_bytes,authorization_evidence,installed_at_be) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    lease.plan_id.as_slice(), u64_blob(version), replacement_digest.as_slice(),
                    replacement.bindings().effect_id.as_slice(), u64_blob(lease.route_fencing_epoch),
                    replacement_bytes, authorization.evidence_digest().as_slice(),
                    u64_blob(now_unix_ms),
                ],
            )
            .map_err(storage)?;
        let changed = transaction
            .execute(
                "UPDATE settlement_plans SET plan_digest=?2,effect_id=?3,route_fence_be=?4,
                 plan_bytes=?5,authorization_evidence=?6,updated_at_be=?7
                 WHERE plan_id=?1 AND plan_digest=?8 AND route_fence_be=?9",
                params![
                    lease.plan_id.as_slice(),
                    replacement_digest.as_slice(),
                    replacement.bindings().effect_id.as_slice(),
                    u64_blob(lease.route_fencing_epoch),
                    replacement.encode_canonical()?,
                    authorization.evidence_digest().as_slice(),
                    u64_blob(now_unix_ms),
                    current.plan_digest.as_slice(),
                    u64_blob(current.route_fence),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        append_next_journal(
            &transaction,
            JournalEventV1 {
                plan_id: lease.plan_id,
                event_tag: 8,
                event_id: domain_digest_v1(
                    b"DOM-INTEROP/SETTLEMENT-COORDINATOR/REFENCE-EVENT/V1\0",
                    &[
                        &replacement_digest,
                        &lease.route_fencing_epoch.to_be_bytes(),
                    ],
                ),
                event_digest: domain_digest_v1(
                    b"DOM-INTEROP/SETTLEMENT-COORDINATOR/REFENCE-RECORD/V1\0",
                    &[
                        &current.plan_digest,
                        &replacement_digest,
                        &progress_evidence_digest,
                    ],
                ),
                route_fence: lease.route_fencing_epoch,
                coordinator_fence: lease.coordinator_fencing_epoch,
            },
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        self.load_plan(lease.plan_id)
    }

    /// Observe one exact child. The request is journaled before the single
    /// chain-observer call, and aggregate finality requires both child proofs.
    pub fn observe_child_once<O: SettlementChildObserverV1>(
        &mut self,
        lease: CoordinatorLeaseV1,
        child_index: u8,
        observer: &mut O,
        now_unix_ms: u64,
    ) -> Result<CoordinatorObservationOutcomeV1> {
        if usize::from(child_index) >= MAX_SETTLEMENT_CHILDREN_V1 {
            return Err(CoordinatorErrorV1::InvalidBound);
        }
        let (request, request_digest) =
            self.prepare_observation(lease, child_index, now_unix_ms)?;
        let outcome = observer
            .observe_child(&request)
            .map_err(|_| CoordinatorErrorV1::ChildObserverRefused)?;
        self.complete_observation(lease, request, request_digest, outcome, now_unix_ms)
    }

    fn prepare_observation(
        &mut self,
        lease: CoordinatorLeaseV1,
        child_index: u8,
        now_unix_ms: u64,
    ) -> Result<(ChildObservationRequestV1, Digest32)> {
        let transaction = self.immediate(now_unix_ms)?;
        let plan = validate_lease(&transaction, lease, now_unix_ms, true)?;
        if !matches!(
            plan.stage,
            AGGREGATE_EXTERNALIZED | AGGREGATE_FINAL | AGGREGATE_FINALITY_INVALIDATED
        ) {
            return Err(CoordinatorErrorV1::InvalidState);
        }
        let child = load_child_row(&transaction, lease.plan_id, child_index)?;
        if !matches!(
            child.stage,
            CHILD_EXTERNALIZED | CHILD_FINAL | CHILD_FINALITY_INVALIDATED
        ) {
            return Err(CoordinatorErrorV1::InvalidState);
        }
        if let Some((attempt_id, request_digest)) = transaction
            .query_row(
                "SELECT observation_attempt_id,request_digest FROM observation_calls
                 WHERE plan_id=?1 AND child_index=?2 AND outcome_digest IS NULL
                 ORDER BY created_at_be DESC LIMIT 1",
                params![lease.plan_id.as_slice(), i64::from(child_index)],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(storage)?
        {
            let attempt_id = blob32(attempt_id)?;
            let observation_plan = pending_observation_plan(&transaction, &plan, attempt_id)?;
            let request =
                child_observation_request(&observation_plan, &child, child_index, attempt_id)?;
            let expected = child_observation_request_digest(&request);
            if blob32(request_digest)? != expected {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            transaction.commit().map_err(storage)?;
            return Ok((request, expected));
        }
        let sequence = count_observation_calls(&transaction, lease.plan_id, child_index)?
            .checked_add(1)
            .ok_or(CoordinatorErrorV1::InvalidBound)?;
        if sequence > MAX_OBSERVATIONS_PER_CHILD {
            return Err(CoordinatorErrorV1::InvalidBound);
        }
        let attempt_id = domain_digest_v1(
            b"DOM-INTEROP/SETTLEMENT-COORDINATOR/OBSERVATION-ATTEMPT/V1\0",
            &[
                &lease.plan_id,
                &[child_index],
                &sequence.to_be_bytes(),
                &plan.plan_digest,
                &lease.route_fencing_epoch.to_be_bytes(),
            ],
        );
        let request = child_observation_request(&plan, &child, child_index, attempt_id)?;
        let request_digest = child_observation_request_digest(&request);
        transaction
            .execute(
                "INSERT INTO observation_calls(observation_attempt_id,plan_id,child_index,request_digest,outcome_digest,result_tag,result_evidence,created_at_be,completed_at_be) VALUES(?1,?2,?3,?4,NULL,NULL,NULL,?5,NULL)",
                params![
                    attempt_id.as_slice(), lease.plan_id.as_slice(), i64::from(child_index),
                    request_digest.as_slice(), u64_blob(now_unix_ms),
                ],
            )
            .map_err(storage)?;
        append_next_journal(
            &transaction,
            JournalEventV1 {
                plan_id: lease.plan_id,
                event_tag: 9,
                event_id: attempt_id,
                event_digest: request_digest,
                route_fence: lease.route_fencing_epoch,
                coordinator_fence: lease.coordinator_fencing_epoch,
            },
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok((request, request_digest))
    }

    fn complete_observation(
        &mut self,
        lease: CoordinatorLeaseV1,
        request: ChildObservationRequestV1,
        request_digest: Digest32,
        outcome: ChildObservationOutcomeV1,
        now_unix_ms: u64,
    ) -> Result<CoordinatorObservationOutcomeV1> {
        let outcome_digest = child_observation_outcome_digest(&outcome)?;
        let transaction = self.immediate(now_unix_ms)?;
        let plan = validate_lease(&transaction, lease, now_unix_ms, true)?;
        if request.plan_id != lease.plan_id
            || request.route_fencing_epoch > lease.route_fencing_epoch
            || !observation_plan_version_matches(&transaction, &plan, &request)?
            || child_observation_request_digest(&request) != request_digest
        {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
        let retained: RetainedObservationRow = transaction
            .query_row(
                "SELECT request_digest,outcome_digest,result_tag,result_evidence FROM observation_calls WHERE observation_attempt_id=?1",
                params![request.observation_attempt_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(storage)?;
        if blob32(retained.0)? != request_digest {
            return Err(CoordinatorErrorV1::CorruptState);
        }
        if let Some(existing) = retained.1 {
            if blob32(existing)? != outcome_digest {
                fail_closed_conflict(
                    &transaction,
                    lease.plan_id,
                    request_digest,
                    outcome_digest,
                    request.observation_attempt_id,
                    now_unix_ms,
                )?;
                transaction.commit().map_err(storage)?;
                return Err(CoordinatorErrorV1::IdempotencyConflict);
            }
            let result_tag = retained.2.ok_or(CoordinatorErrorV1::CorruptState)?;
            let result_evidence = blob32(retained.3.ok_or(CoordinatorErrorV1::CorruptState)?)?;
            transaction.commit().map_err(storage)?;
            return retained_observation_outcome(
                &self.connection,
                lease.plan_id,
                request.child_index,
                result_tag,
                result_evidence,
            );
        }
        let child = load_child_row(&transaction, lease.plan_id, request.child_index)?;
        validate_observation_scope(&request, &child)?;
        let result = match outcome {
            ChildObservationOutcomeV1::Pending { evidence_digest } => {
                validate_digest(evidence_digest)?;
                CoordinatorObservationOutcomeV1::Pending { evidence_digest }
            }
            ChildObservationOutcomeV1::Final { evidence_digest } => {
                validate_digest(evidence_digest)?;
                if !matches!(
                    child.stage,
                    CHILD_EXTERNALIZED | CHILD_FINAL | CHILD_FINALITY_INVALIDATED
                ) {
                    return Err(CoordinatorErrorV1::InvalidState);
                }
                transaction
                    .execute(
                        "UPDATE settlement_children SET stage_tag=?3,finality_evidence=?4,
                         reorg_evidence=NULL WHERE plan_id=?1 AND child_index=?2",
                        params![
                            lease.plan_id.as_slice(),
                            i64::from(request.child_index),
                            CHILD_FINAL,
                            evidence_digest.as_slice(),
                        ],
                    )
                    .map_err(storage)?;
                let aggregate =
                    materialize_aggregate_finality(&transaction, lease.plan_id, now_unix_ms)?;
                match aggregate {
                    Some(value) => CoordinatorObservationOutcomeV1::AggregateFinal(value),
                    None => CoordinatorObservationOutcomeV1::ChildFinalized {
                        child_index: request.child_index,
                        evidence_digest,
                    },
                }
            }
            ChildObservationOutcomeV1::FinalityInvalidated {
                prior_finality_evidence_digest,
                reorg_evidence_digest,
            } => {
                validate_digest(prior_finality_evidence_digest)?;
                validate_digest(reorg_evidence_digest)?;
                if child.stage != CHILD_FINAL
                    || child.finality_evidence != Some(prior_finality_evidence_digest)
                {
                    return Err(CoordinatorErrorV1::ChildReceiptMismatch);
                }
                transaction
                    .execute(
                        "UPDATE settlement_children SET stage_tag=?3,finality_evidence=NULL,
                         reorg_evidence=?4 WHERE plan_id=?1 AND child_index=?2",
                        params![
                            lease.plan_id.as_slice(),
                            i64::from(request.child_index),
                            CHILD_FINALITY_INVALIDATED,
                            reorg_evidence_digest.as_slice(),
                        ],
                    )
                    .map_err(storage)?;
                let reorg = materialize_aggregate_reorg(
                    &transaction,
                    lease.plan_id,
                    request.child_index,
                    prior_finality_evidence_digest,
                    reorg_evidence_digest,
                    now_unix_ms,
                )?;
                CoordinatorObservationOutcomeV1::AggregateInvalidated(reorg)
            }
        };
        let (result_tag, result_evidence) = observation_result_record(&result);
        transaction
            .execute(
                "UPDATE observation_calls SET outcome_digest=?2,result_tag=?3,
                 result_evidence=?4,completed_at_be=?5
                 WHERE observation_attempt_id=?1 AND outcome_digest IS NULL",
                params![
                    request.observation_attempt_id.as_slice(),
                    outcome_digest.as_slice(),
                    result_tag,
                    result_evidence.as_slice(),
                    u64_blob(now_unix_ms),
                ],
            )
            .map_err(storage)?;
        append_next_journal(
            &transaction,
            JournalEventV1 {
                plan_id: lease.plan_id,
                event_tag: match outcome {
                    ChildObservationOutcomeV1::Pending { .. } => 10,
                    ChildObservationOutcomeV1::Final { .. } => 11,
                    ChildObservationOutcomeV1::FinalityInvalidated { .. } => 12,
                },
                event_id: domain_digest_v1(
                    b"DOM-INTEROP/SETTLEMENT-COORDINATOR/OBSERVATION-EVENT/V1\0",
                    &[&request.observation_attempt_id, &outcome_digest],
                ),
                event_digest: outcome_digest,
                route_fence: lease.route_fencing_epoch,
                coordinator_fence: lease.coordinator_fencing_epoch,
            },
            now_unix_ms,
        )?;
        transaction.commit().map_err(storage)?;
        Ok(result)
    }

    fn current_drive_outcome(&self, plan_id: Digest32) -> Result<CoordinatorDriveOutcomeV1> {
        let view = self.load_plan(plan_id)?;
        if view.completed_prefix == MAX_SETTLEMENT_CHILDREN_V1 as u8 {
            return Ok(CoordinatorDriveOutcomeV1::AggregateExternalized(
                aggregate_receipt_from_view(&self.connection, &view)?,
            ));
        }
        let progress = partial_progress_from_view(&self.connection, &view)?;
        Ok(CoordinatorDriveOutcomeV1::PartialProgress(progress))
    }
}

fn validate_identity(coordinator_id: Digest32, plan_authority_id: Digest32) -> Result<()> {
    validate_digest(coordinator_id)?;
    validate_digest(plan_authority_id)?;
    if coordinator_id == plan_authority_id {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

fn validate_digest(value: Digest32) -> Result<()> {
    if value == ZERO_DIGEST {
        return Err(CoordinatorErrorV1::InvalidPlan);
    }
    Ok(())
}

fn validate_lease_bound(now_unix_ms: u64, lease_duration_ms: u64) -> Result<()> {
    if now_unix_ms == 0
        || lease_duration_ms == 0
        || lease_duration_ms > MAX_LEASE_DURATION_MS
        || now_unix_ms.checked_add(lease_duration_ms).is_none()
    {
        return Err(CoordinatorErrorV1::InvalidBound);
    }
    Ok(())
}

fn acquire_lease_row(
    connection: &Connection,
    plan_id: Digest32,
    owner_id: Digest32,
    route_fence: u64,
    takeover_evidence: Option<Digest32>,
    now_unix_ms: u64,
    lease_duration_ms: u64,
) -> Result<CoordinatorLeaseAcquireV1> {
    let lease_until = now_unix_ms
        .checked_add(lease_duration_ms)
        .ok_or(CoordinatorErrorV1::InvalidBound)?;
    let retained = connection
        .query_row(
            "SELECT owner_id,route_fence_be,coordinator_fence_be,lease_until_be
             FROM coordinator_leases WHERE plan_id=?1",
            params![plan_id.as_slice()],
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
        .map_err(storage)?;
    match retained {
        None => {
            connection
                .execute(
                    "INSERT INTO coordinator_leases(plan_id,owner_id,route_fence_be,
                     coordinator_fence_be,lease_until_be,takeover_evidence,updated_at_be)
                     VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        plan_id.as_slice(),
                        owner_id.as_slice(),
                        u64_blob(route_fence),
                        u64_blob(1),
                        u64_blob(lease_until),
                        takeover_evidence.map(|value| value.to_vec()),
                        u64_blob(now_unix_ms),
                    ],
                )
                .map_err(storage)?;
            Ok(CoordinatorLeaseAcquireV1::Acquired(CoordinatorLeaseV1 {
                plan_id,
                owner_id,
                route_fencing_epoch: route_fence,
                coordinator_fencing_epoch: 1,
                lease_until_unix_ms: lease_until,
            }))
        }
        Some((stored_owner, stored_route, stored_coordinator, stored_until)) => {
            let stored_owner = blob32(stored_owner)?;
            let stored_route = blob_u64(stored_route)?;
            let stored_coordinator = blob_u64(stored_coordinator)?;
            let stored_until = blob_u64(stored_until)?;
            if takeover_evidence.is_none()
                && stored_owner == owner_id
                && stored_route == route_fence
                && stored_until >= now_unix_ms
            {
                let new_until = stored_until.max(lease_until);
                connection
                    .execute(
                        "UPDATE coordinator_leases SET lease_until_be=?2,updated_at_be=?3
                         WHERE plan_id=?1",
                        params![
                            plan_id.as_slice(),
                            u64_blob(new_until),
                            u64_blob(now_unix_ms)
                        ],
                    )
                    .map_err(storage)?;
                return Ok(CoordinatorLeaseAcquireV1::AlreadyOwned(
                    CoordinatorLeaseV1 {
                        plan_id,
                        owner_id,
                        route_fencing_epoch: route_fence,
                        coordinator_fencing_epoch: stored_coordinator,
                        lease_until_unix_ms: new_until,
                    },
                ));
            }
            if takeover_evidence.is_none() && stored_until >= now_unix_ms {
                return Err(CoordinatorErrorV1::LeaseHeld);
            }
            if takeover_evidence.is_some() && stored_route >= route_fence {
                return Err(CoordinatorErrorV1::StaleFencing);
            }
            let coordinator_fence = stored_coordinator
                .checked_add(1)
                .ok_or(CoordinatorErrorV1::InvalidBound)?;
            connection
                .execute(
                    "UPDATE coordinator_leases SET owner_id=?2,route_fence_be=?3,
                     coordinator_fence_be=?4,lease_until_be=?5,takeover_evidence=?6,
                     updated_at_be=?7 WHERE plan_id=?1",
                    params![
                        plan_id.as_slice(),
                        owner_id.as_slice(),
                        u64_blob(route_fence),
                        u64_blob(coordinator_fence),
                        u64_blob(lease_until),
                        takeover_evidence.map(|value| value.to_vec()),
                        u64_blob(now_unix_ms),
                    ],
                )
                .map_err(storage)?;
            Ok(CoordinatorLeaseAcquireV1::Acquired(CoordinatorLeaseV1 {
                plan_id,
                owner_id,
                route_fencing_epoch: route_fence,
                coordinator_fencing_epoch: coordinator_fence,
                lease_until_unix_ms: lease_until,
            }))
        }
    }
}

fn validate_lease(
    connection: &Connection,
    lease: CoordinatorLeaseV1,
    now_unix_ms: u64,
    require_current_plan_fence: bool,
) -> Result<PlanRow> {
    validate_digest(lease.plan_id)?;
    let clock: Vec<u8> = connection
        .query_row(
            "SELECT clock_high_water_be FROM coordinator_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if now_unix_ms < blob_u64(clock)? {
        return Err(CoordinatorErrorV1::InvalidBound);
    }
    let retained = connection
        .query_row(
            "SELECT owner_id,route_fence_be,coordinator_fence_be,lease_until_be
             FROM coordinator_leases WHERE plan_id=?1",
            params![lease.plan_id.as_slice()],
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
        .map_err(storage)?
        .ok_or(CoordinatorErrorV1::StaleFencing)?;
    let retained_until = blob_u64(retained.3)?;
    if blob32(retained.0)? != lease.owner_id
        || blob_u64(retained.1)? != lease.route_fencing_epoch
        || blob_u64(retained.2)? != lease.coordinator_fencing_epoch
        || retained_until != lease.lease_until_unix_ms
    {
        return Err(CoordinatorErrorV1::StaleFencing);
    }
    if retained_until < now_unix_ms {
        return Err(CoordinatorErrorV1::LeaseExpired);
    }
    let plan = load_plan_row(connection, lease.plan_id)?;
    if plan.stage == AGGREGATE_FAILED_CLOSED {
        return Err(CoordinatorErrorV1::FailedClosed);
    }
    if require_current_plan_fence {
        if plan.route_fence != lease.route_fencing_epoch {
            return Err(CoordinatorErrorV1::StaleFencing);
        }
    } else if lease.route_fencing_epoch < plan.route_fence {
        return Err(CoordinatorErrorV1::StaleFencing);
    }
    Ok(plan)
}

fn advance_clock(connection: &Connection, now_unix_ms: u64) -> Result<()> {
    if now_unix_ms == 0 {
        return Err(CoordinatorErrorV1::InvalidBound);
    }
    let retained: Vec<u8> = connection
        .query_row(
            "SELECT clock_high_water_be FROM coordinator_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    let retained = blob_u64(retained)?;
    if now_unix_ms < retained {
        return Err(CoordinatorErrorV1::InvalidBound);
    }
    connection
        .execute(
            "UPDATE coordinator_metadata SET clock_high_water_be=?1 WHERE singleton=1",
            params![u64_blob(now_unix_ms)],
        )
        .map_err(storage)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct JournalEventV1 {
    plan_id: Digest32,
    event_tag: i64,
    event_id: Digest32,
    event_digest: Digest32,
    route_fence: u64,
    coordinator_fence: u64,
}

fn append_journal(connection: &Connection, event: JournalEventV1, now_unix_ms: u64) -> Result<()> {
    validate_digest(event.event_id)?;
    validate_digest(event.event_digest)?;
    if !(1..=14).contains(&event.event_tag) {
        return Err(CoordinatorErrorV1::InvalidState);
    }
    let plan = load_plan_row(connection, event.plan_id)?;
    let sequence = plan
        .revision
        .checked_add(1)
        .ok_or(CoordinatorErrorV1::InvalidBound)?;
    if sequence > MAX_JOURNAL_ENTRIES {
        return Err(CoordinatorErrorV1::InvalidBound);
    }
    let entry_hash = journal_entry_hash(event, sequence, plan.journal_head);
    connection
        .execute(
            "INSERT INTO coordinator_journal(plan_id,sequence_be,event_id,event_tag,event_digest,
             route_fence_be,coordinator_fence_be,previous_entry_hash,entry_hash,created_at_be)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                event.plan_id.as_slice(),
                u64_blob(sequence),
                event.event_id.as_slice(),
                event.event_tag,
                event.event_digest.as_slice(),
                u64_blob(event.route_fence),
                u64_blob(event.coordinator_fence),
                plan.journal_head.as_slice(),
                entry_hash.as_slice(),
                u64_blob(now_unix_ms),
            ],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                CoordinatorErrorV1::IdempotencyConflict
            } else {
                storage(error)
            }
        })?;
    let changed = connection
        .execute(
            "UPDATE settlement_plans SET revision_be=?2,journal_head=?3,updated_at_be=?4
             WHERE plan_id=?1 AND revision_be=?5 AND journal_head=?6",
            params![
                event.plan_id.as_slice(),
                u64_blob(sequence),
                entry_hash.as_slice(),
                u64_blob(now_unix_ms),
                u64_blob(plan.revision),
                plan.journal_head.as_slice(),
            ],
        )
        .map_err(storage)?;
    if changed != 1 {
        return Err(CoordinatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn append_next_journal(
    connection: &Connection,
    event: JournalEventV1,
    now_unix_ms: u64,
) -> Result<()> {
    append_journal(connection, event, now_unix_ms)
}

fn journal_entry_hash(event: JournalEventV1, sequence: u64, previous: Digest32) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/JOURNAL-ENTRY/V1\0",
        &[
            &event.plan_id,
            &sequence.to_be_bytes(),
            &event.event_id,
            &event.event_tag.to_be_bytes(),
            &event.event_digest,
            &event.route_fence.to_be_bytes(),
            &event.coordinator_fence.to_be_bytes(),
            &previous,
        ],
    )
}

fn fail_closed_conflict(
    connection: &Connection,
    plan_id: Digest32,
    existing_digest: Digest32,
    conflicting_digest: Digest32,
    evidence_digest: Digest32,
    now_unix_ms: u64,
) -> Result<()> {
    let conflict_id = domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CONFLICT/V1\0",
        &[
            &plan_id,
            &existing_digest,
            &conflicting_digest,
            &evidence_digest,
        ],
    );
    connection
        .execute(
            "INSERT OR IGNORE INTO coordinator_conflicts(conflict_id,plan_id,existing_digest,
             conflicting_digest,evidence_digest,created_at_be) VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                conflict_id.as_slice(),
                plan_id.as_slice(),
                existing_digest.as_slice(),
                conflicting_digest.as_slice(),
                evidence_digest.as_slice(),
                u64_blob(now_unix_ms),
            ],
        )
        .map_err(storage)?;
    connection
        .execute(
            "UPDATE settlement_plans SET stage_tag=?2,updated_at_be=?3 WHERE plan_id=?1",
            params![
                plan_id.as_slice(),
                AGGREGATE_FAILED_CLOSED,
                u64_blob(now_unix_ms)
            ],
        )
        .map_err(storage)?;
    Ok(())
}

fn count_plan_versions(connection: &Connection, plan_id: Digest32) -> Result<u64> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM settlement_plan_versions WHERE plan_id=?1",
            params![plan_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    u64::try_from(count).map_err(|_| CoordinatorErrorV1::CorruptState)
}

fn count_observation_calls(
    connection: &Connection,
    plan_id: Digest32,
    child_index: u8,
) -> Result<u64> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM observation_calls WHERE plan_id=?1 AND child_index=?2",
            params![plan_id.as_slice(), i64::from(child_index)],
            |row| row.get(0),
        )
        .map_err(storage)?;
    u64::try_from(count).map_err(|_| CoordinatorErrorV1::CorruptState)
}

fn prepared_dispatch_sequence(
    connection: &Connection,
    plan_id: Digest32,
    attempt_id: Digest32,
) -> Result<u64> {
    let sequence: Vec<u8> = connection
        .query_row(
            "SELECT sequence_be FROM coordinator_journal
             WHERE plan_id=?1 AND event_id=?2 AND event_tag=2",
            params![plan_id.as_slice(), attempt_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(storage)?;
    blob_u64(sequence)
}

fn audited_dispatch_request(
    connection: &Connection,
    current: &PlanRow,
    child: &ChildRow,
    attempt: u64,
    attempt_id: Digest32,
) -> Result<ChildDispatchRequestV1> {
    let prepared: (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT event_digest,route_fence_be,coordinator_fence_be
             FROM coordinator_journal
             WHERE plan_id=?1 AND event_id=?2 AND event_tag=2",
            params![current.plan_id.as_slice(), attempt_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(storage)?;
    let call_record_digest = blob32(prepared.0)?;
    let route_fence = blob_u64(prepared.1)?;
    let coordinator_fence = blob_u64(prepared.2)?;

    let mut statement = connection
        .prepare(
            "SELECT plan_digest,plan_bytes FROM settlement_plan_versions
             WHERE plan_id=?1 AND route_fence_be=?2 ORDER BY version_be LIMIT 2",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(
            params![current.plan_id.as_slice(), u64_blob(route_fence)],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .map_err(storage)?;
    let mut versions = Vec::with_capacity(2);
    for row in rows {
        versions.push(row.map_err(storage)?);
    }
    if versions.len() != 1 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let (plan_digest, plan_bytes) = versions.pop().ok_or(CoordinatorErrorV1::CorruptState)?;
    let plan_digest = blob32(plan_digest)?;
    let decoded = CompositeSettlementPlanV1::decode_canonical(&plan_bytes)
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    if decoded
        .canonical_digest()
        .map_err(|_| CoordinatorErrorV1::CorruptState)?
        != plan_digest
        || stable_plan_id(&decoded).map_err(|_| CoordinatorErrorV1::CorruptState)?
            != current.plan_id
        || aggregate_action_id(&decoded).map_err(|_| CoordinatorErrorV1::CorruptState)?
            != current.aggregate_action_id
        || aggregate_custody_digest(&decoded).map_err(|_| CoordinatorErrorV1::CorruptState)?
            != current.aggregate_custody_digest
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let mut historical = current.clone();
    historical.plan_digest = plan_digest;
    historical.route_fence = route_fence;
    historical.plan_bytes = plan_bytes;
    let request = child_dispatch_request_with_fences(
        &historical,
        &decoded,
        child,
        ChildDispatchFenceV1 {
            child_index: child.child_index,
            attempt,
            route_fence,
            coordinator_fence,
        },
    )?;
    if request.attempt_id != attempt_id || child_call_record_digest(&request) != call_record_digest
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(request)
}

fn child_dispatch_request(
    plan: &PlanRow,
    decoded: &CompositeSettlementPlanV1,
    child: &ChildRow,
    lease: CoordinatorLeaseV1,
    child_index: u8,
    attempt: u64,
) -> Result<ChildDispatchRequestV1> {
    if lease.plan_id != plan.plan_id
        || lease.route_fencing_epoch != plan.route_fence
        || child.child_index != child_index
        || attempt == 0
    {
        return Err(CoordinatorErrorV1::StaleFencing);
    }
    child_dispatch_request_with_fences(
        plan,
        decoded,
        child,
        ChildDispatchFenceV1 {
            child_index,
            attempt,
            route_fence: lease.route_fencing_epoch,
            coordinator_fence: lease.coordinator_fencing_epoch,
        },
    )
}

#[derive(Clone, Copy)]
struct ChildDispatchFenceV1 {
    child_index: u8,
    attempt: u64,
    route_fence: u64,
    coordinator_fence: u64,
}

fn child_dispatch_request_with_fences(
    plan: &PlanRow,
    decoded: &CompositeSettlementPlanV1,
    child: &ChildRow,
    fence: ChildDispatchFenceV1,
) -> Result<ChildDispatchRequestV1> {
    if plan.plan_id == ZERO_DIGEST
        || plan.plan_digest == ZERO_DIGEST
        || child.child_index != fence.child_index
        || usize::from(fence.child_index) >= MAX_SETTLEMENT_CHILDREN_V1
        || fence.attempt == 0
        || fence.route_fence != decoded.bindings().fencing_epoch
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let bindings = decoded.bindings();
    let (profile_digest, deployment_digest) = if child.face == SettlementFaceV1::Dom {
        (bindings.dom_profile_digest, bindings.dom_deployment_digest)
    } else {
        (
            bindings.counterparty_profile_digest,
            bindings.counterparty_deployment_digest,
        )
    };
    let attempt_id = domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-ATTEMPT/V1\0",
        &[
            &plan.plan_id,
            &plan.plan_digest,
            &bindings.route_id,
            &bindings.effect_id,
            &[fence.child_index],
            &fence.attempt.to_be_bytes(),
            &fence.route_fence.to_be_bytes(),
            &fence.coordinator_fence.to_be_bytes(),
            &child.expected_tx_id,
            &child.intent_digest,
            &child.custody_digest,
        ],
    );
    Ok(ChildDispatchRequestV1 {
        plan_id: plan.plan_id,
        plan_digest: plan.plan_digest,
        aggregate_action_id: plan.aggregate_action_id,
        aggregate_custody_digest: plan.aggregate_custody_digest,
        route_id: bindings.route_id,
        effect_id: bindings.effect_id,
        settlement_id: bindings.settlement_id,
        leg: bindings.leg,
        action: bindings.action,
        semantic_digest: bindings.semantic_digest,
        terms_digest: bindings.terms_digest,
        registry_digest: bindings.registry_digest,
        profile_digest,
        deployment_digest,
        route_fencing_epoch: fence.route_fence,
        coordinator_fencing_epoch: fence.coordinator_fence,
        child_index: fence.child_index,
        face: child.face,
        exposure: child.exposure,
        chain_id: child.chain_id,
        expected_transaction_id: child.expected_tx_id,
        intent_digest: child.intent_digest,
        custody_digest: child.custody_digest,
        attempt: fence.attempt,
        attempt_id,
    })
}

fn pending_dispatch_request(
    connection: &Connection,
    plan: &PlanRow,
    decoded: &CompositeSettlementPlanV1,
    child: &ChildRow,
    child_index: u8,
) -> Result<ChildDispatchRequestV1> {
    let attempt_id = child
        .pending_attempt_id
        .ok_or(CoordinatorErrorV1::CorruptState)?;
    let (route_fence, coordinator_fence): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT route_fence_be,coordinator_fence_be FROM coordinator_journal
             WHERE plan_id=?1 AND event_id=?2 AND event_tag=2",
            params![plan.plan_id.as_slice(), attempt_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(storage)?;
    let request = child_dispatch_request_with_fences(
        plan,
        decoded,
        child,
        ChildDispatchFenceV1 {
            child_index,
            attempt: child.call_attempt,
            route_fence: blob_u64(route_fence)?,
            coordinator_fence: blob_u64(coordinator_fence)?,
        },
    )?;
    if request.attempt_id != attempt_id
        || child.pending_call_digest != Some(child_call_record_digest(&request))
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(request)
}

fn pending_child_token(
    connection: &Connection,
    plan: &PlanRow,
    decoded: &CompositeSettlementPlanV1,
    child: &ChildRow,
    lease: CoordinatorLeaseV1,
    child_index: u8,
) -> Result<PendingChildCallV1> {
    let request = pending_dispatch_request(connection, plan, decoded, child, child_index)?;
    if request.route_fencing_epoch != lease.route_fencing_epoch
        || request.coordinator_fencing_epoch != lease.coordinator_fencing_epoch
    {
        return Err(CoordinatorErrorV1::ReconciliationRequired);
    }
    Ok(PendingChildCallV1 {
        call_record_digest: child_call_record_digest(&request),
        request,
    })
}

fn child_call_record_digest(request: &ChildDispatchRequestV1) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-CALL/V1\0",
        &[
            &request.plan_id,
            &request.plan_digest,
            &request.aggregate_action_id,
            &request.aggregate_custody_digest,
            &request.route_id,
            &request.effect_id,
            &request.settlement_id,
            &[request.leg.tag()],
            &[request.action.tag()],
            &request.semantic_digest,
            &request.terms_digest,
            &request.registry_digest,
            &request.profile_digest,
            &request.deployment_digest,
            &request.route_fencing_epoch.to_be_bytes(),
            &request.coordinator_fencing_epoch.to_be_bytes(),
            &[request.child_index],
            &[request.face.tag()],
            &[request.exposure.tag()],
            &request.chain_id,
            &request.expected_transaction_id,
            &request.intent_digest,
            &request.custody_digest,
            &request.attempt.to_be_bytes(),
            &request.attempt_id,
        ],
    )
}

fn validate_pending_call_token(
    plan: &PlanRow,
    pending: &PendingChildCallV1,
    lease: CoordinatorLeaseV1,
) -> Result<()> {
    let request = &pending.request;
    if request.plan_id != plan.plan_id
        || request.plan_digest != plan.plan_digest
        || request.effect_id != plan.effect_id
        || request.aggregate_action_id != plan.aggregate_action_id
        || request.aggregate_custody_digest != plan.aggregate_custody_digest
        || request.route_fencing_epoch != lease.route_fencing_epoch
        || request.coordinator_fencing_epoch != lease.coordinator_fencing_epoch
        || pending.call_record_digest != child_call_record_digest(request)
    {
        return Err(CoordinatorErrorV1::StaleFencing);
    }
    Ok(())
}

fn receipt_digest(receipt: &ChildExternalizationReceiptV1) -> Result<Digest32> {
    validate_digest(receipt.externalization_evidence_digest)?;
    if let Some(evidence) = receipt.first_exposure_evidence_digest {
        validate_digest(evidence)?;
    }
    let (present, exposure) = match receipt.first_exposure_evidence_digest {
        Some(value) => (1u8, value),
        None => (0u8, ZERO_DIGEST),
    };
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-RECEIPT/V1\0",
        &[
            &receipt.plan_id,
            &[receipt.child_index],
            &[receipt.face.tag()],
            &receipt.chain_id,
            &receipt.transaction_id,
            &receipt.intent_digest,
            &receipt.custody_digest,
            &receipt.externalization_evidence_digest,
            &[present],
            &exposure,
        ],
    ))
}

fn persisted_child_receipt_digest(plan: &PlanRow, child: &ChildRow) -> Result<Digest32> {
    if child.stage < CHILD_EXTERNALIZED {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let first_exposure_evidence_digest = match child.exposure {
        ChildExposureV1::FirstSecretExposure => {
            if plan.first_exposure_child != Some(child.child_index) {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            Some(
                plan.first_exposure_evidence
                    .ok_or(CoordinatorErrorV1::CorruptState)?,
            )
        }
        ChildExposureV1::UsesPublicSecret | ChildExposureV1::NonSecret => None,
    };
    receipt_digest(&ChildExternalizationReceiptV1 {
        plan_id: plan.plan_id,
        child_index: child.child_index,
        face: child.face,
        chain_id: child.chain_id,
        transaction_id: child.expected_tx_id,
        intent_digest: child.intent_digest,
        custody_digest: child.custody_digest,
        externalization_evidence_digest: child
            .externalization_evidence
            .ok_or(CoordinatorErrorV1::CorruptState)?,
        first_exposure_evidence_digest,
    })
}

fn child_execution_outcome_digest(outcome: &ChildExecutionOutcomeV1) -> Result<Digest32> {
    match outcome {
        ChildExecutionOutcomeV1::Externalized(receipt) => Ok(domain_digest_v1(
            b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-OUTCOME/EXTERNALIZED/V1\0",
            &[&receipt_digest(receipt)?],
        )),
        ChildExecutionOutcomeV1::RetryableBeforeExternalization { evidence_digest } => {
            validate_digest(*evidence_digest)?;
            Ok(domain_digest_v1(
                b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-OUTCOME/RETRYABLE/V1\0",
                &[evidence_digest],
            ))
        }
        ChildExecutionOutcomeV1::Unknown { evidence_digest } => {
            validate_digest(*evidence_digest)?;
            Ok(original_unknown_outcome_digest(*evidence_digest))
        }
    }
}

fn original_unknown_outcome_digest(evidence_digest: Digest32) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-OUTCOME/UNKNOWN/V1\0",
        &[&evidence_digest],
    )
}

fn child_completion_event_id(attempt_id: Digest32) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-COMPLETED-EVENT/V2\0",
        &[&attempt_id],
    )
}

fn child_completion_record_digest(outcome_digest: Digest32, completed_at_unix_ms: u64) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-COMPLETION/V2\0",
        &[&outcome_digest, &completed_at_unix_ms.to_be_bytes()],
    )
}

fn validate_child_receipt(
    request: &ChildDispatchRequestV1,
    receipt: &ChildExternalizationReceiptV1,
) -> Result<()> {
    receipt_digest(receipt)?;
    let exposure_valid = match request.exposure {
        ChildExposureV1::FirstSecretExposure => receipt.first_exposure_evidence_digest.is_some(),
        ChildExposureV1::NonSecret | ChildExposureV1::UsesPublicSecret => {
            receipt.first_exposure_evidence_digest.is_none()
        }
    };
    if !exposure_valid
        || receipt.plan_id != request.plan_id
        || receipt.child_index != request.child_index
        || receipt.face != request.face
        || receipt.chain_id != request.chain_id
        || receipt.transaction_id != request.expected_transaction_id
        || receipt.intent_digest != request.intent_digest
        || receipt.custody_digest != request.custody_digest
    {
        return Err(CoordinatorErrorV1::ChildReceiptMismatch);
    }
    Ok(())
}

fn clear_pending_child(
    connection: &Connection,
    plan_id: Digest32,
    child_index: u8,
    target_stage: i64,
    ambiguity_evidence: Option<Digest32>,
) -> Result<()> {
    let changed = connection
        .execute(
            "UPDATE settlement_children SET stage_tag=?3,pending_attempt_id=NULL,
             pending_call_digest=NULL,last_ambiguity_evidence=?4,
             reconciliation_attempt_id=NULL,reconciliation_record_digest=NULL
             WHERE plan_id=?1 AND child_index=?2 AND stage_tag=?5",
            params![
                plan_id.as_slice(),
                i64::from(child_index),
                target_stage,
                ambiguity_evidence.map(|value| value.to_vec()),
                CHILD_CALL_PENDING,
            ],
        )
        .map_err(storage)?;
    if changed != 1 {
        return Err(CoordinatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn persist_child_externalized(
    connection: &Connection,
    plan: &PlanRow,
    request: &ChildDispatchRequestV1,
    receipt: &ChildExternalizationReceiptV1,
    now_unix_ms: u64,
) -> Result<()> {
    validate_child_receipt(request, receipt)?;
    let child = load_child_row(connection, plan.plan_id, request.child_index)?;
    if child.stage != CHILD_CALL_PENDING
        || child.pending_attempt_id != Some(request.attempt_id)
        || child.pending_call_digest != Some(child_call_record_digest(request))
    {
        return Err(CoordinatorErrorV1::IdempotencyConflict);
    }
    let fresh_plan = load_plan_row(connection, plan.plan_id)?;
    match request.exposure {
        ChildExposureV1::FirstSecretExposure => {
            let exposure = receipt
                .first_exposure_evidence_digest
                .ok_or(CoordinatorErrorV1::ChildReceiptMismatch)?;
            if fresh_plan.secret_state != SECRET_EXPOSURE_POSSIBLE || request.child_index != 0 {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            let changed = connection
                .execute(
                    "UPDATE settlement_plans SET secret_state_tag=?2,
                     first_exposure_child=?3,first_exposure_chain=?4,
                     first_exposure_tx=?5,first_exposure_evidence=?6,
                     first_exposure_observed_at_be=?7,updated_at_be=?7
                     WHERE plan_id=?1 AND secret_state_tag=?8",
                    params![
                        plan.plan_id.as_slice(),
                        SECRET_PUBLIC,
                        i64::from(request.child_index),
                        request.chain_id.as_slice(),
                        request.expected_transaction_id.as_slice(),
                        exposure.as_slice(),
                        u64_blob(now_unix_ms),
                        SECRET_EXPOSURE_POSSIBLE,
                    ],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
        ChildExposureV1::UsesPublicSecret => {
            if fresh_plan.secret_state != SECRET_PUBLIC {
                return Err(CoordinatorErrorV1::InvalidState);
            }
        }
        ChildExposureV1::NonSecret => {
            if fresh_plan.secret_state == SECRET_EXPOSURE_POSSIBLE {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
    }
    let changed = connection
        .execute(
            "UPDATE settlement_children SET stage_tag=?3,pending_attempt_id=NULL,
             pending_call_digest=NULL,last_ambiguity_evidence=NULL,
             externalization_evidence=?4,finality_evidence=NULL,reorg_evidence=NULL,
             reconciliation_attempt_id=NULL,reconciliation_record_digest=NULL
             WHERE plan_id=?1 AND child_index=?2 AND stage_tag=?5",
            params![
                plan.plan_id.as_slice(),
                i64::from(request.child_index),
                CHILD_EXTERNALIZED,
                receipt.externalization_evidence_digest.as_slice(),
                CHILD_CALL_PENDING,
            ],
        )
        .map_err(storage)?;
    if changed != 1 {
        return Err(CoordinatorErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn child_receipts_digest(connection: &Connection, plan: &PlanRow) -> Result<Digest32> {
    let children = load_child_rows(connection, plan.plan_id)?;
    if children
        .iter()
        .any(|child| child.stage < CHILD_EXTERNALIZED || child.externalization_evidence.is_none())
    {
        return Err(CoordinatorErrorV1::InvalidState);
    }
    let first_exposure = plan.first_exposure_evidence.unwrap_or(ZERO_DIGEST);
    let first_exposure_observed_at = plan.first_exposure_observed_at.unwrap_or(0);
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/AGGREGATE-RECEIPTS/V2\0",
        &[
            &plan.plan_id,
            &plan.aggregate_action_id,
            &plan.aggregate_custody_digest,
            &[children[0].face.tag()],
            &children[0].chain_id,
            &children[0].expected_tx_id,
            &children[0].intent_digest,
            &children[0].custody_digest,
            &children[0]
                .externalization_evidence
                .ok_or(CoordinatorErrorV1::CorruptState)?,
            &[children[1].face.tag()],
            &children[1].chain_id,
            &children[1].expected_tx_id,
            &children[1].intent_digest,
            &children[1].custody_digest,
            &children[1]
                .externalization_evidence
                .ok_or(CoordinatorErrorV1::CorruptState)?,
            &first_exposure,
            &first_exposure_observed_at.to_be_bytes(),
        ],
    ))
}

fn expected_aggregate_finality_digest(plan: &PlanRow, children: &[ChildRow]) -> Result<Digest32> {
    if children.len() != MAX_SETTLEMENT_CHILDREN_V1
        || !children.iter().all(|child| child.stage == CHILD_FINAL)
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let first = children[0]
        .finality_evidence
        .ok_or(CoordinatorErrorV1::CorruptState)?;
    let second = children[1]
        .finality_evidence
        .ok_or(CoordinatorErrorV1::CorruptState)?;
    let aggregate_receipt = plan
        .aggregate_receipt_digest
        .ok_or(CoordinatorErrorV1::CorruptState)?;
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/AGGREGATE-FINALITY/V1\0",
        &[
            &plan.plan_id,
            &plan.aggregate_action_id,
            &aggregate_receipt,
            &first,
            &second,
        ],
    ))
}

fn materialize_aggregate_externalization(
    connection: &Connection,
    plan_id: Digest32,
    now_unix_ms: u64,
) -> Result<()> {
    let plan = load_plan_row(connection, plan_id)?;
    let decoded = decode_plan_row(&plan)?;
    let children = load_child_rows(connection, plan_id)?;
    if validate_child_prefix(&children, &decoded)? != MAX_SETTLEMENT_CHILDREN_V1 as u8 {
        return Ok(());
    }
    let receipts = child_receipts_digest(connection, &plan)?;
    match plan.stage {
        AGGREGATE_ACTIVE => {
            let changed = connection
                .execute(
                    "UPDATE settlement_plans SET stage_tag=?2,aggregate_receipt_digest=?3,
                     aggregate_finality_digest=NULL,aggregate_reorg_digest=NULL,updated_at_be=?4
                     WHERE plan_id=?1 AND stage_tag=?5 AND aggregate_receipt_digest IS NULL",
                    params![
                        plan_id.as_slice(),
                        AGGREGATE_EXTERNALIZED,
                        receipts.as_slice(),
                        u64_blob(now_unix_ms),
                        AGGREGATE_ACTIVE,
                    ],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
        AGGREGATE_EXTERNALIZED | AGGREGATE_FINAL | AGGREGATE_FINALITY_INVALIDATED
            if plan.aggregate_receipt_digest == Some(receipts) => {}
        _ => return Err(CoordinatorErrorV1::CorruptState),
    }
    Ok(())
}

fn child_reconciliation_record_digest(request: &ChildReconciliationRequestV1) -> Digest32 {
    child_reconciliation_record_digest_parts(
        child_call_record_digest(&request.dispatch),
        request.current_route_fencing_epoch,
        request.current_coordinator_fencing_epoch,
        request.reconciliation_attempt_id,
    )
}

fn child_reconciliation_record_digest_parts(
    dispatch_record_digest: Digest32,
    route_fence: u64,
    coordinator_fence: u64,
    reconciliation_attempt_id: Digest32,
) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION-CALL/V2\0",
        &[
            &dispatch_record_digest,
            &route_fence.to_be_bytes(),
            &coordinator_fence.to_be_bytes(),
            &reconciliation_attempt_id,
        ],
    )
}

fn reconciliation_prepared_prior_digest(dispatch: &ChildDispatchRequestV1) -> Digest32 {
    reconciliation_prepared_prior_digest_parts(
        dispatch.attempt_id,
        child_call_record_digest(dispatch),
    )
}

fn reconciliation_prepared_prior_digest_parts(
    dispatch_attempt_id: Digest32,
    dispatch_record_digest: Digest32,
) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION-PREPARED-PRIOR/V1\0",
        &[&dispatch_attempt_id, &dispatch_record_digest],
    )
}

fn reconciliation_attempt_id(
    dispatch_attempt_id: Digest32,
    sequence: u64,
    scope_tag: i64,
    route_fence: u64,
    coordinator_fence: u64,
    prior_outcome_digest: Digest32,
) -> Result<Digest32> {
    validate_digest(dispatch_attempt_id)?;
    validate_digest(prior_outcome_digest)?;
    if sequence == 0 || sequence > MAX_RECONCILIATIONS_PER_CHILD || !matches!(scope_tag, 1 | 2) {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/CHILD-RECONCILE/V2\0",
        &[
            &dispatch_attempt_id,
            &sequence.to_be_bytes(),
            &scope_tag.to_be_bytes(),
            &route_fence.to_be_bytes(),
            &coordinator_fence.to_be_bytes(),
            &prior_outcome_digest,
        ],
    ))
}

fn reconciliation_completion_event_id(reconciliation_attempt_id: Digest32) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILED-EVENT/V2\0",
        &[&reconciliation_attempt_id],
    )
}

fn reconciliation_completion_record_digest(
    outcome_digest: Digest32,
    completed_at_unix_ms: u64,
) -> Digest32 {
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILED-COMPLETION/V2\0",
        &[&outcome_digest, &completed_at_unix_ms.to_be_bytes()],
    )
}

fn reconciliation_supersession_evidence(
    superseded_attempt_id: Digest32,
    superseded_request_digest: Digest32,
    replacement_scope_tag: i64,
    replacement_route_fence: u64,
    replacement_coordinator_fence: u64,
) -> Result<Digest32> {
    validate_digest(superseded_attempt_id)?;
    validate_digest(superseded_request_digest)?;
    if !matches!(replacement_scope_tag, 1 | 2) || replacement_coordinator_fence == 0 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION-SUPERSESSION-EVIDENCE/V1\0",
        &[
            &superseded_attempt_id,
            &superseded_request_digest,
            &replacement_scope_tag.to_be_bytes(),
            &replacement_route_fence.to_be_bytes(),
            &replacement_coordinator_fence.to_be_bytes(),
        ],
    ))
}

fn reconciliation_supersession_outcome_digest(evidence_digest: Digest32) -> Result<Digest32> {
    validate_digest(evidence_digest)?;
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION/SUPERSEDED/V1\0",
        &[&evidence_digest],
    ))
}

fn child_reconciliation_outcome_digest(outcome: &ChildReconciliationOutcomeV1) -> Result<Digest32> {
    match outcome {
        ChildReconciliationOutcomeV1::Externalized(receipt) => Ok(domain_digest_v1(
            b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION/EXTERNALIZED/V1\0",
            &[&receipt_digest(receipt)?],
        )),
        ChildReconciliationOutcomeV1::ProvenNotExternalized { evidence_digest } => {
            validate_digest(*evidence_digest)?;
            Ok(domain_digest_v1(
                b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION/NOT-EXTERNALIZED/V1\0",
                &[evidence_digest],
            ))
        }
        ChildReconciliationOutcomeV1::Unknown { evidence_digest } => {
            validate_digest(*evidence_digest)?;
            Ok(domain_digest_v1(
                b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION/UNKNOWN/V1\0",
                &[evidence_digest],
            ))
        }
    }
}

fn reconciliation_outcome_record(
    outcome: &ChildReconciliationOutcomeV1,
) -> Result<(i64, Digest32)> {
    match outcome {
        ChildReconciliationOutcomeV1::ProvenNotExternalized { evidence_digest } => {
            validate_digest(*evidence_digest)?;
            Ok((1, *evidence_digest))
        }
        ChildReconciliationOutcomeV1::Externalized(receipt) => Ok((2, receipt_digest(receipt)?)),
        ChildReconciliationOutcomeV1::Unknown { evidence_digest } => {
            validate_digest(*evidence_digest)?;
            Ok((3, *evidence_digest))
        }
    }
}

fn reconciliation_outcome_digest_from_record(
    outcome_tag: i64,
    outcome_evidence: Digest32,
) -> Result<Digest32> {
    validate_digest(outcome_evidence)?;
    match outcome_tag {
        1 => Ok(domain_digest_v1(
            b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION/NOT-EXTERNALIZED/V1\0",
            &[&outcome_evidence],
        )),
        2 => Ok(domain_digest_v1(
            b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION/EXTERNALIZED/V1\0",
            &[&outcome_evidence],
        )),
        3 => Ok(domain_digest_v1(
            b"DOM-INTEROP/SETTLEMENT-COORDINATOR/RECONCILIATION/UNKNOWN/V1\0",
            &[&outcome_evidence],
        )),
        RECONCILIATION_SUPERSEDED => reconciliation_supersession_outcome_digest(outcome_evidence),
        _ => Err(CoordinatorErrorV1::CorruptState),
    }
}

fn public_exposure(plan: &PlanRow) -> Result<Option<ChildPublicExposureV1>> {
    match (
        plan.first_exposure_child,
        plan.first_exposure_chain,
        plan.first_exposure_tx,
        plan.first_exposure_evidence,
        plan.first_exposure_observed_at,
    ) {
        (
            Some(child_index),
            Some(chain_id),
            Some(transaction_id),
            Some(evidence_digest),
            Some(observed_at_unix_ms),
        ) => {
            validate_digest(chain_id)?;
            validate_digest(transaction_id)?;
            validate_digest(evidence_digest)?;
            if observed_at_unix_ms == 0 {
                return Err(CoordinatorErrorV1::CorruptState);
            }
            Ok(Some(ChildPublicExposureV1 {
                child_index,
                chain_id,
                transaction_id,
                evidence_digest,
                observed_at_unix_ms,
            }))
        }
        (None, None, None, None, None) => Ok(None),
        _ => Err(CoordinatorErrorV1::CorruptState),
    }
}

fn progress_evidence_digest(
    plan: &PlanRow,
    children: &[ChildRow],
    completed_prefix: u8,
) -> Result<Digest32> {
    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(&plan.plan_id);
    encoded.extend_from_slice(&plan.plan_digest);
    encoded.extend_from_slice(&plan.aggregate_action_id);
    encoded.extend_from_slice(&plan.aggregate_custody_digest);
    encoded.push(completed_prefix);
    encoded.extend_from_slice(&plan.revision.to_be_bytes());
    encoded.extend_from_slice(&plan.journal_head);
    encoded.extend_from_slice(&plan.secret_state.to_be_bytes());
    for child in children {
        encoded.push(child.child_index);
        encoded.extend_from_slice(&child.stage.to_be_bytes());
        encoded.extend_from_slice(&child.call_attempt.to_be_bytes());
        encoded.extend_from_slice(&child.expected_tx_id);
        encoded.extend_from_slice(&child.externalization_evidence.unwrap_or(ZERO_DIGEST));
        encoded.extend_from_slice(&child.last_ambiguity_evidence.unwrap_or(ZERO_DIGEST));
    }
    encoded.extend_from_slice(&plan.first_exposure_evidence.unwrap_or(ZERO_DIGEST));
    encoded.extend_from_slice(&plan.first_exposure_observed_at.unwrap_or(0).to_be_bytes());
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/PARTIAL-PROGRESS/V2\0",
        &[&encoded],
    ))
}

fn partial_progress_from_view(
    connection: &Connection,
    view: &SettlementPlanViewV1,
) -> Result<PartialCustodyProgressV1> {
    let plan = load_plan_row(connection, view.plan_id)?;
    let decoded = decode_plan_row(&plan)?;
    let children = load_child_rows(connection, view.plan_id)?;
    let prefix = validate_child_prefix(&children, &decoded)?;
    if prefix != view.completed_prefix
        || usize::from(prefix) >= MAX_SETTLEMENT_CHILDREN_V1
        || plan.stage == AGGREGATE_FAILED_CLOSED
    {
        return Err(CoordinatorErrorV1::InvalidState);
    }
    Ok(PartialCustodyProgressV1 {
        plan_id: plan.plan_id,
        aggregate_action_id: plan.aggregate_action_id,
        aggregate_custody_digest: plan.aggregate_custody_digest,
        completed_prefix: prefix,
        progress_evidence_digest: progress_evidence_digest(&plan, &children, prefix)?,
        exposure: public_exposure(&plan)?,
    })
}

fn aggregate_receipt_from_view(
    connection: &Connection,
    view: &SettlementPlanViewV1,
) -> Result<AggregateExternalizationReceiptV1> {
    let plan = load_plan_row(connection, view.plan_id)?;
    if usize::from(view.completed_prefix) != MAX_SETTLEMENT_CHILDREN_V1
        || !matches!(
            plan.stage,
            AGGREGATE_EXTERNALIZED | AGGREGATE_FINAL | AGGREGATE_FINALITY_INVALIDATED
        )
    {
        return Err(CoordinatorErrorV1::InvalidState);
    }
    let digest = child_receipts_digest(connection, &plan)?;
    if plan.aggregate_receipt_digest != Some(digest) {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(AggregateExternalizationReceiptV1 {
        plan_id: plan.plan_id,
        aggregate_action_id: plan.aggregate_action_id,
        aggregate_custody_digest: plan.aggregate_custody_digest,
        child_receipts_digest: digest,
        first_exposure: public_exposure(&plan)?,
    })
}

fn takeover_status_from_view(
    connection: &Connection,
    view: &SettlementPlanViewV1,
) -> Result<CustodyTakeoverStatusV1> {
    if view.stage == AggregateStageV1::FailedClosed {
        return Err(CoordinatorErrorV1::FailedClosed);
    }
    if usize::from(view.completed_prefix) == MAX_SETTLEMENT_CHILDREN_V1 {
        return Ok(CustodyTakeoverStatusV1::AggregateExternalized(
            aggregate_receipt_from_view(connection, view)?,
        ));
    }
    let plan = load_plan_row(connection, view.plan_id)?;
    let children = load_child_rows(connection, view.plan_id)?;
    let progress = partial_progress_from_view(connection, view)?;
    if children
        .iter()
        .any(|child| child.stage == CHILD_CALL_PENDING)
        || plan.secret_state == SECRET_EXPOSURE_POSSIBLE
    {
        return Ok(CustodyTakeoverStatusV1::Unknown {
            evidence_digest: progress.progress_evidence_digest,
        });
    }
    if view.completed_prefix == 0 {
        return Ok(CustodyTakeoverStatusV1::NothingExternalized {
            evidence_digest: progress.progress_evidence_digest,
        });
    }
    if progress.exposure.is_some() {
        Ok(CustodyTakeoverStatusV1::SecretPublicPartial(progress))
    } else if plan.secret_state != SECRET_EXPOSURE_POSSIBLE {
        Ok(CustodyTakeoverStatusV1::SafeToResumeCustody(progress))
    } else {
        Ok(CustodyTakeoverStatusV1::Unknown {
            evidence_digest: progress.progress_evidence_digest,
        })
    }
}

fn takeover_progress_evidence(
    connection: &Connection,
    view: &SettlementPlanViewV1,
) -> Result<Digest32> {
    match takeover_status_from_view(connection, view)? {
        CustodyTakeoverStatusV1::NothingExternalized { evidence_digest }
        | CustodyTakeoverStatusV1::Unknown { evidence_digest } => Ok(evidence_digest),
        CustodyTakeoverStatusV1::SafeToResumeCustody(progress)
        | CustodyTakeoverStatusV1::SecretPublicPartial(progress) => {
            Ok(progress.progress_evidence_digest)
        }
        CustodyTakeoverStatusV1::AggregateExternalized(receipt) => {
            Ok(receipt.child_receipts_digest)
        }
    }
}

fn child_observation_request(
    plan: &PlanRow,
    child: &ChildRow,
    child_index: u8,
    observation_attempt_id: Digest32,
) -> Result<ChildObservationRequestV1> {
    validate_digest(observation_attempt_id)?;
    if child.child_index != child_index
        || child.stage < CHILD_EXTERNALIZED
        || child.externalization_evidence.is_none()
    {
        return Err(CoordinatorErrorV1::InvalidState);
    }
    let decoded = decode_plan_row(plan)?;
    let bindings = decoded.bindings();
    let (profile_digest, deployment_digest) = if child.face == SettlementFaceV1::Dom {
        (bindings.dom_profile_digest, bindings.dom_deployment_digest)
    } else {
        (
            bindings.counterparty_profile_digest,
            bindings.counterparty_deployment_digest,
        )
    };
    Ok(ChildObservationRequestV1 {
        plan_id: plan.plan_id,
        plan_digest: plan.plan_digest,
        route_id: bindings.route_id,
        effect_id: bindings.effect_id,
        settlement_id: bindings.settlement_id,
        leg: bindings.leg,
        action: bindings.action,
        semantic_digest: bindings.semantic_digest,
        route_fencing_epoch: plan.route_fence,
        terms_digest: bindings.terms_digest,
        registry_digest: bindings.registry_digest,
        profile_digest,
        deployment_digest,
        child_index,
        face: child.face,
        exposure: child.exposure,
        chain_id: child.chain_id,
        transaction_id: child.expected_tx_id,
        intent_digest: child.intent_digest,
        custody_digest: child.custody_digest,
        prior_finality_evidence_digest: child.finality_evidence,
        observation_attempt_id,
    })
}

fn pending_observation_plan(
    connection: &Connection,
    current: &PlanRow,
    observation_attempt_id: Digest32,
) -> Result<PlanRow> {
    let fence: Vec<u8> = connection
        .query_row(
            "SELECT route_fence_be FROM coordinator_journal
             WHERE plan_id=?1 AND event_id=?2 AND event_tag=9",
            params![
                current.plan_id.as_slice(),
                observation_attempt_id.as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(storage)?;
    plan_row_at_fence(connection, current, blob_u64(fence)?)
}

fn plan_row_at_fence(
    connection: &Connection,
    current: &PlanRow,
    route_fence: u64,
) -> Result<PlanRow> {
    if route_fence == current.route_fence {
        return Ok(current.clone());
    }
    let retained = connection
        .query_row(
            "SELECT plan_digest,effect_id,plan_bytes,authorization_evidence
             FROM settlement_plan_versions WHERE plan_id=?1 AND route_fence_be=?2",
            params![current.plan_id.as_slice(), u64_blob(route_fence)],
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
        .map_err(storage)?
        .ok_or(CoordinatorErrorV1::CorruptState)?;
    let mut historical = current.clone();
    historical.plan_digest = blob32(retained.0)?;
    historical.effect_id = blob32(retained.1)?;
    historical.route_fence = route_fence;
    historical.plan_bytes = retained.2;
    historical.authorization_evidence = blob32(retained.3)?;
    let current_plan = decode_plan_row(current)?;
    let historical_plan = decode_plan_row(&historical)?;
    if historical_plan
        .canonical_digest()
        .map_err(|_| CoordinatorErrorV1::CorruptState)?
        != historical.plan_digest
        || historical_plan.bindings().effect_id != historical.effect_id
        || historical_plan.bindings().fencing_epoch != route_fence
        || !stable_plan_equivalent(&current_plan, &historical_plan)
            .map_err(|_| CoordinatorErrorV1::CorruptState)?
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(historical)
}

fn observation_plan_version_matches(
    connection: &Connection,
    current: &PlanRow,
    request: &ChildObservationRequestV1,
) -> Result<bool> {
    let version = plan_row_at_fence(connection, current, request.route_fencing_epoch)?;
    if version.plan_digest != request.plan_digest {
        return Ok(false);
    }
    let decoded = decode_plan_row(&version)?;
    let bindings = decoded.bindings();
    let retained_child;
    let retained_plan;
    let child = match decoded.materialized_child(usize::from(request.child_index)) {
        Some(child) => child,
        None if request.child_index == 1 => {
            retained_child = load_child_row(connection, current.plan_id, 1)?;
            if !audit_deferred_materialized_child(connection, current, &decoded, &retained_child)? {
                return Ok(false);
            }
            retained_plan = SettlementChildPlanV1 {
                face: retained_child.face,
                exposure: retained_child.exposure,
                chain_id: retained_child.chain_id,
                expected_transaction_id: retained_child.expected_tx_id,
                intent_digest: retained_child.intent_digest,
                custody_digest: retained_child.custody_digest,
            };
            &retained_plan
        }
        None => return Ok(false),
    };
    let (profile, deployment) = if child.face == SettlementFaceV1::Dom {
        (bindings.dom_profile_digest, bindings.dom_deployment_digest)
    } else {
        (
            bindings.counterparty_profile_digest,
            bindings.counterparty_deployment_digest,
        )
    };
    Ok(request.route_id == bindings.route_id
        && request.effect_id == bindings.effect_id
        && request.settlement_id == bindings.settlement_id
        && request.leg == bindings.leg
        && request.action == bindings.action
        && request.semantic_digest == bindings.semantic_digest
        && request.terms_digest == bindings.terms_digest
        && request.registry_digest == bindings.registry_digest
        && request.profile_digest == profile
        && request.deployment_digest == deployment
        && request.face == child.face
        && request.exposure == child.exposure
        && request.chain_id == child.chain_id
        && request.transaction_id == child.expected_transaction_id
        && request.intent_digest == child.intent_digest
        && request.custody_digest == child.custody_digest)
}

fn child_observation_request_digest(request: &ChildObservationRequestV1) -> Digest32 {
    let (prior_present, prior) = match request.prior_finality_evidence_digest {
        Some(value) => (1u8, value),
        None => (0u8, ZERO_DIGEST),
    };
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/OBSERVATION-REQUEST/V1\0",
        &[
            &request.plan_id,
            &request.plan_digest,
            &request.route_id,
            &request.effect_id,
            &request.settlement_id,
            &[request.leg.tag()],
            &[request.action.tag()],
            &request.semantic_digest,
            &request.route_fencing_epoch.to_be_bytes(),
            &request.terms_digest,
            &request.registry_digest,
            &request.profile_digest,
            &request.deployment_digest,
            &[request.child_index],
            &[request.face.tag()],
            &[request.exposure.tag()],
            &request.chain_id,
            &request.transaction_id,
            &request.intent_digest,
            &request.custody_digest,
            &[prior_present],
            &prior,
            &request.observation_attempt_id,
        ],
    )
}

fn child_observation_outcome_digest(outcome: &ChildObservationOutcomeV1) -> Result<Digest32> {
    match outcome {
        ChildObservationOutcomeV1::Pending { evidence_digest } => {
            validate_digest(*evidence_digest)?;
            Ok(domain_digest_v1(
                b"DOM-INTEROP/SETTLEMENT-COORDINATOR/OBSERVATION/PENDING/V1\0",
                &[evidence_digest],
            ))
        }
        ChildObservationOutcomeV1::Final { evidence_digest } => {
            validate_digest(*evidence_digest)?;
            Ok(domain_digest_v1(
                b"DOM-INTEROP/SETTLEMENT-COORDINATOR/OBSERVATION/FINAL/V1\0",
                &[evidence_digest],
            ))
        }
        ChildObservationOutcomeV1::FinalityInvalidated {
            prior_finality_evidence_digest,
            reorg_evidence_digest,
        } => {
            validate_digest(*prior_finality_evidence_digest)?;
            validate_digest(*reorg_evidence_digest)?;
            Ok(domain_digest_v1(
                b"DOM-INTEROP/SETTLEMENT-COORDINATOR/OBSERVATION/REORG/V1\0",
                &[prior_finality_evidence_digest, reorg_evidence_digest],
            ))
        }
    }
}

fn validate_observation_scope(request: &ChildObservationRequestV1, child: &ChildRow) -> Result<()> {
    if request.child_index != child.child_index
        || request.face != child.face
        || request.exposure != child.exposure
        || request.chain_id != child.chain_id
        || request.transaction_id != child.expected_tx_id
        || request.intent_digest != child.intent_digest
        || request.custody_digest != child.custody_digest
        || request.prior_finality_evidence_digest != child.finality_evidence
        || child.externalization_evidence.is_none()
    {
        return Err(CoordinatorErrorV1::ChildReceiptMismatch);
    }
    Ok(())
}

fn materialize_aggregate_finality(
    connection: &Connection,
    plan_id: Digest32,
    now_unix_ms: u64,
) -> Result<Option<AggregateFinalityV1>> {
    let plan = load_plan_row(connection, plan_id)?;
    let children = load_child_rows(connection, plan_id)?;
    if !children.iter().all(|child| child.stage == CHILD_FINAL) {
        return Ok(None);
    }
    let evidence = expected_aggregate_finality_digest(&plan, &children)?;
    match plan.stage {
        AGGREGATE_EXTERNALIZED | AGGREGATE_FINALITY_INVALIDATED => {
            let changed = connection
                .execute(
                    "UPDATE settlement_plans SET stage_tag=?2,aggregate_finality_digest=?3,
                     aggregate_reorg_digest=NULL,updated_at_be=?4 WHERE plan_id=?1 AND stage_tag=?5",
                    params![
                        plan_id.as_slice(),
                        AGGREGATE_FINAL,
                        evidence.as_slice(),
                        u64_blob(now_unix_ms),
                        plan.stage,
                    ],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(CoordinatorErrorV1::CorruptState);
            }
        }
        AGGREGATE_FINAL if plan.aggregate_finality_digest == Some(evidence) => {}
        _ => return Err(CoordinatorErrorV1::CorruptState),
    }
    Ok(Some(AggregateFinalityV1 {
        plan_id,
        aggregate_action_id: plan.aggregate_action_id,
        evidence_digest: evidence,
    }))
}

fn materialize_aggregate_reorg(
    connection: &Connection,
    plan_id: Digest32,
    child_index: u8,
    prior_finality_evidence: Digest32,
    reorg_evidence: Digest32,
    now_unix_ms: u64,
) -> Result<AggregateReorgV1> {
    let plan = load_plan_row(connection, plan_id)?;
    let prior_aggregate = plan.aggregate_finality_digest.unwrap_or(ZERO_DIGEST);
    let evidence = domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/AGGREGATE-REORG/V1\0",
        &[
            &plan.plan_id,
            &plan.aggregate_action_id,
            &prior_aggregate,
            &[child_index],
            &prior_finality_evidence,
            &reorg_evidence,
        ],
    );
    if !matches!(
        plan.stage,
        AGGREGATE_EXTERNALIZED | AGGREGATE_FINAL | AGGREGATE_FINALITY_INVALIDATED
    ) {
        return Err(CoordinatorErrorV1::InvalidState);
    }
    connection
        .execute(
            "UPDATE settlement_plans SET stage_tag=?2,aggregate_reorg_digest=?3,
             updated_at_be=?4 WHERE plan_id=?1",
            params![
                plan_id.as_slice(),
                AGGREGATE_FINALITY_INVALIDATED,
                evidence.as_slice(),
                u64_blob(now_unix_ms),
            ],
        )
        .map_err(storage)?;
    Ok(AggregateReorgV1 {
        plan_id,
        aggregate_action_id: plan.aggregate_action_id,
        evidence_digest: evidence,
    })
}

fn observation_result_record(outcome: &CoordinatorObservationOutcomeV1) -> (i64, Digest32) {
    match *outcome {
        CoordinatorObservationOutcomeV1::Pending { evidence_digest } => (1, evidence_digest),
        CoordinatorObservationOutcomeV1::ChildFinalized {
            evidence_digest, ..
        } => (2, evidence_digest),
        CoordinatorObservationOutcomeV1::AggregateFinal(finality) => (3, finality.evidence_digest),
        CoordinatorObservationOutcomeV1::AggregateInvalidated(reorg) => (4, reorg.evidence_digest),
    }
}

fn retained_observation_outcome(
    connection: &Connection,
    plan_id: Digest32,
    child_index: u8,
    result_tag: i64,
    evidence_digest: Digest32,
) -> Result<CoordinatorObservationOutcomeV1> {
    validate_digest(evidence_digest)?;
    let plan = load_plan_row(connection, plan_id)?;
    match result_tag {
        1 => Ok(CoordinatorObservationOutcomeV1::Pending { evidence_digest }),
        2 => Ok(CoordinatorObservationOutcomeV1::ChildFinalized {
            child_index,
            evidence_digest,
        }),
        3 => Ok(CoordinatorObservationOutcomeV1::AggregateFinal(
            AggregateFinalityV1 {
                plan_id,
                aggregate_action_id: plan.aggregate_action_id,
                evidence_digest,
            },
        )),
        4 => Ok(CoordinatorObservationOutcomeV1::AggregateInvalidated(
            AggregateReorgV1 {
                plan_id,
                aggregate_action_id: plan.aggregate_action_id,
                evidence_digest,
            },
        )),
        _ => Err(CoordinatorErrorV1::CorruptState),
    }
}

fn storage(_error: rusqlite::Error) -> CoordinatorErrorV1 {
    CoordinatorErrorV1::StorageUnavailable
}

fn u64_blob(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn blob_u64(bytes: Vec<u8>) -> Result<u64> {
    let bytes = <[u8; 8]>::try_from(bytes).map_err(|_| CoordinatorErrorV1::CorruptState)?;
    Ok(u64::from_be_bytes(bytes))
}

fn blob32(bytes: Vec<u8>) -> Result<Digest32> {
    <Digest32>::try_from(bytes).map_err(|_| CoordinatorErrorV1::CorruptState)
}

#[cfg(target_os = "linux")]
fn require_linux() -> Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_linux() -> Result<()> {
    Err(CoordinatorErrorV1::InvalidStorageAuthority)
}

fn create_schema_and_metadata(
    connection: &Connection,
    coordinator_id: Digest32,
    plan_authority_id: Digest32,
    now_unix_ms: u64,
) -> Result<()> {
    create_schema_and_metadata_with_boundary_hook(
        connection,
        coordinator_id,
        plan_authority_id,
        now_unix_ms,
        || Ok(()),
    )
}

fn create_schema_and_metadata_with_boundary_hook<F>(
    connection: &Connection,
    coordinator_id: Digest32,
    plan_authority_id: Digest32,
    now_unix_ms: u64,
    before_commit: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let transaction = connection.unchecked_transaction().map_err(storage)?;
    transaction.execute_batch(SCHEMA_V3).map_err(storage)?;
    transaction
        .execute(
            "INSERT INTO coordinator_metadata(
                 singleton,coordinator_id,plan_authority_id,clock_high_water_be,created_at_be
             ) VALUES(1,?1,?2,?3,?3)",
            params![
                coordinator_id.as_slice(),
                plan_authority_id.as_slice(),
                u64_blob(now_unix_ms)
            ],
        )
        .map_err(storage)?;
    before_commit()?;
    transaction.commit().map_err(storage)
}

fn preflight_resumable_creation_state(
    path: &Path,
    database_authority: &File,
) -> Result<ResumableCreationStateV1> {
    validate_open_file_identity(database_authority, path)?;
    if database_authority
        .metadata()
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?
        .len()
        == 0
    {
        return Ok(ResumableCreationStateV1::PristineSqlite);
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    connection
        .busy_timeout(Duration::from_millis(5_000))
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .and_then(|_| connection.pragma_update(None, "trusted_schema", "OFF"))
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection
        .set_db_config(defensive, true)
        .map_err(|_| CoordinatorErrorV1::CorruptState)?
        || !connection
            .db_config(defensive)
            .map_err(|_| CoordinatorErrorV1::CorruptState)?
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let quick: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    let foreign_key_violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    let objects = schema_objects(&connection).map_err(|_| CoordinatorErrorV1::CorruptState)?;
    if quick != "ok" || foreign_key_violations != 0 || application_id != 0 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    if version == 0 {
        return if objects.is_empty() {
            Ok(ResumableCreationStateV1::PristineSqlite)
        } else {
            Err(CoordinatorErrorV1::CorruptState)
        };
    }
    if version != SCHEMA_VERSION {
        return Err(CoordinatorErrorV1::UnsupportedFormat);
    }
    let reference = Connection::open_in_memory().map_err(storage)?;
    reference.execute_batch(SCHEMA_V3).map_err(storage)?;
    if objects != schema_objects(&reference)? {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    validate_open_file_identity(database_authority, path)?;
    Ok(ResumableCreationStateV1::InitializedExact)
}

fn validate_pristine_initialized_store(
    connection: &Connection,
    coordinator_id: Digest32,
    plan_authority_id: Digest32,
) -> Result<()> {
    validate_backend_and_schema(connection)?;
    let row: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT coordinator_id,plan_authority_id,clock_high_water_be,created_at_be
             FROM coordinator_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    let metadata_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM coordinator_metadata", [], |row| {
            row.get(0)
        })
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    let economic_rows: i64 = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM settlement_plans) +
                 (SELECT COUNT(*) FROM settlement_plan_versions) +
                 (SELECT COUNT(*) FROM settlement_children) +
                 (SELECT COUNT(*) FROM deferred_child_materializations) +
                 (SELECT COUNT(*) FROM coordinator_leases) +
                 (SELECT COUNT(*) FROM coordinator_journal) +
                 (SELECT COUNT(*) FROM child_call_outcomes) +
                 (SELECT COUNT(*) FROM child_reconciliation_calls) +
                 (SELECT COUNT(*) FROM observation_calls) +
                 (SELECT COUNT(*) FROM coordinator_conflicts)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoordinatorErrorV1::CorruptState)?;
    let clock_high_water = blob_u64(row.2)?;
    let created_at = blob_u64(row.3)?;
    if blob32(row.0)? != coordinator_id || blob32(row.1)? != plan_authority_id {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    if metadata_count != 1 || clock_high_water != created_at || economic_rows != 0 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<()> {
    connection
        .busy_timeout(Duration::from_millis(5_000))
        .map_err(storage)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(storage)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(CoordinatorErrorV1::StorageUnavailable);
    }
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(storage)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(storage)?;
    connection
        .pragma_update(None, "read_uncommitted", "OFF")
        .map_err(storage)?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(storage)?;
    connection
        .pragma_update(None, "secure_delete", "ON")
        .map_err(storage)?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection.set_db_config(defensive, true).map_err(storage)?
        || !connection.db_config(defensive).map_err(storage)?
    {
        return Err(CoordinatorErrorV1::UnsupportedFormat);
    }
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(storage)?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(storage)?;
    let read_uncommitted: i64 = connection
        .query_row("PRAGMA read_uncommitted", [], |row| row.get(0))
        .map_err(storage)?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(storage)?;
    let secure_delete: i64 = connection
        .query_row("PRAGMA secure_delete", [], |row| row.get(0))
        .map_err(storage)?;
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(storage)?;
    if synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || secure_delete != 1
        || busy_timeout != 5_000
    {
        return Err(CoordinatorErrorV1::UnsupportedFormat);
    }
    Ok(())
}

fn validate_backend_and_schema(connection: &Connection) -> Result<()> {
    let quick: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(storage)?;
    if quick != "ok" {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let foreign_key_violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(storage)?;
    if foreign_key_violations != 0 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(storage)?;
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(storage)?;
    if version != SCHEMA_VERSION {
        return Err(CoordinatorErrorV1::UnsupportedFormat);
    }
    if application_id != 0 {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let actual = schema_objects(connection)?;
    let reference = Connection::open_in_memory().map_err(storage)?;
    reference.execute_batch(SCHEMA_V3).map_err(storage)?;
    if actual != schema_objects(&reference)? {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(())
}

type SchemaObjectV1 = (String, String, String, String);

fn schema_objects(connection: &Connection) -> Result<BTreeSet<SchemaObjectV1>> {
    const MAX_OBJECTS: i64 = 16;
    const MAX_SCHEMA_BYTES: i64 = 131_072;
    let (count, maximum, total): (i64, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT COUNT(*),MAX(length(sql)),SUM(length(sql)) FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(storage)?;
    if !(0..=MAX_OBJECTS).contains(&count)
        || maximum.is_some_and(|value| !(0..=MAX_SCHEMA_BYTES).contains(&value))
        || total.is_some_and(|value| !(0..=MAX_SCHEMA_BYTES).contains(&value))
    {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    let mut statement = connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(storage)?;
    let mut objects = BTreeSet::new();
    for row in rows {
        if !objects.insert(row.map_err(storage)?) {
            return Err(CoordinatorErrorV1::CorruptState);
        }
    }
    if i64::try_from(objects.len()).map_err(|_| CoordinatorErrorV1::CorruptState)? != count {
        return Err(CoordinatorErrorV1::CorruptState);
    }
    Ok(objects)
}

fn validate_database_path(connection: &Connection, expected_path: &Path) -> Result<()> {
    let expected =
        fs::canonicalize(expected_path).map_err(|_| CoordinatorErrorV1::InvalidStorageAuthority)?;
    if expected != expected_path {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    let mut statement = connection
        .prepare("PRAGMA database_list")
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })
        .map_err(storage)?;
    let mut saw_main = false;
    for row in rows {
        let (name, path) = row.map_err(storage)?;
        match name.as_str() {
            "main" if Path::new(&path) == expected => saw_main = true,
            "temp" if path.is_empty() => {}
            _ => return Err(CoordinatorErrorV1::InvalidStorageAuthority),
        }
    }
    if !saw_main {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owner_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| CoordinatorErrorV1::InvalidStorageAuthority)?;
    let canonical =
        fs::canonicalize(path).map_err(|_| CoordinatorErrorV1::InvalidStorageAuthority)?;
    if canonical != path
        || !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != DIRECTORY_MODE
        || metadata.nlink() == 0
    {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_owner_directory(_path: &Path) -> Result<()> {
    Err(CoordinatorErrorV1::InvalidStorageAuthority)
}

#[cfg(target_os = "linux")]
fn validate_owner_file(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| CoordinatorErrorV1::InvalidStorageAuthority)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_owner_file(_path: &Path) -> Result<()> {
    Err(CoordinatorErrorV1::InvalidStorageAuthority)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn require_create_path_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CoordinatorErrorV1::DatabasePresent),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CoordinatorErrorV1::StorageUnavailable),
    }
}

fn require_sidecars_absent(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        match fs::symlink_metadata(sidecar_path(path, suffix)) {
            Ok(_) => return Err(CoordinatorErrorV1::InvalidStorageAuthority),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CoordinatorErrorV1::StorageUnavailable),
        }
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
fn validate_resumable_sidecars(path: &Path) -> Result<()> {
    for (suffix, kind) in [
        ("-wal", SqliteSidecarKindV1::Wal),
        ("-shm", SqliteSidecarKindV1::SharedMemory),
        ("-journal", SqliteSidecarKindV1::RollbackJournal),
    ] {
        let sidecar = sidecar_path(path, suffix);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => validate_sqlite_sidecar_shape(&sidecar, kind)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CoordinatorErrorV1::StorageUnavailable),
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_resumable_sidecars(_path: &Path) -> Result<()> {
    Err(CoordinatorErrorV1::InvalidStorageAuthority)
}

#[cfg(target_os = "linux")]
fn validate_sqlite_sidecar_shape(path: &Path, kind: SqliteSidecarKindV1) -> Result<()> {
    validate_owner_file(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    let retained = file
        .metadata()
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    if retained.len() == 0 {
        return Ok(());
    }
    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .map_err(|_| CoordinatorErrorV1::InvalidStorageAuthority)?;
    let valid = match kind {
        SqliteSidecarKindV1::Wal => {
            retained.len() >= 32
                && matches!(
                    u32::from_be_bytes(
                        header[..4]
                            .try_into()
                            .map_err(|_| CoordinatorErrorV1::InvalidStorageAuthority)?
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
                        .map_err(|_| CoordinatorErrorV1::InvalidStorageAuthority)?,
                ) == 3_007_000
        }
        SqliteSidecarKindV1::RollbackJournal => {
            retained.len() >= 28 && header == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
        }
    };
    if !valid {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

fn process_lock_path(path: &Path) -> PathBuf {
    sidecar_path(path, ".lock")
}

#[cfg(target_os = "linux")]
fn acquire_process_lock(path: &Path, create: bool) -> Result<File> {
    let lock_path = process_lock_path(path);
    let mut options = OpenOptions::new();
    options.read(true).write(true).mode(FILE_MODE);
    if create {
        options.create_new(true);
    }
    let file = options
        .open(&lock_path)
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    validate_open_file_identity(&file, &lock_path)?;
    if file
        .metadata()
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?
        .len()
        != 0
    {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    validate_open_file_identity(&file, &lock_path)?;
    if create {
        file.sync_all()
            .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
        sync_directory(
            path.parent()
                .ok_or(CoordinatorErrorV1::InvalidStorageAuthority)?,
        )?;
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn acquire_process_lock(_path: &Path, _create: bool) -> Result<File> {
    Err(CoordinatorErrorV1::InvalidStorageAuthority)
}

#[cfg(target_os = "linux")]
fn create_database_authority(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE);
    let file = options
        .open(path)
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    validate_open_file_identity(&file, path)?;
    file.sync_all()
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    sync_directory(
        path.parent()
            .ok_or(CoordinatorErrorV1::InvalidStorageAuthority)?,
    )?;
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn create_database_authority(_path: &Path) -> Result<File> {
    Err(CoordinatorErrorV1::InvalidStorageAuthority)
}

fn open_database_authority(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    validate_open_file_identity(&file, path)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn validate_open_file_identity(file: &File, path: &Path) -> Result<()> {
    validate_owner_file(path)?;
    let open = file
        .metadata()
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| CoordinatorErrorV1::StorageUnavailable)?;
    if open.dev() != named.dev() || open.ino() != named.ino() {
        return Err(CoordinatorErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CoordinatorErrorV1::StorageUnavailable)
}

#[cfg(all(test, target_os = "linux"))]
mod provisioning_tests {
    use super::*;
    use std::error::Error;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    const TEST_COORDINATOR_ID: Digest32 = [0xc1; 32];
    const TEST_PLAN_AUTHORITY_ID: Digest32 = [0xc2; 32];
    const TEST_CREATED_AT: u64 = 1_700_000_000_000;
    const FAULT_PATH_ENV: &str = "SETTLEMENT_COORDINATOR_TEST_FAULT_PATH";
    const FAULT_BOUNDARY_ENV: &str = "SETTLEMENT_COORDINATOR_TEST_FAULT_BOUNDARY";
    const LOCK_PROBE_PATH_ENV: &str = "SETTLEMENT_COORDINATOR_TEST_LOCK_PROBE_PATH";
    const CRASH_EXIT: i32 = 91;

    type TestResult<T = ()> = core::result::Result<T, Box<dyn Error>>;

    fn test_path() -> TestResult<(tempfile::TempDir, PathBuf)> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))?;
        let canonical = fs::canonicalize(directory.path())?;
        Ok((directory, canonical.join("settlement-coordinator.sqlite3")))
    }

    fn boundary_name(boundary: CreationBoundaryV1) -> &'static str {
        match boundary {
            CreationBoundaryV1::ProcessLockPublished => "process-lock-published",
            CreationBoundaryV1::DatabaseFileSynced => "database-file-synced",
            CreationBoundaryV1::BeforeSchemaTransaction => "before-schema-transaction",
            CreationBoundaryV1::BeforeSchemaCommit => "before-schema-commit",
            CreationBoundaryV1::SchemaCommitted => "schema-committed",
        }
    }

    fn parse_boundary(name: &str) -> core::result::Result<CreationBoundaryV1, std::io::Error> {
        match name {
            "process-lock-published" => Ok(CreationBoundaryV1::ProcessLockPublished),
            "database-file-synced" => Ok(CreationBoundaryV1::DatabaseFileSynced),
            "before-schema-transaction" => Ok(CreationBoundaryV1::BeforeSchemaTransaction),
            "before-schema-commit" => Ok(CreationBoundaryV1::BeforeSchemaCommit),
            "schema-committed" => Ok(CreationBoundaryV1::SchemaCommitted),
            _ => Err(std::io::Error::other(
                "unknown coordinator creation boundary",
            )),
        }
    }

    fn stage_process_crash(path: &Path, boundary: CreationBoundaryV1) -> TestResult {
        let status = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("store::provisioning_tests::creation_fault_process_child")
            .arg("--nocapture")
            .env(FAULT_PATH_ENV, path)
            .env(FAULT_BOUNDARY_ENV, boundary_name(boundary))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.code() != Some(CRASH_EXIT) {
            return Err(std::io::Error::other(
                "coordinator creation child did not exit at the requested boundary",
            )
            .into());
        }
        Ok(())
    }

    fn stage_creation_fault(path: &Path, boundary: CreationBoundaryV1) -> Result<()> {
        DurableSettlementCoordinatorV1::create_with_boundary_hook(
            path,
            TEST_COORDINATOR_ID,
            TEST_PLAN_AUTHORITY_ID,
            TEST_CREATED_AT,
            |reached| {
                if reached == boundary {
                    Err(CoordinatorErrorV1::StorageUnavailable)
                } else {
                    Ok(())
                }
            },
        )
        .map(drop)
    }

    #[test]
    fn creation_fault_process_child() -> TestResult {
        let Some(path) = std::env::var_os(FAULT_PATH_ENV) else {
            return Ok(());
        };
        let boundary = parse_boundary(&std::env::var(FAULT_BOUNDARY_ENV)?)?;
        let store = DurableSettlementCoordinatorV1::create_with_boundary_hook(
            Path::new(&path),
            TEST_COORDINATOR_ID,
            TEST_PLAN_AUTHORITY_ID,
            TEST_CREATED_AT,
            |reached| {
                if reached == boundary {
                    std::process::exit(CRASH_EXIT);
                }
                Ok(())
            },
        )?;
        drop(store);
        Err(std::io::Error::other("coordinator creation boundary was not reached").into())
    }

    #[test]
    fn lock_probe_process_child() -> TestResult {
        let Some(path) = std::env::var_os(LOCK_PROBE_PATH_ENV) else {
            return Ok(());
        };
        match DurableSettlementCoordinatorV1::open_existing(
            Path::new(&path),
            TEST_COORDINATOR_ID,
            TEST_PLAN_AUTHORITY_ID,
        ) {
            Err(CoordinatorErrorV1::StorageUnavailable) => Ok(()),
            Ok(store) => {
                drop(store);
                Err(std::io::Error::other("second process acquired coordinator lock").into())
            }
            Err(error) => Err(std::io::Error::other(format!(
                "unexpected second-process coordinator error: {error}"
            ))
            .into()),
        }
    }

    #[test]
    fn resume_recovers_all_creation_crash_prefixes_and_reopens() -> TestResult {
        for boundary in [
            CreationBoundaryV1::ProcessLockPublished,
            CreationBoundaryV1::DatabaseFileSynced,
            CreationBoundaryV1::BeforeSchemaTransaction,
            CreationBoundaryV1::BeforeSchemaCommit,
            CreationBoundaryV1::SchemaCommitted,
        ] {
            let (_directory, path) = test_path()?;
            stage_process_crash(&path, boundary)?;
            match boundary {
                CreationBoundaryV1::ProcessLockPublished => assert_eq!(
                    DurableSettlementCoordinatorV1::open_existing(
                        &path,
                        TEST_COORDINATOR_ID,
                        TEST_PLAN_AUTHORITY_ID,
                    )
                    .unwrap_err(),
                    CoordinatorErrorV1::DatabaseMissing
                ),
                CreationBoundaryV1::DatabaseFileSynced
                | CreationBoundaryV1::BeforeSchemaTransaction
                | CreationBoundaryV1::BeforeSchemaCommit => assert_eq!(
                    DurableSettlementCoordinatorV1::open_existing(
                        &path,
                        TEST_COORDINATOR_ID,
                        TEST_PLAN_AUTHORITY_ID,
                    )
                    .unwrap_err(),
                    CoordinatorErrorV1::CreationIncomplete
                ),
                CreationBoundaryV1::SchemaCommitted => {
                    let opened = DurableSettlementCoordinatorV1::open_existing(
                        &path,
                        TEST_COORDINATOR_ID,
                        TEST_PLAN_AUTHORITY_ID,
                    )?;
                    drop(opened);
                }
            }

            let resumed = DurableSettlementCoordinatorV1::resume_create_production(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
                TEST_CREATED_AT,
            )?;
            assert_eq!(
                DurableSettlementCoordinatorV1::resume_create_production(
                    &path,
                    TEST_COORDINATOR_ID,
                    TEST_PLAN_AUTHORITY_ID,
                    TEST_CREATED_AT,
                )
                .unwrap_err(),
                CoordinatorErrorV1::StorageUnavailable
            );
            drop(resumed);
            let resumed_again = DurableSettlementCoordinatorV1::resume_create_production(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
                TEST_CREATED_AT.saturating_add(1),
            )?;
            drop(resumed_again);
            let reopened = DurableSettlementCoordinatorV1::open_existing(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
            )?;
            drop(reopened);
        }
        Ok(())
    }

    #[test]
    fn resume_requires_exact_lock_schema_metadata_and_sidecars() -> TestResult {
        let (_directory, path) = test_path()?;
        let database = create_database_authority(&path)?;
        drop(database);
        assert_eq!(
            DurableSettlementCoordinatorV1::resume_create_production(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
                TEST_CREATED_AT,
            )
            .unwrap_err(),
            CoordinatorErrorV1::StorageUnavailable
        );

        let (_directory, path) = test_path()?;
        assert_eq!(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced).unwrap_err(),
            CoordinatorErrorV1::StorageUnavailable
        );
        let foreign = Connection::open(&path)?;
        foreign.execute_batch("CREATE TABLE caller_shaped(value BLOB) STRICT;")?;
        drop(foreign);
        assert_eq!(
            DurableSettlementCoordinatorV1::resume_create_production(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
                TEST_CREATED_AT,
            )
            .unwrap_err(),
            CoordinatorErrorV1::CorruptState
        );

        let (_directory, path) = test_path()?;
        assert_eq!(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced).unwrap_err(),
            CoordinatorErrorV1::StorageUnavailable
        );
        let legacy = Connection::open(&path)?;
        legacy.pragma_update(None, "user_version", 1)?;
        drop(legacy);
        assert_eq!(
            DurableSettlementCoordinatorV1::resume_create_production(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
                TEST_CREATED_AT,
            )
            .unwrap_err(),
            CoordinatorErrorV1::UnsupportedFormat
        );

        let (_directory, path) = test_path()?;
        assert_eq!(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced).unwrap_err(),
            CoordinatorErrorV1::StorageUnavailable
        );
        let alternate = Connection::open(&path)?;
        alternate.pragma_update(None, "application_id", 41)?;
        drop(alternate);
        assert_eq!(
            DurableSettlementCoordinatorV1::resume_create_production(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
                TEST_CREATED_AT,
            )
            .unwrap_err(),
            CoordinatorErrorV1::CorruptState
        );

        let (_directory, path) = test_path()?;
        assert_eq!(
            stage_creation_fault(&path, CreationBoundaryV1::SchemaCommitted).unwrap_err(),
            CoordinatorErrorV1::StorageUnavailable
        );
        let advanced = Connection::open(&path)?;
        advanced.execute(
            "UPDATE coordinator_metadata SET clock_high_water_be=?1 WHERE singleton=1",
            params![(TEST_CREATED_AT + 1).to_be_bytes().as_slice()],
        )?;
        drop(advanced);
        assert_eq!(
            DurableSettlementCoordinatorV1::resume_create_production(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
                TEST_CREATED_AT,
            )
            .unwrap_err(),
            CoordinatorErrorV1::CorruptState
        );

        let (_directory, path) = test_path()?;
        assert_eq!(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced).unwrap_err(),
            CoordinatorErrorV1::StorageUnavailable
        );
        let wal = sidecar_path(&path, "-wal");
        fs::write(&wal, b"caller-shaped")?;
        fs::set_permissions(&wal, fs::Permissions::from_mode(FILE_MODE))?;
        assert_eq!(
            DurableSettlementCoordinatorV1::resume_create_production(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
                TEST_CREATED_AT,
            )
            .unwrap_err(),
            CoordinatorErrorV1::InvalidStorageAuthority
        );
        Ok(())
    }

    #[test]
    fn owner_links_process_exclusion_and_retained_path_identity_fail_closed() -> TestResult {
        let (_directory, path) = test_path()?;
        assert_eq!(
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced).unwrap_err(),
            CoordinatorErrorV1::StorageUnavailable
        );
        let hardlink = path.with_file_name("coordinator-hardlink.sqlite3");
        fs::hard_link(&path, &hardlink)?;
        assert_eq!(
            DurableSettlementCoordinatorV1::resume_create_production(
                &path,
                TEST_COORDINATOR_ID,
                TEST_PLAN_AUTHORITY_ID,
                TEST_CREATED_AT,
            )
            .unwrap_err(),
            CoordinatorErrorV1::InvalidStorageAuthority
        );

        let (_directory, path) = test_path()?;
        let store = DurableSettlementCoordinatorV1::create(
            &path,
            TEST_COORDINATOR_ID,
            TEST_PLAN_AUTHORITY_ID,
            TEST_CREATED_AT,
        )?;
        let status = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("store::provisioning_tests::lock_probe_process_child")
            .arg("--nocapture")
            .env(LOCK_PROBE_PATH_ENV, &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        assert!(
            status.success(),
            "second-process lock probe must be refused"
        );

        let displaced = path.with_file_name("displaced-coordinator.sqlite3");
        fs::rename(&path, &displaced)?;
        let replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&path)?;
        replacement.sync_all()?;
        drop(replacement);
        assert_eq!(
            store.audit_storage().unwrap_err(),
            CoordinatorErrorV1::InvalidStorageAuthority
        );
        drop(store);

        let (_directory, path) = test_path()?;
        let store = DurableSettlementCoordinatorV1::create(
            &path,
            TEST_COORDINATOR_ID,
            TEST_PLAN_AUTHORITY_ID,
            TEST_CREATED_AT,
        )?;
        let lock = process_lock_path(&path);
        let displaced_lock = path.with_file_name("displaced-coordinator.lock");
        fs::rename(&lock, &displaced_lock)?;
        let replacement_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&lock)?;
        replacement_lock.sync_all()?;
        drop(replacement_lock);
        assert_eq!(
            store.audit_storage().unwrap_err(),
            CoordinatorErrorV1::InvalidStorageAuthority
        );
        Ok(())
    }
}

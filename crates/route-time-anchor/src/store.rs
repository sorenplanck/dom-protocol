use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::fs::{self, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

use btc_crypto::SecpContext;
use deployment_registry::{AuthoritySetV1, ResolvedRegistryV1};
use kaystra_core::terms::SettlementTermsV1;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
#[cfg(target_os = "linux")]
use rustix::fs::{flock, FlockOperation};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;

use crate::signed::{
    authority_set_digest, SignedRouteTimeEvidenceV2, SignedRouteTimePolicyV2,
    MAX_SIGNED_EVIDENCE_BYTES_V2, MAX_SIGNED_POLICY_BYTES_V2,
};
use crate::types::{
    prove_ladder, route_scope_digest, CanonicalTimeCheckpointV2, CurrentRouteTimeLadderV2,
    FrozenRouteTimeCheckpointV2, FrozenRouteTimeProofCheckpointV2, RouteTimeEvidenceV2,
    RouteTimePolicyV2, VerifiedFrozenRouteTimeLadderV2, VerifiedRouteTimeLadderV2,
};
use crate::{Result, RouteTimeAnchorErrorV2};

const SCHEMA_VERSION_V2: i64 = 2;
const EVIDENCE_ACTIVE: i64 = 0;
const EVIDENCE_INVALIDATED: i64 = 1;
const EVIDENCE_CONFLICT: i64 = 2;
const MAX_HISTORY_ROWS_V2: u64 = 4_096;
#[cfg(target_os = "linux")]
const DIRECTORY_MODE: u32 = 0o700;
#[cfg(target_os = "linux")]
const FILE_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreationBoundaryV2 {
    ProcessLockPublished,
    DatabaseFileSynced,
    BeforeSchemaTransaction,
    BeforeSchemaCommit,
    SchemaCommitted,
}

/// Immutable route and authority-set pins stored in a route time database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteTimeAnchorStoreConfigV2 {
    network_id: [u8; 32],
    registry_digest: [u8; 32],
    route_scope_digest: [u8; 32],
    policy_authority_set_digest: [u8; 32],
    evidence_authority_set_digest: [u8; 32],
}

impl RouteTimeAnchorStoreConfigV2 {
    /// Derives immutable pins from the resolved registry, exact route terms and
    /// distinct externally configured policy/evidence threshold sets.
    pub fn new(
        registry: &ResolvedRegistryV1,
        upstream: &SettlementTermsV1,
        downstream: &SettlementTermsV1,
        policy_authorities: &AuthoritySetV1,
        evidence_authorities: &AuthoritySetV1,
        secp: &SecpContext,
    ) -> Result<Self> {
        let value = Self {
            network_id: registry.manifest().network_id,
            registry_digest: registry.manifest_digest(),
            route_scope_digest: route_scope_digest(upstream, downstream)?,
            policy_authority_set_digest: authority_set_digest(policy_authorities, secp)?,
            evidence_authority_set_digest: authority_set_digest(evidence_authorities, secp)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.network_id == [0; 32]
            || self.registry_digest == [0; 32]
            || self.route_scope_digest == [0; 32]
            || self.policy_authority_set_digest == [0; 32]
            || self.evidence_authority_set_digest == [0; 32]
        {
            return Err(RouteTimeAnchorErrorV2::InvalidPolicy);
        }
        Ok(())
    }

    /// Authenticated deployment-network identity.
    pub const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Exact signed deployment-registry digest.
    pub const fn registry_digest(&self) -> [u8; 32] {
        self.registry_digest
    }

    /// Exact pair of canonical settlement terms.
    pub const fn route_scope_digest(&self) -> [u8; 32] {
        self.route_scope_digest
    }

    /// Pinned threshold policy-authority set digest.
    pub const fn policy_authority_set_digest(&self) -> [u8; 32] {
        self.policy_authority_set_digest
    }

    /// Pinned threshold checkpoint-authority set digest.
    pub const fn evidence_authority_set_digest(&self) -> [u8; 32] {
        self.evidence_authority_set_digest
    }
}

/// Result of idempotently freezing the single route policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyInstallOutcomeV2 {
    /// Policy bytes were durably frozen now.
    Installed,
    /// The exact signed policy was already frozen.
    AlreadyCurrent,
}

/// Result of installing a fresh canonical checkpoint revalidation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceInstallOutcomeV2 {
    /// A strictly newer revalidation became current.
    Installed,
    /// The exact signed evidence was already current.
    AlreadyCurrent,
}

/// Authenticated policy inputs shared by all policy-bound store operations.
#[derive(Clone, Copy)]
pub struct RouteTimePolicyVerificationContextV2<'a> {
    policy_authorities: &'a AuthoritySetV1,
    secp: &'a SecpContext,
    registry: &'a ResolvedRegistryV1,
    upstream: &'a SettlementTermsV1,
    downstream: &'a SettlementTermsV1,
}

impl<'a> RouteTimePolicyVerificationContextV2<'a> {
    /// Binds policy verification to exact authorities, registry and route terms.
    pub fn new(
        policy_authorities: &'a AuthoritySetV1,
        secp: &'a SecpContext,
        registry: &'a ResolvedRegistryV1,
        upstream: &'a SettlementTermsV1,
        downstream: &'a SettlementTermsV1,
    ) -> Self {
        Self {
            policy_authorities,
            secp,
            registry,
            upstream,
            downstream,
        }
    }
}

/// Authenticated policy and evidence inputs for current-ladder operations.
#[derive(Clone, Copy)]
pub struct RouteTimeEvidenceVerificationContextV2<'a> {
    policy: RouteTimePolicyVerificationContextV2<'a>,
    evidence_authorities: &'a AuthoritySetV1,
}

impl<'a> RouteTimeEvidenceVerificationContextV2<'a> {
    /// Extends an exact policy context with the independent evidence authorities.
    pub fn new(
        policy: RouteTimePolicyVerificationContextV2<'a>,
        evidence_authorities: &'a AuthoritySetV1,
    ) -> Self {
        Self {
            policy,
            evidence_authorities,
        }
    }
}

/// Owner-only SQLite/WAL authority for one route's temporal ladder.
pub struct DurableRouteTimeAnchorStoreV2 {
    connection: Connection,
    config: RouteTimeAnchorStoreConfigV2,
    opening_epoch: u64,
    #[cfg(target_os = "linux")]
    _process_lock: File,
}

impl core::fmt::Debug for DurableRouteTimeAnchorStoreV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableRouteTimeAnchorStoreV2")
            .field("route_scope_digest", &self.config.route_scope_digest)
            .field("opening_epoch", &self.opening_epoch)
            .finish_non_exhaustive()
    }
}

impl DurableRouteTimeAnchorStoreV2 {
    /// Creates a new route-scoped owner-only database; replacement is refused.
    pub fn create(path: &Path, config: RouteTimeAnchorStoreConfigV2) -> Result<Self> {
        Self::create_with_boundary_hook(path, config, |_| Ok(()))
    }

    fn create_with_boundary_hook<F>(
        path: &Path,
        config: RouteTimeAnchorStoreConfigV2,
        mut boundary: F,
    ) -> Result<Self>
    where
        F: FnMut(CreationBoundaryV2) -> Result<()>,
    {
        config.validate()?;
        if fs::symlink_metadata(path).is_ok() {
            return Err(RouteTimeAnchorErrorV2::DatabasePresent);
        }
        #[cfg(target_os = "linux")]
        {
            validate_owner_directory(
                path.parent()
                    .ok_or(RouteTimeAnchorErrorV2::InvalidStorageAuthority)?,
            )?;
            require_sidecars_absent(path)?;
        }
        #[cfg(target_os = "linux")]
        let process_lock = acquire_process_lock(path, true)?;
        boundary(CreationBoundaryV2::ProcessLockPublished)?;
        create_owner_database_file(path)?;
        boundary(CreationBoundaryV2::DatabaseFileSynced)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        boundary(CreationBoundaryV2::BeforeSchemaTransaction)?;
        create_schema_and_meta_with_boundary_hook(&connection, config, || {
            boundary(CreationBoundaryV2::BeforeSchemaCommit)
        })?;
        boundary(CreationBoundaryV2::SchemaCommitted)?;
        validate_backend_and_schema(&connection)?;
        validate_meta(&connection, config)?;
        #[cfg(target_os = "linux")]
        {
            validate_sqlite_sidecars(path)?;
            sync_owner_directory(
                path.parent()
                    .ok_or(RouteTimeAnchorErrorV2::InvalidStorageAuthority)?,
            )?;
        }
        Ok(Self {
            connection,
            config,
            opening_epoch: 1,
            #[cfg(target_os = "linux")]
            _process_lock: process_lock,
        })
    }

    /// Resumes only the narrow create crash window authorized by an external
    /// durable provisioning journal.
    ///
    /// The journal must already have durably recorded this exact store's
    /// create intent. This method is deliberately not open-or-create: the
    /// exact owner-only process lock published by [`Self::create`] must exist
    /// and be exclusively acquirable. The database may be absent after lock
    /// publication, may be a pristine SQLite file, or may contain only the
    /// exact V2 schema and initial metadata for `config`. Any economic row,
    /// advanced metadata, alternate schema/version, or malformed SQLite
    /// sidecar is refused.
    pub fn resume_create_production(
        path: &Path,
        config: RouteTimeAnchorStoreConfigV2,
    ) -> Result<Self> {
        config.validate()?;
        #[cfg(target_os = "linux")]
        validate_owner_directory(
            path.parent()
                .ok_or(RouteTimeAnchorErrorV2::InvalidStorageAuthority)?,
        )?;
        #[cfg(target_os = "linux")]
        let process_lock = acquire_process_lock(path, false)?;

        match fs::symlink_metadata(path) {
            Ok(_) => {
                #[cfg(target_os = "linux")]
                {
                    validate_owner_file(path)?;
                    validate_resumable_sqlite_sidecars(path)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(target_os = "linux")]
                require_sidecars_absent(path)?;
                create_owner_database_file(path)?;
            }
            Err(_) => return Err(RouteTimeAnchorErrorV2::StorageUnavailable),
        }

        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        match resumable_creation_state(&connection)? {
            ResumableCreationStateV2::PristineSqlite => {
                create_schema_and_meta(&connection, config)?;
            }
            ResumableCreationStateV2::PristineInitialized => {}
        }
        validate_pristine_initialized_store(&connection, config)?;
        #[cfg(target_os = "linux")]
        {
            validate_resumable_sqlite_sidecars(path)?;
            sync_owner_directory(
                path.parent()
                    .ok_or(RouteTimeAnchorErrorV2::InvalidStorageAuthority)?,
            )?;
        }
        Ok(Self {
            connection,
            config,
            opening_epoch: 1,
            #[cfg(target_os = "linux")]
            _process_lock: process_lock,
        })
    }

    /// Opens only an existing V2 database, audits it and advances the durable
    /// process-opening epoch so capabilities from before restart are stale.
    pub fn open_existing(path: &Path, config: RouteTimeAnchorStoreConfigV2) -> Result<Self> {
        config.validate()?;
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(RouteTimeAnchorErrorV2::DatabaseMissing)
            }
            Err(_) => return Err(RouteTimeAnchorErrorV2::StorageUnavailable),
        }
        #[cfg(target_os = "linux")]
        {
            validate_owner_directory(
                path.parent()
                    .ok_or(RouteTimeAnchorErrorV2::InvalidStorageAuthority)?,
            )?;
            validate_owner_file(path)?;
            validate_resumable_sqlite_sidecars(path)?;
        }
        #[cfg(target_os = "linux")]
        let process_lock = acquire_process_lock(path, false)?;
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        if resumable_creation_state(&connection)? == ResumableCreationStateV2::PristineSqlite {
            return Err(RouteTimeAnchorErrorV2::CreationIncomplete);
        }
        validate_backend_and_schema(&connection)?;
        validate_meta(&connection, config)?;
        validate_retained_bounds(&connection)?;
        validate_retained_encoding(&connection, config)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        let previous = meta_u64(&transaction, "opening_epoch_be")?;
        let opening_epoch = previous
            .checked_add(1)
            .ok_or(RouteTimeAnchorErrorV2::CorruptState)?;
        transaction
            .execute(
                "UPDATE route_time_meta SET opening_epoch_be = ?1 WHERE singleton = 1",
                params![opening_epoch.to_be_bytes().as_slice()],
            )
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        #[cfg(target_os = "linux")]
        {
            validate_owner_directory(
                path.parent()
                    .ok_or(RouteTimeAnchorErrorV2::InvalidStorageAuthority)?,
            )?;
            validate_owner_file(path)?;
            validate_resumable_sqlite_sidecars(path)?;
        }
        Ok(Self {
            connection,
            config,
            opening_epoch,
            #[cfg(target_os = "linux")]
            _process_lock: process_lock,
        })
    }

    /// Verifies and durably freezes the one policy authorized for this route.
    pub fn install_policy(
        &mut self,
        signed: &SignedRouteTimePolicyV2,
        context: RouteTimePolicyVerificationContextV2<'_>,
        now: u64,
    ) -> Result<PolicyInstallOutcomeV2> {
        self.validate_call_context(
            context.registry,
            context.upstream,
            context.downstream,
            context.policy_authorities,
            None,
            context.secp,
        )?;
        advance_clock_durably(&mut self.connection, self.opening_epoch, now)?;
        let policy = signed.verify(
            context.policy_authorities,
            context.secp,
            context.registry,
            context.upstream,
            context.downstream,
            now,
        )?;
        let signed_bytes = signed.canonical_bytes()?;
        let digest = policy.policy_digest()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        require_current_opening(&transaction, self.opening_epoch)?;
        validate_retained_bounds_tx(&transaction)?;
        let current: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT policy_digest, signed_bytes FROM route_time_policy WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        if let Some((indexed_digest, stored_bytes)) = current {
            let retained = SignedRouteTimePolicyV2::decode(&stored_bytes)?;
            let retained_policy = retained.verify_authenticity(
                context.policy_authorities,
                context.secp,
                context.registry,
                context.upstream,
                context.downstream,
            )?;
            let retained_digest = retained_policy.policy_digest()?;
            if decode_32(&indexed_digest)? != retained_digest {
                return Err(RouteTimeAnchorErrorV2::CorruptState);
            }
            if retained_digest != digest || stored_bytes != signed_bytes {
                return Err(RouteTimeAnchorErrorV2::PolicyConflict);
            }
            transaction
                .commit()
                .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
            return Ok(PolicyInstallOutcomeV2::AlreadyCurrent);
        }
        transaction
            .execute(
                "INSERT INTO route_time_policy(singleton, policy_digest, signed_bytes, installed_at_be)
                 VALUES(1, ?1, ?2, ?3)",
                params![digest.as_slice(), signed_bytes, now.to_be_bytes().as_slice()],
            )
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        increment_revision(&transaction)?;
        transaction
            .commit()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        Ok(PolicyInstallOutcomeV2::Installed)
    }

    /// Installs one fresh signed revalidation. Frozen anchor movement, tip
    /// rollback or same-sequence equivocation invalidates the route durably.
    pub fn install_evidence(
        &mut self,
        signed: &SignedRouteTimeEvidenceV2,
        context: RouteTimeEvidenceVerificationContextV2<'_>,
        now: u64,
    ) -> Result<EvidenceInstallOutcomeV2> {
        self.validate_call_context(
            context.policy.registry,
            context.policy.upstream,
            context.policy.downstream,
            context.policy.policy_authorities,
            Some(context.evidence_authorities),
            context.policy.secp,
        )?;
        advance_clock_durably(&mut self.connection, self.opening_epoch, now)?;
        let retained_signed_policy = self.load_policy()?;
        let policy = retained_signed_policy.verify(
            context.policy.policy_authorities,
            context.policy.secp,
            context.policy.registry,
            context.policy.upstream,
            context.policy.downstream,
            now,
        )?;
        let evidence = signed.verify(
            context.evidence_authorities,
            context.policy.secp,
            &policy,
            now,
        )?;
        let signed_bytes = signed.canonical_bytes()?;
        let evidence_digest = evidence.evidence_digest()?;
        let policy_digest = policy.policy_digest()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        require_current_opening(&transaction, self.opening_epoch)?;
        validate_retained_bounds_tx(&transaction)?;
        let current = load_current_evidence_row(&transaction)?;
        if let Some(row) = current {
            let retained_signed = SignedRouteTimeEvidenceV2::decode(&row.signed_bytes)?;
            let retained = retained_signed.verify_authenticity(
                context.evidence_authorities,
                context.policy.secp,
                &policy,
            )?;
            reconcile_evidence_row(&row, &retained)?;
            if row.status == EVIDENCE_INVALIDATED {
                return Err(RouteTimeAnchorErrorV2::AnchorReorged);
            }
            if row.status != EVIDENCE_ACTIVE {
                return Err(RouteTimeAnchorErrorV2::CorruptState);
            }
            if row.digest == evidence_digest && row.signed_bytes == signed_bytes {
                transaction
                    .commit()
                    .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
                return Ok(EvidenceInstallOutcomeV2::AlreadyCurrent);
            }
            if evidence.sequence() == retained.sequence() {
                persist_conflict_and_invalidate(
                    &transaction,
                    &evidence,
                    evidence_digest,
                    policy_digest,
                    &signed_bytes,
                    now,
                )?;
                transaction
                    .commit()
                    .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
                return Err(RouteTimeAnchorErrorV2::EvidenceRollback);
            }
            if evidence.sequence() < retained.sequence()
                || evidence.observed_at_seconds() <= retained.observed_at_seconds()
            {
                return Err(RouteTimeAnchorErrorV2::EvidenceRollback);
            }
            if !same_frozen_anchors(&retained, &evidence) || !tips_extend(&retained, &evidence) {
                persist_conflict_and_invalidate(
                    &transaction,
                    &evidence,
                    evidence_digest,
                    policy_digest,
                    &signed_bytes,
                    now,
                )?;
                transaction
                    .commit()
                    .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
                return Err(RouteTimeAnchorErrorV2::AnchorReorged);
            }
        }
        insert_evidence_history(
            &transaction,
            EvidenceHistoryRecordV2 {
                evidence: &evidence,
                evidence_digest,
                policy_digest,
                status: EVIDENCE_ACTIVE,
                signed_bytes: &signed_bytes,
                installed_at: now,
            },
        )?;
        transaction
            .execute(
                "INSERT INTO route_time_evidence_current(
                     singleton, sequence_be, evidence_digest, policy_digest,
                     observed_at_be, expires_at_be, status_tag, signed_bytes)
                 VALUES(1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(singleton) DO UPDATE SET
                     sequence_be = excluded.sequence_be,
                     evidence_digest = excluded.evidence_digest,
                     policy_digest = excluded.policy_digest,
                     observed_at_be = excluded.observed_at_be,
                     expires_at_be = excluded.expires_at_be,
                     status_tag = excluded.status_tag,
                     signed_bytes = excluded.signed_bytes",
                params![
                    evidence.sequence().to_be_bytes().as_slice(),
                    evidence_digest.as_slice(),
                    policy_digest.as_slice(),
                    evidence.observed_at_seconds().to_be_bytes().as_slice(),
                    evidence.expires_at_seconds().to_be_bytes().as_slice(),
                    EVIDENCE_ACTIVE,
                    signed_bytes,
                ],
            )
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        increment_revision(&transaction)?;
        enforce_history_bound(&transaction)?;
        transaction
            .commit()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        Ok(EvidenceInstallOutcomeV2::Installed)
    }

    /// Reauthenticates the current policy and evidence, advances the durable
    /// clock and issues a single-use proof of both worst-case inequalities.
    pub fn prove_route_ladder(
        &mut self,
        context: RouteTimeEvidenceVerificationContextV2<'_>,
        now: u64,
    ) -> Result<VerifiedRouteTimeLadderV2> {
        self.validate_call_context(
            context.policy.registry,
            context.policy.upstream,
            context.policy.downstream,
            context.policy.policy_authorities,
            Some(context.evidence_authorities),
            context.policy.secp,
        )?;
        advance_clock_durably(&mut self.connection, self.opening_epoch, now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        require_current_opening(&transaction, self.opening_epoch)?;
        validate_retained_bounds_tx(&transaction)?;
        let signed_policy = load_policy_tx(&transaction)?;
        let policy = signed_policy.verify(
            context.policy.policy_authorities,
            context.policy.secp,
            context.policy.registry,
            context.policy.upstream,
            context.policy.downstream,
            now,
        )?;
        let row = load_current_evidence_row(&transaction)?
            .ok_or(RouteTimeAnchorErrorV2::InvalidEvidence)?;
        if row.status == EVIDENCE_INVALIDATED {
            return Err(RouteTimeAnchorErrorV2::AnchorReorged);
        }
        if row.status != EVIDENCE_ACTIVE {
            return Err(RouteTimeAnchorErrorV2::CorruptState);
        }
        let signed_evidence = SignedRouteTimeEvidenceV2::decode(&row.signed_bytes)?;
        let evidence = signed_evidence.verify(
            context.evidence_authorities,
            context.policy.secp,
            &policy,
            now,
        )?;
        reconcile_evidence_row(&row, &evidence)?;
        let revision = meta_u64(&transaction, "revision_be")?;
        let proof = prove_ladder(
            &policy,
            &evidence,
            context.policy.upstream,
            context.policy.downstream,
            now,
            revision,
            self.opening_epoch,
        )?;
        transaction
            .commit()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        Ok(proof)
    }

    /// Proves and immediately consumes a current capability only if the exact
    /// checkpoint frozen by admission remains in this store's authenticated
    /// monotonic ancestry.
    ///
    /// A newer evidence sequence is accepted only after every retained active
    /// revalidation from the frozen checkpoint through the current row has
    /// valid threshold signatures, unchanged anchors and extending tips. A
    /// fresh replacement database that merely starts at a higher sequence is
    /// therefore not an admissible continuation.
    pub fn prove_current_route_ladder_from_checkpoint<'authority>(
        &'authority mut self,
        checkpoint: FrozenRouteTimeCheckpointV2,
        context: RouteTimeEvidenceVerificationContextV2<'_>,
        now: u64,
    ) -> Result<CurrentRouteTimeLadderV2<'authority>> {
        if checkpoint.route_scope_digest() != self.config.route_scope_digest {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }
        let proof = self.prove_route_ladder(context, now)?;
        self.verify_frozen_checkpoint_ancestry(checkpoint, context, &proof)?;
        self.consume_capability_at(proof, now)
    }

    /// Reauthenticates and reconstructs the exact historical ladder consumed
    /// by route admission without treating it as a current capability.
    ///
    /// The signed policy must equal the frozen policy row byte-for-byte. The
    /// signed evidence must equal the retained history row identified by its
    /// digest and sequence, including all derived SQL columns. Current expiry,
    /// reorg or equivocation does not erase that historical fact; this method
    /// neither advances the durable clock nor authorizes new funding.
    pub fn verify_frozen_route_ladder(
        &self,
        checkpoint: FrozenRouteTimeProofCheckpointV2,
        signed_policy: &SignedRouteTimePolicyV2,
        signed_evidence: &SignedRouteTimeEvidenceV2,
        context: RouteTimeEvidenceVerificationContextV2<'_>,
    ) -> Result<VerifiedFrozenRouteTimeLadderV2> {
        self.validate_call_context(
            context.policy.registry,
            context.policy.upstream,
            context.policy.downstream,
            context.policy.policy_authorities,
            Some(context.evidence_authorities),
            context.policy.secp,
        )?;
        validate_retained_bounds(&self.connection)?;
        validate_retained_encoding(&self.connection, self.config)?;

        let policy_bytes = signed_policy.canonical_bytes()?;
        let retained_policy: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT policy_digest, signed_bytes FROM route_time_policy
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        let (retained_policy_digest, retained_policy_bytes) =
            retained_policy.ok_or(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch)?;
        if retained_policy_bytes != policy_bytes {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }
        let policy = signed_policy.verify_authenticity(
            context.policy.policy_authorities,
            context.policy.secp,
            context.policy.registry,
            context.policy.upstream,
            context.policy.downstream,
        )?;
        let ancestry = checkpoint.ancestry();
        if decode_32(&retained_policy_digest)? != ancestry.policy_digest()
            || policy.policy_digest()? != ancestry.policy_digest()
            || policy.route_scope_digest() != ancestry.route_scope_digest()
        {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }

        let evidence_bytes = signed_evidence.canonical_bytes()?;
        let retained_evidence: Option<EncodedEvidenceHistoryRowV2> = self
            .connection
            .query_row(
                "SELECT evidence_digest, sequence_be, policy_digest, observed_at_be,
                        expires_at_be, status_tag, signed_bytes
                 FROM route_time_evidence_history
                 WHERE evidence_digest = ?1 AND sequence_be = ?2",
                params![
                    ancestry.evidence_digest().as_slice(),
                    ancestry.evidence_sequence().to_be_bytes().as_slice()
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        let (digest, sequence, policy_digest, observed_at, expires_at, status, retained_bytes) =
            retained_evidence.ok_or(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch)?;
        if retained_bytes != evidence_bytes || status != EVIDENCE_ACTIVE {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }
        let evidence = signed_evidence.verify_authenticity(
            context.evidence_authorities,
            context.policy.secp,
            &policy,
        )?;
        if decode_32(&digest)? != ancestry.evidence_digest()
            || decode_u64(&sequence)? != ancestry.evidence_sequence()
            || decode_32(&policy_digest)? != ancestry.policy_digest()
            || decode_u64(&observed_at)? != evidence.observed_at_seconds()
            || decode_u64(&expires_at)? != evidence.expires_at_seconds()
            || evidence.evidence_digest()? != ancestry.evidence_digest()
            || evidence.sequence() != ancestry.evidence_sequence()
            || evidence.policy_digest() != ancestry.policy_digest()
            || evidence.route_scope_digest() != ancestry.route_scope_digest()
        {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }

        let proof = prove_ladder(
            &policy,
            &evidence,
            context.policy.upstream,
            context.policy.downstream,
            checkpoint.issued_at_seconds(),
            0,
            0,
        )?;
        evidence.validate_at(&policy, checkpoint.validated_at_seconds())?;
        if proof.route_scope_digest() != ancestry.route_scope_digest()
            || proof.policy_digest() != ancestry.policy_digest()
            || proof.evidence_digest() != ancestry.evidence_digest()
            || proof.evidence_sequence() != ancestry.evidence_sequence()
            || proof.binding_digest() != checkpoint.proof_digest()
            || proof.issued_at_seconds() != checkpoint.issued_at_seconds()
            || proof.valid_until_seconds() != checkpoint.valid_until_seconds()
            || checkpoint.validated_at_seconds() < checkpoint.issued_at_seconds()
            || checkpoint.validated_at_seconds() >= checkpoint.valid_until_seconds()
        {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }
        Ok(VerifiedFrozenRouteTimeLadderV2::new(
            proof,
            checkpoint.validated_at_seconds(),
        ))
    }

    /// Confirms that an unconsumed proof still belongs to this exact process
    /// opening and current evidence revision. Restart or any update rejects it.
    pub fn revalidate_capability(&self, proof: &VerifiedRouteTimeLadderV2) -> Result<()> {
        let current: Option<EncodedCapabilityStateV2> = self
            .connection
            .query_row(
                "SELECT m.opening_epoch_be, m.revision_be,
                        e.policy_digest, e.evidence_digest, e.status_tag
                 FROM route_time_meta AS m
                 JOIN route_time_evidence_current AS e ON e.singleton = m.singleton
                 WHERE m.singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        let (opening_epoch, revision, policy_digest, evidence_digest, status) =
            current.ok_or(RouteTimeAnchorErrorV2::StaleCapability)?;
        if proof.store_opening_epoch() != decode_u64(&opening_epoch)?
            || proof.store_revision() != decode_u64(&revision)?
            || proof.policy_digest() != decode_32(&policy_digest)?
            || proof.evidence_digest() != decode_32(&evidence_digest)?
            || status != EVIDENCE_ACTIVE
        {
            return Err(RouteTimeAnchorErrorV2::StaleCapability);
        }
        Ok(())
    }

    /// Revalidates opening/revision and freshness against the durable trusted
    /// clock. A stale attempt still advances the high-water mark, so clock
    /// rollback cannot revive the capability later.
    pub fn revalidate_capability_at(
        &mut self,
        proof: &VerifiedRouteTimeLadderV2,
        now: u64,
    ) -> Result<()> {
        advance_clock_durably(&mut self.connection, self.opening_epoch, now)?;
        self.revalidate_capability(proof)?;
        if now < proof.issued_at_seconds() {
            return Err(RouteTimeAnchorErrorV2::ClockRollback);
        }
        if now >= proof.valid_until_seconds() {
            return Err(RouteTimeAnchorErrorV2::EvidenceStale);
        }
        Ok(())
    }

    /// Consumes an issued proof only after final opening/revision/freshness
    /// revalidation. The returned lifetime exclusively borrows this authority
    /// until the caller consumes the current capability.
    pub fn consume_capability_at<'authority>(
        &'authority mut self,
        proof: VerifiedRouteTimeLadderV2,
        now: u64,
    ) -> Result<CurrentRouteTimeLadderV2<'authority>> {
        self.revalidate_capability_at(&proof, now)?;
        Ok(CurrentRouteTimeLadderV2::new(proof, now))
    }

    fn load_policy(&self) -> Result<SignedRouteTimePolicyV2> {
        let bytes: Vec<u8> = self
            .connection
            .query_row(
                "SELECT signed_bytes FROM route_time_policy WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?
            .ok_or(RouteTimeAnchorErrorV2::InvalidPolicy)?;
        SignedRouteTimePolicyV2::decode(&bytes)
    }

    fn verify_frozen_checkpoint_ancestry(
        &self,
        checkpoint: FrozenRouteTimeCheckpointV2,
        context: RouteTimeEvidenceVerificationContextV2<'_>,
        proof: &VerifiedRouteTimeLadderV2,
    ) -> Result<()> {
        self.validate_call_context(
            context.policy.registry,
            context.policy.upstream,
            context.policy.downstream,
            context.policy.policy_authorities,
            Some(context.evidence_authorities),
            context.policy.secp,
        )?;
        let signed_policy = self.load_policy()?;
        let policy = signed_policy.verify_authenticity(
            context.policy.policy_authorities,
            context.policy.secp,
            context.policy.registry,
            context.policy.upstream,
            context.policy.downstream,
        )?;
        if policy.policy_digest()? != checkpoint.policy_digest()
            || proof.policy_digest() != checkpoint.policy_digest()
            || proof.route_scope_digest() != checkpoint.route_scope_digest()
            || proof.evidence_sequence() < checkpoint.evidence_sequence()
            || (proof.evidence_sequence() == checkpoint.evidence_sequence()
                && proof.evidence_digest() != checkpoint.evidence_digest())
        {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }

        let mut statement = self
            .connection
            .prepare(
                "SELECT evidence_digest, sequence_be, policy_digest, observed_at_be,
                        expires_at_be, status_tag, signed_bytes
                 FROM route_time_evidence_history
                 WHERE sequence_be >= ?1 AND status_tag = ?2
                 ORDER BY sequence_be ASC, evidence_digest ASC",
            )
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        let rows = statement
            .query_map(
                params![
                    checkpoint.evidence_sequence().to_be_bytes().as_slice(),
                    EVIDENCE_ACTIVE
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;

        let mut previous: Option<RouteTimeEvidenceV2> = None;
        let mut saw_frozen = false;
        for row in rows {
            let (digest, sequence, policy_digest, observed_at, expires_at, status, signed_bytes) =
                row.map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
            let row = EvidenceRowV2 {
                digest: decode_32(&digest)?,
                sequence: decode_u64(&sequence)?,
                policy_digest: decode_32(&policy_digest)?,
                observed_at: decode_u64(&observed_at)?,
                expires_at: decode_u64(&expires_at)?,
                status,
                signed_bytes,
            };
            let signed = SignedRouteTimeEvidenceV2::decode(&row.signed_bytes)?;
            let evidence = signed.verify_authenticity(
                context.evidence_authorities,
                context.policy.secp,
                &policy,
            )?;
            reconcile_evidence_row(&row, &evidence)?;
            if row.status != EVIDENCE_ACTIVE
                || row.policy_digest != checkpoint.policy_digest()
                || (previous.is_none()
                    && (row.sequence != checkpoint.evidence_sequence()
                        || row.digest != checkpoint.evidence_digest()))
            {
                return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
            }
            if let Some(prior) = previous.as_ref() {
                if evidence.sequence() <= prior.sequence()
                    || evidence.observed_at_seconds() <= prior.observed_at_seconds()
                    || !same_frozen_anchors(prior, &evidence)
                    || !tips_extend(prior, &evidence)
                {
                    return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
                }
            } else {
                saw_frozen = true;
            }
            previous = Some(evidence);
        }
        let current = previous.ok_or(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch)?;
        if !saw_frozen
            || current.sequence() != proof.evidence_sequence()
            || current.evidence_digest()? != proof.evidence_digest()
        {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }
        Ok(())
    }

    fn validate_call_context(
        &self,
        registry: &ResolvedRegistryV1,
        upstream: &SettlementTermsV1,
        downstream: &SettlementTermsV1,
        policy_authorities: &AuthoritySetV1,
        evidence_authorities: Option<&AuthoritySetV1>,
        secp: &SecpContext,
    ) -> Result<()> {
        if registry.manifest().network_id != self.config.network_id
            || registry.manifest_digest() != self.config.registry_digest
            || route_scope_digest(upstream, downstream)? != self.config.route_scope_digest
            || authority_set_digest(policy_authorities, secp)?
                != self.config.policy_authority_set_digest
        {
            return Err(RouteTimeAnchorErrorV2::RegistryMismatch);
        }
        if let Some(authorities) = evidence_authorities {
            if authority_set_digest(authorities, secp)? != self.config.evidence_authority_set_digest
            {
                return Err(RouteTimeAnchorErrorV2::InvalidAuthoritySet);
            }
        }
        Ok(())
    }
}

struct EvidenceRowV2 {
    sequence: u64,
    digest: [u8; 32],
    policy_digest: [u8; 32],
    observed_at: u64,
    expires_at: u64,
    status: i64,
    signed_bytes: Vec<u8>,
}

type EncodedEvidenceRowV2 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);
type EncodedEvidenceHistoryRowV2 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);
type EncodedCapabilityStateV2 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);
type EncodedStoreMetaV2 = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn load_current_evidence_row(transaction: &Transaction<'_>) -> Result<Option<EvidenceRowV2>> {
    let row: Option<EncodedEvidenceRowV2> = transaction
        .query_row(
            "SELECT sequence_be, evidence_digest, policy_digest, observed_at_be,
                    expires_at_be, status_tag, signed_bytes
             FROM route_time_evidence_current WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    row.map(
        |(sequence, digest, policy, observed, expires, status, signed_bytes)| {
            Ok(EvidenceRowV2 {
                sequence: decode_u64(&sequence)?,
                digest: decode_32(&digest)?,
                policy_digest: decode_32(&policy)?,
                observed_at: decode_u64(&observed)?,
                expires_at: decode_u64(&expires)?,
                status,
                signed_bytes,
            })
        },
    )
    .transpose()
}

fn reconcile_evidence_row(row: &EvidenceRowV2, evidence: &RouteTimeEvidenceV2) -> Result<()> {
    if row.sequence != evidence.sequence()
        || row.digest != evidence.evidence_digest()?
        || row.policy_digest != evidence.policy_digest()
        || row.observed_at != evidence.observed_at_seconds()
        || row.expires_at != evidence.expires_at_seconds()
    {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    Ok(())
}

fn same_frozen_anchors(left: &RouteTimeEvidenceV2, right: &RouteTimeEvidenceV2) -> bool {
    left.checkpoints()
        .iter()
        .zip(right.checkpoints().iter())
        .all(|(left, right)| frozen_anchor(left) == frozen_anchor(right))
}

type FrozenAnchorV2 = (
    crate::CheckpointRoleV2,
    crate::ClockKindV2,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    u64,
    [u8; 32],
    [u8; 32],
    u64,
    u64,
);

fn frozen_anchor(checkpoint: &CanonicalTimeCheckpointV2) -> FrozenAnchorV2 {
    (
        checkpoint.role,
        checkpoint.clock_kind,
        checkpoint.chain_id.0,
        checkpoint.genesis_hash,
        checkpoint.profile_digest,
        checkpoint.anchor_height,
        checkpoint.anchor_hash,
        checkpoint.parent_hash,
        checkpoint.time_lower_seconds,
        checkpoint.time_upper_seconds,
    )
}

fn tips_extend(left: &RouteTimeEvidenceV2, right: &RouteTimeEvidenceV2) -> bool {
    left.checkpoints()
        .iter()
        .zip(right.checkpoints().iter())
        .all(|(left, right)| {
            right.canonical_tip_height > left.canonical_tip_height
                || (right.canonical_tip_height == left.canonical_tip_height
                    && right.canonical_tip_hash == left.canonical_tip_hash)
        })
}

fn persist_conflict_and_invalidate(
    transaction: &Transaction<'_>,
    evidence: &RouteTimeEvidenceV2,
    evidence_digest: [u8; 32],
    policy_digest: [u8; 32],
    signed_bytes: &[u8],
    now: u64,
) -> Result<()> {
    insert_evidence_history(
        transaction,
        EvidenceHistoryRecordV2 {
            evidence,
            evidence_digest,
            policy_digest,
            status: EVIDENCE_CONFLICT,
            signed_bytes,
            installed_at: now,
        },
    )?;
    transaction
        .execute(
            "UPDATE route_time_evidence_current SET status_tag = ?1 WHERE singleton = 1",
            params![EVIDENCE_INVALIDATED],
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    increment_revision(transaction)?;
    enforce_history_bound(transaction)
}

struct EvidenceHistoryRecordV2<'a> {
    evidence: &'a RouteTimeEvidenceV2,
    evidence_digest: [u8; 32],
    policy_digest: [u8; 32],
    status: i64,
    signed_bytes: &'a [u8],
    installed_at: u64,
}

fn insert_evidence_history(
    transaction: &Transaction<'_>,
    record: EvidenceHistoryRecordV2<'_>,
) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO route_time_evidence_history(
                 evidence_digest, sequence_be, policy_digest, observed_at_be,
                 expires_at_be, status_tag, signed_bytes, installed_at_be)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.evidence_digest.as_slice(),
                record.evidence.sequence().to_be_bytes().as_slice(),
                record.policy_digest.as_slice(),
                record
                    .evidence
                    .observed_at_seconds()
                    .to_be_bytes()
                    .as_slice(),
                record
                    .evidence
                    .expires_at_seconds()
                    .to_be_bytes()
                    .as_slice(),
                record.status,
                record.signed_bytes,
                record.installed_at.to_be_bytes().as_slice(),
            ],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                RouteTimeAnchorErrorV2::EvidenceRollback
            } else {
                RouteTimeAnchorErrorV2::StorageUnavailable
            }
        })?;
    Ok(())
}

fn load_policy_tx(transaction: &Transaction<'_>) -> Result<SignedRouteTimePolicyV2> {
    let bytes: Vec<u8> = transaction
        .query_row(
            "SELECT signed_bytes FROM route_time_policy WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?
        .ok_or(RouteTimeAnchorErrorV2::InvalidPolicy)?;
    SignedRouteTimePolicyV2::decode(&bytes)
}

fn increment_revision(transaction: &Transaction<'_>) -> Result<u64> {
    let revision = meta_u64(transaction, "revision_be")?
        .checked_add(1)
        .ok_or(RouteTimeAnchorErrorV2::CorruptState)?;
    transaction
        .execute(
            "UPDATE route_time_meta SET revision_be = ?1 WHERE singleton = 1",
            params![revision.to_be_bytes().as_slice()],
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    Ok(revision)
}

fn advance_clock(transaction: &Transaction<'_>, now: u64) -> Result<()> {
    let high_water = meta_u64(transaction, "clock_high_water_be")?;
    if now < high_water {
        return Err(RouteTimeAnchorErrorV2::ClockRollback);
    }
    if now > high_water {
        transaction
            .execute(
                "UPDATE route_time_meta SET clock_high_water_be = ?1 WHERE singleton = 1",
                params![now.to_be_bytes().as_slice()],
            )
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    }
    Ok(())
}

fn advance_clock_durably(
    connection: &mut Connection,
    expected_opening_epoch: u64,
    now: u64,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    require_current_opening(&transaction, expected_opening_epoch)?;
    advance_clock(&transaction, now)?;
    transaction
        .commit()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)
}

fn require_current_opening(transaction: &Transaction<'_>, expected: u64) -> Result<()> {
    if meta_u64(transaction, "opening_epoch_be")? != expected {
        return Err(RouteTimeAnchorErrorV2::StaleCapability);
    }
    Ok(())
}

fn meta_u64(transaction: &Transaction<'_>, column: &str) -> Result<u64> {
    let query = match column {
        "clock_high_water_be" => {
            "SELECT clock_high_water_be FROM route_time_meta WHERE singleton = 1"
        }
        "opening_epoch_be" => "SELECT opening_epoch_be FROM route_time_meta WHERE singleton = 1",
        "revision_be" => "SELECT revision_be FROM route_time_meta WHERE singleton = 1",
        _ => return Err(RouteTimeAnchorErrorV2::CorruptState),
    };
    let bytes: Vec<u8> = transaction
        .query_row(query, [], |row| row.get(0))
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    decode_u64(&bytes)
}

fn enforce_history_bound(transaction: &Transaction<'_>) -> Result<()> {
    let count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM route_time_evidence_history",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let count = u64::try_from(count).map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    if count > MAX_HISTORY_ROWS_V2 {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    Ok(())
}

fn create_schema_and_meta(
    connection: &Connection,
    config: RouteTimeAnchorStoreConfigV2,
) -> Result<()> {
    create_schema_and_meta_with_boundary_hook(connection, config, || Ok(()))
}

fn create_schema_and_meta_with_boundary_hook<F>(
    connection: &Connection,
    config: RouteTimeAnchorStoreConfigV2,
    before_commit: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    create_schema(&transaction)?;
    transaction
        .execute(
            "INSERT INTO route_time_meta(
                 singleton, network_id, registry_digest, route_scope_digest,
                 policy_authority_set_digest, evidence_authority_set_digest,
                 clock_high_water_be, opening_epoch_be, revision_be)
             VALUES(1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                config.network_id.as_slice(),
                config.registry_digest.as_slice(),
                config.route_scope_digest.as_slice(),
                config.policy_authority_set_digest.as_slice(),
                config.evidence_authority_set_digest.as_slice(),
                0u64.to_be_bytes().as_slice(),
                1u64.to_be_bytes().as_slice(),
                0u64.to_be_bytes().as_slice(),
            ],
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION_V2)
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    before_commit()?;
    transaction
        .commit()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)
}

fn create_schema(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE route_time_meta (
                 singleton                     INTEGER PRIMARY KEY CHECK(singleton = 1),
                 network_id                    BLOB NOT NULL CHECK(length(network_id) = 32),
                 registry_digest               BLOB NOT NULL CHECK(length(registry_digest) = 32),
                 route_scope_digest            BLOB NOT NULL CHECK(length(route_scope_digest) = 32),
                 policy_authority_set_digest   BLOB NOT NULL CHECK(length(policy_authority_set_digest) = 32),
                 evidence_authority_set_digest BLOB NOT NULL CHECK(length(evidence_authority_set_digest) = 32),
                 clock_high_water_be           BLOB NOT NULL CHECK(length(clock_high_water_be) = 8),
                 opening_epoch_be              BLOB NOT NULL CHECK(length(opening_epoch_be) = 8),
                 revision_be                   BLOB NOT NULL CHECK(length(revision_be) = 8)
             ) STRICT;
             CREATE TABLE route_time_policy (
                 singleton       INTEGER PRIMARY KEY CHECK(singleton = 1),
                 policy_digest   BLOB NOT NULL UNIQUE CHECK(length(policy_digest) = 32),
                 signed_bytes    BLOB NOT NULL CHECK(length(signed_bytes) > 0),
                 installed_at_be BLOB NOT NULL CHECK(length(installed_at_be) = 8)
             ) STRICT;
             CREATE TABLE route_time_evidence_current (
                 singleton       INTEGER PRIMARY KEY CHECK(singleton = 1),
                 sequence_be     BLOB NOT NULL CHECK(length(sequence_be) = 8),
                 evidence_digest BLOB NOT NULL UNIQUE CHECK(length(evidence_digest) = 32),
                 policy_digest   BLOB NOT NULL CHECK(length(policy_digest) = 32),
                 observed_at_be  BLOB NOT NULL CHECK(length(observed_at_be) = 8),
                 expires_at_be   BLOB NOT NULL CHECK(length(expires_at_be) = 8),
                 status_tag      INTEGER NOT NULL CHECK(status_tag IN (0, 1)),
                 signed_bytes    BLOB NOT NULL CHECK(length(signed_bytes) > 0),
                 FOREIGN KEY(policy_digest) REFERENCES route_time_policy(policy_digest)
             ) STRICT;
             CREATE TABLE route_time_evidence_history (
                 evidence_digest BLOB PRIMARY KEY CHECK(length(evidence_digest) = 32),
                 sequence_be     BLOB NOT NULL CHECK(length(sequence_be) = 8),
                 policy_digest   BLOB NOT NULL CHECK(length(policy_digest) = 32),
                 observed_at_be  BLOB NOT NULL CHECK(length(observed_at_be) = 8),
                 expires_at_be   BLOB NOT NULL CHECK(length(expires_at_be) = 8),
                 status_tag      INTEGER NOT NULL CHECK(status_tag IN (0, 1, 2)),
                 signed_bytes    BLOB NOT NULL CHECK(length(signed_bytes) > 0),
                 installed_at_be BLOB NOT NULL CHECK(length(installed_at_be) = 8),
                 FOREIGN KEY(policy_digest) REFERENCES route_time_policy(policy_digest)
             ) STRICT;",
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)
}

fn validate_meta(connection: &Connection, expected: RouteTimeAnchorStoreConfigV2) -> Result<()> {
    let row: EncodedStoreMetaV2 = connection
        .query_row(
            "SELECT network_id, registry_digest, route_scope_digest,
                        policy_authority_set_digest, evidence_authority_set_digest,
                        clock_high_water_be, opening_epoch_be, revision_be
                 FROM route_time_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    if decode_32(&row.0)? != expected.network_id
        || decode_32(&row.1)? != expected.registry_digest
        || decode_32(&row.2)? != expected.route_scope_digest
        || decode_32(&row.3)? != expected.policy_authority_set_digest
        || decode_32(&row.4)? != expected.evidence_authority_set_digest
        || decode_u64(&row.6)? == 0
    {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    decode_u64(&row.5)?;
    decode_u64(&row.7)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResumableCreationStateV2 {
    PristineSqlite,
    PristineInitialized,
}

fn resumable_creation_state(connection: &Connection) -> Result<ResumableCreationStateV2> {
    let quick: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let foreign: String = connection
        .query_row(
            "SELECT CASE WHEN EXISTS(SELECT 1 FROM pragma_foreign_key_check) THEN 'bad' ELSE 'ok' END",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let objects = schema_objects(connection).map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    if quick != "ok" || foreign != "ok" || application_id != 0 {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    if version == 0 && objects.is_empty() {
        return Ok(ResumableCreationStateV2::PristineSqlite);
    }
    if version == SCHEMA_VERSION_V2 {
        validate_backend_and_schema(connection)?;
        return Ok(ResumableCreationStateV2::PristineInitialized);
    }
    Err(RouteTimeAnchorErrorV2::CorruptState)
}

fn validate_pristine_initialized_store(
    connection: &Connection,
    config: RouteTimeAnchorStoreConfigV2,
) -> Result<()> {
    validate_backend_and_schema(connection)?;
    validate_meta(connection, config)?;
    let row: EncodedStoreMetaV2 = connection
        .query_row(
            "SELECT network_id, registry_digest, route_scope_digest,
                    policy_authority_set_digest, evidence_authority_set_digest,
                    clock_high_water_be, opening_epoch_be, revision_be
             FROM route_time_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let meta_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM route_time_meta", [], |row| row.get(0))
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let policy_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM route_time_policy", [], |row| {
            row.get(0)
        })
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let current_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM route_time_evidence_current",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let history_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM route_time_evidence_history",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    if meta_count != 1
        || decode_32(&row.0)? != config.network_id
        || decode_32(&row.1)? != config.registry_digest
        || decode_32(&row.2)? != config.route_scope_digest
        || decode_32(&row.3)? != config.policy_authority_set_digest
        || decode_32(&row.4)? != config.evidence_authority_set_digest
        || decode_u64(&row.5)? != 0
        || decode_u64(&row.6)? != 1
        || decode_u64(&row.7)? != 0
        || policy_count != 0
        || current_count != 0
        || history_count != 0
    {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    validate_retained_bounds(connection)?;
    validate_retained_encoding(connection, config)
}

fn configure_connection(connection: &Connection) -> Result<()> {
    connection
        .busy_timeout(Duration::from_millis(5_000))
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(RouteTimeAnchorErrorV2::StorageUnavailable);
    }
    connection
        .pragma_update(None, "synchronous", "FULL")
        .and_then(|_| connection.pragma_update(None, "foreign_keys", "ON"))
        .and_then(|_| connection.pragma_update(None, "read_uncommitted", "OFF"))
        .and_then(|_| connection.pragma_update(None, "trusted_schema", "OFF"))
        .and_then(|_| connection.pragma_update(None, "secure_delete", "ON"))
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection
        .set_db_config(defensive, true)
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?
        || !connection
            .db_config(defensive)
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?
    {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    Ok(())
}

fn validate_backend_and_schema(connection: &Connection) -> Result<()> {
    let quick: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let foreign: String = connection
        .query_row(
            "SELECT CASE WHEN EXISTS(SELECT 1 FROM pragma_foreign_key_check) THEN 'bad' ELSE 'ok' END",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    if quick != "ok" || foreign != "ok" || version != SCHEMA_VERSION_V2 {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    let actual = schema_objects(connection)?;
    let reference =
        Connection::open_in_memory().map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    create_schema(&reference)?;
    let expected = schema_objects(&reference)?;
    if actual != expected {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    Ok(())
}

type SchemaObjectV2 = (String, String, String, String);

fn schema_objects(connection: &Connection) -> Result<BTreeSet<SchemaObjectV2>> {
    let (count, maximum, total): (i64, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT COUNT(*), MAX(length(sql)), SUM(length(sql))
             FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    if !(0..=16).contains(&count)
        || maximum.map(|value| value > 131_072).unwrap_or(false)
        || total.map(|value| value > 131_072).unwrap_or(false)
    {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'",
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let mut objects = BTreeSet::new();
    for row in rows {
        if !objects.insert(row.map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?) {
            return Err(RouteTimeAnchorErrorV2::CorruptState);
        }
    }
    if i64::try_from(objects.len()).map_err(|_| RouteTimeAnchorErrorV2::CorruptState)? != count {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    Ok(objects)
}

fn validate_retained_bounds(connection: &Connection) -> Result<()> {
    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    validate_retained_bounds_tx(&transaction)?;
    transaction
        .commit()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)
}

fn validate_retained_bounds_tx(transaction: &Transaction<'_>) -> Result<()> {
    let policy_max: Option<i64> = transaction
        .query_row(
            "SELECT MAX(length(signed_bytes)) FROM route_time_policy",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let evidence_max: Option<i64> = transaction
        .query_row(
            "SELECT MAX(length(signed_bytes)) FROM (
                 SELECT signed_bytes FROM route_time_evidence_current
                 UNION ALL SELECT signed_bytes FROM route_time_evidence_history)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    if policy_max
        .map(|value| value < 0 || value as usize > MAX_SIGNED_POLICY_BYTES_V2)
        .unwrap_or(false)
        || evidence_max
            .map(|value| value < 0 || value as usize > MAX_SIGNED_EVIDENCE_BYTES_V2)
            .unwrap_or(false)
    {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    enforce_history_bound(transaction)
}

fn validate_retained_encoding(
    connection: &Connection,
    config: RouteTimeAnchorStoreConfigV2,
) -> Result<()> {
    let policy_row: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT policy_digest, signed_bytes FROM route_time_policy WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let Some((indexed_policy_digest, signed_policy_bytes)) = policy_row else {
        let orphan_count: i64 = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM route_time_evidence_current) +
                    (SELECT COUNT(*) FROM route_time_evidence_history)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        let revision: Vec<u8> = connection
            .query_row(
                "SELECT revision_be FROM route_time_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        return if orphan_count == 0 && decode_u64(&revision)? == 0 {
            Ok(())
        } else {
            Err(RouteTimeAnchorErrorV2::CorruptState)
        };
    };
    let signed_policy = SignedRouteTimePolicyV2::decode(&signed_policy_bytes)
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let policy = RouteTimePolicyV2::decode(signed_policy.policy_bytes())
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let policy_digest = policy
        .policy_digest()
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    if decode_32(&indexed_policy_digest)? != policy_digest
        || policy.network_id() != config.network_id
        || policy.registry_digest() != config.registry_digest
        || policy.route_scope_digest() != config.route_scope_digest
    {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }

    let mut statement = connection
        .prepare(
            "SELECT evidence_digest, sequence_be, policy_digest, observed_at_be,
                    expires_at_be, status_tag, signed_bytes
             FROM route_time_evidence_history
             ORDER BY sequence_be ASC, status_tag ASC, evidence_digest ASC",
        )
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let mut history = statement
        .query_map([], |row| {
            let encoded: EncodedEvidenceHistoryRowV2 = (
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            );
            Ok(encoded)
        })
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    let mut history_count = 0u64;
    let mut conflict_sequence = None;
    let mut previous_active: Option<RouteTimeEvidenceV2> = None;
    for row in &mut history {
        history_count = history_count
            .checked_add(1)
            .ok_or(RouteTimeAnchorErrorV2::CorruptState)?;
        let (digest, sequence, policy_column, observed, expires, status, signed_bytes) =
            row.map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        let signed = SignedRouteTimeEvidenceV2::decode(&signed_bytes)
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        let evidence = RouteTimeEvidenceV2::decode(signed.evidence_bytes())
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        evidence
            .validate_at(&policy, evidence.observed_at_seconds())
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        if decode_32(&digest)?
            != evidence
                .evidence_digest()
                .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?
            || decode_u64(&sequence)? != evidence.sequence()
            || decode_32(&policy_column)? != policy_digest
            || evidence.policy_digest() != policy_digest
            || decode_u64(&observed)? != evidence.observed_at_seconds()
            || decode_u64(&expires)? != evidence.expires_at_seconds()
        {
            return Err(RouteTimeAnchorErrorV2::CorruptState);
        }
        match status {
            EVIDENCE_ACTIVE => {
                if let Some(previous) = previous_active.as_ref() {
                    if evidence.sequence() <= previous.sequence()
                        || evidence.observed_at_seconds() <= previous.observed_at_seconds()
                        || !same_frozen_anchors(previous, &evidence)
                        || !tips_extend(previous, &evidence)
                    {
                        return Err(RouteTimeAnchorErrorV2::CorruptState);
                    }
                }
                previous_active = Some(evidence);
            }
            EVIDENCE_CONFLICT => {
                if conflict_sequence.replace(evidence.sequence()).is_some() {
                    return Err(RouteTimeAnchorErrorV2::CorruptState);
                }
            }
            _ => return Err(RouteTimeAnchorErrorV2::CorruptState),
        }
    }
    drop(history);
    drop(statement);
    let expected_revision = history_count
        .checked_add(1)
        .ok_or(RouteTimeAnchorErrorV2::CorruptState)?;
    let revision: Vec<u8> = connection
        .query_row(
            "SELECT revision_be FROM route_time_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    if decode_u64(&revision)? != expected_revision {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }

    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
    if let Some(current) = load_current_evidence_row(&transaction)? {
        let signed = SignedRouteTimeEvidenceV2::decode(&current.signed_bytes)
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        let evidence = RouteTimeEvidenceV2::decode(signed.evidence_bytes())
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        evidence
            .validate_at(&policy, evidence.observed_at_seconds())
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        reconcile_evidence_row(&current, &evidence)
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        let latest_active = previous_active
            .as_ref()
            .ok_or(RouteTimeAnchorErrorV2::CorruptState)?;
        let status_is_consistent = match (current.status, conflict_sequence) {
            (EVIDENCE_ACTIVE, None) => true,
            (EVIDENCE_INVALIDATED, Some(sequence)) => sequence >= current.sequence,
            _ => false,
        };
        if current.policy_digest != policy_digest
            || current.sequence != latest_active.sequence()
            || current.digest
                != latest_active
                    .evidence_digest()
                    .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?
            || !status_is_consistent
        {
            return Err(RouteTimeAnchorErrorV2::CorruptState);
        }
        let retained: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM route_time_evidence_history
                 WHERE evidence_digest = ?1 AND status_tag = ?2 AND signed_bytes = ?3",
                params![
                    current.digest.as_slice(),
                    EVIDENCE_ACTIVE,
                    current.signed_bytes.as_slice()
                ],
                |row| row.get(0),
            )
            .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
        if retained != 1 {
            return Err(RouteTimeAnchorErrorV2::CorruptState);
        }
    } else if history_count != 0 || previous_active.is_some() || conflict_sequence.is_some() {
        return Err(RouteTimeAnchorErrorV2::CorruptState);
    }
    transaction
        .commit()
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)
}

fn validate_database_path(connection: &Connection, expected_path: &Path) -> Result<()> {
    let expected = fs::canonicalize(expected_path)
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidStorageAuthority)?;
    if expected != expected_path {
        return Err(RouteTimeAnchorErrorV2::InvalidStorageAuthority);
    }
    let mut statement = connection
        .prepare("PRAGMA database_list")
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let mut saw_main = false;
    for row in rows {
        let (name, path) = row.map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        match name.as_str() {
            "main" if Path::new(&path) == expected => saw_main = true,
            "temp" if path.is_empty() => {}
            _ => return Err(RouteTimeAnchorErrorV2::InvalidStorageAuthority),
        }
    }
    if !saw_main {
        return Err(RouteTimeAnchorErrorV2::InvalidStorageAuthority);
    }
    Ok(())
}

fn decode_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)
}

fn decode_u64(bytes: &[u8]) -> Result<u64> {
    bytes
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)
}

fn create_owner_database_file(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(target_os = "linux")]
    options.mode(FILE_MODE);
    let file = options
        .open(path)
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    file.sync_all()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    drop(file);
    #[cfg(target_os = "linux")]
    {
        validate_owner_file(path)?;
        sync_owner_directory(
            path.parent()
                .ok_or(RouteTimeAnchorErrorV2::InvalidStorageAuthority)?,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owner_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RouteTimeAnchorErrorV2::InvalidStorageAuthority)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != DIRECTORY_MODE
        || metadata.nlink() == 0
    {
        return Err(RouteTimeAnchorErrorV2::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owner_file(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RouteTimeAnchorErrorV2::InvalidStorageAuthority)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(RouteTimeAnchorErrorV2::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_sqlite_sidecars(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = std::path::PathBuf::from(sidecar);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => validate_owner_file(&sidecar)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RouteTimeAnchorErrorV2::StorageUnavailable),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_resumable_sqlite_sidecars(path: &Path) -> Result<()> {
    for (suffix, kind) in [
        ("-wal", SqliteSidecarKindV2::Wal),
        ("-shm", SqliteSidecarKindV2::SharedMemory),
        ("-journal", SqliteSidecarKindV2::RollbackJournal),
    ] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = std::path::PathBuf::from(sidecar);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => validate_sqlite_sidecar_shape(&sidecar, kind)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RouteTimeAnchorErrorV2::StorageUnavailable),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SqliteSidecarKindV2 {
    Wal,
    SharedMemory,
    RollbackJournal,
}

#[cfg(target_os = "linux")]
fn validate_sqlite_sidecar_shape(path: &Path, kind: SqliteSidecarKindV2) -> Result<()> {
    validate_owner_file(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let retained = file
        .metadata()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let named =
        fs::symlink_metadata(path).map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(RouteTimeAnchorErrorV2::InvalidStorageAuthority);
    }
    if retained.len() == 0 {
        return Ok(());
    }
    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidStorageAuthority)?;
    let valid = match kind {
        SqliteSidecarKindV2::Wal => {
            retained.len() >= 32
                && matches!(
                    u32::from_be_bytes(
                        header[..4]
                            .try_into()
                            .map_err(|_| { RouteTimeAnchorErrorV2::InvalidStorageAuthority })?
                    ),
                    0x377f_0682 | 0x377f_0683
                )
        }
        SqliteSidecarKindV2::SharedMemory => {
            retained.len() >= 32_768
                && retained.len() % 32_768 == 0
                && u32::from_ne_bytes(
                    header[..4]
                        .try_into()
                        .map_err(|_| RouteTimeAnchorErrorV2::InvalidStorageAuthority)?,
                ) == 3_007_000
        }
        SqliteSidecarKindV2::RollbackJournal => {
            retained.len() >= 28 && header == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
        }
    };
    if !valid {
        return Err(RouteTimeAnchorErrorV2::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_sidecars_absent(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(std::path::PathBuf::from(sidecar)) {
            Ok(_) => return Err(RouteTimeAnchorErrorV2::InvalidStorageAuthority),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RouteTimeAnchorErrorV2::StorageUnavailable),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_lock_path(path: &Path) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    std::path::PathBuf::from(value)
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
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    validate_owner_file(&lock_path)?;
    let retained = file
        .metadata()
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    let named =
        fs::symlink_metadata(&lock_path).map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(RouteTimeAnchorErrorV2::InvalidStorageAuthority);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
    if create {
        file.sync_all()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        sync_owner_directory(
            path.parent()
                .ok_or(RouteTimeAnchorErrorV2::InvalidStorageAuthority)?,
        )?;
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn sync_owner_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::error::Error;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    type TestResult = core::result::Result<(), Box<dyn Error>>;

    fn test_config() -> RouteTimeAnchorStoreConfigV2 {
        RouteTimeAnchorStoreConfigV2 {
            network_id: [1; 32],
            registry_digest: [2; 32],
            route_scope_digest: [3; 32],
            policy_authority_set_digest: [4; 32],
            evidence_authority_set_digest: [5; 32],
        }
    }

    fn test_path() -> TestResultWithPath {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))?;
        let path = directory.path().join("route-time-v2.sqlite");
        Ok((directory, path))
    }

    type TestResultWithPath =
        core::result::Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn Error>>;

    fn require_error<T>(
        result: Result<T>,
    ) -> core::result::Result<RouteTimeAnchorErrorV2, std::io::Error> {
        result
            .err()
            .ok_or_else(|| std::io::Error::other("expected strict creation refusal"))
    }

    fn stage_creation_fault(
        path: &Path,
        config: RouteTimeAnchorStoreConfigV2,
        fault: CreationBoundaryV2,
    ) -> TestResult {
        let error = require_error(DurableRouteTimeAnchorStoreV2::create_with_boundary_hook(
            path,
            config,
            |boundary| {
                if boundary == fault {
                    Err(RouteTimeAnchorErrorV2::StorageUnavailable)
                } else {
                    Ok(())
                }
            },
        ))?;
        assert_eq!(error, RouteTimeAnchorErrorV2::StorageUnavailable);
        Ok(())
    }

    fn boundary_name(boundary: CreationBoundaryV2) -> &'static str {
        match boundary {
            CreationBoundaryV2::ProcessLockPublished => "process-lock-published",
            CreationBoundaryV2::DatabaseFileSynced => "database-file-synced",
            CreationBoundaryV2::BeforeSchemaTransaction => "before-schema-transaction",
            CreationBoundaryV2::BeforeSchemaCommit => "before-schema-commit",
            CreationBoundaryV2::SchemaCommitted => "schema-committed",
        }
    }

    fn parse_boundary(name: &str) -> core::result::Result<CreationBoundaryV2, std::io::Error> {
        match name {
            "process-lock-published" => Ok(CreationBoundaryV2::ProcessLockPublished),
            "database-file-synced" => Ok(CreationBoundaryV2::DatabaseFileSynced),
            "before-schema-transaction" => Ok(CreationBoundaryV2::BeforeSchemaTransaction),
            "before-schema-commit" => Ok(CreationBoundaryV2::BeforeSchemaCommit),
            "schema-committed" => Ok(CreationBoundaryV2::SchemaCommitted),
            _ => Err(std::io::Error::other("unknown creation fault boundary")),
        }
    }

    fn stage_process_crash(path: &Path, boundary: CreationBoundaryV2) -> TestResult {
        let executable = std::env::current_exe()?;
        let status = Command::new(executable)
            .arg("--exact")
            .arg("store::tests::creation_fault_process_child")
            .arg("--nocapture")
            .env("ROUTE_TIME_ANCHOR_TEST_FAULT_PATH", path)
            .env(
                "ROUTE_TIME_ANCHOR_TEST_FAULT_BOUNDARY",
                boundary_name(boundary),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.code() != Some(91) {
            return Err(
                std::io::Error::other("creation fault child did not crash at boundary").into(),
            );
        }
        Ok(())
    }

    #[test]
    fn creation_fault_process_child() -> TestResult {
        let Some(path) = std::env::var_os("ROUTE_TIME_ANCHOR_TEST_FAULT_PATH") else {
            return Ok(());
        };
        let boundary = std::env::var("ROUTE_TIME_ANCHOR_TEST_FAULT_BOUNDARY")?;
        let fault = parse_boundary(&boundary)?;
        let store = DurableRouteTimeAnchorStoreV2::create_with_boundary_hook(
            Path::new(&path),
            test_config(),
            |boundary| {
                if boundary == fault {
                    std::process::exit(91);
                }
                Ok(())
            },
        )?;
        drop(store);
        Err(std::io::Error::other("creation fault boundary was not reached").into())
    }

    #[test]
    fn resume_create_recovers_every_durable_creation_prefix_and_reopens() -> TestResult {
        for boundary in [
            CreationBoundaryV2::ProcessLockPublished,
            CreationBoundaryV2::DatabaseFileSynced,
            CreationBoundaryV2::BeforeSchemaTransaction,
            CreationBoundaryV2::BeforeSchemaCommit,
            CreationBoundaryV2::SchemaCommitted,
        ] {
            let (_directory, path) = test_path()?;
            let config = test_config();
            stage_process_crash(&path, boundary)?;

            match boundary {
                CreationBoundaryV2::ProcessLockPublished => assert_eq!(
                    require_error(DurableRouteTimeAnchorStoreV2::open_existing(&path, config,))?,
                    RouteTimeAnchorErrorV2::DatabaseMissing
                ),
                CreationBoundaryV2::DatabaseFileSynced
                | CreationBoundaryV2::BeforeSchemaTransaction
                | CreationBoundaryV2::BeforeSchemaCommit => assert_eq!(
                    require_error(DurableRouteTimeAnchorStoreV2::open_existing(&path, config,))?,
                    RouteTimeAnchorErrorV2::CreationIncomplete
                ),
                CreationBoundaryV2::SchemaCommitted => {
                    let (_open_directory, open_path) = test_path()?;
                    stage_process_crash(&open_path, boundary)?;
                    let opened = DurableRouteTimeAnchorStoreV2::open_existing(&open_path, config)?;
                    drop(opened);
                }
            }

            let resumed = DurableRouteTimeAnchorStoreV2::resume_create_production(&path, config)?;
            drop(resumed);
            let resumed_again =
                DurableRouteTimeAnchorStoreV2::resume_create_production(&path, config)?;
            drop(resumed_again);
            let reopened = DurableRouteTimeAnchorStoreV2::open_existing(&path, config)?;
            drop(reopened);
        }
        Ok(())
    }

    #[test]
    fn resume_create_requires_lock_and_refuses_alternate_durable_state() -> TestResult {
        let (_directory, path) = test_path()?;
        create_owner_database_file(&path)?;
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::resume_create_production(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::StorageUnavailable
        );

        let (_directory, path) = test_path()?;
        stage_creation_fault(&path, test_config(), CreationBoundaryV2::DatabaseFileSynced)?;
        let alternate = Connection::open(&path)?;
        alternate.execute_batch("CREATE TABLE caller_shaped(value BLOB) STRICT;")?;
        drop(alternate);
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::open_existing(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::CorruptState
        );
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::resume_create_production(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::CorruptState
        );

        let (_directory, path) = test_path()?;
        stage_creation_fault(&path, test_config(), CreationBoundaryV2::DatabaseFileSynced)?;
        let alternate = Connection::open(&path)?;
        alternate.pragma_update(None, "application_id", 41)?;
        drop(alternate);
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::open_existing(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::CorruptState
        );
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::resume_create_production(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::CorruptState
        );

        let (_directory, path) = test_path()?;
        stage_creation_fault(&path, test_config(), CreationBoundaryV2::DatabaseFileSynced)?;
        let alternate = Connection::open(&path)?;
        alternate.pragma_update(None, "user_version", 1)?;
        drop(alternate);
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::open_existing(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::CorruptState
        );
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::resume_create_production(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::CorruptState
        );

        let (_directory, path) = test_path()?;
        stage_creation_fault(&path, test_config(), CreationBoundaryV2::SchemaCommitted)?;
        let alternate = Connection::open(&path)?;
        alternate.execute(
            "UPDATE route_time_meta SET registry_digest = ?1 WHERE singleton = 1",
            params![[9u8; 32].as_slice()],
        )?;
        drop(alternate);
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::resume_create_production(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::CorruptState
        );

        let (_directory, path) = test_path()?;
        stage_creation_fault(&path, test_config(), CreationBoundaryV2::SchemaCommitted)?;
        let alternate = Connection::open(&path)?;
        alternate.execute(
            "INSERT INTO route_time_policy(
                 singleton, policy_digest, signed_bytes, installed_at_be
             ) VALUES(1, ?1, ?2, ?3)",
            params![
                [7u8; 32].as_slice(),
                [8u8; 1].as_slice(),
                0u64.to_be_bytes().as_slice()
            ],
        )?;
        drop(alternate);
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::resume_create_production(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::CorruptState
        );

        let (_directory, path) = test_path()?;
        stage_creation_fault(&path, test_config(), CreationBoundaryV2::DatabaseFileSynced)?;
        let mut wal_path = path.as_os_str().to_os_string();
        wal_path.push("-wal");
        let wal_path = std::path::PathBuf::from(wal_path);
        fs::write(&wal_path, b"caller-shaped")?;
        fs::set_permissions(&wal_path, fs::Permissions::from_mode(FILE_MODE))?;
        assert_eq!(
            require_error(DurableRouteTimeAnchorStoreV2::resume_create_production(
                &path,
                test_config(),
            ))?,
            RouteTimeAnchorErrorV2::InvalidStorageAuthority
        );
        Ok(())
    }
}

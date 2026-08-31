//! Crash-safe production authority provisioning journal.
//!
//! Production creation spans independent durable stores, so no filesystem
//! transaction can publish all of them atomically.  This journal makes the
//! ordering explicit: a stage is durably marked `started` before its authority
//! may be created and durably marked `complete` only after that authority has
//! been reopened and authenticated.  Recovery may resume only the single
//! started prefix stage; unrelated pre-existing state remains a refusal.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use blake2::digest::{Update as _, VariableOutput as _};
use blake2::Blake2bVar;
use cap_std::fs::{
    Dir, DirBuilder as CapDirBuilder, DirBuilderExt as _, MetadataExt as _,
    OpenOptions as CapOpenOptions, OpenOptionsExt as _,
};
use fs2::FileExt as _;

const JOURNAL_ROOT_NAME_V1: &str = "production-provisioning-v1";
const JOURNAL_STAGING_NAME_V1: &str = "production-provisioning-v1.new";
const BINDING_FILE_V1: &str = "binding.v1";
const LOCK_FILE_V1: &str = "provisioning.lock";
const MAGIC_V1: &[u8; 8] = b"DOMPRV1\0";
const VERSION_V1: u16 = 1;
const RECORD_BYTES_V1: usize = 80;
const DIRECTORY_MODE_V1: u32 = 0o700;
const FILE_MODE_V1: u32 = 0o600;
const BINDING_DOMAIN_V1: &[u8] = b"DOM-INTEROP/PROVISIONING/BINDING/V1\0";
const RECORD_DOMAIN_V1: &[u8] = b"DOM-INTEROP/PROVISIONING/RECORD/V1\0";

pub(crate) const ROUTE_SECRET_VAULT_ROOT_NAME_V1: &str = "route-secret-vault-v1";

/// Ordered authority creation stages.  Adding an authority requires adding it
/// to this exhaustive sequence before production composition may create it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub(crate) enum ProductionProvisioningStageV1 {
    TimeAnchorStore = 1,
    RouteStore = 2,
    RouteSecretVault = 3,
    CoordinatorStore = 4,
    DomActuatorStore = 5,
    EvmActuatorStore = 6,
    BitcoinActuatorStore = 7,
    ChainSignerAuthorities = 8,
    SolverInventoryStore = 9,
    // The F6 and Relay workers borrow the already-open Contracts Stores. F6
    // must itself exist before a Relay worker can be constructed with a real
    // `F6TransportPortV1`. This order is therefore a construction invariant,
    // not an arbitrary label order.
    ContractsStores = 10,
    F6Authorities = 11,
    RelayAuthorities = 12,
}

impl ProductionProvisioningStageV1 {
    const ALL: [Self; 12] = [
        Self::TimeAnchorStore,
        Self::RouteStore,
        Self::RouteSecretVault,
        Self::CoordinatorStore,
        Self::DomActuatorStore,
        Self::EvmActuatorStore,
        Self::BitcoinActuatorStore,
        Self::ChainSignerAuthorities,
        Self::SolverInventoryStore,
        Self::ContractsStores,
        Self::F6Authorities,
        Self::RelayAuthorities,
    ];

    const fn tag(self) -> u8 {
        self as u8
    }

    const fn label(self) -> &'static str {
        match self {
            Self::TimeAnchorStore => "01-time-anchor-store",
            Self::RouteStore => "02-route-store",
            Self::RouteSecretVault => "03-route-secret-vault",
            Self::CoordinatorStore => "04-coordinator-store",
            Self::DomActuatorStore => "05-dom-actuator-store",
            Self::EvmActuatorStore => "06-evm-actuator-store",
            Self::BitcoinActuatorStore => "07-bitcoin-actuator-store",
            Self::ChainSignerAuthorities => "08-chain-signer-authorities",
            Self::SolverInventoryStore => "09-solver-inventory-store",
            Self::ContractsStores => "10-contracts-stores",
            Self::F6Authorities => "11-f6-authorities",
            Self::RelayAuthorities => "12-relay-authorities",
        }
    }
}

/// Redacted journal refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionProvisioningErrorV1 {
    #[error("invalid provisioning binding")]
    InvalidBinding,
    #[error("provisioning journal is absent")]
    NotFound,
    #[error("provisioning journal already exists")]
    AlreadyPresent,
    #[error("provisioning journal storage unavailable")]
    StorageUnavailable,
    #[error("provisioning journal authority is invalid")]
    InvalidAuthority,
    #[error("provisioning journal is owned by another live process")]
    InUse,
    #[error("provisioning journal is corrupt or out of order")]
    Inconsistent,
}

/// State of one exact stage after a full journal audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionProvisioningStageStateV1 {
    Absent,
    Started,
    Complete,
}

/// Retained owner of one provisioning journal.
pub(crate) struct DurableProductionProvisioningJournalV1 {
    state_dir: Dir,
    root: Dir,
    binding: [u8; 32],
    root_identity: RetainedNodeIdentityV1,
    lock_identity: RetainedNodeIdentityV1,
    _lock: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedNodeIdentityV1 {
    device: u64,
    inode: u64,
}

impl core::fmt::Debug for DurableProductionProvisioningJournalV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableProductionProvisioningJournalV1([authority redacted])")
    }
}

impl DurableProductionProvisioningJournalV1 {
    /// Creates and durably publishes the empty journal.  A valid staging root
    /// left by a crash is promoted; any other pre-existing object is refused.
    pub(crate) fn create(
        state_dir: &Path,
        binding: [u8; 32],
    ) -> Result<Self, ProductionProvisioningErrorV1> {
        validate_binding(binding)?;
        validate_state_directory(state_dir)?;
        let state_dir = Dir::from_std_file(
            File::open(state_dir).map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?,
        );
        if cap_path_present(&state_dir, JOURNAL_ROOT_NAME_V1)? {
            return Err(ProductionProvisioningErrorV1::AlreadyPresent);
        }
        if !cap_path_present(&state_dir, JOURNAL_STAGING_NAME_V1)? {
            let mut builder = CapDirBuilder::new();
            builder.mode(DIRECTORY_MODE_V1);
            state_dir
                .create_dir_with(JOURNAL_STAGING_NAME_V1, &builder)
                .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
            sync_cap_directory(&state_dir)?;
        }
        let staging = state_dir
            .open_dir(JOURNAL_STAGING_NAME_V1)
            .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
        let root_identity = validate_cap_directory(&staging)?;
        let (lock, lock_identity) = acquire_process_lock(&staging, true)?;
        if cap_path_present(&staging, BINDING_FILE_V1)? {
            if let Err(error) =
                validate_record_file(&staging, BINDING_FILE_V1, &binding_record(binding)?)
            {
                if !remove_torn_staging_record(&staging, BINDING_FILE_V1)? {
                    return Err(error);
                }
            }
        }
        if !cap_path_present(&staging, BINDING_FILE_V1)? {
            validate_uninitialized_staging_root(&staging)?;
            write_new_file_durable(&staging, BINDING_FILE_V1, &binding_record(binding)?)?;
            sync_cap_directory(&staging)?;
        }
        validate_journal_root(&staging, binding)?;
        state_dir
            .rename(JOURNAL_STAGING_NAME_V1, &state_dir, JOURNAL_ROOT_NAME_V1)
            .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
        sync_cap_directory(&state_dir)?;
        let root = staging;
        let journal = Self {
            state_dir,
            root,
            binding,
            root_identity,
            lock_identity,
            _lock: lock,
        };
        journal.audit()?;
        Ok(journal)
    }

    /// Reopens only an exact, already-published journal.
    pub(crate) fn open(
        state_dir: &Path,
        binding: [u8; 32],
    ) -> Result<Self, ProductionProvisioningErrorV1> {
        validate_binding(binding)?;
        validate_state_directory(state_dir)?;
        let state_dir = Dir::from_std_file(
            File::open(state_dir).map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?,
        );
        if !cap_path_present(&state_dir, JOURNAL_ROOT_NAME_V1)? {
            return Err(ProductionProvisioningErrorV1::NotFound);
        }
        let root = state_dir
            .open_dir(JOURNAL_ROOT_NAME_V1)
            .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
        let root_identity = validate_cap_directory(&root)?;
        let (lock, lock_identity) = acquire_process_lock(&root, false)?;
        let journal = Self {
            state_dir,
            root,
            binding,
            root_identity,
            lock_identity,
            _lock: lock,
        };
        journal.audit()?;
        Ok(journal)
    }

    /// Opens the journal when present, otherwise publishes a new one.  The
    /// caller must have already proved that no managed authority exists before
    /// taking the create branch.
    pub(crate) fn open_or_create_after_absence_check(
        state_dir: &Path,
        binding: [u8; 32],
    ) -> Result<Self, ProductionProvisioningErrorV1> {
        match Self::open(state_dir, binding) {
            Ok(journal) => Ok(journal),
            Err(ProductionProvisioningErrorV1::NotFound) => Self::create(state_dir, binding),
            Err(error) => Err(error),
        }
    }

    /// Returns the exact audited state of a stage.
    pub(crate) fn stage_state(
        &self,
        stage: ProductionProvisioningStageV1,
    ) -> Result<ProductionProvisioningStageStateV1, ProductionProvisioningErrorV1> {
        self.audit()?;
        stage_state_unchecked(&self.root, self.binding, stage)
    }

    /// Durably marks one stage started before any authority creation.
    pub(crate) fn begin(
        &mut self,
        stage: ProductionProvisioningStageV1,
    ) -> Result<ProductionProvisioningStageStateV1, ProductionProvisioningErrorV1> {
        self.audit()?;
        match stage_state_unchecked(&self.root, self.binding, stage)? {
            ProductionProvisioningStageStateV1::Complete => {
                return Ok(ProductionProvisioningStageStateV1::Complete);
            }
            ProductionProvisioningStageStateV1::Started => {
                return Ok(ProductionProvisioningStageStateV1::Started);
            }
            ProductionProvisioningStageStateV1::Absent => {}
        }
        for prior in ProductionProvisioningStageV1::ALL {
            if prior >= stage {
                break;
            }
            if stage_state_unchecked(&self.root, self.binding, prior)?
                != ProductionProvisioningStageStateV1::Complete
            {
                return Err(ProductionProvisioningErrorV1::Inconsistent);
            }
        }
        publish_marker(&self.root, self.binding, stage, false)?;
        self.audit()?;
        Ok(ProductionProvisioningStageStateV1::Started)
    }

    /// Durably marks one authenticated authority complete.
    pub(crate) fn complete(
        &mut self,
        stage: ProductionProvisioningStageV1,
    ) -> Result<(), ProductionProvisioningErrorV1> {
        self.audit()?;
        match stage_state_unchecked(&self.root, self.binding, stage)? {
            ProductionProvisioningStageStateV1::Complete => return Ok(()),
            ProductionProvisioningStageStateV1::Started => {}
            ProductionProvisioningStageStateV1::Absent => {
                return Err(ProductionProvisioningErrorV1::Inconsistent);
            }
        }
        publish_marker(&self.root, self.binding, stage, true)?;
        self.audit()
    }

    fn audit(&self) -> Result<(), ProductionProvisioningErrorV1> {
        let named_root = self
            .state_dir
            .open_dir(JOURNAL_ROOT_NAME_V1)
            .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
        if validate_cap_directory(&named_root)? != self.root_identity
            || validate_cap_directory(&self.root)? != self.root_identity
            || validate_named_lock(&self.root)? != self.lock_identity
            || retained_file_identity(&self._lock)? != self.lock_identity
        {
            return Err(ProductionProvisioningErrorV1::InvalidAuthority);
        }
        validate_journal_root(&self.root, self.binding)?;
        let mut incomplete_seen = false;
        for stage in ProductionProvisioningStageV1::ALL {
            let state = stage_state_unchecked(&self.root, self.binding, stage)?;
            match state {
                ProductionProvisioningStageStateV1::Complete if incomplete_seen => {
                    return Err(ProductionProvisioningErrorV1::Inconsistent);
                }
                ProductionProvisioningStageStateV1::Started => {
                    if incomplete_seen {
                        return Err(ProductionProvisioningErrorV1::Inconsistent);
                    }
                    incomplete_seen = true;
                }
                ProductionProvisioningStageStateV1::Absent => incomplete_seen = true,
                ProductionProvisioningStageStateV1::Complete => {}
            }
        }
        Ok(())
    }
}

pub(crate) fn provisioning_binding_v1(
    create_manifest: &[u8],
    reopen_manifest: &[u8],
    route_id: [u8; 32],
) -> Result<[u8; 32], ProductionProvisioningErrorV1> {
    if create_manifest.is_empty()
        || reopen_manifest.is_empty()
        || route_id == [0; 32]
        || create_manifest == reopen_manifest
    {
        return Err(ProductionProvisioningErrorV1::InvalidBinding);
    }
    digest(
        BINDING_DOMAIN_V1,
        &[create_manifest, reopen_manifest, &route_id],
    )
}

fn stage_state_unchecked(
    root: &Dir,
    binding: [u8; 32],
    stage: ProductionProvisioningStageV1,
) -> Result<ProductionProvisioningStageStateV1, ProductionProvisioningErrorV1> {
    recover_marker(root, binding, stage, false)?;
    recover_marker(root, binding, stage, true)?;
    let started = cap_path_present(root, &marker_name(stage, false))?;
    let complete = cap_path_present(root, &marker_name(stage, true))?;
    match (started, complete) {
        (false, false) => Ok(ProductionProvisioningStageStateV1::Absent),
        (true, false) => Ok(ProductionProvisioningStageStateV1::Started),
        (true, true) => Ok(ProductionProvisioningStageStateV1::Complete),
        (false, true) => Err(ProductionProvisioningErrorV1::Inconsistent),
    }
}

fn publish_marker(
    root: &Dir,
    binding: [u8; 32],
    stage: ProductionProvisioningStageV1,
    complete: bool,
) -> Result<(), ProductionProvisioningErrorV1> {
    recover_marker(root, binding, stage, complete)?;
    let final_name = marker_name(stage, complete);
    if cap_path_present(root, &final_name)? {
        validate_record_file(root, &final_name, &stage_record(binding, stage, complete)?)?;
        return Ok(());
    }
    let staging_name = marker_staging_name(stage, complete);
    write_new_file_durable(
        root,
        &staging_name,
        &stage_record(binding, stage, complete)?,
    )?;
    root.rename(&staging_name, root, &final_name)
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
    sync_cap_directory(root)?;
    validate_record_file(root, &final_name, &stage_record(binding, stage, complete)?)
}

fn recover_marker(
    root: &Dir,
    binding: [u8; 32],
    stage: ProductionProvisioningStageV1,
    complete: bool,
) -> Result<(), ProductionProvisioningErrorV1> {
    let final_name = marker_name(stage, complete);
    let staging_name = marker_staging_name(stage, complete);
    if cap_path_present(root, &final_name)? {
        validate_record_file(root, &final_name, &stage_record(binding, stage, complete)?)?;
        if cap_path_present(root, &staging_name)? {
            if let Err(error) = validate_record_file(
                root,
                &staging_name,
                &stage_record(binding, stage, complete)?,
            ) {
                if !remove_torn_staging_record(root, &staging_name)? {
                    return Err(error);
                }
                return Ok(());
            }
            root.remove_file(&staging_name)
                .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
            sync_cap_directory(root)?;
        }
        return Ok(());
    }
    if cap_path_present(root, &staging_name)? {
        if let Err(error) = validate_record_file(
            root,
            &staging_name,
            &stage_record(binding, stage, complete)?,
        ) {
            if !remove_torn_staging_record(root, &staging_name)? {
                return Err(error);
            }
            return Ok(());
        }
        root.rename(&staging_name, root, &final_name)
            .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
        sync_cap_directory(root)?;
        validate_record_file(root, &final_name, &stage_record(binding, stage, complete)?)?;
    }
    Ok(())
}

fn remove_torn_staging_record(
    root: &Dir,
    name: &str,
) -> Result<bool, ProductionProvisioningErrorV1> {
    let metadata = root
        .symlink_metadata(name)
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
    validate_cap_file(root, name)?;
    if metadata.len() >= RECORD_BYTES_V1 as u64 {
        return Ok(false);
    }
    root.remove_file(name)
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
    sync_cap_directory(root)?;
    Ok(true)
}

fn marker_name(stage: ProductionProvisioningStageV1, complete: bool) -> String {
    format!(
        "{}.{}",
        stage.label(),
        if complete { "complete" } else { "started" }
    )
}

fn marker_staging_name(stage: ProductionProvisioningStageV1, complete: bool) -> String {
    format!("{}.new", marker_name(stage, complete))
}

fn binding_record(
    binding: [u8; 32],
) -> Result<[u8; RECORD_BYTES_V1], ProductionProvisioningErrorV1> {
    record(binding, 0, 0)
}

fn stage_record(
    binding: [u8; 32],
    stage: ProductionProvisioningStageV1,
    complete: bool,
) -> Result<[u8; RECORD_BYTES_V1], ProductionProvisioningErrorV1> {
    record(binding, stage.tag(), u8::from(complete))
}

fn record(
    binding: [u8; 32],
    stage: u8,
    state: u8,
) -> Result<[u8; RECORD_BYTES_V1], ProductionProvisioningErrorV1> {
    let mut bytes = [0_u8; RECORD_BYTES_V1];
    bytes[..8].copy_from_slice(MAGIC_V1);
    bytes[8..10].copy_from_slice(&VERSION_V1.to_be_bytes());
    bytes[10] = stage;
    bytes[11] = state;
    bytes[12..44].copy_from_slice(&binding);
    let checksum = digest(RECORD_DOMAIN_V1, &[&bytes[..48]])?;
    bytes[48..80].copy_from_slice(&checksum);
    Ok(bytes)
}

fn validate_journal_root(
    root: &Dir,
    binding: [u8; 32],
) -> Result<(), ProductionProvisioningErrorV1> {
    validate_cap_directory(root)?;
    validate_record_file(root, BINDING_FILE_V1, &binding_record(binding)?)?;
    for entry in root
        .entries()
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?
    {
        let entry = entry.map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
        let known = name == BINDING_FILE_V1
            || name == LOCK_FILE_V1
            || ProductionProvisioningStageV1::ALL.iter().any(|stage| {
                [false, true].into_iter().any(|complete| {
                    let marker = marker_name(*stage, complete);
                    name == marker || name == format!("{marker}.new")
                })
            });
        if !known {
            return Err(ProductionProvisioningErrorV1::InvalidAuthority);
        }
    }
    Ok(())
}

fn validate_uninitialized_staging_root(root: &Dir) -> Result<(), ProductionProvisioningErrorV1> {
    validate_cap_directory(root)?;
    for entry in root
        .entries()
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?
    {
        let name = entry
            .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?
            .file_name()
            .into_string()
            .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
        if name != LOCK_FILE_V1 {
            return Err(ProductionProvisioningErrorV1::InvalidAuthority);
        }
    }
    validate_named_lock(root)?;
    Ok(())
}

fn validate_record_file(
    root: &Dir,
    name: &str,
    expected: &[u8; RECORD_BYTES_V1],
) -> Result<(), ProductionProvisioningErrorV1> {
    let named_identity = validate_cap_file(root, name)?;
    let mut file = root
        .open(name)
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
    let before = file
        .metadata()
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
    let mut bytes = Vec::with_capacity(RECORD_BYTES_V1 + 1);
    Read::by_ref(&mut file)
        .take((RECORD_BYTES_V1 + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
    let after = file
        .metadata()
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
    if metadata_identity(&before) != named_identity
        || metadata_identity(&after) != named_identity
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || bytes.as_slice() != expected
    {
        return Err(ProductionProvisioningErrorV1::Inconsistent);
    }
    Ok(())
}

fn write_new_file_durable(
    root: &Dir,
    name: &str,
    bytes: &[u8],
) -> Result<(), ProductionProvisioningErrorV1> {
    let mut options = CapOpenOptions::new();
    options.write(true).create_new(true).mode(FILE_MODE_V1);
    let mut file = root
        .open_with(name, &options)
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
    file.write_all(bytes)
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
    file.sync_all()
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
    let named_identity = validate_cap_file(root, name)?;
    if metadata_identity(
        &file
            .metadata()
            .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?,
    ) != named_identity
    {
        return Err(ProductionProvisioningErrorV1::InvalidAuthority);
    }
    Ok(())
}

fn acquire_process_lock(
    root: &Dir,
    create: bool,
) -> Result<(File, RetainedNodeIdentityV1), ProductionProvisioningErrorV1> {
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .mode(FILE_MODE_V1);
    let file = root
        .open_with(LOCK_FILE_V1, &options)
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?
        .into_std();
    let named_identity = validate_named_lock(root)?;
    if retained_file_identity(&file)? != named_identity {
        return Err(ProductionProvisioningErrorV1::InvalidAuthority);
    }
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            ProductionProvisioningErrorV1::InUse
        } else {
            ProductionProvisioningErrorV1::StorageUnavailable
        }
    })?;
    if validate_named_lock(root)? != named_identity
        || retained_file_identity(&file)? != named_identity
    {
        return Err(ProductionProvisioningErrorV1::InvalidAuthority);
    }
    if create {
        file.sync_all()
            .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
        sync_cap_directory(root)?;
    }
    Ok((file, named_identity))
}

fn validate_named_lock(
    root: &Dir,
) -> Result<RetainedNodeIdentityV1, ProductionProvisioningErrorV1> {
    validate_cap_file(root, LOCK_FILE_V1)
}

fn retained_file_identity(
    file: &File,
) -> Result<RetainedNodeIdentityV1, ProductionProvisioningErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
    validate_file_metadata(&metadata)
}

fn metadata_identity(metadata: &cap_std::fs::Metadata) -> RetainedNodeIdentityV1 {
    RetainedNodeIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn validate_cap_directory(
    directory: &Dir,
) -> Result<RetainedNodeIdentityV1, ProductionProvisioningErrorV1> {
    let metadata = directory
        .dir_metadata()
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o7777 != DIRECTORY_MODE_V1
        || metadata.uid() != effective_uid()?
    {
        return Err(ProductionProvisioningErrorV1::InvalidAuthority);
    }
    Ok(metadata_identity(&metadata))
}

fn validate_cap_file(
    root: &Dir,
    name: &str,
) -> Result<RetainedNodeIdentityV1, ProductionProvisioningErrorV1> {
    let metadata = root
        .symlink_metadata(name)
        .map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
    if !metadata.is_file()
        || metadata.is_symlink()
        || metadata.mode() & 0o7777 != FILE_MODE_V1
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid()?
    {
        return Err(ProductionProvisioningErrorV1::InvalidAuthority);
    }
    Ok(metadata_identity(&metadata))
}

fn validate_file_metadata(
    metadata: &std::fs::Metadata,
) -> Result<RetainedNodeIdentityV1, ProductionProvisioningErrorV1> {
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != FILE_MODE_V1
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid()?
    {
        return Err(ProductionProvisioningErrorV1::InvalidAuthority);
    }
    Ok(RetainedNodeIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn cap_path_present(root: &Dir, name: &str) -> Result<bool, ProductionProvisioningErrorV1> {
    match root.symlink_metadata(name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ProductionProvisioningErrorV1::StorageUnavailable),
    }
}

fn sync_cap_directory(root: &Dir) -> Result<(), ProductionProvisioningErrorV1> {
    let mut options = CapOpenOptions::new();
    options.read(true);
    root.open_with(".", &options)
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?
        .into_std()
        .sync_all()
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)
}

fn validate_state_directory(path: &Path) -> Result<(), ProductionProvisioningErrorV1> {
    if !path.is_absolute()
        || fs::canonicalize(path).map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?
            != path
    {
        return Err(ProductionProvisioningErrorV1::InvalidAuthority);
    }
    validate_owner_directory(path)
}

fn validate_owner_directory(path: &Path) -> Result<(), ProductionProvisioningErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProductionProvisioningErrorV1::InvalidAuthority)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE_V1
        || metadata.uid() != effective_uid()?
    {
        return Err(ProductionProvisioningErrorV1::InvalidAuthority);
    }
    Ok(())
}

fn effective_uid() -> Result<u32, ProductionProvisioningErrorV1> {
    let mut status = File::open("/proc/self/status")
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
    let mut bytes = Vec::with_capacity(4_096);
    Read::by_ref(&mut status)
        .take(64 * 1_024)
        .read_to_end(&mut bytes)
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)?;
    let line = text
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or(ProductionProvisioningErrorV1::StorageUnavailable)?;
    line[4..]
        .split_ascii_whitespace()
        .nth(1)
        .ok_or(ProductionProvisioningErrorV1::StorageUnavailable)?
        .parse()
        .map_err(|_| ProductionProvisioningErrorV1::StorageUnavailable)
}

fn validate_binding(binding: [u8; 32]) -> Result<(), ProductionProvisioningErrorV1> {
    if binding == [0; 32] {
        return Err(ProductionProvisioningErrorV1::InvalidBinding);
    }
    Ok(())
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], ProductionProvisioningErrorV1> {
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| ProductionProvisioningErrorV1::InvalidBinding)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(
            &u64::try_from(part.len())
                .map_err(|_| ProductionProvisioningErrorV1::InvalidBinding)?
                .to_be_bytes(),
        );
        hasher.update(part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| ProductionProvisioningErrorV1::InvalidBinding)?;
    validate_binding(output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_temp() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(DIRECTORY_MODE_V1))?;
        Ok(root)
    }

    #[test]
    fn stages_are_prefix_ordered_and_reopen_exactly() -> Result<(), Box<dyn std::error::Error>> {
        let root = owner_temp()?;
        let binding = provisioning_binding_v1(b"create", b"reopen", [7; 32])?;
        let mut journal = DurableProductionProvisioningJournalV1::create(root.path(), binding)?;
        assert_eq!(
            journal.stage_state(ProductionProvisioningStageV1::TimeAnchorStore)?,
            ProductionProvisioningStageStateV1::Absent
        );
        assert_eq!(
            journal.begin(ProductionProvisioningStageV1::TimeAnchorStore)?,
            ProductionProvisioningStageStateV1::Started
        );
        assert_eq!(
            journal.begin(ProductionProvisioningStageV1::RouteStore),
            Err(ProductionProvisioningErrorV1::Inconsistent)
        );
        journal.complete(ProductionProvisioningStageV1::TimeAnchorStore)?;
        journal.begin(ProductionProvisioningStageV1::RouteStore)?;
        drop(journal);
        let reopened = DurableProductionProvisioningJournalV1::open(root.path(), binding)?;
        assert_eq!(
            reopened.stage_state(ProductionProvisioningStageV1::TimeAnchorStore)?,
            ProductionProvisioningStageStateV1::Complete
        );
        assert_eq!(
            reopened.stage_state(ProductionProvisioningStageV1::RouteStore)?,
            ProductionProvisioningStageStateV1::Started
        );
        drop(reopened);
        assert!(matches!(
            DurableProductionProvisioningJournalV1::open(root.path(), [8; 32]),
            Err(ProductionProvisioningErrorV1::Inconsistent)
        ));
        Ok(())
    }

    #[test]
    fn contracts_and_f6_are_durably_complete_before_relay_can_begin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = owner_temp()?;
        let binding = provisioning_binding_v1(b"create", b"reopen", [15; 32])?;
        let mut journal = DurableProductionProvisioningJournalV1::create(root.path(), binding)?;
        for stage in ProductionProvisioningStageV1::ALL {
            if stage == ProductionProvisioningStageV1::ContractsStores {
                break;
            }
            journal.begin(stage)?;
            journal.complete(stage)?;
        }
        assert_eq!(
            journal.begin(ProductionProvisioningStageV1::RelayAuthorities),
            Err(ProductionProvisioningErrorV1::Inconsistent)
        );
        journal.begin(ProductionProvisioningStageV1::ContractsStores)?;
        journal.complete(ProductionProvisioningStageV1::ContractsStores)?;
        assert_eq!(
            journal.begin(ProductionProvisioningStageV1::RelayAuthorities),
            Err(ProductionProvisioningErrorV1::Inconsistent)
        );
        journal.begin(ProductionProvisioningStageV1::F6Authorities)?;
        journal.complete(ProductionProvisioningStageV1::F6Authorities)?;
        assert_eq!(
            journal.begin(ProductionProvisioningStageV1::RelayAuthorities)?,
            ProductionProvisioningStageStateV1::Started
        );
        Ok(())
    }

    #[test]
    fn valid_staging_marker_is_recovered_after_crash() -> Result<(), Box<dyn std::error::Error>> {
        let root = owner_temp()?;
        let binding = provisioning_binding_v1(b"create", b"reopen", [9; 32])?;
        let journal = DurableProductionProvisioningJournalV1::create(root.path(), binding)?;
        let stage = ProductionProvisioningStageV1::TimeAnchorStore;
        let staging = marker_staging_name(stage, false);
        write_new_file_durable(
            &journal.root,
            &staging,
            &stage_record(binding, stage, false)?,
        )?;
        drop(journal);
        let reopened = DurableProductionProvisioningJournalV1::open(root.path(), binding)?;
        assert_eq!(
            reopened.stage_state(stage)?,
            ProductionProvisioningStageStateV1::Started
        );
        assert!(!cap_path_present(&reopened.root, &staging)?);
        Ok(())
    }

    #[test]
    fn unknown_entry_and_completed_without_started_are_refused(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = owner_temp()?;
        let binding = provisioning_binding_v1(b"create", b"reopen", [10; 32])?;
        let journal = DurableProductionProvisioningJournalV1::create(root.path(), binding)?;
        write_new_file_durable(&journal.root, "foreign", &[1])?;
        assert_eq!(
            journal.audit(),
            Err(ProductionProvisioningErrorV1::InvalidAuthority)
        );
        journal.root.remove_file("foreign")?;
        write_new_file_durable(
            &journal.root,
            &marker_name(ProductionProvisioningStageV1::TimeAnchorStore, true),
            &stage_record(
                binding,
                ProductionProvisioningStageV1::TimeAnchorStore,
                true,
            )?,
        )?;
        assert_eq!(
            journal.audit(),
            Err(ProductionProvisioningErrorV1::Inconsistent)
        );
        Ok(())
    }

    #[test]
    fn owner_lock_and_named_root_identity_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
        let state = owner_temp()?;
        let binding = provisioning_binding_v1(b"create", b"reopen", [11; 32])?;
        let journal = DurableProductionProvisioningJournalV1::create(state.path(), binding)?;
        assert!(matches!(
            DurableProductionProvisioningJournalV1::open(state.path(), binding),
            Err(ProductionProvisioningErrorV1::InUse)
        ));

        let published = state.path().join(JOURNAL_ROOT_NAME_V1);
        let displaced = state.path().join("displaced-journal");
        fs::rename(&published, &displaced)?;
        fs::create_dir(&published)?;
        fs::set_permissions(&published, fs::Permissions::from_mode(DIRECTORY_MODE_V1))?;
        assert_eq!(
            journal.audit(),
            Err(ProductionProvisioningErrorV1::InvalidAuthority)
        );

        let second_state = owner_temp()?;
        let second_binding = provisioning_binding_v1(b"create", b"reopen", [14; 32])?;
        let second =
            DurableProductionProvisioningJournalV1::create(second_state.path(), second_binding)?;
        drop(second);
        fs::remove_file(
            second_state
                .path()
                .join(JOURNAL_ROOT_NAME_V1)
                .join(LOCK_FILE_V1),
        )?;
        assert!(matches!(
            DurableProductionProvisioningJournalV1::open(second_state.path(), second_binding),
            Err(ProductionProvisioningErrorV1::InvalidAuthority)
        ));
        let external_lock = second_state.path().join("hardlink-source");
        let state_capability = Dir::from_std_file(File::open(second_state.path())?);
        write_new_file_durable(&state_capability, "hardlink-source", b"")?;
        fs::hard_link(
            &external_lock,
            second_state
                .path()
                .join(JOURNAL_ROOT_NAME_V1)
                .join(LOCK_FILE_V1),
        )?;
        assert!(matches!(
            DurableProductionProvisioningJournalV1::open(second_state.path(), second_binding),
            Err(ProductionProvisioningErrorV1::InvalidAuthority)
        ));
        Ok(())
    }

    #[test]
    fn empty_root_staging_and_torn_marker_are_recovered() -> Result<(), Box<dyn std::error::Error>>
    {
        let state = owner_temp()?;
        let staging_root = state.path().join(JOURNAL_STAGING_NAME_V1);
        fs::create_dir(&staging_root)?;
        fs::set_permissions(&staging_root, fs::Permissions::from_mode(DIRECTORY_MODE_V1))?;
        let binding = provisioning_binding_v1(b"create", b"reopen", [12; 32])?;
        let mut journal = DurableProductionProvisioningJournalV1::create(state.path(), binding)?;
        let stage = ProductionProvisioningStageV1::TimeAnchorStore;
        let staging = marker_staging_name(stage, false);
        write_new_file_durable(&journal.root, &staging, b"partial")?;
        assert_eq!(
            journal.stage_state(stage)?,
            ProductionProvisioningStageStateV1::Absent
        );
        assert!(!cap_path_present(&journal.root, &staging)?);
        assert_eq!(
            journal.begin(stage)?,
            ProductionProvisioningStageStateV1::Started
        );

        let second_state = owner_temp()?;
        let second_staging_path = second_state.path().join(JOURNAL_STAGING_NAME_V1);
        fs::create_dir(&second_staging_path)?;
        fs::set_permissions(
            &second_staging_path,
            fs::Permissions::from_mode(DIRECTORY_MODE_V1),
        )?;
        let second_staging = Dir::from_std_file(File::open(&second_staging_path)?);
        write_new_file_durable(&second_staging, BINDING_FILE_V1, b"partial")?;
        drop(second_staging);
        let second_binding = provisioning_binding_v1(b"create", b"reopen", [13; 32])?;
        let second =
            DurableProductionProvisioningJournalV1::create(second_state.path(), second_binding)?;
        assert_eq!(
            second.stage_state(stage)?,
            ProductionProvisioningStageStateV1::Absent
        );
        Ok(())
    }
}
